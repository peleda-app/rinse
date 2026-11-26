use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use async_trait::async_trait;
use rinse_sandbox::{
    Exit, KillReason, LockdownReport, MAX_ANNOUNCEMENT, Policy, SandboxError, WorkerCommand,
    WorkerProcess, decode_announcement, frame_header, frame_len,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::Instant;

/// Reads the memory footprint of a live child in bytes.
pub(crate) type Footprint = fn(u32) -> Option<u64>;

const WATCH_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) struct Worker {
    child: Child,
    pid: Option<u32>,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    deadline: Instant,
    report: LockdownReport,
    killed: Option<KillReason>,
    exit: Option<Exit>,
    memory: Option<(Footprint, u64)>,
}

enum Raced<T> {
    Done(T),
    Deadline,
    Memory,
}

async fn race<T>(
    fut: impl Future<Output = T>,
    deadline: Instant,
    pid: Option<u32>,
    memory: Option<(Footprint, u64)>,
) -> Raced<T> {
    tokio::pin!(fut);
    let mut tick = tokio::time::interval(WATCH_INTERVAL);
    loop {
        tokio::select! {
            out = &mut fut => return Raced::Done(out),
            () = tokio::time::sleep_until(deadline) => return Raced::Deadline,
            _ = tick.tick(), if memory.is_some() => {
                if let (Some((footprint, limit)), Some(pid)) = (memory, pid)
                    && footprint(pid).is_some_and(|bytes| bytes > limit)
                {
                    return Raced::Memory;
                }
            }
        }
    }
}

fn io_error(e: &std::io::Error) -> SandboxError {
    match e.kind() {
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe => SandboxError::Closed,
        _ => SandboxError::Io,
    }
}

impl Worker {
    /// Spawns `command` and waits for its announcement. `memory` is checked while the parent
    /// waits on the worker.
    pub(crate) async fn start(
        command: &WorkerCommand,
        policy: &Policy,
        memory: Option<Footprint>,
    ) -> Result<Self, SandboxError> {
        let deadline = Instant::now() + policy.wall_time;
        let mut cmd = Command::new(&command.program);
        cmd.args(&command.args)
            .arg(policy.to_arg())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if cfg!(unix) {
            cmd.current_dir("/");
        }
        let mut child = cmd.spawn().map_err(|_| SandboxError::Spawn)?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or(SandboxError::Spawn)?;
        let mut worker = Self {
            pid: child.id(),
            child,
            stdin,
            stdout,
            deadline,
            report: LockdownReport::default(),
            killed: None,
            exit: None,
            memory: memory.map(|f| (f, policy.memory_bytes)),
        };
        let frame = match worker.read(MAX_ANNOUNCEMENT).await {
            Ok(frame) => frame,
            Err(SandboxError::FrameTooLarge) => return Err(SandboxError::Protocol),
            Err(e) => return Err(e),
        };
        worker.report = decode_announcement(&frame)?;
        Ok(worker)
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        self.pid
    }

    pub(crate) fn report_mut(&mut self) -> &mut LockdownReport {
        &mut self.report
    }

    fn watch(&self) -> Option<(Footprint, u64)> {
        if self.killed.is_some() {
            None
        } else {
            self.memory
        }
    }

    fn kill_for(&mut self, reason: KillReason) {
        if self.exit.is_none() && self.killed.is_none() {
            self.killed = Some(reason);
            let _ = self.child.start_kill();
        }
    }

    fn expired(&mut self) -> Result<(), SandboxError> {
        if Instant::now() >= self.deadline {
            self.kill_for(KillReason::WallTime);
            return Err(SandboxError::WallTime);
        }
        Ok(())
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), SandboxError> {
        let watch = self.watch();
        let raced = race(self.stdout.read_exact(buf), self.deadline, self.pid, watch).await;
        match raced {
            Raced::Done(Ok(_)) => Ok(()),
            Raced::Done(Err(e)) => Err(io_error(&e)),
            Raced::Deadline => {
                self.kill_for(KillReason::WallTime);
                Err(SandboxError::WallTime)
            }
            Raced::Memory => {
                self.kill_for(KillReason::Memory);
                Err(SandboxError::Closed)
            }
        }
    }

    async fn read(&mut self, max_len: usize) -> Result<Vec<u8>, SandboxError> {
        self.expired()?;
        let mut header = [0u8; 4];
        self.read_exact(&mut header).await?;
        let len = frame_len(header);
        if len > max_len {
            self.kill_for(KillReason::Caller);
            return Err(SandboxError::FrameTooLarge);
        }
        let mut payload = vec![0u8; len];
        self.read_exact(&mut payload).await?;
        Ok(payload)
    }

    fn exit_of(&self, status: ExitStatus) -> Exit {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            const SIGKILL: i32 = 9;
            const SIGXCPU: i32 = 24;
            if let Some(signal) = status.signal() {
                return match (signal, self.killed) {
                    (SIGKILL, Some(reason)) => Exit::Killed(reason),
                    (SIGXCPU, _) => Exit::Killed(KillReason::Cpu),
                    _ => Exit::Signal(signal),
                };
            }
        }
        match (status.code(), self.killed) {
            (Some(code), Some(reason)) if code != 0 && cfg!(not(unix)) => Exit::Killed(reason),
            (Some(code), _) => Exit::Code(code),
            (None, _) => Exit::Signal(0),
        }
    }
}

#[async_trait]
impl WorkerProcess for Worker {
    fn report(&self) -> &LockdownReport {
        &self.report
    }

    async fn send(&mut self, payload: &[u8]) -> Result<(), SandboxError> {
        self.expired()?;
        let header = frame_header(payload.len())?;
        let watch = self.watch();
        let stdin = self.stdin.as_mut().ok_or(SandboxError::Closed)?;
        let write = async {
            stdin.write_all(&header).await?;
            stdin.write_all(payload).await?;
            stdin.flush().await
        };
        match race(write, self.deadline, self.pid, watch).await {
            Raced::Done(Ok(())) => Ok(()),
            Raced::Done(Err(e)) => Err(io_error(&e)),
            Raced::Deadline => {
                self.kill_for(KillReason::WallTime);
                Err(SandboxError::WallTime)
            }
            Raced::Memory => {
                self.kill_for(KillReason::Memory);
                Err(SandboxError::Closed)
            }
        }
    }

    async fn receive(&mut self, max_len: usize) -> Result<Vec<u8>, SandboxError> {
        self.read(max_len).await
    }

    async fn kill(&mut self) {
        self.kill_for(KillReason::Caller);
    }

    async fn wait(&mut self) -> Result<Exit, SandboxError> {
        if let Some(exit) = self.exit {
            return Ok(exit);
        }
        self.stdin = None;
        let status = loop {
            let watch = self.watch();
            let raced = race(self.child.wait(), self.deadline, self.pid, watch).await;
            match raced {
                Raced::Done(status) => break status.map_err(|_| SandboxError::Io)?,
                Raced::Deadline => {
                    self.kill_for(KillReason::WallTime);
                    break self.child.wait().await.map_err(|_| SandboxError::Io)?;
                }
                Raced::Memory => self.kill_for(KillReason::Memory),
            }
        };
        let exit = self.exit_of(status);
        self.exit = Some(exit);
        Ok(exit)
    }
}
