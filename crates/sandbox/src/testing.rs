//! Conformance suite for [`Launcher`] and [`Lockdown`] implementations, and the probe worker it
//! launches.
//!
//! An implementation's test binary doubles as the probe: when started with [`PROBE_ARG`] its
//! `main` calls [`probe_main`] with the implementation's [`Lockdown`]; otherwise it calls
//! [`run`] (or [`run_mechanics`] for an implementation that is not a wall) with its [`Launcher`]
//! and a [`WorkerCommand`] that starts the same binary with [`PROBE_ARG`].

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::{
    Exit, KillReason, Launcher, Lockdown, Policy, SandboxError, WorkerCommand, WorkerProcess,
    announce, read_frame, write_frame,
};

/// The argument that turns a test binary into the probe.
pub const PROBE_ARG: &str = "--rinse-sandbox-probe";
const EXIT_BEFORE_ANNOUNCING: &str = "--rinse-sandbox-probe-exit-early";
const BAD_ANNOUNCEMENT: &str = "--rinse-sandbox-probe-bad-announcement";
const GUARD: Duration = Duration::from_secs(30);

/// Whether the current process was started as the probe.
pub fn is_probe() -> bool {
    std::env::args().any(|a| a == PROBE_ARG)
}

/// The probe worker: locks down with `lockdown` and the policy of its arguments, announces, then
/// performs the one operation the parent asks for and reports whether the operating system
/// allowed it.
pub fn probe_main(lockdown: &dyn Lockdown) -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut stdout = std::io::stdout().lock();
    if args.iter().any(|a| a == EXIT_BEFORE_ANNOUNCING) {
        return ExitCode::from(3);
    }
    if args.iter().any(|a| a == BAD_ANNOUNCEMENT) {
        let _ = write_frame(&mut stdout, &[0xff; 8]);
        return ExitCode::SUCCESS;
    }
    let Ok(policy) = Policy::from_args(&args) else {
        return ExitCode::from(2);
    };
    let report = match lockdown
        .prepare(&policy)
        .and_then(|prepared| lockdown.lock_down(&policy, prepared))
    {
        Ok(report) => report,
        Err(_) => return ExitCode::from(4),
    };
    if announce(&mut stdout, &report).is_err() {
        return ExitCode::from(5);
    }
    let mut stdin = std::io::stdin().lock();
    let Ok(request) = read_frame(&mut stdin, 64 << 10) else {
        return ExitCode::from(6);
    };
    let request = String::from_utf8_lossy(&request).into_owned();
    let reply = probe(&request);
    if write_frame(&mut stdout, &reply).is_err() {
        return ExitCode::from(7);
    }
    ExitCode::SUCCESS
}

fn verdict(allowed: bool) -> Vec<u8> {
    if allowed {
        b"allowed".to_vec()
    } else {
        b"denied".to_vec()
    }
}

fn probe(request: &str) -> Vec<u8> {
    let (op, arg) = request.split_once(':').unwrap_or((request, ""));
    match op {
        "echo" => request.as_bytes().to_vec(),
        "env" => format!("env:{}", std::env::vars_os().count()).into_bytes(),
        "read" => verdict(
            std::fs::File::open(arg)
                .and_then(|mut f| f.read(&mut [0u8; 1]))
                .is_ok(),
        ),
        "list" => verdict(std::fs::read_dir(arg).is_ok_and(|mut d| d.next().is_some())),
        "write" => verdict(
            std::fs::File::create(arg)
                .and_then(|mut f| f.write_all(b"probe"))
                .is_ok(),
        ),
        "connect" => verdict(arg.parse().is_ok_and(|addr| {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok()
        })),
        "bind-udp" => verdict(std::net::UdpSocket::bind("127.0.0.1:0").is_ok()),
        "spawn" => verdict(std::process::Command::new(arg).status().is_ok()),
        #[cfg(unix)]
        "inherited" => verdict(
            arg.parse()
                .is_ok_and(|fd| crate::sys::write_descriptor(fd, b"probe")),
        ),
        #[cfg(unix)]
        "signal" => verdict(
            arg.parse()
                .is_ok_and(|pid| crate::sys::request_signals(pid, 15)),
        ),
        #[cfg(unix)]
        "memory-shared" => verdict(crate::sys::touch_shared_memory(arg.parse().unwrap_or(0))),
        #[cfg(unix)]
        "unix-path" => verdict(std::os::unix::net::UnixStream::connect(arg).is_ok()),
        #[cfg(target_os = "linux")]
        "unix-abstract" => {
            use std::os::linux::net::SocketAddrExt;
            verdict(
                std::os::unix::net::SocketAddr::from_abstract_name(arg)
                    .is_ok_and(|addr| std::os::unix::net::UnixStream::connect_addr(&addr).is_ok()),
            )
        }
        "memory" => {
            let bytes: usize = arg.parse().unwrap_or(0);
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve_exact(bytes).is_err() {
                return verdict(false);
            }
            v.resize(bytes, 1);
            std::hint::black_box(&v);
            verdict(true)
        }
        "spin" => {
            let mut x = 0u64;
            loop {
                x = std::hint::black_box(x.wrapping_add(1));
            }
        }
        "big" => vec![b'x'; arg.parse().unwrap_or(0)],
        _ => b"unknown".to_vec(),
    }
}

/// What a probed operation came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The operating system allowed it.
    Allowed,
    /// It failed inside the probe.
    Denied,
    /// The probe was killed or crashed trying.
    Died(Exit),
}

fn command(probe: &WorkerCommand, extra: &str) -> WorkerCommand {
    let mut command = probe.clone();
    command.args.push(extra.to_owned());
    command
}

async fn guard<T>(what: &str, f: impl Future<Output = T>) -> T {
    tokio::time::timeout(GUARD, f)
        .await
        .unwrap_or_else(|_| panic!("{what}: no answer within {GUARD:?}"))
}

async fn launch(
    launcher: &Arc<dyn Launcher>,
    probe: &WorkerCommand,
    policy: &Policy,
) -> Box<dyn WorkerProcess> {
    guard("launch", launcher.launch(probe, policy))
        .await
        .unwrap_or_else(|e| panic!("launching the probe failed: {e}"))
}

/// Starts a probe under `policy`, asks for `request` and reports what happened.
pub async fn outcome(
    launcher: &Arc<dyn Launcher>,
    probe: &WorkerCommand,
    policy: &Policy,
    request: &str,
) -> Outcome {
    let mut worker = launch(launcher, probe, policy).await;
    worker.send(request.as_bytes()).await.unwrap_or_else(|e| {
        panic!("{request}: sending failed: {e}");
    });
    let reply = guard(request, worker.receive(1 << 20)).await;
    match reply {
        Ok(bytes) if bytes == b"allowed" => {
            let _ = guard(request, worker.wait()).await;
            Outcome::Allowed
        }
        Ok(bytes) if bytes == b"denied" => {
            let _ = guard(request, worker.wait()).await;
            Outcome::Denied
        }
        Ok(other) => panic!("{request}: unexpected reply of {} bytes", other.len()),
        Err(SandboxError::Closed) => {
            let exit = guard(request, worker.wait())
                .await
                .unwrap_or_else(|e| panic!("{request}: wait failed: {e}"));
            assert_ne!(
                exit,
                Exit::Code(0),
                "{request}: exited cleanly without a reply"
            );
            Outcome::Died(exit)
        }
        Err(e) => panic!("{request}: receive failed: {e}"),
    }
}

fn denied(request: &str, outcome: &Outcome) {
    println!("{request}: {outcome:?}");
    assert!(
        !matches!(outcome, Outcome::Allowed),
        "{request}: allowed inside the sandbox"
    );
}

/// Runs [`run_mechanics`] and then checks that the sandbox holds: after lockdown the probe cannot
/// read or list files (`/etc/passwd`, `/`, the home directory), create or write a file, connect
/// to a listener on loopback, bind a socket, or start a process, and going over the memory or CPU
/// limit ends it.
pub async fn run(launcher: Arc<dyn Launcher>, probe: WorkerCommand) {
    assert!(launcher.is_wall(), "run is for sandboxing launchers");
    run_mechanics(Arc::clone(&launcher), probe.clone()).await;
    let policy = Policy::default();

    {
        let worker = launch(&launcher, &probe, &policy).await;
        assert!(
            !worker.report().applied.is_empty(),
            "a sandboxing launcher reported no restriction"
        );
    }

    let mut requests = vec!["read:/etc/passwd".to_owned(), "list:/".to_owned()];
    if let Some(home) = std::env::var_os("HOME") {
        requests.push(format!("list:{}", home.to_string_lossy()));
    }
    for request in &requests {
        denied(request, &outcome(&launcher, &probe, &policy, request).await);
    }

    let target = scratch_path();
    let request = format!("write:{}", target.display());
    denied(
        &request,
        &outcome(&launcher, &probe, &policy, &request).await,
    );
    assert!(!target.exists(), "the probe created {}", target.display());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let request = format!("connect:{}", listener.local_addr().expect("address"));
    denied(
        &request,
        &outcome(&launcher, &probe, &policy, &request).await,
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), listener.accept())
            .await
            .is_err(),
        "the probe reached a loopback listener"
    );

    denied(
        "bind-udp",
        &outcome(&launcher, &probe, &policy, "bind-udp").await,
    );

    let request = format!("spawn:{}", probe.program.display());
    denied(
        &request,
        &outcome(&launcher, &probe, &policy, &request).await,
    );
    denied(
        "spawn:/bin/sh",
        &outcome(&launcher, &probe, &policy, "spawn:/bin/sh").await,
    );

    #[cfg(unix)]
    {
        unix_sockets(&launcher, &probe, &policy).await;
        signals(&launcher, &probe, &policy).await;
    }

    let small = Policy {
        memory_bytes: 256 << 20,
        ..policy
    };
    let request = format!("memory:{}", 1u64 << 30);
    denied(
        &request,
        &outcome(&launcher, &probe, &small, &request).await,
    );
    #[cfg(unix)]
    {
        let request = format!("memory-shared:{}", 1u64 << 30);
        denied(
            &request,
            &outcome(&launcher, &probe, &small, &request).await,
        );
    }

    let cpu = Policy {
        cpu_seconds: 1,
        wall_time: Duration::from_secs(25),
        ..policy
    };
    let started = Instant::now();
    let spun = outcome(&launcher, &probe, &cpu, "spin").await;
    println!(
        "spin past the CPU limit: {spun:?} after {:?}",
        started.elapsed()
    );
    match spun {
        Outcome::Died(Exit::Killed(KillReason::Cpu) | Exit::Signal(_)) => {}
        other => panic!("spin past the CPU limit: {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the CPU limit took {:?}",
        started.elapsed()
    );
}

#[cfg(unix)]
async fn unix_sockets(launcher: &Arc<dyn Launcher>, probe: &WorkerCommand, policy: &Policy) {
    use std::os::unix::net::UnixListener;

    let path = scratch_path();
    let listener = UnixListener::bind(&path).expect("a Unix socket listener");
    listener.set_nonblocking(true).expect("non-blocking");
    let request = format!("unix-path:{}", path.display());
    denied(&request, &outcome(launcher, probe, policy, &request).await);
    assert!(
        listener.accept().is_err(),
        "the probe reached a Unix socket at a path"
    );
    drop(listener);
    let _ = std::fs::remove_file(&path);

    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;

        let name = format!("rinse-sandbox-probe-{}", std::process::id());
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(&name).expect("name");
        let listener = UnixListener::bind_addr(&addr).expect("an abstract Unix socket listener");
        listener.set_nonblocking(true).expect("non-blocking");
        let request = format!("unix-abstract:{name}");
        denied(&request, &outcome(launcher, probe, policy, &request).await);
        assert!(
            listener.accept().is_err(),
            "the probe reached an abstract Unix socket"
        );
    }
}

#[cfg(unix)]
async fn signals(launcher: &Arc<dyn Launcher>, probe: &WorkerCommand, policy: &Policy) {
    let mut target = std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a target process");
    let request = format!("signal:{}", target.id());
    let signalled = outcome(launcher, probe, policy, &request).await;
    if cfg!(target_os = "linux") {
        denied(&request, &signalled);
    } else if cfg!(target_os = "macos") {
        println!("{request}: {signalled:?}");
        assert!(
            matches!(signalled, Outcome::Allowed),
            "{request}: Seatbelt now denies F_SETOWN toward another process; update WALLS.md"
        );
    } else {
        println!("{request}: {signalled:?}");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let alive = matches!(target.try_wait(), Ok(None));
    let _ = target.kill();
    let _ = target.wait();
    assert!(alive, "the probe signalled another process");
}

#[cfg(unix)]
async fn inherited_descriptor(launcher: &Arc<dyn Launcher>, probe: &WorkerCommand) {
    use std::os::fd::AsRawFd;

    let (read, write) = rustix::pipe::pipe().expect("a pipe without close-on-exec");
    let request = format!("inherited:{}", write.as_raw_fd());
    let mut worker = launch(launcher, probe, &Policy::default()).await;
    drop(write);
    worker.send(request.as_bytes()).await.expect("send");
    let reply = guard(&request, worker.receive(64)).await.expect("reply");
    let _ = guard(&request, worker.wait()).await;
    println!("{request}: {}", String::from_utf8_lossy(&reply));
    assert_eq!(reply, b"denied", "the worker kept an inherited descriptor");
    let mut leaked = Vec::new();
    std::fs::File::from(read)
        .read_to_end(&mut leaked)
        .expect("read the pipe");
    assert!(
        leaked.is_empty(),
        "the worker wrote to an inherited descriptor"
    );
}

fn scratch_path() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    std::env::temp_dir().join(format!(
        "rinse-sandbox-probe-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Checks launching and talking to workers, for every implementation including those that are
/// not walls: the policy and an empty environment reach the worker, frames round-trip, a frame
/// over the cap is refused, the wall time and [`WorkerProcess::kill`] end the worker, and a
/// missing program, a worker that exits before announcing and a malformed announcement fail the
/// launch.
pub async fn run_mechanics(launcher: Arc<dyn Launcher>, probe: WorkerCommand) {
    let policy = Policy::default();

    let mut worker = launch(&launcher, &probe, &policy).await;
    worker.send(b"echo:hello").await.expect("send");
    assert_eq!(
        guard("echo", worker.receive(64)).await.expect("echo reply"),
        b"echo:hello"
    );
    assert_eq!(
        guard("echo", worker.wait()).await.expect("wait"),
        Exit::Code(0)
    );

    let mut worker = launch(&launcher, &probe, &policy).await;
    worker.send(b"env").await.expect("send");
    assert_eq!(
        guard("env", worker.receive(64)).await.expect("env reply"),
        b"env:0",
        "the worker inherited environment variables"
    );
    drop(worker);

    let mut worker = launch(&launcher, &probe, &policy).await;
    worker.send(b"big:100000").await.expect("send");
    assert_eq!(
        guard("big", worker.receive(100_000))
            .await
            .expect("big reply")
            .len(),
        100_000
    );
    drop(worker);

    let mut worker = launch(&launcher, &probe, &policy).await;
    worker.send(b"big:1000").await.expect("send");
    assert_eq!(
        guard("cap", worker.receive(999)).await.unwrap_err(),
        SandboxError::FrameTooLarge
    );
    drop(worker);

    #[cfg(unix)]
    inherited_descriptor(&launcher, &probe).await;

    let short = Policy {
        wall_time: Duration::from_secs(2),
        cpu_seconds: 30,
        ..policy
    };
    let mut worker = launch(&launcher, &probe, &short).await;
    let started = Instant::now();
    worker.send(b"spin").await.expect("send");
    assert_eq!(
        guard("wall time", worker.receive(64)).await.unwrap_err(),
        SandboxError::WallTime
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "wall time enforced after {:?}",
        started.elapsed()
    );
    assert_eq!(
        guard("wall time", worker.wait()).await.expect("wait"),
        Exit::Killed(KillReason::WallTime)
    );

    let mut worker = launch(&launcher, &probe, &policy).await;
    worker.send(b"spin").await.expect("send");
    worker.kill().await;
    assert_eq!(
        guard("kill", worker.wait()).await.expect("wait"),
        Exit::Killed(KillReason::Caller)
    );

    let missing = WorkerCommand {
        program: std::env::temp_dir().join("rinse-sandbox-no-such-program"),
        args: Vec::new(),
    };
    assert_eq!(
        guard("missing", launcher.launch(&missing, &policy))
            .await
            .err(),
        Some(SandboxError::Spawn)
    );
    assert_eq!(
        guard(
            "exit early",
            launcher.launch(&command(&probe, EXIT_BEFORE_ANNOUNCING), &policy)
        )
        .await
        .err(),
        Some(SandboxError::Closed)
    );
    assert_eq!(
        guard(
            "bad announcement",
            launcher.launch(&command(&probe, BAD_ANNOUNCEMENT), &policy)
        )
        .await
        .err(),
        Some(SandboxError::Protocol)
    );
}
