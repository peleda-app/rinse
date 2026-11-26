//! Contract for sandboxed worker processes (wall 2 of `docs/WALLS.md`): what a worker process
//! may do ([`Policy`]), how the parent starts one and talks to it ([`Launcher`],
//! [`WorkerProcess`]), and how the worker locks itself down before it reads any input
//! ([`Lockdown`]). No platform type appears here; implementations live in `sandbox-linux`,
//! `sandbox-macos` and `sandbox-none`.
//!
//! A worker's life: the parent calls [`Launcher::launch`]; the worker calls [`Lockdown::prepare`]
//! as the first thing in `main`, loads what it needs from trusted sources, calls
//! [`Lockdown::lock_down`], writes the report with [`announce`], and only then reads requests.
//! Everything sent after the announcement is one frame: a 4-byte little-endian length and that many
//! bytes.

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

mod sys;
#[cfg(feature = "testing")]
pub mod testing;

/// Entry points for the fuzz targets in `fuzz/` (nightly `cargo fuzz`), which feed them arbitrary
/// bytes; the unit tests feed them hostile variants on every `cargo test`. None may panic.
#[doc(hidden)]
pub mod fuzz {
    use super::{MAX_ANNOUNCEMENT, Policy, decode_announcement, read_frame};

    /// A launcher reading the announcement frame from a worker's stdout.
    pub fn frame(data: &[u8]) {
        let mut input = data;
        if let Ok(frame) = read_frame(&mut input, MAX_ANNOUNCEMENT) {
            assert!(frame.len() <= MAX_ANNOUNCEMENT);
            let _ = decode_announcement(&frame);
        }
    }

    /// A launcher decoding an announcement payload.
    pub fn announcement(data: &[u8]) {
        let _ = decode_announcement(data);
    }

    /// A worker reading its policy from its arguments, split at NUL bytes.
    pub fn policy(data: &[u8]) {
        let text = String::from_utf8_lossy(data);
        let _ = Policy::from_args(text.split('\0'));
    }
}

/// What a worker process may use. Everything not covered here (files, network, other processes,
/// IPC) is denied by every implementation that is a wall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Most memory the process may hold, in bytes.
    pub memory_bytes: u64,
    /// Most CPU time the process may use after it locked down, in seconds.
    pub cpu_seconds: u64,
    /// Longest the process may live from launch; the parent kills it after that.
    pub wall_time: Duration,
    /// Whether the locked-down process may create executable memory (a JIT).
    pub allow_jit: bool,
}

impl Default for Policy {
    /// 1 GiB, 10 s of CPU, 60 s of wall time, no JIT.
    fn default() -> Self {
        Self {
            memory_bytes: 1 << 30,
            cpu_seconds: 10,
            wall_time: Duration::from_secs(60),
            allow_jit: false,
        }
    }
}

const POLICY_ARG: &str = "--rinse-sandbox-policy=";

impl Policy {
    /// The command-line argument a launcher appends to the worker's arguments. Only
    /// [`Policy::from_args`] needs to understand it.
    pub fn to_arg(&self) -> String {
        format!(
            "{POLICY_ARG}m{},c{},w{},j{}",
            self.memory_bytes,
            self.cpu_seconds,
            self.wall_time.as_millis(),
            u8::from(self.allow_jit)
        )
    }

    /// Finds the argument written by [`Policy::to_arg`] among a worker's arguments. Fails with
    /// [`SandboxError::Policy`] when it is missing, repeated or malformed.
    pub fn from_args<I, S>(args: I) -> Result<Self, SandboxError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut found = None;
        for arg in args {
            if let Some(value) = arg.as_ref().strip_prefix(POLICY_ARG) {
                if found.is_some() {
                    return Err(SandboxError::Policy);
                }
                found = Some(Self::parse(value).ok_or(SandboxError::Policy)?);
            }
        }
        found.ok_or(SandboxError::Policy)
    }

    fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split(',');
        let mut field =
            |tag: char| -> Option<u64> { parts.next()?.strip_prefix(tag)?.parse().ok() };
        let memory_bytes = field('m')?;
        let cpu_seconds = field('c')?;
        let wall_ms = field('w')?;
        let allow_jit = match field('j')? {
            0 => false,
            1 => true,
            _ => return None,
        };
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            memory_bytes,
            cpu_seconds,
            wall_time: Duration::from_millis(wall_ms),
            allow_jit,
        })
    }
}

/// The program a launcher starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCommand {
    /// Absolute path of the executable.
    pub program: PathBuf,
    /// Arguments before the policy argument the launcher appends.
    pub args: Vec<String>,
}

/// One restriction a worker can be under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Restriction {
    /// The process and its descendants can never gain privileges (setuid, file capabilities).
    NoNewPrivileges,
    /// CPU time is capped at [`Policy::cpu_seconds`].
    CpuLimit,
    /// Memory is capped at [`Policy::memory_bytes`].
    MemoryLimit,
    /// No file can grow and no core dump is written (zero file-size and core-size limits).
    FileSizeLimit,
    /// The process runs in a new user namespace without privileges outside it.
    UserNamespace,
    /// The process runs in a new network namespace with no interfaces but an unconfigured
    /// loopback.
    NetworkNamespace,
    /// The process runs in a new IPC namespace.
    IpcNamespace,
    /// The process runs in a new mount namespace.
    MountNamespace,
    /// Landlock denies every file system access and, where the kernel supports it, TCP bind and
    /// connect, abstract Unix sockets and signals to other processes.
    Landlock,
    /// A seccomp filter kills the process on every system call outside a small allowlist.
    Seccomp,
    /// The locked-down process cannot create executable memory.
    NoExecutableMemory,
    /// A Seatbelt profile denies everything the process does not need (macOS).
    Seatbelt,
    /// Every descriptor above stderr the process inherited from its parent was closed before it
    /// loaded or read anything, so it holds only its stdin, stdout and stderr.
    ClosedDescriptors,
}

/// What a worker applied to itself, reported to the parent before it reads input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockdownReport {
    /// Restrictions in force, in the order they were applied.
    pub applied: Vec<Restriction>,
    /// Restrictions this implementation would apply but the system does not support (for
    /// example user namespaces disabled by the distribution). Never a required restriction: a
    /// required one that fails is an error.
    pub missing: Vec<Restriction>,
}

impl LockdownReport {
    /// Whether `restriction` is in force.
    pub fn has(&self, restriction: Restriction) -> bool {
        self.applied.contains(&restriction)
    }

    /// Records `restriction` as applied once.
    pub fn applied(&mut self, restriction: Restriction) {
        if !self.has(restriction) {
            self.applied.push(restriction);
        }
    }

    /// Records `restriction` as missing once.
    pub fn missing(&mut self, restriction: Restriction) {
        if !self.missing.contains(&restriction) {
            self.missing.push(restriction);
        }
    }
}

/// How a worker process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// It exited with this code.
    Code(i32),
    /// A signal not sent by the launcher ended it (a crash, a seccomp kill).
    Signal(i32),
    /// The launcher or the system killed it for this reason.
    Killed(KillReason),
}

/// Why a worker was killed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillReason {
    /// [`WorkerProcess::kill`] was called.
    Caller,
    /// [`Policy::wall_time`] ran out.
    WallTime,
    /// The process went over [`Policy::memory_bytes`] and the implementation can tell.
    Memory,
    /// The process went over [`Policy::cpu_seconds`].
    Cpu,
}

/// The parent side: starts workers under a policy.
#[async_trait]
pub trait Launcher: Send + Sync {
    /// A short name for logs (`"linux"`, `"macos"`, `"none"`).
    fn name(&self) -> &'static str;

    /// Whether workers started by this launcher are sandboxed at all. Only `sandbox-none`
    /// returns `false`.
    fn is_wall(&self) -> bool;

    /// Starts `command` with [`Policy::to_arg`] appended to its arguments, an empty environment,
    /// piped stdin and stdout and discarded stderr, and waits for the worker's [`announce`].
    ///
    /// Returns only once the worker has reported its lockdown and the report holds every
    /// restriction this launcher requires; otherwise the process is killed and the call fails
    /// ([`SandboxError::Unavailable`] naming the first missing restriction,
    /// [`SandboxError::Protocol`] for a malformed announcement, [`SandboxError::Closed`] when the
    /// worker exits first, [`SandboxError::Spawn`] when the program cannot start). The
    /// announcement must arrive within [`Policy::wall_time`] ([`SandboxError::WallTime`]).
    async fn launch(
        &self,
        command: &WorkerCommand,
        policy: &Policy,
    ) -> Result<Box<dyn WorkerProcess>, SandboxError>;
}

/// A running worker. Dropping it kills the process.
///
/// Every method called after [`Policy::wall_time`] has passed since launch kills the process and
/// fails with [`SandboxError::WallTime`] (or returns [`Exit::Killed`] with
/// [`KillReason::WallTime`] from [`WorkerProcess::wait`]); a method that is waiting when the time
/// runs out does the same.
#[async_trait]
pub trait WorkerProcess: Send {
    /// The lockdown the worker announced, plus what the launcher enforces from outside.
    fn report(&self) -> &LockdownReport;

    /// Writes one frame. Fails with [`SandboxError::FrameTooLarge`] above [`MAX_FRAME`] and
    /// [`SandboxError::Closed`] when the worker no longer reads.
    async fn send(&mut self, payload: &[u8]) -> Result<(), SandboxError>;

    /// Reads one frame of at most `max_len` bytes. A longer frame is never read: the worker is
    /// killed and the call fails with [`SandboxError::FrameTooLarge`]. End of output before a
    /// whole frame is [`SandboxError::Closed`].
    async fn receive(&mut self, max_len: usize) -> Result<Vec<u8>, SandboxError>;

    /// Kills the process (no-op if it already ended).
    async fn kill(&mut self);

    /// Waits for the process to end and says how.
    async fn wait(&mut self) -> Result<Exit, SandboxError>;
}

/// The worker side: a process restricting itself.
pub trait Lockdown: Send + Sync {
    /// A short name for logs.
    fn name(&self) -> &'static str;

    /// The first call of the worker's `main`, while the process has a single thread and has read
    /// nothing. Applies what must happen before threads exist (namespaces on Linux).
    fn prepare(&self, policy: &Policy) -> Result<LockdownReport, SandboxError>;

    /// Applies every remaining restriction to the whole process, all threads included, and
    /// returns the full report. After it returns the process can only read and write the file
    /// descriptors it already has, compute, and exit. A required restriction that cannot be
    /// applied fails with [`SandboxError::Lockdown`] (or [`SandboxError::Unavailable`] when the
    /// system lacks it), and the worker must then exit without reading input.
    fn lock_down(
        &self,
        policy: &Policy,
        prepared: LockdownReport,
    ) -> Result<LockdownReport, SandboxError>;
}

/// Closes every file descriptor above stderr the calling process inherited, for
/// [`Lockdown::prepare`] implementations: the parent's spawn passes on each of its descriptors
/// that lacks close-on-exec, and no OS sandbox mediates descriptors that are already open.
/// Records [`Restriction::ClosedDescriptors`] as applied on Unix and as missing elsewhere (on
/// Windows only inheritable handles pass, and closing them is the launcher's job). Must run while
/// the process has a single thread. Fails with [`SandboxError::Lockdown`] when the open
/// descriptors cannot be listed.
pub fn close_inherited_descriptors(report: &mut LockdownReport) -> Result<(), SandboxError> {
    sys::close_inherited_descriptors()
        .map_err(|_| SandboxError::Lockdown(Restriction::ClosedDescriptors))?;
    if cfg!(unix) {
        report.applied(Restriction::ClosedDescriptors);
    } else {
        report.missing(Restriction::ClosedDescriptors);
    }
    Ok(())
}

/// Why a sandbox operation failed. No variant carries data from the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    /// The system does not offer a restriction this implementation requires.
    #[error("sandbox restriction unavailable: {0:?}")]
    Unavailable(Restriction),
    /// Applying a restriction failed.
    #[error("could not apply sandbox restriction {0:?}")]
    Lockdown(Restriction),
    /// The worker program could not be started.
    #[error("worker could not be started")]
    Spawn,
    /// The policy argument is missing or malformed.
    #[error("malformed sandbox policy")]
    Policy,
    /// The worker broke the protocol (malformed announcement).
    #[error("worker broke the sandbox protocol")]
    Protocol,
    /// A frame was over the size limit.
    #[error("frame too large")]
    FrameTooLarge,
    /// The worker closed its pipe or exited.
    #[error("worker closed its pipe")]
    Closed,
    /// [`Policy::wall_time`] ran out; the worker was killed.
    #[error("worker wall time exceeded")]
    WallTime,
    /// Another I/O failure talking to the worker.
    #[error("i/o error talking to the worker")]
    Io,
}

/// Largest frame either side may send.
pub const MAX_FRAME: usize = u32::MAX as usize;

/// Largest announcement a launcher accepts.
pub const MAX_ANNOUNCEMENT: usize = 4_096;

/// The 4-byte header of a frame of `len` bytes; [`SandboxError::FrameTooLarge`] above
/// [`MAX_FRAME`].
pub fn frame_header(len: usize) -> Result<[u8; 4], SandboxError> {
    u32::try_from(len)
        .map(u32::to_le_bytes)
        .map_err(|_| SandboxError::FrameTooLarge)
}

/// The payload length a frame header announces.
pub fn frame_len(header: [u8; 4]) -> usize {
    u32::from_le_bytes(header) as usize
}

/// Writes one frame and flushes.
pub fn write_frame(out: &mut dyn Write, payload: &[u8]) -> io::Result<()> {
    let header = frame_header(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    out.write_all(&header)?;
    out.write_all(payload)?;
    out.flush()
}

/// Reads one frame of at most `max_len` bytes; a longer one fails with
/// [`SandboxError::FrameTooLarge`] before its payload is read, end of input with
/// [`SandboxError::Closed`].
pub fn read_frame(input: &mut dyn Read, max_len: usize) -> Result<Vec<u8>, SandboxError> {
    let mut header = [0u8; 4];
    input.read_exact(&mut header).map_err(io_error)?;
    let len = frame_len(header);
    if len > max_len {
        return Err(SandboxError::FrameTooLarge);
    }
    let mut payload = Vec::new();
    input
        .take(len as u64)
        .read_to_end(&mut payload)
        .map_err(io_error)?;
    if payload.len() < len {
        return Err(SandboxError::Closed);
    }
    Ok(payload)
}

fn io_error(e: io::Error) -> SandboxError {
    if e.kind() == io::ErrorKind::UnexpectedEof || e.kind() == io::ErrorKind::BrokenPipe {
        SandboxError::Closed
    } else {
        SandboxError::Io
    }
}

/// Writes the announcement that ends the worker's lockdown: one frame holding `report`.
pub fn announce(out: &mut dyn Write, report: &LockdownReport) -> io::Result<()> {
    let bytes = postcard::to_stdvec(report)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "report does not encode"))?;
    write_frame(out, &bytes)
}

/// Decodes an announcement frame read by a launcher; [`SandboxError::Protocol`] when it is not
/// one.
pub fn decode_announcement(frame: &[u8]) -> Result<LockdownReport, SandboxError> {
    if frame.len() > MAX_ANNOUNCEMENT {
        return Err(SandboxError::Protocol);
    }
    postcard::from_bytes(frame).map_err(|_| SandboxError::Protocol)
}

/// The first restriction of `required` that `report` lacks.
pub fn first_missing(report: &LockdownReport, required: &[Restriction]) -> Option<Restriction> {
    required.iter().copied().find(|r| !report.has(*r))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_round_trips_through_an_argument() {
        let policy = Policy {
            memory_bytes: 123 << 20,
            cpu_seconds: 7,
            wall_time: Duration::from_millis(1_500),
            allow_jit: true,
        };
        let args = ["worker".to_owned(), "--x".to_owned(), policy.to_arg()];
        assert_eq!(Policy::from_args(&args).unwrap(), policy);
    }

    #[test]
    fn policy_argument_must_be_present_once_and_well_formed() {
        let arg = Policy::default().to_arg();
        assert_eq!(Policy::from_args(["a"]).unwrap_err(), SandboxError::Policy);
        assert_eq!(
            Policy::from_args([arg.as_str(), arg.as_str()]).unwrap_err(),
            SandboxError::Policy
        );
        for bad in [
            "--rinse-sandbox-policy=m1,c1,w1",
            "--rinse-sandbox-policy=m1,c1,w1,j2",
            "--rinse-sandbox-policy=m1,c1,w1,j0,x",
            "--rinse-sandbox-policy=c1,m1,w1,j0",
            "--rinse-sandbox-policy=m-1,c1,w1,j0",
        ] {
            assert_eq!(
                Policy::from_args([bad]).unwrap_err(),
                SandboxError::Policy,
                "{bad}"
            );
        }
    }

    #[test]
    fn policy_arguments_of_older_names_are_not_understood() {
        assert!(
            Policy::default()
                .to_arg()
                .starts_with("--rinse-sandbox-policy=")
        );
        for old in [
            "--washer-sandbox-policy=m1,c1,w1,j0",
            "--peleda-sandbox-policy=m1,c1,w1,j0",
        ] {
            assert_eq!(
                Policy::from_args([old]).unwrap_err(),
                SandboxError::Policy,
                "{old}"
            );
        }
    }

    #[test]
    fn frames_round_trip_and_respect_the_cap() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        write_frame(&mut buf, &[7u8; 100]).unwrap();
        let mut input = buf.as_slice();
        assert_eq!(read_frame(&mut input, 5).unwrap(), b"hello");
        assert_eq!(
            read_frame(&mut input, 99).unwrap_err(),
            SandboxError::FrameTooLarge
        );
        let mut truncated = &buf[..7];
        assert_eq!(
            read_frame(&mut truncated, 100).unwrap_err(),
            SandboxError::Closed
        );
    }

    #[test]
    fn announcements_round_trip() {
        let mut report = LockdownReport::default();
        report.applied(Restriction::Seccomp);
        report.applied(Restriction::Seccomp);
        report.missing(Restriction::UserNamespace);
        let mut buf = Vec::new();
        announce(&mut buf, &report).unwrap();
        let frame = read_frame(&mut buf.as_slice(), MAX_ANNOUNCEMENT).unwrap();
        assert_eq!(decode_announcement(&frame).unwrap(), report);
        assert_eq!(
            decode_announcement(&[0xff; 3]).unwrap_err(),
            SandboxError::Protocol
        );
        assert_eq!(
            first_missing(&report, &[Restriction::Seccomp, Restriction::Landlock]),
            Some(Restriction::Landlock)
        );
    }

    struct Rng(u64);

    impl Rng {
        fn below(&mut self, n: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % n.max(1) as u64) as usize
        }
    }

    fn variants(seed: &[u8], rng: &mut Rng) -> Vec<Vec<u8>> {
        let mut out = vec![seed.to_vec(), Vec::new()];
        for _ in 0..64 {
            let mut v = seed.to_vec();
            match rng.below(3) {
                0 => v.truncate(rng.below(seed.len())),
                1 => {
                    for _ in 0..=rng.below(4) {
                        if !v.is_empty() {
                            let i = rng.below(v.len());
                            v[i] ^= 1 << rng.below(8);
                        }
                    }
                }
                _ => {
                    let i = rng.below(v.len());
                    v.splice(i..i, [0xff, 0xff, 0xff, 0xff]);
                }
            }
            out.push(v);
        }
        out
    }

    fn announcement_frame() -> Vec<u8> {
        let mut report = LockdownReport::default();
        report.applied(Restriction::Seccomp);
        report.missing(Restriction::UserNamespace);
        let mut buf = Vec::new();
        announce(&mut buf, &report).unwrap();
        buf
    }

    #[test]
    fn hostile_frames_and_announcements_never_panic() {
        let mut rng = Rng(0x5eed_0101);
        for v in variants(&announcement_frame(), &mut rng) {
            fuzz::frame(&v);
            fuzz::announcement(&v);
            fuzz::announcement(v.get(4..).unwrap_or_default());
        }
    }

    #[test]
    fn hostile_policy_arguments_never_panic() {
        let mut rng = Rng(0x5eed_0102);
        for v in variants(Policy::default().to_arg().as_bytes(), &mut rng) {
            fuzz::policy(&v);
        }
        fuzz::policy(b"--rinse-sandbox-policy=m18446744073709551616,c1,w1,j0");
        fuzz::policy(b"--rinse-sandbox-policy=m1,c1,w18446744073709551615,j1");
    }

    #[test]
    fn a_lying_frame_header_is_refused_without_its_payload() {
        let mut lying = u32::MAX.to_le_bytes().to_vec();
        lying.extend_from_slice(b"abc");
        assert_eq!(
            read_frame(&mut lying.as_slice(), MAX_FRAME).unwrap_err(),
            SandboxError::Closed
        );
        assert_eq!(
            read_frame(&mut lying.as_slice(), MAX_ANNOUNCEMENT).unwrap_err(),
            SandboxError::FrameTooLarge
        );
        assert_eq!(
            decode_announcement(&vec![0; MAX_ANNOUNCEMENT + 1]).unwrap_err(),
            SandboxError::Protocol
        );
    }
}
