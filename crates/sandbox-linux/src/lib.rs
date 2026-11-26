//! The worker sandbox on Linux, applied by the worker to itself ([`LinuxLockdown`]) and checked
//! by the parent ([`LinuxLauncher`]):
//!
//! 1. [`Lockdown::prepare`], first in `main`: closes every inherited descriptor above stderr,
//!    then new user, network, IPC and mount namespaces where unprivileged user namespaces are
//!    available (reported missing where they are not).
//! 2. [`Lockdown::lock_down`], once the worker has loaded what it needs: rlimits (CPU time,
//!    `RLIMIT_DATA` for memory, zero file size and core size), `no_new_privs`, a Landlock ruleset
//!    that handles every access right and allows none, on every thread, and a seccomp filter on
//!    every thread that kills the process on any system call outside a small allowlist.
//!
//! The only unsafe code is the `unshare` call in `namespaces.rs` (rustix marks it unsafe).
#![cfg(target_os = "linux")]

use async_trait::async_trait;
use landlock::{
    ABI, Access, AccessFs, AccessNet, RestrictSelfAttr, Ruleset, RulesetAttr, RulesetStatus, Scope,
};
use rinse_sandbox::{
    Launcher, Lockdown, LockdownReport, Policy, Restriction, SandboxError, WorkerCommand,
    WorkerProcess, close_inherited_descriptors, first_missing,
};
use rustix::process::{Resource, Rlimit, setrlimit};

mod namespaces;
mod process;
mod seccomp;

/// Restrictions [`LinuxLauncher::new`] requires in a worker's report. Namespaces and Landlock
/// depend on the kernel and the distribution and are reported, not required; the seccomp filter
/// alone already denies files, sockets, processes, signals to other processes and shared memory.
pub const REQUIRED: &[Restriction] = &[
    Restriction::ClosedDescriptors,
    Restriction::CpuLimit,
    Restriction::MemoryLimit,
    Restriction::FileSizeLimit,
    Restriction::NoNewPrivileges,
    Restriction::Seccomp,
];

/// The worker side on Linux. Every layer is on by default; the `with_*` switches exist to test
/// one layer at a time and are never turned off in a release.
#[derive(Debug, Clone, Copy)]
pub struct LinuxLockdown {
    namespaces: bool,
    landlock: bool,
    seccomp: bool,
}

impl Default for LinuxLockdown {
    fn default() -> Self {
        Self {
            namespaces: true,
            landlock: true,
            seccomp: true,
        }
    }
}

impl LinuxLockdown {
    /// Turns the namespaces layer on or off.
    pub fn with_namespaces(mut self, on: bool) -> Self {
        self.namespaces = on;
        self
    }

    /// Turns the Landlock layer on or off.
    pub fn with_landlock(mut self, on: bool) -> Self {
        self.landlock = on;
        self
    }

    /// Turns the seccomp layer on or off.
    pub fn with_seccomp(mut self, on: bool) -> Self {
        self.seccomp = on;
        self
    }
}

fn limit(resource: Resource, value: u64, maximum: u64) -> rustix::io::Result<()> {
    setrlimit(
        resource,
        Rlimit {
            current: Some(value),
            maximum: Some(maximum),
        },
    )
}

fn landlock(report: &mut LockdownReport) -> Result<(), SandboxError> {
    let abi = ABI::V6;
    let failed = |_| SandboxError::Lockdown(Restriction::Landlock);
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(failed)?
        .handle_access(AccessNet::from_all(abi))
        .map_err(failed)?
        .scope(Scope::from_all(abi))
        .map_err(failed)?
        .create()
        .map_err(failed)?
        .all_threads(true)
        .map_err(failed)?
        .restrict_self()
        .map_err(failed)?;
    if status.ruleset == RulesetStatus::NotEnforced || !status.all_threads {
        report.missing(Restriction::Landlock);
    } else {
        report.applied(Restriction::Landlock);
    }
    Ok(())
}

impl Lockdown for LinuxLockdown {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn prepare(&self, _policy: &Policy) -> Result<LockdownReport, SandboxError> {
        let mut report = LockdownReport::default();
        close_inherited_descriptors(&mut report)?;
        let all = [
            Restriction::UserNamespace,
            Restriction::NetworkNamespace,
            Restriction::IpcNamespace,
            Restriction::MountNamespace,
        ];
        if self.namespaces {
            let unshared = namespaces::unshare_namespaces().is_ok();
            for r in all {
                if unshared {
                    report.applied(r);
                } else {
                    report.missing(r);
                }
            }
        }
        Ok(report)
    }

    fn lock_down(
        &self,
        policy: &Policy,
        mut report: LockdownReport,
    ) -> Result<LockdownReport, SandboxError> {
        let used = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let soft = (u64::try_from(used.tv_sec).unwrap_or(0) + 1).saturating_add(policy.cpu_seconds);
        limit(Resource::Cpu, soft, soft.saturating_add(1))
            .map_err(|_| SandboxError::Lockdown(Restriction::CpuLimit))?;
        report.applied(Restriction::CpuLimit);
        limit(Resource::Data, policy.memory_bytes, policy.memory_bytes)
            .map_err(|_| SandboxError::Lockdown(Restriction::MemoryLimit))?;
        report.applied(Restriction::MemoryLimit);
        for resource in [Resource::Fsize, Resource::Core] {
            limit(resource, 0, 0)
                .map_err(|_| SandboxError::Lockdown(Restriction::FileSizeLimit))?;
        }
        report.applied(Restriction::FileSizeLimit);
        rustix::thread::set_no_new_privs(true)
            .map_err(|_| SandboxError::Lockdown(Restriction::NoNewPrivileges))?;
        report.applied(Restriction::NoNewPrivileges);
        if self.landlock {
            landlock(&mut report)?;
        }
        if self.seccomp {
            let pid = rustix::process::getpid().as_raw_nonzero().get();
            let program = seccomp::program(policy.allow_jit, pid)
                .ok_or(SandboxError::Unavailable(Restriction::Seccomp))?;
            seccompiler::apply_filter_all_threads(&program)
                .map_err(|_| SandboxError::Lockdown(Restriction::Seccomp))?;
            report.applied(Restriction::Seccomp);
            if !policy.allow_jit {
                report.applied(Restriction::NoExecutableMemory);
            }
        }
        Ok(report)
    }
}

/// The parent side on Linux: starts the worker and requires a set of restrictions in its report
/// ([`REQUIRED`] by default).
#[derive(Debug, Clone)]
pub struct LinuxLauncher {
    required: Vec<Restriction>,
}

impl Default for LinuxLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxLauncher {
    /// A launcher requiring [`REQUIRED`].
    pub fn new() -> Self {
        Self {
            required: REQUIRED.to_vec(),
        }
    }

    /// Replaces the required restrictions, for example to also insist on
    /// [`Restriction::Landlock`] and the namespaces on systems known to have them.
    pub fn requiring(mut self, required: &[Restriction]) -> Self {
        self.required = required.to_vec();
        self
    }
}

#[async_trait]
impl Launcher for LinuxLauncher {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn is_wall(&self) -> bool {
        true
    }

    async fn launch(
        &self,
        command: &WorkerCommand,
        policy: &Policy,
    ) -> Result<Box<dyn WorkerProcess>, SandboxError> {
        let worker = process::Worker::start(command, policy, None).await?;
        if let Some(missing) = first_missing(worker.report(), &self.required) {
            return Err(SandboxError::Unavailable(missing));
        }
        Ok(Box::new(worker))
    }
}
