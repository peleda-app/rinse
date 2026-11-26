//! The worker sandbox on macOS. The worker applies a deny-default Seatbelt profile to itself with
//! `sandbox_init` after it has loaded everything it needs ([`SeatbeltLockdown`]); the parent
//! starts it, checks its report and kills it when it goes over its memory or wall time
//! ([`MacosLauncher`]). See `docs/README.md` for the choice of `sandbox_init`, its deprecation and
//! how it composes with the App Sandbox and the hardened runtime.
#![cfg(target_os = "macos")]

use async_trait::async_trait;
use rinse_sandbox::{
    Launcher, Lockdown, LockdownReport, Policy, Restriction, SandboxError, WorkerCommand,
    WorkerProcess, close_inherited_descriptors, first_missing,
};
use rustix::process::{Resource, Rlimit, setrlimit};

mod ffi;
mod process;

/// Restrictions [`MacosLauncher`] requires in a worker's report.
pub const REQUIRED: &[Restriction] = &[
    Restriction::ClosedDescriptors,
    Restriction::Seatbelt,
    Restriction::CpuLimit,
    Restriction::FileSizeLimit,
];

/// sysctl names the runtime reads (page size, CPU count and features); everything else is
/// denied.
const SYSCTLS: &[&str] = &[
    "hw.pagesize",
    "hw.pagesize_compat",
    "hw.ncpu",
    "hw.activecpu",
    "hw.logicalcpu",
    "hw.logicalcpu_max",
    "hw.physicalcpu",
    "hw.physicalcpu_max",
    "hw.cachelinesize",
    "hw.l1dcachesize",
    "hw.l2cachesize",
    "kern.osrelease",
    "kern.osversion",
    "kern.osproductversion",
];

/// The SBPL profile a worker applies: deny everything, then allow reading a few sysctls,
/// signals to itself (for `abort`) and, only with [`Policy::allow_jit`], dynamic code
/// generation. No file, network, process, IPC, Mach lookup or IOKit operation is allowed;
/// reading and writing already open descriptors is not mediated by Seatbelt.
pub fn profile(policy: &Policy) -> String {
    let names: Vec<String> = SYSCTLS.iter().map(|n| format!("\"{n}\"")).collect();
    let mut profile = format!(
        "(version 1)\n(deny default)\n(allow sysctl-read (sysctl-name {}) (sysctl-name-prefix \"hw.optional.\") (sysctl-name-prefix \"hw.perflevel\"))\n(allow signal (target self))\n",
        names.join(" ")
    );
    if policy.allow_jit {
        profile.push_str("(allow dynamic-code-generation)\n");
    }
    profile
}

/// The worker side: rlimits and the Seatbelt profile of [`profile`].
///
/// [`Lockdown::prepare`] closes every inherited descriptor above stderr. [`Lockdown::lock_down`] sets the CPU limit to the CPU
/// time used so far plus [`Policy::cpu_seconds`] (`SIGXCPU`, then `SIGKILL` a second later),
/// the file-size and core-dump limits to zero, and applies the profile; any failure is an error.
/// Memory is enforced by [`MacosLauncher`] from outside, because macOS does not enforce
/// `RLIMIT_DATA` or `RLIMIT_AS`. Executable memory is governed by the code signature
/// (hardened runtime and its JIT entitlements), not by this lockdown, so
/// [`Restriction::NoExecutableMemory`] is never reported.
#[derive(Debug, Clone, Copy, Default)]
pub struct SeatbeltLockdown;

impl Lockdown for SeatbeltLockdown {
    fn name(&self) -> &'static str {
        "seatbelt"
    }

    fn prepare(&self, _policy: &Policy) -> Result<LockdownReport, SandboxError> {
        let mut report = LockdownReport::default();
        close_inherited_descriptors(&mut report)?;
        Ok(report)
    }

    fn lock_down(
        &self,
        policy: &Policy,
        mut report: LockdownReport,
    ) -> Result<LockdownReport, SandboxError> {
        let used = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let used = u64::try_from(used.tv_sec).unwrap_or(0) + 1;
        let soft = used.saturating_add(policy.cpu_seconds);
        setrlimit(
            Resource::Cpu,
            Rlimit {
                current: Some(soft),
                maximum: Some(soft.saturating_add(1)),
            },
        )
        .map_err(|_| SandboxError::Lockdown(Restriction::CpuLimit))?;
        report.applied(Restriction::CpuLimit);
        for resource in [Resource::Fsize, Resource::Core] {
            setrlimit(
                resource,
                Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )
            .map_err(|_| SandboxError::Lockdown(Restriction::FileSizeLimit))?;
        }
        report.applied(Restriction::FileSizeLimit);
        ffi::apply_profile(&profile(policy))
            .map_err(|_| SandboxError::Lockdown(Restriction::Seatbelt))?;
        report.applied(Restriction::Seatbelt);
        Ok(report)
    }
}

/// The parent side on macOS.
///
/// Starts the worker, requires [`REQUIRED`] in its report, and while the parent waits on the
/// worker (in [`WorkerProcess::send`], [`WorkerProcess::receive`] or [`WorkerProcess::wait`])
/// checks its physical footprint every 10 ms, killing it above [`Policy::memory_bytes`]
/// ([`rinse_sandbox::KillReason::Memory`]); reports [`Restriction::MemoryLimit`] for that, and
/// fails the launch with [`SandboxError::Unavailable`] for it when the worker's footprint cannot
/// be read (the worker is killed). A
/// worker that nobody waits on has no input to work on, so it is not watched. The check is
/// polling: a worker can overshoot the limit by what it allocates in 10 ms.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosLauncher;

#[async_trait]
impl Launcher for MacosLauncher {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn is_wall(&self) -> bool {
        true
    }

    async fn launch(
        &self,
        command: &WorkerCommand,
        policy: &Policy,
    ) -> Result<Box<dyn WorkerProcess>, SandboxError> {
        let mut worker = process::Worker::start(command, policy, Some(ffi::footprint)).await?;
        if let Some(missing) =
            first_missing(rinse_sandbox::WorkerProcess::report(&worker), REQUIRED)
        {
            return Err(SandboxError::Unavailable(missing));
        }
        if !worker
            .pid()
            .is_some_and(|pid| ffi::footprint(pid).is_some())
        {
            return Err(SandboxError::Unavailable(Restriction::MemoryLimit));
        }
        worker.report_mut().applied(Restriction::MemoryLimit);
        Ok(Box::new(worker))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_denies_by_default_and_allows_jit_only_when_asked() {
        let strict = profile(&Policy::default());
        assert!(strict.starts_with("(version 1)\n(deny default)\n"));
        assert!(!strict.contains("dynamic-code-generation"));
        assert!(!strict.contains("file-read"));
        assert!(!strict.contains("network"));
        let jit = profile(&Policy {
            allow_jit: true,
            ..Policy::default()
        });
        assert!(jit.contains("(allow dynamic-code-generation)"));
    }

    #[test]
    fn footprint_of_this_process_is_visible() {
        assert!(ffi::footprint(std::process::id()).is_some_and(|b| b > 0));
        assert_eq!(ffi::footprint(u32::MAX), None);
    }
}
