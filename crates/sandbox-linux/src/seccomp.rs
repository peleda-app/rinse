use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// System calls an already running worker may make: I/O on descriptors it holds, memory
/// management, futexes, clocks and sleeping, signal handling for the runtime's trap handler,
/// random bytes, and exit.
const ALLOWED: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_readv,
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_lseek,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_brk,
    libc::SYS_membarrier,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_gettid,
    libc::SYS_getpid,
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_restart_syscall,
    libc::SYS_getrandom,
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// `fcntl` commands a worker may use: descriptor and status flags only. Owners, signals, leases
/// and directory notifications (`F_SETOWN`, `F_SETOWN_EX`, `F_SETSIG`, `F_SETLEASE`, `F_NOTIFY`)
/// would let it signal other processes.
const FCNTL_COMMANDS: &[libc::c_int] =
    &[libc::F_GETFD, libc::F_SETFD, libc::F_GETFL, libc::F_SETFL];

#[cfg(target_arch = "x86_64")]
const ARCH: Option<TargetArch> = Some(TargetArch::x86_64);
#[cfg(target_arch = "aarch64")]
const ARCH: Option<TargetArch> = Some(TargetArch::aarch64);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const ARCH: Option<TargetArch> = None;

fn no_exec() -> Result<SeccompCondition, seccompiler::BackendError> {
    SeccompCondition::new(
        2,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
        0,
    )
}

fn private_only() -> Result<SeccompCondition, seccompiler::BackendError> {
    SeccompCondition::new(
        3,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(libc::MAP_SHARED as u64),
        0,
    )
}

/// The filter: [`ALLOWED`] unconditionally; `fcntl` with [`FCNTL_COMMANDS`] only; `mmap` only
/// for private mappings (shared memory escapes `RLIMIT_DATA`), and `mmap` and `mprotect` without
/// `PROT_EXEC` unless `allow_jit`; `tgkill` only to `pid` (so `abort` can raise its signal);
/// every other call, and every call from another architecture, kills the process.
pub(crate) fn program(allow_jit: bool, pid: i32) -> Option<BpfProgram> {
    let arch = ARCH?;
    let build = || -> Result<BpfProgram, seccompiler::BackendError> {
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
            ALLOWED.iter().map(|&nr| (nr, Vec::new())).collect();
        let mut mmap = vec![private_only()?];
        if !allow_jit {
            mmap.push(no_exec()?);
            rules.insert(
                libc::SYS_mprotect,
                vec![SeccompRule::new(vec![no_exec()?])?],
            );
        } else {
            rules.insert(libc::SYS_mprotect, Vec::new());
        }
        rules.insert(libc::SYS_mmap, vec![SeccompRule::new(mmap)?]);
        let fcntl = FCNTL_COMMANDS
            .iter()
            .map(|&command| {
                SeccompRule::new(vec![SeccompCondition::new(
                    1,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    command as u64,
                )?])
            })
            .collect::<Result<Vec<_>, _>>()?;
        rules.insert(libc::SYS_fcntl, fcntl);
        rules.insert(
            libc::SYS_tgkill,
            vec![SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                pid as u32 as u64,
            )?])?],
        );
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::KillProcess,
            SeccompAction::Allow,
            arch,
        )?;
        filter.try_into()
    };
    build().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_compile_for_this_architecture() {
        let strict = program(false, 1).expect("strict filter");
        let jit = program(true, 1).expect("jit filter");
        assert!(!strict.is_empty());
        assert!(strict.len() > jit.len());
    }

    #[test]
    fn nothing_that_reaches_outside_is_allowed() {
        for nr in [
            libc::SYS_openat,
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_execve,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_kill,
            libc::SYS_ptrace,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_memfd_create,
            libc::SYS_process_vm_writev,
            libc::SYS_io_uring_setup,
            libc::SYS_bpf,
            libc::SYS_prctl,
            libc::SYS_seccomp,
            libc::SYS_fcntl,
            libc::SYS_mmap,
        ] {
            assert!(!ALLOWED.contains(&nr), "{nr} is allowed");
        }
        const F_SETSIG: libc::c_int = 10;
        const F_SETOWN_EX: libc::c_int = 15;
        for command in [
            libc::F_SETOWN,
            F_SETOWN_EX,
            F_SETSIG,
            libc::F_SETLEASE,
            libc::F_NOTIFY,
            libc::F_DUPFD,
        ] {
            assert!(
                !FCNTL_COMMANDS.contains(&command),
                "fcntl {command} is allowed"
            );
        }
    }
}
