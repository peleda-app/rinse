# rinse-sandbox-linux

The worker sandbox on Linux, an implementation of [`rinse-sandbox`](../../sandbox/docs/README.md). The worker applies it to itself (`LinuxLockdown`); the parent starts the worker and checks its report (`LinuxLauncher`). On other platforms the crate compiles to nothing.

## What the worker applies

`Lockdown::prepare`, first in `main` (the kernel refuses a new user namespace in a process with more than one thread):

- `rinse_sandbox::close_inherited_descriptors` (`close_range(3, ~0, 0)`, or every entry of `/proc/self/fd` above 2 on kernels without it): the spawn passes on every descriptor of the parent that lacks close-on-exec, and neither Landlock nor seccomp mediates descriptors that are already open. Reported as `ClosedDescriptors`.
- `unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWNS)`: no privileges outside the new user namespace, a network namespace with only an unconfigured loopback, no System V IPC or POSIX message queues of the host, and a private mount table. Where unprivileged user namespaces are disabled (some distributions, Docker's default seccomp profile) all four are reported in `missing`, not as an error. No uid map is written; the process appears as the overflow uid. No PID namespace (it would need a fork).

`Lockdown::lock_down`, after the worker loaded what it needs:

| Step | Effect | Reported as |
| --- | --- | --- |
| `RLIMIT_CPU` = CPU used so far + `cpu_seconds` (hard limit one second later) | `SIGXCPU`, then `SIGKILL` | `CpuLimit` |
| `RLIMIT_DATA` = `memory_bytes` | private writable memory (heap, `mmap`, the WebAssembly linear memories once made accessible) is capped; Wasmtime's `PROT_NONE` reservations do not count, so the runtime still works. Allocation then fails, and the Rust runtime aborts. Shared mappings escape `RLIMIT_DATA`, so the seccomp filter refuses `MAP_SHARED`; without the filter the cap does not hold | `MemoryLimit` |
| `RLIMIT_FSIZE` = 0, `RLIMIT_CORE` = 0 | no file can grow, no core dump holds the input | `FileSizeLimit` |
| `PR_SET_NO_NEW_PRIVS` | no setuid or file capabilities ever; also what unprivileged Landlock and seccomp need | `NoNewPrivileges` |
| Landlock, ABI v6 rights, best effort: every file system right, TCP bind and connect, abstract Unix socket and signal scoping handled, no rule added; applied to all threads (`LANDLOCK_RESTRICT_SELF_TSYNC`, ABI v8, Linux 7.0) | no path can be opened, no TCP connection made or accepted | `Landlock` when enforced on every thread; `missing` on kernels without Landlock or without the all-threads flag |
| seccomp filter on all threads (`SECCOMP_FILTER_FLAG_TSYNC`), kill-process by default | see below | `Seccomp`, and `NoExecutableMemory` without `allow_jit` |

### The seccomp allowlist

Everything else kills the process, including calls from a foreign architecture.

- I/O on descriptors the process holds: `read`, `readv`, `write`, `writev`, `close`, `fstat`, `lseek`, and `fcntl` with `F_GETFD`, `F_SETFD`, `F_GETFL` or `F_SETFL` only. `F_SETOWN`, `F_SETOWN_EX`, `F_SETSIG`, `F_SETLEASE` and `F_NOTIFY` would let the worker have the kernel signal any process of the same user (with no PID namespace, `F_SETOWN` plus `F_SETSIG` and `O_ASYNC` on a pipe sends any signal), which only Landlock's signal scoping would stop otherwise.
- Memory: `mmap` of private mappings only (no `MAP_SHARED`, which `RLIMIT_DATA` does not count), and `mmap` and `mprotect` without `PROT_EXEC` (any protection with `allow_jit`), `munmap`, `mremap`, `madvise`, `brk`, `membarrier` (Wasmtime's instruction cache coherence on aarch64).
- Threads already running: `futex`, `sched_yield`, `sched_getaffinity`, `gettid`, `getpid`.
- Time: `clock_gettime`, `clock_getres`, `clock_nanosleep`, `nanosleep` (the epoch ticker thread sleeps).
- Signals for Wasmtime's trap handler: `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `restart_syscall`; `tgkill` only to the process's own pid (so `abort` can raise `SIGABRT`).
- `getrandom`, `exit`, `exit_group`.

Not allowed, among others: `openat`, `socket`, `connect`, `execve`, `clone`, `clone3`, `fork`, `kill`, `ptrace`, `unshare`, `setns`, `mount`, `memfd_create`, `process_vm_writev`, `io_uring_setup`, `bpf`, `prctl`, `seccomp`, and the `fcntl` commands above (a unit test checks these stay out).

The worker therefore needs nothing after lockdown that it did not set up before: the WebAssembly component is compiled, a warm-up request served (see `rinse-process`'s `worker_main`), and Wasmtime's signal handlers, memory images and the WASI context runtime (a current-thread Tokio runtime owned by `rinse-wasm`, so WASI does not start its multi-threaded one) exist before the filter goes on. Because compilation happens before the lockdown, the native backend runs without `allow_jit`: the `rinse-host` serve test (and the mail conformance through the process adapter) under this filter proves the locked-down worker never needs executable memory or a shared mapping again (Wasmtime maps its memory images `MAP_PRIVATE`).

## Parent side

`LinuxLauncher::new()` requires `REQUIRED` = `ClosedDescriptors`, `CpuLimit`, `MemoryLimit`, `FileSizeLimit`, `NoNewPrivileges`, `Seccomp`. Namespaces and Landlock depend on the kernel and the distribution and are reported, not required: the seccomp filter alone already denies files, sockets, processes, signals to other processes and shared memory. `requiring(&[...])` replaces the set (for example adding `Landlock` on systems known to have Linux 7.0). Memory is enforced inside the worker (`RLIMIT_DATA`), so `Exit::Killed(Memory)` is never reported on Linux; an allocation failure shows as an abort (`Exit::Signal(6)`).

`LinuxLockdown::with_namespaces`, `with_landlock`, `with_seccomp` switch one layer off for tests of the others; everything is on by default and nothing turns a layer off in a release.

## Unsafe code

`src/namespaces.rs` is listed in `unsafe-allowlist.txt`: rustix exposes `unshare` only as `unshare_unsafe` because `CLONE_FILES` can break descriptor ownership between threads. The call passes only namespace flags, before any thread exists. Everything else uses safe APIs (`rustix` for rlimits and `no_new_privs`, `landlock`, `seccompiler`).

## Tests

Run in the Linux check image:

```sh
mise run linux -- cargo test -p rinse-sandbox-linux
RINSE_DOCKER_FLAGS="--security-opt seccomp=unconfined" mise run linux -- cargo test -p rinse-sandbox-linux
```

`tests/conformance.rs` (also its own probe) prints the lockdown report, checks Landlock alone (seccomp off: reading `/etc/passwd`, listing `/` and creating a file are denied, not killed), checks a loopback connect without seccomp (denied by the network namespace or Landlock), then runs the full `rinse_sandbox::testing::run` suite (including the inherited descriptor, Unix socket at a path and abstract, `F_SETOWN` signal and shared memory probes). Unit tests compile the filter for the host architecture and check the forbidden lists.

Verified (Docker on OrbStack, Linux 7.2, aarch64): with Docker's default seccomp profile, user namespaces are refused, so the report is `ClosedDescriptors, CpuLimit, MemoryLimit, FileSizeLimit, NoNewPrivileges, Landlock, Seccomp, NoExecutableMemory` with the four namespaces missing; with `--security-opt seccomp=unconfined` all twelve restrictions apply. The suite passes both ways; under the full lockdown every forbidden operation ends in a seccomp kill (`SIGSYS`), `F_SETOWN` toward another process and a 1 GiB shared mapping included, a write to an inherited descriptor fails (`EBADF`), the 1 GiB private allocation fails under `RLIMIT_DATA`, and the CPU limit kills a spinning probe after about 2 s. Not verified: x86_64, kernels older than 7.0 (Landlock without the all-threads flag is then reported missing), distributions with AppArmor restrictions on user namespaces (Ubuntu 24.04+: reported missing).

## Dependencies

`rinse-sandbox`, `async-trait`, `landlock` 0.4 (MIT OR Apache-2.0), `seccompiler` 0.5 (Apache-2.0 OR BSD-3-Clause), `rustix` 1.1 (`process`, `thread`, `time`), `libc` (system call numbers), `tokio` (`process`, `io-util`, `time`).
