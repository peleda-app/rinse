# rinse-sandbox-macos

The worker sandbox on macOS, an implementation of [`rinse-sandbox`](../../sandbox/docs/README.md): the worker applies a deny-default Seatbelt profile to itself (`SeatbeltLockdown`), the parent checks its report and watches its memory (`MacosLauncher`). On other platforms the crate compiles to nothing.

## What the worker applies

`Lockdown::prepare` does nothing. `Lockdown::lock_down`, after the worker compiled its WebAssembly component:

| Step | Effect | Reported as |
| --- | --- | --- |
| `RLIMIT_CPU` = CPU used so far + `cpu_seconds` (hard limit one second later) | `SIGXCPU`, then `SIGKILL` | `CpuLimit` |
| `RLIMIT_FSIZE` = 0, `RLIMIT_CORE` = 0 | no file can grow, no core dump | `FileSizeLimit` |
| `sandbox_init` with the profile of `profile(&policy)` | see below | `Seatbelt` |

The profile (`profile()` returns it, unit-tested):

```scheme
(version 1)
(deny default)
(allow sysctl-read (sysctl-name "hw.pagesize" "hw.ncpu" ... "kern.osrelease" ...)
                   (sysctl-name-prefix "hw.optional.") (sysctl-name-prefix "hw.perflevel"))
(allow signal (target self))
; only with Policy::allow_jit:
(allow dynamic-code-generation)
```

Nothing else: no file read or write (not even the worker's own executable: it is already loaded), no network, no `fork` or `exec`, no Mach service lookup, no IOKit, no IPC. Reading and writing descriptors the process already has (its pipes) is not mediated by Seatbelt, nor are memory operations. The sysctls are what Rust's standard library and Wasmtime read for the page size, CPU count and CPU features; without `hw.pagesize` even `sysconf(_SC_PAGESIZE)` fails. Signals to itself let `abort` work.

## Parent side

`MacosLauncher` requires `REQUIRED` = `ClosedDescriptors`, `Seatbelt`, `CpuLimit`, `FileSizeLimit`. `SeatbeltLockdown::prepare` closes every inherited descriptor above stderr (`rinse_sandbox::close_inherited_descriptors`, every entry of `/dev/fd`), because Seatbelt does not mediate descriptors that are already open. macOS does not enforce `RLIMIT_DATA` or `RLIMIT_AS` (setting them fails or has no effect, checked on this Mac), so memory is enforced from outside: while the parent waits on the worker (in `send`, `receive` or `wait`) the launcher reads the worker's physical footprint (`proc_pid_rusage`, `ri_phys_footprint`, the number Activity Monitor shows) every 10 ms and kills it above `memory_bytes`, reporting `Exit::Killed(Memory)`; the report gains `MemoryLimit`. `launch` reads the footprint once right after the announcement and, if it cannot (for example if a future App Sandbox or hardened runtime setup denied it), kills the worker and fails with `Unavailable(MemoryLimit)`, so the memory cap fails closed. Footprint counts shared anonymous memory too (checked by the suite). A worker nobody waits on has received no input, so it is not watched. The check polls, so a worker can overshoot by what it allocates in 10 ms. The pid is only used while the child is unreaped, so it cannot refer to another process.

## Why `sandbox_init`, and its status

Two ways to put a process under a Seatbelt profile without private APIs:

- `sandbox_init(profile, 0, &error)` from the process itself, with SBPL source as the profile. Deprecated in the headers since macOS 10.8 (the replacement Apple names is the App Sandbox, which cannot express a per-process deny-everything profile), still present and working on macOS 27, and the mechanism Chromium, Firefox and Bazel build on (Chromium through the related private `sandbox_compile_string`/`sandbox_apply`).
- `/usr/bin/sandbox-exec -p <profile> <worker>`: a wrapper that applies the profile before `exec`. Its man page is marked deprecated too, and it uses the same mechanism.

This crate uses `sandbox_init` because the profile then goes on **after** the worker has compiled the WebAssembly component and served a warm-up request. With `sandbox-exec` the profile would apply before `exec`, so it would have to allow everything loading needs (reading the executable and the dyld shared cache, thread creation, executable memory for Cranelift), and the deny-everything profile above would be impossible. Both are deprecated; if `sandbox_init` stopped working the lockdown fails and `launch` refuses the worker, so the caller notices instead of running unsandboxed.

## App Sandbox and hardened runtime

- **Executable memory is governed by the code signature, not by Seatbelt.** Without the hardened runtime (development builds) a process may create executable memory whatever the profile says: a deny-default profile still allowed `mprotect` to `PROT_EXEC` and `MAP_JIT` in a test on this Mac. So `NoExecutableMemory` is never reported here. Under the hardened runtime, Wasmtime's native backend needs `com.apple.security.cs.allow-unsigned-executable-memory` on the worker binary (Wasmtime uses `mmap` + `mprotect`, not `MAP_JIT`; `allow-jit` alone would only cover `MAP_JIT`); the worker compiles before the lockdown, so the entitlement is needed only for that. A worker signed without it must run with `--backend=pulley` (no executable memory at all, about 25 times slower).
- **App Sandbox.** When the host application runs in the App Sandbox, a helper it starts must be signed with exactly `com.apple.security.app-sandbox` and `com.apple.security.inherit` (it then inherits the app's sandbox) plus the executable-memory entitlement above if it uses the native backend. Applying `sandbox_init` inside an already sandboxed process should narrow the sandbox further (Seatbelt policies stack); **this is not verified**, because signing and the App Sandbox are not set up for development builds. If it fails, `lock_down` returns `Lockdown(Seatbelt)` and the launcher refuses the worker.
- An XPC service without entitlements is the other way to get a rightless helper. A sidecar started with `posix_spawn` and self-applied Seatbelt gives the same rights (none) without an Xcode target; moving to an XPC service later only changes the launcher.

## Unsafe code

`src/ffi.rs` is listed in `unsafe-allowlist.txt`: `sandbox_init` and `sandbox_free_error` have no binding in any crate, and `proc_pid_rusage` is only in `libc` as a raw function. Each call is one small block with a `// SAFETY:` comment.

## Tests

`cargo test -p rinse-sandbox-macos` runs, on this Mac, for real: unit tests (the profile, the footprint of the test process) and `tests/conformance.rs`, the full `rinse_sandbox::testing::run` suite with the test binary as its own probe. Verified on macOS 27 (Apple silicon): reading `/etc/passwd`, listing `/` and the home directory, creating a file, connecting to a loopback listener, binding a UDP socket and starting `/bin/sh` or itself are all denied by the kernel (`EPERM`), and so is connecting to a Unix socket at a path; a write to an inherited descriptor fails (it was closed); 1 GiB under a 256 MiB policy, private or shared anonymous memory, is killed by the footprint watchdog (`Killed(Memory)`); a spinning probe is killed by `SIGXCPU` about 2 s after a 1 s CPU limit (`Killed(Cpu)`). Creating an unconnected socket is not denied by Seatbelt; connecting, binding and sending are. `fcntl(F_SETOWN)` toward another process plus `O_ASYNC` on the worker's pipe is allowed: macOS cannot choose the signal (no `F_SETSIG`), so the target only gets `SIGIO`, which it ignores unless it installed a handler; the suite checks that the target survives. Mach service lookups are denied by the profile's text only; no probe exercises them.

## Dependencies

`rinse-sandbox`, `async-trait`, `libc` (`proc_pid_rusage`, `rusage_info_v2`), `rustix` 1.1 (`process`, `time`: rlimits and the CPU clock), `tokio` (`process`, `io-util`, `time`).
