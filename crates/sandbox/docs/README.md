# rinse-sandbox

Contract for sandboxed worker processes, wall 2 of [WALLS.md](../../../docs/WALLS.md): what a worker process may do, how the parent starts it and talks to it, and how the worker locks itself down before it reads any input. Contract crate: traits, the types in their signatures, the error, and the framing helpers both sides share. No platform type appears here.

Implementations: [`sandbox-linux`](../../sandbox-linux/docs/README.md) (namespaces, rlimits, Landlock, seccomp), [`sandbox-macos`](../../sandbox-macos/docs/README.md) (Seatbelt), [`sandbox-none`](../../sandbox-none/docs/README.md) (no sandbox, development only). Windows is planned (below). [`rinse-process`](../../process/docs/README.md) runs requests through it and [`rinse-host`](../../host/docs/README.md) is the worker side for WebAssembly components.

## Why the worker locks itself down

A worker restricts itself (`Lockdown`) instead of the parent restricting it between `fork` and `exec`. Restricting from the parent needs `pre_exec` hooks (unsafe, and only async-signal-safe code may run there) or a platform launcher binary; self-restriction is ordinary code in the worker's `main`. It is safe as long as the worker has read nothing untrusted before it is locked down, which the protocol enforces: the parent sends the request only after the worker has announced its lockdown.

## Life of a worker

1. The parent calls `Launcher::launch(&WorkerCommand, &Policy)`. The launcher starts the program with the policy appended as one argument (`Policy::to_arg`), an empty environment, `/` as the working directory, piped stdin and stdout and discarded stderr.
2. The worker calls `Lockdown::prepare` first in `main`, while it has one thread (Linux namespaces must be entered then).
3. It loads what it needs from trusted sources (the WebAssembly component is compiled here, while executable memory and threads are still allowed).
4. It calls `Lockdown::lock_down`, which restricts every thread of the process.
5. It writes the announcement (`announce`): one frame holding the postcard `LockdownReport`.
6. `launch` returns only now, once the report holds every restriction the launcher requires. Then the parent sends frames and reads frames.

Everything sent after the announcement is a frame: a 4-byte little-endian length and that many bytes.

## API

| Item | Guarantees |
| --- | --- |
| `Policy { memory_bytes, cpu_seconds, wall_time, allow_jit }` | what the worker may use; default 1 GiB, 10 s CPU after lockdown, 60 s from launch, no JIT. `to_arg` / `from_args` carry it to the worker (`from_args` fails with `Policy` when the argument is missing, repeated or malformed) |
| `WorkerCommand { program, args }` | the executable and the arguments before the policy |
| `Restriction` | `NoNewPrivileges`, `CpuLimit`, `MemoryLimit`, `FileSizeLimit` (no file can grow, no core dump), `UserNamespace`, `NetworkNamespace`, `IpcNamespace`, `MountNamespace`, `Landlock`, `Seccomp`, `NoExecutableMemory`, `Seatbelt`, `ClosedDescriptors` (every inherited descriptor above stderr closed before loading) |
| `LockdownReport { applied, missing }` | what is in force, and what the implementation would apply but the system lacks (never a required restriction: a required one that fails is an error) |
| `Launcher::launch` | starts and returns a worker that has announced a report with every required restriction; otherwise kills it and fails: `Spawn` (cannot start), `Closed` (exited first), `Protocol` (malformed announcement), `Unavailable(r)` (report lacks `r`), `WallTime` (no announcement within `wall_time`) |
| `Launcher::name`, `is_wall` | for logs; `is_wall` is `false` only for `sandbox-none` |
| `WorkerProcess::report` | the announced report plus what the launcher enforces from outside |
| `WorkerProcess::send` | writes one frame; `FrameTooLarge` above `MAX_FRAME` (4 GiB − 1), `Closed` when the worker stopped reading |
| `WorkerProcess::receive(max_len)` | one frame of at most `max_len` bytes; a longer one is never read: the worker is killed and the call fails with `FrameTooLarge`; end of output is `Closed` |
| `WorkerProcess::kill`, `wait` | kill (no-op once ended); wait for the end: `Exit::Code`, `Exit::Signal` (a crash or a seccomp kill), `Exit::Killed(KillReason::{Caller, WallTime, Memory, Cpu})` |
| wall time | any call after `wall_time` since launch, or waiting when it runs out, kills the worker and fails with `WallTime` (`wait` returns `Killed(WallTime)`); dropping a `WorkerProcess` kills it |
| `Lockdown::prepare`, `lock_down` | see "Life of a worker"; after `lock_down` the process can only use the descriptors it already has, compute and exit. A required restriction that fails is `Lockdown(r)` or `Unavailable(r)`, and the worker must exit without reading input |
| `close_inherited_descriptors(&mut report)` | for `Lockdown::prepare`: closes every descriptor above stderr (`close_range` on Linux, else each entry of `/proc/self/fd` or `/dev/fd`) and records `ClosedDescriptors` (`missing` on Windows); the parent's spawn passes on every descriptor without close-on-exec, and no OS sandbox mediates descriptors already open. Must run while the process has one thread |
| `announce`, `decode_announcement`, `write_frame`, `read_frame`, `frame_header`, `frame_len`, `first_missing` | the shared wire format; `read_frame` refuses an oversized frame before reading its payload, and grows its buffer only with bytes that arrive, so a lying header costs nothing |
| `fuzz::{frame, announcement, policy}` (hidden) | entry points of the fuzz targets in `../../fuzz`; never panic on any input, fed hostile variants by the unit tests |

Errors (`SandboxError`): `Unavailable(Restriction)`, `Lockdown(Restriction)`, `Spawn`, `Policy`, `Protocol`, `FrameTooLarge`, `Closed`, `WallTime`, `Io`. No variant carries data from the worker.

## What an implementation must do

- A launcher passes the policy argument, clears the environment, discards stderr, waits for and decodes the announcement within the wall time, requires its restriction set, enforces the wall time on every call, kills on drop, and maps how the process ended to `Exit` (SIGXCPU is `Killed(Cpu)`).
- A lockdown calls `close_inherited_descriptors` first in `prepare`, applies every restriction it reports, to all threads, and fails rather than report something it could not apply.
- Run the conformance suite.

## Conformance suite

Feature `testing`. The implementation's test binary (`harness = false`) is also the probe: when started with `testing::PROBE_ARG` its `main` calls `testing::probe_main(&lockdown)`, otherwise it runs the suite with a `WorkerCommand` that starts itself with that argument:

```rust
fn main() -> std::process::ExitCode {
    if testing::is_probe() {
        return testing::probe_main(&MyLockdown);
    }
    let probe = WorkerCommand { program: std::env::current_exe().unwrap(), args: vec![PROBE_ARG.into()] };
    tokio::runtime::Runtime::new().unwrap().block_on(testing::run(Arc::new(MyLauncher), probe));
    std::process::ExitCode::SUCCESS
}
```

- `testing::run_mechanics(launcher, probe)`, for every implementation: echo round trip and exit code, empty environment, a 100 kB frame, a frame over the cap refused, the wall time ending a spinning worker within 2 s plus slack (`WallTime`, then `Killed(WallTime)`), `kill` (`Killed(Caller)`), a pipe the parent opens without close-on-exec is no longer usable by the worker (the write fails and nothing arrives; Unix), and `Spawn`, `Closed` and `Protocol` for a missing program, a worker that exits before announcing and a garbage announcement.
- `testing::run(launcher, probe)`, for walls: the mechanics, a non-empty report, and after lockdown the probe cannot read `/etc/passwd`, list `/` or the home directory, create a file in the temporary directory (and none appears), connect to a TCP listener the suite opens on loopback (and the listener sees no connection), bind a UDP socket, connect to a Unix socket at a path or (Linux) an abstract one the suite listens on (and neither sees a connection), or start a process (`/bin/sh` and itself); after `fcntl(F_SETOWN)`, `F_SETSIG(SIGTERM)` (Linux) and `O_ASYNC` toward a `sleep` process the suite started, that process is still alive (on Linux the probe must also be denied); allocating 1 GiB under a 256 MiB policy, as private memory or as a shared anonymous mapping, fails or kills it; spinning under a 1 s CPU limit kills it within 20 s. An operation counts as denied when it fails in the probe or the probe dies trying (a seccomp kill). The suite prints each outcome.

`testing::outcome(launcher, probe, policy, request)` runs one probe operation for implementation-specific tests (for example one layer at a time).

## Windows (planned, not implemented)

The worker will run in a Less Privileged AppContainer (LPAC) with no capabilities: the launcher creates an AppContainer profile (`CreateAppContainerProfile`), starts the worker with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` and `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` (LPAC), passes only the two pipe handles (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), puts it in a Job object (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_JOB_TIME`, `ActiveProcessLimit = 1`, kill on job close), with child process creation blocked (`PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`) and mitigation policies (no win32k system calls, no remote or low-label images, ACG and CIG where the backend allows: Pulley if dynamic code is forbidden). The worker's own `Lockdown` would then only lower its token further and report. That is a launcher-side sandbox (the restrictions are set at process creation), so the Windows launcher, not the worker, will report most restrictions. It needs FFI to `windows-sys` in one allowlisted file. Until then an application on Windows can only run wall 1 ([`rinse-wasm`](../../wasm/docs/README.md)) in its own process, and must say so.

## Unsafe code

`src/sys.rs` is listed in `unsafe-allowlist.txt`: closing descriptors by number (`close_range`, `close`) has no safe binding, and neither do the probe operations that act on a raw descriptor number or map shared memory (`write`, `fcntl`, `mmap`; compiled only with `testing`). Each call is one small block with a `// SAFETY:` comment.

## Dependencies

`async-trait`, `postcard`, `serde`, `thiserror`; on Unix `libc` and `rustix` (`process`, `pipe`); with `testing`: `tokio` (`net`).
