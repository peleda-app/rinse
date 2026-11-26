# rinse-process

Runs every request in a fresh locked-down worker process started through a [`rinse-sandbox`](../../sandbox/docs/README.md) `Launcher`. This is wall 2 of [WALLS.md](../../../docs/WALLS.md): an exploit that escapes whatever the worker runs (usually wall 1, [`rinse-wasm`](../../wasm/docs/README.md), inside [`rinse-host`](../../host/docs/README.md)) holds one request in a process that cannot open a file or a socket and is gone after that request. The runner moves opaque frames; the caller decodes and validates the response as untrusted.

A library, not a contract: it composes the `rinse-sandbox` contract, whose implementations are swappable through the `Launcher` it is given.

## API

- `ProcessRunner::new(Arc<dyn Launcher>, ProcessConfig)`: starts nothing yet. Cheap to clone; calls need a Tokio runtime with the time driver.
- `ProcessConfig { worker: WorkerCommand, policy: Policy, warm_workers, grace }`; `ProcessConfig::new(worker)` uses the default policy (1 GiB, 10 s CPU, 60 s wall time, no JIT), one warm worker and 500 ms of grace.
- `ProcessRunner::call(request: Vec<u8>, budget: Duration, max_response: usize) -> Result<Vec<u8>, ProcessError>`: one request to a fresh worker.
- `ProcessRunner::warm_up()`: starts the warm workers in the background.
- `ProcessRunner::probe()`: starts one worker, waits for its lockdown report and kills it; `Unavailable` when the sandbox does not work here.
- `launcher_name()`, `is_wall()`, `config()`: for the composition root's log line.
- `ProcessError::{Unavailable, RequestTooLarge, Timeout, MemoryExceeded, ResponseTooLarge, Crashed}`.
- `MAX_REQUEST_BYTES` (512 MiB): the largest request frame a worker reads.
- `worker::worker_main(&dyn Lockdown, load) -> ExitCode` and the `worker::Serve` trait (`warm_up`, `serve`): the worker side.

No platform type crosses the API.

## Behavior per call

1. A request over `MAX_REQUEST_BYTES` is `RequestTooLarge`; nothing is started.
2. A worker that has never served a request: a warm one if it still has `budget + grace + 2 s` of wall time left, otherwise a new one (with a wall time stretched to fit the budget). A failed launch (including a report that lacks a required restriction) is `Unavailable`. Every worker serves exactly one request, so one request cannot poison the next.
3. The request is one frame (a 4-byte little-endian length and the bytes).
4. The response frame is read with a cap of `max_response`; a longer one is never read (`ResponseTooLarge`).
5. After `budget + grace` without a response the worker is killed (`Timeout`). Whatever runs inside normally answers first with its own deadline; the kill is for a worker that no longer cooperates.
6. A worker that ends without a response: `MemoryExceeded` when the launcher killed it for memory (macOS), `Timeout` when it was killed for CPU or wall time, `Crashed` otherwise (a signal, a seccomp kill, a non-zero exit).
7. The finished worker is reaped in the background (killed if it does not exit within 2 s).

After taking a warm worker, another is started in the background so `warm_workers` stay ready. Every worker runs under `ProcessConfig::policy.memory_bytes`, the outer bound an escape from the inner wall cannot exceed.

## The worker side

`worker_main(lockdown, load)` is everything a worker executable's `main` does:

1. reads the `Policy` from its arguments (exit 2);
2. `lockdown.prepare` (exit 3);
3. `load(&policy)` builds the server from trusted bytes (compiling a component, for example), then `Serve::warm_up` runs it once on trusted input, so everything set up lazily on a first call exists before system calls are restricted (exit 4);
4. `lockdown.lock_down` (exit 5; nothing has been read);
5. announces the report, reads one request frame, answers it with `Serve::serve` on the calling thread, writes the response frame and exits 0 (exit 6 when the parent is gone, 7 when `serve` says the request is malformed).

## Platform status

| Platform | Launcher | Status |
| --- | --- | --- |
| macOS | `rinse-sandbox-macos` | the runner test passes on macOS 27 with real Seatbelt |
| Linux | `rinse-sandbox-linux` | the runner test passes in the Linux check image with seccomp, Landlock and rlimits (see [WALLS.md](../../../docs/WALLS.md) for what was run when) |
| Windows | none yet | compiles against `rinse-sandbox-none` in tests only |

## Tests

`tests/runner.rs` (`harness = false`) is also the worker: `--worker=serve` runs `worker_main` under this platform's real lockdown with an echo server, `--worker=cold` fails its warm-up, `--worker=unloadable` fails `load`, `--worker=<fault>` locks down and then spins, aborts, exits without answering, answers 2 MiB, or allocates 4 GiB.

Checked: echo round trips (also empty), four calls get four different worker pids (one request per worker), six concurrent 100 kB calls, a stale warm worker is replaced, `Timeout` within 5 s for a 300 ms budget, `Crashed` for abort, silent exit and a malformed request, `ResponseTooLarge` for a response one byte over the cap and for 2 MiB, `MemoryExceeded` on macOS and `Crashed` or `MemoryExceeded` on Linux for 4 GiB under 256 MiB, `Unavailable` from `probe` and `call` for a worker that fails before announcing and for a missing executable, `RequestTooLarge` before any launch.

Linux: `mise run linux -- cargo test -p rinse-process`.

## Dependencies

`rinse-sandbox`, `thiserror`, `tokio` (`rt`, `time`).
