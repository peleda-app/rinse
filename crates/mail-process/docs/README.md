# rinse-mail-process

An implementation of [`rinse-mail`](../../mail/docs/README.md): a thin adapter that runs every request in a fresh sandboxed worker process with [`rinse-process`](../../process/docs/README.md). This is wall 2 ([docs/WALLS.md](../../../docs/WALLS.md)) around wall 1: the worker executable ([`apps/rinse-worker`](../../../apps/rinse-worker/docs/README.md)) embeds the WebAssembly pipeline of [`mail-wasm`](../../mail-wasm/docs/README.md), so an exploit has to escape Wasmtime and then the OS sandbox, and even then it holds one message in a process that cannot open a file or a socket and is gone after that message.

What the adapter adds to `rinse-process`: the request frame (an op byte, 0 render or 1 decode part, and the postcard request), the response cap (`max_output_bytes + 1` for the postcard `Result` tag), the budget (`time_budget_ms`), the mapping of `ProcessError` to `ContentError`, the validation of every response, and the worker-side handler.

## API

- `ProcessContent::new(Arc<dyn Launcher>, ProcessConfig) -> ProcessContent`: starts nothing yet. Implements `Content`; cheap to clone; calls need a Tokio runtime with the time driver.
- `ProcessConfig` (re-exported from `rinse-process`): `{ worker: WorkerCommand, policy: Policy, warm_workers, grace }`; `ProcessConfig::new(worker)` uses the default policy (1 GiB, 10 s CPU, 60 s wall time, no JIT), one warm worker and 500 ms of grace.
- `ProcessContent::warm_up()`, `probe()`, `launcher_name()`, `is_wall()`: as in `rinse-process`, with `ContentError::Unavailable` for a sandbox that does not work here.
- `worker::BlockingContent` (render and decode a part on the calling thread) and `worker::ContentHandler<C>`: the `rinse_process::worker::Serve` handler a worker executable gives `rinse_host::run`. Its warm-up renders a built-in message (trusted bytes) before the lockdown; it answers the postcard `Result<Rendered | DecodedPart, ContentError>`; a request that does not decode makes the worker exit without answering.

## Behavior per call

1. `max_input_bytes` is checked first (`InputTooLarge`); nothing is started or sent for oversized input.
2. `rinse-process` sends the frame to a worker that has never served a request and reads the response with the cap above; after `time_budget_ms + grace` it kills the worker.
3. Errors: `Unavailable` (no worker could start or its report lacked a required restriction), `Timeout` (budget, CPU or wall time), `LimitExceeded(Memory)` (killed for memory, macOS), `LimitExceeded(Output)` (response over the cap, never read), `InputTooLarge` (a frame over 512 MiB), `Crashed` (anything else, including a malformed response).
4. The response decodes as `Result<Rendered, ContentError>` through `rinse_mail::decode_render_response` (within the render decode budget) (or `DecodedPart`); errors the worker reports pass through; a successful one is checked with `verify_rendered` / `verify_decoded_part`.

Memory: every worker process runs under `ProcessConfig::policy.memory_bytes`; the request's `ContentLimits::memory_bytes` is enforced inside the worker by Wasmtime (wall 1).

## Platform status

| Platform | Launcher | Status |
| --- | --- | --- |
| macOS | `rinse-sandbox-macos` | the full conformance suite passes on macOS 27 with real Seatbelt, native backend |
| Linux | `rinse-sandbox-linux` | the full suite passes in the Linux check image with seccomp, Landlock and rlimits, native backend, no executable memory after lockdown (see [WALLS.md](../../../docs/WALLS.md) for the run) |
| Windows | none yet | compiles against `rinse-sandbox-none` in tests only; not used by the shell |

## Tests

`tests/conformance.rs` (`harness = false`) is also the worker: `--worker=wasm` is a `rinse_host::run` worker with `WasmContent` and `ContentHandler` (the same stack as the shipped executable), `--worker=<fault>` locks down with `rinse_host::lockdown()` and then spins, aborts, exits without answering, answers garbage, answers 2 MiB, answers an error, or allocates 4 GiB.

- Every build: the fault cases (`Timeout` within 5 s for a 300 ms budget, `Crashed`, `LimitExceeded(Output)`, `LimitExceeded(Memory)` on macOS and `Crashed` or `LimitExceeded(Memory)` on Linux, a passed-through `PartNotFound`), `InputTooLarge` before any launch, `Unavailable` for a missing worker, and one real render. Unit tests: the handler refuses malformed requests and passes the content's result through.
- `cargo test --release -p rinse-mail-process` (in `mise run check`): also four concurrent renders and the full `rinse_mail::testing::run` suite with two warm workers, about 30 s.
- Linux: `mise run linux -- cargo test --release -p rinse-mail-process`.

## Dependencies

`rinse-mail`, `rinse-process`, `rinse-sandbox`, `async-trait`, `bytes`, `postcard`.
