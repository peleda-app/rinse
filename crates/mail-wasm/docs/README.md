# rinse-mail-wasm

An implementation of [`rinse-mail`](../../mail/docs/README.md): a thin adapter that runs the content worker ([`rinse-mail-worker`](../../mail-worker/docs/README.md), a `wasi:cli/command` WebAssembly component) with [`rinse-wasm`](../../wasm/docs/README.md). This is wall 1 ([docs/WALLS.md](../../../docs/WALLS.md)): a parser bug exploited by a message lands inside a WebAssembly instance with no files, no network, no clock and a memory and time cap, and whatever it returns is checked before use (wall 3, [WALLS.md](../../../docs/WALLS.md)).

What the adapter adds to `rinse-wasm`: the worker protocol (an op byte and a postcard request in; a status byte and a postcard response or `ContentError` out), the mapping of `ContentLimits` to `rinse_wasm::Limits`, the mapping of `WasmError` to `ContentError`, and the validation of every response. Everything about the instance, the WASI context and the limits is `rinse-wasm`'s and documented there.

## API

- `WasmContent::embedded() -> Result<WasmContent, ContentError>` (feature `embedded`, on by default): compiles the worker built into this crate with the default `Backend`.
- `WasmContent::from_component(bytes, Backend)`: compiles any worker component speaking the protocol (for example a reproducibly built one). `Unavailable` when the bytes do not compile or do not link against WASI 0.2, or Wasmtime cannot run here.
- `WasmContent::from_runner(WasmRunner)`: wraps an already compiled `rinse_wasm::WasmRunner` (what `apps/rinse-worker` gets from `rinse_host::run`).
- `Backend::{Native, Pulley}` (re-exported from `rinse-wasm`), `WasmContent::backend()`, `EMBEDDED_WORKER` (the component bytes).
- `WasmContent::render_blocking(RenderRequest)`, `decode_part_blocking(PartRequest)`: the same calls on the calling thread, without a Tokio runtime, for the sandboxed worker executable (they start no thread after the first call; see `rinse-wasm`).
- `WasmContent` implements `Content` (calls on Tokio's blocking pool), is cheap to clone and share as `Arc<dyn Content>`. Compiling takes about a second natively for the 3 MB worker, so build one value and keep it.

No wasmtime or `rinse-wasm` error type crosses the `Content` API; all errors are `ContentError`.

## Behavior per call

- `max_input_bytes` is checked before anything is sent to the worker (`InputTooLarge`).
- `rinse-wasm` runs the request with `memory_bytes`, `time_budget_ms` and `max_output_bytes + 1` (the status byte) as its limits: `MemoryExceeded` becomes `LimitExceeded(Memory)`, `Timeout` `Timeout`, `OutputTooLarge` `LimitExceeded(Output)` (before anything is decoded), `Crashed` and `Unavailable` themselves.
- A missing or unknown status byte or a response that does not decode is `Crashed`. Render responses decode through `rinse_mail::decode_render_response`, within the render decode budget. Errors the worker reports pass through (a closed enum).
- **Validation** of every response with `rinse_mail::verify_rendered` / `verify_decoded_part` (see the [contract](../../mail/docs/README.md#validation-by-the-receiver)): a body that fails `rinse_doc_model::validate` is `LimitExceeded(Document)`, an oversized decoded part `LimitExceeded(Output)`, any other violation `Crashed`.

## How the worker artifact is built

`build.rs` runs when the `embedded` feature is on. Through [`rinse-build`](../../build/docs/README.md) it builds `rinse-mail-worker --bin rinse-mail-worker --target wasm32-wasip2 --release` from this workspace, once plain and once with `test-hooks`, each in its own target directory (`<target>/rinse-mail-worker-component` and `<target>/rinse-mail-worker-test-component`, so a concurrent build of one can never hand out the other), so it never waits on the outer build's lock and is incremental. Both artifacts are copied into `OUT_DIR`; the plain one is embedded, the test one is included only by this crate's tests. It reruns when the worker, engine, contract, document model or text crates, this workspace's manifest, `Cargo.lock` or `rust-toolchain.toml` change. When another workspace (`../app`) depends on this crate by path, the nested build still uses this workspace's manifest and lock file.

`RINSE_MAIL_WORKER_WASM=/path/to/worker.wasm` embeds a prebuilt worker instead (for reproducible release builds); the test artifact is still built, first, and a prebuilt file with the same bytes as it fails the build. `../app/scripts/build-worker-host.sh` passes the variable on only with `RINSE_MAIL_WORKER_WASM_SHA256` naming the file's SHA-256, and unsets it otherwise. The toolchain rules (rustup fallback when `$RUSTC` lacks `wasm32-wasip2`) are `rinse-build`'s.

## Platform notes

- **iOS**: build with the `pulley` feature (it turns on `rinse-wasm/pulley`), which makes `Backend::Pulley` the default.
- **macOS and Linux**: the shell runs this crate inside a sandboxed worker process ([`rinse-mail-process`](../../mail-process/docs/README.md) and [`apps/rinse-worker`](../../../apps/rinse-worker/docs/README.md)), compiling the component before the lockdown. **Windows** and debug fallbacks run it in the calling process.

## Features

- `embedded` (default): build and embed the worker; enables `WasmContent::embedded`.
- `pulley`: `rinse-wasm/pulley`.

## Tests

`cargo test -p rinse-mail-wasm` runs the `rinse-mail` conformance suite on the native backend, and targeted tests with the test-hooks worker on both backends: a worker that loops forever times out, one that allocates without end hits the memory limit, an oversized output is refused before decoding, garbage output and a panic become `Crashed`, the next call after each failure works, bytes that are not a worker give `Unavailable`, the embedded worker differs from the test one and answers none of the `RINSE-TEST-*` inputs like it, `from_runner` works, and calls run concurrently. The conformance suite on Pulley is ignored in unoptimized builds and runs with `cargo test --release -p rinse-mail-wasm` (in `mise run check`).

## Dependencies

`rinse-mail`, `rinse-wasm`, `async-trait`, `postcard`, `tokio` (`rt`); build: `rinse-build`.
