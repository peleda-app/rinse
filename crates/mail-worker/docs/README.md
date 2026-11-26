# rinse-mail-worker

The content worker: [`rinse-mail-engine`](../../mail-engine/docs/README.md) packaged as a WebAssembly component. Built for `wasm32-wasip2`, its binary is a `wasi:cli/command` component that reads one request from stdin, writes one response to stdout and exits. [`rinse-mail-wasm`](../../mail-wasm/docs/README.md) runs it under Wasmtime, one fresh instance per call. This crate holds no host code and no wasmtime dependency.

## Interface

The component's world is the standard `wasi:cli/command` of WASI 0.2: it exports `wasi:cli/run.run` and imports only what Rust's `std` for `wasm32-wasip2` links (stdio, environment, exit, clocks, random, and the filesystem and socket interfaces `std` declares). The host satisfies those imports with an empty context: stdin and stdout are in-memory pipes, stderr is discarded, there are no files, environment variables, arguments or network, and both clocks read zero. The worker uses only stdin, stdout and, through `HashMap`, the random seed.

The protocol on the pipes:

| Direction | Bytes |
| --- | --- |
| request (stdin) | `0` + postcard `RenderRequest`, or `1` + postcard `PartRequest` |
| success (stdout) | `0` + postcard `Rendered` or `DecodedPart` |
| failure (stdout) | `1` + postcard `ContentError` |

A request that does not decode answers `ContentError::Crashed` (only a mismatched host sends one). A panic ends the instance (a trap or a non-zero exit), which the host reports as `Crashed`. The exit status is 0 after a response was written and non-zero when stdin or stdout failed.

Why a command and not a custom WIT world exported with `wit-bindgen`: exporting functions from a Rust component needs `#[unsafe(export_name)]` attributes and `unsafe` glue generated into this crate, and `unsafe_code` is forbidden in the workspace (including the sandbox layer, whose `rinse-wasm` runs commands). A command needs neither, keeps the worker's surface to two byte streams, and the same binary built natively speaks the same protocol over a pipe, which the OS-process sandboxes (XPC, AppContainer, Linux, Android `isolatedProcess`) can reuse.

## API (library)

The library half exists so the protocol can be tested natively and shared by the binary:

- `handle(&[u8]) -> Vec<u8>`: runs one request and returns the response bytes. Never panics on any input beyond what the engine guarantees.
- `OP_RENDER`, `OP_DECODE_PART`, `STATUS_OK`, `STATUS_ERR`: the protocol bytes above.

## Limits

The worker enforces the engine's own bounds (input size before parsing, document, text, image, link and output limits). Time, memory and output size are enforced by the host around it; the worker has no clock to measure anything with.

## Feature `test-hooks`

Adds misbehavior selected by the first bytes of a rendered message (`RINSE-TEST-SPIN` loops forever, `RINSE-TEST-HOG` allocates without end, `RINSE-TEST-HUGE` returns 4 MiB, `RINSE-TEST-GARBAGE` returns bytes that do not decode, `RINSE-TEST-PANIC` panics). Only `rinse-mail-wasm`'s tests use an artifact built with it; the shipped worker never has it.

## Building

```sh
cargo build -p rinse-mail-worker --target wasm32-wasip2 --release
# -> <target-dir>/wasm32-wasip2/release/rinse-mail-worker.wasm
```

`rinse-mail-wasm`'s build script does this automatically (see its README). On the host target the crate builds as a normal library and binary, so `cargo test --workspace` and `cargo clippy --workspace` cover it.

## Tests

`cargo test -p rinse-mail-worker` checks the protocol natively: a render round trip, garbage requests, and engine errors passing through. `tests/untrusted_inputs.rs` feeds the hostile corpus and truncated, bit-flipped and length-lying variants to the request decoder, the MIME, HTML and image pipeline, the host's decoding and verification of an answer, `rinse_doc_model::decode` and the facts extraction (variants of seeds spliced into every place facts are read from by `rinse_mail::testing::facts_message`; every answer must pass `verify_rendered`); the same entry points are the fuzz targets in `../../fuzz`. The component itself is tested by `rinse-mail-wasm` (conformance suite and limit tests).

## Dependencies

`rinse-mail`, `rinse-mail-engine`, `postcard` (MIT OR Apache-2.0). No `wit-bindgen`.
