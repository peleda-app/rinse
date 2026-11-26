# rinse-wasm

Runs an untrusted WebAssembly component under Wasmtime: bytes in, bytes out, a fresh store and instance per call, inside memory, time and output limits. This is wall 1 of [WALLS.md](../../../docs/WALLS.md): a parser bug exploited by hostile input lands inside a WebAssembly instance with no files, no network, no clock and a memory and time cap, and whatever it returns is the caller's to check. The crate knows nothing about what the bytes mean.

A library, not a contract: the input and output protocol is fixed (below), and the one implementation is Wasmtime. Callers that need a contract (for example `rinse-mail`) wrap it in an adapter.

## The component

A `wasi:cli/command` component (what `cargo build --target wasm32-wasip2` makes of a Rust binary). The input is its stdin; the output is everything it writes to stdout; only a clean exit (status 0, or returning from `main`) counts as an answer. This is the bytes-in/bytes-out function of the wall. A custom WIT world exporting `run: func(input: list<u8>) -> list<u8>` without any WASI import is a later hardening step (see [DECISIONS.md](../../../docs/DECISIONS.md)).

## API

- `WasmRunner::new(bytes, Backend) -> Result<WasmRunner, WasmError>`: compiles the component (about a second natively for a 3 MB component, so build one value and keep it). `Unavailable` when the bytes do not compile or do not link against WASI 0.2, or Wasmtime cannot run on the platform.
- `WasmRunner::run_blocking(input: Vec<u8>, &Limits) -> Result<Bytes, WasmError>`: one call on the calling thread. Outside a Tokio runtime it enters a current-thread runtime owned by the value (created on the first call), so WASI does not start its own multi-threaded one: after the first call a call starts no thread and opens no descriptor, which a worker under seccomp relies on.
- `WasmRunner::run(input, Limits)`: the same on Tokio's blocking pool.
- `WasmRunner::backend()`. Cheap to clone; clones share the compiled component.
- `Backend::{Native, Pulley}`: `Native` compiles to machine code with Cranelift; `Pulley` compiles to Pulley bytecode run by Wasmtime's interpreter, with no executable memory. `Backend::default()` is `Pulley` with the `pulley` feature, `Native` without.
- `Limits { memory_bytes, time_budget, max_output_bytes }`; default 256 MiB, 2 s, 64 MiB.
- `WasmError::{Unavailable, Timeout, MemoryExceeded, OutputTooLarge, Crashed}`.

No wasmtime type crosses the API.

## Behavior and limits

Per call:

- A **fresh `Store` and instance** from a cached `InstancePre`: nothing survives from one call to the next.
- **WASI context with nothing:** stdin an in-memory pipe holding the input, stdout an in-memory pipe, stderr discarded; no preopened directories, no environment, no arguments, TCP, UDP and name lookup off, wall and monotonic clocks frozen at zero. Random sources are the WASI defaults.
- **Memory:** a `ResourceLimiter` caps the sum of all linear memories at `memory_bytes`; tables are capped at 100,000 elements. A refused growth makes the component's allocator abort, and the call fails with `MemoryExceeded`.
- **Time:** epoch interruption. A ticker thread (one per compiled component, stopped when the last clone drops) advances the engine epoch every 5 ms; each call's deadline is `ceil(time_budget_ms / 5) + 1` ticks. Running past it traps: `Timeout`. On `Pulley` the same deadline applies, so a slower backend gets less work done in the same budget. Epochs rather than fuel: no per-instruction cost on the native backend, and a wall-clock budget is what callers state.
- **Output:** the stdout pipe keeps at most `max_output_bytes + 1` bytes; more than `max_output_bytes` is `OutputTooLarge`, whatever the exit status.
- Order of checks: `MemoryExceeded`, `Timeout`, `OutputTooLarge`, then any other trap or a non-zero exit is `Crashed`.

## Platform notes

- **iOS** allows no JIT and no helper processes: build with the `pulley` feature (or pass `Backend::Pulley`). Pulley is roughly 25 times slower than native code in an optimized build (and about 100 times slower again in an unoptimized one). Compiling still uses Cranelift at run time; shipping a precompiled component and a runtime-only Wasmtime is a later step.
- **macOS, Windows, Linux, Android** use `Native`. Wall 2 (an OS process sandbox around this runtime) is [`rinse-process`](../../process/docs/README.md) with [`rinse-host`](../../host/docs/README.md) as the worker, which compiles the component before the lockdown.
- Wasmtime reserves virtual address space per linear memory (several GiB on 64-bit hosts); concurrent calls each reserve their own.

## Features

- `pulley`: make `Backend::Pulley` the default. The interpreter (`wasmtime/pulley`) is always compiled in, so both backends are available and tested in every build.

## Tests

`cargo test -p rinse-wasm`, with the test component of [`rinse-wasm-fixtures`](../../wasm-fixtures/docs/README.md), on both backends: echo, a component that loops forever times out within 5 s of a 100 ms budget, one that allocates without end hits the memory limit, more output than allowed is refused (exactly the limit passes), a panic and a non-zero exit are `Crashed`, the next call after each failure works, bytes that are not a component are `Unavailable`, the WASI context sees no environment, arguments, files, sockets or time, a static counter is 1 in every call (fresh instances), and calls run concurrently. `cargo test --release -p rinse-wasm` (in `mise run check`) runs the same optimized.

## Dependencies and licenses

| Crate | License |
| --- | --- |
| `wasmtime` 51 (`runtime`, `std`, `cranelift`, `component-model`, `parallel-compilation`, `pulley`) | Apache-2.0 WITH LLVM-exception |
| `wasmtime-wasi` 51 (`p2`) | Apache-2.0 WITH LLVM-exception |
| `tokio` 1 (`rt`, `time`), `bytes` 1, `thiserror` 2 | MIT / MIT OR Apache-2.0 |
