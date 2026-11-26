# rinse-host

The child side of a sandboxed WebAssembly worker, for a worker executable's `main`: it picks this platform's `Lockdown` (`rinse-sandbox-macos`, `rinse-sandbox-linux`, otherwise `rinse-sandbox-none`), compiles the component with [`rinse-wasm`](../../wasm/docs/README.md), warms up, locks down, announces, and serves exactly one request through [`rinse-process`](../../process/docs/README.md)'s `worker_main`. A worker executable is then a few lines: its component bytes and a handler (`apps/rinse-worker` is one).

## API

- `run(component: &[u8], make: impl FnOnce(WasmRunner) -> Option<S>) -> ExitCode` where `S: rinse_process::worker::Serve`: the whole worker. `make` gets the compiled runner and returns the handler; its `warm_up` runs before the lockdown, its `serve` answers the one request. A component that does not compile or a `make` that returns `None` exits with 4 before the lockdown; the other exit codes are `worker_main`'s.
- `lockdown() -> impl Lockdown`: this platform's lockdown.
- `backend_from_args(args) -> Backend` and `PULLEY_ARG` (`--backend=pulley`).

## Arguments

- the policy argument appended by the launcher (required);
- `--backend=pulley`: run the component on Wasmtime's Pulley interpreter instead of native code, for a worker signed without permission to create executable memory (macOS hardened runtime without `allow-unsigned-executable-memory`). Native by default.
- with the `probe` feature only (tests): `--rinse-sandbox-probe` makes the executable the probe of the `rinse-sandbox` conformance suite under the same lockdown.

## Why native code without JIT after the lockdown

The component is compiled in `load`, before `lock_down`, and the handler's warm-up runs there too. After the lockdown nothing new is compiled, so the policy keeps `allow_jit = false` and Linux's seccomp filter forbids `PROT_EXEC` while the native backend runs at full speed; the serve test passing under that filter shows it. On macOS executable memory is decided by the code signature (see `rinse-sandbox-macos`), which is when `--backend=pulley` matters.

## Features

- `probe`: turns on `rinse-sandbox/testing` and the probe argument. Tests only; never in a shipped worker. With `debug_assertions` off (any release build) the crate refuses to compile with it.

## Tests

- `cargo test -p rinse-host`: `tests/serve.rs` starts the test binary itself as a `run` worker through this platform's launcher and `ProcessRunner`, with the test component of `rinse-wasm-fixtures`, on both backends: echo, the WASI context is empty (`probe`), a fresh instance (`count`), and the component's own timeout, memory limit, output limit and panic all reported by the handler under the lockdown; a worker whose component does not compile is `Unavailable`.
- `cargo test -p rinse-host --features probe --test probe` (in `mise run check`): the `rinse-sandbox` conformance suite with a `run` executable as the probe (`run` on macOS and Linux, `run_mechanics` elsewhere).

## Dependencies

`rinse-process`, `rinse-sandbox`, `rinse-wasm`, and per platform `rinse-sandbox-macos`, `rinse-sandbox-linux` or `rinse-sandbox-none`.
