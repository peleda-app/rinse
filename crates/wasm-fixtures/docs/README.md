# rinse-wasm-fixtures

Test components for the sandbox layer's own tests. `build.rs` compiles [`rinse-wasm-test-worker`](../../wasm-test-worker/docs/README.md) for `wasm32-wasip2` with [`rinse-build`](../../build/docs/README.md) (a nested release build in `<target>/rinse-wasm-test-worker`) and embeds it.

## API

- `TEST_WORKER: &[u8]`: the component bytes.

Used as a dev-dependency by `rinse-wasm` and `rinse-host`; never a dependency of anything shipped. The first build needs the toolchain of `rust-toolchain.toml` with the `wasm32-wasip2` target.
