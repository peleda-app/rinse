//! Components for the sandbox layer's own tests. Never a dependency of anything shipped.

/// `rinse-wasm-test-worker` as a `wasm32-wasip2` component: echoes its input, or misbehaves
/// when the input is `spin`, `hog`, `huge`, `panic`, `exit3`, `probe` or `count`.
pub const TEST_WORKER: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/rinse-wasm-test-worker.wasm"));
