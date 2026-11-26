# rinse-mail-direct

An implementation of [`rinse-mail`](../../mail/docs/README.md) that runs [`rinse-mail-engine`](../../mail-engine/docs/README.md) in the calling process.

**Not a security wall.** A parser bug exploited by a message runs with every right of the host process: its keys, its network, its files. Use it for tests, development, and the server node, which runs inside its own container. Devices use the sandboxed WebAssembly worker of [WALLS.md](../../../docs/WALLS.md).

## API

- `DirectContent::new()` (or `Default`): no configuration. Implements `Content` and is cheap to clone or share as `Arc<dyn Content>`.

## Behavior and limits

- Rejects input over `max_input_bytes` with `InputTooLarge` before moving it to a worker thread.
- Runs each call on `tokio::task::spawn_blocking` inside `catch_unwind`: a panic becomes `Crashed`.
- Wraps the call in `tokio::time::timeout(time_budget_ms)`: an overrun returns `Timeout`. A render runs through `rinse_mail_engine::render_until` and is told to stop on timeout; it gives its blocking thread back within one small step of work. A `decode_part` (one linear transfer decode of at most `max_input_bytes`) runs to its end.
- Memory: nothing caps the process. What bounds a call is the engine: at most 400,000 parser nodes and depth 4,096 per message, 4 MiB per HTML part, image allocations of at most a quarter of `memory_bytes` and 400 million decoded pixels per message, plus the input itself (at most `max_input_bytes`, held a few times over during MIME decoding). Expect a few hundred MiB for a hostile 32 MiB message; give the server node's container a memory limit that allows that per concurrent render.
- Checks every output like the core does, with `verify_rendered` / `verify_decoded_part` (body failures: `LimitExceeded(Document)`, other contract violations: `Crashed`).
- Needs a Tokio runtime with the blocking pool and timers.

## Platforms

Everything the engine and Tokio support. On iOS and in any process holding secrets, use the sandboxed worker instead.

## Tests

`cargo test -p rinse-mail-direct` runs the `rinse-mail` conformance suite, plus panic, timeout, stop-signal and concurrency tests.
