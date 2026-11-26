# rinse

Everything untrusted, washed before anyone looks at it. A program hands rinse hostile bytes; rinse parses them in Rust, compiled to WebAssembly (wall 1), inside a fresh, locked-down OS process (wall 2), and the receiver validates everything that comes back against a closed schema (wall 3). Only things rebuilt from scratch leave; the original bytes never do.

rinse is generic: the sandbox layer knows nothing about what the bytes are, and each format sits in its own layer on top. Today that is mail (message bytes to Peleda's safe document model); a files layer (images, PDF, office documents, archives) and a remote runner on a dirty server are planned ([docs/PLAN.md](docs/PLAN.md)).

Open source under MIT OR Apache-2.0. First user: the Peleda application ([`app`](../app)), later the Peleda node and server and `bento`.

## Layers and crates

Package prefix `rinse-`; crate directories drop it (`crates/sandbox-linux` is `rinse-sandbox-linux`).

### Sandbox (walls 1 and 2, generic)

| Crate | Kind | What it does |
| --- | --- | --- |
| [`rinse-sandbox`](crates/sandbox/docs/README.md) | contract | what a worker process may do, how it is launched, how it locks itself down; the framing; the conformance suite (`testing`) |
| [`rinse-sandbox-linux`](crates/sandbox-linux/docs/README.md) | implementation | namespaces, rlimits, `no_new_privs`, Landlock, a kill-by-default seccomp filter |
| [`rinse-sandbox-macos`](crates/sandbox-macos/docs/README.md) | implementation | a deny-default Seatbelt profile, rlimits, a memory watchdog |
| [`rinse-sandbox-none`](crates/sandbox-none/docs/README.md) | implementation | no restriction, for development and tests only |
| [`rinse-wasm`](crates/wasm/docs/README.md) | library | wall 1: a component in a fresh Wasmtime store per call, memory, time and output limits, empty frozen WASI context, Native or Pulley |
| [`rinse-process`](crates/process/docs/README.md) | library | wall 2: one locked-down worker process per request through a `Launcher`, framed request and response, size cap, wall-clock kill, warm pool used once; the worker-side `worker_main` |
| [`rinse-host`](crates/host/docs/README.md) | library | the child side: lock down, compile the component, warm up, announce, serve one request |
| [`rinse-build`](crates/build/docs/README.md) | build helper | compiles a workspace binary to a `wasm32-wasip2` component from a build script |
| [`rinse-wasm-fixtures`](crates/wasm-fixtures/docs/README.md), [`rinse-wasm-test-worker`](crates/wasm-test-worker/docs/README.md) | tests only | a misbehaving test component |

### Files (planned)

Nothing yet. Image re-encoding moves here from the mail layer; PDF, office documents and archives with bomb limits follow.

### Mail (wall 3 for messages)

| Crate | Kind | What it does |
| --- | --- | --- |
| [`rinse-mail`](crates/mail/docs/README.md) | contract | `Content`: render a message, decode a part; limits, errors, receiver-side validation; `MessageFacts` and `verify_facts`; the conformance suite and the hostile corpus (`testing`) |
| [`rinse-doc-model`](crates/doc-model/docs/README.md) | library | the safe document model: closed schema, limits, validation, flat encoding |
| [`rinse-text`](crates/text/docs/README.md) | library | normalization of untrusted display text |
| [`rinse-mail-engine`](crates/mail-engine/docs/README.md) | library | the pipeline itself: MIME, HTML to the model, image re-encoding, link and attachment checks |
| [`rinse-mail-worker`](crates/mail-worker/docs/README.md) | component | the engine as a `wasm32-wasip2` command |
| [`rinse-mail-direct`](crates/mail-direct/docs/README.md) | implementation | in-process, not a wall (tests, development, the server node) |
| [`rinse-mail-wasm`](crates/mail-wasm/docs/README.md) | implementation | the embedded worker over `rinse-wasm` (wall 1) |
| [`rinse-mail-process`](crates/mail-process/docs/README.md) | implementation | a fresh sandboxed process per message over `rinse-process` (wall 2) |
| [`rinse-worker`](apps/rinse-worker/docs/README.md) | binary | the worker executable (`rinse-worker-host`): `rinse-host` + the embedded mail worker + the mail handler; shipped by the app as the `rinse-worker` sidecar |

Windows (Less Privileged AppContainer and a Job object) is planned in [`rinse-sandbox`](crates/sandbox/docs/README.md#windows-planned-not-implemented); Android (`isolatedProcess`) later.

## Using the sandbox layer

```rust
// parent
let runner = ProcessRunner::new(Arc::new(rinse_sandbox_macos::MacosLauncher), ProcessConfig::new(worker_command));
let response = runner.call(request_bytes, Duration::from_secs(2), max_response).await?;

// worker executable
fn main() -> ExitCode {
    rinse_host::run(MY_COMPONENT, |runner| Some(MyHandler(runner)))
}
```

See [docs/WALLS.md](docs/WALLS.md) for the threat model of the three walls and what is verified where, [docs/DECISIONS.md](docs/DECISIONS.md) for decisions taken, [docs/REMOTE.md](docs/REMOTE.md) for the planned dirty server.

## Checks

`mise run check` (unsafe allowlist, fmt, clippy, tests, both probe suites, the optimized WebAssembly and process tests, `dojo check`). Linux: `mise run linux -- cargo test -p rinse-sandbox-linux` (Docker image in `tests/linux`); the Linux CI checks: `mise run check-linux`. Windows compile check: `mise run check-windows`. Fuzzing: `mise run fuzz -- all 60`. What CI runs and how fuzzing works: [docs/CI.md](docs/CI.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option. Contributions are accepted under the same terms with a DCO sign-off.
