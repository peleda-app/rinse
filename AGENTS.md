# Agent guide

Read [docs/RULES.md](docs/RULES.md) first: the rules of every repository of the workspace, synced from dojo. Then [README.md](README.md), [docs/WALLS.md](docs/WALLS.md) before touching anything that handles untrusted bytes, and [docs/PLAN.md](docs/PLAN.md). [docs/DECISIONS.md](docs/DECISIONS.md) records what was decided and why; [docs/QUESTIONS.md](docs/QUESTIONS.md) lists what the maintainer still has to decide.

rinse washes untrusted files: it parses hostile bytes only inside its walls and hands back things rebuilt from scratch, never the original. It is generic for untrusted files; mail is one layer of it, not its purpose. It never trusts what its own workers return, never logs content, and never depends on any other repository of the workspace. Its first user is the Peleda application (`../app`, path dependencies and the `rinse-worker` sidecar); `../peleda-insight` (later `bento`) reads its document model.

Status: the sandbox layer (walls 1 and 2 on macOS and Linux) and the mail layer (MIME, HTML, images, facts, wall 3, the hostile corpus) exist and are tested; the files layer, the remote-resource proxy and the remote runner do not exist yet. Windows and Android walls are not written. Run `mise run check` before considering a change done; Rust goes through `mise exec -- cargo ...` (the toolchain of `rust-toolchain.toml`, which has the `wasm32-wasip2` target).

## Layers

Each layer depends only on the layers below it:

1. **Sandbox** (`crates/sandbox*`, `wasm`, `process`, `host`, `build`, `wasm-fixtures`, `wasm-test-worker`): walls 1 and 2. Knows nothing about any input format; callers bring the component and interpret the bytes.
2. **Files** (planned, nothing yet): format-level washing shared by every caller: images re-encoded (moving here from the mail layer), PDF, office documents and archives under bomb limits, the remote-resource proxy.
3. **Mail** (`crates/mail*`, `doc-model`, `text`, `apps/rinse-worker`): message bytes to the safe document model, and wall 3 for it.

## Layout

- `crates/*`: contracts, implementations and libraries of every layer
- `apps/rinse-worker`: the mail worker executable, the only composition root (its binary is `rinse-worker-host`, so it never collides with the app's `rinse-worker` sidecar copy in a shared target directory)
- `fuzz/`: one fuzz workspace with every target of every layer
- `tests/linux`: the Linux check image
- `docs/`: project-wide docs; every crate and app also has its own `docs/README.md`

Package prefix `rinse-`; crate directories drop it: `crates/sandbox-linux` is `rinse-sandbox-linux`, `crates/mail-wasm` is `rinse-mail-wasm`.

## Rules for this repository

- **Lower layers stay generic.** Nothing mail-specific goes into the sandbox layer, and nothing message-specific into the files layer; a layer plugs into the one below through its public API.
- **Untrusted bytes only in a worker.** Content is parsed only by an engine that a wall or a container runs; the receiver validates every answer (wall 3) whatever produced it.
- **Unsafe only for OS sandbox FFI** (`unsafe-allowlist.txt`: `crates/sandbox/src/sys.rs`, `crates/sandbox-macos/src/ffi.rs`, `crates/sandbox-linux/src/namespaces.rs`).
- **Hostile corpus rules** in [docs/WALLS.md](docs/WALLS.md#the-hostile-corpus); a bug found in a pipeline adds a fixture that fails before the fix.
- **Linux code is tested in a container**: `mise run linux -- cargo test -p <crate>` (image in `tests/linux`, this repository at `/work/rinse`). `RINSE_DOCKER_FLAGS="--security-opt seccomp=unconfined"` lets the container create user namespaces.
- **Windows** is compile-checked: `mise run check-windows`. Crates with Wasmtime (`rinse-wasm`, `rinse-host`, `rinse-mail-wasm`, `rinse-worker`) need the Windows SDK headers and are not checked.
- **Worker and parent ship together.** The worker's arguments (`--rinse-sandbox-policy=`, `--rinse-sandbox-probe`) and environment (`RINSE_MAIL_WORKER_WASM`) have no compatibility shims; `../app` checks that its wire crates resolve alike in both lockfiles.
