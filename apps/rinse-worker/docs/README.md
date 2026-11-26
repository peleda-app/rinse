# rinse-worker

The mail worker executable, a composition root. The package is `rinse-worker`; its binary is `rinse-worker-host`, so cargo's own binary never shares a path with the app's `rinse-worker` sidecar copy in a target directory shared between workspaces. It runs `rinse_host::run` ([`rinse-host`](../../../crates/host/docs/README.md)) with the embedded content worker of [`mail-wasm`](../../../crates/mail-wasm/docs/README.md) and the `ContentHandler` of [`mail-process`](../../../crates/mail-process/docs/README.md). `rinse-host` picks this platform's lockdown (Seatbelt on macOS, seccomp, Landlock and rlimits on Linux, none elsewhere), compiles the component, warms up by rendering a built-in message, locks down, announces, serves exactly one request and exits. It is never started by hand: `ProcessContent` starts it through a launcher, and the app (`../app`) ships it as the Tauri sidecar `rinse-worker`.

## Arguments

- the policy argument appended by the launcher (required);
- `--backend=pulley`: run the component on Wasmtime's Pulley interpreter, for a worker signed without permission to create executable memory (hardened runtime without `allow-unsigned-executable-memory`). Native by default.
- with the `probe` feature only (tests): `--rinse-sandbox-probe` makes it the probe of the `rinse-sandbox` conformance suite under the same lockdown.

Exit codes are `rinse-process`'s `worker_main` codes (4 when the component does not compile or the warm-up render fails).

## Building the sidecar

`../app/scripts/build-worker-host.sh` (`mise run worker-host` in `../app`, part of its `mise run check`, and the shell's `beforeBuildCommand`) runs a release build of this package in this workspace and copies `rinse-worker-host` to `../app/apps/shell/src-tauri/binaries/rinse-worker-<target triple>`. Release builds compile the component in about 0.2 s per worker; an unoptimized worker takes about 3 s, which is why the sidecar is always built in release.

## Tests

- `cargo test -p rinse-worker`: `tests/serve.rs` starts the real executable through this platform's launcher with `ProcessContent` and renders a message and decodes a part on both backends.
- `cargo test -p rinse-worker --features probe --test probe` (in `mise run check`): the `rinse-sandbox` conformance suite with this executable as the probe (`run` on macOS and Linux, `run_mechanics` elsewhere).

## Dependencies

`rinse-mail`, `rinse-mail-process`, `rinse-mail-wasm`, `rinse-host`.
