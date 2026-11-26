# rinse-build

A helper for build scripts that embed a WebAssembly component built from their own workspace (for example `rinse-wasm-fixtures` here, `rinse-mail-wasm` in the mail layer). Not a runtime dependency of anything.

## API

- `Component { workspace, package, bin, features, target_dir }` and `Component::build() -> PathBuf`: runs `cargo build --manifest-path <workspace>/Cargo.toml -p <package> --bin <bin> --target wasm32-wasip2 --release [--features ...]` with `CARGO_TARGET_DIR=<target_dir>` and returns `<target_dir>/wasm32-wasip2/release/<bin>.wasm`. Panics with an explanation when cargo cannot start or the build fails, which fails the calling build script.
- `Component::rerun_if_changed(inputs)`: prints `cargo:rerun-if-changed` for the workspace's `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` and each input path (relative to the workspace root).
- `nested_target_dir(name)`: `<target>/<name>` (or `<build-dir>/<name>`), four levels above `OUT_DIR`, so the nested build is incremental, shared by all profiles and never waits on the outer build's lock. Cargo locks the outer build per profile only, so a caller that builds one binary with several feature sets must give each its own `name`, or a concurrent build may copy the other set's file.
- `copy(from, to)`: `std::fs::copy` that panics with both paths.
- `TARGET`: `"wasm32-wasip2"`.

## Behavior

- Wrapper and flag variables of the outer build are cleared for the nested one: `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` (clippy), `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_TARGET`, `CARGO_BUILD_RUSTFLAGS`, `CARGO_TARGET_DIR`, `CARGO_PRIMARY_PACKAGE`, `CLIPPY_ARGS`.
- Toolchain: if the compiler running the build (`$RUSTC`) has the `wasm32-wasip2` standard library, the nested build uses the same cargo and compiler. Otherwise (for example a Homebrew `cargo` ahead of rustup's on `PATH`), it asks `rustup which --toolchain <channel from rust-toolchain.toml>` for that toolchain's `cargo` and `rustc`.
- The nested build's stdout is discarded, its stderr inherited (cargo shows it only on failure or with `-vv`).
- The first build needs the crates in the cargo cache or network access; tests never use the network.

## Tests

`cargo test -p rinse-build`: the toolchain channel is read from `rust-toolchain.toml`. The nested build itself is exercised by every build of `rinse-wasm-fixtures`.
