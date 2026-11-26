#!/usr/bin/env bash
# The Linux half of CI, run inside the check image: `mise run check-linux`.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p rinse-host --features probe --all-targets -- -D warnings
cargo clippy -p rinse-worker --features probe --all-targets -- -D warnings
cargo test --workspace
cargo test -p rinse-host --features probe --test probe
cargo test -p rinse-worker --features probe --test probe
cargo test --release -p rinse-wasm
cargo test --release -p rinse-mail-wasm
cargo test --release -p rinse-mail-process
