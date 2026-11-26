#!/usr/bin/env bash
# Runs a command inside the Linux check image with this repository mounted at /work/rinse.
set -euo pipefail
here="$(cd "$(dirname "$0")/../.." && pwd)"
image="rinse-linux:1"
# LINUX_CACHE_DIR (CI) puts the registry and target directory in host directories that can be
# cached; otherwise they live in named Docker volumes.
registry=rinse-cargo-registry
target=rinse-linux-target
if [ -n "${LINUX_CACHE_DIR:-}" ]; then
  mkdir -p "$LINUX_CACHE_DIR/registry" "$LINUX_CACHE_DIR/target"
  registry="$(cd "$LINUX_CACHE_DIR/registry" && pwd)"
  target="$(cd "$LINUX_CACHE_DIR/target" && pwd)"
fi
docker build -q -t "$image" "$here/tests/linux" >/dev/null
docker run --rm \
  ${RINSE_DOCKER_FLAGS:-} \
  -v "$here:/work/rinse" \
  -v "$registry:/usr/local/cargo/registry" \
  -v "$target:/work/rinse/target" \
  -e RUSTUP_TOOLCHAIN=1.99.1 \
  -e CARGO_TARGET_DIR=/work/rinse/target \
  -w /work/rinse \
  "$image" "$@"
