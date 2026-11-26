//! Builds `rinse-wasm-test-worker` for `wasm32-wasip2` into `OUT_DIR`.

use std::env;
use std::path::{Path, PathBuf};

use rinse_build::{Component, copy, nested_target_dir};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(Path::parent)
        .expect("crate sits in <workspace>/crates/");
    let target_dir = nested_target_dir("rinse-wasm-test-worker-component");
    let component = Component {
        workspace,
        package: "rinse-wasm-test-worker",
        bin: "rinse-wasm-test-worker",
        features: &[],
        target_dir: &target_dir,
    };
    component.rerun_if_changed(&["crates/wasm-test-worker"]);
    let built = component.build();
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    copy(&built, &out.join("rinse-wasm-test-worker.wasm"));
}
