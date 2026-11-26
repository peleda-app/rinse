//! Builds the content worker for `wasm32-wasip2` into `OUT_DIR` when the `embedded` feature is on:
//! `rinse-mail-worker.wasm` (shipped) and `rinse-mail-worker-test.wasm` (with the
//! `test-hooks` feature, used only by this crate's tests), through `rinse-build`. Each feature set
//! has its own nested target directory, so a build of one can never hand out the other's file.

use std::env;
use std::path::{Path, PathBuf};

use rinse_build::{Component, copy, nested_target_dir};

const WORKER: &str = "rinse-mail-worker";
const INPUTS: &[&str] = &[
    "crates/mail-worker",
    "crates/mail-engine",
    "crates/mail",
    "crates/doc-model",
    "crates/text",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RINSE_MAIL_WORKER_WASM");
    if env::var_os("CARGO_FEATURE_EMBEDDED").is_none() {
        return;
    }
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(Path::parent)
        .expect("crate sits in <workspace>/crates/");
    let shipped_dir = nested_target_dir("rinse-mail-worker-component");
    let test_dir = nested_target_dir("rinse-mail-worker-test-component");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let component = |features: &'static [&'static str], target_dir| Component {
        workspace,
        package: WORKER,
        bin: WORKER,
        features,
        target_dir,
    };
    component(&[], &shipped_dir).rerun_if_changed(INPUTS);

    let test = out.join(format!("{WORKER}-test.wasm"));
    copy(&component(&["test-hooks"], &test_dir).build(), &test);
    let shipped = out.join(format!("{WORKER}.wasm"));
    match env::var_os("RINSE_MAIL_WORKER_WASM") {
        Some(prebuilt) => {
            let prebuilt = Path::new(&prebuilt);
            let bytes = std::fs::read(prebuilt).expect("read RINSE_MAIL_WORKER_WASM");
            assert!(
                bytes != std::fs::read(&test).expect("read the test worker"),
                "RINSE_MAIL_WORKER_WASM is the test-hooks worker; refusing to ship it"
            );
            copy(prebuilt, &shipped);
        }
        None => copy(&component(&[], &shipped_dir).build(), &shipped),
    }
}
