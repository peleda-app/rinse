//! The `rinse-sandbox` conformance suite with the worker executable itself as the probe, so
//! the composition root's lockdown is the one under test.

use std::path::PathBuf;
use std::process::ExitCode;

use rinse_sandbox::WorkerCommand;
use rinse_sandbox::testing::{self, PROBE_ARG};

mod common;

fn main() -> ExitCode {
    let probe = WorkerCommand {
        program: PathBuf::from(env!("CARGO_BIN_EXE_rinse-worker-host")),
        args: vec![PROBE_ARG.to_owned()],
    };
    let launcher = common::launcher();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    if launcher.is_wall() {
        runtime.block_on(testing::run(launcher, probe));
    } else {
        runtime.block_on(testing::run_mechanics(launcher, probe));
    }
    println!("worker host probe: ok");
    ExitCode::SUCCESS
}
