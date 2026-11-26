//! The `rinse-sandbox` conformance suite with a `rinse_host::run` executable as the probe, so
//! the lockdown `run` picks is the one under test.

use std::process::ExitCode;

use rinse_process::worker::Serve;
use rinse_sandbox::WorkerCommand;
use rinse_sandbox::testing::{self, PROBE_ARG};

mod common;

struct Never;

impl Serve for Never {
    fn warm_up(&self) -> bool {
        false
    }

    fn serve(&self, _request: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

fn main() -> ExitCode {
    if testing::is_probe() {
        return rinse_host::run(rinse_wasm_fixtures::TEST_WORKER, |_| Some(Never));
    }
    let probe = WorkerCommand {
        program: std::env::current_exe().expect("test binary path"),
        args: vec![PROBE_ARG.to_owned()],
    };
    let launcher = common::launcher();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    if launcher.is_wall() {
        runtime.block_on(testing::run(launcher, probe));
    } else {
        runtime.block_on(testing::run_mechanics(launcher, probe));
    }
    println!("rinse-host probe: ok");
    ExitCode::SUCCESS
}
