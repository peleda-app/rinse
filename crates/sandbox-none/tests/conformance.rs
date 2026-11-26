//! The sandbox mechanics suite; this binary is also its own probe.

use std::process::ExitCode;
use std::sync::Arc;

use rinse_sandbox::WorkerCommand;
use rinse_sandbox::testing::{self, PROBE_ARG};
use rinse_sandbox_none::{NoLockdown, NoneLauncher};

fn main() -> ExitCode {
    if testing::is_probe() {
        return testing::probe_main(&NoLockdown);
    }
    let probe = WorkerCommand {
        program: std::env::current_exe().expect("test binary path"),
        args: vec![PROBE_ARG.to_owned()],
    };
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(testing::run_mechanics(Arc::new(NoneLauncher), probe));
    println!("sandbox-none mechanics: ok");
    ExitCode::SUCCESS
}
