//! The worker side: what a worker executable's `main` runs.

use std::io::Write;
use std::process::ExitCode;

use rinse_sandbox::{Lockdown, Policy, announce, read_frame, write_frame};

use crate::MAX_REQUEST_BYTES;

/// What a worker does with its one request, on the calling thread.
pub trait Serve {
    /// Runs once before the lockdown on trusted input, so everything set up lazily on a first
    /// call (runtime contexts, signal stacks, memory images) exists before system calls are
    /// restricted. `false` means the worker cannot serve.
    fn warm_up(&self) -> bool;

    /// Answers one request. `None` means the request is malformed; the worker then exits
    /// without a response.
    fn serve(&self, request: &[u8]) -> Option<Vec<u8>>;
}

/// Runs a worker process: reads the policy from the arguments, calls [`Lockdown::prepare`],
/// `load` (which builds the server from trusted bytes while the process may still allocate
/// executable memory and start threads), [`Serve::warm_up`], [`Lockdown::lock_down`], announces
/// the report, then serves exactly one request frame from stdin and writes one response frame to
/// stdout.
///
/// Exit codes: 0 after a response, 2 for a missing policy, 3 when preparing fails, 4 when `load`
/// or the warm-up fails, 5 when the lockdown fails (nothing has been read then), 6 when the
/// parent goes away, 7 for a malformed request.
pub fn worker_main<S: Serve>(
    lockdown: &dyn Lockdown,
    load: impl FnOnce(&Policy) -> Option<S>,
) -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let Ok(policy) = Policy::from_args(&args) else {
        return ExitCode::from(2);
    };
    let Ok(prepared) = lockdown.prepare(&policy) else {
        return ExitCode::from(3);
    };
    let Some(server) = load(&policy) else {
        return ExitCode::from(4);
    };
    if !server.warm_up() {
        return ExitCode::from(4);
    }
    let Ok(report) = lockdown.lock_down(&policy, prepared) else {
        return ExitCode::from(5);
    };
    let mut stdout = std::io::stdout().lock();
    if announce(&mut stdout, &report).is_err() {
        return ExitCode::from(6);
    }
    let Ok(request) = read_frame(&mut std::io::stdin().lock(), MAX_REQUEST_BYTES) else {
        return ExitCode::from(6);
    };
    let Some(response) = server.serve(&request) else {
        return ExitCode::from(7);
    };
    drop(request);
    if write_frame(&mut stdout, &response)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::from(6);
    }
    ExitCode::SUCCESS
}
