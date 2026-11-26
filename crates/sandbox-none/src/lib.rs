//! **Not a wall.** [`NoneLauncher`] starts workers with no restriction at all and [`NoLockdown`]
//! applies none, so a compromised worker has every right of the user running the app. For
//! development builds, tests and platforms whose sandbox does not exist yet; never in a release.
//!
//! What it does keep: closing inherited descriptors above stderr, an empty environment, `/` as the working directory, discarded stderr, the
//! framing protocol with its size caps, and the wall-time kill.

use async_trait::async_trait;
use rinse_sandbox::{
    Launcher, Lockdown, LockdownReport, Policy, SandboxError, WorkerCommand, WorkerProcess,
    close_inherited_descriptors,
};

mod process;

/// Starts workers without any sandbox. [`Launcher::is_wall`] is `false`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoneLauncher;

#[async_trait]
impl Launcher for NoneLauncher {
    fn name(&self) -> &'static str {
        "none"
    }

    fn is_wall(&self) -> bool {
        false
    }

    async fn launch(
        &self,
        command: &WorkerCommand,
        policy: &Policy,
    ) -> Result<Box<dyn WorkerProcess>, SandboxError> {
        let worker = process::Worker::start(command, policy, None).await?;
        Ok(Box::new(worker))
    }
}

/// Applies no restriction. Like every lockdown it closes the descriptors the worker inherited
/// above stderr in [`Lockdown::prepare`], so it reports only
/// [`rinse_sandbox::Restriction::ClosedDescriptors`] (on Unix).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLockdown;

impl Lockdown for NoLockdown {
    fn name(&self) -> &'static str {
        "none"
    }

    fn prepare(&self, _policy: &Policy) -> Result<LockdownReport, SandboxError> {
        let mut report = LockdownReport::default();
        close_inherited_descriptors(&mut report)?;
        Ok(report)
    }

    fn lock_down(
        &self,
        _policy: &Policy,
        prepared: LockdownReport,
    ) -> Result<LockdownReport, SandboxError> {
        Ok(prepared)
    }
}
