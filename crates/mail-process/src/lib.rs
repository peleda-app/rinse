//! [`ProcessContent`] runs every request of the content pipeline in a fresh worker process
//! through `rinse-process`: one locked-down process per message, killed when it overruns its
//! time budget, its output size-capped and verified like any untrusted response. This is wall 2
//! (`docs/WALLS.md`) around wall 1 (the WebAssembly worker the executable embeds).
//!
//! The worker executable serves with [`worker::ContentHandler`]; see `apps/rinse-worker`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rinse_mail::{
    Content, ContentError, ContentLimits, DecodedPart, LimitKind, PartRequest, RenderRequest,
    Rendered,
};
use rinse_process::{ProcessError, ProcessRunner};
use rinse_sandbox::Launcher;

pub use rinse_process::ProcessConfig;

pub mod worker;

const OP_RENDER: u8 = 0;
const OP_DECODE_PART: u8 = 1;

/// The content pipeline in sandboxed worker processes.
///
/// Per call: the input size is checked before anything is started or sent (`InputTooLarge`);
/// the request (an op byte and the postcard request) goes to a worker that has never served
/// another request; the response is read with a cap of `max_output_bytes` plus one byte of
/// framing (`LimitExceeded(Output)`); after `time_budget_ms` plus [`ProcessConfig::grace`] the
/// worker is killed (`Timeout`). A worker killed for memory is `LimitExceeded(Memory)`, for CPU
/// or wall time `Timeout`, any other end without a response `Crashed`; a launch that fails is
/// `Unavailable`. Every response is checked with [`rinse_mail::verify_rendered`] or
/// [`rinse_mail::verify_decoded_part`].
///
/// Every worker process runs under the `memory_bytes` of [`ProcessConfig::policy`], whatever the
/// request's `ContentLimits::memory_bytes`: that one is enforced only by the WebAssembly runtime
/// inside the worker.
///
/// Needs a Tokio runtime (with the time driver) for its calls; cheap to clone.
#[derive(Clone, Debug)]
pub struct ProcessContent {
    runner: ProcessRunner,
}

impl ProcessContent {
    /// A pipeline that starts workers with `launcher`. Starts nothing until the first call or
    /// [`ProcessContent::warm_up`].
    pub fn new(launcher: Arc<dyn Launcher>, config: ProcessConfig) -> Self {
        Self {
            runner: ProcessRunner::new(launcher, config),
        }
    }

    /// Starts the warm workers now, in the background. Needs a Tokio runtime.
    pub fn warm_up(&self) {
        self.runner.warm_up();
    }

    /// Starts one worker and waits for its lockdown report, to check at startup that the
    /// sandbox works on this system. Fails with `Unavailable` when it does not.
    pub async fn probe(&self) -> Result<(), ContentError> {
        self.runner.probe().await.map_err(map_error)
    }

    /// The name of the launcher (`"linux"`, `"macos"`, `"none"`).
    pub fn launcher_name(&self) -> &'static str {
        self.runner.launcher_name()
    }

    /// Whether the launcher sandboxes its workers.
    pub fn is_wall(&self) -> bool {
        self.runner.is_wall()
    }

    async fn call(
        &self,
        op: u8,
        body: Vec<u8>,
        limits: &ContentLimits,
    ) -> Result<Vec<u8>, ContentError> {
        let mut frame = Vec::with_capacity(body.len() + 1);
        frame.push(op);
        frame.extend_from_slice(&body);
        drop(body);
        let cap = usize::try_from(limits.max_output_bytes)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        self.runner
            .call(frame, Duration::from_millis(limits.time_budget_ms), cap)
            .await
            .map_err(map_error)
    }
}

fn map_error(error: ProcessError) -> ContentError {
    match error {
        ProcessError::Unavailable => ContentError::Unavailable,
        ProcessError::RequestTooLarge => ContentError::InputTooLarge,
        ProcessError::Timeout => ContentError::Timeout,
        ProcessError::MemoryExceeded => ContentError::LimitExceeded(LimitKind::Memory),
        ProcessError::ResponseTooLarge => ContentError::LimitExceeded(LimitKind::Output),
        ProcessError::Crashed => ContentError::Crashed,
    }
}

#[async_trait]
impl Content for ProcessContent {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError> {
        if request.raw.len() as u64 > request.limits.max_input_bytes {
            return Err(ContentError::InputTooLarge);
        }
        let body = postcard::to_stdvec(&request).map_err(|_| ContentError::Crashed)?;
        let response = self.call(OP_RENDER, body, &request.limits).await?;
        let rendered = rinse_mail::decode_render_response::<Result<Rendered, ContentError>>(
            &response,
            &request.limits,
        )??;
        rinse_mail::verify_rendered(&request, &rendered)?;
        Ok(rendered)
    }

    async fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError> {
        if request.raw.len() as u64 > request.limits.max_input_bytes {
            return Err(ContentError::InputTooLarge);
        }
        let body = postcard::to_stdvec(&request).map_err(|_| ContentError::Crashed)?;
        let response = self.call(OP_DECODE_PART, body, &request.limits).await?;
        let part = postcard::from_bytes::<Result<DecodedPart, ContentError>>(&response)
            .map_err(|_| ContentError::Crashed)??;
        rinse_mail::verify_decoded_part(&request, &part)?;
        Ok(part)
    }
}
