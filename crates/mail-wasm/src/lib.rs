//! [`WasmContent`] runs the content worker (`rinse-mail-worker`, a `wasi:cli/command`
//! WebAssembly component) with `rinse-wasm`, one fresh instance per call, inside the memory,
//! time and output limits of the request. This is wall 1 (`docs/WALLS.md`); on macOS
//! and Linux the shell runs it inside a sandboxed worker process (`rinse-mail-process` and
//! `apps/rinse-worker`), iOS runs it in-process on the Pulley interpreter.
//!
//! The worker is untrusted: everything it returns is size-checked before decoding and validated
//! after, like the core validates any [`Content`] implementation.

use std::time::Duration;

use async_trait::async_trait;
use rinse_mail::{
    Content, ContentError, ContentLimits, DecodedPart, LimitKind, PartRequest, RenderRequest,
    Rendered,
};
use rinse_wasm::{Limits, WasmError, WasmRunner};

pub use rinse_wasm::Backend;

const OP_RENDER: u8 = 0;
const OP_DECODE_PART: u8 = 1;
const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;

/// The worker component built from `rinse-mail-worker` for this version of the crate.
#[cfg(feature = "embedded")]
pub const EMBEDDED_WORKER: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/rinse-mail-worker.wasm"));

/// The content pipeline in a WebAssembly sandbox.
///
/// Every call runs the worker in a fresh instance with an empty, frozen WASI context (see
/// `rinse-wasm`), a memory cap of `memory_bytes`, a deadline of `time_budget_ms`, and an output
/// cap of `max_output_bytes` plus the status byte. A trap or a non-zero exit becomes
/// [`ContentError::Crashed`], an exhausted deadline [`ContentError::Timeout`], a refused memory
/// growth [`ContentError::LimitExceeded`] with [`LimitKind::Memory`], too much output
/// [`LimitKind::Output`]. Every response is checked with [`rinse_mail::verify_rendered`] or
/// [`rinse_mail::verify_decoded_part`], like the core checks one.
///
/// [`Content`] calls run on Tokio's blocking pool, [`WasmContent::render_blocking`] and
/// [`WasmContent::decode_part_blocking`] on the calling thread; cheap to clone or share as
/// `Arc<dyn Content>`.
#[derive(Clone, Debug)]
pub struct WasmContent {
    runner: WasmRunner,
}

impl WasmContent {
    /// Compiles the embedded worker with the default [`Backend`]. Compilation takes a moment (it
    /// is done once per value); fails with [`ContentError::Unavailable`] if Wasmtime cannot run on
    /// this platform.
    #[cfg(feature = "embedded")]
    pub fn embedded() -> Result<Self, ContentError> {
        Self::from_component(EMBEDDED_WORKER, Backend::default())
    }

    /// Compiles a worker component from its bytes. The component must be a `wasi:cli/command`
    /// speaking the worker protocol; fails with [`ContentError::Unavailable`] if it does not
    /// compile or link against WASI preview 2.
    pub fn from_component(bytes: &[u8], backend: Backend) -> Result<Self, ContentError> {
        WasmRunner::new(bytes, backend)
            .map(Self::from_runner)
            .map_err(|_| ContentError::Unavailable)
    }

    /// Wraps a runner that already compiled a worker component.
    pub fn from_runner(runner: WasmRunner) -> Self {
        Self { runner }
    }

    /// The backend this value runs the worker on.
    pub fn backend(&self) -> Backend {
        self.runner.backend()
    }

    /// [`Content::render`] on the calling thread, without a Tokio runtime: for a worker process
    /// that serves one request and must not start threads after it locked itself down.
    pub fn render_blocking(&self, request: RenderRequest) -> Result<Rendered, ContentError> {
        if request.raw.len() as u64 > request.limits.max_input_bytes {
            return Err(ContentError::InputTooLarge);
        }
        let payload = postcard::to_stdvec(&request).map_err(|_| ContentError::Crashed)?;
        let output = self.run(OP_RENDER, payload, &request.limits)?;
        let rendered: Rendered = rinse_mail::decode_render_response(&output, &request.limits)?;
        rinse_mail::verify_rendered(&request, &rendered)?;
        Ok(rendered)
    }

    /// [`Content::decode_part`] on the calling thread, without a Tokio runtime.
    pub fn decode_part_blocking(&self, request: PartRequest) -> Result<DecodedPart, ContentError> {
        if request.raw.len() as u64 > request.limits.max_input_bytes {
            return Err(ContentError::InputTooLarge);
        }
        let payload = postcard::to_stdvec(&request).map_err(|_| ContentError::Crashed)?;
        let output = self.run(OP_DECODE_PART, payload, &request.limits)?;
        let part: DecodedPart = postcard::from_bytes(&output).map_err(|_| ContentError::Crashed)?;
        rinse_mail::verify_decoded_part(&request, &part)?;
        Ok(part)
    }

    fn run(
        &self,
        op: u8,
        payload: Vec<u8>,
        limits: &ContentLimits,
    ) -> Result<Vec<u8>, ContentError> {
        let mut input = Vec::with_capacity(payload.len() + 1);
        input.push(op);
        input.extend_from_slice(&payload);
        drop(payload);
        let limits = Limits {
            memory_bytes: limits.memory_bytes,
            time_budget: Duration::from_millis(limits.time_budget_ms),
            max_output_bytes: limits.max_output_bytes.saturating_add(1),
        };
        let output = self
            .runner
            .run_blocking(input, &limits)
            .map_err(map_error)?;
        match output.split_first() {
            Some((&STATUS_OK, body)) => Ok(body.to_vec()),
            Some((&STATUS_ERR, body)) => {
                Err(postcard::from_bytes::<ContentError>(body)
                    .map_err(|_| ContentError::Crashed)?)
            }
            _ => Err(ContentError::Crashed),
        }
    }
}

fn map_error(error: WasmError) -> ContentError {
    match error {
        WasmError::Unavailable => ContentError::Unavailable,
        WasmError::Timeout => ContentError::Timeout,
        WasmError::MemoryExceeded => ContentError::LimitExceeded(LimitKind::Memory),
        WasmError::OutputTooLarge => ContentError::LimitExceeded(LimitKind::Output),
        WasmError::Crashed => ContentError::Crashed,
    }
}

#[async_trait]
impl Content for WasmContent {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError> {
        if request.raw.len() as u64 > request.limits.max_input_bytes {
            return Err(ContentError::InputTooLarge);
        }
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.render_blocking(request))
            .await
            .unwrap_or(Err(ContentError::Crashed))
    }

    async fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError> {
        if request.raw.len() as u64 > request.limits.max_input_bytes {
            return Err(ContentError::InputTooLarge);
        }
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.decode_part_blocking(request))
            .await
            .unwrap_or(Err(ContentError::Crashed))
    }
}

#[cfg(all(test, feature = "embedded"))]
mod tests;
