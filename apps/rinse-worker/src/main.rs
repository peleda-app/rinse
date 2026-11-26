//! The content worker executable, a composition root. Started by `rinse-mail-process` (the
//! app ships it as a sidecar), it hands the embedded WebAssembly worker and the content handler
//! to `rinse_host::run`, which locks the process down with this platform's sandbox, compiles
//! the component first, serves exactly one request and exits.
//!
//! `--backend=pulley` runs the component on Wasmtime's interpreter instead of native code. With
//! the `probe` feature (tests only), `--rinse-sandbox-probe` turns it into the probe of the
//! `rinse-sandbox` conformance suite under the same lockdown.

use std::process::ExitCode;

use rinse_mail::{ContentError, DecodedPart, PartRequest, RenderRequest, Rendered};
use rinse_mail_process::worker::{BlockingContent, ContentHandler};
use rinse_mail_wasm::{EMBEDDED_WORKER, WasmContent};

struct Wasm(WasmContent);

impl BlockingContent for Wasm {
    fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError> {
        self.0.render_blocking(request)
    }

    fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError> {
        self.0.decode_part_blocking(request)
    }
}

fn main() -> ExitCode {
    rinse_host::run(EMBEDDED_WORKER, |runner| {
        Some(ContentHandler::new(Wasm(WasmContent::from_runner(runner))))
    })
}
