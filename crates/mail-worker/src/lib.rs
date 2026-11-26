//! The content worker: [`rinse_mail_engine`] as a `wasi:cli/command` component.
//!
//! Built for `wasm32-wasip2`, the binary of this crate is a WebAssembly component that reads one
//! request from stdin, writes one response to stdout and exits. On a native target the same binary
//! speaks the same protocol over a pipe, and this library exposes [`handle`] so the protocol can be
//! tested natively. The worker trusts nothing it is given; the host trusts nothing it returns.
//!
//! Protocol (see `docs/README.md`): the request is one operation byte ([`OP_RENDER`] or
//! [`OP_DECODE_PART`]) followed by the postcard encoding of a `RenderRequest` or `PartRequest`;
//! the response is one status byte, [`STATUS_OK`] followed by the postcard `Rendered` or
//! `DecodedPart`, or [`STATUS_ERR`] followed by the postcard `ContentError`.

use rinse_mail::{ContentError, PartRequest, RenderRequest};

/// Operation byte of a render request.
pub const OP_RENDER: u8 = 0;
/// Operation byte of a decode-part request.
pub const OP_DECODE_PART: u8 = 1;
/// Status byte of a successful response.
pub const STATUS_OK: u8 = 0;
/// Status byte of a failed response.
pub const STATUS_ERR: u8 = 1;

/// Runs one request and returns the response bytes. Never panics on any input beyond what the
/// engine itself guarantees; a request that cannot be decoded answers [`ContentError::Crashed`],
/// since only a mismatched host sends one.
pub fn handle(input: &[u8]) -> Vec<u8> {
    let result = match input.split_first() {
        Some((&OP_RENDER, rest)) => render(rest),
        Some((&OP_DECODE_PART, rest)) => decode_part(rest),
        _ => Err(ContentError::Crashed),
    };
    let encoded = result.map(|body| {
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(STATUS_OK);
        out.extend_from_slice(&body);
        out
    });
    encoded.unwrap_or_else(|e| {
        let mut out = vec![STATUS_ERR];
        out.extend(postcard::to_stdvec(&e).unwrap_or_default());
        out
    })
}

fn render(request: &[u8]) -> Result<Vec<u8>, ContentError> {
    let request: RenderRequest =
        postcard::from_bytes(request).map_err(|_| ContentError::Crashed)?;
    #[cfg(feature = "test-hooks")]
    if let Some(out) = test_hooks::render(&request) {
        return Ok(out);
    }
    let rendered = rinse_mail_engine::render(&request)?;
    postcard::to_stdvec(&rendered).map_err(|_| ContentError::Crashed)
}

fn decode_part(request: &[u8]) -> Result<Vec<u8>, ContentError> {
    let request: PartRequest = postcard::from_bytes(request).map_err(|_| ContentError::Crashed)?;
    let part = rinse_mail_engine::decode_part(&request)?;
    postcard::to_stdvec(&part).map_err(|_| ContentError::Crashed)
}

#[cfg(feature = "test-hooks")]
mod test_hooks {
    use rinse_mail::RenderRequest;

    /// Misbehavior for the host's limit tests, selected by the first bytes of the message.
    /// Compiled only into the test artifact, never into the shipped worker.
    pub(crate) fn render(request: &RenderRequest) -> Option<Vec<u8>> {
        let raw = &request.raw[..];
        if raw.starts_with(b"RINSE-TEST-SPIN") {
            let mut x = 0u64;
            loop {
                x = std::hint::black_box(x.wrapping_add(1));
            }
        }
        if raw.starts_with(b"RINSE-TEST-HOG") {
            let mut hoard: Vec<Vec<u8>> = Vec::new();
            loop {
                hoard.push(std::hint::black_box(vec![1u8; 1 << 20]));
            }
        }
        if raw.starts_with(b"RINSE-TEST-HUGE") {
            return Some(vec![0u8; 4 << 20]);
        }
        if raw.starts_with(b"RINSE-TEST-GARBAGE") {
            return Some(vec![0xff; 64]);
        }
        if raw.starts_with(b"RINSE-TEST-PANIC") {
            panic!("test hook");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rinse_mail::{ContentLimits, DecodedPart, RenderOptions, Rendered};

    use super::*;

    const MESSAGE: &[u8] =
        b"From: a@example.com\r\nTo: b@example.org\r\nSubject: Hi\r\n\r\nHello there.\r\n";

    fn request(op: u8, body: &impl serde::Serialize) -> Vec<u8> {
        let mut v = vec![op];
        v.extend(postcard::to_stdvec(body).unwrap());
        v
    }

    fn error(out: &[u8]) -> ContentError {
        assert_eq!(out[0], STATUS_ERR);
        postcard::from_bytes(&out[1..]).unwrap()
    }

    #[test]
    fn renders_through_the_protocol() {
        let req = RenderRequest {
            raw: Bytes::from_static(MESSAGE),
            options: RenderOptions::default(),
            limits: ContentLimits::default(),
        };
        let out = handle(&request(OP_RENDER, &req));
        assert_eq!(out[0], STATUS_OK);
        let rendered: Rendered = postcard::from_bytes(&out[1..]).unwrap();
        assert_eq!(rendered.headers.subject.as_deref(), Some("Hi"));
        assert!(rendered.text.contains("Hello there."));
    }

    #[test]
    fn garbage_requests_answer_crashed() {
        assert_eq!(error(&handle(&[])), ContentError::Crashed);
        assert_eq!(error(&handle(&[7, 1, 2])), ContentError::Crashed);
        assert_eq!(
            error(&handle(&[OP_RENDER, 0xff, 0xff])),
            ContentError::Crashed
        );
        assert_eq!(error(&handle(&[OP_DECODE_PART])), ContentError::Crashed);
    }

    #[test]
    fn engine_errors_pass_through() {
        let limits = ContentLimits {
            max_input_bytes: 3,
            ..ContentLimits::default()
        };
        let req = RenderRequest {
            raw: Bytes::from_static(MESSAGE),
            options: RenderOptions::default(),
            limits,
        };
        assert_eq!(
            error(&handle(&request(OP_RENDER, &req))),
            ContentError::InputTooLarge
        );
        let part = PartRequest {
            raw: Bytes::from_static(MESSAGE),
            part: 99,
            limits: ContentLimits::default(),
        };
        assert_eq!(
            error(&handle(&request(OP_DECODE_PART, &part))),
            ContentError::PartNotFound
        );
        let leaf = handle(&request(OP_DECODE_PART, &PartRequest { part: 0, ..part }));
        if leaf[0] == STATUS_OK {
            let _: DecodedPart = postcard::from_bytes(&leaf[1..]).unwrap();
        }
    }
}
