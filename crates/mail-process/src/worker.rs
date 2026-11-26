//! The worker side of the protocol: the handler a worker executable gives `rinse-host`.

use rinse_mail::{
    ContentError, ContentLimits, DecodedPart, PartRequest, RenderOptions, RenderRequest, Rendered,
};
use rinse_process::worker::Serve;

use crate::{OP_DECODE_PART, OP_RENDER};

/// The pipeline a worker runs on its one request, on the calling thread.
pub trait BlockingContent {
    /// Renders a message, as [`rinse_mail::Content::render`].
    fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError>;
    /// Decodes a part, as [`rinse_mail::Content::decode_part`].
    fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError>;
}

/// Serves the [`crate::ProcessContent`] protocol with a [`BlockingContent`]: warms up by
/// rendering a built-in message, then decodes the one request (an op byte and a postcard
/// request), runs it, and answers the postcard `Result`. A request that does not decode is
/// malformed (the worker exits without answering).
#[derive(Debug)]
pub struct ContentHandler<C> {
    content: C,
}

impl<C: BlockingContent> ContentHandler<C> {
    /// A handler around `content`.
    pub fn new(content: C) -> Self {
        Self { content }
    }
}

fn warm_up_request() -> RenderRequest {
    RenderRequest {
        raw: bytes::Bytes::from_static(
            b"From: worker@example.com\r\nSubject: warm-up\r\n\r\nwarm-up\r\n",
        ),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    }
}

impl<C: BlockingContent> Serve for ContentHandler<C> {
    fn warm_up(&self) -> bool {
        self.content.render(warm_up_request()).is_ok()
    }

    fn serve(&self, request: &[u8]) -> Option<Vec<u8>> {
        let response = match request.split_first() {
            Some((&OP_RENDER, body)) => {
                let request = postcard::from_bytes::<RenderRequest>(body).ok()?;
                postcard::to_stdvec(&self.content.render(request))
            }
            Some((&OP_DECODE_PART, body)) => {
                let request = postcard::from_bytes::<PartRequest>(body).ok()?;
                postcard::to_stdvec(&self.content.decode_part(request))
            }
            _ => return None,
        };
        Some(response.unwrap_or_else(|_| {
            postcard::to_stdvec(&Err::<(), _>(ContentError::Crashed)).unwrap_or_default()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;

    impl BlockingContent for Fixed {
        fn render(&self, _request: RenderRequest) -> Result<Rendered, ContentError> {
            Err(ContentError::Timeout)
        }

        fn decode_part(&self, _request: PartRequest) -> Result<DecodedPart, ContentError> {
            Err(ContentError::PartNotFound)
        }
    }

    #[test]
    fn malformed_requests_get_no_answer() {
        let handler = ContentHandler::new(Fixed);
        for request in [&[][..], &[2], &[OP_RENDER], &[OP_DECODE_PART, 0xff, 0xff]] {
            assert_eq!(handler.serve(request), None, "{request:?}");
        }
    }

    #[test]
    fn answers_the_result_of_the_content() {
        let handler = ContentHandler::new(Fixed);
        assert!(!handler.warm_up());
        let mut frame = vec![OP_RENDER];
        frame.extend(postcard::to_stdvec(&warm_up_request()).unwrap());
        let answer = handler.serve(&frame).unwrap();
        assert_eq!(
            postcard::from_bytes::<Result<Rendered, ContentError>>(&answer).unwrap(),
            Err(ContentError::Timeout)
        );
    }
}
