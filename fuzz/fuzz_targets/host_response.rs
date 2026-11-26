#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rinse_mail::{
    ContentError, ContentLimits, RenderOptions, RenderRequest, Rendered, verify_rendered,
};

fuzz_target!(|data: &[u8]| {
    let request = RenderRequest {
        raw: Bytes::new(),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    };
    if let Ok(rendered) = postcard::from_bytes::<Rendered>(data) {
        let _ = verify_rendered(&request, &rendered);
    }
    if let Ok(Ok(rendered)) = postcard::from_bytes::<Result<Rendered, ContentError>>(data) {
        let _ = verify_rendered(&request, &rendered);
    }
});
