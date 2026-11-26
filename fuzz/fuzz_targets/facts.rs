#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rinse_mail::testing::facts_message;
use rinse_mail::{ContentLimits, RenderOptions, RenderRequest, Rendered, verify_rendered};

fuzz_target!(|data: &[u8]| {
    let request = RenderRequest {
        raw: Bytes::from(facts_message(data)),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    };
    let mut framed = vec![rinse_mail_worker::OP_RENDER];
    framed.extend(postcard::to_stdvec(&request).unwrap());
    let response = rinse_mail_worker::handle(&framed);
    if let Some((&rinse_mail_worker::STATUS_OK, body)) = response.split_first() {
        let rendered: Rendered = postcard::from_bytes(body).unwrap();
        assert_eq!(verify_rendered(&request, &rendered), Ok(()));
    }
});
