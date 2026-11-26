#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rinse_mail::{ContentError, ContentLimits, RenderOptions, RenderRequest, Rendered};
use rinse_mail_worker::{STATUS_ERR, STATUS_OK};

fuzz_target!(|data: &[u8]| {
    let request = RenderRequest {
        raw: Bytes::copy_from_slice(data),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    };
    let mut framed = vec![rinse_mail_worker::OP_RENDER];
    framed.extend(postcard::to_stdvec(&request).unwrap());
    let answer = rinse_mail_worker::handle(&framed);
    let through_worker = match answer.split_first() {
        Some((&STATUS_OK, body)) => Ok(postcard::from_bytes::<Rendered>(body).unwrap()),
        Some((&STATUS_ERR, body)) => Err(postcard::from_bytes::<ContentError>(body).unwrap()),
        _ => panic!("worker answered without a status byte"),
    };
    assert_eq!(through_worker, rinse_mail_engine::render(&request));
});
