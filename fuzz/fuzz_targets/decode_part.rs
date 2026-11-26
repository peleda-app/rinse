#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rinse_mail::{ContentError, ContentLimits, DecodedPart, PartRequest};
use rinse_mail_worker::{STATUS_ERR, STATUS_OK};

fuzz_target!(|data: &[u8]| {
    let [a, b, raw @ ..] = data else {
        return;
    };
    let mut limits = ContentLimits::default();
    if a & 0x80 != 0 {
        limits.max_output_bytes = 4 << 10;
    }
    let request = PartRequest {
        raw: Bytes::copy_from_slice(raw),
        part: u32::from(u16::from_be_bytes([a & 0x7f, *b])),
        limits,
    };
    let direct = rinse_mail_engine::decode_part(&request);
    if let Ok(part) = &direct {
        assert_eq!(part.part, request.part);
        assert!(part.bytes.len() as u64 <= limits.max_output_bytes);
        assert!(!part.media_type.bytes().any(|c| c.is_ascii_uppercase()));
    }
    let mut framed = vec![rinse_mail_worker::OP_DECODE_PART];
    framed.extend(postcard::to_stdvec(&request).unwrap());
    let answer = rinse_mail_worker::handle(&framed);
    let through_worker = match answer.split_first() {
        Some((&STATUS_OK, body)) => Ok(postcard::from_bytes::<DecodedPart>(body).unwrap()),
        Some((&STATUS_ERR, body)) => Err(postcard::from_bytes::<ContentError>(body).unwrap()),
        _ => panic!("worker answered without a status byte"),
    };
    assert_eq!(through_worker, direct);
});
