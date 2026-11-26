#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rinse_mail::{ContentLimits, RenderOptions, RenderRequest, verify_rendered};

fuzz_target!(|data: &[u8]| {
    let Some((&flags, raw)) = data.split_first() else {
        return;
    };
    let mut options = RenderOptions {
        want_original_html: flags & 1 != 0,
        ..RenderOptions::default()
    };
    if flags & 2 != 0 {
        options.max_image_px = 16;
    }
    let mut limits = ContentLimits::default();
    if flags & 4 != 0 {
        limits.max_output_bytes = 64 << 10;
    }
    let request = RenderRequest {
        raw: Bytes::copy_from_slice(raw),
        options,
        limits,
    };
    if let Ok(rendered) = rinse_mail_engine::render(&request) {
        assert_eq!(verify_rendered(&request, &rendered), Ok(()));
        let size = postcard::to_stdvec(&rendered).unwrap().len() as u64;
        assert!(size <= limits.max_output_bytes);
    }
});
