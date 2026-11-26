#![no_main]

use libfuzzer_sys::fuzz_target;
use rinse_sandbox::{MAX_ANNOUNCEMENT, announce, decode_announcement, read_frame, write_frame};

fuzz_target!(|data: &[u8]| {
    let Some((&cap, mut input)) = data.split_first() else {
        return;
    };
    let cap = usize::from(cap) * 64;
    while let Ok(frame) = read_frame(&mut input, cap) {
        assert!(frame.len() <= cap);
        let mut written = Vec::new();
        write_frame(&mut written, &frame).unwrap();
        assert_eq!(read_frame(&mut written.as_slice(), cap).unwrap(), frame);
        if let Ok(report) = decode_announcement(&frame) {
            let mut again = Vec::new();
            announce(&mut again, &report).unwrap();
            let reread = read_frame(&mut again.as_slice(), MAX_ANNOUNCEMENT).unwrap();
            assert_eq!(decode_announcement(&reread).unwrap(), report);
        }
    }
});
