#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rinse_doc_model::decode(data, &rinse_doc_model::Limits::default(), |_| true);
});
