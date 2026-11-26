//! The decoders of untrusted bytes, fed the hostile corpus and truncated, bit-flipped and
//! length-lying variants of it on every `cargo test`. The same entry points are the fuzz targets
//! in `fuzz/` (nightly `cargo fuzz`); none of them may panic or hang.

use bytes::Bytes;
use rinse_doc_model::Limits;
use rinse_mail::facts::StructuredItem;
use rinse_mail::testing::CORPUS;
use rinse_mail::{
    ContentError, ContentLimits, PartRequest, RenderOptions, RenderRequest, Rendered,
    verify_rendered,
};
use rinse_mail_worker::{OP_DECODE_PART, OP_RENDER, STATUS_ERR, STATUS_OK, handle};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn variants(seed: &[u8], rng: &mut Rng, count: usize) -> Vec<Vec<u8>> {
    let mut out = vec![seed.to_vec(), Vec::new()];
    for _ in 0..count {
        let mut v = seed.to_vec();
        match rng.below(4) {
            0 => v.truncate(rng.below(seed.len())),
            1 => {
                for _ in 0..=rng.below(8) {
                    if !v.is_empty() {
                        let i = rng.below(v.len());
                        v[i] ^= 1 << rng.below(8);
                    }
                }
            }
            2 => {
                let i = rng.below(v.len());
                v.splice(i..i, [0xff, 0xff, 0xff, 0xff, 0x0f]);
            }
            _ => {
                let i = rng.below(v.len());
                let n = rng.below(64);
                v.splice(i..i, std::iter::repeat_n(b'=', n));
            }
        }
        out.push(v);
    }
    out
}

fn render_request(raw: &[u8]) -> RenderRequest {
    RenderRequest {
        raw: Bytes::copy_from_slice(raw),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    }
}

fn framed(op: u8, body: Vec<u8>) -> Vec<u8> {
    let mut out = vec![op];
    out.extend(body);
    out
}

fn check_response(response: &[u8]) {
    match response.split_first() {
        Some((&STATUS_OK, _)) => {}
        Some((&STATUS_ERR, body)) => {
            postcard::from_bytes::<ContentError>(body).expect("an error the host can decode");
        }
        _ => panic!("no status byte"),
    }
}

fn worker_request(data: &[u8]) {
    check_response(&handle(data));
}

fn render_raw(data: &[u8]) {
    let request = postcard::to_stdvec(&render_request(data)).unwrap();
    check_response(&handle(&framed(OP_RENDER, request)));
}

fn host_response(data: &[u8]) {
    let request = render_request(b"");
    if let Ok(rendered) = postcard::from_bytes::<Rendered>(data) {
        let _ = verify_rendered(&request, &rendered);
    }
    if let Ok(Ok(rendered)) = postcard::from_bytes::<Result<Rendered, ContentError>>(data) {
        let _ = verify_rendered(&request, &rendered);
    }
}

fn facts(data: &[u8]) -> Option<Rendered> {
    let request = render_request(&rinse_mail::testing::facts_message(data));
    let response = handle(&framed(OP_RENDER, postcard::to_stdvec(&request).unwrap()));
    check_response(&response);
    if let Some((&STATUS_OK, body)) = response.split_first() {
        let rendered: Rendered =
            postcard::from_bytes(body).expect("the worker's own answer decodes");
        assert_eq!(
            verify_rendered(&request, &rendered),
            Ok(()),
            "the engine's facts verify"
        );
        return Some(rendered);
    }
    None
}

const PASS_JSON: &[u8] = br#"{"formatVersion":1,"organizationName":"Example Air","description":"Boarding pass","relevantDate":"2026-12-01T09:00:00+02:00","boardingPass":{}}"#;

fn le16(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap().to_le_bytes()
}

fn le32(n: usize) -> [u8; 4] {
    u32::try_from(n).unwrap().to_le_bytes()
}

/// A zip archive with an icon and `pass.json`, stored or deflated (one stored deflate block).
fn pkpass(deflated: bool) -> Vec<u8> {
    let entries: [(&str, Vec<u8>, usize); 2] = [
        ("icon.png", b"\x89PNG\r\n".to_vec(), 6),
        (
            "pass.json",
            if deflated {
                let mut d = vec![1];
                d.extend(le16(PASS_JSON.len()));
                d.extend(le16(!PASS_JSON.len() & 0xffff));
                d.extend(PASS_JSON);
                d
            } else {
                PASS_JSON.to_vec()
            },
            PASS_JSON.len(),
        ),
    ];
    let method = if deflated { 8 } else { 0 };
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, size) in &entries {
        let offset = out.len();
        out.extend(b"PK\x03\x04\x14\0\0\0");
        out.extend(le16(method));
        out.extend([0; 8]);
        out.extend(le32(data.len()));
        out.extend(le32(*size));
        out.extend(le16(name.len()));
        out.extend([0, 0]);
        out.extend(name.as_bytes());
        out.extend(data);
        central.extend(b"PK\x01\x02\x14\0\x14\0\0\0");
        central.extend(le16(method));
        central.extend([0; 8]);
        central.extend(le32(data.len()));
        central.extend(le32(*size));
        central.extend(le16(name.len()));
        central.extend([0; 12]);
        central.extend(le32(offset));
        central.extend(name.as_bytes());
    }
    let cd_offset = out.len();
    out.extend(&central);
    out.extend(b"PK\x05\x06\0\0\0\0");
    out.extend(le16(entries.len()));
    out.extend(le16(entries.len()));
    out.extend(le32(central.len()));
    out.extend(le32(cd_offset));
    out.extend([0, 0]);
    out
}

fn doc_model(data: &[u8]) {
    let _ = rinse_doc_model::decode(data, &Limits::default(), |_| true);
}

#[test]
fn raw_messages() {
    let mut rng = Rng(0x5eed_0001);
    for fixture in CORPUS {
        for v in variants(fixture.raw, &mut rng, 4) {
            render_raw(&v);
        }
    }
}

#[test]
fn facts_inputs() {
    let mut rng = Rng(0x5eed_0004);
    let seeds: [&[u8]; 5] = [
        b"<mailto:u@example.com?subject=a%0D%0Ab>, <https://news.example.com/u> (c) <a@example.com>\0{\"@type\":\"Order\",\"orderNumber\":\"1\",\"url\":\"https://shop.example.com/\"}\0BEGIN:VEVENT\r\nORGANIZER;CN=x:mailto:a@example.com\r\nDTSTART:20261201T100000Z\r\nEND:VEVENT\0<p>-- Forwarded message --</p><a href=\"https://example.com/unsubscribe\" style=\"padding:4px\">x</a>\0PK\x05\x06",
        b"mx.example.org; dkim=pass header.d=example.com header.i=@example.com; spf=pass smtp.mailfrom=a@example.com\0[[[[{\"@graph\":[{\"@type\":[\"FlightReservation\"],\"reservationFor\":{\"departureTime\":\"2026-01-01T00:00:00+14:00\"}}]}]]]]",
        b"v=1; d=example.com; s=s; h=from:from; l=1; b=AAAA",
        b"\xe2\x80\xae<\xff@example.com>\0\0BEGIN:VEVENT\nUID:\xe2\x80\xae\nEND:VEVENT",
        b"",
    ];
    for seed in seeds {
        for v in variants(seed, &mut rng, 64) {
            facts(&v);
        }
    }
    for deflated in [false, true] {
        let mut seed = b"\0\0\0\0".to_vec();
        seed.extend(pkpass(deflated));
        let rendered = facts(&seed).expect("the seed renders");
        assert!(
            rendered
                .facts
                .structured
                .iter()
                .any(|i| matches!(i, StructuredItem::Pass(_))),
            "the seed reaches pass.json (deflated: {deflated})"
        );
        for v in variants(&seed, &mut rng, 256) {
            facts(&v);
        }
    }
    for fixture in CORPUS.iter().filter(|f| f.raw.len() < 16 << 10) {
        facts(fixture.raw);
    }
}

#[test]
fn worker_requests() {
    let mut rng = Rng(0x5eed_0002);
    for fixture in CORPUS.iter().filter(|f| f.raw.len() < 64 << 10) {
        let render = framed(
            OP_RENDER,
            postcard::to_stdvec(&render_request(fixture.raw)).unwrap(),
        );
        let part = framed(
            OP_DECODE_PART,
            postcard::to_stdvec(&PartRequest {
                raw: Bytes::copy_from_slice(fixture.raw),
                part: 1,
                limits: ContentLimits::default(),
            })
            .unwrap(),
        );
        for seed in [render, part] {
            for v in variants(&seed, &mut rng, 4) {
                worker_request(&v);
            }
        }
    }
    for lying in [
        vec![OP_RENDER, 0xff, 0xff, 0xff, 0xff, 0x0f],
        vec![OP_DECODE_PART, 0xff, 0xff, 0xff, 0xff, 0x0f],
        vec![2],
        Vec::new(),
    ] {
        worker_request(&lying);
    }
}

#[test]
fn host_responses_and_documents() {
    let mut rng = Rng(0x5eed_0003);
    for fixture in CORPUS.iter().filter(|f| f.raw.len() < 64 << 10) {
        let response = handle(&framed(
            OP_RENDER,
            postcard::to_stdvec(&render_request(fixture.raw)).unwrap(),
        ));
        let Some((&STATUS_OK, body)) = response.split_first() else {
            continue;
        };
        let rendered: Rendered = postcard::from_bytes(body).unwrap();
        let document = rinse_doc_model::encode(&rendered.body).unwrap();
        let wrapped = postcard::to_stdvec(&Ok::<_, ContentError>(rendered)).unwrap();
        for seed in [body.to_vec(), wrapped] {
            for v in variants(&seed, &mut rng, 16) {
                host_response(&v);
            }
        }
        for v in variants(&document, &mut rng, 16) {
            doc_model(&v);
        }
    }
    for lying in [
        vec![0xff, 0xff, 0xff, 0xff, 0x0f],
        vec![0, 0xff, 0xff, 0xff, 0xff, 0x0f],
        vec![1; 1 << 16],
    ] {
        host_response(&lying);
        doc_model(&lying);
    }
}
