//! Conformance suite for [`Content`]: every implementation runs [`run`] in its tests.
//!
//! The corpus in `crates/mail/fixtures/hostile` is embedded at compile time; its README says
//! what each message attacks and what must happen to it.

use std::sync::Arc;

use bytes::Bytes;
use rinse_doc_model::{Block, Document, Limits};

use crate::facts::{
    AuthMethod, AuthOutcome, CalendarMethod, HeaderSignal, MAX_AUTH_RESULTS, MAX_REFERENCES,
    MAX_STRUCTURED_ITEMS, OrderStatus, PassStyle, StructuredItem, UnsubscribeTarget, When,
};
use crate::{
    AttachmentRisk, Content, ContentError, ContentLimits, LimitKind, PartRequest, RemoteImage,
    RenderOptions, RenderRequest, Rendered,
};

/// One message of the hostile corpus.
#[derive(Debug, Clone, Copy)]
pub struct Fixture {
    /// File name in `fixtures/hostile`.
    pub name: &'static str,
    /// The raw message.
    pub raw: &'static [u8],
}

macro_rules! fixtures {
    ($($name:literal),* $(,)?) => {
        &[$(Fixture {
            name: $name,
            raw: include_bytes!(concat!("../fixtures/hostile/", $name)),
        }),*]
    };
}

/// The hostile corpus.
pub const CORPUS: &[Fixture] = fixtures![
    "text-only.eml",
    "nested-multipart-bomb.eml",
    "huge-header.eml",
    "script-and-active-content.eml",
    "bidi-attachment-name.eml",
    "punycode-link.eml",
    "tracking-pixel.eml",
    "cid-image.eml",
    "data-image.eml",
    "malformed-base64.eml",
    "wrong-charset.eml",
    "eight-bit-garbage.eml",
    "deep-html-nesting.eml",
    "oversized-image.eml",
    "calendar-attachment.eml",
    "formatting-reconstruct-bomb.eml",
    "long-grapheme-header.eml",
    "cid-many-spellings.eml",
    "internal-remote-image.eml",
    "forged-auth-results.eml",
    "list-unsubscribe-injection.eml",
    "javascript-unsubscribe.eml",
    "gigantic-references.eml",
    "ld-json-bombs.eml",
    "ld-json-type-confusion.eml",
    "calendar-bidi-organizer.eml",
    "forward-and-footer.eml",
    "wallet-pass.eml",
];

/// A valid 6x2 PNG, the body of the remote image the suite provides for `cid-image.eml`.
pub const REMOTE_PNG: &[u8] = include_bytes!("../fixtures/images/remote-6x2.png");

/// The URL of the remote image in `cid-image.eml`.
pub const REMOTE_URL: &str = "https://images.example.com/banner.png";

const MARKER: &str = "XSS-MARKER";
const HIDDEN_MARKER: &str = "HIDDEN-MARKER";

/// A message that puts the pieces of `data` (split at zero bytes) where the facts are read
/// from: the first into `List-Unsubscribe`, `List-Id`, `Authentication-Results`,
/// `DKIM-Signature`, `In-Reply-To`, `References` and `Sender`, the second into a JSON-LD script,
/// the third into a `text/calendar` part, the fourth into the HTML body and the fifth into a
/// `.pkpass` attachment. Used by the `facts` fuzz target and the worker's untrusted-input tests.
pub fn facts_message(data: &[u8]) -> Vec<u8> {
    let mut pieces = data.splitn(5, |b| *b == 0);
    let mut next = || pieces.next().unwrap_or_default();
    let (header, ld, ics, html, pass) = (next(), next(), next(), next(), next());
    let mut m = Vec::new();
    m.extend_from_slice(b"From: a@example.com\r\n");
    for name in [
        "List-Unsubscribe",
        "List-Id",
        "Authentication-Results",
        "DKIM-Signature",
        "In-Reply-To",
        "References",
        "Sender",
    ] {
        m.extend_from_slice(name.as_bytes());
        m.extend_from_slice(b": ");
        m.extend_from_slice(header);
        m.extend_from_slice(b"\r\n");
    }
    m.extend_from_slice(b"Content-Type: multipart/mixed; boundary=\"=b=\"\r\n\r\n");
    m.extend_from_slice(b"--=b=\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<script type=\"application/ld+json\">");
    m.extend_from_slice(ld);
    m.extend_from_slice(b"</script>");
    m.extend_from_slice(html);
    m.extend_from_slice(b"\r\n--=b=\r\nContent-Type: text/calendar\r\n\r\n");
    m.extend_from_slice(ics);
    m.extend_from_slice(b"\r\n--=b=\r\nContent-Type: application/vnd.apple.pkpass\r\nContent-Transfer-Encoding: base64\r\n\r\n");
    for chunk in pass.chunks(57) {
        m.extend_from_slice(base64(chunk).as_bytes());
        m.extend_from_slice(b"\r\n");
    }
    m.extend_from_slice(b"--=b=--\r\n");
    m
}

fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(ABC[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The fixture with this file name. Panics for an unknown name.
pub fn fixture(name: &str) -> &'static [u8] {
    CORPUS
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.raw)
        .unwrap_or_else(|| panic!("no fixture {name}"))
}

fn request(raw: &[u8], original: bool) -> RenderRequest {
    RenderRequest {
        raw: Bytes::copy_from_slice(raw),
        options: RenderOptions {
            want_original_html: original,
            ..RenderOptions::default()
        },
        limits: ContentLimits::default(),
    }
}

/// Runs the whole suite. Panics with the fixture name on the first broken guarantee.
pub async fn run(content: Arc<dyn Content>) {
    for f in CORPUS {
        for original in [true, false] {
            let req = request(f.raw, original);
            match content.render(req.clone()).await {
                Ok(out) => {
                    check_rendered(f.name, &req, &out);
                    if original {
                        expectations(f.name, &out);
                    }
                }
                Err(e) => {
                    assert!(
                        matches!(e, ContentError::Malformed | ContentError::LimitExceeded(_)),
                        "{}: unexpected error {e:?}",
                        f.name
                    );
                    assert!(
                        tolerated_failure(f.name),
                        "{}: must render, got {e:?}",
                        f.name
                    );
                }
            }
        }
    }
    tight_limits(&content).await;
    input_too_large(&content).await;
    tiny_output(&content).await;
    remote_images(&content).await;
    decode_parts(&content).await;
    not_a_message(&content).await;
}

fn tolerated_failure(name: &str) -> bool {
    matches!(
        name,
        "nested-multipart-bomb.eml" | "malformed-base64.eml" | "eight-bit-garbage.eml"
    )
}

/// Checks the guarantees every successful render must keep, whatever the input: everything
/// [`verify_rendered`](crate::verify_rendered) checks, plus the output size, a postcard round
/// trip and the absence of script and hidden content.
pub fn check_rendered(name: &str, req: &RenderRequest, out: &Rendered) {
    if let Err(e) = crate::verify_rendered(req, out) {
        panic!("{name}: response fails verify_rendered: {e:?}");
    }
    let encoded = postcard::to_stdvec(out).expect("encodes");
    assert!(
        encoded.len() as u64 <= req.limits.max_output_bytes,
        "{name}: output within max_output_bytes"
    );
    let back: Rendered = postcard::from_bytes(&encoded).expect("decodes");
    assert_eq!(&back, out, "{name}: round-trips through postcard");
    let everything = format!("{out:?}");
    assert!(
        !everything.contains(MARKER),
        "{name}: content of scripts, styles, frames and templates never shows"
    );
    assert!(
        !format!("{:?}{}", out.body, out.text).contains(HIDDEN_MARKER),
        "{name}: content hidden with CSS stays out of the safe view"
    );
}

fn blocks_of(doc: &Document) -> Vec<&Block> {
    let mut out = Vec::new();
    let mut stack: Vec<&Block> = doc.blocks.iter().rev().collect();
    while let Some(b) = stack.pop() {
        out.push(b);
        match b {
            Block::Quote(children) => stack.extend(children.iter().rev()),
            Block::List { items, .. } => {
                for item in items.iter().rev() {
                    stack.extend(item.iter().rev());
                }
            }
            Block::Table { rows } => {
                for row in rows.iter().rev() {
                    for cell in row.iter().rev() {
                        stack.extend(cell.blocks.iter().rev());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn image_ids(doc: &Document) -> Vec<String> {
    blocks_of(doc)
        .into_iter()
        .filter_map(|b| match b {
            Block::Image(i) => Some(i.id.clone()),
            _ => None,
        })
        .collect()
}

fn link<'a>(out: &'a Rendered, href_prefix: &str) -> &'a crate::LinkInfo {
    out.links
        .iter()
        .find(|l| {
            l.href
                .as_ref()
                .is_some_and(|h| h.as_str().starts_with(href_prefix))
        })
        .unwrap_or_else(|| panic!("no link starting with {href_prefix}"))
}

fn no_bidi(s: &str) -> bool {
    !s.chars()
        .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200B}'))
}

fn expectations(name: &str, out: &Rendered) {
    let f = &out.findings;
    let facts = &out.facts;
    match name {
        "text-only.eml" => {
            assert!(out.text.contains("Hello Bob"));
            assert_eq!(out.headers.subject.as_deref(), Some("Plain text"));
            assert_eq!(out.headers.from[0].address, "ann@example.com");
            assert_eq!(out.headers.from[0].name.as_deref(), Some("Ann Sender"));
            assert_eq!(
                out.headers.message_id.as_deref(),
                Some("fixture@example.com")
            );
            assert!(out.headers.date.is_some());
            let l = link(out, "https://www.example.com/docs/notes");
            assert_eq!(
                l.href.as_ref().unwrap().as_str(),
                "https://www.example.com/docs/notes"
            );
            assert_eq!(l.warnings, Default::default());
            assert!(link(out, "mailto:").warnings == Default::default());
            assert!(
                blocks_of(&out.body)
                    .iter()
                    .any(|b| matches!(b, Block::Quote(_))),
                "quoted lines become a quote"
            );
            assert!(out.attachments.is_empty());
        }
        "nested-multipart-bomb.eml" => assert!(f.damaged_structure),
        "huge-header.eml" => {
            let subject = out.headers.subject.as_deref().unwrap_or_default();
            assert!(subject.chars().count() <= 1_000);
            assert!(f.header_text.truncated >= 1);
            assert!(postcard::to_stdvec(&out.headers).unwrap().len() < 256 << 10);
        }
        "script-and-active-content.eml" => {
            assert!(f.scripts_removed >= 1);
            assert!(f.active_content_removed >= 1);
            assert!(out.text.contains("Visible text"));
            assert!(out.original_html.is_some(), "this message can be sanitized");
            let removed = out
                .links
                .iter()
                .filter(|l| l.warnings.unsupported_scheme_removed)
                .count();
            assert!(
                removed >= 3,
                "javascript:, vbscript: and data: links are removed"
            );
            assert!(
                out.links
                    .iter()
                    .filter(|l| l.warnings.unsupported_scheme_removed)
                    .all(|l| l.href.is_none())
            );
            link(out, "https://www.example.com/ok");
        }
        "bidi-attachment-name.eml" => {
            assert_eq!(out.attachments.len(), 1);
            let a = &out.attachments[0];
            let file = a.file_name.as_deref().unwrap();
            assert!(!file.contains('\u{202E}'));
            assert!(file.ends_with(".exe"));
            assert_eq!(a.risk, AttachmentRisk::Executable);
            assert!(a.sniffed_type.is_some());
            assert!(f.header_text.bidi_controls >= 1);
        }
        "punycode-link.eml" => {
            let l = link(out, "https://xn--exmple-cua.com/");
            assert!(l.warnings.punycode && l.warnings.text_href_mismatch);
            assert_eq!(l.display_host.as_deref(), Some("ex\u{e4}mple.com"));
            let l = out
                .links
                .iter()
                .find(|l| l.warnings.mixed_script)
                .expect("the Cyrillic look-alike is flagged");
            assert!(l.warnings.punycode);
            assert!(link(out, "http://192.0.2.10/").warnings.ip_host);
            let l = out
                .links
                .iter()
                .find(|l| l.warnings.userinfo)
                .expect("userinfo is flagged");
            assert!(l.warnings.text_href_mismatch);
            assert_eq!(
                link(out, "https://www.example.com/fine").warnings,
                Default::default()
            );
        }
        "tracking-pixel.eml" => {
            assert!(f.tracking_pixels >= 3);
            assert!(out.images.is_empty());
            assert_eq!(out.remote_images, ["https://images.example.org/hero.png"]);
            assert!(f.remote_references >= 1);
        }
        "cid-image.eml" => {
            assert_eq!(out.images.len(), 1);
            assert_eq!(image_ids(&out.body), [out.images[0].id.clone()]);
            assert_eq!(out.remote_images, [REMOTE_URL]);
            let html = out.original_html.as_ref().expect("original HTML");
            assert!(
                html.html
                    .contains(&format!("peleda-image:{}", out.images[0].id))
            );
            assert!(html.html.contains("peleda-remote:0"));
            assert_eq!(html.remote_images, [REMOTE_URL]);
            assert!(out.attachments.iter().all(|a| a.inline));
        }
        "data-image.eml" => {
            assert_eq!(out.images.len(), 1);
            assert!(f.images_dropped >= 1);
        }
        "wrong-charset.eml" => assert!(out.text.contains("Caf")),
        "deep-html-nesting.eml" => {
            assert!(out.text.contains("before"));
            assert!(f.truncated, "parsing stops at the depth limit");
            assert!(out.original_html.is_none());
        }
        "oversized-image.eml" => {
            assert!(out.images.is_empty());
            assert!(f.images_dropped >= 1);
        }
        "formatting-reconstruct-bomb.eml" => {
            assert!(f.truncated, "the parser node budget cuts the part");
            assert!(out.original_html.is_none(), "a cut part is not sanitized");
        }
        "long-grapheme-header.eml" => {
            let subject = out.headers.subject.as_deref().unwrap_or_default();
            assert!(subject.chars().count() <= crate::DISPLAY_MAX_CHARS);
            let file = out.attachments[0].file_name.as_deref().unwrap_or_default();
            assert!(file.chars().count() <= crate::DISPLAY_MAX_CHARS);
            assert!(f.header_text.truncated >= 2);
        }
        "cid-many-spellings.eml" => {
            assert_eq!(out.images.len(), 1);
            assert_eq!(
                f.images_dropped, 0,
                "every spelling resolves to the one decoded part"
            );
            assert!(image_ids(&out.body).len() >= 2);
        }
        "internal-remote-image.eml" => {
            assert_eq!(out.remote_images, ["https://images.example.com/ok.png"]);
        }
        "forged-auth-results.eml" => {
            let auth = &facts.auth;
            assert_eq!(auth.field_counts.authentication_results, 23);
            assert_eq!(auth.results.len(), MAX_AUTH_RESULTS);
            assert!(auth.cap_hit);
            let top = &auth.results[0];
            assert_eq!(top.position, 0, "the top field keeps its position");
            assert_eq!(top.methods[0].method, AuthMethod::Dkim);
            assert_eq!(top.methods[0].result, AuthOutcome::Fail);
            assert_eq!(top.methods[0].domain.as_deref(), Some("bank.example.com"));
            assert_eq!(top.methods[1].domain.as_deref(), Some("bank.example.com"));
            assert_eq!(top.methods[2].result, AuthOutcome::Fail);
            let commented = &auth.results[1];
            assert_eq!(
                commented.methods.len(),
                1,
                "a pass inside a comment is no result"
            );
            assert_eq!(commented.methods[0].result, AuthOutcome::Neutral);
            assert_eq!(
                auth.results[2].position, 3,
                "the field with a bidi authserv-id is dropped"
            );
            assert!(auth.results.iter().all(|r| no_bidi(&r.authserv_id)));
            assert_eq!(auth.field_counts.dkim_signature, 3);
            assert_eq!(auth.signatures.len(), 1, "invalid tag-lists are dropped");
            let sig = &auth.signatures[0];
            assert_eq!(sig.d.as_deref(), Some("bank.example.com"));
            assert_eq!(sig.s.as_deref(), Some("sel1"));
            assert_eq!(sig.b_prefix.as_deref(), Some("AbCdEfGh"));
            assert_eq!((sig.signed.from, sig.signed.list_unsubscribe), (2, 1));
            assert!(sig.body_length);
        }
        "list-unsubscribe-injection.eml" => {
            let list = &facts.list;
            assert_eq!(list.unsubscribe.len(), 2, "{:?}", list.unsubscribe);
            let UnsubscribeTarget::Mailto(m) = &list.unsubscribe[0] else {
                panic!("the mailto with a bcc field is dropped, the plain one kept");
            };
            assert_eq!(
                m.address, "unsub@example.com",
                "the address with percent-encoded header syntax is dropped"
            );
            let subject = m.subject.as_deref().unwrap_or_default();
            assert!(!subject.contains(['\r', '\n']), "no header break survives");
            let UnsubscribeTarget::Https(url) = &list.unsubscribe[1] else {
                panic!("https target");
            };
            assert!(!url.as_str().contains(['\r', '\n']));
            assert!(list.one_click);
            let s = facts.header.signals;
            for signal in [
                HeaderSignal::ListId,
                HeaderSignal::ListPostNo,
                HeaderSignal::Unsubscribe,
                HeaderSignal::UnsubscribePost,
                HeaderSignal::PrecedenceBulk,
                HeaderSignal::FeedbackId,
                HeaderSignal::Esp,
            ] {
                assert!(s.contains(signal), "{signal:?}");
            }
            assert!(!s.contains(HeaderSignal::ListPost) && !s.contains(HeaderSignal::Noreply));
            assert_eq!(facts.header.list_id.as_deref(), Some("news.example.com"));
        }
        "javascript-unsubscribe.eml" => {
            assert!(
                facts.list.unsubscribe.is_empty(),
                "{:?}",
                facts.list.unsubscribe
            );
            assert!(!facts.list.one_click, "one-click needs an https target");
            let s = facts.header.signals;
            assert!(s.contains(HeaderSignal::Noreply) && s.contains(HeaderSignal::AutoSubmitted));
            assert!(s.contains(HeaderSignal::Unsubscribe));
        }
        "gigantic-references.eml" => {
            let t = &facts.thread;
            assert_eq!(t.references.len(), MAX_REFERENCES);
            assert!(t.references_cut);
            assert!(t.references[0].starts_with("id0."), "the root is kept");
            assert!(
                t.references[MAX_REFERENCES - 1].starts_with("id4999."),
                "the parent is kept"
            );
            assert!(
                t.in_reply_to
                    .as_deref()
                    .is_some_and(|id| id.starts_with("id4999."))
            );
        }
        "ld-json-bombs.eml" => {
            let order = facts
                .structured
                .iter()
                .find_map(|i| match i {
                    StructuredItem::Order(o) => Some(o),
                    _ => None,
                })
                .expect("the honest order in the head survives the bombs");
            assert_eq!(order.number.as_deref(), Some("A-1001"));
            assert_eq!(order.merchant.as_deref(), Some("Example Shop"));
            assert_eq!(order.status, Some(OrderStatus::Processing));
            assert_eq!(
                order.total.as_ref().map(|t| t.amount.as_str()),
                Some("25.00")
            );
            assert!(matches!(order.date, Some(When::Instant(_))));
            assert!(facts.structured.len() <= MAX_STRUCTURED_ITEMS);
            assert!(out.text.contains("Order confirmed"));
            assert!(
                !out.text.contains("@type"),
                "JSON-LD never reaches the body"
            );
        }
        "ld-json-type-confusion.eml" => {
            let items = &facts.structured;
            assert_eq!(items.len(), 4, "{items:?}");
            let StructuredItem::Order(o) = &items[0] else {
                panic!("{items:?}");
            };
            assert_eq!(
                (&o.number, &o.total, &o.merchant, &o.date, &o.url),
                (&None, &None, &None, &None, &None)
            );
            let StructuredItem::Reservation(r) = &items[1] else {
                panic!("{items:?}");
            };
            assert_eq!((&r.number, &r.url), (&None, &None));
            let StructuredItem::Action(a) = &items[2] else {
                panic!("the javascript: action is dropped: {items:?}");
            };
            assert_eq!(a.url.as_str(), "https://shop.example.com/o/1");
            assert!(a.name.as_deref().is_some_and(no_bidi));
            let StructuredItem::Invoice(i) = &items[3] else {
                panic!("{items:?}");
            };
            assert_eq!((&i.total, &i.due), (&None, &None));
        }
        "calendar-bidi-organizer.eml" => {
            let inv = facts.invitation.as_ref().expect("invitation");
            assert_eq!(inv.method, CalendarMethod::Request);
            assert_eq!(inv.uid.as_deref(), Some("meeting-1@example.com"));
            let org = inv.organizer.as_ref().expect("organizer");
            assert_eq!(org.address, "ann@example.com");
            assert!(org.name.as_deref().is_some_and(no_bidi));
            assert!(
                inv.summary
                    .as_deref()
                    .is_some_and(|s| no_bidi(s) && s.contains("room 4"))
            );
            assert!(inv.location.as_deref().is_some_and(no_bidi));
            assert!(matches!(inv.start, Some(When::Local(_))));
            assert_eq!(inv.time_zone.as_deref(), Some("Europe/Vilnius"));
            assert_eq!(inv.attendees, 1);
        }
        "forward-and-footer.eml" => {
            let lay = &facts.layout;
            let forward = lay.forward_at.expect("forward marker");
            let footer = lay.footer_at.expect("footer");
            assert!(forward < footer);
            let place = |prefix: &str| {
                let i = out
                    .links
                    .iter()
                    .position(|l| {
                        l.href
                            .as_ref()
                            .is_some_and(|h| h.as_str().starts_with(prefix))
                    })
                    .unwrap_or_else(|| panic!("no link {prefix}"));
                &lay.links[i]
            };
            let track = place("https://shop.example.com/track");
            assert!(track.button_like && track.below_forward && !track.in_footer);
            assert_eq!(track.aria_label.as_deref(), Some("Track your parcel"));
            let blog = place("https://shop.example.com/blog");
            assert!(!blog.button_like && !blog.in_footer);
            let unsub = place("https://shop.example.com/unsubscribe");
            assert!(unsub.in_footer && unsub.below_forward && !unsub.button_like);
        }
        "wallet-pass.eml" => {
            let passes: Vec<_> = facts
                .structured
                .iter()
                .filter_map(|i| match i {
                    StructuredItem::Pass(p) => Some(p),
                    _ => None,
                })
                .collect();
            assert_eq!(passes.len(), 1, "the zip bomb pass is refused");
            assert_eq!(passes[0].style, PassStyle::BoardingPass);
            assert!(no_bidi(&passes[0].organization));
            assert!(passes[0].relevant.is_some());
        }
        "calendar-attachment.eml" => {
            let a = out
                .attachments
                .iter()
                .find(|a| a.risk == AttachmentRisk::Calendar)
                .expect("calendar attachment");
            assert_eq!(a.file_name.as_deref(), Some("invite.ics"));
        }
        _ => {}
    }
}

async fn tight_limits(content: &Arc<dyn Content>) {
    let doc = Limits {
        max_depth: 4,
        max_blocks: 8,
        max_inlines: 30,
        max_text_bytes: 200,
        max_links: 2,
        max_images: 1,
        max_url_len: 64,
        max_table_rows: 2,
        max_table_cols: 2,
        max_image_px: 4,
    };
    for f in CORPUS {
        let mut req = request(f.raw, true);
        req.limits.doc = doc;
        req.options.max_image_px = 3;
        req.options.remote_images = vec![RemoteImage {
            url: REMOTE_URL.into(),
            bytes: Bytes::from_static(REMOTE_PNG),
        }];
        match content.render(req.clone()).await {
            Ok(out) => check_rendered(f.name, &req, &out),
            Err(e) => assert!(
                matches!(e, ContentError::Malformed | ContentError::LimitExceeded(_)),
                "{}: tight limits gave {e:?}",
                f.name
            ),
        }
    }
}

async fn input_too_large(content: &Arc<dyn Content>) {
    for f in CORPUS {
        let mut req = request(f.raw, false);
        req.limits.max_input_bytes = f.raw.len() as u64 - 1;
        assert_eq!(
            content.render(req.clone()).await,
            Err(ContentError::InputTooLarge),
            "{}",
            f.name
        );
        let part = PartRequest {
            raw: req.raw,
            part: 1,
            limits: req.limits,
        };
        assert_eq!(
            content.decode_part(part).await,
            Err(ContentError::InputTooLarge),
            "{}",
            f.name
        );
    }
}

async fn tiny_output(content: &Arc<dyn Content>) {
    for f in CORPUS {
        let mut req = request(f.raw, true);
        req.limits.max_output_bytes = 64;
        match content.render(req.clone()).await {
            Ok(out) => check_rendered(f.name, &req, &out),
            Err(e) => assert!(
                matches!(
                    e,
                    ContentError::LimitExceeded(LimitKind::Output) | ContentError::Malformed
                ),
                "{}: tiny output gave {e:?}",
                f.name
            ),
        }
    }
}

async fn remote_images(content: &Arc<dyn Content>) {
    let mut req = request(fixture("cid-image.eml"), true);
    req.options.remote_images = vec![
        RemoteImage {
            url: REMOTE_URL.into(),
            bytes: Bytes::from_static(REMOTE_PNG),
        },
        RemoteImage {
            url: "https://images.example.com/unused.png".into(),
            bytes: Bytes::from_static(b"not an image"),
        },
    ];
    let out = content.render(req.clone()).await.expect("renders");
    check_rendered("cid-image.eml with remote image", &req, &out);
    assert_eq!(
        out.images.len(),
        2,
        "the provided remote image is re-encoded"
    );
    assert!(out.remote_images.is_empty());
    assert_eq!(image_ids(&out.body).len(), 2);
    let html = out.original_html.expect("original HTML");
    for image in &out.images {
        assert!(html.html.contains(&format!("peleda-image:{}", image.id)));
    }

    req.options.remote_images = vec![RemoteImage {
        url: REMOTE_URL.into(),
        bytes: Bytes::from_static(b"\x89PNG\r\n\x1a\ngarbage"),
    }];
    let out = content.render(req.clone()).await.expect("renders");
    check_rendered("cid-image.eml with broken remote image", &req, &out);
    assert_eq!(out.images.len(), 1);
    assert!(out.findings.images_dropped >= 1);
}

async fn decode_parts(content: &Arc<dyn Content>) {
    for f in CORPUS {
        let req = request(f.raw, false);
        let Ok(out) = content.render(req.clone()).await else {
            continue;
        };
        for a in &out.attachments {
            let decoded = content
                .decode_part(PartRequest {
                    raw: req.raw.clone(),
                    part: a.part,
                    limits: req.limits,
                })
                .await
                .unwrap_or_else(|e| panic!("{}: part {} gave {e:?}", f.name, a.part));
            assert_eq!(decoded.part, a.part);
            assert_eq!(decoded.bytes.len() as u64, a.size, "{}", f.name);
            assert_eq!(decoded.file_name, a.file_name, "{}", f.name);
            assert_eq!(decoded.media_type, a.declared_type, "{}", f.name);
            match f.name {
                "bidi-attachment-name.eml" => assert!(decoded.bytes.starts_with(b"MZ")),
                "calendar-attachment.eml" => {
                    assert!(decoded.bytes.starts_with(b"BEGIN:VCALENDAR"))
                }
                _ => {}
            }
            let mut small = req.limits;
            small.max_output_bytes = a.size.saturating_sub(1);
            if a.size > 0 {
                assert_eq!(
                    content
                        .decode_part(PartRequest {
                            raw: req.raw.clone(),
                            part: a.part,
                            limits: small,
                        })
                        .await,
                    Err(ContentError::LimitExceeded(LimitKind::Output)),
                    "{}",
                    f.name
                );
            }
        }
        assert_eq!(
            content
                .decode_part(PartRequest {
                    raw: req.raw.clone(),
                    part: u32::MAX,
                    limits: req.limits,
                })
                .await,
            Err(ContentError::PartNotFound),
            "{}",
            f.name
        );
    }
    assert_eq!(
        content
            .decode_part(PartRequest {
                raw: Bytes::from_static(fixture("cid-image.eml")),
                part: 0,
                limits: ContentLimits::default(),
            })
            .await,
        Err(ContentError::PartNotFound),
        "a multipart container is not a part to save"
    );
}

async fn not_a_message(content: &Arc<dyn Content>) {
    for raw in [&b""[..], b"\x00", b"no header and no blank line"] {
        let req = request(raw, true);
        match content.render(req.clone()).await {
            Ok(out) => check_rendered("not a message", &req, &out),
            Err(e) => assert_eq!(e, ContentError::Malformed),
        }
    }
}
