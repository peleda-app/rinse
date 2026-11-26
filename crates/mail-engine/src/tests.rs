use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use rinse_doc_model::{Align, Tone};
use rinse_mail::testing::{self, fixture};
use rinse_mail::{Content, ContentLimits, RenderOptions, Rendered};

use super::*;

struct InProcess;

#[async_trait]
impl Content for InProcess {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError> {
        render(&request)
    }

    async fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError> {
        decode_part(&request)
    }
}

#[test]
fn conformance() {
    futures::executor::block_on(testing::run(Arc::new(InProcess)));
}

fn html(body: &str) -> Rendered {
    let raw = format!(
        "From: a@example.com\r\nSubject: t\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}"
    );
    render(&RenderRequest {
        raw: Bytes::from(raw),
        options: RenderOptions {
            want_original_html: true,
            ..RenderOptions::default()
        },
        limits: ContentLimits::default(),
    })
    .unwrap()
}

#[test]
fn styles_map_to_the_model() {
    let out = html(
        r#"<h2 style="text-align:center">Title</h2>
        <p><b>bold</b> <span style="color:#d00">red</span> <a href="https://example.com/x">link</a></p>
        <ul><li>one</li><li>two</li></ul>
        <table border="1"><tr><th>h</th><td>d</td></tr></table>
        <pre>a
  b</pre><hr>"#,
    );
    let blocks = &out.body.blocks;
    assert!(matches!(
        &blocks[0],
        Block::Heading {
            level: 2,
            align: Align::Center,
            ..
        }
    ));
    let Block::Paragraph { inlines, .. } = &blocks[1] else {
        panic!("paragraph: {blocks:?}");
    };
    assert!(
        inlines
            .iter()
            .any(|i| matches!(i, Inline::Text { style, .. } if style.bold))
    );
    assert!(
        inlines
            .iter()
            .any(|i| matches!(i, Inline::Text { style, .. } if style.tone == Some(Tone::Red)))
    );
    assert!(inlines.iter().any(|i| matches!(i, Inline::Link { .. })));
    assert!(matches!(&blocks[2], Block::List { items, ordered: false } if items.len() == 2));
    assert!(matches!(&blocks[3], Block::Table { rows } if rows[0].len() == 2 && rows[0][0].header));
    assert!(matches!(&blocks[4], Block::Preformatted(t) if t == "a\n  b"));
    assert!(matches!(&blocks[5], Block::Divider));
    assert_eq!(out.links.len(), 1);
}

#[test]
fn layout_tables_flatten() {
    let out = html(
        "<table><tr><td>left</td><td><table><tr><td>inner</td></tr></table></td></tr></table>",
    );
    assert!(
        out.body
            .blocks
            .iter()
            .all(|b| matches!(b, Block::Paragraph { .. }))
    );
    assert!(out.text.contains("left") && out.text.contains("inner"));
}

#[test]
fn bidi_and_invisible_characters_are_removed_from_the_body() {
    let out = html("<p>pay\u{202E}lapyap\u{200B}now</p>");
    assert!(out.text.contains("paylapyapnow"));
    assert_eq!(out.findings.body_text.bidi_controls, 1);
    assert_eq!(out.findings.body_text.invisible, 1);
}

#[test]
fn links_continue_across_blocks() {
    let out = html(r#"<a href="https://example.com/"><div>one</div><div>two</div></a>"#);
    let links = out
        .body
        .blocks
        .iter()
        .filter(|b| matches!(b, Block::Paragraph { inlines, .. } if matches!(inlines[0], Inline::Link { .. })))
        .count();
    assert_eq!(links, 2);
}

#[test]
fn decode_part_of_a_text_message() {
    let raw = Bytes::from_static(fixture("calendar-attachment.eml"));
    let out = render(&RenderRequest {
        raw: raw.clone(),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    })
    .unwrap();
    let part = out.attachments[0].part;
    let decoded = decode_part(&PartRequest {
        raw,
        part,
        limits: ContentLimits::default(),
    })
    .unwrap();
    assert_eq!(decoded.media_type, "text/calendar");
}
