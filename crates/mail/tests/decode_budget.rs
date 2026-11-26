//! Decoding a worker's render response stays within memory proportional to its size.

use rinse_doc_model::{Block, Document, Inline, SCHEMA_VERSION, Style};
use rinse_mail::{
    ContentError, ContentLimits, Findings, Headers, LinkInfo, LinkWarnings, Rendered,
    decode_render_response,
};

fn empty() -> Rendered {
    Rendered {
        headers: Headers::default(),
        body: Document::new(),
        text: String::new(),
        images: Vec::new(),
        remote_images: Vec::new(),
        attachments: Vec::new(),
        links: Vec::new(),
        original_html: None,
        findings: Findings::default(),
        facts: Default::default(),
    }
}

fn decode(out: &Rendered) -> Result<Rendered, ContentError> {
    let wire = postcard::to_stdvec(&Ok::<_, ContentError>(out)).unwrap();
    decode_render_response::<Result<Rendered, ContentError>>(&wire, &ContentLimits::default())
        .and_then(|r| r)
}

#[test]
fn attack_lying_worker_divider_flood_is_refused_while_decoding() {
    let mut out = empty();
    out.body = Document {
        version: SCHEMA_VERSION,
        blocks: vec![Block::Divider; 2_000_000],
    };
    assert!(matches!(decode(&out), Err(ContentError::Crashed)));
}

#[test]
fn attack_lying_worker_empty_link_flood_is_refused_while_decoding() {
    let mut out = empty();
    out.links = vec![
        LinkInfo {
            href: None,
            display_host: None,
            text: String::new(),
            warnings: LinkWarnings::default(),
        };
        1_000_000
    ];
    assert!(matches!(decode(&out), Err(ContentError::Crashed)));
}

#[test]
fn a_response_at_the_default_limits_decodes() {
    let limits = ContentLimits::default().doc;
    let per_block = limits.max_inlines / limits.max_blocks;
    let mut out = empty();
    out.body = Document {
        version: SCHEMA_VERSION,
        blocks: vec![
            Block::Paragraph {
                align: Default::default(),
                inlines: vec![
                    Inline::Text {
                        text: "a".into(),
                        style: Style::default(),
                    };
                    per_block
                ],
            };
            limits.max_blocks
        ],
    };
    out.links = vec![
        LinkInfo {
            href: None,
            display_host: None,
            text: String::new(),
            warnings: LinkWarnings::default(),
        };
        limits.max_links
    ];
    out.facts.layout.links = vec![Default::default(); limits.max_links];
    assert!(decode(&out) == Ok(out));
}
