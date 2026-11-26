use super::*;

const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn text(s: &str) -> Inline {
    Inline::Text {
        text: s.to_owned(),
        style: Style::default(),
    }
}

fn para(inlines: Vec<Inline>) -> Block {
    Block::Paragraph {
        align: Align::Start,
        inlines,
    }
}

fn sample() -> Document {
    Document {
        version: SCHEMA_VERSION,
        blocks: vec![
            Block::Heading {
                level: 2,
                align: Align::Center,
                inlines: vec![text("Hello")],
            },
            para(vec![
                text("See "),
                Inline::Link {
                    href: SafeUrl::new("https://www.example.com/a?b=c", 2048).unwrap(),
                    inlines: vec![Inline::Text {
                        text: "docs".into(),
                        style: Style {
                            bold: true,
                            tone: Some(Tone::Blue),
                            ..Style::default()
                        },
                    }],
                },
                Inline::LineBreak,
            ]),
            Block::Quote(vec![para(vec![text("quoted")])]),
            Block::List {
                ordered: true,
                items: vec![vec![para(vec![text("one")])], vec![para(vec![text("two")])]],
            },
            Block::Table {
                rows: vec![vec![
                    Cell {
                        header: true,
                        blocks: vec![para(vec![text("h")])],
                    },
                    Cell {
                        header: false,
                        blocks: vec![],
                    },
                ]],
            },
            Block::Preformatted("line 1\n\tline 2".into()),
            Block::Image(ImageRef {
                id: ID.into(),
                alt: "logo".into(),
                width: 10,
                height: 20,
            }),
            Block::Divider,
        ],
    }
}

fn known(id: &str) -> bool {
    id == ID
}

#[test]
fn sample_is_valid_and_round_trips() {
    let doc = sample();
    validate(&doc, &Limits::default(), known).unwrap();
    let bytes = encode(&doc).unwrap();
    assert_eq!(bytes[0], FORMAT_VERSION);
    assert_eq!(decode(&bytes, &Limits::default(), known).unwrap(), doc);
}

#[test]
fn safe_url_schemes() {
    for ok in [
        "https://example.com",
        "HTTP://example.com/x",
        "mailto:a@example.com",
        "tel:+15550100",
    ] {
        assert!(SafeUrl::new(ok, 100).is_some(), "{ok}");
    }
    for bad in [
        "javascript:alert(1)",
        "data:text/html,x",
        "file:///etc/passwd",
        "https:/example.com",
        "https://",
        "https://exa mple.com",
        "https://example.com/\u{202E}",
        "https://example.com/\u{200B}",
        "mailto:",
        "relative/path",
        "peleda-image:abc",
    ] {
        assert!(SafeUrl::new(bad, 100).is_none(), "{bad}");
    }
    assert!(SafeUrl::new("https://example.com/long", 10).is_none());
}

#[test]
fn rejects_unsafe_text() {
    for (bad, violation) in [
        ("a\u{202E}b", Violation::BidiControl),
        ("a\u{200B}b", Violation::Invisible),
        ("a\nb", Violation::Control),
        ("a\u{7}b", Violation::Control),
    ] {
        let doc = Document {
            version: SCHEMA_VERSION,
            blocks: vec![para(vec![text(bad)])],
        };
        assert_eq!(validate(&doc, &Limits::default(), known), Err(violation));
    }
}

#[test]
fn rejects_wrong_version_and_heading_level() {
    let mut doc = sample();
    doc.version = 2;
    assert_eq!(
        validate(&doc, &Limits::default(), known),
        Err(Violation::Version)
    );
    let doc = Document {
        version: SCHEMA_VERSION,
        blocks: vec![Block::Heading {
            level: 7,
            align: Align::Start,
            inlines: vec![],
        }],
    };
    assert_eq!(
        validate(&doc, &Limits::default(), known),
        Err(Violation::HeadingLevel)
    );
}

#[test]
fn rejects_unknown_and_malformed_images() {
    let image = |id: &str, w| Document {
        version: SCHEMA_VERSION,
        blocks: vec![Block::Image(ImageRef {
            id: id.into(),
            alt: String::new(),
            width: w,
            height: 1,
        })],
    };
    let l = Limits::default();
    assert_eq!(
        validate(&image(ID, 1), &l, |_| false),
        Err(Violation::UnknownImage)
    );
    assert_eq!(
        validate(&image("abc", 1), &l, known),
        Err(Violation::ImageId)
    );
    assert_eq!(
        validate(&image(&ID.to_uppercase(), 1), &l, |_| true),
        Err(Violation::ImageId)
    );
    assert_eq!(
        validate(&image(ID, 0), &l, known),
        Err(Violation::ImageSize)
    );
    assert_eq!(
        validate(&image(ID, 5000), &l, known),
        Err(Violation::ImageSize)
    );
}

#[test]
fn enforces_counts() {
    let doc = sample();
    let check = |f: fn(&mut Limits), v: Violation| {
        let mut l = Limits::default();
        f(&mut l);
        assert_eq!(validate(&doc, &l, known), Err(v));
    };
    check(|l| l.max_blocks = 3, Violation::Blocks);
    check(|l| l.max_inlines = 2, Violation::Inlines);
    check(|l| l.max_text_bytes = 10, Violation::TextBytes);
    check(|l| l.max_links = 0, Violation::Links);
    check(|l| l.max_images = 0, Violation::Images);
    check(|l| l.max_url_len = 10, Violation::UrlLength);
    check(|l| l.max_table_cols = 1, Violation::TableSize);
    check(|l| l.max_table_rows = 0, Violation::TableSize);
    check(|l| l.max_depth = 2, Violation::Depth);
}

fn nested(depth: usize) -> Document {
    let mut block = para(vec![text("x")]);
    for _ in 0..depth {
        block = Block::Quote(vec![block]);
    }
    Document {
        version: SCHEMA_VERSION,
        blocks: vec![block],
    }
}

#[test]
fn depth_limit_counts_levels() {
    let l = Limits {
        max_depth: 5,
        ..Limits::default()
    };
    assert!(validate(&nested(3), &l, known).is_ok());
    assert_eq!(validate(&nested(4), &l, known), Err(Violation::Depth));
    let huge = Limits {
        max_depth: usize::MAX,
        ..Limits::default()
    };
    assert_eq!(validate(&nested(40), &huge, known), Err(Violation::Depth));
}

#[test]
fn encoding_refuses_too_deep_documents() {
    assert!(encode(&nested(WIRE_MAX_DEPTH + 5)).is_err());
}

#[test]
fn deeply_nested_wire_input_fails_without_recursion() {
    let mut bytes = vec![FORMAT_VERSION];
    bytes.extend(postcard::to_stdvec(&SCHEMA_VERSION).unwrap());
    bytes.push(1);
    let levels = 200_000u32;
    let mut nodes = postcard::to_stdvec(&(levels + 1)).unwrap();
    for _ in 0..levels {
        nodes.extend([2u8, 1]);
    }
    bytes.extend(nodes);
    bytes.push(10);
    assert_eq!(
        decode(&bytes, &Limits::default(), known),
        Err(CodecError::Malformed)
    );
}

#[test]
fn decode_rejects_garbage_and_trailing_nodes() {
    assert_eq!(
        decode(&[], &Limits::default(), known),
        Err(CodecError::Malformed)
    );
    assert_eq!(
        decode(&[9, 0], &Limits::default(), known),
        Err(CodecError::Format)
    );
    for seed in 0..2000u32 {
        let mut x = seed.wrapping_mul(2_654_435_761);
        let bytes: Vec<u8> = (0..(seed % 64))
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let mut input = vec![FORMAT_VERSION];
        input.extend(bytes);
        let _ = decode(&input, &Limits::default(), known);
    }
    let mut doc_bytes = encode(&sample()).unwrap();
    doc_bytes.push(0);
    assert!(decode(&doc_bytes, &Limits::default(), known).is_err());
}

#[test]
fn decode_validates() {
    let doc = Document {
        version: SCHEMA_VERSION,
        blocks: vec![para(vec![text("a\u{202E}b")])],
    };
    let bytes = encode(&doc).unwrap();
    assert_eq!(
        decode(&bytes, &Limits::default(), known),
        Err(CodecError::Invalid(Violation::BidiControl))
    );
}

fn empty_cells(rows: usize, cols: usize) -> Block {
    Block::Table {
        rows: (0..rows)
            .map(|_| {
                (0..cols)
                    .map(|_| Cell {
                        header: false,
                        blocks: vec![],
                    })
                    .collect()
            })
            .collect(),
    }
}

#[test]
fn items_rows_and_cells_count_as_blocks() {
    let l = Limits::default();
    let item = || vec![para(vec![text("x")])];
    let list = |n: usize| Document {
        version: SCHEMA_VERSION,
        blocks: vec![Block::List {
            ordered: false,
            items: (0..n).map(|_| item()).collect(),
        }],
    };
    assert!(validate(&list(l.max_blocks / 2 - 1), &l, known).is_ok());
    assert_eq!(
        validate(&list(l.max_blocks), &l, known),
        Err(Violation::Blocks)
    );
    let tables = Document {
        version: SCHEMA_VERSION,
        blocks: (0..10).map(|_| empty_cells(1_000, 64)).collect(),
    };
    assert_eq!(validate(&tables, &l, known), Err(Violation::Blocks));
    let small = Document {
        version: SCHEMA_VERSION,
        blocks: vec![empty_cells(3, 3)],
    };
    assert!(validate(&small, &l, known).is_ok());
}

#[test]
fn rejects_empty_containers() {
    let l = Limits::default();
    let doc = |b: Block| Document {
        version: SCHEMA_VERSION,
        blocks: vec![b],
    };
    let empty_items = Block::List {
        ordered: false,
        items: vec![vec![]; 5_000_000],
    };
    assert_eq!(
        validate(&doc(empty_items), &l, known),
        Err(Violation::Empty)
    );
    let no_items = Block::List {
        ordered: true,
        items: vec![],
    };
    assert_eq!(validate(&doc(no_items), &l, known), Err(Violation::Empty));
    assert_eq!(
        validate(&doc(Block::Table { rows: vec![] }), &l, known),
        Err(Violation::Empty)
    );
    assert_eq!(
        validate(&doc(empty_cells(2, 0)), &l, known),
        Err(Violation::Empty)
    );
}

#[test]
fn safe_url_deserialization_checks() {
    let ok: SafeUrl =
        postcard::from_bytes(&postcard::to_stdvec("https://example.com/").unwrap()).unwrap();
    assert_eq!(ok.as_str(), "https://example.com/");
    for bad in [
        "javascript:alert(1)",
        "https://exa mple.com/",
        "data:text/html,x",
        "",
    ] {
        let bytes = postcard::to_stdvec(bad).unwrap();
        assert!(postcard::from_bytes::<SafeUrl>(&bytes).is_err(), "{bad}");
    }
    let long = format!("https://example.com/{}", "a".repeat(SAFE_URL_MAX_LEN));
    assert!(postcard::from_bytes::<SafeUrl>(&postcard::to_stdvec(&long).unwrap()).is_err());
}

#[test]
fn attack_node_flood_stops_while_decoding() {
    let limits = Limits::default();
    let flood = Document {
        version: SCHEMA_VERSION,
        blocks: vec![Block::Divider; limits.max_blocks + limits.max_inlines + 1],
    };
    let bytes = encode(&flood).unwrap();
    assert!(matches!(
        decode(&bytes, &limits, known),
        Err(CodecError::Malformed)
    ));
    let at_budget = Document {
        version: SCHEMA_VERSION,
        blocks: vec![Block::Divider; limits.max_blocks],
    };
    let bytes = encode(&at_budget).unwrap();
    assert_eq!(decode(&bytes, &limits, known), Ok(at_budget));
}

#[test]
fn decode_budget_ends_with_its_scope() {
    let bytes = postcard::to_stdvec(&vec![0u8; 3]).unwrap();
    let bounded = |b: &[u8]| {
        let mut d = postcard::Deserializer::from_bytes(b);
        bounded_vec::<_, u8>(&mut d).is_ok()
    };
    assert!(!with_decode_budget(2, || bounded(&bytes)));
    assert!(with_decode_budget(3, || bounded(&bytes)));
    assert!(bounded(&bytes));
}
