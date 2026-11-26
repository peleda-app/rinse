use bytes::Bytes;
use rinse_doc_model::{Document, Inline, Style};

use super::*;
use crate::{ContentLimits, Findings, Headers, LinkInfo, LinkWarnings, RenderOptions};

fn request() -> RenderRequest {
    RenderRequest {
        raw: Bytes::new(),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    }
}

fn rendered(facts: MessageFacts) -> Rendered {
    Rendered {
        headers: Headers::default(),
        body: Document {
            version: rinse_doc_model::SCHEMA_VERSION,
            blocks: vec![Block::Paragraph {
                align: Default::default(),
                inlines: vec![Inline::Text {
                    text: "hi".into(),
                    style: Style::default(),
                }],
            }],
        },
        text: "hi".into(),
        images: Vec::new(),
        remote_images: Vec::new(),
        attachments: Vec::new(),
        links: Vec::new(),
        original_html: None,
        findings: Findings::default(),
        facts,
    }
}

fn url(s: &str) -> SafeUrl {
    SafeUrl::new(s, 2048).unwrap()
}

fn date(year: u16, month: u8, day: u8) -> CalendarDate {
    CalendarDate { year, month, day }
}

fn good() -> MessageFacts {
    let mut signals = HeaderSignals::default();
    signals.insert(HeaderSignal::ListId);
    signals.insert(HeaderSignal::Noreply);
    signals.insert(HeaderSignal::Unsubscribe);
    signals.insert(HeaderSignal::UnsubscribePost);
    MessageFacts {
        header: HeaderFacts {
            signals,
            from_fields: 1,
            from_addresses: 1,
            sender: Some(MailAddress {
                name: Some("News".into()),
                address: "news@example.com".into(),
            }),
            list_id: Some("news.example.com".into()),
        },
        auth: AuthFacts {
            results: vec![AuthResult {
                authserv_id: "mx.example.org".into(),
                position: 0,
                methods: vec![AuthMethodResult {
                    method: AuthMethod::Dkim,
                    result: AuthOutcome::Pass,
                    domain: Some("example.com".into()),
                    identity: Some("@example.com".into()),
                }],
            }],
            signatures: vec![DkimTags {
                d: Some("example.com".into()),
                s: Some("s1".into()),
                b_prefix: Some("AbC1+/=x".into()),
                ..DkimTags::default()
            }],
            field_counts: FieldCounts {
                from: 1,
                list_unsubscribe: 1,
                list_unsubscribe_post: 1,
                authentication_results: 1,
                ..FieldCounts::default()
            },
            cap_hit: false,
        },
        list: ListFacts {
            unsubscribe: vec![
                UnsubscribeTarget::Https(url("https://news.example.com/u?id=1")),
                UnsubscribeTarget::Mailto(MailtoTarget {
                    address: "unsub@example.com".into(),
                    subject: Some("unsubscribe".into()),
                    body: None,
                }),
            ],
            one_click: true,
        },
        thread: ThreadFacts {
            in_reply_to: Some("a@example.com".into()),
            references: vec!["a@example.com".into()],
            references_cut: false,
        },
        structured: vec![
            StructuredItem::Order(Order {
                number: Some("A-1".into()),
                merchant: Some("Shop".into()),
                status: Some(OrderStatus::Processing),
                total: Some(Price {
                    amount: "12.50".into(),
                    currency: Some("EUR".into()),
                }),
                date: Some(When::Date(date(2026, 11, 25))),
                url: Some(url("https://shop.example.com/o/1")),
            }),
            StructuredItem::Action(Action {
                kind: ActionKind::View,
                name: Some("Open".into()),
                url: url("https://shop.example.com/o/1"),
            }),
        ],
        invitation: Some(InvitationFacts {
            method: CalendarMethod::Request,
            uid: Some("uid-1@example.com".into()),
            sequence: Some(0),
            summary: Some("Planning".into()),
            organizer: Some(MailAddress {
                name: Some("Ann".into()),
                address: "ann@example.com".into(),
            }),
            start: Some(When::Instant(1_796_000_000)),
            end: None,
            time_zone: None,
            location: None,
            status: Some(EventStatus::Confirmed),
            attendees: 2,
        }),
        layout: LayoutFacts {
            forward_at: Some(0),
            footer_at: None,
            links: Vec::new(),
        },
    }
}

fn check(f: MessageFacts) -> Result<(), ContentError> {
    verify_facts(&request(), &rendered(f))
}

#[test]
fn accepts_good_facts_and_defaults() {
    assert_eq!(check(good()), Ok(()));
    assert_eq!(check(MessageFacts::default()), Ok(()));
}

#[test]
fn rejects_each_broken_guarantee() {
    type Mutation = Box<dyn Fn(&mut MessageFacts)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "unknown signal bit",
            Box::new(|f| f.header.signals = HeaderSignals::from_bits(1 << 20)),
        ),
        (
            "bidi in sender name",
            Box::new(|f| f.header.sender.as_mut().unwrap().name = Some("a\u{202E}b".into())),
        ),
        (
            "whitespace in list id",
            Box::new(|f| f.header.list_id = Some("news example".into())),
        ),
        (
            "uppercase list id",
            Box::new(|f| f.header.list_id = Some("News.example.com".into())),
        ),
        (
            "too many results",
            Box::new(|f| {
                let r = f.auth.results[0].clone();
                f.auth.results = (0..=MAX_AUTH_RESULTS as u8)
                    .map(|p| AuthResult {
                        position: p,
                        ..r.clone()
                    })
                    .collect();
            }),
        ),
        (
            "positions not rising",
            Box::new(|f| {
                let r = f.auth.results[0].clone();
                f.auth.results.push(r);
            }),
        ),
        (
            "domain with a newline",
            Box::new(|f| f.auth.results[0].methods[0].domain = Some("a.example\ncom".into())),
        ),
        (
            "identity on spf",
            Box::new(|f| f.auth.results[0].methods[0].method = AuthMethod::Spf),
        ),
        (
            "domain on arc",
            Box::new(|f| {
                let m = &mut f.auth.results[0].methods[0];
                m.method = AuthMethod::Arc;
                m.identity = None;
            }),
        ),
        (
            "long b prefix",
            Box::new(|f| f.auth.signatures[0].b_prefix = Some("AbCdEfGhI".into())),
        ),
        (
            "javascript unsubscribe",
            Box::new(|f| f.list.unsubscribe[0] = UnsubscribeTarget::Https(url("mailto:x"))),
        ),
        (
            "http unsubscribe",
            Box::new(|f| {
                f.list.unsubscribe[0] = UnsubscribeTarget::Https(url("http://news.example.com/u"))
            }),
        ),
        (
            "internal unsubscribe host",
            Box::new(|f| {
                f.list.unsubscribe[0] =
                    UnsubscribeTarget::Https(url("https://169.254.169.254/latest"))
            }),
        ),
        (
            "two mailto addresses",
            Box::new(|f| {
                f.list.unsubscribe[1] = UnsubscribeTarget::Mailto(MailtoTarget {
                    address: "a@example.com,b@example.org".into(),
                    subject: None,
                    body: None,
                })
            }),
        ),
        (
            "header syntax in mailto address",
            Box::new(|f| {
                f.list.unsubscribe[1] = UnsubscribeTarget::Mailto(MailtoTarget {
                    address: "x?bcc=victim%40evil.example.org&a@example.com".into(),
                    subject: None,
                    body: None,
                })
            }),
        ),
        (
            "fragment in mailto address",
            Box::new(|f| {
                f.list.unsubscribe[1] = UnsubscribeTarget::Mailto(MailtoTarget {
                    address: "x#y/z@example.com".into(),
                    subject: None,
                    body: None,
                })
            }),
        ),
        (
            "result position past the field count",
            Box::new(|f| f.auth.results[0].position = 1),
        ),
        (
            "from fields disagree with the count",
            Box::new(|f| f.header.from_fields = 2),
        ),
        (
            "crlf in mailto subject",
            Box::new(|f| {
                f.list.unsubscribe[1] = UnsubscribeTarget::Mailto(MailtoTarget {
                    address: "a@example.com".into(),
                    subject: Some("x\r\nBcc: v@example.org".into()),
                    body: None,
                })
            }),
        ),
        (
            "one click without https",
            Box::new(|f| {
                f.list.unsubscribe.remove(0);
            }),
        ),
        (
            "too many targets",
            Box::new(|f| {
                let t = f.list.unsubscribe[1].clone();
                f.list.unsubscribe = vec![t; MAX_UNSUBSCRIBE_TARGETS + 1];
                f.list.one_click = false;
            }),
        ),
        (
            "too many references",
            Box::new(|f| f.thread.references = vec!["a@example.com".into(); MAX_REFERENCES + 1]),
        ),
        (
            "reference with space",
            Box::new(|f| f.thread.references = vec!["a b@example.com".into()]),
        ),
        (
            "long reference",
            Box::new(|f| f.thread.in_reply_to = Some("a".repeat(ID_MAX_CHARS + 1))),
        ),
        (
            "float-like amount",
            Box::new(|f| {
                if let StructuredItem::Order(o) = &mut f.structured[0] {
                    o.total.as_mut().unwrap().amount = "1e9".into();
                }
            }),
        ),
        (
            "lowercase currency",
            Box::new(|f| {
                if let StructuredItem::Order(o) = &mut f.structured[0] {
                    o.total.as_mut().unwrap().currency = Some("eur".into());
                }
            }),
        ),
        (
            "invalid date",
            Box::new(|f| {
                if let StructuredItem::Order(o) = &mut f.structured[0] {
                    o.date = Some(When::Date(date(2026, 2, 30)));
                }
            }),
        ),
        (
            "action to loopback",
            Box::new(|f| {
                f.structured[1] = StructuredItem::Action(Action {
                    kind: ActionKind::Confirm,
                    name: None,
                    url: url("https://127.0.0.1/confirm"),
                })
            }),
        ),
        (
            "too many items",
            Box::new(|f| {
                let i = f.structured[1].clone();
                f.structured = vec![i; MAX_STRUCTURED_ITEMS + 1];
            }),
        ),
        (
            "empty pass organization",
            Box::new(|f| {
                f.structured[0] = StructuredItem::Pass(Pass {
                    style: PassStyle::Generic,
                    organization: String::new(),
                    description: None,
                    relevant: None,
                })
            }),
        ),
        (
            "bidi in organizer",
            Box::new(|f| {
                f.invitation.as_mut().unwrap().organizer = Some(MailAddress {
                    name: Some("\u{202E}nnA".into()),
                    address: "ann@example.com".into(),
                })
            }),
        ),
        (
            "instant out of range",
            Box::new(|f| f.invitation.as_mut().unwrap().start = Some(When::Instant(-1))),
        ),
        (
            "hour 24",
            Box::new(|f| {
                f.invitation.as_mut().unwrap().end = Some(When::Local(LocalDateTime {
                    date: date(2026, 1, 1),
                    hour: 24,
                    minute: 0,
                    second: 0,
                }))
            }),
        ),
        (
            "forward marker past the body",
            Box::new(|f| f.layout.forward_at = Some(1)),
        ),
        (
            "placement without a link",
            Box::new(|f| f.layout.links.push(LinkPlacement::default())),
        ),
        (
            "one-click with two List-Unsubscribe-Post fields",
            Box::new(|f| f.auth.field_counts.list_unsubscribe_post = 2),
        ),
        (
            "one-click with no List-Unsubscribe-Post field",
            Box::new(|f| {
                f.auth.field_counts.list_unsubscribe_post = 0;
                f.header.signals = HeaderSignals::from_bits(
                    f.header.signals.bits() & !HeaderSignal::UnsubscribePost.bit(),
                );
            }),
        ),
        (
            "one-click without the List-Unsubscribe-Post signal",
            Box::new(|f| {
                f.header.signals = HeaderSignals::from_bits(
                    f.header.signals.bits() & !HeaderSignal::UnsubscribePost.bit(),
                );
            }),
        ),
        (
            "time zone on an instant start",
            Box::new(|f| f.invitation.as_mut().unwrap().time_zone = Some("Europe/Vilnius".into())),
        ),
        (
            "time zone without a start",
            Box::new(|f| {
                let i = f.invitation.as_mut().unwrap();
                i.start = None;
                i.time_zone = Some("Europe/Vilnius".into());
            }),
        ),
    ];
    for (name, mutate) in cases {
        let mut f = good();
        mutate(&mut f);
        assert_eq!(check(f), Err(ContentError::Crashed), "{name}");
    }
}

#[test]
fn time_zone_with_a_local_start_is_accepted() {
    let mut f = good();
    let i = f.invitation.as_mut().unwrap();
    i.start = Some(When::Local(LocalDateTime {
        date: date(2026, 11, 25),
        hour: 9,
        minute: 30,
        second: 0,
    }));
    i.time_zone = Some("Europe/Vilnius".into());
    assert_eq!(check(f), Ok(()));
}

#[test]
fn placements_follow_links() {
    let mut r = rendered(MessageFacts::default());
    r.links.push(LinkInfo {
        href: None,
        display_host: None,
        text: "x".into(),
        warnings: LinkWarnings::default(),
    });
    assert_eq!(verify_facts(&request(), &r), Err(ContentError::Crashed));
    r.facts.layout.links.push(LinkPlacement {
        aria_label: Some("Unsubscribe".into()),
        ..LinkPlacement::default()
    });
    assert_eq!(verify_facts(&request(), &r), Ok(()));
    r.facts.layout.links[0].aria_label = Some("a\u{200B}b".into());
    assert_eq!(verify_facts(&request(), &r), Err(ContentError::Crashed));
}

#[test]
fn placements_agree_with_markers() {
    let mut r = rendered(MessageFacts::default());
    r.links.push(LinkInfo {
        href: None,
        display_host: None,
        text: "x".into(),
        warnings: LinkWarnings::default(),
    });
    r.facts.layout.links.push(LinkPlacement {
        in_footer: true,
        below_forward: true,
        ..LinkPlacement::default()
    });
    assert_eq!(
        verify_facts(&request(), &r),
        Err(ContentError::Crashed),
        "footer and forward flags without markers"
    );
    r.facts.layout.footer_at = Some(0);
    assert_eq!(
        verify_facts(&request(), &r),
        Err(ContentError::Crashed),
        "forward flag without a marker"
    );
    r.facts.layout.forward_at = Some(0);
    assert_eq!(verify_facts(&request(), &r), Ok(()));
    r.facts.layout.footer_at = None;
    assert_eq!(
        verify_facts(&request(), &r),
        Err(ContentError::Crashed),
        "footer flag without a footer"
    );
}

#[test]
fn saturated_counts_allow_any_position() {
    let mut f = good();
    f.auth.field_counts.authentication_results = 255;
    f.auth.results[0].position = 254;
    assert_eq!(check(f), Ok(()));
}

#[test]
fn calendar_arithmetic() {
    assert_eq!(date(1970, 1, 1).unix_days(), 0);
    assert_eq!(date(2000, 3, 1).unix_days(), 11_017);
    assert_eq!(date(2201, 1, 1).unix_days() * 86_400 - 1, When::MAX_INSTANT);
    assert!(date(2024, 2, 29).is_valid());
    assert!(!date(2100, 2, 29).is_valid());
    assert!(!date(1969, 12, 31).is_valid());
    assert!(!date(2201, 1, 1).is_valid());
}
