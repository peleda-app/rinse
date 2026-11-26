use bytes::Bytes;
use rinse_mail::facts::{EventStatus, HeaderSignal, StructuredItem};
use rinse_mail::testing::fixture;
use rinse_mail::{ContentLimits, RenderOptions, RenderRequest, Rendered, verify_rendered};

fn render(raw: &[u8]) -> Rendered {
    let request = RenderRequest {
        raw: Bytes::copy_from_slice(raw),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    };
    let out = crate::render(&request).expect("renders");
    verify_rendered(&request, &out).expect("verifies");
    out
}

#[test]
fn plain_text_forward_and_signature_footer() {
    let out = render(
        b"From: Ann <ann@example.com>\r\nSender: List Robot <\xe2\x80\xaerobot@example.com>\r\nFrom: Eve <eve@example.org>\r\nContent-Type: text/plain\r\n\r\nSee below.\r\n\r\nBegin forwarded message:\r\nFrom: shop@example.com\r\n\r\nVisit https://shop.example.com/a\r\n\r\n(c) Shop, \xc2\xa9 2026\r\n",
    );
    let f = &out.facts;
    assert_eq!(f.header.from_fields, 2);
    assert_eq!(f.header.from_addresses, 1);
    assert_eq!(f.layout.forward_at, Some(1));
    assert!(f.layout.footer_at.is_some_and(|i| i > 1));
    assert!(f.layout.links[0].below_forward);
    assert!(!f.layout.links[0].in_footer);
    assert!(
        f.header
            .sender
            .as_ref()
            .is_none_or(|s| !s.address.contains('\u{202E}'))
    );
}

#[test]
fn calendar_from_an_ics_attachment_and_flags() {
    let ics = "BEGIN:VCALENDAR\r\nMETHOD:CANCEL\r\nBEGIN:VEVENT\r\nUID:x@example.com\r\nSTATUS:CANCELLED\r\nDTSTART;VALUE=DATE:20261224\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let raw = format!(
        "From: a@example.com\r\nAuto-Submitted: auto-replied (vacation)\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: application/octet-stream; name=cancel.ics\r\nContent-Disposition: attachment; filename=cancel.ics\r\n\r\n{ics}--b--\r\n"
    );
    let out = render(raw.as_bytes());
    let inv = out.facts.invitation.expect("invitation");
    assert_eq!(inv.status, Some(EventStatus::Cancelled));
    assert!(out.facts.header.signals.contains(HeaderSignal::AutoReplied));
    assert!(
        !out.facts
            .header
            .signals
            .contains(HeaderSignal::AutoSubmitted)
    );
}

#[test]
fn facts_of_the_corpus_are_bounded() {
    for name in [
        "ld-json-bombs.eml",
        "gigantic-references.eml",
        "forged-auth-results.eml",
    ] {
        let out = render(fixture(name));
        let size = postcard::to_stdvec(&out.facts).unwrap().len();
        assert!(size < 64 << 10, "{name}: {size} bytes of facts");
    }
    let out = render(fixture("ld-json-bombs.eml"));
    assert!(
        out.facts
            .structured
            .iter()
            .all(|i| !matches!(i, StructuredItem::Pass(_)))
    );
}

#[test]
fn link_hints_are_capped() {
    let links: String = (0..crate::facts::MAX_LINK_HINTS + 50)
        .map(|i| format!("<a href=\"https://example.com/{i}\" title=\"t\">x</a> "))
        .collect();
    let raw = format!("From: a@example.com\r\nContent-Type: text/html\r\n\r\n<p>{links}</p>");
    let request = RenderRequest {
        raw: Bytes::from(raw),
        options: RenderOptions::default(),
        limits: ContentLimits::default(),
    };
    let out = crate::render(&request).unwrap();
    verify_rendered(&request, &out).unwrap();
    assert_eq!(out.facts.layout.links.len(), out.links.len());
}
