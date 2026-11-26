use std::collections::HashSet;

use rinse_doc_model::{Block, Document, Inline, Limits, SCHEMA_VERSION, SafeUrl, Style, validate};

use crate::{
    ContentError, DecodedPart, LimitKind, LinkInfo, PartRequest, RenderRequest, Rendered,
    check_sanitized_html, link_destination, remote_image_url_ok, text_names_other_host,
};

/// The most characters (Unicode scalar values) any display string of a response may hold:
/// header fields, addresses, file names, media types, link texts and hosts.
pub const DISPLAY_MAX_CHARS: usize = 1_000;

/// The most mailboxes in one address field of [`Headers`](crate::Headers).
pub const MAX_ADDRESSES: usize = 100;

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

fn unlimited() -> Limits {
    Limits {
        max_text_bytes: usize::MAX,
        ..Limits::default()
    }
}

pub(crate) fn display_text_ok(field: &str) -> bool {
    if field.len() > DISPLAY_MAX_CHARS * 4 || field.chars().count() > DISPLAY_MAX_CHARS {
        return false;
    }
    let doc = Document {
        version: SCHEMA_VERSION,
        blocks: vec![Block::Paragraph {
            align: Default::default(),
            inlines: vec![Inline::Text {
                text: field.to_owned(),
                style: Style::default(),
            }],
        }],
    };
    validate(&doc, &unlimited(), |_| false).is_ok()
}

/// Checks a [`Rendered`] against every guarantee of the contract a receiver can verify without
/// parsing message content. The core runs it on every response, whatever implementation
/// produced it, and drops the response on failure.
///
/// Checked: the body with [`rinse_doc_model::validate`] against `request.limits.doc` and the
/// returned image ids (failure: [`ContentError::LimitExceeded`] with [`LimitKind::Document`]);
/// image ids unique, each the lowercase BLAKE3 hash of PNG bytes, dimensions within
/// `min(options.max_image_px, doc.max_image_px)`, at most `doc.max_images` images; at most
/// `doc.max_links` links, every destination a [`SafeUrl`] within `doc.max_url_len`; every link's
/// `display_host` and destination warnings (`punycode`, `mixed_script`, `ip_host`, `userinfo`,
/// `text_href_mismatch`) equal to what [`link_destination`] and [`text_names_other_host`] derive
/// from its `href` and text, no removal flag on a link that has a destination, and no
/// `display_host` on one that has none (a compromised worker can neither rename a host nor clear
/// a warning); the plain
/// text within `doc.max_text_bytes` with the preformatted character rules; every display string
/// (addresses and names, subject, Message-ID, file names, declared and sniffed types, link texts
/// and hosts) one line under the text rules and at most [`DISPLAY_MAX_CHARS`] characters; at most
/// [`MAX_ADDRESSES`] mailboxes per field; every remote image URL, in the response and in the
/// original HTML, accepted by [`remote_image_url_ok`]; the original HTML present only when asked
/// for, passing [`check_sanitized_html`], its links [`SafeUrl`]s; the facts with
/// [`verify_facts`](crate::verify_facts). Any other failure is
/// [`ContentError::Crashed`]: the implementation broke the contract.
///
/// Not checked: the postcard size of the response (check it before decoding), and whether the
/// `peleda-` references inside the original HTML resolve; the viewer must treat an unknown
/// reference as missing.
pub fn verify_rendered(request: &RenderRequest, out: &Rendered) -> Result<(), ContentError> {
    let bad = Err(ContentError::Crashed);
    let limits = &request.limits.doc;
    let ids: HashSet<&str> = out.images.iter().map(|i| i.id.as_str()).collect();
    if ids.len() != out.images.len() {
        return bad;
    }
    if validate(&out.body, limits, |id| ids.contains(id)).is_err() {
        return Err(ContentError::LimitExceeded(LimitKind::Document));
    }
    if out.images.len() > limits.max_images || out.links.len() > limits.max_links {
        return bad;
    }
    let max_px = request.options.max_image_px.min(limits.max_image_px);
    for image in &out.images {
        let size_ok = (1..=max_px).contains(&image.width) && (1..=max_px).contains(&image.height);
        if !size_ok
            || !image.png.starts_with(PNG_MAGIC)
            || image.id != blake3::hash(&image.png).to_hex().as_str()
        {
            return bad;
        }
    }
    if out.text.len() > limits.max_text_bytes {
        return bad;
    }
    let text_doc = Document {
        version: SCHEMA_VERSION,
        blocks: vec![Block::Preformatted(out.text.clone())],
    };
    if validate(&text_doc, &unlimited(), |_| false).is_err() {
        return bad;
    }

    let h = &out.headers;
    let mut fields: Vec<&str> = Vec::new();
    for list in [&h.from, &h.to, &h.cc, &h.reply_to] {
        if list.len() > MAX_ADDRESSES {
            return bad;
        }
        for a in list {
            fields.push(&a.address);
            fields.extend(a.name.as_deref());
        }
    }
    fields.extend(h.subject.as_deref());
    fields.extend(h.message_id.as_deref());
    for a in &out.attachments {
        fields.extend(a.file_name.as_deref());
        fields.push(&a.declared_type);
        fields.extend(a.sniffed_type.as_deref());
    }
    for l in &out.links {
        fields.push(&l.text);
        fields.extend(l.display_host.as_deref());
    }
    if !fields.into_iter().all(display_text_ok) {
        return bad;
    }

    let safe = |url: &SafeUrl| SafeUrl::new(url.as_str(), limits.max_url_len).is_some();
    if !out.links.iter().filter_map(|l| l.href.as_ref()).all(safe) {
        return bad;
    }
    if !out.links.iter().all(link_matches_destination) {
        return bad;
    }
    let remote_ok = |url: &String| remote_image_url_ok(url, limits.max_url_len);
    if !out.remote_images.iter().all(remote_ok) {
        return bad;
    }
    if let Some(html) = &out.original_html
        && (!request.options.want_original_html
            || check_sanitized_html(&html.html).is_err()
            || !html.links.iter().all(safe)
            || !html.remote_images.iter().all(remote_ok))
    {
        return bad;
    }
    crate::verify_facts(request, out)
}

fn link_matches_destination(link: &LinkInfo) -> bool {
    let Some(href) = &link.href else {
        return link.display_host.is_none();
    };
    let Some(d) = link_destination(href.as_str()) else {
        return false;
    };
    let w = link.warnings;
    let mismatch = d
        .host
        .as_deref()
        .is_some_and(|host| text_names_other_host(host, &link.text));
    link.display_host == d.display_host
        && w.punycode == d.warnings.punycode
        && w.mixed_script == d.warnings.mixed_script
        && w.ip_host == d.warnings.ip_host
        && w.userinfo == d.warnings.userinfo
        && w.text_href_mismatch == mismatch
        && !w.unsupported_scheme_removed
        && !w.malformed_removed
}

/// Checks a [`DecodedPart`]: the requested part (else [`ContentError::Crashed`]), bytes within
/// `max_output_bytes` (else [`ContentError::LimitExceeded`] with [`LimitKind::Output`]), and a
/// file name and media type that are display strings like those [`verify_rendered`] checks.
pub fn verify_decoded_part(request: &PartRequest, out: &DecodedPart) -> Result<(), ContentError> {
    if out.bytes.len() as u64 > request.limits.max_output_bytes {
        return Err(ContentError::LimitExceeded(LimitKind::Output));
    }
    if out.part != request.part
        || !display_text_ok(&out.media_type)
        || !out.file_name.as_deref().is_none_or(display_text_ok)
    {
        return Err(ContentError::Crashed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rinse_doc_model::Document;

    use super::*;
    use crate::{
        ContentLimits, Findings, Headers, LinkInfo, LinkWarnings, MailAddress, RenderOptions,
        SanitizedHtml,
    };

    fn request() -> RenderRequest {
        RenderRequest {
            raw: Bytes::new(),
            options: RenderOptions {
                want_original_html: true,
                ..RenderOptions::default()
            },
            limits: ContentLimits::default(),
        }
    }

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

    #[test]
    fn accepts_a_clean_response() {
        let mut out = empty();
        out.headers.subject = Some("Hello".into());
        out.remote_images = vec!["https://images.example.com/a.png".into()];
        out.original_html = Some(SanitizedHtml {
            html: "<p>hi</p>".into(),
            remote_images: out.remote_images.clone(),
            links: Vec::new(),
        });
        assert_eq!(verify_rendered(&request(), &out), Ok(()));
    }

    #[test]
    fn rejects_broken_fields() {
        let req = request();
        let mut out = empty();
        out.headers.subject = Some(format!("\u{1F44D}{}", "\u{200D}\u{1F44D}".repeat(3000)));
        assert_eq!(verify_rendered(&req, &out), Err(ContentError::Crashed));

        let mut out = empty();
        out.headers.from = vec![
            MailAddress {
                name: None,
                address: "a@example.com".into(),
            };
            MAX_ADDRESSES + 1
        ];
        assert_eq!(verify_rendered(&req, &out), Err(ContentError::Crashed));

        let mut out = empty();
        out.remote_images = vec!["http://169.254.169.254/latest/meta-data/".into()];
        assert_eq!(verify_rendered(&req, &out), Err(ContentError::Crashed));

        let mut out = empty();
        out.links = vec![LinkInfo {
            href: None,
            display_host: Some("a\u{202E}b".into()),
            text: String::new(),
            warnings: LinkWarnings::default(),
        }];
        assert_eq!(verify_rendered(&req, &out), Err(ContentError::Crashed));

        let mut out = empty();
        out.original_html = Some(SanitizedHtml {
            html: r#"<img srcset="peleda-image:a 1x, //evil.example.org/p 2x">"#.into(),
            remote_images: Vec::new(),
            links: Vec::new(),
        });
        assert_eq!(verify_rendered(&req, &out), Err(ContentError::Crashed));

        let mut not_asked = request();
        not_asked.options.want_original_html = false;
        let mut out = empty();
        out.original_html = Some(SanitizedHtml {
            html: String::new(),
            remote_images: Vec::new(),
            links: Vec::new(),
        });
        assert_eq!(
            verify_rendered(&not_asked, &out),
            Err(ContentError::Crashed)
        );
    }

    fn link(href: &str, host: Option<&str>, text: &str, warnings: LinkWarnings) -> Rendered {
        let mut out = empty();
        out.links = vec![LinkInfo {
            href: Some(SafeUrl::new(href, 2_048).unwrap()),
            display_host: host.map(str::to_owned),
            text: text.into(),
            warnings,
        }];
        out.facts.layout.links = vec![Default::default()];
        out
    }

    #[test]
    fn attack_lying_worker_link_host_and_warnings_are_rejected() {
        let req = request();
        let honest = link(
            "https://evil.example/login",
            Some("evil.example"),
            "Verify your account",
            LinkWarnings::default(),
        );
        assert_eq!(verify_rendered(&req, &honest), Ok(()));
        let lying_host = link(
            "https://evil.example/login",
            Some("bank.example"),
            "Verify your account",
            LinkWarnings::default(),
        );
        assert_eq!(
            verify_rendered(&req, &lying_host),
            Err(ContentError::Crashed)
        );
        let cleared_userinfo = link(
            "https://bank.example@203.0.113.9/x",
            Some("203.0.113.9"),
            "Pay now",
            LinkWarnings::default(),
        );
        assert_eq!(
            verify_rendered(&req, &cleared_userinfo),
            Err(ContentError::Crashed)
        );
        let cleared_mismatch = link(
            "https://evil.example/login",
            Some("evil.example"),
            "bank.example",
            LinkWarnings::default(),
        );
        assert_eq!(
            verify_rendered(&req, &cleared_mismatch),
            Err(ContentError::Crashed)
        );
        let cleared_punycode = link(
            "https://xn--pypal-4ve.com/",
            Some("p\u{430}ypal.com"),
            "Log in",
            LinkWarnings::default(),
        );
        assert_eq!(
            verify_rendered(&req, &cleared_punycode),
            Err(ContentError::Crashed)
        );
        let honest_punycode = link(
            "https://xn--pypal-4ve.com/",
            Some("p\u{430}ypal.com"),
            "Log in",
            LinkWarnings {
                punycode: true,
                mixed_script: true,
                ..LinkWarnings::default()
            },
        );
        assert_eq!(verify_rendered(&req, &honest_punycode), Ok(()));
        let mut host_without_href = honest;
        host_without_href.links[0].href = None;
        host_without_href.links[0].warnings.malformed_removed = true;
        assert_eq!(
            verify_rendered(&req, &host_without_href),
            Err(ContentError::Crashed)
        );
    }
}
