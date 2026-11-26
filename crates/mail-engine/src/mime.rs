use std::collections::HashMap;

use mail_parser::{AddressList, Message, MessageParser, MessagePart, PartId, PartKind};
use rinse_mail::{Attachment, Headers, MailAddress, TextFindings};

use crate::risk;
use crate::text::display;

const MAX_ADDRESSES: usize = 100;
const MAX_ATTACHMENTS: usize = 500;
const SNIFF_BYTES: usize = 0x8010;

/// The MIME parser with the nesting and part limits of the pipeline.
pub(crate) fn parser() -> MessageParser {
    MessageParser::new()
        .max_depth(16)
        .max_parts(1_000)
        .max_encoded_nesting(2)
}

/// One part of the body to render.
pub(crate) enum Body {
    Html(String),
    Text(String),
    Image(PartId),
}

/// The parts of the body in reading order: the HTML version when there is one, else the text
/// version, with inline images in between.
pub(crate) fn body_parts(message: &Message<'_>) -> Vec<Body> {
    let root = message.root();
    let html: Vec<MessagePart<'_>> = root.html_body().collect();
    let parts: Vec<MessagePart<'_>> = if html.iter().any(|p| matches!(p.kind(), PartKind::Html)) {
        html
    } else {
        root.text_body().collect()
    };
    parts
        .into_iter()
        .filter_map(|part| match part.kind() {
            PartKind::Html => part.text().map(|t| Body::Html(t.into_owned())),
            PartKind::Text => part.text().map(|t| Body::Text(t.into_owned())),
            PartKind::Binary | PartKind::InlineBinary
                if part
                    .content_type()
                    .is_some_and(|ct| ct.ctype().eq_ignore_ascii_case("image")) =>
            {
                Some(Body::Image(part.id()))
            }
            _ => None,
        })
        .collect()
}

/// `Content-ID` (without angle brackets, as written and lowercased) to part, for `cid:` URLs.
pub(crate) fn content_ids(message: &Message<'_>) -> HashMap<String, PartId> {
    let mut map = HashMap::new();
    for part in message.parts() {
        if part.is_multipart() {
            continue;
        }
        if let Some(cid) = part.content_id() {
            let cid = cid.trim().trim_start_matches('<').trim_end_matches('>');
            map.entry(cid.to_owned()).or_insert(part.id());
            map.entry(cid.to_ascii_lowercase()).or_insert(part.id());
        }
    }
    map
}

fn addresses(list: Option<AddressList<'_>>, findings: &mut TextFindings) -> Vec<MailAddress> {
    let Some(list) = list else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for mailbox in list.mailboxes() {
        if out.len() >= MAX_ADDRESSES {
            findings.truncated += 1;
            break;
        }
        let address = display(mailbox.address().unwrap_or_default(), 320, findings);
        if address.is_empty() {
            continue;
        }
        let name = mailbox
            .name()
            .map(|n| display(n, 200, findings))
            .filter(|n| !n.is_empty());
        out.push(MailAddress { name, address });
    }
    out
}

/// The header fields the app shows, normalized for display.
pub(crate) fn headers(message: &Message<'_>, findings: &mut TextFindings) -> Headers {
    let root = message.root();
    Headers {
        from: addresses(root.from(), findings),
        to: addresses(root.to(), findings),
        cc: addresses(root.cc(), findings),
        reply_to: addresses(root.reply_to(), findings),
        subject: root
            .subject()
            .map(|s| display(s, 500, findings))
            .filter(|s| !s.is_empty()),
        date: root
            .date()
            .filter(|d| d.is_valid())
            .map(|d| d.to_timestamp()),
        message_id: root
            .message_id()
            .map(|s| display(s, 500, findings))
            .filter(|s| !s.is_empty()),
    }
}

/// The lowercase `type/subtype` of a part; `application/octet-stream` when missing or odd.
pub(crate) fn media_type(part: &MessagePart<'_>) -> String {
    let Some(ct) = part.content_type() else {
        return if part.is_text() {
            "text/plain".to_owned()
        } else {
            "application/octet-stream".to_owned()
        };
    };
    let value = match ct.subtype() {
        Some(sub) => format!("{}/{}", ct.ctype(), sub),
        None => ct.ctype().to_owned(),
    }
    .to_ascii_lowercase();
    let ok = value.len() <= 127
        && value.contains('/')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/.+-_".contains(&b));
    if ok {
        value
    } else {
        "application/octet-stream".to_owned()
    }
}

/// The part's file name for display; `None` when absent or empty after normalization.
pub(crate) fn file_name(part: &MessagePart<'_>, findings: &mut TextFindings) -> Option<String> {
    part.attachment_name()
        .map(|n| display(n, 255, findings))
        .filter(|n| !n.is_empty())
}

/// The parts offered as files, in message order.
pub(crate) fn attachments(message: &Message<'_>, findings: &mut TextFindings) -> Vec<Attachment> {
    let mut out = Vec::new();
    for part in message.root().attachments() {
        if part.is_multipart() {
            continue;
        }
        if out.len() >= MAX_ATTACHMENTS {
            findings.truncated += 1;
            break;
        }
        let file_name = file_name(&part, findings);
        let declared_type = media_type(&part);
        let bytes = part.decoded();
        let sniffed = risk::sniff(&bytes[..bytes.len().min(SNIFF_BYTES)]);
        out.push(Attachment {
            part: part.id(),
            risk: risk::classify(file_name.as_deref(), &declared_type, sniffed.map(|s| s.1)),
            file_name,
            declared_type,
            sniffed_type: sniffed.map(|s| s.0.to_owned()),
            size: bytes.len() as u64,
            inline: part.is_inline(),
        });
    }
    out
}
