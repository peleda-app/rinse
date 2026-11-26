use std::collections::VecDeque;

use mail_parser::{AddressList, Header, Message};
use rinse_doc_model::SafeUrl;
use rinse_mail::facts::{
    AuthFacts, FieldCounts, HeaderFacts, HeaderSignal, HeaderSignals, ListFacts, MAX_AUTH_RESULTS,
    MAX_DKIM_SIGNATURES, MAX_REFERENCES, MAX_UNSUBSCRIBE_TARGETS, MailtoTarget, ThreadFacts,
    UnsubscribeTarget,
};
use rinse_mail::{MailAddress, remote_image_url_ok};

use super::{auth, domain, ident, sat, text};

const MAX_FIELDS: usize = 4_096;
const MAX_VALUE_BYTES: usize = 4 << 20;
const MAX_UNSUBSCRIBE_ITEMS: usize = 64;
const ESP_FIELDS: &[&str] = &["x-sg-eid", "x-mc-user", "x-ses-outgoing", "x-pm-message-id"];
const ESP_PREFIXES: &[&str] = &["x-mailgun-"];
const AUTOMATED: &[&str] = &[
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
    "do_not_reply",
    "mailer-daemon",
    "postmaster",
    "bounce",
];
const ONE_CLICK: &str = "List-Unsubscribe=One-Click";

/// One top-level header field: lowercase name, unfolded value, and the parser's view of it.
pub(crate) struct Field<'m> {
    pub(crate) name: String,
    pub(crate) value: String,
    header: Header<'m>,
}

/// Unfolds a raw field value: line breaks followed by white space go, the final line break
/// goes, and the value is trimmed. Bytes that are not UTF-8 become U+FFFD.
pub(crate) fn unfold(raw: &[u8]) -> String {
    let raw = &raw[..raw.len().min(MAX_VALUE_BYTES)];
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            chars.next();
            if !matches!(chars.peek(), Some(' ' | '\t')) {
                out.push('\n');
            }
            continue;
        }
        if c == '\n' && matches!(chars.peek(), Some(' ' | '\t')) {
            continue;
        }
        out.push(c);
    }
    out.trim().to_owned()
}

/// The top-level header fields in order, at most [`MAX_FIELDS`].
pub(crate) fn fields<'m>(message: &'m Message<'m>) -> Vec<Field<'m>> {
    message
        .root()
        .headers()
        .iter()
        .take(MAX_FIELDS)
        .map(|header| Field {
            name: header.raw_name().to_ascii_lowercase(),
            value: unfold(header.raw_value()),
            header,
        })
        .collect()
}

fn strip_comments(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut depth = 0usize;
    let mut escaped = false;
    for c in value.chars() {
        if depth > 0 {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
        } else if c == '(' {
            depth = 1;
        } else {
            out.push(c);
        }
    }
    out.trim().to_owned()
}

fn mailbox(list: Option<AddressList<'_>>) -> Option<MailAddress> {
    let first = list?.mailboxes().next()?;
    let address = text(first.address()?, 320)?;
    Some(MailAddress {
        name: first.name().and_then(|n| text(n, 200)),
        address,
    })
}

fn automated(address: &str) -> bool {
    let local = address.rsplit_once('@').map_or(address, |(l, _)| l);
    AUTOMATED.iter().any(|a| {
        local
            .get(..a.len())
            .is_some_and(|start| start.eq_ignore_ascii_case(a))
    })
}

fn signals(fields: &[Field<'_>]) -> HeaderSignals {
    let mut s = HeaderSignals::default();
    let mut set = |signal, on: bool| {
        if on {
            s.insert(signal);
        }
    };
    let named = |name: &'static str| fields.iter().filter(move |f| f.name == name);
    let has = |name: &'static str| named(name).next().is_some();
    set(HeaderSignal::ListId, has("list-id"));
    for f in named("list-post") {
        let no = strip_comments(&f.value).eq_ignore_ascii_case("no");
        set(
            if no {
                HeaderSignal::ListPostNo
            } else {
                HeaderSignal::ListPost
            },
            true,
        );
    }
    set(HeaderSignal::Unsubscribe, has("list-unsubscribe"));
    set(HeaderSignal::UnsubscribePost, has("list-unsubscribe-post"));
    set(
        HeaderSignal::PrecedenceBulk,
        named("precedence").any(|f| {
            let v = strip_comments(&f.value);
            ["bulk", "list", "junk"]
                .iter()
                .any(|k| v.eq_ignore_ascii_case(k))
        }),
    );
    for f in named("auto-submitted") {
        let v = strip_comments(&f.value);
        let keyword = v.split(';').next().unwrap_or("").trim();
        if keyword.eq_ignore_ascii_case("auto-replied") {
            set(HeaderSignal::AutoReplied, true);
        } else if !keyword.is_empty() && !keyword.eq_ignore_ascii_case("no") {
            set(HeaderSignal::AutoSubmitted, true);
        }
    }
    set(HeaderSignal::FeedbackId, has("feedback-id"));
    set(
        HeaderSignal::Esp,
        fields.iter().any(|f| {
            ESP_FIELDS.contains(&f.name.as_str())
                || ESP_PREFIXES.iter().any(|p| f.name.starts_with(p))
        }),
    );
    s
}

fn list_id(value: &str) -> Option<String> {
    let inner = match value.rfind('<') {
        Some(start) => {
            let rest = &value[start + 1..];
            &rest[..rest.find('>')?]
        }
        None => value,
    };
    ident(&inner.to_lowercase())
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

pub(crate) fn mail_address(s: &str) -> Option<String> {
    let (local, host) = s.split_once('@')?;
    let local_ok = (1..=64).contains(&local.len())
        && local
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"<>()[],;:\"\\@?&=%#/".contains(&b));
    if !local_ok {
        return None;
    }
    ident(&format!("{local}@{}", domain(host)?))
}

/// A `mailto:` target with one address and only `subject` and `body` header fields.
pub(crate) fn mailto(url: &str) -> Option<MailtoTarget> {
    let rest = url
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("mailto:"))
        .map(|_| &url[7..])?;
    let (addr, query) = rest.split_once('?').unwrap_or((rest, ""));
    let address = mail_address(&percent_decode(addr)?)?;
    let mut target = MailtoTarget {
        address,
        subject: None,
        body: None,
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v)?;
        let (slot, max) = match percent_decode(k)?.to_ascii_lowercase().as_str() {
            "subject" => (&mut target.subject, 200),
            "body" => (&mut target.body, 500),
            _ => return None,
        };
        if slot.is_some() {
            return None;
        }
        *slot = text(&v, max);
    }
    Some(target)
}

fn https(url: &str, max_url_len: usize) -> Option<SafeUrl> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let s = String::from(parsed);
    if !remote_image_url_ok(&s, max_url_len) {
        return None;
    }
    SafeUrl::new(&s, max_url_len)
}

/// The usable targets of a `List-Unsubscribe` value, read strictly by RFC 2369: `<…>` items
/// separated by commas, white space inside the brackets ignored, reading stops at the first item
/// that is not bracketed or not closed. Items with control characters, other schemes, `http`,
/// internal hosts or mailto header fields other than subject and body are skipped.
pub(crate) fn unsubscribe(value: &str, max_url_len: usize) -> Vec<UnsubscribeTarget> {
    let mut out: Vec<UnsubscribeTarget> = Vec::new();
    let mut rest = value;
    for _ in 0..MAX_UNSUBSCRIBE_ITEMS {
        if out.len() >= MAX_UNSUBSCRIBE_TARGETS {
            break;
        }
        let Some(after) = rest.trim_start().strip_prefix('<') else {
            break;
        };
        let Some((inner, tail)) = after.split_once('>') else {
            break;
        };
        let has_control = inner
            .chars()
            .any(|c| c.is_control() && !matches!(c, ' ' | '\t'));
        let compact: String = inner.chars().filter(|c| !c.is_whitespace()).collect();
        let target = if has_control {
            None
        } else if compact
            .get(..7)
            .is_some_and(|p| p.eq_ignore_ascii_case("mailto:"))
        {
            mailto(&compact).map(UnsubscribeTarget::Mailto)
        } else {
            https(&compact, max_url_len).map(UnsubscribeTarget::Https)
        };
        if let Some(t) = target
            && !out.contains(&t)
        {
            out.push(t);
        }
        match tail.split_once(',') {
            Some((_, next)) => rest = next,
            None => break,
        }
    }
    out
}

fn msg_ids(value: &str, mut each: impl FnMut(String)) {
    let mut bracketed = false;
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        let Some(len) = rest[start + 1..].find('>') else {
            break;
        };
        bracketed = true;
        if let Some(id) = ident(&rest[start + 1..start + 1 + len]) {
            each(id);
        }
        rest = &rest[start + 2 + len..];
    }
    if !bracketed {
        for token in value.split_whitespace().filter(|t| t.contains('@')) {
            if let Some(id) = ident(token) {
                each(id);
            }
        }
    }
}

fn thread(fields: &[Field<'_>]) -> ThreadFacts {
    let mut facts = ThreadFacts::default();
    if let Some(f) = fields.iter().find(|f| f.name == "in-reply-to") {
        msg_ids(&f.value, |id| {
            facts.in_reply_to.get_or_insert(id);
        });
    }
    if let Some(f) = fields.iter().find(|f| f.name == "references") {
        let mut first = None;
        let mut last: VecDeque<String> = VecDeque::new();
        let mut total = 0usize;
        msg_ids(&f.value, |id| {
            total += 1;
            if first.is_none() {
                first = Some(id);
            } else {
                if last.len() == MAX_REFERENCES - 1 {
                    last.pop_front();
                }
                last.push_back(id);
            }
        });
        facts.references = first.into_iter().chain(last).collect();
        facts.references_cut = total > facts.references.len();
    }
    facts
}

/// Header, authentication, list and thread facts.
pub(crate) fn facts(
    _message: &Message<'_>,
    fields: &[Field<'_>],
    max_url_len: usize,
) -> (HeaderFacts, AuthFacts, ListFacts, ThreadFacts) {
    let count = |name: &str| sat(fields.iter().filter(|f| f.name == name).count());
    let first = |name: &str| fields.iter().find(|f| f.name == name);

    let mut signals = signals(fields);
    let from = first("from").map(|f| f.header.value().as_address());
    let from_addresses = from
        .as_ref()
        .and_then(|l| l.as_ref())
        .map_or(0, |l| sat(l.mailboxes().count()));
    if from
        .flatten()
        .and_then(|l| {
            l.mailboxes()
                .next()
                .and_then(|m| m.address().map(str::to_owned))
        })
        .is_some_and(|a| automated(&a))
    {
        signals.insert(HeaderSignal::Noreply);
    }
    let header = HeaderFacts {
        signals,
        from_fields: count("from"),
        from_addresses,
        sender: first("sender").and_then(|f| mailbox(f.header.value().as_address())),
        list_id: first("list-id").and_then(|f| list_id(&f.value)),
    };

    let mut auth = AuthFacts {
        field_counts: FieldCounts {
            from: count("from"),
            list_unsubscribe: count("list-unsubscribe"),
            list_unsubscribe_post: count("list-unsubscribe-post"),
            authentication_results: count("authentication-results"),
            dkim_signature: count("dkim-signature"),
        },
        ..AuthFacts::default()
    };
    for (position, f) in fields
        .iter()
        .filter(|f| f.name == "authentication-results")
        .enumerate()
    {
        let Ok(position) = u8::try_from(position) else {
            auth.cap_hit = true;
            break;
        };
        if let Some((result, cut)) = auth::auth_result(&f.value, position) {
            if auth.results.len() == MAX_AUTH_RESULTS {
                auth.cap_hit = true;
                break;
            }
            auth.cap_hit |= cut;
            auth.results.push(result);
        }
    }
    for f in fields.iter().filter(|f| f.name == "dkim-signature") {
        if let Some(tags) = auth::dkim_tags(&f.value) {
            if auth.signatures.len() == MAX_DKIM_SIGNATURES {
                auth.cap_hit = true;
                break;
            }
            auth.signatures.push(tags);
        }
    }

    let unsubscribe = first("list-unsubscribe")
        .map(|f| unsubscribe(&f.value, max_url_len))
        .unwrap_or_default();
    let posts: Vec<&Field<'_>> = fields
        .iter()
        .filter(|f| f.name == "list-unsubscribe-post")
        .collect();
    let one_click = posts.len() == 1
        && posts[0].value == ONE_CLICK
        && unsubscribe
            .iter()
            .any(|t| matches!(t, UnsubscribeTarget::Https(_)));
    let list = ListFacts {
        unsubscribe,
        one_click,
    };
    (header, auth, list, thread(fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfolds() {
        assert_eq!(unfold(b" a\r\n b\r\n"), "a b");
        assert_eq!(unfold(b" a\r\nb"), "a\nb");
        assert_eq!(unfold(b" a\n\tb"), "a\tb");
    }

    #[test]
    fn unsubscribe_items() {
        let t = unsubscribe(
            "<https://news.example.com/u?a=1>, <mailto:u@example.com?subject=stop>",
            2048,
        );
        assert_eq!(t.len(), 2);
        assert!(
            matches!(&t[0], UnsubscribeTarget::Https(u) if u.as_str() == "https://news.example.com/u?a=1")
        );
        assert!(
            matches!(&t[1], UnsubscribeTarget::Mailto(m) if m.address == "u@example.com" && m.subject.as_deref() == Some("stop"))
        );
        for bad in [
            "<javascript:alert(1)>",
            "<JaVaScRiPt:alert(1)>",
            "<http://news.example.com/u>",
            "<https://user:pw@news.example.com/u>",
            "<https://127.0.0.1/u>",
            "<https://localhost/u>",
            "<mailto:u@example.com?bcc=victim@example.org>",
            "<mailto:u@example.com,v@example.org>",
            "<mailto:x%3Fbcc%3Dvictim%2540evil.example.org%26a@example.com?subject=stop>",
            "<mailto:x%23y@example.com>",
            "<mailto:x%2Fy@example.com>",
            "<mailto:x%25y@example.com>",
            "<mailto:u@example.com?subject=a&subject=b>",
            "<mailto:u@example.com?subject=%zz>",
            "<data:text/html,x>",
            "https://news.example.com/unbracketed",
            "<https://news.example.com/u\u{1}x>",
        ] {
            assert!(unsubscribe(bad, 2048).is_empty(), "{bad}");
        }
        let t = unsubscribe("junk, <https://news.example.com/u>", 2048);
        assert!(t.is_empty(), "reading stops at an unbracketed item");
        let t = unsubscribe(
            "<mailto:u@example.com?subject=a%0D%0ABcc:%20v@example.org>",
            2048,
        );
        let UnsubscribeTarget::Mailto(m) = &t[0] else {
            panic!()
        };
        assert_eq!(m.subject.as_deref(), Some("a Bcc: v@example.org"));
        let many = "<https://news.example.com/a>,".repeat(1000);
        assert_eq!(unsubscribe(&many, 2048).len(), 1);
    }

    #[test]
    fn message_ids() {
        let mut v = Vec::new();
        msg_ids("<a@example.com> <b c@example.com> <c@example.com>", |id| {
            v.push(id)
        });
        assert_eq!(v, ["a@example.com", "c@example.com"]);
        let mut v = Vec::new();
        msg_ids("d@example.com", |id| v.push(id));
        assert_eq!(v, ["d@example.com"]);
    }

    #[test]
    fn list_ids() {
        assert_eq!(
            list_id("News <News.Example.COM>").as_deref(),
            Some("news.example.com")
        );
        assert_eq!(
            list_id("news.example.com").as_deref(),
            Some("news.example.com")
        );
        assert_eq!(list_id("a b"), None);
        assert_eq!(list_id("<unclosed"), None);
    }
}
