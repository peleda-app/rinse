//! Extraction of [`MessageFacts`] inside the worker: header signals, authentication grammar,
//! list and thread headers, JSON-LD and Wallet passes, calendar invitations and layout.

mod auth;
mod calendar;
mod headers;
mod layout;
mod pkpass;
mod structured;
mod when;

use std::collections::HashMap;

use mail_parser::Message;
use rinse_doc_model::Document;
use rinse_mail::facts::{ID_MAX_CHARS, MAX_STRUCTURED_ITEMS, MessageFacts};
use rinse_mail::{LinkInfo, TextFindings};

pub(crate) use layout::LinkHint;

/// The most JSON-LD scripts read per message.
pub(crate) const MAX_LD_JSON_SCRIPTS: usize = 8;
/// The most bytes of one JSON-LD script; longer scripts are skipped whole.
pub(crate) const MAX_LD_JSON_BYTES: usize = 64 << 10;
/// The most link hints kept per message.
pub(crate) const MAX_LINK_HINTS: usize = 4_096;

/// What the HTML walk collected for the facts.
#[derive(Default)]
pub(crate) struct Hints {
    /// Hints per link destination ([`rinse_doc_model::SafeUrl`] text).
    pub(crate) links: HashMap<String, LinkHint>,
    /// The text of `<script type="application/ld+json">` elements, in document order.
    pub(crate) ld_json: Vec<String>,
}

/// Everything the facts are made from.
pub(crate) struct Input<'a> {
    pub(crate) message: &'a Message<'a>,
    pub(crate) body: &'a Document,
    pub(crate) links: &'a [LinkInfo],
    pub(crate) hints: &'a Hints,
    pub(crate) max_url_len: usize,
    pub(crate) stop: &'a dyn Fn() -> bool,
}

/// The facts of one message. Never fails: anything unreadable is left out.
pub(crate) fn extract(input: &Input<'_>) -> MessageFacts {
    let fields = headers::fields(input.message);
    let (header, auth, list, thread) = headers::facts(input.message, &fields, input.max_url_len);
    let mut structured = Vec::new();
    for script in &input.hints.ld_json {
        if (input.stop)() || structured.len() >= MAX_STRUCTURED_ITEMS {
            break;
        }
        structured::read(script, input.max_url_len, &mut structured);
    }
    if !(input.stop)() {
        pkpass::read(input.message, &mut structured);
    }
    structured.truncate(MAX_STRUCTURED_ITEMS);
    let invitation = if (input.stop)() {
        None
    } else {
        calendar::read(input.message)
    };
    let layout = layout::layout(input.body, input.links, &input.hints.links);
    MessageFacts {
        header,
        auth,
        list,
        thread,
        structured,
        invitation,
        layout,
    }
}

/// Display text of at most `max` graphemes; `None` when empty.
pub(crate) fn text(s: &str, max: usize) -> Option<String> {
    let t = crate::text::display(s, max, &mut TextFindings::default());
    (!t.is_empty()).then_some(t)
}

/// An identifier as written: `None` unless trimming leaves a non-empty string of at most
/// [`ID_MAX_CHARS`] characters that display normalization leaves unchanged and that holds no
/// whitespace.
pub(crate) fn ident(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s.len() > ID_MAX_CHARS * 4 || s.chars().count() > ID_MAX_CHARS {
        return None;
    }
    if s.chars().any(char::is_whitespace) {
        return None;
    }
    let t = crate::text::display(s, ID_MAX_CHARS, &mut TextFindings::default());
    (t == s).then_some(t)
}

/// A domain name as lowercase ASCII (punycode for internationalized labels), without a final
/// dot; `None` when it is not one.
pub(crate) fn domain(s: &str) -> Option<String> {
    let s = s.trim().trim_end_matches('.');
    if s.is_empty() || s.len() > 253 * 4 || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let ascii = idna::domain_to_ascii(s).ok()?.to_ascii_lowercase();
    let ok = (1..=253).contains(&ascii.len())
        && ascii
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
        && !ascii.starts_with('.')
        && !ascii.ends_with('.')
        && !ascii.contains("..");
    ok.then_some(ascii)
}

/// `n` saturated to a `u8`.
pub(crate) fn sat(n: usize) -> u8 {
    u8::try_from(n).unwrap_or(u8::MAX)
}

#[cfg(test)]
mod tests;
