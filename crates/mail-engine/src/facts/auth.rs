//! Grammar of `Authentication-Results` (RFC 8601) and `DKIM-Signature` (RFC 6376), without
//! verification. Ported from Holtmail's `auth-results` crate (same author, MIT/Apache-2.0).

use rinse_mail::facts::{
    AuthMethod, AuthMethodResult, AuthOutcome, AuthResult, B_PREFIX_LEN, DkimTags,
    MAX_AUTH_METHODS, SignedCounts,
};

use super::{domain, ident, sat};

const MAX_FIELD_BYTES: usize = 16 << 10;

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

fn strip_comments(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            escaped = false;
            if depth == 0 {
                out.push(c);
            }
            continue;
        }
        match c {
            '\\' if quoted || depth > 0 => {
                escaped = true;
                if depth == 0 {
                    out.push(c);
                }
            }
            '"' if depth == 0 => {
                quoted = !quoted;
                out.push(c);
            }
            '(' if !quoted => {
                if depth == 0 {
                    out.push(' ');
                }
                depth += 1;
            }
            ')' if !quoted && depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

pub(crate) fn split_outside_quotes(value: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            _ if c == sep && !quoted => {
                parts.push(&value[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

struct Cursor<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
}

impl<'a> Cursor<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            chars: s.chars().peekable(),
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }

    fn bump(&mut self) -> Option<char> {
        self.chars.next()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(is_ws) {
            self.bump();
        }
    }

    fn take_while(&mut self, keep: impl Fn(char) -> bool) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek() {
            if !keep(c) {
                break;
            }
            out.push(c);
            self.bump();
        }
        out
    }

    fn value(&mut self) -> String {
        if self.peek() == Some('"') {
            self.bump();
            let mut out = String::new();
            while let Some(c) = self.bump() {
                match c {
                    '"' => break,
                    '\\' => {
                        if let Some(next) = self.bump() {
                            out.push(next);
                        }
                    }
                    _ => out.push(c),
                }
            }
            out
        } else {
            self.take_while(|c| !is_ws(c))
        }
    }
}

fn name_char(c: char) -> bool {
    !is_ws(c) && !matches!(c, '=' | '"' | '.' | '/')
}

struct Raw {
    method: String,
    result: String,
    props: Vec<(String, String)>,
}

fn method_result(segment: &str) -> Option<Raw> {
    let mut cur = Cursor::new(segment);
    cur.skip_ws();
    let method = cur.take_while(name_char).to_ascii_lowercase();
    if method.is_empty() {
        return None;
    }
    cur.skip_ws();
    if cur.peek() == Some('/') {
        cur.bump();
        cur.skip_ws();
        cur.take_while(|c| c.is_ascii_digit());
        cur.skip_ws();
    }
    if cur.bump() != Some('=') {
        return None;
    }
    cur.skip_ws();
    let result = cur.take_while(name_char).to_ascii_lowercase();
    if result.is_empty() {
        return None;
    }
    let mut props = Vec::new();
    loop {
        cur.skip_ws();
        let Some(first) = cur.peek() else { break };
        let key = key(&mut cur);
        cur.skip_ws();
        if cur.peek() != Some('=') {
            if key.is_empty() && cur.peek() == Some(first) {
                cur.bump();
            }
            continue;
        }
        cur.bump();
        cur.skip_ws();
        let value = cur.value();
        let key = key.to_ascii_lowercase();
        if let Some((ptype, name)) = key.split_once('.')
            && !ptype.is_empty()
            && !name.is_empty()
            && props.len() < 64
        {
            props.push((key, value));
        }
    }
    Some(Raw {
        method,
        result,
        props,
    })
}

fn key(cur: &mut Cursor<'_>) -> String {
    let mut key = cur.take_while(name_char);
    if key.is_empty() {
        return key;
    }
    cur.skip_ws();
    if cur.peek() == Some('.') {
        cur.bump();
        key.push('.');
        cur.skip_ws();
        key.push_str(&cur.take_while(name_char));
    }
    key
}

fn outcome(result: &str) -> AuthOutcome {
    match result {
        "pass" => AuthOutcome::Pass,
        "fail" | "hardfail" => AuthOutcome::Fail,
        "softfail" => AuthOutcome::SoftFail,
        "neutral" => AuthOutcome::Neutral,
        "none" => AuthOutcome::None,
        "temperror" => AuthOutcome::TempError,
        "permerror" => AuthOutcome::PermError,
        "policy" => AuthOutcome::Policy,
        _ => AuthOutcome::Other,
    }
}

fn after_at(s: &str) -> &str {
    s.rsplit_once('@').map_or(s, |(_, d)| d)
}

/// One `Authentication-Results` value as a fact, or `None` when it has no authserv-id or is
/// too long. The flag is true when methods were left out.
pub(crate) fn auth_result(value: &str, position: u8) -> Option<(AuthResult, bool)> {
    if value.len() > MAX_FIELD_BYTES {
        return None;
    }
    let clean = strip_comments(value);
    let mut segments = split_outside_quotes(&clean, ';').into_iter();
    let mut head = Cursor::new(segments.next()?);
    head.skip_ws();
    let authserv_id = ident(&head.value().to_lowercase())?;
    let mut methods = Vec::new();
    let mut cut = false;
    for raw in segments.filter_map(method_result) {
        if methods.len() == MAX_AUTH_METHODS {
            cut = true;
            break;
        }
        let prop = |k: &str| {
            raw.props
                .iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        let method = match raw.method.as_str() {
            "dkim" => AuthMethod::Dkim,
            "spf" => AuthMethod::Spf,
            "dmarc" => AuthMethod::Dmarc,
            "arc" => AuthMethod::Arc,
            _ => AuthMethod::Other,
        };
        let (domain_of, identity) = match method {
            AuthMethod::Dkim => (
                prop("header.d").or_else(|| prop("header.i").map(after_at)),
                prop("header.i").and_then(ident),
            ),
            AuthMethod::Spf => (prop("smtp.mailfrom").map(after_at), None),
            AuthMethod::Dmarc => (prop("header.from"), None),
            _ => (None, None),
        };
        methods.push(AuthMethodResult {
            method,
            result: outcome(&raw.result),
            domain: domain_of.and_then(domain),
            identity,
        });
    }
    Some((
        AuthResult {
            authserv_id,
            position,
            methods,
        },
        cut,
    ))
}

fn valid_tag_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One `DKIM-Signature` value as a fact, or `None` when it is not a tag-list (an entry without
/// `=`, an invalid or repeated tag name) or is too long.
pub(crate) fn dkim_tags(value: &str) -> Option<DkimTags> {
    if value.len() > MAX_FIELD_BYTES {
        return None;
    }
    let mut tags = DkimTags::default();
    let mut seen: Vec<&str> = Vec::new();
    let mut signed = SignedCounts::default();
    for spec in value.split(';') {
        if spec.chars().all(is_ws) {
            continue;
        }
        let (name, raw) = spec.split_once('=')?;
        let name = name.trim_matches(is_ws);
        if !valid_tag_name(name) || seen.contains(&name) {
            return None;
        }
        seen.push(name);
        let trimmed = raw.trim_matches(is_ws);
        match name {
            "d" => tags.d = domain(trimmed),
            "s" => tags.s = ident(&trimmed.to_lowercase()),
            "b" => {
                let b: String = raw
                    .chars()
                    .filter(|c| !is_ws(*c))
                    .take(B_PREFIX_LEN)
                    .collect();
                tags.b_prefix = (!b.is_empty()
                    && b.bytes()
                        .all(|x| x.is_ascii_alphanumeric() || b"+/=".contains(&x)))
                .then_some(b);
            }
            "h" => {
                let mut n = 0usize;
                for field in trimmed.split(':') {
                    let field = field.trim_matches(is_ws).to_ascii_lowercase();
                    if field.is_empty() {
                        continue;
                    }
                    n += 1;
                    match field.as_str() {
                        "from" => signed.from = signed.from.saturating_add(1),
                        "list-unsubscribe" => {
                            signed.list_unsubscribe = signed.list_unsubscribe.saturating_add(1)
                        }
                        "list-unsubscribe-post" => {
                            signed.list_unsubscribe_post =
                                signed.list_unsubscribe_post.saturating_add(1)
                        }
                        _ => {}
                    }
                }
                tags.signed_fields = sat(n);
            }
            "l" => tags.body_length = true,
            _ => {}
        }
    }
    tags.signed = signed;
    Some(tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_full_field() {
        let (ar, cut) = auth_result(
            "MX.Example.ORG 1; dkim=pass (2048-bit key; unprotected) header.d=News.Example.com \
             header.i=@news.example.com header.s=S1 header.b=\"AbC1+/=xyz\"; \
             spf=pass (sender ok) smtp.mailfrom=bounce@example.com; dmarc=pass action=none \
             header.from=example.com; arc=none",
            3,
        )
        .unwrap();
        assert!(!cut);
        assert_eq!(ar.authserv_id, "mx.example.org");
        assert_eq!(ar.position, 3);
        let m = &ar.methods;
        assert_eq!(m.len(), 4);
        assert_eq!(
            (m[0].method, m[0].result, m[0].domain.as_deref()),
            (
                AuthMethod::Dkim,
                AuthOutcome::Pass,
                Some("news.example.com")
            )
        );
        assert_eq!(m[0].identity.as_deref(), Some("@news.example.com"));
        assert_eq!(m[1].domain.as_deref(), Some("example.com"));
        assert_eq!(m[2].domain.as_deref(), Some("example.com"));
        assert_eq!(
            (m[3].method, m[3].result),
            (AuthMethod::Arc, AuthOutcome::None)
        );
    }

    #[test]
    fn a_commented_pass_is_not_a_pass() {
        let (ar, _) = auth_result(
            "mx.example.org (a (nested; comment)); dkim=fail (dkim=pass header.d=a.example.com) header.d=a.example.com",
            0,
        )
        .unwrap();
        assert_eq!(ar.methods.len(), 1);
        assert_eq!(ar.methods[0].result, AuthOutcome::Fail);
    }

    #[test]
    fn hostile_values() {
        assert!(auth_result("  (only a comment) ", 0).is_none());
        assert!(auth_result("", 0).is_none());
        assert!(auth_result("mx\u{202E}.example.org; dkim=pass", 0).is_none());
        let many = format!("mx.example.org{}", "; dkim=pass".repeat(40));
        let (ar, cut) = auth_result(&many, 0).unwrap();
        assert!(cut && ar.methods.len() == MAX_AUTH_METHODS);
        let deep = format!("mx.example.org; dkim=pass {}", "(".repeat(10_000));
        assert!(auth_result(&deep, 0).is_some());
        assert!(auth_result(&"a".repeat(MAX_FIELD_BYTES + 1), 0).is_none());
        let (ar, _) = auth_result(
            "mx.example.org; dkim=pass header.d=\"evil\r\nexample.com\"",
            0,
        )
        .unwrap();
        assert_eq!(ar.methods[0].domain, None);
    }

    #[test]
    fn dkim_tags_with_folding() {
        let t = dkim_tags(
            "v=1; a=rsa-sha256; d=News.Example.com;\r\n s=S1;\r\n\th=From:To:Subject:\r\n List-Unsubscribe : list-unsubscribe:From;\r\n bh=abc; l=1234;\r\n b=AbC12345\r\n\t xyz+/ ==;",
        )
        .unwrap();
        assert_eq!(t.d.as_deref(), Some("news.example.com"));
        assert_eq!(t.s.as_deref(), Some("s1"));
        assert_eq!(t.b_prefix.as_deref(), Some("AbC12345"));
        assert_eq!(t.signed.from, 2);
        assert_eq!(t.signed.list_unsubscribe, 2);
        assert_eq!(t.signed_fields, 6);
        assert!(t.body_length);
        assert!(dkim_tags("d=example.com; d=example.org").is_none());
        assert!(dkim_tags("d=example.com; garbage").is_none());
        assert_eq!(dkim_tags("b=<script>").unwrap().b_prefix, None);
    }
}
