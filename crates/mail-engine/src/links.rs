use std::collections::HashMap;

use rinse_doc_model::SafeUrl;
use rinse_mail::{
    LinkDestination, LinkInfo, LinkWarnings, TextFindings, link_destination, text_names_other_host,
};
use url::Url;

/// A link destination after checking, before its text is known.
#[derive(Debug, Clone)]
pub(crate) struct Checked {
    pub(crate) href: Option<SafeUrl>,
    host: Option<String>,
    display_host: Option<String>,
    pub(crate) warnings: LinkWarnings,
}

/// Checks a link destination. `None` for links that go nowhere and are simply ignored: empty,
/// fragment-only or relative (a message has no base URL).
pub(crate) fn check(raw: &str, max_len: usize) -> Option<Checked> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let cleaned = cleaned.trim_matches(|c: char| c.is_ascii_whitespace() || c.is_control());
    if cleaned.is_empty() || cleaned.starts_with('#') {
        return None;
    }
    let absolute = if cleaned.starts_with("//") {
        format!("https:{cleaned}")
    } else {
        cleaned.to_owned()
    };
    let scheme_end = absolute.find(':')?;
    if absolute[..scheme_end].contains(['/', '?', '#']) {
        return None;
    }
    let scheme = absolute[..scheme_end].to_ascii_lowercase();
    let mut warnings = LinkWarnings::default();
    let removed = |mut warnings: LinkWarnings, unsupported: bool| {
        if unsupported {
            warnings.unsupported_scheme_removed = true;
        } else {
            warnings.malformed_removed = true;
        }
        Some(Checked {
            href: None,
            host: None,
            display_host: None,
            warnings,
        })
    };
    if !matches!(scheme.as_str(), "https" | "http" | "mailto" | "tel") {
        if !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return None;
        }
        return removed(warnings, true);
    }
    let Ok(url) = Url::parse(&absolute) else {
        return removed(warnings, false);
    };
    let Some(destination) = link_destination(url.as_str()) else {
        return removed(warnings, false);
    };
    let LinkDestination {
        host,
        display_host,
        warnings: found,
    } = destination;
    warnings = found;
    let Some(href) = SafeUrl::new(url.as_str(), max_len) else {
        return removed(warnings, false);
    };
    Some(Checked {
        href: Some(href),
        host,
        display_host,
        warnings,
    })
}

/// Completes a checked link with its text: flags text that names another host.
pub(crate) fn finish(checked: Checked, text: &str, findings: &mut TextFindings) -> LinkInfo {
    let mut warnings = checked.warnings;
    let text = crate::text::display(text, 200, findings);
    if let Some(host) = &checked.host
        && text_names_other_host(host, &text)
    {
        warnings.text_href_mismatch = true;
    }
    LinkInfo {
        href: checked.href,
        display_host: checked.display_host,
        text,
        warnings,
    }
}

/// The links of one message, each destination once, capped.
pub(crate) struct Links {
    pub(crate) list: Vec<LinkInfo>,
    seen: HashMap<String, usize>,
    max: usize,
}

impl Links {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            list: Vec::new(),
            seen: HashMap::new(),
            max,
        }
    }

    /// Whether no more link will be listed.
    pub(crate) fn is_full(&self) -> bool {
        self.list.len() >= self.max
    }

    /// Lists `info`, or merges it into the entry with the same destination: the stored
    /// entry keeps every warning either one carries, and takes the text of the occurrence
    /// whose text names another host, so a later deceptive occurrence is never hidden behind
    /// an earlier honest one.
    pub(crate) fn add(&mut self, info: LinkInfo) {
        if let Some(href) = &info.href
            && let Some(&i) = self.seen.get(href.as_str())
        {
            let stored = &mut self.list[i];
            let b = info.warnings;
            if b.text_href_mismatch && !stored.warnings.text_href_mismatch {
                stored.text = info.text;
            }
            let a = &mut stored.warnings;
            a.punycode |= b.punycode;
            a.mixed_script |= b.mixed_script;
            a.text_href_mismatch |= b.text_href_mismatch;
            a.ip_host |= b.ip_host;
            a.userinfo |= b.userinfo;
            return;
        }
        if self.list.len() >= self.max {
            return;
        }
        if let Some(href) = &info.href {
            self.seen.insert(href.as_str().to_owned(), self.list.len());
        }
        self.list.push(info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(href: &str, text: &str) -> LinkInfo {
        finish(
            check(href, 2048).unwrap(),
            text,
            &mut TextFindings::default(),
        )
    }

    #[test]
    fn plain_link_has_no_warnings() {
        let l = info("https://www.example.com/a", "www.example.com/a");
        assert_eq!(l.warnings, LinkWarnings::default());
        assert_eq!(l.href.unwrap().as_str(), "https://www.example.com/a");
        assert_eq!(l.display_host.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn flags() {
        let l = info("https://xn--exmple-cua.com/", "https://example.com");
        assert!(l.warnings.punycode && l.warnings.text_href_mismatch && !l.warnings.mixed_script);
        assert_eq!(l.display_host.as_deref(), Some("ex\u{e4}mple.com"));
        let l = info("https://ex\u{430}mple.com/", "Account");
        assert!(l.warnings.punycode && l.warnings.mixed_script && !l.warnings.text_href_mismatch);
        assert!(info("http://192.0.2.1/", "x").warnings.ip_host);
        assert!(info("http://3221225985/", "x").warnings.ip_host);
        let l = info(
            "https://www.example.com@evil.example.org/",
            "www.example.com",
        );
        assert!(l.warnings.userinfo && l.warnings.text_href_mismatch);
        assert!(
            !info("https://mail.example.com/", "example.com")
                .warnings
                .text_href_mismatch
        );
    }

    #[test]
    fn removed_and_ignored() {
        for bad in [
            "javascript:alert(1)",
            " JaVaScRiPt:alert(1)",
            "java\tscript:x",
            "data:text/html,x",
            "vbscript:x",
            "file:///etc/passwd",
        ] {
            let c = check(bad, 2048).unwrap();
            assert!(
                c.href.is_none() && c.warnings.unsupported_scheme_removed,
                "{bad}"
            );
        }
        for ignored in ["", "#top", "page.html", "/path", "?q=1"] {
            assert!(check(ignored, 2048).is_none(), "{ignored}");
        }
        let long = format!("https://example.com/{}", "a".repeat(3000));
        assert!(check(&long, 2048).unwrap().warnings.malformed_removed);
        assert!(check("//example.com/x", 2048).unwrap().href.is_some());
        assert!(check("mailto:a@example.com", 2048).unwrap().href.is_some());
    }

    #[test]
    fn a_shared_destination_keeps_every_warning() {
        let mut links = Links::new(10);
        links.add(info("https://evil.example.org/", "here"));
        links.add(info(
            "https://evil.example.org/",
            "https://bank.example.com/login",
        ));
        links.add(info("https://example.com/", "example.com"));
        assert_eq!(links.list.len(), 2);
        assert!(links.list[0].warnings.text_href_mismatch);
        assert_eq!(links.list[0].text, "https://bank.example.com/login");
        assert!(!links.list[1].warnings.text_href_mismatch);
    }
}
