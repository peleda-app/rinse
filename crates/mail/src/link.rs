//! What a receiver derives from a link destination by itself, so that no host, display host or
//! destination warning has to be taken from the worker.

use unicode_security::MixedScript;
use url::{Host, Url};

use crate::LinkWarnings;
use crate::verify::display_text_ok;

/// What a link destination says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkDestination {
    /// The host as the browser connects to it, lowercase ASCII (punycode); `None` for an IP
    /// host and for `mailto:` and `tel:`.
    pub host: Option<String>,
    /// The host for display: the Unicode form of a domain (its ASCII form when the Unicode form
    /// is not a valid display string), an IPv4 address, or an IPv6 address in brackets; `None`
    /// for `mailto:` and `tel:`.
    pub display_host: Option<String>,
    /// `punycode`, `mixed_script`, `ip_host` and `userinfo`; every other flag is false.
    pub warnings: LinkWarnings,
}

/// The destination facts of `href`. `None` when `href` does not parse as a URL, or is an
/// `http`/`https` URL without a host.
pub fn link_destination(href: &str) -> Option<LinkDestination> {
    let url = Url::parse(href).ok()?;
    let mut warnings = LinkWarnings::default();
    if !matches!(url.scheme(), "https" | "http") {
        return Some(LinkDestination {
            host: None,
            display_host: None,
            warnings,
        });
    }
    let (host, display_host) = match url.host()? {
        Host::Domain(domain) => {
            let ascii = domain.to_ascii_lowercase();
            warnings.punycode = ascii.split('.').any(|l| l.starts_with("xn--"));
            let (unicode, _) = idna::domain_to_unicode(&ascii);
            warnings.mixed_script = unicode
                .split('.')
                .any(|label| !label.is_empty() && !label.is_single_script());
            let display = if display_text_ok(&unicode) {
                unicode
            } else {
                ascii.clone()
            };
            (Some(ascii), display)
        }
        Host::Ipv4(ip) => {
            warnings.ip_host = true;
            (None, ip.to_string())
        }
        Host::Ipv6(ip) => {
            warnings.ip_host = true;
            (None, format!("[{ip}]"))
        }
    };
    warnings.userinfo = !url.username().is_empty() || url.password().is_some();
    Some(LinkDestination {
        host,
        display_host: Some(display_host),
        warnings,
    })
}

/// Whether link text `text` reads as a single host name (optionally with scheme, user info,
/// port or path) that is not `host` (lowercase ASCII), a subdomain of it, or a parent of it;
/// `www.` is ignored on both sides.
pub fn text_names_other_host(host: &str, text: &str) -> bool {
    host_in_text(text).is_some_and(|text_host| !same_site(host, &text_host))
}

fn host_in_text(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() || t.contains(char::is_whitespace) {
        return None;
    }
    let lower = t.to_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .unwrap_or(&lower);
    let rest = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    let candidate = rest
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('.');
    let labels: Vec<&str> = candidate.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let tld = labels.last()?;
    if tld.chars().count() < 2 || !tld.chars().all(char::is_alphabetic) {
        return None;
    }
    if !candidate
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    idna::domain_to_ascii(candidate).ok()
}

fn same_site(a: &str, b: &str) -> bool {
    let a = a.strip_prefix("www.").unwrap_or(a);
    let b = b.strip_prefix("www.").unwrap_or(b);
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}
