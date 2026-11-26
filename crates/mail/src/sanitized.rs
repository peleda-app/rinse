/// Why markup fails [`check_sanitized_html`]. No variant carries any byte of the markup, so the
/// error can be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HtmlViolation {
    /// A comment, doctype, CDATA section or processing instruction.
    #[error("comment or declaration")]
    Declaration,
    /// A `<` that does not start a tag.
    #[error("bare '<' in markup")]
    BareLessThan,
    /// A tag or quoted attribute value without its end.
    #[error("unterminated tag or attribute")]
    Unterminated,
    /// An element that can run, load, embed or submit something, or a document-level element.
    #[error("element not allowed")]
    Element,
    /// An event handler attribute.
    #[error("event handler attribute")]
    EventHandler,
    /// A character reference other than `&amp;`, `&quot;` and `&nbsp;` in an attribute value.
    #[error("character reference in attribute")]
    CharacterReference,
    /// A `javascript:`, `vbscript:`, `livescript:` or `data:text` URL.
    #[error("script URL")]
    ScriptUrl,
    /// Inline CSS that can load or run something.
    #[error("unsafe inline style")]
    Style,
    /// A `srcset` attribute.
    #[error("srcset attribute")]
    Srcset,
    /// A URL attribute that points outside the message, or a remote or protocol-relative URL.
    #[error("URL outside the message")]
    ExternalUrl,
}

const BANNED: &[&str] = &[
    "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet", "form", "input",
    "button", "textarea", "select", "option", "meta", "base", "link", "svg", "math", "template",
    "noscript", "param", "audio", "video", "source", "track", "portal", "html", "head", "body",
    "title", "image",
];

const URL_ATTRS: &[&str] = &[
    "src",
    "href",
    "background",
    "action",
    "formaction",
    "poster",
    "xlink:href",
    "cite",
    "longdesc",
    "usemap",
    "data",
    "codebase",
    "lowsrc",
    "dynsrc",
    "ping",
    "manifest",
    "profile",
    "archive",
    "classid",
];

/// The attribute value a browser sees, if it holds no character reference other than the three
/// the sanitizer's serializer writes.
fn decode_value(raw: &str) -> Result<String, HtmlViolation> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let (text, len) = if rest.starts_with("&amp;") {
            ("&", 5)
        } else if rest.starts_with("&quot;") {
            ("\"", 6)
        } else if rest.starts_with("&nbsp;") {
            ("\u{a0}", 6)
        } else {
            return Err(HtmlViolation::CharacterReference);
        };
        out.push_str(text);
        rest = &rest[len..];
    }
    out.push_str(rest);
    Ok(out)
}

fn check_attribute(attr: &str, raw_value: &str) -> Result<(), HtmlViolation> {
    if attr.starts_with("on") {
        return Err(HtmlViolation::EventHandler);
    }
    if attr == "srcset" || attr == "imagesrcset" {
        return Err(HtmlViolation::Srcset);
    }
    let value = decode_value(raw_value)?;
    let compact: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    for bad in ["javascript:", "vbscript:", "livescript:", "data:text"] {
        if compact.contains(bad) {
            return Err(HtmlViolation::ScriptUrl);
        }
    }
    let is_url = URL_ATTRS.contains(&attr);
    if attr == "style" {
        for bad in [
            "url(",
            "expression",
            "@import",
            "\\",
            "behavior",
            "-moz-binding",
            "image-set",
            "image(",
            "src(",
        ] {
            if compact.contains(bad) {
                return Err(HtmlViolation::Style);
            }
        }
    }
    if is_url || attr == "style" {
        if compact.contains("//") || compact.contains('\\') {
            return Err(HtmlViolation::ExternalUrl);
        }
        if compact.contains("http:") || compact.contains("https:") {
            return Err(HtmlViolation::ExternalUrl);
        }
    }
    if is_url
        && !compact.is_empty()
        && !["peleda-image:", "peleda-remote:", "peleda-link:", "#"]
            .iter()
            .any(|p| compact.starts_with(p))
    {
        return Err(HtmlViolation::ExternalUrl);
    }
    Ok(())
}

/// Checks markup against the guarantees of [`SanitizedHtml`](crate::SanitizedHtml): no active,
/// embedding or document-level element, no comment or declaration, no event handler, no
/// `srcset`, no character reference in an attribute value other than `&amp;`, `&quot;` and
/// `&nbsp;` (the values are checked as a browser decodes them), no script URL, no CSS that loads
/// or runs anything, no `//` or `\` in URL attributes or styles, and no URL attribute other than
/// `peleda-image:`, `peleda-remote:`, `peleda-link:` and fragments. Tag and attribute names are
/// compared without ASCII case. Returns the first problem found.
///
/// Part of [`verify_rendered`](crate::verify_rendered), which the core runs on every response.
pub fn check_sanitized_html(html: &str) -> Result<(), HtmlViolation> {
    let lower = html.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0;
    while let Some(start) = lower[i..].find('<').map(|p| p + i) {
        let mut j = start + 1;
        if matches!(bytes.get(j), Some(b'!' | b'?')) {
            return Err(HtmlViolation::Declaration);
        }
        if bytes.get(j) == Some(&b'/') {
            j += 1;
        }
        let name_start = j;
        while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || b"-:_".contains(&bytes[j])) {
            j += 1;
        }
        let name = &lower[name_start..j];
        if name.is_empty() {
            return Err(HtmlViolation::BareLessThan);
        }
        if BANNED.contains(&name) {
            return Err(HtmlViolation::Element);
        }
        loop {
            while j < bytes.len() && (bytes[j].is_ascii_whitespace() || bytes[j] == b'/') {
                j += 1;
            }
            match bytes.get(j) {
                None => return Err(HtmlViolation::Unterminated),
                Some(b'>') => {
                    j += 1;
                    break;
                }
                _ => {}
            }
            let attr_start = j;
            while j < bytes.len() && !b" \t\r\n\x0c/>=".contains(&bytes[j]) {
                j += 1;
            }
            let attr = &lower[attr_start..j];
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let mut value = "";
            if bytes.get(j) == Some(&b'=') {
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                match bytes.get(j) {
                    Some(&q @ (b'"' | b'\'')) => {
                        let end = lower[j + 1..]
                            .find(q as char)
                            .map(|p| p + j + 1)
                            .ok_or(HtmlViolation::Unterminated)?;
                        value = &lower[j + 1..end];
                        j = end + 1;
                    }
                    _ => {
                        let vs = j;
                        while j < bytes.len() && !bytes[j].is_ascii_whitespace() && bytes[j] != b'>'
                        {
                            j += 1;
                        }
                        value = &lower[vs..j];
                    }
                }
            }
            check_attribute(attr, value)?;
        }
        i = j;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_sanitizer_output() {
        let ok = r##"<p style="color: red; font-family: &quot;A B&quot;">Tom &amp; Jerry &lt;x&gt;
            <a href="peleda-link:0" rel="noopener noreferrer nofollow" title="a &amp; b">x</a>
            <img src="peleda-image:00ff" alt="&nbsp;"><img src="peleda-remote:1"><a href="#top">t</a></p>"##;
        assert_eq!(check_sanitized_html(ok), Ok(()));
    }

    #[test]
    fn rejects_hostile_markup() {
        let cases: &[(&str, HtmlViolation)] = &[
            (
                r#"<div style="background-image:u&#114;l(&#47;&#47;evil.example.org/p.png)">"#,
                HtmlViolation::CharacterReference,
            ),
            (
                r#"<div style="background:url&#40;https&#58;//evil.example.org/p)">"#,
                HtmlViolation::CharacterReference,
            ),
            (
                r#"<div style="background:u&#92;72l(x)">"#,
                HtmlViolation::CharacterReference,
            ),
            (
                r#"<div style="background:u&#x5C;72l(x)">"#,
                HtmlViolation::CharacterReference,
            ),
            (
                r#"<a href="&#106;avascript:alert(1)">"#,
                HtmlViolation::CharacterReference,
            ),
            (
                r#"<a href="java&Tab;script:alert(1)">"#,
                HtmlViolation::CharacterReference,
            ),
            (
                r#"<a href="&#x6a&#x61vascript:x">"#,
                HtmlViolation::CharacterReference,
            ),
            (
                r#"<a href="JaVaScRiPt:alert(1)">"#,
                HtmlViolation::ScriptUrl,
            ),
            (
                r#"<a href="java	script:alert(1)">"#,
                HtmlViolation::ScriptUrl,
            ),
            (r#"<div style="background:u\72l(x)">"#, HtmlViolation::Style),
            (r#"<div style="background:URL(x)">"#, HtmlViolation::Style),
            (
                r#"<div style="width:expression(alert(1))">"#,
                HtmlViolation::Style,
            ),
            (
                r#"<div style="color:red;//evil.example.org">"#,
                HtmlViolation::ExternalUrl,
            ),
            (
                r#"<img srcset="peleda-image:aa 1x, //evil.example.org/p.png 2x">"#,
                HtmlViolation::Srcset,
            ),
            (r#"<IMG SRCSET="peleda-image:aa">"#, HtmlViolation::Srcset),
            (
                r#"<img src="peleda-image:aa//evil.example.org">"#,
                HtmlViolation::ExternalUrl,
            ),
            (
                r#"<img src="peleda-image:\\evil.example.org">"#,
                HtmlViolation::ExternalUrl,
            ),
            (
                r#"<img src="//evil.example.org/p.png">"#,
                HtmlViolation::ExternalUrl,
            ),
            (
                r#"<img src="https://evil.example.org/p.png">"#,
                HtmlViolation::ExternalUrl,
            ),
            (
                r#"<img src=peleda-remote:0#https://x>"#,
                HtmlViolation::ExternalUrl,
            ),
            (r#"<ScRiPt>alert(1)</script>"#, HtmlViolation::Element),
            (r#"<p><STYLE>p{}</STYLE>"#, HtmlViolation::Element),
            (
                r#"<img src="peleda-image:a" ONERROR="x()">"#,
                HtmlViolation::EventHandler,
            ),
            (
                "<img\x0csrc=\"peleda-image:a\"\x0conload=\"x()\">",
                HtmlViolation::EventHandler,
            ),
            (
                "<img/src=\"peleda-image:a\"/onload=x()>",
                HtmlViolation::EventHandler,
            ),
            (
                "<a\nhref\n=\n'//evil.example.org'>",
                HtmlViolation::ExternalUrl,
            ),
            ("<!-- x -->", HtmlViolation::Declaration),
            ("<p title=\"x>", HtmlViolation::Unterminated),
            ("a < b", HtmlViolation::BareLessThan),
        ];
        for (html, expected) in cases {
            assert_eq!(check_sanitized_html(html), Err(*expected), "{html}");
        }
    }

    #[test]
    fn errors_echo_no_input() {
        let err = check_sanitized_html("<evil-tag onevilattr=1>").unwrap_err();
        assert!(!err.to_string().contains("evil"));
        assert!(!format!("{err:?}").contains("evil"));
    }
}
