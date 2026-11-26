use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use ammonia::UrlRelative;
use rinse_doc_model::SafeUrl;
use rinse_mail::{SanitizedHtml, check_sanitized_html};

use crate::links;

const CSS_PROPERTIES: &[&str] = &[
    "color",
    "background-color",
    "font-weight",
    "font-style",
    "font-size",
    "font-family",
    "line-height",
    "text-align",
    "text-decoration",
    "text-transform",
    "letter-spacing",
    "vertical-align",
    "white-space",
    "word-break",
    "width",
    "height",
    "max-width",
    "min-width",
    "margin",
    "margin-top",
    "margin-right",
    "margin-bottom",
    "margin-left",
    "padding",
    "padding-top",
    "padding-right",
    "padding-bottom",
    "padding-left",
    "border",
    "border-top",
    "border-right",
    "border-bottom",
    "border-left",
    "border-color",
    "border-width",
    "border-style",
    "border-collapse",
    "border-spacing",
    "border-radius",
    "display",
];

/// Inline CSS reduced to allowlisted properties whose values cannot load or run anything.
pub(crate) fn filter_css(style: &str) -> Option<String> {
    let mut out = Vec::new();
    for (prop, value) in crate::style::declarations(style) {
        if !CSS_PROPERTIES.contains(&prop.as_str()) || value.len() > 200 {
            continue;
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " #%.,()-+'\"!".contains(c))
        {
            continue;
        }
        let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        let mut ok = true;
        for (i, _) in compact.match_indices('(') {
            let before = &compact[..i];
            if !["rgb", "rgba", "hsl", "hsla"]
                .iter()
                .any(|f| before.ends_with(f))
            {
                ok = false;
            }
        }
        for bad in [
            "url",
            "expression",
            "image",
            "javascript",
            "behavior",
            "binding",
            "import",
        ] {
            if compact.contains(bad) {
                ok = false;
            }
        }
        if ok {
            out.push(format!("{prop}: {value}"));
        }
    }
    (!out.is_empty()).then(|| out.join("; "))
}

/// The HTML parts of the message, each sanitized on its own (markup cannot leak from one part
/// into the next) and joined, for the Original view: images through `src_map`
/// (source as written to `peleda-image:` or `peleda-remote:`), links to `peleda-link:<index>`,
/// everything else that could run, load or submit removed. `None` when the result fails
/// [`check_sanitized_html`].
pub(crate) fn original(
    parts: &[String],
    src_map: &HashMap<String, String>,
    remote_images: &[String],
    max_url_len: usize,
) -> Option<SanitizedHtml> {
    type Found = (Vec<SafeUrl>, HashMap<String, usize>);
    let links: Arc<Mutex<Found>> = Arc::default();
    let found = Arc::clone(&links);
    let src_map = Arc::new(src_map.clone());
    let schemes: HashSet<&str> = ["http", "https", "mailto", "tel", "cid", "data"].into();
    let mut builder = ammonia::Builder::default();
    builder
        .add_tags(["center", "font"])
        .add_clean_content_tags([
            "title",
            "noscript",
            "template",
            "svg",
            "math",
            "iframe",
            "object",
            "textarea",
            "select",
            "option",
            "button",
            "head",
            "frameset",
            "noembed",
            "noframes",
            "xmp",
            "plaintext",
            "embed",
            "applet",
            "form",
        ])
        .add_generic_attributes([
            "style",
            "align",
            "valign",
            "bgcolor",
            "width",
            "height",
            "border",
            "cellpadding",
            "cellspacing",
        ])
        .add_tag_attributes("font", ["color", "face", "size"])
        .url_schemes(schemes)
        .url_relative(UrlRelative::Deny)
        .strip_comments(true)
        .link_rel(Some("noopener noreferrer nofollow"))
        .attribute_filter(move |_element, attribute, value| match attribute {
            "href" => {
                let href = links::check(value, max_url_len)?.href?;
                let mut guard = found.lock().unwrap_or_else(|e| e.into_inner());
                let (list, index) = &mut *guard;
                let i = match index.get(href.as_str()) {
                    Some(&i) => i,
                    None => {
                        index.insert(href.as_str().to_owned(), list.len());
                        list.push(href);
                        list.len() - 1
                    }
                };
                Some(Cow::Owned(format!("peleda-link:{i}")))
            }
            "src" => src_map.get(value.trim()).map(|r| Cow::Owned(r.clone())),
            "style" => filter_css(value).map(Cow::Owned),
            "cite" | "background" | "longdesc" | "usemap" | "srcset" | "imagesrcset" => None,
            _ => Some(Cow::Borrowed(value)),
        });
    let cleaned = parts
        .iter()
        .map(|part| builder.clean(part).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    drop(builder);
    let links = std::mem::take(&mut links.lock().unwrap_or_else(|e| e.into_inner()).0);
    check_sanitized_html(&cleaned).ok()?;
    Some(SanitizedHtml {
        html: cleaned,
        remote_images: remote_images.to_vec(),
        links,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn css_allowlist() {
        assert_eq!(
            filter_css("color: red; position: fixed; background: url(x)").as_deref(),
            Some("color: red")
        );
        assert_eq!(filter_css("width: expression(alert(1))"), None);
        assert_eq!(
            filter_css("color: rgb(1, 2, 3)").as_deref(),
            Some("color: rgb(1, 2, 3)")
        );
        assert_eq!(filter_css("color: var(--x)"), None);
        assert_eq!(filter_css("font-family: a\\62 c"), None);
        assert_eq!(filter_css("background-color: image-set(x)"), None);
    }

    #[test]
    fn rewrites_and_removes() {
        let mut map = HashMap::new();
        map.insert("cid:logo".to_owned(), "peleda-image:abc".to_owned());
        map.insert(
            "https://example.com/r.png".to_owned(),
            "peleda-remote:0".to_owned(),
        );
        let html = r#"<p onclick="x()">Hi <a href="https://example.com/a">a</a>
            <a href="javascript:alert(1)">b</a><img src="cid:logo"><img src="https://example.com/r.png">
            <img src="https://example.com/other.png"><script>bad()</script><iframe src="https://example.com"></iframe>
            <form action="https://example.com"><input name="p"></form><style>p{}</style><!-- c --></p>"#;
        let out = original(
            &[html.to_owned()],
            &map,
            &["https://example.com/r.png".into()],
            2048,
        )
        .unwrap();
        assert!(out.html.contains("peleda-link:0"));
        assert!(out.html.contains("peleda-image:abc"));
        assert!(out.html.contains("peleda-remote:0"));
        assert!(!out.html.contains("other.png"));
        assert!(!out.html.contains("bad()"));
        assert_eq!(out.links.len(), 1);
        check_sanitized_html(&out.html).unwrap();
    }
}
