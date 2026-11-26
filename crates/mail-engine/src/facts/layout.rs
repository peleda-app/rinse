use std::collections::HashMap;

use rinse_doc_model::{Block, Document, Inline};
use rinse_mail::LinkInfo;
use rinse_mail::facts::{LayoutFacts, LinkPlacement};

/// What the HTML walk saw about the occurrences of one link destination.
#[derive(Debug, Clone, Default)]
pub(crate) struct LinkHint {
    /// Some occurrence looked like a button.
    pub(crate) button: bool,
    /// `aria-label`, else `title`, of the first occurrence with one, already display text.
    pub(crate) label: Option<String>,
}

const DASHED: &[&str] = &[
    "forwarded message",
    "weitergeleitete nachricht",
    "message transféré",
    "пересылаемое сообщение",
];
const PLAIN: &[&str] = &["begin forwarded message"];
const UNSUBSCRIBE: &[&str] = &[
    "unsubscribe",
    "opt out",
    "opt-out",
    "abmelden",
    "abbestellen",
    "désabonner",
    "desabonner",
    "désinscri",
    "desinscri",
    "отписаться",
    "отписка",
    "darse de baja",
];

/// Whether a line is an inline-forward marker: `---------- Forwarded message ---------` and its
/// German, French and Russian forms (at least two dashes first), or `Begin forwarded message:`.
pub(crate) fn is_marker(line: &str) -> bool {
    let line = line.trim_start();
    let rest = line.trim_start_matches('-');
    let dashes = line.len() - rest.len();
    let head: String = rest
        .trim_start()
        .chars()
        .take(32)
        .flat_map(char::to_lowercase)
        .collect();
    PLAIN.iter().any(|p| head.starts_with(p))
        || (dashes >= 2 && DASHED.iter().any(|p| head.starts_with(p)))
}

fn unsubscribe_words(s: &str) -> bool {
    let lower = s.to_lowercase();
    UNSUBSCRIBE.iter().any(|w| lower.contains(w))
}

struct Scan<'a> {
    hints: &'a HashMap<String, LinkHint>,
    lines: Vec<String>,
    footer: bool,
    links: Vec<&'a str>,
}

impl<'a> Scan<'a> {
    fn inlines(&mut self, inlines: &'a [Inline]) {
        for inline in inlines {
            match inline {
                Inline::Text { text, .. } => {
                    if self.lines.is_empty() {
                        self.lines.push(String::new());
                    }
                    if let Some(last) = self.lines.last_mut()
                        && last.len() < 256
                    {
                        last.push_str(crate::text::cut(text, 256));
                    }
                    self.footer |= text.contains('©');
                }
                Inline::LineBreak => self.lines.push(String::new()),
                Inline::Link { href, inlines } => {
                    let start = self.lines.len();
                    self.inlines(inlines);
                    let shown: String = self.lines[start.saturating_sub(1)..].concat();
                    let label = self
                        .hints
                        .get(href.as_str())
                        .and_then(|h| h.label.as_deref())
                        .unwrap_or_default();
                    self.footer |= href.as_str().to_ascii_lowercase().contains("unsubscribe")
                        || unsubscribe_words(&shown)
                        || unsubscribe_words(label);
                    self.links.push(href.as_str());
                }
            }
        }
    }
}

/// Markers and link placement, block indices in depth-first pre-order.
pub(crate) fn layout(
    body: &Document,
    links: &[LinkInfo],
    hints: &HashMap<String, LinkHint>,
) -> LayoutFacts {
    let mut forward_at = None;
    let mut footer_at = None;
    let mut first_at: HashMap<&str, u32> = HashMap::new();
    let mut stack: Vec<&Block> = body.blocks.iter().rev().collect();
    let mut index: u32 = 0;
    while let Some(block) = stack.pop() {
        let mut scan = Scan {
            hints,
            lines: Vec::new(),
            footer: false,
            links: Vec::new(),
        };
        match block {
            Block::Paragraph { inlines, .. } | Block::Heading { inlines, .. } => {
                scan.inlines(inlines)
            }
            Block::Preformatted(text) => {
                scan.lines = text.lines().take(10_000).map(str::to_owned).collect();
                scan.footer = text.contains('©');
            }
            Block::Quote(children) => stack.extend(children.iter().rev()),
            Block::List { items, .. } => {
                for item in items.iter().rev() {
                    stack.extend(item.iter().rev());
                }
            }
            Block::Table { rows } => {
                for row in rows.iter().rev() {
                    for cell in row.iter().rev() {
                        stack.extend(cell.blocks.iter().rev());
                    }
                }
            }
            Block::Image(_) | Block::Divider => {}
        }
        if forward_at.is_none() && scan.lines.iter().any(|l| is_marker(l)) {
            forward_at = Some(index);
        }
        if footer_at.is_none() && scan.footer {
            footer_at = Some(index);
        }
        for href in scan.links {
            first_at.entry(href).or_insert(index);
        }
        index = index.saturating_add(1);
    }
    let links = links
        .iter()
        .map(|link| {
            let href = link.href.as_ref().map(|h| h.as_str());
            let at = href.and_then(|h| first_at.get(h)).copied();
            let hint = href.and_then(|h| hints.get(h));
            LinkPlacement {
                button_like: hint.is_some_and(|h| h.button),
                in_footer: matches!((at, footer_at), (Some(a), Some(f)) if a >= f),
                below_forward: matches!((at, forward_at), (Some(a), Some(f)) if a > f),
                aria_label: hint.and_then(|h| h.label.clone()),
            }
        })
        .collect();
    LayoutFacts {
        forward_at,
        footer_at,
        links,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers() {
        assert!(is_marker("---------- Forwarded message ---------"));
        assert!(is_marker("  -------- Пересылаемое сообщение --------"));
        assert!(is_marker("Begin forwarded message:"));
        assert!(!is_marker("I read the forwarded message yesterday."));
        assert!(!is_marker("-Forwarded message"));
        assert!(!is_marker("-----Original Message-----"));
    }
}
