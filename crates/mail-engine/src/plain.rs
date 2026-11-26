use rinse_doc_model::{Align, Style};

use crate::Env;
use crate::builder::Builder;
use crate::links;
use crate::text::clean_inline;

const MAX_QUOTE_DEPTH: usize = 6;
const MAX_LINES: usize = 200_000;

/// Converts a `text/plain` body: blank lines separate paragraphs, other line breaks stay,
/// lines starting with `>` become quotes, and URLs become links.
pub(crate) fn convert(text: &str, env: &mut Env<'_>, b: &mut Builder) {
    let lines: Vec<&str> = text.lines().take(MAX_LINES).collect();
    if text.lines().nth(MAX_LINES).is_some() {
        env.findings.truncated = true;
    }
    block(&lines, 0, env, b);
}

fn block(lines: &[&str], depth: usize, env: &mut Env<'_>, b: &mut Builder) {
    let mut i = 0;
    let mut in_para = false;
    while i < lines.len() && !b.is_full() {
        if (i + 1).is_multiple_of(1024) && (env.stop)() {
            return;
        }
        let line = lines[i].trim_end();
        if depth < MAX_QUOTE_DEPTH && line.starts_with('>') {
            let mut j = i;
            let mut inner = Vec::new();
            while j < lines.len() && lines[j].starts_with('>') {
                let l = &lines[j][1..];
                inner.push(l.strip_prefix(' ').unwrap_or(l));
                j += 1;
            }
            b.boundary();
            in_para = false;
            let mark = b.open_quote();
            block(&inner, depth + 1, env, b);
            match mark {
                Some(m) => b.close_to(m),
                None => b.boundary(),
            }
            i = j;
            continue;
        }
        if line.trim().is_empty() {
            b.boundary();
            in_para = false;
            i += 1;
            continue;
        }
        if in_para {
            b.line_break();
        }
        emit_line(line, env, b);
        in_para = true;
        i += 1;
    }
    b.boundary();
}

fn emit_line(line: &str, env: &mut Env<'_>, b: &mut Builder) {
    let cleaned = clean_inline(line, &mut env.findings.body_text);
    let style = Style::default();
    let mut finder = Finder::new(&cleaned);
    let mut at = 0;
    while !b.is_full() {
        let Some((start, end)) = finder.next(at) else {
            break;
        };
        b.text(&cleaned[at..start], style, Align::Start);
        let shown = &cleaned[start..end];
        at = end;
        if env.links.is_full() {
            b.text(shown, style, Align::Start);
            continue;
        }
        let href = if shown.len() >= 4 && shown[..4].eq_ignore_ascii_case("www.") {
            format!("https://{shown}")
        } else {
            shown.to_owned()
        };
        match links::check(&href, env.limits.doc.max_url_len) {
            Some(checked) => {
                let started = checked.href.clone().is_some_and(|h| b.start_link(h));
                b.text(shown, style, Align::Start);
                if started {
                    b.end_link();
                }
                let info = links::finish(checked, shown, &mut env.findings.body_text);
                env.links.add(info);
            }
            None => b.text(shown, style, Align::Start),
        }
    }
    if !b.is_full() {
        b.text(&cleaned[at..], style, Align::Start);
    }
}

const PREFIXES: [&str; 4] = ["https://", "http://", "mailto:", "www."];

/// Finds URL-looking tokens in one line: `https://`, `http://`, `mailto:` or `www.` at a token
/// start, up to whitespace or `<>"`, without trailing punctuation. The line is lowercased once and
/// each prefix is searched forward only, so a whole line takes linear time.
struct Finder<'a> {
    s: &'a str,
    lower: String,
    found: [Option<(usize, usize)>; 4],
    from: [usize; 4],
}

impl<'a> Finder<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            s,
            lower: s.to_ascii_lowercase(),
            found: [None; 4],
            from: [0; 4],
        }
    }

    /// The byte range of the first link starting at or after `at`.
    fn next(&mut self, at: usize) -> Option<(usize, usize)> {
        for k in 0..PREFIXES.len() {
            if self.found[k].is_some_and(|(p, _)| p < at) {
                self.found[k] = None;
            }
            if self.found[k].is_none() {
                self.from[k] = self.from[k].max(at);
                self.found[k] = self.scan(k);
            }
        }
        self.found.iter().flatten().min_by_key(|(p, _)| *p).copied()
    }

    fn scan(&mut self, k: usize) -> Option<(usize, usize)> {
        let prefix = PREFIXES[k];
        let s = self.s;
        while let Some(pos) = self.lower.get(self.from[k]..)?.find(prefix) {
            let pos = pos + self.from[k];
            self.from[k] = pos + prefix.len();
            let boundary = pos == 0
                || s[..pos]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_whitespace() || "<([\"'".contains(c));
            if !boundary {
                continue;
            }
            let len = s[pos..]
                .find(|c: char| c.is_whitespace() || "<>\"".contains(c))
                .unwrap_or(s.len() - pos);
            let token = s[pos..pos + len].trim_end_matches(|c: char| ".,;:!?)]}'\"".contains(c));
            if token.len() > prefix.len() {
                self.from[k] = pos + len;
                return Some((pos, pos + token.len()));
            }
        }
        self.from[k] = self.lower.len();
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find_link(s: &str) -> Option<(usize, usize)> {
        Finder::new(s).next(0)
    }

    #[test]
    fn finds_links() {
        let s = "See https://example.com/a. Or www.example.org, (http://example.com/b)";
        let (a, b) = find_link(s).unwrap();
        assert_eq!(&s[a..b], "https://example.com/a");
        let rest = &s[b..];
        let (a, b) = find_link(rest).unwrap();
        assert_eq!(&rest[a..b], "www.example.org");
        assert!(find_link("nohttps://x").is_none());
        assert!(find_link("http://").is_none());
    }

    #[test]
    fn finds_every_link_in_order() {
        let s = "a www.example.com b https://example.org/x www.example.net";
        let mut f = Finder::new(s);
        let mut at = 0;
        let mut found = Vec::new();
        while let Some((a, b)) = f.next(at) {
            found.push(&s[a..b]);
            at = b;
        }
        assert_eq!(
            found,
            [
                "www.example.com",
                "https://example.org/x",
                "www.example.net"
            ]
        );
    }

    #[test]
    fn long_lines_take_linear_time() {
        let line = "www.a ".repeat(800_000);
        let start = std::time::Instant::now();
        let mut f = Finder::new(&line);
        let mut at = 0;
        let mut n = 0;
        while let Some((_, b)) = f.next(at) {
            at = b;
            n += 1;
        }
        assert_eq!(n, 800_000);
        assert!(start.elapsed() < std::time::Duration::from_secs(20));
        let junk = "www.) ".repeat(1_000_000);
        assert!(Finder::new(&junk).next(0).is_none());
    }
}
