use rinse_mail::{DISPLAY_MAX_CHARS, TextFindings};
use rinse_text::{is_bidi_control, is_invisible, normalize_line};

/// Text for a text run: bidi controls, invisible and control characters removed, every kind of
/// line break and tab turned into a space. Records one finding per kind found in `input`.
pub(crate) fn clean_inline(input: &str, findings: &mut TextFindings) -> String {
    clean(input, false, findings)
}

/// Text for a preformatted block: like [`clean_inline`] but keeps `\n` and `\t`.
pub(crate) fn clean_multiline(input: &str, findings: &mut TextFindings) -> String {
    clean(&input.replace("\r\n", "\n"), true, findings)
}

fn clean(input: &str, multiline: bool, findings: &mut TextFindings) -> String {
    let mut out = String::with_capacity(input.len());
    let (mut bidi, mut invisible, mut control) = (false, false, false);
    for c in input.chars() {
        if is_bidi_control(c) {
            bidi = true;
        } else if is_invisible(c) {
            invisible = true;
        } else if multiline && (c == '\n' || c == '\t') {
            out.push(c);
        } else if matches!(
            c,
            '\t' | '\n' | '\r' | '\u{0B}' | '\u{0C}' | '\u{2028}' | '\u{2029}' | '\u{85}'
        ) {
            out.push(' ');
        } else if c.is_control() {
            control = true;
        } else {
            out.push(c);
        }
    }
    findings.bidi_controls += u32::from(bidi);
    findings.invisible += u32::from(invisible);
    findings.controls += u32::from(control);
    out
}

/// One line of display text with at most `max` grapheme clusters and at most
/// `min(4 * max, DISPLAY_MAX_CHARS)` characters (a single grapheme can be arbitrarily long),
/// findings recorded. A cut ends in `…`.
pub(crate) fn display(input: &str, max: usize, findings: &mut TextFindings) -> String {
    let n = normalize_line(input, max);
    findings.bidi_controls += u32::from(n.findings.bidi_controls);
    findings.invisible += u32::from(n.findings.invisible);
    findings.controls += u32::from(n.findings.controls);
    let max_chars = max.saturating_mul(4).clamp(1, DISPLAY_MAX_CHARS);
    let mut text = n.text;
    let mut cut = n.findings.truncated;
    if let Some((end, _)) = text.char_indices().nth(max_chars) {
        let keep = text[..end]
            .char_indices()
            .nth(max_chars - 1)
            .map_or(end, |(i, _)| i);
        text.truncate(keep);
        text.push('\u{2026}');
        cut = true;
    }
    findings.truncated += u32::from(cut);
    text
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a character boundary.
pub(crate) fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_graphemes_are_capped_in_characters() {
        let mut f = TextFindings::default();
        let zwj = format!("\u{1F44D}{}", "\u{200D}\u{1F44D}".repeat(3000));
        let out = display(&zwj, 500, &mut f);
        assert_eq!(out.chars().count(), DISPLAY_MAX_CHARS);
        assert!(out.ends_with('\u{2026}'));
        assert_eq!(f.truncated, 1);
        let marks = format!("x{}", "\u{301}".repeat(3000));
        let out = display(&marks, 200, &mut f);
        assert_eq!(out.chars().count(), 800);
        assert_eq!(display("short", 200, &mut f), "short");
        assert_eq!(f.truncated, 2);
    }
}
