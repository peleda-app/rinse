//! Normalization of display text that came from outside: sender names, subjects,
//! file names, snippets. The output is safe to place in our UI, in notifications
//! and in widgets without reordering the layout around it or hiding characters.

use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

/// What a normalization changed, so the UI can warn about it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Findings {
    /// Bidirectional control characters were removed.
    pub bidi_controls: bool,
    /// Invisible or zero-width characters were removed.
    pub invisible: bool,
    /// Control characters other than whitespace were removed.
    pub controls: bool,
    /// The text was cut to the length limit.
    pub truncated: bool,
}

/// Normalized text and what was done to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    /// NFC text on one line, without bidi controls, invisible or control
    /// characters, with runs of whitespace collapsed to one space and no more
    /// than the requested number of grapheme clusters.
    pub text: String,
    /// What was removed or cut.
    pub findings: Findings,
}

/// True for characters that change the direction of surrounding text
/// (LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI, LRM, RLM, ALM).
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}'
    )
}

/// True for characters that render as nothing and can hide or join text:
/// zero-width spaces and joiners, word joiner, invisible operators, BOM,
/// soft hyphen, Mongolian vowel separator, Hangul fillers, tag characters,
/// variation selectors outside emoji sequences are kept.
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180E}'
            | '\u{200B}'
            | '\u{200C}'
            | '\u{2060}'..='\u{2064}'
            | '\u{206A}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// Upper bounds for [`normalize`]. The trailing `…` of a cut counts against both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// At most this many grapheme clusters.
    pub graphemes: usize,
    /// At most this many bytes of UTF-8.
    pub bytes: usize,
}

impl Caps {
    /// Only a grapheme cap.
    pub const fn graphemes(graphemes: usize) -> Self {
        Self {
            graphemes,
            bytes: usize::MAX,
        }
    }
}

const ELLIPSIS: &str = "\u{2026}";

/// Normalizes one line of display text and keeps at most `max_graphemes`
/// grapheme clusters, the trailing `…` of a cut included. Same as
/// [`normalize`] with [`Caps::graphemes`].
pub fn normalize_line(input: &str, max_graphemes: usize) -> Normalized {
    normalize(input, Caps::graphemes(max_graphemes))
}

/// Normalizes one line of display text within `caps`.
///
/// Characters are filtered first (bidi controls, invisible and control
/// characters removed, whitespace collapsed), then composed to NFC, then cut
/// on grapheme boundaries with a trailing `…` that fits inside both caps.
/// Zero-width joiners between emoji parts are kept so emoji render as one
/// glyph. The function is idempotent: normalizing its own output with the
/// same caps returns the same text and no findings. A cap too small for even
/// the `…` gives an empty string.
pub fn normalize(input: &str, caps: Caps) -> Normalized {
    let mut findings = Findings::default();
    let mut cleaned = String::with_capacity(input.len().min(caps.bytes).min(4096));
    let mut pending_space = false;
    let mut prev: Option<char> = None;
    let chars: Vec<char> = input.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if is_bidi_control(c) {
            findings.bidi_controls = true;
            continue;
        }
        if c == '\u{200D}' {
            let next = chars[i + 1..]
                .iter()
                .copied()
                .find(|&n| !is_bidi_control(n) && !is_invisible(n) && n != '\u{200D}');
            if !pending_space && prev.is_some_and(is_emoji_part) && next.is_some_and(is_emoji_part)
            {
                cleaned.push(c);
                prev = Some(c);
            } else {
                findings.invisible = true;
            }
            continue;
        }
        if is_invisible(c) {
            findings.invisible = true;
            continue;
        }
        if c.is_whitespace() {
            pending_space = !cleaned.is_empty();
            continue;
        }
        if c.is_control() {
            findings.controls = true;
            continue;
        }
        if pending_space {
            cleaned.push(' ');
            pending_space = false;
        }
        cleaned.push(c);
        prev = Some(c);
    }
    let composed: String = cleaned.nfc().collect();

    let fits =
        composed.len() <= caps.bytes && composed.graphemes(true).nth(caps.graphemes).is_none();
    if fits {
        return Normalized {
            text: composed,
            findings,
        };
    }
    findings.truncated = true;
    let mut text = String::new();
    if caps.graphemes == 0 || caps.bytes < ELLIPSIS.len() {
        return Normalized { text, findings };
    }
    let byte_room = caps.bytes - ELLIPSIS.len();
    for g in composed.graphemes(true).take(caps.graphemes - 1) {
        if text.len() + g.len() > byte_room {
            break;
        }
        text.push_str(g);
    }
    let trimmed = text.trim_end_matches('\u{200D}').trim_end().len();
    text.truncate(trimmed);
    text.push_str(ELLIPSIS);
    Normalized { text, findings }
}

fn is_emoji_part(c: char) -> bool {
    matches!(c, '\u{1F000}'..='\u{1FAFF}' | '\u{2600}'..='\u{27BF}' | '\u{FE0F}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_bidi_override_used_for_file_name_spoofing() {
        let n = normalize_line("invoice\u{202E}fdp.exe", 100);
        assert_eq!(n.text, "invoicefdp.exe");
        assert!(n.findings.bidi_controls);
    }

    #[test]
    fn removes_zero_width_characters_and_marks_them() {
        let n = normalize_line("pay\u{200B}pal\u{FEFF}", 100);
        assert_eq!(n.text, "paypal");
        assert!(n.findings.invisible);
    }

    #[test]
    fn joiner_after_collapsed_whitespace_is_dropped_so_output_is_stable() {
        for input in [
            "\u{274D} \u{200D}\u{274D}",
            "\u{1F468}\u{2004}\u{200D}\u{1F469}",
        ] {
            let once = normalize_line(input, 100);
            assert!(!once.text.contains('\u{200D}'), "{input:?}");
            assert!(once.findings.invisible);
            assert_eq!(normalize_line(&once.text, 100).text, once.text, "{input:?}");
        }
    }

    #[test]
    fn cut_never_ends_in_a_joiner_so_output_is_stable() {
        let input = "ab\u{274D}\u{200D}\u{1F469}cd";
        for graphemes in 1..8 {
            let once = normalize_line(input, graphemes);
            assert!(
                !once.text.contains("\u{200D}\u{2026}"),
                "{graphemes}: {:?}",
                once.text
            );
            let again = normalize_line(&once.text, graphemes);
            assert_eq!(again.text, once.text, "{graphemes}");
        }
    }

    #[test]
    fn keeps_emoji_zwj_sequences() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        let n = normalize_line(family, 100);
        assert_eq!(n.text, family);
        assert!(!n.findings.invisible);
    }

    #[test]
    fn collapses_whitespace_and_newlines_to_one_line() {
        let n = normalize_line("  Re:\n\tHello \r\n  world  ", 100);
        assert_eq!(n.text, "Re: Hello world");
    }

    #[test]
    fn removes_control_characters() {
        let n = normalize_line("a\u{0007}b\u{009B}c", 100);
        assert_eq!(n.text, "abc");
        assert!(n.findings.controls);
    }

    #[test]
    fn truncates_by_grapheme_clusters() {
        let n = normalize_line("e\u{0301}e\u{0301}e\u{0301}", 2);
        assert_eq!(n.text, "\u{e9}…");
        assert!(n.findings.truncated);
    }

    #[test]
    fn composes_to_nfc() {
        assert_eq!(normalize_line("e\u{0301}", 10).text, "\u{e9}");
    }

    #[test]
    fn removes_tag_characters() {
        let n = normalize_line("hi\u{E0041}\u{E0042}", 10);
        assert_eq!(n.text, "hi");
        assert!(n.findings.invisible);
    }

    #[test]
    fn composes_after_removing_hidden_characters() {
        assert_eq!(normalize_line("e\u{200B}\u{301}", 10).text, "\u{e9}");
        assert_eq!(normalize_line("e\u{202E}\u{301}", 10).text, "\u{e9}");
    }

    #[test]
    fn huge_cap_does_not_overflow() {
        assert_eq!(normalize_line("abc", usize::MAX).text, "abc");
        assert_eq!(
            normalize(
                "abc",
                Caps {
                    graphemes: usize::MAX,
                    bytes: usize::MAX
                }
            )
            .text,
            "abc"
        );
    }

    #[test]
    fn byte_cap_includes_the_ellipsis() {
        let n = normalize(
            "abcdefg",
            Caps {
                graphemes: 100,
                bytes: 6,
            },
        );
        assert_eq!(n.text, "abc…");
        assert!(n.text.len() <= 6);
        assert!(n.findings.truncated);
    }

    #[test]
    fn long_single_grapheme_is_dropped_by_byte_cap() {
        let zalgo = format!("a{}b", "\u{301}".repeat(1000));
        let n = normalize(
            &zalgo,
            Caps {
                graphemes: 10,
                bytes: 64,
            },
        );
        assert!(n.text.len() <= 64);
        assert!(n.findings.truncated);
    }

    #[test]
    fn caps_too_small_give_empty_text() {
        assert_eq!(normalize_line("abc", 0).text, "");
        assert_eq!(
            normalize(
                "abc",
                Caps {
                    graphemes: 5,
                    bytes: 2
                }
            )
            .text,
            ""
        );
    }

    #[test]
    fn idempotent_over_tricky_inputs() {
        let inputs = [
            "e\u{200B}\u{301}x",
            "\u{1F468}\u{200D}\u{202E}\u{1F469}",
            "  a \u{2066} \u{2069} b  ",
            "\u{0627}\u{0644}\u{0639}\u{0631}\u{0628}\u{064A}\u{0629} abc",
            "a\u{0007}\u{200D}\u{1F600}",
            "\u{1100}\u{1161}\u{11A8}\u{1100}\u{1161}",
        ];
        for input in inputs {
            for g in [0, 1, 2, 3, 5, 100] {
                for b in [0, 3, 4, 7, 16, usize::MAX] {
                    let caps = Caps {
                        graphemes: g,
                        bytes: b,
                    };
                    let once = normalize(input, caps);
                    let twice = normalize(&once.text, caps);
                    assert_eq!(twice.text, once.text, "{input:?} {caps:?}");
                    assert_eq!(twice.findings, Findings::default(), "{input:?} {caps:?}");
                    assert!(once.text.len() <= b);
                    assert!(once.text.graphemes(true).count() <= g);
                }
            }
        }
    }
}
