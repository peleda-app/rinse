#![no_main]

use libfuzzer_sys::fuzz_target;
use rinse_text::{Caps, Findings, is_bidi_control, is_invisible, normalize};
use unicode_segmentation::UnicodeSegmentation;

fn cap(byte: u8) -> usize {
    if byte == u8::MAX {
        usize::MAX
    } else {
        usize::from(byte)
    }
}

fn emoji_part(c: char) -> bool {
    matches!(c, '\u{1F000}'..='\u{1FAFF}' | '\u{2600}'..='\u{27BF}' | '\u{FE0F}')
}

fuzz_target!(|data: &[u8]| {
    let [graphemes, bytes, rest @ ..] = data else {
        return;
    };
    let caps = Caps {
        graphemes: cap(*graphemes),
        bytes: cap(*bytes),
    };
    let input = String::from_utf8_lossy(rest);
    let once = normalize(&input, caps);
    let again = normalize(&once.text, caps);
    assert_eq!(again.text, once.text);
    assert_eq!(again.findings, Findings::default());
    assert!(once.text.len() <= caps.bytes);
    assert!(once.text.graphemes(true).count() <= caps.graphemes);
    let chars: Vec<char> = once.text.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        assert!(!is_bidi_control(c) && !is_invisible(c), "{c:?}");
        assert!(!c.is_control(), "{c:?}");
        if c == '\u{200D}' {
            assert!(
                i > 0 && emoji_part(chars[i - 1]),
                "joiner after {:?}",
                chars.get(i.wrapping_sub(1))
            );
            assert!(
                chars.get(i + 1).copied().is_some_and(emoji_part),
                "joiner before {:?}",
                chars.get(i + 1)
            );
        }
    }
});
