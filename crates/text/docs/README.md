# rinse-text

Normalization of display text that came from outside (sender names, subjects, file names, snippets) before it reaches the UI, notifications or widgets. A pure library with no I/O; used by the content worker, the core and the widget snapshot.

## API

- `normalize_line(input, max_graphemes) -> Normalized` returns one line of NFC text and the `Findings` of what was removed or cut.
- `is_bidi_control(c)`, `is_invisible(c)` classify single characters.

## Guarantees

- The output contains no bidirectional control characters (U+202A–202E, U+2066–2069, LRM, RLM, ALM), so a name or file name cannot reorder the text around it (`invoice\u{202E}fdp.exe`).
- The output contains no zero-width or invisible characters (zero-width space and non-joiner, word joiner, invisible operators, BOM, soft hyphen, Hangul fillers, tag characters). Zero-width joiners stay only between emoji parts, so emoji sequences still render as one glyph.
- The output contains no control characters; all whitespace, line breaks included, collapses to single spaces, and leading and trailing whitespace is removed.
- The output has at most `max_graphemes` grapheme clusters plus a trailing `…` when it was cut; clusters are never split.
- `Findings` reports every kind of removal, so the UI can mark a sender whose name hid characters.

It does not detect homoglyphs or mixed scripts; link and domain checks live in the content pipeline.
