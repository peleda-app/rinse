# rinse-doc-model

The safe document model (wall 3 of [WALLS.md](../../../docs/WALLS.md)): the only shape a message body has once it leaves the content worker. A closed, versioned schema that the UI renders with its own components, the limits it must stay within, validation, and a compact binary encoding. A pure library: no I/O, no global state.

## Schema (version 1)

- `Document { version, blocks }`
- `Block`: `Paragraph { align, inlines }`, `Heading { level 1..=6, align, inlines }`, `Quote(blocks)`, `List { ordered, items: Vec<Vec<Block>> }`, `Table { rows: Vec<Vec<Cell { header, blocks }>> }`, `Preformatted(String)`, `Image(ImageRef { id, alt, width, height })`, `Divider`
- `Align`: `Start`, `Center`, `End`
- `Inline`: `Text { text, style }`, `Link { href: SafeUrl, inlines }`, `LineBreak`
- `Style { bold, italic, underline, strike, code, tone: Option<Tone> }`
- `Tone`: a small palette (`Gray`, `Red`, `Orange`, `Yellow`, `Green`, `Teal`, `Blue`, `Purple`, `Pink`, `Brown`) that the UI maps to design tokens readable in both themes; `None` is the default text color.
- `ImageRef.id` is the lowercase hex BLAKE3 hash of the re-encoded image bytes.

## API and guarantees

- `validate(&Document, &Limits, is_known_image) -> Result<(), Violation>` returns the first broken rule:
  - schema version is `SCHEMA_VERSION`;
  - nesting depth (top-level blocks are depth 1; the content of a quote, list item, table cell, paragraph, heading or link is one level deeper), block count (every block, list item, table row and table cell counts), inline count, total text bytes (text runs, preformatted text and alt texts), links, images, URL length, table rows and columns, image dimensions, all within `Limits`; `Limits::max_depth` is capped at `MAX_DEPTH` (32);
  - links are `https:`/`http:` (with a host), `mailto:` or `tel:` only, without whitespace, control, bidi or invisible characters;
  - text contains no bidi control (`rinse_text::is_bidi_control`), no invisible character (`rinse_text::is_invisible`), and no control character except tab (and line feed in preformatted text);
  - no list without items, table without rows, empty list item or empty row (cells may be empty, so columns stay aligned);
  - headings are level 1 to 6; images are 64 lowercase hex characters for which `is_known_image` returns true.
  It runs in linear time and recurses no deeper than the depth limit.
- `SafeUrl::new(url, max_len)` builds a link destination only if it passes the same link rules. Deserializing a `SafeUrl` runs them too, with a cap of `SAFE_URL_MAX_LEN` (64 KiB), so no unchecked `SafeUrl` comes out of any serde format.
- `encode(&Document)` writes `FORMAT_VERSION` (1) and the postcard encoding. `decode(bytes, &Limits, is_known_image)` refuses another format byte, malformed or trailing bytes, and returns the document only if it validates. It decodes under a budget of `max_blocks + max_inlines` nodes (`with_decode_budget`), so a flood of one-byte nodes fails while decoding instead of allocating about 120 bytes per byte first.
- `with_decode_budget(elements, f)` and `bounded_vec` (a `deserialize_with` helper): a per-thread budget of sequence elements for decoding untrusted postcard; a declared length above what is left fails at once, every element takes one. The document's wire nodes always read through it; without a budget decoding is unbounded.
- Serde: `Document` serializes as a flat pre-order list of nodes with child counts, not as nested values. Deserializing it from any serde format rebuilds the tree with recursion bounded by `WIRE_MAX_DEPTH` (128), so hostile input cannot overflow the stack; serializing a deeper document fails. `Block` and `Inline` have no serde impls of their own for this reason.

## Default limits

Depth 16, 20,000 blocks (list items, rows and cells included), 100,000 inline runs, 4 MiB of text, 2,000 links, 200 images, 2,048-byte URLs, tables of 1,000 rows by 64 columns, images up to 4,096 pixels on a side.

## Dependencies

`rinse-text`, `serde`, `postcard` (MIT OR Apache-2.0), `thiserror`.
