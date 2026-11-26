# rinse-mail-engine

The content pipeline itself: a pure, synchronous library that does the real work behind `rinse-mail`. No I/O, no global state, no clock, no threads. It builds for `wasm32-wasip2`, so the content worker can run it inside the WebAssembly sandbox; `rinse-mail-direct` runs it in-process.

The engine is not a security wall on its own. It is written to be robust (memory-safe Rust, `unsafe` forbidden, the parser's DOM, image decoding and every output bounded, work linear in the input apart from the bounded HTML parse), but the walls are the sandbox it runs in and the validation the core applies to what it returns.

## API

- `render(&RenderRequest) -> Result<Rendered, ContentError>`
- `render_until(&RenderRequest, stop: &dyn Fn() -> bool)`: `render` that returns `Timeout` soon after `stop` returns true. It asks between small steps (256 bytes of HTML fed to the parser, 4,096 DOM nodes walked, one image, 1,024 lines of text, each body part), so an in-process caller whose timeout cannot kill the thread gets it back quickly.
- `decode_part(&PartRequest) -> Result<DecodedPart, ContentError>`

All keep every guarantee of [`rinse-mail`](../../mail/docs/README.md) except the time budget, which the caller enforces (a fuel or epoch deadline in the worker, a timeout in `mail-direct`).

## What it does

1. **Input size** is checked against `max_input_bytes` before anything is parsed.
2. **MIME** with `mail-parser` (nesting depth 16, 1,000 parts, 2 levels of encoded nested messages; all charsets through `encoding_rs`). Any damaged part sets `findings.damaged_structure`. The body is the HTML version when one exists, otherwise the text version, with inline image parts in between.
3. **Headers** are normalized with `rinse_text::normalize_line`: names 200, addresses 320, subject and Message-ID 500 graphemes, 100 addresses per field. Every display string (headers, file names, link texts and hosts) is also cut to at most four characters per allowed grapheme and never more than 1,000 characters (`DISPLAY_MAX_CHARS`), ending in `…`, because one grapheme (an emoji ZWJ chain, stacked combining marks) can be arbitrarily long.
4. **HTML to the document model**: `html5ever` builds the DOM into a bounded sink, then the DOM is walked with an explicit stack (never recursion). Parsing is bounded before the walk: at most 4 MiB of each HTML part are parsed; the part is cut before the formatting start tag (`a`, `b`, `font`, `i`, ...) that would leave more than 1,000 of them open at once, because the tree builder rescans and rebuilds that list on every such tag and every new block (quadratic time and, with distinct attributes, quadratic nodes); the sink creates at most 400,000 nodes per message and no element deeper than 4,096 levels, and once either limit is hit it freezes the tree (new elements are created detached, every change is dropped) and the input stops being fed within 256 bytes. Parse errors are not stored. Any of these cuts sets `findings.truncated` and rules out the original HTML. Measured in release mode: a formatting-reconstruction bomb or 400,000 nested `div`s render in about 30 ms and under 110 MB of RSS. The walk skips elements deeper than 512 levels and stops after 400,000 nodes, also counted as truncation. `head`, `script`, `style`, `template`, `svg`, `math`, `noscript`, media and form controls are dropped with their content; frames, objects, embeds, forms, meta refresh and `base` are counted as active content; event handler attributes and `javascript:`/`vbscript:` links as scripts; CSS `url()`, `@import`, external style sheets and `background` attributes as remote references. Elements hidden with CSS (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, collapsed `max-height`) are dropped and counted. Inline styles map to the allowlist: bold, italic, underline, strike, code, alignment, and color to the nearest `Tone` (blacks, whites and transparent map to the default color). Tables with `th`, or bordered with two or more columns and no nested table, become data tables; every other table is layout and flattens into its cells' content. Containers that would break the depth limit are flattened instead of nested; once a count limit is reached the rest is dropped and `findings.truncated` is set.
5. **Plain text**: blank lines separate paragraphs, line breaks stay, `>` lines become quotes (6 levels), `https://`, `http://`, `mailto:` and `www.` tokens become links. Each line is lowercased once and scanned forward once (linear time); scanning stops when the document is full, and once the link list is full further URLs stay plain text.
6. **Images**: `cid:` parts, `data:` images (base64, raster types only) and the remote images provided in the request are decoded with `image` under `image::Limits` (at most 16,384 pixels per side, allocations at most a quarter of `memory_bytes`, also checked from the header before decoding), flattened to the first frame, scaled to `min(max_image_px, doc.max_image_px)`, and re-encoded as RGBA PNG without metadata, named by BLAKE3. PNG, JPEG, GIF, WebP and BMP are accepted; SVG and everything else is dropped and counted. Images declared or decoded at 2x2 pixels or less, or hidden, are tracking pixels: dropped and counted. Each image is decoded once per message whatever spelling refers to it: the cache key is `part:<id>` for `cid:` and inline parts, the BLAKE3 of the bytes for `data:` and provided remote images. Each message gets at most `2 * max_images` (at least 8) decode attempts and 400 million decoded pixels; after that, images are dropped and counted. Remote URLs are parsed and normalized with `url` and listed only if `rinse_mail::remote_image_url_ok` accepts them (no internal hosts or IP literals, no userinfo); remote images not provided are listed in `remote_images` (500 at most) and counted as remote references. The total PNG bytes stay under three quarters of `max_output_bytes`.
7. **Links** are parsed with `url`; hosts are decoded with `idna` for display and flagged for punycode labels, mixed scripts in a label (`unicode-security`), IP hosts and userinfo; text that names another host than the destination is flagged. Schemes other than `https`, `http`, `mailto` and `tel` are removed (the text stays), as are malformed and overlong URLs. Fragment-only and relative links are ignored. Each destination is listed once: a later link to the same destination merges into the first entry, which keeps every warning of either (and the text of the occurrence whose text names another host), because the document maps every link with that destination to that one entry.
8. **Attachments** come from the message's attachment list with a normalized file name, the declared type, a type sniffed from the first bytes (PE, ELF, Mach-O, scripts, HTML, SVG, OLE, RTF, PDF, archives, ISO, images, iCalendar, vCard) and the most dangerous `AttachmentRisk` of the three signals. The extension is taken as Windows sees it (an NTFS stream suffix such as `::$DATA` and trailing dots and spaces ignored); a zip container counts as an archive unless its extension is a zip-based document format (OOXML, OpenDocument, iWork, EPUB).
9. **Original HTML**, only when asked and only when no HTML part was cut by a parsing bound or the walk's depth limit: each HTML part on its own (markup cannot carry over into the next part) through `ammonia` with its default tag allowlist plus `center` and `font`; `title`, `noscript`, `template`, `svg`, `math`, frames, objects, form controls and `head` dropped with their content; comments stripped; inline CSS reduced to an allowlist of layout and text properties whose values cannot load anything; `cid:`, `data:` and provided remote images rewritten to `peleda-image:<id>`, other remote images to `peleda-remote:<index>`, links to `peleda-link:<index>`, `srcset` and everything else removed. The result must pass `rinse_mail::check_sanitized_html`, or it is dropped.
10. **Facts** (`src/facts`, `rinse_mail::facts`), from the parsed message after the body is built: the top-level header fields are read raw and unfolded (at most 4,096 fields, 4 MiB per value) for the header signals (Holtmail's rules), `List-Id`, `List-Unsubscribe` (RFC 2369, strict) and `List-Unsubscribe-Post`, `In-Reply-To` and `References` (constant memory: the first id and a ring of the last 31); `Authentication-Results` and `DKIM-Signature` go through a grammar ported from Holtmail's `auth-results` crate (same author; comments stripped, quoted strings unquoted, fields over 16 KiB skipped). The HTML step collects `<script type="application/ld+json">` text from the whole DOM, `head` included (at most 8 scripts; a script over 64 KiB is skipped), and per link destination a button hint and the `aria-label` or `title`; the JSON is parsed with `serde_json` (its recursion limit of 128 stops nesting bombs), at most 64 nodes per script are looked at, and only the closed schema.org subset is mapped, every value type-checked (an object where a string belongs, a float where a decimal belongs, a `javascript:` or internal URL, an impossible date: the field is left out). `.pkpass` attachments (at most 4, 4 MiB each) are read with a small zip reader: one `pass.json`, stored or deflated (`miniz_oxide`, inflating stops at 64 KiB), not encrypted. The first `text/calendar` part or `.ics` attachment with a `VEVENT` is unfolded and read (at most 256 KiB and 20,000 lines; nested components such as `VALARM` ignored). Layout walks the finished body once. All strings go through the same display normalization as headers, identifiers must survive it unchanged, domains go through `idna`.
11. **Output**: the body is validated against the document limits before returning (a failure is a bug and returns `LimitExceeded(Document)`); if the postcard size exceeds `max_output_bytes`, the original HTML is dropped first, then the call fails with `LimitExceeded(Output)`.

## Building for WebAssembly

```sh
cargo build -p rinse-mail-engine --target wasm32-wasip2
```

The toolchain must have the `wasm32-wasip2` standard library (`rustup target add wasm32-wasip2`).

## Tests

Unit tests next to each module (`src/facts/*` carry attack tests for every grammar), plus the `rinse-mail` conformance suite through a small in-process adapter (`cargo test -p rinse-mail-engine`).

## Dependencies and licenses

| Crate | License |
| --- | --- |
| `mail-parser` 1.0 (`full_encoding`) | Apache-2.0 OR MIT |
| `encoding_rs` (through `mail-parser`) | (Apache-2.0 OR MIT) AND BSD-3-Clause |
| `html5ever` 0.40, `markup5ever_rcdom` 0.40 | MIT OR Apache-2.0 |
| `ammonia` 4.2 | MIT OR Apache-2.0 |
| `image` 0.25 (png, jpeg, gif, webp, bmp; no rayon) | MIT OR Apache-2.0 |
| `url` 2.5, `idna` 1.1 | MIT OR Apache-2.0 |
| `unicode-security` 0.1 | MIT OR Apache-2.0 |
| `blake3` 1.8 | CC0-1.0 OR Apache-2.0 |
| `data-encoding` 2.11 | MIT |
| `postcard` 1.1 | MIT OR Apache-2.0 |
| `serde_json` 1.0 | MIT OR Apache-2.0 |
| `miniz_oxide` 0.8 (already used by `png`) | MIT OR Zlib OR Apache-2.0 |
