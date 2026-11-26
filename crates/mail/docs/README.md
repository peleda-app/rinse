# rinse-mail

Contract of the content pipeline: the raw bytes of an untrusted message go in; the safe document model, normalized headers, re-encoded images, checked links, classified attachments and, on request, sanitized HTML come out. Contract crate: the trait, the types in its signatures and its error. Every type is serde, so requests and responses cross a process or WebAssembly boundary unchanged.

## The trait

```rust
#[async_trait]
pub trait Content: Send + Sync {
    async fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError>;
    async fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError>;
}
```

- `render` turns an RFC 5322 message into a `Rendered`. Malformed messages render as far as possible; only input that is not a message at all fails with `Malformed`.
- `decode_part` transfer-decodes one leaf part (an `Attachment::part` id from `render` of the same bytes) for saving. Decoding is parsing, so it stays behind the same walls.

## Requests

- `RenderRequest { raw, options, limits }`
- `RenderOptions { want_original_html, max_image_px, remote_images: Vec<RemoteImage { url, bytes }> }`: remote images are fetched by the core (only when the person allowed it) and handed in for re-encoding; the URL is the one the previous render listed in `Rendered::remote_images`.
- `ContentLimits { doc: rinse_doc_model::Limits, max_input_bytes, max_output_bytes, time_budget_ms, memory_bytes }`; defaults: default document limits, 32 MiB in, 48 MiB out (postcard size of the response), 2 s, 256 MiB.
- `PartRequest { raw, part, limits }`

## Responses

- `Rendered { headers, body, text, images, remote_images, attachments, links, original_html, findings, facts }`
- `Headers { from, to, cc, reply_to: Vec<MailAddress { name, address }>, subject, date (Unix seconds), message_id }`: every text normalized by `rinse_text::normalize_line` (one line, NFC, no bidi controls, invisible or control characters) and length-capped; at most `MAX_ADDRESSES` (100) addresses per field. Every display string of a response (header texts, file names, media types, link texts and hosts) holds at most `DISPLAY_MAX_CHARS` (1,000) characters, whatever its grapheme count.
- `EncodedImage { id, width, height, png }`: `id` is the lowercase hex BLAKE3 hash of `png`, a PNG without metadata, at most `max_image_px` (and `doc.max_image_px`) on each side.
- `Attachment { part, file_name, declared_type, sniffed_type, size, risk, inline }`, with `AttachmentRisk` one of `Executable`, `Script`, `MacroDocument`, `DiskImage`, `Archive`, `Document`, `Image`, `Calendar`, `Contact`, `Other`: the most dangerous class suggested by the extension, the declared type or the first bytes.
- `LinkInfo { href: Option<SafeUrl>, display_host, text, warnings }` (text at most 200 graphemes and 800 characters) with `LinkWarnings { punycode, mixed_script, text_href_mismatch, ip_host, userinfo, unsupported_scheme_removed, malformed_removed }`; `href` is `None` when the link was removed. `display_host` and the destination warnings are a function of `href` and `text`: `link_destination(href)` gives the host, the display host (the Unicode form of a domain, its ASCII form when the Unicode form is not a display string, an IP address, `None` for `mailto:` and `tel:`) and `punycode`, `mixed_script`, `ip_host`, `userinfo`; `text_names_other_host(host, text)` gives `text_href_mismatch`. Implementations use them, receivers check against them, and consumers can call them instead of reading the fields.
- `remote_images`: URLs accepted by `remote_image_url_ok`: lowercase `http(s)`, `SafeUrl` characters, no userinfo, no `localhost`/`.local`/`.internal`/`.home.arpa` name and no loopback, private, link-local, CGNAT, unspecified, multicast or reserved IP literal. **They are chosen by the sender.** Whoever fetches them (the core, or the node in connected mode) must check the address it actually connects to on every connection (DNS rebinding), must not follow redirects to hosts that fail the same rules, and must cap the response size.
- `SanitizedHtml { html, remote_images, links }`: images point at `peleda-image:<id>` or `peleda-remote:<index>`, links at `peleda-link:<index>`.
- `facts: MessageFacts`: see [Facts](#facts).
- `Findings`: counts of scripts removed, active content removed, remote references, tracking pixels, dropped images, hidden content, header and body `TextFindings`, plus `truncated` and `damaged_structure`.

## Facts

`rinse_mail::facts` holds what a message says beyond its display, for bento and its notification policy (`../../../../bento/docs/ARCHITECTURE.md`, "What rinse-mail provides"). The engine extracts it inside the worker; nothing in it is verified (an `Authentication-Results` field or a JSON-LD order can be forged by any sender), so consumers weigh it against Pellet's verdict.

```rust
pub struct MessageFacts {
    pub header: HeaderFacts,              // signals, From counts, Sender, List-Id
    pub auth: AuthFacts,                  // Authentication-Results and DKIM-Signature grammar
    pub list: ListFacts,                  // List-Unsubscribe targets, RFC 8058 one-click
    pub thread: ThreadFacts,              // In-Reply-To, References (capped)
    pub structured: Vec<StructuredItem>,  // closed schema.org subset and Wallet passes
    pub invitation: Option<InvitationFacts>,
    pub layout: LayoutFacts,              // forward and footer markers, link placement
}
```

- **`HeaderFacts`**: `signals: HeaderSignals` (bits of `HeaderSignal`, positions append-only: `ListId` 0, `ListPost` 1, `ListPostNo` 2, `Unsubscribe` 3, `UnsubscribePost` 4, `PrecedenceBulk` 5, `AutoSubmitted` 6, `AutoReplied` 7, `FeedbackId` 8, `Esp` 9, `Noreply` 10; `HeaderSignals::KNOWN` masks them), `from_fields`, `from_addresses` (in the first `From`), `sender` (first `Sender` mailbox), `list_id` (inside the angle brackets, lowercase).
- **`AuthFacts`**: `results: Vec<AuthResult { authserv_id, position, methods: Vec<AuthMethodResult { method, result, domain, identity }> }>` (at most `MAX_AUTH_RESULTS` = 16 fields from the top, `MAX_AUTH_METHODS` = 16 per field; `position` counts every `Authentication-Results` field from the top, so a consumer trusts only results at the position its own server writes; comments are ignored, so a `pass` inside parentheses is no result), `signatures: Vec<DkimTags { d, s, b_prefix, signed, signed_fields, body_length }>` (at most `MAX_DKIM_SIGNATURES` = 8; `b_prefix` the first 8 characters; `signed` counts `from`, `list-unsubscribe`, `list-unsubscribe-post` in `h=`; fields that are not a valid tag-list are dropped), `field_counts` and `cap_hit`.
- **`ListFacts`**: `unsubscribe: Vec<UnsubscribeTarget>` (at most 4) from the first `List-Unsubscribe`, read strictly by RFC 2369 (bracketed items, white space inside ignored, reading stops at the first unbracketed item); `Https(SafeUrl)` only for lowercase `https://` URLs that pass `remote_image_url_ok` (public host, no userinfo), `Mailto(MailtoTarget { address, subject, body })` only with one address and no header field but `subject` and `body` (a `bcc`, `cc` or `to` drops the target); the percent-decoded address has none of `<>()[],;:"\?&=%#/` and white space, so rebuilding `mailto:{address}?subject=...` cannot add a header field. Items with control characters, `http`, `javascript:` and every other scheme are dropped. `one_click` needs exactly one `List-Unsubscribe-Post: List-Unsubscribe=One-Click` and an `https` target. Whoever POSTs must still check the address it connects to.
- **`ThreadFacts`**: `in_reply_to`, `references` (at most `MAX_REFERENCES` = 32: the first and the last 31), `references_cut`.
- **`StructuredItem`**: `Reservation` (flight, lodging, train, bus, rental car, event, food: number, status, name, provider, start, end, from, to, url), `Order` (number, merchant, status, total, date, url), `Invoice` (number, provider, total, due, status, url), `Parcel` (carrier, tracking number and URL, expected window, order number), `Action` (view, confirm, save, track, RSVP: name and URL; top level or an `EmailMessage`'s `potentialAction`) and `Pass` (Apple Wallet: style, organization, description, relevant date). Times are `When::{Instant(unix seconds), Local(LocalDateTime), Date(CalendarDate)}` within the years 1970 to 2200, money is `Price { amount: decimal string, currency: ISO 4217 }`, never a float. At most `MAX_STRUCTURED_ITEMS` = 16. Never raw JSON.
- **`InvitationFacts`**: from the first `VEVENT` of the first `text/calendar` part or `.ics` attachment: `method`, `uid`, `sequence`, `summary`, `organizer` (`mailto:` address and `CN`), `start`, `end`, `time_zone` (`TZID` of a local start), `location`, `status`, `attendees` count.
- **`LayoutFacts`**: `forward_at` and `footer_at` are block indices of `Rendered::body` in depth-first pre-order (containers before their children); `links: Vec<LinkPlacement { button_like, in_footer, below_forward, aria_label }>` has one entry per `Rendered::links` entry. The footer starts at the first block with an unsubscribe link (by URL, text or label, in English, German, French, Russian or Spanish) or a `©`; placement is that of a link's first occurrence in the body; `button_like` means some occurrence had a background or padding on the link or its table cell, or `role="button"`, and at most 40 graphemes of text.

Rules for every fact: strings follow the display rules of `Headers` and `DISPLAY_MAX_CHARS`; identifiers (Message-IDs, `List-Id`, authserv-ids, selectors, UIDs, order, reservation and tracking numbers) are also at most `ID_MAX_CHARS` (255) characters without white space; domains are lowercase ASCII (punycode); URLs pass `remote_image_url_ok`. Values that break a rule are left out by the engine, never repaired.

## Errors

`ContentError`: `InputTooLarge` (checked before any parsing), `LimitExceeded(LimitKind::{Output, Memory, Document})`, `Timeout`, `Crashed`, `Malformed`, `PartNotFound`, `Unavailable`. No variant carries input bytes.

## What an implementation must do

- Check `max_input_bytes` before parsing and fail with `InputTooLarge`.
- Never panic, hang or recurse without bound on any input; turn crashes and traps into `Crashed` and budget overruns into `Timeout`.
- Return a body that passes `rinse_doc_model::validate` with `request.limits.doc` and the ids of `Rendered::images`; plain text within `doc.max_text_bytes` with the same character rules (plus line breaks); at most `doc.max_images` images and `doc.max_links` links; a response whose postcard encoding fits `max_output_bytes`.
- Produce `original_html` only when asked, and only if it passes `check_sanitized_html`: no `script`, `style`, `iframe`, `object`, `embed`, `form`, `meta`, `base`, `link`, `svg` or similar element, no comment, no event handler, no `srcset`, no character reference in an attribute value other than `&amp;`, `&quot;` and `&nbsp;` (values are checked as a browser decodes them), no `javascript:` or `vbscript:` URL, no CSS that loads or runs anything, no `//` or `\` in URL attributes and styles, no URL attribute other than the `peleda-` schemes and fragments, no remote `http(s)` URL. Its error, `HtmlViolation`, names the rule and carries no byte of the markup.
- Keep the content of scripts, styles, frames and templates out of every output, and content hidden with CSS out of the body and the plain text.

## Validation by the receiver

The core trusts nothing an implementation returns. It checks the postcard size of a response before decoding it, decodes a render response with `decode_render_response(bytes, &ContentLimits)` (a decode budget of `render_decode_budget(limits)` sequence elements: every node a valid body can hold, links, images, addresses, the capped fact lists and `RENDER_DECODE_ALLOWANCE`; every `Vec` of `Rendered` except byte buffers is read with `rinse_doc_model::bounded_vec`, so a compromised worker cannot turn a small encoding into a value a hundred times larger before the limits below are checked), then runs `verify_rendered(&RenderRequest, &Rendered)` (or `verify_decoded_part(&PartRequest, &DecodedPart)`) on it, whatever implementation produced it, and drops it on failure. `verify_rendered` checks every attacker-controlled field:

- `body`: `rinse_doc_model::validate` with `request.limits.doc` and the returned image ids (failure: `LimitExceeded(Document)`);
- `images`: ids unique, each the lowercase BLAKE3 of PNG bytes, sizes within `min(options.max_image_px, doc.max_image_px)`, at most `doc.max_images`;
- `links`: at most `doc.max_links`, every `href` a `SafeUrl` within `doc.max_url_len` (deserializing a `SafeUrl` already runs the link rules, with a 64 KiB cap); `display_host` and the destination warnings equal to what `link_destination` and `text_names_other_host` derive from `href` and `text`, no removal flag on a link with an `href`, no `display_host` on one without (a compromised worker can neither show another host nor clear a warning);
- `text`: within `doc.max_text_bytes`, preformatted character rules;
- display strings (addresses, names, subject, Message-ID, file names, declared and sniffed types, link texts and hosts): one line under the document text rules, at most `DISPLAY_MAX_CHARS` characters; at most `MAX_ADDRESSES` per address field;
- `remote_images` and `original_html.remote_images`: `remote_image_url_ok`;
- `original_html`: only when asked, `check_sanitized_html`, its `links` `SafeUrl`s;
- `facts`: `verify_facts(&RenderRequest, &Rendered)`, called by `verify_rendered`: only known signal bits, every string a display string, identifiers and domains as above, every list within its cap, `Authentication-Results` positions strictly increasing and below `field_counts.authentication_results` (unless it is saturated at 255), `from_fields` equal to `field_counts.from`, domains only on DKIM, SPF and DMARC results and identities only on DKIM, `one_click` only with an `https` target, `field_counts.list_unsubscribe_post` equal to 1 and the `UnsubscribePost` signal, `time_zone` only with a `When::Local` start, every URL a `SafeUrl` within `doc.max_url_len` passing `remote_image_url_ok` (unsubscribe URLs `https://` only), mailto targets one address without `?&=%#/`, prices and times in range, layout indices inside the body, exactly one placement per link, `in_footer` only with `footer_at` and `below_forward` only with `forward_at`.

Any other failure is `Crashed`. Not checked: whether the `peleda-` references inside the original HTML resolve; the viewer treats an unknown reference as missing. `verify_decoded_part` checks the part id, the size against `max_output_bytes` (`LimitExceeded(Output)`) and the display strings.

## Conformance suite

Enable the `testing` feature and call `rinse_mail::testing::run(Arc<dyn Content>)` from a test of the implementation (any async runtime). The suite renders the hostile corpus in [`fixtures/hostile`](../fixtures/hostile/README.md) with default, tight and tiny-output limits and with an input limit one byte too small, with and without original HTML, with remote image bytes provided, broken or missing, and decodes every attachment; the facts fixtures check what the facts must say (forged authentication results, unsubscribe injection, `javascript:` targets, gigantic `References`, JSON-LD bombs and type confusion, bidi in a calendar organizer, forward and footer layout, Wallet passes and a pass zip bomb). `testing::facts_message(data)` builds a message with `data` spliced into every place facts are read from, for fuzzing. `testing::check_rendered` runs `verify_rendered` and adds the output size, a postcard round trip and the absence of script and hidden content.

## Dependencies

`rinse-doc-model`, `async-trait`, `blake3` (CC0-1.0 OR Apache-2.0, for the image id check), `bytes` (with `serde`), `serde`, `thiserror`; with `testing`: `postcard`.
