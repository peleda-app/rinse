//! Contract of the content pipeline: the raw bytes of an untrusted message go in, the safe
//! document model and checked metadata come out. Implementations run the parsing behind the
//! walls of `docs/WALLS.md` (a WebAssembly worker in an OS sandbox, through the sandbox layer) or, for
//! tests and the server node, in-process.
//!
//! Every request and response type is serde, so it can cross a process or WebAssembly boundary.
//! The receiving side never trusts a [`Rendered`]: it checks it with [`verify_rendered`] before
//! use.

use async_trait::async_trait;
use bytes::Bytes;
use rinse_doc_model::{Document, Limits, SafeUrl};
use serde::{Deserialize, Serialize};

mod decode;
pub mod facts;
mod link;
mod remote;
mod sanitized;
#[cfg(feature = "testing")]
pub mod testing;
mod verify;

pub use decode::{RENDER_DECODE_ALLOWANCE, decode_render_response, render_decode_budget};
pub use facts::{MessageFacts, verify_facts};
pub use link::{LinkDestination, link_destination, text_names_other_host};
pub use remote::remote_image_url_ok;
pub use sanitized::{HtmlViolation, check_sanitized_html};
pub use verify::{DISPLAY_MAX_CHARS, MAX_ADDRESSES, verify_decoded_part, verify_rendered};

/// The content pipeline.
///
/// Implementations must check [`ContentLimits::max_input_bytes`] before parsing anything, never
/// panic or hang on any input, stay within every limit of the request, and return only typed
/// errors that echo none of the input.
#[async_trait]
pub trait Content: Send + Sync {
    /// Renders one message into the document model and its metadata.
    ///
    /// Malformed messages render as far as possible: broken encodings, unknown charsets and
    /// damaged structure give partial output, not an error. The returned body passes
    /// [`rinse_doc_model::validate`] with `request.limits.doc` and the ids of
    /// [`Rendered::images`]; [`Rendered::original_html`] is present only when asked for and holds
    /// no active content and no remote URL.
    async fn render(&self, request: RenderRequest) -> Result<Rendered, ContentError>;

    /// Transfer-decodes one part of a message, for saving an attachment. The part id is
    /// [`Attachment::part`] from a [`Content::render`] of the same bytes. Fails with
    /// [`ContentError::PartNotFound`] for an id that is not a leaf part of the message.
    async fn decode_part(&self, request: PartRequest) -> Result<DecodedPart, ContentError>;
}

/// What to render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderRequest {
    /// The message as an RFC 5322 byte string.
    pub raw: Bytes,
    /// Rendering choices.
    pub options: RenderOptions,
    /// Limits the output and the work must stay within.
    pub limits: ContentLimits,
}

/// Rendering choices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderOptions {
    /// Also produce [`Rendered::original_html`] for the Original view.
    pub want_original_html: bool,
    /// Longest side in pixels of every re-encoded image; larger images are scaled down.
    pub max_image_px: u32,
    /// Remote images the core fetched for this message (only when the person allowed it),
    /// to be re-encoded like inline images.
    pub remote_images: Vec<RemoteImage>,
}

impl Default for RenderOptions {
    /// No original HTML, 1,600-pixel images, no remote images.
    fn default() -> Self {
        Self {
            want_original_html: false,
            max_image_px: 1_600,
            remote_images: Vec::new(),
        }
    }
}

/// The bytes of one remote image, fetched by the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteImage {
    /// The URL exactly as listed in [`Rendered::remote_images`].
    pub url: String,
    /// The response body, untrusted.
    pub bytes: Bytes,
}

/// Limits for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentLimits {
    /// Limits of the output document; also caps [`Rendered::text`] at
    /// `doc.max_text_bytes` and the number of images at `doc.max_images`.
    pub doc: Limits,
    /// Largest accepted message (or [`PartRequest::raw`]); larger input fails with
    /// [`ContentError::InputTooLarge`] before any parsing.
    pub max_input_bytes: u64,
    /// Largest output, measured as the postcard encoding of the response.
    pub max_output_bytes: u64,
    /// Wall-clock or fuel budget for the call in milliseconds.
    pub time_budget_ms: u64,
    /// Memory the call may use, in bytes.
    pub memory_bytes: u64,
}

impl Default for ContentLimits {
    /// Default document limits, 32 MiB input, 48 MiB output, 2 s, 256 MiB.
    fn default() -> Self {
        Self {
            doc: Limits::default(),
            max_input_bytes: 32 << 20,
            max_output_bytes: 48 << 20,
            time_budget_ms: 2_000,
            memory_bytes: 256 << 20,
        }
    }
}

/// A rendered message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rendered {
    /// The header fields the app shows, normalized for display.
    pub headers: Headers,
    /// The body as the safe document model.
    pub body: Document,
    /// Plain text of the body for search and snippets, at most `doc.max_text_bytes` bytes,
    /// with the same character rules as text runs of the document plus line breaks.
    pub text: String,
    /// Re-encoded images the body refers to, each once.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub images: Vec<EncodedImage>,
    /// Remote image URLs the body uses and the request did not provide, in document order, each
    /// once, tracking pixels excluded; each passes [`remote_image_url_ok`]. They are chosen by the
    /// sender: the core may fetch them when the person allows (re-checking the connected address
    /// and every redirect, see [`remote_image_url_ok`]) and render again with
    /// [`RenderOptions::remote_images`].
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub remote_images: Vec<String>,
    /// Parts offered as files, in message order.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub attachments: Vec<Attachment>,
    /// Links found in the body, in document order, each destination once.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub links: Vec<LinkInfo>,
    /// Sanitized HTML for the Original view, only when asked for and when it could be made safe.
    pub original_html: Option<SanitizedHtml>,
    /// What was removed or looked suspicious.
    pub findings: Findings,
    /// Facts beyond the display: header signals, authentication grammar, list and thread
    /// headers, structured data, invitations, layout. See [`facts`].
    pub facts: MessageFacts,
}

/// Header fields for display. Every text field is one line, NFC, without bidi controls,
/// invisible or control characters, and at most [`DISPLAY_MAX_CHARS`] characters; every address
/// list at most [`MAX_ADDRESSES`] long.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Headers {
    /// `From` mailboxes.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub from: Vec<MailAddress>,
    /// `To` mailboxes, groups flattened.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub to: Vec<MailAddress>,
    /// `Cc` mailboxes, groups flattened.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub cc: Vec<MailAddress>,
    /// `Reply-To` mailboxes.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub reply_to: Vec<MailAddress>,
    /// Decoded subject.
    pub subject: Option<String>,
    /// `Date` as Unix seconds; `None` when missing or invalid.
    pub date: Option<i64>,
    /// `Message-ID` without angle brackets.
    pub message_id: Option<String>,
}

/// One mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailAddress {
    /// Display name, normalized; `None` when absent or empty after normalization.
    pub name: Option<String>,
    /// The address as written, normalized like the name.
    pub address: String,
}

/// An image decoded and re-encoded by the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedImage {
    /// Lowercase hex BLAKE3 hash of `png`; the id image blocks refer to.
    pub id: String,
    /// Width in pixels, at most [`RenderOptions::max_image_px`].
    pub width: u32,
    /// Height in pixels, at most [`RenderOptions::max_image_px`].
    pub height: u32,
    /// A PNG file without metadata.
    pub png: Bytes,
}

/// A part offered as a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// Part id for [`Content::decode_part`].
    pub part: u32,
    /// File name, normalized like header text (at most [`DISPLAY_MAX_CHARS`] characters); `None`
    /// when the part has none.
    pub file_name: Option<String>,
    /// Lowercase media type from `Content-Type`; `application/octet-stream` when missing.
    pub declared_type: String,
    /// Media type recognized from the first bytes, when known.
    pub sniffed_type: Option<String>,
    /// Decoded size in bytes.
    pub size: u64,
    /// The most dangerous class suggested by the extension, the declared type or the content.
    pub risk: AttachmentRisk,
    /// Marked to be shown inside the message rather than as a download.
    pub inline: bool,
}

/// What opening an attachment could do, most dangerous first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttachmentRisk {
    /// A program: `exe`, `msi`, `app`, `apk`, `jar`, ELF, Mach-O, PE.
    Executable,
    /// Code run by an interpreter or a browser: `js`, `vbs`, `ps1`, `bat`, `sh`, `hta`, `html`,
    /// `svg`.
    Script,
    /// An office document that can carry macros: `docm`, `xlsm`, legacy `doc`, `xls`, `ppt`.
    MacroDocument,
    /// A disk image: `iso`, `img`, `dmg`, `vhd`.
    DiskImage,
    /// An archive that can hide any of the above: `zip`, `rar`, `7z`, `gz`.
    Archive,
    /// A document without macros: `pdf`, `docx`, `odt`, `txt`.
    Document,
    /// A picture.
    Image,
    /// A calendar object.
    Calendar,
    /// A contact card.
    Contact,
    /// Anything else.
    Other,
}

/// A link of the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkInfo {
    /// The destination; `None` when the link was removed (unsupported scheme, malformed, too
    /// long).
    pub href: Option<SafeUrl>,
    /// Host for display, decoded from punycode, normalized; `None` for links without a host.
    pub display_host: Option<String>,
    /// The link text, normalized, at most 200 grapheme clusters and 800 characters.
    pub text: String,
    /// Reasons to warn before opening.
    pub warnings: LinkWarnings,
}

/// Reasons to warn about a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LinkWarnings {
    /// The host has internationalized (punycode) labels.
    pub punycode: bool,
    /// A host label mixes scripts (for example Latin and Cyrillic).
    pub mixed_script: bool,
    /// The text looks like a different destination than the link.
    pub text_href_mismatch: bool,
    /// The host is an IP address.
    pub ip_host: bool,
    /// The URL carries a user name or password before the host.
    pub userinfo: bool,
    /// The link was removed because its scheme is not `https`, `http`, `mailto` or `tel`.
    pub unsupported_scheme_removed: bool,
    /// The link was removed because it is malformed or longer than the URL limit.
    pub malformed_removed: bool,
}

/// HTML for the Original view.
///
/// Holds no `script`, `style`, `iframe`, `object`, `embed`, `form`, `meta`, `base` or `link`
/// element, no event handler attribute, no `javascript:` URL and no remote URL. Images point at
/// `peleda-image:<id>` (an id of [`Rendered::images`]) or `peleda-remote:<index>` (an index of
/// [`SanitizedHtml::remote_images`]); links point at `peleda-link:<index>` (an index of
/// [`SanitizedHtml::links`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedHtml {
    /// The body markup, without `html`, `head` and `body` elements.
    pub html: String,
    /// Remote image URLs that `peleda-remote:<index>` stands for.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub remote_images: Vec<String>,
    /// Link destinations that `peleda-link:<index>` stands for.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub links: Vec<SafeUrl>,
}

/// Counts of what the pipeline removed or flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Findings {
    /// Script elements, event handler attributes and `javascript:` or `vbscript:` URLs.
    pub scripts_removed: u32,
    /// Frames, objects, embeds, forms and their controls, meta refresh and base elements.
    pub active_content_removed: u32,
    /// Remote references: images, backgrounds, style sheets and fonts.
    pub remote_references: u32,
    /// Images of at most 2x2 pixels or hidden, the usual read receipts.
    pub tracking_pixels: u32,
    /// Images that could not be decoded or broke the size limits.
    pub images_dropped: u32,
    /// Elements hidden with CSS whose content was dropped.
    pub hidden_content: u32,
    /// Characters removed from or cuts made to header fields and file names.
    pub header_text: TextFindings,
    /// Characters removed from the body text.
    pub body_text: TextFindings,
    /// The body was cut to fit a limit.
    pub truncated: bool,
    /// The MIME structure was damaged or hit a parser limit.
    pub damaged_structure: bool,
}

/// Counts of display text changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TextFindings {
    /// Fields or runs that held bidi control characters.
    pub bidi_controls: u32,
    /// Fields or runs that held invisible characters.
    pub invisible: u32,
    /// Fields or runs that held control characters.
    pub controls: u32,
    /// Fields cut to their length limit.
    pub truncated: u32,
}

/// One part to decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartRequest {
    /// The message as an RFC 5322 byte string.
    pub raw: Bytes,
    /// [`Attachment::part`].
    pub part: u32,
    /// Limits; the decoded bytes must fit `max_output_bytes`.
    pub limits: ContentLimits,
}

/// A decoded part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedPart {
    /// The requested part id.
    pub part: u32,
    /// File name, normalized like [`Attachment::file_name`].
    pub file_name: Option<String>,
    /// Lowercase declared media type.
    pub media_type: String,
    /// The transfer-decoded bytes, untrusted.
    pub bytes: Bytes,
}

/// Which limit a call broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LimitKind {
    /// The output would exceed [`ContentLimits::max_output_bytes`].
    Output,
    /// The call needed more than [`ContentLimits::memory_bytes`].
    Memory,
    /// The output document broke [`ContentLimits::doc`].
    Document,
}

/// Why a call failed. No variant carries any byte of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum ContentError {
    /// The input is larger than [`ContentLimits::max_input_bytes`]; nothing was parsed.
    #[error("input too large")]
    InputTooLarge,
    /// A limit was hit while working.
    #[error("limit exceeded: {0:?}")]
    LimitExceeded(LimitKind),
    /// The time budget ran out.
    #[error("time budget exceeded")]
    Timeout,
    /// The worker crashed (panic, trap, killed process).
    #[error("content worker crashed")]
    Crashed,
    /// The input is not a message at all.
    #[error("malformed input")]
    Malformed,
    /// [`PartRequest::part`] is not a leaf part of the message.
    #[error("part not found")]
    PartNotFound,
    /// The implementation cannot run now (no sandbox, worker pool shut down).
    #[error("content pipeline unavailable")]
    Unavailable,
}
