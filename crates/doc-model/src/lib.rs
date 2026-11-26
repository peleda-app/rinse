//! The safe document model: the only shape a message body takes once it leaves the content
//! worker. A closed, versioned schema of blocks and inline runs that the UI renders with its own
//! components, so no message HTML, CSS or original image byte ever reaches a browser engine.
//!
//! Everything that crosses a trust boundary is checked with [`validate`]; [`decode`] validates
//! before it returns. Deserializing a [`Document`] with any serde format never recurses deeper
//! than [`WIRE_MAX_DEPTH`], whatever the input.

mod validate;
mod wire;

use serde::{Deserialize, Serialize};

pub use validate::{Limits, MAX_DEPTH, Violation, validate};
pub use wire::{WIRE_MAX_DEPTH, bounded_vec, with_decode_budget};

/// The schema version this crate writes and accepts.
pub const SCHEMA_VERSION: u16 = 1;

/// The first byte of every [`encode`]d document.
pub const FORMAT_VERSION: u8 = 1;

/// A message body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    /// Schema version; [`validate`] accepts only [`SCHEMA_VERSION`].
    pub version: u16,
    /// Top-level blocks in reading order.
    pub blocks: Vec<Block>,
}

impl Document {
    /// An empty document of the current schema version.
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION,
            blocks: Vec::new(),
        }
    }
}

/// One block of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// A paragraph of inline runs.
    Paragraph {
        /// Horizontal alignment.
        align: Align,
        /// The content.
        inlines: Vec<Inline>,
    },
    /// A heading; `level` is 1 to 6.
    Heading {
        /// 1 (largest) to 6.
        level: u8,
        /// Horizontal alignment.
        align: Align,
        /// The content.
        inlines: Vec<Inline>,
    },
    /// Quoted content, such as an earlier message in a reply.
    Quote(Vec<Block>),
    /// A list; every item is a sequence of blocks.
    List {
        /// Numbered when true, bulleted otherwise.
        ordered: bool,
        /// The items in order.
        items: Vec<Vec<Block>>,
    },
    /// A data table.
    Table {
        /// Rows of cells, top to bottom.
        rows: Vec<Vec<Cell>>,
    },
    /// Text shown as written, in a monospace font, line breaks kept.
    Preformatted(String),
    /// A re-encoded image.
    Image(ImageRef),
    /// A horizontal rule.
    Divider,
}

/// One table cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    /// A header cell.
    pub header: bool,
    /// The content.
    pub blocks: Vec<Block>,
}

/// Horizontal alignment of a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Align {
    /// The start edge of the text direction.
    #[default]
    Start,
    /// Centered.
    Center,
    /// The end edge of the text direction.
    End,
}

/// A reference to an image the content worker re-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    /// Lowercase hex BLAKE3 hash (64 characters) of the re-encoded image bytes.
    pub id: String,
    /// Alternative text, possibly empty.
    pub alt: String,
    /// Width in pixels of the re-encoded image.
    pub width: u32,
    /// Height in pixels of the re-encoded image.
    pub height: u32,
}

/// One inline run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    /// Styled text. Never contains line breaks or control characters; see [`Inline::LineBreak`].
    Text {
        /// The text.
        text: String,
        /// How it is shown.
        style: Style,
    },
    /// A link to a checked destination.
    Link {
        /// The destination.
        href: SafeUrl,
        /// The link text.
        inlines: Vec<Inline>,
    },
    /// A line break inside a paragraph or heading.
    LineBreak,
}

/// The styles the UI supports; anything else in a message is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Style {
    /// Bold.
    pub bold: bool,
    /// Italic.
    pub italic: bool,
    /// Underlined.
    pub underline: bool,
    /// Struck through.
    pub strike: bool,
    /// Monospace code.
    pub code: bool,
    /// Text color from the palette; `None` is the default text color.
    pub tone: Option<Tone>,
}

/// A text color from a small palette. The UI maps each tone to a design token that stays
/// readable in light and dark themes, so a message cannot pick an invisible color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tone {
    /// Neutral, less prominent text.
    Gray,
    /// Red.
    Red,
    /// Orange.
    Orange,
    /// Yellow.
    Yellow,
    /// Green.
    Green,
    /// Teal.
    Teal,
    /// Blue.
    Blue,
    /// Purple.
    Purple,
    /// Pink.
    Pink,
    /// Brown.
    Brown,
}

/// A link destination. [`SafeUrl::new`] and [`validate`] accept only `https:`, `http:`,
/// `mailto:` and `tel:` URLs without whitespace, control, bidi or invisible characters.
///
/// Serializes as a plain string. Deserializing runs the same checks with a length cap of
/// [`SAFE_URL_MAX_LEN`], so no unchecked `SafeUrl` can come out of any serde format; callers still
/// apply their own, usually smaller, [`Limits::max_url_len`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeUrl(String);

/// The longest [`SafeUrl`] deserialization accepts, in bytes.
pub const SAFE_URL_MAX_LEN: usize = 64 << 10;

impl<'de> Deserialize<'de> for SafeUrl {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let url = String::deserialize(deserializer)?;
        validate::check_url(&url, SAFE_URL_MAX_LEN)
            .map_err(|_| serde::de::Error::custom("unsafe link destination"))?;
        Ok(Self(url))
    }
}

impl SafeUrl {
    /// The URL if it passes the scheme and character checks and is at most `max_len` bytes.
    pub fn new(url: &str, max_len: usize) -> Option<Self> {
        validate::check_url(url, max_len).ok()?;
        Some(Self(url.to_owned()))
    }

    /// The URL as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The lowercase scheme, without the colon.
    pub fn scheme(&self) -> String {
        self.0
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
    }
}

impl std::fmt::Display for SafeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why [`decode`] or [`encode`] failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// The first byte is not [`FORMAT_VERSION`].
    #[error("unknown format version")]
    Format,
    /// The bytes are not a well-formed document.
    #[error("malformed document")]
    Malformed,
    /// The document is well-formed but breaks a rule.
    #[error("invalid document: {0}")]
    Invalid(#[from] Violation),
}

/// The document as [`FORMAT_VERSION`] followed by its postcard encoding. Fails with
/// [`CodecError::Malformed`] only for documents nested deeper than [`WIRE_MAX_DEPTH`].
pub fn encode(document: &Document) -> Result<Vec<u8>, CodecError> {
    let mut out = vec![FORMAT_VERSION];
    let body = postcard::to_stdvec(document).map_err(|_| CodecError::Malformed)?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decodes bytes written by [`encode`] and returns the document only if it passes [`validate`]
/// with these limits and image ids. Never panics and never recurses unboundedly on any input;
/// decoding stops after `max_blocks + max_inlines` nodes (see [`with_decode_budget`]), so its
/// memory stays proportional to what the limits allow, whatever the input length.
pub fn decode(
    bytes: &[u8],
    limits: &Limits,
    is_known_image: impl Fn(&str) -> bool,
) -> Result<Document, CodecError> {
    let (&format, body) = bytes.split_first().ok_or(CodecError::Malformed)?;
    if format != FORMAT_VERSION {
        return Err(CodecError::Format);
    }
    let budget = limits.max_blocks.saturating_add(limits.max_inlines);
    let (document, rest): (Document, _) =
        with_decode_budget(budget, || postcard::take_from_bytes(body))
            .map_err(|_| CodecError::Malformed)?;
    if !rest.is_empty() {
        return Err(CodecError::Malformed);
    }
    validate(&document, limits, is_known_image)?;
    Ok(document)
}

#[cfg(test)]
mod tests;
