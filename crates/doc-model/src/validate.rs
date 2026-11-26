use rinse_text::{is_bidi_control, is_invisible};
use serde::{Deserialize, Serialize};

use crate::{Block, Document, ImageRef, Inline, SCHEMA_VERSION};

/// The deepest nesting [`Limits::max_depth`] may allow; larger values are treated as this.
pub const MAX_DEPTH: usize = 32;

/// Size limits a document must stay within. Every count covers the whole document, nested
/// content included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Nesting depth: top-level blocks are at depth 1, the content of a quote, list item, table
    /// cell, paragraph, heading or link is one level deeper than its container. Capped at
    /// [`MAX_DEPTH`].
    pub max_depth: usize,
    /// Number of blocks of every kind, list items, table rows and table cells together.
    pub max_blocks: usize,
    /// Number of inline runs of every kind.
    pub max_inlines: usize,
    /// Bytes of text in text runs, preformatted blocks and image alternative texts together.
    pub max_text_bytes: usize,
    /// Number of links.
    pub max_links: usize,
    /// Number of image blocks.
    pub max_images: usize,
    /// Bytes in one link destination.
    pub max_url_len: usize,
    /// Rows in one table.
    pub max_table_rows: usize,
    /// Cells in one table row.
    pub max_table_cols: usize,
    /// Width and height in pixels of one image.
    pub max_image_px: u32,
}

impl Default for Limits {
    /// Depth 16, 20,000 blocks (list items, rows and cells included), 100,000 inline runs, 4 MiB of text, 2,000 links, 200 images,
    /// 2,048-byte URLs, 1,000 rows by 64 columns per table, 4,096-pixel images.
    fn default() -> Self {
        Self {
            max_depth: 16,
            max_blocks: 20_000,
            max_inlines: 100_000,
            max_text_bytes: 4 << 20,
            max_links: 2_000,
            max_images: 200,
            max_url_len: 2_048,
            max_table_rows: 1_000,
            max_table_cols: 64,
            max_image_px: 4_096,
        }
    }
}

impl Limits {
    /// [`Limits::max_depth`] capped at [`MAX_DEPTH`].
    pub fn depth(&self) -> usize {
        self.max_depth.min(MAX_DEPTH)
    }
}

/// The first rule a document breaks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Violation {
    /// The schema version is not [`SCHEMA_VERSION`].
    #[error("unsupported schema version")]
    Version,
    /// Nesting is deeper than the limit.
    #[error("too deeply nested")]
    Depth,
    /// More blocks than the limit.
    #[error("too many blocks")]
    Blocks,
    /// More inline runs than the limit.
    #[error("too many inline runs")]
    Inlines,
    /// More text than the limit.
    #[error("too much text")]
    TextBytes,
    /// More links than the limit.
    #[error("too many links")]
    Links,
    /// More images than the limit.
    #[error("too many images")]
    Images,
    /// A link destination is longer than the limit.
    #[error("link too long")]
    UrlLength,
    /// A link scheme other than https, http, mailto and tel, or a malformed URL.
    #[error("link scheme not allowed")]
    Url,
    /// A table has more rows or columns than the limit.
    #[error("table too large")]
    TableSize,
    /// A heading level outside 1 to 6.
    #[error("heading level out of range")]
    HeadingLevel,
    /// Text contains a bidirectional control character.
    #[error("bidi control character in text")]
    BidiControl,
    /// Text contains an invisible character.
    #[error("invisible character in text")]
    Invisible,
    /// Text contains a control character other than those its kind allows.
    #[error("control character in text")]
    Control,
    /// An image id is not 64 lowercase hex characters.
    #[error("malformed image id")]
    ImageId,
    /// An image refers to an id the caller does not know.
    #[error("unknown image")]
    UnknownImage,
    /// An image has a zero or oversized dimension.
    #[error("image size out of range")]
    ImageSize,
    /// A list without items, a table without rows, an empty list item or an empty table row.
    #[error("empty container")]
    Empty,
}

/// Checks a document against the limits and the safety rules: schema version, nesting and size
/// limits (list items, table rows and cells count as blocks), no empty list, list item, table or
/// row (cells may be empty, to keep columns aligned), link schemes only `https`, `http`, `mailto` and `tel`, no bidi controls, invisible or
/// control characters in text (preformatted text may hold line breaks and tabs, text runs tabs),
/// images only as well-formed references to ids for which `is_known_image` returns true.
///
/// Returns the first violation found. Runs in time linear in the document size and recurses no
/// deeper than the depth limit.
pub fn validate(
    document: &Document,
    limits: &Limits,
    is_known_image: impl Fn(&str) -> bool,
) -> Result<(), Violation> {
    if document.version != SCHEMA_VERSION {
        return Err(Violation::Version);
    }
    let mut v = Validator {
        limits,
        is_known_image: &is_known_image,
        blocks: 0,
        inlines: 0,
        text: 0,
        links: 0,
        images: 0,
    };
    v.blocks(&document.blocks, 1)
}

struct Validator<'a> {
    limits: &'a Limits,
    is_known_image: &'a dyn Fn(&str) -> bool,
    blocks: usize,
    inlines: usize,
    text: usize,
    links: usize,
    images: usize,
}

impl Validator<'_> {
    fn depth(&self, depth: usize) -> Result<(), Violation> {
        if depth > self.limits.depth() {
            Err(Violation::Depth)
        } else {
            Ok(())
        }
    }

    fn blocks(&mut self, blocks: &[Block], depth: usize) -> Result<(), Violation> {
        if blocks.is_empty() {
            return Ok(());
        }
        self.depth(depth)?;
        for block in blocks {
            self.blocks += 1;
            if self.blocks > self.limits.max_blocks {
                return Err(Violation::Blocks);
            }
            match block {
                Block::Paragraph { inlines, .. } => self.inlines(inlines, depth + 1)?,
                Block::Heading { level, inlines, .. } => {
                    if !(1..=6).contains(level) {
                        return Err(Violation::HeadingLevel);
                    }
                    self.inlines(inlines, depth + 1)?;
                }
                Block::Quote(children) => self.blocks(children, depth + 1)?,
                Block::List { items, .. } => {
                    if items.is_empty() {
                        return Err(Violation::Empty);
                    }
                    for item in items {
                        self.count_container(item.is_empty())?;
                        self.blocks(item, depth + 1)?;
                    }
                }
                Block::Table { rows } => {
                    if rows.is_empty() {
                        return Err(Violation::Empty);
                    }
                    if rows.len() > self.limits.max_table_rows {
                        return Err(Violation::TableSize);
                    }
                    for row in rows {
                        if row.len() > self.limits.max_table_cols {
                            return Err(Violation::TableSize);
                        }
                        self.count_container(row.is_empty())?;
                        for cell in row {
                            self.count_container(false)?;
                            self.blocks(&cell.blocks, depth + 1)?;
                        }
                    }
                }
                Block::Preformatted(text) => self.text(text, true)?,
                Block::Image(image) => self.image(image)?,
                Block::Divider => {}
            }
        }
        Ok(())
    }

    fn count_container(&mut self, empty: bool) -> Result<(), Violation> {
        if empty {
            return Err(Violation::Empty);
        }
        self.blocks += 1;
        if self.blocks > self.limits.max_blocks {
            return Err(Violation::Blocks);
        }
        Ok(())
    }

    fn inlines(&mut self, inlines: &[Inline], depth: usize) -> Result<(), Violation> {
        if inlines.is_empty() {
            return Ok(());
        }
        self.depth(depth)?;
        for inline in inlines {
            self.inlines += 1;
            if self.inlines > self.limits.max_inlines {
                return Err(Violation::Inlines);
            }
            match inline {
                Inline::Text { text, .. } => self.text(text, false)?,
                Inline::Link { href, inlines } => {
                    self.links += 1;
                    if self.links > self.limits.max_links {
                        return Err(Violation::Links);
                    }
                    check_url(href.as_str(), self.limits.max_url_len)?;
                    self.inlines(inlines, depth + 1)?;
                }
                Inline::LineBreak => {}
            }
        }
        Ok(())
    }

    fn text(&mut self, text: &str, multiline: bool) -> Result<(), Violation> {
        self.text += text.len();
        if self.text > self.limits.max_text_bytes {
            return Err(Violation::TextBytes);
        }
        check_text(text, multiline)
    }

    fn image(&mut self, image: &ImageRef) -> Result<(), Violation> {
        self.images += 1;
        if self.images > self.limits.max_images {
            return Err(Violation::Images);
        }
        if image.id.len() != 64
            || !image
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Violation::ImageId);
        }
        if !(self.is_known_image)(&image.id) {
            return Err(Violation::UnknownImage);
        }
        let max = self.limits.max_image_px;
        if image.width == 0 || image.height == 0 || image.width > max || image.height > max {
            return Err(Violation::ImageSize);
        }
        self.text(&image.alt, false)
    }
}

pub(crate) fn check_text(text: &str, multiline: bool) -> Result<(), Violation> {
    for c in text.chars() {
        if is_bidi_control(c) {
            return Err(Violation::BidiControl);
        }
        if is_invisible(c) {
            return Err(Violation::Invisible);
        }
        let allowed_control = c == '\t' || (multiline && c == '\n');
        if (c.is_control() && !allowed_control) || c == '\u{2028}' || c == '\u{2029}' {
            return Err(Violation::Control);
        }
    }
    Ok(())
}

pub(crate) fn check_url(url: &str, max_len: usize) -> Result<(), Violation> {
    if url.len() > max_len {
        return Err(Violation::UrlLength);
    }
    if url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || is_bidi_control(c) || is_invisible(c))
    {
        return Err(Violation::Url);
    }
    let Some((scheme, rest)) = url.split_once(':') else {
        return Err(Violation::Url);
    };
    match scheme.to_ascii_lowercase().as_str() {
        "https" | "http" => {
            let host = rest
                .strip_prefix("//")
                .ok_or(Violation::Url)?
                .split(['/', '?', '#'])
                .next()
                .unwrap_or_default();
            if host.is_empty() || host.contains('\\') {
                return Err(Violation::Url);
            }
            Ok(())
        }
        "mailto" | "tel" if !rest.is_empty() => Ok(()),
        _ => Err(Violation::Url),
    }
}
