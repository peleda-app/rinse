//! The content pipeline itself: a pure, synchronous library that turns the raw bytes of an
//! untrusted message into the safe document model ([`render`]) and decodes single parts for saving
//! ([`decode_part`]). No I/O, no global state, no clock; it builds for `wasm32-wasip2` so the
//! content worker can run it inside the WebAssembly sandbox.
//!
//! Every output is bounded by [`ContentLimits`], the HTML parser's DOM by node, depth and
//! open-formatting budgets, image decoding by allocation, attempt and pixel budgets; the input
//! size is checked before anything is parsed. It is not a security wall by itself: the walls of
//! `docs/WALLS.md` are the sandbox it runs in and the validation the core applies to its
//! output.

mod builder;
mod facts;
mod html;
mod images;
mod links;
mod mime;
mod plain;
mod risk;
mod sanitize;
mod style;
mod text;

use std::collections::{HashMap, HashSet};

use mail_parser::{Message, PartId};
use rinse_doc_model::{Block, Document, Inline, validate};
use rinse_mail::{
    ContentError, ContentLimits, DecodedPart, Findings, LimitKind, PartRequest, RenderOptions,
    RenderRequest, Rendered,
};

use crate::builder::Builder;
use crate::images::{Images, Outcome};
use crate::links::Links;

const MAX_REMOTE_IMAGES: usize = 500;
const MAX_HTML_PARTS: usize = 32;

pub(crate) struct Env<'m> {
    pub(crate) limits: ContentLimits,
    options: &'m RenderOptions,
    message: &'m Message<'m>,
    pub(crate) findings: Findings,
    images: Images,
    pub(crate) links: Links,
    remote: Vec<String>,
    src_map: HashMap<String, String>,
    cids: HashMap<String, PartId>,
    no_original: bool,
    parse_budget: usize,
    pub(crate) hints: facts::Hints,
    pub(crate) stop: &'m dyn Fn() -> bool,
}

impl Env<'_> {
    /// Resolves an image source to a re-encoded image, recording what happened. `tiny` marks
    /// images that are hidden or declared at most 2x2 pixels.
    pub(crate) fn resolve_image(&mut self, src: &str, tiny: bool) -> Option<(String, u32, u32)> {
        if (self.stop)() {
            return None;
        }
        let src = src.trim();
        let lower = src.get(..8).unwrap_or(src).to_ascii_lowercase();
        let remote =
            lower.starts_with("https://") || lower.starts_with("http://") || src.starts_with("//");
        if tiny {
            self.findings.tracking_pixels += 1;
            self.findings.remote_references += u32::from(remote);
            return None;
        }
        let outcome = if lower.starts_with("cid:") {
            let id = percent_decode(&src[4..]);
            let id = id.trim().trim_start_matches('<').trim_end_matches('>');
            let found = self
                .cids
                .get(id)
                .or_else(|| self.cids.get(&id.to_ascii_lowercase()))
                .copied();
            match found.and_then(|p| Some((p, self.message.part(p)?))) {
                Some((id, part)) => {
                    let key = format!("part:{id}");
                    self.images.add(&key, || part.decoded().into_owned())
                }
                None => Outcome::Dropped,
            }
        } else if lower.starts_with("data:") {
            match images::data_url(src) {
                Some(bytes) => {
                    let key = format!("data:{}", blake3::hash(&bytes).to_hex());
                    self.images.add(&key, || bytes)
                }
                None => Outcome::Dropped,
            }
        } else if remote {
            self.findings.remote_references += 1;
            let absolute = if src.starts_with("//") {
                format!("https:{src}")
            } else {
                src.to_owned()
            };
            let max_url_len = self.limits.doc.max_url_len;
            let url = url::Url::parse(&absolute)
                .ok()
                .map(String::from)
                .filter(|u| rinse_mail::remote_image_url_ok(u, max_url_len))?;
            let provided = self.options.remote_images.iter().find(|r| r.url == url);
            match provided {
                Some(r) => {
                    let key = format!("remote:{}", blake3::hash(&r.bytes).to_hex());
                    self.images.add(&key, || r.bytes.to_vec())
                }
                None => {
                    let index = match self.remote.iter().position(|u| *u == url) {
                        Some(i) => i,
                        None if self.remote.len() < MAX_REMOTE_IMAGES => {
                            self.remote.push(url);
                            self.remote.len() - 1
                        }
                        None => return None,
                    };
                    self.src_map
                        .insert(src.to_owned(), format!("peleda-remote:{index}"));
                    return None;
                }
            }
        } else {
            return None;
        };
        self.record(src, outcome)
    }

    /// Re-encodes an image part that is itself part of the body.
    fn part_image(&mut self, id: PartId) -> Option<(String, u32, u32)> {
        let outcome = match self.message.part(id) {
            Some(part) => self
                .images
                .add(&format!("part:{id}"), || part.decoded().into_owned()),
            None => Outcome::Dropped,
        };
        self.record(&format!("part:{id}"), outcome)
    }

    fn record(&mut self, src: &str, outcome: Outcome) -> Option<(String, u32, u32)> {
        match outcome {
            Outcome::Encoded(id, w, h) => {
                self.src_map
                    .insert(src.to_owned(), format!("peleda-image:{id}"));
                Some((id, w, h))
            }
            Outcome::Tracking => {
                self.findings.tracking_pixels += 1;
                None
            }
            Outcome::Dropped => {
                self.findings.images_dropped += 1;
                None
            }
        }
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = s.get(i + 1..i + 3)
            && let Ok(b) = u8::from_str_radix(hex, 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Renders one message. See [`rinse_mail::Content::render`] for the guarantees; this
/// function keeps all of them except the time budget, which the caller enforces.
pub fn render(request: &RenderRequest) -> Result<Rendered, ContentError> {
    render_until(request, &|| false)
}

/// [`render`] that gives up with [`ContentError::Timeout`] soon after `stop` returns true. The
/// engine asks between small steps (a few hundred bytes of HTML, a few thousand DOM nodes, one
/// image, a thousand lines of text), so a caller that cannot kill the work, like an in-process
/// timeout, gets its thread back quickly.
pub fn render_until(
    request: &RenderRequest,
    stop: &dyn Fn() -> bool,
) -> Result<Rendered, ContentError> {
    let limits = request.limits;
    if request.raw.len() as u64 > limits.max_input_bytes {
        return Err(ContentError::InputTooLarge);
    }
    let message = mime::parser()
        .parse(&request.raw[..])
        .ok_or(ContentError::Malformed)?;
    if message.root().headers().iter().next().is_none() && message.root().raw().is_empty() {
        return Err(ContentError::Malformed);
    }
    let max_px = request
        .options
        .max_image_px
        .min(limits.doc.max_image_px)
        .max(1);
    let mut env = Env {
        limits,
        options: &request.options,
        message: &message,
        findings: Findings::default(),
        images: Images::new(
            max_px,
            limits.doc.max_images,
            limits.max_output_bytes / 4 * 3,
            limits.memory_bytes,
        ),
        links: Links::new(limits.doc.max_links),
        remote: Vec::new(),
        src_map: HashMap::new(),
        cids: mime::content_ids(&message),
        no_original: false,
        parse_budget: html::MAX_PARSED_NODES,
        hints: facts::Hints::default(),
        stop,
    };
    env.findings.damaged_structure = message.parts().any(|p| p.has_problems());
    let headers = mime::headers(&message, &mut env.findings.header_text);

    let mut b = Builder::new(limits.doc);
    let mut html_sources = Vec::new();
    for part in mime::body_parts(&message).into_iter().take(MAX_HTML_PARTS) {
        if b.is_full() {
            break;
        }
        if stop() {
            return Err(ContentError::Timeout);
        }
        match part {
            mime::Body::Html(text) => {
                if !html::convert(&text, &mut env, &mut b) {
                    env.no_original = true;
                }
                html_sources.push(text);
            }
            mime::Body::Text(text) => plain::convert(&text, &mut env, &mut b),
            mime::Body::Image(id) => {
                if b.image_fits()
                    && let Some((id, width, height)) = env.part_image(id)
                {
                    b.image(rinse_doc_model::ImageRef {
                        id,
                        alt: String::new(),
                        width,
                        height,
                    });
                }
            }
        }
    }
    if stop() {
        return Err(ContentError::Timeout);
    }
    let (body, truncated) = b.finish();
    env.findings.truncated |= truncated;

    let ids: HashSet<String> = env.images.list.iter().map(|i| i.id.clone()).collect();
    validate(&body, &limits.doc, |id| ids.contains(id))
        .map_err(|_| ContentError::LimitExceeded(LimitKind::Document))?;
    let text = plain_text(&body, limits.doc.max_text_bytes);
    let attachments = mime::attachments(&message, &mut env.findings.header_text);

    if stop() {
        return Err(ContentError::Timeout);
    }
    let facts = facts::extract(&facts::Input {
        message: &message,
        body: &body,
        links: &env.links.list,
        hints: &env.hints,
        max_url_len: limits.doc.max_url_len,
        stop,
    });
    if stop() {
        return Err(ContentError::Timeout);
    }
    let original_html =
        if request.options.want_original_html && !html_sources.is_empty() && !env.no_original {
            sanitize::original(
                &html_sources,
                &env.src_map,
                &env.remote,
                limits.doc.max_url_len,
            )
        } else {
            None
        };

    let mut rendered = Rendered {
        headers,
        body,
        text,
        images: env.images.list,
        remote_images: env.remote,
        attachments,
        links: env.links.list,
        original_html,
        findings: env.findings,
        facts,
    };
    let size = |r: &Rendered| {
        postcard::to_stdvec(r)
            .map(|v| v.len() as u64)
            .unwrap_or(u64::MAX)
    };
    if size(&rendered) > limits.max_output_bytes {
        rendered.original_html = None;
        if size(&rendered) > limits.max_output_bytes {
            return Err(ContentError::LimitExceeded(LimitKind::Output));
        }
    }
    Ok(rendered)
}

/// Decodes one leaf part for saving. See [`rinse_mail::Content::decode_part`].
pub fn decode_part(request: &PartRequest) -> Result<DecodedPart, ContentError> {
    if request.raw.len() as u64 > request.limits.max_input_bytes {
        return Err(ContentError::InputTooLarge);
    }
    let message = mime::parser()
        .parse(&request.raw[..])
        .ok_or(ContentError::Malformed)?;
    let part = message
        .part(request.part)
        .filter(|p| !p.is_multipart())
        .ok_or(ContentError::PartNotFound)?;
    let bytes = part.decoded();
    if bytes.len() as u64 > request.limits.max_output_bytes {
        return Err(ContentError::LimitExceeded(LimitKind::Output));
    }
    let mut scratch = Default::default();
    Ok(DecodedPart {
        part: request.part,
        file_name: mime::file_name(&part, &mut scratch),
        media_type: mime::media_type(&part),
        bytes: bytes::Bytes::from(bytes.into_owned()),
    })
}

/// Plain text of a document: paragraphs separated by blank lines, at most `max` bytes.
fn plain_text(doc: &Document, max: usize) -> String {
    let mut out = String::new();
    blocks_text(&doc.blocks, &mut out, max);
    let trimmed = out.trim_end().len();
    out.truncate(trimmed);
    text::cut(&out, max).to_owned()
}

fn push(out: &mut String, s: &str, max: usize) {
    if out.len() < max {
        out.push_str(text::cut(s, max - out.len()));
    }
}

fn blocks_text(blocks: &[Block], out: &mut String, max: usize) {
    for block in blocks {
        if out.len() >= max {
            return;
        }
        match block {
            Block::Paragraph { inlines, .. } | Block::Heading { inlines, .. } => {
                inlines_text(inlines, out, max);
                push(out, "\n\n", max);
            }
            Block::Quote(children) => blocks_text(children, out, max),
            Block::List { items, .. } => {
                for item in items {
                    push(out, "- ", max);
                    blocks_text(item, out, max);
                }
            }
            Block::Table { rows } => {
                for row in rows {
                    for cell in row {
                        blocks_text(&cell.blocks, out, max);
                        push(out, "\t", max);
                    }
                    push(out, "\n", max);
                }
            }
            Block::Preformatted(t) => {
                push(out, t, max);
                push(out, "\n\n", max);
            }
            Block::Image(image) => {
                if !image.alt.is_empty() {
                    push(out, &image.alt, max);
                    push(out, "\n\n", max);
                }
            }
            Block::Divider => {}
        }
    }
}

fn inlines_text(inlines: &[Inline], out: &mut String, max: usize) {
    for inline in inlines {
        match inline {
            Inline::Text { text, .. } => push(out, text, max),
            Inline::Link { inlines, .. } => inlines_text(inlines, out, max),
            Inline::LineBreak => push(out, "\n", max),
        }
    }
}

#[cfg(test)]
mod tests;
