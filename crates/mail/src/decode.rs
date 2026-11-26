//! Decoding a worker's response on the host within a memory bound.

use rinse_doc_model::with_decode_budget;
use serde::de::DeserializeOwned;

use crate::facts::{
    MAX_AUTH_METHODS, MAX_AUTH_RESULTS, MAX_DKIM_SIGNATURES, MAX_REFERENCES, MAX_STRUCTURED_ITEMS,
    MAX_UNSUBSCRIBE_TARGETS,
};
use crate::{ContentError, ContentLimits, MAX_ADDRESSES};

/// Room in a render budget for sequences no document limit covers: attachments and remote
/// image URLs (the engine lists at most 500 of each).
pub const RENDER_DECODE_ALLOWANCE: usize = 4_096;

/// The decode budget (see [`rinse_doc_model::with_decode_budget`]) of a render response under
/// `limits`: every node a valid body can hold (`max_blocks + max_inlines`), links twice (the
/// list and its layout facts) and again twice for the Original view, images twice, four
/// address fields, the capped fact lists, and [`RENDER_DECODE_ALLOWANCE`]. A response within
/// the limits always fits; one that does not fails while decoding.
pub fn render_decode_budget(limits: &ContentLimits) -> usize {
    let doc = &limits.doc;
    let facts = MAX_STRUCTURED_ITEMS
        + MAX_AUTH_RESULTS * (1 + MAX_AUTH_METHODS)
        + MAX_DKIM_SIGNATURES
        + MAX_UNSUBSCRIBE_TARGETS
        + MAX_REFERENCES;
    doc.max_blocks
        .saturating_add(doc.max_inlines)
        .saturating_add(doc.max_links.saturating_mul(4))
        .saturating_add(doc.max_images.saturating_mul(2))
        .saturating_add(4 * MAX_ADDRESSES + facts + RENDER_DECODE_ALLOWANCE)
}

/// Decodes the postcard bytes of a render response (`Rendered` or `Result<Rendered, _>`)
/// within [`render_decode_budget`]. Run it on every response before
/// [`verify_rendered`](crate::verify_rendered): the limits that verification checks bound
/// memory only once the value exists, and a compromised worker can make a small encoding
/// decode into a value a hundred times larger. Any decoding failure is
/// [`ContentError::Crashed`].
pub fn decode_render_response<T: DeserializeOwned>(
    bytes: &[u8],
    limits: &ContentLimits,
) -> Result<T, ContentError> {
    with_decode_budget(render_decode_budget(limits), || postcard::from_bytes(bytes))
        .map_err(|_| ContentError::Crashed)
}
