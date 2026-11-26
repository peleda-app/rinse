use std::collections::HashMap;
use std::io::Cursor;

use bytes::Bytes;
use image::{ExtendedColorType, ImageEncoder, ImageFormat, ImageReader, codecs::png::PngEncoder};
use rinse_mail::EncodedImage;

/// The largest width or height a source image may declare before decoding is refused.
pub(crate) const MAX_SOURCE_PX: u32 = 16_384;
/// Pixels decoded per message at most, over all images.
pub(crate) const MAX_DECODED_PX: u64 = 400_000_000;

/// What became of one image source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Re-encoded: id, width, height.
    Encoded(String, u32, u32),
    /// At most 2x2 pixels: a read receipt.
    Tracking,
    /// Not decodable, unsupported, or over a limit.
    Dropped,
}

/// The re-encoded images of one message, each once, under count, size and memory limits, with
/// at most `2 * max_count` (and at least 8) decode attempts and [`MAX_DECODED_PX`] decoded pixels
/// per message.
pub(crate) struct Images {
    pub(crate) list: Vec<EncodedImage>,
    cache: HashMap<String, Outcome>,
    attempts_left: usize,
    pixels_left: u64,
    max_px: u32,
    max_count: usize,
    max_total_bytes: u64,
    total_bytes: u64,
    max_alloc: u64,
}

impl Images {
    pub(crate) fn new(max_px: u32, max_count: usize, max_total_bytes: u64, memory: u64) -> Self {
        Self {
            list: Vec::new(),
            cache: HashMap::new(),
            attempts_left: max_count.saturating_mul(2).max(8),
            pixels_left: MAX_DECODED_PX,
            max_px: max_px.max(1),
            max_count,
            max_total_bytes,
            total_bytes: 0,
            max_alloc: (memory / 4).max(1 << 20),
        }
    }

    /// Decodes and re-encodes the bytes `bytes` gives, known by `key` (what the reference
    /// resolves to: a part id or the hash of the bytes) so the same image is decoded once
    /// however it is referenced.
    pub(crate) fn add(&mut self, key: &str, bytes: impl FnOnce() -> Vec<u8>) -> Outcome {
        if let Some(done) = self.cache.get(key) {
            return done.clone();
        }
        let outcome = if self.attempts_left == 0 || self.list.len() >= self.max_count {
            Outcome::Dropped
        } else {
            self.attempts_left -= 1;
            self.encode(&bytes())
        };
        self.cache.insert(key.to_owned(), outcome.clone());
        outcome
    }

    fn encode(&mut self, bytes: &[u8]) -> Outcome {
        let Some(img) = decode(bytes, self.max_alloc, &mut self.pixels_left) else {
            return Outcome::Dropped;
        };
        if img.width() <= 2 && img.height() <= 2 {
            return Outcome::Tracking;
        }
        let img = if img.width() > self.max_px || img.height() > self.max_px {
            img.thumbnail(self.max_px, self.max_px)
        } else {
            img
        };
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        if w == 0 || h == 0 || w > self.max_px || h > self.max_px {
            return Outcome::Dropped;
        }
        let mut png = Vec::new();
        if PngEncoder::new(&mut png)
            .write_image(rgba.as_raw(), w, h, ExtendedColorType::Rgba8)
            .is_err()
        {
            return Outcome::Dropped;
        }
        let id = blake3::hash(&png).to_hex().to_string();
        if self.list.iter().any(|i| i.id == id) {
            return Outcome::Encoded(id, w, h);
        }
        if self.total_bytes + png.len() as u64 > self.max_total_bytes {
            return Outcome::Dropped;
        }
        self.total_bytes += png.len() as u64;
        self.list.push(EncodedImage {
            id: id.clone(),
            width: w,
            height: h,
            png: Bytes::from(png),
        });
        Outcome::Encoded(id, w, h)
    }
}

fn reader(bytes: &[u8], max_alloc: u64) -> Option<ImageReader<Cursor<&[u8]>>> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    if !matches!(
        reader.format()?,
        ImageFormat::Png
            | ImageFormat::Jpeg
            | ImageFormat::Gif
            | ImageFormat::WebP
            | ImageFormat::Bmp
    ) {
        return None;
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_PX);
    limits.max_image_height = Some(MAX_SOURCE_PX);
    limits.max_alloc = Some(max_alloc);
    reader.limits(limits);
    Some(reader)
}

fn decode(bytes: &[u8], max_alloc: u64, pixels_left: &mut u64) -> Option<image::DynamicImage> {
    let (w, h) = reader(bytes, max_alloc)?.into_dimensions().ok()?;
    let pixels = u64::from(w) * u64::from(h);
    if w == 0 || h == 0 || pixels * 4 > max_alloc || pixels > *pixels_left {
        return None;
    }
    *pixels_left -= pixels;
    reader(bytes, max_alloc)?.decode().ok()
}

/// Bytes of a `data:` URL with an image media type and base64 payload; `None` otherwise.
pub(crate) fn data_url(src: &str) -> Option<Vec<u8>> {
    let src = src.trim();
    if !src.get(..5)?.eq_ignore_ascii_case("data:") {
        return None;
    }
    let rest = &src[5..];
    let (meta, payload) = rest.split_once(',')?;
    let meta = meta.to_ascii_lowercase();
    if !meta.starts_with("image/") || meta.starts_with("image/svg") || !meta.ends_with(";base64") {
        return None;
    }
    base64_lenient(payload)
}

/// Base64 with whitespace and padding ignored.
pub(crate) fn base64_lenient(payload: &str) -> Option<Vec<u8>> {
    let mut clean: Vec<u8> = payload
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
        .collect();
    if clean.len() % 4 == 1 {
        clean.pop();
    }
    data_encoding::BASE64_NOPAD.decode(&clean).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_pixel(w, h, image::Rgb([10, 200, 30]));
        let mut out = Vec::new();
        PngEncoder::new(&mut out)
            .write_image(img.as_raw(), w, h, ExtendedColorType::Rgb8)
            .unwrap();
        out
    }

    #[test]
    fn reencodes_and_scales() {
        let mut images = Images::new(10, 5, 1 << 20, 64 << 20);
        let Outcome::Encoded(id, w, h) = images.add("a", || png(40, 20)) else {
            panic!("encoded");
        };
        assert_eq!((w, h), (10, 5));
        assert_eq!(id, blake3::hash(&images.list[0].png).to_hex().as_str());
        assert_eq!(
            images.add("a", Vec::new),
            Outcome::Encoded(id.clone(), 10, 5)
        );
        assert_eq!(images.add("b", || png(40, 20)), Outcome::Encoded(id, 10, 5));
        assert_eq!(images.list.len(), 1);
    }

    #[test]
    fn tracking_and_garbage() {
        let mut images = Images::new(100, 5, 1 << 20, 64 << 20);
        assert_eq!(images.add("p", || png(1, 1)), Outcome::Tracking);
        assert_eq!(
            images.add("g", || b"\x89PNG\r\n\x1a\nnope".to_vec()),
            Outcome::Dropped
        );
        assert_eq!(
            images.add("s", || b"<svg></svg>".to_vec()),
            Outcome::Dropped
        );
        assert!(images.list.is_empty());
    }

    #[test]
    fn count_and_bytes_caps() {
        let mut images = Images::new(100, 1, 1 << 20, 64 << 20);
        assert!(matches!(
            images.add("a", || png(5, 5)),
            Outcome::Encoded(..)
        ));
        assert_eq!(images.add("b", || png(6, 6)), Outcome::Dropped);
        let mut images = Images::new(100, 5, 10, 64 << 20);
        assert_eq!(images.add("a", || png(5, 5)), Outcome::Dropped);
    }

    #[test]
    fn attempts_and_pixels_are_budgeted() {
        let mut images = Images::new(100, 2, 1 << 20, 64 << 20);
        for i in 0..8 {
            assert_eq!(
                images.add(&format!("g{i}"), || b"junk".to_vec()),
                Outcome::Dropped
            );
        }
        let mut called = false;
        let outcome = images.add("late", || {
            called = true;
            png(5, 5)
        });
        assert_eq!(outcome, Outcome::Dropped);
        assert!(!called, "no decode after the attempt budget");

        let mut images = Images::new(100, 50, 1 << 30, 1 << 40);
        images.pixels_left = 30;
        assert!(matches!(
            images.add("a", || png(5, 5)),
            Outcome::Encoded(..)
        ));
        assert_eq!(images.add("b", || png(4, 4)), Outcome::Dropped);
    }

    #[test]
    fn data_urls() {
        let b64 = data_encoding::BASE64.encode(&png(3, 3));
        assert!(data_url(&format!("data:image/png;base64,{b64}")).is_some());
        assert!(data_url(&format!("DATA:image/png;base64,\n{b64}")).is_some());
        assert!(data_url(&format!("data:image/svg+xml;base64,{b64}")).is_none());
        assert!(data_url("data:text/html;base64,PHA+").is_none());
        assert!(data_url("data:image/png,raw").is_none());
    }
}
