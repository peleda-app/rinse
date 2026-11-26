//! Apple Wallet passes: `pass.json` read from a `.pkpass` attachment (a zip archive) with a
//! small bounded zip reader. The signature is not checked.

use mail_parser::Message;
use rinse_mail::facts::{MAX_STRUCTURED_ITEMS, Pass, PassStyle, StructuredItem};
use serde_json::Value;

use super::{text, when};

const MAX_PKPASS_BYTES: usize = 4 << 20;
const MAX_PASS_JSON_BYTES: usize = 64 << 10;
const MAX_ENTRIES: usize = 256;
const MAX_PASSES: usize = 4;
const EOCD: u32 = 0x0605_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const LOCAL: u32 = 0x0403_4b50;

const STYLES: [(&str, PassStyle); 5] = [
    ("boardingPass", PassStyle::BoardingPass),
    ("eventTicket", PassStyle::EventTicket),
    ("coupon", PassStyle::Coupon),
    ("storeCard", PassStyle::StoreCard),
    ("generic", PassStyle::Generic),
];

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?) as usize)
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    usize::try_from(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?)).ok()
}

fn sum(parts: &[usize]) -> Option<usize> {
    parts.iter().try_fold(0usize, |acc, &p| acc.checked_add(p))
}

/// The bytes of `pass.json` inside a zip archive: stored or deflated, not encrypted, at most
/// [`MAX_PASS_JSON_BYTES`] after inflating, the only entry with that name.
pub(crate) fn pass_json(zip: &[u8]) -> Option<Vec<u8>> {
    if zip.len() > MAX_PKPASS_BYTES || zip.len() < 22 {
        return None;
    }
    let from = zip.len().saturating_sub(22 + 0xffff);
    let eocd = (from..=zip.len() - 22)
        .rev()
        .find(|&i| u32_at(zip, i) == Some(EOCD as usize))?;
    let entries = u16_at(zip, eocd + 10)?;
    let mut at = u32_at(zip, eocd + 16)?;
    if entries > MAX_ENTRIES {
        return None;
    }
    let mut found = None;
    for _ in 0..entries {
        if at > zip.len() || u32_at(zip, at)? != CENTRAL as usize {
            return None;
        }
        let flags = u16_at(zip, at + 8)?;
        let method = u16_at(zip, at + 10)?;
        let compressed = u32_at(zip, at + 20)?;
        let size = u32_at(zip, at + 24)?;
        let name_len = u16_at(zip, at + 28)?;
        let next = sum(&[
            at,
            46,
            name_len,
            u16_at(zip, at + 30)?,
            u16_at(zip, at + 32)?,
        ])?;
        let name = zip.get(at + 46..sum(&[at, 46, name_len])?)?;
        if name == b"pass.json" {
            if found.is_some() || flags & 1 != 0 || size > MAX_PASS_JSON_BYTES {
                return None;
            }
            found = Some((method, compressed, u32_at(zip, at + 42)?));
        }
        at = next;
    }
    let (method, compressed, local) = found?;
    if local > zip.len() || u32_at(zip, local)? != LOCAL as usize {
        return None;
    }
    let start = sum(&[
        local,
        30,
        u16_at(zip, local + 26)?,
        u16_at(zip, local + 28)?,
    ])?;
    let data = zip.get(start..start.checked_add(compressed)?)?;
    match method {
        0 if data.len() <= MAX_PASS_JSON_BYTES => Some(data.to_vec()),
        8 => miniz_oxide::inflate::decompress_to_vec_with_limit(data, MAX_PASS_JSON_BYTES).ok(),
        _ => None,
    }
}

/// A pass from the bytes of `pass.json`: exactly one style key, an organization name.
pub(crate) fn pass(json: &[u8]) -> Option<Pass> {
    let json = json.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(json);
    let Value::Object(root) = serde_json::from_slice::<Value>(json).ok()? else {
        return None;
    };
    let mut styles = STYLES
        .iter()
        .filter(|(key, _)| root.get(*key).is_some_and(Value::is_object));
    let (_, style) = styles.next()?;
    if styles.next().is_some() {
        return None;
    }
    let field = |key: &str| root.get(key).and_then(Value::as_str);
    Some(Pass {
        style: *style,
        organization: text(field("organizationName")?, 200)?,
        description: field("description").and_then(|d| text(d, 300)),
        relevant: field("relevantDate").and_then(when::iso),
    })
}

/// Appends the passes of the message's `.pkpass` attachments.
pub(crate) fn read(message: &Message<'_>, out: &mut Vec<StructuredItem>) {
    let mut seen = 0;
    for part in message.parts().take(1_000) {
        if seen == MAX_PASSES || out.len() >= MAX_STRUCTURED_ITEMS {
            return;
        }
        if part.is_multipart() {
            continue;
        }
        let is_pass = crate::mime::media_type(&part) == "application/vnd.apple.pkpass"
            || part
                .attachment_name()
                .is_some_and(|n| n.to_ascii_lowercase().ends_with(".pkpass"));
        if !is_pass || part.decoded_len() > MAX_PKPASS_BYTES {
            continue;
        }
        seen += 1;
        if let Some(p) = pass_json(&part.decoded()).and_then(|j| pass(&j)) {
            out.push(StructuredItem::Pass(p));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A zip archive with these stored entries.
    pub(crate) fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let offset = out.len() as u32;
            out.extend(LOCAL.to_le_bytes());
            out.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((data.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend([0, 0]);
            out.extend(name.as_bytes());
            out.extend(*data);
            central.extend(CENTRAL.to_le_bytes());
            central.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            central.extend((data.len() as u32).to_le_bytes());
            central.extend((data.len() as u32).to_le_bytes());
            central.extend((name.len() as u16).to_le_bytes());
            central.extend([0; 12]);
            central.extend(offset.to_le_bytes());
            central.extend(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        let cd_len = central.len() as u32;
        out.extend(central);
        out.extend(EOCD.to_le_bytes());
        out.extend([0, 0, 0, 0]);
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend(cd_len.to_le_bytes());
        out.extend(cd_offset.to_le_bytes());
        out.extend([0, 0]);
        out
    }

    const PASS: &[u8] = br#"{"formatVersion":1,"organizationName":"Example Air","description":"Boarding pass","relevantDate":"2026-12-01T09:00:00+02:00","boardingPass":{"transitType":"PKTransitTypeAir"}}"#;

    #[test]
    fn reads_a_stored_pass() {
        let archive = zip(&[("icon.png", b"\x89PNG"), ("pass.json", PASS)]);
        let p = pass(&pass_json(&archive).unwrap()).unwrap();
        assert_eq!(p.style, PassStyle::BoardingPass);
        assert_eq!(p.organization, "Example Air");
        assert!(p.relevant.is_some());
    }

    #[test]
    fn reads_a_deflated_pass_and_refuses_bombs() {
        let deflated = miniz_oxide::deflate::compress_to_vec(PASS, 6);
        let mut archive = zip(&[("pass.json", &deflated)]);
        archive[8] = 8;
        let cd = archive.len() - 22 - 46 - 9;
        archive[cd + 10] = 8;
        archive[cd + 24..cd + 28].copy_from_slice(&(PASS.len() as u32).to_le_bytes());
        assert_eq!(pass_json(&archive).as_deref(), Some(PASS));

        let bomb = miniz_oxide::deflate::compress_to_vec(&vec![b' '; 10 << 20], 10);
        let mut archive = zip(&[("pass.json", &bomb)]);
        let cd = archive.len() - 22 - 46 - 9;
        archive[cd + 10] = 8;
        assert_eq!(pass_json(&archive), None, "inflating stops at the limit");
    }

    #[test]
    fn refuses_offsets_near_the_end_of_u32() {
        let mut far_central = zip(&[("pass.json", PASS)]);
        let eocd = far_central.len() - 22;
        far_central[eocd + 16..eocd + 20].copy_from_slice(&(u32::MAX - 20).to_le_bytes());
        assert_eq!(pass_json(&far_central), None);

        let mut far_local = zip(&[("pass.json", PASS)]);
        let cd = far_local.len() - 22 - 46 - 9;
        far_local[cd + 42..cd + 46].copy_from_slice(&(u32::MAX - 10).to_le_bytes());
        assert_eq!(pass_json(&far_local), None);
    }

    #[test]
    fn refuses_odd_archives() {
        assert_eq!(pass_json(b""), None);
        assert_eq!(pass_json(&[0u8; 100]), None);
        assert_eq!(
            pass_json(&zip(&[("pass.json", PASS), ("pass.json", PASS)])),
            None
        );
        assert_eq!(pass_json(&zip(&[("other.json", PASS)])), None);
        let mut lying = zip(&[("pass.json", PASS)]);
        let cd = lying.len() - 22 - 46 - 9;
        lying[cd + 20..cd + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(pass_json(&lying), None);
        assert!(pass(br#"{"organizationName":"x","coupon":{},"generic":{}}"#).is_none());
        assert!(pass(br#"{"coupon":{}}"#).is_none());
        assert!(pass(b"[]").is_none());
    }
}
