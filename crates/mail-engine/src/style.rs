use rinse_doc_model::{Align, Tone};

/// Declarations of an inline `style` attribute, property names lowercased, at most 64.
pub(crate) fn declarations(style: &str) -> Vec<(String, String)> {
    style
        .split(';')
        .take(64)
        .filter_map(|decl| {
            let (prop, value) = decl.split_once(':')?;
            let prop = prop.trim().to_ascii_lowercase();
            let value = value
                .trim()
                .trim_end_matches("!important")
                .trim()
                .to_ascii_lowercase();
            (!prop.is_empty()).then_some((prop, value))
        })
        .collect()
}

pub(crate) fn get<'a>(decls: &'a [(String, String)], prop: &str) -> Option<&'a str> {
    decls
        .iter()
        .rev()
        .find(|(p, _)| p == prop)
        .map(|(_, v)| v.as_str())
}

/// Whether the declarations hide the element: `display: none`, `visibility: hidden`,
/// `opacity: 0`, `font-size: 0`, or a zero `max-height` with hidden overflow.
pub(crate) fn hidden(decls: &[(String, String)]) -> bool {
    let zero = |v: &str| {
        let v = v.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '%');
        v.parse::<f32>().is_ok_and(|n| n <= 0.0)
    };
    get(decls, "display") == Some("none")
        || matches!(get(decls, "visibility"), Some("hidden" | "collapse"))
        || get(decls, "opacity").is_some_and(zero)
        || get(decls, "font-size").is_some_and(zero)
        || (get(decls, "max-height").is_some_and(zero) && get(decls, "overflow") == Some("hidden"))
}

/// A length in CSS pixels from `12`, `12px` or `12.5px`; other units give `None`.
/// Whether declarations give an element a background or padding, as buttons in mail have.
pub(crate) fn button(decls: &[(String, String)]) -> bool {
    decls.iter().any(|(p, v)| match p.as_str() {
        "background" | "background-color" | "background-image" => !matches!(
            v.trim(),
            "" | "none" | "transparent" | "inherit" | "initial" | "unset"
        ),
        p if p.starts_with("padding") => v.split_whitespace().any(|part| {
            part.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '%')
                .parse::<f32>()
                .is_ok_and(|n| n > 0.0)
        }),
        _ => false,
    })
}

pub(crate) fn pixels(value: &str) -> Option<f32> {
    let v = value.trim();
    let v = v.strip_suffix("px").unwrap_or(v).trim();
    v.parse::<f32>().ok().filter(|n| n.is_finite())
}

pub(crate) fn align(value: &str) -> Option<Align> {
    match value.trim().to_ascii_lowercase().as_str() {
        "left" | "start" | "justify" => Some(Align::Start),
        "center" | "middle" => Some(Align::Center),
        "right" | "end" => Some(Align::End),
        _ => None,
    }
}

pub(crate) fn bold(value: &str) -> Option<bool> {
    match value {
        "bold" | "bolder" => Some(true),
        "normal" | "lighter" => Some(false),
        v => v.parse::<u32>().ok().map(|n| n >= 600),
    }
}

/// The palette tone nearest to a CSS color; `None` for the default text color (black, white,
/// near-greys at the ends, transparent, or anything unparseable).
#[cfg(test)]
fn tone(value: &str) -> Option<Tone> {
    color(value).flatten()
}

/// `None` when the value is not a color this module understands; otherwise the nearest tone,
/// where `Some(None)` is the default text color.
pub(crate) fn color(value: &str) -> Option<Option<Tone>> {
    rgb(value.trim()).map(|(r, g, b)| nearest(r, g, b))
}

fn nearest(r: u8, g: u8, b: u8) -> Option<Tone> {
    let (r, g, b) = (
        f32::from(r) / 255.0,
        f32::from(g) / 255.0,
        f32::from(b) / 255.0,
    );
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let l = (max + min) / 2.0;
    let d = max - min;
    let s = if d == 0.0 {
        0.0
    } else {
        d / (1.0 - (2.0 * l - 1.0).abs())
    };
    if s < 0.18 || d < 0.08 {
        return (0.3..=0.8).contains(&l).then_some(Tone::Gray);
    }
    if !(0.12..=0.92).contains(&l) {
        return None;
    }
    let h = if max == r {
        60.0 * (((g - b) / d) % 6.0)
    } else if max == g {
        60.0 * ((b - r) / d + 2.0)
    } else {
        60.0 * ((r - g) / d + 4.0)
    };
    let h = if h < 0.0 { h + 360.0 } else { h };
    Some(match h {
        h if !(15.0..345.0).contains(&h) => Tone::Red,
        h if h < 45.0 && l < 0.35 => Tone::Brown,
        h if h < 40.0 => Tone::Orange,
        h if h < 65.0 => Tone::Yellow,
        h if h < 160.0 => Tone::Green,
        h if h < 195.0 => Tone::Teal,
        h if h < 250.0 => Tone::Blue,
        h if h < 320.0 => Tone::Purple,
        _ => Tone::Pink,
    })
}

fn rgb(value: &str) -> Option<(u8, u8, u8)> {
    let v = value.to_ascii_lowercase();
    if let Some(hex) = v.strip_prefix('#') {
        let digits: Vec<u8> = hex
            .chars()
            .map(|c| c.to_digit(16).map(|d| d as u8))
            .collect::<Option<_>>()?;
        return match digits.len() {
            3 | 4 => Some((digits[0] * 17, digits[1] * 17, digits[2] * 17)),
            6 | 8 => Some((
                digits[0] * 16 + digits[1],
                digits[2] * 16 + digits[3],
                digits[4] * 16 + digits[5],
            )),
            _ => None,
        };
    }
    if let Some(args) = v
        .strip_prefix("rgba(")
        .or_else(|| v.strip_prefix("rgb("))
        .and_then(|a| a.strip_suffix(')'))
    {
        let parts: Vec<&str> = args
            .split([',', ' ', '/'])
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() < 3 {
            return None;
        }
        let channel = |p: &str| -> Option<u8> {
            if let Some(pct) = p.strip_suffix('%') {
                let n: f32 = pct.parse().ok()?;
                Some((n.clamp(0.0, 100.0) * 2.55).round() as u8)
            } else {
                let n: f32 = p.parse().ok()?;
                Some(n.clamp(0.0, 255.0).round() as u8)
            }
        };
        if let Some(alpha) = parts.get(3)
            && alpha
                .trim_end_matches('%')
                .parse::<f32>()
                .is_ok_and(|a| a == 0.0)
        {
            return None;
        }
        return Some((channel(parts[0])?, channel(parts[1])?, channel(parts[2])?));
    }
    Some(match v.as_str() {
        "red" => (255, 0, 0),
        "darkred" | "maroon" => (128, 0, 0),
        "crimson" => (220, 20, 60),
        "orange" => (255, 165, 0),
        "darkorange" => (255, 140, 0),
        "orangered" => (255, 69, 0),
        "gold" => (255, 215, 0),
        "yellow" => (255, 255, 0),
        "olive" => (128, 128, 0),
        "green" => (0, 128, 0),
        "darkgreen" => (0, 100, 0),
        "lime" => (0, 255, 0),
        "teal" => (0, 128, 128),
        "cyan" | "aqua" => (0, 255, 255),
        "blue" => (0, 0, 255),
        "navy" | "darkblue" => (0, 0, 139),
        "royalblue" => (65, 105, 225),
        "purple" => (128, 0, 128),
        "indigo" => (75, 0, 130),
        "violet" => (238, 130, 238),
        "magenta" | "fuchsia" => (255, 0, 255),
        "pink" => (255, 192, 203),
        "hotpink" => (255, 105, 180),
        "brown" => (165, 42, 42),
        "saddlebrown" => (139, 69, 19),
        "gray" | "grey" => (128, 128, 128),
        "darkgray" | "darkgrey" => (169, 169, 169),
        "dimgray" | "dimgrey" => (105, 105, 105),
        "silver" => (192, 192, 192),
        "black" => (0, 0, 0),
        "white" => (255, 255, 255),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tones() {
        assert_eq!(tone("#ff0000"), Some(Tone::Red));
        assert_eq!(tone("rgb(0, 128, 0)"), Some(Tone::Green));
        assert_eq!(tone("#00f"), Some(Tone::Blue));
        assert_eq!(tone("purple"), Some(Tone::Purple));
        assert_eq!(tone("#808080"), Some(Tone::Gray));
        assert_eq!(tone("black"), None);
        assert_eq!(tone("#ffffff"), None);
        assert_eq!(tone("rgba(255,0,0,0)"), None);
        assert_eq!(tone("saddlebrown"), Some(Tone::Brown));
        assert_eq!(tone("url(x)"), None);
        assert_eq!(tone("#12"), None);
    }

    #[test]
    fn hiding() {
        assert!(hidden(&declarations("display: none")));
        assert!(hidden(&declarations("DISPLAY:NONE !important")));
        assert!(hidden(&declarations("font-size:0px")));
        assert!(hidden(&declarations("max-height:0;overflow:hidden")));
        assert!(!hidden(&declarations("display:block; font-size: 12px")));
    }
}
