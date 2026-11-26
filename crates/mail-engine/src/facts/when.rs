use rinse_mail::facts::{CalendarDate, LocalDateTime, When};

fn num(s: &str) -> Option<u32> {
    (!s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

fn date(year: &str, month: &str, day: &str) -> Option<CalendarDate> {
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return None;
    }
    let d = CalendarDate {
        year: u16::try_from(num(year)?).ok()?,
        month: u8::try_from(num(month)?).ok()?,
        day: u8::try_from(num(day)?).ok()?,
    };
    d.is_valid().then_some(d)
}

fn time(date: CalendarDate, h: &str, m: &str, s: Option<&str>) -> Option<LocalDateTime> {
    if h.len() != 2 || m.len() != 2 || s.is_some_and(|s| s.len() != 2) {
        return None;
    }
    let t = LocalDateTime {
        date,
        hour: u8::try_from(num(h)?).ok()?,
        minute: u8::try_from(num(m)?).ok()?,
        second: u8::try_from(s.map_or(Some(0), num)?).ok()?.min(59),
    };
    When::Local(t).is_valid().then_some(t)
}

fn instant(t: LocalDateTime, offset_s: i64) -> Option<When> {
    let secs = t.date.unix_days() * 86_400
        + i64::from(t.hour) * 3_600
        + i64::from(t.minute) * 60
        + i64::from(t.second)
        - offset_s;
    let w = When::Instant(secs);
    w.is_valid().then_some(w)
}

fn offset(zone: &str) -> Option<i64> {
    if zone.eq_ignore_ascii_case("z") {
        return Some(0);
    }
    let (sign, rest) = match zone.as_bytes().first()? {
        b'+' => (1, &zone[1..]),
        b'-' => (-1, &zone[1..]),
        _ => return None,
    };
    let compact: String = rest.chars().filter(|c| *c != ':').collect();
    if rest.matches(':').count() > 1 || !matches!(compact.len(), 2 | 4) {
        return None;
    }
    let h = i64::from(num(&compact[..2])?);
    let m = if compact.len() == 4 {
        i64::from(num(&compact[2..])?)
    } else {
        0
    };
    (h <= 18 && m < 60).then_some(sign * (h * 3_600 + m * 60))
}

/// An ISO 8601 date or date-time as schema.org and Wallet passes write them:
/// `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM[:SS[.fff]][Z|±HH[:MM]]`, `T` or a space between.
pub(crate) fn iso(s: &str) -> Option<When> {
    let s = s.trim();
    if s.len() > 40 || !s.is_ascii() {
        return None;
    }
    let d = date(s.get(..4)?, s.get(5..7)?, s.get(8..10)?)?;
    if s.as_bytes().get(4) != Some(&b'-') || s.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    if s.len() == 10 {
        return Some(When::Date(d));
    }
    if !matches!(s.as_bytes()[10], b'T' | b't' | b' ') {
        return None;
    }
    let rest = &s[11..];
    let zone_at = rest.find(['Z', 'z', '+', '-']).unwrap_or(rest.len());
    let (clock, zone) = rest.split_at(zone_at);
    let clock = clock.split('.').next()?;
    let mut parts = clock.split(':');
    let (h, m, sec) = (parts.next()?, parts.next()?, parts.next());
    if parts.next().is_some() {
        return None;
    }
    let t = time(d, h, m, sec)?;
    if zone.is_empty() {
        Some(When::Local(t))
    } else {
        instant(t, offset(zone)?)
    }
}

/// An iCalendar `DATE` (`YYYYMMDD`) or `DATE-TIME` (`YYYYMMDDTHHMMSS[Z]`) value.
pub(crate) fn ical(s: &str) -> Option<When> {
    let s = s.trim();
    if !s.is_ascii() {
        return None;
    }
    let d = date(s.get(..4)?, s.get(4..6)?, s.get(6..8)?)?;
    match s.len() {
        8 => Some(When::Date(d)),
        15 | 16 if s.as_bytes()[8] == b'T' => {
            let t = time(d, &s[9..11], &s[11..13], Some(&s[13..15]))?;
            match s.as_bytes().get(15) {
                None => Some(When::Local(t)),
                Some(b'Z') => instant(t, 0),
                Some(_) => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_forms() {
        assert_eq!(
            iso("2026-11-25"),
            Some(When::Date(CalendarDate {
                year: 2026,
                month: 11,
                day: 25
            }))
        );
        assert_eq!(iso("1970-01-01T00:00:00Z"), Some(When::Instant(0)));
        assert_eq!(iso("1970-01-01T03:00:00+03:00"), Some(When::Instant(0)));
        assert_eq!(iso("1970-01-01 01:30+0130"), Some(When::Instant(0)));
        assert_eq!(
            iso("2026-01-01T10:00:00.123-05"),
            iso("2026-01-01T15:00:00Z")
        );
        assert!(matches!(iso("2026-01-01T10:00"), Some(When::Local(_))));
        for bad in [
            "",
            "2026-13-01",
            "2026-02-30",
            "1969-12-31T23:00:00Z",
            "2026-01-01T25:00",
            "2026-01-01T10:00:00+99:00",
            "2026-01-01X10:00",
            "２０２６-01-01",
            "2026-01-01T10",
            "2026-01-01T10:00:00:00",
        ] {
            assert_eq!(iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn ical_forms() {
        assert_eq!(ical("19700101T000000Z"), Some(When::Instant(0)));
        assert!(matches!(ical("20261201T100000"), Some(When::Local(_))));
        assert!(matches!(ical("20261201"), Some(When::Date(_))));
        for bad in ["2026120", "20261201T1000", "20261201T100000X", "20261301"] {
            assert_eq!(ical(bad), None, "{bad}");
        }
    }
}
