use mail_parser::Message;
use rinse_mail::MailAddress;
use rinse_mail::facts::{CalendarMethod, EventStatus, InvitationFacts, When};

use super::auth::split_outside_quotes;
use super::headers::mail_address;
use super::{ident, text, when};

const MAX_CALENDAR_BYTES: usize = 256 << 10;
const MAX_LINES: usize = 20_000;

struct Line<'a> {
    name: String,
    params: Vec<(String, String)>,
    value: &'a str,
}

impl Line<'_> {
    fn param(&self, key: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

fn split_line(line: &str) -> Option<Line<'_>> {
    let mut quoted = false;
    let mut colon = None;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ':' if !quoted => {
                colon = Some(i);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let (head, value) = (&line[..colon], &line[colon + 1..]);
    let mut parts = split_outside_quotes(head, ';').into_iter();
    let name = parts.next()?.trim().to_ascii_uppercase();
    let params = parts
        .take(32)
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((
                k.trim().to_ascii_uppercase(),
                v.trim().trim_matches('"').to_owned(),
            ))
        })
        .collect();
    Some(Line {
        name,
        params,
        value,
    })
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n' | 'N') => out.push(' '),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn method(value: &str) -> CalendarMethod {
    match value.trim().to_ascii_uppercase().as_str() {
        "REQUEST" => CalendarMethod::Request,
        "REPLY" => CalendarMethod::Reply,
        "CANCEL" => CalendarMethod::Cancel,
        "PUBLISH" => CalendarMethod::Publish,
        "ADD" => CalendarMethod::Add,
        "REFRESH" => CalendarMethod::Refresh,
        "COUNTER" => CalendarMethod::Counter,
        "DECLINECOUNTER" => CalendarMethod::DeclineCounter,
        _ => CalendarMethod::Other,
    }
}

fn organizer(line: &Line<'_>) -> Option<MailAddress> {
    let v = line.value.trim();
    let address = v
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("mailto:"))
        .and_then(|_| mail_address(&v[7..]))?;
    Some(MailAddress {
        name: line.param("CN").and_then(|n| text(n, 200)),
        address,
    })
}

/// The first `VEVENT` of an iCalendar text.
pub(crate) fn parse(source: &str) -> Option<InvitationFacts> {
    let source = crate::text::cut(source, MAX_CALENDAR_BYTES);
    let mut lines: Vec<String> = Vec::new();
    for raw in source.split('\n').take(MAX_LINES) {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        match (raw.strip_prefix([' ', '\t']), lines.last_mut()) {
            (Some(cont), Some(last)) => last.push_str(cont),
            _ => lines.push(raw.to_owned()),
        }
    }
    let mut facts = InvitationFacts {
        method: CalendarMethod::Publish,
        uid: None,
        sequence: None,
        summary: None,
        organizer: None,
        start: None,
        end: None,
        time_zone: None,
        location: None,
        status: None,
        attendees: 0,
    };
    let mut depth = 0usize;
    let mut in_event = false;
    let mut found = false;
    let mut done = false;
    for line in lines.iter().filter_map(|l| split_line(l)) {
        let value = line.value.trim();
        match line.name.as_str() {
            "BEGIN" => {
                depth += 1;
                if !found && value.eq_ignore_ascii_case("VEVENT") {
                    in_event = true;
                    found = true;
                    depth = 1;
                }
                continue;
            }
            "END" => {
                depth = depth.saturating_sub(1);
                if in_event && depth == 0 {
                    in_event = false;
                    done = true;
                }
                continue;
            }
            "METHOD" if !in_event => facts.method = method(value),
            _ => {}
        }
        if !in_event || depth != 1 || done {
            continue;
        }
        match line.name.as_str() {
            "UID" => facts.uid = facts.uid.take().or_else(|| ident(value)),
            "SEQUENCE" => facts.sequence = value.parse().ok(),
            "SUMMARY" => facts.summary = text(&unescape(value), 300),
            "LOCATION" => facts.location = text(&unescape(value), 300),
            "ORGANIZER" => facts.organizer = organizer(&line),
            "DTSTART" => {
                facts.start = when::ical(value);
                facts.time_zone = matches!(facts.start, Some(When::Local(_)))
                    .then(|| line.param("TZID").and_then(ident))
                    .flatten();
            }
            "DTEND" => facts.end = when::ical(value),
            "STATUS" => {
                facts.status = match value.to_ascii_uppercase().as_str() {
                    "TENTATIVE" => Some(EventStatus::Tentative),
                    "CONFIRMED" => Some(EventStatus::Confirmed),
                    "CANCELLED" => Some(EventStatus::Cancelled),
                    _ => None,
                }
            }
            "ATTENDEE" => facts.attendees = facts.attendees.saturating_add(1),
            _ => {}
        }
    }
    found.then_some(facts)
}

/// The invitation of the first `text/calendar` part (or `.ics` attachment) that has an event.
pub(crate) fn read(message: &Message<'_>) -> Option<InvitationFacts> {
    for part in message.parts().take(1_000) {
        if part.is_multipart() {
            continue;
        }
        let calendar = crate::mime::media_type(&part) == "text/calendar"
            || part
                .attachment_name()
                .is_some_and(|n| n.to_ascii_lowercase().ends_with(".ics"));
        if !calendar {
            continue;
        }
        let bytes = part.decoded();
        let bytes = &bytes[..bytes.len().min(MAX_CALENDAR_BYTES)];
        if let Some(facts) = parse(&String::from_utf8_lossy(bytes)) {
            return Some(facts);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_an_invitation() {
        let ics = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:abc@example.com\r\nSEQUENCE:2\r\nSUMMARY:Plan\\, review\r\n  and lunch\r\nORGANIZER;CN=\"Ann \u{202E}rennaP\":mailto:ann@example.com\r\nATTENDEE:mailto:bob@example.com\r\nATTENDEE:mailto:cy@example.com\r\nDTSTART;TZID=Europe/Vilnius:20261201T100000\r\nDTEND:20261201T090000Z\r\nSTATUS:CONFIRMED\r\nBEGIN:VALARM\r\nSUMMARY:not this\r\nEND:VALARM\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:second@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let f = parse(ics).unwrap();
        assert_eq!(f.method, CalendarMethod::Request);
        assert_eq!(f.uid.as_deref(), Some("abc@example.com"));
        assert_eq!(f.sequence, Some(2));
        assert_eq!(f.summary.as_deref(), Some("Plan, review and lunch"));
        let o = f.organizer.unwrap();
        assert_eq!(o.address, "ann@example.com");
        assert_eq!(o.name.as_deref(), Some("Ann rennaP"));
        assert_eq!(f.attendees, 2);
        assert!(matches!(f.start, Some(When::Local(_))));
        assert_eq!(f.time_zone.as_deref(), Some("Europe/Vilnius"));
        assert!(matches!(f.end, Some(When::Instant(_))));
        assert_eq!(f.status, Some(EventStatus::Confirmed));
    }

    #[test]
    fn quoted_parameters_keep_separators() {
        let f = parse("BEGIN:VEVENT\r\nORGANIZER;CN=\"Doe; John: Sales\";ROLE=CHAIR:mailto:jd@example.com\r\nDTSTART;TZID=\"Zone; A\";VALUE=DATE-TIME:20261201T100000\r\nEND:VEVENT\r\n").unwrap();
        let o = f.organizer.unwrap();
        assert_eq!(o.name.as_deref(), Some("Doe; John: Sales"));
        assert_eq!(o.address, "jd@example.com");
        assert_eq!(
            f.time_zone, None,
            "a time zone id with a space is not an identifier"
        );
        assert!(matches!(f.start, Some(When::Local(_))));
    }

    #[test]
    fn hostile_calendars() {
        assert!(parse("").is_none());
        assert!(parse("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nEND:VCALENDAR").is_none());
        let f = parse("BEGIN:VEVENT\nORGANIZER:mailto:a\u{202E}b@example.com\nUID:a b\nDTSTART:99999999\nEND:VEVENT").unwrap();
        assert_eq!(f.organizer, None);
        assert_eq!(f.uid, None);
        assert_eq!(f.start, None);
        let deep = format!(
            "{}BEGIN:VEVENT\nUID:x@example.com\nEND:VEVENT",
            "BEGIN:X\n".repeat(50_000)
        );
        assert!(parse(&deep).is_none(), "lines past the cap are not read");
        let wide = format!("BEGIN:VEVENT\nSUMMARY:{}\nEND:VEVENT", "a".repeat(1 << 20));
        let f = parse(&wide);
        assert!(f.is_none_or(|f| f.summary.is_none_or(|s| s.chars().count() <= 1_000)));
    }
}
