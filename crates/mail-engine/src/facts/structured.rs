//! A closed subset of schema.org read from `application/ld+json`, mapped onto typed items.

use rinse_doc_model::SafeUrl;
use rinse_mail::facts::{
    Action, ActionKind, Invoice, MAX_STRUCTURED_ITEMS, Order, OrderStatus, ParcelDelivery,
    PaymentStatus, Price, Reservation, ReservationKind, ReservationStatus, StructuredItem, When,
};
use rinse_mail::remote_image_url_ok;
use serde_json::{Map, Value};

use super::{MAX_LD_JSON_BYTES, ident, text, when};

const MAX_NODES: usize = 64;
const MAX_ACTIONS: usize = 4;
const MAX_TYPES: usize = 4;
const NAME_GRAPHEMES: usize = 200;

type Obj = Map<String, Value>;

fn first(v: &Value) -> &Value {
    match v {
        Value::Array(items) => items.first().unwrap_or(&Value::Null),
        other => other,
    }
}

fn get<'a>(o: &'a Obj, key: &str) -> Option<&'a Value> {
    o.get(key).map(first).filter(|v| !v.is_null())
}

fn obj<'a>(o: &'a Obj, key: &str) -> Option<&'a Obj> {
    get(o, key)?.as_object()
}

fn scalar(v: &Value) -> Option<String> {
    match first(v) {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn string(o: &Obj, key: &str) -> Option<String> {
    get(o, key).and_then(scalar)
}

fn name(o: &Obj, key: &str) -> Option<String> {
    let v = get(o, key)?;
    let s = match v {
        Value::Object(inner) => string(inner, "name")?,
        other => scalar(other)?,
    };
    text(&s, NAME_GRAPHEMES)
}

fn id(o: &Obj, key: &str) -> Option<String> {
    ident(&string(o, key)?)
}

fn enum_name(o: &Obj, key: &str) -> Option<String> {
    let v = string(o, key)?;
    let v = v.trim();
    let short = v.rsplit('/').next().unwrap_or(v);
    Some(short.to_owned())
}

fn time(o: &Obj, key: &str) -> Option<When> {
    when::iso(&string(o, key)?)
}

fn url(o: &Obj, key: &str, max_len: usize) -> Option<SafeUrl> {
    let raw = match get(o, key)? {
        Value::Object(entry) => string(entry, "urlTemplate").or_else(|| string(entry, "url"))?,
        other => scalar(other)?,
    };
    let s = String::from(url::Url::parse(raw.trim()).ok()?);
    if !remote_image_url_ok(&s, max_len) {
        return None;
    }
    SafeUrl::new(&s, max_len)
}

fn amount(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let (int, frac) = match raw.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (raw, None),
    };
    let digits =
        |s: &str, max: usize| (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    (digits(int, 15) && frac.is_none_or(|f| digits(f, 4))).then(|| raw.to_owned())
}

fn currency(raw: &str) -> Option<String> {
    let c = raw.trim().to_ascii_uppercase();
    (c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase())).then_some(c)
}

fn price_in(o: &Obj, value_key: &str, currency_key: &str) -> Option<Price> {
    Some(Price {
        amount: amount(&string(o, value_key)?)?,
        currency: string(o, currency_key).and_then(|c| currency(&c)),
    })
}

fn price(o: &Obj, key: &str) -> Option<Price> {
    match get(o, key)? {
        Value::Object(spec) => {
            price_in(spec, "price", "priceCurrency").or_else(|| price_in(spec, "value", "currency"))
        }
        other => Some(Price {
            amount: amount(&scalar(other)?)?,
            currency: string(o, "priceCurrency").and_then(|c| currency(&c)),
        }),
    }
}

fn place(o: &Obj, key: &str) -> Option<String> {
    let v = get(o, key)?;
    let Value::Object(p) = v else {
        return text(&scalar(v)?, NAME_GRAPHEMES);
    };
    if let Some(code) = id(p, "iataCode") {
        return text(&code, 8);
    }
    if let Some(n) = name(p, "name") {
        return Some(n);
    }
    let address = obj(p, "address").unwrap_or(p);
    let parts: Vec<String> = ["streetAddress", "addressLocality"]
        .iter()
        .filter_map(|k| string(address, k))
        .collect();
    text(&parts.join(", "), NAME_GRAPHEMES)
}

fn types(o: &Obj) -> Vec<String> {
    let strip = |s: &str| {
        s.trim()
            .trim_start_matches("https://schema.org/")
            .trim_start_matches("http://schema.org/")
            .to_owned()
    };
    match o.get("@type") {
        Some(Value::String(s)) => vec![strip(s)],
        Some(Value::Array(items)) => items
            .iter()
            .take(MAX_TYPES)
            .filter_map(Value::as_str)
            .map(strip)
            .collect(),
        _ => Vec::new(),
    }
}

fn reservation(kind: ReservationKind, o: &Obj, max_url_len: usize) -> Reservation {
    let empty = Obj::new();
    let rf = obj(o, "reservationFor").unwrap_or(&empty);
    let mut r = Reservation {
        kind,
        number: id(o, "reservationNumber"),
        status: enum_name(o, "reservationStatus").and_then(|s| match s.as_str() {
            "ReservationConfirmed" | "Confirmed" => Some(ReservationStatus::Confirmed),
            "ReservationCancelled" | "Cancelled" => Some(ReservationStatus::Cancelled),
            "ReservationPending" | "Pending" => Some(ReservationStatus::Pending),
            "ReservationHold" | "Hold" => Some(ReservationStatus::Hold),
            _ => None,
        }),
        name: None,
        provider: name(rf, "provider").or_else(|| name(o, "provider")),
        start: None,
        end: None,
        from: None,
        to: None,
        url: url(o, "modifyReservationUrl", max_url_len).or_else(|| url(o, "url", max_url_len)),
    };
    match kind {
        ReservationKind::Flight => {
            let airline = obj(rf, "airline");
            let code = airline.and_then(|a| id(a, "iataCode")).unwrap_or_default();
            let number = string(rf, "flightNumber").unwrap_or_default();
            r.name = text(&format!("{code}{number}"), 32);
            r.provider = airline.and_then(|a| name(a, "name")).or(r.provider);
            r.start = time(rf, "departureTime");
            r.end = time(rf, "arrivalTime");
            r.from = place(rf, "departureAirport");
            r.to = place(rf, "arrivalAirport");
        }
        ReservationKind::Train | ReservationKind::Bus => {
            let (number, from, to) = if kind == ReservationKind::Train {
                ("trainNumber", "departureStation", "arrivalStation")
            } else {
                ("busNumber", "departureBusStop", "arrivalBusStop")
            };
            r.name = name(rf, number);
            r.start = time(rf, "departureTime");
            r.end = time(rf, "arrivalTime");
            r.from = place(rf, from);
            r.to = place(rf, to);
        }
        ReservationKind::Lodging => {
            r.name = name(rf, "name");
            r.start = time(o, "checkinTime");
            r.end = time(o, "checkoutTime");
            r.from = place(rf, "address");
        }
        ReservationKind::RentalCar => {
            r.name = name(rf, "name");
            r.provider = name(rf, "brand").or(r.provider);
            r.start = time(o, "pickupTime");
            r.end = time(o, "dropoffTime");
            r.from = place(o, "pickupLocation");
            r.to = place(o, "dropoffLocation");
        }
        ReservationKind::Event => {
            r.name = name(rf, "name");
            r.start = time(rf, "startDate");
            r.end = time(rf, "endDate");
            r.from = place(rf, "location");
        }
        ReservationKind::Food => {
            r.name = name(rf, "name");
            r.start = time(o, "startTime");
            r.end = time(o, "endTime");
            r.from = place(rf, "address");
        }
    }
    r
}

fn order(o: &Obj, max_url_len: usize) -> Order {
    Order {
        number: id(o, "orderNumber"),
        merchant: name(o, "seller").or_else(|| name(o, "merchant")),
        status: enum_name(o, "orderStatus").and_then(|s| match s.as_str() {
            "OrderProcessing" => Some(OrderStatus::Processing),
            "OrderPaymentDue" => Some(OrderStatus::PaymentDue),
            "OrderInTransit" => Some(OrderStatus::InTransit),
            "OrderPickupAvailable" => Some(OrderStatus::PickupAvailable),
            "OrderDelivered" => Some(OrderStatus::Delivered),
            "OrderReturned" => Some(OrderStatus::Returned),
            "OrderCancelled" => Some(OrderStatus::Cancelled),
            "OrderProblem" => Some(OrderStatus::Problem),
            _ => None,
        }),
        total: price(o, "price")
            .or_else(|| price(o, "totalPrice"))
            .or_else(|| price(o, "priceSpecification")),
        date: time(o, "orderDate"),
        url: url(o, "url", max_url_len),
    }
}

fn invoice(o: &Obj, max_url_len: usize) -> Invoice {
    Invoice {
        number: id(o, "confirmationNumber")
            .or_else(|| id(o, "identifier"))
            .or_else(|| id(o, "accountId")),
        provider: name(o, "provider"),
        total: price(o, "totalPaymentDue").or_else(|| price(o, "minimumPaymentDue")),
        due: time(o, "paymentDueDate"),
        status: enum_name(o, "paymentStatus").and_then(|s| match s.as_str() {
            "PaymentDue" => Some(PaymentStatus::Due),
            "PaymentPastDue" => Some(PaymentStatus::PastDue),
            "PaymentComplete" => Some(PaymentStatus::Complete),
            "PaymentDeclined" => Some(PaymentStatus::Declined),
            "PaymentAutomaticallyApplied" => Some(PaymentStatus::AutomaticallyApplied),
            _ => None,
        }),
        url: url(o, "url", max_url_len),
    }
}

fn parcel(o: &Obj, max_url_len: usize) -> ParcelDelivery {
    ParcelDelivery {
        carrier: name(o, "carrier").or_else(|| name(o, "provider")),
        tracking_number: id(o, "trackingNumber"),
        tracking_url: url(o, "trackingUrl", max_url_len),
        expected_from: time(o, "expectedArrivalFrom"),
        expected_until: time(o, "expectedArrivalUntil"),
        order_number: obj(o, "partOfOrder").and_then(|p| id(p, "orderNumber")),
    }
}

fn action_kind(t: &str) -> Option<ActionKind> {
    match t {
        "ViewAction" => Some(ActionKind::View),
        "ConfirmAction" => Some(ActionKind::Confirm),
        "SaveAction" => Some(ActionKind::Save),
        "TrackAction" => Some(ActionKind::Track),
        "RsvpAction" => Some(ActionKind::Rsvp),
        _ => None,
    }
}

fn action(o: &Obj, max_url_len: usize) -> Option<Action> {
    let kind = types(o).iter().find_map(|t| action_kind(t))?;
    Some(Action {
        kind,
        name: name(o, "name"),
        url: url(o, "target", max_url_len).or_else(|| url(o, "url", max_url_len))?,
    })
}

fn item(o: &Obj, max_url_len: usize, out: &mut Vec<StructuredItem>) {
    for t in types(o) {
        let kind = match t.as_str() {
            "FlightReservation" => Some(ReservationKind::Flight),
            "LodgingReservation" => Some(ReservationKind::Lodging),
            "TrainReservation" => Some(ReservationKind::Train),
            "BusReservation" => Some(ReservationKind::Bus),
            "RentalCarReservation" => Some(ReservationKind::RentalCar),
            "EventReservation" => Some(ReservationKind::Event),
            "FoodEstablishmentReservation" => Some(ReservationKind::Food),
            _ => None,
        };
        let found = if let Some(kind) = kind {
            Some(StructuredItem::Reservation(reservation(
                kind,
                o,
                max_url_len,
            )))
        } else {
            match t.as_str() {
                "Order" => Some(StructuredItem::Order(order(o, max_url_len))),
                "Invoice" => Some(StructuredItem::Invoice(invoice(o, max_url_len))),
                "ParcelDelivery" => Some(StructuredItem::Parcel(parcel(o, max_url_len))),
                "EmailMessage" => {
                    let actions: Vec<&Value> = match o.get("potentialAction") {
                        Some(Value::Array(a)) => a.iter().take(MAX_ACTIONS).collect(),
                        Some(v) => vec![v],
                        None => Vec::new(),
                    };
                    for a in actions.into_iter().filter_map(Value::as_object) {
                        if let Some(a) = action(a, max_url_len)
                            && out.len() < MAX_STRUCTURED_ITEMS
                        {
                            out.push(StructuredItem::Action(a));
                        }
                    }
                    return;
                }
                other if action_kind(other).is_some() => {
                    action(o, max_url_len).map(StructuredItem::Action)
                }
                _ => None,
            }
        };
        if let Some(found) = found {
            if out.len() < MAX_STRUCTURED_ITEMS {
                out.push(found);
            }
            return;
        }
    }
}

/// Reads one JSON-LD script and appends its items. Scripts longer than [`MAX_LD_JSON_BYTES`],
/// nested deeper than serde_json's recursion limit or not JSON are skipped whole; at most
/// [`MAX_NODES`] top-level and `@graph` nodes are looked at.
pub(crate) fn read(script: &str, max_url_len: usize, out: &mut Vec<StructuredItem>) {
    if script.len() > MAX_LD_JSON_BYTES {
        return;
    }
    let trimmed = script
        .trim()
        .trim_start_matches("<!--")
        .trim_end_matches("-->")
        .trim();
    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
        return;
    };
    fn push<'v>(v: &'v Value, nodes: &mut Vec<&'v Obj>) {
        if let Value::Object(o) = v
            && nodes.len() < MAX_NODES
        {
            nodes.push(o);
        }
    }
    let mut nodes: Vec<&Obj> = Vec::new();
    let roots: Vec<&Value> = match &value {
        Value::Array(items) => items.iter().take(MAX_NODES).collect(),
        other => vec![other],
    };
    for root in roots {
        match root.get("@graph") {
            Some(Value::Array(graph)) => graph
                .iter()
                .take(MAX_NODES)
                .for_each(|g| push(g, &mut nodes)),
            _ => push(root, &mut nodes),
        }
    }
    for node in nodes {
        if out.len() >= MAX_STRUCTURED_ITEMS {
            break;
        }
        item(node, max_url_len, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(json: &str) -> Vec<StructuredItem> {
        let mut out = Vec::new();
        read(json, 2048, &mut out);
        out
    }

    #[test]
    fn flight_and_order() {
        let out = items(
            r#"[{"@context":"https://schema.org","@type":"FlightReservation","reservationNumber":"RXJ34P",
            "reservationStatus":"https://schema.org/ReservationConfirmed",
            "reservationFor":{"@type":"Flight","flightNumber":"110","airline":{"name":"Example Air","iataCode":"EX"},
            "departureAirport":{"name":"Vilnius","iataCode":"VNO"},"arrivalAirport":{"iataCode":"RIX"},
            "departureTime":"2026-12-01T10:00:00+02:00","arrivalTime":"2026-12-01T11:00:00+02:00"}},
            {"@type":"Order","orderNumber":12345,"seller":{"name":"Shop"},"price":"19.90","priceCurrency":"eur",
            "orderStatus":"http://schema.org/OrderInTransit","url":"https://shop.example.com/o/1"}]"#,
        );
        let StructuredItem::Reservation(r) = &out[0] else {
            panic!("{out:?}")
        };
        assert_eq!(r.kind, ReservationKind::Flight);
        assert_eq!(r.number.as_deref(), Some("RXJ34P"));
        assert_eq!(r.status, Some(ReservationStatus::Confirmed));
        assert_eq!(r.name.as_deref(), Some("EX110"));
        assert_eq!(r.provider.as_deref(), Some("Example Air"));
        assert_eq!(r.from.as_deref(), Some("VNO"));
        assert!(matches!(r.start, Some(When::Instant(_))));
        let StructuredItem::Order(o) = &out[1] else {
            panic!()
        };
        assert_eq!(o.number.as_deref(), Some("12345"));
        assert_eq!(o.status, Some(OrderStatus::InTransit));
        assert_eq!(
            o.total,
            Some(Price {
                amount: "19.90".into(),
                currency: Some("EUR".into())
            })
        );
    }

    #[test]
    fn graph_actions_parcel_invoice() {
        let out = items(
            r#"{"@graph":[{"@type":"EmailMessage","potentialAction":[{"@type":"ViewAction","name":"Track","target":{"urlTemplate":"https://track.example.com/1"}},
            {"@type":"ConfirmAction","url":"javascript:alert(1)"}]},
            {"@type":["Thing","ParcelDelivery"],"carrier":"Example Post","trackingNumber":"EX123","trackingUrl":"https://track.example.com/1",
             "partOfOrder":{"orderNumber":"A1"},"expectedArrivalUntil":"2026-12-03"},
            {"@type":"Invoice","provider":{"name":"Power"},"totalPaymentDue":{"@type":"PriceSpecification","price":42,"priceCurrency":"USD"},
             "paymentDueDate":"2026-12-10","paymentStatus":"PaymentDue"}]}"#,
        );
        assert_eq!(out.len(), 3, "{out:?}");
        assert!(
            matches!(&out[0], StructuredItem::Action(a) if a.kind == ActionKind::View && a.url.as_str() == "https://track.example.com/1")
        );
        assert!(
            matches!(&out[1], StructuredItem::Parcel(p) if p.order_number.as_deref() == Some("A1"))
        );
        assert!(
            matches!(&out[2], StructuredItem::Invoice(i) if i.total.as_ref().is_some_and(|t| t.amount == "42"))
        );
    }

    #[test]
    fn hostile_json() {
        assert!(items(&format!("{}{}", "[".repeat(100_000), "]".repeat(100_000))).is_empty());
        assert!(items("{not json").is_empty());
        assert!(items(&" ".repeat(MAX_LD_JSON_BYTES + 1)).is_empty());
        let confused = items(
            r#"[{"@type":5},{"@type":{"a":1}},{"@type":["Order"],"orderNumber":{"x":[1,2]},"price":1e300,
            "seller":[[{"name":"x"}]],"url":"http://127.0.0.1/admin","orderDate":["2026-02-30"]},
            {"@type":"FlightReservation","reservationFor":"not an object","reservationNumber":"a b"},
            {"@type":"ViewAction","target":"https://user:pw@example.com/"}]"#,
        );
        assert_eq!(confused.len(), 2, "{confused:?}");
        let StructuredItem::Order(o) = &confused[0] else {
            panic!()
        };
        assert_eq!(
            (o.number.as_ref(), o.total.as_ref(), o.url.as_ref(), o.date),
            (None, None, None, None)
        );
        let StructuredItem::Reservation(r) = &confused[1] else {
            panic!()
        };
        assert_eq!(r.number, None);
        let many = format!("[{}]", vec![r#"{"@type":"Order"}"#; 1000].join(","));
        assert_eq!(items(&many).len(), MAX_STRUCTURED_ITEMS);
        let bidi = items(&format!(
            r#"{{"@type":"Order","seller":{{"name":"Shop{}gnp.exe"}}}}"#,
            '\u{202E}'
        ));
        let StructuredItem::Order(o) = &bidi[0] else {
            panic!()
        };
        assert_eq!(o.merchant.as_deref(), Some("Shopgnp.exe"));
    }
}
