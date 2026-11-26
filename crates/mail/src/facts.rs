//! Facts about a message beyond what the app displays: header signals, the grammar of
//! authentication fields, list and thread headers, typed structured data, calendar invitations
//! and where links sit in the body. The engine extracts them inside the worker; the receiver
//! checks them with [`verify_facts`] (called by [`verify_rendered`](crate::verify_rendered))
//! before anything reads them.
//!
//! Every string follows the display rules of [`Headers`](crate::Headers) (one line, no bidi,
//! invisible or control characters, at most [`DISPLAY_MAX_CHARS`](crate::DISPLAY_MAX_CHARS)
//! characters), identifiers and domains also carry no whitespace and are at most
//! [`ID_MAX_CHARS`] characters, every URL is a [`SafeUrl`], and every list is capped by the
//! constants of this module. Nothing here is verified: an `Authentication-Results` field or a
//! JSON-LD order can be forged by anyone who can send mail; consumers weigh them against the
//! spam filter's verdict.

use rinse_doc_model::SafeUrl;
use serde::{Deserialize, Serialize};

use crate::MailAddress;

mod verify;

pub use verify::verify_facts;

/// The most characters of an identifier, domain or selector: Message-IDs, `List-Id`,
/// authserv-ids, DKIM `d=` and `s=`, calendar UIDs, reservation and tracking numbers.
pub const ID_MAX_CHARS: usize = 255;
/// The most ids kept from `References`: the first and the last 31.
pub const MAX_REFERENCES: usize = 32;
/// The most `Authentication-Results` fields kept, from the top of the header.
pub const MAX_AUTH_RESULTS: usize = 16;
/// The most method results kept per `Authentication-Results` field.
pub const MAX_AUTH_METHODS: usize = 16;
/// The most `DKIM-Signature` fields kept, from the top of the header.
pub const MAX_DKIM_SIGNATURES: usize = 8;
/// The characters of a signature that identify it, as RFC 6008 recommends for `header.b`.
pub const B_PREFIX_LEN: usize = 8;
/// The most `List-Unsubscribe` targets kept.
pub const MAX_UNSUBSCRIBE_TARGETS: usize = 4;
/// The most structured items kept per message.
pub const MAX_STRUCTURED_ITEMS: usize = 16;
/// Earliest year of a [`When`].
pub const MIN_YEAR: u16 = 1970;
/// Latest year of a [`When`].
pub const MAX_YEAR: u16 = 2200;

/// Everything the worker found out about a message besides its display.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MessageFacts {
    /// Signals from header fields.
    pub header: HeaderFacts,
    /// The grammar of `Authentication-Results` and `DKIM-Signature`, unverified.
    pub auth: AuthFacts,
    /// `List-Unsubscribe` and `List-Unsubscribe-Post`.
    pub list: ListFacts,
    /// `In-Reply-To` and `References`.
    pub thread: ThreadFacts,
    /// Typed schema.org items from JSON-LD and Wallet passes, at most
    /// [`MAX_STRUCTURED_ITEMS`], in message order.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub structured: Vec<StructuredItem>,
    /// The first event of the first `text/calendar` part.
    pub invitation: Option<InvitationFacts>,
    /// Forward and footer markers and link placement in [`Rendered::body`](crate::Rendered::body).
    pub layout: LayoutFacts,
}

/// One header signal. The bit positions never change and are never reused; new signals take
/// the next free position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HeaderSignal {
    /// A `List-Id` field is present.
    ListId = 0,
    /// A `List-Post` field other than `NO` is present.
    ListPost = 1,
    /// `List-Post: NO`, comments ignored.
    ListPostNo = 2,
    /// A `List-Unsubscribe` field is present.
    Unsubscribe = 3,
    /// A `List-Unsubscribe-Post` field is present.
    UnsubscribePost = 4,
    /// `Precedence: bulk`, `list` or `junk`.
    PrecedenceBulk = 5,
    /// `Auto-Submitted` other than `no` and `auto-replied`.
    AutoSubmitted = 6,
    /// `Auto-Submitted: auto-replied`.
    AutoReplied = 7,
    /// A `Feedback-ID` field is present.
    FeedbackId = 8,
    /// A field that email service providers add (`X-SG-EID`, `X-Mailgun-*`, ...) is present.
    Esp = 9,
    /// The local part of the first `From` address starts like an automatic sender's
    /// (`noreply`, `no-reply`, `donotreply`, `mailer-daemon`, `postmaster`, `bounce`, ...).
    Noreply = 10,
}

impl HeaderSignal {
    /// Every signal in bit order.
    pub const ALL: [Self; 11] = [
        Self::ListId,
        Self::ListPost,
        Self::ListPostNo,
        Self::Unsubscribe,
        Self::UnsubscribePost,
        Self::PrecedenceBulk,
        Self::AutoSubmitted,
        Self::AutoReplied,
        Self::FeedbackId,
        Self::Esp,
        Self::Noreply,
    ];

    /// The bit of this signal in [`HeaderSignals`].
    pub const fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

/// A set of [`HeaderSignal`]s, stored as its bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HeaderSignals(u32);

impl HeaderSignals {
    /// The bits of every signal this version knows; [`verify_facts`] rejects any other bit.
    pub const KNOWN: u32 = (1 << HeaderSignal::ALL.len()) - 1;

    /// The set with exactly these bits, unknown ones included.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The stored bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `signal` is in the set.
    pub const fn contains(self, signal: HeaderSignal) -> bool {
        self.0 & signal.bit() != 0
    }

    /// Adds `signal`.
    pub fn insert(&mut self, signal: HeaderSignal) {
        self.0 |= signal.bit();
    }

    /// The known signals in the set, in bit order.
    pub fn iter(self) -> impl Iterator<Item = HeaderSignal> {
        HeaderSignal::ALL
            .into_iter()
            .filter(move |s| self.contains(*s))
    }
}

/// Signals from header fields.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HeaderFacts {
    /// The header signals; only bits of [`HeaderSignals::KNOWN`].
    pub signals: HeaderSignals,
    /// The number of `From` fields, at most 255.
    pub from_fields: u8,
    /// The number of mailboxes in the first `From` field, at most 255.
    pub from_addresses: u8,
    /// The first mailbox of `Sender`, normalized like [`Headers`](crate::Headers) addresses.
    pub sender: Option<MailAddress>,
    /// The identifier of `List-Id` (inside its angle brackets when it has them), lowercase, an
    /// identifier.
    pub list_id: Option<String>,
}

/// The grammar of authentication header fields. Nothing is verified: these are what the
/// fields say, and anyone can write them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthFacts {
    /// Readable `Authentication-Results` fields, top of the header first, at most
    /// [`MAX_AUTH_RESULTS`].
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub results: Vec<AuthResult>,
    /// Readable `DKIM-Signature` fields, top of the header first, at most
    /// [`MAX_DKIM_SIGNATURES`].
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub signatures: Vec<DkimTags>,
    /// How often some fields occur in the header.
    pub field_counts: FieldCounts,
    /// Some field, result or signature was left out because a cap was reached.
    pub cap_hit: bool,
}

/// One `Authentication-Results` field (RFC 8601).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResult {
    /// The authserv-id, lowercase, an identifier.
    pub authserv_id: String,
    /// The index of the field among all `Authentication-Results` fields of the header, 0 at
    /// the top (the one added last); strictly increasing over [`AuthFacts::results`].
    pub position: u8,
    /// The method results in field order, at most [`MAX_AUTH_METHODS`].
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub methods: Vec<AuthMethodResult>,
}

/// One `method=result` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMethodResult {
    /// The method.
    pub method: AuthMethod,
    /// The result.
    pub result: AuthOutcome,
    /// The domain the result is about, lowercase ASCII: `header.d` for DKIM, the domain of
    /// `smtp.mailfrom` for SPF, `header.from` for DMARC; `None` for other methods.
    pub domain: Option<String>,
    /// `header.i` of a DKIM result, an identifier.
    pub identity: Option<String>,
}

/// An authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthMethod {
    /// `dkim`.
    Dkim,
    /// `spf`.
    Spf,
    /// `dmarc`.
    Dmarc,
    /// `arc`.
    Arc,
    /// Anything else.
    Other,
}

/// A method result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthOutcome {
    /// `pass`.
    Pass,
    /// `fail` or `hardfail`.
    Fail,
    /// `softfail`.
    SoftFail,
    /// `neutral`.
    Neutral,
    /// `none`.
    None,
    /// `temperror`.
    TempError,
    /// `permerror`.
    PermError,
    /// `policy`.
    Policy,
    /// Anything else.
    Other,
}

/// The tags of one `DKIM-Signature` field (RFC 6376) that say what it covers.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DkimTags {
    /// `d=`, lowercase ASCII domain.
    pub d: Option<String>,
    /// `s=`, lowercase, an identifier.
    pub s: Option<String>,
    /// The first [`B_PREFIX_LEN`] characters of `b=`, base64 characters only.
    pub b_prefix: Option<String>,
    /// How often some fields are listed in `h=`; a count above [`FieldCounts`] means the field
    /// is oversigned (a later added field would break the signature).
    pub signed: SignedCounts,
    /// The number of names in `h=`, at most 255.
    pub signed_fields: u8,
    /// An `l=` (body length) tag is present, so content may be appended unsigned.
    pub body_length: bool,
}

/// How often some field names are listed in a signature's `h=`, each at most 255.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignedCounts {
    /// `from`.
    pub from: u8,
    /// `list-unsubscribe`.
    pub list_unsubscribe: u8,
    /// `list-unsubscribe-post`.
    pub list_unsubscribe_post: u8,
}

/// How often fields occur in the message header, each at most 255.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FieldCounts {
    /// `From`.
    pub from: u8,
    /// `List-Unsubscribe`.
    pub list_unsubscribe: u8,
    /// `List-Unsubscribe-Post`.
    pub list_unsubscribe_post: u8,
    /// `Authentication-Results`.
    pub authentication_results: u8,
    /// `DKIM-Signature`.
    pub dkim_signature: u8,
}

/// `List-Unsubscribe` (RFC 2369) and `List-Unsubscribe-Post` (RFC 8058).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ListFacts {
    /// The usable targets of the first `List-Unsubscribe` field in field order, at most
    /// [`MAX_UNSUBSCRIBE_TARGETS`]. Reading stops at the first item not in angle brackets.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub unsubscribe: Vec<UnsubscribeTarget>,
    /// Exactly one `List-Unsubscribe-Post: List-Unsubscribe=One-Click` field and at least one
    /// [`UnsubscribeTarget::Https`] target: a POST to that target unsubscribes.
    pub one_click: bool,
}

/// Where to unsubscribe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsubscribeTarget {
    /// A lowercase `https://` URL that passes
    /// [`remote_image_url_ok`](crate::remote_image_url_ok): public host, no user name or
    /// password. Whoever POSTs to it must still check the address it connects to.
    Https(SafeUrl),
    /// A `mailto:` with one address and at most a subject and a body; targets with any other
    /// header field (`cc`, `bcc`, `to`, ...) are dropped by the worker.
    Mailto(MailtoTarget),
}

/// A checked `mailto:` unsubscribe target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailtoTarget {
    /// One `local@domain` address: an identifier with exactly one `@`, no characters that
    /// separate addresses or start header fields (none of `<>()[],;:"\?&=%#/`), so it can be
    /// put back into a `mailto:` URL as is.
    pub address: String,
    /// The percent-decoded `subject`, display text.
    pub subject: Option<String>,
    /// The percent-decoded `body`, display text (line breaks become spaces).
    pub body: Option<String>,
}

/// `In-Reply-To` and `References`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ThreadFacts {
    /// The first id of `In-Reply-To`, without angle brackets, an identifier.
    pub in_reply_to: Option<String>,
    /// The ids of `References` without angle brackets, each an identifier, at most
    /// [`MAX_REFERENCES`]: the first and the last ones when there are more.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub references: Vec<String>,
    /// `References` held more ids than were kept.
    pub references_cut: bool,
}

/// A point or day in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum When {
    /// An instant, from a time with `Z` or a UTC offset: Unix seconds within the years
    /// [`MIN_YEAR`] to [`MAX_YEAR`].
    Instant(i64),
    /// A wall-clock time without a zone.
    Local(LocalDateTime),
    /// A whole day.
    Date(CalendarDate),
}

/// A day of the Gregorian calendar between [`MIN_YEAR`] and [`MAX_YEAR`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarDate {
    /// The year.
    pub year: u16,
    /// 1 to 12.
    pub month: u8,
    /// 1 to the length of the month.
    pub day: u8,
}

/// A wall-clock time on a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalDateTime {
    /// The day.
    pub date: CalendarDate,
    /// 0 to 23.
    pub hour: u8,
    /// 0 to 59.
    pub minute: u8,
    /// 0 to 59.
    pub second: u8,
}

/// An amount of money, never a float.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Price {
    /// A non-negative decimal: 1 to 15 digits, optionally `.` and 1 to 4 digits.
    pub amount: String,
    /// An ISO 4217 code: three uppercase ASCII letters.
    pub currency: Option<String>,
}

/// A typed item from a closed subset of schema.org (from `application/ld+json` in an HTML
/// part) or from a Wallet pass. Never raw JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuredItem {
    /// `FlightReservation`, `LodgingReservation`, `TrainReservation`, `BusReservation`,
    /// `RentalCarReservation`, `EventReservation`, `FoodEstablishmentReservation`.
    Reservation(Reservation),
    /// `Order`.
    Order(Order),
    /// `Invoice`.
    Invoice(Invoice),
    /// `ParcelDelivery`.
    Parcel(ParcelDelivery),
    /// `ViewAction`, `ConfirmAction`, `SaveAction`, `TrackAction`, `RsvpAction`, top level or
    /// as the `potentialAction` of an `EmailMessage`.
    Action(Action),
    /// An Apple Wallet pass (`.pkpass` attachment).
    Pass(Pass),
}

/// The kind of a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReservationKind {
    /// A flight.
    Flight,
    /// A hotel or other lodging.
    Lodging,
    /// A train trip.
    Train,
    /// A bus trip.
    Bus,
    /// A rental car.
    RentalCar,
    /// An event ticket.
    Event,
    /// A table at a restaurant.
    Food,
}

/// The status of a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReservationStatus {
    /// `ReservationConfirmed`.
    Confirmed,
    /// `ReservationCancelled`.
    Cancelled,
    /// `ReservationPending`.
    Pending,
    /// `ReservationHold`.
    Hold,
}

/// A reservation. Text fields are display text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    /// The kind.
    pub kind: ReservationKind,
    /// `reservationNumber`, an identifier.
    pub number: Option<String>,
    /// `reservationStatus`.
    pub status: Option<ReservationStatus>,
    /// What is reserved: the event, hotel or restaurant name, or the flight, train or bus
    /// number.
    pub name: Option<String>,
    /// The company: airline, train or bus operator, rental brand.
    pub provider: Option<String>,
    /// Departure, check-in, pickup or start.
    pub start: Option<When>,
    /// Arrival, check-out, drop-off or end.
    pub end: Option<When>,
    /// Departure airport (IATA code when given), station, stop, pickup place or venue.
    pub from: Option<String>,
    /// Arrival airport, station, stop or drop-off place.
    pub to: Option<String>,
    /// `modifyReservationUrl` or `url`; passes
    /// [`remote_image_url_ok`](crate::remote_image_url_ok).
    pub url: Option<SafeUrl>,
}

/// The status of an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OrderStatus {
    /// `OrderProcessing`.
    Processing,
    /// `OrderPaymentDue`.
    PaymentDue,
    /// `OrderInTransit`.
    InTransit,
    /// `OrderPickupAvailable`.
    PickupAvailable,
    /// `OrderDelivered`.
    Delivered,
    /// `OrderReturned`.
    Returned,
    /// `OrderCancelled`.
    Cancelled,
    /// `OrderProblem`.
    Problem,
}

/// An order. Text fields are display text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// `orderNumber`, an identifier.
    pub number: Option<String>,
    /// `seller` or `merchant` name.
    pub merchant: Option<String>,
    /// `orderStatus`.
    pub status: Option<OrderStatus>,
    /// `price`/`priceCurrency`, or the `totalPrice` of a price specification.
    pub total: Option<Price>,
    /// `orderDate`.
    pub date: Option<When>,
    /// `url`; passes [`remote_image_url_ok`](crate::remote_image_url_ok).
    pub url: Option<SafeUrl>,
}

/// The status of a payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaymentStatus {
    /// `PaymentDue`.
    Due,
    /// `PaymentPastDue`.
    PastDue,
    /// `PaymentComplete`.
    Complete,
    /// `PaymentDeclined`.
    Declined,
    /// `PaymentAutomaticallyApplied`.
    AutomaticallyApplied,
}

/// An invoice or bill. Text fields are display text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invoice {
    /// `confirmationNumber`, `identifier` or `accountId`, an identifier.
    pub number: Option<String>,
    /// `provider` name.
    pub provider: Option<String>,
    /// `totalPaymentDue`, else `minimumPaymentDue`.
    pub total: Option<Price>,
    /// `paymentDueDate`.
    pub due: Option<When>,
    /// `paymentStatus`.
    pub status: Option<PaymentStatus>,
    /// `url`; passes [`remote_image_url_ok`](crate::remote_image_url_ok).
    pub url: Option<SafeUrl>,
}

/// A parcel on its way. Text fields are display text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParcelDelivery {
    /// `carrier` or `provider` name.
    pub carrier: Option<String>,
    /// `trackingNumber`, an identifier.
    pub tracking_number: Option<String>,
    /// `trackingUrl`; passes [`remote_image_url_ok`](crate::remote_image_url_ok).
    pub tracking_url: Option<SafeUrl>,
    /// `expectedArrivalFrom`.
    pub expected_from: Option<When>,
    /// `expectedArrivalUntil`.
    pub expected_until: Option<When>,
    /// `partOfOrder.orderNumber`, an identifier.
    pub order_number: Option<String>,
}

/// The kind of an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionKind {
    /// `ViewAction`.
    View,
    /// `ConfirmAction`.
    Confirm,
    /// `SaveAction`.
    Save,
    /// `TrackAction`.
    Track,
    /// `RsvpAction`.
    Rsvp,
}

/// A one-click action offered by the sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    /// The kind.
    pub kind: ActionKind,
    /// `name`, display text.
    pub name: Option<String>,
    /// `target` or `url`; passes [`remote_image_url_ok`](crate::remote_image_url_ok).
    pub url: SafeUrl,
}

/// The style of a Wallet pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PassStyle {
    /// `boardingPass`.
    BoardingPass,
    /// `eventTicket`.
    EventTicket,
    /// `coupon`.
    Coupon,
    /// `storeCard`.
    StoreCard,
    /// `generic`.
    Generic,
}

/// An Apple Wallet pass read from `pass.json` inside a `.pkpass` attachment (signature not
/// checked). Text fields are display text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pass {
    /// The style.
    pub style: PassStyle,
    /// `organizationName`.
    pub organization: String,
    /// `description`.
    pub description: Option<String>,
    /// `relevantDate`.
    pub relevant: Option<When>,
}

/// The `METHOD` of an iCalendar object (RFC 5546).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CalendarMethod {
    /// `REQUEST`: an invitation or update.
    Request,
    /// `REPLY`: an attendee's answer.
    Reply,
    /// `CANCEL`.
    Cancel,
    /// `PUBLISH`, or no `METHOD`.
    Publish,
    /// `ADD`.
    Add,
    /// `REFRESH`.
    Refresh,
    /// `COUNTER`.
    Counter,
    /// `DECLINECOUNTER`.
    DeclineCounter,
    /// Anything else.
    Other,
}

/// The `STATUS` of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventStatus {
    /// `TENTATIVE`.
    Tentative,
    /// `CONFIRMED`.
    Confirmed,
    /// `CANCELLED`.
    Cancelled,
}

/// The first `VEVENT` of the first `text/calendar` part, display-normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitationFacts {
    /// `METHOD` of the calendar object.
    pub method: CalendarMethod,
    /// `UID`, an identifier.
    pub uid: Option<String>,
    /// `SEQUENCE`.
    pub sequence: Option<u32>,
    /// `SUMMARY`, display text.
    pub summary: Option<String>,
    /// `ORGANIZER`: the `mailto:` address and its `CN`, normalized like header addresses.
    pub organizer: Option<MailAddress>,
    /// `DTSTART`.
    pub start: Option<When>,
    /// `DTEND`.
    pub end: Option<When>,
    /// The `TZID` of `DTSTART` when it is a [`When::Local`] time, an identifier.
    pub time_zone: Option<String>,
    /// `LOCATION`, display text.
    pub location: Option<String>,
    /// `STATUS`.
    pub status: Option<EventStatus>,
    /// The number of `ATTENDEE` properties, at most 65,535.
    pub attendees: u16,
}

/// Where things sit in [`Rendered::body`](crate::Rendered::body). Block indices count every
/// block of the body in depth-first pre-order: a quote, list or table before its children,
/// list items and table cells in order.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LayoutFacts {
    /// The block with the first inline-forward marker (`---------- Forwarded message
    /// ---------`, `Begin forwarded message:` and their translations at the start of a line).
    pub forward_at: Option<u32>,
    /// The first block of the footer: the first block with an unsubscribe link or a `©`.
    pub footer_at: Option<u32>,
    /// One entry per entry of [`Rendered::links`](crate::Rendered::links), same order and
    /// length.
    #[serde(deserialize_with = "rinse_doc_model::bounded_vec")]
    pub links: Vec<LinkPlacement>,
}

/// Where one link sits.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LinkPlacement {
    /// Some occurrence looks like a button: short text and a background or padding on the link
    /// or its table cell, or `role="button"`.
    pub button_like: bool,
    /// The first occurrence in the body is at or after [`LayoutFacts::footer_at`].
    pub in_footer: bool,
    /// The first occurrence in the body is after [`LayoutFacts::forward_at`].
    pub below_forward: bool,
    /// `aria-label`, else `title`, of the first occurrence that has one, display text.
    pub aria_label: Option<String>,
}

impl CalendarDate {
    /// Whether the date exists and lies between [`MIN_YEAR`] and [`MAX_YEAR`].
    pub fn is_valid(&self) -> bool {
        (MIN_YEAR..=MAX_YEAR).contains(&self.year)
            && (1..=12).contains(&self.month)
            && self.day >= 1
            && self.day <= days_in_month(self.year, self.month)
    }

    /// Days since 1970-01-01 (proleptic Gregorian), for a valid date.
    pub fn unix_days(&self) -> i64 {
        let y = i64::from(self.year) - i64::from(self.month <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = i64::from(self.month);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

impl When {
    /// The first second of [`MIN_YEAR`] as Unix seconds.
    pub const MIN_INSTANT: i64 = 0;
    /// The last second of [`MAX_YEAR`] as Unix seconds.
    pub const MAX_INSTANT: i64 = 7_289_654_399;

    /// Whether every part is in range: instants within [`When::MIN_INSTANT`] and
    /// [`When::MAX_INSTANT`], dates valid, hours below 24, minutes and seconds below 60.
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Instant(t) => (Self::MIN_INSTANT..=Self::MAX_INSTANT).contains(t),
            Self::Date(d) => d.is_valid(),
            Self::Local(l) => l.date.is_valid() && l.hour < 24 && l.minute < 60 && l.second < 60,
        }
    }
}
