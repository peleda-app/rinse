use rinse_doc_model::{Block, SafeUrl};

use super::*;
use crate::verify::display_text_ok;
use crate::{ContentError, RenderRequest, Rendered, remote_image_url_ok};

struct Check {
    max_url_len: usize,
}

fn text_ok(s: &str) -> bool {
    display_text_ok(s)
}

fn opt_text(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(text_ok)
}

fn id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= ID_MAX_CHARS
        && !s.chars().any(char::is_whitespace)
        && display_text_ok(s)
}

fn opt_id(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(id_ok)
}

fn domain_ok(s: &str) -> bool {
    (1..=253).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
}

fn opt_domain(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(domain_ok)
}

fn address_ok(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    id_ok(s)
        && !local.is_empty()
        && domain_ok(domain)
        && !s.chars().any(|c| "<>()[],;:\"\\?&=%#/".contains(c))
}

fn mailbox_ok(m: &MailAddress) -> bool {
    text_ok(&m.address) && !m.address.is_empty() && opt_text(&m.name)
}

fn price_ok(p: &Price) -> bool {
    let (int, frac) = match p.amount.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (p.amount.as_str(), None),
    };
    let digits =
        |s: &str, max: usize| (1..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    digits(int, 15)
        && frac.is_none_or(|f| digits(f, 4))
        && p.currency
            .as_deref()
            .is_none_or(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase()))
}

fn when_ok(w: &Option<When>) -> bool {
    w.as_ref().is_none_or(When::is_valid)
}

impl Check {
    fn web(&self, url: &SafeUrl) -> bool {
        SafeUrl::new(url.as_str(), self.max_url_len).is_some()
            && remote_image_url_ok(url.as_str(), self.max_url_len)
    }

    fn opt_web(&self, url: &Option<SafeUrl>) -> bool {
        url.as_ref().is_none_or(|u| self.web(u))
    }

    fn item(&self, item: &StructuredItem) -> bool {
        match item {
            StructuredItem::Reservation(r) => {
                opt_id(&r.number)
                    && opt_text(&r.name)
                    && opt_text(&r.provider)
                    && opt_text(&r.from)
                    && opt_text(&r.to)
                    && when_ok(&r.start)
                    && when_ok(&r.end)
                    && self.opt_web(&r.url)
            }
            StructuredItem::Order(o) => {
                opt_id(&o.number)
                    && opt_text(&o.merchant)
                    && o.total.as_ref().is_none_or(price_ok)
                    && when_ok(&o.date)
                    && self.opt_web(&o.url)
            }
            StructuredItem::Invoice(i) => {
                opt_id(&i.number)
                    && opt_text(&i.provider)
                    && i.total.as_ref().is_none_or(price_ok)
                    && when_ok(&i.due)
                    && self.opt_web(&i.url)
            }
            StructuredItem::Parcel(p) => {
                opt_text(&p.carrier)
                    && opt_id(&p.tracking_number)
                    && self.opt_web(&p.tracking_url)
                    && when_ok(&p.expected_from)
                    && when_ok(&p.expected_until)
                    && opt_id(&p.order_number)
            }
            StructuredItem::Action(a) => opt_text(&a.name) && self.web(&a.url),
            StructuredItem::Pass(p) => {
                !p.organization.is_empty()
                    && text_ok(&p.organization)
                    && opt_text(&p.description)
                    && when_ok(&p.relevant)
            }
        }
    }
}

fn block_count(blocks: &[Block]) -> usize {
    let mut n = 0;
    let mut stack: Vec<&Block> = blocks.iter().collect();
    while let Some(b) = stack.pop() {
        n += 1;
        match b {
            Block::Quote(children) => stack.extend(children),
            Block::List { items, .. } => items.iter().for_each(|i| stack.extend(i)),
            Block::Table { rows } => rows
                .iter()
                .flatten()
                .for_each(|cell| stack.extend(&cell.blocks)),
            _ => {}
        }
    }
    n
}

/// Checks the [`MessageFacts`] of a [`Rendered`] against every guarantee of this module that a
/// receiver can verify without parsing message content: only known signal bits; every string a
/// display string, identifiers and domains as documented; every list within its cap;
/// `Authentication-Results` positions strictly increasing; domains only on DKIM, SPF and DMARC
/// results and identities only on DKIM results; `one_click` only with an `https` target, exactly
/// one `List-Unsubscribe-Post` field and its signal; `time_zone` only with a local start; every
/// URL a [`SafeUrl`] within `doc.max_url_len` that passes [`remote_image_url_ok`], unsubscribe
/// URLs `https://` only; mailto targets one address; prices and times in range; layout indices
/// inside the body and exactly one placement per link. [`verify_rendered`](crate::verify_rendered)
/// calls it; any failure is [`ContentError::Crashed`].
pub fn verify_facts(request: &RenderRequest, out: &Rendered) -> Result<(), ContentError> {
    if facts_ok(request, out) {
        Ok(())
    } else {
        Err(ContentError::Crashed)
    }
}

fn facts_ok(request: &RenderRequest, out: &Rendered) -> bool {
    let f = &out.facts;
    let c = Check {
        max_url_len: request.limits.doc.max_url_len,
    };

    let h = &f.header;
    let header = h.signals.bits() & !HeaderSignals::KNOWN == 0
        && h.sender.as_ref().is_none_or(mailbox_ok)
        && h.list_id
            .as_deref()
            .is_none_or(|id| id_ok(id) && id.to_lowercase() == id);

    let a = &f.auth;
    let positions_rise = a.results.windows(2).all(|w| w[0].position < w[1].position);
    let counted = |p: u8| {
        a.field_counts.authentication_results == u8::MAX
            || p < a.field_counts.authentication_results
    };
    let results = a.results.len() <= MAX_AUTH_RESULTS
        && positions_rise
        && h.from_fields == a.field_counts.from
        && a.results.iter().all(|r| {
            counted(r.position)
                && id_ok(&r.authserv_id)
                && r.authserv_id.to_lowercase() == r.authserv_id
                && r.methods.len() <= MAX_AUTH_METHODS
                && r.methods.iter().all(|m| {
                    let domain_allowed = matches!(
                        m.method,
                        AuthMethod::Dkim | AuthMethod::Spf | AuthMethod::Dmarc
                    );
                    opt_domain(&m.domain)
                        && (domain_allowed || m.domain.is_none())
                        && opt_id(&m.identity)
                        && (m.method == AuthMethod::Dkim || m.identity.is_none())
                })
        });
    let signatures = a.signatures.len() <= MAX_DKIM_SIGNATURES
        && a.signatures.iter().all(|s| {
            opt_domain(&s.d)
                && s.s
                    .as_deref()
                    .is_none_or(|sel| id_ok(sel) && sel.to_lowercase() == sel)
                && s.b_prefix.as_deref().is_none_or(|b| {
                    !b.is_empty()
                        && b.len() <= B_PREFIX_LEN
                        && b.bytes()
                            .all(|x| x.is_ascii_alphanumeric() || b"+/=".contains(&x))
                })
        });

    let l = &f.list;
    let mut https = false;
    let list = l.unsubscribe.len() <= MAX_UNSUBSCRIBE_TARGETS
        && l.unsubscribe.iter().all(|t| match t {
            UnsubscribeTarget::Https(url) => {
                https = true;
                url.as_str().starts_with("https://") && c.web(url)
            }
            UnsubscribeTarget::Mailto(m) => {
                address_ok(&m.address) && opt_text(&m.subject) && opt_text(&m.body)
            }
        })
        && (!l.one_click
            || (https
                && a.field_counts.list_unsubscribe_post == 1
                && h.signals.contains(HeaderSignal::UnsubscribePost)));

    let t = &f.thread;
    let thread = opt_id(&t.in_reply_to)
        && t.references.len() <= MAX_REFERENCES
        && t.references.iter().all(|r| id_ok(r));

    let structured =
        f.structured.len() <= MAX_STRUCTURED_ITEMS && f.structured.iter().all(|i| c.item(i));

    let invitation = f.invitation.as_ref().is_none_or(|i| {
        opt_id(&i.uid)
            && opt_text(&i.summary)
            && i.organizer.as_ref().is_none_or(mailbox_ok)
            && when_ok(&i.start)
            && when_ok(&i.end)
            && opt_id(&i.time_zone)
            && (i.time_zone.is_none() || matches!(i.start, Some(When::Local(_))))
            && opt_text(&i.location)
    });

    let blocks = block_count(&out.body.blocks);
    let lay = &f.layout;
    let inside = |at: Option<u32>| at.is_none_or(|i| (i as usize) < blocks);
    let layout = lay.links.len() == out.links.len()
        && inside(lay.forward_at)
        && inside(lay.footer_at)
        && lay.links.iter().all(|p| {
            opt_text(&p.aria_label)
                && (!p.in_footer || lay.footer_at.is_some())
                && (!p.below_forward || lay.forward_at.is_some())
        });

    header && results && signatures && list && thread && structured && invitation && layout
}

#[cfg(test)]
mod tests;
