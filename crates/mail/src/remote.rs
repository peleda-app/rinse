use std::net::{Ipv4Addr, Ipv6Addr};

use rinse_doc_model::SafeUrl;

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0 && ip.octets()[2] == 0))
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4] {
        return public_v4(Ipv4Addr::new(
            (s[6] >> 8) as u8,
            s[6] as u8,
            (s[7] >> 8) as u8,
            s[7] as u8,
        ));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || s[0..6] == [0; 6]
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0)
}

fn numeric_label(label: &str) -> bool {
    !label.is_empty()
        && (label.bytes().all(|b| b.is_ascii_digit())
            || label
                .strip_prefix("0x")
                .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Whether `url` may be listed in [`Rendered::remote_images`](crate::Rendered::remote_images):
/// a lowercase `https://` or `http://` URL of at most `max_len` bytes that passes the
/// [`SafeUrl`] rules, has no user name or password, and whose host is an ASCII domain name that
/// is not `localhost`, `*.localhost`, `*.local`, `*.internal` or `*.home.arpa`, or an IP literal
/// that is publicly routable (no loopback, private, link-local, CGNAT, unspecified, multicast,
/// reserved or benchmarking range, IPv4-mapped and NAT64 addresses judged by their IPv4 part).
/// A host whose last label is numeric must be a dotted-quad IPv4 address.
///
/// This only judges the text. A fetcher must still check the address it actually connects to on
/// every connection (a public name can resolve to a private address, and DNS answers change) and
/// must not follow redirects to hosts that fail these rules.
pub fn remote_image_url_ok(url: &str, max_len: usize) -> bool {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    if SafeUrl::new(url, max_len).is_none() {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if let Some(v6) = authority.strip_prefix('[') {
        let Some((addr, port)) = v6.split_once(']') else {
            return false;
        };
        let port_ok = port.is_empty()
            || port
                .strip_prefix(':')
                .is_some_and(|p| p.bytes().all(|b| b.is_ascii_digit()));
        return port_ok && addr.parse::<Ipv6Addr>().is_ok_and(public_v6);
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        Some(_) => return false,
        None => authority,
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    let last = host.rsplit('.').next().unwrap_or_default();
    if numeric_label(last) {
        return host.parse::<Ipv4Addr>().is_ok_and(public_v4);
    }
    !(host == "localhost"
        || [".localhost", ".local", ".internal", ".home.arpa"]
            .iter()
            .any(|s| host.ends_with(s)))
}

#[cfg(test)]
mod tests {
    use super::remote_image_url_ok as ok;

    #[test]
    fn public_hosts_pass() {
        for url in [
            "https://images.example.com/banner.png",
            "http://images.example.org:8080/a.png?x=1",
            "https://93.184.215.14/x.png",
            "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/x.png",
        ] {
            assert!(ok(url, 2048), "{url}");
        }
    }

    #[test]
    fn internal_and_odd_hosts_fail() {
        for url in [
            "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[64:ff9b::a00:1]/",
            "http://[fd00::1]/",
            "http://[fe80::1]/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://100.64.0.1/",
            "http://0.0.0.0/",
            "http://2130706433/",
            "http://0x7f.1/",
            "http://localhost/",
            "http://printer.local/",
            "http://db.internal/",
            "https://user:pw@images.example.com/a.png",
            "https://images.example.com\u{202e}/a.png",
            "https://images.example.com/\u{200b}a.png",
            "https://IMAGES.example.com/a.png",
            "ftp://images.example.com/a.png",
            "https:///a.png",
        ] {
            assert!(!ok(url, 2048), "{url}");
        }
        assert!(!ok("https://images.example.com/a.png", 10));
    }
}
