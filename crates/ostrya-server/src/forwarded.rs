//! The client address and the scheme that a trusted proxy forwards.
//!
//! A proxy that forwards a request writes the address of its own client into
//! a request header. A chain of proxies gives a list of hops, from the client
//! on the left to the last proxy on the right. The server reads one header,
//! the [`ForwardedHeader`] of `trusted-proxy-header`, and only from a peer in
//! `trusted-proxy`. It walks the hops from the right and skips each hop whose
//! address is in `trusted-proxy`. The first other hop is the client. When all
//! hops are trusted, the client is the leftmost hop.
//!
//! - `Forwarded` (RFC 7239): each element of the list is one hop. A pair is
//!   `NAME=VALUE`, and the names compare with no regard to case. A value is a
//!   token or a quoted string with `\` escapes. The `for` value of a hop is
//!   `IPV4`, `IPV4:PORT`, `[IPV6]`, or `[IPV6]:PORT`, the last three in
//!   quotes. `unknown`, an obfuscated name, a missing `for`, and another
//!   value give a hop with no address. A list that does not tokenize gives
//!   no address.
//! - `X-Forwarded-For`: each item of the comma list is one hop: `ADDR`,
//!   `IPV4:PORT`, or `[IPV6]:PORT`. Another item is a hop with no address.
//! - `X-Real-IP`: one hop, in the forms of an `X-Forwarded-For` item.
//!
//! The lines of the header join in their order, with a `,` between two
//! lines. A header that is absent, or that has one line of white space alone,
//! leaves the peer address. A header with other text and no hop, for example
//! `X-Forwarded-For: , ,`, gives no address. A header that is not UTF-8 gives
//! no address. A client with no address matches no `net:` item.
//!
//! The scheme of the request is `https` when the trusted proxy states it:
//! the `proto` of the selected hop of `Forwarded`, or else the rightmost
//! value of `X-Forwarded-Proto`. The server reads the scheme also when the
//! address header is absent.

use std::borrow::Cow;
use std::iter::Peekable;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hyper::HeaderMap;
use hyper::header::{FORWARDED, HeaderName};
use ostrya::access::{ForwardedHeader, IpNet};

/// The trusted proxies and the header of the client address.
#[derive(Debug)]
pub(crate) struct Forwarding {
    proxies: Vec<IpNet>,
    header: ForwardedHeader,
}

/// The client of a request, as the peer and its forwarding headers state it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Origin {
    /// The client address, or `None` when the trusted proxy gives a hop with
    /// no address.
    pub(crate) addr: Option<IpAddr>,
    /// `true` if a trusted proxy states the scheme `https`.
    pub(crate) https: bool,
}

/// One hop of a `Forwarded` header.
#[derive(Clone, Copy, Default)]
struct Hop {
    /// The address of the hop, or `None` for a hop with no address.
    addr: Option<IpAddr>,
    /// `true` if the `proto` of the hop is `https`, in any case.
    https: bool,
}

impl Forwarding {
    /// The forwarding of `proxies` by `header`.
    pub(crate) fn new(proxies: Vec<IpNet>, header: ForwardedHeader) -> Forwarding {
        Forwarding { proxies, header }
    }

    /// Returns `true` if `addr` is in a trusted network.
    pub(crate) fn trusts(&self, addr: IpAddr) -> bool {
        self.proxies.iter().any(|net| net.contains(addr))
    }

    /// The client of a request with `headers` from the peer address `peer`.
    /// The function reads no header of a peer that it does not trust.
    pub(crate) fn origin(&self, headers: &HeaderMap, peer: IpAddr) -> Origin {
        let peer_origin = Origin {
            addr: Some(peer),
            https: false,
        };
        if !self.trusts(peer) {
            return peer_origin;
        }
        let name = match self.header {
            ForwardedHeader::Forwarded => FORWARDED,
            ForwardedHeader::XForwardedFor => HeaderName::from_static("x-forwarded-for"),
            ForwardedHeader::XRealIp => HeaderName::from_static("x-real-ip"),
        };
        let proto_https =
            || self.header != ForwardedHeader::Forwarded && forwarded_proto_https(headers);
        // A header is blank when it is absent, or when it has one line of
        // white space alone. Two lines join with a `,`, so they are not blank.
        let mut blank = true;
        for (i, value) in headers.get_all(&name).iter().enumerate() {
            let Ok(line) = std::str::from_utf8(value.as_bytes()) else {
                return Origin {
                    addr: None,
                    https: proto_https(),
                };
            };
            blank = i == 0 && line.trim_matches([' ', '\t']).is_empty();
        }
        if blank {
            return Origin {
                https: proto_https(),
                ..peer_origin
            };
        }
        let lines = headers
            .get_all(&name)
            .iter()
            .filter_map(|value| std::str::from_utf8(value.as_bytes()).ok());
        let trusts = |addr: IpAddr| self.trusts(addr);
        match self.header {
            ForwardedHeader::Forwarded => {
                let hop = forwarded_hop(lines, trusts).unwrap_or_default();
                Origin {
                    addr: hop.addr,
                    https: hop.https,
                }
            }
            ForwardedHeader::XForwardedFor => Origin {
                addr: list_client(lines, trusts),
                https: proto_https(),
            },
            ForwardedHeader::XRealIp => {
                let mut lines = lines;
                let addr = match (lines.next(), lines.next()) {
                    (Some(line), None) => list_addr(line.trim_matches([' ', '\t'])),
                    _ => None,
                };
                Origin {
                    addr,
                    https: proto_https(),
                }
            }
        }
    }
}

/// The client address of the `X-Forwarded-For` lines `lines`. The function
/// walks the items from the right and stops at the first hop that `trusts`
/// does not accept. When all hops are trusted, the client is the leftmost
/// hop. With no hop, the result is `None`.
fn list_client<'a>(
    lines: impl DoubleEndedIterator<Item = &'a str>,
    trusts: impl Fn(IpAddr) -> bool,
) -> Option<IpAddr> {
    let mut leftmost = None;
    for item in lines.rev().flat_map(|line| line.rsplit(',')) {
        let item = item.trim_matches([' ', '\t']);
        if item.is_empty() {
            continue;
        }
        match list_addr(item) {
            Some(addr) if trusts(addr) => leftmost = Some(addr),
            addr => return addr,
        }
    }
    leftmost
}

/// Returns `true` if the rightmost value of `X-Forwarded-Proto` is `https`,
/// in any case. The rightmost value is the last comma item of the last line,
/// with no white space around it.
fn forwarded_proto_https(headers: &HeaderMap) -> bool {
    let Some(line) = headers.get_all("x-forwarded-proto").iter().next_back() else {
        return false;
    };
    let Ok(line) = std::str::from_utf8(line.as_bytes()) else {
        return false;
    };
    line.rsplit(',')
        .next()
        .is_some_and(|item| item.trim_matches([' ', '\t']).eq_ignore_ascii_case("https"))
}

/// The address of an `X-Forwarded-For` item or of `X-Real-IP`: `ADDR`,
/// `IPV4:PORT`, or `[IPV6]:PORT`. The port is dropped. Another form gives
/// `None`.
fn list_addr(item: &str) -> Option<IpAddr> {
    if let Ok(addr) = item.parse::<IpAddr>() {
        return Some(addr.to_canonical());
    }
    if let Some(rest) = item.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        is_port(port).then_some(())?;
        return addr
            .parse::<Ipv6Addr>()
            .ok()
            .map(|addr| IpAddr::V6(addr).to_canonical());
    }
    let (addr, port) = item.split_once(':')?;
    is_port(port).then_some(())?;
    addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

/// Returns `true` if `text` is a port: decimal digits alone, with a value of
/// at most 65535.
fn is_port(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && text.parse::<u16>().is_ok()
}

/// Returns `true` if `b` is a character of an HTTP token.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A reader of the lines of a header as one text, with a `,` between two
/// lines.
struct Cursor<'a, I: Iterator<Item = &'a str>> {
    line: &'a str,
    pos: usize,
    rest: Peekable<I>,
}

impl<'a, I: Iterator<Item = &'a str>> Cursor<'a, I> {
    fn new(mut lines: I) -> Self {
        Cursor {
            line: lines.next().unwrap_or(""),
            pos: 0,
            rest: lines.peekable(),
        }
    }

    /// The next byte, or `None` at the end of the last line.
    fn peek(&mut self) -> Option<u8> {
        match self.line.as_bytes().get(self.pos) {
            Some(b) => Some(*b),
            None => self.rest.peek().map(|_| b','),
        }
    }

    /// Moves past the next byte.
    fn bump(&mut self) {
        if self.pos < self.line.len() {
            self.pos += 1;
        } else if let Some(line) = self.rest.next() {
            self.line = line;
            self.pos = 0;
        }
    }

    /// Moves past spaces and tabs.
    fn skip_ows(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.bump();
        }
    }

    /// Moves past a token and gives it. The token is empty when the next
    /// byte is not a token character. A token ends at the end of a line,
    /// because `,` is not a token character.
    fn token(&mut self) -> &'a str {
        let start = self.pos;
        while self
            .line
            .as_bytes()
            .get(self.pos)
            .copied()
            .is_some_and(is_tchar)
        {
            self.pos += 1;
        }
        &self.line[start..self.pos]
    }

    /// Moves past the rest of a quoted string, after its opening quote, and
    /// gives its value with the escapes removed. The value is empty when
    /// `keep` is `false`. The result is `None` when the string does not
    /// end.
    fn quoted(&mut self, keep: bool) -> Option<Cow<'a, str>> {
        let start = self.pos;
        let bytes = self.line.as_bytes();
        while let Some(&b) = bytes.get(self.pos) {
            match b {
                b'"' => {
                    let value = &self.line[start..self.pos];
                    self.pos += 1;
                    return Some(Cow::Borrowed(if keep { value } else { "" }));
                }
                b'\\' => break,
                _ => self.pos += 1,
            }
        }
        // The string has an escape or goes on in the next line.
        let mut value = Vec::new();
        if keep {
            value.extend_from_slice(&bytes[start..self.pos]);
        }
        loop {
            let b = match self.peek()? {
                b'"' => break,
                b'\\' => {
                    self.bump();
                    self.peek()?
                }
                b => b,
            };
            if keep {
                value.push(b);
            }
            self.bump();
        }
        self.bump();
        String::from_utf8(value).ok().map(Cow::Owned)
    }
}

/// The selected hop of the `Forwarded` lines `lines`: the rightmost hop that
/// `trusts` does not accept, or else the leftmost hop. An element with no
/// pair is not a hop. The result is `None` when the value does not tokenize
/// or has no hop.
fn forwarded_hop<'a>(
    lines: impl Iterator<Item = &'a str>,
    trusts: impl Fn(IpAddr) -> bool,
) -> Option<Hop> {
    let mut cur = Cursor::new(lines);
    let mut leftmost = None;
    let mut client = None;
    let mut hop = Hop::default();
    let mut pairs = 0;
    let mut seen_for = false;
    let mut seen_proto = false;
    loop {
        cur.skip_ows();
        let name = cur.token();
        if !name.is_empty() {
            if cur.peek() != Some(b'=') {
                return None;
            }
            cur.bump();
            let is_for = name.eq_ignore_ascii_case("for");
            let is_proto = name.eq_ignore_ascii_case("proto");
            let value = if cur.peek() == Some(b'"') {
                cur.bump();
                cur.quoted(is_for || is_proto)?
            } else {
                let value = cur.token();
                if value.is_empty() {
                    return None;
                }
                Cow::Borrowed(value)
            };
            pairs += 1;
            if is_for {
                if seen_for {
                    return None;
                }
                seen_for = true;
                hop.addr = node_addr(&value);
            } else if is_proto {
                if seen_proto {
                    return None;
                }
                seen_proto = true;
                hop.https = value.eq_ignore_ascii_case("https");
            }
            cur.skip_ows();
        }
        match cur.peek() {
            Some(b';') => cur.bump(),
            Some(b',') | None => {
                if pairs > 0 {
                    leftmost.get_or_insert(hop);
                    if !hop.addr.is_some_and(&trusts) {
                        client = Some(hop);
                    }
                }
                hop = Hop::default();
                pairs = 0;
                seen_for = false;
                seen_proto = false;
                if cur.peek().is_none() {
                    return client.or(leftmost);
                }
                cur.bump();
            }
            Some(_) => return None,
        }
    }
}

/// The address of a `for` value of `Forwarded`: `IPV4`, `IPV4:PORT`,
/// `[IPV6]`, or `[IPV6]:PORT`. A port is digits or an obfuscated port that
/// starts with `_`. `unknown`, an obfuscated name, and another value give
/// `None`.
fn node_addr(value: &str) -> Option<IpAddr> {
    let port_ok = |port: Option<&str>| match port {
        None => true,
        Some(port) => {
            is_port(port)
                || port.strip_prefix('_').is_some_and(|rest| {
                    !rest.is_empty()
                        && rest
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                })
        }
    };
    if let Some(rest) = value.strip_prefix('[') {
        let (addr, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        port_ok(port).then_some(())?;
        return addr
            .parse::<Ipv6Addr>()
            .ok()
            .map(|addr| IpAddr::V6(addr).to_canonical());
    }
    let (addr, port) = match value.split_once(':') {
        Some((addr, port)) => (addr, Some(port)),
        None => (value, None),
    };
    port_ok(port).then_some(())?;
    addr.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;

    use super::*;

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    /// The forwarding of the proxies 10.0.0.0/8 and 2001:db8:f::/48 by
    /// `header`.
    fn forwarding(header: ForwardedHeader) -> Forwarding {
        Forwarding::new(vec![net("10.0.0.0/8"), net("2001:db8:f::/48")], header)
    }

    /// The headers of the pairs `lines`, in order.
    fn headers(lines: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in lines {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_bytes(value.as_bytes()).unwrap(),
            );
        }
        headers
    }

    /// The origin of `lines` by `header` from the trusted peer 10.0.0.1.
    fn origin(header: ForwardedHeader, lines: &[(&str, &str)]) -> Origin {
        forwarding(header).origin(&headers(lines), "10.0.0.1".parse().unwrap())
    }

    fn addr(text: &str) -> Option<IpAddr> {
        Some(text.parse().unwrap())
    }

    fn client(header: ForwardedHeader, lines: &[(&str, &str)]) -> Option<IpAddr> {
        origin(header, lines).addr
    }

    /// The examples of RFC 7239 give their client.
    #[test]
    fn the_examples_of_rfc_7239_give_their_client() {
        let f = ForwardedHeader::Forwarded;
        for (value, expected) in [
            (r#"for="_gazonk""#, None),
            (
                r#"For="[2001:db8:cafe::17]:4711""#,
                addr("2001:db8:cafe::17"),
            ),
            (
                "for=192.0.2.60;proto=http;by=203.0.113.43",
                addr("192.0.2.60"),
            ),
            ("for=192.0.2.43, for=198.51.100.17", addr("198.51.100.17")),
            ("for=unknown", None),
            (r#"for="192.0.2.43:47011""#, addr("192.0.2.43")),
            (r#"for="[2001:db8::1]""#, addr("2001:db8::1")),
            (r#"for="192.0.2.43:_hidden""#, addr("192.0.2.43")),
            ("proto=https;by=10.0.0.9", None),
        ] {
            assert_eq!(client(f, &[("forwarded", value)]), expected, "{value}");
        }
    }

    /// The names compare with no regard to case, a quoted string takes `\`
    /// escapes, and white space around a pair has no effect.
    #[test]
    fn names_and_escapes_of_forwarded() {
        let f = ForwardedHeader::Forwarded;
        for value in [
            "FOR=192.0.2.1;PROTO=HTTPS",
            "For=\"192.0.2.1\";Proto=\"https\"",
            "for=\"\\1\\9\\2.0.2.1\" ; proto=\"\\https\"",
            " for=192.0.2.1 ;proto=https ,",
            ",for=192.0.2.1;;proto=https",
        ] {
            let found = origin(f, &[("forwarded", value)]);
            let expected = Origin {
                addr: addr("192.0.2.1"),
                https: true,
            };
            assert_eq!(found, expected, "{value}");
        }
        // A `\` is no escape outside a quoted string.
        let found = origin(f, &[("forwarded", "for=192.0.2.1;proto=\\https")]);
        assert_eq!(found.addr, None);
    }

    /// A value that does not tokenize gives no address: an unterminated
    /// quote, an IPv6 address with no quotes, a pair with no value, a name
    /// with no `=`, and a repeated `for`.
    #[test]
    fn a_bad_forwarded_value_gives_no_address() {
        for value in [
            "for=\"192.0.2.1",
            "for=\"192.0.2.1\\",
            "for=[2001:db8::1]",
            "for=2001:db8::1",
            "for=192.0.2.1:80",
            "for=",
            "for",
            "for=192.0.2.1;for=192.0.2.2",
            "for=192.0.2.1 x",
            "for=\"a\"b",
        ] {
            let found = origin(ForwardedHeader::Forwarded, &[("forwarded", value)]);
            assert_eq!(
                found,
                Origin {
                    addr: None,
                    https: false
                },
                "{value}"
            );
        }
    }

    /// The walk skips each trusted hop from the right. With all hops
    /// trusted, the client is the leftmost hop. An untrusted hop with no
    /// address is the client, with no address.
    #[test]
    fn the_walk_skips_the_trusted_hops() {
        let f = ForwardedHeader::Forwarded;
        let x = ForwardedHeader::XForwardedFor;
        for (header, name, value, expected) in [
            (
                f,
                "forwarded",
                "for=192.0.2.1, for=198.51.100.1, for=10.0.0.2",
                addr("198.51.100.1"),
            ),
            (
                f,
                "forwarded",
                "for=192.0.2.1, for=10.1.0.1, for=\"[2001:db8:f::1]\"",
                addr("192.0.2.1"),
            ),
            (
                f,
                "forwarded",
                "for=10.0.0.3, for=10.0.0.2",
                addr("10.0.0.3"),
            ),
            (
                f,
                "forwarded",
                "for=192.0.2.1, for=unknown, for=10.0.0.2",
                None,
            ),
            (f, "forwarded", "for=192.0.2.1, proto=https", None),
            (
                x,
                "x-forwarded-for",
                "192.0.2.1, 198.51.100.1, 10.0.0.2",
                addr("198.51.100.1"),
            ),
            (x, "x-forwarded-for", "10.0.0.3,10.0.0.2", addr("10.0.0.3")),
            (x, "x-forwarded-for", "192.0.2.1, garbage, 10.0.0.2", None),
            (
                x,
                "x-forwarded-for",
                "192.0.2.1, ::ffff:10.0.0.9",
                addr("192.0.2.1"),
            ),
        ] {
            assert_eq!(client(header, &[(name, value)]), expected, "{value}");
        }
    }

    /// The forms of an `X-Forwarded-For` item and of `X-Real-IP`.
    #[test]
    fn the_forms_of_a_list_item() {
        let x = ForwardedHeader::XForwardedFor;
        let r = ForwardedHeader::XRealIp;
        for (value, expected) in [
            ("192.0.2.1", addr("192.0.2.1")),
            ("192.0.2.1:8080", addr("192.0.2.1")),
            ("2001:db8::1", addr("2001:db8::1")),
            ("[2001:db8::1]:443", addr("2001:db8::1")),
            ("::ffff:192.0.2.1", addr("192.0.2.1")),
            ("[2001:db8::1]", None),
            ("192.0.2.1:", None),
            ("192.0.2.1:65536", None),
            ("192.0.2.1:+1", None),
            ("host.example", None),
            ("unknown", None),
        ] {
            assert_eq!(
                client(x, &[("x-forwarded-for", value)]),
                expected,
                "{value}"
            );
            assert_eq!(client(r, &[("x-real-ip", value)]), expected, "{value}");
        }
        assert_eq!(
            client(r, &[("x-real-ip", " 192.0.2.1 ")]),
            addr("192.0.2.1")
        );
        assert_eq!(client(r, &[("x-real-ip", "192.0.2.1, 192.0.2.2")]), None);
    }

    /// Two lines of the header join in their order. An empty header counts
    /// as absent and leaves the peer address. A line that is not UTF-8 gives
    /// no address.
    #[test]
    fn lines_join_and_an_empty_header_is_absent() {
        let x = ForwardedHeader::XForwardedFor;
        let lines = [
            ("x-forwarded-for", "192.0.2.1, 198.51.100.1"),
            ("x-forwarded-for", "10.0.0.2"),
        ];
        assert_eq!(client(x, &lines), addr("198.51.100.1"));
        let lines = [
            ("forwarded", "for=192.0.2.1"),
            ("forwarded", "for=10.0.0.2"),
        ];
        assert_eq!(
            client(ForwardedHeader::Forwarded, &lines),
            addr("192.0.2.1")
        );
        for value in ["", " ", "\t"] {
            assert_eq!(client(x, &[("x-forwarded-for", value)]), addr("10.0.0.1"));
        }
        assert_eq!(client(x, &[]), addr("10.0.0.1"));
        assert_eq!(client(x, &[("x-forwarded-for", "192.0.2.1\u{e9}")]), None);
    }

    /// A quoted string of `Forwarded` goes on in the next line, with the `,`
    /// of the join in its value.
    #[test]
    fn a_quoted_string_spans_the_join_of_two_lines() {
        let f = ForwardedHeader::Forwarded;
        let lines = [
            ("forwarded", "for=192.0.2.1;by=\"a"),
            ("forwarded", "b\", for=10.0.0.2;proto=https"),
        ];
        assert_eq!(client(f, &lines), addr("192.0.2.1"));
        let lines = [
            ("forwarded", "for=192.0.2.1;proto=\"https\\"),
            ("forwarded", "\""),
        ];
        let found = origin(f, &lines);
        assert_eq!(
            found,
            Origin {
                addr: addr("192.0.2.1"),
                https: false
            }
        );
        let lines = [("forwarded", "for=\"192.0.2.1"), ("forwarded", "\"")];
        assert_eq!(client(f, &lines), None);
    }

    /// A header with text and no hop gives no address. Two empty lines join
    /// to a `,`, which is text.
    #[test]
    fn a_header_with_no_hop_gives_no_address() {
        let x = ForwardedHeader::XForwardedFor;
        let f = ForwardedHeader::Forwarded;
        for (header, name, value) in [
            (x, "x-forwarded-for", ","),
            (x, "x-forwarded-for", " , ,"),
            (f, "forwarded", ","),
            (f, "forwarded", ";"),
            (f, "forwarded", " ; , ;"),
        ] {
            assert_eq!(client(header, &[(name, value)]), None, "{value}");
        }
        for (header, name) in [(x, "x-forwarded-for"), (f, "forwarded")] {
            assert_eq!(client(header, &[(name, ""), (name, "")]), None, "{name}");
        }
        let r = ForwardedHeader::XRealIp;
        assert_eq!(client(r, &[("x-real-ip", ""), ("x-real-ip", "")]), None);
    }

    /// A port of a `for` value of `Forwarded` has a value of at most 65535.
    #[test]
    fn a_forwarded_port_is_at_most_65535() {
        let f = ForwardedHeader::Forwarded;
        for (value, expected) in [
            ("for=\"192.0.2.1:65535\"", addr("192.0.2.1")),
            ("for=\"192.0.2.1:65536\"", None),
            ("for=\"192.0.2.1:99999\"", None),
            ("for=\"[2001:db8::1]:443\"", addr("2001:db8::1")),
            ("for=\"[2001:db8::1]:99999\"", None),
        ] {
            assert_eq!(client(f, &[("forwarded", value)]), expected, "{value}");
        }
    }

    /// Only the configured header gives the client. A forged header of
    /// another kind has no effect.
    #[test]
    fn only_the_configured_header_is_read() {
        let lines = [
            ("forwarded", "for=192.0.2.66;proto=https"),
            ("x-forwarded-for", "192.0.2.1"),
            ("x-real-ip", "192.0.2.77"),
        ];
        assert_eq!(
            client(ForwardedHeader::XForwardedFor, &lines),
            addr("192.0.2.1")
        );
        assert_eq!(client(ForwardedHeader::XRealIp, &lines), addr("192.0.2.77"));
        assert_eq!(
            client(ForwardedHeader::Forwarded, &lines),
            addr("192.0.2.66")
        );
        let found = origin(ForwardedHeader::XForwardedFor, &lines);
        assert!(!found.https);
    }

    /// The scheme of `Forwarded` is the `proto` of the selected hop. The
    /// scheme of the other headers is the rightmost value of
    /// `X-Forwarded-Proto`, also when the address header is absent.
    #[test]
    fn the_scheme_follows_the_header_kind() {
        let f = ForwardedHeader::Forwarded;
        for (value, https) in [
            ("for=192.0.2.1;proto=https, for=10.0.0.2;proto=http", true),
            ("for=192.0.2.1;proto=http, for=10.0.0.2;proto=https", false),
            ("for=10.0.0.3;proto=HTTPS, for=10.0.0.2", true),
            ("for=192.0.2.1", false),
        ] {
            let lines = [("forwarded", value), ("x-forwarded-proto", "https")];
            assert_eq!(origin(f, &lines).https, https, "{value}");
        }
        assert!(!origin(f, &[("x-forwarded-proto", "https")]).https);
        for header in [ForwardedHeader::XForwardedFor, ForwardedHeader::XRealIp] {
            for (lines, https) in [
                (&[("x-forwarded-proto", "https")][..], true),
                (&[("x-forwarded-proto", " HTTPS ")], true),
                (&[("x-forwarded-proto", "http, https")], true),
                (&[("x-forwarded-proto", "https, http")], false),
                (
                    &[
                        ("x-forwarded-proto", "https"),
                        ("x-forwarded-proto", "http"),
                    ],
                    false,
                ),
                (
                    &[
                        ("x-forwarded-proto", "http"),
                        ("x-forwarded-proto", "https"),
                    ],
                    true,
                ),
                (&[("x-forwarded-proto", "https,")], false),
                (&[], false),
            ] {
                assert_eq!(origin(header, lines).https, https, "{header} {lines:?}");
            }
            let lines = [
                ("x-forwarded-for", "192.0.2.1"),
                ("x-forwarded-proto", "https"),
            ];
            let lines = if header == ForwardedHeader::XRealIp {
                [("x-real-ip", "192.0.2.1"), ("x-forwarded-proto", "https")]
            } else {
                lines
            };
            assert_eq!(
                origin(header, &lines),
                Origin {
                    addr: addr("192.0.2.1"),
                    https: true
                }
            );
        }
    }

    /// A peer that is not trusted gives its own address, and no header has
    /// an effect.
    #[test]
    fn an_untrusted_peer_ignores_each_header() {
        let lines = [
            ("forwarded", "for=192.0.2.1;proto=https"),
            ("x-forwarded-for", "192.0.2.1"),
            ("x-real-ip", "192.0.2.1"),
            ("x-forwarded-proto", "https"),
        ];
        for header in [
            ForwardedHeader::Forwarded,
            ForwardedHeader::XForwardedFor,
            ForwardedHeader::XRealIp,
        ] {
            let peer = "192.0.2.200".parse().unwrap();
            let found = forwarding(header).origin(&headers(&lines), peer);
            assert_eq!(
                found,
                Origin {
                    addr: Some(peer),
                    https: false
                }
            );
        }
    }
}
