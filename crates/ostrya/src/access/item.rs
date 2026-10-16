//! The authentication items of a client group, and the networks of the
//! `net:` items and of `trusted-proxy`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

/// One item of the `auth` list of a client group.
///
/// Each variant has one text form:
///
/// - `anonymous` -- [`Anonymous`](AuthItem::Anonymous).
/// - `tls:*` -- [`TlsAny`](AuthItem::TlsAny).
/// - `tls:NAME` -- [`TlsName`](AuthItem::TlsName). `NAME` is not empty, is
///   not `*`, holds no control character, and does not start or end with
///   white space.
/// - `tls-sha256:HEX` -- [`TlsSha256`](AuthItem::TlsSha256).
/// - `token-sha256:HEX` -- [`TokenSha256`](AuthItem::TokenSha256).
/// - `basic-sha256:USER:HEX` -- [`BasicSha256`](AuthItem::BasicSha256). The
///   text splits at the last `:`. `USER` is not empty, holds no `:` and no
///   control character, and does not start or end with white space.
/// - `ssh:NAME` -- [`Ssh`](AuthItem::Ssh). `NAME` is not empty, holds no
///   control character, and does not start or end with white space.
/// - `net:CIDR` -- [`Net`](AuthItem::Net), with the forms of [`IpNet`].
///
/// `HEX` is a SHA-256 digest in 64 lowercase hex digits. White space is a
/// character for which [`char::is_whitespace`] is true.
///
/// Two items are equal when their parsed values are equal. So
/// `net:2001:0db8::/56` is equal to `net:2001:db8::/56`. For an item that
/// [`parse`](AuthItem::parse) returns, [`Display`](fmt::Display) writes a
/// text that parses to an equal item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthItem {
    /// A request with no credential and no match of a `net:` item.
    Anonymous,
    /// A client certificate that the client CA verified.
    TlsAny,
    /// A verified client certificate whose subject CN is this name, byte for
    /// byte.
    TlsName(String),
    /// A verified client certificate whose DER bytes have this SHA-256
    /// digest.
    TlsSha256([u8; 32]),
    /// A bearer token whose SHA-256 digest is this digest.
    ///
    /// The digest covers the whole token.
    TokenSha256([u8; 32]),
    /// An HTTP Basic credential with this user name and a password whose
    /// SHA-256 digest is `digest`.
    ///
    /// The user name compares byte for byte. The digest covers the password
    /// alone.
    BasicSha256 {
        /// The user name of the credential.
        user: String,
        /// The SHA-256 digest of the password.
        digest: [u8; 32],
    },
    /// An ssh session whose client name is this name.
    Ssh(String),
    /// A request whose client address is in this network.
    Net(IpNet),
}

/// The forms of an auth item, for the error messages.
const ITEM_FORMS: &str = "the item is anonymous, tls:*, tls:NAME, tls-sha256:HEX, \
                          token-sha256:HEX, basic-sha256:USER:HEX, ssh:NAME, or net:CIDR";

impl AuthItem {
    /// Parses one auth item.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] if `text` has none of the forms of
    /// [`AuthItem`]. White space around the item is refused too.
    pub fn parse(text: &str) -> Result<AuthItem> {
        parse_item(text)
            .map_err(|why| Error::InvalidFormat(format!("malformed auth item '{text}': {why}")))
    }

    /// Returns `true` if the item identifies a client certificate:
    /// `tls:*`, `tls:NAME`, or `tls-sha256:HEX`.
    ///
    /// A server can match such an item only with a client CA, which
    /// verifies the client certificate.
    pub fn is_tls(&self) -> bool {
        matches!(
            self,
            AuthItem::TlsAny | AuthItem::TlsName(_) | AuthItem::TlsSha256(_)
        )
    }
}

impl fmt::Display for AuthItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthItem::Anonymous => write!(f, "anonymous"),
            AuthItem::TlsAny => write!(f, "tls:*"),
            AuthItem::TlsName(name) => write!(f, "tls:{name}"),
            AuthItem::TlsSha256(digest) => write!(f, "tls-sha256:{}", Hex(digest)),
            AuthItem::TokenSha256(digest) => write!(f, "token-sha256:{}", Hex(digest)),
            AuthItem::BasicSha256 { user, digest } => {
                write!(f, "basic-sha256:{user}:{}", Hex(digest))
            }
            AuthItem::Ssh(name) => write!(f, "ssh:{name}"),
            AuthItem::Net(net) => write!(f, "net:{net}"),
        }
    }
}

/// Writes a digest in lowercase hex.
struct Hex<'a>(&'a [u8; 32]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Parses an auth item. The error is the reason.
pub(super) fn parse_item(text: &str) -> std::result::Result<AuthItem, String> {
    if text == "anonymous" {
        return Ok(AuthItem::Anonymous);
    }
    if let Some(name) = text.strip_prefix("tls:") {
        if name == "*" {
            return Ok(AuthItem::TlsAny);
        }
        return name_part(name, "tls:NAME").map(AuthItem::TlsName);
    }
    if let Some(hex) = text.strip_prefix("tls-sha256:") {
        return digest(hex).map(AuthItem::TlsSha256);
    }
    if let Some(hex) = text.strip_prefix("token-sha256:") {
        return digest(hex).map(AuthItem::TokenSha256);
    }
    if let Some(rest) = text.strip_prefix("basic-sha256:") {
        let Some((user, hex)) = rest.rsplit_once(':') else {
            return Err("the form is basic-sha256:USER:HEX".to_owned());
        };
        if user.is_empty()
            || user.contains(':')
            || user.contains(char::is_control)
            || has_edge_space(user)
        {
            return Err(
                "USER is not empty, holds no ':' and no control character, and does \
                        not start or end with white space"
                    .to_owned(),
            );
        }
        return Ok(AuthItem::BasicSha256 {
            user: user.to_owned(),
            digest: digest(hex)?,
        });
    }
    if let Some(name) = text.strip_prefix("ssh:") {
        return name_part(name, "ssh:NAME").map(AuthItem::Ssh);
    }
    if let Some(cidr) = text.strip_prefix("net:") {
        return parse_net(cidr).map(AuthItem::Net);
    }
    Err(ITEM_FORMS.to_owned())
}

/// Returns the `NAME` of a `tls:NAME` or `ssh:NAME` item.
fn name_part(name: &str, form: &str) -> std::result::Result<String, String> {
    if name.is_empty() || name.contains(char::is_control) || has_edge_space(name) {
        return Err(format!(
            "the NAME of {form} is not empty, holds no control character, and does not \
             start or end with white space"
        ));
    }
    Ok(name.to_owned())
}

/// Returns `true` if `text` starts or ends with white space.
fn has_edge_space(text: &str) -> bool {
    text.starts_with(char::is_whitespace) || text.ends_with(char::is_whitespace)
}

/// Parses a SHA-256 digest in 64 lowercase hex digits.
fn digest(hex: &str) -> std::result::Result<[u8; 32], String> {
    let refused = || "HEX is a SHA-256 digest in 64 lowercase hex digits".to_owned();
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(refused());
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let (Some(high), Some(low)) = (nibble(pair[0]), nibble(pair[1])) else {
            return Err(refused());
        };
        out[i] = high << 4 | low;
    }
    Ok(out)
}

/// An IP network: an address and a prefix length.
///
/// The text form is `ADDR/LEN` or a bare `ADDR`. A bare IPv4 address is a
/// `/32` network, and a bare IPv6 address is a `/128` network. `LEN` is
/// decimal digits with no sign and no leading zero, at most 32 for IPv4 and at
/// most 128 for IPv6. These forms are refused:
///
/// - an address with host bits set, for example `10.0.0.1/24`;
/// - an IPv6 address with a zone id, for example `fe80::1%eth0`;
/// - an IPv4-mapped IPv6 address, for example `::ffff:10.0.0.0/104`. The
///   IPv4 form, `10.0.0.0/8`, names the same network.
///
/// [`Display`](fmt::Display) writes `ADDR/LEN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNet {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    /// Parses a network, `ADDR/LEN` or a bare `ADDR`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] if `text` has none of the forms of [`IpNet`].
    pub fn parse(text: &str) -> Result<IpNet> {
        parse_net(text)
            .map_err(|why| Error::InvalidFormat(format!("malformed CIDR '{text}': {why}")))
    }

    /// Returns the address of the network. Its host bits are zero.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Returns the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Returns `true` if `addr` is in the network.
    ///
    /// An IPv4-mapped IPv6 address is read as its IPv4 address, so
    /// `::ffff:10.0.0.1` is in `10.0.0.0/8`.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                masked_v4(addr, self.prefix_len) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                masked_v6(addr, self.prefix_len) == u128::from(net)
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// Returns `addr` with the bits after the first `len` bits set to zero.
fn masked_v4(addr: Ipv4Addr, len: u8) -> u32 {
    u32::from(addr)
        .checked_shr(32 - u32::from(len))
        .and_then(|v| v.checked_shl(32 - u32::from(len)))
        .unwrap_or(0)
}

/// Returns `addr` with the bits after the first `len` bits set to zero.
fn masked_v6(addr: Ipv6Addr, len: u8) -> u128 {
    u128::from(addr)
        .checked_shr(128 - u32::from(len))
        .and_then(|v| v.checked_shl(128 - u32::from(len)))
        .unwrap_or(0)
}

/// Parses a network. The error is the reason.
pub(super) fn parse_net(text: &str) -> std::result::Result<IpNet, String> {
    let (addr_text, len_text) = match text.split_once('/') {
        Some((addr, len)) => (addr, Some(len)),
        None => (text, None),
    };
    if addr_text.contains('%') {
        return Err("a zone id is refused".to_owned());
    }
    let addr: IpAddr = addr_text
        .parse()
        .map_err(|_| "the form is ADDR/LEN or ADDR, with an IP address".to_owned())?;
    let max: u8 = if addr.is_ipv4() { 32 } else { 128 };
    let prefix_len = match len_text {
        None => max,
        Some(len) => {
            let digits = !len.is_empty() && len.bytes().all(|b| b.is_ascii_digit());
            let leading_zero = len.len() > 1 && len.starts_with('0');
            match len.parse::<u8>() {
                Ok(n) if digits && !leading_zero && n <= max => n,
                _ => {
                    return Err(format!(
                        "LEN is a decimal number from 0 to {max}, with no sign and no \
                         leading zero"
                    ));
                }
            }
        }
    };
    let host_bits = match addr {
        IpAddr::V4(v4) => masked_v4(v4, prefix_len) != u32::from(v4),
        IpAddr::V6(v6) => masked_v6(v6, prefix_len) != u128::from(v6),
    };
    if host_bits {
        return Err("the address has host bits set".to_owned());
    }
    if let IpAddr::V6(v6) = addr
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        // The check of the host bits refuses a mapped address with a prefix
        // under 96, because the `ffff` part is then in the host bits. A
        // prefix of 96 or more gives an IPv4 network with no host bits set.
        return Err(match prefix_len.checked_sub(96) {
            Some(len) => format!("an IPv4-mapped address is refused; write {v4}/{len}"),
            None => "an IPv4-mapped address is refused".to_owned(),
        });
    }
    Ok(IpNet { addr, prefix_len })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn item(text: &str) -> AuthItem {
        AuthItem::parse(text).unwrap()
    }

    fn net(text: &str) -> IpNet {
        IpNet::parse(text).unwrap()
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// Each form parses to its variant, and `Display` gives back the text.
    #[test]
    fn each_form_parses_and_displays_its_text() {
        let mut digest = [0u8; 32];
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77][i % 8]
                + if i % 16 >= 8 { 0x88 } else { 0 };
        }
        let cases = [
            ("anonymous".to_owned(), AuthItem::Anonymous),
            ("tls:*".to_owned(), AuthItem::TlsAny),
            (
                "tls:mirror.example.com".to_owned(),
                AuthItem::TlsName("mirror.example.com".into()),
            ),
            (
                "tls:*.example.com".to_owned(),
                AuthItem::TlsName("*.example.com".into()),
            ),
            ("tls:a b".to_owned(), AuthItem::TlsName("a b".into())),
            (format!("tls-sha256:{HEX}"), AuthItem::TlsSha256(digest)),
            (format!("token-sha256:{HEX}"), AuthItem::TokenSha256(digest)),
            (
                format!("basic-sha256:ci:{HEX}"),
                AuthItem::BasicSha256 {
                    user: "ci".into(),
                    digest,
                },
            ),
            (
                format!("basic-sha256:a b@x:{HEX}"),
                AuthItem::BasicSha256 {
                    user: "a b@x".into(),
                    digest,
                },
            ),
            ("ssh:user".to_owned(), AuthItem::Ssh("user".into())),
            (
                "net:10.0.1.0/24".to_owned(),
                AuthItem::Net(net("10.0.1.0/24")),
            ),
            (
                "net:2001:db8::/56".to_owned(),
                AuthItem::Net(net("2001:db8::/56")),
            ),
        ];
        for (text, want) in cases {
            let parsed = item(&text);
            assert_eq!(parsed, want, "{text}");
            assert_eq!(parsed.to_string(), text);
            assert_eq!(item(&parsed.to_string()), parsed, "{text}");
        }
    }

    /// Two items compare by their parsed values.
    #[test]
    fn items_compare_after_parsing() {
        assert_eq!(item("net:2001:0db8::/56"), item("net:2001:db8::/56"));
        assert_eq!(item("net:10.0.0.1"), item("net:10.0.0.1/32"));
        assert_eq!(item("net:10.0.0.1").to_string(), "net:10.0.0.1/32");
        assert_ne!(item("tls:a"), item("ssh:a"));
        assert_ne!(
            item(&format!("tls-sha256:{HEX}")),
            item(&format!("token-sha256:{HEX}"))
        );
    }

    /// Each other form is refused, the removed forms and white space
    /// included.
    #[test]
    fn the_other_forms_are_refused() {
        let upper = HEX.to_uppercase();
        let short = &HEX[..63];
        for text in [
            "".to_owned(),
            "Anonymous".to_owned(),
            "anonymous ".to_owned(),
            " anonymous".to_owned(),
            " tls:*".to_owned(),
            "tls:".to_owned(),
            "tls:a\tb".to_owned(),
            "tls-sha256:".to_owned(),
            format!("tls-sha256:{upper}"),
            format!("tls-sha256:{short}"),
            format!("tls-sha256:{HEX}0"),
            format!("token-sha256:{HEX} "),
            format!("token-sha256:{upper}"),
            format!("token:{HEX}"),
            "token:ci".to_owned(),
            format!("cert:{HEX}"),
            "basic-sha256:".to_owned(),
            format!("basic-sha256:{HEX}"),
            format!("basic-sha256::{HEX}"),
            format!("basic-sha256:a:b:{HEX}"),
            format!("basic-sha256:a\nb:{HEX}"),
            format!("basic-sha256:a:{upper}"),
            "basic-sha256:a:b".to_owned(),
            "ssh:".to_owned(),
            "ssh:a\u{7f}".to_owned(),
            "net:".to_owned(),
            "net: 10.0.0.0/8".to_owned(),
            "net:10.0.0.0/8 ".to_owned(),
            "net:10.0.0.1 ".to_owned(),
            format!("tls-sha256: {HEX}"),
            format!("token-sha256: {HEX}"),
            "net:10.0.0.1/24".to_owned(),
            "net:host.example.com".to_owned(),
            "remote:origin".to_owned(),
        ] {
            let Err(Error::InvalidFormat(message)) = AuthItem::parse(&text) else {
                panic!("{text:?} was accepted");
            };
            assert!(
                message.starts_with(&format!("malformed auth item '{text}': ")),
                "{message}"
            );
        }
    }

    /// White space at the start or the end of `NAME` and `USER` is refused,
    /// and white space inside them is kept.
    #[test]
    fn white_space_at_the_edges_of_a_name_is_refused() {
        for text in [
            "ssh:user ".to_owned(),
            "ssh: user".to_owned(),
            "ssh:\u{a0}user".to_owned(),
            "ssh:user\u{3000}".to_owned(),
            "ssh: ".to_owned(),
            "tls:a ".to_owned(),
            "tls: a".to_owned(),
            "tls:* ".to_owned(),
            "tls: *".to_owned(),
            format!("basic-sha256: ci:{HEX}"),
            format!("basic-sha256:ci :{HEX}"),
        ] {
            let Err(Error::InvalidFormat(message)) = AuthItem::parse(&text) else {
                panic!("{text:?} was accepted");
            };
            assert!(message.contains("white space"), "{message}");
        }
        assert_eq!(item("ssh:a b"), AuthItem::Ssh("a b".into()));
        assert_eq!(item("tls:a\u{a0}b"), AuthItem::TlsName("a\u{a0}b".into()));
    }

    /// A network takes `ADDR/LEN` and a bare `ADDR`.
    #[test]
    fn a_network_takes_a_length_or_a_bare_address() {
        for (text, addr, len) in [
            ("10.0.0.0/8", "10.0.0.0", 8),
            ("10.0.0.1", "10.0.0.1", 32),
            ("10.0.0.1/32", "10.0.0.1", 32),
            ("0.0.0.0/0", "0.0.0.0", 0),
            ("2001:db8::/32", "2001:db8::", 32),
            ("2001:db8::1", "2001:db8::1", 128),
            ("::/0", "::", 0),
            ("::1/128", "::1", 128),
        ] {
            let parsed = net(text);
            assert_eq!(parsed.addr(), ip(addr), "{text}");
            assert_eq!(parsed.prefix_len(), len, "{text}");
            assert_eq!(net(&parsed.to_string()), parsed, "{text}");
        }
    }

    /// The other forms of a network are refused.
    #[test]
    fn the_other_networks_are_refused() {
        for text in [
            "",
            "/8",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/-8",
            "10.0.0.0/08",
            "10.0.0.0/00",
            "10.0.0.0/33",
            "10.0.0.0/8/8",
            "10.0.0.0/ 8",
            "10.0.0.0 /8",
            "10.0.0.1/24",
            "10.0.0.0/256",
            "2001:db8::/129",
            "2001:db8::1/64",
            "fe80::1%eth0",
            "fe80::%1/64",
            "::ffff:10.0.0.0/104",
            "::ffff:10.0.0.1",
            "::ffff:0:0/96",
            "[::1]/128",
            "010.0.0.0/8",
            "example.com/8",
        ] {
            let Err(Error::InvalidFormat(message)) = IpNet::parse(text) else {
                panic!("{text:?} was accepted");
            };
            assert!(
                message.starts_with(&format!("malformed CIDR '{text}': ")),
                "{message}"
            );
        }
    }

    /// The refusal of an IPv4-mapped network names the IPv4 form.
    #[test]
    fn the_refusal_of_a_mapped_network_names_the_ipv4_form() {
        for (text, form) in [
            ("::ffff:10.0.0.0/104", "10.0.0.0/8"),
            ("::ffff:0:0/96", "0.0.0.0/0"),
            ("::ffff:10.0.0.1", "10.0.0.1/32"),
        ] {
            let Err(Error::InvalidFormat(message)) = IpNet::parse(text) else {
                panic!("{text:?} was accepted");
            };
            assert!(message.ends_with(&format!("write {form}")), "{message}");
            net(form);
        }
    }

    /// A mapped network with host bits set gets the refusal of the host bits,
    /// and no IPv4 form.
    #[test]
    fn a_mapped_network_with_host_bits_names_no_ipv4_form() {
        for text in ["::ffff:10.0.0.1/104", "::ffff:0:0/80", "::ffff:0:0/95"] {
            let Err(Error::InvalidFormat(message)) = IpNet::parse(text) else {
                panic!("{text:?} was accepted");
            };
            assert!(message.ends_with("host bits set"), "{message}");
        }
    }

    /// `contains` compares the network bits, and reads an IPv4-mapped client
    /// address as its IPv4 address.
    #[test]
    fn contains_compares_the_network_bits() {
        let v4 = net("10.0.1.0/24");
        assert!(v4.contains(ip("10.0.1.0")));
        assert!(v4.contains(ip("10.0.1.255")));
        assert!(!v4.contains(ip("10.0.2.1")));
        assert!(v4.contains(ip("::ffff:10.0.1.7")));
        assert!(!v4.contains(ip("::ffff:10.0.2.7")));
        assert!(!v4.contains(ip("2001:db8::1")));
        let v6 = net("2001:db8::/56");
        assert!(v6.contains(ip("2001:db8:0:ff::1")));
        assert!(!v6.contains(ip("2001:db8:0:100::1")));
        assert!(!v6.contains(ip("10.0.1.1")));
        assert!(net("0.0.0.0/0").contains(ip("192.0.2.1")));
        assert!(net("0.0.0.0/0").contains(ip("::ffff:192.0.2.1")));
        assert!(!net("0.0.0.0/0").contains(ip("::1")));
        assert!(net("::/0").contains(ip("::1")));
        assert!(!net("::/0").contains(ip("::ffff:192.0.2.1")));
        assert!(net("10.0.0.1").contains(ip("10.0.0.1")));
        assert!(!net("10.0.0.1").contains(ip("10.0.0.2")));
        assert!(net("::1").contains(ip("::1")));
    }
}
