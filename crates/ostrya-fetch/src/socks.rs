//! The client side of a SOCKS5 handshake.
//!
//! [`handshake`] opens a tunnel through a SOCKS5 proxy on a stream that is
//! connected to the proxy. It follows RFC 1928 for the protocol and RFC 1929
//! for the user name and the password. After the handshake, the stream
//! carries the bytes of the target.
//!
//! The client offers method `00` (no authentication). With a [`Credential`],
//! it also offers method `02` (user name and password). If the proxy selects
//! `02`, the client sends the user name and the password. Then the client
//! sends one `CONNECT` request. The target is an IPv4 address, an IPv6
//! address, or a host name of 1 to 255 bytes. A host name with a `%` has a
//! zone id, and a SOCKS5 request has no field for it. The client checks the
//! name before it writes a byte.
//!
//! Each failure has a [`Class`]:
//!
//! - Definitive: the proxy accepts no method that the client offers, the
//!   proxy refuses the user name and password, the host name has a length
//!   that SOCKS5 cannot send, or the host name has a `%`. A retry gets the
//!   same result.
//! - Retryable: each other failure. This includes each reply code other than
//!   `00`, each reply that breaks the protocol, and each I/O failure.
//!
//! The client reads the `RSV` byte of the reply and ignores its value. It
//! reads each reply with exact reads, so it consumes no byte after the reply.
//! The bytes that follow belong to the target.
//!
//! A [`SocksError`] holds no part of the credential. The `Debug` output of a
//! [`Credential`] shows no field.

use std::fmt;
use std::io;
use std::net::IpAddr;

use futures_io::{AsyncRead, AsyncWrite};
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

/// The version byte of each SOCKS5 message.
const VERSION: u8 = 0x05;
/// The method that needs no authentication.
const NO_AUTH: u8 = 0x00;
/// The user name and password method of RFC 1929.
const USER_PASS: u8 = 0x02;
/// The method reply that accepts no offered method.
const NO_ACCEPTABLE: u8 = 0xff;
/// The version byte of the RFC 1929 exchange.
const AUTH_VERSION: u8 = 0x01;
/// The `CONNECT` command.
const CONNECT: u8 = 0x01;
/// The address type of an IPv4 address.
const ATYP_V4: u8 = 0x01;
/// The address type of a host name.
const ATYP_NAME: u8 = 0x03;
/// The address type of an IPv6 address.
const ATYP_V6: u8 = 0x04;

/// The host part of a target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Host {
    /// An IP address, which the client sends as `ATYP` `01` or `04`.
    Ip(IpAddr),
    /// A host name, which the proxy resolves. The client sends it as `ATYP`
    /// `03`.
    Name(String),
}

/// The host and the port that the proxy connects to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Target {
    pub(crate) host: Host,
    pub(crate) port: u16,
}

impl Target {
    /// Creates a target. An IP literal without brackets gives an IP address,
    /// and each other value gives a host name. The caller gives the host
    /// without brackets, as the origin holds it.
    pub(crate) fn new(host: &str, port: u16) -> Self {
        let host = match host.parse() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Name(host.to_owned()),
        };
        Target { host, port }
    }

    /// Checks that a SOCKS5 request can carry the host name.
    ///
    /// A name with a `%` or a name that is not 1 to 255 bytes is refused, and
    /// the refusal is definitive. An IP address always passes.
    pub(crate) fn check(&self) -> Result<(), SocksError> {
        let Host::Name(name) = &self.host else {
            return Ok(());
        };
        if name.contains('%') {
            return Err(definitive(
                "the host name has a zone id or a `%`, which a SOCKS5 request cannot carry",
            ));
        }
        if name.is_empty() || name.len() > 255 {
            return Err(definitive(format!(
                "the host name is {} bytes, and SOCKS5 sends a name of 1 to 255 bytes",
                name.len()
            )));
        }
        Ok(())
    }
}

/// The user name and the password of RFC 1929, each 1 to 255 bytes.
pub(crate) struct Credential {
    /// The RFC 1929 message: `01`, the user name length, the user name, the
    /// password length, and the password.
    message: Vec<u8>,
}

impl Credential {
    /// Reads the userinfo of a proxy URL.
    ///
    /// The first `:` ends the user name. The function percent-decodes each
    /// field, and each field must be UTF-8 after the decode. A decoded `:` or
    /// `@` is part of the field.
    pub(crate) fn from_userinfo(userinfo: &str) -> Result<Self, CredentialError> {
        let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        let field = |text: &str| {
            super::percent_decode(text)
                .filter(|bytes| std::str::from_utf8(bytes).is_ok())
                .ok_or(CredentialError::Undecodable)
        };
        let user = field(user)?;
        let password = field(password)?;
        if user.is_empty() {
            return Err(CredentialError::EmptyUser);
        }
        if password.is_empty() {
            return Err(CredentialError::EmptyPassword);
        }
        let user_len = u8::try_from(user.len()).map_err(|_| CredentialError::UserTooLong)?;
        let password_len =
            u8::try_from(password.len()).map_err(|_| CredentialError::PasswordTooLong)?;
        let mut message = Vec::with_capacity(3 + user.len() + password.len());
        message.push(AUTH_VERSION);
        message.push(user_len);
        message.extend_from_slice(&user);
        message.push(password_len);
        message.extend_from_slice(&password);
        Ok(Credential { message })
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential").finish_non_exhaustive()
    }
}

/// The reason that [`Credential::from_userinfo`] refuses a userinfo.
///
/// The text names the problem and quotes no field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialError {
    /// A field has an escape other than `%` and two hexadecimal digits, or
    /// its bytes are not UTF-8 after the decode.
    Undecodable,
    /// The user name is empty.
    EmptyUser,
    /// The password is empty, or the userinfo has no `:`.
    EmptyPassword,
    /// The user name is longer than 255 bytes after the decode.
    UserTooLong,
    /// The password is longer than 255 bytes after the decode.
    PasswordTooLong,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CredentialError::Undecodable => {
                "the userinfo is not a percent-encoded user name and password the proxy can be \
                 sent"
            }
            CredentialError::EmptyUser => {
                "the user name is empty, and RFC 1929 needs 1 to 255 bytes"
            }
            CredentialError::EmptyPassword => {
                "the password is empty, and RFC 1929 needs 1 to 255 bytes"
            }
            CredentialError::UserTooLong => {
                "the user name is longer than 255 bytes after the percent-decode"
            }
            CredentialError::PasswordTooLong => {
                "the password is longer than 255 bytes after the percent-decode"
            }
        })
    }
}

/// The retry class of a failed handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Class {
    /// A retry gets the same result.
    Definitive,
    /// A later attempt can succeed.
    Retryable,
}

/// A failed handshake. The caller adds the proxy and the target to the
/// message.
#[derive(Debug)]
pub(crate) struct SocksError {
    pub(crate) class: Class,
    pub(crate) reason: String,
}

fn definitive(reason: impl Into<String>) -> SocksError {
    SocksError {
        class: Class::Definitive,
        reason: reason.into(),
    }
}

fn retryable(reason: impl Into<String>) -> SocksError {
    SocksError {
        class: Class::Retryable,
        reason: reason.into(),
    }
}

/// Runs the SOCKS5 handshake for `target` on `stream`.
///
/// `credential` adds the user name and password method to the offer. On
/// success, the next byte of `stream` is the first byte of the target.
pub(crate) async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &Target,
    credential: Option<&Credential>,
) -> Result<(), SocksError> {
    // The request is built first, so a name that SOCKS5 cannot send stops the
    // handshake before the greeting.
    let request = connect_request(target)?;
    let greeting: &[u8] = match credential {
        Some(_) => &[VERSION, 2, NO_AUTH, USER_PASS],
        None => &[VERSION, 1, NO_AUTH],
    };
    send(stream, greeting, "the greeting").await?;
    let [version, method] = receive::<_, 2>(stream, "the method reply").await?;
    if version != VERSION {
        return Err(retryable(format!(
            "the method reply has the version {version:02x}, and SOCKS5 is 05"
        )));
    }
    match (method, credential) {
        (NO_AUTH, _) => {}
        (USER_PASS, Some(credential)) => authenticate(stream, credential).await?,
        (NO_ACCEPTABLE, _) => {
            return Err(definitive(
                "the proxy accepts none of the methods that the client offers",
            ));
        }
        (method, _) => {
            return Err(retryable(format!(
                "the proxy selected the method {method:02x}, which the client did not offer"
            )));
        }
    }
    send(stream, &request, "the connect request").await?;
    // REP is checked before the rest of the reply is read, so a proxy that
    // ends the connection after a refusal still gives its code.
    let [version, code] = receive::<_, 2>(stream, "the connect reply").await?;
    if version != VERSION {
        return Err(retryable(format!(
            "the connect reply has the version {version:02x}, and SOCKS5 is 05"
        )));
    }
    if code != 0 {
        return Err(retryable(format!(
            "the proxy refused the connect with the code {code:02x} ({})",
            reply_meaning(code)
        )));
    }
    let [_reserved, address_type] = receive::<_, 2>(stream, "the connect reply").await?;
    let bound = match address_type {
        ATYP_V4 => 4 + 2,
        ATYP_V6 => 16 + 2,
        ATYP_NAME => {
            let [len] = receive::<_, 1>(stream, "the bound address").await?;
            usize::from(len) + 2
        }
        other => {
            return Err(retryable(format!(
                "the connect reply has the address type {other:02x}, which RFC 1928 does not \
                 define"
            )));
        }
    };
    // BND.ADDR and BND.PORT go into a scratch buffer and are dropped.
    let mut scratch = [0u8; 255 + 2];
    read_exact(stream, &mut scratch[..bound], "the bound address").await
}

/// Builds the `CONNECT` request for `target`.
fn connect_request(target: &Target) -> Result<Vec<u8>, SocksError> {
    target.check()?;
    let address_len = match &target.host {
        Host::Ip(IpAddr::V4(_)) => 1 + 4,
        Host::Ip(IpAddr::V6(_)) => 1 + 16,
        Host::Name(name) => 1 + 1 + name.len(),
    };
    let mut request = Vec::with_capacity(3 + address_len + 2);
    request.extend_from_slice(&[VERSION, CONNECT, 0]);
    match &target.host {
        Host::Ip(IpAddr::V4(ip)) => {
            request.push(ATYP_V4);
            request.extend_from_slice(&ip.octets());
        }
        Host::Ip(IpAddr::V6(ip)) => {
            request.push(ATYP_V6);
            request.extend_from_slice(&ip.octets());
        }
        Host::Name(name) => {
            request.push(ATYP_NAME);
            // `check` keeps the length in 1 to 255 bytes.
            request.push(name.len() as u8);
            request.extend_from_slice(name.as_bytes());
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    Ok(request)
}

/// Runs the RFC 1929 exchange.
async fn authenticate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    credential: &Credential,
) -> Result<(), SocksError> {
    send(stream, &credential.message, "the user name and password").await?;
    let [version, status] = receive::<_, 2>(stream, "the authentication reply").await?;
    if version != AUTH_VERSION {
        return Err(retryable(format!(
            "the authentication reply has the version {version:02x}, and RFC 1929 sets 01"
        )));
    }
    if status != 0 {
        return Err(definitive(format!(
            "the proxy refused the user name and password with the status {status:02x}"
        )));
    }
    Ok(())
}

/// Returns the RFC 1928 meaning of a reply code other than `00`.
fn reply_meaning(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "not defined by RFC 1928",
    }
}

/// Writes one message and flushes the stream.
async fn send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &[u8],
    what: &str,
) -> Result<(), SocksError> {
    let written = async {
        stream.write_all(message).await?;
        stream.flush().await
    };
    written
        .await
        .map_err(|e| retryable(format!("cannot send {what}: {e}")))
}

/// Reads exactly `N` bytes.
async fn receive<S: AsyncRead + Unpin, const N: usize>(
    stream: &mut S,
    what: &str,
) -> Result<[u8; N], SocksError> {
    let mut buf = [0u8; N];
    read_exact(stream, &mut buf, what).await?;
    Ok(buf)
}

/// Fills `buf` from the stream.
async fn read_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
    what: &str,
) -> Result<(), SocksError> {
    stream.read_exact(buf).await.map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            retryable(format!("the proxy closed the connection before {what}"))
        } else {
            retryable(format!("cannot read {what}: {e}"))
        }
    })
}

// The handshake future moves across tasks and threads with a stream that can.
const _: fn() = || {
    fn assert_send<T: Send>(_: &T) {}
    fn handshake_is_send<S: AsyncRead + AsyncWrite + Unpin + Send>(
        stream: &mut S,
        target: &Target,
        credential: Option<&Credential>,
    ) {
        assert_send(&handshake(stream, target, credential));
    }
    let _ = handshake_is_send::<ostrya_rt::TcpStream>;
};

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_rt::block_on;
    use std::io::Read as _;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A scripted proxy. It records each byte that the client writes.
    struct Peer {
        replies: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
        /// Each write fails with `BrokenPipe` if this is `true`.
        broken: bool,
        /// If this is `true`, each read gives as many bytes as the buffer
        /// holds, so a read past the end of a reply consumes the bytes after
        /// it. If this is `false`, each read gives one byte, so each exact
        /// read loops.
        greedy: bool,
    }

    impl Peer {
        fn new(replies: &[u8]) -> Self {
            Peer {
                replies: std::io::Cursor::new(replies.to_vec()),
                written: Vec::new(),
                broken: false,
                greedy: false,
            }
        }

        /// Returns the replies that the client did not read.
        fn unread(&self) -> &[u8] {
            let at = usize::try_from(self.replies.position()).unwrap();
            &self.replies.get_ref()[at..]
        }
    }

    impl AsyncRead for Peer {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let len = if self.greedy {
                buf.len()
            } else {
                buf.len().min(1)
            };
            Poll::Ready(self.replies.read(&mut buf[..len]))
        }
    }

    impl AsyncWrite for Peer {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.broken {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// A successful connect reply with an IPv4 `BND.ADDR`.
    const CONNECTED: [u8; 10] = [5, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90];

    /// The request for `example.org:443`.
    const EXAMPLE_REQUEST: [u8; 18] = [
        5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g', 0x01,
        0xbb,
    ];

    fn example() -> Target {
        Target::new("example.org", 443)
    }

    fn credential() -> Credential {
        Credential::from_userinfo("alice:secret").unwrap()
    }

    /// The two read modes of [`Peer`]: one byte for each read, and greedy.
    const READ_MODES: [bool; 2] = [false, true];

    /// Runs the handshake against a peer with `replies` that gives one byte
    /// for each read.
    fn run(
        target: &Target,
        credential: Option<&Credential>,
        replies: &[u8],
    ) -> (Result<(), SocksError>, Peer) {
        run_with(false, target, credential, replies)
    }

    /// Runs the handshake against a peer with `replies`. `greedy` sets the
    /// read mode of the peer.
    fn run_with(
        greedy: bool,
        target: &Target,
        credential: Option<&Credential>,
        replies: &[u8],
    ) -> (Result<(), SocksError>, Peer) {
        let mut peer = Peer::new(replies);
        peer.greedy = greedy;
        let result = block_on(handshake(&mut peer, target, credential));
        (result, peer)
    }

    fn concat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn the_greeting_without_a_credential_offers_no_authentication_alone() {
        let replies = concat(&[&[5, 0], &CONNECTED]);
        let (result, peer) = run(&example(), None, &replies);
        result.unwrap();
        assert_eq!(peer.written, concat(&[&[5, 1, 0], &EXAMPLE_REQUEST]));
    }

    #[test]
    fn the_greeting_with_a_credential_offers_both_methods() {
        let replies = concat(&[&[5, 0], &CONNECTED]);
        let (result, peer) = run(&example(), Some(&credential()), &replies);
        result.unwrap();
        assert_eq!(&peer.written[..4], &[5, 2, 0, 2]);
    }

    #[test]
    fn the_rfc_1929_message_carries_the_user_name_and_password() {
        let replies = concat(&[&[5, 2], &[1, 0], &CONNECTED]);
        let expected = concat(&[
            &[5, 2, 0, 2],
            &[1, 5],
            b"alice",
            &[6],
            b"secret",
            &EXAMPLE_REQUEST,
        ]);
        for greedy in READ_MODES {
            let (result, peer) = run_with(greedy, &example(), Some(&credential()), &replies);
            result.unwrap();
            assert_eq!(peer.written, expected);
            assert!(peer.unread().is_empty());
        }
    }

    #[test]
    fn the_request_carries_an_ipv4_address() {
        let target = Target::new("192.0.2.7", 0x1234);
        assert_eq!(
            target.host,
            Host::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))
        );
        let replies = concat(&[&[5, 0], &CONNECTED]);
        let (result, peer) = run(&target, None, &replies);
        result.unwrap();
        assert_eq!(&peer.written[3..], &[5, 1, 0, 1, 192, 0, 2, 7, 0x12, 0x34]);
    }

    #[test]
    fn the_request_carries_an_ipv6_address() {
        let target = Target::new("2001:db8::1", 8080);
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(target.host, Host::Ip(IpAddr::V6(ip)));
        let replies = concat(&[&[5, 0], &CONNECTED]);
        let (result, peer) = run(&target, None, &replies);
        result.unwrap();
        let expected = concat(&[&[5, 1, 0, 4], &ip.octets(), &8080u16.to_be_bytes()]);
        assert_eq!(&peer.written[3..], expected);
    }

    #[test]
    fn a_bracketed_ipv6_literal_is_a_name() {
        let target = Target::new("[2001:db8::1]", 80);
        assert_eq!(target.host, Host::Name("[2001:db8::1]".to_owned()));
    }

    #[test]
    fn the_request_carries_a_255_byte_name() {
        let name = "a".repeat(255);
        let target = Target::new(&name, 80);
        let replies = concat(&[&[5, 0], &CONNECTED]);
        let (result, peer) = run(&target, None, &replies);
        result.unwrap();
        let expected = concat(&[&[5, 1, 0, 3, 255], name.as_bytes(), &[0, 80]]);
        assert_eq!(&peer.written[3..], expected);
    }

    #[test]
    fn a_name_of_256_bytes_or_no_bytes_is_definitive_and_sends_nothing() {
        for name in ["a".repeat(256), String::new()] {
            let (result, peer) = run(&Target::new(&name, 80), None, &[5, 0]);
            let error = result.unwrap_err();
            assert_eq!(error.class, Class::Definitive, "{}", error.reason);
            assert!(error.reason.contains("1 to 255 bytes"), "{}", error.reason);
            assert!(peer.written.is_empty());
        }
    }

    #[test]
    fn a_name_with_a_zone_id_is_definitive_and_sends_nothing() {
        for host in ["fe80::1%eth0", "fe80::1%25eth0"] {
            let target = Target::new(host, 80);
            assert_eq!(target.host, Host::Name(host.to_owned()));
            let (result, peer) = run(&target, None, &concat(&[&[5, 0], &CONNECTED]));
            let error = result.unwrap_err();
            assert_eq!(error.class, Class::Definitive, "{}", error.reason);
            assert!(error.reason.contains("zone id"), "{}", error.reason);
            assert!(peer.written.is_empty());
        }
    }

    #[test]
    fn no_authentication_selected_sends_no_credential() {
        let replies = concat(&[&[5, 0], &CONNECTED]);
        let (result, peer) = run(&example(), Some(&credential()), &replies);
        result.unwrap();
        assert_eq!(peer.written, concat(&[&[5, 2, 0, 2], &EXAMPLE_REQUEST]));
    }

    #[test]
    fn no_acceptable_method_is_definitive() {
        for credential in [None, Some(credential())] {
            let (result, peer) = run(&example(), credential.as_ref(), &[5, 0xff]);
            let error = result.unwrap_err();
            assert_eq!(error.class, Class::Definitive, "{}", error.reason);
            // The client sent the greeting alone.
            let greeting: &[u8] = if credential.is_some() {
                &[5, 2, 0, 2]
            } else {
                &[5, 1, 0]
            };
            assert_eq!(peer.written, greeting);
        }
    }

    #[test]
    fn a_failed_authentication_status_is_definitive_and_sends_no_request() {
        let replies = concat(&[&[5, 2], &[1, 1], &CONNECTED]);
        for greedy in READ_MODES {
            let (result, peer) = run_with(greedy, &example(), Some(&credential()), &replies);
            let error = result.unwrap_err();
            assert_eq!(error.class, Class::Definitive, "{}", error.reason);
            assert!(error.reason.contains("status 01"), "{}", error.reason);
            assert!(!error.reason.contains("alice") && !error.reason.contains("secret"));
            assert_eq!(peer.written.len(), 4 + 2 + 5 + 1 + 6);
            assert_eq!(peer.unread(), CONNECTED);
        }
    }

    #[test]
    fn each_refusal_code_is_retryable_and_named() {
        let meanings = [
            (0x01, "general failure"),
            (0x02, "not allowed by ruleset"),
            (0x03, "network unreachable"),
            (0x04, "host unreachable"),
            (0x05, "connection refused"),
            (0x06, "TTL expired"),
            (0x07, "command not supported"),
            (0x08, "address type not supported"),
            (0x09, "not defined by RFC 1928"),
            (0xff, "not defined by RFC 1928"),
        ];
        for (code, meaning) in meanings {
            let replies = concat(&[&[5, 0], &[5, code, 0, 1, 0, 0, 0, 0, 0, 0]]);
            let (result, _) = run(&example(), None, &replies);
            let error = result.unwrap_err();
            assert_eq!(error.class, Class::Retryable, "{}", error.reason);
            assert!(
                error
                    .reason
                    .contains(&format!("code {code:02x} ({meaning})")),
                "{}",
                error.reason
            );
        }
    }

    #[test]
    fn a_refusal_that_ends_after_its_code_is_named() {
        for greedy in READ_MODES {
            let replies = concat(&[&[5, 0], &[5, 5]]);
            let (result, peer) = run_with(greedy, &example(), None, &replies);
            let error = result.unwrap_err();
            assert_eq!(error.class, Class::Retryable, "{}", error.reason);
            assert!(
                error.reason.contains("code 05 (connection refused)"),
                "{}",
                error.reason
            );
            assert!(peer.unread().is_empty());
        }
    }

    #[test]
    fn the_name_check_runs_without_a_stream() {
        for host in ["a".repeat(256), String::new(), "fe80::1%eth0".to_owned()] {
            let error = Target::new(&host, 80).check().unwrap_err();
            assert_eq!(error.class, Class::Definitive, "{}", error.reason);
        }
        for host in ["a".repeat(255), "127.0.0.1".to_owned(), "::1".to_owned()] {
            Target::new(&host, 80).check().unwrap();
        }
    }

    #[test]
    fn a_protocol_break_is_retryable() {
        let cases: [(&[u8], bool, &str); 6] = [
            (&[4, 0], false, "the method reply has the version 04"),
            (
                &[5, 2, 2, 0],
                true,
                "the authentication reply has the version 02",
            ),
            (
                &[5, 0, 4, 0, 0, 1],
                false,
                "the connect reply has the version 04",
            ),
            (&[5, 1], true, "the method 01"),
            (&[5, 2], false, "the method 02"),
            (&[5, 0, 5, 0, 0, 2], false, "the address type 02"),
        ];
        let credential = credential();
        for (replies, with_credential, reason) in cases {
            let credential = with_credential.then_some(&credential);
            let (result, _) = run(&example(), credential, replies);
            let error = result.unwrap_err();
            assert_eq!(error.class, Class::Retryable, "{}", error.reason);
            assert!(error.reason.contains(reason), "{}", error.reason);
        }
    }

    #[test]
    fn an_early_end_of_stream_is_retryable() {
        let replies = concat(&[&[5, 2], &[1, 0], &[5, 0, 0, 3, 3], b"abc", &[0, 80]]);
        // The step that each prefix of the replies ends in.
        let step = |len: usize| match len {
            0..=1 => "the method reply",
            2..=3 => "the authentication reply",
            4..=7 => "the connect reply",
            _ => "the bound address",
        };
        let credential = credential();
        for len in 0..replies.len() {
            let (result, _) = run(&example(), Some(&credential), &replies[..len]);
            let error = result.unwrap_err();
            assert_eq!(error.class, Class::Retryable, "{}", error.reason);
            assert_eq!(
                error.reason,
                format!("the proxy closed the connection before {}", step(len)),
                "prefix of {len} bytes"
            );
        }
        for greedy in READ_MODES {
            let (result, peer) = run_with(greedy, &example(), Some(&credential), &replies);
            result.unwrap();
            assert!(peer.unread().is_empty());
        }
    }

    #[test]
    fn a_failed_write_is_retryable() {
        let mut peer = Peer::new(&[5, 0]);
        peer.broken = true;
        let error = block_on(handshake(&mut peer, &example(), None)).unwrap_err();
        assert_eq!(error.class, Class::Retryable, "{}", error.reason);
        assert!(
            error.reason.starts_with("cannot send the greeting"),
            "{}",
            error.reason
        );
    }

    #[test]
    fn the_bytes_after_the_reply_stay_unread() {
        let trailer: &[u8] = b"HTTP/1.1";
        let bound: [&[u8]; 4] = [
            &[1, 10, 0, 0, 1, 0, 80],
            &[3, 3, b'a', b'b', b'c', 0, 80],
            &[3, 0, 0, 80],
            &[4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80],
        ];
        for greedy in READ_MODES {
            for address in bound {
                let replies = concat(&[&[5, 0], &[5, 0, 0], address, trailer]);
                let (result, peer) = run_with(greedy, &example(), None, &replies);
                result.unwrap();
                assert_eq!(peer.unread(), trailer, "greedy: {greedy}");
            }
        }
    }

    #[test]
    fn a_nonzero_reserved_byte_is_ignored() {
        let replies = concat(&[&[5, 0], &[5, 0, 0x7f, 1, 0, 0, 0, 0, 0, 0]]);
        for greedy in READ_MODES {
            let (result, peer) = run_with(greedy, &example(), None, &replies);
            result.unwrap();
            assert!(peer.unread().is_empty());
        }
    }

    #[test]
    fn a_userinfo_with_a_bad_escape_or_no_text_is_refused() {
        for userinfo in [
            "u%zz:pw",
            "u%4:pw",
            "u%:pw",
            "u%ff:pw",
            "user:p%zz",
            "user:p%4",
            "user:pw%",
            "user:%ff",
        ] {
            let error = Credential::from_userinfo(userinfo).unwrap_err();
            assert_eq!(error, CredentialError::Undecodable, "{userinfo}");
        }
    }

    #[test]
    fn a_userinfo_with_an_empty_field_is_refused() {
        let cases = [
            ("user", CredentialError::EmptyPassword),
            ("user:", CredentialError::EmptyPassword),
            (":pw", CredentialError::EmptyUser),
            ("", CredentialError::EmptyUser),
            (":", CredentialError::EmptyUser),
        ];
        for (userinfo, expected) in cases {
            assert_eq!(Credential::from_userinfo(userinfo).unwrap_err(), expected);
        }
    }

    #[test]
    fn each_field_is_1_to_255_bytes_after_the_decode() {
        let long = "a".repeat(255);
        let credential = Credential::from_userinfo(&format!("{long}:{long}")).unwrap();
        let expected = concat(&[&[1, 255], long.as_bytes(), &[255], long.as_bytes()]);
        assert_eq!(credential.message, expected);
        let raw = "a".repeat(256);
        assert_eq!(
            Credential::from_userinfo(&format!("{raw}:pw")).unwrap_err(),
            CredentialError::UserTooLong
        );
        assert_eq!(
            Credential::from_userinfo(&format!("user:{raw}")).unwrap_err(),
            CredentialError::PasswordTooLong
        );
        // 255 escapes decode to 255 bytes, and one more byte makes 256.
        let escaped = format!("{}a", "%61".repeat(255));
        assert_eq!(
            Credential::from_userinfo(&format!("{escaped}:pw")).unwrap_err(),
            CredentialError::UserTooLong
        );
        assert_eq!(
            Credential::from_userinfo(&format!("user:{escaped}")).unwrap_err(),
            CredentialError::PasswordTooLong
        );
        let fits = "%61".repeat(255);
        assert!(Credential::from_userinfo(&format!("{fits}:{fits}")).is_ok());
    }

    #[test]
    fn a_decoded_colon_or_at_sign_is_part_of_the_field() {
        let credential = Credential::from_userinfo("a%3Ab:c%40d:e").unwrap();
        assert_eq!(
            credential.message,
            concat(&[&[1, 3], b"a:b", &[5], b"c@d:e"])
        );
    }

    #[test]
    fn a_refusal_quotes_no_field() {
        for userinfo in ["user:secret%zz", "%zz:secret", ":secret", "secret:"] {
            let error = Credential::from_userinfo(userinfo).unwrap_err();
            assert!(!error.to_string().contains("secret"), "{error}");
        }
        let long = "s".repeat(256);
        let error = Credential::from_userinfo(&format!("user:{long}")).unwrap_err();
        assert!(!error.to_string().contains(&long[..8]), "{error}");
    }

    #[test]
    fn the_debug_output_of_a_credential_shows_no_field() {
        assert_eq!(format!("{:?}", credential()), "Credential { .. }");
    }
}
