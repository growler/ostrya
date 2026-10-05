//! The authorization of the requests of the receive endpoint.
//!
//! The credential file holds one credential on each line, `NAME:HEX`, where
//! `HEX` is the SHA-256 digest of the secret in 64 lowercase hex digits. A
//! bearer token matches a line by the digest of the token. A Basic
//! credential matches a line by its name and the digest of its password.
//! Each request compares its digest with every line in constant time and
//! does not stop at a match.

use std::collections::HashMap;
use std::future::{Future, ready};
use std::hint::black_box;
use std::sync::Arc;

use hyper::header::{AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE};
use hyper::http::request::Parts;
use hyper::{HeaderMap, StatusCode};
use ostrya::push::proto::Hello;
use ostrya::{Checksum, ReceivePolicy};

use crate::error::Error;
use crate::options::ServeOptions;
use crate::receive_auth::{ReceiveAuth, Refusal, RequestKind, SessionSetup};

/// The `WWW-Authenticate` headers of a 401: the two schemes of a credential.
const CHALLENGES: [&str; 2] = [r#"Bearer realm="ostrya""#, r#"Basic realm="ostrya""#];

/// What the connection of a request states about its client. The server puts
/// it into the extensions of each request.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Peer {
    /// Whether the connection runs over TLS.
    pub(crate) tls: bool,
    /// The SHA-256 digest of the DER bytes of the end-entity certificate that
    /// the client presented in the TLS handshake. The handshake verified the
    /// certificate against the client CA.
    pub(crate) cert: Option<Checksum>,
}

/// One line of the credential file.
#[derive(Debug)]
pub(crate) struct Credential {
    name: String,
    digest: [u8; 32],
}

/// The credential lines of the credential file `bytes`. A line that starts
/// with `#` and an empty line hold no credential. Each other line is
/// `NAME:HEX`: `NAME` is one or more visible ASCII characters other than
/// `:`, and `HEX` is 64 lowercase hex digits. A malformed line, a name on
/// two lines, and a digest on two lines are [`Error::Credentials`], which
/// names the line by its number and holds no byte of it.
pub(crate) fn parse_credentials(bytes: &[u8]) -> Result<Vec<Credential>, Error> {
    let mut lines = Vec::new();
    let mut names = HashMap::new();
    let mut digests = HashMap::new();
    for (index, line) in bytes.split(|&b| b == b'\n').enumerate() {
        let number = index + 1;
        let malformed = |message: String| Error::Credentials {
            line: number,
            message,
        };
        if line.contains(&b'\r') {
            return Err(malformed("the line holds a CR".into()));
        }
        let Ok(line) = std::str::from_utf8(line) else {
            return Err(malformed("the line is not UTF-8".into()));
        };
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains(' ') {
            return Err(malformed("the line holds a space".into()));
        }
        let Some((name, hex)) = line.split_once(':') else {
            return Err(malformed("the line is not NAME:HEX".into()));
        };
        if name.is_empty() {
            return Err(malformed("the name is empty".into()));
        }
        if !name.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(malformed(
                "the name holds a character other than visible ASCII".into(),
            ));
        }
        let Ok(digest) = Checksum::from_hex_lower(hex) else {
            return Err(malformed(
                "the digest is not 64 lowercase hex digits".into(),
            ));
        };
        if let Some(first) = names.insert(name.to_owned(), number) {
            return Err(malformed(format!("the name of line {first} is repeated")));
        }
        if let Some(first) = digests.insert(digest, number) {
            return Err(malformed(format!("the digest of line {first} is repeated")));
        }
        lines.push(Credential {
            name: name.to_owned(),
            digest: *digest.as_bytes(),
        });
    }
    Ok(lines)
}

#[cfg(test)]
thread_local! {
    /// The number of digest compares on this thread.
    static COMPARES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Whether two digests are equal, in a time that does not depend on their
/// bytes: each digest is read as four 64-bit words, the XOR of each word
/// pair is ORed into one word, and no step branches on a byte.
fn digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    #[cfg(test)]
    COMPARES.with(|n| n.set(n.get() + 1));
    let (a, _) = a.as_chunks::<8>();
    let (b, _) = b.as_chunks::<8>();
    let mut diff = 0u64;
    for (x, y) in a.iter().zip(b) {
        diff |= black_box(u64::from_ne_bytes(*x) ^ u64::from_ne_bytes(*y));
    }
    black_box(diff) == 0
}

/// The index of the first line of `lines` with the digest `digest`. The
/// digest of every line is compared, also after a match.
fn match_line(lines: &[Credential], digest: &[u8; 32]) -> Option<usize> {
    let mut found = None;
    for (index, line) in lines.iter().enumerate() {
        if digest_eq(&line.digest, digest) && found.is_none() {
            found = Some(index);
        }
    }
    found
}

/// The authentication methods of `ostrya serve`: the credential file, the
/// client certificate, and anonymous push. The owner key of a principal has a
/// prefix for each method: `token:NAME` for a bearer token or a Basic
/// credential, by the name of its line, `cert:HEX` for a client certificate,
/// by the SHA-256 digest of its DER bytes in lowercase hex, and `anonymous`.
/// A name can be equal to a digest, and the prefix keeps the keys of two
/// methods apart. A bearer token and a Basic credential of one line give one
/// key. Each session gets the policy of the server.
pub(crate) struct FileAuth {
    /// A request with no credential may push.
    anonymous: bool,
    /// The TLS layer verifies a client certificate against a client CA.
    client_ca: bool,
    /// A bearer or Basic credential is taken over plain HTTP.
    cleartext: bool,
    /// The lines of the credential file.
    credentials: Vec<Credential>,
    /// The policy of each session.
    policy: Arc<ReceivePolicy>,
}

impl FileAuth {
    /// The methods of `opts`, with `policy` for each session. A malformed
    /// line of the credential file is [`Error::Credentials`]. A server with
    /// no method is refused, and so is a server with no TLS whose one method
    /// is the credential file and that takes no credential over plain HTTP,
    /// because no request can pass it.
    pub(crate) fn new(opts: &ServeOptions, policy: Arc<ReceivePolicy>) -> Result<FileAuth, Error> {
        let credentials = match &opts.credentials {
            Some(bytes) => parse_credentials(bytes)?,
            None => Vec::new(),
        };
        let auth = FileAuth {
            anonymous: opts.allow_anonymous_push,
            client_ca: opts
                .tls
                .as_ref()
                .is_some_and(|tls| tls.client_ca_pem.is_some()),
            cleartext: opts.allow_cleartext_credentials,
            credentials,
            policy,
        };
        if !auth.has_method() {
            return Err(Error::Options(
                "a receive endpoint with no authentication method".into(),
            ));
        }
        // With no TLS there is no client CA, so the credential lines are the one
        // method, and the endpoint refuses each of them over plain HTTP.
        if opts.tls.is_none() && !auth.anonymous && !auth.cleartext {
            return Err(Error::Options(
                "a receive endpoint over plain HTTP with the credential file as its one method \
                 and no allow_cleartext_credentials"
                    .into(),
            ));
        }
        Ok(auth)
    }

    /// Whether one method or more can accept a request.
    fn has_method(&self) -> bool {
        self.anonymous || self.client_ca || !self.credentials.is_empty()
    }

    /// The owner key of a request with `headers` from `peer`, or the refusal
    /// of the request.
    ///
    /// More than one `Authorization` header is 401. A bearer or Basic
    /// credential on a connection without TLS is 403, unless the server
    /// takes credentials over plain HTTP. A credential that matches no line
    /// is 401, also beside a client certificate. With no `Authorization`
    /// header, a verified client certificate gives its owner, then
    /// anonymous push where it is allowed. Else the request is 401 where the
    /// server has credential lines, and 403 where it has a client CA alone.
    fn authorize(&self, headers: &HeaderMap, peer: &Peer) -> Result<String, Refusal> {
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return self.without_credential(peer);
        };
        if values.next().is_some() {
            return Err(Refusal::unauthorized(
                "the request has more than one Authorization header",
            ));
        }
        let value = value.as_bytes();
        let (scheme, rest) = match value.iter().position(|&b| b == b' ') {
            Some(space) => (&value[..space], value[space..].trim_ascii_start()),
            None => (value, &value[value.len()..]),
        };
        let bearer = scheme.eq_ignore_ascii_case(b"Bearer");
        let basic = scheme.eq_ignore_ascii_case(b"Basic");
        if (bearer || basic) && !peer.tls && !self.cleartext {
            return Err(Refusal::forbidden(
                "the server takes no credential over plain HTTP",
            ));
        }
        let matched = if bearer {
            self.bearer(rest)
        } else if basic {
            self.basic(rest)
        } else {
            None
        };
        match matched {
            Some(index) => Ok(format!("token:{}", self.credentials[index].name)),
            None => Err(Refusal::unauthorized(
                "the credential of the request matches no credential of the server",
            )),
        }
    }

    /// The line of the bearer token `token`. An empty token matches no line.
    fn bearer(&self, token: &[u8]) -> Option<usize> {
        if token.is_empty() {
            return None;
        }
        match_line(&self.credentials, Checksum::sha256(token).as_bytes())
    }

    /// The line of the Basic credential `encoded`: the base64 of the name, a
    /// `:`, and the password, which can hold `:` too. The digest of the
    /// password selects the line, and the name must then be the name of that
    /// line. No two lines have one digest, so one name compare is enough. A
    /// credential with no `:`, a name that is not UTF-8, and an empty
    /// password match no line.
    fn basic(&self, encoded: &[u8]) -> Option<usize> {
        let encoded = std::str::from_utf8(encoded).ok()?;
        let decoded = ostrya::base64::decode(encoded).ok()?;
        let colon = decoded.iter().position(|&b| b == b':')?;
        let name = std::str::from_utf8(&decoded[..colon]).ok()?;
        let password = &decoded[colon + 1..];
        if password.is_empty() {
            return None;
        }
        let index = match_line(&self.credentials, Checksum::sha256(password).as_bytes())?;
        (self.credentials[index].name == name).then_some(index)
    }

    /// The owner key of a request with no `Authorization` header.
    fn without_credential(&self, peer: &Peer) -> Result<String, Refusal> {
        if self.client_ca
            && let Some(cert) = peer.cert
        {
            return Ok(format!("cert:{}", cert.to_hex()));
        }
        if self.anonymous {
            return Ok("anonymous".into());
        }
        if self.credentials.is_empty() {
            Err(Refusal::forbidden(
                "the request has no client certificate, and the server takes no other credential",
            ))
        } else {
            Err(Refusal::unauthorized("the request has no credential"))
        }
    }
}

/// `refusal`, with the two challenges of a credential when it is 401.
fn challenge(refusal: Refusal) -> Refusal {
    if refusal.status != StatusCode::UNAUTHORIZED {
        return refusal;
    }
    CHALLENGES.into_iter().fold(refusal, |refusal, challenge| {
        refusal.with_header(WWW_AUTHENTICATE, HeaderValue::from_static(challenge))
    })
}

impl ReceiveAuth for FileAuth {
    /// The owner key.
    type Principal = String;

    fn owner(principal: &String) -> &str {
        principal
    }

    /// The owner key of the request, from its headers and the [`Peer`] in
    /// its extensions. The server puts a peer into each request of its
    /// receive endpoint. A request with no peer is taken as plain HTTP with
    /// no client certificate. The route does not change the answer.
    fn authenticate(
        &self,
        parts: &Parts,
        _kind: RequestKind,
    ) -> impl Future<Output = Result<String, Refusal>> + Send {
        let peer = parts.extensions.get::<Peer>().copied();
        debug_assert!(peer.is_some(), "the server puts a peer into each request");
        let peer = peer.unwrap_or(Peer {
            tls: false,
            cert: None,
        });
        ready(self.authorize(&parts.headers, &peer).map_err(challenge))
    }

    /// The policy of the server and no hooks, for every principal.
    fn open(
        &self,
        _principal: &String,
        _hello: &Hello,
    ) -> impl Future<Output = Result<SessionSetup, Refusal>> + Send {
        ready(Ok(SessionSetup {
            policy: self.policy.clone(),
            hooks: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use hyper::header::HeaderValue;

    use super::*;

    const PLAIN: Peer = Peer {
        tls: false,
        cert: None,
    };

    const TLS: Peer = Peer {
        tls: true,
        cert: None,
    };

    fn line(name: &str, secret: &str) -> String {
        format!("{name}:{}\n", Checksum::sha256(secret.as_bytes()).to_hex())
    }

    fn auth(file: &str) -> FileAuth {
        FileAuth {
            anonymous: false,
            client_ca: false,
            cleartext: false,
            credentials: parse_credentials(file.as_bytes()).unwrap(),
            policy: Arc::new(ReceivePolicy::default()),
        }
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn basic(name: &str, password: &str) -> String {
        format!(
            "Basic {}",
            ostrya::base64::encode(format!("{name}:{password}").as_bytes())
        )
    }

    /// The line number and the message of the refusal of `file`.
    fn malformed(file: &str) -> (usize, String) {
        match parse_credentials(file.as_bytes()) {
            Err(Error::Credentials { line, message }) => (line, message),
            other => panic!("{file:?}: {other:?}"),
        }
    }

    #[test]
    fn comments_and_empty_lines_hold_no_credential() {
        let file = format!(
            "# the push credentials\n\n{}#{}{}",
            line("alice", "a"),
            line("bob", "b"),
            line("carol", "c").trim_end()
        );
        let lines = parse_credentials(file.as_bytes()).unwrap();
        let names: Vec<&str> = lines.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["alice", "carol"]);
        assert!(parse_credentials(b"").unwrap().is_empty());
        assert!(parse_credentials(b"# none\n\n").unwrap().is_empty());
        let odd = parse_credentials(line("a!~\"", "x").as_bytes()).unwrap();
        assert_eq!(odd[0].name, "a!~\"");
    }

    #[test]
    fn a_cr_is_malformed() {
        let file = format!("# ok\n{}\r\n", line("alice", "a").trim_end());
        assert_eq!(malformed(&file), (2, "the line holds a CR".into()));
        assert_eq!(malformed("# a comment\r\n").0, 1);
    }

    #[test]
    fn a_space_is_malformed() {
        let hex = Checksum::sha256(b"a").to_hex();
        for file in [
            format!("alice :{hex}"),
            format!(" alice:{hex}"),
            format!("alice:{hex} "),
            " ".to_string(),
        ] {
            assert_eq!(malformed(&file), (1, "the line holds a space".into()));
        }
    }

    #[test]
    fn a_line_with_no_colon_is_malformed() {
        assert_eq!(
            malformed(&Checksum::sha256(b"a").to_hex()),
            (1, "the line is not NAME:HEX".into())
        );
    }

    #[test]
    fn an_empty_name_is_malformed() {
        let file = format!(":{}", Checksum::sha256(b"a").to_hex());
        assert_eq!(malformed(&file), (1, "the name is empty".into()));
    }

    #[test]
    fn a_name_outside_visible_ascii_is_malformed() {
        let hex = Checksum::sha256(b"a").to_hex();
        for name in ["al\tice", "älice", "al\u{7f}ice"] {
            let (number, message) = malformed(&format!("{name}:{hex}"));
            assert_eq!(number, 1);
            assert!(message.contains("visible ASCII"), "{message}");
        }
    }

    #[test]
    fn a_digest_that_is_not_64_lowercase_hex_is_malformed() {
        let hex = Checksum::sha256(b"a").to_hex();
        for digest in [
            hex.to_ascii_uppercase(),
            hex[..63].to_string(),
            format!("{hex}0"),
            format!("{}g", &hex[..63]),
            format!("{}:{}", &hex[..31], &hex[32..]),
            String::new(),
        ] {
            let (number, message) = malformed(&format!("alice:{digest}"));
            assert_eq!(number, 1);
            assert_eq!(message, "the digest is not 64 lowercase hex digits");
        }
    }

    #[test]
    fn a_line_that_is_not_utf8_is_malformed() {
        let mut file = line("alice", "a").into_bytes();
        file.extend_from_slice(b"# \xff\n");
        match parse_credentials(&file) {
            Err(Error::Credentials { line, message }) => {
                assert_eq!((line, message.as_str()), (2, "the line is not UTF-8"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_repeated_name_is_malformed() {
        let file = format!(
            "{}\n{}{}",
            line("alice", "a"),
            line("bob", "b"),
            line("alice", "c")
        );
        assert_eq!(
            malformed(&file),
            (4, "the name of line 1 is repeated".into())
        );
    }

    #[test]
    fn a_repeated_digest_is_malformed() {
        let file = format!("{}{}", line("alice", "a"), line("bob", "a"));
        assert_eq!(
            malformed(&file),
            (2, "the digest of line 1 is repeated".into())
        );
    }

    /// The message of a malformed line holds no byte of the line.
    #[test]
    fn a_refusal_holds_no_byte_of_the_line() {
        let secret_name = "secret-name-1234";
        let error = parse_credentials(format!("{secret_name}:abc").as_bytes()).unwrap_err();
        let text = error.to_string();
        assert!(!text.contains(secret_name), "{text}");
        assert!(!text.contains("abc"), "{text}");
        assert!(text.contains("line 1"), "{text}");
    }

    #[test]
    fn digests_compare_by_every_byte() {
        let a = *Checksum::sha256(b"a").as_bytes();
        assert!(digest_eq(&a, &a));
        for i in 0..32 {
            let mut b = a;
            b[i] ^= 0x80;
            assert!(!digest_eq(&a, &b), "byte {i}");
        }
    }

    /// A match compares the digest with every line, also when the first line
    /// matches, and gives the first line that matches.
    #[test]
    fn a_match_visits_every_line() {
        let file: String = (0..5)
            .map(|i| line(&format!("n{i}"), &format!("s{i}")))
            .collect();
        let lines = parse_credentials(file.as_bytes()).unwrap();
        let count = |secret: &str| {
            COMPARES.with(|n| n.set(0));
            let found = match_line(&lines, Checksum::sha256(secret.as_bytes()).as_bytes());
            (found, COMPARES.with(|n| n.get()))
        };
        assert_eq!(count("s0"), (Some(0), 5));
        assert_eq!(count("s4"), (Some(4), 5));
        assert_eq!(count("none"), (None, 5));
    }

    /// A Basic credential compares the digest of every line, and then the
    /// name of the line that matched.
    #[test]
    fn basic_visits_every_line_and_then_checks_the_name() {
        let file: String = (0..5)
            .map(|i| line(&format!("n{i}"), &format!("s{i}")))
            .collect();
        let auth = auth(&file);
        let count = |name: &str, secret: &str| {
            COMPARES.with(|n| n.set(0));
            let value = basic(name, secret);
            let found = auth.basic(value.strip_prefix("Basic ").unwrap().as_bytes());
            (found, COMPARES.with(|n| n.get()))
        };
        assert_eq!(count("n0", "s0"), (Some(0), 5));
        assert_eq!(count("n2", "s2"), (Some(2), 5));
        assert_eq!(count("n1", "s2"), (None, 5));
        assert_eq!(count("n1", "none"), (None, 5));
    }

    #[test]
    fn a_bearer_token_and_basic_give_the_owner_of_their_line() {
        let auth = auth(&(line("alice", "a-token") + &line("bob", "b-token")));
        let owner = |value: &str| auth.authorize(&headers(&[value]), &TLS);
        let bob = "token:bob";
        assert_eq!(owner("Bearer b-token").unwrap(), bob);
        assert_eq!(owner("bearer   b-token").unwrap(), bob);
        assert_eq!(owner(&basic("bob", "b-token")).unwrap(), bob);
        assert_eq!(
            owner(&basic("alice", "a-token").replacen("Basic", "BASIC", 1)).unwrap(),
            "token:alice"
        );
        assert_eq!(owner(&basic("bob", "x:y")).unwrap_err().status, 401);
    }

    /// The password of a Basic credential runs from the first `:` to the
    /// end, so a password that holds `:` matches its line.
    #[test]
    fn a_basic_password_with_a_colon_matches() {
        let auth = auth(&(line("alice", "a-token") + &line("bob", "pa:ss:")));
        let owner = |value: &str| auth.authorize(&headers(&[value]), &TLS);
        assert_eq!(owner(&basic("bob", "pa:ss:")).unwrap(), "token:bob");
        assert_eq!(owner(&basic("bob", "pa:ss")).unwrap_err().status, 401);
        assert_eq!(owner(&basic("alice", "pa:ss:")).unwrap_err().status, 401);
    }

    #[test]
    fn a_credential_that_matches_no_line_is_401() {
        let mut auth = auth(&line("alice", "a-token"));
        auth.client_ca = true;
        auth.anonymous = true;
        let peer = Peer {
            tls: true,
            cert: Some(Checksum::sha256(b"cert")),
        };
        for value in [
            "Bearer other".to_string(),
            "Bearer".to_string(),
            "Bearer ".to_string(),
            basic("bob", "a-token"),
            basic("alice", "other"),
            basic("alice", ""),
            "Basic !!!".to_string(),
            format!("Basic {}", ostrya::base64::encode(b"alice")),
            "Digest a-token".to_string(),
        ] {
            let refusal = auth.authorize(&headers(&[&value]), &peer).unwrap_err();
            assert_eq!(refusal.status, StatusCode::UNAUTHORIZED, "{value}");
        }
    }

    #[test]
    fn more_than_one_authorization_header_is_401() {
        let auth = auth(&line("alice", "a-token"));
        let two = headers(&["Bearer a-token", "Bearer a-token"]);
        let refusal = auth.authorize(&two, &TLS).unwrap_err();
        assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            refusal.message,
            "the request has more than one Authorization header"
        );
    }

    /// A bearer or Basic credential over plain HTTP is 403 before any
    /// compare, also where anonymous push is allowed, unless the server takes
    /// credentials over plain HTTP.
    #[test]
    fn a_credential_over_plain_http_is_403() {
        let mut auth = auth(&line("alice", "a-token"));
        auth.anonymous = true;
        for value in [
            "Bearer a-token",
            "BEARER a-token",
            &basic("alice", "a-token"),
        ] {
            COMPARES.with(|n| n.set(0));
            let refusal = auth.authorize(&headers(&[value]), &PLAIN).unwrap_err();
            assert_eq!(refusal.status, StatusCode::FORBIDDEN, "{value}");
            assert_eq!(COMPARES.with(|n| n.get()), 0);
        }
        auth.cleartext = true;
        assert_eq!(
            auth.authorize(&headers(&["Bearer a-token"]), &PLAIN)
                .unwrap(),
            "token:alice"
        );
    }

    /// With no header: a client certificate, then anonymous push, then 401
    /// with credential lines and 403 with a client CA alone.
    #[test]
    fn a_request_with_no_header() {
        let cert = Checksum::sha256(b"cert");
        let with_cert = Peer {
            tls: true,
            cert: Some(cert),
        };
        let cert_key = format!("cert:{}", cert.to_hex());
        let none = HeaderMap::new();
        let mut auth = auth("");
        auth.client_ca = true;
        assert!(auth.has_method());
        assert_eq!(auth.authorize(&none, &with_cert).unwrap(), cert_key);
        assert_eq!(auth.authorize(&none, &TLS).unwrap_err().status, 403);
        auth.anonymous = true;
        assert_eq!(auth.authorize(&none, &with_cert).unwrap(), cert_key);
        assert_eq!(auth.authorize(&none, &TLS).unwrap(), "anonymous");
        let mut auth = self::auth(&line("alice", "a-token"));
        assert!(auth.has_method());
        assert_eq!(auth.authorize(&none, &with_cert).unwrap_err().status, 401);
        auth.client_ca = true;
        assert_eq!(auth.authorize(&none, &TLS).unwrap_err().status, 401);
    }

    #[test]
    fn a_file_with_no_line_is_no_method() {
        let auth = auth("# none\n");
        assert!(!auth.has_method());
        let mut open = self::auth("");
        open.anonymous = true;
        assert!(open.has_method());
        assert_eq!(
            open.authorize(&HeaderMap::new(), &PLAIN).unwrap(),
            "anonymous"
        );
    }

    /// The parts of a request with the `Authorization` values `values` and,
    /// when it is given, `peer` in its extensions.
    fn parts(values: &[&str], peer: Option<Peer>) -> Parts {
        let mut builder = hyper::Request::builder();
        for value in values {
            builder = builder.header(AUTHORIZATION, *value);
        }
        if let Some(peer) = peer {
            builder = builder.extension(peer);
        }
        builder.body(()).unwrap().into_parts().0
    }

    fn authenticate(auth: &FileAuth, parts: &Parts) -> Result<String, Refusal> {
        ostrya_rt::block_on(auth.authenticate(parts, RequestKind::Open))
    }

    /// `authenticate` reads the peer from the extensions of the request, and
    /// adds the two challenges to a 401 alone. The route does not change the
    /// answer.
    #[test]
    fn authenticate_reads_the_peer_and_challenges_a_401_alone() {
        let mut auth = auth(&line("alice", "a-token"));
        auth.client_ca = true;
        let cert = Checksum::sha256(b"cert");
        let with_cert = Peer {
            tls: true,
            cert: Some(cert),
        };
        assert_eq!(
            authenticate(&auth, &parts(&[], Some(with_cert))).unwrap(),
            format!("cert:{}", cert.to_hex())
        );
        let token = parts(&["Bearer a-token"], Some(TLS));
        for kind in [
            RequestKind::Open,
            RequestKind::Have,
            RequestKind::Objects,
            RequestKind::Commit,
            RequestKind::Delete,
        ] {
            let owner = ostrya_rt::block_on(auth.authenticate(&token, kind)).unwrap();
            assert_eq!(FileAuth::owner(&owner), "token:alice");
        }

        let refusal = authenticate(&auth, &parts(&[], Some(TLS))).unwrap_err();
        assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
        let challenges: Vec<_> = CHALLENGES
            .into_iter()
            .map(|c| (WWW_AUTHENTICATE, HeaderValue::from_static(c)))
            .collect();
        assert_eq!(refusal.headers, challenges);

        let refusal = authenticate(&auth, &parts(&["Bearer a-token"], Some(PLAIN))).unwrap_err();
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        assert!(refusal.headers.is_empty());
    }

    /// In a build with debug assertions, a request with no peer panics.
    /// Otherwise it is plain HTTP with no client certificate, so a
    /// credential is 403.
    #[test]
    fn a_request_with_no_peer_is_plain_http() {
        let auth = auth(&line("alice", "a-token"));
        let no_peer = parts(&["Bearer a-token"], None);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            authenticate(&auth, &no_peer)
        }));
        if cfg!(debug_assertions) {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().unwrap_err().status, StatusCode::FORBIDDEN);
        }
    }

    /// `open` gives the policy of the server to every principal.
    #[test]
    fn open_gives_the_policy_of_the_server() {
        let auth = auth("");
        let hello = Hello {
            version: 1,
            agent: None,
            refs: vec!["main".into()],
            one_way: false,
        };
        for principal in ["anonymous", "token:alice"] {
            let setup = ostrya_rt::block_on(auth.open(&principal.to_owned(), &hello)).unwrap();
            assert!(Arc::ptr_eq(&setup.policy, &auth.policy));
        }
    }

    /// `FileAuth::new` refuses a server with no method, and a server with
    /// no TLS whose one method is the credential file, unless it takes
    /// credentials over plain HTTP. A malformed line is
    /// [`Error::Credentials`].
    #[test]
    fn new_refuses_a_server_that_no_request_can_pass() {
        let policy = Arc::new(ReceivePolicy::default());
        let new = |change: &dyn Fn(&mut ServeOptions)| {
            let mut opts = ServeOptions::default();
            change(&mut opts);
            FileAuth::new(&opts, policy.clone())
        };
        let options = |result: Result<FileAuth, Error>| match result {
            Err(Error::Options(message)) => message,
            Err(other) => panic!("{other}"),
            Ok(_) => panic!("the options pass"),
        };
        let file = line("alice", "a-token").into_bytes();
        assert_eq!(
            options(new(&|_| {})),
            "a receive endpoint with no authentication method"
        );
        assert_eq!(
            options(new(&|o| o.credentials = Some(b"# none\n".to_vec()))),
            "a receive endpoint with no authentication method"
        );
        assert!(options(new(&|o| o.credentials = Some(file.clone()))).contains("over plain HTTP"),);
        assert!(matches!(
            new(&|o| o.credentials = Some(b"alice".to_vec())),
            Err(Error::Credentials { line: 1, .. })
        ));
        let auth = new(&|o| {
            o.credentials = Some(file.clone());
            o.allow_cleartext_credentials = true;
        })
        .unwrap();
        assert!(auth.cleartext && !auth.anonymous && !auth.client_ca);
        assert_eq!(auth.credentials.len(), 1);
        let auth = new(&|o| {
            o.credentials = Some(file.clone());
            o.tls = Some(crate::ServerTls {
                cert_chain_pem: Vec::new(),
                key_pem: Vec::new(),
                key_passphrase: None,
                client_ca_pem: Some(Vec::new()),
            });
        })
        .unwrap();
        assert!(auth.client_ca && !auth.cleartext);
        let auth = new(&|o| o.allow_anonymous_push = true).unwrap();
        assert!(auth.anonymous && auth.credentials.is_empty());
    }
}
