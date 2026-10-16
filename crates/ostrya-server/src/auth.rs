//! The authentication of the requests of a server by the client groups of
//! the repository: the reads of the archive view and of the ref listing,
//! and the requests of the receive endpoint.
//!
//! The doc of [`ServeOptions`](crate::ServeOptions) states the order of the
//! checks and the rules of the claims of a client certificate. The server
//! compares the digest of a credential with every `token-sha256` or
//! `basic-sha256` item in constant time, and does not stop at a match.

use std::borrow::Cow;
use std::collections::HashMap;
use std::future::{Future, ready};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use futures_rustls::pki_types::UnixTime;
use hyper::header::{AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE};
use hyper::http::Extensions;
use hyper::http::request::Parts;
use hyper::{HeaderMap, StatusCode};
use ostrya::access::{AuthItem, Claims, ClientAccess, ClientGroup, IpNet, ReadAccess};
use ostrya::remote::proto::Hello;
use ostrya::{Checksum, ReceivePolicies, ReceivePolicy};

use crate::cert::{ClientCert, ForwardedCerts};
use crate::event::{EventSink, ServerEvent};
use crate::forwarded::{Forwarding, Origin};
use crate::receive_auth::{ReceiveAuth, Refusal, RequestKind, SessionSetup};

/// The `WWW-Authenticate` headers of a 401: the two schemes of a credential.
const CHALLENGES: [&str; 2] = [r#"Bearer realm="ostrya""#, r#"Basic realm="ostrya""#];

/// What the connection of a request states about its client. The server puts
/// it into the extensions of each request.
#[derive(Clone, Debug)]
pub(crate) struct Peer {
    /// `true` if the connection runs over TLS.
    pub(crate) tls: bool,
    /// The peer address of the connection: the source address of its PROXY
    /// header, else the TCP peer address.
    pub(crate) addr: IpAddr,
    /// The end-entity certificate that the client presented in the TLS
    /// handshake. The handshake verified it against the client CA. The
    /// server reads it one time for each connection, and each request of
    /// the connection shares it.
    pub(crate) cert: Option<Arc<ClientCert>>,
}

#[cfg(test)]
thread_local! {
    /// The number of digest compares on this thread.
    static COMPARES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Returns `true` if two digests are equal, in a time that does not depend
/// on their bytes. The function reads each digest as four 64-bit words and
/// ORs the XOR of each word pair into one word. No step branches on a byte.
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

/// One `token-sha256:HEX` item.
#[derive(Debug)]
struct TokenEntry {
    digest: [u8; 32],
    client: Client,
}

/// One `basic-sha256:USER:HEX` item, with the SHA-256 digest of its user
/// name.
#[derive(Debug)]
struct BasicEntry {
    user: [u8; 32],
    password: [u8; 32],
    client: Client,
}

/// The auth items of the client groups, in the form that each step of the
/// identification reads. An `ssh:NAME` item has no place, because a request
/// over HTTP never matches it. Each item has its [`Client`], so a request
/// that matches an item clones two `Arc`s alone.
#[derive(Debug, Default)]
struct CredentialIndex {
    tokens: Vec<TokenEntry>,
    basics: Vec<BasicEntry>,
    tls_sha256: HashMap<[u8; 32], Client>,
    tls_names: HashMap<String, Client>,
    tls_any: Option<Client>,
    nets: Vec<(IpNet, Client)>,
    anonymous: Option<Client>,
}

impl CredentialIndex {
    fn new(access: &ClientAccess) -> CredentialIndex {
        let mut index = CredentialIndex::default();
        for item in access.items() {
            let claims = item.is_tls() && access.groups_of(item).any(ClientGroup::tls_accept_claim);
            let client = Client::new(item.clone(), claims);
            match item {
                AuthItem::Anonymous => index.anonymous = Some(client),
                AuthItem::TlsAny => index.tls_any = Some(client),
                AuthItem::TlsName(name) => {
                    index.tls_names.insert(name.clone(), client);
                }
                AuthItem::TlsSha256(digest) => {
                    index.tls_sha256.insert(*digest, client);
                }
                AuthItem::TokenSha256(digest) => index.tokens.push(TokenEntry {
                    digest: *digest,
                    client,
                }),
                AuthItem::BasicSha256 { user, digest } => index.basics.push(BasicEntry {
                    user: *Checksum::sha256(user.as_bytes()).as_bytes(),
                    password: *digest,
                    client,
                }),
                AuthItem::Ssh(_) => {}
                AuthItem::Net(net) => index.nets.push((*net, client)),
            }
        }
        index
    }

    /// The `token-sha256` item of the bearer token `token`. The function
    /// compares the digest of the token with every item, also after a match.
    /// An empty token matches no item.
    fn bearer(&self, token: &[u8]) -> Option<Client> {
        if token.is_empty() {
            return None;
        }
        let digest = *Checksum::sha256(token).as_bytes();
        let mut found = None;
        for entry in &self.tokens {
            if digest_eq(&entry.digest, &digest) && found.is_none() {
                found = Some(&entry.client);
            }
        }
        found.cloned()
    }

    /// The `basic-sha256` item of the Basic credential `encoded`: the base64
    /// of the user name, a `:`, and the password, which can hold `:` too.
    /// The function compares the digest of the user name and the digest of
    /// the password with every item, also after a match. A credential with
    /// no `:`, a user name that is not UTF-8, and an empty password match no
    /// item.
    fn basic(&self, encoded: &[u8]) -> Option<Client> {
        let encoded = std::str::from_utf8(encoded).ok()?;
        let decoded = ostrya::base64::decode(encoded).ok()?;
        let colon = decoded.iter().position(|&b| b == b':')?;
        let user = std::str::from_utf8(&decoded[..colon]).ok()?;
        let password = &decoded[colon + 1..];
        if password.is_empty() {
            return None;
        }
        let user = *Checksum::sha256(user.as_bytes()).as_bytes();
        let password = *Checksum::sha256(password).as_bytes();
        let mut found = None;
        for entry in &self.basics {
            let user_eq = digest_eq(&entry.user, &user);
            let password_eq = digest_eq(&entry.password, &password);
            if user_eq & password_eq && found.is_none() {
                found = Some(&entry.client);
            }
        }
        found.cloned()
    }

    /// The first item that `cert` matches, in this order: `tls-sha256:HEX`,
    /// `tls:NAME`, `tls:*`.
    fn certificate(&self, cert: &ClientCert) -> Option<Client> {
        if let Some(client) = self.tls_sha256.get(cert.digest.as_bytes()) {
            return Some(client.clone());
        }
        if let Some(cn) = &cert.cn
            && let Some(client) = self.tls_names.get(cn)
        {
            return Some(client.clone());
        }
        self.tls_any.clone()
    }

    /// The `net:` item with the longest prefix that holds `addr`. A client
    /// with no address matches no item.
    fn net(&self, addr: Option<IpAddr>) -> Option<Client> {
        let addr = addr?;
        self.nets
            .iter()
            .filter(|(net, _)| net.contains(addr))
            .max_by_key(|(net, _)| net.prefix_len())
            .map(|(_, client)| client.clone())
    }

    /// Returns `true` if a `token-sha256` or a `basic-sha256` item exists.
    fn takes_credentials(&self) -> bool {
        !self.tokens.is_empty() || !self.basics.is_empty()
    }
}

/// The identified client of a request: its auth item, and the owner key of
/// its sessions.
#[derive(Debug, Clone)]
pub(crate) struct Client {
    item: Arc<AuthItem>,
    /// The text of `item`. For a certificate of `claims`, the
    /// `tls-sha256:HEX` text of the certificate alone.
    owner: Arc<str>,
    /// `true` if `item` is a TLS item and a group that carries it has
    /// `tls-accept-claim=true`.
    claims: bool,
    /// The certificate that gave `item`, when `claims` is `true`.
    cert: Option<Arc<ClientCert>>,
}

impl Client {
    fn new(item: AuthItem, claims: bool) -> Client {
        Client {
            owner: item.to_string().into(),
            item: Arc::new(item),
            claims,
            cert: None,
        }
    }

    /// The client that the certificate `cert` identifies. When a group of
    /// the item reads claims, the client keeps the certificate, and its
    /// owner key is the `tls-sha256:HEX` text of the certificate.
    ///
    /// The digest alone is a key with no collision. The certificate sets
    /// the item that it matches, and a `tls-sha256:HEX` item, the one other
    /// item with this text, matches only the certificate of that digest.
    fn with_cert(mut self, cert: &Arc<ClientCert>) -> Client {
        if self.claims {
            self.owner = cert.owner.clone();
            self.cert = Some(cert.clone());
        }
        self
    }
}

/// The authentication of `ostrya serve`: the client groups of the repository.
/// [`ServeOptions`](crate::ServeOptions) states the order of the checks and
/// the selection of a group.
pub(crate) struct GroupAuth {
    /// `true` if the server takes a bearer or Basic credential over plain
    /// HTTP.
    cleartext: bool,
    /// The client groups and their policies. The read rights of each request
    /// share the client groups.
    policies: Arc<ReceivePolicies>,
    /// The auth items of the groups.
    index: CredentialIndex,
    /// The trusted proxies and the header of the client address, or `None`
    /// with no trusted proxy.
    forwarding: Option<Forwarding>,
    /// The client certificates that trusted proxies forward, or `None` with
    /// no header of a forwarded certificate.
    forwarded_certs: Option<ForwardedCerts>,
    /// The callback of the events, or `None`.
    on_event: Option<EventSink>,
}

impl GroupAuth {
    /// The authentication by the groups of `policies`. With `cleartext`, the
    /// server takes a bearer or Basic credential over plain HTTP.
    pub(crate) fn new(policies: Arc<ReceivePolicies>, cleartext: bool) -> GroupAuth {
        GroupAuth {
            cleartext,
            index: CredentialIndex::new(policies.access()),
            policies,
            forwarding: None,
            forwarded_certs: None,
            on_event: None,
        }
    }

    /// The authentication with the forwarding data of the trusted proxies
    /// of `forwarding`, and the forwarded certificates of `certs`. The server
    /// reads a forwarded certificate only from a trusted proxy.
    pub(crate) fn with_proxies(
        mut self,
        forwarding: Option<Forwarding>,
        certs: Option<ForwardedCerts>,
    ) -> GroupAuth {
        self.forwarding = forwarding;
        self.forwarded_certs = certs;
        self
    }

    /// The authentication that reports its events to `on_event`.
    pub(crate) fn with_events(mut self, on_event: Option<EventSink>) -> GroupAuth {
        self.on_event = on_event;
        self
    }

    /// The auth item of a request with `headers` from `peer`, or the refusal
    /// of the request. The server takes the first step that applies, in the
    /// order that [`ServeOptions`](crate::ServeOptions#authentication) states.
    fn identify(&self, headers: &HeaderMap, peer: &Peer) -> Result<Client, Refusal> {
        self.identify_at(headers, peer, UnixTime::now())
    }

    /// [`identify`](GroupAuth::identify) at the time `now`, which checks the
    /// validity of a forwarded certificate.
    fn identify_at(
        &self,
        headers: &HeaderMap,
        peer: &Peer,
        now: UnixTime,
    ) -> Result<Client, Refusal> {
        let (origin, trusted) = match &self.forwarding {
            Some(forwarding) => (
                forwarding.origin(headers, peer.addr),
                forwarding.trusts(peer.addr),
            ),
            None => (
                Origin {
                    addr: Some(peer.addr),
                    https: false,
                },
                false,
            ),
        };
        let tls = peer.tls || origin.https;
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let value = values.next();
        if values.next().is_some() {
            return Err(Refusal::unauthorized(
                "the request has more than one Authorization header",
            ));
        }
        if let Some(value) = value {
            let value = value.as_bytes();
            let (scheme, rest) = match value.iter().position(|&b| b == b' ') {
                Some(space) => (&value[..space], value[space..].trim_ascii_start()),
                None => (value, &value[value.len()..]),
            };
            let bearer = scheme.eq_ignore_ascii_case(b"Bearer");
            let basic = scheme.eq_ignore_ascii_case(b"Basic");
            if (bearer || basic) && !tls && !self.cleartext {
                return Err(Refusal::forbidden(
                    "the server takes no credential over plain HTTP",
                ));
            }
            let item = if bearer {
                self.index.bearer(rest)
            } else if basic {
                self.index.basic(rest)
            } else {
                None
            };
            return item.ok_or_else(|| {
                Refusal::unauthorized(
                    "the credential of the request matches no auth item of the server",
                )
            });
        }
        // From a trusted proxy with a header of a forwarded certificate, the
        // header alone gives the certificate. The certificate of the
        // handshake is then the certificate of the proxy.
        let forwarded;
        let cert = match &self.forwarded_certs {
            Some(certs) if trusted => {
                forwarded = certs
                    .certificate(headers, now)
                    .map_err(|bad| Refusal::forbidden(bad.message()))?;
                forwarded.as_ref()
            }
            _ => peer.cert.as_ref(),
        };
        if let Some(cert) = cert {
            return match self.index.certificate(cert) {
                Some(client) => Ok(client.with_cert(cert)),
                None => Err(Refusal::forbidden(
                    "the client certificate of the request matches no auth item of the server",
                )),
            };
        }
        if let Some(client) = self.index.net(origin.addr) {
            return Ok(client);
        }
        if let Some(client) = &self.index.anonymous {
            return Ok(client.clone());
        }
        if self.index.takes_credentials() {
            Err(Refusal::unauthorized("the request has no credential"))
        } else {
            Err(Refusal::forbidden(
                "the request matches no auth item of the server",
            ))
        }
    }

    /// The read rights of a request with `headers` from `peer`, or the
    /// refusal of the request.
    ///
    /// The identification takes the steps of [`identify`](GroupAuth::identify),
    /// and a 401 carries the two challenges. When a group with
    /// `tls-accept-claim=true` carries the item of a certificate, claims that
    /// do not parse get 403, and the server reports an event. Else the rights
    /// carry the item and the claims of the client.
    pub(crate) fn identify_read(
        &self,
        headers: &HeaderMap,
        peer: &Peer,
    ) -> Result<ReadAccess, Refusal> {
        let client = self.identify(headers, peer).map_err(challenge)?;
        let claims = match &client.cert {
            Some(cert) => Some(self.claims_of(cert)?.clone()),
            None => None,
        };
        Ok(ReadAccess::new(
            self.policies.access().clone(),
            client.item.clone(),
            claims,
        ))
    }

    /// The claims of `cert`, or the 403 of claims that do not parse. The
    /// refusal reports a [`ServerEvent::BadClaims`].
    fn claims_of<'c>(&self, cert: &'c ClientCert) -> Result<&'c Arc<Claims>, Refusal> {
        cert.claims.as_ref().map_err(|fault| {
            if let Some(on_event) = &self.on_event {
                on_event(&ServerEvent::BadClaims {
                    digest: cert.digest,
                    san: fault.san().map(str::to_owned),
                    reason: fault.reason(),
                });
            }
            Refusal::forbidden(format!(
                "the claims of the client certificate do not parse: {fault}"
            ))
        })
    }

    /// The setup of a session that `client` opens. [`open`](ReceiveAuth::open)
    /// states the rules.
    fn setup(&self, client: &Client) -> Result<SessionSetup, Refusal> {
        let access = self.policies.access();
        let namespace = access.namespace(None);
        let Some((group, policy)) = self.policies.select(&client.item, &namespace) else {
            return Err(Refusal::forbidden(
                "no client group of the request covers the local refs",
            ));
        };
        let claims = match &client.cert {
            Some(cert) if group.tls_accept_claim() => Some(self.claims_of(cert)?),
            _ => None,
        };
        let claimed = match access.effective_rules(group, &namespace, claims.map(|c| &**c)) {
            Cow::Owned(rules) => Some(rules),
            Cow::Borrowed(_) => None,
        };
        let policy = match claimed {
            Some(rules) if !rules.opens_push_session() => {
                return Err(Refusal::forbidden(format!(
                    "the claims of the client certificate open no push session in client \
                     group '{}'",
                    group.name()
                )));
            }
            Some(rules) => {
                // Each field but `rules` by name, so a new field of the
                // policy needs a decision here.
                let ReceivePolicy {
                    rules: _,
                    verify,
                    allow_unsigned,
                    signers,
                    allow_privileged,
                    summary_signers,
                    update_summary,
                    detached_metadata_filter,
                    group,
                } = &**policy;
                Arc::new(ReceivePolicy {
                    rules,
                    verify: verify.clone(),
                    allow_unsigned: *allow_unsigned,
                    signers: signers.clone(),
                    allow_privileged: *allow_privileged,
                    summary_signers: summary_signers.clone(),
                    update_summary: *update_summary,
                    detached_metadata_filter: detached_metadata_filter.clone(),
                    group: group.clone(),
                })
            }
            None if !policy.rules.opens_push_session() => {
                return Err(Refusal::forbidden(format!(
                    "client group '{}' opens no push session",
                    group.name()
                )));
            }
            None => policy.clone(),
        };
        Ok(SessionSetup {
            policy,
            hooks: None,
        })
    }
}

/// The [`Peer`] in the extensions of a request. The server puts a peer into
/// each request when it has client groups.
///
/// If a request has no peer, a build with debug assertions panics. Other
/// builds take the request as plain HTTP from the unspecified address, with
/// no client certificate.
pub(crate) fn peer_of(extensions: &Extensions) -> Peer {
    let peer = extensions.get::<Peer>().cloned();
    debug_assert!(peer.is_some(), "the server puts a peer into each request");
    peer.unwrap_or(Peer {
        tls: false,
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        cert: None,
    })
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

impl ReceiveAuth for GroupAuth {
    type Principal = Client;

    /// The text of the auth item.
    fn owner(principal: &Client) -> &str {
        &principal.owner
    }

    /// The client of the request, from its headers and the [`Peer`] in its
    /// extensions. The route does not change the answer. [`peer_of`] states
    /// the case of a request with no peer.
    fn authenticate(
        &self,
        parts: &Parts,
        _kind: RequestKind,
    ) -> impl Future<Output = Result<Client, Refusal>> + Send {
        let peer = peer_of(&parts.extensions);
        ready(self.identify(&parts.headers, &peer).map_err(challenge))
    }

    /// The policy of the client group that carries the item of `client` in
    /// the local refs, and no hooks. `Hello` names no collection, so the
    /// namespace of each session is the local refs.
    ///
    /// When the group has `tls-accept-claim=true` and a certificate gave the
    /// item, the claims of the certificate for the local refs replace the
    /// rules of the group. Claims that do not parse get 403, and the server
    /// reports an event. With no such group, and with rules that open no
    /// push session, the refusal is 403.
    fn open(
        &self,
        client: &Client,
        _hello: &Hello,
    ) -> impl Future<Output = Result<SessionSetup, Refusal>> + Send {
        ready(self.setup(client))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use hyper::header::HeaderValue;

    use super::*;
    use crate::session::tests::TmpRepo;
    use crate::test_pki::TestCa;

    /// The hex digest of `text`.
    fn hex(text: &str) -> String {
        Checksum::sha256(text.as_bytes()).to_hex()
    }

    /// The authentication by `groups`, in a new repository. The repository
    /// lives until the end of the test.
    fn auth(groups: &str) -> (GroupAuth, TmpRepo) {
        static N: AtomicU32 = AtomicU32::new(0);
        let tmp = TmpRepo::new(&format!("auth-{}", N.fetch_add(1, Ordering::Relaxed)));
        (GroupAuth::new(tmp.policies(groups), false), tmp)
    }

    /// Two groups of credentials: `tokens` with two bearer tokens, and
    /// `basics` with two Basic credentials. Both push to each ref.
    fn credentials() -> String {
        format!(
            "[ex-ostrya client \"tokens\"]\n\
             auth=token-sha256:{};token-sha256:{}\nallow=w:**\n\
             [ex-ostrya client \"basics\"]\n\
             auth=basic-sha256:alice:{};basic-sha256:bob:{}\nallow=w:**\n",
            hex("a-token"),
            hex("b-token"),
            hex("a-pass"),
            hex("pa:ss:"),
        )
    }

    fn peer(tls: bool, addr: &str, cert: Option<ClientCert>) -> Peer {
        Peer {
            tls,
            addr: addr.parse().unwrap(),
            cert: cert.map(Arc::new),
        }
    }

    fn plain() -> Peer {
        peer(false, "192.0.2.1", None)
    }

    fn tls() -> Peer {
        peer(true, "192.0.2.1", None)
    }

    /// A certificate with the digest of `der` and the CN `cn`.
    fn cert(der: &str, cn: Option<&str>) -> ClientCert {
        let digest = Checksum::sha256(der.as_bytes());
        ClientCert {
            owner: format!("tls-sha256:{digest}").into(),
            digest,
            cn: cn.map(str::to_owned),
            not_after: None,
            claims: Ok(Arc::new(ostrya::access::Claims::default())),
        }
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            ostrya::base64::encode(format!("{user}:{password}").as_bytes())
        )
    }

    /// The text of the item that `auth` gives to `values` from `peer`.
    fn item(auth: &GroupAuth, values: &[&str], peer: &Peer) -> String {
        auth.identify(&headers(values), peer)
            .unwrap()
            .owner
            .to_string()
    }

    /// The status of the refusal of `values` from `peer`.
    fn refused(auth: &GroupAuth, values: &[&str], peer: &Peer) -> StatusCode {
        auth.identify(&headers(values), peer).unwrap_err().status
    }

    /// The result of `f`, and the number of digest compares it made.
    fn counted<T>(f: impl FnOnce() -> T) -> (T, usize) {
        COMPARES.with(|n| n.set(0));
        let result = f();
        (result, COMPARES.with(|n| n.get()))
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

    /// The index holds each item of each group once, and no `ssh:` item.
    #[test]
    fn the_index_holds_the_items_of_each_group() {
        let (auth, _tmp) = auth(&format!(
            "{}[ex-ostrya client \"other\"]\nauth=ssh:u;token-sha256:{};tls:*;net:10.0.0.0/8\n\
             collection=*\n",
            credentials(),
            hex("a-token"),
        ));
        let index = &auth.index;
        assert_eq!(index.tokens.len(), 2);
        assert_eq!(index.basics.len(), 2);
        assert!(index.tls_any.is_some() && index.anonymous.is_none());
        assert_eq!(index.nets.len(), 1);
        assert!(index.tls_names.is_empty() && index.tls_sha256.is_empty());
    }

    /// A bearer token gives its `token-sha256` item, and a Basic credential
    /// its `basic-sha256` item. Each compare visits every item of its kind:
    /// one compare for each token, and two for each Basic item.
    #[test]
    fn a_credential_gives_its_item_and_visits_every_item() {
        let (auth, _tmp) = auth(&credentials());
        for (value, expected) in [
            (
                "Bearer a-token".to_owned(),
                format!("token-sha256:{}", hex("a-token")),
            ),
            (
                "bearer   b-token".to_owned(),
                format!("token-sha256:{}", hex("b-token")),
            ),
        ] {
            let (found, compares) = counted(|| item(&auth, &[&value], &tls()));
            assert_eq!((found, compares), (expected, 2), "{value}");
        }
        for (user, password) in [("alice", "a-pass"), ("bob", "pa:ss:")] {
            let value = basic(user, password);
            let (found, compares) = counted(|| item(&auth, &[&value], &tls()));
            let expected = format!("basic-sha256:{user}:{}", hex(password));
            assert_eq!((found, compares), (expected, 4), "{user}");
        }
        let upper = basic("alice", "a-pass").replacen("Basic", "BASIC", 1);
        assert!(item(&auth, &[&upper], &tls()).starts_with("basic-sha256:alice:"));
    }

    /// A credential that matches no item is 401, also with a client
    /// certificate, an anonymous item, and a `net:` item that holds the peer.
    /// A Basic credential with a wrong user name or a wrong password visits
    /// every item.
    #[test]
    fn a_credential_that_matches_no_item_is_401() {
        let (auth, _tmp) = auth(&format!(
            "{}[ex-ostrya client \"others\"]\nauth=anonymous;tls:*;net:0.0.0.0/0\nallow=w:**\n",
            credentials()
        ));
        let with_cert = peer(true, "192.0.2.1", Some(cert("cert", Some("host"))));
        for value in [
            "Bearer other".to_owned(),
            "Bearer".to_owned(),
            "Bearer ".to_owned(),
            basic("alice", "pa:ss:"),
            basic("bob", "a-pass"),
            basic("carol", "a-pass"),
            basic("alice", ""),
            "Basic !!!".to_owned(),
            format!("Basic {}", ostrya::base64::encode(b"alice")),
            format!("Basic {}", ostrya::base64::encode(b"\xff:a-pass")),
            "Digest a-token".to_owned(),
            "a-token".to_owned(),
        ] {
            assert_eq!(
                refused(&auth, &[&value], &with_cert),
                StatusCode::UNAUTHORIZED,
                "{value}"
            );
        }
        for (user, password) in [("alice", "b-pass"), ("carol", "a-pass")] {
            let value = basic(user, password);
            let (status, compares) = counted(|| refused(&auth, &[&value], &tls()));
            assert_eq!((status, compares), (StatusCode::UNAUTHORIZED, 4));
        }
        let (status, compares) = counted(|| refused(&auth, &["Bearer other"], &tls()));
        assert_eq!((status, compares), (StatusCode::UNAUTHORIZED, 2));
    }

    /// More than one `Authorization` header is 401 before each other step,
    /// also over plain HTTP.
    #[test]
    fn more_than_one_authorization_header_is_401() {
        let (auth, _tmp) = auth(&credentials());
        let two = headers(&["Bearer a-token", "Bearer a-token"]);
        for peer in [tls(), plain()] {
            let refusal = auth.identify(&two, &peer).unwrap_err();
            assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
            assert_eq!(
                refusal.message,
                "the request has more than one Authorization header"
            );
        }
    }

    /// A bearer or Basic credential over plain HTTP is 403 before any
    /// compare, also where an anonymous item exists. With the cleartext
    /// switch, the credential gives its item.
    #[test]
    fn a_credential_over_plain_http_is_403() {
        let (mut auth, _tmp) = auth(&format!(
            "{}[ex-ostrya client \"anonymous\"]\nauth=anonymous\nallow=w:**\n",
            credentials()
        ));
        for value in [
            "Bearer a-token".to_owned(),
            "BEARER a-token".to_owned(),
            basic("alice", "a-pass"),
        ] {
            let (status, compares) = counted(|| refused(&auth, &[&value], &plain()));
            assert_eq!((status, compares), (StatusCode::FORBIDDEN, 0), "{value}");
        }
        assert_eq!(refused(&auth, &["Digest x"], &plain()), 401);
        assert_eq!(item(&auth, &[], &plain()), "anonymous");
        auth.cleartext = true;
        assert_eq!(
            item(&auth, &["Bearer a-token"], &plain()),
            format!("token-sha256:{}", hex("a-token"))
        );
    }

    /// A certificate gives the first item that it matches: `tls-sha256:HEX`,
    /// then `tls:NAME` by the CN, then `tls:*`. A certificate that matches
    /// no item is 403, also with an anonymous item and a `net:` item that
    /// holds the peer.
    #[test]
    fn a_certificate_gives_the_first_item_that_matches() {
        let (auth, _tmp) = auth(&format!(
            "[ex-ostrya client \"by-digest\"]\nauth=tls-sha256:{}\nallow=w:**\n\
             [ex-ostrya client \"by-name\"]\nauth=tls:host\nallow=w:**\n\
             [ex-ostrya client \"any\"]\nauth=tls:*\nallow=w:**\n",
            hex("pinned"),
        ));
        let with =
            |der: &str, cn: Option<&str>| item(&auth, &[], &peer(true, "::1", Some(cert(der, cn))));
        assert_eq!(
            with("pinned", Some("host")),
            format!("tls-sha256:{}", hex("pinned"))
        );
        assert_eq!(with("other", Some("host")), "tls:host");
        assert_eq!(with("other", Some("Host")), "tls:*");
        assert_eq!(with("other", None), "tls:*");
        assert_eq!(refused(&auth, &[], &tls()), StatusCode::FORBIDDEN);

        let (auth, _tmp) = self::auth(&format!(
            "[ex-ostrya client \"by-name\"]\nauth=tls:host\nallow=w:**\n\
             [ex-ostrya client \"others\"]\nauth=anonymous;net:0.0.0.0/0;token-sha256:{}\n\
             allow=w:**\n",
            hex("a-token"),
        ));
        let unknown = peer(true, "192.0.2.1", Some(cert("other", Some("guest"))));
        let refusal = auth.identify(&HeaderMap::new(), &unknown).unwrap_err();
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        assert!(
            refusal.message.contains("client certificate"),
            "{refusal:?}"
        );
        assert_eq!(item(&auth, &[], &tls()), "net:0.0.0.0/0");
    }

    /// A request with no credential and no certificate gets the `net:` item
    /// with the longest prefix that holds its address. An IPv4-mapped IPv6
    /// address counts as its IPv4 address. A `net:` item wins over the
    /// anonymous item.
    #[test]
    fn a_net_item_with_the_longest_prefix_wins() {
        let (auth, _tmp) = auth(
            "[ex-ostrya client \"wide\"]\nauth=net:10.0.0.0/8;net:2001:db8::/32\nallow=w:**\n\
             [ex-ostrya client \"narrow\"]\nauth=net:10.0.1.0/24;net:2001:db8::/56\nallow=w:**\n\
             [ex-ostrya client \"anonymous\"]\nauth=anonymous\nallow=w:**\n",
        );
        for (addr, expected) in [
            ("10.0.1.7", "net:10.0.1.0/24"),
            ("10.0.2.7", "net:10.0.0.0/8"),
            ("::ffff:10.0.1.7", "net:10.0.1.0/24"),
            ("::ffff:10.9.0.1", "net:10.0.0.0/8"),
            ("2001:db8::1", "net:2001:db8::/56"),
            ("2001:db8:1::1", "net:2001:db8::/32"),
            ("192.0.2.1", "anonymous"),
            ("::1", "anonymous"),
        ] {
            assert_eq!(
                item(&auth, &[], &peer(false, addr, None)),
                expected,
                "{addr}"
            );
        }
    }

    /// With no credential, no certificate, and no `net:` match, a request
    /// gets the anonymous item. With no anonymous item, it gets 401 when a
    /// `token-sha256` or `basic-sha256` item exists, and 403 when none
    /// exists.
    #[test]
    fn a_request_with_nothing_is_anonymous_401_or_403() {
        let (auth, _tmp) = auth(&format!(
            "{}[ex-ostrya client \"anonymous\"]\nauth=anonymous\nallow=w:**\n",
            credentials()
        ));
        assert_eq!(item(&auth, &[], &tls()), "anonymous");
        let (auth, _tmp) = self::auth(&credentials());
        assert_eq!(refused(&auth, &[], &tls()), StatusCode::UNAUTHORIZED);
        let (auth, _tmp) =
            self::auth("[ex-ostrya client \"c\"]\nauth=tls:*;ssh:u;net:10.0.0.0/8\nallow=w:**\n");
        assert_eq!(refused(&auth, &[], &tls()), StatusCode::FORBIDDEN);
        assert_eq!(refused(&auth, &[], &plain()), StatusCode::FORBIDDEN);
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

    fn authenticate(auth: &GroupAuth, parts: &Parts) -> Result<Client, Refusal> {
        ostrya_rt::block_on(auth.authenticate(parts, RequestKind::Open))
    }

    /// `authenticate` reads the peer from the extensions of the request, and
    /// adds the two challenges to a 401 alone. The owner key is the text of
    /// the item. The route does not change the answer.
    #[test]
    fn authenticate_reads_the_peer_and_challenges_a_401_alone() {
        let (auth, _tmp) = auth(&format!(
            "{}[ex-ostrya client \"cert\"]\nauth=tls:*\nallow=w:**\n",
            credentials()
        ));
        let with_cert = peer(true, "192.0.2.1", Some(cert("cert", None)));
        let client = authenticate(&auth, &parts(&[], Some(with_cert))).unwrap();
        assert_eq!(GroupAuth::owner(&client), "tls:*");
        let token = parts(&["Bearer a-token"], Some(tls()));
        for kind in [
            RequestKind::Open,
            RequestKind::Have,
            RequestKind::Objects,
            RequestKind::Commit,
            RequestKind::Delete,
        ] {
            let client = ostrya_rt::block_on(auth.authenticate(&token, kind)).unwrap();
            let expected = format!("token-sha256:{}", hex("a-token"));
            assert_eq!(GroupAuth::owner(&client), expected);
        }

        let refusal = authenticate(&auth, &parts(&[], Some(tls()))).unwrap_err();
        assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
        let challenges: Vec<_> = CHALLENGES
            .into_iter()
            .map(|c| (WWW_AUTHENTICATE, HeaderValue::from_static(c)))
            .collect();
        assert_eq!(refusal.headers, challenges);

        let refusal = authenticate(&auth, &parts(&["Bearer a-token"], Some(plain()))).unwrap_err();
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        assert!(refusal.headers.is_empty());
    }

    /// In a build with debug assertions, a request with no peer panics.
    /// Otherwise it is plain HTTP with no client certificate, so a
    /// credential is 403.
    #[test]
    fn a_request_with_no_peer_is_plain_http() {
        let (auth, _tmp) = auth(&credentials());
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

    /// `open` gives the policy of the group that carries the item in the
    /// local refs. An item with no such group, and a group that opens no
    /// push session, get 403. A `tls:NAME` item whose groups do not cover
    /// the local refs gets 403, although a group of `tls:*` covers them.
    #[test]
    fn open_selects_the_group_of_the_item() {
        let (auth, _tmp) = auth(
            "[ex-ostrya client \"push\"]\nauth=anonymous;tls:*\nallow=w:**\n\
             [ex-ostrya client \"read\"]\nauth=ssh:r;net:10.0.0.0/8\nallow=r:**\n\
             [ex-ostrya client \"mirror\"]\nauth=tls:host\ncollection=*\nallow=w:**\n",
        );
        let hello = Hello {
            version: 1,
            agent: None,
            refs: vec!["main".into()],
            one_way: false,
        };
        let open = |text: &str| {
            let client = Client::new(AuthItem::parse(text).unwrap(), false);
            ostrya_rt::block_on(auth.open(&client, &hello))
        };
        for text in ["anonymous", "tls:*"] {
            let setup = open(text).unwrap_or_else(|r| panic!("{text}: {r:?}"));
            assert!(Arc::ptr_eq(
                &setup.policy,
                auth.policies.get("push").unwrap()
            ));
            assert_eq!(setup.policy.group.as_deref(), Some("push"));
            assert!(setup.hooks.is_none());
        }
        for (text, needle) in [
            (
                "net:10.0.0.0/8",
                "client group 'read' opens no push session",
            ),
            (
                "tls:host",
                "no client group of the request covers the local refs",
            ),
            (
                "tls:other",
                "no client group of the request covers the local refs",
            ),
        ] {
            let Err(refusal) = open(text) else {
                panic!("{text} opens a session");
            };
            assert_eq!(refusal.status, StatusCode::FORBIDDEN, "{text}");
            assert_eq!(refusal.message, needle, "{text}");
        }
    }

    const CA_PEM: &[u8] = include_bytes!("../../../tests/fixtures/tls/ca.pem");
    const CLIENT_PEM: &str = include_str!("../../../tests/fixtures/tls/client.pem");
    const SERVER_PEM: &str = include_str!("../../../tests/fixtures/tls/server.pem");

    /// The base64 of the DER bytes of the one certificate of `pem`.
    fn base64_der(pem: &str) -> String {
        pem.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect()
    }

    /// The authentication by `groups` behind the trusted proxies of
    /// 10.0.0.0/8, which forward the client address in `X-Forwarded-For` and
    /// the client certificate in `X-Client-Cert`. The fixture CA verifies the
    /// certificate.
    fn proxied(groups: &str) -> (GroupAuth, TmpRepo) {
        let (auth, tmp) = auth(groups);
        let forwarding = Forwarding::new(
            vec![IpNet::parse("10.0.0.0/8").unwrap()],
            ostrya::access::ForwardedHeader::XForwardedFor,
        );
        let verifier = ostrya_fetch::client_cert_verifier(CA_PEM).unwrap();
        let certs = ForwardedCerts::new(
            hyper::header::HeaderName::from_static("x-client-cert"),
            verifier,
        );
        (auth.with_proxies(Some(forwarding), Some(certs)), tmp)
    }

    /// The headers of the pairs `lines`.
    fn lines(lines: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in lines {
            headers.append(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn proxy() -> Peer {
        peer(false, "10.0.0.1", None)
    }

    fn stranger() -> Peer {
        peer(false, "192.0.2.9", None)
    }

    /// `X-Forwarded-Proto: https` from a trusted proxy passes the step of a
    /// credential over plain HTTP. From another peer, it has no effect.
    #[test]
    fn https_from_a_trusted_proxy_counts_as_tls() {
        let (auth, _tmp) = proxied(&credentials());
        let request = lines(&[
            ("authorization", "Bearer a-token"),
            ("x-forwarded-proto", "https"),
        ]);
        let found = auth.identify(&request, &proxy()).unwrap();
        assert_eq!(&*found.owner, format!("token-sha256:{}", hex("a-token")));
        let refusal = auth.identify(&request, &stranger()).unwrap_err();
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        assert!(refusal.message.contains("plain HTTP"), "{refusal:?}");
        let http = lines(&[
            ("authorization", "Bearer a-token"),
            ("x-forwarded-proto", "http"),
        ]);
        assert_eq!(auth.identify(&http, &proxy()).unwrap_err().status, 403);
    }

    /// A forwarded certificate from a trusted proxy matches `tls:NAME` and
    /// `tls-sha256:HEX`. From another peer, the server ignores it.
    #[test]
    fn a_forwarded_certificate_matches_the_tls_items() {
        let der = ostrya::base64::decode(&base64_der(CLIENT_PEM)).unwrap();
        let by_digest = format!("tls-sha256:{}", Checksum::sha256(&der).to_hex());
        for (groups, expected) in [
            (
                "[ex-ostrya client \"c\"]\nauth=tls:ostrya test\nallow=w:**\n\
                 [ex-ostrya client \"a\"]\nauth=anonymous\nallow=w:**\n"
                    .to_owned(),
                "tls:ostrya test".to_owned(),
            ),
            (
                format!(
                    "[ex-ostrya client \"c\"]\nauth={by_digest};tls:*\nallow=w:**\n\
                     [ex-ostrya client \"a\"]\nauth=anonymous\nallow=w:**\n"
                ),
                by_digest.clone(),
            ),
        ] {
            let (auth, _tmp) = proxied(&groups);
            let request = lines(&[("x-client-cert", &base64_der(CLIENT_PEM))]);
            assert_eq!(&*auth.identify(&request, &proxy()).unwrap().owner, expected);
            assert_eq!(
                &*auth.identify(&request, &stranger()).unwrap().owner,
                "anonymous"
            );
        }
    }

    /// A forwarded certificate that does not decode, that holds two
    /// certificates, or that the CA does not verify gets 403, also with an
    /// anonymous item. With an `Authorization` header, the credential
    /// decides first.
    #[test]
    fn a_bad_forwarded_certificate_is_403() {
        let (auth, _tmp) = proxied(&format!(
            "{}[ex-ostrya client \"a\"]\nauth=anonymous;tls:*\nallow=w:**\n",
            credentials()
        ));
        let client = base64_der(CLIENT_PEM);
        for (value, needle) in [
            ("!!!".to_owned(), "does not parse"),
            (format!("{client},{client}"), "more than one"),
            (base64_der(SERVER_PEM), "does not verify"),
        ] {
            let request = lines(&[("x-client-cert", &value)]);
            let refusal = auth.identify(&request, &proxy()).unwrap_err();
            assert_eq!(refusal.status, StatusCode::FORBIDDEN, "{value}");
            assert!(refusal.message.contains(needle), "{refusal:?}");
            let with_token = lines(&[
                ("x-client-cert", &value),
                ("authorization", "Bearer a-token"),
                ("x-forwarded-proto", "https"),
            ]);
            let found = auth.identify(&with_token, &proxy()).unwrap();
            assert_eq!(&*found.owner, format!("token-sha256:{}", hex("a-token")));
            assert_eq!(
                &*auth.identify(&request, &stranger()).unwrap().owner,
                "anonymous"
            );
        }
        let empty = lines(&[("x-client-cert", "")]);
        assert_eq!(
            &*auth.identify(&empty, &proxy()).unwrap().owner,
            "anonymous"
        );
    }

    /// From a trusted proxy with a header of a forwarded certificate, the
    /// header alone gives the certificate: with no header, or an empty
    /// header, the certificate of the handshake does not identify the
    /// client. From another peer, or with no header of a forwarded
    /// certificate, the certificate of the handshake applies.
    #[test]
    fn a_forwarded_certificate_replaces_the_handshake() {
        let groups = format!(
            "[ex-ostrya client \"c\"]\nauth=tls:ostrya test\nallow=w:**\n\
             [ex-ostrya client \"h\"]\nauth=tls-sha256:{}\nallow=w:**\n\
             [ex-ostrya client \"a\"]\nauth=anonymous\nallow=w:**\n",
            hex("handshake")
        );
        let (direct, _direct_tmp) = auth(&groups);
        let (auth, _tmp) = proxied(&groups);
        let handshake = peer(true, "10.0.0.1", Some(cert("handshake", Some("other"))));
        let request = lines(&[("x-client-cert", &base64_der(CLIENT_PEM))]);
        let by_handshake = format!("tls-sha256:{}", hex("handshake"));
        assert_eq!(
            &*auth.identify(&request, &handshake).unwrap().owner,
            "tls:ostrya test"
        );
        for request in [HeaderMap::new(), lines(&[("x-client-cert", "")])] {
            assert_eq!(
                &*auth.identify(&request, &handshake).unwrap().owner,
                "anonymous"
            );
        }
        let untrusted = peer(true, "192.0.2.9", Some(cert("handshake", Some("other"))));
        assert_eq!(
            &*auth.identify(&request, &untrusted).unwrap().owner,
            by_handshake
        );
        let forwarding = Forwarding::new(
            vec![IpNet::parse("10.0.0.0/8").unwrap()],
            ostrya::access::ForwardedHeader::XForwardedFor,
        );
        let auth = direct.with_proxies(Some(forwarding), None);
        assert_eq!(
            &*auth.identify(&request, &handshake).unwrap().owner,
            by_handshake
        );
    }

    /// A `net:` item matches the forwarded client address. A client with no
    /// address matches no `net:` item, and never takes the address of the
    /// proxy.
    #[test]
    fn a_net_item_matches_the_forwarded_address() {
        let (auth, _tmp) = proxied(
            "[ex-ostrya client \"farm\"]\nauth=net:192.0.2.0/24\nallow=w:**\n\
             [ex-ostrya client \"proxies\"]\nauth=net:10.0.0.0/8\nallow=w:**\n",
        );
        let request = |value: &str| lines(&[("x-forwarded-for", value)]);
        let owner = |value: &str, peer: &Peer| {
            auth.identify(&request(value), peer)
                .map(|client| client.owner.to_string())
                .map_err(|refusal| refusal.status)
        };
        assert_eq!(
            owner("192.0.2.7, 10.0.0.2", &proxy()).unwrap(),
            "net:192.0.2.0/24"
        );
        assert_eq!(owner("10.0.0.3", &proxy()).unwrap(), "net:10.0.0.0/8");
        assert_eq!(owner("unknown", &proxy()), Err(StatusCode::FORBIDDEN));
        assert_eq!(owner("", &proxy()).unwrap(), "net:10.0.0.0/8");
        assert_eq!(owner("10.9.9.9", &stranger()).unwrap(), "net:192.0.2.0/24");
    }

    /// The events that `auth` reports, in order.
    fn recording(auth: GroupAuth) -> (GroupAuth, Arc<std::sync::Mutex<Vec<ServerEvent>>>) {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = events.clone();
        let auth = auth.with_events(Some(Arc::new(move |event: &ServerEvent| {
            sink.lock().unwrap().push(event.clone());
        })));
        (auth, events)
    }

    fn hello() -> Hello {
        Hello {
            version: 1,
            agent: None,
            refs: vec!["main".into()],
            one_way: false,
        }
    }

    /// The setup of the session that a request with `headers` from `peer`
    /// opens.
    fn open_with(
        auth: &GroupAuth,
        headers: &HeaderMap,
        peer: &Peer,
    ) -> Result<SessionSetup, Refusal> {
        let client = auth.identify(headers, peer)?;
        ostrya_rt::block_on(auth.open(&client, &hello()))
    }

    /// A TLS peer with the certificate `der`.
    fn with_der(der: &[u8]) -> Peer {
        peer(true, "192.0.2.1", Some(ClientCert::from_der(der)))
    }

    /// The allow items and the deny items of `setup`, as text.
    fn rule_texts(setup: &SessionSetup) -> (Vec<String>, Vec<String>) {
        let rules = &setup.policy.rules;
        (
            rules.allow.iter().map(ToString::to_string).collect(),
            rules.deny.iter().map(|p| p.as_str().to_owned()).collect(),
        )
    }

    /// A group of `tls:*` that reads the claims, reads all refs, and accepts
    /// privileged content.
    const CLAIMS_GROUP: &str = "[ex-ostrya client \"certs\"]\nauth=tls:*\n\
                                tls-accept-claim=true\nallow=r:**\nallow-privileged=true\n";

    /// The claims of the local refs replace the allow items and the deny
    /// items of the group. The other values of the policy and the name of
    /// the group stay. Claims of a collection are ignored.
    #[test]
    fn the_claims_replace_the_rules_of_the_group() {
        let (auth, _tmp) = auth(CLAIMS_GROUP);
        let ca = TestCa::new();
        let der = ca.leaf(
            "c",
            &[
                "ostrya:ref:w:main",
                "ostrya:collection:a.b:d:x",
                "ostrya:ref:!main/secret",
            ],
        );
        let setup = open_with(&auth, &HeaderMap::new(), &with_der(&der)).unwrap();
        assert_eq!(
            rule_texts(&setup),
            (vec!["w:main".to_owned()], vec!["main/secret".to_owned()])
        );
        let group = auth.policies.get("certs").unwrap();
        assert!(!Arc::ptr_eq(&setup.policy, group));
        assert_eq!(setup.policy.group.as_deref(), Some("certs"));
        assert!(setup.policy.allow_privileged);
        assert_eq!(group.rules.allow[0].to_string(), "r:**");
    }

    /// With no claim of the local refs, also with claims of a collection
    /// alone, the rules of the group apply.
    #[test]
    fn with_no_claim_of_the_namespace_the_group_applies() {
        let (auth, _tmp) = auth(&CLAIMS_GROUP.replace("allow=r:**", "allow=w:**"));
        let ca = TestCa::new();
        let group = auth.policies.get("certs").unwrap();
        for uris in [
            &[][..],
            &["ostrya:collection:a.b:w:main", "https://example.com/"],
        ] {
            let setup = open_with(&auth, &HeaderMap::new(), &with_der(&ca.leaf("c", uris)))
                .unwrap_or_else(|r| panic!("{uris:?}: {r:?}"));
            assert!(Arc::ptr_eq(&setup.policy, group), "{uris:?}");
        }
    }

    /// The own collection id of the repository names the local refs in a
    /// claim.
    #[test]
    fn a_claim_of_the_own_collection_names_the_local_refs() {
        static N: AtomicU32 = AtomicU32::new(0);
        let tmp = TmpRepo::new(&format!("auth-own-{}", N.fetch_add(1, Ordering::Relaxed)));
        let config = tmp.repo.path().join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        let text = text.replacen("[core]\n", "[core]\ncollection-id=own.id\n", 1);
        std::fs::write(&config, text).unwrap();
        let auth = GroupAuth::new(tmp.policies(CLAIMS_GROUP), false);
        let der = TestCa::new().leaf("c", &["ostrya:collection:own.id:t:release/**"]);
        let setup = open_with(&auth, &HeaderMap::new(), &with_der(&der)).unwrap();
        assert_eq!(
            rule_texts(&setup),
            (vec!["t:release/**".to_owned()], Vec::new())
        );
    }

    /// Claims that open no push session get 403 with a message that names
    /// the claims, also where the group opens a push session.
    #[test]
    fn claims_with_no_push_mode_open_no_session() {
        let (auth, _tmp) = auth(&CLAIMS_GROUP.replace("allow=r:**", "allow=w:**"));
        let ca = TestCa::new();
        for uris in [&["ostrya:ref:!secret"][..], &["ostrya:ref:main"]] {
            let refusal = open_with(&auth, &HeaderMap::new(), &with_der(&ca.leaf("c", uris)))
                .err()
                .unwrap();
            assert_eq!(refusal.status, StatusCode::FORBIDDEN);
            assert_eq!(
                refusal.message,
                "the claims of the client certificate open no push session in client group \
                 'certs'"
            );
        }
    }

    /// Claims that do not parse get 403 at the open of a session, and the
    /// server reports one event that names the digest and the URI SAN. The
    /// identification of the request succeeds.
    #[test]
    fn claims_that_do_not_parse_get_403_and_an_event() {
        let (auth, _tmp) = auth(CLAIMS_GROUP);
        let (auth, events) = recording(auth);
        let ca = TestCa::new();
        let many: Vec<String> = (0..=ostrya::access::MAX_CLAIMS)
            .map(|i| format!("ostrya:ref:w:r{i}"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let san = crate::test_pki::uri_sans(&["ostrya:ref:w:main"]);
        for (der, san, reason) in [
            (
                ca.leaf("c", &["ostrya:ref:w:main", "ostrya:ref:x:a"]),
                Some("ostrya:ref:x:a"),
                "the modes are one or more of r, w, c, t, and d",
            ),
            (
                ca.leaf("c", &["Ostrya:ref:w:main"]),
                Some("Ostrya:ref:w:main"),
                "a claim starts with ostrya:ref: or ostrya:collection:ID:",
            ),
            (
                ca.leaf("c", &["ostrya:collection:a.b:x:y"]),
                Some("ostrya:collection:a.b:x:y"),
                "the modes are one or more of r, w, c, t, and d",
            ),
            (
                ca.leaf("c", &many),
                None,
                "the certificate holds more than 256 claims",
            ),
            (
                ca.leaf_with("c", None, &[vec![0x30, 0x03, 0x86, 0x01, 0x80]]),
                None,
                "the subjectAltName extension of the certificate does not decode",
            ),
            (
                ca.leaf_with("c", None, &[san.clone(), san.clone()]),
                None,
                "the certificate holds more than one subjectAltName extension",
            ),
            (
                b"not a certificate".to_vec(),
                None,
                "the certificate does not decode",
            ),
        ] {
            events.lock().unwrap().clear();
            let peer = with_der(&der);
            auth.identify(&HeaderMap::new(), &peer).unwrap();
            let refusal = open_with(&auth, &HeaderMap::new(), &peer).err().unwrap();
            assert_eq!(refusal.status, StatusCode::FORBIDDEN, "{san:?}");
            let fault = match san {
                Some(san) => format!("malformed claim '{san}': {reason}"),
                None => reason.to_owned(),
            };
            assert_eq!(
                refusal.message,
                format!("the claims of the client certificate do not parse: {fault}")
            );
            let digest = Checksum::sha256(&der);
            assert_eq!(
                *events.lock().unwrap(),
                [ServerEvent::BadClaims {
                    digest,
                    san: san.map(str::to_owned),
                    reason: reason.to_owned(),
                }]
            );
            assert_eq!(
                events.lock().unwrap()[0].to_string(),
                format!("refused the client certificate tls-sha256:{digest}: {fault}")
            );
        }
    }

    /// A group with `tls-accept-claim=false` reads no claim: claims that do
    /// not parse get no 403 and no event, and the owner key is the item.
    #[test]
    fn a_group_that_reads_no_claim_ignores_the_claims() {
        let (auth, _tmp) = auth("[ex-ostrya client \"certs\"]\nauth=tls:*\nallow=w:**\n");
        let (auth, events) = recording(auth);
        let ca = TestCa::new();
        for uris in [&["ostrya:ref:x:a"][..], &["ostrya:ref:r:main"]] {
            let peer = with_der(&ca.leaf("c", uris));
            let setup = open_with(&auth, &HeaderMap::new(), &peer).unwrap();
            assert!(Arc::ptr_eq(
                &setup.policy,
                auth.policies.get("certs").unwrap()
            ));
            let client = auth.identify(&HeaderMap::new(), &peer).unwrap();
            assert_eq!(&*client.owner, "tls:*");
            assert!(client.cert.is_none());
        }
        assert!(events.lock().unwrap().is_empty());
    }

    /// A credential, a `net:` item, and the anonymous item take no claims,
    /// also with a client certificate in the request.
    #[test]
    fn an_item_other_than_a_certificate_takes_no_claims() {
        let (auth, _tmp) = auth(&format!(
            "[ex-ostrya client \"mixed\"]\nauth=tls-sha256:{};token-sha256:{}\n\
             tls-accept-claim=true\nallow=w:**\n\
             [ex-ostrya client \"anonymous\"]\nauth=anonymous\nallow=w:**\n",
            hex("unused"),
            hex("a-token")
        ));
        let (auth, events) = recording(auth);
        let der = TestCa::new().leaf("c", &["ostrya:ref:x:a"]);
        let peer = with_der(&der);
        let token = headers(&["Bearer a-token"]);
        let setup = open_with(&auth, &token, &peer).unwrap();
        assert!(Arc::ptr_eq(
            &setup.policy,
            auth.policies.get("mixed").unwrap()
        ));
        let client = auth.identify(&token, &peer).unwrap();
        assert_eq!(&*client.owner, format!("token-sha256:{}", hex("a-token")));
        let setup = open_with(&auth, &HeaderMap::new(), &tls()).unwrap();
        assert!(Arc::ptr_eq(
            &setup.policy,
            auth.policies.get("anonymous").unwrap()
        ));
        assert!(events.lock().unwrap().is_empty());
    }

    /// With a group that reads claims, the owner key of a certificate item
    /// is the digest of the certificate, so two certificates of one item
    /// have two owner keys.
    #[test]
    fn the_owner_key_is_the_digest_of_a_certificate_with_claims() {
        let (auth, _tmp) = auth(CLAIMS_GROUP);
        let ca = TestCa::new();
        let a = ca.leaf("a", &["ostrya:ref:w:a"]);
        let b = ca.leaf("b", &["ostrya:ref:w:b"]);
        let owner = |der: &[u8]| {
            let client = auth.identify(&HeaderMap::new(), &with_der(der)).unwrap();
            GroupAuth::owner(&client).to_owned()
        };
        assert_eq!(owner(&a), format!("tls-sha256:{}", Checksum::sha256(&a)));
        assert_ne!(owner(&a), owner(&b));
    }

    /// A `tls:NAME` item can hold a space. The item `tls:* tls-sha256:HEX`
    /// of a group that reads no claim and the certificate of that digest
    /// under `tls:*` of a group that reads claims have two owner keys.
    #[test]
    fn a_name_with_a_space_shares_no_owner_key_with_a_digest() {
        let ca = TestCa::new();
        let pinned = ca.leaf("pinned", &[]);
        let digest = Checksum::sha256(&pinned);
        let (auth, _tmp) = auth(&format!(
            "{CLAIMS_GROUP}[ex-ostrya client \"named\"]\n\
             auth=tls:* tls-sha256:{digest}\nallow=r:**\n"
        ));
        let named = ca.leaf(&format!("* tls-sha256:{digest}"), &[]);
        let owner = |der: &[u8]| {
            let client = auth.identify(&HeaderMap::new(), &with_der(der)).unwrap();
            GroupAuth::owner(&client).to_owned()
        };
        assert_eq!(owner(&named), format!("tls:* tls-sha256:{digest}"));
        assert_eq!(owner(&pinned), format!("tls-sha256:{digest}"));
        assert_ne!(owner(&named), owner(&pinned));
    }

    /// The claims of a forwarded certificate replace the rules of the group,
    /// as the claims of the certificate of a handshake do.
    #[test]
    fn a_forwarded_certificate_takes_its_claims() {
        let ca = TestCa::new();
        let (auth, _tmp) = auth(CLAIMS_GROUP);
        let forwarding = Forwarding::new(
            vec![IpNet::parse("10.0.0.0/8").unwrap()],
            ostrya::access::ForwardedHeader::XForwardedFor,
        );
        let verifier = ostrya_fetch::client_cert_verifier(ca.pem.as_bytes()).unwrap();
        let certs = ForwardedCerts::new(
            hyper::header::HeaderName::from_static("x-client-cert"),
            verifier,
        );
        let auth = auth.with_proxies(Some(forwarding), Some(certs));
        let (auth, events) = recording(auth);
        let good = ca.leaf("c", &["ostrya:ref:c:main"]);
        let request = lines(&[("x-client-cert", &ostrya::base64::encode(&good))]);
        let setup = open_with(&auth, &request, &proxy()).unwrap();
        assert_eq!(rule_texts(&setup), (vec!["c:main".to_owned()], Vec::new()));
        let bad = ca.leaf("c", &["ostrya:ref:c:main/"]);
        let request = lines(&[("x-client-cert", &ostrya::base64::encode(&bad))]);
        let refusal = open_with(&auth, &request, &proxy()).err().unwrap();
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], ServerEvent::BadClaims { digest, san: Some(san), .. }
                if *digest == Checksum::sha256(&bad) && san == "ostrya:ref:c:main/"),
            "{events:?}"
        );
    }

    /// A read takes the steps of the identification: a 401 carries the two
    /// challenges, a credential over plain HTTP gets 403, and a request
    /// with nothing gets the anonymous item. A `net:` item matches the
    /// address that a trusted proxy forwards. The rights carry the item.
    #[test]
    fn a_read_takes_the_steps_of_the_identification() {
        let (auth, _tmp) = proxied(&format!(
            "{}[ex-ostrya client \"farm\"]\nauth=net:198.51.100.0/24\nallow=r:farm/**\n\
             [ex-ostrya client \"anonymous\"]\nauth=anonymous\nallow=r:pub/**\n",
            credentials()
        ));
        let refusal = auth
            .identify_read(&headers(&["Bearer x", "Bearer y"]), &tls())
            .unwrap_err();
        assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
        assert_eq!(refusal.headers.len(), 2);
        let refusal = auth
            .identify_read(&headers(&["Bearer a-token"]), &stranger())
            .unwrap_err();
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        assert!(refusal.headers.is_empty());

        let read = auth.identify_read(&HeaderMap::new(), &stranger()).unwrap();
        assert_eq!(read.item(), &AuthItem::Anonymous);
        assert!(read.can_read_path("refs/heads/pub/a"));
        assert!(!read.can_read_path("refs/heads/farm/a"));
        let forwarded = lines(&[("x-forwarded-for", "198.51.100.7")]);
        let read = auth.identify_read(&forwarded, &proxy()).unwrap();
        assert_eq!(read.item().to_string(), "net:198.51.100.0/24");
        assert!(read.can_read_path("refs/heads/farm/a"));
        assert!(!read.can_read_path("refs/heads/pub/a"));
        let read = auth
            .identify_read(&headers(&["Bearer a-token"]), &tls())
            .unwrap();
        assert!(read.can_read_path("refs/heads/any"));
        assert!(!read.serves_summary());

        let (auth, _tmp) = self::auth(&credentials());
        let refusal = auth.identify_read(&HeaderMap::new(), &tls()).unwrap_err();
        assert_eq!(refusal.status, StatusCode::UNAUTHORIZED);
        assert_eq!(refusal.headers.len(), 2);
    }

    /// The claims of a certificate set the read rights in a group with
    /// `tls-accept-claim=true`. Claims that do not parse refuse each read
    /// with 403, and the server reports one event for each read.
    #[test]
    fn claims_set_the_read_rights_and_bad_claims_refuse_a_read() {
        let (auth, _tmp) = auth(CLAIMS_GROUP);
        let (auth, events) = recording(auth);
        let ca = TestCa::new();
        let good = with_der(&ca.leaf("c", &["ostrya:ref:r:main"]));
        let read = auth.identify_read(&HeaderMap::new(), &good).unwrap();
        assert!(read.can_read_path("refs/heads/main"));
        assert!(!read.can_read_path("refs/heads/other"));
        let plain = with_der(&ca.leaf("c", &[]));
        let read = auth.identify_read(&HeaderMap::new(), &plain).unwrap();
        assert!(read.can_read_path("refs/heads/other"));
        assert!(events.lock().unwrap().is_empty());

        let der = ca.leaf("c", &["ostrya:ref:x:a"]);
        let bad = with_der(&der);
        for _ in 0..2 {
            let refusal = auth.identify_read(&HeaderMap::new(), &bad).unwrap_err();
            assert_eq!(refusal.status, StatusCode::FORBIDDEN);
            assert!(refusal.headers.is_empty());
        }
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            matches!(&events[0], ServerEvent::BadClaims { digest, .. }
                if *digest == Checksum::sha256(&der)),
            "{events:?}"
        );
    }

    /// A group with `tls-accept-claim=false` reads no claim on a read:
    /// claims that do not parse get no 403 and no event.
    #[test]
    fn a_read_of_a_group_that_reads_no_claim_ignores_the_claims() {
        let (auth, _tmp) = auth("[ex-ostrya client \"certs\"]\nauth=tls:*\nallow=r:**\n");
        let (auth, events) = recording(auth);
        let peer = with_der(&TestCa::new().leaf("c", &["ostrya:ref:x:a"]));
        let read = auth.identify_read(&HeaderMap::new(), &peer).unwrap();
        assert!(read.can_read_path("refs/heads/main"));
        assert!(events.lock().unwrap().is_empty());
    }

    /// The time of the request checks the validity of a forwarded
    /// certificate.
    #[test]
    fn an_expired_forwarded_certificate_is_403() {
        let (auth, _tmp) = proxied("[ex-ostrya client \"c\"]\nauth=tls:*\nallow=w:**\n");
        let request = lines(&[("x-client-cert", &base64_der(CLIENT_PEM))]);
        let late = UnixTime::since_unix_epoch(std::time::Duration::from_secs(4_938_667_341));
        let refusal = auth.identify_at(&request, &proxy(), late).unwrap_err();
        assert_eq!(refusal.status, StatusCode::FORBIDDEN);
        assert_eq!(&*auth.identify(&request, &proxy()).unwrap().owner, "tls:*");
    }
}
