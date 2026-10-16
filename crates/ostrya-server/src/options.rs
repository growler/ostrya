//! The options of a server.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ostrya::access::{ForwardedHeader, IpNet};
use ostrya::{ReceivePolicies, ReceiveReport};

use crate::endpoint::EndpointOptions;
use crate::event::EventSink;

/// The PEM bytes of the server TLS files.
///
/// The caller reads each file once at start.
#[derive(Clone, Eq, PartialEq)]
pub struct ServerTls {
    /// The server certificate, followed by any intermediates.
    pub cert_chain_pem: Vec<u8>,
    /// The private key of the certificate: plain, or encrypted PKCS#8 under
    /// PBES2.
    pub key_pem: Vec<u8>,
    /// The passphrase of an encrypted key.
    pub key_passphrase: Option<String>,
}

/// The debug text holds no byte of the private key or of the passphrase. It
/// shows the key as `<N bytes redacted>`, and a passphrase that is set as
/// `<redacted>`.
impl fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTls")
            .field("cert_chain_pem", &self.cert_chain_pem)
            .field(
                "key_pem",
                &format!("<{} bytes redacted>", self.key_pem.len()),
            )
            .field(
                "key_passphrase",
                &self.key_passphrase.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The options of [`bind`](crate::bind).
///
/// The struct is `#[non_exhaustive]`, so a caller starts from
/// [`ServeOptions::default`] and sets the fields.
///
/// [`bind`](crate::bind) checks the fields that go together. Its
/// [errors](crate::bind#errors) list the refusals.
///
/// The fields `parallel_uploads`, `session_idle_timeout`, `max_sessions`, and
/// `on_report` go to the [`EndpointOptions`] of the receive endpoint. Their
/// defaults are the defaults of [`EndpointOptions::default`]. If
/// [`receive`](ServeOptions::receive) is `None`, [`bind`](crate::bind) does
/// not read these four fields, `allow_cleartext_credentials`, or `on_event`.
/// It then refuses no value of them.
///
/// # Authentication
///
/// The server identifies the client of each request of the receive endpoint
/// by the auth items of the client groups of
/// [`receive`](ServeOptions::receive). Identification gives one auth item.
/// The server takes the first step that applies:
///
/// 1. A request with more than one `Authorization` header gets 401.
/// 2. If the connection has no TLS, a bearer or Basic credential gets 403,
///    unless
///    [`allow_cleartext_credentials`](ServeOptions::allow_cleartext_credentials)
///    is set, or a trusted proxy states the scheme `https` (see
///    [Client address](ServeOptions#client-address)).
/// 3. A request with an `Authorization` header gets the item of its
///    credential. A bearer token, `Authorization: Bearer TOKEN`, gets the
///    `token-sha256:HEX` item of the SHA-256 digest of the token. A Basic
///    credential, `Authorization: Basic` with the base64 of `USER:PASSWORD`,
///    gets the `basic-sha256:USER:HEX` item of the user name and of the
///    digest of the password. The user name runs to the first `:`, so the
///    password can hold `:`. A credential that matches no item gets 401, also
///    when the request has a client certificate. An empty token, a Basic
///    credential with no `:`, a user name that is not UTF-8, an empty
///    password, and another scheme match no item.
/// 4. A request with a client certificate gets the first item that matches,
///    in this order: `tls-sha256:HEX` by the SHA-256 digest of the DER
///    bytes, `tls:NAME` by the subject CN, `tls:*`. A certificate that
///    matches no item gets 403. A subject matches `tls:NAME` only if it holds
///    exactly one CN, of type UTF8String or PrintableString. From a trusted
///    proxy with a header of a forwarded certificate, the certificate comes
///    from that header alone, and never from the TLS handshake (see
///    [Forwarded certificate](ServeOptions#forwarded-certificate)).
/// 5. A request whose client address is in the network of a `net:` item gets
///    that item. When two items match, the item with the longer prefix wins.
/// 6. A request gets the `anonymous` item, if one exists.
/// 7. Else the request gets 401 when a `token-sha256` or a `basic-sha256`
///    item exists, and 403 when none exists.
///
/// The server compares the digest of a credential with every `token-sha256`
/// or `basic-sha256` item in constant time. It does not stop at a match. The
/// TLS handshake verifies a client certificate against
/// [`client_ca_pem`](ServeOptions::client_ca_pem). The server reads the
/// certificate of the handshake one time for each connection.
///
/// Each 401 carries two headers: `WWW-Authenticate: Bearer realm="ostrya"`
/// and `WWW-Authenticate: Basic realm="ostrya"`.
///
/// The owner key of a request is the text of its item, as
/// [`AuthItem`](ostrya::access::AuthItem) writes it. All clients with one
/// item share one owner key, for example all anonymous clients. A client
/// certificate that gives a `tls:*`, `tls:NAME`, or `tls-sha256:HEX` item of
/// a group with `tls-accept-claim=true` has the key `tls-sha256:HEX`, the
/// SHA-256 digest of its DER bytes. So two certificates with different
/// claims never share a session. This key is the key of no other client:
/// the certificate sets the item that it matches, and only the certificate
/// of that digest matches the item `tls-sha256:HEX`.
///
/// A `session` request selects the client group that carries the item in the
/// local refs, with
/// [`ReceivePolicies::select`](ostrya::ReceivePolicies::select). `Hello`
/// names no collection, so the namespace of each session is the local refs.
/// The session gets the policy of that group and no hooks. With no such
/// group, and with a group that opens no push session, the request gets 403.
///
/// # Claims
///
/// A client group with `tls-accept-claim=true` reads the claims of the client
/// certificate that gives the item of a `session` request: the URI SANs with
/// the scheme `ostrya`, as [`Claims`](ostrya::access::Claims) reads them.
/// The claims of the certificate of the TLS handshake are read one time for
/// each connection. The claims of a forwarded certificate are read one time
/// for each cache entry.
///
/// - When the certificate holds one or more claims for the namespace of the
///   session, as
///   [`ClientAccess::claim_rules`](ostrya::access::ClientAccess::claim_rules)
///   gives them, they replace the allow items and the deny items of the
///   group. The other values of the policy come from the group.
/// - When it holds no claim for the namespace, the rules of the group apply.
/// - When the claims do not parse, the request gets 403, and the server
///   reports a [`ServerEvent::BadClaims`](crate::ServerEvent::BadClaims) to
///   [`on_event`](ServeOptions::on_event). The claims do not parse when a
///   URI with the scheme `ostrya`, in any case, is no claim form, when the
///   certificate holds more than [`MAX_CLAIMS`](ostrya::access::MAX_CLAIMS)
///   such URIs, when the certificate does not decode, when it holds more
///   than one subjectAltName extension, and when its subjectAltName
///   extension does not decode. Each case has its own reason.
/// - When the rules of the claims open no push session, the request gets
///   403.
///
/// A group with `tls-accept-claim=false`, a credential, a `net:` item, and the
/// `anonymous` item read no claim.
///
/// # Client address
///
/// The client address is the TCP peer address of the connection, with these
/// changes:
///
/// - With [`proxy_protocol`](ServeOptions::proxy_protocol), the source
///   address of the PROXY header replaces the peer address. A header with
///   no address keeps the peer address.
/// - When the peer address is in
///   [`trusted_proxies`](ServeOptions::trusted_proxies), the server reads
///   the client address from the one header of
///   [`trusted_proxy_header`](ServeOptions::trusted_proxy_header). It walks
///   the hops of the header from the right, and skips each hop whose address
///   is in a trusted network. The first other hop is the client. When all
///   hops are trusted, the client is the leftmost hop. A hop with no
///   address, for example `unknown`, gives a client with no address, which
///   matches no `net:` item. A header that is absent, or that has one line
///   of white space alone, keeps the peer address. A header that is not
///   UTF-8, that does not parse, or that has text and no hop, for example
///   `X-Forwarded-For: , ,`, gives no address.
/// - From a trusted peer, the request counts as TLS for step 2 when the
///   proxy states the scheme `https`, in any case. With
///   [`ForwardedHeader::Forwarded`], the scheme is the `proto` of the
///   selected hop. With the other headers, it is the rightmost value of
///   `X-Forwarded-Proto`.
/// - From a peer that is not trusted, the server reads no forwarding header,
///   no `X-Forwarded-Proto`, and no forwarded certificate.
///
/// An IPv4-mapped IPv6 address counts as its IPv4 address.
///
/// With [`proxy_protocol`](ServeOptions::proxy_protocol), the server compares
/// the source address of the PROXY header with
/// [`trusted_proxies`](ServeOptions::trusted_proxies), so it does not read
/// the forwarding headers and the forwarded certificate of a proxy that
/// states the address of its client in the PROXY header.
///
/// A trusted proxy must set or remove the forwarding header, the
/// `X-Forwarded-Proto` header, and the header of a forwarded certificate of
/// each request. Else a client can send these headers through the proxy and
/// take another address or another certificate.
///
/// # Forwarded certificate
///
/// [`trusted_proxy_client_cert`](ServeOptions::trusted_proxy_client_cert)
/// names the request header that carries the client certificate from a
/// trusted proxy. The server reads the header for each request, and never
/// keeps the result for a connection, because a proxy sends the requests of
/// many clients over one connection. The value is one of these forms, after
/// the server percent-decodes it, with `+` kept as `+`:
///
/// - a PEM certificate that starts with `-----BEGIN`, as nginx
///   `$ssl_client_escaped_cert` gives it URL-escaped;
/// - the base64 of the DER bytes, as HAProxy `ssl_c_der,base64` gives it, or
///   URL-escaped, as Traefik `passTLSClientCert` gives it.
///
/// From a trusted proxy, this header alone gives the certificate. The server
/// does not use the certificate of the TLS handshake, which is the
/// certificate of the proxy. A request with no such header gives no
/// certificate. From a peer that is not trusted, or with no
/// `trusted_proxy_client_cert`, the certificate of the TLS handshake applies.
///
/// An empty value, or white space alone, is no certificate. These cases get
/// 403: a value with a comma, as the chain of Traefik holds; more than one
/// line of the header; PEM with more than one `CERTIFICATE` section; a value
/// that does not decode; and a certificate that
/// [`client_ca_pem`](ServeOptions::client_ca_pem) does not verify. The
/// server uses no intermediate certificate from the proxy, so the client CA
/// must hold each intermediate CA. The verification checks the validity
/// period and the `clientAuth` extended key usage.
///
/// The server keeps each verified certificate in a cache of 1024 entries,
/// keyed by the SHA-256 digest of its DER bytes, until the end of its
/// validity period. A full cache removes its oldest entry. The cache keeps
/// no refusal.
#[derive(Clone)]
#[non_exhaustive]
pub struct ServeOptions {
    /// The addresses to listen on.
    ///
    /// Port 0 lets the kernel choose a port, which
    /// [`Server::local_addrs`](crate::Server::local_addrs) reports.
    /// [`bind`](crate::bind) refuses an empty list. The default is
    /// `127.0.0.1:8080`.
    pub listen: Vec<SocketAddr>,
    /// The TLS files, or `None` for plain HTTP. The default is `None`.
    pub tls: Option<ServerTls>,
    /// The PEM CA certificates that verify the client certificate of the TLS
    /// handshake and a forwarded certificate, or `None`.
    ///
    /// [`bind`](crate::bind) builds one verifier from the certificates, and
    /// the handshake and each forwarded certificate use it. The server also
    /// serves a client that presents no certificate. A client that presents
    /// a certificate that the CA did not sign fails the handshake. The field
    /// needs [`tls`](ServeOptions::tls) or
    /// [`trusted_proxy_client_cert`](ServeOptions::trusted_proxy_client_cert).
    /// The default is `None`.
    pub client_ca_pem: Option<Vec<u8>>,
    /// The networks of the peers whose forwarding data the server reads.
    ///
    /// [Client address](ServeOptions#client-address) states the rules. A
    /// non-empty list needs
    /// [`trusted_proxy_header`](ServeOptions::trusted_proxy_header). The
    /// default is an empty list, which trusts no peer.
    pub trusted_proxies: Vec<IpNet>,
    /// The request header from which the server reads the client address of
    /// a request from a trusted proxy, or `None`.
    ///
    /// The server reads this one header, and no other header of a client
    /// address. The field needs a non-empty
    /// [`trusted_proxies`](ServeOptions::trusted_proxies). The default is
    /// `None`.
    pub trusted_proxy_header: Option<ForwardedHeader>,
    /// The name of the request header that carries the client certificate
    /// from a trusted proxy, or `None`.
    ///
    /// [Forwarded certificate](ServeOptions#forwarded-certificate) states the
    /// rules. The name passes [`ostrya::access::is_header_name`]. The field
    /// needs [`client_ca_pem`](ServeOptions::client_ca_pem) and a non-empty
    /// [`trusted_proxies`](ServeOptions::trusted_proxies). The default is
    /// `None`.
    pub trusted_proxy_client_cert: Option<String>,
    /// The switch that reads a PROXY protocol header, version 1 or 2, at the
    /// start of each connection.
    ///
    /// With the switch, each listener reads the header before the TLS
    /// handshake and before the first request. Its source address replaces
    /// the peer address. A header with no address, for example `UNKNOWN` or
    /// `LOCAL`, keeps the peer address. The server closes a connection with
    /// no valid header, or with no header within 30 seconds, and writes no
    /// byte to it. The default is `false`.
    ///
    /// Each peer that can connect states its own client address in the
    /// header. Only the proxy must be able to reach the listener.
    pub proxy_protocol: bool,
    /// The longest time that a response body waits for the client to take its
    /// next bytes.
    ///
    /// If a body waits longer, its connection ends. The bodies of the
    /// connection then drop and release the files and the compressors that
    /// they hold. An HTTP/2 connection sends a ping after half this time with
    /// no frame from the peer. It ends if the peer does not answer within
    /// this time.
    ///
    /// A body that waits for its own reader, for example for a compressor of
    /// the archive view, does not wait for the client. The time does not
    /// count for such a body until it gives its next frame.
    ///
    /// The default is 60 seconds. [`bind`](crate::bind) refuses zero.
    pub body_timeout: Duration,
    /// The client groups of the receive endpoint and their policies, or
    /// `None` for a read-only server.
    ///
    /// The default is `None`.
    /// [`ReceivePolicies::from_config`](ostrya::ReceivePolicies::from_config)
    /// builds the value from the repository config.
    /// [Authentication](ServeOptions#authentication) states how a request
    /// gets its group. The server does not read the groups or a repository
    /// setting of the endpoint again while it runs. A change takes effect at
    /// the next start.
    pub receive: Option<Arc<ReceivePolicies>>,
    /// The switch that takes a bearer or Basic credential on a connection
    /// without TLS.
    ///
    /// The default is `false`. If the switch is `false`, the endpoint refuses
    /// such a credential with 403, unless a trusted proxy states the scheme
    /// `https`. A server on a loopback address, or behind a proxy that
    /// terminates TLS and is not in
    /// [`trusted_proxies`](ServeOptions::trusted_proxies), can set it. A
    /// read-only server does not read the field.
    pub allow_cleartext_credentials: bool,
    /// The number of object streams of one session, as in
    /// [`EndpointOptions::parallel_uploads`].
    ///
    /// The default is 4.
    pub parallel_uploads: u32,
    /// The idle timeout of a session, as in
    /// [`EndpointOptions::session_idle_timeout`].
    ///
    /// The default is 300 seconds.
    pub session_idle_timeout: Duration,
    /// The most sessions open at the same time, as in
    /// [`EndpointOptions::max_sessions`].
    ///
    /// The default is 16.
    pub max_sessions: usize,
    /// The callback for the report of a committed session, as in
    /// [`EndpointOptions::on_report`].
    pub on_report: Option<Arc<dyn Fn(ReceiveReport) + Send + Sync>>,
    /// The callback for each [`ServerEvent`](crate::ServerEvent) of the
    /// receive endpoint, or `None`.
    ///
    /// The server calls it in the task of the request, so the callback must
    /// return soon. A host writes the event to its log, for example the
    /// [`Display`](std::fmt::Display) text of the event on standard error.
    /// The default is `None`, which drops each event.
    pub on_event: Option<EventSink>,
}

/// The debug text shows a callback that is set as `<callback>`, a
/// client CA that is set as `<N bytes>`, the trusted proxies as networks,
/// and the receive policies as the
/// names of their client groups. It holds no auth item, so no digest and no
/// user name.
impl fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeOptions")
            .field("listen", &self.listen)
            .field("tls", &self.tls)
            .field(
                "client_ca_pem",
                &self
                    .client_ca_pem
                    .as_ref()
                    .map(|pem| format!("<{} bytes>", pem.len())),
            )
            .field(
                "trusted_proxies",
                &self
                    .trusted_proxies
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
            .field("trusted_proxy_header", &self.trusted_proxy_header)
            .field("trusted_proxy_client_cert", &self.trusted_proxy_client_cert)
            .field("proxy_protocol", &self.proxy_protocol)
            .field("body_timeout", &self.body_timeout)
            .field(
                "receive",
                &self.receive.as_ref().map(|policies| {
                    policies
                        .access()
                        .groups()
                        .iter()
                        .map(|group| group.name())
                        .collect::<Vec<_>>()
                }),
            )
            .field(
                "allow_cleartext_credentials",
                &self.allow_cleartext_credentials,
            )
            .field("parallel_uploads", &self.parallel_uploads)
            .field("session_idle_timeout", &self.session_idle_timeout)
            .field("max_sessions", &self.max_sessions)
            .field("on_report", &self.on_report.as_ref().map(|_| "<callback>"))
            .field("on_event", &self.on_event.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        let endpoint = EndpointOptions::default();
        ServeOptions {
            listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))],
            tls: None,
            client_ca_pem: None,
            trusted_proxies: Vec::new(),
            trusted_proxy_header: None,
            trusted_proxy_client_cert: None,
            proxy_protocol: false,
            body_timeout: Duration::from_secs(60),
            receive: None,
            allow_cleartext_credentials: false,
            parallel_uploads: endpoint.parallel_uploads,
            session_idle_timeout: endpoint.session_idle_timeout,
            max_sessions: endpoint.max_sessions,
            on_report: endpoint.on_report,
            on_event: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use ostrya::Checksum;

    use super::*;
    use crate::session::tests::TmpRepo;

    #[test]
    fn debug_redacts_the_key_and_the_passphrase() {
        let tls = ServerTls {
            cert_chain_pem: b"cert".to_vec(),
            key_pem: b"secret key".to_vec(),
            key_passphrase: Some("secret passphrase".into()),
        };
        let text = format!("{tls:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(text.contains("<10 bytes redacted>"), "{text}");
    }

    #[test]
    fn debug_shows_no_auth_item_of_the_receive_policies() {
        let token = Checksum::sha256(b"a-token").to_hex();
        let password = Checksum::sha256(b"a-pass").to_hex();
        let tmp = TmpRepo::new("options-debug");
        let options = ServeOptions {
            receive: Some(tmp.policies(&format!(
                "[ex-ostrya client \"pushers\"]\n\
                 auth=token-sha256:{token};basic-sha256:alice:{password}\n\
                 allow=w:**\n"
            ))),
            ..ServeOptions::default()
        };
        let text = format!("{options:?}");
        assert!(text.contains("\"pushers\""), "{text}");
        assert!(!text.contains(&token), "{text}");
        assert!(!text.contains(&password), "{text}");
        assert!(!text.contains("alice"), "{text}");
    }
}
