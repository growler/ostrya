//! The options of a server.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ostrya::{ReceivePolicies, ReceiveReport};

use crate::endpoint::EndpointOptions;

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
    /// The CA against which the server verifies client certificates. The
    /// server also serves a client that presents no certificate.
    pub client_ca_pem: Option<Vec<u8>>,
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
            .field("client_ca_pem", &self.client_ca_pem)
            .finish()
    }
}

/// The options of [`bind`](crate::bind).
///
/// The struct is `#[non_exhaustive]`, so a caller starts from
/// [`ServeOptions::default`] and sets the fields.
///
/// The fields `parallel_uploads`, `session_idle_timeout`, `max_sessions`, and
/// `on_report` go to the [`EndpointOptions`] of the receive endpoint. Their
/// defaults are the defaults of [`EndpointOptions::default`]. If
/// [`receive`](ServeOptions::receive) is `None`, [`bind`](crate::bind) does
/// not read these four fields or `allow_cleartext_credentials`. It then
/// refuses no value of them.
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
///    is set.
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
///    exactly one CN, of type UTF8String or PrintableString.
/// 5. A request whose peer address is in the network of a `net:` item gets
///    that item. When two items match, the item with the longer prefix wins.
/// 6. A request gets the `anonymous` item, if one exists.
/// 7. Else the request gets 401 when a `token-sha256` or a `basic-sha256`
///    item exists, and 403 when none exists.
///
/// The server compares the digest of a credential with every `token-sha256`
/// or `basic-sha256` item in constant time. It does not stop at a match. The
/// TLS handshake verifies a client certificate against the client CA of
/// [`tls`](ServeOptions::tls). The server reads the certificate one time for
/// each connection.
///
/// Each 401 carries two headers: `WWW-Authenticate: Bearer realm="ostrya"`
/// and `WWW-Authenticate: Basic realm="ostrya"`.
///
/// The owner key of a request is the text of its item, as
/// [`AuthItem`](ostrya::access::AuthItem) writes it. All clients with one
/// item share one owner key, for example all anonymous clients.
///
/// A `session` request selects the client group that carries the item in the
/// local refs, with
/// [`ReceivePolicies::select`](ostrya::ReceivePolicies::select). `Hello`
/// names no collection, so the namespace of each session is the local refs.
/// The session gets the policy of that group and no hooks. With no such
/// group, and with a group that opens no push session, the request gets 403.
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
    /// such a credential with 403. A server on a loopback address or behind a
    /// proxy that terminates TLS can set it. A read-only server does not read
    /// the field.
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
}

/// The debug text shows a report callback that is set as `<callback>`, and
/// the receive policies as the names of their client groups. It holds no auth
/// item, so no digest and no user name.
impl fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeOptions")
            .field("listen", &self.listen)
            .field("tls", &self.tls)
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
            .finish()
    }
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        let endpoint = EndpointOptions::default();
        ServeOptions {
            listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))],
            tls: None,
            body_timeout: Duration::from_secs(60),
            receive: None,
            allow_cleartext_credentials: false,
            parallel_uploads: endpoint.parallel_uploads,
            session_idle_timeout: endpoint.session_idle_timeout,
            max_sessions: endpoint.max_sessions,
            on_report: endpoint.on_report,
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
            client_ca_pem: None,
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
