//! The options of a server.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ostrya::{ReceivePolicy, ReceiveReport};

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
/// not read these four fields, `allow_anonymous_push`, `credentials`, or
/// `allow_cleartext_credentials`. It then refuses no value of them.
///
/// # Authentication
///
/// The server runs the receive endpoint with built-in authentication methods.
/// Each session gets the policy of [`receive`](ServeOptions::receive) and no
/// hooks. The methods are:
///
/// - A bearer token, `Authorization: Bearer TOKEN`. It matches a line of
///   [`credentials`](ServeOptions::credentials) by the SHA-256 digest of the
///   token. An empty token matches no line.
/// - A Basic credential, `Authorization: Basic` with the base64 of
///   `NAME:TOKEN`. It matches the line of `NAME` by the digest of the token.
///   The token runs from the first `:` to the end, so it can hold `:`. A
///   credential with no `:`, a name that is not UTF-8, and an empty token
///   match no line.
/// - A client certificate that the TLS handshake verified against the client
///   CA of [`tls`](ServeOptions::tls).
/// - [`allow_anonymous_push`](ServeOptions::allow_anonymous_push), for a
///   request with no credential.
///
/// [`bind`](crate::bind) refuses an endpoint with no method. If the server
/// has no TLS, [`bind`](crate::bind) also refuses an endpoint whose one method
/// is the credential file, unless
/// [`allow_cleartext_credentials`](ServeOptions::allow_cleartext_credentials)
/// is set. No request can pass that method, because the endpoint refuses
/// each credential over plain HTTP.
///
/// The server compares the digest of a request with the digest of each line
/// in constant time. It does not stop at a match. The checks run in this
/// order:
///
/// 1. A request with more than one `Authorization` header gets 401.
/// 2. If the connection has no TLS, a bearer or Basic credential gets 403,
///    unless
///    [`allow_cleartext_credentials`](ServeOptions::allow_cleartext_credentials)
///    is set. This check also applies where anonymous push is allowed.
/// 3. An `Authorization` header that matches no line gets 401, also when the
///    request has a client certificate.
/// 4. A request with no `Authorization` header gets the first result that
///    applies:
///    - the owner of its client certificate
///    - the owner `anonymous`, if anonymous push is allowed
///    - 401, if the server has credential lines
///    - 403, if the client CA is the one method of the server
///
/// Each 401 of the built-in methods carries two headers:
/// `WWW-Authenticate: Bearer realm="ostrya"` and
/// `WWW-Authenticate: Basic realm="ostrya"`.
///
/// The owner key of a request has a prefix for each method:
///
/// - `token:NAME` for a bearer token or a Basic credential, where `NAME` is
///   the name of its credential line.
/// - `cert:HEX` for a client certificate, where `HEX` is the SHA-256 digest
///   of its DER bytes in lowercase hex.
/// - `anonymous` for anonymous push.
///
/// A name can be equal to a digest, so the prefix keeps the keys of two
/// methods apart. A bearer token and a Basic credential of one line give one
/// key.
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
    /// The receive policy of the receive endpoint, or `None` for a read-only
    /// server.
    ///
    /// The default is `None`. Every session of the endpoint shares the
    /// policy. The server does not read the policy or a repository setting of
    /// the endpoint again while it runs. A change takes effect at the next
    /// start.
    pub receive: Option<Arc<ReceivePolicy>>,
    /// The switch that lets a request with no credential push.
    ///
    /// The default is `false`. The switch is one of the methods in
    /// [Authentication](ServeOptions#authentication).
    pub allow_anonymous_push: bool,
    /// The bytes of the push credential file.
    ///
    /// The default is `None`. Each line of the file holds one credential,
    /// `NAME:HEX`. `NAME` is one or more visible ASCII characters other than
    /// `:`. `HEX` is the SHA-256 digest of the secret in 64 lowercase hex
    /// digits.
    ///
    /// A line that starts with `#` and an empty line hold no credential. A
    /// file with no credential line gives no authentication method.
    ///
    /// If [`receive`](ServeOptions::receive) is set, [`bind`](crate::bind)
    /// parses the file. A read-only server does not read the field. A
    /// malformed line, a name on two lines, and a digest on two lines are
    /// [`Error::Credentials`](crate::Error::Credentials). This error names
    /// the line by its number and holds no byte of the line.
    pub credentials: Option<Vec<u8>>,
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

/// The debug text holds no byte of the credential file. It shows the file as
/// `<N bytes redacted>`, and a report callback that is set as `<callback>`.
impl fmt::Debug for ServeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServeOptions")
            .field("listen", &self.listen)
            .field("tls", &self.tls)
            .field("body_timeout", &self.body_timeout)
            .field("receive", &self.receive)
            .field("allow_anonymous_push", &self.allow_anonymous_push)
            .field(
                "credentials",
                &self
                    .credentials
                    .as_ref()
                    .map(|c| format!("<{} bytes redacted>", c.len())),
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
            allow_anonymous_push: false,
            credentials: None,
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
    use super::*;

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
    fn debug_states_the_credentials_by_their_length() {
        let opts = ServeOptions {
            credentials: Some(b"alice:secret".to_vec()),
            ..ServeOptions::default()
        };
        let text = format!("{opts:?}");
        assert!(!text.contains("secret"), "{text}");
        assert!(!text.contains("alice"), "{text}");
        assert!(text.contains("<12 bytes redacted>"), "{text}");
    }
}
