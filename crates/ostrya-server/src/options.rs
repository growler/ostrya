//! The options of a server.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ostrya::{ReceivePolicy, ReceiveReport};

/// The PEM bytes of the server TLS files. The caller reads each file once at
/// start.
#[derive(Clone, Eq, PartialEq)]
pub struct ServerTls {
    /// The server certificate, followed by any intermediates.
    pub cert_chain_pem: Vec<u8>,
    /// The private key of the certificate: plain, or encrypted PKCS#8 under
    /// PBES2.
    pub key_pem: Vec<u8>,
    /// Decrypts an encrypted key.
    pub key_passphrase: Option<String>,
    /// The CA that client certificates are verified against. A client that
    /// presents no certificate is served.
    pub client_ca_pem: Option<Vec<u8>>,
}

/// The private key and the passphrase are held out of the formatted text.
/// The key is stated by its length, and the passphrase by whether it is set.
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

/// The options of [`bind`](crate::bind). Start from
/// [`ServeOptions::default`] and set the fields.
#[derive(Clone)]
#[non_exhaustive]
pub struct ServeOptions {
    /// The addresses to listen on. Port 0 lets the kernel choose a port,
    /// which [`Server::local_addrs`](crate::Server::local_addrs) reports. The
    /// default is `127.0.0.1:8080`.
    pub listen: Vec<SocketAddr>,
    /// The TLS files, or `None` for plain HTTP.
    pub tls: Option<ServerTls>,
    /// The time a response body may wait for the client to take its next
    /// bytes. A connection with a body that waits longer ends, and the file
    /// and the compressor the body holds are released. An HTTP/2 connection
    /// sends a ping after half this time with no frame from the peer, and
    /// ends when the peer does not answer within this time. The default is 60
    /// seconds, and zero is refused.
    pub body_timeout: Duration,
    /// The receive policy of the receive endpoint, or `None` for a read-only
    /// server, which is the default. Every session of the endpoint shares
    /// the policy. The server reads no policy and no repository setting of
    /// the endpoint again while it runs, so a change applies at the next
    /// start.
    pub receive: Option<Arc<ReceivePolicy>>,
    /// Let a request with no credential push. The default is `false`.
    ///
    /// The authentication methods of the receive endpoint are this switch,
    /// the lines of [`credentials`](ServeOptions::credentials), and the
    /// client CA of [`tls`](ServeOptions::tls). [`bind`](crate::bind)
    /// refuses a receive endpoint with no method. With no TLS, it also
    /// refuses an endpoint whose one method is the credential lines unless
    /// [`allow_cleartext_credentials`](ServeOptions::allow_cleartext_credentials)
    /// is set, because no request can pass it.
    pub allow_anonymous_push: bool,
    /// The bytes of the push credential file, or `None`, which is the
    /// default. The file holds one credential on each line, `NAME:HEX`, where
    /// `HEX` is the SHA-256 digest of the secret in 64 lowercase hex digits.
    /// A line that starts with `#` and an empty line hold no credential.
    /// With [`receive`](ServeOptions::receive) set, [`bind`](crate::bind)
    /// parses the file, and a malformed line is
    /// [`Error::Credentials`](crate::Error::Credentials). A file with no
    /// credential line gives no authentication method. A read-only server
    /// does not read the field.
    pub credentials: Option<Vec<u8>>,
    /// Take a bearer or Basic credential of the receive endpoint on a
    /// connection without TLS. The default is `false`, and the endpoint then
    /// refuses such a credential with 403. Set it for a server on a loopback
    /// address or behind a proxy that terminates TLS. A read-only server does
    /// not read the field.
    pub allow_cleartext_credentials: bool,
    /// The number of object streams one session runs at the same time, which
    /// `HelloReply` announces. The value is in `1..=31`, and the default
    /// is 4. The HTTP/2 receive window of a connection is 2 MiB for each
    /// stream, and the window of one stream is 2 MiB.
    pub parallel_uploads: u32,
    /// The time a session may stay with no request in progress, and the time
    /// a request body of a session may deliver no byte. Past it the server
    /// aborts the session. The default is 300 seconds, and zero is refused.
    pub session_idle_timeout: Duration,
    /// The most sessions open at the same time. The default is 16, and zero
    /// is refused.
    pub max_sessions: usize,
    /// Called with the report of each session that committed, after the
    /// server sent `CommitReply` or failed to send it. A reply that the
    /// connection did not take adds a warning of the step
    /// [`ReplyNotDelivered`](ostrya::ReceiveStep::ReplyNotDelivered). The
    /// call runs on a task of the server, so it must return soon. The
    /// default is `None`.
    pub on_report: Option<Arc<dyn Fn(ReceiveReport) + Send + Sync>>,
}

/// The report callback is stated by whether it is set, and the credential
/// file by its length.
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
        ServeOptions {
            listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))],
            tls: None,
            body_timeout: Duration::from_secs(60),
            receive: None,
            allow_anonymous_push: false,
            credentials: None,
            allow_cleartext_credentials: false,
            parallel_uploads: 4,
            session_idle_timeout: Duration::from_secs(300),
            max_sessions: 16,
            on_report: None,
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
