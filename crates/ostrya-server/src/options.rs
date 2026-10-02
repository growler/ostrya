//! The options of a server.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

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
#[derive(Clone, Debug)]
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
}

impl Default for ServeOptions {
    fn default() -> ServeOptions {
        ServeOptions {
            listen: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))],
            tls: None,
            body_timeout: Duration::from_secs(60),
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
}
