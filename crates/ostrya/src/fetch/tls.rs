//! The fetcher's TLS configuration.
//!
//! One rustls [`ClientConfig`] is built per [`Fetcher`](crate::Fetcher) and
//! shared by every connection it opens. The crypto provider is `graviola`:
//! Rust plus formally-verified assembly, so the provider adds no C to the
//! build and carries no `cc` build dependency.
//!
//! ALPN advertises `h2` before `http/1.1` unless HTTP/2 is switched off, which
//! is what selects the protocol version -- the server picks from the offer
//! during the handshake, and the fetcher speaks whichever came back.
//!
//! Building the configuration is async because [`TrustRoots::System`] reads the
//! host trust store off the filesystem, which belongs on the blocking pool.
//! Everything else here is decoding already-loaded bytes.

use std::io::BufReader;
use std::sync::Arc;

use ostrya_rt as rt;
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{Error, Result};

/// Which certificate authorities the fetcher trusts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum TrustRoots {
    /// The certificates the host system trusts.
    #[default]
    System,
    /// Exactly the PEM-encoded certificates in this blob.
    Pem(Vec<u8>),
}

/// A client certificate and its private key, both PEM-encoded, for a remote
/// that authenticates its clients with TLS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    /// The client certificate, followed by any intermediates.
    pub cert_chain_pem: Vec<u8>,
    /// The matching private key.
    pub key_pem: Vec<u8>,
}

/// How the fetcher negotiates TLS.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsOptions {
    /// The trust anchors used to verify the server certificate.
    pub roots: TrustRoots,
    /// The client certificate to present, for a remote that requires one.
    pub client_identity: Option<ClientIdentity>,
}

/// Build the shared client configuration. `http2` decides whether `h2` is
/// offered in ALPN. `https` says whether any mirror is reached over TLS, which
/// decides whether an empty system trust store is fatal.
pub(crate) async fn client_config(
    options: &TlsOptions,
    http2: bool,
    https: bool,
) -> Result<Arc<ClientConfig>> {
    let store = root_store(&options.roots, https).await?;
    let provider = Arc::new(rustls_graviola::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Fetch(format!("tls setup: {e}")))?
        .with_root_certificates(store);
    let mut config = match &options.client_identity {
        Some(identity) => {
            let chain = parse_certs(&identity.cert_chain_pem)?;
            if chain.is_empty() {
                return Err(Error::Fetch(
                    "client certificate holds no certificate".into(),
                ));
            }
            let key = parse_key(&identity.key_pem)?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| Error::Fetch(format!("client certificate rejected: {e}")))?
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(Arc::new(config))
}

/// Assemble the trust anchors. `https` says whether a handshake will consult
/// them.
async fn root_store(roots: &TrustRoots, https: bool) -> Result<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    match roots {
        TrustRoots::System => {
            // Reading and parsing the host store is filesystem work, so it runs
            // on the blocking pool rather than on the caller's executor thread.
            // The certificates come back as bytes; adding them is not I/O.
            let (certs, detail) = rt::unblock(|| {
                let loaded = rustls_native_certs::load_native_certs();
                let detail = loaded.errors.first().map(|e| e.to_string());
                (loaded.certs, detail)
            })
            .await;
            for cert in certs {
                // A malformed certificate in the system store is skipped, the
                // same as any other consumer of that store does.
                let _ = store.add(cert);
            }
            // A host without a CA bundle carries no anchors. That fails a
            // fetcher with an `https` mirror, whose handshake needs them, and
            // is left to the empty store for a cleartext-only fetcher, which
            // never opens one.
            if store.is_empty() && https {
                let detail =
                    detail.unwrap_or_else(|| "the system trust store is empty".to_string());
                return Err(Error::Fetch(format!("no trusted certificates: {detail}")));
            }
        }
        TrustRoots::Pem(pem) => {
            for cert in parse_certs(pem)? {
                store
                    .add(cert)
                    .map_err(|e| Error::Fetch(format!("trust anchor rejected: {e}")))?;
            }
            if store.is_empty() {
                return Err(Error::Fetch("trust anchors hold no certificate".into()));
            }
        }
    }
    Ok(store)
}

/// Decode every certificate in a PEM blob.
fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Fetch(format!("certificate pem: {e}")))
}

/// Decode the first private key in a PEM blob.
fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(pem))
        .map_err(|e| Error::Fetch(format!("private key pem: {e}")))?
        .ok_or_else(|| Error::Fetch("private key pem holds no key".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_rt::block_on;

    const CA_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/ca.pem");
    const CLIENT_CERT_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/client.pem");
    const CLIENT_KEY_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/client.key.pem");

    #[test]
    fn alpn_offers_h2_first_unless_disabled() {
        let options = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: None,
        };
        let with_h2 = block_on(client_config(&options, true, true)).unwrap();
        assert_eq!(
            with_h2.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let without = block_on(client_config(&options, false, true)).unwrap();
        assert_eq!(without.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn a_client_identity_is_accepted() {
        let options = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: Some(ClientIdentity {
                cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
                key_pem: CLIENT_KEY_PEM.to_vec(),
            }),
        };
        assert!(block_on(client_config(&options, true, true)).is_ok());
    }

    #[test]
    fn empty_trust_anchors_and_bad_keys_are_rejected() {
        let no_roots = TlsOptions {
            roots: TrustRoots::Pem(b"not a certificate\n".to_vec()),
            client_identity: None,
        };
        let err = block_on(client_config(&no_roots, true, true)).unwrap_err();
        assert!(err.to_string().contains("no certificate"), "{err}");

        // A well-formed PEM blob that holds a certificate rather than a key.
        let no_key = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: Some(ClientIdentity {
                cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
                key_pem: CA_PEM.to_vec(),
            }),
        };
        let err = block_on(client_config(&no_key, true, true)).unwrap_err();
        assert!(err.to_string().contains("no key"), "{err}");

        let unparsable_key = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: Some(ClientIdentity {
                cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
                key_pem: b"-----BEGIN PRIVATE KEY-----\n".to_vec(),
            }),
        };
        let err = block_on(client_config(&unparsable_key, true, true)).unwrap_err();
        assert!(err.to_string().contains("private key pem"), "{err}");
    }
}
