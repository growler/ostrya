//! The fetcher's TLS configuration.
//!
//! Two rustls [`ClientConfig`]s are built per [`Fetcher`](crate::Fetcher) and
//! shared by the connections it opens: one presents the configured client
//! certificate and one presents none, so the certificate reaches the origin a
//! route named and no redirect hop elsewhere. Everything else -- the crypto
//! provider, the protocol versions, the trust anchors, and the ALPN offer --
//! is one configuration both hold. With no client certificate configured the
//! two are one `Arc`, so nothing is built twice. The crypto provider is
//! `graviola`: Rust plus formally-verified assembly, so the provider adds no C
//! to the build and carries no `cc` build dependency.
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

/// The client configurations one fetcher opens its connections with.
#[derive(Debug)]
pub(crate) struct ClientConfigs {
    /// What a connection to the origin a route named is opened with. It
    /// presents the configured client certificate.
    pub(crate) with_identity: Arc<ClientConfig>,
    /// What a connection to a redirect hop at any other origin is opened with.
    /// It presents no client certificate. With none configured this is the
    /// other field's own `Arc`.
    pub(crate) without_identity: Arc<ClientConfig>,
    /// Whether the trust store holds an anchor. A store with none reaches here
    /// for a fetcher whose mirrors are all cleartext, which opens no handshake
    /// to consult them; the caller refuses a fetch that would, whether the
    /// route named the TLS origin or a redirect hop did.
    pub(crate) has_trust_anchors: bool,
}

/// Build the shared client configurations. `http2` decides whether `h2` is
/// offered in ALPN. `https` says whether any mirror is reached over TLS, which
/// decides whether an empty system trust store is fatal.
pub(crate) async fn client_config(
    options: &TlsOptions,
    http2: bool,
    https: bool,
) -> Result<ClientConfigs> {
    let store = Arc::new(root_store(&options.roots, https).await?);
    let has_trust_anchors = !store.is_empty();
    let provider = Arc::new(rustls_graviola::default_provider());
    let alpn = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    let mut plain = shared(&provider, &store)?.with_no_client_auth();
    plain.alpn_protocols = alpn.clone();
    let without_identity = Arc::new(plain);
    // The certificate half is built only where a certificate is configured, so
    // a fetcher without one holds one configuration under two names.
    let with_identity = match &options.client_identity {
        Some(identity) => {
            let chain = parse_certs(&identity.cert_chain_pem)?;
            if chain.is_empty() {
                return Err(Error::Fetch(
                    "client certificate holds no certificate".into(),
                ));
            }
            let key = parse_key(&identity.key_pem)?;
            let mut config = shared(&provider, &store)?
                .with_client_auth_cert(chain, key)
                .map_err(|e| Error::Fetch(format!("client certificate rejected: {e}")))?;
            config.alpn_protocols = alpn;
            Arc::new(config)
        }
        None => without_identity.clone(),
    };
    Ok(ClientConfigs {
        with_identity,
        without_identity,
        has_trust_anchors,
    })
}

/// What both client configurations hold: the crypto provider, the protocol
/// versions, and the trust anchors. The anchors are shared by `Arc`, so the
/// store is parsed once and held once.
fn shared(
    provider: &Arc<rustls::crypto::CryptoProvider>,
    store: &Arc<rustls::RootCertStore>,
) -> Result<rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>> {
    Ok(ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Fetch(format!("tls setup: {e}")))?
        .with_root_certificates(store.clone()))
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
            with_h2.without_identity.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        let without = block_on(client_config(&options, false, true)).unwrap();
        assert_eq!(
            without.without_identity.alpn_protocols,
            vec![b"http/1.1".to_vec()]
        );
    }

    /// A configuration built from anchors of its own reports that it holds
    /// them, whichever scheme the mirrors carry.
    #[test]
    fn pem_anchors_are_reported_as_held() {
        let options = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: None,
        };
        for https in [true, false] {
            let configs = block_on(client_config(&options, true, https)).unwrap();
            assert!(configs.has_trust_anchors, "https={https}");
        }
    }

    /// A configured client certificate makes the two configurations two, and
    /// the ALPN offer of both is the one offer. With none configured the two
    /// are one `Arc`.
    #[test]
    fn a_client_identity_is_accepted() {
        let options = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: Some(ClientIdentity {
                cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
                key_pem: CLIENT_KEY_PEM.to_vec(),
            }),
        };
        let configs = block_on(client_config(&options, true, true)).unwrap();
        assert!(!Arc::ptr_eq(
            &configs.with_identity,
            &configs.without_identity
        ));
        assert_eq!(
            configs.with_identity.alpn_protocols,
            configs.without_identity.alpn_protocols
        );

        let options = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: None,
        };
        let configs = block_on(client_config(&options, true, true)).unwrap();
        assert!(Arc::ptr_eq(
            &configs.with_identity,
            &configs.without_identity
        ));
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
