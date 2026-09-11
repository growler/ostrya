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
//! A client private key comes in as PEM. The blob holds one section or more.
//! The fetcher takes the first section whose armor label names a private key,
//! and that section decides the path. The labels it reads are
//! `ENCRYPTED PRIVATE KEY`, `PRIVATE KEY`, `RSA PRIVATE KEY`, and
//! `EC PRIVATE KEY`.
//!
//! A section under one of the last three labels is read as it is. An
//! `ENCRYPTED PRIVATE KEY` section is PKCS#8 under PBES2, and
//! [`ClientIdentity::key_passphrase`] decrypts it. The supported ciphers are
//! AES-128-CBC, AES-192-CBC, and AES-256-CBC. The supported key derivation
//! functions are PBKDF2 with an HMAC-SHA-2 pseudorandom function, and scrypt.
//!
//! Each of these cases is refused with a message of its own:
//!
//! - a key that is encrypted, where no passphrase is set;
//! - a passphrase set for a key section that carries no encryption;
//! - a passphrase that does not decrypt the key;
//! - a PBES2 cipher or key derivation function this build carries no
//!   implementation for. The message names the OID. DES, 3DES, and PBKDF2
//!   with an HMAC-SHA-1 pseudorandom function all reach it;
//! - a key under PKCS#5 PBES1, which `pkcs5` parses and does not decrypt. The
//!   message names PBES1. `pkcs5` recognizes six PBES1 OIDs, and an OID
//!   outside that set gives a DER decoding failure. A corrupted document
//!   gives the same failure, so the two cases are not told apart;
//! - the legacy OpenSSL traditional PEM, which carries a
//!   `Proc-Type: 4,ENCRYPTED` header line in the section. The message names
//!   the `openssl pkcs8 -topk8` conversion that gives a PKCS#8 key.
//!
//! The key file sets the cost of the key derivation. The iteration count of
//! PBKDF2 and the cost parameter of scrypt both come out of the document. A
//! file that names an extreme parameter spends that much processor time or
//! that much memory. The key file is operator-supplied, so no bound is applied
//! to either parameter.
//!
//! Building the configuration is async for two reasons.
//! [`TrustRoots::System`] reads the host trust store off the filesystem, and
//! an encrypted client key runs a key derivation function. Both belong on the
//! blocking pool. Everything else here is decoding already-loaded bytes.
//!
//! Two trust settings bypass verification, for an origin whose certificate the
//! operator has decided not to check.
//! [`DangerousAcceptAnyChain`](TrustRoots::DangerousAcceptAnyChain) takes the
//! server certificate chain as presented: no trust anchor, no expiry check,
//! and no key-usage check, so a client certificate or a CA certificate is
//! taken as a server leaf. It keeps the host name check.
//! [`DangerousAcceptAny`](TrustRoots::DangerousAcceptAny) drops the name check
//! as well. Revocation is checked on neither path, since the anchored path
//! configures no CRL.
//!
//! Both keep the handshake signature check, so the peer proves it holds the
//! private key of the certificate it presented. Nobody vouches for that
//! certificate, so the peer is not authenticated: an active attacker on the
//! path presents a certificate of its own and the handshake completes, and a
//! credential sent to such an origin reaches whoever answered the connection.
//! The fetcher's cleartext credential guards read the scheme alone, so a
//! credential does reach a bypass origin, which is what the reference tool and
//! `curl -k` both do. The operator who asks for the bypass carries that risk.
//!
//! Under either one no trust store is read: the constructor touches no file
//! and reaches no blocking pool, and a handshake proceeds, so
//! [`ClientConfigs::has_trust_anchors`] is true.

use std::io::BufReader;
use std::sync::Arc;

use ostrya_rt as rt;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::error::{Error, Result};

/// Which certificate authorities the fetcher trusts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum TrustRoots {
    /// The certificates the host system trusts.
    #[default]
    System,
    /// Exactly the PEM-encoded certificates in this blob.
    Pem(Vec<u8>),
    /// Take the server certificate chain as presented: no trust anchor, no
    /// expiry check, and no key-usage check, so a client certificate or a CA
    /// certificate is taken as a server leaf. No trust store is read.
    /// Revocation is checked on neither this path nor the anchored path, which
    /// configures no CRL. The host name check is kept, so the certificate
    /// still has to carry the name the request asked for, and the handshake
    /// signature check is kept, so the peer still proves it holds the matching
    /// private key. Nobody vouches for that certificate, so the peer is not
    /// authenticated: an active attacker on the path presents a certificate of
    /// its own, and a credential sent to such an origin reaches whoever
    /// answered the connection.
    DangerousAcceptAnyChain,
    /// The above, and the host name check dropped as well: any certificate the
    /// server presents is taken, whatever name it carries. The handshake
    /// signature check is kept, and the peer is as unauthenticated as it is
    /// above.
    DangerousAcceptAny,
}

/// A client certificate and its private key, both PEM-encoded, for a remote
/// that authenticates its clients with TLS.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientIdentity {
    /// The client certificate, followed by any intermediates.
    pub cert_chain_pem: Vec<u8>,
    /// The matching private key. The first section whose armor label names a
    /// private key is the one read. A `PRIVATE KEY`, `RSA PRIVATE KEY`, or
    /// `EC PRIVATE KEY` section is read as it is, and an
    /// `ENCRYPTED PRIVATE KEY` section is decrypted with `key_passphrase`.
    pub key_pem: Vec<u8>,
    /// Decrypts an encrypted PKCS#8 key. A key section that carries no
    /// encryption is refused where this is set, because a passphrase that
    /// decrypts nothing hides a configuration mistake.
    pub key_passphrase: Option<String>,
}

/// The private key and the passphrase are both held out of the formatted
/// text, so a logged fetcher configuration carries neither. The key is stated
/// by its length, and the passphrase by whether it is set. The certificate
/// chain is public material and is formatted in full.
impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
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

/// How the fetcher negotiates TLS.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TlsOptions {
    /// Which certificate authorities the server certificate is verified
    /// against, or the bypass that verifies it against none.
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
    /// Whether a handshake has what it needs to verify the peer. A store with
    /// no anchor reaches here for a fetcher whose mirrors are all cleartext,
    /// which opens no handshake to consult them; the caller refuses a fetch
    /// that would, whether the route named the TLS origin or a redirect hop
    /// did. A bypass variant of [`TrustRoots`] reads no store and reports
    /// true, because its handshake consults no anchor and completes.
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
    let provider = Arc::new(rustls_graviola::default_provider());
    let verification = verification(&options.roots, https, &provider).await?;
    let has_trust_anchors = match &verification {
        Verification::Anchors(store) => !store.is_empty(),
        Verification::Bypass(_) => true,
    };
    let alpn = if http2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    let mut plain = shared(&provider, &verification)?.with_no_client_auth();
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
            let key = parse_key(&identity.key_pem, identity.key_passphrase.as_deref()).await?;
            let mut config = shared(&provider, &verification)?
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
/// versions, and how the server certificate is verified. Both are shared by
/// `Arc`, so the store is parsed once and held once, and the bypass verifier
/// is one object under both configurations.
fn shared(
    provider: &Arc<rustls::crypto::CryptoProvider>,
    verification: &Verification,
) -> Result<rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert>> {
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Fetch(format!("tls setup: {e}")))?;
    Ok(match verification {
        Verification::Anchors(store) => builder.with_root_certificates(store.clone()),
        Verification::Bypass(verifier) => builder
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone()),
    })
}

/// How the client configurations verify the server certificate.
enum Verification {
    /// Against these trust anchors, which is the full check.
    Anchors(Arc<rustls::RootCertStore>),
    /// Against this verifier, which drops part of the check.
    Bypass(Arc<dyn ServerCertVerifier>),
}

/// Resolve the trust setting into what the configurations verify with. `https`
/// says whether a handshake will consult the anchors. A bypass variant reads
/// nothing, so this returns without reaching the filesystem or the blocking
/// pool.
async fn verification(
    roots: &TrustRoots,
    https: bool,
    provider: &Arc<rustls::crypto::CryptoProvider>,
) -> Result<Verification> {
    Ok(match roots {
        TrustRoots::System => Verification::Anchors(Arc::new(system_store(https).await?)),
        TrustRoots::Pem(pem) => Verification::Anchors(Arc::new(pem_store(pem)?)),
        TrustRoots::DangerousAcceptAnyChain => Verification::Bypass(Arc::new(AcceptAnyChain {
            provider: provider.clone(),
            check_name: true,
        })),
        TrustRoots::DangerousAcceptAny => Verification::Bypass(Arc::new(AcceptAnyChain {
            provider: provider.clone(),
            check_name: false,
        })),
    })
}

/// The verifier the bypass variants of [`TrustRoots`] install. It accepts the
/// chain the server presented with no trust anchor, no expiry check, and no
/// key-usage check: the anchored path holds the leaf to webpki's
/// `KeyUsage::server_auth`, and this one holds it to nothing, so a client
/// certificate or a CA certificate is taken as a server leaf. Revocation is
/// checked on neither path. `check_name` decides whether the end-entity
/// certificate is still held to the name the request asked for, which is the
/// one difference between [`TrustRoots::DangerousAcceptAnyChain`] and
/// [`TrustRoots::DangerousAcceptAny`].
///
/// The three signature members delegate to the crypto provider, so the
/// handshake signature is verified as it is under the full check. That proves
/// possession of the private key of a certificate nobody vouched for, so it
/// authenticates no peer.
#[derive(Debug)]
struct AcceptAnyChain {
    provider: Arc<rustls::crypto::CryptoProvider>,
    check_name: bool,
}

impl ServerCertVerifier for AcceptAnyChain {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if self.check_name {
            let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
            rustls::client::verify_server_name(&cert, server_name)?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Assemble the trust anchors the host system holds. `https` says whether a
/// handshake will consult them.
async fn system_store(https: bool) -> Result<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    // Reading and parsing the host store is filesystem work, so it runs on the
    // blocking pool rather than on the caller's executor thread. The
    // certificates come back as bytes; adding them is not I/O.
    let (certs, detail) = rt::unblock(|| {
        let loaded = rustls_native_certs::load_native_certs();
        let detail = loaded.errors.first().map(|e| e.to_string());
        (loaded.certs, detail)
    })
    .await;
    for cert in certs {
        // A malformed certificate in the system store is skipped, the same as
        // any other consumer of that store does.
        let _ = store.add(cert);
    }
    // A host without a CA bundle carries no anchors. That fails a fetcher with
    // an `https` mirror, whose handshake needs them, and is left to the empty
    // store for a cleartext-only fetcher, which never opens one.
    if store.is_empty() && https {
        let detail = detail.unwrap_or_else(|| "the system trust store is empty".to_string());
        return Err(Error::Fetch(format!("no trusted certificates: {detail}")));
    }
    Ok(store)
}

/// Assemble the trust anchors a PEM blob holds.
fn pem_store(pem: &[u8]) -> Result<rustls::RootCertStore> {
    let mut store = rustls::RootCertStore::empty();
    for cert in parse_certs(pem)? {
        store
            .add(cert)
            .map_err(|e| Error::Fetch(format!("trust anchor rejected: {e}")))?;
    }
    if store.is_empty() {
        return Err(Error::Fetch("trust anchors hold no certificate".into()));
    }
    Ok(store)
}

/// Decode every certificate in a PEM blob.
fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Fetch(format!("certificate pem: {e}")))
}

/// The armor label of an encrypted PKCS#8 section, which this module decrypts
/// itself.
const ENCRYPTED_KEY_LABEL: &[u8] = b"ENCRYPTED PRIVATE KEY";

/// The armor labels `rustls_pemfile` reads a private key out of.
const PLAIN_KEY_LABELS: [&[u8]; 3] = [b"PRIVATE KEY", b"RSA PRIVATE KEY", b"EC PRIVATE KEY"];

/// The header a legacy OpenSSL traditional encrypted PEM carries on a line of
/// its own inside the section. RFC 7468 allows no header, so the PEM readers
/// here stop on such a section; the fetcher finds the line first and names the
/// conversion. RFC 1421 leaves the space after the colon optional.
const LEGACY_ENCRYPTED_HEADER: &[u8] = b"Proc-Type:";

/// The value that header carries where the section is encrypted.
const LEGACY_ENCRYPTED_VALUE: &[u8] = b"4,ENCRYPTED";

/// The first section of a PEM blob whose armor label names a private key.
enum KeySection<'a> {
    /// An `ENCRYPTED PRIVATE KEY` section, sliced out of the blob so the
    /// decoder sees that section and nothing around it.
    Encrypted(&'a [u8]),
    /// A section under a label `rustls_pemfile` reads a key out of.
    Plain(&'a [u8]),
}

/// Decode the private key a PEM blob holds. The first section whose armor
/// label names a private key decides the path. A blob that carries a
/// certificate and a key, or two plain keys, therefore reads the way
/// `rustls_pemfile` reads one. An `ENCRYPTED PRIVATE KEY` section in front of
/// a plain key parts from that reader, which holds the label unknown and steps
/// over the section to the plain key behind it. `passphrase` decrypts an
/// `ENCRYPTED PRIVATE KEY` section. It is refused on a section that carries no
/// encryption, because a passphrase that decrypts nothing hides a
/// configuration mistake.
async fn parse_key(pem: &[u8], passphrase: Option<&str>) -> Result<PrivateKeyDer<'static>> {
    match first_key_section(pem) {
        Some(KeySection::Encrypted(section)) => decrypt_key(section, passphrase).await,
        Some(KeySection::Plain(section)) => {
            if is_legacy_encrypted(section) {
                return Err(Error::Fetch(
                    "private key pem is in the legacy openssl encrypted format. \
                     convert the key to pkcs#8 with `openssl pkcs8 -topk8`"
                        .into(),
                ));
            }
            if passphrase.is_some() {
                return Err(Error::Fetch(
                    "a passphrase is set for a private key pem that carries no encryption".into(),
                ));
            }
            read_plain_key(pem)
        }
        // A blob that carries no private-key section holds no key, whatever
        // else it carries. `rustls_pemfile` states that.
        None => read_plain_key(pem),
    }
}

/// Read the key `rustls_pemfile` finds first. The section scan has already
/// settled which section that is.
fn read_plain_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(pem))
        .map_err(|e| Error::Fetch(format!("private key pem: {e}")))?
        .ok_or_else(|| Error::Fetch("private key pem holds no key".into()))
}

/// Find the first section whose armor label names a private key. A key blob is
/// a configuration-sized buffer, so this walks its lines; a certificate
/// section, or a section under any other label, is stepped over.
fn first_key_section(pem: &[u8]) -> Option<KeySection<'_>> {
    for (start, end) in line_ranges(pem, 0) {
        let Some(label) = armor_label(pem[start..end].trim_ascii(), b"BEGIN") else {
            continue;
        };
        if label == ENCRYPTED_KEY_LABEL {
            return Some(KeySection::Encrypted(section_at(pem, start, label)));
        }
        if PLAIN_KEY_LABELS.contains(&label) {
            return Some(KeySection::Plain(section_at(pem, start, label)));
        }
    }
    None
}

/// The bytes of the section that opens at `begin`, from that line through the
/// end of the matching end line. A section with no end line runs to the end of
/// the blob, and the decoder that reads it reports it as no key.
fn section_at<'a>(pem: &'a [u8], begin: usize, label: &[u8]) -> &'a [u8] {
    for (start, end) in line_ranges(pem, begin) {
        if armor_label(pem[start..end].trim_ascii(), b"END") == Some(label) {
            return &pem[begin..end];
        }
    }
    &pem[begin..]
}

/// The label of a PEM armor line, `-----BEGIN <label>-----` for the keyword
/// `BEGIN` and `-----END <label>-----` for `END`. A line that is neither gives
/// `None`.
fn armor_label<'a>(line: &'a [u8], keyword: &[u8]) -> Option<&'a [u8]> {
    line.strip_prefix(b"-----".as_slice())?
        .strip_prefix(keyword)?
        .strip_prefix(b" ".as_slice())?
        .strip_suffix(b"-----".as_slice())
}

/// Whether a section carries the header of the legacy OpenSSL traditional
/// encrypted PEM. The header opens a line of its own, so the same text in the
/// free space around a section reads as free text.
fn is_legacy_encrypted(section: &[u8]) -> bool {
    line_ranges(section, 0).any(|(start, end)| {
        section[start..end]
            .trim_ascii()
            .strip_prefix(LEGACY_ENCRYPTED_HEADER)
            .is_some_and(|value| value.trim_ascii_start() == LEGACY_ENCRYPTED_VALUE)
    })
}

/// The byte range of each line of `pem` from `from`, the terminating newline
/// counted in the range it ends.
fn line_ranges(pem: &[u8], from: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut offset = from;
    std::iter::from_fn(move || {
        let start = offset;
        if start >= pem.len() {
            return None;
        }
        offset = pem[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(pem.len(), |index| start + index + 1);
        Some((start, offset))
    })
}

/// Decrypt an encrypted PKCS#8 section with `passphrase`.
///
/// PBKDF2 and scrypt are deliberately slow, and the key file sets how slow.
/// The work therefore runs on the blocking pool, away from the caller's
/// executor thread. The closure owns its inputs. That costs one copy of the
/// section and one of the passphrase, once per fetcher.
async fn decrypt_key(section: &[u8], passphrase: Option<&str>) -> Result<PrivateKeyDer<'static>> {
    let Some(passphrase) = passphrase else {
        return Err(Error::Fetch(
            "private key pem is encrypted, and no passphrase is set".into(),
        ));
    };
    let section = section.to_vec();
    let passphrase = passphrase.to_string();
    rt::unblock(move || decrypt_pkcs8(&section, &passphrase)).await
}

/// Decode an encrypted PKCS#8 section and decrypt it. A section the decoder
/// reads no document out of reports the failure an empty blob reports, because
/// it holds no key either way.
fn decrypt_pkcs8(section: &[u8], passphrase: &str) -> Result<PrivateKeyDer<'static>> {
    let no_key = || Error::Fetch("private key pem holds no key".into());
    let text = std::str::from_utf8(section).map_err(|_| no_key())?;
    let (_, document) = pkcs8::SecretDocument::from_pem(text).map_err(|_| no_key())?;
    // The cipher and the key derivation function are named by OID in the
    // document, and the decoder rejects an OID it carries no implementation
    // for. DES and 3DES are compiled out, so a PBES2 key under either stops
    // here.
    let info = document
        .decode_msg::<pkcs8::EncryptedPrivateKeyInfo<'_>>()
        .map_err(|e| match e.kind() {
            pkcs8::der::ErrorKind::OidUnknown { oid } => unsupported_algorithm(&oid),
            _ => Error::Fetch(format!("encrypted private key pem: {e}")),
        })?;
    let key = info.decrypt(passphrase).map_err(|e| match e {
        // A wrong passphrase derives a wrong key, and the plaintext that key
        // gives carries invalid padding. `pkcs5` reports a padding failure as
        // `EncryptFailed` on the decryption path as well as the encryption
        // path, and constructs `DecryptFailed` nowhere.
        pkcs8::Error::EncryptedPrivateKey(pkcs8::pkcs5::Error::EncryptFailed) => {
            Error::Fetch("the passphrase does not decrypt the private key".into())
        }
        // A PBES2 pseudorandom function that is compiled out lands here, where
        // an unknown cipher OID lands in the decoder above.
        pkcs8::Error::EncryptedPrivateKey(pkcs8::pkcs5::Error::UnsupportedAlgorithm { oid }) => {
            unsupported_algorithm(&oid)
        }
        // `pkcs5` parses PBES1 and decrypts none of it.
        pkcs8::Error::EncryptedPrivateKey(pkcs8::pkcs5::Error::NoPbes1CryptSupport) => {
            Error::Fetch(
                "private key pem is encrypted under pkcs#5 pbes1, \
                 which this build does not decrypt"
                    .into(),
            )
        }
        other => Error::Fetch(format!("encrypted private key: {other}")),
    })?;
    Ok(PrivateKeyDer::Pkcs8(key.as_bytes().to_vec().into()))
}

/// The refusal an algorithm this build carries no implementation for gets. The
/// document names the algorithm by OID, and so does the message.
fn unsupported_algorithm(oid: &pkcs8::ObjectIdentifier) -> Error {
    Error::Fetch(format!(
        "private key pem is encrypted with algorithm {oid}, \
         which this build does not decrypt"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostrya_rt::block_on;

    const CA_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/ca.pem");
    const CLIENT_CERT_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/client.pem");
    const CLIENT_KEY_PEM: &[u8] = include_bytes!("../../../../tests/fixtures/tls/client.key.pem");
    /// The same key, in PKCS#8 under PBES2 with AES-256-CBC.
    const CLIENT_KEY_ENC_PEM: &[u8] =
        include_bytes!("../../../../tests/fixtures/tls/client.key.enc.pem");
    /// The same key, in the legacy OpenSSL traditional encrypted PEM.
    const CLIENT_KEY_LEGACY_PEM: &[u8] =
        include_bytes!("../../../../tests/fixtures/tls/client.key.legacy.pem");
    /// The same key, in PKCS#8 under PBES1 with pbeWithMD5AndDES-CBC.
    const CLIENT_KEY_PBES1_PEM: &[u8] =
        include_bytes!("../../../../tests/fixtures/tls/client.key.pbes1.pem");
    /// The passphrase `tests/fixtures/tls/generate.sh` encrypted all three
    /// with.
    const KEY_PASSPHRASE: &str = "ostrya test passphrase";

    /// Build the configurations from a client key and whatever passphrase goes
    /// with it, so a test states the one pair it is about.
    fn configs_for_key(key_pem: &[u8], passphrase: Option<&str>) -> Result<ClientConfigs> {
        block_on(client_config(
            &TlsOptions {
                roots: TrustRoots::Pem(CA_PEM.to_vec()),
                client_identity: Some(ClientIdentity {
                    cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
                    key_pem: key_pem.to_vec(),
                    key_passphrase: passphrase.map(str::to_string),
                }),
            },
            true,
            true,
        ))
    }

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
                key_passphrase: None,
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

    /// A bypass variant builds with no anchors configured and still reports
    /// that a handshake can proceed, and with no client identity the two
    /// configurations stay one `Arc`. That the host store is not read as well
    /// is held by `tests/fetch_no_trust_store.rs`, which runs the constructor
    /// in a child process whose store holds nothing.
    #[test]
    fn a_bypass_needs_no_trust_store() {
        for roots in [
            TrustRoots::DangerousAcceptAnyChain,
            TrustRoots::DangerousAcceptAny,
        ] {
            let options = TlsOptions {
                roots: roots.clone(),
                client_identity: None,
            };
            for https in [true, false] {
                let configs = block_on(client_config(&options, true, https)).unwrap();
                assert!(configs.has_trust_anchors, "{roots:?} https={https}");
                assert!(Arc::ptr_eq(
                    &configs.with_identity,
                    &configs.without_identity
                ));
            }
        }
    }

    /// A client identity alongside a bypass builds two configurations, both
    /// verifying with the one bypass verifier.
    #[test]
    fn a_bypass_carries_a_client_identity() {
        for roots in [
            TrustRoots::DangerousAcceptAnyChain,
            TrustRoots::DangerousAcceptAny,
        ] {
            let options = TlsOptions {
                roots,
                client_identity: Some(ClientIdentity {
                    cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
                    key_pem: CLIENT_KEY_PEM.to_vec(),
                    key_passphrase: None,
                }),
            };
            let configs = block_on(client_config(&options, true, true)).unwrap();
            assert!(!Arc::ptr_eq(
                &configs.with_identity,
                &configs.without_identity
            ));
            assert!(configs.has_trust_anchors);
        }
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
                key_passphrase: None,
            }),
        };
        let err = block_on(client_config(&no_key, true, true)).unwrap_err();
        assert!(err.to_string().contains("no key"), "{err}");

        let unparsable_key = TlsOptions {
            roots: TrustRoots::Pem(CA_PEM.to_vec()),
            client_identity: Some(ClientIdentity {
                cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
                key_pem: b"-----BEGIN PRIVATE KEY-----\n".to_vec(),
                key_passphrase: None,
            }),
        };
        let err = block_on(client_config(&unparsable_key, true, true)).unwrap_err();
        assert!(err.to_string().contains("private key pem"), "{err}");
    }

    /// An encrypted PKCS#8 key with its passphrase builds the two
    /// configurations, the same as the key that carries no encryption.
    #[test]
    fn an_encrypted_client_key_is_decrypted() {
        let configs = configs_for_key(CLIENT_KEY_ENC_PEM, Some(KEY_PASSPHRASE)).unwrap();
        assert!(!Arc::ptr_eq(
            &configs.with_identity,
            &configs.without_identity
        ));
    }

    /// Each refusal the encrypted-key path carries names its own case: a wrong
    /// passphrase, an encrypted key with no passphrase, a passphrase on a key
    /// that carries no encryption, and the legacy OpenSSL format.
    #[test]
    fn the_encrypted_key_refusals_name_their_case() {
        let err = configs_for_key(CLIENT_KEY_ENC_PEM, Some("not the passphrase")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "fetch: the passphrase does not decrypt the private key"
        );

        let err = configs_for_key(CLIENT_KEY_ENC_PEM, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "fetch: private key pem is encrypted, and no passphrase is set"
        );

        let err = configs_for_key(CLIENT_KEY_PEM, Some(KEY_PASSPHRASE)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "fetch: a passphrase is set for a private key pem that carries no \
             encryption"
        );

        // The legacy form is refused whether a passphrase is set or not, and
        // the message names the conversion that gives a readable key.
        for passphrase in [Some(KEY_PASSPHRASE), None] {
            let err = configs_for_key(CLIENT_KEY_LEGACY_PEM, passphrase).unwrap_err();
            assert_eq!(
                err.to_string(),
                "fetch: private key pem is in the legacy openssl encrypted \
                 format. convert the key to pkcs#8 with `openssl pkcs8 -topk8`"
            );
        }
    }

    /// The formatted identity carries neither the private key nor the
    /// passphrase, so a logged fetcher configuration carries neither. The key
    /// is stated by its length. The certificate chain is public material and
    /// is formatted in full.
    #[test]
    fn debug_redacts_the_key_and_the_passphrase() {
        // A key that carries no encryption is the case a `Debug` leak costs
        // most, and it is the case a pull configures.
        let identity = ClientIdentity {
            cert_chain_pem: CLIENT_CERT_PEM.to_vec(),
            key_pem: CLIENT_KEY_PEM.to_vec(),
            key_passphrase: Some(KEY_PASSPHRASE.to_string()),
        };
        let text = format!("{identity:?}");
        assert!(!text.contains(KEY_PASSPHRASE), "{text}");
        assert!(
            text.contains("key_passphrase: Some(\"<redacted>\")"),
            "{text}"
        );
        for line in std::str::from_utf8(CLIENT_KEY_PEM)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("-----"))
        {
            assert!(!text.contains(line), "{line} in {text}");
        }
        assert!(
            text.contains(&format!("<{} bytes redacted>", CLIENT_KEY_PEM.len())),
            "{text}"
        );
        assert!(text.contains("cert_chain_pem: ["), "{text}");

        let without = ClientIdentity {
            key_passphrase: None,
            ..identity
        };
        let text = format!("{without:?}");
        assert!(text.contains("key_passphrase: None"), "{text}");
        assert!(!text.contains(KEY_PASSPHRASE), "{text}");
    }

    /// The encrypted section is read whatever follows it: a trailing blank
    /// line, or the certificate the usual bundle carries in front of the key.
    /// The decoder sees that one section, sliced out of the blob.
    #[test]
    fn an_encrypted_key_is_read_out_of_a_longer_blob() {
        let blobs = [
            [CLIENT_KEY_ENC_PEM, b"\n"].concat(),
            [CLIENT_CERT_PEM, CLIENT_KEY_ENC_PEM].concat(),
            [CLIENT_KEY_ENC_PEM, CLIENT_CERT_PEM].concat(),
        ];
        for blob in blobs {
            let configs = configs_for_key(&blob, Some(KEY_PASSPHRASE)).unwrap();
            assert!(!Arc::ptr_eq(
                &configs.with_identity,
                &configs.without_identity
            ));
        }
    }

    /// The first section whose label names a private key decides the path, so
    /// a blob that holds an encrypted key and a plain one is read as whichever
    /// comes first.
    #[test]
    fn the_first_key_section_decides_the_path() {
        // Encrypted first: the passphrase is spent on it, and leaving the
        // passphrase out refuses rather than falling through to the plain key
        // behind it.
        let encrypted_first = [CLIENT_KEY_ENC_PEM, CLIENT_KEY_PEM].concat();
        configs_for_key(&encrypted_first, Some(KEY_PASSPHRASE)).unwrap();
        let err = configs_for_key(&encrypted_first, None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "fetch: private key pem is encrypted, and no passphrase is set"
        );

        // Plain first: it is read as it is, and a passphrase is refused
        // although an encrypted section stands behind it.
        let plain_first = [CLIENT_KEY_PEM, CLIENT_KEY_ENC_PEM].concat();
        configs_for_key(&plain_first, None).unwrap();
        let err = configs_for_key(&plain_first, Some(KEY_PASSPHRASE)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "fetch: a passphrase is set for a private key pem that carries no \
             encryption"
        );
    }

    /// The legacy header is read inside the section that carries it. A plain
    /// key in front of a legacy one is served, and the same text in the free
    /// space around a plain key reads as free text.
    #[test]
    fn the_legacy_header_is_read_inside_its_own_section() {
        let plain_first = [CLIENT_KEY_PEM, CLIENT_KEY_LEGACY_PEM].concat();
        configs_for_key(&plain_first, None).unwrap();

        let with_note = [
            b"Proc-Type: 4,ENCRYPTED\n".as_slice(),
            b"# Proc-Type: 4,ENCRYPTED\n".as_slice(),
            CLIENT_KEY_PEM,
        ]
        .concat();
        configs_for_key(&with_note, None).unwrap();
    }

    /// RFC 1421 leaves the space after the colon optional, and the header is
    /// named under either spelling.
    #[test]
    fn the_legacy_header_is_named_without_the_space() {
        let text = std::str::from_utf8(CLIENT_KEY_LEGACY_PEM)
            .unwrap()
            .replace("Proc-Type: 4,ENCRYPTED", "Proc-Type:4,ENCRYPTED");
        let err = configs_for_key(text.as_bytes(), Some(KEY_PASSPHRASE)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "fetch: private key pem is in the legacy openssl encrypted \
             format. convert the key to pkcs#8 with `openssl pkcs8 -topk8`"
        );
    }

    /// A key under PKCS#5 PBES1 is refused, and the message names PBES1.
    #[test]
    fn a_pbes1_key_is_refused_by_name() {
        let err = configs_for_key(CLIENT_KEY_PBES1_PEM, Some(KEY_PASSPHRASE)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "fetch: private key pem is encrypted under pkcs#5 pbes1, \
             which this build does not decrypt"
        );
    }
}
