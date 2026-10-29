//! The trait of a signer with an X.509 certificate chain.

use crate::Signer;

/// A signer with an X.509 certificate chain and the algorithm identifiers of
/// a CMS `SignerInfo`.
///
/// A caller builds a CMS `SignedData` structure, for example an Authenticode
/// signature of a UEFI image, with the values of the trait. This crate builds
/// no CMS structure and no Authenticode structure.
///
/// [`Signer::sign`] hashes `data` with the digest algorithm of
/// [`digest_algorithm`](Self::digest_algorithm) and signs the hash. For
/// Authenticode, `data` is the DER of the CMS signed attributes.
///
/// The methods other than [`Signer::sign`] need no private key. So a signer
/// whose key is in a hardware token, an HSM, or a key service can implement
/// the trait. The trait is dyn-compatible.
///
/// `X509SpkiSigner` implements the trait for the spki engine, with the
/// features `x509` and `spki`.
pub trait X509Signer: Signer {
    /// Returns the DER of each certificate of the chain.
    ///
    /// The certificate of the signer is first. The intermediate certificates
    /// follow in chain order. The list can hold the certificate of the signer
    /// alone.
    fn certificates(&self) -> &[Vec<u8>];

    /// Returns the DER `AlgorithmIdentifier` of the signature, for the
    /// `signatureAlgorithm` field of a CMS `SignerInfo`.
    fn signature_algorithm(&self) -> &[u8];

    /// Returns the DER `AlgorithmIdentifier` of the digest, for the
    /// `digestAlgorithm` field of a CMS `SignerInfo`.
    fn digest_algorithm(&self) -> &[u8];
}
