//! A signing key, with a verifier that trusts that key alone.

use std::sync::Arc;

use ostrya_core::Value;

use crate::error::{Error, Result};
use crate::sign::{Ed25519Signer, Ed25519Verifier, Signer, Verifier, signatures_for};
use crate::verify::Payload;

/// The length of an ed25519 secret key: the 32-byte seed, then the 32-byte
/// public key.
const ED25519_SECRET_LEN: usize = 64;

/// A signing key, with a verifier that trusts that key alone.
///
/// [`SigningKey::from_key_group`] builds the keys of one
/// `[ex-ostrya key "NAME"]` group of the repository config. A caller signs a
/// commit with the [`signer`](Self::signer) of the key, through
/// [`Repo::sign_commit`](crate::Repo::sign_commit) or
/// [`Transaction::sign_commit`](crate::Transaction::sign_commit). Before it
/// signs, the caller can look for a signature of this key with
/// [`has_signed`](Self::has_signed) or
/// [`Repo::has_signed_commit`](crate::Repo::has_signed_commit). If it finds
/// one, the caller does not add a second signature.
///
/// With the `receive` feature, `ReceivePolicy::signers` holds the keys that
/// a receiving server signs with. The server signs each commit that becomes
/// the new value of a ref with these keys. Before it signs, the server looks
/// for a signature of each key in the detached metadata of the commit, stored
/// or incoming. If it finds one, the server does not add a second signature.
///
/// # Existing signatures
///
/// The search for a signature of this key verifies each signature with the
/// verifier and makes no byte comparison. A GPG signature holds the time of
/// signing, so two GPG signatures from one key over one commit have different
/// bytes.
///
/// The search reads the signatures under the detached-metadata key of the
/// engine, in the stored order. It verifies each signature on its own, with
/// this key alone, and stops at the first signature that verifies. These
/// signatures count as not made by this key:
///
/// - a signature from another key
/// - a signature over other bytes
/// - a signature that the verifier refuses, for example a blob that does not
///   parse, a blob over 1 MiB, or a blob with more than 64 GPG signature
///   packets (the limits of `GpgVerifier`).
///
/// A refused signature does not stop the search, so a signature that another
/// party adds, for example a client of a server, cannot hide the signature of
/// this key.
///
/// The search reads at most
/// [`MAX_SIGNATURES_PER_ENGINE`](crate::sign::MAX_SIGNATURES_PER_ENGINE)
/// signatures under the detached-metadata key of the engine, as
/// [`signatures_for`](crate::sign::signatures_for) does. If the dict holds
/// more, the search fails with [`Error::Signature`] before it verifies a
/// signature.
pub struct SigningKey {
    /// The key that the caller signs with.
    signer: Box<dyn Signer>,
    /// A verifier that trusts the public half of the key of `signer` and no
    /// other key.
    verifier: Arc<dyn Verifier>,
}

impl SigningKey {
    /// Creates a signing key from a signer and a verifier of its public key.
    ///
    /// `verifier` must trust the public half of the key of `signer` and no
    /// other key. The caller is responsible for this pairing, and `new` does
    /// not check it:
    ///
    /// - If `verifier` trusts another key, the search does not find a
    ///   signature of this key, and a caller signs a commit that this key
    ///   already signed.
    /// - If `verifier` trusts more keys, the search finds the signature of
    ///   another key, and a caller does not sign a commit that another key
    ///   signed.
    ///
    /// The search verifies the [existing signatures](SigningKey#existing-signatures)
    /// with this pair on the blocking pool.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `signer` and `verifier` use different
    ///   detached-metadata keys. The message is
    ///   `the signer writes '<key>' and the verifier reads '<key>'`.
    pub fn new(signer: Box<dyn Signer>, verifier: Box<dyn Verifier>) -> Result<SigningKey> {
        if signer.metadata_key() != verifier.metadata_key() {
            return Err(Error::InvalidFormat(format!(
                "the signer writes '{}' and the verifier reads '{}'",
                signer.metadata_key(),
                verifier.metadata_key()
            )));
        }
        Ok(SigningKey {
            signer,
            verifier: Arc::from(verifier),
        })
    }

    /// Creates a signing key from a 64-byte ed25519 secret key.
    ///
    /// The secret is the 32-byte seed, then the 32-byte public key. The
    /// verifier trusts that public key alone.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if `secret` is not 64 bytes long. The message is
    ///   `ed25519 secret key must be 64 bytes, got <n>`.
    /// - [`Error::Signature`] if the public half of `secret` does not match
    ///   its seed. The message starts with `ed25519 secret key:`.
    pub fn ed25519(secret: &[u8]) -> Result<SigningKey> {
        let signer = Ed25519Signer::from_secret_key(secret)?;
        let public = &secret[ED25519_SECRET_LEN / 2..ED25519_SECRET_LEN];
        let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new())?;
        Ok(SigningKey {
            signer: Box::new(signer),
            verifier: Arc::new(verifier),
        })
    }

    /// Creates a signing key from an spki signer.
    ///
    /// The verifier is a [`SpkiVerifier`](crate::spki::SpkiVerifier) that
    /// trusts the public key of `signer` alone.
    ///
    /// The key signs on the blocking pool, because the spki signer does its
    /// work in the call to [`Signer::sign`]. An RSA signature with a
    /// 16384-bit key takes about 0.5 seconds of CPU time. The signer that
    /// [`signer`](Self::signer) returns also signs on the blocking pool.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the verifier does not accept the DER public
    ///   key of `signer`. The message is
    ///   `spki public key: expected SubjectPublicKeyInfo DER`.
    #[cfg(feature = "sign-spki")]
    pub fn spki(signer: crate::spki::SpkiSigner) -> Result<SigningKey> {
        let verifier =
            crate::spki::SpkiVerifier::new([signer.public_key_der()], Vec::<Vec<u8>>::new())?;
        Ok(SigningKey {
            signer: Box::new(Unblocked {
                inner: Arc::new(signer),
            }),
            verifier: Arc::new(verifier),
        })
    }

    /// Creates a signing key from the one secret key that a GPG signer
    /// selects.
    ///
    /// The selector of `signer` must name exactly one secret key in the GnuPG
    /// home of `signer`. The function refuses a user id that matches two keys.
    /// The signing key signs with the selected key by its fingerprint.
    ///
    /// [`GpgSigner::export_public`](crate::gpg::GpgSigner::export_public) gives
    /// the minimal public certificate of the key from the same home. The
    /// certificate holds the primary key, the primary user id with its
    /// self-signature, and each signing subkey with its binding signature. A
    /// revocation of the primary key or of a signing subkey stays in the
    /// certificate. The verifier trusts that certificate alone.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if `gpg` cannot start. If `gpg` is not in
    ///   `PATH`, the message is `gpg: program not found in PATH`. For another
    ///   failure, the message is `gpg: <io error>`.
    /// - [`Error::Signature`] with the message
    ///   `the key selector names no secret key` if the selector names no
    ///   secret key. The same error occurs if the `gpg` listing fails, for
    ///   example if the GnuPG home does not exist.
    /// - [`Error::Signature`] with the message
    ///   `the key selector names more than one secret key; use the fingerprint`
    ///   if the selector names two or more secret keys.
    /// - [`Error::Signature`] for each error of
    ///   [`GpgSigner::export_public`](crate::gpg::GpgSigner::export_public).
    /// - The errors of
    ///   [`GpgVerifier::from_keyring_bytes`](crate::gpg::GpgVerifier::from_keyring_bytes)
    ///   for the exported certificate.
    #[cfg(feature = "sign-gpg")]
    pub async fn gpg(signer: crate::gpg::GpgSigner) -> Result<SigningKey> {
        let fingerprints = signer.secret_key_fingerprints().await?;
        let fingerprint = match fingerprints.as_slice() {
            [one] => one,
            [] => {
                return Err(Error::Signature(
                    "the key selector names no secret key".into(),
                ));
            }
            _ => {
                return Err(Error::Signature(
                    "the key selector names more than one secret key; use the fingerprint".into(),
                ));
            }
        };
        let mut bound = crate::gpg::GpgSigner::new(fingerprint.as_str());
        if let Some(dir) = signer.homedir() {
            bound = bound.with_homedir(dir);
        }
        let certificate = bound.export_public(fingerprint).await?;
        let verifier = crate::gpg::GpgVerifier::from_keyring_bytes([certificate])?;
        Ok(SigningKey {
            signer: Box::new(bound),
            verifier: Arc::new(verifier),
        })
    }

    /// Returns the signer of the key.
    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }

    /// Returns `true` if `dict` holds a signature over `payload` that this key
    /// made.
    ///
    /// `payload` is the signed bytes, for example the serialized commit
    /// object that [`Repo::sign_commit`](crate::Repo::sign_commit) signs.
    /// `dict` is the signature dict of the payload, for example the detached
    /// metadata of a commit, or `None` for a commit with no detached metadata.
    /// [`SigningKey`](SigningKey#existing-signatures) states the rules of the
    /// search. [`Repo::has_signed_commit`](crate::Repo::has_signed_commit)
    /// reads the commit and its detached metadata from a repository and makes
    /// the same search.
    ///
    /// The search runs on the blocking pool, because a verifier does its work
    /// in the call. If `dict` holds a signature under the detached-metadata
    /// key of the engine, the pool gets a copy of `payload`.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] with the message of
    ///   [`signatures_for`](crate::sign::signatures_for) if `dict` holds more
    ///   than [`MAX_SIGNATURES_PER_ENGINE`](crate::sign::MAX_SIGNATURES_PER_ENGINE)
    ///   blobs under the detached-metadata key of the engine.
    pub async fn has_signed(&self, payload: &[u8], dict: Option<&Value>) -> Result<bool> {
        self.has_signed_payload(payload, dict).await
    }

    /// Returns `true` if `dict` holds a signature over `payload` that this key
    /// made, the search of [`has_signed`](Self::has_signed).
    ///
    /// The pool gets a [`Payload::Shared`] payload with no copy, and a copy of
    /// a [`Payload::Borrowed`] payload. The errors are the errors of
    /// [`has_signed`](Self::has_signed).
    pub(crate) async fn has_signed_payload<'p>(
        &self,
        payload: impl Into<Payload<'p>>,
        dict: Option<&Value>,
    ) -> Result<bool> {
        let Some(dict) = dict else {
            return Ok(false);
        };
        let blobs = signatures_for(dict, self.verifier.metadata_key())?;
        Ok(self.signed_one_of(payload, blobs).await)
    }

    /// Returns `true` if one of `blobs` is a signature over `payload` that this
    /// key made.
    ///
    /// The call reads `blobs` as a list of signatures of the engine of this
    /// key, with no limit on the number. The search runs on the blocking pool,
    /// and the pool gets the payload as
    /// [`has_signed_payload`](Self::has_signed_payload) states. An empty list
    /// gives `false` with no trip to the pool.
    pub(crate) async fn signed_one_of<'p>(
        &self,
        payload: impl Into<Payload<'p>>,
        blobs: Vec<Vec<u8>>,
    ) -> bool {
        if blobs.is_empty() {
            return false;
        }
        let verifier = Arc::clone(&self.verifier);
        let payload = payload.into().to_shared();
        ostrya_rt::unblock(move || any_verifies(verifier.as_ref(), &payload, &blobs)).await
    }
}

/// A signer that signs on the blocking pool.
///
/// The signer copies the data of each call and gives the copy to the pool.
/// The data is a commit object or a summary, whose size the format caps.
#[cfg(feature = "sign-spki")]
struct Unblocked {
    /// The signer that does the work.
    inner: Arc<crate::spki::SpkiSigner>,
}

#[cfg(feature = "sign-spki")]
impl Signer for Unblocked {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn metadata_key(&self) -> &str {
        self.inner.metadata_key()
    }

    fn sign<'a>(&'a self, data: &'a [u8]) -> crate::sign::SignFuture<'a> {
        let inner = Arc::clone(&self.inner);
        let data = data.to_vec();
        Box::pin(ostrya_rt::unblock(move || {
            futures_lite::future::block_on(inner.sign(&data))
        }))
    }
}

/// Returns `true` if one of `blobs` verifies over `payload` under `verifier`.
///
/// The function verifies each blob on its own and stops at the first blob that
/// verifies. A blob that the verifier refuses counts as not valid.
fn any_verifies(verifier: &dyn Verifier, payload: &[u8], blobs: &[Vec<u8>]) -> bool {
    for blob in blobs {
        if let Ok(outcome) = verifier.verify(payload, std::slice::from_ref(blob))
            && outcome.valid
        {
            return true;
        }
    }
    false
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("engine", &self.signer.name())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use ostrya_core::base64;

    use super::*;
    use crate::sign::{DummySigner, DummyVerifier, append_signature};

    /// The base64 of a 64-byte ed25519 secret key (seed, then public key).
    const SECRET_B64: &str =
        "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
    /// Another ed25519 secret key.
    const OTHER_SECRET_B64: &str =
        "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";

    const PAYLOAD: &[u8] = b"the commit bytes";

    /// Returns a detached-metadata dict that holds `blob` under `key`.
    fn dict_with(key: &str, blob: Vec<u8>) -> Value {
        let mut dict = Value::Array(Vec::new());
        append_signature(&mut dict, key, blob).unwrap();
        dict
    }

    /// Returns a detached-metadata dict that holds `blobs` under `key`, in order.
    fn dict_of(key: &str, blobs: Vec<Vec<u8>>) -> Value {
        let mut dict = Value::Array(Vec::new());
        for blob in blobs {
            append_signature(&mut dict, key, blob).unwrap();
        }
        dict
    }

    /// Returns a blob one byte over the size limit of a GPG signature blob.
    fn oversize_blob() -> Vec<u8> {
        vec![0x88; 1024 * 1024 + 1]
    }

    /// Returns a signature that `signer` makes over [`PAYLOAD`].
    fn signature(signer: &SigningKey) -> Vec<u8> {
        ostrya_rt::block_on(signer.signer().sign(PAYLOAD)).unwrap()
    }

    fn has_signed(signer: &SigningKey, dict: Option<&Value>) -> bool {
        ostrya_rt::block_on(signer.has_signed(PAYLOAD, dict)).unwrap()
    }

    /// The ed25519 search recognizes the signature of the key and no other
    /// signature.
    #[test]
    fn an_ed25519_key_recognizes_its_own_signature() {
        let server = SigningKey::ed25519(&base64::decode(SECRET_B64).unwrap()).unwrap();
        let other = SigningKey::ed25519(&base64::decode(OTHER_SECRET_B64).unwrap()).unwrap();
        let key = server.signer().metadata_key().to_owned();

        assert!(has_signed(
            &server,
            Some(&dict_with(&key, signature(&server)))
        ));
        assert!(!has_signed(
            &server,
            Some(&dict_with(&key, signature(&other)))
        ));
        assert!(!has_signed(&server, Some(&dict_with(&key, vec![0u8; 64]))));
        assert!(!has_signed(
            &server,
            Some(&dict_with(&key, b"garbage".to_vec()))
        ));
        assert!(!has_signed(&server, None));
        assert!(!has_signed(&server, Some(&Value::Array(Vec::new()))));
        // The search does not read a signature of this key under the
        // detached-metadata key of another engine.
        assert!(!has_signed(
            &server,
            Some(&dict_with("ostree.sign.dummy", signature(&server)))
        ));
        // A signature over other bytes is not one over the payload.
        let elsewhere = ostrya_rt::block_on(server.signer().sign(b"other bytes")).unwrap();
        assert!(!has_signed(&server, Some(&dict_with(&key, elsewhere))));
    }

    /// A garbage or oversize blob beside the ed25519 signature of the key does
    /// not hide that signature, in either order.
    #[test]
    fn an_ed25519_signature_beside_a_bad_blob_is_recognized() {
        let server = SigningKey::ed25519(&base64::decode(SECRET_B64).unwrap()).unwrap();
        let key = server.signer().metadata_key().to_owned();
        let own = signature(&server);
        for bad in [b"garbage".to_vec(), oversize_blob()] {
            let before = dict_of(&key, vec![bad.clone(), own.clone()]);
            assert!(has_signed(&server, Some(&before)));
            let after = dict_of(&key, vec![own.clone(), bad.clone()]);
            assert!(has_signed(&server, Some(&after)));
            assert!(!has_signed(&server, Some(&dict_of(&key, vec![bad]))));
        }
    }

    /// A verifier that returns an error for each blob except one.
    struct RefusesOthers {
        good: Vec<u8>,
    }

    impl Verifier for RefusesOthers {
        fn metadata_key(&self) -> &str {
            "ostree.sign.dummy"
        }

        fn verify(
            &self,
            _data: &[u8],
            signatures: &[Vec<u8>],
        ) -> ostrya_sign::Result<ostrya_sign::VerifyOutcome> {
            if signatures.iter().any(|blob| *blob != self.good) {
                return Err(ostrya_sign::Error::Signature("refused".into()));
            }
            let valid = ostrya_sign::SignatureInfo {
                valid: true,
                ..Default::default()
            };
            Ok(ostrya_sign::VerifyOutcome {
                valid: true,
                signatures: vec![valid; signatures.len()],
            })
        }
    }

    /// A blob that the verifier refuses with an error counts as not signed. It
    /// does not hide a blob that verifies.
    #[test]
    fn a_refused_blob_counts_as_not_signed() {
        let server = SigningKey::new(
            Box::new(DummySigner::new(b"k".to_vec())),
            Box::new(RefusesOthers {
                good: b"good".to_vec(),
            }),
        )
        .unwrap();
        let key = "ostree.sign.dummy";
        let mixed = dict_of(key, vec![b"bad".to_vec(), b"good".to_vec()]);
        assert!(has_signed(&server, Some(&mixed)));
        assert!(!has_signed(&server, Some(&dict_with(key, b"bad".to_vec()))));
    }

    /// The search runs the verifier of a pair from `new` on the blocking pool,
    /// so a verifier that works in the call does not hold the async executor.
    /// The search gives a payload in an [`Arc`] to the verifier with no copy.
    #[test]
    fn the_search_verifies_on_the_blocking_pool() {
        use crate::verify::trust::tests::ThreadRecorder;

        let recorder = ThreadRecorder::new("ostree.sign.dummy");
        let server = SigningKey::new(
            Box::new(DummySigner::new(b"k".to_vec())),
            Box::new(recorder.clone()),
        )
        .unwrap();
        let payload = Arc::new(PAYLOAD.to_vec());
        let dict = dict_with("ostree.sign.dummy", b"k".to_vec());
        assert!(ostrya_rt::block_on(server.has_signed_payload(&payload, Some(&dict))).unwrap());
        recorder.assert_one_foreign_call();
        recorder.assert_no_copy_of(&payload);
    }

    /// `SigningKey::ed25519` refuses a secret of another length and a secret
    /// whose public half does not match its seed.
    #[test]
    fn a_malformed_ed25519_secret_is_refused() {
        let secret = base64::decode(SECRET_B64).unwrap();
        assert!(SigningKey::ed25519(&secret[..63]).is_err());
        let other = base64::decode(OTHER_SECRET_B64).unwrap();
        let mut mixed = secret[..32].to_vec();
        mixed.extend_from_slice(&other[32..]);
        assert!(SigningKey::ed25519(&mixed).is_err());
    }

    /// The search recognizes a signature of a pair that the caller builds. `new`
    /// refuses a pair whose two halves read different detached-metadata keys.
    #[test]
    fn new_checks_the_metadata_key() {
        let server = SigningKey::new(
            Box::new(DummySigner::new(b"k".to_vec())),
            Box::new(DummyVerifier::new([b"k".to_vec()])),
        )
        .unwrap();
        assert!(has_signed(
            &server,
            Some(&dict_with("ostree.sign.dummy", signature(&server)))
        ));

        let err = SigningKey::new(
            Box::new(DummySigner::new(b"k".to_vec())),
            Box::new(Ed25519Verifier::new(Vec::<Vec<u8>>::new(), Vec::<Vec<u8>>::new()).unwrap()),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
    }

    /// The spki search recognizes the DER signature of the key, the form
    /// that the verifier reads. It does not recognize the fixed-width
    /// `r || s` form of the same signature, or the signature of another key.
    #[cfg(feature = "sign-spki")]
    #[test]
    fn an_spki_key_recognizes_its_own_der_signature_alone() {
        use crate::spki::SpkiSigner;

        // Two P-256 secret keys, base64 of the PKCS#8 DER.
        let server = SigningKey::spki(
            SpkiSigner::from_base64(concat!(
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2L708EsnnzHER0SYasMNIUcG",
                "v63QapC/3kVsoPerzKGhRANCAATxfzfHKUPeJtyLTGMUoxHhvBS1NT9guWhUQPGiZRLZIcB8Wc3",
                "csdVU1iOiTRmbZGKJTtekOdEAbVRrx5HxIpst",
            ))
            .unwrap(),
        )
        .unwrap();
        let other = SigningKey::spki(
            SpkiSigner::from_base64(concat!(
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgU5tYPz/hTTxfsSTPOxD/H9U+",
                "IkBj5qWV4/H3D1NBfRChRANCAAQPyTr9rh2d6WiYOi3oxNiE3ppTP2g5JP2xX9D7rEKnzixp",
                "MqVuqA9XnzQr5GlCYd71m/D7BnYIqS4MytNawYrR",
            ))
            .unwrap(),
        )
        .unwrap();
        let key = server.signer().metadata_key().to_owned();

        let der = signature(&server);
        assert!(has_signed(&server, Some(&dict_with(&key, der.clone()))));
        assert!(!has_signed(
            &server,
            Some(&dict_with(&key, fixed_width(&der)))
        ));
        assert!(!has_signed(
            &server,
            Some(&dict_with(&key, signature(&other)))
        ));
    }

    /// An spki signing key of the RSA key type signs on the blocking pool, and
    /// the search recognizes its own signature alone. It does not recognize
    /// the signature of another key, or a blob of another length.
    #[cfg(feature = "sign-spki")]
    #[test]
    fn an_rsa_spki_key_recognizes_its_own_signature_alone() {
        use crate::spki::{SpkiSigner, spki_secret_keys};

        /// Returns the signing key of the key fixture file `name`.
        fn server(name: &str) -> SigningKey {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/spki/keys")
                .join(name);
            let mut signers = spki_secret_keys(std::fs::read(path).unwrap(), name).unwrap();
            assert_eq!(signers.len(), 1);
            SigningKey::spki(signers.remove(0)).unwrap()
        }

        let server_key = server("rsa-2048.pem");
        let other = server("rsa-8192.pem");
        let key = server_key.signer().metadata_key().to_owned();
        assert_eq!(server_key.signer().name(), "spki");

        let own = signature(&server_key);
        assert_eq!(own.len(), 256);
        assert!(has_signed(&server_key, Some(&dict_with(&key, own.clone()))));
        assert!(!has_signed(
            &server_key,
            Some(&dict_with(&key, signature(&other)))
        ));
        assert!(!has_signed(
            &server_key,
            Some(&dict_with(&key, own[1..].to_vec()))
        ));

        // The key signs on the blocking pool, and gives the bytes of the
        // signer that it holds.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/spki/keys/rsa-2048.pem");
        let text = std::fs::read_to_string(path).unwrap();
        let direct = SpkiSigner::from_pkcs8_pem(&text).unwrap();
        assert_eq!(ostrya_rt::block_on(direct.sign(PAYLOAD)).unwrap(), own);
    }

    /// Returns the fixed-width `r || s` form of a DER ECDSA signature over
    /// P-256.
    #[cfg(feature = "sign-spki")]
    fn fixed_width(der: &[u8]) -> Vec<u8> {
        // SEQUENCE { INTEGER r, INTEGER s }, each short-form length.
        assert_eq!(der[0], 0x30);
        let mut out = Vec::with_capacity(64);
        let mut at = 2;
        for _ in 0..2 {
            assert_eq!(der[at], 0x02);
            let len = usize::from(der[at + 1]);
            let int = &der[at + 2..at + 2 + len];
            let int = &int[int.len().saturating_sub(32)..];
            out.extend(std::iter::repeat_n(0u8, 32 - int.len()));
            out.extend_from_slice(int);
            at += 2 + len;
        }
        out
    }

    /// Returns `true` if `gpg` answers.
    ///
    /// If `gpg` does not answer, a test that needs it skips. If
    /// `OSTRYA_REQUIRE_GNUPG` is set, the absence of `gpg` fails the test.
    #[cfg(feature = "sign-gpg")]
    fn gpg_or_skip() -> bool {
        if crate::gpg::tests::gpg_available() {
            return true;
        }
        assert!(
            std::env::var_os("OSTRYA_REQUIRE_GNUPG").is_none(),
            "OSTRYA_REQUIRE_GNUPG is set and `gpg` is not available"
        );
        eprintln!("skipping: gpg not available");
        false
    }

    /// The GPG search recognizes a signature that the key made, stored or,
    /// with the `receive` feature, from the merge of a receiving server. It
    /// does not recognize a signature from another key.
    #[cfg(feature = "sign-gpg")]
    #[test]
    fn a_gpg_key_recognizes_its_own_signature() {
        use crate::gpg::GpgSigner;
        use crate::gpg::tests::KeyFixture;

        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Receive Server <server@example.org>");
        let stranger = KeyFixture::new("Stranger <stranger@example.org>");
        let server = ostrya_rt::block_on(SigningKey::gpg(
            GpgSigner::new("server@example.org").with_homedir(&home.dir),
        ))
        .unwrap();
        let key = server.signer().metadata_key().to_owned();
        assert_eq!(key, "ostree.gpgsigs");

        let own = signature(&server);
        assert!(has_signed(&server, Some(&dict_with(&key, own.clone()))));
        let foreign = stranger.sign(PAYLOAD);
        assert!(!has_signed(
            &server,
            Some(&dict_with(&key, foreign.clone()))
        ));

        // Through the merge: a stored signature from another key and an
        // incoming signature from the server key.
        #[cfg(feature = "receive")]
        {
            let merged = crate::receive::merge_detached(
                Some(dict_with(&key, foreign)),
                dict_with(&key, own),
                &[],
            )
            .unwrap();
            assert!(has_signed(&server, Some(&merged)));
        }
    }

    /// A blob that the GPG verifier refuses does not hide the signature of the
    /// key beside it. The blobs are one over the blob limit, one with too many
    /// signature packets, and garbage.
    #[cfg(feature = "sign-gpg")]
    #[test]
    fn a_gpg_signature_beside_a_refused_blob_is_recognized() {
        use crate::gpg::GpgSigner;
        use crate::gpg::tests::KeyFixture;

        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Receive Server <server@example.org>");
        let server = ostrya_rt::block_on(SigningKey::gpg(
            GpgSigner::new("server@example.org").with_homedir(&home.dir),
        ))
        .unwrap();
        let key = server.signer().metadata_key().to_owned();
        let own = signature(&server);
        for bad in [oversize_blob(), own.repeat(65), b"garbage".to_vec()] {
            let mixed = dict_of(&key, vec![bad.clone(), own.clone()]);
            assert!(has_signed(&server, Some(&mixed)));
            assert!(!has_signed(&server, Some(&dict_of(&key, vec![bad]))));
        }
    }

    /// `SigningKey::gpg` refuses a selector that names no secret key and a
    /// selector that names two.
    #[cfg(feature = "sign-gpg")]
    #[test]
    fn a_gpg_selector_names_exactly_one_key() {
        use crate::gpg::GpgSigner;
        use crate::gpg::tests::KeyFixture;

        if !gpg_or_skip() {
            return;
        }
        let home = KeyFixture::new("Server A <a@example.org>");
        home.add_key("Server B <b@example.org>");

        let refused = |selector: &str, part: &str| {
            let err = ostrya_rt::block_on(SigningKey::gpg(
                GpgSigner::new(selector).with_homedir(&home.dir),
            ))
            .unwrap_err();
            assert!(
                matches!(&err, Error::Signature(m) if m.contains(part)),
                "{err}"
            );
        };
        refused("Server", "more than one secret key");
        refused("nobody@example.org", "no secret key");

        // The fingerprint names one of the two.
        let fingerprint = home.fingerprint();
        ostrya_rt::block_on(SigningKey::gpg(
            GpgSigner::new(fingerprint).with_homedir(&home.dir),
        ))
        .unwrap();
    }
}
