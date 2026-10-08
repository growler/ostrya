//! The signing keys a receiving server holds.

use std::sync::Arc;

use ostrya_core::Value;

use crate::error::{Error, Result};
use crate::sign::{Ed25519Signer, Ed25519Verifier, Signer, Verifier, signatures_for};

/// The length of an ed25519 secret key: the 32-byte seed, then the 32-byte
/// public key.
const ED25519_SECRET_LEN: usize = 64;

/// A signing key of the server, with a verifier that trusts that key alone.
///
/// The server signs each commit that becomes the new value of a ref with the
/// keys in [`ReceiveRule::signers`](super::ReceiveRule::signers). Before it
/// signs, the server looks for a signature of this key in the detached
/// metadata of the commit, stored or incoming. If it finds one, the server
/// does not add a second signature.
///
/// # Existing signatures
///
/// The server verifies each signature with the verifier and makes no byte
/// comparison. A GPG signature holds the time of signing, so two GPG
/// signatures from one key over one commit have different bytes.
///
/// The server reads the signatures under the detached-metadata key of the
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
/// A refused signature does not stop the search, so a signature that a
/// client adds cannot hide the signature of the server.
pub struct ServerSigner {
    /// The key that the server signs with.
    signer: Box<dyn Signer>,
    /// A verifier that trusts the public half of the key of `signer` and no
    /// other key.
    verifier: Arc<dyn Verifier>,
    /// `true` if `verifier` does its work in the call to
    /// [`Verifier::verify`], on the thread that calls it.
    ///
    /// The value is `true` for the keys that [`ed25519`](Self::ed25519) and
    /// `spki` give. [`has_signed`](Self::has_signed) then verifies on the
    /// blocking pool, so the verification does not hold the async executor.
    verifies_in_call: bool,
}

impl ServerSigner {
    /// Creates a server key from a signer and a verifier of its public key.
    ///
    /// `verifier` must trust the public half of the key of `signer` and no
    /// other key. The caller is responsible for this pairing, and `new` does
    /// not check it:
    ///
    /// - If `verifier` trusts another key, the server signs a commit that its
    ///   own key already signed.
    /// - If `verifier` trusts more keys, the server does not sign a commit
    ///   that another key signed.
    ///
    /// The server verifies the [existing signatures](ServerSigner#existing-signatures)
    /// with this pair in the calling task.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if `signer` and `verifier` use different
    ///   detached-metadata keys. The message is
    ///   `the signer writes '<key>' and the verifier reads '<key>'`.
    pub fn new(signer: Box<dyn Signer>, verifier: Box<dyn Verifier>) -> Result<ServerSigner> {
        if signer.metadata_key() != verifier.metadata_key() {
            return Err(Error::InvalidFormat(format!(
                "the signer writes '{}' and the verifier reads '{}'",
                signer.metadata_key(),
                verifier.metadata_key()
            )));
        }
        Ok(ServerSigner {
            signer,
            verifier: Arc::from(verifier),
            verifies_in_call: false,
        })
    }

    /// Creates a server key from a 64-byte ed25519 secret key.
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
    pub fn ed25519(secret: &[u8]) -> Result<ServerSigner> {
        let signer = Ed25519Signer::from_secret_key(secret)?;
        let public = &secret[ED25519_SECRET_LEN / 2..ED25519_SECRET_LEN];
        let verifier = Ed25519Verifier::new([public], Vec::<Vec<u8>>::new())?;
        Ok(ServerSigner {
            signer: Box::new(signer),
            verifier: Arc::new(verifier),
            verifies_in_call: true,
        })
    }

    /// Creates a server key from an spki signer.
    ///
    /// The verifier is a [`SpkiVerifier`](crate::spki::SpkiVerifier) that
    /// trusts the public key of `signer` alone.
    ///
    /// # Errors
    ///
    /// - [`Error::Signature`] if the verifier does not accept the DER public
    ///   key of `signer`. The message is
    ///   `spki public key: expected SubjectPublicKeyInfo DER or a SEC1 point`.
    #[cfg(feature = "sign-spki")]
    pub fn spki(signer: crate::spki::SpkiSigner) -> Result<ServerSigner> {
        let verifier =
            crate::spki::SpkiVerifier::new([signer.public_key_der()], Vec::<Vec<u8>>::new())?;
        Ok(ServerSigner {
            signer: Box::new(signer),
            verifier: Arc::new(verifier),
            verifies_in_call: true,
        })
    }

    /// Creates a server key from the one secret key that a GPG signer selects.
    ///
    /// The selector of `signer` must name exactly one secret key in the GnuPG
    /// home of `signer`. The function refuses a user id that matches two keys.
    /// The server key signs with the selected key by its fingerprint.
    ///
    /// `gpg --export` reads the public certificate of the key from the same
    /// home. The verifier trusts that certificate alone.
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
    /// - [`Error::Signature`] if the export is over 4 MiB, if `gpg --export`
    ///   fails, or if it writes nothing.
    /// - [`Error::Io`] if the read of the export or the wait for `gpg` fails.
    /// - The errors of
    ///   [`GpgVerifier::from_keyring_bytes`](crate::gpg::GpgVerifier::from_keyring_bytes)
    ///   for the exported certificate.
    #[cfg(feature = "sign-gpg")]
    pub async fn gpg(signer: crate::gpg::GpgSigner) -> Result<ServerSigner> {
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
        let certificate = crate::gpg::export_public_key(signer.homedir(), fingerprint).await?;
        let verifier = crate::gpg::GpgVerifier::from_keyring_bytes([certificate])?;
        Ok(ServerSigner {
            signer: Box::new(bound),
            verifier: Arc::new(verifier),
            verifies_in_call: false,
        })
    }

    /// Returns the key that the server signs with.
    pub fn signer(&self) -> &dyn Signer {
        self.signer.as_ref()
    }

    /// Returns `true` if `dict` holds a signature over `payload` that this key
    /// made.
    ///
    /// `dict` is the detached metadata of a commit, or `None` for a commit
    /// with no detached metadata. [`ServerSigner`](ServerSigner#existing-signatures)
    /// states the rules of the search.
    ///
    /// For a key from [`ed25519`](Self::ed25519) or `spki`, the search runs on
    /// the blocking pool, because those verifiers do their work in the calling
    /// thread. The GPG verifier moves its own work to the blocking pool. The
    /// search of a pair from [`new`](Self::new) runs in the calling task.
    pub(crate) async fn has_signed(&self, payload: &[u8], dict: Option<&Value>) -> bool {
        let Some(dict) = dict else {
            return false;
        };
        let blobs = signatures_for(dict, self.verifier.metadata_key());
        if blobs.is_empty() {
            return false;
        }
        if self.verifies_in_call {
            let verifier = Arc::clone(&self.verifier);
            let payload = payload.to_vec();
            return ostrya_rt::unblock(move || {
                futures_lite::future::block_on(any_verifies(verifier.as_ref(), &payload, &blobs))
            })
            .await;
        }
        any_verifies(self.verifier.as_ref(), payload, &blobs).await
    }
}

/// Returns `true` if one of `blobs` verifies over `payload` under `verifier`.
///
/// The function verifies each blob on its own and stops at the first blob that
/// verifies. A blob that the verifier refuses counts as not valid.
async fn any_verifies(verifier: &dyn Verifier, payload: &[u8], blobs: &[Vec<u8>]) -> bool {
    for blob in blobs {
        if let Ok(outcome) = verifier.verify(payload, std::slice::from_ref(blob)).await
            && outcome.valid
        {
            return true;
        }
    }
    false
}

impl std::fmt::Debug for ServerSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSigner")
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
    fn signature(signer: &ServerSigner) -> Vec<u8> {
        ostrya_rt::block_on(signer.signer().sign(PAYLOAD)).unwrap()
    }

    fn has_signed(signer: &ServerSigner, dict: Option<&Value>) -> bool {
        ostrya_rt::block_on(signer.has_signed(PAYLOAD, dict))
    }

    /// The ed25519 search recognizes the signature of the key and no other
    /// signature.
    #[test]
    fn an_ed25519_key_recognizes_its_own_signature() {
        let server = ServerSigner::ed25519(&base64::decode(SECRET_B64).unwrap()).unwrap();
        let other = ServerSigner::ed25519(&base64::decode(OTHER_SECRET_B64).unwrap()).unwrap();
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
        let server = ServerSigner::ed25519(&base64::decode(SECRET_B64).unwrap()).unwrap();
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

        fn verify<'a>(
            &'a self,
            _data: &'a [u8],
            signatures: &'a [Vec<u8>],
        ) -> ostrya_sign::VerifyFuture<'a> {
            Box::pin(async move {
                if signatures.iter().any(|blob| *blob != self.good) {
                    return Err(ostrya_sign::Error::Signature("refused".into()));
                }
                Ok(ostrya_sign::VerifyOutcome {
                    valid: true,
                    ..Default::default()
                })
            })
        }
    }

    /// A blob that the verifier refuses with an error counts as not signed. It
    /// does not hide a blob that verifies.
    #[test]
    fn a_refused_blob_counts_as_not_signed() {
        let server = ServerSigner::new(
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

    /// `ServerSigner::ed25519` refuses a secret of another length and a secret
    /// whose public half does not match its seed.
    #[test]
    fn a_malformed_ed25519_secret_is_refused() {
        let secret = base64::decode(SECRET_B64).unwrap();
        assert!(ServerSigner::ed25519(&secret[..63]).is_err());
        let other = base64::decode(OTHER_SECRET_B64).unwrap();
        let mut mixed = secret[..32].to_vec();
        mixed.extend_from_slice(&other[32..]);
        assert!(ServerSigner::ed25519(&mixed).is_err());
    }

    /// The search recognizes a signature of a pair that the caller builds. `new`
    /// refuses a pair whose two halves read different detached-metadata keys.
    #[test]
    fn new_checks_the_metadata_key() {
        let server = ServerSigner::new(
            Box::new(DummySigner::new(b"k".to_vec())),
            Box::new(DummyVerifier::new([b"k".to_vec()])),
        )
        .unwrap();
        assert!(has_signed(
            &server,
            Some(&dict_with("ostree.sign.dummy", signature(&server)))
        ));

        let err = ServerSigner::new(
            Box::new(DummySigner::new(b"k".to_vec())),
            Box::new(Ed25519Verifier::new(Vec::<Vec<u8>>::new(), Vec::<Vec<u8>>::new()).unwrap()),
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
    }

    /// The spki search recognizes the signature of the key in the two forms
    /// that the verifier reads, DER and fixed-width `r || s`. It does not
    /// recognize the signature of another key.
    #[cfg(feature = "sign-spki")]
    #[test]
    fn an_spki_key_recognizes_its_own_signature() {
        use crate::spki::SpkiSigner;

        let server = ServerSigner::spki(SpkiSigner::from_secret_key(&[3u8; 32]).unwrap()).unwrap();
        let other = ServerSigner::spki(SpkiSigner::from_secret_key(&[5u8; 32]).unwrap()).unwrap();
        let key = server.signer().metadata_key().to_owned();

        let der = signature(&server);
        assert!(has_signed(&server, Some(&dict_with(&key, der.clone()))));
        assert!(has_signed(
            &server,
            Some(&dict_with(&key, fixed_width(&der)))
        ));
        assert!(!has_signed(
            &server,
            Some(&dict_with(&key, signature(&other)))
        ));
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

    /// The GPG search recognizes a signature that the server key made, stored
    /// or from the merge. It does not recognize a signature from another key.
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
        let server = ostrya_rt::block_on(ServerSigner::gpg(
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
        let merged = super::super::merge::merge_detached(
            Some(dict_with(&key, foreign)),
            dict_with(&key, own),
            &[],
        )
        .unwrap();
        assert!(has_signed(&server, Some(&merged)));
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
        let server = ostrya_rt::block_on(ServerSigner::gpg(
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

    /// `ServerSigner::gpg` refuses a selector that names no secret key and a
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
            let err = ostrya_rt::block_on(ServerSigner::gpg(
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
        ostrya_rt::block_on(ServerSigner::gpg(
            GpgSigner::new(fingerprint).with_homedir(&home.dir),
        ))
        .unwrap();
    }
}
