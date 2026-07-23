//! Commit signing framework and the dummy test engine (Phase 13a).
//!
//! [`Signer`] and [`Verifier`] are the engine-agnostic surface: a signer names
//! its engine and its detached-metadata key and signs an opaque byte payload; a
//! verifier checks a set of signature blobs against a payload and reports a
//! [`VerifyOutcome`]. Both operate on opaque bytes, so the commit path here and
//! the summary path in a later phase share one surface.
//!
//! The signed payload for a commit is the canonical serialized commit GVariant
//! bytes -- the same normal-form bytes that hash to the commit checksum
//! (`format-reference.md`, "Signing details").
//!
//! Signatures live in the commit's detached metadata (`.commitmeta`), a bare
//! `a{sv}` dict. Each engine owns one key whose value is an `aay` (an array of
//! signature blobs); signing appends one `ay` element, creating the array when
//! absent and leaving other engines' arrays untouched. [`Repo::sign_commit`]
//! and [`Repo::verify_commit`] tie the engine to the detached-metadata I/O.
//!
//! The dummy engine ([`DummySigner`] / [`DummyVerifier`]) carries no crypto: a
//! signature is the raw bytes of its key identifier, and verification matches a
//! stored blob against a trusted key byte string. It exercises the framework
//! and cross-checks against the tool's `ostree.sign.dummy` engine.

use std::future::Future;
use std::pin::Pin;

use ostrya_core::{Checksum, ObjectType, Type, Value};

use crate::error::{Error, Result};
use crate::repo::Repo;

/// The GVariant type of a per-engine signature array in the detached-metadata
/// dict: an array of signature blobs.
const SIGNATURE_ARRAY_SIGNATURE: &str = "aay";

/// The future returned by [`Signer::sign`]. A boxed future keeps `Signer`
/// dyn-compatible, so [`Repo::sign_commit`] can take `&dyn Signer`; each engine
/// decides internally whether to offload heavy work to the blocking pool.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;

/// An engine that produces a detached signature over an opaque payload.
pub trait Signer: Send + Sync {
    /// The engine's short name (`"ed25519"`, `"spki"`, `"gpg"`, `"dummy"`).
    fn name(&self) -> &str;

    /// The detached-metadata dict key the engine's signatures accumulate under
    /// (for example `"ostree.sign.dummy"`).
    fn metadata_key(&self) -> &str;

    /// Sign `data`, yielding one signature blob.
    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a>;
}

/// An engine that checks detached signatures over an opaque payload.
pub trait Verifier: Send + Sync {
    /// The detached-metadata dict key whose `aay` value holds the blobs this
    /// verifier consumes.
    fn metadata_key(&self) -> &str;

    /// Verify `signatures` against `data`. The outcome is valid when at least
    /// one blob verifies; the per-signature detail is reported in
    /// [`VerifyOutcome::signatures`].
    fn verify(&self, data: &[u8], signatures: &[Vec<u8>]) -> Result<VerifyOutcome>;
}

/// The result of verifying a payload against one or more engines.
#[derive(Debug, Clone, Default)]
pub struct VerifyOutcome {
    /// Whether at least one signature verified.
    pub valid: bool,
    /// One entry per signature blob examined, in the order examined.
    pub signatures: Vec<SignatureInfo>,
}

/// Per-signature detail. The fields mirror the documented GPG verify result;
/// engines without a notion of a field leave it unset.
#[derive(Debug, Clone, Default)]
pub struct SignatureInfo {
    /// Whether this signature verified.
    pub valid: bool,
    /// The signing key fingerprint, when the engine exposes one.
    pub fingerprint: Option<String>,
    /// The signature creation time (seconds since the Unix epoch), when known.
    pub created: Option<u64>,
    /// Whether the signing key had expired.
    pub expired: bool,
    /// Whether the signing key was absent from the trusted set.
    pub key_missing: bool,
    /// The signer's user name, when the engine exposes one.
    pub user_name: Option<String>,
    /// The signer's user email, when the engine exposes one.
    pub user_email: Option<String>,
}

impl Repo {
    /// Sign the commit `checksum` with `signer` and append the signature to the
    /// commit's detached metadata.
    ///
    /// The signed payload is the commit object's canonical bytes. The signature
    /// is appended to the engine's `aay` array in the `.commitmeta` `a{sv}`
    /// dict, which is created if absent; other engines' arrays are untouched.
    ///
    /// Appending is a read-modify-write: the dict is loaded, the signature is
    /// added, and the `.commitmeta` file is replaced atomically. The
    /// read-modify-write is not serialized across calls, so signing one commit
    /// from more than one task at a time can drop a signature. Sign a given
    /// commit from a single task at a time; signing different commits
    /// concurrently is safe.
    pub async fn sign_commit(&self, checksum: &Checksum, signer: &dyn Signer) -> Result<()> {
        let data = self.load_object_bytes(ObjectType::Commit, checksum).await?;
        let signature = signer.sign(&data).await?;
        let mut dict = self
            .read_commit_detached_metadata(checksum)
            .await?
            .unwrap_or_else(|| Value::Array(Vec::new()));
        append_signature(&mut dict, signer.metadata_key(), signature)?;
        self.write_commit_detached_metadata(checksum, Some(&dict))
            .await
    }

    /// Verify the commit `checksum` against `verifiers`.
    ///
    /// Each verifier receives the signature blobs stored under its engine key in
    /// the commit's detached metadata (an empty set when the key or the metadata
    /// is absent) together with the commit's canonical bytes. The outcome is
    /// valid when any verifier reports a valid signature; every examined
    /// signature contributes a [`SignatureInfo`].
    pub async fn verify_commit(
        &self,
        checksum: &Checksum,
        verifiers: &[&dyn Verifier],
    ) -> Result<VerifyOutcome> {
        let data = self.load_object_bytes(ObjectType::Commit, checksum).await?;
        let dict = self.read_commit_detached_metadata(checksum).await?;
        let mut outcome = VerifyOutcome::default();
        for verifier in verifiers {
            let signatures = match &dict {
                Some(dict) => signatures_for(dict, verifier.metadata_key()),
                None => Vec::new(),
            };
            let result = verifier.verify(&data, &signatures)?;
            outcome.valid |= result.valid;
            outcome.signatures.extend(result.signatures);
        }
        Ok(outcome)
    }
}

/// Append `signature` to the `metadata_key` engine's `aay` array in the `a{sv}`
/// dict `dict`, creating the entry when absent and preserving insertion order.
/// Other entries, including other engines' signature arrays, are left in place.
pub(crate) fn append_signature(
    dict: &mut Value,
    metadata_key: &str,
    signature: Vec<u8>,
) -> Result<()> {
    let entries = match dict {
        Value::Array(entries) => entries,
        _ => {
            return Err(Error::InvalidFormat(
                "detached metadata must be an a{sv} dict".into(),
            ));
        }
    };
    for entry in entries.iter_mut() {
        if let Value::Tuple(fields) = entry
            && let [key, value] = fields.as_mut_slice()
            && key.as_str() == Some(metadata_key)
        {
            return push_blob(value, signature);
        }
    }
    let array_type = Type::parse(SIGNATURE_ARRAY_SIGNATURE).map_err(ostrya_core::Error::from)?;
    let value = Value::variant(array_type, Value::Array(vec![Value::Bytes(signature)]));
    entries.push(Value::Tuple(vec![
        Value::Str(metadata_key.to_owned()),
        value,
    ]));
    Ok(())
}

/// Push a signature blob onto an existing engine value, an `aay` wrapped in the
/// `a{sv}` variant.
fn push_blob(value: &mut Value, signature: Vec<u8>) -> Result<()> {
    let array = match value {
        Value::Variant(inner) => &mut inner.1,
        other => other,
    };
    match array {
        Value::Array(blobs) => {
            blobs.push(Value::Bytes(signature));
            Ok(())
        }
        _ => Err(Error::InvalidFormat(
            "detached-metadata signature value is not an array".into(),
        )),
    }
}

/// Collect the signature blobs stored under `metadata_key` in the `a{sv}` dict
/// `dict`. Missing key, wrong shape, or non-byte-array elements yield an empty
/// set rather than an error, so a malformed foreign entry cannot fail a verify.
pub(crate) fn signatures_for(dict: &Value, metadata_key: &str) -> Vec<Vec<u8>> {
    let Some(value) = dict.dict_get(metadata_key) else {
        return Vec::new();
    };
    let array = match value.as_variant() {
        Some((_, inner)) => inner,
        None => value,
    };
    match array.as_array() {
        Some(blobs) => blobs
            .iter()
            .filter_map(|blob| blob.as_bytes().map(<[u8]>::to_vec))
            .collect(),
        None => Vec::new(),
    }
}

/// The test-only dummy signer. Its signature is the raw bytes of its key
/// identifier and does not depend on the payload; the secret and public key are
/// the same byte string (`format-reference.md`, "Signing details").
#[derive(Debug, Clone)]
pub struct DummySigner {
    key: Vec<u8>,
}

impl DummySigner {
    /// A dummy signer whose signature is the bytes of `key`.
    pub fn new(key: impl Into<Vec<u8>>) -> DummySigner {
        DummySigner { key: key.into() }
    }
}

impl Signer for DummySigner {
    fn name(&self) -> &str {
        "dummy"
    }

    fn metadata_key(&self) -> &str {
        "ostree.sign.dummy"
    }

    fn sign<'a>(&'a self, _data: &'a [u8]) -> SignFuture<'a> {
        let signature = self.key.clone();
        Box::pin(async move { Ok(signature) })
    }
}

/// The test-only dummy verifier. A signature verifies when its bytes equal one
/// of the trusted key byte strings.
#[derive(Debug, Clone)]
pub struct DummyVerifier {
    trusted: Vec<Vec<u8>>,
}

impl DummyVerifier {
    /// A dummy verifier trusting each key in `keys`.
    pub fn new<K, I>(keys: I) -> DummyVerifier
    where
        K: Into<Vec<u8>>,
        I: IntoIterator<Item = K>,
    {
        DummyVerifier {
            trusted: keys.into_iter().map(Into::into).collect(),
        }
    }
}

impl Verifier for DummyVerifier {
    fn metadata_key(&self) -> &str {
        "ostree.sign.dummy"
    }

    fn verify(&self, _data: &[u8], signatures: &[Vec<u8>]) -> Result<VerifyOutcome> {
        let mut outcome = VerifyOutcome::default();
        for signature in signatures {
            let valid = self.trusted.iter().any(|key| key == signature);
            outcome.valid |= valid;
            outcome.signatures.push(SignatureInfo {
                valid,
                key_missing: !valid,
                ..SignatureInfo::default()
            });
        }
        Ok(outcome)
    }
}

/// The signing public types move freely across tasks and threads. The trait
/// objects the `Repo` entry points accept are `Send + Sync` through the
/// supertrait bounds; their dyn-compatibility is enforced by the `&dyn Signer`
/// and `&dyn Verifier` arguments on [`Repo::sign_commit`] and
/// [`Repo::verify_commit`].
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DummySigner>();
    assert_send_sync::<DummyVerifier>();
    assert_send_sync::<VerifyOutcome>();
    assert_send_sync::<SignatureInfo>();
};
