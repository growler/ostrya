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
//!
//! The ed25519 engine ([`Ed25519Signer`] / [`Ed25519Verifier`], Phase 13b) is
//! the first real engine: a 32-byte public key, a 64-byte signature, and a
//! 64-byte secret key (32-byte seed followed by the 32-byte public key), all per
//! `format-reference.md`. ed25519 is deterministic, so signing needs no RNG and
//! the same key over the same commit yields byte-identical detached metadata.
//! [`load_sign_keys`] loads the sign-api key store -- base64-one-key-per-line
//! `trusted.<type>` and `revoked.<type>` files and their `.d` directories under
//! a system search path -- parameterized by sign-type name so the spki engine
//! reuses it; a verifier trusts the loaded set minus the revoked set.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use ostrya_core::{Checksum, ObjectType, Type, Value, base64};

use crate::error::{Error, Result};
use crate::repo::Repo;

/// The GVariant type of a per-engine signature array in the detached-metadata
/// dict: an array of signature blobs.
const SIGNATURE_ARRAY_SIGNATURE: &str = "aay";

/// The future returned by [`Signer::sign`]. A boxed future keeps `Signer`
/// dyn-compatible, so [`Repo::sign_commit`] can take `&dyn Signer`; each engine
/// decides internally whether to offload heavy work to the blocking pool.
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;

/// The future returned by [`Verifier::verify`]. A boxed future keeps `Verifier`
/// dyn-compatible, so [`Repo::verify_commit`] can take `&dyn Verifier`; an
/// engine that delegates to an external helper awaits it internally, while the
/// in-process engines resolve immediately.
pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<VerifyOutcome>> + Send + 'a>>;

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
    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a>;
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
    /// The primary-key fingerprint of the signer's certificate, when the
    /// signing key is a subkey (GPG). Equal to [`fingerprint`](Self::fingerprint)
    /// when the primary key signed.
    pub primary_fingerprint: Option<String>,
    /// The signature creation time (seconds since the Unix epoch), when known.
    pub created: Option<u64>,
    /// The signature expiry time (seconds since the Unix epoch), when the
    /// signature carries one.
    pub expires: Option<u64>,
    /// The signing key's expiry time (seconds since the Unix epoch), when the
    /// key carries one and it has passed.
    pub key_expires: Option<u64>,
    /// Whether the signing key had expired.
    pub expired: bool,
    /// Whether the signing key was revoked.
    pub revoked: bool,
    /// Whether the signing key was absent from the trusted set.
    pub key_missing: bool,
    /// The public-key algorithm name, when the engine exposes one (GPG).
    pub pubkey_algorithm: Option<String>,
    /// The digest algorithm name, when the engine exposes one (GPG).
    pub hash_algorithm: Option<String>,
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
            let result = verifier.verify(&data, &signatures).await?;
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

    fn verify<'a>(&'a self, _data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a> {
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
        Box::pin(async move { Ok(outcome) })
    }
}

/// The ed25519 sign-type name, used both as the engine name and as the base
/// name of its key-store files (`trusted.ed25519`, `revoked.ed25519`).
const ED25519_SIGN_TYPE: &str = "ed25519";
/// The ed25519 engine's detached-metadata dict key.
const ED25519_METADATA_KEY: &str = "ostree.sign.ed25519";
/// The raw byte length of an ed25519 public key.
const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// The raw byte length of an ed25519 secret key (seed followed by public key).
const ED25519_SECRET_KEY_LEN: usize = 64;

/// The ed25519 commit-signing engine.
///
/// The secret key is the 64-byte seed-plus-public-key form the tool uses;
/// [`from_keypair_bytes`](SigningKey::from_keypair_bytes) checks that the stored
/// public half matches the seed. Signing is deterministic (RFC 8032), so it
/// needs no RNG and completes in-task without offloading to the blocking pool.
#[derive(Debug, Clone)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Build a signer from a 64-byte secret key (32-byte seed followed by the
    /// 32-byte public key). Accepts the raw bytes or an `ay` payload.
    pub fn from_secret_key(secret: &[u8]) -> Result<Ed25519Signer> {
        let bytes: [u8; ED25519_SECRET_KEY_LEN] = secret.try_into().map_err(|_| {
            Error::Signature(format!(
                "ed25519 secret key must be {ED25519_SECRET_KEY_LEN} bytes, got {}",
                secret.len()
            ))
        })?;
        let signing_key = SigningKey::from_keypair_bytes(&bytes)
            .map_err(|e| Error::Signature(format!("ed25519 secret key: {e}")))?;
        Ok(Ed25519Signer { signing_key })
    }

    /// Build a signer from a base64-encoded 64-byte secret key. Surrounding
    /// whitespace (a trailing newline from a key file) is ignored.
    pub fn from_base64(secret_b64: &str) -> Result<Ed25519Signer> {
        Ed25519Signer::from_secret_key(&base64::decode(secret_b64.trim())?)
    }
}

impl Signer for Ed25519Signer {
    fn name(&self) -> &str {
        ED25519_SIGN_TYPE
    }

    fn metadata_key(&self) -> &str {
        ED25519_METADATA_KEY
    }

    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a> {
        let signature = self.signing_key.sign(data).to_bytes().to_vec();
        Box::pin(async move { Ok(signature) })
    }
}

/// The ed25519 commit-verifying engine, holding the effective trusted key set.
///
/// A signature verifies when any trusted key accepts it. Verification uses the
/// lenient (cofactored) equation, matching the acceptance the tool's libsodium
/// backend applies, so a valid signature written by either side verifies on the
/// other.
#[derive(Debug, Clone)]
pub struct Ed25519Verifier {
    trusted: Vec<VerifyingKey>,
}

impl Ed25519Verifier {
    /// Build a verifier trusting each key in `trusted` except those also in
    /// `revoked`. Keys are 32-byte public keys, as raw bytes or `ay` payloads.
    /// A trusted key that is not a valid curve point is an error; a revoked key
    /// need only match by bytes and is not validated as a point.
    pub fn new<T, R>(trusted: T, revoked: R) -> Result<Ed25519Verifier>
    where
        T: IntoIterator,
        T::Item: AsRef<[u8]>,
        R: IntoIterator,
        R::Item: AsRef<[u8]>,
    {
        let revoked: Vec<[u8; ED25519_PUBLIC_KEY_LEN]> = revoked
            .into_iter()
            .map(|k| ed25519_public_bytes(k.as_ref()))
            .collect::<Result<_>>()?;
        let mut keys = Vec::new();
        for key in trusted {
            let raw = ed25519_public_bytes(key.as_ref())?;
            if revoked.contains(&raw) {
                continue;
            }
            let vk = VerifyingKey::from_bytes(&raw)
                .map_err(|e| Error::Signature(format!("ed25519 public key: {e}")))?;
            keys.push(vk);
        }
        Ok(Ed25519Verifier { trusted: keys })
    }

    /// Build a verifier from a loaded [`SignKeys`] set (trusted minus revoked).
    pub fn from_sign_keys(keys: SignKeys) -> Result<Ed25519Verifier> {
        Ed25519Verifier::new(keys.trusted, keys.revoked)
    }

    /// Build a verifier from the system sign-api key store: `trusted.ed25519`
    /// and `revoked.ed25519` and their `.d` directories under the system search
    /// path (see [`load_sign_keys`]).
    pub fn from_system_keys() -> Result<Ed25519Verifier> {
        Ed25519Verifier::from_sign_keys(load_sign_keys(ED25519_SIGN_TYPE)?)
    }
}

impl Verifier for Ed25519Verifier {
    fn metadata_key(&self) -> &str {
        ED25519_METADATA_KEY
    }

    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>]) -> VerifyFuture<'a> {
        let mut outcome = VerifyOutcome::default();
        for blob in signatures {
            let valid = match <[u8; 64]>::try_from(blob.as_slice()) {
                Ok(sig_bytes) => {
                    let sig = Signature::from_bytes(&sig_bytes);
                    self.trusted.iter().any(|k| k.verify(data, &sig).is_ok())
                }
                // A blob that is not 64 bytes cannot be an ed25519 signature.
                Err(_) => false,
            };
            outcome.valid |= valid;
            outcome.signatures.push(SignatureInfo {
                valid,
                key_missing: !valid,
                ..SignatureInfo::default()
            });
        }
        Box::pin(async move { Ok(outcome) })
    }
}

/// Interpret a byte slice as a 32-byte ed25519 public key.
fn ed25519_public_bytes(key: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_LEN]> {
    key.try_into().map_err(|_| {
        Error::Signature(format!(
            "ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
            key.len()
        ))
    })
}

/// The trusted and revoked key sets loaded from a sign-api key store, as raw
/// decoded key bytes. The engine that consumes them validates their length.
#[derive(Debug, Clone, Default)]
pub struct SignKeys {
    /// Keys from the `trusted.<type>` files and directories.
    pub trusted: Vec<Vec<u8>>,
    /// Keys from the `revoked.<type>` files and directories.
    pub revoked: Vec<Vec<u8>>,
}

/// The system directories searched for sign-api keys, in order. The second is
/// `<datadir>/ostree`.
const SYSTEM_KEY_ROOTS: [&str; 2] = ["/etc/ostree", "/usr/share/ostree"];

/// Load the sign-api key store for `sign_type` from the system search path
/// (`/etc/ostree` and `/usr/share/ostree`).
pub fn load_sign_keys(sign_type: &str) -> Result<SignKeys> {
    let roots: Vec<PathBuf> = SYSTEM_KEY_ROOTS.iter().map(PathBuf::from).collect();
    let refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    load_sign_keys_from(&refs, sign_type)
}

/// Load the sign-api key store for `sign_type` from the given search roots.
///
/// Under each root, reads the `trusted.<type>` file and every file in the
/// `trusted.<type>.d/` directory, and likewise `revoked.<type>` and
/// `revoked.<type>.d/`. Each line is one base64 key; blank and whitespace-only
/// lines are skipped and any other line must decode. A missing file or
/// directory is not an error. Directory entries are read in sorted name order.
pub fn load_sign_keys_from(roots: &[&Path], sign_type: &str) -> Result<SignKeys> {
    let mut keys = SignKeys::default();
    for root in roots {
        collect_keys(root, &format!("trusted.{sign_type}"), &mut keys.trusted)?;
        collect_keys(root, &format!("revoked.{sign_type}"), &mut keys.revoked)?;
    }
    Ok(keys)
}

/// Read `<root>/<base>` and every file in `<root>/<base>.d/` into `out`.
fn collect_keys(root: &Path, base: &str, out: &mut Vec<Vec<u8>>) -> Result<()> {
    read_key_file(&root.join(base), out)?;
    let dir = root.join(format!("{base}.d"));
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    for file in files {
        read_key_file(&file, out)?;
    }
    Ok(())
}

/// Read one base64-per-line key file into `out`. A missing file is not an error.
fn read_key_file(path: &Path, out: &mut Vec<Vec<u8>>) -> Result<()> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(base64::decode(line)?);
    }
    Ok(())
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
    assert_send_sync::<Ed25519Signer>();
    assert_send_sync::<Ed25519Verifier>();
    assert_send_sync::<VerifyOutcome>();
    assert_send_sync::<SignatureInfo>();
};
