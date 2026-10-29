# ostrya-sign

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

The engines that sign and verify ostree commits and summaries.

A caller signs a commit or a summary with a `Signer` and verifies it with
a `Verifier`. Each engine stores its signatures under its own key in the
detached metadata. The `ostrya` crate reads and writes this metadata, loads
the system key store, and reads the GPG keyrings of the ostree paths. The
crate compiles on Linux, macOS, and Windows.

A `Verifier` verifies in the call to `Verifier::verify`, so a program
with no async runtime can verify. A `Signer` returns a future.

API documentation: <https://docs.rs/ostrya-sign>

## Entry points

- `Signer` and `Verifier` are the traits of an engine.
- `Ed25519Signer` and `Ed25519Verifier` are the ed25519 engine.
- `DummySigner` and `DummyVerifier` are the dummy engine for tests.
- `append_signature` adds a signature to a detached-metadata dict.
- `read_key_file` reads a key file, and `SignKeys` holds the keys.
- `X509Signer`, with the feature `x509`, is the trait of a signer
  with an X.509 certificate chain, for a CMS signature.
- `GpgVerifier`, with the feature `gpg`, is the GPG verifier.
  `gpg_keyring_keys` lists the keys of a keyring, and `gpg_offered_keys`
  and `gpg_merge_keyring` merge a keyring into another.

## Features

- `smol` (default): with `gpg-sign`, `GpgSigner` runs `gpg` on `smol`.
- `tokio`: with `gpg-sign`, `GpgSigner` runs `gpg` on `tokio`.
- `spki`: the spki engine with each of its key types: ECDSA P-256, ECDSA
  P-384 with SHA-256, pure Ed25519 of RFC 8032, and RSA PKCS#1 v1.5 with
  SHA-256. The engine is `SpkiSigner` and `SpkiVerifier`,
  `spki_public_keys`, which reads the keys of a public key file,
  `spki_secret_keys`, which reads the signers of a PEM secret key file,
  and `spki_secret_key_lines`, which reads the signers of a file of base64
  key lines. The ed25519 engine needs no feature.
- `gpg`: `GpgVerifier`, which verifies GPG signatures in the process
  with rPGP, and the keyring functions `gpg_keyring_keys`,
  `gpg_offered_keys`, and `gpg_merge_keyring`, with `GpgKey`,
  `GpgOfferedKeys`, and `MAX_KEYRING`. The feature holds no runtime.
- `gpg-sign`: `GpgSigner`, which signs with the `gpg` command. It does
  not turn on `gpg`.
- `x509`: the trait `X509Signer`. With `spki`, also `X509SpkiSigner`, the
  spki signer with an X.509 certificate chain, which
  `SpkiSigner::with_certificates` makes, and
  `SpkiVerifier::from_certificates`, which trusts the keys of X.509
  certificates. The feature validates no certificate chain.

## Examples

```rust
use futures_lite::future::block_on;
use ostrya_sign::{Ed25519Signer, Ed25519Verifier, Signer, Verifier};

// The key of test 1 in RFC 8032: the 32-byte seed, then the public key.
let secret = ostrya_core::base64::decode(concat!(
    "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6",
    "DuFy89qmIyWvAhpo9wdRGg==",
))?;
let signer = Ed25519Signer::from_secret_key(&secret)?;
let signature = block_on(signer.sign(b"commit bytes"))?;
let verifier = Ed25519Verifier::new([&secret[32..]], Vec::<&[u8]>::new())?;
let outcome = verifier.verify(b"commit bytes", &[signature])?;
assert!(outcome.valid);
```
