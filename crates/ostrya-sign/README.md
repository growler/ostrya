# ostrya-sign

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

The engines that sign and verify ostree commits and summaries.

A caller signs a commit or a summary with a `Signer` and verifies it with
a `Verifier`. Each engine stores its signatures under its own key in the
detached metadata. The `ostrya` crate reads and writes this metadata and
loads the system key store. The crate compiles on Linux, macOS, and Windows.

API documentation: <https://docs.rs/ostrya-sign>

## Entry points

- `Signer` and `Verifier` are the traits of an engine.
- `Ed25519Signer` and `Ed25519Verifier` are the ed25519 engine.
- `DummySigner` and `DummyVerifier` are the dummy engine for tests.
- `append_signature` adds a signature to a detached-metadata dict.
- `read_key_file` reads a key file, and `SignKeys` holds the keys.

## Features

- `smol` (default): with `sign-gpg`, `GpgSigner` runs `gpg` on `smol`.
- `tokio`: with `sign-gpg`, `GpgSigner` runs `gpg` on `tokio`.
- `sign-spki`: the spki engine, `SpkiSigner` and `SpkiVerifier`, and
  `spki_public_keys`, which reads the keys of a public key file.
- `sign-gpg`: `GpgSigner`, which signs with the `gpg` command.

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
let outcome = block_on(verifier.verify(b"commit bytes", &[signature]))?;
assert!(outcome.valid);
```
