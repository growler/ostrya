# Ostrya -- Design Decisions

This document records the design decisions of the port and the alternatives
that were rejected, with the reason for each. The on-disk format is in
`format-reference.md`. The observed behavior of the `ostree` command is in
`conformance/cli-behavior.md`, and each difference from it is in
`conformance/cli-surface.md`. The rustdoc of each crate documents the API.

## Dependency policy

The port is pure Rust. The Rust crate ecosystem is in scope, and C libraries
are excluded. `CLAUDE.md`, "Goals", states the two exceptions: `liblzma` for
xz, and PCRE2 in the `ostrya-cli` binary alone. Each is built from source and
linked statically under its feature, and needs no C runtime beyond the libc
that `std` links.

These C libraries are excluded, with the Rust path that replaces each:

- `openssl-sys` -- TLS through `rustls` with the `rustls-graviola` provider,
  and ECDSA through `p256` and `p384`.
- `libgpg-error` and `gpgme` -- GPG signing through the system `gpg` binary,
  and GPG verification through the `pgp` crate.
- `libcurl` and `libsoup` -- HTTP through `hyper`.
- `libarchive` -- tar through `smol-tar`.
- `libcomposefs` -- composefs images through `ostrya-composefs`.
- `glib` -- GVariant through `ostrya-gvariant`, and the key file through
  `ostrya-core`.

Two CI steps in `.github/workflows/ci.yml` hold the rules over the whole
graph. One step holds the permissive-license rule. The other step fails on a
package that declares a `links` key and is not on its allowlist. The comments
of the two steps state their rules.

## Foundation crates

The workspace crates take these external crates directly. `CLAUDE.md` has an
"Authorized" section for each crate it marks so, with the terms of its
feature set and its graph.

- `rustix` -- the syscalls that a portable async file API cannot express:
  fd-relative open, stat, link, rename, readlink and mkdir, xattrs, statx,
  statvfs, FICLONE, O_TMPFILE with linkat, record locks, and fsync and
  syncfs.
- `smol` -- the default runtime backend, in `ostrya-rt` alone.
- `tokio` -- the optional runtime backend, in `ostrya-rt` alone.
- `futures-io` and `futures-lite` -- the async traits and the combinators
  that the library is written against.
- `pin-project-lite` -- pin projection for the stream wrapper types.
- `sha2` -- SHA-256, for object checksums, for fs-verity digests, and for
  the SigV4 signer of the `s3` feature of `ostrya-remote`.
- `hmac` -- HMAC-SHA256 for the SigV4 signer, in `ostrya-remote` under its
  `s3` feature. See "SigV4 and the AWS credentials".
- `miniz_oxide` -- the raw DEFLATE encoder of archive-mode content objects.
  `ostrya-core` takes it directly, so the stored `.filez` bytes for a given
  `[archive] zlib-level` are the same under each feature set. The golden
  SHA-256 vectors in `crates/ostrya-core/src/deflate.rs`, one for each level
  from 1 to 9, fail the test suite if a new version writes other bytes.
- `async-compression` -- streaming DEFLATE inflate of archive-mode content
  objects, and streaming xz of static-delta parts.
- `liblzma` -- the xz codec behind `async-compression`.
- `bsdiff` -- bspatch stream generation for static deltas. It has no
  dependencies and no `unsafe`. The port reads the streams with its own
  bspatch.
- `smol-tar` -- async tar import and export.
- `ed25519-dalek` -- the ed25519 sign engine and the Ed25519 key type of the
  spki sign engine, in `ostrya-sign`.
- `p256` -- the spki sign engine, in `ostrya-sign`.
- `pgp` -- OpenPGP keyring parsing and signature verification.
- `hyper` -- the HTTP/1.1 and HTTP/2 engine of `ostrya-fetch` and
  `ostrya-server`. Both crates take version 1.11.1 or later. Version 1.11.0
  can keep the last chunk of a response body in its write buffer when the
  first poll of the body is pending, and then the response does not end.
- `rustls`, `rustls-graviola`, `futures-rustls`, `rustls-native-certs` and
  `rustls-pemfile` -- TLS. See "TLS stack".
- `url` and `pkcs8` -- in `ostrya-fetch`.
- `getrandom` -- in `ostrya-server`.
- `x509-cert` -- in `ostrya-server`, and in `ostrya-sign` under the feature
  `sign-x509`.
- `thiserror` -- the error types.
- `libc` -- in `ostrya-sys`, `ostrya-remote` and `ostrya-sign`.
- `clap` -- command-line parsing, in `ostrya-cli` and `ostrya-mountd`.
- `pcre2` -- the `commit --tar-pathname-filter` expression, in `ostrya-cli`
  alone. See "The expression engine of `--tar-pathname-filter`".
- `indicatif` -- the progress bar of `push` and `push-tree`, in `ostrya-cli`.

## The repository lock

The lock on `<repo>/.lock` is a classic `fcntl` record lock (`F_SETLK`,
through `rustix::fs::fcntl_lock`). An OFD lock was rejected: `rustix` does
not expose the OFD commands, and a raw OFD call needs the `libc` crate and
`unsafe` code.

A record lock and an OFD lock share one lock space. Thus the port and the
`ostree` command exclude each other on the same repository. This was
verified in both directions: each side held its lock while the other side
tried to get the lock.

A record lock belongs to the process, and the kernel releases it when the
process closes any descriptor of the file. Thus a process-global registry,
keyed by the `(device, inode)` of the lock file, keeps one descriptor and one
reference count for each repository. `crates/ostrya/src/lock.rs` documents
the registry.

## The GVariant codec

`ostrya-gvariant` is a GVariant codec written in the tree for the fixed type
set of ostree. No crate was taken, because the port needs byte-exact normal
form and decode with no heap allocation on the read paths.

Each object type has a hand-written codec impl. A proc-macro derive was
rejected. The set of object types is small and fixed, and a derive adds a
proc-macro crate together with `syn`, `quote` and `proc-macro2`. A derive
needs a dependency proposal under the confirmation rule of `CLAUDE.md`.

## The composefs writer

`ostrya-composefs` writes the composefs EROFS image. It is written in the
tree because no crate writes byte-exact composefs images under the no-C
rule. These crates were examined and rejected:

- `erofs/erofs-rs` and `Dreamacro/erofs-rs` read EROFS images and do not
  write them. Neither knows composefs.
- `composefs` (`containers/composefs-rs`, MIT OR Apache-2.0) writes images
  that are byte-identical to `mkcomposefs`. It has a non-optional `zstd`,
  which links C through `zstd-sys`, and a full `tokio`. No feature turns
  either off.
- `am-fs-erofs` writes generic EROFS images. It has no overlay xattrs and no
  fs-verity, and its byte layout is different from composefs.
- `lamfold-erofs`, `gobblytes-erofs`, `liberofs`, `erofs` and `nydus-rs`
  read images only, are stubs, or are container-image stacks.

`ostrya-composefs` writes only the metadata subset that composefs uses, and
no EROFS compression.

The fs-verity digest is a SHA-256 Merkle calculation over `sha2`. The
`fs-verity` crate was rejected because it takes `libc` with no condition.

The XATTR_FILTER field hashes each xattr name with xxHash32. The xxHash32 in
`crates/ostrya-composefs/src/xxhash.rs` is written in the tree to add no
crate. The golden filter bytes verify it.

## The composefs image object

The port stores the composefs image of a commit as an object of the type 100
(`format-reference.md`, "The composefs image object"). The `ostree` command
does not know this type. A read of a port repository that holds images by
the `ostree` command is not a goal. The cross-checks in which the `ostree`
command reads the output of the port cover repositories and static deltas
with no image. The port reads the repositories and the static deltas of the
`ostree` command.

## The mount daemon

`ostrya-mountd` mounts a commit as composefs for a caller in a user
namespace of its own. The kernel forced these choices:

- Each request runs in a worker process, the daemon binary run again. The
  kernel refuses `setns(CLONE_NEWUSER)` in a process with more than one
  thread. A process that enters a user namespace cannot go back to its
  parent namespace. Thus a thread of the runtime pool cannot do the steps
  on the side of the caller.
- The worker gives the daemon `open_tree(OPEN_TREE_CLONE)` copies of the
  repository directory and of `objects`. overlayfs takes a layer only from
  the mount namespace of the mounter or from a detached mount, and the
  daemon mounts in its own mount namespace.
- The worker makes an `open_tree(OPEN_TREE_CLONE)` copy of the composefs
  mount of the daemon. overlayfs takes a detached layer only from a process
  with `CAP_SYS_ADMIN` in the user namespace that owns the detached mount.
  The daemon makes the composefs mount in the initial user namespace, so the
  top overlay of the worker on the detached mount of the daemon fails with
  EPERM. The copy belongs to the user namespace of the caller.

The daemon checks that the sent user namespace owns the sent mount
namespace, and that it is not the initial user namespace. It does not check
that the peer is a member of the namespaces that it sends. A client such as
ostree-podman sends the namespaces of podman, which are not its own.

## The spki sign engine

The spki engine is pure Rust. It has four key types: ECDSA on NIST P-256
with SHA-256 over `p256`, ECDSA on NIST P-384 with SHA-256 over `p384`,
pure Ed25519 over `ed25519-dalek`, and RSA PKCS#1 v1.5 with SHA-256 over
`rsa` 0.9.10. The engine signs ECDSA with RFC 6979 nonces, so one key and
one data give the same signature bytes. The `ostree` command builds this engine only with OpenSSL,
and it signs ECDSA with a random nonce. The two forms verify the same way.
Ed25519 (RFC 8032) and RSASSA-PKCS1-v1_5 (RFC 8017) are deterministic on
both sides.

The `ostree` command signs ECDSA with SHA-256 on each curve, also on P-384.
The default `Signer` and `Verifier` of `p384` hash the data with SHA-384, so
the engine does not call them. It hashes the data with SHA-256 and calls
`sign_prehash` and `verify_prehash`. `sign_prehash` makes the RFC 6979 nonce
of a prehash with HMAC-SHA-384. So a P-384 signature of the port is the same
bytes for one key and one data, and it differs from the RFC 6979 test vectors
for P-384 with SHA-256, which use HMAC-SHA-256. The verify does not depend on
the nonce. A round trip of the port alone does not find a wrong digest, so
the P-384 fixtures that the `ostree` command signs are part of the tests.

An Ed25519 key signs the data itself, with no prehash and no context. The
signature is 64 bytes, `R || S`. The verify is `VerifyingKey::verify` of
`ed25519-dalek`, the verify of the ed25519 engine. It checks `[S]B = R +
[k]A` with no cofactor, refuses an `S` that is not below the group order,
and accepts a public key of small order. The `ostree` command gives the same
result for each of these cases. `verify_strict` was rejected: it refuses a
public key of small order, which the `ostree` command accepts. The ed25519
engine and the Ed25519 key type of the spki engine share no code. They write
the same bytes for one seed and one data, under two metadata keys, and the
verifier of each engine trusts only the keys of its own engine. The feature
`pkcs8` of `ed25519-dalek` reads the SubjectPublicKeyInfo of a key and
writes it again. The engine reads the fields of a PKCS#8 key itself, because
the `KeypairBytes` of `ed25519` wipes its copy of the seed only with a
feature that the build does not turn on.

The RSA signer blinds each private-key operation with a random value from the
operating system. The blinding does not change the signature. RUSTSEC-2023-0071
applies to `rsa` 0.9.10, and `CLAUDE.md`, "Advisory exceptions", states the
terms of the exception. `roadmap.md` records the move to a release of `rsa`
with the fix.

The engine takes an RSA modulus of 2048 to 16384 bits. OpenSSL verifies no
signature of a modulus above 16384 bits: `openssl dgst -verify` writes
`modulus too large`. The `ostree` command signs with such a key, and its
verify then fails. The `ostree` command signs and verifies with a 512-bit
key, and the port refuses it. `RsaPublicKey::new` of `rsa` 0.9.10 caps the
modulus at 4096 bits, and the SubjectPublicKeyInfo decoder of the crate calls
it. The private-key decoders of the crate apply no cap. They give general
errors, such as `KeyMalformed`, that do not state the reason of a refusal. So
the engine does not use the decoders of the crate. It reads the
`RSAPublicKey` and `RSAPrivateKey` structures with the `pkcs1` crate that
`rsa` exports, checks the size of the modulus and the number of primes, and
gives a message for each refusal. It then calls
`RsaPublicKey::new_with_max_size` with 16384 bits or
`RsaPrivateKey::from_components`. A direct dependency on `pkcs1` was
rejected, because the re-export gives the same crate.

The engine refuses a secret key of more than two primes. The `ostree` command
signs with keys of 3, 4, and 5 primes. `RsaPrivateKey::from_components` takes
more than two primes, so the engine reads the version of the `RSAPrivateKey`
before the call. The public key of a multi-prime key is a modulus and an
exponent, and the engine takes it. The engine refuses an `rsaEncryption` key
whose parameters are not `NULL`. The `ostree` command verifies with a key
with no parameters field, and with a key with an OID in the field.

The engine tells the three secret key forms apart by their ASN.1 structure.
After the version, a PKCS#8 `PrivateKeyInfo` holds an `AlgorithmIdentifier`,
a PKCS#1 `RSAPrivateKey` holds an `INTEGER`, and a SEC1 `ECPrivateKey` holds
an `OCTET STRING`. A PKCS#1 key is RSA. The version of a PKCS#1 key is 0 or
1, so a multi-prime PKCS#1 key gets the refusal of its primes.

The engine has one feature for each key type. `sign-spki-p256` gates the
P-256 key type, and `sign-spki` turns on each key type. The code that the key
types share -- the PEM splitter, the OID dispatch, and the key file readers --
compiles when one key feature is on. This code takes `der`, `spki`, `pkcs8`,
and `pem-rfc7468` as direct dependencies, and not through the re-exports of
`p256`, so a key type that does not use `p256` builds the engine with no
`p256`. `sign-spki-p384` gates the P-384 key type, `sign-spki-ed25519`
gates the Ed25519 key type, and `sign-spki-rsa` gates the RSA key type. A
build with one of the three alone has no `p256`. A build with no key feature has no ECDSA crate tree. The gates of the
shared code take the form `any(feature = ...)` over the key features, so each
key feature adds one item to each gate. `ostrya` and `ostrya-sign` allow the
clippy lint `non_minimal_cfg`, which refuses a gate of this form with one
item. Two other forms were rejected. A hidden feature that each key feature
turns on is a public feature of a published crate. A build script that sets a
private cfg adds a build script to two crates.

A build without a key type refuses a key of that type, with the
`Error::Signature` message `this build has no code for <the key type RSA |
the key type Ed25519 | the curve P-256 | the curve P-384>; build with the
<feature> feature`. A signature of that type
is a blob that no trusted key verifies. A revoked key that the build cannot
read refuses the key store, so the revocation fails closed.

The algorithm OID of a key selects its key type, and the curve OID selects the
curve of an EC key. The engine refuses each key type and each curve outside
its set, and an EC key with explicit curve parameters. Explicit parameters let
a key name a curve of its own. The `ostree` command signs and verifies with
such a key. `conformance/cli-surface.md` records the differences.

The verify is strict. A trusted key tries a blob only when the blob parses in
the signature form of its key type, and a blob is valid only when a trusted
key verifies it. The `ostree` command with OpenSSL reports a valid signature
for blobs that no trusted key verifies. `conformance/cli-surface.md`, `sign`,
records the observed results.

The revocation compare and the fingerprint use one rule. The port encodes the
SubjectPublicKeyInfo DER of a key again from the decoded key, with an
uncompressed EC point, with `id-Ed25519` and no parameters for an Ed25519
key, or with `rsaEncryption` and `NULL` parameters for an RSA key. The DER of
an Ed25519 key holds the 32 bytes of the key as they were given: the port
does not encode the point again, so a non-canonical encoding of a point is a
key of its own. A trusted key whose DER is in the revoked set is not
trusted. The fingerprint of a verified signature is the SHA-256 of this DER
in lowercase hex. So two forms of one key give one key and one fingerprint. A
compare of the typed values of each key type was rejected: the DER is a
function of the decoded key and holds the algorithm OID, so one compare serves
each key type. The GPG engine keeps its uppercase hex fingerprint. The report
of `sign --verify` and `summary --verify` prints the fingerprint under the
GPG engine alone.

The OpenSSL build of the `ostree` command on the development host has the
spki engine. The tests in `crates/ostrya/tests/sign_spki_fixtures.rs` compare
the engine with this build in both directions for each key type: the port
verifies the signatures of the fixtures that the tool wrote, and the tool
verifies a commit, a summary, and a static delta that the port signs. Without
this build, the second direction skips. The test `spki_openssl_interop`
compares the engine with the `openssl` command in both directions.

The spki signer signs in the call to `Signer::sign`, and its future is ready
at once, so a program with no async runtime can sign and verify. An RSA
signature with a 16384-bit key takes about 0.5 seconds of CPU time. The
receive endpoint of `ostrya` signs with the spki key of an `[ex-ostrya key]`
group on the blocking pool, through `ostrya_rt::unblock`, so the signature
does not hold the async executor. The trust check of the receive endpoint
runs the verifiers of the sign-api axis on the blocking pool too, with a copy
of the commit, because a client sets the number of signature blobs that the
check verifies. The summary check of a pull runs these verifiers on the
blocking pool, with a copy of the summary, because a summary can be as large
as 64 MiB. The GPG verifier moves its own work to the blocking pool. A
sign future in `ostrya-sign` that moves the work to the blocking pool was
rejected, because the engine then needs a runtime.

The spki verifier computes the SHA-256 of the data one time for each call,
when the first ECDSA or RSA key tries a blob. Each of these keys verifies the
blob with this hash. A store of many keys then hashes a commit one time, and
a blob that no key tries computes no hash. An Ed25519 key verifies with the
data and computes no SHA-256.

With the feature `sign-x509`, `ostrya-sign` has the trait `X509Signer`, with
the supertrait `Signer`. The trait gives the values of a CMS `SignerInfo` for
a signature with an X.509 certificate chain, for example an Authenticode
signature of a UEFI image. `certificates()` gives the DER of each
certificate: the certificate of the signer first, then the intermediate
certificates in chain order. `signature_algorithm()` and
`digest_algorithm()` give DER `AlgorithmIdentifier` values. `Signer::sign`
hashes the data with the digest algorithm and signs the hash. For
Authenticode, the data is the DER of the CMS signed attributes. The methods
other than `sign` need no private key. So a signer whose key is in a hardware
token, an HSM, or a key service can implement the trait with no change to
the traits.

`SpkiSigner::with_certificates` consumes a signer and gives an
`X509SpkiSigner`, which implements `Signer` and `X509Signer`. `SpkiSigner`
does not implement `X509Signer`, so `certificates()` always holds the
certificate of the signer. The constructor refuses an empty list, and a
first certificate whose key is not the key of the signer. It compares the
two keys by the rule of the revocation compare. It decodes each intermediate
certificate, and does not read its key.

The signature algorithm of an RSA key is `rsaEncryption` with `NULL`
parameters. `sha256WithRSAEncryption` is not used: `sbsign` and
`systemd-sbsign` of Debian trixie write `rsaEncryption` with `NULL`, and
firmware reads this form. The signature algorithm of a P-256 key and of a
P-384 key is `ecdsa-with-SHA256` with no parameters, because the engine
signs with SHA-256 on each curve. The digest algorithm is SHA-256 with
`NULL` parameters. The engine keeps these values as DER constants.

Ed25519 is outside the trait. An Ed25519 key signs the data and not a hash,
and Authenticode for UEFI does not use Ed25519. `with_certificates` refuses
an Ed25519 signer.

The port builds no CMS structure and no Authenticode structure, and it reads
no PE file. The caller builds these structures with the values of the trait.

`SpkiVerifier::from_certificates` trusts the SubjectPublicKeyInfo of each
certificate that it gets as DER or as PEM `CERTIFICATE` blocks. It validates
no chain, no signature of a certificate, and no validity period. A key from
a certificate, from a PEM `PUBLIC KEY` block, and from a SubjectPublicKeyInfo
DER is one trusted key, with one fingerprint. The function trusts the key of
an Ed25519 certificate.

The engine decodes a certificate with `x509-cert`, which reads strict DER. A
hand-written walk of the ASN.1 structure to the SubjectPublicKeyInfo was
rejected: a strict decode of the full structure refuses each malformed
certificate, and a walk to one field does not. `x509-cert` 0.2.5 was in the
graph through `ostrya-server`, so no package enters `Cargo.lock`.

The feature `sign-spki` does not turn on `sign-x509`. `X509SpkiSigner`
needs `sign-x509` and one of the key features `sign-spki-p256`,
`sign-spki-p384`, and `sign-spki-rsa`. `SpkiVerifier::from_certificates`
needs `sign-x509` and one of the four key features. `sign-x509` alone gives
the trait `X509Signer` alone.

## GPG

Signing runs the system `gpg` binary as a subprocess over its `--status-fd`
interface. Thus keys in an agent and keys on a hardware token work through
`gpg` with no code of their own, and the private key stays with `gpg`.

Verification is in the process, over the `pgp` crate. `sequoia-openpgp` was
rejected for its LGPL license. The port owns the trust policy: issuer
resolution, subkey bindings, expiry, revocation, the signature class and the
digest policy. No fallback to the `gpgv` binary exists, so one engine and one
policy give each verdict.

## The signature policy of a local pull

`Repo::pull_local` takes each field of `PullVerify` that is `None` from the
`[remote "NAME"]` section that `PullOptions::remote` names. The four keys
apply: `gpg-verify` (default true), `gpg-verify-summary`, `sign-verify`, and
`sign-verify-summary`. For a remote with a section, the defaults are those of
`Repo::pull`. So a local pull and a pull over HTTP of one remote apply one
policy. The rule is in the library, so each caller of `Repo::pull_local` gets
it.

A remote name with no section gives no check. So `--remote` can name a ref
namespace alone. A field that is `Some(true)` turns on its check for a name
with no section too, and with no key the check fails. `Repo::pull` applies the
defaults of a described remote to a name with no section, so its GPG check of
the commits is on.

`ostrya pull-local` has the off switches `--no-gpg-verify`,
`--no-gpg-verify-summary`, `--no-sign-verify`, and `--no-sign-verify-summary`.
Each switch sets its field of `PullVerify` to `Some(false)`. The two summary
off switches need `--remote`. `--no-gpg-verify` and `--no-sign-verify` need
`--remote` or `--trust`, because each one also turns off an axis of the trust
group that `--trust` names. Each off switch conflicts with its positive
switch.
`--sign-verify` and `--sign-verify-summary` set `sign` and `sign_summary` to
`Some(true)` and need `--remote`. Each one selects each engine of the build,
as `ostrya pull --sign-verify` does. The two GPG switches and the two sign
switches take no value. The `ostree` command reads `--gpg-verify=false` as
`--gpg-verify`, so a valued form of a GPG switch in the port would give that
spelling a different meaning. The `ostree` command has no `pull-local
--sign-verify` or `--sign-verify-summary`, so the two sign switches take no
value to match the GPG switches.

Two alternatives were rejected:

- The rule of the `ostree` command, where only a switch turns on a check. The
  command reads none of the four keys for `pull-local`
  (`conformance/cli-behavior.md`, "Signature verification during a pull").
  So a local pull accepts an unsigned commit from a remote whose config
  requires a signature, and a pull over HTTP of the same remote refuses it.
- The config read with no off switch. A configured check would then apply
  to each local pull of the remote, and a command line could not turn it off.

## The trust group of a remote

The remote key `trust=NAME` names a trust group `[ex-ostrya trust "NAME"]`.
The group supplies the commit keys of each pull from the remote. The key name
has no prefix, as the other remote keys of the port (`ssh-command`,
`push-user`, `s3-region`). The value is the quoted part of the group name.

Each pull reads the key: `pull` over HTTP, over ssh, and from an `s3://`
address, `pull --collection`, and `pull-local`. `PullTrust::resolve` reads
it, and each pull calls that function.

The group sets the commit policy alone. The remote keys `gpg-verify-summary`
and `sign-verify-summary`, and the key sources that they read, set the
summary policy. So `ostrya remote fsck NAME` keeps its summary check. A trust
group refuses `gpg-verify-summary` and `sign-verify-summary` on the receive
side and on the pull side, because a trust group sets a commit policy alone.
The commit policy and the summary policy share no verifier. So the GPG check
of the summary cannot take the verifier of the group, which reads no
repository keyring.

With a trust group, the pull refuses `Some(true)` in `PullVerify::gpg` or
`PullVerify::sign` with `Error::InvalidInput`. `Some(false)` in one of the two
fields turns that commit axis of the group off. The summary fields override
the summary keys of the remote, as without a trust group. `ostrya remote
fsck NAME` sets both commit fields to `Some(false)`, so it reads no key of
the group.

Beside `trust`, the pull refuses a remote key that turns on a commit check:
`gpg-verify=true`, and a `sign-verify` value other than false. It accepts
`gpg-verify=false`, which `remote add --no-gpg-verify` writes. An absent
`gpg-verify` gives no GPG check of the commits, because the group sets the
commit policy. The pull also refuses a key source of the remote that no
summary check reads: `gpgkeypath` without a GPG summary check, and a
`verification-ENGINE-key` or a `verification-ENGINE-file` of an engine that
the summary check does not select. This rule reads the summary keys of the
config, and not the overrides of `PullVerify`. So an override that turns the
summary check off for one pull does not make the remote refused. A summary
key of the remote that the pull reads and cannot parse is refused too. Each
refusal comes before the pull reads a key source and before it fetches
anything.

A pull checks and builds the one trust group that it names, and no other
group. `ostrya receive` and `ostrya serve` keep their check of each group.

The commit policy of a group reads no repository keyring
`<repo>/NAME.trustedkeys.gpg` and no system key store. So the keys that
`ostrya remote gpg-import NAME` writes do not check the commits of a remote
with `trust=NAME`. The GPG check of the summary still reads them. The pull
does not refuse the keyring file, and `ostrya-config(1)` states the rule.

Three alternatives were rejected:

- A key that `pull-local` alone reads. A pull over HTTP of the same remote
  would then use the keys of the remote, with no message.
- A trust group with no summary check. The summary keys of the remote would
  then apply to no check, and `ostrya remote fsck NAME` would verify no
  summary of such a remote.
- A refusal of each `Some` field of `PullVerify`. `Some(false)` makes the
  policy of the group smaller and never larger, and `ostrya remote fsck
  NAME` sets it. The summary fields do not touch the group.

## The trust group of one pull

`PullOptions::trust_group` names a trust group `[ex-ostrya trust "NAME"]` for
one pull. The field applies to each pull that reads its policy from the
config: `Repo::pull` over HTTP, over ssh, and from an `s3://` address,
`Repo::pull_collection`, and `Repo::pull_local`. `Repo::pull_with_session`
takes its keys from the trust of the caller, so it refuses the field with
`Error::InvalidInput`.

The field wins over the remote key `trust`, and the pull then does not read
the key. The rules of "The trust group of a remote" apply to the group that
the field names: the refusal of `Some(true)` in `PullVerify::gpg` and
`PullVerify::sign`, the refusal of the commit keys of the remote, and the
summary policy from the summary keys of the remote. A name that is malformed
or names no group is `Error::InvalidInput`, because the name comes from the
caller and not from the config.

A local pull with the field needs no remote. With no remote, no section
supplies the summary keys, so the pull checks no summary. A summary field that
is `Some(true)` then fails with `Error::Pull`, as it does with no field.
`PullOptions::remote` still names the ref namespace.

The option `--trust=NAME` of the command is on `ostrya pull-local` alone.
`ostrya pull --trust` is in `roadmap.md`.

Two alternatives were rejected:

- `--trust` on each pull command now. The library field gives each pull the
  rule, and the option of the other commands can come later with no change
  to the library.
- A field that `Repo::pull_local` alone reads. A pull over HTTP with the same
  options would then use the keys of the remote, with no message.

## TLS stack

The fetcher uses `rustls` 0.23 with `rustls-graviola` 0.4 as the crypto
provider. The provider is Rust together with formally verified assembly from
s2n-bignum, so the build needs no C compiler and no `cc` build dependency.
The provider supports x86_64 and aarch64 alone. A build for another target
needs a different provider in `crates/ostrya-fetch/src/tls.rs`.

`rustls-native-certs` reads the trust store of the host. `webpki-roots` was
rejected: its license, CDLA-Permissive-2.0, is not on the permissive list.

`h2` puts `tokio` and `tokio-util` into the graph under the `smol` backend
too. The fetcher uses only their I/O traits and codec framing, and drives no
tokio runtime.

## The HTTP adapters

The adapters between `hyper` and `futures-io` keep `forbid(unsafe_code)`.
They fill the read cursor of `hyper` through its safe `put_slice`. This
costs one copy for each read, because a read into the uninitialized buffer
needs `unsafe` code.

The request body is a `Body` type of the fetcher, so `http-body-util` is not
a dependency. The `basic` authorization header is encoded by
`ostrya-core::base64`, so no base64 crate is a dependency.

## Request signing in the fetcher

`ostrya_fetch::RequestSigner` is a hook that adds headers to each attempt.
The fetcher calls it after it takes the connection, for each retry, each
round, and each redirect hop at the origin that the route names. A hop at
another origin gets no signature. A signer is a credential: the fetcher
refuses it beside basic-auth credentials, a bearer token, or an
`Authorization` header, and toward a cleartext mirror without the permission
of the caller. The same refusal applies to these credentials on a fetch or
an upload: the request fails before admission, and the signer is not called.
Each header value of the signer is marked sensitive, so an HTTP/2
connection never adds it to its header compression table.

A presigned query for each target was rejected, for three reasons:

- A signature with a date must be fresh when the request leaves. A retry
  after a backoff, or a request that waits for a connection, needs a new
  date. The hook signs each attempt.
- The signature stays in a credential header, which the fetcher marks
  sensitive and keeps from other origins. A presigned signature is part of
  the URL, and each error message of the fetcher prints the URL.
- A signed `PUT` with the signature in its headers signs the hash of the
  body.

The signer gets a body given whole as a slice of the request body, with no
copy. A body of `UploadBody::bytes` reaches the signer as
`SignPayload::Bytes`, and the signer hashes it on the task of the request,
on each call. A body of `UploadBody::bytes_with_sha256` carries the SHA-256
that the caller computed. It reaches the signer as `SignPayload::Sha256`,
with the slice and the digest, so the signer hashes no byte of it. The
upload gives the same digest to the signer of each attempt, each retry, and
each redirect hop, and a copy of the body keeps the digest. The fetcher does
not check the digest, and it does not hash a body itself: `ostrya-fetch`
has no SHA-256 code. A streamed body reaches the signer as
`SignPayload::Streamed`, with no bytes.

## SigV4 and the AWS credentials

`ostrya_remote::s3::SigV4` is the AWS Signature Version 4 code, written in
the tree over `sha2` and the `hmac` crate 0.12.1. The algorithm is a fixed
sequence of hashes and string joins, and the AWS documentation gives worked
examples with full inputs and outputs. The unit tests check the signer
against these examples. `hmac` was in `Cargo.lock` before the feature, so no
package entered the graph. Two alternatives were rejected:

- HMAC-SHA256 written in the tree too, over `sha2`. It adds no manifest
  entry, but it is cryptographic code that the RustCrypto crate `hmac`
  already supplies, and that crate is in the graph.
- A SigV4 crate, for example `aws-sigv4` or `rusty-s3`. Each one brings
  packages that are not in `Cargo.lock`, and `rusty-s3` makes presigned URLs
  alone, which "Request signing in the fetcher" rejects.

`ostrya_remote::s3::resolve` reads static key pairs alone: the environment
variables, then the shared credentials file, then the shared config file,
with an optional session token. A profile section that names another source
(`role_arn`, `source_profile`, `credential_process`, `web_identity_token_file`,
or a key that starts with `sso_`) is refused with an error that names the
file, the section, and the key. The chain does not skip to the next source,
so the port never signs with an identity other than the one that the profile
names. If the environment gives the key pair, these keys are not read. The
full chain of the AWS SDKs, with STS, IMDSv2, and the container endpoint, was
rejected: it is a large part of the work, and each source needs a test
server of its own.

A profile that the caller names skips the key pair, the region, and the
endpoint of the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION`,
`AWS_ENDPOINT_URL_S3`, and `AWS_ENDPOINT_URL`). The chain reads the shared
files for that profile alone. Without this rule, a named profile `prod` with
`AWS_ENDPOINT_URL` set for a test server sends requests that the key of
`prod` signs to the test server, and `AWS_ACCESS_KEY_ID` wins over the named
profile. A profile from `AWS_PROFILE`, or the profile `default`, keeps the
order of the AWS documentation, where the keys of the environment win. The
order of the AWS documentation in all cases was rejected for these two
reasons.

When no source gives a region, the region is `us-east-1`. SigV4 puts the
region into the scope of each signature, so each request carries a region.
A server that does not check the region then needs an endpoint alone. A
server that checks its own region, and an AWS bucket outside `us-east-1`,
needs a region from the caller, the environment, or the config file. The
region changes no byte of the repository, only the signature. A default
that applies only with an endpoint of the caller was rejected.

## Error responses of a fetch

`ostrya_fetch::FetchRequest::max_error_body` asks a fetch to keep the
unsuccessful response that it reports. `Error::HttpStatus` then carries an
`ErrorResponse` with the headers of that response, and its body if the whole
body is within the cap. A fetch that does not set the field reads no error
body, as before. The bucket client of S3 needs the field: the code and the
message of an S3 error, and the region of a bucket, are in the body and in
the headers of the error response.

- A fetch reads the body of a failure only if the failure order can make it
  the reported failure. So it reads at most two bodies, one retryable and
  one definitive, and keeps the body of the failure that it reports.
- The read has one progress window from the arrival of the response head.
  A body over the cap, a coded body, a stalled body, and a body that fails
  in transit give the headers alone. The fetch keeps no part of a body.
- The declared length of a body is a claim of the server, so the read
  reserves at most 64 KiB before the body arrives. The capacity of a kept
  body never passes the cap. A cap of `u64::MAX` and a response that
  declares 1 PiB then cost no allocation of 1 PiB.
- The read never changes the retry class of a status, and the kept bytes do
  not count in the received counters.
- `ostrya::Error::HttpStatus` does not carry the response. Its conversion
  from the fetch error drops it, so the error type of the library keeps its
  shape.
- `Error::HttpStatus` of `ostrya-fetch` has no `#[non_exhaustive]`. A caller
  outside the crate can build each variant, and a pattern names the new
  field or ends in `..`.

These alternatives were rejected:

- `UploadMethod::Get`, a `GET` through `Fetcher::upload`, which gives each
  final status with its headers and a capped body. The bucket client then
  owns the retries of its `GET` requests, and a streamed object loses the
  refetch of a failed body and the low-speed rule of a fetch. The
  maintainer chose the change of the fetch.
- A `Fetched::Status` variant, which makes each caller of `fetch` match an
  unsuccessful status as a success.
- A new `Error` variant for a status with a response. Each caller that
  matches `Error::HttpStatus` then also matches the new variant.
- A per-request switch of redirect following. `max_redirects` of the
  fetcher already gives each redirect as a status at the limit of zero.
- A truncated prefix of a body over the cap. The caller cannot tell a
  truncated XML document from a malformed one.

An upload gives each final status as an `Uploaded`. An answer other than
2xx whose body declares a coding, or a `Content-Length` over
`max_response`, keeps its status and its headers, and the upload withholds
the body: `Uploaded::body_withheld` returns `true`, and the body reads as
empty. A 2xx answer with such a body fails the upload with
`Error::UploadInterrupted`. So a definitive refusal, for example
a 403 behind a proxy that compresses it, keeps its status, and the bucket
client of S3 does not send it again as an interrupted upload. An
interrupted upload in place of the status was rejected: the caller loses
the status, and repeats a request that the server refused.

## The S3 bucket client

`ostrya_remote::s3::Bucket` is the client of a bucket repository, in the
module `s3` of `ostrya-remote`, under the feature `s3`. `ostrya-remote`
holds the transports of push and pull and the type `Endpoint`, so the
client side of S3 goes there with the signer and the credential chain. A
new published crate `ostrya-s3` was rejected: it needs a `README.md`, a place
in the release sequence, and the same dependencies.

The XML bodies of the S3 responses are read with the crate `quick-xml`
0.42.0, with no feature. The reader of the port refuses a `DOCTYPE`, accepts
the five predefined entities and the character references of XML 1.0, and
refuses each other reference. It refuses a body with an open element at its
end, a second root, or an element deeper than 32 levels, and it reads at
most 4 MiB of UTF-8. Two alternatives were rejected:

- The crate `xml` 1.4.0. It reads the definitions of internal entities and
  expands them, up to 1,000,000 bytes for each expansion. Its time is
  quadratic in the depth of the elements: 40,000 levels took 831 ms, and a
  body of 4 MiB of nested elements took more than 5 minutes. In a test
  program, it cost 151,312 bytes of a stripped release binary, and
  `quick-xml` cost 45,528 bytes. On a listing of 4 MiB, `quick-xml` took
  22 ms and `xml` took 122 ms.
- A reader written in the tree. `quick-xml` gives each event and each
  reference to the caller, so the rules of the port are a short walker over
  the events. A tokenizer of its own adds the code of the lexical rules of
  XML, which the crate already has.

The fetch, the stream, and the lists of the client are fetches with
`max_error_body` of 4 MiB, and the fetcher of the client follows no redirect.
So the client sees the `x-amz-bucket-region` header and the S3 `Error`
document of each unsuccessful response. A region other than the region of
the signature, from the header or from the `Region` element, gives
`Error::S3Region`, which names both regions. A redirect of S3 to another
region is never followed, because a hop to another origin carries no
signature. The retries of a `GET` are the retries of the fetcher. The
client sends a `PUT` and a `DELETE` again itself, after an interrupted
upload and after a 408, 429, or 5xx, because an upload is never repeated by
the fetcher. `UploadBody::try_clone` gives the second request the bytes of
the first one with no copy.

A 404 is an absent key only if its body arrived whole and holds the code
`NoSuchKey` or no S3 code. A 404 with `NoSuchBucket` is an error, so a
missing bucket never reads as an empty repository. A 404 whose body did not
arrive, for example a body that stalls or fails in transit, can come from
a missing bucket too, so it is an error with no code. The absent-key rule
runs before the region check: a server that does not check the region of
the signature, and names another region in the header of a 404, still
gives an absent key. A region check on 301, 307, 400, and 403 alone was
rejected, because S3 can name the region of a bucket with another status.

`Bucket::get_strict` reads a key by a strict rule: a 404 is an absent key
only if its body arrived whole and holds the code `NoSuchKey`. The
reachability walk over a bucket repository reads each commit and each
dirtree with it. A false absent key hides a subtree from the walk, and each
object of that subtree then reads as unreachable. So in the walk, a 404
with an empty body, or with a body that is not an S3 `Error` document, for
example a page of a proxy, is an error. The fsck of a bucket repository
reads each object with the strict rule too: `Bucket::get_strict` for a
metadata object and `Bucket::get_stream_strict` for a `.filez` and a
`.cfs`. A false absent key there gives a false finding, and with the repair
a marker on a commit whose tree is whole. `get_stream_strict` shares the
code of `get_stream`, as `get_strict` shares the code of `get`. The other
readers of a bucket keep the rule above.

`Bucket::exists` and `Bucket::exists_strict` check that a key holds an
object, by the rule of `get` and by the rule of `get_strict`. A check is a
`GET` with `Range: bytes=0-0` and a size cap of one byte. A 206 and a 200
are an object. A 416 is an object too, because a server gives it for an
object of zero bytes. No object of a bucket repository has zero bytes, so
the rule costs nothing. The client reads a body that declares a length of
at most one byte to its end, so the connection goes back to the pool. A
failure of the body after the status does not change the answer, because
the status decides, and the drop of the body closes the connection. The
client does not read a body with no declared length, and the drop of the
body closes its connection. A read of such a body was rejected: a server
that sends no byte and stalls holds the check, and one of the
`max_outstanding` places of the caller, until the progress timeout. A
server that ignores the range answers 200 with the whole object. The fetcher then refuses a declared
length over one byte with `FetchTooLarge`, and the check takes that refusal
as an object. The fetcher reads a declared body of at most 64 KiB to its
end, so the connection goes back to the pool. It closes the connection of
a larger body, or of a body with no declared length. The fetcher takes a
206 as a body only for a request with a `Range` header. A 206 to another
request is `Error::HttpStatus`, because it holds a part of the object that
the caller did not ask for. The SigV4 signature does not cover the `Range`
header, so the signer signs a check as it signs each other `GET`.

A `HEAD` was rejected. The response to a `HEAD` has no body, so a 404 to a
`HEAD` holds no S3 code, and the strict rule cannot tell `NoSuchKey` from
`NoSuchBucket` or from a page of a proxy. A `GET` with no range was
rejected. For a large object, the server starts to send the body, and the
drop of the stream closes the connection. So many checks open many
connections, and each one uses bandwidth. `rclone serve s3` 1.75.1 answers
a check with 200, `Content-Range: bytes 0-0/<size>`, and one byte.
SeaweedFS 4.36 answers it with 206 and one byte.

A conditional `PUT` (`If-None-Match: *`) gives `PutIfAbsent::Created` only
when a request of the call got a 2xx. A request whose outcome is not known,
then a 412 or a failed request, makes the client read the key and compare
its SHA-256 with the SHA-256 of the body. The same bytes give
`PutIfAbsent::Refused` after a 412 and `PutIfAbsent::Matches` after a
failed request, other bytes give `PutIfAbsent::Present`, and an absent key
after a failed request sends the request again. `Matches` and `Refused`
state that the key holds the bytes of the body, and no answer names the
writer. So a writer lock that sends its own body again tells a 2xx of its
own request from bytes that the key held before the call. `Refused` also
states that the server answered 412, so the server honors the header,
and a writer lock that probes the header does not read a 412 after a 503
`SlowDown` as an unknown outcome. `rclone serve s3` 1.75.1 does not honor `If-None-Match: *`: a second
conditional `PUT` writes over the object.

The compare reads the object as a stream in chunks of 64 KiB, and holds no
copy of the object. A response that declares a length other than the
length of the body holds other bytes, and the client reads none of it. For
a body of more than 1 MiB, the client computes the SHA-256 of the body on
the blocking pool of the runtime, once before the first request. The signer
of each request and the compare use that digest. For a body of 1 MiB or
less, the signer hashes the body on the task of each request, and the
compare computes the digest on the blocking pool at the first compare.

A conditional `DELETE` (`If-Match` with an `ETag`) gives
`DeleteIfMatch::Deleted` for a 2xx, and `DeleteIfMatch::NotMatched` for a
412 or an absent key to the first request. SeaweedFS 4.36 answers 412 also
for an absent key, so a 412 after a request with an unknown outcome can
answer a delete of this call. The client then checks the key with
`Bucket::exists`, which asks for the first byte of the object alone: an
absent key gives `Deleted`, and an object gives `NotMatched`. `rclone serve s3` 1.75.1 does
not honor `If-Match`, and deletes the object whatever its `ETag` is.

Each page of a list must move forward, or the list fails. Each key and
common prefix of a page of `ListObjectsV2` comes after each one of the
earlier pages, in the byte order of UTF-8. S3 can give a truncated page
with no key and no common prefix, for example over many delete markers of a
versioned bucket. The client follows such a page if its continuation token
is new since the last page with a key or a common prefix. The client keeps
the tokens of that run in a set, and a page with a key or a common prefix
clears the set. A run of more than 1000 truncated pages with no key and no
common prefix fails the list. So a server that gives the same page again,
or empty pages with new tokens and no end, fails the list. A cap on the
number of all pages was rejected: a repository has no fixed upper limit of
keys. The cap on a run of empty pages bounds the set and the time of a
list, and it does not limit the number of keys.

For `ListMultipartUploads`, the `NextKeyMarker` of each truncated page does
not come before the key marker of the page before it, in the byte order of
UTF-8. While the key marker stays the same, the `NextUploadIdMarker` is one
that no earlier page gave for that key marker. The set of these upload id
markers clears when the key marker moves forward. S3 sorts the uploads of
one key by the time of their start, and not by the upload id, so the
upload id markers of one key have no order. A rule that the pair of the
markers increases was rejected: it refuses a key with more than one page of
incomplete multipart uploads.

The request path of a key encodes each byte outside `A-Z a-z 0-9 - . _ ~ /`
as `%XX`, which is the canonical URI of SigV4. So a `+` of a delta key goes
as `%2B`, and the signature does not depend on how a server reads a raw `+`
of a path. A listing asks for the encoding type `url`, and the client
decodes `%XX` and reads a `+` as a space, as S3 and `rclone serve s3` write
a space in that encoding.

The deletion of a key is one `DELETE` for each key. `DeleteObjects`
(`POST ?delete`) was rejected: AWS requires a `Content-MD5` or a checksum
header on it, and the first one needs the crate `md-5` in a manifest.

`Bucket::put_stream` writes an object from a reader. A body of at most
one part goes in one `PUT`, and a longer body goes in a multipart upload.
The call holds one part buffer, and the parts of one object go one after
the other. The first buffer starts at 8 KiB and doubles up to the part
size, so a small object takes a small buffer. After a full part, the call
reads one byte more, so a body of exactly one part goes in one `PUT`.

After each part, the call takes the buffer back with `UploadBody::into_vec`
of `ostrya-fetch`, and reads the next part into it with no fill of zeros.
The retries of a part share its buffer, so the buffer comes back after the
last request of the part. If the fetcher still holds the bytes, the next
part takes a new buffer with the capacity of one part. Its length doubles
from 8 KiB while the bytes arrive, so a short last part does not fill a
whole part with zeros.

`s3::part_size` gives the part size of an object of `N` bytes: the larger
of 8 MiB and `(2N + 1 MiB) / 10,000`, rounded up to a whole MiB. A `.filez`
of a file with `N` bytes of content is smaller than `2N + 1 MiB`, so
10,000 parts hold it. The part size is 8 MiB up to 41,942,515,712 bytes.
A part size over 5 GiB, the S3 limit of a part, gives
`Error::LimitExceeded`. No value is clamped. A body that is longer than
10,000 parts aborts the upload and gives `Error::LimitExceeded`.

`put_stream` refuses a part size below 5 MiB or above 5 GiB. No test hook
gives smaller parts. `rclone serve s3` 1.75.1 does not enforce the 5 MiB
minimum, but SeaweedFS 4.36 refuses a small part at the completion with
400 `EntityTooSmall`. The multipart tests use parts of 5 MiB.

The retries of a multipart upload differ for each request:

- The `POST` that starts the upload and each part are sent again after an
  interrupted request and after a 408, 429, or 5xx, as a `PUT` is. A part
  goes again with the same bytes.
- The `POST` that starts the upload is also sent again after a 2xx whose
  body did not arrive. Such an answer is an interrupted request, because
  the client does not get the upload id. An interrupted start can leave an
  upload that the client does not know. Such an upload holds storage until
  an abort or a lifecycle rule of the bucket removes it, and this is
  accepted.
- The `POST` that completes the upload is also sent again after a 2xx
  whose body cannot be read, and after a 200 whose body is an S3 `Error`
  document. The AWS API reference states that a completion can fail after
  the head of a 200.
- An answer to a part with no `ETag` fails the upload, because the
  completion cannot name the part.

The client takes an upload id and an `ETag` of a part of at most 1 KiB
each. A longer upload id fails the start, and the client sends no part. A
longer `ETag` fails the upload as a missing `ETag` does, and the client
aborts the upload. So the list of the `ETag` values holds at most 10,000
values of 1 KiB, and the completion document has a limit.

The outcome of a completion is unknown after an interrupted request,
after a 408, 429, or 5xx, and after a 2xx that cannot be used. A gateway
or a load balancer can give a 408, 429, or 5xx after the server completed
the upload. A later request can then get a 404 with the code
`NoSuchUpload`, because the earlier request completed the upload:
`rclone serve s3` 1.75.1 gives this answer to a second completion, and
SeaweedFS 4.36 gives 200 with the same `ETag`. After such a 404, the
client reads the key, and accepts the object if the declared
`Content-Length` equals the number of bytes of the parts. It reads no byte
of the object. A compare of the bytes was rejected, because it reads the
whole object again and the client holds one part alone. The completion has
the default timeout of the fetcher.

The check compares the length alone. It is sound for a key whose name sets
its content, such as a content-addressed object or a static delta. For a
key whose content changes, an older object of the same length passes the
check. The check runs for each key, and this limit is accepted. An absent
object and an object of another length give `Error::Transport`, whose
message states that the completion got 404 `NoSuchUpload` and what the key
holds. A failed read of the key gives the error of `Bucket::get_stream`.

After each failure that comes after the start of an upload, the client
sends one `DELETE KEY?uploadId=ID` and ignores its outcome, so the error of
the failure is the error of the call. If the last answer to a request of
the upload is a 404 `NoSuchUpload`, the server holds no such upload, and
the client sends no abort. This is the case after the check of the key
that follows such an answer to a completion. A dropped future sends no
abort.
`Bucket::abort_upload` takes a 404 `NoSuchUpload` as success: after a
refused completion, `rclone serve s3` 1.75.1 removes the upload and gives
404 `NoSuchUpload` to each later request of it, but `ListMultipartUploads`
still gives the upload. SeaweedFS 4.36 keeps the upload after a refused
completion.

`Bucket::abort_upload` refuses an empty upload id with
`Error::InvalidInput`, and sends no request. `rclone serve s3` 1.75.1 reads
`DELETE KEY?uploadId=` with an empty value as a `DeleteObject`: it gave 204
and removed the object.

The answer that starts an upload has the root
`InitiateMultipartUploadResult` in the AWS API reference and on SeaweedFS
4.36, and `InitiateMultipartUpload` with no namespace on `rclone serve s3`
1.75.1. The reader takes both roots, and refuses an absent or empty
`UploadId`. An `ETag` of the completion result that is empty or white space
alone reads as absent, so the `ETag` header of the answer applies.

The completion document gives the `ETag` of each part as the answer to the
part gave it, with its quotes, and with `&`, `<`, and `>` escaped. Both
servers take an `ETag` with quotes, with no quotes, and with `&quot;`.

The `ETag` that `put_stream` returns is not compared with the `ETag` of a
later read. For an object of several parts, the completion gives
`"<MD5 of the MD5 values of the parts>-N"` on both servers. A later read
on `rclone serve s3` 1.75.1 gives the MD5 of the whole object, and
SeaweedFS 4.36 keeps the value with `-N`.

The bucket client hashes a body of more than 1 MiB once, on the blocking
pool of the runtime, before the first request of the body. The rule applies
to each part of a multipart upload, to the body of `put`, `put_if_absent`,
and a `put_stream` of one part, and to the document that completes an
upload. The body moves to the pool and back with no copy, so the buffer of
a part comes back for the next part. The client gives the digest with
`UploadBody::bytes_with_sha256`, so the signer gets `SignPayload::Sha256`,
and each retry of the body signs the same digest. The compare of
`put_if_absent` uses that digest too. The signer hashes a body of 1 MiB or
less on the task of each request, as `SignPayload::Bytes`. The SHA-256 of
8 MiB takes about 4.8 ms on the dev host, so 1 MiB takes about 0.6 ms.

`Endpoint` of `ostrya-remote` has `#[non_exhaustive]`, and the variant
`Endpoint::S3` is behind the feature `s3`. Cargo features are additive, so
without the attribute a crate that matches each variant compiles alone and
fails when another crate of the same build turns `s3` on. A variant with no
feature gate was rejected: `S3Endpoint` and the types that it holds then
compile in each build. The push session constructors refuse `Endpoint::S3`.
`PullSession::connect` opens an HTTP pull session to it, with the fetcher
options of `S3Endpoint::pull_options`. `Endpoint::parse` refuses an `s3://`
address, because the endpoint needs credentials that the parse does not
read.

## The S3 pull

`resolve_pull` gives `Endpoint::S3` for an `s3://` address, and the variant
is the mark of a pull from a bucket repository. `Endpoint::Http` with a
signer was rejected: such an endpoint has no mark of S3, and the pull needs
the mark for two rules. The pull reads the root files through the bucket
client, and `Repo::pull_collection` reads no ref listing from the remote.

The fetcher of the pull has the one mirror of the repository URL, the SigV4
signer, and `max_redirects` set to 0. A redirect to another origin carries
no signature, so a redirect of S3 to the region of the bucket fails at the
other origin. With no redirect, the pull fails at the first answer, and the
bucket client names the region.

The pull sends the path of each request in the canonical form of SigV4.
The modified base64 of a delta name holds `+`, and SigV4 signs a `+` of a
path as `%2B`. With a raw `+` on the wire, the signature depends on how the
server reads a raw `+` of a path. `RequestSigner` of `ostrya-fetch` has the
provided method `request_path`. The fetcher gives it the path of each
`Target::Path` and `Target::PathQuery`, and sends the path that it returns.
A fetcher with no signer does not call it, and the default method returns
the path unchanged. So such a fetcher sends the path as the caller writes
it. `SigV4` returns the canonical path. It refuses a path that holds an
escaped `/`, or an escaped `.` that makes a `.` or a `..` segment, because
the decoded path names another key.
A `Target::Url` goes as written, and `SigV4` refuses a request whose path
is not in the canonical form. So no signature covers a path other than the
path on the wire.

This refusal has a known cost. AWS accepts a path with a raw `$`, an escape
with lowercase hex digits, or `%7E`, but `SigV4` refuses such a path in a
`Target::Url`, in the `Location` of a redirect to the same origin, and in
the base path of a mirror. No path of the port gets there: the S3 options
set `max_redirects` to 0, and each URL target of the bucket client comes
from `encode_path`.

Three alternatives were rejected:

- A new field of `FetcherOptions` that sets the form of the path. A caller
  that builds `FetcherOptions` with a struct literal and no `..` then fails
  to compile.
- The encoding of the delta paths in the delta source of the pull that the
  bucket client gives. The pull without a bucket client,
  `PullSession::connect` with `Endpoint::S3`, then sends a raw `+`.
- The encoding of the delta paths in each HTTP pull. That changes the bytes
  that a plain HTTP pull sends, and such a pull has no signature to match.

`summary.sig`, `summary`, and `config` go through `s3::Bucket::get`, and the
objects, the deltas, and the ref files go through the signed fetcher of the
pull. A fetch keeps no body of an error response, so through the fetcher a
wrong secret key is a bare 403, and a 404 of an absent bucket reads as a
repository with no summary. The bucket client reads the S3 error document.
Thus a wrong secret key gives `Error::S3` with the code
`SignatureDoesNotMatch`, a bucket of another region gives `Error::S3Region`,
and 404 `NoSuchBucket` is an error. `ostrya::Error::Remote` carries each of
them. `s3::Bucket::from_fetcher` opens the bucket client over a clone of
the fetcher of the pull, so the pull builds one fetcher: one read of the
trust store and one connection pool. A second fetcher from
`s3::Bucket::new` was rejected: it reads the trust store again and opens its
own connections. The bucket client names each request by its URL under the
bucket URL, so it reads the keys of the repository through the fetcher
whose mirror is the repository URL. The source of the pull gives the bucket
client the byte counters of the pull through `s3::Bucket::counted`. So these
reads count in the live progress of the pull until the count starts again,
as the reads of the root files over HTTP do, and
`PullStats::bytes_transferred` does not include them. These alternatives
were rejected:

- `s3::Bucket::with_fetcher`, which takes the counted fetcher of the pull.
  A client from `s3::Bucket::new` sends its request paths under the one
  mirror of its fetcher, the bucket URL. Over the fetcher of the pull, whose
  mirror is the repository URL, such a client adds the key prefix two times,
  unless the call forces a base URL.
- An `S3Endpoint` in the connection of the pull, so that the source opens
  the bucket client over its counted fetcher. That needs more code in three
  files.

The bucket client asks for `summary.sig` first and for `summary` next. If
the fetcher admits two requests at once, the bucket client keeps the two
requests in flight together, as the stream source does. So a pull of an
`s3://` remote, and a collection probe of it under a summary policy, wait
for one round trip for the two files in place of two. A pull over HTTP with
no bucket client keeps the order of the `ostree` command: `summary.sig`,
and then `summary`.

A pull from a bucket repository needs the permissions `s3:GetObject` and
`s3:ListBucket` on the bucket. Without `s3:ListBucket`, AWS answers the read
of an absent key with 403 `AccessDenied` in place of 404. The pull then fails
at an absent optional file, for example `summary.sig` or the `.commitmeta`
of a commit. A 403 stays an error: the same answer comes for a present key
that the credentials cannot read, and a pull that reads it as absent
continues without a signature or a file that the bucket holds.

`EndpointOverrides` gets four fields with no feature gate: `s3_region`,
`s3_endpoint`, `s3_addressing`, and `s3_profile`, each an `Option<String>`.
A build without the feature `s3` has the same struct, so a caller that
builds it compiles with and without the feature. `s3_addressing` is text,
because the type `s3::Addressing` is behind the feature. The pull reads it
with `Addressing::from_name` and refuses another value by the name
`s3-addressing`. The keys of the same names follow the same rule. A field
of the caller wins over its key, and `s3::resolve` gives each other source.

An S3 field or an S3 key with an address that is not S3 is refused. An
`s3://` address in the key `url` is refused, in each build, as an ssh
address there is refused: the `ostree` command also reads `url`. An
`s3://` address in `url` for a remote that the port alone reads, with a
note in the documentation, was rejected: the config has no mark of such a
remote, and the `ostree` command refuses the remote at each pull and each
`remote refs` with `error: Invalid URI scheme in s3://BUCKET/PREFIX`.

`resolve_pull` refuses an `http://` S3 endpoint without
`allow_cleartext_credentials`, because the signature is a credential. The
check comes after the resolution, because the endpoint can come from the
environment or from a profile. The rule applies to an S3 endpoint alone,
and the resolution of a pull from an HTTP address does not change.

`Repo::pull_collection` reads the refs of a remote at an `s3://` address
from the summary of its bucket repository alone. No server answers
`_ostrya/refs/v1` for a bucket repository, so the pull does not send that
request, and `Repo::pull` does not send it either. The probe reads
`summary` through the bucket client. Under a summary policy it also reads
`summary.sig`: it asks for `summary.sig` first, and if the fetcher admits
two requests at once, the two requests are in flight together. So an absent
bucket and a wrong secret key skip the remote with the S3 code. The pull
from a selected bucket repository reads its `config` through the same
client. A bucket repository with no `summary` fails the probe, and the pull
skips it with an event. A bucket repository with no summary that lists no
ref was rejected: the remote then gives no sign of the reason that it serves
no ref.

A list of the ref keys of the bucket, as a source of the collection refs,
was rejected. The summary is the one signed source of the refs of a bucket
repository, so a remote under a summary policy reads it in each case.
`ostrya remote refs` reads the summary too. A probe from a list costs a
`ListObjectsV2` of `refs/`, a read of each ref file, and a read of each
commit for its timestamp. A check of the summary against the ref files of
the bucket was rejected for the same cost. So a ref file that names a newer
commit than the summary has no effect: the pull takes the commit of the
summary, as `Repo::pull` takes it for a ref that the summary lists. The
pull does not compare the `collection-id` of the bucket `config` with
`ostree.summary.collection-id`: the summary alone states the collection of
each ref, as for an HTTP remote.

A listing request to S3, with a 404 read as no listing, was rejected. S3
answers the read of an absent key with 403 when the credentials have no
`s3:ListBucket`, and the request costs one round trip at each probe for no
answer.

The check of the length of each requested name against the limits of a ref
listing request applies also when each remote is a bucket repository. The
check reads the arguments alone, before the resolution of the remotes, so
one rule applies to each pull of collection refs.

## The writer lock of a bucket repository

S3 has no transaction over more than one object, so two writers on one
bucket repository race in two ways. Two pushes, or a push and an update of
the summary, each read the refs and each write a summary that does not hold
the ref of the other. A prune removes an object that no ref reaches, and at
the same time a push finds the object in its listing, does not upload it,
and writes a ref that reaches it. Each writer therefore holds a writer lock,
one object at `extensions/ostrya/lock`, which it writes with
`If-None-Match: *` and removes at the end. A read takes no lock.
`docs/format-reference.md`, "The writer lock", gives the body and the
requests. `ostrya::bucket` holds the lock, and `BucketRepo` is in `ostrya`,
because the push, the fsck, and the prune of a bucket repository need the
parsers and the summary builder of the crate.

Two alternatives were rejected:

- Conditional writes on the ref files and the summary, and a documented
  rule that a prune runs when no push runs. Conditional writes do not stop
  the race of a prune and a push.
- A lock with a lease: an expiry time in the lock, which the holder writes
  again during a long run, and a take of an expired lock with `If-Match`.
  It adds a dependency on the clocks of the hosts, and a run that stops
  writing the lock in time loses it during a change.

The lock has no lease. A lock that a crashed writer leaves stays until a
break of the lock removes it.

The `id` of a run is the SHA-256 of the host name, the process id, the time
in nanoseconds, and a counter of the process, in lowercase hex. The id
needs no random source: `getrandom` is authorized for `ostrya-server` alone.
The host name comes from `/proc/sys/kernel/hostname`, because `ostrya`
builds on Linux alone. The feature `system` of `rustix`, for `uname`, was
rejected: it changes a feature of a dependency and gives the same value on
Linux.

Before a request to the lock key, the writer probes that the server honors
`If-None-Match`, on the key `extensions/ostrya/lock-probe`. It sends the
fixed body `ostrya lock probe\n` with `If-None-Match: *`, and sends it again
if the first request wrote the key. A 412 to either request shows that the
server honors the header. A server that writes the second request gives no
exclusion, and the writer fails with `Error::BucketNoExclusion` before a
request to the lock key, so a lock that the key holds does not change. The
library has no option that lets a writer run on such a server.
`rclone serve s3` 1.75.1 ignores the header, so no writer runs on it. The
tests of a writer run on SeaweedFS 4.36, which honors the header, and on a
stand-in server in the test process, and the tests on `rclone serve s3`
check the refusal. An option that lets a writer run with no exclusion was
rejected, and so was a test proxy in front of `rclone serve s3` that gives
the headers their meaning.

A second probe request with an unknown outcome, whose read finds the probe
body, fails the take before a request to the lock key, and the operator
runs the operation again. `PutIfAbsent::Present` counts as a 412. It also
comes from a read after an interrupted request that finds other bytes, and
only a program other than the port writes other bytes to the probe key. The
probe runs on each take. A cache of an earlier result was rejected: the
server in front of a bucket can change between runs, and the probe costs
one `PUT` on a bucket that holds the key.

Three alternatives of the probe were rejected:

- A probe after the take: a second `PUT` of the lock body to the lock key.
  On a server that ignores the header, the take writes over the live lock
  of another writer, and the removal after the failed probe deletes the
  key. The other writer then stops in the middle of its run, at its next
  check, with `Error::BucketLockLost`.
- A delete of the probe key after the probe. A delete between the two
  requests of the probe of another writer lets the second request of that
  writer write the key, and that writer fails with
  `Error::BucketNoExclusion` on a server that honors the header. So no
  writer deletes the key.
- A body for each run, for example with the id of the run. After a
  request with an unknown outcome, put-if-absent reads the key and
  compares its bytes with the body, and other bytes give
  `PutIfAbsent::Present`, which the probe counts as a 412. With the same
  bytes from each writer, the probe of another writer on a server that
  ignores the header cannot give other bytes and a false 412. Such a body
  also leaves the data of a host in a key that no writer deletes.

The release and the break read the lock and its `ETag`, and send `DELETE`
with `If-Match` and that `ETag`. The writer does not probe for `If-Match`:
on a server that ignores the header, the conditional delete is a delete
with no condition. A break removes only the lock that it read. A 412 to the
delete of a break fails the take with `Error::BucketLocked`, which names
the new holder. If the read after the 412 finds no lock, its holder
removed it, and the break goes on to the take. A delete with no condition
on a break was rejected: it can remove the lock of another writer that
broke the lock after the read. So a break whose `GET` gives no `ETag`
fails, and deletes no lock.

A release whose `DELETE` removed the lock, but whose answer did not
arrive, sends the `DELETE` again. If another writer took the lock between
the two requests, the release fails with `Error::BucketLockLost`, although
it was complete. The documentation of the release states this case. A
third outcome of `Bucket::delete_if_match` for it was rejected: another
writer holds the lock at the end of the release, as the error states.

A lock body that the port cannot read is the lock of an unknown writer: a
take fails with `Error::BucketLocked`, a check fails with
`Error::BucketLockLost`, and a break removes the lock. An error that stops
each writer and the break was rejected, because the operator then deletes
the object by hand.

A take that gets 412 and then reads no lock fails with
`Error::BucketLocked` with no holder, and makes no second attempt. A
release that finds another `id` or no lock fails with
`Error::BucketLockLost`. The writes of the run were done under its last
check, and the error tells the operator that another writer ran. A success
with a flag was rejected.

`ostrya::Error` has the variants `BucketLocked`, `BucketLockLost`, and
`BucketNoExclusion` behind the feature `s3`, so a caller tells a refusal of
the lock from other errors. `BucketRepo::lock`, `BucketRepo::lock_holder`,
`WriterLock`, `LockHolder`, `LockOperation`, and `BucketRepo::list_objects`
are public, so another tool on the bucket client keeps the exclusion.
`BucketRepo::open` sends no request. An init and a push take the lock
before they read `config`.

`BucketRepo::list_objects` sends one list of each of the 256 fan-out
prefixes. The lists are futures of one set that the call polls, with no
spawned task. At most `max_outstanding` lists are in the set at a time, the
admission limit of the fetcher. A list of a prefix with more than one page
holds the keys of its earlier pages while it waits for the next page. With
256 lists in the set, the fetcher admits page 1 of each prefix before page
2 of any, so almost each key of the repository is in memory before the
first list ends. A set that holds the 256 lists at one time was rejected
for this reason.

## The S3 push

`Repo::push_to_bucket` writes commits to a bucket repository with no
session, and `Repo::push` with `Endpoint::S3` calls it. It gives
`BucketPushOutcome`: the `PushOutcome` and the holder of a lock that
`break_lock` deleted. `Repo::push` drops the holder. A field in
`PushOutcome` was rejected: the type is in `ostrya-remote`, it has no
`#[non_exhaustive]`, and a session push has no writer lock.

`RepoPushOptions` gets `break_lock` and the hidden `part_size`, with no
feature gate, as `EndpointOverrides` gets its S3 fields. A gate behind the
feature `s3` was rejected: a caller that builds the struct then compiles in
one feature set alone. A push over ssh or HTTP refuses each of the two
fields. `part_size` lets a test send an object in parts of 5 MiB.
`Bucket::put_stream` still refuses a part below 5 MiB, because SeaweedFS
4.36 refuses it at the completion.

The push runs all local checks of a session push before it takes the writer
lock, so a local refusal takes no lock and sends no request. The
fast-forward check needs the refs of the bucket, so it comes after the
lock.

The collection of a push selects its namespace by the rule of the receive
push, with the `config` of the bucket in the role of the server. A bucket
repository can have a `[core] collection-id`, and it is then the primary
server of that collection. It can also mirror other collections under
`refs/mirrors/ID/`. A bucket repository with no collection id and with the
refs of `refs/heads/` alone was rejected: a bucket repository must serve as
the primary server of a collection and as a mirror of several collections.
The summary holds `ostree.summary.collection-id` and
`ostree.summary.collection-map` from the builder of the local summary, and
no `ostree-metadata` anchor commit.

`BucketRepo::init` writes the `config`, with an optional collection id,
under the writer lock with the operation `init`. It refuses a bucket that
holds a `config`, so the collection id of a bucket repository never
changes. A push to a bucket with no `config` is refused. A push that writes
the `config` of a new bucket was rejected: the collection id is then set by
the first push, with no step of its own.

Each writer refuses a bucket repository that holds `refs/mirrors/ID/` of its
own collection id. The rule of a local repository, in which such a mirror
ref takes the place of the head of the same name, was rejected for a
bucket: a push writes the refs of the own collection under `refs/heads/`
alone, so no writer of the port makes that state.

A push reads the ref files of the ref directory of its namespace alone:
`refs/heads/` for a push into the own collection or with no collection, and
`refs/mirrors/ID/` for a mirror push. For the refusal of `refs/mirrors/ID/`
of the own collection id, it lists that directory alone. The check that
each ref names a commit that the bucket holds or that the push uploads,
and the check of the directory prefixes, cover the ref directory of the
namespace alone. A key or a ref file of another namespace that breaks a
rule does not refuse the push, and the fsck of a bucket repository checks
it. A read of all refs of the bucket at each push was rejected: the cost of
the push then grows with the refs of each namespace, also of the namespaces
that the push does not write, and only a summary write needs all refs.

A push refuses an update whose new ref set holds, in the ref directory of
its namespace, a name that is a directory of another name. A bucket has no
directories, so the two keys can both exist, but a local repository cannot
hold the two refs, and a pull into one fails.

After a failure before the ref writes, the push releases its lock and
returns the first error. An error of that release is dropped: the lock
stays, and the next writer names it. After `Error::BucketLockLost` and
`Error::BucketLocked`, the push releases no lock, because the lock is the
lock of another writer.

When one upload fails, the push starts no new upload, waits for the uploads
in flight, and returns the first error. Each failed `put_stream` aborts its
own multipart upload. A drop of the uploads in flight was rejected: a
dropped `put_stream` sends no abort, so it leaves open multipart uploads
that hold storage.

The push uploads a `.commitmeta` when the listing does not hold it, when
its size in the listing differs, or when a read of it gives other bytes.
So a second push with no change uploads no object. A `.commitmeta` that
holds `ostrya.related` alone uploads nothing under
`[ex-ostrya] keep-detached-related=false` of the bucket, and the bucket keeps
its copy, as a pull under the same switch keeps the copy of the destination.
An upload of an empty file and a delete of the bucket copy were rejected:
each one removes metadata other than `ostrya.related`. An
upload of each `.commitmeta` of each source commit at each run was
rejected: a second push with no change then uploads the `.commitmeta` of
each source commit.

The push writes no summary. The update of the summary of a bucket
repository is always explicit, as in a local `archive` repository with no
`auto-update-summary`. A push leaves a `summary` and a `summary.sig` of the
bucket as they are, so they can list old refs, and a pull of a named ref
reads the ref file when the summary does not list the ref. The writer
still reads `tombstone-commits` and `indexed-deltas` with the `config`, so
a value that is not a boolean refuses the push before its first upload.

The push uploads no static delta. A delta comes into a bucket repository
from another writer, for example as a copy of a delta directory of a local
`archive` repository, and a summary update lists each delta with a
superblock. An upload of the deltas of the local repository that end at a
pushed commit, in the `archive` mode alone, was rejected: the deltas of the
bucket then follow the content and the mode of the local repository, so
two pushes of one commit from two repositories leave different deltas in
the bucket.

A summary write on each push, signed by the signers of a field
`summary_signers` of `RepoPushOptions`, with a refusal of a push with no
signer to a bucket repository with a `summary.sig`, is rejected. With it,
each push needs the signing keys of the summary, and reads the commit of
each ref and each superblock of the bucket. One rule, the explicit update,
writes the summary. `RepoPushOptions` has no field for the signers of a
summary. `BucketRepo::update_summary` is the explicit update ("The summary
update of a bucket repository").

The push walks no tree of a commit that the listing of the bucket holds,
unless the commit has a partial-commit marker under `state/`. Each writer
uploads a commit object after each object of its tree, so a commit object
in the bucket has its whole tree in the bucket, or a marker that the repair
of the fsck wrote, and the fsck checks this rule. A walk of each source
commit, as a push over a session does, was rejected: a push with no change
then reads each dirtree of its commits and uploads nothing. The push lists
`state/` only if the listing holds an offered commit, walks the tree of
each offered commit with a marker, uploads the objects that the listing
lacks, and deletes the marker after a check of the lock and before the ref
writes. The commit object of such a commit does not go up again. A tree
push lists no `state/`: the tree of its parent does not change. The push
still adds the composefs image of each source commit, because the local
repository can make the image after the commit went up.

The holder of a lock that `break_lock` deleted is in `BucketPushOutcome`
and in the result of `BucketRepo::init` on success alone. A push or an
init that breaks the lock and then fails returns its error with no holder.
A holder in the error was rejected: it changes the error type of each
writer for one case, and a caller can read the holder with
`BucketRepo::lock_holder` before it breaks the lock.

`PushProgress` gets the public methods `set_phase`, `add_upload`,
`object_uploaded`, and `add_content`, so a client that uploads with no
session counts into the handle of the caller. The progress bar of the
`ostrya` command reads the same handle with no change. A progress type of
its own for the bucket push was rejected for this reason.

A push builds each `.filez` at the `[archive] zlib-level` of the `config`
of the bucket. The level of the local repository was rejected: two pushes
of one commit from two repositories then upload other bytes for one
object, and the bucket has no level of its own. A `.filez` of a local
`archive` repository still goes up as it is stored, at the level of that
repository, because a build again costs a deflate of each file. The push of
commits still refuses a compression. `BucketRepo::init` takes the level as
an argument, and writes the group `[archive]` with it. With no level, the
`config` has no `[archive]` group, and a writer takes the level 6, as a
local repository does.

`BucketRepo::push_tree` writes a local directory to a bucket repository as
one new commit. It takes `TreePushOptions` of `ostrya-remote` and a new
`BucketWriteOptions` with `break_lock` and the hidden `part_size`, and it
gives `BucketPushOutcome` with the new commit in `PushOutcome::commit`. The
struct is `#[non_exhaustive]`, so a later writer option is additive. Two
fields in `TreePushOptions` were rejected: the struct is in `ostrya-remote`
and has no `#[non_exhaustive]`, and a session push has no writer lock.

The bucket has no server, so the client makes the commit, with the commit
builder of the receive side of a session tree push. The two writers share
one crate-private function, so the same inputs give the same bytes.
`ostrya_remote::scan_tree` runs the checks of the options of a session tree
push and the scan, and gives the model of the tree and the checked fields
of the commit. It also checks the depth of each metadata value, which a
session push checks after the session opens. A copy of the checks in
`ostrya` was rejected: the two writers then refuse different options. The
size limits of the two writers are different: a session push refuses a
`Commit` frame over the `max-frame` of the server, 1 MiB for an ostrya
server, and a bucket push has no frame and refuses a commit object over
`MAX_METADATA_SIZE`.

The tree push takes the writer lock with the operation `push`. A new
operation for the tree push was rejected: the operation tells the operator
which writer holds the lock, and the two pushes make the same kind of
change. The parent is the tip of the branch that the push reads under the
lock, so each tree push is a fast-forward. With `orphan` on a branch that
exists, the new commit replaces the tip with no check. A right of the
client, as the `d` of a server, was rejected: a bucket has no client
groups, and the writer of a bucket can write each ref.

A tree push to a bucket refuses tags. A tag of a server commit needs a
check that the tag is absent and a write of two refs, and the push of
commits creates no tag either. The anchor ref `ostree-metadata` in
`refs/heads/` of a bucket with a collection id is refused, as a server
refuses it.

A tree push signs no commit. A signer in the options was rejected for this
release: the signing engines are in `ostrya`, and a session tree push signs
on the server. To sign the commit, a user pulls it into a local
repository, signs it there, and pushes it with `Repo::push_to_bucket`,
which then uploads the `.commitmeta` alone. `docs/roadmap.md` records the
gap.

The tree push reads each file again as a stream, hashes its header and its
payload, and fails at the end of the payload if the checksum is not the
checksum of the scan. The bucket client reads one byte past each full part
before it sends the part, so the last part never goes up, and a failed
multipart upload is aborted. So a file that changed after the scan leaves
no object of it in the bucket. A check by a server, as in a session push,
does not exist for a bucket.

## The `ostrya` command and bucket repositories

`ostrya-cli` turns on the feature `s3` of `ostrya` in its default set, so
the shipped binary reads and writes bucket repositories. The feature is
off by default in `ostrya-remote` and in `ostrya`, so a build of the
library that reads no bucket compiles no SigV4 signer and no XML reader.
The feature off in all crates was rejected: the shipped binary then
refuses each `s3://` address. The feature gates
the S3 options, `--break-lock`, `remote init`, `remote fsck`,
`remote prune`, and `remote summary -u`, as the features `push`, `serve`,
and `send` gate their commands. A build without
the feature refuses an `s3://` address with the message of the library,
which names the feature.

The init of a bucket repository is `ostrya remote init NAME|ADDRESS`, with
`--collection-id`, `--break-lock`, the S3 options, and
`--allow-cleartext-credentials`. A group `repo` with a command
`repo init-s3` was rejected: `remote` already holds the commands that act on
a remote, and the init needs no local repository. With an address, the
command opens no repository. With a remote name, it reads the remote from
the config of the repository.

`endpoint::resolve_bucket` gives the endpoint of each writer of a bucket
repository other than a push. For a remote name, the address is `push-url`
when it is `s3://`, else `pull-url` when it is `s3://`, and else the remote
is refused. The key `url` is never read. The function makes the refusals of
a push to an `s3://` address: `tls-permissive=true`, `push-token-file`,
`push-user`, and the ssh fields. A resolver for each writer was rejected,
because each writer takes the same address and the same refusals.

`endpoint::pull_address_is_s3` tells if the pull address of a remote,
`--url`, else `pull-url`, else `url`, is `s3://`, an HTTP or an ssh
address, or an address that `resolve_pull` refuses, with no file and no
environment. The command refuses `--allow-cleartext-credentials` and the
four `--s3-*` options of `pull`, `remote refs`, and `remote summary` when
the address is an HTTP or an ssh address, with the name of the option. For
an address that `resolve_pull` refuses, the command passes the options on,
and `resolve_pull` states its refusal. A refusal of the options for such an
address was rejected: its message hides the real refusal, for example an
`s3://` address in `url` or a remote that the config does not describe.
`Repo::remote_fetch_summary_with` takes the overrides of the caller, so
`remote refs` and `remote summary` take the S3 options.
`Repo::remote_fetch_summary` stays, with the default overrides. For
`push`, the command reads the push address of the remote, `push-url`, else
`url`, and refuses `--break-lock` and the `--s3-*` options for an HTTP or
an ssh destination with the name of the option. A refusal by the library,
which names the remote key, was rejected for these options, because the
key names do not tell the user which option to remove.

`ostrya push` calls `Repo::push_to_bucket` for an S3 endpoint, because
`Repo::push` drops the holder of a broken lock. The holder goes to standard
error in one line, `warning: removed the writer lock of HOLDER`, after a
push or an init that succeeds. `--break-lock` conflicts with `--onto`.

`ostrya remote add NAME s3://...` writes `pull-url` and `push-url` after the
branches, and writes no `url`, also in a build without the feature `s3`.
The command does not parse the address. A pull or a push refuses a bad
address when it uses the remote. `remote show-url` and `remote list -u`
then fail for the remote, because it has no `url`.

`resolve_push` reads the environment and the shared AWS files before the
library refuses `--tag` and `--compress` for an S3 destination. A check of
these options in the command before the resolution was rejected: it copies
a rule of the library, and the read of the files sends no request.

A push to a bucket repository shows no progress bar while it lists the
bucket and walks the commits, because the bar of `push` shows nothing in
the phase `Scanning`. A bar of its own for the listing was rejected for
this release.

`ostrya push-tree` takes an `s3://` destination, and calls
`BucketRepo::push_tree`. It takes the S3 options and `--break-lock`, and
refuses them for an HTTP or an ssh destination, with the rule and the
message of `push`. The command prints the new commit, as for a session
tree push, and the holder of a broken lock on standard error. The timestamp
of the commit is `--timestamp`, else `SOURCE_DATE_EPOCH`, else the clock of
the host, which the library reads. `--compress=LEVEL` sets the level of the
`.filez` objects of the push in place of the level of the bucket.
`ostrya remote init` takes `--zlib-level LEVEL`, which `clap` checks for 1
to 9 before any request.

The tests of the S3 options run against the stand-in of
`crates/ostrya/tests/common/s3.rs`, which keeps the `Authorization` header
of each request, so a test of `--s3-region` and of `--s3-profile` needs no
rclone. CI installs `rclone` and sets `OSTRYA_REQUIRE_S3`, and a CI step
builds `ostrya-cli` without the feature `s3` and runs
`crates/ostrya-cli/tests/s3_absent.rs`.

## The fsck of a bucket repository

The fsck of a bucket repository is `BucketRepo::fsck` and the command
`ostrya remote fsck NAME|ADDRESS`. The group `remote` holds the commands
that act on a remote, and the init of a bucket repository is there. Two
other commands were rejected: `ostrya fsck` with an `s3://` value of
`--repo`, which gives `--repo` a second meaning, and most of whose options
have no meaning for a bucket, and a new group `ostrya bucket`.

The fsck reads and checks each object that a commit reaches, as the local
fsck does. Its cost is the download of these objects. An option that checks
the metadata objects alone, and the presence and the size of each content
object from the listing, was rejected: it does not find a `.filez` whose
bytes changed.

The repair, `delete`, writes a partial-commit marker
`state/<checksum>.commitpartial` for each commit that reaches a missing or a
bad object of a tree, and then deletes each bad object. It deletes no commit
because of a bad object of its tree. The push walks the tree of an offered
commit with a marker, uploads the objects that the bucket lacks, and deletes
the marker, so a push of the ref repairs the commit with no option. The key
`state/<checksum>.commitpartial` is the path of the marker of a local
repository, and a copy of the bucket directory opened as a local repository
sees the commit as partial. These alternatives were rejected:

- No repair of a commit that a ref names. The commit stays broken until a
  deletion of its ref, which no command of the port makes.
- A delete of each commit that reaches a bad object, also a commit that a
  ref names. Each push to the namespace of the ref is then refused, because
  a ref names a commit that the bucket does not hold, and so is the update
  of the summary, until a push of the ref.
- A delete of each such commit that no ref names, and a marker on each ref
  target. It deletes commits of the history, and the local fsck deletes no
  commit: it marks each commit that reaches a missing or a deleted
  object.
- An option of the push that walks the tree of each offered commit that the
  bucket holds. It needs a manual step, and each such push reads each
  dirtree of its commits.

A commit object whose own bytes are bad goes, also when a ref names it. No
reader can use it: a pull and the build of a summary both check its
checksum. A push of the ref uploads it again, because the listing does not
hold it. A commit whose object goes gets no marker. The report names each
ref of such a commit, because until the push of the ref, each push to its
namespace is refused. The repair does not check the `.cfs` of such a
commit, and does not delete it: the digest of bad bytes has no meaning, and
the local fsck keeps the image of a commit that it deletes as an orphan.

The repair also deletes the marker of each commit whose tree the run finds
whole, and a run without the repair gives a note for such a marker. The
push deletes the marker of an offered commit alone, and the offer stops at
the tip of the ref in the bucket. So with no such delete, the marker of a
commit of the history stays after a push repaired its tree.

A repair that fails after its first change gives
`Error::BucketRepairIncomplete`. The error holds the report, with each
marker and each delete that completed, and states that the repair must run
again before a push. The marker goes up before the delete of the bad
objects, so a failure between the two leaves a marker on a commit whose bad
objects are still in the bucket, and a push of that commit uploads no
object that the listing holds and deletes the marker. The push does not
change for this state. Two changes of the push were rejected: an upload of
each tree object of a marked commit that the local repository holds, and a
read and a check of each listed tree object of a marked commit before the
delete of the marker. Each costs each push of a marked commit the upload or
the download of its whole tree, for a state that only a failed repair
leaves.

The repair needs a valid `config`. A run with `delete` reads `config` before
it takes the lock, and an absent or a bad `config` refuses the repair: the
run then checks the bucket, writes no key, and takes no lock. A wrong
address thus never loses an object. A push refuses a bucket with no
`config` in the same way.

The summary of a bucket repository changes only with an explicit update,
and a push writes none. So a summary that differs from the ref files or the
deltas is a note, and an absent summary is a note when the run verifies no
signature. A summary that a pull trusts and that leads the pull to an
absent object is an error: a summary ref whose commit is absent, a summary
delta whose superblock is absent or has another digest, a summary that does
not parse, and a signature that does not verify. A summary that differs is
an error in no case, because each fsck after a push then fails until an
update of the summary.

`BucketFsckOptions::summary_keys` takes the summary keys as
`TrustedKeys`, and `PullTrust::summary_keys` gives the summary keys of a
remote. `ostrya remote fsck NAME` reads the remote with the commit checks
off, so it reads no commit keyring. A field of the type `PullTrust` was
rejected: the fsck verifies no commit, and the type holds the commit keys
too. The options have no progress field. With `#[non_exhaustive]`, a later
field is additive.

A finding names the commits that reach its object. The walk keeps no list
of the files of a dirtree, so when a finding names an object of a tree, a
second pass reads each dirtree one more time. It gives each dirtree a
32-bit number, keeps each edge from a dirtree to its parent as two numbers
in one sorted list, and keeps the dirtrees that hold each bad object. The
cost is one more `GET` for each dirtree, and only with such a finding. A
list of parents for each dirtree in a map was rejected: it costs one heap
allocation for each dirtree.

The summary of a bucket gives the delta map that a pull reads. With a
summary in the bucket, a delta map of the bucket that the run cannot build
is a `summary` error: a superblock key whose directory names do not decode
as a delta, or a superblock larger than its cap. The summary builder fails
on the same keys. The run reads the superblocks of the deltas that the
summary advertises alone, and takes the names of the other deltas from the
list of `deltas/`.

A run without the repair takes no lock, and the listing of the 256 fan-out
prefixes is no snapshot, so a push or a prune during the run can give a
false `missing` finding. Before the run records a `missing` finding for an
object that the listing does not hold, it reads the object again. An object
that the bucket holds now gives a note. Else the run reads each commit of
the finding again, and a finding whose commits are all gone is dropped. The
read is a check of `Bucket::exists_strict`, which asks for the first byte
of the object alone, so its connection serves the next read. A `HEAD`
cannot apply the strict rule, and the key rule refuses a list with the key
as its prefix.

The hash and the parse of a metadata object larger than 1 MiB, and the
parse of a summary, run on the blocking pool, as the parse of a commit and
of a summary of a pull does. The reads of the other slots go on in the
meantime.

A body of a `.filez` or a `.cfs` that fails in transit is read again once
from its start, and a second failure fails the run. A failure of the run on
the first failure was rejected: the fsck reads the whole bucket, and one
failed connection then stops the run.

`ostrya remote fsck` prints the counts and the result line on standard
output, and one line for each finding on standard error, as `ostrya fsck`
does. A note starts with `note: `. A report with an error exits 1, and a
report with notes alone exits 0.

## The prune of a bucket repository

The prune of a bucket repository is `BucketRepo::prune` and the command
`ostrya remote prune NAME|ADDRESS`, for the reasons of the fsck: the group
`remote` holds the commands that act on a remote. `ostrya prune` with an
`s3://` value of `--repo`, and a new group `ostrya bucket`, were rejected.

The walk is the walk of the local prune, `traverse::walk_reachable_gc`,
over a source of metadata objects that the local repository and the bucket
both give. So the bucket prune has the roots and the bounds of
`Repo::prune` with no copy, and the tests of the local prune gate the walk.
The bucket prune follows the field 2 edge of the walk and does not follow
the `ostrya.related` edge ("Related commits"). With `refs_only` or
`keep_younger_than`, it deletes a build source that the local prune keeps.
In each case, it deletes the `.commitmeta` and the `.cfs` of a build source
that the listing does not hold, which the local prune keeps. A walk for the
bucket alone, with a copy of the rules of the bounds, was rejected: a
later change to one copy can miss the other.

The walk reads the commits one at a time, and walks the tree of a commit
before it reads the next commit. It reads the dirtrees of one tree with the
`Slots` driver of the pull, at most `max_reads` of the source at a time. The
local repository gives one, so the local walk reads one object at a time. A
bucket repository gives `max_outstanding`. With a limit of one, the walk
reads the dirtrees in depth-first order, and starts each read after the
read before it ends. If more than one read fails, the first read that fails
in time gives the error, and the walk drops the other reads in flight, as
the bucket fsck does. These alternatives were rejected:

- A prefetch in the source of the bucket prune of each commit and each
  dirtree of the listing. It reads objects that no root reaches, and holds
  them in memory.
- A batch of the subdirectories of one dirtree. A dirtree with few
  subdirectories does not use the limit.
- A batch across the frontier, with each read of a batch done before the
  next batch starts. Each batch waits for its slowest read.

`BucketRepo::prune` takes the `PruneOptions` of the local prune and a
`BucketPruneOptions` with `break_lock`. It takes `refs_only`, `depth`,
`keep_younger_than`, and `no_prune`, and refuses each other option that is
not at its default, before a request, with `Error::InvalidInput` that
names the first such field in the order of the fields. A type of options
for the bucket alone was rejected: the four options have the meaning of the
local prune, and a later option of the local prune that the bucket takes
then needs no new field. `delete_commit` and `static_deltas_only` need a
tombstone, `only_branch`, `retain_branch_depth`, and `weak_ref_filter` read
names of the local ref space, `commit_only` leaves objects with no commit,
and `traverse_parent` reads the metadata of each commit. These stay for a
later version.

The result is `BucketPruneReport`: the `PruneStats` of the local prune,
whose `deleted_refs` is always empty and whose `warnings` hold the
defective field 2 entries, and the deleted deltas, the deleted
markers, the aborted uploads, and the holder of a broken lock. With
`no_prune`, the lists name what a run deletes. A `PruneStats` alone was
rejected, because the command prints the deltas, the markers, and the
uploads, and the holder of a broken lock needs a place on success.

When the roots are not on the refs alone, each commit of the listing is a
root, so each root, the ref targets and the commits of the summary
included, keeps no parent. A dependency is then a root that keeps no parent
too. Each commit of the listing is already a root, so a parent bound adds
no commit of the listing to the kept set. The kept objects of the listing
are the same as in the local prune, with one exception, apart from the
build sources. The walk does not reach a parent commit that the listing
does not hold, so the prune deletes the `.commitmeta` and the `.cfs` of
that commit. The local prune keeps them when its bound reaches that parent.
These objects have no commit object in the bucket, and a push of that
commit uploads them again. So the prune treats them as objects that no root
reaches. The bound of the local prune for these roots was rejected: it
keeps these objects, and it adds no object of the listing to the kept set.
With `refs_only` or `keep_younger_than`, the walk takes the bounds of the
local prune. A dependency, also a dependency of a commit of the summary, is
a root under the bound of the run, as in the local prune. A commit of the
summary that a ref also names is a root under the bound of the ref alone.
The walk keeps the parent and the timestamp of each commit that it reads,
so it reads each commit one time in each mode, with one exception. With
`keep_younger_than`, the walk reads a commit a second time when the time
bound rejected the commit as a parent and the walk then reaches the commit
as a root, for example as a dependency.

The walk reads an object that the listing does not hold as absent, with no
request. The run holds the writer lock, so no writer adds an object during
the run. Each read takes at most the size of the object in the listing, and
the run checks the SHA-256 of each commit and dirtree that it reads. A bad
object fails the run before its first delete, with a message that names
`ostrya remote fsck --delete`. A walk with no check was rejected: a dirtree
with other bytes names other children, and the prune then deletes objects
that a commit of the bucket reaches. `BucketRepo::traverse_reachable`, which
is not a stable API, keeps its reads with no listing and no check.

The commits that the summary names, in field 0 and in the collection map,
are roots with no parent. The prune writes no summary, so the summary that
a pull reads after a prune can still name the commits of refs that moved
before the prune. With these roots, such a pull finds its commits. A
summary that does not parse fails the run before its first delete. A
prune that ignores the summary was rejected, because it can break a pull
that trusts the summary until an update of the summary. The deltas that
the summary names get no such rule: a delta whose target commit goes, goes
too, as in the local prune. The summary then names an absent delta until an
update of the summary, and the fsck reports it as a `summary` error.

A run with `no_prune` takes the writer lock too, so its counts describe a
state that no writer changes during the run. Thus a dry run needs the
permissions of a writer. The prune refuses `break_lock` together with
`no_prune`, with `Error::InvalidInput`, before a request. Thus a dry run
never removes the lock of another writer. A removed lock makes that writer
fail at its next check of the lock. `ostrya remote prune` refuses
`--break-lock` with `--no-prune` in the option parser. A refusal in the
option parser alone was rejected: a library caller can set both options. A
dry run that takes no lock, as the fsck with no repair, was rejected: its
counts then describe a state that a concurrent push can change.

The prune refuses a `config` that sets `[core] tombstone-commits=true`,
because it writes no tombstone. A run that ignores the key was rejected: it
deletes commits with no tombstone, which the repository policy asks for.
The refusal comes before the lock.

The prune deletes a delta directory whose target commit is absent also when
it has no superblock, and deletes the superblock first when it has one. A
run that stops between the two deletes then leaves a directory with no
superblock, and the next run deletes it. A key under `deltas/` that fails
`ostrya_remote::s3::is_repository_key` stays, as a stray key. The key rule
is exported for this check, so the prune and the bucket client take one
rule. `delta-indexes/` does not change, as in the local prune.

The run checks the lock before each step that has a change to make, and
after each 1000 deletes or aborts of a step. The steps are the commits with
the `.commitmeta` and the `.cfs` of absent commits, the other objects, the
static deltas with the markers, and the aborts. One check for each delete was
rejected: it doubles the requests of a run. The check gives no exclusion of
its own, as "The writer lock of a bucket repository" states.

Each delete is one `DELETE` of one key, in parallel under the admission
limit of the fetcher. `DeleteObjects` was rejected: AWS needs a
`Content-MD5` or a checksum header on it, and the first needs a crate.

A failed run gives the error of the failure, and releases the lock unless
the lock was lost or held by another writer. An error that holds the
deletes that completed, as the error of the fsck repair holds its report,
was rejected: the deletes of a prune leave a bucket repository that a
reader can use, and a run again completes the prune. A lost lock at the
release is an error, as for a push.

## The summary update of a bucket repository

The summary update of a bucket repository is `BucketRepo::update_summary`
and the mode `-u` of `ostrya remote summary NAME|ADDRESS`. `-u`/`--update`
is the option name of `ostrya summary`, and `ostree remote summary` has no
`-u`. The maintainer rejected a new subcommand `remote update-summary`,
which leaves the surface of `remote summary` of the `ostree` command as it
is, and selected the option name of `ostrya summary`. With an address,
the command opens no repository. Without `-u`, `remote summary` keeps its
behavior and takes a remote name alone.

`BucketRepo::update_summary` takes a `BucketSummaryOptions` with the
summary signers, `last_modified`, and `break_lock`, and gives a
`BucketSummaryReport`: the number of refs of field 0 and of the collection
map, the number of deltas, the name of the engine of each signer in the
order of the signatures, the `last-modified` value that it wrote, and the
holder of a broken lock. The options struct has a hand-written `Debug` that
names the engines of the signers, as `DeltaOptions` does.

The update reads the `config` before it takes the lock, as the prune does,
so a bucket repository with no `config` refuses the update with no lock
`PUT`. It reads the refs under the lock. An update with no signer probes
`summary.sig` under the lock, at the same time as the read of the refs. An
update with a signer sends no probe: the refusal below is the one reader of
the probe, and it applies to an update with no signer alone. A probe in
each update was rejected: it costs one request for no use.

The update reads the commit objects of the refs and the superblocks at the
same time. Each of the two reads at most `max_outstanding` keys at a time,
and the fetcher holds the requests in flight to `max_outstanding`. A
failure of a commit read takes precedence over a failure of a superblock
read in the error that the update gives.

Each read of a superblock takes the strict rule of an absent key, as the
fsck does. A superblock gone with an answer 404 `NoSuchKey` is left out of
`ostree.static-deltas`, as the local scan leaves out a superblock that went
away. The lenient rule was rejected: with it, a 404 that is not an absent
key leaves a superblock that the bucket holds out of the map, and the
update writes a summary that does not name the delta.

A bucket repository that holds a `summary.sig` refuses an update with no
signer, and no option turns the refusal off. The refusal changes nothing in
the bucket but the probe key of the writer lock.
A signed bucket repository is a signed bucket repository by the presence
of the key `summary.sig` alone. The probe is a check of
`Bucket::exists_strict`. It takes the strict rule of an absent key, so only
an answer 404 `NoSuchKey` is an absent key, and it asks for the first byte
of the key alone. A
probe with the lenient rule was rejected: with it, a 404 that is not an
absent key lets an update with no signer go on, and its summary then has
no signature that covers it. A read of the body was rejected: the body can
be as large as the cap of a summary, 64 MiB. The update never deletes
`summary.sig`. The local writer removes the old signature file before it
writes the summary. A delete in the bucket was rejected: a reader of a
bucket sees each write at once, so a delete first gives a window in which
the bucket repository has no `summary.sig`. An opt-out of the refusal was
rejected: the update does not delete `summary.sig`, so an update with no
signer leaves an old signature that does not cover the new summary, and
each reader that verifies the summary then refuses it.

The update writes `summary` and then `summary.sig`. S3 has no write of two
keys in one operation, so a reader that verifies the summary refuses it
between the two writes. An update with a signer gives
`Error::BucketSummaryIncomplete` when it can leave a pair that does not
match: the write of `summary.sig` fails after the server accepted the
write of `summary`, or the write of `summary` fails with an unknown
outcome. An unknown outcome is a failure of the HTTP client or a last
answer 408, 429, or 5xx, by the retry rule of the bucket client. A failure
of the HTTP client before the request was sent counts too, because it can
end the retries after an interrupted request. The error holds the report
of the update, with the holder of a broken lock, and the failure of the
write. Its message states the state of the pair and names
`ostrya remote summary -u` with the same signers. The update tries to
release the lock, and drops an error of that release. A refusal of the
write of `summary`, for example an answer 403, keeps the error of the
bucket client, and so does an update with no signer. A refusal of the
first request of that write changes nothing. A refusal of a request that
the bucket client sent again can leave the new summary with the old
`summary.sig`, because an earlier request can have written `summary`. A
process that stops between the two writes gives no error. The fsck with
the summary keys reports such a pair as an error on `summary.sig`, and its
detail states that a summary update with the signers writes a matching
pair. For an absent `summary.sig`, the detail states that a summary update
with the signers writes a `summary.sig`. The repair of the fsck does not
change for these findings, because only a signer can write a matching
pair. These alternatives were rejected:

- A write of `summary.sig` first: the window is the same, with the order
  of the two keys reversed.
- A read of the old summary before the write, and a write of it again
  after a failure: the read takes up to 64 MiB, and the second write can
  fail too.
- More attempts of the write of `summary.sig` in the update, after the
  retries of the bucket client: a 403 does not change with a new attempt.
- A probe of `summary.sig` in an update with a signer, to state in the
  error if the bucket holds an old `summary.sig`: the probe costs one more
  request for a detail of the text.
- `Error::BucketSummaryIncomplete` for a refusal of the write of `summary`
  after a request that the bucket client sent again: the bucket client
  returns the last answer alone. A result that tells the update of an
  earlier interrupted request, or of an earlier answer 408, 429, or 5xx,
  changes the public error API of `ostrya-remote`. The trigger is rare,
  and the fsck with the summary keys finds the pair that it leaves.

The update reads each commit of a ref with one `GET`, at most the cap of a
metadata object, and checks its SHA-256 against its name. It sends no
list of `objects/`. A listing of the 256 fan-out prefixes was rejected: it
costs 256 requests or more for each update, and the read of the commit
finds an absent commit too. The hash and the parse of a commit object
larger than 1 MiB run on the blocking pool, as in the prune. The summary
builder lost its input of a local repository and of a listing: the push
writes no summary, so no caller gave them.

The update writes `ostree.summary.tombstone-commits` from the `config`, as
the local summary does, and refuses no value of it. A ref whose commit has
a partial-commit marker is in the summary, and the update reads no key
under `state/`: the marker tells a push to upload the missing objects, and
the commit object is in the bucket. A bucket repository with no ref gets a
summary with an empty field 0, as a local repository with no ref does.

A ref name that is a directory of another ref name of the same directory,
as `a` is of `a/b`, refuses the update with the check of the push. The
refusal changes nothing in the bucket but the probe key of the writer lock.
A local repository cannot hold both refs: `refs/heads/a` is a file, and
`refs/heads/a/b` needs a directory at the same path.

`ostrya remote summary -u` prints nothing on standard output on success,
as `ostrya summary -u` prints nothing. A lock that `--break-lock` removed
gives one `warning: removed the writer lock of HOLDER` line on standard
error, as for the other writers. The command takes `--gpg-sign`,
`--gpg-homedir`, `--sign`, `--sign-type`, `--keys-file`, `--break-lock`,
and `--last-modified`, and each one needs `-u`. `-u` conflicts with
`--raw`, `--list-metadata-keys`, and `--print-metadata-key`. The command
builds the signers with the code of `ostrya summary -u`, in the same order
and with the same checks. Two refusals name the options of
`remote summary -u`, which has no KEY-ID operand: `--keys-file` under the
gpg engine, and a key file with no key. The command does not carry these
options of `ostrya summary`:

- `-m`/`--add-metadata`: the summary of a bucket repository holds the keys
  of the builder alone, so the update and a local update of a copy write
  the same bytes.
- `-c`/`--client-groups`: a bucket repository has no auth items.
- `--metadata-commit-timestamp`: the update writes no anchor commit.
- the positional KEY-ID: the operand of `remote summary` is the remote or
  the address.
- `--keys-dir`: it serves a verify alone.

## The `ostree` command and a bucket repository

A bucket repository has the layout of a static `archive` repository, so
the `ostree` command pulls it over HTTP, and the port writes nothing for
it. The URL is `https://BUCKET.s3.REGION.amazonaws.com/PREFIX`, or the URL
of the endpoint in path style, `ENDPOINT/BUCKET/PREFIX`. The `ostree`
command sends no signature, so the bucket policy gives anonymous
`s3:GetObject` on the keys that the `ostree` command reads: `PREFIX/config`,
`PREFIX/summary`, `PREFIX/summary.sig`, `PREFIX/objects/*`,
`PREFIX/refs/*`, `PREFIX/deltas/*`, and `PREFIX/delta-indexes/*`. The
writer lock under `PREFIX/extensions/` holds the host name and the pid of
the writer, and the `ostree` command reads no key under
`PREFIX/extensions/`, so the policy gives no key there. An anonymous
`s3:GetObject` on `PREFIX/*` with a Deny statement on
`PREFIX/extensions/*` for each principal was rejected: the Deny also
refuses the signed `GET` of the lock by a writer of the port.

S3 answers a read of an absent key with 403 when the caller has no
`s3:ListBucket`. The `ostree` command reads a 403 for `summary.sig`,
`summary`, a delta index, a superblock, and a `.commitmeta` as an absent
file, and a 403 for `config` after a summary fails the pull
(`conformance/cli-behavior.md`, "A 403 for an optional file"). The init
writes `config`, so an anonymous policy with `s3:GetObject` alone serves a
pull of the `ostree` command. A rule that also gives anonymous
`s3:ListBucket` was not taken, because no read of the `ostree` command
needs it.

The port pulls a bucket repository from its `s3://` address alone, with
signed requests. An anonymous S3 pull of the port is not in this release.
The S3 pull reads a 403 as an error ("The S3 pull"), and the HTTP pull of
the port reads a 403 for an optional file as an error too. So the HTTP
pull of the port stops at the first absent optional file of a bucket
repository under the anonymous policy (`roadmap.md`, "Gaps in pull").

The tests that check a bucket repository with the `ostree` command run
`ostree fsck` on a dump of the bucket, which the S3 client of the port
writes to a directory. SeaweedFS keeps no tree of files of a bucket on disk,
and no writer of the port runs on `rclone serve s3`, which honors no
conditional write. The `ostree` command pulls from the S3 port of SeaweedFS
with the identity `anonymous` and the action `Read`. The read-only port of
the filer was not taken, because the S3 port serves the same reads. Under
this identity, the S3 port answers an unsigned `GET` of an absent key with
404 `NoSuchKey`, and an unsigned list with 403 `AccessDenied`. AWS answers
the same `GET` with 403 under the anonymous policy, so the tests cover the
reads of the `ostree` command after a 403 on the stand-in alone, which
answers 403 for the keys of a test. The compare of the findings of the
bucket fsck with the findings of `ostree fsck -a` runs on a dump of the
stand-in, which makes each corruption with no write through S3.

## The client access of `ostrya serve`

- The reader of the PROXY protocol, v1 and v2, is written in the tree, with
  no crate. The CIDR match of `trusted-proxy` and of a `net:` item is
  `std::net::IpAddr` and a prefix length, with no crate.
- A forwarded certificate in base64 DER is decoded by `ostrya::base64`, so
  no base64 crate is a dependency.
- The server keeps each verified forwarded certificate in a cache. One
  verification costs 23 to 52 µs of CPU, and each request from a proxy
  carries the certificate, each object `GET` included.

## The protocol versions

Protocol version 1 changed in place for the client groups, the server
commit, the collection selectors of the ref listing, and the object type
100. No deployment ran version 1 when these changes came, so the version
number did not change. Thus a receiver that does not take the type 100
refuses a sender that sends an image.

## Related commits

A commit names its related commits in two fixed fields, both of type
`a(say)`. `format-reference.md`, "Related commits", states the format and
the rules.

- Field 2 of the commit object holds the dependencies: the runtime needs of
  the commit, for example the UKI, the kernel, the initrd, or a container.
  The detached metadata key `ostrya.related` holds the build sources: for
  example an intermediate layer, an artifact, or a package set. The two
  fields are fixed: no config key and no option of a call selects them.
  Thus a reader finds the related commits with no repository config, and
  the check of a write is the same in each repository.
- A dependency names no dependency. The commit write and the composefs
  rewrite refuse a nested dependency with `Error::InvalidRelated`. A
  dependency can have a parent and build sources. A UKI, a kernel, an
  initrd, or a container needs no dependency of its own. With one level,
  field 2 cannot make a cycle, and a check reads one commit and the commits
  that it names.
- A local prune roots on the commits that field 2 and `ostrya.related` of
  each reached commit name. The walk treats each such commit as a root of
  its own, at the global bound of the run.
- The prune reads field 2 of each commit that it reaches, a dependency
  included. So it keeps the commits that a nested dependency names, with no
  warning. To keep too much is the safe direction.
- Build sources are recursive in the local prune: the prune reads
  `ostrya.related` of each commit that it reaches, a build source included.
  `Repo::add_detached_related` can make a cycle. The walk reads the fields of
  each commit one time, so a cycle ends the walk.
- A related entry that names a commit that the repository does not hold
  gives no error, and the walk reads nothing below it. The prune keeps the
  name of that commit, as it keeps the name of an absent parent within the
  bound. So it keeps the
  `.commitmeta` and the `.cfs` of that commit if the store holds them.
- A prune that reads a defective related value gives a warning and
  continues. The warning names the commit, the field, and the reason. The
  defective value or entry roots nothing, and the other entries of the field
  root as usual. `PruneStats::warnings` carries the warnings, and
  `ostrya prune` writes each one to standard error and exits 0. For the
  prune, a nested dependency is not defective.
- The bucket prune roots on field 2 alone. It reads field 2 from the bytes
  of each commit object that it reads, so the field gives no extra request.
  It reads no `.commitmeta`, so a build source in a bucket repository stays
  only if a ref or another root keeps it. The bucket prune gives the warning
  of a defective field 2 entry in `BucketPruneReport`, and
  `ostrya remote prune` writes each one to standard error. A bucket prune
  that also reads the `.commitmeta` of each commit that it reaches was
  rejected: it sends one more `GET` for each such commit.
- A pull from a remote and a local pull follow the dependencies of each
  commit that they read, the parents that their depth takes included. Field
  2 is in the signed commit, so the pull is complete with no option, and the
  signature policy of the pull applies to each dependency. The pull takes
  each dependency at depth 0, with no parent: a dependency is a runtime need
  of the commit, and its history is not. A prune of the destination accepts
  the missing parents, as after a pull with a small depth. A dependency
  gets no ref. A commit-only pull and a pull with subpaths take no
  dependency. A dependency that neither the repository, a localcache
  repository, nor the remote (the source of a local pull) holds fails the
  pull, and the pull moves no ref. A local pull finds each such failure before its
  transaction opens. A pull that follows each dependency at the depth of the
  pull was rejected: it takes the history of each dependency, which no
  commit needs.
- A pull looks for a static delta of each dependency of its own. After the
  pull reads the commits that name the dependencies, it looks for a delta of
  each dependency that it does not hold complete. The `from` is the entry of
  the same name in field 2 of the commit that the local ref of a target names
  before the pull, the paired entry, so an update of a dependency goes from
  the dependency that the client runs. The pull takes the first paired entry
  that it holds complete, in the order of the targets, and takes the
  from-scratch delta only if it holds no paired entry complete. The
  requirement of static deltas applies to each dependency. With a list of
  static deltas, the pull takes one entry of the list to the dependency. A
  change to the delta format, so that the delta of a target also carries its
  dependencies, was rejected: the tool writes and reads the format, and a
  delta of each dependency keeps it.
- A push (`Repo::push`, `Repo::push_over_stream`, and `Repo::push_to_bucket`)
  sends the dependencies of each commit that it offers, at depth 0 and with
  no ref. It refuses an absent or a partial dependency, a defective field 2
  entry, and a nested dependency before the first upload. With a depth, the
  push resolves each dependency before it writes a byte. With no depth, the
  history of the offer ends at the server tip, which the push knows only
  after `HelloReply`, or under the writer lock of a bucket. So the push
  resolves the dependencies of the source commits first, and the
  dependencies of the offered history commits after the cut. It checks the
  format of field 2 of each commit of its walk, from the bytes that it
  already read. Two alternatives were rejected. To leave each check to the
  receiver was rejected: a push to a bucket repository has no receiver, and
  the client can refuse before it sends an object. To resolve the
  dependencies of the whole local history with no depth was rejected: the
  push reads the commit objects of dependencies that it does not send, and
  a dependency of old history that the server holds, which the local
  repository no longer holds, refuses the push. The one-way export
  (`Repo::export_stream`) sends the dependencies of each new commit by the
  same rules. It does no negotiation, so it sends a dependency that the
  receiver holds, and it finds each refusal before it writes the first byte.
  A receiver that holds a dependency with a partial-commit marker refuses
  the stream, also though the stream carries the whole tree of the
  dependency. The sender completes such a dependency with an update that
  takes it as a new commit.
- The receiver of a push session and of a one-way stream checks the
  dependencies of each commit that it stages, the staged parents of a new
  commit included. It also checks a new commit that it holds with a
  partial-commit marker, because the session completes the tree of that
  commit and removes its marker. For the same reason, a dependency that is a
  new commit counts as complete. Each other dependency must be staged or
  held complete, and no dependency can have dependencies of its own. A
  staged dependency passes the signature rules of each update whose new
  commit names it in its staged chain: the new commit and its parents as far
  as the session staged them. Field 2 of a new commit that the server holds
  counts too. The server signs it one time with each distinct key of these
  rules. A
  dependency that the server already holds gets no check and no signature:
  the server accepted it when it stored it. For the same reason, the server
  drops a detached metadata dict for a commit that it holds, that the
  session did not stage, and that no update names, if field 2 of a commit of
  the session names that commit. The server writes and merges nothing from
  the dict. The one-way export sends such a dict, because it does no
  negotiation. A refusal of the dict was rejected: it refuses each second
  export of a dependency with a `.commitmeta` to one receiver. A merge of
  the dict was rejected: no rule of the session covers a held dependency. A
  dict for each other commit that the session did not stage and that no
  update names stays `protocol`. A `Commit` message that lists the
  dependencies of the push was rejected. The dependencies are in the signed
  commits, so a list in the message adds a second source that can disagree
  with them.
- No transfer follows a build source. A pull, a push, and the one-way stream
  move `ostrya.related` as any other detached metadata key, under the switch
  of the destination, and fetch no commit that it names. A build cache needs the refs of its sources, and not
  only the commits. A distributed build cache mirrors the refs of its build
  sources with the existing pull and push.
- `[ex-ostrya] keep-detached-related=false` makes each transfer into the
  repository drop `ostrya.related`: a pull, a pull-local, a receive, and a
  push to a bucket. The repository that stores the dict reads its own
  switch, and a push to a bucket reads the `config` of the bucket. A
  distribution repository sets `false`, so the build sources of a builder
  do not go to the clients. A local write ignores the switch: a commit
  write and the add API always store the key, because the owner of the
  repository writes the value. A pull, also a pull-local and a pull through
  a static delta, and a push to a bucket replace the whole stored
  `.commitmeta` with the dict that the switch leaves, so a stored value
  stays only if that dict is empty. A receive merges the incoming dict into
  the stored dict, so a stored value stays. An option of the sender was
  rejected: the rule belongs to the repository that stores the dict, and a
  sender that does not set the option stores the key against the rule of the
  destination.
- The switch is the one rule that drops a detached metadata key in a
  transfer. `[ex-ostrya] detached-metadata-exclude`, a list of keys to
  drop, was removed with no alias and no refusal. The config reader ignores
  an unknown key, so a config that sets it gets no filter and no message.
  `DetachedMetadataFilter` and each option field that took it were removed
  too: `PullOptions`, `RepoPushOptions`, `ExportStreamOptions`,
  `ReceivePolicy`, and `StreamPolicy` carry no filter. The one key that a
  distribution repository must not keep is `ostrya.related`, and the
  destination reads its own switch, so the sender needs no option. A list
  of keys to drop lets a fault span two configs: if an upstream drops a key
  and a downstream roots on that key, the downstream prune deletes the
  commits that the key kept, and no call reports it.
- A config key that names more metadata keys with commit checksums was
  rejected. A reader then needs the repository config to find the related
  commits, and one dict is valid in one repository and not valid in
  another. If an upstream drops a key from the detached metadata and a
  downstream roots on that key, the downstream prune deletes the commits
  that the key kept, and no call reports it.

## The pull scheduler

`crates/ostrya/src/pull/drive.rs` is a poll core of the port.
`FuturesUnordered` was rejected: `futures-lite` has no unordered join, and
`futures-util` is not in the graph.

## The expression engine of `--tar-pathname-filter`

`commit --tar-pathname-filter` compiles its expression with PCRE2, the
library that the `ostree` command compiles it with. This follows rule 2 of
`CLAUDE.md`, "CLI compatibility is functional, not literal". Two other
engines were rejected on measurements:

- A backtracking matcher written in the tree. A review found three
  constructs that it read differently from PCRE, and three paths with no
  bound on the work.
- The `regex` crate. It read the POSIX class names as ASCII, and `$` as the
  end of the text. Thus one command line wrote two different commits.

## `#[non_exhaustive]` on the public types

The attribute marks a type that a caller matches over and does not build,
when the port owns its set of members and expects the set to grow.

- `ostrya::Error` has the attribute. Its variants are the error vocabulary of
  the port, and a new failure mode adds a variant.
- `TrustRoots` has the attribute. The port owns the set of trust settings.
- `ostrya_fetch::UploadMethod` and `ostrya_fetch::SignPayload` have the
  attribute. The fetcher owns the set of upload methods and the set of body
  forms that a signer gets.
- `ostrya_remote::s3::Origin` and `ostrya_remote::s3::Resolved` have the
  attribute. The port owns the set of sources of an S3 setting, and the set
  of resolved settings grows with the S3 support.
- `ostrya_remote::transport::Endpoint` has the attribute, and
  `Endpoint::S3` is behind the feature `s3`. A match outside
  `ostrya-remote` needs a wildcard arm, so the build compiles with and
  without the feature. "The S3 bucket client" states the reason.
- `ostrya_remote::s3::S3Endpoint`, `Object`, `PutIfAbsent`,
  `DeleteIfMatch`, `Listing`, `Listed`, and `Upload` have the attribute, and
  so do the variants `ostrya_remote::Error::S3` and
  `ostrya_remote::Error::S3Region`. The bucket client builds them, and the
  set of fields grows with the S3 support. A caller builds an `S3Endpoint`
  with `S3Endpoint::new` and sets its fields.
- `ostrya::bucket::LockOperation`, `LockHolder`, `ObjectListing`,
  `BucketPushOutcome`, `BucketFsckReport`, `BucketFinding`,
  `BucketFindingKind`, `BucketPruneReport`, and `BucketSummaryReport` have
  the attribute. The port builds them, and a later
  version can add an operation, a field, or a kind of finding.
- The option structs of the `ostrya` crate do not have the attribute:
  `PruneOptions`, `PullOptions`, `TarExportOptions`, `TarImportOptions` and
  the others. The attribute stops a struct expression outside the defining
  crate, `..Default::default()` included. Thus a new field in one of these
  option structs is a breaking change, and it takes a minor version before
  1.0. The option structs of the bucket writers, `BucketWriteOptions`,
  `BucketFsckOptions`, `BucketPruneOptions`, and `BucketSummaryOptions`,
  have the attribute. A caller starts from
  `Default::default()` and sets the fields, so a later field is additive.
- `ostrya_server::ServeOptions` and `ostrya_mount::MountOptions` have the
  attribute. A caller starts from `Default::default()` and sets the fields.
- `ostrya_gvariant::Type` and `ostrya_gvariant::Value` do not have the
  attribute. The GVariant serialization specification closes the type
  alphabet, and the two enums name all of it. An exhaustive `match` over
  either enum is the gate that makes each site answer for a new type
  character. A new variant in either enum takes a major version.
