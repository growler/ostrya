# Contributing to Ostrya

This file gives the procedures for work on the Ostrya source tree. The design
documents in `docs/` are the source of truth. A change that alters behavior
changes the related document in the same commit.

## Development environment

The workspace builds on stable Rust, edition 2024, minimum version 1.92.

The Nix flake supplies the development shell:

```sh
nix develop
```

The shell holds Rust 1.92, the `ostree` tool, GnuPG, and the other binaries
that the test suite runs.

## Tests

The test suite runs under both runtime backends:

```sh
cargo test                                        # smol (default)
cargo test -p ostrya --no-default-features --features tokio
```

The mount tests of `ostrya-sys`, `ostrya-mount`, and `ostrya-mountd` need
`CAP_SYS_ADMIN` in the initial user namespace, so they skip for another user.
Run them as root on a file system with fs-verity. If `OSTRYA_REQUIRE_MOUNT` is
set, a missing privilege or a file system without fs-verity fails them:

```sh
OSTRYA_REQUIRE_MOUNT=1 cargo test -p ostrya-sys -p ostrya-mount -p ostrya-mountd
```

The tests of `ostrya-mountd` also need `setpriv`, `unshare`, `nsenter`, and
user namespaces for an unprivileged user. They run each client as the user
65534 in its own user namespace, and keep their repositories and targets in
`/var/tmp`, where that user can reach them.

The unit tests of the protocol and of the daemon handler in `ostrya-mount`
need the `server` feature:

```sh
cargo test -p ostrya-mount --features server
```

The tests of the bucket client in `ostrya-remote` need the `s3` feature. The
tests in `crates/ostrya-remote/tests/s3_bucket.rs` run `rclone serve s3` on a
scratch directory, with a key pair and a port that the server picks. They
skip if `rclone` is not on `PATH`. If `OSTRYA_REQUIRE_S3` is set, a missing
`rclone` fails them:

```sh
OSTRYA_REQUIRE_S3=1 cargo test -p ostrya-remote --features s3
```

The tests of a pull from an `s3://` address in `crates/ostrya/tests/pull_s3.rs`
need the `s3` and `verify-gpg` features. They serve a copy of the `archive`
fixture with `rclone serve s3`. One test signs the summary of the copy with
the `ostree` command and a new key of `gpg`. A test skips if `rclone`, the
`ostree` command, or `gpg` is absent. `OSTRYA_REQUIRE_S3`,
`OSTRYA_REQUIRE_OSTREE`, and `OSTRYA_REQUIRE_GNUPG` turn each skip into a
failure:

```sh
OSTRYA_REQUIRE_S3=1 OSTRYA_REQUIRE_OSTREE=1 OSTRYA_REQUIRE_GNUPG=1 \
    cargo test -p ostrya --features s3,verify-gpg --test pull_s3
```

The tests of the writer lock and of the object listing of a bucket
repository in `crates/ostrya/tests/bucket_lock.rs` need the `s3` feature.
Most of them run against a stand-in S3 server in the test process, and they
never skip. The other tests run against `rclone serve s3` and against
`weed mini` of SeaweedFS. A SeaweedFS test starts `weed mini` with a data
directory in a scratch directory, one bucket, the key pair of the tests, and
a free port for each component that it picks, so it never uses a default
port. The harness waits until a read of the bucket stops getting
`NoSuchBucket`. A drop of the server kills it and removes its sockets in
`/tmp`. A
test skips if `rclone` or `weed` is not on `PATH`. `OSTRYA_REQUIRE_S3` and
`OSTRYA_REQUIRE_SEAWEEDFS` turn each skip into a failure:

```sh
OSTRYA_REQUIRE_S3=1 OSTRYA_REQUIRE_SEAWEEDFS=1 \
    cargo test -p ostrya --features s3 --test bucket_lock
```

The tests of the init of a bucket repository and of the push to a bucket
repository in `crates/ostrya/tests/push_s3.rs` need the `push` and `s3`
features. They call the library alone and read no AWS variable. Most of
them run against the stand-in S3 server, which can refuse or delay the
requests of one method to a key and change its objects before a request,
so the tests cover each failure state of a push. The tests of a push and a pull, of a
multipart upload, and of a wrong secret key run against `weed mini` of
SeaweedFS. `rclone serve s3` ignores `If-None-Match`, so the tests against
it check that the init and the push are refused. Other tests pull a pushed
bucket with the `ostree` command over HTTP with no signature: from the
stand-in, which answers 403 for the keys of a test, and from the S3 port of
`weed mini`, which the harness starts with the identity `anonymous` and the
action `Read`. They run `ostree fsck` on a dump of the bucket, which the S3
client of the port writes to a scratch directory, because SeaweedFS keeps no
tree of files on disk. A test skips if `rclone`, `weed`, the `ostree`
command, or the ed25519 engine of the `ostree` command is absent, and the
four variables turn each skip into a failure:

```sh
OSTRYA_REQUIRE_S3=1 OSTRYA_REQUIRE_SEAWEEDFS=1 OSTRYA_REQUIRE_OSTREE=1 \
    OSTRYA_REQUIRE_OSTREE_ED25519=1 \
    cargo test -p ostrya --features push,s3 --test push_s3
```

The tests of the tree push to a bucket repository in
`crates/ostrya/tests/push_tree_s3.rs` need the `push` and `s3` features.
Most of them run against the stand-in S3 server, and the others against
`weed mini` and `rclone serve s3`:

```sh
OSTRYA_REQUIRE_S3=1 OSTRYA_REQUIRE_SEAWEEDFS=1 \
    cargo test -p ostrya --features push,s3 --test push_tree_s3
```

The tests of the reachability walk, of the fsck, of the prune, and of the
summary update of a bucket repository in
`crates/ostrya/tests/bucket_walk.rs`, `bucket_fsck.rs`, `bucket_prune.rs`,
and `bucket_summary.rs` need the `s3` feature. The tests against `weed mini`
also need the `push` feature, and the GPG test of the summary update needs
the `sign-gpg` feature. Most of the tests copy the files of a local
`archive` repository into the stand-in S3 server, and then change the
bucket. The others run against `rclone serve s3` and `weed mini`. A test of
`bucket_fsck.rs` compares the findings of the fsck with the findings of
`ostree fsck -a` on a dump of the stand-in, and a test of `bucket_prune.rs`
runs `ostree fsck` on such a dump. A test skips if `rclone`, `weed`, the
`ostree` command, or `gpg` is absent, and the four variables turn each skip
into a failure:

```sh
OSTRYA_REQUIRE_S3=1 OSTRYA_REQUIRE_SEAWEEDFS=1 OSTRYA_REQUIRE_OSTREE=1 \
    OSTRYA_REQUIRE_GNUPG=1 cargo test -p ostrya --features push,s3,sign-gpg \
    --test bucket_walk --test bucket_fsck --test bucket_prune --test bucket_summary
```

The module `s3_remote` of `crates/ostrya/tests/pull_collection.rs` needs the
`s3` feature. It pulls collection refs from a bucket repository on the
stand-in S3 server and on `rclone serve s3`, each case in a child process
with the key pair of the tests:

```sh
OSTRYA_REQUIRE_S3=1 cargo test -p ostrya --features s3 --test pull_collection s3_remote
```

The tests of the `ostrya` command with a bucket repository in
`crates/ostrya-cli/tests/s3.rs` need the `s3` feature, and most of them the
`push` feature. They run the built `ostrya` with the key pair of the tests,
the shared AWS files at absent paths in a scratch directory, a scratch
`HOME`, and no other AWS variable and no proxy variable. Most of them run
against the stand-in S3 server, which keeps the `Authorization` header of
each request, so the tests of `--s3-region` and `--s3-profile` need no
rclone. One test reads a copy of the `archive` fixture through `rclone
serve s3`, and one test runs an init, a push, and a pull against `weed
mini`. That test also pulls the push from the S3 port of `weed mini` with
the `ostree` command, and skips this part if the `ostree` command is
absent. The three variables turn each skip into a failure:

```sh
OSTRYA_REQUIRE_S3=1 OSTRYA_REQUIRE_SEAWEEDFS=1 OSTRYA_REQUIRE_OSTREE=1 \
    cargo test -p ostrya-cli --test s3
```

The tests in `crates/ostrya-cli/tests/s3_absent.rs` run in a build without
the `s3` feature alone. They check that a pull and a push refuse an `s3://`
address with a message that names the feature:

```sh
cargo test -p ostrya-cli --no-default-features --features smol,push --test s3_absent
```

## Golden fixtures

The golden fixtures are in `tests/fixtures/`. The `ostree` tool wrote them,
run as a black box. This directory is outside every crate root, so a crate
on crates.io holds no fixture: `cargo package -p ostrya --list --allow-dirty`
lists no path under `tests/fixtures/`, and the same is true for
`ostrya-composefs`. Git tracks each fixture, so a checkout has all of them,
and the tests that read them do not need the `ostree` tool.

### Fixture layout

- `generated/MANIFEST` -- the `key=value` facts that the generator records:
  the commit checksum that all modes share, the owner of the `bare` fixture,
  and the commit checksums and digests of each fixture family.
- `generated/.gitattributes` -- marks the tarballs, the composefs images,
  and the two `summary` files as binary, so git applies no text
  normalization or diff to them.
- `generated/<name>/repo/` -- the `archive`, `bare`, `sizes`, `summary`, and
  `summary-collection` repositories. Each is a plain tree of `config`,
  `objects`, and `refs`.
- `generated/<name>.tar` -- the `bare-user`, `canon`, and `xattr`
  repositories. Each file keeps its metadata in a `user.ostreemeta` xattr,
  which git does not track. Thus these fixtures are tarballs that keep the
  xattrs. `unpack_fixture` in `crates/ostrya/tests/common/mod.rs` unpacks
  each one when a test needs it.
- `generated/export.tar` -- the `ostree export` of the shared commit, a
  plain tar that the tar import tests read.
- `generated/composefs/` -- four EROFS images: `tree.cfs`,
  `tree-noverity.cfs`, `tree-rich.cfs`, and `tree-rich-noverity.cfs`. Each
  image has a `composefs-info dump` text file with the same stem, for
  example `tree.dump`.
- `tls/` -- the TLS certificates and keys of the HTTPS tests.
  `tls/generate.sh` writes them, separately from `generate.sh`. Run it only
  to replace the certificates. Their validity is 100 years.
- `spki/<type>/` -- the spki signature fixtures of one key type, now `p256`,
  `p384`, and `rsa`. `spki/generate.sh` writes them, separately from `generate.sh`.
  `spki/.gitattributes` marks the repository objects, the deltas, the delta
  indexes, and the two `summary` files as binary.
- `spki/keys/` -- the key files of the tests of the spki engine.
  `spki/keys/generate.sh` writes them with OpenSSL 3, separately from the
  other generators. `spki/keys/` is not a key type of `spki/generate.sh`.

### The fixture generator

`tests/fixtures/generate.sh` deletes `generated/` and writes it again in one
run. It takes no argument, and it cannot write one fixture family alone:

```sh
tests/fixtures/generate.sh
```

The script needs the `ostree` tool on `PATH`. If the tool is absent, the
script stops before it writes anything. The script also runs `tar` (with
`--xattrs` and the POSIX pax format), `setfattr`, and `python3`. It needs no
root privilege. The composefs fixtures need `composefs-info` and an `ostree`
build that shows `composefs` in `ostree --version`. If one of the two is
absent, the script writes a warning, skips the composefs fixtures, and
writes all other fixture families.

A fixed branch, a fixed commit timestamp, a fixed owner, and no xattrs where
the fixture does not need them make each content-addressed object and each
ref stable. Thus a second run writes the same bytes into each tracked file.
The script commits the same tree in each mode, and it fails if the commit
checksums are different.

### The spki fixtures

Each `spki/<type>/` directory holds one key type. It holds these files:

- `secret.pem` -- the secret key, one PKCS#8 `PRIVATE KEY` block. The key
  is a test key and signs nothing else.
- `public.pem` -- the public key, one `PUBLIC KEY` block.
- `repo/` -- a copy of `generated/archive/repo`, to which the tool added
  these items:
  - the `.commitmeta` of the commit, with two spki signatures for `p256`
    and `p384`, and one for `rsa`;
  - a signed static delta from scratch to the commit, in the layout of a
    superblock and one part;
  - the delta index in `delta-indexes/`;
  - the `summary` and its signature, `summary.sig`;
  - the key `indexed-deltas=true` in `config`.
- `MANIFEST` -- the key type, the `ostree` and `openssl` versions, the
  commit, the delta, and the class of each signature. For `p256` and
  `p384`, the class is the s class (`low` or `high`). For `rsa`, the class is the length of the
  signature in bytes, `256`, and `modulus_bits` gives the size of the key,
  2048 bits.

The tool read a different signing input for each signature. For the commit,
`ostree sign --keys-file` read `secret.pem`. For the delta and the summary,
`--sign` read the base64 body of `secret.pem` inline.

These fixtures are separate from `generate.sh`. Each run makes a new key,
and ECDSA takes a random nonce for each signature. RSA PKCS#1 v1.5 is
deterministic, but its key is also new in each run. Thus a run cannot write
the same bytes again. Run the script only to replace the fixtures of one key
type. The script deletes and writes `spki/<type>/` alone:

```sh
tests/fixtures/spki/generate.sh p256
OPENSSL=/path/to/openssl tests/fixtures/spki/generate.sh p384
OPENSSL=/path/to/openssl tests/fixtures/spki/generate.sh rsa
```

The `OPENSSL` variable names the `openssl` command. The default is the
`openssl` command on `PATH`. Run `p384` and `rsa` with OpenSSL 3.6.4, the
library that the tool on the NixOS development host links.

The script needs an `ostree` build that shows `openssl` and `sign-spki` in
`ostree --version`. The build on the NixOS development host has both. If one
of the two is absent, the script stops before it writes anything. The script
also runs `openssl` (OpenSSL 3 or LibreSSL) and `python3`. It reads
`generated/archive/repo`. If that directory is absent, the script stops
before it writes anything.

The script makes these checks, and it stops if one fails:

- `openssl` verifies each signature over the bytes that it signs: the commit
  object, the `summary` file, and the superblock bytes in the signed
  envelope. The `ostree` verify accepts blobs that no key signed, so this
  check does not use the tool.
- For `rsa`, `openssl dgst -sha256 -sign` signs the same bytes with
  `secret.pem`. Its signature must be the same bytes as the signature of the
  tool.
- For `rsa`, the key has 2048 bits, each signature is 256 bytes, and the
  commit holds one signature.
- The delta and the summary each hold one signature.
- `ostree static-delta verify` verifies the delta with `public.pem`.
- `ostree fsck` accepts the repository. The script runs it before it writes
  `spki/<type>/`.

Git does not keep the empty `refs/mirrors` and `refs/remotes` directories.
Before you run the tool on `spki/<type>/repo` in a checkout, create them.

ECDSA gives a signature with a low s or with a high s, where a high s is
greater than n/2 and n is the order of the curve. The first commit signature
has a low s, and the second has a high s. The script signs again until it
gets this order, and it stops after 64 tries. The tests
`p256_tool_commit_verifies_low_and_high_s` and
`p384_tool_commit_verifies_low_and_high_s` assert the s class of each
signature and that each signature verifies. Thus the test shows that the
port accepts a high s that the tool writes. The s class of the delta and
summary signatures is random. `MANIFEST` records it.

The `p384` fixture also shows the digest. The tool signs the SHA-256 of the
data with a P-384 key, and the port verifies a P-384 signature over the
SHA-256 of the data. A round trip of the port alone does not find a wrong
digest. The key of the `p384` fixture is not the P-384 key of the unit
tests. The `p384` tests use that key, the key of RFC 6979, appendix A.2.6,
as a key that signed no fixture.

RSA has no s class. The `rsa` case of the script sets `kind=rsa`. The
script signs the commit one time, and the class of each signature is its
length in bytes.

A later ECDSA curve adds these items:

- a case in the script, with `kind=ecdsa`, its `genpkey` options, and its
  group order in `param`;
- a `spki/<type>/` directory;
- a test module under a `cfg` of its key feature, with n/2 of the curve for
  the s class, and the key feature in the `any()` list of the `cfg` of the
  test file and of `has_high_s`;
- a bullet in the fixture layout.

The tests are in `crates/ostrya/tests/sign_spki_fixtures.rs`. The `cfg` of
the file is an `any()` list of the key features. The tests of each key type
are in one module, `p256`, `p384`, or `rsa`, under the `cfg` of its key
feature. The
items that the modules share are at the top level of the file. Run the tests
of each key type with its key feature:

```sh
cargo test -p ostrya --no-default-features --features smol,sign-spki-p256 \
    --test sign_spki_fixtures
cargo test -p ostrya --no-default-features --features smol,sign-spki-p384 \
    --test sign_spki_fixtures
cargo test -p ostrya --no-default-features --features smol,sign-spki-rsa \
    --test sign_spki_fixtures
```

RSA PKCS#1 v1.5 is deterministic. Thus the `rsa` tests also sign with the
port and compare the bytes with the signatures of the tool:

- The port signs the commit in a copy of the fixture repository, without
  the `.commitmeta` of the tool. The signature and the whole `.commitmeta`
  file must be the same bytes as the ones that the tool wrote.
- The port signs the `summary` file and the signed superblock bytes. Each
  signature must be the same bytes as the signature in `summary.sig` or in
  the superblock.

The key of the `rsa` fixture is not one of the keys in `spki/keys/`. The
`rsa` tests use `spki/keys/rsa-2048.pub.pem` as a key that signed no
fixture.

### The spki key fixtures

`spki/keys/` holds the keys that the tests of the spki engine read. The
tests do not make keys, because a large RSA key takes a long time to make.
The directory holds these files:

- `rsa-<bits>.pem` and `rsa-<bits>.pub.pem` -- two-prime RSA keys as a
  PKCS#8 `PRIVATE KEY` block and a `PUBLIC KEY` block. `<bits>` is 1024,
  2047, 2048, 8192, 16384, and 16386. The engine takes 2048 to 16384 bits,
  so 2047 and 16386 are outside the range. OpenSSL 3.6.4 writes a key of
  16384 bits for the request of 16385 bits, so 16386 bits is the smallest
  size above the range.
- `rsa-2048.pkcs1.pem` -- the 2048-bit key as a PKCS#1 `RSA PRIVATE KEY`
  block.
- `rsa-3prime.pem`, `rsa-3prime.pkcs1.pem`, and `rsa-3prime.pub.pem` -- a
  2048-bit RSA key of three primes, in the PKCS#8 and the PKCS#1 form, and
  its public key.
- `rsa-pss.pem` and `rsa-pss.pub.pem` -- an `id-RSASSA-PSS` key.
- `vector.data` and `rsa-2048.vector.sig` -- a test vector: a buffer, and the
  signature of `openssl dgst -sha256 -sign rsa-2048.pem` over it. The tests
  sign the buffer and compare the bytes, so `spki/.gitattributes` marks the
  two files as binary.
- `MANIFEST` -- the OpenSSL version that wrote the files.

Each run makes new keys, so the files are committed. Run the script only to
replace them. It needs OpenSSL 3, because LibreSSL cannot make a key of more
than two primes. The `OPENSSL` variable names the `openssl` command:

```sh
OPENSSL=/path/to/openssl tests/fixtures/spki/keys/generate.sh
```

The script stops if `$OPENSSL version` does not start with `OpenSSL 3`, if a
key does not have the number of bits that it asks for, or if `openssl` does
not verify the test vector. The tests pin the fingerprint of
`rsa-2048.pub.pem` in the constant `FINGERPRINT_2048`, in
`crates/ostrya-sign/src/spki/rsa.rs` and in
`crates/ostrya/tests/sign_spki_rsa.rs`. After a run, set the two constants to
the new fingerprint.

### Fixtures that the tool cannot write

The `ostree` tool refuses to write a `bare-split-xattrs` repository, so no
golden fixture of that mode exists. The tests of that mode build a
repository by hand from the public documentation and the observed layout.
Such a repository is valid only after the `ostree` tool accepts it with
`fsck`, `ls`, and `checkout`. `crates/ostrya/tests/read_split_xattrs.rs`
runs these checks when the tool is on `PATH`.

A `bare-user-shared` repository is made from a `bare-user` repository: the
test changes the mode of the objects and the `[core] mode` key.

### Absent fixtures

A test that reads a composefs fixture, and
`imports_tool_export_into_matching_tree` in `crates/ostrya/tests/tar.rs`,
skip when their fixture is absent. Each writes a message to standard error,
for example `composefs fixture tree absent; skipping`, and passes. Cargo
shows the output of a test only when the test fails. To tell a skip from a
pass, run the test with `--nocapture` and look for the message:

```sh
cargo test -p ostrya-composefs --test golden -- --nocapture
cargo test -p ostrya --test composefs -- --nocapture
```

No environment variable makes such a skip a failure.

Each other test that reads a fixture fails when its fixture is absent. The
tests that use the TLS fixtures compile them in with `include_bytes!`, so
they do not build without them.

This difference is not visible in a checkout, where each fixture is present.
It applies to the published packages:

- The package of `ostrya-composefs` holds only `tests/golden.rs`, which
  skips. Its tests pass without the fixtures.
- The package of `ostrya` also holds tests that fail without the fixtures.
- The unit tests of `ostrya-fetch` include the TLS fixtures from outside the
  package, so they do not build from the package. The library build includes
  no fixture.

## Test gates

### Cross-compatibility

A change that writes a repository format passes two checks: the `ostree`
tool reads what the port writes, and the port reads what the tool writes.
The commit checksum is the oracle where one exists. The golden fixtures
cover the second check. A test that runs the tool covers the first check,
and it needs the tool on `PATH`.

A port extension that has no counterpart in the tool and does not change the
format compares its result with the result of a port path that the tool
checks. For example, an overlay changeset merged over a base tree gives the
same root checksum as the ingest of the expected merged tree, which the test
builds by hand (`crates/ostrya/tests/overlay.rs`).

### Skips that a harness can make a failure

A test that needs a program or a privilege that is absent skips and writes
the reason to standard error. A skipped test passes, so a harness that
lacks the program reports the test as tested. A harness that has the
program sets the related variable, and then an absent program fails the
test:

- `OSTRYA_REQUIRE_OSTREE` -- the `ostree` tool, for the cross-checks. Some
  of these tests are the `evidence:` of a conformance record. The
  cross-checks include the pull and the fsck of a bucket repository by the
  tool.
- `OSTRYA_REQUIRE_OSTREE_ED25519` -- the ed25519 engine of the `ostree`
  tool, which `ostree --version` shows as `sign-ed25519`. The ed25519
  cross-checks include the verify of the signed summary of a bucket
  repository by the tool.
- `OSTRYA_REQUIRE_GNUPG` -- `gpg` and `gpgv`, for each GPG test.
- `OSTRYA_REQUIRE_MULTIGROUP` -- a second group of the process, for the
  ownership tests of `pull-local`. These tests are the only coverage of the
  ownership gate.
- `OSTRYA_REQUIRE_MOUNT` -- `CAP_SYS_ADMIN` and fs-verity, for the mount
  tests (see "Tests").
- `OSTRYA_REQUIRE_S3` -- `rclone`, for the tests of the bucket client, of
  the pull from an `s3://` address, of the pull of collection refs, and of
  a bucket repository against `rclone serve s3`: the writer lock, the
  listing, the init, the push, the tree push, the fsck, the prune, and the
  commands of the `ostrya` command (see "Tests").
- `OSTRYA_REQUIRE_SEAWEEDFS` -- `weed` of SeaweedFS, for the tests of a
  bucket repository against `weed mini`: the writer lock, the object
  listing, the init, the push, the tree push, the fsck, the prune, the
  summary update, and the pull of the `ostree` command, through the library
  and through the `ostrya` command (see "Tests").

The CI test job sets `OSTRYA_REQUIRE_GNUPG`, `OSTRYA_REQUIRE_MULTIGROUP`, and
`OSTRYA_REQUIRE_S3`. It installs `rclone` from the release archive of the
rclone project, because the `rclone` package of the runner has no
`serve s3`.

### GPG verification against `gpgv`

`crates/ostrya/tests/verify_gpg_agreement.rs` is the differential gate of
the GPG verify engine. Each case builds its fixtures with `gpg` in a private
GnuPG home. It puts the same keyring, signature, and payload through the
public verify path and through `gpgv`, and it compares the two reports field
by field. The module doc of the file lists the axes of the matrix and the
differences that it declares and does not compare.

The gate also gives the parser a corpus of keyrings and signatures made from
the good fixtures by truncation and by single-bit flips. A changed input can
still hold a full certificate or a full signature, so the corpus asserts
these three properties and no verdict per input:

- No changed input gets a valid verdict over a payload that no key signed.
- A valid verdict over the signed payload names the key of the fixture.
- No case panics. A panic hook counts the panics and passes each one to the
  hook that was installed before it, so the message of a panic is written.
  The test asserts that the count is zero.

`gpg` builds the fixtures and `gpgv` is the reference, so the gate skips
when one of the two is absent. The gate is the only check of the engine
against GnuPG, so CI sets `OSTRYA_REQUIRE_GNUPG`.

## Man pages

The man pages of the `ostrya` command are in `crates/ostrya-cli/man/`. A unit
test of `ostrya-cli` generates the pages from the `clap` definition. The test
fails if a checked-in page is different.

After a change to the help text, write the pages again:

```sh
OSTRYA_BLESS_MAN=1 cargo test -p ostrya-cli --bin ostrya man_pages
```

The hand-written sections, for example ENVIRONMENT and EXAMPLES, are in
`crates/ostrya-cli/man/extra/<page>.roff`.

The man page `ostrya-mountd(8)` is in `crates/ostrya-mountd/man/`, and its
hand-written sections are in
`crates/ostrya-mountd/man/extra/ostrya-mountd.8.roff`. Write it again with:

```sh
OSTRYA_BLESS_MAN=1 cargo test -p ostrya-mountd man_page
```
