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
  of these tests are the `evidence:` of a conformance record.
- `OSTRYA_REQUIRE_OSTREE_ED25519` -- the ed25519 engine of the `ostree`
  tool, which `ostree --version` shows as `sign-ed25519`.
- `OSTRYA_REQUIRE_GNUPG` -- `gpg` and `gpgv`, for each GPG test.
- `OSTRYA_REQUIRE_MULTIGROUP` -- a second group of the process, for the
  ownership tests of `pull-local`. These tests are the only coverage of the
  ownership gate.
- `OSTRYA_REQUIRE_MOUNT` -- `CAP_SYS_ADMIN` and fs-verity, for the mount
  tests (see "Tests").
- `OSTRYA_REQUIRE_S3` -- `rclone`, for the tests of the bucket client, of
  the pull from an `s3://` address, and of a bucket repository against
  `rclone serve s3` (see "Tests").
- `OSTRYA_REQUIRE_SEAWEEDFS` -- `weed` of SeaweedFS, for the tests of the
  writer lock and of the object listing of a bucket repository against
  `weed mini` (see "Tests").

The CI test job sets `OSTRYA_REQUIRE_GNUPG` and `OSTRYA_REQUIRE_MULTIGROUP`.

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
