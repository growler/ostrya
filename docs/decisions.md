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
  and ECDSA through `p256`.
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
- `sha2` -- SHA-256, for object checksums and for fs-verity digests.
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
- `ed25519-dalek` -- the ed25519 sign engine, in `ostrya-sign`.
- `p256` -- the spki sign engine, in `ostrya-sign`.
- `pgp` -- OpenPGP keyring parsing and signature verification.
- `hyper` -- the HTTP/1.1 and HTTP/2 engine of `ostrya-fetch` and
  `ostrya-server`. Both crates take version 1.11.1 or later. Version 1.11.0
  can keep the last chunk of a response body in its write buffer when the
  first poll of the body is pending, and then the response does not end.
- `rustls`, `rustls-graviola`, `futures-rustls`, `rustls-native-certs` and
  `rustls-pemfile` -- TLS. See "TLS stack".
- `url` and `pkcs8` -- in `ostrya-fetch`.
- `getrandom` and `x509-cert` -- in `ostrya-server`.
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

The spki engine is pure Rust over `p256`: deterministic ECDSA on NIST P-256
with SHA-256. The `ostree` command builds this engine only with OpenSSL.
The engine is behind the `sign-spki` feature, so a build without it has no
ECDSA crate tree.

No available build of the `ostree` command has spki. The maintainer decided
to cross-check the engine against the `openssl` command in both directions.
`format-reference.md`, "Signing details", marks the spki facts as a design
target. The test `spki_tool_cross_verify_pending` skips until a build of the
`ostree` command with spki is available.

## GPG

Signing runs the system `gpg` binary as a subprocess over its `--status-fd`
interface. Thus keys in an agent and keys on a hardware token work through
`gpg` with no code of their own, and the private key stays with `gpg`.

Verification is in the process, over the `pgp` crate. `sequoia-openpgp` was
rejected for its LGPL license. The port owns the trust policy: issuer
resolution, subkey bindings, expiry, revocation, the signature class and the
digest policy. No fallback to the `gpgv` binary exists, so one engine and one
policy give each verdict.

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
copy, and hashes it on the task of the request, on each call. On the
development host, the SHA-256 of 8 MiB takes about 4.8 ms in a release build.
This is less than the limit of 10 ms for work on the task, so the fetcher
gives the signer the bytes and does not hash the body itself. A streamed body
reaches the signer as `SignPayload::Streamed`, with no bytes.

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

## GC anchor keys

- `Repo::prune` reads `[ex-ostrya] gc-root-metadata-keys` and merges the
  keys of the caller into the list. The config key is the policy of the
  repository, and it only adds roots. Thus a library caller cannot remove a
  config key from a run, and a run keeps at least what the same run with no
  config key keeps.
- A commit write refuses a value of an anchor key that a prune refuses.
  Else the commit enters the store, and each later prune that reaches it
  fails.
- The library does not know where an entry of a metadata dict comes from.
  Thus the check cannot exempt a value that `ostrya commit --keep-metadata`
  copies from the parent commit.

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
- No option struct of the `ostrya` crate has the attribute: `PruneOptions`,
  `PullOptions`, `TarExportOptions`, `TarImportOptions` and the others. The
  attribute stops a struct expression outside the defining crate,
  `..Default::default()` included. Thus a new field in one of these option
  structs is a breaking change, and it takes a minor version before 1.0.
- `ostrya_server::ServeOptions` and `ostrya_mount::MountOptions` have the
  attribute. A caller starts from `Default::default()` and sets the fields.
- `ostrya_gvariant::Type` and `ostrya_gvariant::Value` do not have the
  attribute. The GVariant serialization specification closes the type
  alphabet, and the two enums name all of it. An exhaustive `match` over
  either enum is the gate that makes each site answer for a new type
  character. A new variant in either enum takes a major version.
