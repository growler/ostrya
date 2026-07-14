# Ostrya -- Phased Plan

Ostrya is a from-scratch reimplementation of libostree as a pure-Rust, async
library. This
plan targets the on-disk format and observable behavior specified in
`format-reference.md`, with the target API in `api-sketch.md`. Each phase is
scoped to be independently reviewable, with explicit success criteria.

Provenance: this is a clean-room reimplementation. Its design is grounded only
in the public ostree documentation (https://ostreedev.github.io/ostree/) and the
observed behavior of the `ostree` tool run as a black box. The LGPL source is
not consulted (see CLAUDE.md, "Licensing and clean-room discipline"). The target
library is MIT-licensed.

## Goals and constraints

1. Rust-native, no C library linkage beyond what `std` links. `rustix`
   handles the syscalls a portable async file API cannot express
   (fd-relative opens and metadata, xattrs, statx, FICLONE reflink,
   O_TMPFILE + linkat, OFD locks); streaming file I/O goes through the
   runtime's async file.
2. Async, with a feature-gated runtime backend behind the internal
   `ostrya-rt` crate: `smol` by default, `tokio` optional.
3. Multiple concurrent transactions within a single process.
4. Capable of passing ostree's test suite, run as an external conformance gate.
5. Extensions: commit signing via `sequoia-openpgp` (replacing gpgme),
   composefs/EROFS export, tar import/export, AWS S3 push/pull, ssh
   git-style push/pull.

The port is a library. It is not a drop-in replacement for the `ostree` tool.
A minimal `ostrya` binary lands once the ingest and checkout paths are ready
(Phase 11); `ostree`-compatible command-line behavior is a late phase
(Phase 17), built specifically to unlock the shell-driven part of the test
suite.

Faithful means: byte-for-byte identical on-disk format, identical checksums,
identical algorithms. It does not mean mirroring the C API shape. The API is
redesigned to be idiomatic Rust (see `api-sketch.md`).

## Interpretation of "no dependencies except rust"

Read as: pure Rust only, no C libraries and no `*-sys` crates that link C. The
Rust crate ecosystem is in scope. Proposed foundation crates, all pure Rust:

- `rustix` -- the syscalls a portable async file API cannot express:
  fd-relative open/stat/link/rename/readlink/mkdir, xattrs, statx, statvfs,
  FICLONE reflink, O_TMPFILE + linkat, flock and fcntl OFD locks,
  fsync/syncfs. No libc linkage.
- `smol` -- the default runtime backend (`smol::unblock`, `smol::fs::File`,
  `smol::Timer`, and its net layer for pull).
- `futures-io` and `futures-lite` -- the runtime-neutral async trait
  surface and combinators the library is written against.
- `tokio` (optional, behind the `tokio` feature) -- alternative runtime
  backend. Pure Rust; its syscalls go through the `libc` crate, which `std`
  already links on glibc targets.
- `async-lock` -- runtime-neutral async locks.
- `pin-project-lite` -- pin projection for the stream wrapper types.
- `sha2` (RustCrypto) -- SHA-256; `digest` -- the hashing trait surface the
  hashing streams are generic over.
- `async-compression`, restricted to its `deflate` codec feature plus the
  trait-family features (its zstd and xz features pull C) -- streaming raw
  DEFLATE for archive-mode content objects, over `flate2` with the
  pure-Rust `miniz_oxide` backend.
- `ed25519-dalek` -- the ed25519 sign engine.
- `sequoia-openpgp` with the RustCrypto backend (`crypto-rust`) -- GPG signing
  and verification without nettle/C.
- `rustls` plus `webpki-roots` / `rustls-native-certs` -- TLS for pull.
- `smol-tar` -- async tar import/export in the smol ecosystem.
- `clap` -- command-line argument parsing for the `ostrya` binary
  (`ostrya-cli` only).
- LZMA/xz, HTTP client, INI parsing, fs-verity, and EROFS: see the Decisions
  section; each has a pure-Rust path.

Anything that would pull in C (openssl-sys, libgpg-error/gpgme, libcurl,
libsoup, liblzma via xz2, libarchive, libcomposefs, glib) is excluded by
constraint 1.

## Architecture

### Workspace layout

A Cargo workspace of focused crates keeps review units small and compile times
bounded:

- `ostrya-gvariant` -- the byte-exact GVariant codec. No ostree knowledge.
- `ostrya-core` -- object model, checksums, varint, loose paths, xattr
  canonicalization, format (de)serialization. Depends on `ostrya-gvariant`.
- `ostrya-rt` -- internal runtime abstraction: `rt::unblock`, `rt::File`
  (over an already-open fd; `smol::fs::File` or `tokio::fs::File`),
  `rt::Timer`, later `rt::spawn` and networking. The only crate that knows
  which backend is compiled. No ostree knowledge.
- `ostrya` -- the library: repo, transactions, commit, checkout, refs, read,
  prune, fsck, sign, summary, deltas, pull, tar, composefs. Feature-gated.
- `ostrya-cli` -- the CLI crate, building the `ostrya` binary: a minimal
  command set once the ingest and checkout paths land (Phase 11), grown
  incrementally; the `ostree`-compatible surface arrives with the
  shell-test harness (Phase 17).

Feature flags on `ostrya`: `pull`, `sign-gpg`, `deltas`, `s3`, `ssh`, plus
the runtime backend selectors `smol` (default) and `tokio`, forwarded to
`ostrya-rt`. Each
heavier or riskier subsystem is opt-in so the core stays small. Tar
import/export (built on `smol-tar`) and composefs export are always
compiled, not feature-gated.

### Async model

The runtime backend is feature-gated and hidden behind the internal
`ostrya-rt` crate, which exposes `rt::unblock`, `rt::File` (constructed
from an already-open fd; read/write/seek, `sync_all`/`sync_data`,
`into_std`; `smol::fs::File` or `tokio::fs::File` underneath), `rt::Timer`,
and later `rt::spawn` and networking. `smol` is the default backend; the
`tokio` feature selects tokio. Only `ostrya-rt` knows the backend: the rest
of the library is written against `rt::*`, the `futures-io` traits,
`async-lock`, and `futures-lite` combinators, and is runtime-neutral.
`rt::File` presents the `futures-io` traits under both backends so that
core code stays generic.

Backend feature policy: the features are additive-safe. `smol` is on by
default; `tokio` takes precedence when both are enabled, so Cargo feature
unification cannot break a build; enabling neither is an explicit compile
error. Concrete public stream types (`ContentReader`, `ContentWriter`, the
hashing streams) implement the `futures-io` traits unconditionally and the
tokio traits under the `tokio` feature. `AsyncRead`/`AsyncWrite` bounds in
argument position are the `futures-io` traits; a tokio caller adapts inputs
with `tokio_util::compat`.

Division of labor between `rustix` and the runtime:

- `rustix` owns namespace and metadata syscalls: fd-relative open, stat,
  link, rename, readlink, mkdir (the `openat` family against the stored
  repo and objects fds), xattrs, statx, FICLONE reflink, O_TMPFILE +
  linkat, OFD locks, and the fsync/syncfs ordering. These run as
  synchronous calls offloaded through `rt::unblock` at coarse granularity
  -- per object write, per checkout file -- rather than wrapping each
  syscall.
- `rt::File` owns streaming reads and writes: payload I/O runs over fds the
  rustix layer opened, in bounded-size chunks.
- `rt::unblock` is the only entry to a blocking pool (`smol::unblock` under
  smol, `tokio::task::spawn_blocking` under tokio), so each backend runs
  exactly one pool under its own configuration.
- Network I/O in pull is genuinely async on the backend's net layer plus
  `rustls`.
- CPU-bound work (SHA-256, DEFLATE, xz) runs through `rt::unblock`, except
  bounded per-chunk work such as archive inflate, which runs in-task inside
  `poll_read`.
- File content is streamed in bounded-size chunks end to end: hashing,
  compression, object store writes, checkout, and transfer never buffer an
  unconstrained blob in memory. Whole-buffer handling is reserved for
  metadata objects, whose size the format caps.

Public entry points are `async fn`. Filter and xattr callbacks stay synchronous
`FnMut`. The await seams sit at object load, the copy/hash/compress loops, and
the fsync/rename phases.

### Concurrency: transactions as owned handles

This is the central deliberate divergence. The reference tool permits only one
transaction per repository at a time; a second concurrent commit against the
same repository is serialized.

The port models `Transaction` as an owned handle that carries its own staging
directory, `object_sizes` map, devino cache, ref queue, and free-space counter.
`Repo` holds only shared, immutable-or-mutex-guarded state (fds, parsed config,
the dirmeta read-cache). `Repo` is cheaply clonable (an `Arc` inner) so a
`Transaction` can be moved into a task without lifetime friction. Multiple
transactions coexist, each atomic on commit via its own staging dir and the
rename-into-objects step. Within one transaction, `&Transaction` is Send+Sync
and concurrent object writers share it with counters behind a `Mutex`.

`Repo`, `Transaction`, `FileObject`, and the file content readers and
writers are `Send + Sync`, so every handle moves freely across tasks and
threads.
Each type gains a compile-time assertion pinning this in the phase that
introduces it.

Cross-process and cross-`Repo` safety uses a two-layer lock on `<repo>/.lock`.
The outer layer is a classic `fcntl` record lock (`F_SETLK`, via
`rustix::fs::fcntl_lock`), which shares a lock space with the OFD locks the
`ostree` tool takes, so the library and the tool exclude each other on the same
repository. The inner layer is a per-repository reference count that supports
same-repo reentrancy and shared-to-exclusive upgrade and downgrade, touching the
descriptor only at the transitions that change the effective lock. A normal
transaction takes the lock shared, matching the read lock the tool holds during
a commit; destructive maintenance takes it exclusive.

Record locks are process-associated: two descriptors in one process do not
conflict, and closing any one descriptor to the file drops every lock the
process holds on it. A process-global registry keyed by the lock file's
`(device, inode)` gives every handle to one repository -- clones and independent
opens alike -- the same descriptor and reference count, so exactly one `.lock`
descriptor exists per repository per process. The reference tool's roughly
one-second lock-acquisition retry spin becomes an `rt::Timer` retry loop bounded
by `lock-timeout-secs`.

### Durability contract

Reproduce the commit ordering the tool exhibits (observable by tracing its
syscalls): `syncfs(repo)` then rename staged objects into `objects/xx/` then
fsync each `objects/xx/` and `objects/` then write refs. Objects are durable
before any ref points at them. Ref writes are individually atomic (tmpfile +
fdatasync + rename) but not atomic as a set. Honor `fsync=false` (all fsync
becomes no-op) and `per-object-fsync`.

## New repository mode: bare-user-shared

A development-only repository mode introduced by this port, offered as an
optional add-on. Production repositories stay `bare`; this mode supports
building images in a group-shared repository on a multi-user build host and
serving as a composefs backing store. The full format is in
`format-reference.md`.

Summary. Storage is `bare-user` -- raw payload on disk, logical
uid/gid/mode/xattrs in the `user.ostreemeta` xattr, symlinks as regular
files -- with one behavioral difference: the logical mode is never applied to
the inode. Objects carry a fixed mode 0644, and `.lock` is group-writable;
group sharing of the repository directories is arranged at the filesystem
level, with the repository directory made setgid 2775 and given a default group
ACL before `init` so the OS propagates the group to everything created
underneath. This resolves the
`bare-user` lockout on restrictively-permissioned files in a shared
repository (an `/etc/shadow` object stored 0600 by one user is unreadable to
the next). Object identity, and therefore dirtree and commit hashes, are
unchanged, so a commit developed here is identical when pulled into a bare
production repository. The distinct mode string keeps the upstream tool from
hardlink-checking-out inodes that do not carry logical modes.

Invariant. `ostree.sizes` never appears in this mode, as in `bare-user`: size
generation is an archive-only mechanism (observed: a size-generation request
in a non-archive repo is a silent no-op in the tool), so the cross-mode commit
identity the development-to-production workflow relies on needs no
mode-specific handling.

Design thread across phases:

- Phase 6a: `mode=bare-user-shared` is accepted, validated, and written to
  `[core] mode` on create; reading is served by the `bare-user` loader, which
  never consults inode permissions.
- Phase 7: the `bare-user` writer with the inode mode application skipped:
  objects `fchmod` 0644 (never trusting umask), repository directories
  created 0777 reduced by the umask (a group-shared repository relies on a
  setgid parent and default group ACL set by the operator before `init`),
  `.lock` written 0664; size generation is archive-only, so a request in this
  mode is a no-op.
- Phase 8: copy-based checkout (reflink where the filesystem supports it)
  applying the `user.ostreemeta` mode; hardlink checkout refused.
- Phase 9: composefs export builds the EROFS metadata from `user.ostreemeta`
  and redirects each regular file to its `.file` loose path; ownership is
  presented via composefs uid mapping at mount.
- Phase 12: fsck and prune as `bare-user`; inode permissions are not
  authoritative and are not checked.

## Testing strategy

The suite is bimodal. Roughly 45-55% is library-format-testable, ~25% needs full
sysroot/deployment (admin), ~20-25% is network/gpg/tar/composefs.

- Every phase ships unit tests plus golden-byte fixtures produced by running the
  `ostree` tool (checked into the repo). Byte-exactness is verified against
  these fixtures and cross-checked by having the tool read what the port writes
  and vice versa. The archive and bare fixtures are checked in as plain trees.
  The bare-user-family fixtures (bare-user, canon, xattr) store each file's
  logical metadata in a `user.ostreemeta` xattr, which git does not track, so
  they are checked in as xattr-preserving tarballs under
  `tests/fixtures/generated/<name>.tar` and unpacked on demand by the test
  harness. Generating the fixtures needs the `ostree` tool; consuming them from
  a fresh checkout does not.
- Unit tests for the format-layer primitives (checksum, varint, mutable-tree,
  bloom, rollsum, dates, utf8, keyfile, etc.) are written early against
  reference vectors captured from the tool; they validate the format layer
  without any CLI.
- A compatible shell-test harness plus a growing `ostree`-compatible CLI unlock
  the published shell conformance tests incrementally, targeted phase by phase
  (commit/checkout, then refs/prune/fsck, then signing, then deltas, then pull).
- Sysroot/deployment (admin) is treated as a separate, later, optional track.
  A repo-operations library does not inherently need the boot/deploy machinery,
  and that cluster is the heaviest (root, bootloaders, `/ostree` layout).

Cross-compatibility (the tool reads the port's output and the reverse) is the
strongest correctness signal and is a required gate at each format-producing
phase.

## Phased roadmap

Phases are ordered by dependency and priority. Early phases are small and
foundational;
the large subsystems (write, checkout, pull) are split into sub-phases. Each
phase is a reviewable unit with a stated verification gate.

### Phase 0 -- Scaffolding (DONE)

Workspace, crates, `Error`/`Result` types, CI (fmt, clippy, test), the
golden-fixture harness (a script that drives the `ostree` tool to emit reference
bytes). No functional code.
Verify: `cargo test` runs green on an empty skeleton; fixtures generate.

### Phase 1 -- GVariant codec (`ostrya-gvariant`) (DONE)

Byte-exact serialize and deserialize for the fixed set of type signatures
ostree uses (`a{sv}`, `ay`, `as`, tuples, `a(say)`, `a(sayay)`, `a(ayay)`,
`(uuu...)`, nested arrays). Normal-form output. This is the bedrock; the
checksum of every metadata object is the hash of these bytes.
Verify: round-trip and byte-equality against golden variants dumped from the
tool for each type string.

### Phase 1a -- Typed codec layer (`ostrya-gvariant`) (DONE)

Typed encode and decode operating directly on serialized bytes: decode reads
fields in place from the buffer, encode writes normal-form output directly.
Two building blocks, both inside `ostrya-gvariant` and free of ostree
knowledge:

- Reader and writer primitives. A cursor over a serialized container that
  resolves framing offsets and yields fields and elements as borrowed slices
  (`&str`, `&[u8]`), applying the same normal-form checks as `from_bytes`. A
  writer that appends fields with correct alignment, padding, and framing
  offsets and produces the same normal-form bytes as `to_bytes`.
- A pair of codec traits, `GvEncode` and `GvDecode`, each carrying the
  GVariant type string as an associated constant, with `encode` writing
  through the writer and `decode` reading from the cursor. Decode is
  borrow-first: strings and byte arrays decode as `&str` and `&[u8]`
  borrowing the input buffer, and arrays decode as lazy iterators over the
  framing offsets, so traversal of read-heavy objects (dirtree walks during
  checkout and pull) performs no heap allocation. Owned decode targets are
  built only where the caller retains or mutates the data.

This phase ships the primitives plus hand-written trait impls for the scalar
and container building blocks (booleans, integers, strings, byte arrays,
arrays, tuples, variants). The ostree object structs (dirmeta, dirtree,
commit, file headers) implement these traits in Phase 3, which is also where
the value-level conventions (big-endian scalar fields, empty `ay` as an
absent parent, checksum length and sort-order validation) are applied. The
`Value` tree stays as the representation for dynamic `a{sv}` content and for
fixtures and tests; `from_bytes` and `to_bytes` are unchanged.

All codec impls are written by hand; the object type set is small and fixed.
A derive macro is out of scope (see Decisions).

Verify: for every golden fixture, typed decode then encode is byte-identical
to the input and agrees with the `Value` path; a counting-allocator test
confirms borrowed dirtree and xattr traversal performs zero heap allocations.

### Phase 2 -- Core primitives (`ostrya-core`, part 1) (DONE)

`ObjectType`, `Checksum` (32-byte, hex/base64/modified-base64/`ay`
conversions), LEB128 varint, loose-path derivation, `ostree.sizes` packing,
xattr canonicalization and validation, GKeyFile/INI subset parser. `RepoMode`
is added here as a supporting primitive because loose-path derivation and
`ObjectType::extension` depend on it.
Verify: unit tests for checksum and varint against captured reference vectors;
golden loose paths.

### Phase 3 -- Object model (`ostrya-core`, part 2) (DONE)

Serialize and parse commit, dirtree, dirmeta, and file headers (both
uncompressed and archive), as typed structs implementing the Phase 1a codec
traits: borrowed views on the read path (dirtree traversal), owned structs
where data is retained. The value-level conventions live in these impls:
big-endian scalar fields, empty `ay` as an absent parent, checksum length
checks, and sort-order validation for dirtree entries and xattrs. Structural
validation (path-traversal defense, mode and rdev checks). Content-object
checksum computation (framed header + payload).
Verify: read real objects from a tool-created repo, recompute their checksums,
and match; reserialize and get identical bytes.

### Phase 4 -- Repo open/create and config (DONE)

Async `Repo` handle over `rustix` fds (repo/objects/tmp/cache dir fds, boot-id
staging prefix). Config parse for `[core]`, `[archive]`, remotes. Directory
layout creation. No object I/O yet beyond config.
Verify: open a tool-created repo and read its config/mode; create a repo and
have the `ostree` tool recognize and operate on it.

The handle holds the repo-root and `objects/` fds, which every repository has.
`create` writes the full layout (`objects`, `refs/{heads,remotes,mirrors}`,
`state`, `tmp`, `tmp/cache`, `extensions`), but the `tmp`/`tmp/cache` fds and
the boot-id staging prefix are acquired at transaction time (Phase 6), not at
open: the tool creates `tmp/` and reads the boot id when a transaction starts,
and a repository served read-only can lack `tmp/` entirely, so requiring those
fds at open would reject repositories the tool opens.

### Phase 5 -- Reading path (DONE)

`load_variant`, `load_commit` (+ commitpartial state), `load_file` (all modes,
including archive decompress and `user.ostreemeta` decode), ref resolution and
listing, the `RepoTree` traversal (lazy children, binary-search child lookup)
and enumerator (files-then-dirs, name-sorted). `load_file` returns file
metadata plus a bounded-chunk async reader; the payload is never buffered
whole (archive decompression streams).
Verify: read objects, refs, and full trees from a tool-created repo; compare
against `ostree ls`, `ostree cat`, `ostree show`; compile-time assertions
that `FileObject` and its reader are `Send + Sync`.

### Phase 5a -- Runtime backend and hashing streams (DONE)

The internal `ostrya-rt` crate: `rt::unblock` and `rt::File` (from an
already-open fd; read/write/seek, `sync_all`/`sync_data`, `into_std`;
`smol::fs::File` or `tokio::fs::File` underneath), with `smol` as the
default backend and `tokio` behind a feature, per the Async model section.
`rt::Timer` lands with Phase 6, `rt::spawn` and networking with Phase 16.
All blocking-pool offload in `ostrya` goes through `rt::unblock`;
`ContentReader` streams from `rt::File`, implements `futures_io::AsyncRead`
unconditionally and `tokio::io::AsyncRead` under the `tokio` feature, and
inflates archive objects through a poll-driven streaming decoder
(`async-compression` raw DEFLATE, bounded chunks decompressed in-task).

The hashing streams (in `ostrya`), the primitives the write path builds on:
`HashingReader` and `HashingWriter` feed a digester with every byte they
pass through, expose the byte count, and yield `(digest, size)` from a
consuming `finalize`. The constructor takes the digester by value, possibly
pre-seeded: a file object id covers the framed file header before the
payload. The verifying counterpart (`VerifyingReader`) lands with pull
(Phase 16a).

Dependency set for the phase: `ostrya-rt` uses `smol`, `futures-io`, and
optional `tokio` (features `fs`, `io-util`, `rt`, `time`); `ostrya` adds
`pin-project-lite`, `digest`, and `async-compression` (`deflate` plus
trait-family features only), routes all pool offload through `ostrya-rt`,
and keeps no direct `blocking` or `miniz_oxide` dependency.

Verify: the test suite passes under both backends (default features, and
with the `tokio` feature selecting the tokio backend); reads from a
tool-created repo are byte-identical under both; the `Send + Sync`
compile-time assertions cover `ContentReader` and the hashing streams; unit
tests drive the hashing streams to EOF and check digest and size, including
the pre-seeded-digester and empty-payload cases.

### Phase 6 -- Transactions and locking (DONE)

Owned `Transaction` handles, staging dir allocation and reaping (boot-id keyed),
a classic `fcntl` record lock (`F_SETLK`) with async acquisition, the two-layer
in-process counter, RAII auto-abort on drop. Concurrency test: two transactions
progressing in one process; cross-process lock contention.

The lock is a record lock rather than an OFD lock because `rustix` does not
expose the OFD `fcntl` commands and a raw call would need the C `libc` crate and
`unsafe`. A record lock shares a lock space with the tool's OFD locks, so the
two exclude each other; the process-global registry keyed by the lock file's
`(device, inode)` keeps a single descriptor per repository per process, which
the process-associated record-lock semantics require (see "Concurrency"). Object
and ref writing and commit assembly land with the write path (Phase 7), so at
this phase a transaction owns its lock hold and staging directory, and
`commit`/`abort` release the lock and remove the staging directory.

Verify: concurrent transactions each hold an independent staging directory;
the shared lock lets many transactions proceed in one process; an exclusive lock
excludes another process, and excludes and is excluded by the `ostree` tool;
drop reaps the staging directory and releases the lock. Independent-commit
verification arrives with the write path.

### Phase 6a -- Mode refactor: bare-user-shared and bare-split-xattrs read (DONE)

Supersedes the `bare-user-split-attrs` design (the `.filea`/`.fileb` object
split); its write path was never built, so the refactor touches only the
mode/objtype surface and the read path.

- Remove the split-attrs surface: `RepoMode::BareUserSplitAttrs`,
  `ObjectType::FileBlob`, the `.filea`/`.fileb` extensions and the
  `(uuuusa(ayay)ay)` codec (`ostrya-core`: `mode.rs`, `objtype.rs`,
  `filehdr.rs`), `load_split_attrs` and `blob_checksum_of` (`ostrya`), and
  their tests and fixtures.
- Add `RepoMode::BareUserShared` (`mode=bare-user-shared`): config parsing
  and serialization, create/open validation, reading through the `bare-user`
  loader.
- Implement `bare-split-xattrs` reading (read-only; writing stays out of
  scope, matching the tool). Publicly documented shape: `.file-xattrs`
  objects keyed by the checksum of the xattr content, reached through the
  `.file-xattrs-link` entry keyed by the file checksum; the reader takes the
  bytes at the link name and never depends on hardlink topology. The exact
  content-object layout (division of uid/gid/mode between `user.ostreemeta`
  and the split objects, treatment of files without xattrs) is not publicly
  documented and is recovered by observation; the recovered facts land in
  `format-reference.md`.

The tool refuses writes into `bare-split-xattrs`, so its read fixtures cannot
be tool-generated: candidate repositories are constructed by hand from the
public documentation and become valid fixtures only once
`ostree fsck`/`ls`/`checkout` accepts them. `bare-user-shared` read fixtures
derive from the bare-user fixture (objects re-chmodded, `[core] mode`
rewritten).

Verify: workspace tests green with the split-attrs surface removed; a
`bare-user-shared` repo opens, and `load_file` returns correct metadata and
content for objects stored 0644; the hand-built `bare-split-xattrs`
repository is accepted by the tool and read identically by the port;
`Send + Sync` compile-time assertions unchanged.

### Phase 7 -- Write path

Six sub-phases, each an independently reviewable unit with its own gate:
7a is the object-store write layer, 7b in-memory tree assembly, 7c
filesystem ingest, 7d commit assembly and durable publication, 7e
overlay changeset import, 7f the staging tree and tree merge. Each
sub-phase consumes only the public surface of the ones before it. The
tool-conformance gate lands with 7d: commits with checksums identical
to the tool's for the same input tree, accepted by `ostree fsck` and
`ostree show`. 7e and 7f are port extensions with no tool counterpart
and no on-disk format impact; their gates are self-consistency against
the 7c ingest path.

Dependency set for the phase: no new crates and no manifest changes.
Staging and metadata application use `rustix` under the already-enabled
`fs` feature (`openat` with `O_TMPFILE`, `linkat`, `symlinkat`,
`renameat`, `fchmod`, `fchown`, `fsetxattr`, `fstatvfs`, `syncfs`, `Dir`
iteration), offloaded through `rt::unblock` at per-object granularity;
hashing is the Phase 5a `HashingWriter` over `sha2`; archive compression
is the encoder half of the `async-compression` raw-DEFLATE codec whose
decoder the read path uses.

Format facts the write path needs that `format-reference.md` does not yet
state -- the inode modes the tool gives loose metadata objects, the exact
canonical-permissions rule, consume/adopt behavior, the per-object-fsync
syscall pattern -- are recovered by black-box observation in the sub-phase
that reaches them and recorded in `format-reference.md` in the same
change.

### Phase 7a -- Object writers: content and metadata (DONE)

The object-store write layer inside `Transaction`: streaming content
ingestion, metadata object writes, per-mode on-disk application, dedup,
free-space accounting, and publication of staged objects into `objects/`
at commit. After 7a a transaction stages and publishes individual
objects; trees and commits arrive in 7b-7d.

Definition:

- `FileMeta` (uid, gid, mode, xattrs): the logical metadata the writers
  consume; header serialization is the Phase 3 `FileHeader`.
- `ContentWriter` (from `Transaction::content_writer`), the push-style
  primary ingestion surface: streams one regular-file payload into a
  staging temp file (`O_TMPFILE` in the staging directory, `linkat` on
  finish; a named temp file where the filesystem refuses `O_TMPFILE`).
  Bytes pass through a `HashingWriter` seeded with the framed
  uncompressed header, so the object id is complete when the stream ends;
  in archive mode the same pass feeds the raw-DEFLATE encoder at
  `[archive] zlib-level` and counts compressed bytes. Bounded chunks end
  to end; the payload is never held whole in memory.
- Archive framing: the stored `.filez` leads with the length-prefixed
  `(tuuuusa(ayay))` header, whose byte length does not depend on the
  payload (the size field is fixed-width), so the writer reserves the
  header region up front and patches the final size in at finish.
- `finish` order: finalize the digest; verify against `expected` when
  given; if the object already exists in `objects/` or in this
  transaction's staging set, drop the temp file and return the existing
  id (dedup early-out); otherwise apply per-mode metadata and link the
  object under its loose name in the staging directory. Dropping a
  `ContentWriter` without `finish` abandons the temporary; the
  transaction reaps abandoned named temporaries at commit and abort.
- Per-mode application, always by explicit `fchmod`/`fchown`, never
  umask: bare applies logical uid/gid/mode and xattrs to the inode and
  stores symlinks as real symlinks; bare-user stores `(uuua(ayay))` in
  `user.ostreemeta`, applies inode mode
  `(mode & (S_IFREG|0775)) | S_IRUSR`, and stores symlinks as regular
  files holding the target plus one NUL; bare-user-shared is bare-user
  with a fixed inode mode 0644 and no logical mode on the inode;
  bare-user-only applies the canonical mode capped at 0775 and discards
  uid/gid and xattrs; archive writes `.filez` chmod 0644.
- `write_content` (pull-style, drives a `ContentWriter` from an
  `AsyncRead`), `write_regfile_inline` (small caller-held content),
  `write_symlink` (framed header only, no payload).
- `write_metadata`: whole-buffer (the format caps metadata size),
  checksum over the normal-form bytes, `expected` verification, staged
  uncompressed under the loose name.
- Free-space guard: at transaction start `fstatvfs` plus
  `min-free-space-percent` / `min-free-space-size` set a byte budget;
  each staged object debits it; exhaustion fails the write with a
  dedicated error carrying the shortfall.
- `object_sizes`: in archive mode each staged object records its on-disk
  (compressed) size and its logical (unpacked) size keyed by checksum, the
  input for `ostree.sizes` in 7d. The tool's `ostree.sizes` covers every
  object in the commit -- content objects and the dirtree/dirmeta metadata
  objects alike -- so a record is kept for metadata as well as content, and
  each carries its own object-type byte (recovered by observation; see
  `format-reference.md`, "Commit -- the ostree.sizes key").
- Object publication in `Transaction::commit()`, the object half of the
  durability contract: `syncfs` on the repo fd, rename staged objects
  into `objects/xx/` (fanout directories created on demand at 0777 reduced by
  the umask; in a group-shared repository the group and setgid bit are
  inherited from the operator-configured parent), fsync each
  touched `objects/xx/` and `objects/`. `fsync=false` turns every sync
  into a no-op; `per-object-fsync` follows the tool's recovered pattern.
  `commit(self)` returns `TransactionStats` (the devino counter stays 0
  until 7c).

Deliverables: `FileMeta`, `ContentWriter`, `Transaction::{content_writer,
write_content, write_regfile_inline, write_symlink, write_metadata}`, the
free-space guard, the `object_sizes` map, object publication inside
`Transaction::commit`, `TransactionStats`, and a `bare` fixture
repository added to `tests/fixtures/generate.sh` (logical owner set to
the invoking uid/gid so unprivileged tests can reproduce ownership
application).

Verify: for every fixture object across archive, bare, and bare-user,
plus the bare-user-shared derivation, the port writes byte-identical
loose objects -- payload bytes, stored header, xattr application, inode
mode -- under identical checksums; re-writing an existing object is a
dedup no-op visible in the stats; several tasks writing through one
`&Transaction` stage correctly; the free-space guard trips on an
artificially small budget; a compile-time assertion pins
`ContentWriter: Send + Sync`; the suite passes under both runtime
backends. Tool-level acceptance of whole repositories lands with 7d,
when commits and refs exist for the tool to read.

### Phase 7b -- Mutable tree and write_mtree (DONE)

In-memory tree construction and its serialization to dirtree and dirmeta
objects. After 7b a full tree's object set can be staged from known
checksums; walking a real filesystem is 7c.

Definition:

- `MutableTree` per `api-sketch.md`: name-keyed files (content checksum)
  and subdirectories (nested trees); `new`, `from_commit`, `ensure_dir`,
  `replace_file`, `remove`, `set_metadata_checksum`. Names are validated
  on insertion (UTF-8, no `/`, not `.` or `..`), and one name cannot be
  both a file and a directory, matching the Phase 3 owned-parse rule.
  `ensure_dir` is `async`: descending into a committed subdirectory reads
  its dirtree through the blocking-pool offload, so it departs from the
  synchronous sketch signature (the sketch is explicitly not final code);
  the other mutators stay synchronous.
- Lazy hydration: `from_commit` records the dirtree/dirmeta checksums
  and loads children only when a subtree is first descended into, so
  editing one path in a large commit reads only that path's spine.
- Dirty tracking and the clean-subtree short-circuit: an unmutated
  subtree keeps its known dirtree checksum and `write_mtree` reuses it
  without re-serializing or re-staging anything beneath it.
- `Transaction::write_mtree`: post-order walk over dirty subtrees; each
  written directory requires its dirmeta checksum set (an unset checksum
  is an error naming the path); assembles the `(a(say)a(sayay))` dirtree
  with byte-wise-sorted entries and stages it through `write_metadata`;
  returns the root as a `RepoTree`.

Deliverables: `MutableTree` with the sketched methods, lazy hydration
and dirty tracking, `Transaction::write_mtree`.

Verify: assembling the fixture tree from its known content checksums and
dirmeta values reproduces the fixture's dirtree and dirmeta objects
byte-for-byte; `from_commit` followed by `write_mtree` with no mutation
returns the original root and stages zero objects; mutating one nested
file re-writes exactly the dirtrees on that path's spine, counted
through the stats; invalid names and file/directory collisions are
rejected.

### Phase 7c -- Filesystem ingest: write_dfd_to_mtree and the modifier (DONE)

Walking an on-disk tree through fd-relative syscalls, ingesting its
contents through the 7a writers into a 7b `MutableTree`, under the
`CommitModifier` surface that shapes what is committed.

Definition:

- The walk: fd-relative directory iteration (`openat` with `O_NOFOLLOW`,
  `rustix::fs::Dir`, `statx` per entry), offloaded through `rt::unblock`
  at per-directory granularity; regular-file payloads stream through
  `write_content` over `rt::File`.
- Per entry: regular files read their xattrs (unless disabled), build a
  `FileMeta`, and stream in; symlinks `readlinkat` into `write_symlink`;
  directories serialize uid/gid/mode/xattrs as dirmeta through
  `write_metadata` and set it with `set_metadata_checksum`, then recurse.
- `CommitModifier`: `CommitModifierFlags` (SKIP_XATTRS, GENERATE_SIZES,
  CANONICAL_PERMISSIONS, ERROR_ON_UNLABELED, CONSUME, DEVINO_CANONICAL,
  SELINUX_LABEL_V1), the synchronous filter callback (`Allow`/`Skip`; a
  skipped directory prunes its whole subtree), and the synchronous
  xattr callback replacing the on-disk xattr set per path.
- CANONICAL_PERMISSIONS zeroes uid/gid and canonicalizes the mode; the
  exact bit rule is recovered by observation (committing crafted trees
  with and without the tool's corresponding option and diffing object
  ids) and recorded in `format-reference.md` before the flag lands.
- Labeling hook: the modifier carries an optional label callback invoked
  per path. When present, a pre-existing `security.selinux` xattr is
  dropped before the callback's label applies, so a label is never
  double-counted; ERROR_ON_UNLABELED makes a present-but-silent hook an
  error. A real SELinux policy backend is out of scope for this phase.
- `DevInoCache`: a (device, inode) to checksum map consulted before
  hashing, so an already-known file skips ingestion; populated by
  checkout in Phase 8, consulted here, hits counted in the stats.
  DEVINO_CANONICAL semantics are recovered by observation alongside it.
- CONSUME: each ingested source file is deleted as it is consumed;
  where the source inode already satisfies the target mode's on-disk
  form the ingest adopts it by rename instead of copying. The conditions
  under which the tool adopts are recovered by observation and recorded.
- GENERATE_SIZES marks the transaction so 7d emits `ostree.sizes`
  (archive-only; elsewhere the request is the documented silent no-op).

Deliverables: `Transaction::write_dfd_to_mtree`, `CommitModifier`,
`CommitModifierFlags`, `FilterResult`, `DevInoCache`, the labeling hook,
devino and filter statistics, and fixture variants in `generate.sh`
covering canonical permissions and `user.*` xattr-bearing files.

Verify: ingesting a source tree matching the fixture input yields the
fixture's root dirtree and dirmeta checksums through `write_mtree`; the
filter excludes exactly the skipped paths and stages none of their
objects; the xattr callback's replacement set lands in the object ids;
canonical-permissions ingest matches the checksums the tool produces
with its corresponding option; a devino hit skips rehashing (stats, and
no duplicate staging); CONSUME leaves the consumed source empty; the
xattr fixture (unprivileged `user.*` names) round-trips.

### Phase 7d -- Commit assembly, refs, and durable publication (DONE)

The commit object, detached commit metadata, the ref queue and immediate
ref writes, and the completed transaction commit sequence. 7d closes the
write path: the port produces complete commits the tool accepts.

Definition:

- `Transaction::write_commit(opts, root)` assembles
  `(a{sv}aya(say)sstayay)`: the caller's metadata dict (GVariant
  preserves dict insertion order, so byte-identity with a tool commit
  requires supplying keys in the tool's observed order), parent (empty
  `ay` for a root commit), related written empty, subject and body
  defaulting to empty strings, timestamp from `CommitOptions` else
  `SOURCE_DATE_EPOCH` else the current time (seconds UTC, big-endian),
  root dirtree and dirmeta from the `RepoTree`; staged through
  `write_metadata`.
- Binding keys (`ostree.ref-binding`, `ostree.collection-binding`) are
  ordinary caller-supplied metadata entries; the fixtures show which
  keys the tool writes for a branch commit and the conformance tests
  supply the same. `write_commit` adds nothing on its own.
- `ostree.sizes`: when the transaction is marked GENERATE_SIZES and the
  repository is archive mode, `write_commit` walks the committed tree to
  find the objects reachable from its root (root dirmeta, each dirtree,
  each subdirectory dirmeta, each file entry) and packs one entry per
  reachable object (checksum-sorted, LEB128 sizes, trailing objtype byte)
  into the metadata dict. A freshly staged object uses the 7a
  `object_sizes` record; an object that already existed in `objects/` and
  deduplicated has its sizes recovered from its loose object (on-disk size
  for the compressed size, the file header's uncompressed size or a
  symlink target length for the unpacked size, a metadata object's byte
  length for both). The walk descends into pre-existing subtrees, so an
  incremental commit that reaches objects from an earlier commit lists
  them too. Scoping to the reachable set gives each commit its own key
  when one transaction stages more than one commit; in every other mode
  the marked commit's bytes are identical to an unmarked one.
- Detached metadata: `Repo::write_commit_detached_metadata` and
  `read_commit_detached_metadata`; a bare `a{sv}` at the `.commitmeta`
  loose path, replaced atomically (tmpfile, fdatasync, rename); `None`
  writes the documented zero-length file.
- Refs: `Transaction::set_ref` and `set_collection_ref` queue
  refspec-to-checksum entries applied at commit;
  `Repo::set_ref_immediate` writes outside a transaction. A ref file is
  64 hex chars plus `\n` (65 bytes), written tmpfile + fdatasync +
  rename, parent directories created for `/`-bearing names; a `None`
  checksum removes the ref file.
- The completed `Transaction::commit()`: 7a's object publication
  followed by the ref queue, per the durability contract -- objects are
  durable before any ref points at them; ref writes are individually
  atomic and not atomic as a set; `fsync=false` and `per-object-fsync`
  behave as in 7a. The Phase 6 concurrency promise completes: concurrent
  transactions publish their staged sets and refs independently.

Deliverables: `Transaction::write_commit`, `CommitOptions`,
`ostree.sizes` emission, detached-metadata read and write on `Repo`,
`Transaction::{set_ref, set_collection_ref}`, `Repo::set_ref_immediate`,
the completed commit sequence, final `TransactionStats`.

Verify: for each fixture mode, replaying the fixture input through 7a-7d
end to end produces a commit object byte-identical to the tool's, the
MANIFEST commit checksum, and a ref file the tool resolves;
`ostree fsck`, `ostree show`, `ostree ls -R`, and `ostree checkout`
accept a repository the port created and populated; the archive
size-generation fixture matches GENERATE_SIZES output byte-for-byte
while bare and bare-user commits are byte-identical with and without the
request; `SOURCE_DATE_EPOCH` pins the timestamp; two transactions in one
process commit concurrently with both commits and refs intact; detached
metadata written by the port is read back by the tool and the reverse;
the suite passes under both runtime backends.

### Phase 7e -- Overlay changeset import (port extension) (DONE)

`Transaction::merge_overlay_dfd_to_mtree`: merging an overlayfs
upperdir changeset into a `MutableTree` holding the tree the overlay
was mounted over. A port extension with no tool counterpart and no
on-disk format impact -- deletions apply to the mtree during the walk
and never serialize. It is a separate walk rather than sugar over 7c
plus a tree merge because a `MutableTree` has no tombstone
representation; it reuses the 7c walk machinery and the 7a writers.

Definition:

- Signature per `api-sketch.md`: `dfd` is the upperdir root; the
  overlay is expected to be unmounted, unchecked.
- Whiteouts: a char 0:0 device removes the corresponding mtree path.
  Other upper entries ingest through the 7c machinery and replace or
  extend the mtree.
- Opaque directories: `trusted.overlay.opaque` or
  `user.overlay.opaque` clears the mtree subtree before ingesting.
  Both namespaces are honored: rootless `userxattr` overlays write
  `user.*`, and `trusted.*` is invisible to an unprivileged reader.
- Merged (non-opaque) directories take dirmeta from the upper inode;
  overlayfs copies directories up with their metadata, so an upper
  entry is authoritative.
- `overlay.*` xattrs are stripped from ingested entries.
- Entries carrying `overlay.metacopy` or `overlay.redirect` are a hard
  error naming the feature: such an entry is not self-contained, and
  the overlay must be mounted with these features off.
- A cross-type replacement drops the base entry and applies the upper
  one: an upper file or symlink over a base directory removes the
  directory, and an upper directory over a base file or symlink removes
  the leaf and creates a fresh directory. A non-directory upper entry
  shadows a lower entry of any type, so overlayfs records a
  directory-to-symlink migration as a plain non-opaque leaf, without a
  whiteout or opaque marker.
- Whiteouts and opaque markers are merge mechanics, not content: the
  modifier callbacks never see them, and a filter `Skip` on an upper
  entry leaves the base version in place.
- Fixtures are synthesized unprivileged: whiteout devices through
  `rustix::fs::mknodat` (char 0:0 creation requires no capability) and
  opacity through `user.overlay.opaque`. No new crates, no manifest
  changes.

Deliverables: `Transaction::merge_overlay_dfd_to_mtree`, the
unsupported-feature error variant, upperdir fixture builders in the
test suite.

Verify: merging a synthesized changeset over a base mtree yields the
same root checksum as applying the same changeset to a scratch checkout
by hand (copy, delete, opaque-replace) and ingesting the result through
`write_dfd_to_mtree`; whiteouts remove exactly the whited-out paths; an
opaque directory drops base-only entries beneath it; `overlay.*`
xattrs appear in no staged object; metacopy and redirect inputs fail
with their dedicated errors; an upper directory over a base symlink and
upper leaves over base directories apply as cross-type replacements;
the modifier filter skips upper entries without disturbing base ones.

### Phase 7f -- Staging tree and tree merge (port extension) (DONE)

Path-addressed tree construction over a transaction: `StagingTree`, its
file and directory operations, tree merge with symlink resolution, and
reading back through the transaction's staged objects. A port extension
with no tool counterpart and no format impact; everything it stages
flows through the 7a writers and 7b trees.

Definition:

- `StagingTree<'txn>` per `api-sketch.md`: borrows the transaction, so
  close, `write_mtree`, commit is the only ordering that compiles; the
  tree sits behind a sync mutex held only across map operations,
  `&StagingTree` is `Send + Sync`, and file writes may run
  concurrently. `close` returns the `MutableTree` and fails while
  `write_file` writers are outstanding (a counter).
- Constructors on `Transaction`: `staging_tree` (empty, or hydrated
  from a `Commit`'s root checksums) and `staging_tree_from_mutable_tree`.
  `staging_tree` is `async`, since hydrating from a commit reads its
  root dirtree, departing from the synchronous sketch the same way
  `MutableTree::ensure_dir` does.
- Path operations: `write_file` (returns `StagedFileWriter`, whose
  `finish` completes the content object and records the entry),
  `write_file_content`, `make_dir`, `make_dir_all`, `symlink`
  (`FileMeta`; the mode is fixed by the object model), `hardlink` (a
  second entry for the content object at the target path; no metadata
  taken). Intermediate path components resolve through symlinks; the
  final component never follows: `write_file` and `write_file_content`
  replace an existing file or symlink and fail on a directory;
  `make_dir`, `symlink`, and `hardlink` fail on any existing entry;
  `make_dir_all` applies its `DirMeta` to directories it creates and
  leaves existing ones untouched.
- Staged-first reads: `StagingTree::read_file` and `read_dir` resolve
  paths against the staged tree and load objects through the
  transaction's staged-first object lookup, which reads the
  transaction's staged set before `objects/`. `read_dir` returns
  `StagingEntry`; a dirty directory has no checksum, so `TreeEntry`
  cannot represent it.
- Symlink resolution (`follow_symlinks` on the read operations and in
  `MergeOptions`) walks the staged tree component-wise: relative
  targets resolve from the symlink's parent, absolute targets from the
  tree root, `..` clamps at the root, chains are capped at depth 40,
  and a dangling target is an error naming the symlink and the missing
  target.
- `StagingTree::merge(other, MergeOptions)`: equal checksums merge
  silently; differing files, file-versus-directory conflicts, and
  dirmeta on shared directories are errors without `allow_overwrite`
  and taken from the right side with it. With `follow_symlinks`, a
  right-side directory over a left-side symlink merges into the
  symlink's target directory; right-side files and symlinks replace
  the left entry and never write through. Merge lives here and not on
  `MutableTree` because resolution loads symlink content objects, and
  only transaction scope sees objects staged in the current
  transaction.

Deliverables: `StagingTree`, `StagedFileWriter`, `StagingEntry`,
`MergeOptions`, the constructors on `Transaction`, the staged-first
object lookup, the merge and resolution error variants.

Verify: a tree built through staging-tree operations alone produces the
same root checksum as ingesting the equivalent scratch directory
through `write_dfd_to_mtree`; hardlinked paths share one content
object; `read_file` and `read_dir` see staged-and-unpublished content
and follow symlink chains, failing on loops and dangling targets; a
package-layer tree merged over a base holding `/opt -> usr/opt` lands
files under `usr/opt` with `follow_symlinks`; a file merged over
`etc/localtime -> /usr/share/zoneinfo/UTC` replaces the symlink and
leaves the target object untouched; a left-tree symlink staged in the
same transaction resolves during merge through the staged-first lookup;
conflicts without `allow_overwrite` fail naming the path; concurrent
`write_file` streams through one `&StagingTree` land correctly;
compile-time assertions pin the new types `Send + Sync`; the suite
passes under both runtime backends.

### Phase 8 -- Checkout path (DONE)

`checkout_at` for all modes; overwrite modes (none/union-files/add-files/
union-identical); hardlink vs copy decision and fallbacks, with the copy
path attempting a FICLONE reflink before falling back to a byte copy;
devino cache; whiteout handling; per-file/dir metadata finalize and
optional fsync.
Verify: checkout of a tool-created commit matches the tool's checkout (mode,
perms, xattrs, hardlink counts); round-trip commit -> checkout is stable; on
a reflink-capable filesystem the copy path clones instead of copying bytes.

### Phase 9 -- composefs / EROFS export

Highest risk, scheduled directly after the checkout path so the riskiest
format work is confronted early and the Phase 11 CLI can emit composefs
images. Always compiled, not feature-gated. Reproduce the EROFS output
byte-for-byte: EROFS superblock/inodes/dirents/xattrs, composefs redirect
and verity xattrs, the fs-verity Merkle digest (SHA-256, 4096 block, 0
salt). Store `ostree.composefs.digest.v0` in commit metadata.
Verify: the fs-verity digest matches what the tool (with composefs) produces
for the same commit; the generated `.ostree.cfs` mounts and verifies.

### Phase 10 -- Tar import/export

Built on `smol-tar` (always compiled, not feature-gated). GNU tar with SCHILY
xattr PAX records, numeric ids, commit-timestamp mtimes, content-checksum
hardlink dedup, `/etc` -> `/usr/etc` convention on import, deferred hardlink
resolution. Early task: confirm `smol-tar` can emit and parse the exact
GNU/SCHILY conventions the tool uses; extend or drive headers manually where it
cannot.
Verify: `test-export`, `test-libarchive`; extract our tar with GNU tar and
re-import into the `ostree` tool.

### Phase 11 -- Minimal CLI (`ostrya`)

The first binary: the `ostrya-cli` crate builds a tool named `ostrya`, a
thin front-end over the ingest, checkout, and export paths, which are all in
place by this phase. Its command surface is its own; `ostree`-compatible
behavior is Phase 17. Initial subcommands:

- `ostrya commit [--repo <repo>] [--parent <commit>] [-b|--branch <branch>]
  [-s|--subject <subject>] [path]` -- commit the tree at `path` and print
  the new commit checksum; `--branch` points the ref at the new commit;
  with no path, read a tar stream from stdin (Phase 10 import).
- `ostrya checkout [--repo <repo>] [-H|--require-hardlinks]
  [-C|--force-copy] [--composefs] <commit> <destination>` -- Phase 8
  checkout; `--composefs` writes the Phase 9 EROFS image to `destination`
  instead of a tree.
- `ostrya export [--repo <repo>] <commit>` -- write the commit to stdout as
  a tar stream (Phase 10 export).

Further subcommands arrive with the phases that provide their machinery.
Argument and option parsing uses `clap`, scoped to the `ostrya-cli` crate;
anything further is settled at phase start per the dependency rule.

Verify: committing a fixture tree through the binary yields the fixture
commit id, a repository the tool accepts, and, with `--branch`, a ref the
tool resolves to the new commit; a tar stream on stdin commits
the same tree as its unpacked form ingested from disk; checkout through the
binary matches the tool's checkout of the same commit, and `--composefs`
emits the Phase 9 image; exported tar re-imported through `commit`
reproduces the root tree.

### Phase 12 -- Prune, fsck, traverse, diff

Reachability traversal, prune (refs-only, depth, delete-commit), fsck (object
integrity, partial-commit detection), diff.
Verify: the published `test-prune`, `test-fsck-*`, and `test-corruption`
subsets via the CLI harness.

### Phase 13 -- Signing

`Signer`/`Verifier` traits; ed25519 engine (ed25519-dalek); dummy engine; spki
engine (pure-Rust X.509/ECDSA, optional); detached-metadata append; commit
sign and verify. GPG via sequoia-openpgp (RustCrypto backend): keyring loading
(binary and armored), detached verify, per-signature metadata.
Verify: signatures produced verify under the `ostree` tool and the reverse;
`test-signed-commit-{ed25519,spki,dummy}`; `test-gpg-signed-commit` and
`test-commit-sign` once GPG verify lands.

### Phase 14 -- Summary generation and signing

Summary assembly (sorted refs, the host-order size asymmetry, big-endian
timestamps), summary signing and verification, summary cache.
Verify: byte-identical summary versus the tool for the same repo; the tool
verifies our signed summary.

### Phase 15 -- Static deltas

GVariant superblock/part/fallback formats, LEB128 op stream, the endianness
byte handling, rollsum (bupsplit) and bsdiff (pure Rust), xz encode/decode,
delta generation and offline application, indexes, signed deltas.
Verify: apply tool-generated deltas and get correct objects; the tool applies
our deltas; `test-delta`, `test-delta-ed25519`, `test-delta-sign`.

### Phase 16 -- Pull

Split into sub-phases:
- 16a Async fetcher: pure-Rust HTTP/1.1 and HTTP/2 over the `ostrya-rt` net
  layer + rustls, with ALPN selecting the version. HTTP/2 support is
  required, so the fetcher builds on a pure-Rust HTTP crate proposed at
  phase start rather than a hand-rolled client. Conditional GET
  (ETag/If-Modified-Since/304), mirrorlist fallback, retry classification,
  max-size streaming cap, priorities, client certs, basic auth. No range.
  Ships `VerifyingReader`, the stream that checks an expected digest at EOF
  and fails the final read with `InvalidData` on a mismatch (the check
  fires only when the consumer polls through to EOF).
- 16b Local pull (`file://`): object import (hardlink/reflink/copy),
  localcache repos.
- 16c HTTP pull: the scan/fetch state machine (bounded fetch semaphore of 8,
  delta-part cap of 2, write throttle of 3, fixed priority drain order),
  summary/sig verification, commit and content verification, bindings and
  timestamp checks, commitpartial, mirror mode.
- 16d Delta-accelerated pull and the config and mount repo finders.
Verify: pull from a local trivial httpd over both HTTP/1.1 and HTTP/2; the
`test-pull-*`, `test-local-pull*`, `test-signed-pull*` clusters via the
harness.

### Phase 17 -- `ostree`-compatible CLI (`ostrya-cli`)

Incremental, driven by which shell tests are targeted; extends the Phase 11
`ostrya` binary. Command-line and stdout/stderr compatibility with the
`ostree` tool for the exercised subcommands (commit, checkout, refs,
rev-parse, ls, cat, show, log, config, prune, fsck, summary, sign, gpg-sign,
static-delta, pull, pull-local, remote, init, export, diff). Provide a
compatible shell-test harness and a TAP producer.
Verify: growing subsets of the shell suite pass unmodified.

### Phase 18 -- S3 push/pull extension

Feature-gated (`s3`). Push publishes a repository -- objects, refs, summary
-- to an S3 bucket; pull fetches directly from one. Push is a port extension
(the tool has no push); a pushed bucket is a plain static repository, so the
tool can pull from it over the bucket's HTTP endpoint. The S3-specific work
is SigV4 request signing, bucket/prefix addressing, and multipart upload for
large objects, over the Phase 16a fetcher; credentials come from the
standard AWS environment and profile chain. The dependency set (a pure-Rust
SigV4 signer versus hand-rolled signing) is settled at phase start.
Verify: push a fixture repository to an S3-compatible test server and pull
it back intact; the tool pulls the pushed bucket over plain HTTP.

### Phase 19 -- SSH push/pull extension

Feature-gated (`ssh`). Git-style transport: the client spawns the system
`ssh` as a subprocess (a child process, not a linked library, so the no-C
constraint holds) and runs `ostrya` on the remote side; the two ends speak
a pack protocol over stdin/stdout. Push uploads missing objects and updates
refs inside a normal transaction on the remote repository; pull is the
reverse. The remote end is the Phase 11 binary grown a serve subcommand.
Protocol framing and the object-negotiation design are specified at phase
start.
Verify: push and pull between two port repositories over ssh to localhost;
the receiving repository passes `ostree fsck` and resolves the pushed refs.

### Phase 20 -- Sysroot / deployment (optional, separate track)

Out of the core library scope. If pursued: sysroot layout, deployments, boot
config parsing, bootloader integration, `admin` subcommands. This is the
heaviest cluster (root, mount namespaces, bootloaders) and unlocks the ~25%
admin tests. Recommend deferring or descoping unless explicitly required.

## Risk register

- composefs/EROFS byte-exactness (Phase 9): the EROFS and composefs on-disk
  formats are defined by the composefs and EROFS projects, not by ostree's
  public docs; reproduction is substantial, and the phase sits early in the
  roadmap on the critical path to the Phase 11 CLI. Mitigation: consider an
  existing pure-Rust composefs crate if its output matches.
- GVariant byte-exactness (Phase 1): everything downstream depends on it.
  Mitigation: extensive golden fixtures before building on it.
- xz encoding in pure Rust (Phase 15): decode is well-supported; encode is
  weaker. Mitigation: delta parts need only valid xz that round-trips (the part
  checksum is over our own compressed bytes), not byte-identity with liblzma.
- HTTP client (Phase 16a): HTTP/2 support is required, which puts a
  pure-Rust HTTP/2 implementation on the dependency surface; candidate
  crates couple to tokio-flavored I/O traits that need adapting to
  `ostrya-rt`. Mitigation: ALPN via rustls, the `tokio_util::compat`-style
  adapter pattern already in use, and a crate proposal at phase start.
- sequoia RustCrypto backend maturity for the exact GPG verify semantics
  ostree needs (revocation, expiry, primary-fingerprint mapping).
- "Pass the test suite" scope: the shell tier requires a compatible CLI; the
  admin tier requires the sysroot track. Scope must be agreed (see decisions).

## Decisions

Resolved:

1. Dependency policy: pure Rust only, no C libraries and no C-linking `*-sys`
   crates. The pure-Rust crate ecosystem is in scope (rustix, smol, sha2,
   ed25519-dalek, sequoia-openpgp with the RustCrypto backend, rustls,
   miniz_oxide, lzma-rs, and so on).
2. GVariant: hand-roll a minimal codec (`ostrya-gvariant`) tailored to
   ostree's fixed type set, fuzzed against golden bytes from the tool.
3. Test-suite scope: phased. Target the library-format-testable subset plus
   format-primitive unit tests first; add CLI-driven shell tests through
   Phase 17; treat the admin/sysroot tier (Phase 20) as a separate, optional
   track.
4. Workspace: multi-crate (`ostrya-gvariant`, `ostrya-core`, `ostrya`,
   `ostrya-cli`), with heavier subsystems behind feature flags on `ostrya`.
5. Development mode `bare-user-shared` (Phase 6a; supersedes the
   `bare-user-split-attrs` object split, removed before its write path was
   built): `bare-user` storage with the logical mode never applied to the
   inode -- fixed 0644 objects and a group-writable lock, with directory group
   sharing arranged at the filesystem level (an operator-set setgid parent and
   default group ACL) -- so a group-shared repository on a multi-user build
   host has no lockout on restrictively-permissioned files. Object identity
   is preserved for development-to-production portability, `ostree.sizes`
   never appears (size generation is archive-only in the tool, a no-op
   elsewhere), and the mode serves as the intended composefs backing store.
   `bare-split-xattrs` support is read-only, matching the tool, specified
   from the public documentation plus black-box observation. See the
   dedicated section above.
6. Typed codec (Phase 1a): object (de)serialization goes through hand-written
   codec impls over in-place reader and writer primitives -- decode reads
   fields directly from the serialized bytes with borrowed views on hot
   paths, encode writes normal-form bytes directly. The `Value` tree serves
   dynamic `a{sv}` content and tests. A proc-macro derive was considered and
   set aside: the object type set is small and fixed, and a derive would add
   a proc-macro crate plus `syn`, `quote`, and `proc-macro2`. Revisiting it
   requires a dependency proposal per the confirmation rule.

7. Runtime backend and streams (Phase 5a): the async runtime sits behind
   the internal `ostrya-rt` crate -- `smol` by default (`smol::unblock`,
   `smol::fs::File`), `tokio` behind a feature, tokio taking precedence
   when both features are enabled, and a compile error when neither is.
   `rustix` is scoped to fd-relative and Linux-specific syscalls offloaded
   through `rt::unblock`, the sole blocking-pool entry; streaming file I/O
   goes through `rt::File`. Concrete public stream types (`ContentReader`,
   `ContentWriter`, the hashing streams) implement the `futures-io` traits
   unconditionally and the tokio traits under the `tokio` feature;
   `AsyncRead`/`AsyncWrite` bounds in argument position are the
   `futures-io` traits (tokio callers adapt with `tokio_util::compat`).
   The hashing streams are concrete types with inherent methods; a trait
   abstraction over them waits for a second consumer. Archive DEFLATE
   streams through `async-compression` (deflate feature only) over
   `flate2`/`miniz_oxide`.

8. Repository lock and transactions (Phase 6): the lock on `<repo>/.lock` is a
   classic `fcntl` record lock (`F_SETLK`, via `rustix::fs::fcntl_lock`), chosen
   over an OFD `fcntl` lock because `rustix` does not expose the OFD commands and
   a raw OFD call would need the C `libc` crate and `unsafe`, both excluded by
   constraint 1. A record lock shares a lock space with the tool's OFD locks, so
   the library and the tool exclude each other on the same repository (verified
   by holding each side's lock while the other acquires). Record locks are
   process-associated, so a process-global registry keyed by the lock file's
   `(device, inode)` keeps one descriptor and one reference count per repository
   per process; the reference count also serves same-repo reentrancy and
   shared-to-exclusive upgrade and downgrade. Acquisition is a non-blocking
   attempt plus an `rt::Timer` retry loop bounded by `lock-timeout-secs`. No new
   external crates: `rt::Timer` wraps the existing backends (`smol::Timer`,
   `tokio::time`) and the in-process coordination uses `std::sync::Mutex`.

9. Repo finders: the config and mount finders land with pull (Phase 16d);
   avahi discovery is out of scope.
10. HTTP/2: required for pull. The fetcher is built on a pure-Rust HTTP
    crate speaking HTTP/1.1 and HTTP/2 with ALPN over rustls; the concrete
    crate is proposed at Phase 16a per the dependency rule.

Deferred to their respective phases:

11. composefs (Phase 9): reproduce the composefs/EROFS format ourselves
    versus depend on an emerging pure-Rust composefs crate.
12. spki sign engine: deferred as optional; ed25519 and gpg cover the
    common cases.
