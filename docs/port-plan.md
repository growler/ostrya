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

1. Rust-native. `liblzma` is the one C library the library links: statically
   built from source for xz in static deltas, requiring no C runtime of its own
   beyond the libc `std` already links. PCRE2 joins it on the same terms in the
   `ostrya-cli` binary alone, where it compiles the `commit
   --tar-pathname-filter` expression the tool also compiles with PCRE2; that
   crate sets `publish = false`, so no published crate links it, and CI holds
   the rule that no other manifest may name `pcre2`. Nothing else links C.
   `rustix` handles the syscalls a portable async file API cannot express
   (fd-relative opens and metadata, xattrs, statx, FICLONE reflink, O_TMPFILE +
   linkat, OFD locks); streaming file I/O goes through the runtime's async file.
2. Async, with a feature-gated runtime backend behind the internal
   `ostrya-rt` crate: `smol` by default, `tokio` optional.
3. Multiple concurrent transactions within a single process.
4. Capable of an external conformance gate matching the scope of ostree's own
   test suite. The gate is authored from scratch, from black-box observation
   of the `ostree` tool; the upstream test suite is LGPL source and is never
   run or vendored.
5. Extensions: GPG commit signing through the system GnuPG binaries (no
   gpgme linkage), composefs/EROFS export, tar import/export, AWS S3
   push/pull, ssh git-style push/pull.

The port is a library. It is not a drop-in replacement for the `ostree` tool.
A minimal `ostrya` binary lands once the ingest and checkout paths are ready
(Phase 11); `ostree`-compatible command-line behavior is a late phase
(Phase 17), built specifically to carry the port's own CLI-driven conformance
suite, recorded in `conformance/` (see `conformance/README.md`).

Faithful means: byte-for-byte identical on-disk format, identical checksums,
identical algorithms. It does not mean mirroring the C API shape. The API is
redesigned to be idiomatic Rust (see `api-sketch.md`).

## Interpretation of "no dependencies except rust"

Read as: the Rust crate ecosystem is in scope and C libraries are avoided. The
library links `liblzma` statically for xz, and the `ostrya-cli` binary links
PCRE2 statically for the `commit --tar-pathname-filter` expression (see the
Decisions section); each requires no C runtime beyond the libc `std` already
links. PCRE2 belongs to that binary alone, which sets `publish = false`. Every
crate is authorized by the operator before it enters a manifest. The foundation
crates below are all pure Rust:

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
- `async-compression`, with its `deflate` and `xz` codec features plus the
  trait-family features -- streaming raw DEFLATE for archive-mode content
  objects (over `flate2` with the pure-Rust `miniz_oxide` backend) and
  streaming xz for static-delta parts (over statically-linked `liblzma`).
- `ed25519-dalek` -- the ed25519 sign engine.
- `bsdiff` (BSD-2-Clause, no dependencies of its own) -- bspatch stream
  generation for static deltas. Its output is the interleaved
  control/diff/extra layout the port's own bspatch reads.
- GPG signing and verification: no crate -- the engine runs the system
  `gpg`/`gpgv` binaries as subprocesses (see Decisions).
- `rustls` plus `webpki-roots` / `rustls-native-certs` -- TLS for pull.
- `smol-tar` -- async tar import/export in the smol ecosystem.
- `clap` -- command-line argument parsing for the `ostrya` binary
  (`ostrya-cli` only).
- `pcre2` (`ostrya-cli` only) -- compiles the `commit
  --tar-pathname-filter` expression, which the tool compiles with PCRE2. The
  crate vendors the PCRE2 C library and builds it statically; `ostrya-cli` sets
  `publish = false`, so no published crate links it.
- HTTP client, INI parsing, fs-verity, and EROFS: see the Decisions section;
  each has a pure-Rust path. LZMA/xz links `liblzma` statically (see the
  Decisions section).

Anything else that would pull in C (openssl-sys, libgpg-error/gpgme, libcurl,
libsoup, libarchive, libcomposefs, glib) is excluded by constraint 1;
statically-linked `liblzma` and statically-linked PCRE2 are the two authorized
exceptions, and PCRE2 is authorized in the `ostrya-cli` binary alone.

## Architecture

### Workspace layout

A Cargo workspace of focused crates keeps review units small and compile times
bounded:

- `ostrya-gvariant` -- the byte-exact GVariant codec. No ostree knowledge.
- `ostrya-core` -- object model, checksums, varint, loose paths, xattr
  canonicalization, format (de)serialization. Depends on `ostrya-gvariant`.
- `ostrya-rt` -- internal runtime abstraction: `rt::unblock`, `rt::File`
  (over an already-open fd; `smol::fs::File` or `tokio::fs::File`),
  `rt::Timer`, `rt::Command` (a short-lived helper process with piped
  standard streams), later `rt::spawn` and networking. The only crate that
  knows which backend is compiled. No ostree knowledge.
- `ostrya-composefs` -- the byte-exact EROFS/composefs image writer and the
  fs-verity digest. Standalone and free of ostree and repository knowledge,
  like `ostrya-gvariant`: it takes a tree model and emits the image bytes and
  the image's fs-verity digest. Reproduces only the metadata subset composefs
  uses, with no EROFS compression. Synchronous, with no runtime dependency.
- `ostrya` -- the library: repo, transactions, commit, checkout, refs, read,
  prune, fsck, sign, summary, deltas, pull, tar, composefs export over
  `ostrya-composefs`. Feature-gated.
- `ostrya-cli` -- the CLI crate, building the `ostrya` binary: a minimal
  command set once the ingest and checkout paths land (Phase 11), grown
  incrementally; the `ostree`-compatible surface arrives with the port's own
  CLI-behavior conformance suite (Phase 17).
- `ostrya-conformance` -- the runner for the interoperability matrix in
  `conformance/`, building the `ostrya-conformance` binary. It links neither
  the library nor the CLI: it drives both the `ostrya` and the `ostree`
  binaries as subprocesses, so it observes the surface a user observes. Its
  design is `conformance/harness.md`.

Feature flags on `ostrya`: `pull`, `sign-spki`, `sign-gpg`, `deltas`, `s3`,
`ssh`, plus the runtime backend selectors `smol` (default) and `tokio`,
forwarded to `ostrya-rt`. Each
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
fdatasync + rename + fsync of the directory holding the ref) but not atomic as a
set. Honor `fsync=false` (all fsync becomes no-op) and `per-object-fsync`.

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
- A growing `ostree`-compatible CLI carries the port's own from-scratch
  CLI-behavior conformance suite (`conformance/`), targeted phase by phase
  (commit/checkout, then refs/prune/fsck, then signing, then deltas, then
  pull). The suite is authored from black-box observation of the `ostree`
  tool; the upstream shell tests are LGPL source and are never run or
  vendored.
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
`rt::Timer` lands with Phase 6, `rt::spawn`, `rt::Deadline`, and networking with
Phase 16a.
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
payload. The verifying counterpart (`VerifyingReader`) landed with the
fetcher (Phase 16a).

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
  bare-user-only applies the canonical mode `perm & 0o755` and discards
  uid/gid and xattrs, and records that canonical header in the object's
  identity, dirmeta included, since it stores no header of its own;
  archive writes `.filez` chmod 0644.
- `write_content` (pull-style, drives a `ContentWriter` from an
  `AsyncRead`), `write_regfile_inline` (small caller-held content),
  `write_symlink` (framed header only, no payload).
- `write_metadata`: whole-buffer (the format caps metadata size),
  checksum over the normal-form bytes, `expected` verification, staged
  uncompressed under the loose name.
- Free-space guard: at transaction start `fstatvfs` plus
  `min-free-space-percent` / `min-free-space-size` set a byte budget;
  each staged object debits it by the blocks it allocates; exhaustion
  fails the write with a dedicated error carrying the shortfall. Every
  object an ingest writes allocates its stored size. An object imported
  from another repository allocates nothing when it shares the source
  inode by hardlink and nothing when its payload came from a `FICLONE`
  reflink, so those debit the budget by zero (Phase 16b); the statistics
  keep counting their stored size, which is the storage the objects
  occupy rather than the space the transaction consumed.
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
artificially small budget; a bare-user-only write of an entry carrying
ownership, an xattr, and a mode the mode reduces lands under the identity
its canonical header has in the other modes, reads back as that header,
and passes `fsck`; a compile-time assertion pins
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
- CANONICAL_PERMISSIONS zeroes uid/gid, canonicalizes the mode, and
  empties the xattr set; the exact rule is recovered by observation
  (committing crafted trees with and without the tool's corresponding
  option and diffing object ids) and recorded in
  `format-reference.md` before the flag lands. The xattr set is emptied
  ahead of the callbacks, so an xattr or label callback still lands its
  own set.
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
with its corresponding option, over a tree of assorted modes and over one
carrying `user.*` xattrs on a file and a directory, where the port's root
dirtree and dirmeta equal the tool's and the xattr-bearing tree takes the
identity of the same tree without xattrs; a devino hit skips rehashing
(stats, and no duplicate staging); CONSUME leaves the consumed source empty; the
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
  rename + fsync of the directory holding the ref, parent directories
  created for `/`-bearing names; a `None` checksum removes the ref file
  and syncs that directory too.
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
metadata written by the port is read back by the tool and the reverse; a
bare-user-only commit of a source tree whose ownership, modes, and xattrs are all
outside what the mode stores produces the tool's own content, dirmeta, and
dirtree object names for that tree and passes the tool's `fsck`;
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
images. Always compiled, not feature-gated. Split into sub-phases:

- 9a (DONE) Investigate the tool as a black box: what `ostree` (built with
  composefs) writes when it exports a commit, and how the exported EROFS
  image is arranged. Dump the produced images with `composefs-info` and
  inspect the raw EROFS structures, capturing golden fixtures for the
  superblock, inode table, dirents, xattrs, the composefs redirect and
  verity xattrs, and the fs-verity Merkle digest (SHA-256, 4096-byte
  block, 0 salt). The EROFS and composefs formats are defined by those
  projects, not by ostree's docs, so the observed layout becomes the
  fixture contract for 9c.
  Delivered: the verity image and its `composefs-info dump` at
  `tests/fixtures/generated/composefs/tree.cfs` and `tree.dump`, produced
  by `generate.sh` from a `--generate-composefs-metadata` commit, with the
  MANIFEST recording `composefs_commit` and `composefs_digest` (the image's
  fs-verity digest, equal to the commit's stored `ostree.composefs.digest.v0`).
  The observed export path, superblock, injected top-level directories,
  redirect and metacopy xattrs, and digest relationship are recorded in
  `format-reference.md`, "composefs".
- 9b (DONE) Survey pure-Rust EROFS/composefs implementations and decide
  build versus depend. Evaluated against the 9a fixtures and the
  no-C-linkage rule:
  - `erofs-rs`, both the official `erofs/erofs-rs` and the crates.io
    `Dreamacro/erofs-rs`, are read-only EROFS parsers. Neither emits images
    (the official `mkfs` workspace member is a stub, and the crates.io crate
    lists image building as an unimplemented TODO), and neither knows
    composefs. Unusable for the write path.
  - `containers/composefs-rs` (crate `composefs`, MIT OR Apache-2.0) writes
    the format: `erofs::writer::mkfs_erofs` produces byte-for-byte identical
    output to C `mkcomposefs` for the default format version, verified in its
    own test suite against the C binary, and it computes the fs-verity digest
    in pure Rust. Its writer, fs-verity, and dumpfile modules are
    self-contained pure Rust. It cannot be a dependency as published: the
    `composefs` crate carries a non-optional `zstd` (which links C through
    `zstd-sys`) and a full `tokio`, with no feature to disable either, so
    adding it violates the no-C-linkage rule and the smol-default runtime
    policy.
  - `am-fs-erofs` (MIT) is a pure-Rust generic EROFS writer with no composefs
    awareness (no overlay redirect/metacopy/opaque xattrs, no fs-verity) and
    byte choices that do not match composefs. `lamfold-erofs`,
    `gobblytes-erofs*`, `liberofs`/`erofs`, and `nydus-rs` are read-only,
    stubs, or unrelated container-image stacks.
  - The fs-verity digest is a self-contained SHA-256 Merkle computation over
    the image bytes (4096-byte blocks, zero salt, 256-byte descriptor) needing
    no kernel call. The `fs-verity` crate pulls an unconditional `libc`, so the
    digest is hand-rolled over the existing `sha2` dependency.

  Decision: reproduce the composefs EROFS format in-tree in a new standalone
  crate `ostrya-composefs` (the EROFS/composefs counterpart to
  `ostrya-gvariant`), reproducing only the metadata subset composefs uses,
  with no EROFS compression. No pure-Rust crate writes byte-exact composefs
  images under the no-C rule. Phase 9c builds the crate and Phase 9d wires it
  into `ostrya`, adding no new crates. `composefs-rs`, permissively licensed
  and safe to read, serves as a clean-room reference and a second cross-check
  oracle alongside the `ostree`/`mkcomposefs` black box.
- 9c (DONE) The `ostrya-composefs` crate: the pure-Rust EROFS/composefs image
  writer and the fs-verity digest, standalone and free of ostree and repository
  knowledge (the composefs counterpart to `ostrya-gvariant`). It takes a tree
  model -- directories, symlinks, and regular-file entries carrying logical
  metadata, xattrs, a backing loose path, and a backing fs-verity digest --
  and emits the EROFS image bytes plus the image's fs-verity digest. The
  writer reproduces only the metadata subset composefs uses: the superblock,
  compact and extended inodes, tail-packed directory blocks, inline symlink
  targets, chunk-based backing-file inodes with placeholder chunk indices, the
  256-entry overlay whiteout table injected into the root, and the
  trusted-namespace overlay xattrs (`overlay.redirect`, `overlay.metacopy`,
  `overlay.opaque`) with the shared-xattr area and the XATTR_FILTER field. It
  needs no EROFS compression, fragments, or multi-device support. The fs-verity
  digest is a streaming SHA-256 Merkle primitive (4096-byte blocks, zero salt,
  256-byte descriptor), reused for both the whole image and each backing
  object. Byte assembly is hand-rolled; the digest is computed over `sha2`. The
  crate is synchronous and builds the image in a single in-memory buffer, as
  the tool does, so it takes no runtime dependency. The field-level layout is
  recorded in `format-reference.md` as it is verified against the golden bytes.
  Dependency set: `sha2` (an approved foundation crate, already used) for the
  fs-verity digest. The XATTR_FILTER field hashes each xattr-name suffix with
  xxHash32, seeded by `0x25BBE08F` plus the prefix index; xxHash32 is
  hand-rolled (`src/xxhash.rs`), verified against the golden filter bytes, so
  no new crate is added.
  Verify: a tree model reconstructed from the 9a `tree.dump` produces an image
  byte-identical to `tree.cfs`, and its fs-verity digest equals the MANIFEST
  `composefs_digest`; the `composefs-rs` writer run over the same input agrees
  byte-for-byte as a second oracle; compile-time assertions pin the public
  writer types `Send + Sync`. A richer fixture, `tree-rich.cfs` with
  `composefs_rich_digest`, is reconstructed from `tree-rich.dump` (whose dump
  lines carry xattrs) and locks in shared-xattr promotion, inline xattrs, a
  multi-block directory with an inline dirent tail, and a long inline symlink
  near the block boundary.
- 9d (DONE) Wire `ostrya-composefs` into `ostrya`: build the writer's tree model from
  a commit's `RepoTree`, inject the five top-level directories (`boot`, `etc`,
  `sysroot`, `usr`, `var`), resolve each regular file to its `.file` loose path
  and stream the loose object through the fs-verity digester to fill the
  metacopy digest, drive the writer, and store the image's fs-verity digest in
  the commit's `ostree.composefs.digest.v0` metadata. Ownership is presented
  through composefs uid mapping at mount. Backing objects stream through
  `rt::unblock` so no unconstrained blob is buffered, and the in-memory image
  build is offloaded to the blocking pool.
  Verify: the fs-verity digest matches what the tool (built with composefs)
  produces for the same commit; the generated `.ostree.cfs` mounts and
  verifies; the digest the port stores in `ostree.composefs.digest.v0` equals
  the tool's for the same tree; the suite passes under both runtime backends.

### Phase 10 -- Tar import/export (DONE)

Built on `smol-tar` (always compiled, not feature-gated), driven through its
`futures-io` flavor so it works under both runtime backends and adds no runtime
coupling. `Repo::export_tar` writes a commit's tree as a filesystem tar
(numeric ids, commit-timestamp mtimes, `SCHILY.xattr.*` PAX records,
content-checksum hardlink coalescing, `./` root and bare relative member names).
`Repo::import_tar` reads a filesystem tar into a `MutableTree` with deferred
hardlink resolution, an optional `/etc` -> `/usr/etc` remap, and rejection of
device and FIFO members. `TarExportOptions` and `TarImportOptions` carry the
option surface. The recovered facts are recorded in `format-reference.md`,
"tar".

Scope decisions taken with the maintainer, recorded there:

- The correctness gate is interoperability and round-trip stability, not
  byte-identity with `ostree export`. The tool emits old-GNU-magic tar; the
  port emits POSIX ustar/pax through `smol-tar`, so the two dialects differ by
  design.
- The port emits `SCHILY.xattr.*` records for xattr-bearing entries so trees
  round-trip losslessly. The observed 2026.1 tool export emitted none; the
  divergence is recorded in `format-reference.md`.
- `smol-tar` was made additive-safe upstream (its `smol`/`tokio` features gained
  tokio precedence rather than a hard mutual-exclusion), matching `ostrya-rt`.

Verify (met): a checked-in `export.tar` fixture from the tool imports into the
fixture commit's exact root dirtree and dirmeta; a port export/import round trip
reproduces a tree including its `user.demo` xattr; identical files import to one
object and export as a hardlink; the `/etc` -> `/usr/etc` remap lands entries
under `usr/etc`; device and FIFO members are rejected; GNU tar reads a port
export and the `ostree` tool re-imports it into a byte-identical tree; the suite
passes under both runtime backends. The shell-suite gates (`test-export`,
`test-libarchive`) arrive with the Phase 17 CLI.

### Phase 11 -- Minimal CLI (`ostrya`) (DONE)

The first binary: the `ostrya-cli` crate builds a tool named `ostrya`, a
thin front-end over the ingest, checkout, and export paths, which are all in
place by this phase. The binary is synchronous and drives the async library
through `ostrya_rt::block_on`; the stdin/stdout tar streams flow through
`ostrya_rt::File` over a duplicated descriptor, so no unbounded stream is
buffered. Its command surface is its own; `ostree`-compatible behavior is
Phase 17. Subcommands:

- `ostrya commit [--repo <repo>] [--parent <commit>] [-b|--branch <branch>]
  [-s|--subject <subject>] [--canonical-permissions] [path]` -- commit the
  tree at `path` and print the new commit checksum; `--branch` points the ref
  at the new commit and binds it into the commit as `ostree.ref-binding`;
  `--canonical-permissions` forces owner 0:0, canonicalizes the mode to
  `perm & 0755`, and drops xattrs, for an owner- and host-independent commit;
  with no path, read a tar stream from stdin (Phase 10 import). The timestamp
  comes from `SOURCE_DATE_EPOCH` when set, else the current time.
- `ostrya checkout [--repo <repo>] [-H|--require-hardlinks]
  [-C|--force-copy] [--composefs] <commit> <destination>` -- Phase 8
  faithful checkout; `-C` forces copies, `-H` (its conflicting opposite)
  requests the hardlink-preferring default path; `--composefs` writes the
  Phase 9 EROFS image to `destination` instead of a tree.
- `ostrya export [--repo <repo>] <commit>` -- write the commit to stdout as
  a tar stream (Phase 10 export).

`<commit>` and `--parent` accept a checksum or a ref. The current `commit`
parenting surface, `--orphan` included, is recorded in `format-reference.md`,
"CLI output formats", under `commit`. Further subcommands arrive with the
phases that provide their machinery. Argument and option parsing uses `clap`
(derive), scoped to the `ostrya-cli` crate, which also depends on `ostrya-rt`
for the runtime driver and streaming descriptor; anything further is settled
at phase start per the dependency rule.

Verify: committing a fixture tree through the binary yields the fixture
commit id, a repository the tool accepts, and, with `--branch`, a ref the
tool resolves to the new commit; a tar stream on stdin commits
the same tree as its unpacked form ingested from disk; checkout through the
binary matches the tool's checkout of the same commit, and `--composefs`
emits the Phase 9 image; exported tar re-imported through `commit`
reproduces the root tree.

### Phase 12 -- Prune, fsck, traverse, diff (DONE)

Reachability traversal, prune (refs-only, depth, delete-commit), fsck (object
integrity, partial-commit detection), diff.

Delivered: `Repo::list_objects` (loose-object enumeration), `traverse_commit`
and `traverse_reachable` (the Merkle-DAG walk, following parents to a depth,
lenient on absent objects), `Repo::prune` (`PruneOptions`/`PruneStats`) with the
tool's observed depth semantics (`-1` keeps all history, `0` only the head), the
refs-only-versus-all-commits root choice, `no_prune` dry runs, `delete_commit`,
kept-commit `.commitmeta` retention and pruned-commit `.commitpartial` removal,
`Repo::fsck` (`FsckOptions`/`FsckReport`/`FsckError`) verifying metadata and
content-object checksums and completeness and marking missing-object commits
partial, `Repo::diff_commits` (`DiffEntry`/`DiffChange`) reproducing
`ostree diff`, the `ObjectName` core type, and the `ostrya` CLI subcommands
`prune`, `fsck`, and `diff`. Observed facts recorded in `format-reference.md`
(the `.commitpartial` fsck state byte).

Verify: done through Rust integration tests cross-checked against the `ostree`
tool (the CLI-behavior conformance suite is Phase 17). The port and the tool
prune identical copies of a multi-commit repository and agree on the
surviving object set, the deleted-object count, and the bytes freed; the
tool's `fsck` accepts a port-pruned repository; the port's `diff_commits`
matches `ostree diff` byte-for-byte on added/removed/modified/type-change/
dirmeta-change cases; fsck detects injected content corruption, metadata
corruption, and a deleted referenced object (marking the commit partial with
the tool's state byte); the suite passes under both runtime backends.
Equivalent prune/fsck/diff conformance cases land in
`conformance/m10-cli-behavior.matrix` once the Phase 17 CLI lands.

### Phase pre13 -- Repository fs-verity (ex-integrity) (DONE)

Enable fs-verity on loose objects as they are written, controlled by the
repository `[ex-integrity]` config section. It belongs to the write path that
later phases build on, and the composefs export (Phase 9) already computes the
same fs-verity digest in userspace, so the two share the digest parameters.

The `ostree` tool (2026.1, built with `ex-fsverity`) was observed as a black box
on a btrfs `target/test-repo`: a commit was straced, objects were probed on a
verity-capable and a non-capable filesystem, and the kernel's measured digest
was cross-checked against the port's `FsVerityHasher`. The recovered contract:

- Config: an `[ex-integrity]` group with keys `fsverity` and `composefs`, each a
  tri-state `yes`, `no`, or `maybe`. `fsverity` defaults to off. `composefs` set
  to `yes` or `maybe` raises the `fsverity` default to `maybe`. The `composefs`
  knob otherwise governs deployment and is out of scope here; it is read only to
  compute the `fsverity` default.
- Scope: verity is enabled on every loose object stored as a regular file --
  content objects (`.file` and `.filez`) and metadata objects (`.dirtree`,
  `.dirmeta`, `.commit`) -- in every repository mode, archive-z2 included. Real
  symlink objects (bare and bare-user-only) are the only objects skipped,
  because fs-verity applies to regular files; bare-user stores symlinks as
  regular files, so those objects are sealed.
- Semantics: `maybe` is best-effort and swallows every `FS_IOC_ENABLE_VERITY`
  error (a filesystem without verity returns `ENOTTY`); `yes` propagates the
  error and fails the write (the tool reports "fsverity required but filesystem
  does not support it").
- Digest parameters: SHA-256, 4096-byte blocks, zero salt. The kernel's
  `FS_IOC_MEASURE_VERITY` result for a bare-user `.file` object equals the
  port's `FsVerityHasher` output for the same payload, confirming the enable
  argument `{version 1, hash_algorithm 1, block_size 4096, salt_size 0}`.
- Write-path order, per object, while the inode is still an anonymous
  `O_TMPFILE`: open `O_TMPFILE|O_WRONLY`, write or reflink the payload, apply
  `fchmod`/`fchown`/xattrs, reopen the inode read-only through `/proc/self/fd/N`,
  close the writable descriptor, call `ioctl(ro_fd, FS_IOC_ENABLE_VERITY)`, then
  `linkat` the read-only descriptor into the staging directory. Publication
  (rename into `objects/`) is unchanged.

Plan:

- A new workspace crate `ostrya-sys` holds the audited `unsafe` site the project
  guide reserves for the few `rustix` calls that require it. It is
  `#![deny(unsafe_code)]` with a single scoped `#[allow(unsafe_code)]`, matching
  the allocation-counting harness, so `ostrya` keeps `#![forbid(unsafe_code)]`.
  It exposes `enable_verity(fd)`, issuing the ioctl through `rustix::ioctl`
  (`opcode::write::<FsverityEnableArg>(b'f', 133)` fed to a `Setter`) over a
  `#[repr(C)]` 128-byte `fsverity_enable_arg`. Its only dependency is `rustix`,
  already a foundation crate, so no new external dependency is added.
- `RepoConfig` gains a `Tristate` type and `fsverity()` and `composefs()`
  accessors applying the default rule above.
- The staging context carries the effective `Tristate`. The content, metadata,
  and regular-file symlink staging paths seal each fresh object in the recovered
  order; real-symlink paths skip it; dedup hits are untouched. With `fsverity`
  off, the staging path is unchanged.
- An `ETXTBSY` enable is retried for up to 50 ms, 1 ms apart. Closing the
  writable descriptor before the ioctl is necessary but not sufficient: `fork`
  copies the file descriptor table, so a child process holds a copy of the
  writable staging descriptor until its `exec` closes it, and the kernel refuses
  to seal an inode any writable descriptor still holds. A process that spawns a
  child from one thread while another stages objects hits that window, which the
  retry outlasts (reproduced by the pull suite, whose interop tests run the
  `ostree` binary while a sealing pull runs alongside them). Every other error is
  reported on the first attempt, so `maybe` on a filesystem without verity still
  returns at once.
- `format-reference.md` gains a "Write path: fs-verity (ex-integrity)" section
  recording the config, scope, ordering, and semantics.

Verify: on a verity-capable filesystem, a commit with `fsverity=yes` seals every
regular-file object and each object's kernel-measured digest equals the port's
`FsVerityHasher`; the tool reads a port-written verity repository and the port
reads the tool's; `maybe` on a filesystem without verity succeeds while `yes`
fails; the digest the kernel measures matches the value the composefs export
stores. Tests are gated on filesystem verity support so the suite passes
elsewhere. The suite passes under both runtime backends.

### Phase 13 -- Signing

Four sub-phases, each an independently reviewable unit with its own gate: 13a
is the signing framework and the dummy test engine, 13b the ed25519 engine and
the sign-api key store, 13c the spki (ECDSA/SPKI) engine, 13d GPG over the
system GnuPG binaries. Each sub-phase consumes only the public surface of the
ones before it. All four engines sign and verify commit objects through the shared
13a framework; summary signing (Phase 14) reuses the same engines on the
summary bytes.

The ed25519 and dummy engines are always compiled; spki is behind the
`sign-spki` feature and GPG behind `sign-gpg`. spki is a required engine, not
deferred: the reference tool gates it on OpenSSL, the port implements it in
pure Rust behind its own feature so the core stays free of the ECDSA/SPKI crate
tree (see Decisions).

The per-engine tool-conformance gate is cross-verification -- the `ostree`
tool verifies a signature the port wrote and the port verifies the tool's,
for that engine. Equivalent sign/verify conformance cases land in
`conformance/m10-cli-behavior.matrix` once the CLI `sign` subcommand lands
(Phase 17).

Format facts the signing path needs that `format-reference.md` does not yet
state -- the spki curve, hash, signature encoding, and secret-key encoding,
and the dummy engine's signature and verification bytes -- are recovered by
black-box observation in the sub-phase that reaches them and recorded in
`format-reference.md` in the same change.

### Phase 13a -- Signing framework and the dummy engine (DONE)

The `Signer`/`Verifier` surface, the detached-metadata signature append, and
`Repo` commit sign and verify, exercised end to end by the trivial dummy
engine with no crypto dependency. After 13a the framework is complete and the
crypto engines drop in behind it.

Definition:

- `Signer` and `Verifier` traits per `api-sketch.md`: `Signer` carries the
  engine name and its detached-metadata key and signs an opaque byte payload;
  `Verifier` verifies a set of signature blobs against a payload and yields a
  `VerifyOutcome`. Both take opaque bytes so the commit path here and the
  summary path in Phase 14 share one surface.
- The signed payload for a commit is the canonical serialized commit GVariant
  bytes -- the same normal-form bytes that hash to the commit checksum, per
  `format-reference.md`, "Signing details".
- Detached-metadata append: signatures accumulate as `ay` elements appended to
  the per-engine `aay` value in the `.commitmeta` `a{sv}` dict, over the
  Phase 7d `read_commit_detached_metadata` / `write_commit_detached_metadata`
  (load the dict, append to the engine's array creating it if absent, rewrite
  atomically). GPG and sign-api keys coexist in one dict.
- `Repo::sign_commit(checksum, signer)` and
  `Repo::verify_commit(checksum, verifiers)`: load the commit bytes, invoke the
  engine, and on the sign side append the signature to detached metadata under
  the guard that serializes the `.commitmeta` read-modify-write in this
  process; on the verify side collect each engine's signature array and run its
  verifier.
- `VerifyOutcome` and `SignatureInfo` per `api-sketch.md`.
- The dummy engine (`DummySigner` / `DummyVerifier`): the test engine whose
  secret and public keys are ASCII strings, whose signature and verification
  bytes are recovered by observation and recorded in `format-reference.md`. It
  validates the framework with no crypto crate.

Dependency set: no new crates. The dict manipulation uses `ostrya-gvariant`'s
`a{sv}` support and the Phase 7d detached-metadata I/O.

Deliverables: `Signer`, `Verifier`, `VerifyOutcome`, `SignatureInfo`, the
detached-metadata signature append and read helpers, `Repo::sign_commit`,
`Repo::verify_commit`, `DummySigner`, `DummyVerifier`.

Verify: a dummy signature the port appends is accepted by
`ostree sign --verify --sign-type=dummy`, and `verify_commit` accepts a dummy
signature the tool wrote; appending a second engine's signatures leaves the
first engine's array intact; verifying an unsigned commit yields a not-valid
outcome; `Send + Sync` compile-time assertions on the new public types; the
suite passes under both runtime backends.

### Phase 13b -- ed25519 engine and the sign-api key store (DONE)

The ed25519 engine and the shared sign-api key-file and key-directory loading,
which 13c reuses for spki.

Definition:

- `Ed25519Signer` / `Ed25519Verifier` over `ed25519-dalek`: 32-byte public
  key, 64-byte signature, 64-byte secret key (32-byte seed followed by the
  32-byte public key), per `format-reference.md`. ed25519 is deterministic, so
  the sign path needs no RNG.
- A general base64 codec in `ostrya-core`: the existing checksum base64 is
  fixed to 32-byte digests, while sign-api keys and signature blobs are
  arbitrary-length, so a general standard-alphabet encoder and decoder lands
  here and is reused by 13c for PEM.
- The sign-api key store: base64-one-key-per-line files, the `trusted.<type>`
  and `revoked.<type>` files and the `trusted.<type>.d` and `revoked.<type>.d`
  directories, and the system search path (`/etc/ostree`,
  `/usr/share/ostree`), parameterized by sign-type name so 13c reuses it for
  spki. A verifier is built from a trusted set minus a revoked set.
- Key input: secret keys for signing and public keys for verifying, accepted
  as base64 strings or raw `ay`.

Dependency set: `ed25519-dalek` (a foundation crate; exact pin confirmed at
phase start), pure Rust over `curve25519-dalek`, `ed25519`, and `signature`,
with the existing `sha2`; the general base64 is hand-rolled in `ostrya-core`,
no crate. Always compiled, not feature-gated.

Deliverables: `Ed25519Signer`, `Ed25519Verifier`, the general base64 codec, the
sign-api key store loader.

Verify: a commit the port signs with ed25519 verifies under
`ostree sign --verify --sign-type=ed25519`, and the port verifies an ed25519
signature the tool wrote for the same key; the trusted and revoked directory
convention resolves keys as the tool does, and a revoked key fails;
`test-signed-commit-ed25519` targeted through the harness when the CLI lands;
the suite passes under both runtime backends.

### Phase 13c -- spki engine (ECDSA / SPKI) (DONE)

The required spki engine: pure-Rust ECDSA over SubjectPublicKeyInfo public
keys, reusing the 13b key store.

Delivered as `SpkiSigner` / `SpkiVerifier` behind the `sign-spki` feature over
`p256` 0.13.2 (RustCrypto, pure Rust): deterministic ECDSA on NIST P-256 with
SHA-256, DER-encoded signatures, SubjectPublicKeyInfo public keys, and secret
keys accepted as base64 of a PKCS#8 DER, a SEC1 DER, or a raw 32-byte scalar.
The key store reuses the 13b `load_sign_keys` as `trusted.spki` /
`revoked.spki`, each line the base64 of a SubjectPublicKeyInfo.

Deviation from the verify gate: the reference tool gates spki on OpenSSL and the
available build (libostree 2026.1) was compiled without it, so the
recovery-by-observation and the `ostree sign --verify --sign-type=spki`
cross-verification cannot run. Per the maintainer's decision the engine targets
the documented containers and the standard OpenSSL/RFC forms, cross-checked
against `openssl` (a general tool, run as a black box) in both directions in
place of the tool. The spki facts in `format-reference.md` are marked "design
target, tool cross-verification pending"; the `spki_tool_cross_verify_pending`
test skips when the tool lacks spki and performs the real check once a
spki-capable build is available.

Definition:

- `SpkiSigner` / `SpkiVerifier`: ECDSA over the NIST curve the tool uses,
  public keys in the SPKI SubjectPublicKeyInfo PEM "PUBLIC KEY" encoding,
  secret keys base64-encoded. The exact curve, hash, ECDSA signature encoding
  (fixed-width versus DER), and secret-key encoding are recovered by
  observation -- generate a key pair with the tool, sign a commit, inspect the
  PEM and the signature bytes -- and recorded in `format-reference.md` before
  the engine lands. The design target is NIST P-256 with SHA-256.
- Reuses the 13b sign-api key store: files `trusted.spki` and `revoked.spki`
  and the `.d` directories under the same system search path, decoding PEM
  public keys through the general base64 plus SPKI/DER parsing.

Dependency set: `p256` (RustCrypto; features `ecdsa`, `pem`, `pkcs8`, `std`;
exact pin confirmed at phase start), pure Rust, pulling `ecdsa`,
`elliptic-curve`, `sec1`, `spki`, `der`, `pem-rfc7468`, and `signature` -- all
pure Rust with no C or `*-sys` linkage -- with the existing `sha2` for the
digest. Behind the `sign-spki` feature. If observation shows a curve other
than P-256, the sibling `p384` from the same family is proposed instead, with
no structural change.

Deliverables: `SpkiSigner`, `SpkiVerifier`, the SPKI PEM key decode, and the
`format-reference.md` "Signing details" update recording the recovered spki
facts.

Verify: a commit the port signs with spki verifies under
`ostree sign --verify --sign-type=spki`, and the port verifies an spki
signature the tool wrote for the same key pair; the trusted and revoked
convention resolves spki keys; `test-signed-commit-spki` targeted through the
harness when the CLI lands; the suite passes under both runtime backends, with
and without the `sign-spki` feature.

### Phase 13d -- GPG signing and verification (system GnuPG) (DONE)

GPG commit signing and verification over the system GnuPG installation,
behind the `sign-gpg` feature: the engine runs the `gpg` and `gpgv` binaries
as short-lived subprocesses, the way git drives them, and reads results from
the machine-readable `--status-fd` line protocol. No OpenPGP implementation
is linked into the library, and the private key never passes through it --
`gpg` performs the private-key operation itself, consulting its `gpg-agent`
(and any hardware token behind it) as needed, so agent-held keys work with
no dedicated code path.

Definition:

- `GpgSigner` names its key the way `gpg --local-user` resolves it -- a
  fingerprint, a key id, or a user id -- with an optional GnuPG home
  directory override. Signing runs `gpg --batch --detach-sign` with the
  commit bytes on stdin and appends the binary signature from stdout to
  `ostree.gpgsigs` through the 13a append path.
- `GpgVerifier` holds binary keyring blobs; armored input is decoded to the
  binary form on load by a hand-rolled RFC 4880 radix-64 decoder, since
  `gpgv` reads only binary keyrings. Keyring resolution: N keyrings from
  bytes or files, the per-remote `<remote>.trustedkeys.gpg` and
  `/etc/ostree/remotes.d/` resolution, and the global
  `<datadir>/ostree/trusted.gpg.d/` directory, per `format-reference.md`.
- Verification materializes the merged keyring in a private scratch
  directory and runs `gpgv --keyring` once per stored blob with the payload
  on stdin. `gpgv` performs public-key operations only and starts no agent.
  A blob may hold several signature packets; each `NEWSIG` status group
  yields one `SignatureInfo`.
- Validity is `GOODSIG` alone. `EXPKEYSIG`, `REVKEYSIG`, `BADSIG`, and
  `ERRSIG`/`NO_PUBKEY` map to the expired, revoked, and missing flags;
  `VALIDSIG` supplies the fingerprints, timestamps, and algorithm ids;
  `KEYEXPIRED` supplies the key expiry. The vocabulary was pinned by
  black-box observation of GnuPG 2.4 (good, bad, unknown-key, expired-key,
  revoked-key, and multi-packet cases); unit tests parse the captured
  streams verbatim.
- `Verifier::verify` is async (a boxed `VerifyFuture` mirroring
  `SignFuture`), so a verifying engine can await a subprocess; the
  in-process engines resolve immediately.
- Subprocess plumbing is `rt::Command` in `ostrya-rt`: piped standard
  streams over `smol::process` (part of the `smol` facade) or
  `tokio::process` (the `process` feature on the existing tokio
  dependency). No new crate enters the lockfile.

Dependency set: none. The engine adds a runtime tool dependency on `gpg`
and `gpgv`; a missing binary surfaces as a signature error naming the
program.

Deliverables: `GpgSigner`, `GpgVerifier`, keyring loading (binary and
armored), per-signature `SignatureInfo` from the status stream,
`rt::Command`, the async `Verifier` trait, the `sign-gpg` feature wiring.

Verify: a commit the port signs round-trips through `gpgv` with the exported
keyring and is rejected under an empty trusted set; armored and file
keyrings load; a wrong payload reports `BADSIG`; GPG and dummy signatures
coexist on one commit; the status parser reproduces the observed GnuPG 2.4
streams; the suite passes under both runtime backends, with and without
`sign-gpg`. Tool cross-verification (`ostree gpg-sign` in both directions)
lands in `conformance/m10-cli-behavior.matrix` once the CLI-compatible
surface lands (Phase 17).

### Phase 13f -- Native `ostrya sign` command (DONE)

A `sign` subcommand on the Phase 11 `ostrya` binary, over the 13a framework and
its engines. Its command surface is the native one; the `ostree`-compatible
`sign` / `gpg-sign` surface remains Phase 17. One command
covers the three engines through `-s|--sign-type` (`ed25519` default, `spki`,
`gpg`), each in three modes:

- add (the default): sign the commit once per key and append each signature;
- `--verify`: check the commit's signatures and exit nonzero when none is valid;
- `-d|--delete`: remove stored signatures the given KEY-IDs match.

```
ostrya sign [--repo <repo>] [-d|--delete] [--verify]
            [-s|--sign-type ed25519|spki|gpg] [--gpg-homedir <dir>]
            [--remote <name>] [--keys-file <path>]... [--keys-dir <path>]...
            <commit> [key-id]...
```

For ed25519 and spki the KEY-IDs are base64 keys, as the tool treats them: a
secret key for signing, a public key for verify and delete. `--keys-file` adds
keys of the same kind, one base64 per line. `--keys-dir` overrides the
`trusted.<type>[.d]` / `revoked.<type>[.d]` system search roots for verify; with
nothing supplied inline, verify falls back to the system store. A delete matches
a stored blob to a KEY-ID by re-verifying it under that public key.

For gpg the KEY-IDs name the signing keys the way `gpg --local-user` resolves
them -- a fingerprint, a key id, or a user id -- in the default GnuPG home
directory or the `--gpg-homedir` override; the private key stays with `gpg`
and its agent, a hardware token included, and `gpg` may start its own agent
for the selected home directory. Verify and delete load keyrings (binary or
armored) from `--keys-file` when any are given; otherwise they fall back to
the default trusted set the `ostree` tool uses -- every `*.gpg` keyring in the
directory named by `OSTREE_GPG_HOME`, or `/usr/share/ostree/trusted.gpg.d/`
when that variable is unset, plus, when `--remote <name>` is given, that
remote's `<name>.trustedkeys.gpg` in the repo and under
`/etc/ostree/remotes.d/`. Verify runs `gpgv`, which starts no agent, and exits
nonzero when no signature is valid, including when the trusted set is empty. A
delete matches by the signature's issuer or primary-key fingerprint; the issuer
fingerprint is reported even for a key absent from the keyrings, and a keyring
in the trusted set lets the match consider the primary-key fingerprint.

Delete is backed by `Repo::delete_signatures(checksum, metadata_key, predicate)`,
which rewrites `.commitmeta`: an emptied engine array drops its dict entry, and
an emptied dict is written as the zero-length marker, leaving other engines'
arrays in place. The read, the predicate and the write run under the guard
`Repo::sign_commit` and the transaction merge take, which reaches this process
alone; the predicate runs on the blocking pool, so it is `Send + 'static`. The `spki` and `gpg` engines are enabled in the `ostrya-cli`
build by default, so all three sign-types work without a rebuild.

Verify: through the built binary, a commit it signs with ed25519 verifies under
the same public key and is rejected by a wrong one; the `ostree` tool verifies
that signature; a delete by the public key makes verification fail. The spki and
gpg engines sign and verify through the same command, and a gpg delete by
fingerprint clears the signature. A gpg commit verifies with no `--keys-file`
when `OSTREE_GPG_HOME` names a directory holding the exported `*.gpg` keyring,
and fails when that directory holds none.

### Phase 14 -- Summary generation and signing (DONE)

Summary assembly (sorted refs, the host-order size asymmetry, big-endian
timestamps), summary signing and verification.

`Repo::regenerate_summary` assembles `(a(s(taya{sv}))a{sv})` from `refs/heads`
(byte-wise sorted, remotes excluded) with per-ref size/checksum/version/
timestamp and the fixed-order global metadata, writes `summary` atomically at
the repo root, and drops any stale `summary.sig`. `SummaryOptions` overrides the
wall-clock `last-modified` (not pinned by `SOURCE_DATE_EPOCH`) for reproducible
output. Collection repositories are supported in full: regeneration refreshes
the empty-tree `ostree-metadata` anchor commit (collection/ref bindings,
parent-chained onto the previous anchor) and groups mirror refs into
`ostree.summary.collection-map`. `Repo::sign_summary` and
`Repo::verify_summary` reuse the Phase 13 signing framework over the exact
`summary` bytes, storing signatures in the `summary.sig` `a{sv}`. A native
`ostrya summary` subcommand exposes update, sign, and verify. The recovered
format facts (metadata key order, the anchor commit shape and its
parent-chaining, the empty-tree constants) are in `format-reference.md`.

The summary cache (`tmp/cache/summaries/`) caches fetched remote summaries and
lands with pull (Phase 16); local generation needs no cache.

Verify: byte-identical summary versus the tool for the same repo, for a
non-collection repo and a first-generation collection repo (the anchor commit
checksum matches the tool's); the tool verifies our port-signed summary via
`ostree remote summary --sign-verify`; sign/verify round-trips under ed25519.

### Phase 15 -- Static deltas

Split into sub-phases, mirroring the interop directions:

#### Phase 15a -- Reading and offline application (DONE)

GVariant superblock/part/fallback/signed formats, the LEB128 operation VM,
xz decode, bspatch, offline application, local delta listing, and signed-delta
verification. `Repo::apply_static_delta_offline` reads a delta the tool wrote --
the superblock (with the target commit embedded whole), the xz-compressed parts,
the mode/xattr tables, the data-source blob, and the operation stream (`S`
splice, `o`/`c` open/close, `r`/`R` read-source, `w` rollsum write, `B` bspatch)
-- and produces the target commit's objects, asserting each object's SHA-256 as
it is written (the `c`/`S` close is the integrity gate). The `w` op appends
`length` bytes read at `offset` in the current source (the read-source object
when one is set, the part's data source otherwise), which reconstructs a rollsum
object by copying its unchanged content-defined chunks out of the source object
and carrying only the changed runs in the payload. bspatch is hand-rolled over
the interleaved bsdiff control/diff/extra layout with `offtin` sign-magnitude
integers. `Repo::verify_static_delta` checks a signed delta's signatures with the
Phase 13 engines over the raw superblock bytes, and `Repo::list_static_deltas`
lists the deltas under `deltas/`. A native `ostrya static-delta` subcommand
exposes `list` and `apply-offline`. The recovered operand grammar and bspatch
layout are in `format-reference.md`. xz decode streams through
`async-compression`'s xz codec; xz encode, the same codec's other half, lands
with generation. Application is memory-bounded: the superblock is read whole
(bounded metadata, capped at the metadata ceiling), a part file is read in under
the size its meta-entry declares and checked against its part checksum before it
decompresses into an anonymous temp file in the repo, part bodies, payloads and
source objects at or below 128 KiB stay on the heap and larger ones are read-only
mmapped, and objects stream through the content writer rather than materializing
whole. A part names
its read source once per contiguous run it copies, so the reader holds the loaded
source across the `R` that ends a run and reuses it when a later `r` names the
same checksum; objects are content-addressed, so a checksum match means
identical bytes. One source object is held at a time.

Dependency: `liblzma` (MIT/Apache-2.0), statically linked and built from source
(bundled xz 5.8, no runtime liblzma), backing `async-compression`'s xz codec in
both directions. It is one of the two authorized C-linking exceptions, the
other being PCRE2 in `ostrya-cli` (see the Interpretation section and decision
#1).

Verify: the port applies the tool's from-scratch, from->to bspatch, and from->to
rollsum deltas and reproduces the target commit's objects, the tool's `fsck` and
`ls -R` validate the objects the port wrote, and ed25519-signed deltas verify
against a trusted key and are rejected under a foreign key (`tests/delta.rs`,
`static_delta_list_and_apply_offline` in the CLI tests). The from-scratch fixture
carries a 512 KiB object to exercise the temp-file + mmap part-payload path; the
bspatch case uses a 20 KiB object; and the rollsum case edits a 2 MiB file in
place, which the tool expresses with `r`/`w`/`R` copy-from-source ops (the test
asserts the tool emitted rollsum writes before applying).

#### Phase 15b -- Generation (DONE)

`Repo::generate_static_delta` writes a delta the tool applies: the superblock
(the target commit embedded whole, `ostree.endianness` metadata, a copy of the
target commit's detached metadata where it has any, a wall-clock big-endian
timestamp, per-part meta-entries, and the fallback array) and the xz-compressed
numbered parts. The detached-metadata copy sits under the delta's own relative
directory with `/commitmeta` appended, which is where a tool pull reads the
signatures it holds a delta-delivered commit to; a commit with no detached
metadata gets no entry. `Repo::sign_static_delta` wraps a written
superblock in the `OSTSGNDT` envelope through the Phase 13 engines, once per
engine, and `Repo::reindex_static_deltas` rebuilds `delta-indexes/`. A native
`ostrya static-delta generate` exposes the knobs, `--sign`, and `--reindex`, and
`ostrya static-delta reindex` the index pass. Newly recovered format facts -- the
meta-entry `size`/`usize` accounting, the fallback entry's two sizes, the part
packing rule, the index file's `a{sv}` shape, and the tool's offline-application
limits -- are in `format-reference.md`.

Each object takes one of four routes, decided per object: a loose fallback past
`min_fallback_size`; a rollsum copy-from-source stream (`o`, then `r`/`w`/`R`
groups interleaved with payload `w` ops, then `c`) when content-defined chunking
finds shared chunks with the object at the same path in the source commit; a
bspatch stream against that same source when chunking finds nothing; or a splice
otherwise, which is also the only route for metadata objects and symlinks.
Chunking is this port's own (a 64-byte rolling window, 8 KiB average chunks
bounded to 2 KiB..64 KiB) rather than a reproduction of the tool's: the receiver
never sees the parameters, so they decide delta size, not validity. Repetitive
content collapses the chunk digests -- zero padding triggers no boundary, so it
cuts into identical maximum-size chunks under one digest -- and a chunk match
prefers the source offset that continues the copy run in progress, which keeps
such a stretch a single copy run and stops the candidate scan at its first byte
comparison. That offset is decided by comparing the source bytes there, which
costs no digest and requires no chunk boundary at the offset, since a copy run is
a length the receiver reads out of the source object. A target chunk whose digest
is absent from the index therefore still copies when the run in progress carries
its bytes.

bsdiff is attempted only where both objects are at or below the chunker's maximum
chunk size (the suffix sort is over the source, and pairing by path can hand a
small object a large predecessor), taking the tighter of that bound and
`max_bsdiff_size`. Chunking having found nothing shared means
different things at different sizes: across many chunks it means no chunk-sized
window of the target occurs anywhere in the source, which is evidence the two
objects are unrelated, while a one-chunk object is defeated by an edit anywhere.
Bounding the attempt by the chunker's own granularity confines it to the second
case, which is also where the tool emits bspatch. A patch that is produced is
kept only when its novel data -- the nonzero bytes of the patch stream, since the
enclosing xz reduces the zero runs of a diff against a near-identical source to
almost nothing -- comes to under half the content it replaces. The bound has to
be a fraction: a diff against unrelated content is nonzero except where the two
bytes coincide, about 1 byte in 256 of high-entropy content, so it counts near
0.996 of the output size and clears any bound at 1.0 while producing a larger
delta for several times the CPU.

A delta's files are written parts first, so an interrupted generation leaves no
superblock for a reader to trust, and regenerating at an existing location unlinks
that delta's superblock before the first part is overwritten. Each file is written
under a temp name held by a drop guard that unlinks it until the rename putting the
file in place disarms it, so a write that fails part-way -- an `ENOSPC` while a part
is being compressed, say -- and a generation future dropped mid-await both take
their temp file with them, leaving the sweep below what a killed process abandoned.
Once the new superblock is in place, that sweep removes numbered parts past the new
part count and temp files that have aged past an hour. Age is what keeps two runs
out of each other's way: a generation renames each of its own temp files into place
as it goes, so every temp file the sweep meets belongs to another run, and the
process id in the name does not separate an abandoned leftover from a file a
generation running right now is still writing, since two generations in one process
share it.
Unlinking a file still being written would fail that run's rename. The sweep
recognizes what it removes by name, so it covers the repository's own `deltas/`
tree alone: a directory named through `output_dir` is the caller's, nothing in it
is removed, and a longer previous delta's extra parts stay there, costing disk
rather than correctness since a reader takes the parts the superblock lists.
Generating one delta twice at once into one directory is unsupported either way,
as both runs write the same names; generating different deltas concurrently is
supported, each having its own directory.

Object order is metadata-then-content, each by checksum, so a given input
produces a given delta; with `timestamp` pinned, generation is byte-reproducible
for a given liblzma, since the part bytes are that library's output and a version
change can move them. That guarantee also rests on the part compressor being
pinned: parts are xz at preset 8, non-extreme, with the CRC64 check, which gives
the 32 MiB LZMA2 dictionary the tool's parts carry, 370 MiB of encoder memory per
concurrent part and 33 MiB to decode (`PART_XZ_LEVEL` in `deltagen.rs`, measured
with `xz -8 -T1 -vv`).

Generation is memory-bounded like application. A part's data source accumulates
in a spill buffer that moves to an anonymous temp file past 128 KiB, spliced
content streams into it in bounded chunks, and the part payload is serialized
straight into the xz encoder: the GVariant framing is written around the two
large byte arrays, whose lengths are known before the first byte, so the payload
is never buffered whole (`ostrya-gvariant` exposes `choose_offset_size` and
`write_offset` for that). Those lengths are also what the framing offsets are
derived from, so the data source is held to them: the handover to the blocking
side flushes the spill file, since the async file performs its writes on a
background task and reports a failed one at the next flush rather than from
`write_all`, and the payload stage counts what it streams out of the spill file
and refuses a count other than the length recorded. An `ENOSPC` on the spill
filesystem then fails generation instead of producing a part that verifies its own
checksum and fails when it is applied.

Diffing is the exception to the streaming rule -- both objects need random access,
so they load through the same heap-or-mmap path the reader uses, and chunking scans
both end to end, so every page of both is resident while a pair is planned. Peak
resident set size therefore tracks the two objects' sizes together, in mapped
temp-file pages rather than heap: measured at 305 MB for a 150 MB object with 512
bytes zeroed in the middle, diffed against its predecessor at
`--min-fallback-size=0`, where the part carrying it came to 31 KB. The same run
shows the packing estimate at work -- the object closed the part holding the two
metadata objects at 109 bytes and travelled in the next one. `min_fallback_size`
bounds the target, since an object at or past it is handed over loose and never
diffed, so the default caps that term near 4 MB and `--min-fallback-size=0` removes
the cap; the source it pairs with is whatever object sits at the same path in the
source commit and carries no bound of its own, so a target that replaced a much
larger object costs that object's size too. `max_bsdiff_size` bounds the patch
attempt alone, whose suffix sort costs about sixteen times the source size on top
of the pair.

The dominant term in the measured footprint is the xz encoder rather than the
delta code: the 370 MiB of liblzma state above is per part being compressed, so a
process compressing N parts side by side holds N times it. Measured peak resident
set size is 5.6 MB for a one-file delta, and 389 MB for a 40 MB part and 390 MB
for a 200 MB part -- a 5x payload for 0.2% more memory, which is the spill
buffer's contribution being flat and the encoder's being fixed.

The CPU-bound stages run on the blocking pool, not on an executor thread:
chunking and hashing a diff candidate's two objects, bsdiff's suffix sort, and
each part's compression. `XzEncoder` compresses inside `poll_write` and never
yields, and a 40 MB part costs 11.5 s of CPU, so driving it from a task would
hold an executor thread for the duration and N concurrent generations would hold
N of them. The encoder stays the streaming one, so the payload is still never
buffered whole: `compress_part` drives it with `block_on` over a blocking file
handle whose I/O completes in place, so the future never parks and needs no
executor behind it. The 15a read path's `XzDecoder` remains inline, where
decoding costs one to two orders of magnitude less CPU per byte.

Dependency: `bsdiff` 0.2.1 (BSD-2-Clause, no dependencies of its own, no
`unsafe`), for patch generation only; the port's own bspatch applies them.

Object-selection thresholds (the `ostree static-delta generate` knobs, defaults
recovered by observing the tool). All three take a value in decimal megabytes (a
factor of 1,000,000); `DeltaOptions` takes the same values in bytes. The
generator reproduces them so it packs, patches, and falls back the way the tool
does:

- `--min-fallback-size`, default 4 (4,000,000 bytes). An object whose file header
  variant plus seven bytes plus content reaches the threshold is delivered as a
  fallback loose object rather than packed into a part. The seven bytes are the
  tool's count, one below the eight-byte on-disk content-stream framing, measured
  at three header shapes spanning the GVariant offset-width boundary; the full
  rule and the measurements are in `format-reference.md`, "Static delta wire
  format".
- `--max-bsdiff-size`, default 64 (64,000,000 bytes). bsdiff is considered for a
  modified object only when the input file content size is at most the threshold;
  a larger input skips bsdiff, leaving rollsum or fallback. The comparison is on
  the content size and is inclusive: content of exactly 64,000,000 still uses
  bsdiff, 64,000,001 does not. The port takes the tighter of this knob and the
  chunker-derived bound above, so at the default the chunker's 64 KiB is what
  binds and the knob decides only when it is set below that.
- `--max-chunk-size`, default 32 (32,000,000 bytes). A part's payload is capped
  near the threshold; once the accumulated payload would exceed it the generator
  starts a new part. The default packs about 31 one-megabyte objects per part and
  splits at the 32nd; `--max-chunk-size=8` splits at the eighth, confirming the
  decimal-megabyte unit. The port decides with the incoming object's content size,
  an upper bound for a diffed object, and decides before appending it, so a part's
  payload never passes the ceiling and a diffed object that comes out small still
  closes the part it would have fit in.

Verify: the tool applies the port's deltas and `fsck` validates the objects it
wrote, for a splice-only from-scratch delta, a rollsum from-to delta, a bspatch
from-to delta, and a multi-part delta; `ostree static-delta show` confirms which
operations each delta carries, so a test cannot pass by silently splicing;
`ostree static-delta verify` accepts the port's ed25519 signature and rejects it
under a foreign key; `ostree static-delta indexes` lists a target the port
indexed; a tool pull under `sign-verify=ed25519` takes the port's delta for a
signed commit, over a `file://` remote with `--require-static-deltas`, and takes
a delta for an unsigned commit whose superblock carries no `commitmeta` entry;
the port applies its own deltas and reproduces the objects, including the
fallback route the tool refuses offline; the fallback threshold is checked at
both sides of its boundary against the tool's own generation over the same
commit at the same threshold, so the compared size is pinned to the tool's byte
for byte; a temp file aged past the sweep's hour is removed while a fresh one
survives; a caller's files named `0` and `.notes.tmp-1-1` in an `output_dir` are
left alone; and generation is byte-identical across two runs over one input
(`tests/delta_generate.rs`, `static_delta_generate_signs_and_indexes` in the CLI
tests). Unit tests cover the data source's two failure modes: a spill write the
async file defers fails the handover to the blocking side, and a data source
holding fewer bytes than the framing counts fails the part. That second failure
also drives a whole `write_part`, which fails after its temp file exists and has to
leave the delta directory empty, pinning the guard. The chunker's own tests cover
the plans it produces, including a target ending inside a source chunk, whose short
last chunk carries a digest the index does not hold and copies on the byte
comparison alone. Equivalent static-delta conformance cases land in
`conformance/m10-cli-behavior.matrix` at the CLI-compatibility phase.

The summary's `ostree.static-deltas` map, which advertises a repository's deltas
to a fetcher, landed with the delta-accelerated pull in Phase 16d; the key's
position in the metadata dict is recorded in `format-reference.md`.

### Phase 16 -- Pull

Split into sub-phases:
- 16a Async fetcher (DONE, see below).
- 16b Local pull (`file://`) (DONE, see below): object import
  (hardlink/reflink/copy), localcache repos.
- 16c HTTP pull (DONE, see below): the scan/fetch state machine (bounded fetch
  semaphore of 8, write throttle of 3, fixed priority drain order), summary
  reading, content and commit verification, timestamp checks, mirror mode. The
  ref-binding check and the commitpartial markers landed with 16b, which is
  source-agnostic; 16c reuses them.
- 16d Delta-accelerated pull and the delta-part cap of 2 (DONE, see below). The
  config and mount repo finders moved out of this sub-phase: a finder resolves a
  collection ref, and collection refs are not yet scheduled.
- 16e Commit and summary signature verification during a pull (DONE, see
  below): the GPG and sign-api axes, their configuration keys and key sources,
  and the delta signature check 16d left open.
- 16f The `ostrya pull` CLI command (DONE, see below).
- 16g Archive-to-archive pass-through (DONE, see below): store a fetched
  `.filez` verbatim instead of inflating and deflating it again.
Verify: pull from a local trivial httpd over both HTTP/1.1 and HTTP/2; the
`test-pull-*`, `test-local-pull*`, `test-signed-pull*` clusters via the
harness.

#### Phase 16a -- Async fetcher (DONE)

`ostrya-rt` grows the network and task layer pull needs: `rt::TcpStream` and
`rt::TcpListener` over the backend's TCP types, presenting the `futures-io`
traits under both backends and the tokio traits under the `tokio` feature, with
Nagle's algorithm off and vectored writes forwarded to the backend socket so a
slice list reaches it in one syscall; and `rt::spawn` with a `JoinHandle` whose
semantics are
uniform across backends -- the task keeps running when the handle drops
(`smol::Task::detach` under smol, tokio's own behavior under tokio) and awaiting
the handle yields the task's output, propagating a panic. A task that ended
cancelled instead, which under tokio is what awaiting through a runtime shutdown
produces, panics the awaiting side with a message naming the cancellation.
`rt::Deadline` joins
`rt::Timer`: a restartable window a `poll_*` method checks, over
`smol::Timer::set_after` or `tokio::time::Sleep::reset`, whose expiry sticks
until the next restart so both backends report it the same way on every poll.

`Fetcher` in `ostrya` is the HTTP client for one remote: `FetcherOptions` holds
the ordered mirror list, extra headers, basic-auth credentials, the TLS options,
whether HTTP/2 is offered, the retry count (5), the in-flight limit (8), the
connect deadline (30s) and the progress deadline (60s). `Fetcher::new` is async:
`TrustRoots::System`, the default, reads the host trust store, which goes to the
blocking pool through `rt::unblock`, keeping that the only door to it. The TLS
configuration is built whatever the mirrors' scheme is, so a cleartext-only
fetcher reads the store as well; under `TrustRoots::Pem` the constructor stays in
memory and never yields. A system store holding no certificate fails the
constructor only when at least one mirror is `https`, whose handshake needs the
anchors, so a host without a CA bundle -- a container without ca-certificates --
still builds a fetcher for a cleartext remote. Credentials are the one thing a
cleartext mirror is refused for: `basic_auth`, and an `Authorization`,
`Proxy-Authorization`, or `Cookie` entry in `headers`, are sent with every
request to every mirror, so one `http` entry in the list fails the constructor
with `Error::Fetch` naming that mirror. Withholding the credential from that one
mirror instead would answer 401 and name nothing, and those three are the header
names whose value is a secret whatever it holds -- any other header is sent as
written.
`Fetcher::fetch` takes a `FetchRequest` -- a path relative to each mirror, a
`Priority`, optional `Validators`, an optional size cap -- and resolves to
`Fetched::Body` or `Fetched::NotModified`.

- Protocol selection is the TLS handshake's: ALPN offers `h2` then `http/1.1`,
  and the connection speaks what the server chose. A cleartext origin speaks
  HTTP/1.1, since cleartext HTTP/2 needs prior knowledge or an upgrade.
  `FetcherOptions::http2 = false` drops `h2` from the offer.
- Connections are pooled per origin (scheme, host, port). An HTTP/2 connection
  multiplexes concurrent requests; an HTTP/1.1 connection returns to the pool
  when its body reaches the end, and a body dropped early closes its connection
  instead, because the rest of the response is still in flight.
- An HTTP/1.1 request carries the origin-form target (the path alone) and a
  `Host` header built from the mirror's authority; the absolute form belongs to
  proxy requests, and a plain static-file server -- how an ostree repository is
  usually published -- answers 404 to it. An HTTP/2 request carries the absolute
  URL, from which the `:scheme` and `:authority` pseudo-headers are filled. A
  caller-supplied `host` header is rejected at construction, since it would
  collide.
- Conditional GET replays `ETag` as `If-None-Match` and `Last-Modified` as
  `If-Modified-Since`; the stored values are the server's own strings, so no
  date parsing enters the fetcher. A 304 resolves to `NotModified` and its
  connection is reusable at once.
- Every mirror is tried in order before anything is retried. Transport failures
  and the statuses 408, 429, and 5xx are retryable, and a round holding one
  repeats after a delay doubling from 250ms to a two-second cap; any other
  unsuccessful status fails once the mirrors are exhausted, as
  `Error::HttpStatus`, which is how a caller sees a 404 for an absent object.
  A repeated round asks only the mirrors whose failure was retryable: a mirror
  that answered definitively answers the same in every round, so it is asked
  once per fetch, and the first such answer received is the one the fetch reports
  when nothing retryable is left.
- Two deadlines bound what one attempt against one mirror can cost.
  `connect_timeout` (30s) covers opening a connection: the TCP connect, the TLS
  handshake, and the HTTP handshake together. `progress_timeout` (60s) covers a
  response delivering bytes -- the wait for the response head, then each stall
  while the body streams. That window runs from the read that finds nothing until
  bytes arrive, so it caps how long a peer may stay silent and leaves the
  transfer time of a large object unbounded. What it measures is silence since a
  read wanted bytes: once a read has found nothing the window runs whether or not
  a read is outstanding, and a body no read has yet found empty is not on the
  clock at all. That distinction becomes observable in 16c, which interleaves body
  reads with a write throttle. Both expire as transport failures, so the next
  mirror is tried; a stalled body fails the read with `io::ErrorKind::TimedOut`,
  and keeps failing it.
- `fetch_timeout` (300s) bounds the fetch as a whole: every mirror round, every
  retry, and the delays between them, from the moment the fetch is admitted until
  the response head arrives. Without it the bound is the product of the mirror
  count, the retry count, and the two per-attempt deadlines -- with the defaults,
  545s for a single mirror that accepts connections and then goes silent -- and
  the admission permit is held for all of it. Expiry drops the attempt in flight
  and the permit with it, and reports `Error::Fetch` naming the path and the
  limit; no mirror is tried afterwards. The body that follows a response is
  bounded by `progress_timeout` alone, so a large object's transfer time stays
  unbounded. `None` applies no cap. 16c sizes this against `max_outstanding`.
- The size cap is enforced twice: a declared `Content-Length` over the cap fails
  the fetch with `Error::FetchTooLarge` before any body is read, and a body that
  outgrows the cap mid-stream fails the read with `io::ErrorKind::FileTooLarge`.
- A failure ends the body. The size cap, the progress deadline, and a transport
  failure mid-body are each latched and replayed on every later read, so a
  consumer reading past a failure never observes a clean end of stream and cannot
  mistake a truncated object for a complete one -- which matters most for the
  paths fetched without an expected digest, since a payload with one is also
  caught by `VerifyingReader`. hyper reports a body error once and then reports
  that body as ended, so the latch is what stands between a cut connection and a
  short object read as whole. The connection and the permit are released on the
  drop path, which closes the connection rather than pooling a response still in
  flight.
- Requests carry a priority. The fetcher admits `max_outstanding` at a time
  through an admission gate that hands a released permit directly to the
  highest-priority waiter, ties in arrival order; the permit is held until the
  body reaches its end or is dropped, since a body in flight occupies a
  connection, and a failure ends the body with both still held, so they go on the
  drop path. A queued waiter is guaranteed only that no later arrival of its own
  priority is served first: the order across priorities is strict, so a steady
  arrival of higher-priority waiters keeps a lower-priority one queued, and what
  bounds that is the caller's mix of priorities. 16c's state machine sets the
  limit and assigns the priorities.
- Range requests are not used, and redirects are not followed.
- A mirror URL is a scheme, an authority, and a base path. A request target is
  that base path with the object path appended, so a URL carrying a query string
  or userinfo is rejected at construction with `Error::Fetch` naming the part:
  serving it with that part missing turns a presigned URL into a 403 and
  credentials into a 401, neither of which points back at the URL. Phase 18
  carries a presigned query per target or signs each request itself. A host
  given as an IPv6 literal keeps its brackets in the `Host` header and in the
  absolute URLs, and is held bare in the origin, which is what the connect
  resolves and the TLS server name is built from; both reject the bracketed
  form.
- A request path is appended to the base path as written, carrying the escaping
  the server is meant to see, and holds no query and no fragment: a `?` or a `#`
  in it fails the fetch with `Error::Fetch` naming the character. Either one
  delimits rather than names -- the tail of a `?` reaches the server as a query
  string it matches on, and the tail of a `#` is dropped at URL assembly, so a
  different resource is requested. The path is the same whichever mirror serves
  it, so the check runs once, before the fetch is admitted: no permit is taken
  and no connection is opened for a path that cannot be served. 16c builds every
  path from hex object names and ref names.

`VerifyingReader` lands with the phase: it wraps a `HashingReader` and fails the
read that reaches EOF with `InvalidData` when the stream did not hash to the
expected digest. The mismatch is latched and replayed by every later read. A
consumer that stops early never observes EOF and so never verifies, and a read
into an empty buffer touches neither the stream nor the check.

Dependency set for the phase, all pure Rust with no C in the graph (verified
with `cargo tree -e normal,build`: the workspace's `cc` sources are liblzma's
and PCRE2's): `hyper` 1.11 (`client`, `http1`, `http2`) as the HTTP engine, with
the `http` and `bytes` types taken from its re-exports; `rustls` 0.23 with
`rustls-graviola` 0.4 as the crypto provider -- Rust plus formally-verified
assembly from s2n-bignum, so no C compiler and no `cc` build dependency, at the
cost of supporting only x86_64 and aarch64; `futures-rustls` 0.26 for the
handshake over `futures-io` streams; `rustls-native-certs` 0.8 for the system
trust store (`webpki-roots` was rejected: CDLA-Permissive-2.0 is not on the
permitted list); and `rustls-pemfile` 2 for CA and client-certificate material.
hyper's `server` feature is a dev-dependency for the test server. `h2` brings
`tokio` and `tokio-util` into the graph even under the smol backend, where only
their I/O traits and codec framing are used and no tokio runtime is driven. Two
crates from the proposal turned out unnecessary: `http-body-util` (the fetcher's
request body is a hand-rolled empty `Body`, ~15 lines) and a base64 crate
(`ostrya-core::base64` encodes the basic-auth header). The glue hyper needs --
`hyper::rt::Read`/`Write` over `futures-io` and `hyper::rt::Executor` over
`rt::spawn` -- is ~90 lines in `fetch/io.rs` and holds `forbid(unsafe_code)`:
hyper's read cursor is filled through its safe `put_slice`, which costs one
extra copy per read, since exposing the uninitialized buffer to `poll_read`
would need `unsafe`. What the adapter tells hyper about vectored writes comes
from the stream it wraps, through a `WriteVectored` trait the adapter defines:
the `futures-io` write trait carries no `is_write_vectored`, and hyper coalesces
the slices itself when the answer is no, so answering for a stream that takes
only the first slice would cost a syscall per slice.

Verify: `tests/fetch.rs` runs an in-process hyper server over cleartext
HTTP/1.1 and over TLS with the committed fixture certificates
(`tests/fixtures/tls/`, an authority signing a `localhost`/`127.0.0.1` server
leaf and a client leaf, regenerated by `generate.sh`), covering ALPN selecting
HTTP/2, HTTP/2 disabled negotiating HTTP/1.1, conditional GET through to 304
with both validators replayed, a 404 reported without a retry, a retryable
status retried and then succeeding, retries stopping at the configured count,
three mirrors tried in order until one answers, a mirror that answered
definitively asked once while the retryable one is asked every round, a
definitive answer from an earlier round reported once the last mirror settles,
both halves of the size cap,
basic auth and extra headers arriving at a TLS server while a cleartext mirror
alongside one fails the constructor with neither server reached, mutual TLS with
and without the client certificate, HTTP/1.1 keep-alive reuse and HTTP/2
multiplexing over a single connection (asserted on the server's connection
count), an abandoned body not being pooled, and a fetched body checked through
`VerifyingReader` both ways. Three tests read past a terminal failure and assert
the same error comes back: a body read on after it outgrew its cap, a body read on
after a peer closed the connection eight bytes into a 64-byte response, and a
`VerifyingReader` read on after a digest mismatch. Three tests point the fetcher at a peer that
accepts a connection and then goes silent, one per deadline: a TLS handshake that
never answers, a request whose response head never arrives, and a body that
stops after eight of its declared bytes, the last asserting that the second read
reports the same timeout. Two tests pin what the progress window measures: a body
nobody has read yet reads fine after the window has passed, and a read abandoned
while the peer is silent leaves the window running, so the next read fails at
once -- raced against a timer shorter than the window, which a read that started a
fresh window would outlast. Two more cover the whole-fetch deadline: one gives a
silent peer two hundred retry rounds, a 300ms `fetch_timeout`, and a gate of one
permit, asserting that the fetch fails naming the deadline and that the next
fetch is admitted, which happens only if the cancelled attempt released its
permit; the other clears `fetch_timeout` and asserts a response arrives
unaffected. One test reads the request bytes off a raw socket
and pins the HTTP/1.1 wire format -- origin-form target, `Host` header -- which
is the property that decides whether an ordinary static-file server answers at
all. One test fetches from a server bound to `[::1]`, asserting that the
bracketed literal reaches the `Host` header while the connect reaches the
listener. One test re-executes its own test
binary with `SSL_CERT_FILE` and `SSL_CERT_DIR` pointed at paths that do not
exist, presenting the child with the store of a host without a CA bundle, and
asserts that a cleartext-only fetcher is built while one with an `https` mirror
fails with `no trusted certificates` (`tests/fetch_no_trust_store.rs`). The
child half is `#[ignore]`d and returns without asserting when the environment is
absent, so the store that trusts nothing reaches no other test and no
`set_var` is called. Unit tests cover mirror-URL parsing and
validation, the request paths a target is refused for, retry classification,
the backoff schedule, header assembly, the
TLS configuration (ALPN, client identity, rejected material), the hyper I/O
adapter, and the admission gate's five orderings. The whole suite passes under
both backends.

#### Phase 16b -- Local pull (DONE)

`Repo::pull_local(&src, PullOptions)` copies refs, the commits they name, and
every object those commits reach out of another local repository, and returns a
`PullStats`. `PullOptions` carries the ref names (empty for every ref under the
source's `refs/heads`), an optional remote name, a `PullFlags` bitset, the
parent depth, and the localcache repositories. The objects are imported in one
transaction, so a failure publishes none of them and writes no ref. A commit's
detached metadata is written as its objects are imported, ahead of the ref that
names it, so a verifier never sees a commit whose signatures have not arrived;
a failed pull can leave a `.commitmeta` for a commit it did not publish, which
prune sweeps.

The order is: resolve every requested ref in the source, check each tip's ref
binding, follow each tip's parents to `depth`, write the commitpartial markers,
import every object, copy each commit's detached metadata, publish, write the
refs, remove the markers. Ref writes come last through the transaction's ref
queue, so no ref names a commit whose objects are not yet durable, matching the
durability contract Phase 7d set.

Each tip is followed to `depth` on its own. The chain walk records the number of
parents a commit still had to follow when it was reached, and a chain arriving at
a commit with more parents left than a previous one had is walked on from rather
than stopped at, the way `traverse_reachable` treats a commit reached from two
roots. The commits a pull collects therefore depend on the refs and the depth
alone and not on the order the refs are listed; only their import order follows
that order, each commit imported once.

Object import, the phase's core. The contract has two parts, in this order: an
imported object carries the filesystem metadata -- unix mode, ownership, and
xattrs -- a commit into the destination would have given it, and subject to that
it shares the source's bytes and its inode.

- A metadata object has one representation in every mode -- its serialized
  bytes in a plain file, and a loose path the mode does not change -- so it is a
  hardlink candidate everywhere. A content object has one representation across
  repositories of the same mode, so it is a candidate too, as is a symlink object
  between bare-user and bare-user-shared: those two store one identically, a
  0644 regular file of the target plus a NUL with the logical metadata in
  `user.ostreemeta`.
- A hardlink shares the source inode entire, ownership included, so a candidate
  is admitted only where that ownership is what a write into the destination
  produces. A content object into a bare destination is admitted outright: its
  uid, gid, permission bits, and xattrs are all a function of the header its
  checksum covers, so two bare repositories agree on the inode byte for byte. In
  every other mode ownership becomes a function of the writer while the mode bits
  and xattrs stay a function of the header, so the source inode's uid and gid are
  compared against the pair an object freshly staged in this transaction takes.
  That pair is measured once per transaction, by creating a temporary in the
  staging directory the way every staged object is created and reading its inode:
  a created inode's group is the directory's when the directory is setgid and the
  process's otherwise, and a filesystem mounted with group inheritance gives the
  directory's group either way, so measuring answers for the filesystem the
  staging directory is on. The pair is measured only where a link may be
  attempted, so a pull under `FORCE_COPY` and a pull into a destination that
  seals its objects take no probe at all. A pull between repositories owned
  differently -- two
  group-shared repositories of differing groups, for one -- therefore stops
  hardlinking and writes its objects afresh, sharing the source extents by
  reflink where the filesystem has one.
- Ownership is all the gate reads. A link trusts the source inode to match the
  object's header in its other attributes: the permission bits and the xattrs
  arrive as the source holds them, and for a content object outside bare mode the
  header is the read the link path exists to avoid. In archive, bare-user, and
  bare-user-shared neither the permission bits nor the xattrs beyond
  `user.ostreemeta` are covered by the object's checksum, so a source whose inodes
  were rewritten out of band -- a copy that dropped modes, a `chmod` over
  `objects/` -- carries that state into the destination undetected. No writer
  produces such a source: the tool and the port agree on the canonical inode mode
  for every logical mode and neither varies with the umask. The tool's
  `pull-local` links the same inodes, so the destination holds what the tool would
  have given it. Attributes the destination's environment assigns rather than its
  writer -- a default POSIX ACL on its directories, a security label -- are not
  reapplied either: an object written there inherits them and a linked one keeps
  the source's, which is again what the tool does.
- A hardlink refused, by that gate or by the filesystem -- a source and
  destination on different filesystems, a source inode at its link limit, the
  kernel's protected-hardlink rules, or `PullFlags::FORCE_COPY`, which refuses
  every link and is what makes the path testable on one filesystem -- routes by
  object type. A metadata object, which has no header, is copied in place of its
  link: the source is opened, a `FICLONE` reflink attempted into a fresh staging
  temp, a byte copy run when the reflink is refused, and the inode a metadata
  object written into the destination carries applied -- 0644, no xattrs, and the
  staging temporary's own ownership, which is the destination's fresh-write pair
  by construction. A content object is reported unstaged to the pull, which
  imports it through its logical header instead -- `stage_clone_content` for a
  regular file, `write_symlink` for a symlink -- so it lands with the mode,
  ownership, and xattrs a commit into the destination would have written. That
  costs one metadata read on a path that is already moving the whole payload.
- A destination whose `[ex-integrity] fsverity` is `maybe` or `yes` does not
  hardlink at all: it refuses every candidate the way `FORCE_COPY` does, so each
  object arrives on a fresh inode that the copy and header paths seal. fs-verity
  is a per-inode property, so sealing a hardlinked object would seal the source
  repository's copy of it and make that copy immutable there, and leaving it
  unsealed would break the scope `format-reference.md` records: every loose object
  stored as a regular file is sealed, in every mode. The whole of the destination
  is therefore sealed or none of it is. The cost is that such a pull copies where
  it could have linked, including under `maybe` on a filesystem with no verity,
  where the copy seals nothing.
- The bare family stores a regular file's payload as its raw bytes, so any two
  of its modes share the payload and differ only on the inode. Such an object is
  imported by a `FICLONE`-then-copy move of the payload, with the destination's
  inode policy applied afresh from the object's logical header --
  `stage_clone_content_blocking`, which hands the cloned temp to the ordinary
  `stage_content_blocking` tail, so mode, ownership, `user.ostreemeta`, xattrs,
  fs-verity, and durability all follow the destination's own rules. The header
  comes from `load_file`, which reads the object's metadata and not its payload,
  so the cost of the import is one metadata read in place of a full read, hash,
  and write. This covers bare-user to bare-user-only, the pair named in the
  divergence below, and a same-mode object of the bare family whose link was
  refused. The byte copy a refused reflink falls back to is `std::io::copy`,
  which for a `File` to `File` transfer on Linux moves the payload inside the
  kernel through `copy_file_range` and drops to a fixed stack buffer only where
  the kernel refuses that, so no object is buffered whatever its size. It runs
  inside the blocking closure rather than through the crate's async
  `copy_stream`: the choice keeps the kernel-side copy on the filesystems that
  reach it, the ones with no reflink, and its cost is that the transfer holds one
  blocking-pool thread for its duration and cannot be cancelled -- a dropped pull
  leaves the copy running into a staging temp the staging reaper collects.
- A content object crossing the archive boundary shares nothing: archive stores
  a framed, deflated form. It is read back into its logical form -- uid, gid,
  mode, xattrs, and payload -- and written afresh through `write_content` /
  `write_symlink`, which stores it the way the destination mode requires. The
  write path computes the checksum as it streams, so this path always compares
  it against the object's name. A symlink between two modes that store it
  differently takes the same route, at the cost of a header hash alone.
- The transaction's free-space budget is charged for the blocks an import
  allocates and not for the bytes it shares. A hardlinked object allocates
  neither blocks nor an inode, and a payload moved by `FICLONE` shares the source
  extents, so a pull whose objects the destination shares with the source runs on
  a filesystem with no room for a second copy of them, which is the case local
  pull exists for. A byte copy and a re-ingest across the archive boundary are
  each charged the object's full stored size. `PullStats::content_bytes_written`
  counts every imported content object's stored size whichever path moved it, so
  it reports the storage those objects occupy rather than the space the pull
  consumed. All three counters cover the objects the pull staged, so an object
  the destination already held is absent from each and a `COMMIT_ONLY` pull
  reports its commit objects and no content at all.
- Every import path tests the destination mode before it touches the source.
  `bare-split-xattrs` needs the `.file-xattrs` and `.file-xattrs-link` sidecars,
  which no import path produces, so `stage_import_blocking` and
  `stage_clone_content_blocking` each refuse that destination with `Unsupported`
  ahead of any stat, open, or payload clone, the way the rest of the write
  surface refuses the mode.
- Objects are sourced from the source repository first and then each
  localcache repository in order, the first holder winning. The tool consults
  its `-L` caches only on an HTTP pull, where the primary source is remote;
  the port consults them on a local pull too, so a source with a hole is
  completed rather than failed. The walk that decides what to import resolves
  each commit and each dirtree through the same order, so the objects under a
  subtree the source has lost are enumerated from the cache that holds it. A
  dirtree no source holds contributes its own name and nothing beneath it, which
  fails the pull when the import reaches that name, so a commit this repository
  publishes is complete.
- The commits of one pull are planned as one walk: a dirtree descended into for
  one commit is not descended into again for another, so a `depth = -1` pull of a
  chain of near-identical trees reads each dirtree once, and each commit's plan
  carries the objects the commits ahead of it did not.

`PullFlags` (a hand-rolled bitset, as `CommitModifierFlags` is):

- `UNTRUSTED` fails the pull on a mismatch between an imported object and its
  name. The read it adds follows the path the import took: the link and clone
  paths move bytes without hashing them, so an object either of them imports is
  read once and hashed, while a re-ingested object is not read for the flag at
  all, since that path hashes the object as it writes it and compares the result
  against its name whatever the flags say -- a corrupt source is rejected on it
  with or without the flag. Which path an object takes is settled by attempting
  it, since a link the filesystem refuses sends a same-mode object on to a clone
  or a re-ingest, so the flag's read follows the attempt rather than predicting
  it, and an untrusted pull reads each object exactly once. Without the flag an
  object is linked or cloned without being read at all, which is what makes those
  paths possible. Both match the tool, which propagates a corrupt object on a
  trusted local import.
- `COMMIT_ONLY` imports the commit objects alone and leaves their
  `.commitpartial` markers in place. A later full pull completes them and
  removes the markers.
- `BAREUSERONLY_FILES` rejects a regular-file content object whose logical mode
  has bits outside `0775`, in any destination. A bare-user-only destination
  applies a rule of its own on top of that, whether or not the flag is set: a
  write into that mode records the canonical header and names the object for it,
  while an import keeps the name the object arrives under, so an object whose
  header is not already canonical -- a non-zero uid or gid, an xattr, or a
  regular-file mode with bits outside `0755` -- is refused with `Error::Pull`. The
  destination could otherwise hold it under a name its stored form does not hash
  to. This is a divergence from the tool, described below.
- `DISABLE_VERIFY_BINDINGS` skips the `ostree.ref-binding` check. Otherwise a
  commit carrying the key must list the ref it is pulled under; a commit
  carrying no binding key at all predates the convention and passes, while one
  carrying an empty list fails, which is what the tool does.
- `FORCE_COPY` is described above.

Commit state: a commit gets a zero-length `state/<commit>.commitpartial` marker
before its objects are imported, removed once they are published, so an
interrupted pull leaves the commit marked partial. The marker a pull writes is
zero-length, unlike the one-byte `0x66` fsck writes (see
`format-reference.md`). A commit this repository already holds without a marker
is not marked, so an unrelated failure elsewhere in the pull cannot demote a
commit that was already complete. A marker already present is left as it stands:
the create uses `O_EXCL` and treats `EEXIST` as success, so a pull over a commit
fsck marked keeps fsck's state byte, which is what the tool's `pull-local` does.

A pull that returns an error removes the markers it wrote for commits this
repository does not hold, leaving the destination as it stood. The objects of a
pull are published by its one transaction or by nothing at all, so a marker over
an absent commit guards nothing and nothing else reaches it: prune removes a
marker for a commit it prunes, and a commit that was never written is in no
doomed set. A commit this repository does hold keeps its marker -- that one was
partial before the pull ran, and fsck's state byte is in that file. The removal
is best-effort: a marker that cannot be unlinked stays, so the error the pull
reports is the one that ended it. Both pull paths do this, the HTTP path over
the markers its slots wrote (see 16c).

Marker durability follows the tool, which syncs neither the marker nor `state/`
on either side (both recovered by tracing its syscalls; see
`format-reference.md`). Every marker of a pull is written before the transaction
stages an object, so the `syncfs` that opens publication makes it durable ahead
of the first object rename, and the marker is on disk before any object of the
commit it guards. The removal is the pull's last operation with no barrier after
it, so a crash immediately after a successful pull can leave the marker on a
commit that is complete. That direction costs availability rather than integrity:
checkout refuses the commit, `commit_state` reports it partial, and the next pull
of that commit or a prune of it clears the marker. The durability of the create
rests on all marking preceding the transaction's first staged object, so moving
the marking into the import loop or into a second transaction would need an
explicit `fsync` of `state/` in its place.

Two divergences from the tool, both byte-for-byte irrelevant and both strictly
safer.

The first is bare-user to bare-user-only: the tool hardlinks a content object
from a bare-user source into a bare-user-only destination, which shares an inode
whose mode and `user.ostreemeta` xattr the destination mode does not describe, and
the result fails the tool's own `fsck` (verified by observation: `pull-local`
between the two modes, then `ostree fsck`, reports the imported object
corrupt; the tool takes the object with no flag given and whatever the source
object's mode and ownership). The port treats the two as different modes, so it
clones the payload onto a fresh inode carrying bare-user-only's own policy -- the
canonical mode and no xattr -- and refuses an object whose logical header is not
already that canonical form, since it would land under a name its stored form
does not hash to. What the port imports into a bare-user-only destination passes
its own `fsck` and the tool's.

The second is fs-verity. The tool hardlinks into a destination that seals its own
writes and leaves the imported objects unsealed (verified by observation on btrfs
with `ostree` 2026.1 built with `ex-fsverity`: a `bare-user` destination carrying
`[ex-integrity] fsverity=yes` takes 7 objects from a `pull-local` on the source's
own inodes, none of them sealed, while a commit written into that same repository
directly is sealed). A repository sealed in part is a repository whose integrity
guarantee holds only for the objects it happened to write itself, so the port
copies instead, as the bullet above describes.

No new crates: the import path is `rustix` `linkat`, `ioctl_ficlone`, and the
existing staging helpers.

Verify (`tests/pull_local.rs`, 38 tests): a ref, its commit, and its tree
arrive with nothing else, and a second pull imports nothing; an empty ref list
pulls every ref, including a `/`-bearing name; a remote name writes
`refs/remotes/<remote>/<ref>` and nothing under `refs/heads`; `depth` follows
parents and a parent the source lacks ends the chain without error; two refs on
one chain, the second three commits behind the first, collect the same commits at
`depth = 1` whichever order they are listed in, and neither order reaches past the
depth; a deep pull
lands both commits' trees whole, which is what the one-visit dirtree walk has to
enumerate from a chain whose commits share a subtree; a missing
ref fails before anything is imported. Import: a same-mode pull shares the
source inode for every object reached; `FORCE_COPY` produces fresh inodes whose
bytes and permission bits match the source and whose bare-user objects still
pass `fsck`, which is only possible if the clone carried the
`user.ostreemeta` xattr; an archive-to-bare-user pull lands the same checksums
and passes `fsck`. Inode policy on the paths a link does not take, each pinned by
drifting the source object's inode away from what a write produces and asserting
the drift does not arrive: a content object whose link `FORCE_COPY` refuses lands
the bare-user mode derived from its header with `user.ostreemeta` and without the
source's stray xattr, and a cloned metadata object lands the permission bits,
uid, and gid of an object the destination wrote itself. The ownership gate, with
the destination inside a setgid directory of a second group the process belongs
to, which is the group-shared arrangement: a bare-user-shared pull hardlinks
nothing and gives every object the destination's own uid and gid, while a bare
pull hardlinks every content object, whose ownership its header fixes, and clones
the metadata objects alone. The bare case also passes the tool's own `fsck` where
the tool is installed, which for bare mode recomputes each checksum from the inode
the link shared; the bare-user-shared case rests on the port's `fsck`, since the
tool refuses to open a repository of that mode. Both ownership tests need the
process to belong to a second group and skip where it does not, and between them
they are the whole of the gate's coverage, so `OSTRYA_REQUIRE_MULTIGROUP` turns
that skip into a failure; the CI job sets it, its runner belonging to several
groups.
Within the bare family: a bare-user to bare-user-only pull of a canonically
committed source gives each regular file a fresh inode holding the source bytes
under the canonical mode with no xattr, which the destination reads back as the
header the object is named for and which passes its `fsck`, while the same pull
from a source committed under the process's own ownership is refused with
`Error::Pull`, publishing no ref; a bare-user to bare-user-shared pull hardlinks the symlink object,
whose representation the two modes share, and clones the regular files, whose
inode mode they do not; a bare-split-xattrs destination is refused with
`Unsupported` on both import paths, the link path under a commit-only pull and
the clone path under a full pull of a branch whose tree is one regular file, each
publishing no object and writing no ref. fs-verity, on a filesystem that supports
it and skipped where it does not: a same-mode bare-user pull into a destination
carrying `fsverity=yes` lands every object sealed on a fresh inode, leaves the
source's objects unsealed, and passes the port's `fsck`, which the link path
cannot do. Free space, with the destination reserving the whole filesystem
through `min-free-space-percent=100`, which leaves a zero write budget: a
same-mode pull imports every object on the source's inodes and reports their
stored size in its statistics, while the same destination in archive mode, where
each content object is re-ingested, fails with `InsufficientFreeSpace`,
publishes no object, writes no ref, and clears the marker. State: `COMMIT_ONLY`
imports exactly
the commit object,
leaves a zero-length marker, and reports the commit partial, and completing the
pull clears it; a pull that reaches an absent source object publishes no
object, writes no ref, and clears the marker it wrote; a repair pull over a
commit fsck marked keeps that marker, state byte and all, since the destination
holds the commit. Trust and checks: a corrupt
content object and a corrupt commit object each travel on the trusted path and
each fail `UNTRUSTED` with `ChecksumMismatch`, with nothing published, and a
corrupt payload crossing the bare family behaves the same way on the clone path;
a corrupt payload crossing into archive, which is the re-ingest path, fails with
`ChecksumMismatch` and publishes nothing whether or not `UNTRUSTED` is set, which
is what lets the flag leave that path its own read;
a ref
binding that omits the pulled ref is rejected and `DISABLE_VERIFY_BINDINGS`
accepts it; a commit with no binding key is accepted; a world-writable mode is
rejected under `BAREUSERONLY_FILES` and by a bare-user-only destination under its
own rule, and accepted by an archive destination without the flag. Detached metadata travels
with its commit; a localcache repository supplies an object the source no
longer holds, and supplies a dirtree it no longer holds, whose subtree the walk
enumerates from the cache and imports whole, while the same pull without the
cache fails with `ObjectNotFound`, publishes no ref, and clears the marker. Three interop tests need the tool: the port pulls a tool-built
archive repository into an archive and a bare-user destination, and the tool
then resolves the ref, passes `fsck`, and reads the tree back; the port pulls
its own bare repository into a bare-user destination, where every regular file
crosses on the clone path, and the tool's `fsck` accepts what the destination's
inode policy wrote, which it can only do if the clone applied
`user.ostreemeta` from the object's logical header rather than reproducing the
source inode; and the tool's `pull-local` reads a port-written repository into a
bare-user destination that passes its `fsck`. Unit tests cover the refspec mapping and the flag bitset.

The CLI grows `ostrya pull-local`, with `--remote`, `--depth`,
`--commit-metadata-only`, `--untrusted`, `--bareuseronly-files`,
`--disable-verify-bindings`, `--force-copy`, and repeatable
`-L/--localcache-repo`. Equivalent pull-local conformance cases land in
`conformance/m10-cli-behavior.matrix` at the CLI-compatibility phase.

Deferred past 16b: the summary, mirror mode, and the timestamp checks land in
16c; delta-accelerated pull in 16d; GPG and sign-engine commit verification in
16e; collection refs, `refs/mirrors`, and subpath pulls are not yet scheduled.

#### Phase 16c -- HTTP pull (DONE)

`Repo::pull(remote, PullOptions)` fetches a set of refs, the commits they name,
and every object those commits reach from an HTTP remote, into one transaction.
What the transaction publishes, when the refs are written, and what the
`.commitpartial` markers mean is 16b's contract unchanged; the phase adds where
the objects come from and how many are fetched at once.
`Repo::remote_fetch_summary(remote)` reports the remote's `summary` and
`summary.sig` bytes on their own.

What a pull asks for, in the order it first asks: `summary.sig`, `summary`,
`config`, then the objects. A remote with no summary answers 404 and each
requested ref resolves through `refs/heads/<ref>` instead. A content object is
requested as `objects/<..>.filez` whatever the remote stores on its own disk,
since the framed, deflated form is the one an HTTP client can read; `config` is
fetched to establish that before the first object is requested, so a non-archive
remote is refused with `Unsupported` naming its mode rather than surfacing as a
404 on the first content object, and a remote serving no `config` is treated as
archive.

Concurrency. A pull holds up to `max_outstanding_fetches` (8) steps in flight,
each a future that fetches one object and stores it, over an in-tree poll core
(`pull/drive.rs`) rather than `FuturesUnordered`: `futures-lite` carries no
unordered join and `futures-util` is not in the graph. The plan the slots are
refilled from holds three classes, drained in this order and carrying the
matching fetch priority -- the commits (the tips, and their parents under
`depth`), the scan (dirtree and dirmeta), and the content (file objects). That
drain order is what orders a pull's requests: the fetcher admits as many requests
at once as the pull has slots and a slot has one fetch outstanding at a time, so
the admission gate a priority is weighed at never queues inside one pull. The
priority a class carries decides the order where a `Fetcher` is shared by more
callers than it admits. The
plan is owned by the loop, so it needs no lock, and nothing is spawned: the step
futures borrow the repository, the transaction, and the fetcher, so a failure
returns from the loop and drops every step still in flight, closing their
connections and releasing their fetcher permits. Above one slot the request order
is not fixed; the request set and the class order between them are.

A commit object is fetched before the objects it references, since its tree is
unknown until it arrives, and staged where it arrives: the write path hashes the
bytes there and compares the result against the name they were requested by, so a
commit stored under the wrong name fails the pull before its tree is asked for,
and nothing is held past the step. What covers a reader against a commit whose
tree is not yet complete is the commit's `.commitpartial` marker, written when the
commit is fetched and removed after the transaction publishes; publication renames
the staged objects in an unspecified order, so a staging order is not something a
reader observes. The markers a failed pull wrote for commits this repository
does not hold are removed on the way out, under 16b's rule, so a commit a later
step refuses leaves nothing behind. An object several commits reach is fetched
once. A commit already here complete has no object of its tree queued, since
what it references is present, and its parent is followed all the same, so a pull
extends the history a shallower pull left. A commit's `.commitmeta` is requested ahead of the commit object and written
once that object is here, so the detached metadata precedes the ref naming its
commit and a parent the remote answers 404 for leaves none behind; the file is
outside the transaction, so a pull that fails after a commit object landed leaves
the copy it wrote, which prune sweeps. Writing is throttled separately: a content step
takes one of three write permits once the response head has arrived and holds it
for the whole body -- the archive header read, the payload streaming into the
object store, and the read that settles the end of the stream. The header arrives
inside the first frame in the ordinary case, so what the permit spans beside the
payload is that frame and the byte that ends the stream. The permit is taken
before the body is read, which keeps a step waiting for one off the fetcher's
progress clock -- the distinction 16a recorded and deferred to this phase. A body
waiting for a permit holds what it has received unread, and over HTTP/2 that is
flow-control credit, which is why the connection window is one stream window per
admitted request: the credit a parked body holds is its own, and the metadata
stream a scan is blocked on receives over a window of its own.

Every fetched object is stored under the name it was requested by, and the write
path hashes what it stores and compares the result against that name, so
verification is inherent and there is no trusted variant: the write path cannot
store an object without naming it. The mode checks are 16b's, made over the
header a content object arrives with. The remote states that header's length
ahead of its bytes, so a length above 1 MiB is refused before the buffer for it
is allocated: a real header is a few hundred bytes, large xattrs put it at a few
kilobytes, and the receive path holds one header for each fetch in flight. The
local archive read path holds the same bound. A fetched metadata object -- a
commit, a dirtree, a dirmeta, or a `.commitmeta` -- is read whole, which is this
project's rule for metadata, under the format's 128 MiB cap
(`MAX_METADATA_SIZE`). The cap is applied to a declared `Content-Length` before
the body is read and to the bytes as they arrive, so an undeclared body stops one
frame past it. The buffer is sized from that declared length, one spare byte
above it so the read that finds the end of the stream does not grow it, which
holds the resident peak of one object to its own size instead of the capacity a
regrowing vector reaches. One such buffer belongs to each step in flight, which puts the
receive path's metadata ceiling at `max_outstanding_fetches` times the cap, 1 GiB
at the default 8; a local pull imports one object at a time, so its ceiling is
the cap itself. A slot holds kilobytes in practice: `ostree` 2026.1 writes a
118-byte commit and a 12-byte dirmeta, and a dirtree of a 10,000-entry directory
measures 710 KB, or 71 bytes an entry, so the cap stands as the format's ceiling.
That header also declares the
payload's uncompressed size, which bounds both sides of the stream. A payload that passes it
is refused with `InvalidFormat` naming the object, so the bytes written before the
checksum comparison at the end of the payload are bounded by what the object
declared. The compressed side is bounded against the same declaration, at
`declared + declared/1024 + 64 KiB`, and refused the same way: an empty non-final
DEFLATE block is five bytes that decompress to nothing, so the decompressed bound
alone leaves the time and the bandwidth of a pull to the remote, and the progress
deadline measures silence, which a stream that keeps delivering never falls into.
That bound sits under the decoder, in the read the decoder makes of its input,
because a decoder whose input keeps yielding does not return to its caller.
After the payload, a content step reads its response
to the end. One byte settles it, since nothing follows an object's final DEFLATE
block. That read returns the connection to the pool, so a pull reuses one
connection per slot rather than opening one per object; at one slot that is one
connection for the whole pull, and at the default eight it is up to eight, since
HTTP/1.1 carries one request at a time. Bytes after the payload are refused with
`InvalidFormat`, and a symlink's stored form is held to the same rule. A
localcache repository is consulted before the network, per object, through 16b's
import path with its checksum verified. Every content object reads through a
128 KiB buffer the loop hands to the step and takes back with its outcome -- the
payload of a fetched object as it streams into the object store, and the
verification of one a localcache repository supplied -- so a pull holds one such
buffer per slot whatever its objects come from. What one in-flight content object
allocates for itself is the 16 KiB read-ahead the decoder consumes its compressed
input through.

Refs and options. Each requested ref resolves against the fetched summary first
and then `refs/heads/<ref>`; a ref neither yields is `RefNotFound`. An empty ref
list takes every summary ref under `MIRROR` and the remote's configured
`branches` otherwise, each missing case failing with `Pull`. Every name is held
to the ref store's rule -- no empty, `.`, or `..` component -- where the targets
are resolved, whether it was requested, configured, or read from the summary, so
a malformed name fails before the first object request. The name reaches the wire
percent-encoded outside the unreserved set, `/` excepted, so a name carrying `%`,
`?`, or `#` asks for the ref rather than for an escape, a query, or a fragment. Refs are written to
`refs/remotes/<prefix>/<ref>`, where `prefix` is `PullOptions::remote` when set
and the remote argument otherwise, or as local refs under `MIRROR`; a mirror pull
of every ref also copies the remote's summary bytes verbatim to `<repo>/summary`,
and the `summary.sig` bytes with them, so a client pulling from the mirror with
`gpg-verify-summary=true` reads the pair.
`TimestampCheck` refuses a fetched tip strictly older than the commit the ref
currently names here (`CurrentRef`, where an absent ref passes) or than a given
commit (`Rev`), naming both revisions and both timestamps. The ref-binding check
and the timestamp check are made for every requested ref that names a commit, so
two refs at one commit are both checked while the commit is fetched once.
`PullOptions` grows
`url`, `http_headers`, `max_outstanding_fetches`, `n_network_retries`, and
`timestamp_check`; `config.rs` grows `Remote::branches` and the TLS keys
`tls-ca-path`, `tls-client-cert-path`, and `tls-client-key-path`, with
`tls-permissive=true` refused as `Unsupported` -- the fetcher has no way to skip
verification, and verifying anyway would misreport the configuration.
`summary.rs` grows `Summary::parse`/`Summary::lookup`, the read side ref
resolution needs.

Four fetcher changes carried in from the 16a review landed with the phase, which
is the first caller to exercise them.

- An attempt that ends on an unsuccessful status, or on a `Content-Length` over
  the request's cap, leaves a response body in flight. One whose declared length
  is at or below 64 KiB is now read to the end and its HTTP/1.1 sender returned
  to the pool before the attempt fails; a larger declared length, or none at all,
  closes the connection as before. A 404 is the ordinary answer for an object a
  remote does not hold, so without this a scan paid a connection setup per absent
  object.
- `handshake_h2` moved from the free `hyper::client::conn::http2::handshake` to
  `hyper::client::conn::http2::Builder`, which is what reaches
  `initial_stream_window_size` (2 MiB), `initial_connection_window_size`, and
  `keep_alive_interval`/`keep_alive_timeout` (15s each, both inside the
  60s progress deadline, so a peer that has gone away is reported by the ping
  rather than by a read that never returns). The builder needs a
  `hyper::rt::Timer`, which `fetch/io.rs` supplies over `rt::Deadline`. The
  connection window is the stream window times `max_outstanding`, capped at the
  protocol's 2^31 - 1 and 16 MiB at the default limit of 8: a receiver credits a
  window back when the data is consumed, so a stream whose body the caller has
  received and not yet read holds credit for as long as it is parked, and giving
  the connection the sum of the stream windows keeps that credit the parked
  stream's own. The cost is the data one connection may hold received and unread,
  which is that window.
- `put_h2` keeps a pooled HTTP/2 entry that is not closed, so the connection that
  loses a concurrent-connect race serves only the request that opened it instead
  of replacing an entry other requests are multiplexing over.
- One error rule for both exhaustion paths: whether a fetch runs out of mirrors
  or of rounds, it reports a definitive answer when it received one, and the
  first retryable failure otherwise. A definitive answer is what a caller acts
  on -- the HTTP pull reads 404 as absence for the summary, an optional parent
  commit, an absent `.commitmeta`, and the remote config -- so a retryable
  failure seen before it does not hide it. Among definitive answers the earliest
  is reported, which is the mirror order the fetcher honors everywhere else. The
  module doc states it.

One more change followed from the phase rather than the review: `attempt` boxes
the connect future. Opening a connection is the largest state a fetch holds --
the TLS handshake and hyper's own -- and the rarest, taken only when the pool has
nothing for the origin. Boxing it takes `Fetcher::fetch` from 76 KB to 6.6 KB,
which matters because a pull nests several helpers around one fetch and a debug
build overflowed a 2 MiB test stack without it.

Verify (`crates/ostrya/tests/pull_http.rs`, which serves a repository directory
from an in-process static file server over cleartext HTTP/1.1 and over TLS where
ALPN selects HTTP/2, using the committed fixture certificates): a ref, its
commit, and its whole tree arrive, the ref lands under `refs/remotes`, the
request order opens `summary.sig`, `summary`, `config`, and a second pull of the
unchanged ref stops after the commit's `.commitmeta`; the same pull over HTTP/2;
an archive remote into archive, bare-user, bare-user-only, and bare destinations,
each passing the port's `fsck` and reading its tree back, with the bare case
skipped off root since it writes each object's own uid and gid; the tool resolves
the ref, passes its own `fsck`, and reads the tree back out of a bare-user
destination the port pulled into; a symlink object and an xattr-bearing object
both cross; a remote with no summary resolving through `refs/heads/<ref>`, and a
ref neither source yields failing with `RefNotFound` before anything is fetched;
an empty ref list through `branches` and through mirror plus summary, and each of
the two failures; mirror mode writing `refs/heads` and copying the summary and
`summary.sig` bytes verbatim, a remote holding no `summary.sig` leaving the
destination's own file as it stands, and a mirror pull of named refs writing
neither file; `depth` following
parents, a 404 parent ending the chain without error and leaving no detached
metadata for the commit it does not hold, and a deep pull after a shallow one
fetching the parent the shallow pull left; a non-archive remote
refused on its config mode with nothing beyond the three root files requested; a
corrupt object failing with `ChecksumMismatch` and a missing one with
`ObjectNotFound`, each publishing nothing, the second clearing the marker it
wrote, while the same failure over a commit the destination already holds
partial keeps that commit's marker;
`COMMIT_ONLY` leaving a zero-length marker and reporting the commit partial,
which completing the pull clears; the timestamp check at older, equal, and `Rev`;
a bare-user-only destination refusing a non-canonical object and
`BAREUSERONLY_FILES` refusing a mode outside `0775`; a localcache repository
supplying an object the remote answers 404 for, where the same pull without it
fails; `max_outstanding_fetches = Some(1)` pinning the request order to the
plan's drain order, and the default limit reaching the same request set with more
than one fetch in flight; a connection cut mid-object failing the pull with
nothing published; a `tls-permissive` remote refused; and
`remote_fetch_summary` reporting both files. Unit tests cover `Summary::parse`,
the `.filez` stream parser, and the driver (slot refill from the plan, the first
ready slot returned, and an error dropping every slot still in flight). The
fetcher tests grew the drain-and-pool cases, the undrained-body case, and
priority ordering end to end through `Fetcher::fetch`. Equivalent pull
conformance cases land in `conformance/m10-cli-behavior.matrix` at the
CLI-compatibility phase.

Deferred: `contenturl`, `metalink`, and mirrorlists; subpath pulls; collection
refs and `refs/mirrors`; the summary cache under `tmp/cache/summaries/`; the
archive-to-archive pass-through, which is 16g.

#### Phase 16d -- Delta-accelerated pull (DONE)

A remote that publishes static deltas delivers a commit as one delta instead of
one request per object. `Repo::pull` looks for such a delta for each requested
tip, applies it into the pull's transaction through the Phase 15a read path, and
falls back to loose objects wherever a delta is not to be had. The write side of
the advertisement lands here too: the summary's `ostree.static-deltas` map,
deferred from 15b.

Which delta a pull takes. Exactly one candidate per tip: `<from>-<to>`, where
`from` is the commit the ref being pulled names in this repository, and the
from-scratch `<to>` where the ref names none. A from-to delta patches against the
source commit's objects, so the source commit has to be here complete; a ref
whose commit is absent or partial, or which already names the target, is read as
naming none. A repository holding the ref's commit therefore does not take a
from-scratch delta, which would re-deliver every object of the target including
the ones it holds -- what it is missing arrives loose instead. The tool was
observed to make the same single choice: a client holding the ref's commit
against a remote advertising only the from-scratch delta fetches loose, and a
fresh client against a remote advertising only the from-to delta does the same.

Where a delta is advertised, in the order a pull reads them:
`delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index` whenever the summary states
`indexed-deltas` (the default a summary that omits the key carries), then the
summary's own `ostree.static-deltas` map when the index answers 404 -- which is
what a repository holding deltas that was never reindexed serves. Both hold the
same thing, a delta name mapped to the SHA-256 of that delta's superblock. A
candidate the map does not name is not asked for. A remote serving no summary
advertises nothing and the superblock is requested by name, which the tool was
observed to do as well.

What is checked. A superblock the remote advertised a digest for is hashed and
compared against it before it is parsed, so a delta swapped underneath a signed
summary fails the pull with `ChecksumMismatch` and no part is fetched; the tool
refuses the same case with `error: Invalid checksum for static delta <name>`. The
parsed superblock has to name the commit being pulled and the source commit its
name claims. The delta's own signatures are checked next, over the raw superblock
bytes and ahead of any part request, so a delta that fails verification costs no
part bytes, which is the property the digest check has. That check is the seam
`verify_fetched_delta` in `crates/ostrya/src/pull/delta.rs`, whose policy Phase
16e supplies. Each part file is hashed against the superblock's entry for it, and
every object a part produces is written under the checksum the superblock names,
which is the read path's own rule. A superblock the remote does not hold is a
404: the advertisement is stale, and the pull fetches the objects loose.

What a part costs to receive. A part is fetched under the size its meta-entry
declares, so the fetcher refuses a `Content-Length` above that size before the
body arrives and stops a body that passes it as the bytes land; the offline path
reads the part file in under the same size. The part checksum is asserted over the
body before the xz decoder runs, so a body that hashes to anything else is refused
having written at most the declared size to the staging filesystem, and what the
payload expands to is bounded by a stream that hashes to the checksum the
superblock names -- a decompression bomb has to be one the delta's own publisher
wrote and advertised. Each part in flight therefore holds two blobs, the verified
body and the payload, each on the heap at or below the 128 KiB threshold and
spilled to a mapped temp file above it.

What a pull retains per delta, for the length of the pull: the target commit's
bytes, the per-part meta-entries, and the fallback list. The raw superblock bytes
and the signature array are read by the verification above and dropped there, so
what stays resident is proportional to the target commit's object count -- 33
bytes per object across the meta-entries -- rather than to the superblock size the
remote chose. A pull of N tips holds N such jobs at once.

A meta-entry's `size` is host order, which
the superblock's `ostree.endianness` byte declares: it is swapped where the byte
states `B` and read as little-endian where the byte is absent, which is what every
producer of these deltas writes. The `usize` field goes unread, since it counts
what the part's objects add up to rather than the size of the payload that carries
them.

A content object a part produces is held to the same mode checks a loose one is:
`BAREUSERONLY_FILES` bounds a regular file's logical mode, and a bare-user-only
destination takes only an object whose logical form is the one it stores. Both
read the mode and xattr tables the part carries, and both run before the object's
writer opens, so a delta delivers no object a loose fetch of the same object
would be refused and a refused object writes nothing. Offline application carries
no pull flags and makes the destination's check alone, which states a
bare-user-only refusal in the destination's own terms rather than as the checksum
mismatch the canonicalized write would produce.

`PullOptions` grows `disable_static_deltas`, which asks for no delta at all, and
`require_static_deltas`, which refuses a remote advertising none -- no summary, or
a summary with neither an index nor the delta map. A remote that advertises deltas
satisfies the requirement even where none of them produces the commit being
pulled, and that pull fetches its objects loose; this is the tool's own rule,
whose message names the same two sources ("no summary deltas or delta index
found"). A tip this repository already holds complete is not looked for, so a pull
with nothing to fetch is not refused, and `disable_static_deltas` wins over the
requirement, since a pull that asks for no delta finds none to require.

The plan grows a part class, drained after the commits and before the scan,
fetched at high priority, and held to two in flight whatever
`max_outstanding_fetches` is. Each part in flight costs an xz decoder, the
verified part body, and the decompressed payload, each blob spilling to a temp
file past its heap threshold, and the cap is the reference tool's own. The loop can therefore run out of work while
parts are queued, which is safe: a part is held back only when another is in
flight, and that one occupies a slot the loop is waiting on. Parts are applied as
they arrive rather than in part order, which the format allows -- a part patches
against the source commit's objects, present before the delta is applied, and
never against another part's output. The write throttle does not cover a part: by
the time a part is applied its payload is a local blob, and the cap of two is what
bounds concurrent part writers.

What a delta contributes to the plan. The target commit rides in the superblock
and is staged from there, so no `.commit` is requested; its `.commitmeta` travels
as it does for any commit. The objects the delta hands over loose are queued at
once, so they travel alongside the parts rather than after them. The commit's tree
walk is queued once the delta's last part is applied: it reads what the delta
staged, asks the network for nothing when the delta was complete, and fetches
loose whatever no part delivered. That is a divergence from the tool, which takes
the delta plus its fallback list as the whole of what a commit needs and does not
walk; the walk is what keeps this pull's invariant that a published commit is
whole. A commit-only pull takes no delta, since its plan is the commit objects
alone.

Summary write side: `ostree.static-deltas` maps each delta under `deltas/` to the
SHA-256 of its superblock, emitted between `ostree.summary.tombstone-commits` and
`ostree.summary.collection-map` and present only when the repository holds a
delta. The port emits the entries ordered by delta name. The tool emits them in
the order it walked `deltas/`, which is the order its filesystem returned -- shown
by four deltas of one target coming back in neither name order nor any other
stable one -- so the two writers agree on the entries of the map and not on their
order, and a summary carrying deltas is not byte-comparable against the tool's.

One capability difference: the tool refuses a delta-accelerated pull into an
archive repository (`error: Can't use static deltas in an archive repo`). The port
applies a delta into any destination mode, since its applier writes through the
transaction's content writer, which stores what each mode requires.

Verify (`crates/ostrya/tests/pull_http.rs`, over the same in-process file server
16c uses): a destination one update behind takes the from-to delta -- the index,
the superblock, and the part are requested, no `.commit` and no `.filez` are, the
`.commitmeta` still travels, and the commit is complete and passes fsck; that same
from-to shape into an archive, a bare-user, and a bare-user-only destination lands
the target commit whole and passes each destination's own fsck, the part copying
most of a 256 KiB edited file out of the source object that destination already
holds in its own storage form; a fresh
destination takes the from-scratch delta; a destination holding the ref's commit
leaves an advertised from-scratch delta alone and fetches loose; a remote with no
index falls back to the summary map; a remote with no summary is probed by name; a
stale advertisement falls back to loose objects; a superblock that misses its
advertised digest fails with `ChecksumMismatch`, leaves the ref where it was, and
fetches no part; `require_static_deltas` refuses a remote advertising none and
accepts one advertising a delta that does not cover the commit; `disable_static_deltas`
asks for neither the index nor a superblock; a multi-part delta (`max_chunk_size`
of one byte, one object per part) has every part fetched and applied; a delta
whose largest object went to a fallback has that object fetched loose; two
refs pulled in one call each take a delta of their own, whose overlapping trees
stage the same objects twice in one transaction and publish each once; and
`BAREUSERONLY_FILES` refuses an object a part delivers at mode `04755`, publishing
nothing, where the same delta pulled without the flag delivers that object and the
destination passes fsck; and a remote answering a part request with four times the
part fails the pull with `FetchTooLarge` at the size the superblock declares,
publishing nothing. Two interop
tests need the tool: the port applies a delta the tool generated and indexed, and
the tool's fsck and `cat` accept the result; and the tool pulls a delta the port
generated over the port's own server with `--require-static-deltas`, resolves the
ref, passes its own fsck, and reads the changed file back. Unit tests cover the
request paths, the delta names, the digest lookup, and the plan: a delta queues
its parts before its tree, the cap of two holds however many parts a delta has,
and a delta of fallbacks alone queues its tree at once. Three more cover what a
part is read under: a body past the size its meta-entry declares is refused at
that ceiling, carrying a checksum that covers the longer body so the size is what
stops it; a part declaring xz whose body is not an xz stream is refused for its
checksum, which places the check ahead of the decoder; and a meta-entry size reads
back in host order through the endianness byte, an absent byte included.
`crates/ostrya/tests/summary.rs`
covers the map: absent without deltas, naming a delta of each shape -- from
scratch and from a source commit -- each under its own superblock's digest,
positioned between `tombstone-commits` and `indexed-deltas`, and read back by the
tool's `summary --print-metadata-key`.

Deferred: inline delta parts, which no remote the port pulls from publishes.
`ostrya pull --disable-static-deltas` and `--require-static-deltas` landed with
the CLI command in 16f. The body of the delta signature check landed in 16e,
which supplies the policy the seam applies.

#### Phase 16e -- Signature verification during a pull (DONE)

A pull checks the signatures on the commits it carries and on the remote's
summary. `PullOptions` grows `verify: PullVerify`, four `Option<bool>` switches
that override the remote configuration keys of the same name; a switch left
`None` reads the configuration for `Repo::pull` and is off for
`Repo::pull_local`, which is the split the tool makes between `pull` and
`pull-local`. Every check takes its keys from a remote's configuration section,
so a local pull that asks for one and names no remote is refused before the
source is read, as the tool refuses `pull-local --gpg-verify` with no `--remote`.

Two axes, each independent of the other and each having to find a valid
signature where it applies.

- GPG, selected by `gpg-verify` (default true) for the commits and
  `gpg-verify-summary` (default false) for the summary. The trusted set is the
  remote's: the repository's own `<remote>.trustedkeys.gpg`, read through the
  repository descriptor, `/etc/ostree/remotes.d/<remote>.trustedkeys.gpg`, the
  global trusted directory Phase 13d already reads, and the keyrings
  `gpgkeypath` names. `gpgkeypath` is a `;`-separated list of keyring files and
  directories of `*.gpg` keyrings, added to the set rather than replacing it,
  and an entry that names neither a file nor a directory fails the pull rather
  than quietly reducing what is trusted. The tool was observed to do all four: a
  keyring imported with `remote add --gpg-import` lands in the repository as
  that file and accepts the commit it signed, an empty `gpgkeypath` directory
  alongside it leaves the import trusted, and `gpgkeypath=/nonexistent;<file>`
  fails with an `opendir` error.
- The sign api, selected by `sign-verify` for the commits and
  `sign-verify-summary` for the summary, both default off. Each value is a
  boolean in the key file's own spelling or a list of engine names split on `,`
  and `;`, a name taken as written -- the tool refuses `ed25519, ed25519`, whose
  second name carries the space. `true` selects every engine this build has,
  which is `ed25519` and, under the `sign-spki` feature, `spki`. Within the axis
  one engine reporting a valid signature is enough: the tool accepts a commit
  signed by ed25519 alone under `sign-verify=ed25519;dummy`. That value fails on
  the port, which leaves the dummy engine out of what `true` selects and out of
  what a name resolves to: the dummy signature is the bytes of the dummy key, so
  a commit held to it passes a check that read nothing. A name the value carries
  twice, which `remote add` writes for an engine given twice
  (`sign-verify=ed25519,ed25519`), builds one verifier, so each signature is
  held to that engine's keys once. An engine's trusted keys are its
  `verification-<engine>-key` (one base64 key, not a list, which the tool
  refuses) and every line of its `verification-<engine>-file`, plus the system
  sign-api key store, whose revoked set applies to all of them. The set left
  after the revoked set is applied is what decides whether an engine has a key,
  each engine by its own key equality, so an engine whose every key the store
  revokes has none. An engine the configuration names by hand and no source
  holds a key for fails the pull, which is the tool's "No keys found for
  required signapi type"; an engine reached by naming every engine is passed
  over instead, and only a policy left with no engine at all fails, which is
  the tool's "no keys loaded". The two switches are read separately:
  `sign-verify=false` leaves a `sign-verify-summary=true` check in place, which
  the tool was observed to do.

Where the checks run. The summary is checked as soon as it and its `summary.sig`
are here and before either is read, so a refused summary costs no object request
and no delta probe; a policy that applies needs both files, and a remote serving
neither is refused by name. A commit is checked in the step that fetched it,
after its detached metadata is here and before its bytes are staged or its tree
is asked for. That holds for whichever source supplied the bytes: a loose fetch,
a localcache repository the step imports the object from, and a delta superblock
each hand the bytes to the check first and stage them after it. Every commit a
pull carries is checked, the parents a depth pull follows included, and so is a
commit this repository already holds, since the pull's policy is what decides
rather than what an earlier pull accepted. The tool makes the same three
choices.

A local pull checks the summary and every commit of the chain before it opens
its transaction, so a source the policy refuses imports nothing at all. Such a
check binds to the source objects as they stand while it runs. The import reads
them a second time, a commit where it walks the tree and the `.commitmeta` where
it copies the bytes, and a trusted local import shares a source object by
hardlink or reflink without hashing it. A source rewritten between the check and
the import is stored as it stands at the import; a concurrent sign of the source
commit is the writer that replaces a `.commitmeta` in place. Carrying the checked
bytes to the import would hold one entry per commit of the chain, which a
`depth=-1` pull leaves unbounded, so the metadata is read twice.

What a commit is checked against is the detached metadata the pull puts in
place: the source's `.commitmeta` where one carries it, and this repository's
own where none does, which holds for a local pull and a pull over HTTP alike.
That is the metadata a later verify of the stored commit reads. A static delta
carries a copy of the commit's detached metadata in its superblock metadata,
under the key `deltas/<fanout>/<rest>/commitmeta`, and the tool checks a
delta-delivered commit against that copy while storing the `.commitmeta` it
fetched separately; a delta generated before a commit was re-signed therefore
fails a tool pull that the current `.commitmeta` satisfies. The port checks what
it stores. The port's generation writes that copy (Phase 15b), so a verifying
tool pull accepts a delta the port produced for a signed commit.

A fetched delta is held to the commit policy's sign-api axis, over the raw
superblock bytes, before any part is requested. A delta carrying no signature
under those engines is accepted: what it produces is named by the superblock, the
superblock is named by the advertisement the summary carries, and the commit it
delivers is checked like any other, so stripping a delta signature buys nothing.
A delta that does carry one has to have it from a trusted key. There is no tool
behavior to reproduce here: `ostree` 2026.1 cannot pull a signed delta at all,
failing with `error: Invalid checksum of length 0 expected 32` for a from-scratch
and a from-to delta alike, with verification configured or off, while
`static-delta apply-offline` applies the same delta.

Two more port rules with no tool behavior behind them. A remote the configuration
does not describe, which only the port can pull from (`PullOptions::url`), takes
the configuration defaults, `gpg-verify` among them, so such a pull states its own
policy or is refused. A build without the `sign-gpg` feature refuses a pull whose
policy asks for the GPG axis, naming the feature, rather than passing a commit it
did not check.

Config reading grows `SignVerify` and the `Remote` accessors `sign_verify`,
`sign_verify_summary`, `verification_key`, and `verification_file`;
`gpgkeypath` now reports the parsed list. `GpgVerifier::for_remote_keyrings`
takes the repository's keyring as bytes, which is what a caller holding a
descriptor rather than a path has.

Both axes read their keys through `rt::unblock`, so a path a configuration file
names holds a pool thread rather than an executor thread. Every sign-api key
file is read whole under one ceiling of a mebibyte -- some twenty thousand
base64 ed25519 keys: the `verification-<engine>-file` a remote names, and each
file of the system key store, which is the `trusted.<type>` and
`revoked.<type>` files and the entries of their `.d` directories. The path is
opened once and read through that ceiling, so the bytes the ceiling admits are
the bytes the keys come from, and a file that carries more fails by the file's
name. Only a regular file is read: a path naming a fifo, a directory, or a
device fails by name as well, since a fifo reports a length its content does
not have and reading one holds the pool thread until a writer opens it. The
system store's paths are root-owned, and it is read under the same rule as the
paths a remote names, so one rule covers every key source.

Every keyring file the GPG trusted set is built from goes through that same
reader, whichever source names it: the repository's own
`<remote>.trustedkeys.gpg`, the system
`/etc/ostree/remotes.d/<remote>.trustedkeys.gpg`, each `*.gpg` file of the
global trusted directory, and each `gpgkeypath` entry. A keyring's ceiling is
its own, four mebibytes, which holds thousands of exported certificates. A
keyring over it fails the pull by the file's name rather than being read in
part, since the part a ceiling admits is a trusted set the operator never
placed there; this is the rule `gpgkeypath` states for an entry that names
nothing. Only a regular file is read, since what a fifo answers a read with is
what its writers sent and an open fifo holds the reading thread until a writer
arrives. A symlink at a keyring's name is followed, which the
tool was observed to do: a destination whose `origin.trustedkeys.gpg` is a
symlink to an exported keyring accepts the commit that keyring's key signed, and
one holding no keyring at all refuses the same commit. The commit policy and the
summary policy take their keys from the same remote, so a verifier both ask for
is built from one read of its key sources and held by both.

Verify (`crates/ostrya/tests/pull_http.rs`, `pull_local.rs`, and
`pull_verify_gpg.rs`): an unsigned commit is refused under the default policy
and publishes nothing; `sign-verify` with the key that signed the commit accepts
it and another key refuses it; a `verification-ed25519-file` of several keys
accepts a commit any one of them signed, and an engine with no key at all is
refused; `sign-verify=true` accepts the commit the one configured engine's key
signed, and a name no engine answers to is refused; a summary another key signed
is refused with only `summary.sig` and `summary` requested, and a remote serving
no `summary.sig` is refused by name; a parent reached under `depth` is checked
and refused where the tip alone is signed; a commit this repository already
holds is checked again under a new policy; the options override the
configuration in both directions; a delta signed by a foreign key fails with no
part fetched and the same delta signed by the trusted key is applied; a local
pull checks nothing by default even where the remote it writes under asks for
both axes, checks the commits and the source's own summary when asked, and
refuses a check that names no remote. Behind the `sign-gpg` feature, over a
generated GnuPG home: the repository's `<remote>.trustedkeys.gpg` is what a
remote trusts, a symlink at that name is followed to the keyring it names, an
unsigned commit and one signed by another key are each refused, `gpgkeypath`
adds a keyring by file and by directory, and a `gpgkeypath` entry that names
neither fails the pull. One interop test needs the tool: it builds an archive
remote, signs the commit and the summary with ed25519, and the port pulls it
under a policy naming that key and refuses it under another. Unit tests cover
the `sign-verify` spellings, the switch resolution, how an unknown engine and an
engine with no key are told apart, that a configuration naming the dummy engine
is refused by that name, that an engine both targets ask for yields one shared
verifier, that an engine the value names twice builds one verifier, and that a
key file over the ceiling and a fifo at a key file's name are each refused by
that name, as are a repository keyring over its ceiling and a fifo at a
keyring's name. In `sign_ed25519.rs`, a key store file over the ceiling and a
fifo at a store file's name are refused by name as well, through the same reader
`load_sign_keys` reaches.

Deferred: `verification-<engine>-file` for an engine whose keys are not base64
lines, which no engine this build verifies with has; and the system sign-api key
store's participation, which is implemented but not observable on a host with no
`/etc/ostree` or `/usr/share/ostree`.

#### Phase 16f -- The `ostrya pull` CLI command (DONE)

The CLI grows `ostrya pull [OPTIONS] <REMOTE> [REFS...]`, which drives
`Repo::pull`. `<REMOTE>` names a `[remote "<name>"]` section of the destination's
config and is also the prefix the refs are written under; naming no ref takes the
remote's configured `branches`, or every ref its summary lists under `--mirror`.
The command prints the line `pull-local` prints, which reports what the pull
imported.

The options and the `PullOptions` field each sets:

- `--repo <PATH>` -- the destination, defaulting to the working directory, as
  every other subcommand takes it.
- `--url <URL>` -- `url`. A remote the config does not describe is reachable this
  way. Such a remote supplies no keys and takes the configuration defaults,
  `gpg-verify` among them, so a pull naming one states its own policy or is
  refused.
- `--mirror`, `--commit-metadata-only`, `--bareuseronly-files`,
  `--disable-verify-bindings`, `--force-copy` -- the `PullFlags` bits of the same
  names. `UNTRUSTED` has no switch: an HTTP pull hashes every object it stores
  whatever the flag says, and the localcache import it reaches sets the bit
  itself.
- `--depth <N>` -- `depth`, defaulting to 0.
- `-L`/`--localcache-repo <REPO>`, repeatable -- `localcache_repos`, opened in the
  order given.
- `--http-header NAME=VALUE`, repeatable -- `http_headers`. The value splits at
  the first `=`, so a header value carrying one arrives whole.
- `--max-outstanding-fetcher-requests <N>`, `--network-retries <N>` -- the two
  fetcher limits, each left at the library's default when absent.
- `-T`/`--timestamp-check` and `--timestamp-check-from-rev <REV>` -- the two
  `TimestampCheck` variants, which conflict with each other since the field holds
  one. A refspec resolves against the destination; a bare checksum is taken as
  given, and the destination's own check applies when the pull loads the commit
  to compare against.
- `--disable-static-deltas` and `--require-static-deltas` -- the pair 16d
  deferred here. They do not conflict: the library states that disabling wins,
  since a pull that asks for no delta finds none to require.
- `--gpg-verify[=BOOL]`, `--gpg-verify-summary[=BOOL]`, `--sign-verify[=BOOL]`,
  and `--sign-verify-summary[=BOOL]` -- the four `PullVerify` switches. Each takes
  an optional value after `=`: absent is `None` and reads the remote's
  configuration, the bare switch is `Some(true)`, and `=false` is `Some(false)`.
  That is the tri-state the field holds, which a plain on/off flag cannot express.
  Turning a sign-api switch on here selects every engine the build has, as
  `sign-verify=true` does.

Verify (`crates/ostrya-cli/tests/cli.rs`): every test serves a repository
directory over HTTP/1.1 from a static file server the test file builds on
`std::net::TcpListener`, one thread per connection so a pull holding several
fetches at once is served without ordering them; the server records the path and
the header lines of each request it answers, which is what the request-set
assertions read. A configured remote pulls a named ref, prints the stats line,
writes the ref under the remote's name, and checks out the tree the fixture
committed, with an `--http-header` value reaching every request; `--url` against a
destination whose config describes no such remote is refused and publishes
nothing, and the same pull with `--gpg-verify=false` lands the ref; `--mirror`
naming no ref writes a local ref and copies the remote's summary byte for byte;
`--depth=-1 --commit-metadata-only` imports both commits of a chain, leaves each
marked partial, and fetches no content; a second remote publishing the same branch
at an earlier timestamp is refused under `-T`, which leaves the ref where it was,
and lands when the switch is absent; a remote publishing an indexed delta is
pulled through its superblock with nothing fetched loose, the same remote under
`--disable-static-deltas` is pulled loose with no superblock fetched, and a remote
advertising no delta is refused under `--require-static-deltas`; `-L` naming a
repository that holds everything the commit reaches leaves the network unasked for
any content object; and a signed commit is accepted by a destination configured
with the key that signed it, refused by one configured with another, and accepted
by that second destination when `--sign-verify=false` overrides it. The suite runs
under both runtime backends.

Deferred: `--subpath`, `--dry-run`, and `--cache-dir`, which name machinery the
library does not have; the `--gpg-verify` and `--gpg-verify-summary` switches on
`ostrya pull-local`, which the library accepts and the CLI does not yet pass;
`PullOptions::remote`, the ref-prefix override `pull-local` exposes as
`--remote`, which has no switch on `pull` since the positional `<REMOTE>`
supplies the prefix; and the `ostree`-compatible spellings, exit codes, and
progress output, which are Phase 17.

#### Phase 16g -- Archive-to-archive pass-through (DONE)

A content object arrives deflated and reaches the object store through
`ContentWriter`, which digests the bytes written to it. An archive destination
deflates those bytes again at its `[archive] zlib-level`, so a pull from an
archive remote into an archive repository inflates the payload and compresses it
a second time.

The stored object is correct: the checksum covers the framed uncompressed header
and the raw uncompressed payload, so the compressed form carries no part of the
identity. Two consequences follow from the second compression.

- Deflate costs about ten times what inflate costs, so the recompression is the
  larger part of the CPU a full-tree pull spends per object.
- The stored bytes differ from the bytes the remote holds. A byte-level
  differential mirror reports every content object as changed. The tool copies
  the fetched bytes to disk unchanged: an `ostree` pull between two archive
  repositories was measured with `cmp` and reproduced all four content objects
  byte for byte, where the port reproduces only the objects small enough for any
  deflate encoder to agree on.

The phase adds a pass-through path for an archive destination. The fetched bytes
go to the staging file as they arrive. A second branch inflates them to feed the
digester, so the object is still stored under a name the write path hashed. Both
branches read bounded chunks, so the receive path stays streaming.

Two points of design:

- `ContentWriter` digests and compresses one stream. The pass-through needs a
  sink that writes one stream and digests another.
- The header is stored as the remote wrote it, including the uncompressed size it
  declares, rather than patched at `finish`. The receive path treats that
  declaration as a ceiling, so the pass-through has to hold it to equality.
  Otherwise a stored header can declare a size its own payload does not have.

Verify: an archive remote pulled into an archive destination reproduces every
`.filez` byte for byte, against a remote the port built and a remote the `ostree`
tool built; the destination passes `fsck` and the tool reads its tree; a payload
whose declared size does not match what it inflates to is refused; a bare-family
destination still stores the inflated payload.

### Phase 17 -- `ostree`-compatible CLI (`ostrya-cli`)

Incremental, driven by which conformance cases are targeted; extends the
Phase 11 `ostrya` binary. Command-line and stdout/stderr compatibility with
the `ostree` tool for the exercised subcommands (commit, checkout, refs,
rev-parse, ls, cat, show, log, config, prune, fsck, summary, sign, gpg-sign,
static-delta, pull, pull-local, remote, init, export, diff). The upstream
shell test suite is part of libostree's LGPL source distribution and stays
out of scope like the rest of that source: it is never read, run, or
vendored (see CLAUDE.md, "Licensing and clean-room discipline"). In its
place, Phase 17 grows `conformance/m10-cli-behavior.matrix`, a family in the
same interoperability-matrix system as `m0`/`m1`, authored from black-box
observation of the `ostree` tool, executed by the record-driven runner
`conformance/harness.md` specifies.

The command-surface scope is stated in `conformance/cli-surface.md`, which
lists the absent commands, the missing options on the commands that exist,
the global option conventions, and the output formats still to be recovered,
ordered by what each unblocks. `init` is the one gap that blocks the
interoperability harness outright.

The phase is split into sub-phases so each is independently reviewable; the
split follows `cli-surface.md`'s own ordering, with the matrix and its runner
moved to the front (17a) so every later sub-phase has a Verify gate to grow
against, matching this phase's "incremental" framing. A sub-phase whose scope a
completed one uncovered is numbered after it rather than renumbering what
follows: 17b1 holds the `commit` parenting divergence Phase 17b's own fixtures
exposed.

#### Phase 17a -- `init`, global `--repo` conventions, and the matrix harness (DONE)

`ostrya init --repo=PATH --mode=MODE --collection-id=ID` wires the already
existing `Repo::create`. The accepted `--mode` values are `archive`,
`archive-z2` (an alias, always serialized back as `archive-z2`), `bare`,
`bare-user`, `bare-user-only`, and the port extension `bare-user-shared`;
`bare-split-xattrs` is excluded, since the port reads that mode and does not
write it. An unrecognized mode is rejected with the tool's own text, `error:
Invalid mode '<mode>' in repository configuration`, and exit 1, before
anything is written.

`--repo`, `-v`/`--verbose`, and `--version` are global `clap` options
(`global = true`), so each is accepted both before and after the subcommand
name; the subcommand-position value wins when both are given, matching the
tool. With no `--repo`, the current directory is used when it opens as a
repository, else `OSTREE_REPO`; with neither, the failing subcommand's usage
text and `error: Command requires a --repo argument` go to standard error and
the process exits 1 -- the same shape the tool uses, though the port's usage
text is `clap`'s own rendering, not byte-identical to the tool's GOption text.
The tool's chain carries a third step, stated in its own `--repo` help text and
quoted in `conformance/cli-surface.md`, "Global conventions": with no `--repo`,
no current-directory repository, and no `OSTREE_REPO` that opens, it resolves
the compiled-in `/sysroot/ostree/repo`, an `OSTREE_REPO` naming a path that
does not open leaving that chain running. A repo-less tool invocation on an
ostree-managed host therefore resolves the system repository, and a writing
subcommand acts on it. The port's chain ends at `OSTREE_REPO` and resolves no
third source, which keeps `ostrya` from acting on a live system repository
through an omitted `--repo` and costs `ostrya prune` an explicit `--repo` where
`ostree prune` needs none on an ostree-managed host. The port holds this
divergence by intent.
`init` shares this precedence rather than special-casing it: a cwd/
`OSTREE_REPO` target that already opens as a repository is reused (an
idempotent re-init, matching `Repo::create`); one that does not falls through
to the same usage-text-plus-error form, so `init` never creates a brand-new
repository except at an explicit `--repo`. Every top-level error, including a
`clap` argument-parsing failure, prints with an `error: ` prefix and exits 1
(`-h`/`--help` still exits 0). A nested subcommand left unnamed
(`static-delta` with no list/apply-offline/generate/reindex) is optional at
the `clap` layer and is checked in the port's own dispatch, before the
repository resolves, matching the tool's order: it prints `static-delta`'s
usage text and `error: No command specified` and exits 1, for every
combination of the global options and whether or not a repository could have
resolved. Leaving the check to `clap` would hold only for the argument-free
form, since `clap` reports a missing subcommand under one error kind when the
command level received no argument at all and under another when a global
option accompanied it.

For `export`, `diff`, `sign`, `pull`, and `pull-local`, the repo check also
comes before the check for each subcommand's required positional operand,
matching the tool: the positional is optional at the `clap` layer and is
checked, with the tool's own message, only once the repository has resolved
(`error: A COMMIT argument is required` for `export`; `error: REV must be
specified` for `diff`; `error: Need a COMMIT to sign or verify` for `sign`;
`error: REMOTE must be specified` for `pull`; `error: DESTINATION must be
specified` for `pull-local`). `checkout` is not fixed the same way: the tool
defaults its second positional, `DESTINATION`, from `COMMIT` rather than
requiring it, a distinct behavior `cli-surface.md`'s "Global conventions"
records but the port does not yet reproduce.

Two observed tool quirks are recorded in `cli-surface.md` and not reproduced:
the leading (pre-subcommand) `--repo` accepts only the `=`-joined form on the
tool (`ostree --repo R` fails, `ostree --repo=R` works), while the port
accepts both forms in both positions; and reusing an existing repository
through the cwd/`OSTREE_REPO` fallback for `init` crashes the tool with
`error: Key file does not have key "collection-id" in group "core"` when
that repository's config has no `collection-id`, even though the identical
reuse through an explicit `--repo` succeeds -- the port's fallback and
explicit-`--repo` paths share one idempotent `Repo::create` call, so both
succeed uniformly.

`conformance/m10-cli-behavior.matrix` is the new record family: a cell is one
CLI invocation, stated by `subcommand`, a `cell` identifier tail, a `setup`,
the `run` line itself, its `expect-*` claims, and the shared
`outcome`/`oracle`/`spec` fields, documented in `conformance/README.md`'s
"Families" and "M10 record format" sections.

`crates/ostrya-conformance` is the runner `conformance/harness.md` specifies:
a workspace member building a library and a standalone binary, with `rustix`
as its one dependency. The record is the program -- the runner reads the
invocation, the setups, the oracles, and the expected results from the
record, gives each implementation its own scratch subtree, runs the line in
both, compares the artifacts the `oracle` field names, and reports one of
pass, fail, or skip-with-reason per cell. A cell the run could not observe
reports as skipped and never as a pass, so a machine with no `ostree`
installed reports `skip: reference-absent` for every cell that needs the
tool; `--require tool=ostree` turns those skips into failures where the tool
is installed. Two cells vary the working directory and the environment, which
a `run:` line does not state, so each names a registered probe.

Verify: `cargo test --workspace --all-features` runs two new test targets and
one new unit test. `crates/ostrya-conformance/tests/check.rs` statically
validates all three record files (63 records, 300 cells) and needs no binary.
`crates/ostrya-cli/tests/conformance.rs` runs the T0 selection against the
`ostrya` binary this workspace builds, and against `ostree` 2026.1 where it is
installed: all twelve M10 cells pass, and the remaining 288 cells report as
skipped: 150 as declarations, 31 filtered out by the T0 tier selection (cells
whose corpus needs a higher tier, declarations in substance), and 107 as
proved elsewhere by a library test. The unit test in `main.rs` holds the
subcommand names the error paths render usage text by against `clap`'s own
set, in both directions, so a renamed or an added subcommand fails a test
rather than the name lookup on an error path.
The twelve: `init` creates a repository in `bare`, `bare-user`,
`bare-user-only`, `archive`, and `archive-z2`, with the `config` bytes of the
two implementations compared byte-for-byte for each; the two archive spellings
state between them that the port normalizes each one the way the tool does,
`format-reference.md` being what states that the normalized value is
`archive-z2`;
`init --mode=bare-user-shared` is accepted by the port, with
`ref-run: n-a` recording that the tool has no such mode value (its refusal to
open the result is `m1-operate.matrix`'s D2 direction); an unrecognized mode
is rejected by both with the same standard-error text and exit 1 (that
neither leaves a repository behind is an observation the record notes, not a
claim its oracles state, since no oracle reads an absence); `--repo` before
the subcommand, after it, and via `OSTREE_REPO` all resolve the same
repository, for both implementations; a trailing `--repo` wins over a leading
one, confirmed for both through `export` reading the marker of the second
repository; `static-delta` with no nested subcommand reports the missing
subcommand, and not the unopenable `--repo` it was also given, for both; a
subcommand with no `--repo`, no `OSTREE_REPO`, and a non-repository current
directory gets the usage-text-plus-error form from both; and `init`'s
cwd/`OSTREE_REPO` reuse succeeds idempotently for both on a repository
carrying a `collection-id`, with the config untouched.

#### Phase 17b -- `refs`, `rev-parse`, `cat` (DONE)

The three subcommands, over `Repo::list_refs`, `Repo::list_mirror_refs`, and
`Repo::resolve_rev`, with their exact output text recovered by observation and
recorded in `format-reference.md`, "CLI output formats".

- `refs`: the default listing, `--list`, `--delete`, `--create=NEWREF`,
  `-r/--revision`, `-A/--alias`, `-c/--collections`, `--force`, and the
  `PREFIX` positional, which the tool takes one or more of. The default
  listing covers `refs/heads` and `refs/remotes`, the latter named
  `remote:name`, sorted together by refspec. A `PREFIX` keeps the refs equal
  to it or nested under it and strips it from the printed name, an exact match
  printing the whole refspec; `--list` suppresses the stripping. More than one
  prefix groups the output in argument order. Each prefix is validated as a
  refspec where it is taken, in every listing form and in `--delete`, so a name
  the ref rule refuses ends the invocation and a valid prefix ahead of it keeps
  the rows it printed and the refs it deleted. A prefix passing that rule names
  the path a listing enumerates, and a path running through a ref file ends the
  invocation the same way, which is the tool's own `ENOTDIR` refusal. A
  whole-remote prefix -- a
  `<remote>:` prefix whose ref half is empty or `.` -- selects every ref of that
  remote, and where it matches one a `--delete` is refused and removes nothing,
  which is the tool's outcome for the name its own join builds. An alias holds
  the ref it names in place: a `--delete` prefix matching a ref under
  `refs/heads` that an alias names reports the tool's own `Ref '<refspec>' has an
  active alias: '<alias>'` and removes none of what that prefix matched, per
  prefix, reading the link body as a name from the `refs/heads` root and taking
  no part under `-c`. With `-A` a `--delete` is an alias-only delete: each
  prefix removes the set a `-A` listing prints for it, the ref the prefix names
  exactly or the aliases nested under it, and the prefix rules, the whole-remote
  refusal, and the alias guard all read that set. Under `-c` a `--delete` prefix
  is a collection id, and the id equal to the repository's own `collection-id`
  removes the refs under `refs/heads` alone, keeping the mirror refs that carry
  that id.
  `--create` wins over `--delete`
  and `-c` wins over `-A`, matching the tool. With `-A`, `--create` writes an
  alias under `refs/heads` and refuses a NEWREF naming a remote with the tool's
  own `Cannot create alias to remote ref: <remote>`, at the tool's own step:
  after the three checks every NEWREF takes and before the positional resolves.
  The target is then checked for being an existing ref, the tool's fifth step,
  which reports `Cannot create alias to non-existent ref: <rev>` and stands ahead
  of ref-name validation, so a refused target draws that line and no
  `Invalid refspec` one.
  Under `-c`, `--create` takes a
  `<collection-id>:<ref>` NEWREF and writes
  `refs/mirrors/<collection-id>/<ref>`, validating the pair shape and the
  collection id in the tool's own words and at the tool's own steps.
- `rev-parse`: the `REV` positional, which the tool takes one or more of, and
  `-S/--single`, whose count is over the commit objects in `objects/`.
- `cat`: `COMMIT` and one or more `PATH`, streaming each file's content
  through `FileObject::write_to` so no payload is buffered whole, and settling
  the async writer over the duplicated stdout descriptor before returning, so
  no tail stays in the backend's hands at process exit.

The library gained what the three needed and no more: `Repo::resolve_rev` now
takes a trailing run of `^` characters, each stepping one generation back
along `parent` (`Error::NoParentCommit` names the root commit it stops at), and
reads a 64-character name as a checksum in lowercase hex alone, through
`Checksum::from_hex_lower`, so an uppercase or mixed-case name of that length is
a refspec, which is the tool's own split at every site a revision or a NEWREF is
taken; the lenient `Checksum::from_hex` stays where a checksum arrives as stored
bytes, which is ref file content and delta metadata
(`format-reference.md`, "Revision syntax");
`Repo::list_remote_refs` and `Repo::list_ref_aliases` list what `list_refs`
does not reach; `Repo::check_refs_path` probes the path a listing prefix names
below `refs/`, one fd-relative `statat` reporting the `ENOTDIR` the CLI renders;
`Repo::set_ref_alias_immediate` writes an alias symlink whose
body is the relative path from the alias's own directory to its target;
`Repo::set_collection_ref_immediate` mirrors `set_ref_immediate` for a
collection ref; and `FileObject::write_to` streams a payload into a writer,
leaving the writer unflushed, since a sink takes as many payloads as its owner
sends it and a framing or compressing sink emits on a flush, so the flush
belongs to the caller. Every ref mutation settles its name as
well as its content: under `[core] fsync` the directory holding the ref is
`fsync`-ed after a write's rename, after an alias rename, and after a removal's
unlink, where the tool syncs the ref file alone
(`format-reference.md`, "Object store layout").
The CLI's shared `resolve` helper now reports a resolution failure in the
tool's own words (`Refspec '<rev>' not found`, `Commit <checksum> has no
parent`), which every subcommand taking a revision inherits. A revision that
resolves and names a commit the store does not hold is neither of those two: it
reaches the object read and carries the library's own `object not found: Commit
<checksum>`, where the tool names the loose object file
(`cli-surface.md`, "P1"). `refs --create`
resolves NEWREF through the same wording, and refuses a NEWREF ending in `^`
with `Invalid refspec <NEWREF>`: a ref name carries no ancestry suffix, and
that is the message the tool gives the same name at its own write path. A name
the ref rule refuses carries the tool's words too: the library reports it as
`Error::InvalidRefspec`, holding the refspec as given, and the CLI renders that
one variant as `Invalid refspec <refspec>` wherever a revision, a NEWREF, an
alias target, or a `commit -b` branch reaches the library. `refs --create`
validates NEWREF at the tool's own step, after the existence check and before
the positional resolves, so `--create=a/../b --force nosuch` reports the name
and not the unresolvable revision. The existence check resolves NEWREF as a
revision whatever `--force` says, and `--force` suppresses the refusal a
resolved NEWREF draws, so `--create=NAME^ --force` reports `Commit <checksum>
has no parent` where NAME's base is a root commit. `commit -b` carries a
write-side guard for each of the two shapes the revision syntax shadows: a
branch name of 64 lowercase hex characters is refused with the tool's own `Rev
name '<name>' looks like a checksum`, and one ending in `^` with `Invalid
refspec <name>`, the words `refs --create` gives that same shape, since
resolution reads the first as a checksum and the second as ancestry, and no
revision would reach the commit either ref holds (`format-reference.md`,
"Revision syntax"). Both run at the ref write, after `--parent` resolves and
after the tree is read, and abort the transaction, so the port publishes
nothing. The tool refuses the checksum shape at that same step and the ancestry
shape a step earlier, reading the branch name as a revision ahead of the tree
and parting three ways over the base it names, one of the three a signal
(`cli-surface.md`, "P2").

Two harness changes came with the phase. The `checksum-agreement` oracle
resolves through `rev-parse` when the invocation printed no checksum, which is
what `harness.md` said Phase 17b would complete. The `refs-bytes` oracle now
rewrites the checksum a ref file holds the way the text oracles do -- the
bound `$REV` becomes the placeholder and any other checksum is masked --
because each side's setup commits with its own binary and neither passes a
timestamp, so two raw checksums never compare until `commit --timestamp`
lands in 17c.

Eighteen tool behaviors are recorded and deliberately not reproduced, listed in
`cli-surface.md`, "P1": the tool names an `-A` alias under
`refs/remotes/<remote>/` by its path below the remote, dropping the remote, and
removes each alias a `-A --delete` prefix reached by that same name, so a prefix
under `refs/remotes` removes no alias of that remote and removes a local ref
carrying the name instead where one exists, where the port removes the alias the
prefix named; it writes the `remote:name` refspec as the link body where an
`-A --create` target lives under `refs/remotes`, so its own `rev-parse` and its
own default listing stop on an alias it wrote itself, where the port writes the
path to the target ref's file and both implementations resolve it; it
names each ref a whole-remote `PREFIX` selects by joining that prefix's ref half
with the name below it, so the `.` of the join stays in what `--list` and `-A`
print and in the refspec a `--delete` is then refused on, where the port prints
the refspec and names the prefix as given; where one `--delete` prefix matches
more than one ref an alias names, it reports the pair its own enumeration reaches
first, which is neither refspec nor directory order throughout, where the port
reports the first in refspec order, and it removes the members of a refused
prefix's selected set that same order reached ahead of the guarded one, where the
port removes none of what that prefix matched; a
single dangling alias fails every invocation whose enumeration reaches it, its
listings and its `--create` writes alike; an invalid
collection id aborts it on a GLib assertion or is rejected outright; a GLib
assertion line precedes its `Invalid ref name (null)` where a `-c --create`
NEWREF holds no ref name; a self-referencing symlink makes `cat` die on a
signal; `refs --create=NEWREF`
dies on a signal where NEWREF ends in `^` and its base names no ref; an empty
refspec searches the ref store, so it resolves against a one-ref repository and
reports `Refspec  not unique` against a larger one where the port refuses the
name; a ref name that names a directory under `refs/` draws three messages from
the tool, two of them naming a ref read in directory order or its own temporary
file, where the port reports one, and the tool's `--create` scans for a ref below
the name under `refs/heads` alone, so it replaces an empty directory, a directory
holding directories alone, and any directory under `refs/remotes` or
`refs/mirrors` with the ref file and removes the refs below it, where the port
refuses every one; a ref name whose path under
`refs/` runs through a ref file draws the path and the syscall from the tool
(`openat(refs/heads/plain/x): Not a directory`) wherever the name is resolved or
written, and `open(O_TMPFILE): Not a directory` under `-c --create`, where the
port reports the one message it gives that condition, and as an `-A --create`
target either shape draws the tool's own `Cannot create alias to non-existent
ref: <target>`, its existence check standing ahead of the name at that one site;
a refused `PREFIX`
carries the
tool's `Listing refs: ` context prefix, where the port reports the refspec
rule's one message and agrees on everything else; a `PREFIX` whose path under
`refs/` runs through a ref file draws the path and the syscall from the tool
(`fstatat(refs/heads/plain/x): Not a directory`), where the port reports the one
message it gives that condition and agrees on the exit status, the standard
output, and the refs tree; a revision resolving to a commit the store does not
hold draws `No such metadata object <checksum>.commit` from the tool, naming the
loose object file, where the port reports `object not found: Commit <checksum>`,
the one message the library gives any absent object, so the wording for the other
object types belongs with the phase that lands the commands reading them; a ref
file holding a checksum in any rendering other than the 64 lowercase hex
characters is refused by the tool wherever that ref is resolved, with `Invalid
character '<byte>' in rev '<content>'`, where the port's reader takes either case
and resolves it, and only an out-of-band write puts such content there, both
implementations writing the lowercase form; an
abbreviated commit checksum resolves anywhere a revision is taken; and a ref
name is validated against a character class narrower than the port's, so a name
of that shape draws `Invalid refspec <name>` from the tool wherever it is taken
as a revision or a NEWREF and `Refspec '<name>' not found` from the port at a
resolution site, which is
what `rev-parse <name>~1` and `rev-parse <name>^2` report, the tool's ref
enumeration skips such a name without a word, so its `prune --refs-only` deletes
the commit that ref holds, and the tool holds such a name to name no ref as an
`-A --create` target, where the port writes the alias. The last two are
resolution behaviors that would change every subcommand at once, so they
belong with a phase that reviews those paths. Building the fixtures also found
three `commit` divergences recorded under "P2": the parent `ostree commit -b
BRANCH` takes from the branch tip, which Phase 17b1 below reproduces; the
checksum arm of the branch-name guard leaves the tool's
tree and commit objects in `objects/` where the port publishes none, the tool
having written them before it reads the name; and the ancestry arm draws one
message from the port and three outcomes from the tool -- `Commit <checksum> has
no parent` over a root commit, the port's own `Invalid refspec <name>` over a
commit holding a parent, and a signal over a base naming no ref -- with a tree
path that does not open reported by the port and never reached by the tool.

Verify: `cargo test --workspace --all-features` is green, `cargo fmt --all
--check` and `cargo clippy --workspace --all-features --all-targets` are
clean. `crates/ostrya-conformance/tests/check.rs` validates 146 records and
383 cells. The T0 selection through `crates/ostrya-cli/tests/conformance.rs`
passes 77 cells where Phase 17a passed 12: 65 new M10 cells covering the
listing forms, the PREFIX validation a listing and a `--delete` share, the
create and delete paths and their nineteen refusals, the
`rev-parse` forms and their seven refusals, the `cat` forms and their eight
refusals, the two shapes `commit -b` parts a 64-character branch name into, and
the two bases a `commit -b` ancestry name the tool reaches no crash on carries.
Eighteen cells state a case the `repo-with-commit` setup cannot bind --
a nested ref name, an alias, a collection id, a parent chain, a NEWREF holding
an ancestry suffix, the collection-ref create forms, the symlink path edges,
the refused-name forms, the refused PREFIX forms, the PREFIX paths that run
through a ref file, the whole-remote PREFIX in
a listing and in a `--delete`, the `--delete` alias guard, the alias-only
`-A --delete`, the own-collection-id `-c --delete`, an absent commit read
through a ref, the case rule of a 64-character name over the repository's
own commit, and the bases a `commit -b` ancestry name needs a commit and a tree
to reach -- and cite the
`crates/ostrya-cli/tests/cli.rs` test that builds the repository and compares
the port to `ostree` 2026.1 over it, invocation by invocation:
`refs_listing_matches_the_tool` (30 invocations),
`refs_refuses_an_invalid_prefix`,
`refs_refuses_a_prefix_through_a_ref_file`,
`refs_whole_remote_prefix_matches_the_tool`,
`refs_alias_matches_the_tool`, `refs_delete_alias_guard_matches_the_tool`,
`refs_delete_aliases_matches_the_tool`,
`refs_delete_collection_own_id_matches_the_tool`,
`refs_collections_match_the_tool`,
`refs_create_ancestry_suffix_matches_the_tool`,
`refs_create_collection_matches_the_tool`,
`rev_parse_ancestry_matches_the_tool`, `absent_commit_object_matches_the_tool`,
`checksum_case_matches_the_tool`, `cat_path_resolution_matches_the_tool`,
`invalid_refspec_matches_the_tool`, and
`commit_ancestry_branch_name_matches_the_tool`, with
`commit_checksum_branch_name_matches_the_tool` beside them for the branch-name
guard's other arm, which two cells state and no cell cites. Each compares the exit status,
standard output, and standard error verbatim, both implementations reading one
repository where the invocation mutates nothing and a byte-identical copy each
where it does; the alias test also pins the remote-alias divergence in both
directions, and the whole-remote test pins the tool's joined names and the
refusal each side reports for a `--delete`. The alias-guard test holds the whole
message where one alias names one matched ref and stops at the guard's words
where a prefix matches more than one, the pair named following each
implementation's own enumeration order. The alias-only delete test compares the
two selections over one prefix and pins the remote-prefix divergence, including
the local ref the tool's own name reaches. The own-collection-id test compares
the own id, a foreign id, both together, and an id no ref carries over a
repository holding both sources of a collection ref under its own id, with the
`-c` listing that reads them and the three narrower repositories the rule's
edges need: the own id with no local ref, a local ref carrying a mirror ref's
name, and no `collection-id` at all. The absent-commit test holds each side's own
message over `cat`, an ancestry suffix on the absent checksum, and the same
revision read through a ref `--create` wrote, and compares the three sites that
take a checksum without reading it. The checksum-case test compares the uppercase
and mixed-case forms of the repository's own commit at every site a revision is
taken, the ref an uppercase NEWREF writes and the revision, the alias, and the
delete guard that then read it, the lowercase NEWREF the existence check reports
as existing, and the two divergences the rule leaves: the tool's `--parent`
reading its value with the parser that refuses a non-lowercase rendering, and
that same parser refusing ref file content the port's reader resolves. The
branch-name test holds the guard's whole message and the untouched refs tree,
pins the object residue that parts the two, states the two faults that stand
ahead of the guard in each implementation's own words, and commits the four other
64-character shapes -- one character short, one long, one outside the hex class,
and an uppercase and a mixed rendering -- reading each side's own checksum out of
its own ref file, since neither passes a timestamp. The ancestry test holds the
port's one message against each of the tool's four readings of the base -- the
signal over a base naming no ref, `Invalid refspec ` over an empty base, `Commit
<checksum> has no parent` over a root commit, and the agreeing `Invalid refspec
main^` over a commit holding a parent -- states the fault order ahead of the
guard, holds the interior `^` the guard does not cross, and pins the destructive
class the guard stands for: over a ref of the refused shape, which an
out-of-band write now places, the tool's `refs` prints nothing and its `prune
--refs-only` removes the commit that ref holds. The refused-name test also holds the alias
target: ten shapes the ref rule refuses draw the tool's own non-existence line in
both implementations, a target whose path runs through a ref file and one naming
a directory draw that line from the tool and the port's i/o message, and a target
the tool's character class refuses leaves the port writing the alias where the
tool refuses. The two prefix-refusal tests assert
each side's own message, the two wording them differently, and compare the exit
status, the standard output, and the refs tree.
`cat_streams_a_large_payload_in_every_mode` commits a 5 MB
pseudo-random payload into `archive`, `bare-user`, and `bare-user-only` and
holds what `cat` writes to the source bytes, with the tool reading the port's
own repository where it is available, so the streaming claim carries a guard
that runs with no reference tool present.
`crates/ostrya/tests/commit.rs`, `ref_writes_run_under_both_fsync_settings`,
runs the ref write, the alias write, the removal, and a transaction's ref write
under `fsync=true` and `fsync=false`, which pins the directory each sync opens,
and `resolve_rev_reads_a_checksum_in_lowercase_hex_alone` pins the case rule at
the library boundary: the lowercase form resolving to itself, the uppercase and
mixed forms reported as missing refs, a ref carrying such a name resolving
through its file, and ref file content still read in either case.
A renamed library test cannot void
the cells that cite it silently either: the workflow runs
`ostrya-conformance check --verify-evidence` as a step of its own
(`conformance/harness.md`, "Cargo and CI wiring").

#### Phase 17b1 -- `commit` parenting (DONE)

A behavior fix rather than an option gap, found while building the Phase 17b
fixtures. `ostree commit -b BRANCH` parents the new commit on that branch's
current tip, which `rev-parse REV^` reads today and `log` (17d) reads next. The
whole behavior is recorded in `format-reference.md`, "CLI output formats", under
`commit`; the values `--parent` takes still part the two implementations and stay
in `cli-surface.md`, "P2".

Observed with `ostree` 2026.1, and reproduced:

- `-b BRANCH` with no `--parent` takes that branch's current tip as the
  parent. A branch that does not exist yet gives a root commit, so the first
  commit onto a fresh branch is unchanged. The tip is read from the ref file and
  not loaded, so a ref standing over an absent commit object is inherited unread.
- `--parent=none` asks for a root commit on a branch that has a tip. The ref
  still moves to the new commit.
- `--orphan` gives a root commit the same way, and additionally permits a
  commit with no `-b`. Its `--help` line reads "Create a commit without writing
  a ref", which describes the no-`-b` case: with `-b` given, the ref moves to
  the new commit and the suppressed parent is the whole observable effect, and
  the branch-name guard 17b landed still refuses a name of 64 lowercase hex
  characters under it. An explicit `--parent` beside `--orphan` parents the commit
  on the value given, so `--orphan` suppresses the implicit parent alone.
- A commit that names no branch still carries `ostree.ref-binding`, as an empty
  `as` array, so the key is present whether or not a branch was named. The port
  writes the array the same way, which is what keeps the two commit checksums
  equal for that form.
- `--parent` takes a 64-character lowercase checksum or the literal `none`. An
  abbreviated checksum and a refspec are both rejected with `error: Invalid rev
  <value>`, an uppercase rendering with `error: Invalid character '<byte>' in rev
  '<value>'`, and the checksum's existence is not checked -- a `--parent` naming
  no object commits successfully. The port resolves a refspec here too, which
  stays a superset of the tool's syntax the way the leading `--repo` form is
  (17a), so this sub-phase added `none` and narrowed nothing. A 64-character
  uppercase value is a refspec to the port, by the case rule 17b landed, and
  `NONE` is one for the same reason, so both refuse either value and word the
  refusal differently (`cli-surface.md`, "P2").
- A commit with neither `-b` nor `--orphan` is refused: `error: A branch must
  be specified with --branch, or use --orphan`. Adopting the refusal is the one
  thing this sub-phase took away, and it is what makes `--orphan` mean something
  rather than being a synonym for the default. The check stands ahead of
  `--parent`, ahead of the tree, and ahead of any object publication, so the same
  line answers a commit whose `--parent` does not resolve and one whose tree path
  does not open.

The parent is read before the transaction publishes, so the tip a commit
inherits is the one its own ref write then replaces. A branch name the guard
refuses is not read as a tip at all, which leaves that refusal the message and
the position 17b gave it: the ref write, after the tree.

Deliverables: the implicit parent in `ostrya commit`, `--parent=none`, `--orphan`,
the `-b`-or-`--orphan` requirement, the `ostree.ref-binding` array a commit that
names no branch carries, the observations folded into `format-reference.md`, "CLI
output formats", and `m10` records for each.

Three of the tool's options read the parent as well and stay with the phases
that own them:

- `--keep-metadata=KEY`, which copies one metadata key from the parent, and
  `--skip-if-unchanged`, which compares the tree against the parent's: both
  17f.
- `--bind-ref=BRANCH` and `--no-bindings`, which write the ref bindings and
  leave the parent alone: 17f. The branch-name guard does not reach the binding:
  `commit --bind-ref=<64 lowercase hex>` writes that name into `ostree.ref-binding`
  at exit 0, so the tool guards the ref it writes and not the name it records
  (`cli-surface.md`, "P2").

One harness change came with the records. A cell committing onto the setup's own
branch needs both the repository the setup populated and the tree it committed,
which is `setup: repo-with-commit tree`; the corpus has one path per side, so the
two setups now share the tree the first of them materialized. A second
materialization over one path fails at the corpus symlink, so the sharing is
what lets one record name both setups (`conformance/harness.md`, "Setups and
placeholders").

Verify: `cargo test --workspace --all-features` is green, `cargo fmt --all
--check` and `cargo clippy --workspace --all-features --all-targets` are clean.
`crates/ostrya-conformance/tests/check.rs` validates 159 records and 396 cells.
The T0 selection through `crates/ostrya-cli/tests/conformance.rs` passes 83 cells
where Phase 17b passed 77: six new `run:` cells covering the refusal a commit that
names no branch draws, the checksum `--orphan` prints with no ref beside it, the
ref move each root-commit form leaves, the branch-name guard standing under
`--orphan`, and a `--parent` naming no object. Six more cells state a parent,
which a second invocation reads, and cite
`ostrya_cli::cli::commit_parenting_matches_the_tool`: the implicit parent, the tip
inherited unread over an absent commit object, the two root-commit forms, the
explicit `--parent` beside `--orphan`, and the empty `ostree.ref-binding`. A
seventh `evidence:` cell states the order the branch check holds, which three
invocations of the cited test carry. That test commits under one
`SOURCE_DATE_EPOCH` on both sides, which the tool honors, so each compared
checksum states the whole commit object -- the `parent` field included -- and not
that a commit happened; it walks the chain two commits onto one branch leave,
inherits the tip a ref standing over an absent commit object holds, holds the root
commit each suppressing form gives with the ref moved, reads the empty binding
back out of the port's own commit with the tool, and holds the refusal over three
invocations that state its order. `rev_parse_ancestry_matches_the_tool` drops its
`--parent` and keeps passing, which is the regression this sub-phase exists to
prevent, and `checkout_roundtrips_and_matches_tool` states its round-trip with
`--parent=none`, the branch it commits onto twice now holding a tip.

#### Phase 17c -- `commit`/`checkout`: the corpus-priority option gaps (DONE)

Exactly the flags `cli-surface.md` orders first because the interop corpora
need them: on `commit`, `--owner-uid`, `--owner-gid`, `--timestamp`,
`--no-xattrs`; on `checkout`, `-U/--user-mode`, `--subpath=PATH`.

Deliverables: the six flags, each backed by library surface Phase 7
already has (ownership override, `CommitOptions` timestamp, the
`SKIP_XATTRS` modifier flag, bare-user checkout, a tree-lookup-scoped
checkout).

Two of those five library pieces were not in fact there. The commit modifier
carried no ownership override, so `CommitModifier` gains `owner_uid` and
`owner_gid`, applied after the canonical-permissions reduction and ahead of the
callbacks, in both ingest walks (the filesystem walk and the overlay merge). And
the tar import took no modifier at all, so `TarImportOptions` gains
`owner_uid`, `owner_gid`, and `skip_xattrs`, which is what lets the three
tree-shaping options reach the tar stream `commit` reads from standard input;
`--canonical-permissions` reached the filesystem walk alone until Phase 17f's
`F4`, which converged the port's stdin form with the tool's `--tree=tar=PATH`.

Each option's accepted values and refusals are the tool's, recovered by
observation and recorded in `format-reference.md`, "CLI output formats":

- the declared ids read as a C `int` with the base taken from the text, so
  `0x2a`, `053`, and `42` are ids and `abc`, `5x`, and a trailing space are not;
  the default is `-1`, so any negative value declares nothing. The two refusal
  texts are GLib's, typographic quotes included, and they are reported while the
  options are read -- ahead of the repository, which the port reproduces by
  reading the ids in the dispatch arm before `resolve_repo`;
- a non-zero declared id beside `--canonical-permissions` is refused, naming the
  option whose id it read, after the missing-branch check and ahead of the tree;
- `--timestamp` wins over `SOURCE_DATE_EPOCH` and is read after the tree opens,
  so a tree path that does not open is reported and the timestamp is not. The
  port's reader takes `@SECONDS` and an absolute date and time carrying a UTC
  offset, which is a subset of the tool's natural-language reader: the local-time,
  relative, and empty forms would need a time-zone database or a date-phrase
  reader, and are refused with the tool's own `Could not parse '<value>'`. The
  divergence is recorded in `cli-surface.md`, "P2". A pre-epoch instant is
  recorded as the unsigned field's two's-complement form, matching the tool for
  `@-1` and for `1969-12-31T23:59:59Z`.

`checkout -U` exposed a library defect the phase fixes: the unprivileged mask was
`perm & 0o777`, where the tool drops the setuid and setgid bits and keeps the
sticky bit on a regular file it writes (`perm & 0o1777`). Recovered by checking a
tree of seven special-bit modes, on files and on directories, out of four
repository modes with `checkout`, `checkout -U`, and `checkout -U -C`. A regular
file the checkout hardlinks instead adopts the object inode's mode, so a
`bare-user` object's sticky bit is absent from a hardlinking unprivileged checkout
and present in the same checkout forced to copy -- the tool's own outcome, which
the port now shares.

Verify: `cargo test --workspace --all-features` passes, with eight new tests.
`ostrya::checkout::a_user_mode_checkout_keeps_the_sticky_bit_of_a_written_file`
holds the corrected mask in `archive`, `bare`, and `bare-user` without needing
the tool, and fails against the old one.
`ostrya_cli::cli` gains `commit_flags_reproduce_the_fixture_id` (the fixture
generator's own command line -- declared ownership, no xattrs, and a fixed
timestamp -- reproduces the golden commit id, where `--canonical-permissions`
stood in for it before),
`commit_ownership_and_timestamp_flags_match_the_tool` (seven option sets over a
tree carrying xattrs, a symlink, and a nested directory, each side's checksum
compared),
`declared_ownership_is_one_commit_across_modes`,
`commit_refuses_the_values_the_tool_refuses` (nine refusals, text and exit status
compared against the tool),
`commit_tar_stream_honours_the_tree_options`,
`checkout_user_mode_and_subpath_match_the_tool` (six forms across `archive`,
`bare-user`, and `bare`, destination trees walked file for file), and
`checkout_refuses_a_subpath_that_names_nothing`; `main.rs` gains unit tests for
the two readers.

In the matrix, `commit --timestamp` is what opened the `checksum-agreement`
oracle: every setup that commits now states `--timestamp=@1700000000`, so the two
sides reach one checksum, and thirteen new `m10` cells state the options
directly. Corpus `C3` stops being a declaration -- `archive` and `bare-user`
compare checksums against the tool through a `commit --owner-uid --owner-gid`
run line, `bare-user-only` does the same and keeps its `lossy` read-back, and
`bare-user-shared` cites the cross-mode identity test, the tool having no way to
open that mode. `C3`'s `bare` cell stays a `needs-priv` declaration, its
unprivileged half now recorded: both implementations refuse the chown at exit 1
and leave nothing behind. `checkout -U` and `--subpath` cite the test that walks
both destinations, no oracle reading a cell's own checkout destination, and the
subpath refusal runs as a cell. An M10 record may now name the one repository
mode its invocation needs, which the declared-ownership cells use to ask for
`archive`, ownership on a `bare` object inode needing root. The run reports 413
cells, 100 pass, 0 fail, where it reported 83 passes before the phase.

One finding outside the phase's scope came out of building its tests, recorded in
`m0-content.matrix`'s `C4` row and left undecided: an xattr whose value is zero
bytes long is recorded by the port and dropped by the tool, so the object
checksums part for any tree carrying one. The loss is at ingest alone -- the
tool's checkout writes such an xattr back out of an object that holds one -- and
it reaches `archive`, `bare`, and `bare-user` alike. Deciding what the port
records touches the ingest path, so it wants a phase of its own.

#### Phase 17d -- `show`, `log`, `ls`, `config get`, and the GVariant text-form printer (DONE)

The GVariant text-form printer is its own distinct deliverable inside this
sub-phase, flagged separately in `cli-surface.md` as easy to overlook: it
reproduces the tool's GLib "print" convention (type annotations, the byte
array literal form, nested containers) for `show --raw`,
every `show --print-*` form, and `summary --raw`. It belongs in
`ostrya-gvariant`, next to the `Value` type it prints, since the convention
is GVariant's own rather than ostree-specific, matching that crate's
"no ostree knowledge" charter. Recovered fact by fact against the tool's
output across every metadata object type in the fixture set, with the
recovered rules landing in `format-reference.md`.

`show --print-variant-type=TYPE` reads any file as a value of a named type, which
made the tool a byte-exact oracle for the printer: one hand-written serialized
value per rule of the form, rather than only the metadata objects a repository
holds. The recovered rules are in `format-reference.md`, "The GVariant text
form". Two of them were not in the plan's picture. A byte array whose last byte
is the only NUL it holds prints as a bytestring literal, `b'user.foo'`, with C
escaping and octal for every byte outside printable ASCII, where every other byte
array prints as `[byte 0x01, 0x02]`; the rule reaches real metadata, since an
xattr name is stored NUL-terminated and a 64-byte ed25519 signature whose last
byte happens to be zero prints as a bytestring too. And the string form escapes
differently from the bytestring form -- one string holding the same bytes is
`'a"b'` and `b'a\"b'` -- so the two literals needed separate escapers.

Floating point was outside the deliverable at this point: `ostrya-gvariant`'s
`Type` modelled the type set the on-disk format uses -- booleans, bytes, `u`,
`t`, strings, variants, arrays, tuples, and dict entries -- and `d`, `i`, `n`,
`q`, `x`, `o`, `g`, and the maybe types sat outside it. Phase 17f brings them
in, `commit --add-metadata` being a path that writes them into a commit's
metadata dict (item `F2` in `phase-17-cli-conformance-plan.md`).

The byte order turned out to be part of the printer's contract. The on-disk
format places its numeric fields in the variant already big-endian while the
framing stays little-endian, so a parsed value holds each numeric field
byte-reversed and one byteswap of the whole tree recovers the numbers the fields
state. That swap is what `-B/--no-byteswap` suppresses, so `Value::byteswapped`
landed beside the printer. `-B` also proved to mean more than its name: it turns
the raw report on by itself, and unlike `--raw` it leaves a commit's own report
in place after the variant line.

One library addition came with the phase: `Repo::commit_sizes`, which totals a
commit's `ostree.sizes` metadata and counts the recorded objects absent locally,
since `--print-sizes` reports both figures and the CLI holds no `ostree-core`
dependency to unpack the entries itself.

- `show`: `--raw`, `--print-related`, `--print-variant-type=TYPE`,
  `--list-metadata-keys`, `--print-metadata-key=KEY`, `--print-hex`,
  `--list-detached-metadata-keys`, `--print-detached-metadata-key=KEY`,
  `--print-sizes`, `-B/--no-byteswap`, `--gpg-homedir=HOMEDIR`,
  `--gpg-verify-remote=REMOTE`.
- `log`: the default form, a parent-chain walk through the existing
  `Repo::load_commit` (no reachability traversal needed), and `--raw`.
- `ls`: `-d/--dironly`, `-R/--recursive`, `-C/--checksum`, `-X/--xattrs`,
  `--nul-filenames-only`, over the existing `RepoTree::read_dir`/`lookup`.
- `config get`, over the existing `RepoConfig`/`KeyFile` read accessors.
  `config set`/`unset` landed in 17e, with the config-write path they need.

Deliverables: the GVariant printer and `Value::byteswapped`
(`ostrya-gvariant`), `Repo::commit_sizes`, `show`, `log`, `ls`, `config get`,
and their output-format recovery folded into `format-reference.md`.

Three tool behaviors are observed and deliberately not reproduced, each recorded
in `cli-surface.md`, "P1": a variant type outside the codec's set, a second
`OBJECT` operand, which the tool reads the first of and ignores the rest, and the
instant a GPG signature was made, which the tool renders through gpgme in the
host's locale and time zone and the port renders in UTC. Everything else in the
signature report -- the algorithm, the short key id, the user id, and the three
verdict lines -- agrees. Two more facts came out of the comparison: `show`'s
absent-object line carries an `Opening content object <checksum>: ` prefix in
every mode but `archive`, and `config`'s operand-count check stands ahead of the
operation name with a one-operand allowance for everything except `set`.

Verify: `cargo test --workspace --all-features` is green, `cargo fmt --all
--check` and `cargo clippy --workspace --all-features --all-targets` are clean.
`crates/ostrya-gvariant` gains five printer tests holding each recovered rule of
the text form -- the annotation placement, the two empty-container forms, the
bytestring rule with its octal escapes, the string escapes, the lone dict entry's
comma, the dirmeta and xattr forms whole, and the byteswap over every numeric
field -- and they fail against the rules the phase started from.
`crates/ostrya-cli/tests/cli.rs` gains seven tests. `show_and_ls_report_the_fixture`
holds the recursive listing, the commit report, and a symlink object's report to
their text without the tool present. `variant_text_matches_the_tool` runs fifty
hand-written serialized values, and one path that does not open, through
`show --print-variant-type`, comparing the port against the tool for each, which
is the printer's oracle. `show_forms_match_the_tool` compares twenty-eight
invocations, thirty-six metadata-key forms over twelve keys, and the seven
observed precedence pairs, over a repository the tool builds with the options the
port's own `commit` does not carry yet -- a body, an empty subject, a `version`
key, metadata of every type, and recorded sizes. `log_forms_match_the_tool`
compares seven invocations: the walk, the raw form, an ancestry suffix, and the
note a parent whose commit object was removed draws.
`ls_forms_match_the_tool` compares twenty-two invocations, adding three more where
the host lets an xattr be set, and `config_get_matches_the_tool` twenty over the
value forms GKeyFile escapes and every refusal.
`show_print_related_lists_each_pair`
assembles a commit carrying two related entries through the library, which no
`commit` option writes, and reads it back with both.
`show_refuses_a_variant_type_the_codec_does_not_hold` states the one divergence
without the tool.

In the matrix, `m10-cli-behavior.matrix` gains forty-eight records: eighteen for
`show`, four for `log`, twelve for `ls`, and fourteen for `config`. The
T0 selection through `crates/ostrya-cli/tests/conformance.rs` reports 461 cells,
148 pass, 0 fail, where it reported 413 cells and 100 passes before the phase.
`crates/ostrya-conformance/tests/check.rs` validates 225 records and 461 cells.

#### Phase 17e -- `config set`/`unset`, `remote` (excluding cookies), `gpg-import`/`gpg-list-keys` (DONE)

New library work, not just CLI wiring:

- `ostrya-core`'s `KeyFile` gains an unset/remove operation and a
  serializer that round-trips a file it did not fully rewrite (preserves
  groups and keys it did not touch); `ostrya`'s `Repo` gains a durable
  config rewrite (tmpfile, fdatasync, rename), matching the durability
  conventions the rest of the write path already follows.
- `remote add/delete/list/show-url/refs/summary`: `add`/`delete` mutate a
  `[remote "name"]` group through the same config-write path; `refs` and
  `summary` reuse the pull machinery's existing remote resolution against a
  live remote.
- `gpg-import`/`gpg-list-keys`: thin wrappers over the `gpg` subprocess
  plumbing `gpg.rs` already runs for signing and verification, importing
  into or listing a remote's `trustedkeys.gpg`.
- Excluded: `remote add-cookie`/`delete-cookie`/`list-cookies`. `fetch.rs`
  currently refuses any `Cookie` header at construction whenever a mirror is
  cleartext `http`, as a deliberate choice (a cookie's value is a secret
  regardless of what it holds). Cookie-jar support needs its own design
  discussion against that existing refusal before it gets a phase slot; it
  carries no matrix weight (`cli-surface.md` P3), so it is left out of this
  decomposition rather than decided here.

Deliverables: `KeyFile` unset and serialization, `Repo`'s config rewrite,
`config set`/`unset`, `remote add/delete/list/show-url/refs/summary`,
`gpg-import`/`gpg-list-keys`.

`KeyFile`'s serializer already round-tripped a document it did not fully
rewrite, so the phase added the two removers beside its setters:
`remove_key`, which keeps an emptied group's header the way the tool keeps
it, and `remove_group`. `Repo::write_config` writes the document through the
same root-file writer `summary` uses (a temporary file at mode `0644`,
`fdatasync` under `[core] fsync`, rename, directory sync). It writes what it
is given and leaves the calling handle's parsed configuration alone: reading
back needs a reopen. Validating the document instead would have refused
`config unset core.mode`, which the tool accepts, and the port has no reason
to guard a key the operator named.

`remote refs` and `remote summary` read a live remote through the
`Repo::remote_fetch_summary` the pull path already carried, which had no
caller until now. Reporting a summary needed the per-ref detail the parser
had been dropping: `Summary::refs` is a `SummaryRef` per entry, carrying the
commit size and the per-ref metadata dict beside the name and the checksum,
and `Summary::collection_map` reads the refs of every collection
`ostree.summary.collection-map` lists. The report's byte order is per field,
not per document: `Last-Modified` and each `Timestamp` are stored big-endian
and are converted, and every other metadata value prints as stored, so a `t`
a caller set through `--add-metadata` reads as the number it holds. `--raw`
and `--print-metadata-key` take the blanket byteswap `show --raw` takes
instead, which is why one summary reports `uint64 8502796096475496448` for a
118-byte commit in `--raw` and `Latest Commit (118 bytes)` in the report.
The report prints an unannotated value where `--print-metadata-key` prints an
annotated one, so `ostrya-gvariant` gained `to_text_unannotated` beside
`to_text`.

`gpg-import` and `gpg-list-keys` run `gpg` in a private scratch directory:
the import stages the remote's current keyring, imports the offered keys into
it, and reads the count of new keys out of the `IMPORT_RES` status line,
which is what the tool's own `Imported <n> GPG key(s)` reports; the listing
parses a `--with-colons` key listing. A `KEY-ID` selection exports each named
key out of a second scratch keyring, so a selector naming nothing is refused
by name; each selector stands after a `--` terminator, so gpg reads it as a key
name rather than as one of its own options. `remote delete` removes `<remote>.trustedkeys.gpg` with the section,
through `Repo::remove_remote_keyring`.

Four facts the option help does not state came out of the comparison, and are
recorded in `format-reference.md`, "CLI output formats": `--no-sign-verify`
writes `gpg-verify=false` as well as `sign-verify=false`; a remote name takes
an alphanumeric or `_` first and then alphanumerics and `-`, `_`, `.`, so `_`
is a name and `-`, `.`, and `..` are not; `remote list` sorts by name whatever
order the sections appear in, and `-u` pads each name to the longest name of
the whole list plus two, counted in bytes; and the `metalink=` URL prefix
names its own key while a `mirrorlist=` prefix stays in the `url` value.

Five divergences are recorded in `cli-surface.md`, "P3", none of them a
repository fact: the tool's `remote` container accepts no `--repo` of its own
where the port accepts one in every position; an unknown nested subcommand
draws clap's own text; `remote delete` removing the document's last section
leaves the tool one trailing blank line and the port none, both reparsing
equal; `--sign-verify=spki=...` is refused by the tool's build and accepted by
the port's `spki` feature; and `gpg-list-keys` leaves out the two Web Key
Directory URL lines and renders the creation instant in UTC, the same locale
and time-zone divergence the GPG signature report in "P1" already carries.
`remote refs`/`summary` also drop `--cache-dir`, and the port's fetcher reads
`http` and `https` where the tool also reads `file://`.

Verify: `cargo test --workspace --all-features` is green, `cargo fmt --all
--check` and `cargo clippy --workspace --all-features --all-targets` are
clean. `crates/ostrya-core` gains five `KeyFile` tests holding the removers
and the rewrite rule; `crates/ostrya-gvariant` one printer test holding the
unannotated form; `crates/ostrya` one summary test for the retained per-ref
detail, three `gpg` tests for the import count, the key listing, and the
colon-field unescaping, and one `repo` test holding the config rewrite -- the
document, the file mode, the stale handle, and the keyring removal. `crates/ostrya-cli/tests/cli.rs` gains four tests.
`config_set_and_unset_match_the_tool` runs twenty-four invocations, each side
against its own repository, comparing both streams, the exit status, and the
two `config` files byte for byte. `remote_add_and_delete_match_the_tool` runs
twenty-nine the same way, the name rule and the existence rules among them,
has each implementation list the remotes out of the other's file, and states
the one delete divergence there. `remote_refs_and_summary_match_the_tool` serves a
repository over HTTP and compares fifteen invocations under `TZ=UTC`.
`remote_gpg_keyring_round_trips_with_the_tool` imports one keyring into each
implementation's repository, states that each reads the keyring the other
wrote, that a key imported by the port verifies a commit the tool's own
`gpg-sign` signed with it, and that deleting the remote takes its keyring with
it.

In the matrix, `m10-cli-behavior.matrix` gains thirty records net: eleven for
`config set`/`unset`, replacing the placeholder record 17d left for the
not-yet-implemented operations, and nineteen for `remote`, four of them citing
`evidence:` for the cases one invocation cannot state. The T0 selection
through `crates/ostrya-cli/tests/conformance.rs` reports 491 cells, 173 pass,
0 fail, where it reported 461 cells and 148 passes before the phase.
`crates/ostrya-conformance/tests/check.rs` validates 255 records and 491
cells.

#### Phase 17f -- the remaining P2 option gaps

Everything `cli-surface.md`'s P2 section lists that 17b1/17c/17d/17e do not
already cover: the rest of `commit`'s and `checkout`'s missing options,
`export --no-xattrs/--subpath/--prefix/-o`, the remaining `prune`, `fsck`,
`diff`, and `summary` flags, and `static-delta show/delete/verify/indexes`. The
`static-delta` additions need new public accessors into the
superblock/part/index structures `delta.rs` already parses internally but
does not yet expose.

The sub-phase is decomposed into thirty items in
`phase-17-cli-conformance-plan.md`, one per command with the larger commands
split by option topic, each carrying its own status, the library work it needs,
and the observation pass it depends on. That file also carries the
cross-cutting decisions several items share and the record of any option
deliberately skipped.

Deliverables: the remaining flags on each command, read-only
superblock/index accessors on `delta.rs` for `static-delta show`/`indexes`, and
the per-transaction fsync override and reporting counters `commit --fsync` and
`commit --table-output` need (`Transaction::set_fsync`, and `metadata_total`,
`content_total`, and `content_bytes_unpacked` on `TransactionStats`; item
`F10`).

Verify: each option's `m10` record and the option's owning `m0`/`m1` cells
move from `unimplemented-cli`/`unobserved` to `full` (or a named, justified
`lossy`/`needs-priv`) as it lands.

Landed so far: `F10` (`commit --fsync`, `commit --table-output`) and `F1`, `F2`,
and `F3`, which together give `commit` its message, its metadata dict, and its
ref bindings. The three carry one library change between them, in
`ostrya-gvariant`: the crate gained the reading half of the GVariant text form
(`from_text`) and the type alphabet that half needs, so `Type` and `Value` now
carry `n`, `q`, `i`, `x`, `h`, `d`, `o`, `g`, and the maybe types through the
serializer, the parser, and the printer. `commit --add-metadata` is what reaches
them, and the widening closes the `show --print-variant-type` type-set
divergence `cli-surface.md` recorded at Phase 17d. The commit metadata dict's
entry order is part of the commit checksum, and the rule the three items share
is stated once in `format-reference.md`, "CLI output formats", `commit`: derived
keys the tree walk produces, then the user keys group by group, then the binding
keys, then the derived keys the commit assembly appends. Item `F9` fills that
rule's first and last group with the keys it derives. The conformance run reports
538 cells and 211 passes after the three (491 cells and 173 passes at the end of
Phase 17e, 504 and 183 after `F10`).

`F5` and `F6` follow, giving `commit` the four options that shape the filesystem
walk -- `--statoverride`, `--skip-list`, `--mode-ro-executables`, and
`--skip-if-unchanged` -- and the two that resolve a source entry by its inode,
`--link-checkout-speedup` and `-I/--devino-canonical`. Both items needed library
work the plan did not expect. `CommitModifier` gained a `mode_callback`, a
per-path hook returning the `st_mode` an entry records: the filter takes its
`FileMeta` by shared reference and returns an include-or-prune verdict, so
`--statoverride` and `--mode-ro-executables` had no way to reach a mode through
it. The `CANONICAL_PERMISSIONS` reduction of the permission bits moved to after
that callback, which is the order the tool applies -- `--mode-ro-executables`,
then `--statoverride`, then the reduction -- and the reduction records the file
type the walk found, so a value carrying file-type bits of its own leaves the
entry the kind it is. `FileMeta::symlink_header` records a mode that already
names a symlink, permission bits included, which a `--statoverride` entry over a
symlink needs, and refuses a mode naming any other file type, which is what the
regular-file arm of the same class already did.
`Repo::devino_cache` builds a `DevInoCache` from the repository's own
uncompressed loose content objects, which is where the tool's own cache comes
from: it is built at commit time from `--repo`, so a checkout any earlier process
made resolves through it, and an `archive` repository contributes nothing because
it stores every content object compressed. The ingest side gained the hit path
the speedup needs -- the stored object supplies the metadata the modifier shapes,
and the object is rewritten from the stored payload only where the shaped
metadata differs -- and under `DEVINO_CANONICAL` the hit now stands ahead of the
filter, the tool skipping the filter and every callback for an entry it resolves.

Two observations corrected claims the plan carried. The first is that neither
devino option changes a commit's checksum: it holds in twelve of the fourteen
checkout variants and fails over a `bare-user` repository checked out with `-U`,
where the plain walk captures the repository's own `user.ostreemeta` xattr off
the hardlinked objects and the flagged commit is the faithful one. The oracle is
therefore the tool's checksum and not the absence of a change. The second is that
`-I` masks a real failure: `--owner-uid=0` against a `bare` repository as a
non-root user fails plainly and under `--link-checkout-speedup` and succeeds
under `-I`, no content object being written for a resolved file. Both are
recorded in `cli-surface.md`, "P2", together with the nine divergences the six
options carry: the order of the `Unmatched ... path:` lines, which the tool
emits in a hash order; a `--statoverride` value naming a file type the object
model does not hold, which the port refuses in every arm and the tool writes for
a regular file and for a symlink, both refusing for a directory; the mode field
itself, which the tool reads through a C `double` and the port reads in decimal,
so a hexadecimal literal, an exponent, and a value past the 32-bit range part
the two; the 128-mebibyte cap the port puts on either control file, matching the
cap `-F/--body-file` takes; `--skip-if-unchanged` beside a `--parent` the
repository does not hold, which ends the tool on a signal where the port reports
the absent object; the wording of a content object that cannot be written, where
the tool reports `Writing content object: fchown: Operation not permitted` and
the port its own `i/o error:` line, both at exit 1; the work a root-pruning skip
list still reaches, where the tool attempts the `--consume` source removal and
reads a `tar=` source under the pruned walk and the port does neither; a
`--skip-list` entry, which is spend-once in the tool and reaches every source in
the port; and `--table-output` beside `--skip-if-unchanged`, which prints
uninitialized counters from the tool, so the port prints the parent's checksum
and zero for each counter and no cell states the combination. Both control files
must hold UTF-8 in both implementations, and a byte that is not, or a NUL,
reports `error: Invalid UTF-8` ahead of everything else the command does. The
conformance run reported 561 cells and 220 passes after the two items.

`F9` closes `commit`'s derived metadata: `--generate-sizes`, `--bootable`, and
`--generate-composefs-metadata`. Three library additions carry it.
`Transaction::set_generate_sizes` settles `ostree.sizes` for a transaction, so
the tar ingest reaches the key the walk's `GENERATE_SIZES` flag already reached.
It stores the caller's answer the way `set_fsync` does, so it wins over the
ingest flag in both directions.
`Transaction::read_dir` lists one directory of a tree the transaction has staged,
reading its staged objects before `objects/`, which is what the kernel search
under `--bootable` reads: the tool searches the committed tree, so a `--skip-list`
that prunes `/usr/lib/modules` leaves no kernel to find. Deferred: a
`TreeEntry::Dir` the call returns reads back through the transaction alone, so
passing one to `RepoTree::read_dir` before the commit reaches
`Error::ObjectNotFound`. The doc comment carries the constraint, and enforcing
it in the type needs a staging-aware tree handle.
`Transaction::composefs_digest` builds the composefs image over a staged tree and
returns its fs-verity digest, so the value goes into the metadata of the commit
it belongs to. The image builder became mode-independent for it: each backing
file redirects to the `.file` loose path and carries the fs-verity digest of the
file's content rather than of the loose object, so `archive`, `bare`, and
`bare-user` holding one tree produce one image and one digest, which is what the
tool stores. `bare-user-only` canonicalizes the tree and so reaches another
digest, in both implementations.

Four divergences came out of that comparison, all in `cli-surface.md`, "P2". The
tool holds the commit metadata dict in a hash-ordered container while
`--bootable` or `--generate-composefs-metadata` is given, so combining either
with a caller-supplied metadata key parts the two orders and therefore the two
checksums; the port keeps the four-group order in every case. `ostree.sizes`
records the stored size of each object, so its values follow the writer's DEFLATE
encoder, and the two encoders reach two lengths for most payloads -- 41 of 45
file objects over the port's own Rust sources, 36 of 40 over a set of system
binaries -- so an archive `--generate-sizes` commit of a real tree reaches two
commit checksums. The kernel search sits after the walk and before the timestamp
in the tool, where the port reads the timestamp earlier. A tree whose
`/usr/lib/modules` is a non-directory, a regular file or a symlink alike, ends
the reference build on an assertion, where the port reports `Not a directory`.
The conformance run reported 582 cells and 230 passes after the item.

`F4` gives `commit` its tree sources: `--tree=dir=`, `--tree=tar=`,
`--tree=ref=`, `--base`, `--consume`, `--tar-autocreate-parents`, and
`--tar-pathname-filter`. The commit is built from an ordered source list --
`--base` at the bottom whatever its position, then each `--tree` in
command-line order -- and the overlay is a recursive merge in which directories
union, a later source's directory metadata replaces the earlier one whole, later
files replace earlier files, and a name that changes between a file and a
directory is refused. No commit modifier reaches an entry that survives from
`--base`, and every modifier reaches an entry from any `--tree`, `ref=`
included.

Two library additions carry it. `Transaction::overlay_tree_to_mtree` reads a
committed tree into a mutable tree under a `CommitModifier`, reusing the stored
checksums where the shaped metadata equals the stored metadata and rewriting the
object from the stored payload where it differs, and recording a subdirectory
the destination does not hold without reading it. `Repo::import_tar_into` reads
an archive into a tree an earlier source already filled, under the same
modifier, which is what lets one command line mix an archive with a filesystem
walk and a committed tree. The tar importer places each member under a directory
the tree already holds, so an archive that names a member before its parent is
refused; `TarImportOptions::autocreate_parents` synthesizes the missing parents
instead. `TarImportOptions::rename` is the hook `--tar-pathname-filter` needs,
and `Transaction::begin_tree_source` scopes `ostree.sizes` to one source, which
is what makes a multi-source `--generate-sizes` commit reach the tool's
checksum.

The filter takes an expression. Both implementations compile it with PCRE2: the
tool through GLib's `GRegex`, and the CLI through the `pcre2` crate, which is
the one dependency this item adds and the only crate in the workspace that may
name it, a rule CI holds. The crate vendors PCRE2 10.46 and links it
statically, pinned to the vendored build by `.cargo/config.toml` so a host that
carries `libpcre2-dev` cannot supply another version, and `ostrya-cli` sets
`publish = false`, so no published crate links it. The compile options the tool
uses are recovered by observation, one probe per option: UTF and UCP on, the
newline convention `any`, and every other option at PCRE2's default. The crate
states no option for the convention, so the compiled pattern carries PCRE2's
own `(*ANY)` start-of-pattern option ahead of the value, and a convention the
value states itself follows it and wins in both. Measured in both directions
and recorded in `conformance/cli-surface.md`, "P2": every expression one
implementation compiles the other compiles too, and no expression both compile
is answered differently, the commit checksum being the oracle. PCRE2 accounts a
match budget, so an expression that requires no literal is refused at the limit
instead of running long.

The replacement half stays the port's own reader, GLib's replacement syntax
being what an operator writes: `\0` to `\9`, `\g<name>`, `\g<number>`, `\\`,
the seven control escapes, and `$` as a literal
(`crates/ostrya-cli/src/main.rs`, `parse_replacement`).

This is the worked example of `CLAUDE.md`, "CLI compatibility is functional,
not literal", rule 2. The item first shipped a from-scratch backtracking
matcher over a PCRE subset, to add no dependency. A review measured three
constructs it read differently from PCRE and three unbounded-work paths in it,
so the engine was removed in favour of a crate. The `regex` crate that replaced
it read the POSIX class names as ASCII and `$` as end-of-text, so one command
line wrote two different commits, and the engine moved again to the library the
tool itself links. Reading somebody else's dialect means running their engine.

This item closes the standing `--tree` divergence. `--tree=tar=PATH` joins the
port's stdin form, and `--tree=tar=-` and `--tree=tar=/dev/stdin` name standard
input in both implementations. The port keeps reading standard input where a
command line names no source at all, where the tool walks the current working
directory: an omitted argument would otherwise commit whatever directory the
caller stands in, which is the accident the omitted `/sysroot/ostree/repo`
fallback is also left out for. `--canonical-permissions` was then compared over
one tree packaged two ways, which is where the two implementations part: the
tool leaves an archive's extended attributes in place and drops a filesystem
walk's, and the port does the same.

Six divergences stand, all in `cli-surface.md`, "P2": the source a command
line naming none states, the wording of an archive that opens and does not parse,
the four places the filter's expression parts (the reason string a compile
failure names, the unit that same line's offset counts in, the exit path a
match-time refusal takes, and the PCRE2 version each side links), the reference
defect a file member filtered to an empty name reaches -- the tool aborts on a
GLib assertion or writes a dirtree entry with an empty name, and the port
refuses the member -- the wording of a tar entry the reader refuses, and the
`--table-output` counters over a `ref` source that does not open the source
list.
Four wordings the port reproduces are the tool's own: `opendir(<path>):
<reason>` for a source that does not open, the positional `PATH` included,
`archive_read_open_filename: Failed to open '<path>'`,
`unlinkat(<name>): <reason>` for an entry a consuming walk cannot remove, and
`Archive entry pathname is not valid UTF-8`. The conformance run reported 618
cells and 248 passes after the item.

`F8` gives `commit` its five signing options: `--gpg-sign`, `--gpg-homedir`,
`--sign`, `--sign-from-file`, and `--sign-type`. The engines are the ones Phase
13 and Phase 14 landed, and the item is the ordering around them. The signature
stands before the ref: the tree and the commit object are staged, every
signature the invocation asks for is produced, the staged objects publish into
`objects/` and the `.commitmeta` is written beside the commit, and the ref is
written last. A key that cannot sign therefore leaves nothing published and the
ref where it stood, and a ref write that cannot happen leaves the commit and its
`.commitmeta` durable with no ref.

Three library additions carry it. `Transaction::sign_commit` signs a commit the
transaction staged, reading the commit object out of the staging directory
before `objects/` and holding the signature in memory until the transaction
publishes. `Transaction::set_commit_detached_metadata` queues the detached
metadata dict a transaction writes, and the transaction writes the queue between
object publication and the ref writes, which is what puts a `.commitmeta` and
the commit it belongs to on disk together and both ahead of the ref.
`GpgSigner::secret_key_fingerprints` resolves a selector through
`gpg --list-secret-keys` without signing and answers the fingerprints it names,
in listing order. An empty list is what the "no gpg key found" refusal reads,
and a home directory that does not exist, one that cannot be read, and one
holding no matching key all answer it. More than one fingerprint means the
selector is ambiguous. The selector stands after a `--`
terminator, so gpg reads it as a key name. Without the terminator gpg reads an
option-shaped selector as one of its own options, and `--gpg-sign=--homedir=PATH`
moves the lookup to `PATH` and creates a keybox and a trust database there, as a
side effect of a read. `format-reference.md`, "Signing" states the outcome the
terminator holds the lookup to.

`--add-detached-metadata-string` and the signing options meet in the same dict,
and they differ: the first replaces the whole stored dict and the second appends
to what stands. The stored keys keep insertion order -- the caller's keys in
command-line order, then `ostree.sign.<type>`, then `ostree.gpgsigs` -- whatever
order the options take on the command line. `format-reference.md`, "Signing
details" states both rules.

Nine divergences stand, all in `cli-surface.md`, "P2": the engines the port
carries and this tool build does not, where each refuses an engine it lacks in
the same words; a `--sign-from-file` file whose first line is empty and one with
no bytes, which end the reference on SIGSEGV and SIGABRT where the port reports
the length refusal; what becomes of the staging directory after a run, where the
port removes the directory and its `-lock` sibling ahead of every exit and the
tool keeps one `staging-<bootid>-XXXXXX` entry and reuses it for every
transaction of the boot; the wording of a ref-write failure, where the state each
leaves is the same and that state is the ordering claim; the keypair check the
port applies to a 64-byte `--sign` value, which the tool signs with; the
65536-byte cap the port puts on a `--sign-from-file` first line; the path a
`--sign-from-file` open failure names, where the tool names the absolute path and
the port names the path as the command line spelled it; the branch-name
term of the signing step's fault order, observable only over a name both ref-name
grammars refuse; and the name-dependent order the tool stores some
detached-metadata key sets in. The conformance run reports 646 cells and 256
passes.

`commit -e` settles the message before it takes any repository lock. The
`[core]` keys the transaction reads -- `locking`, `lock-timeout-secs`,
`tmp-expiry-secs`, and the `min-free-space-*` pair at the open, and the `fsync`
and `per-object-fsync` pair in the write paths -- are parsed ahead of the edit,
so a value their reader refuses is reported with the editor unstarted, as it is
in the tool. The fsync pair is read there whatever `--fsync` says, because the
option narrows the configured policy and so reads it (`format-reference.md`,
"The fsync vocabulary"). The transaction opens once the editor has returned,
which puts the repository lock, the staging directory, and the free-space budget
behind the editing session. An exclusive operation on the same repository,
`ostree prune` among them, runs while the message is being written; the tool
takes its own lock at this same point. The wait for the editor runs on the
blocking pool, so it holds no executor thread
(`crates/ostrya-cli/src/main.rs`, `wait_for_editor`).

#### Phase 17g -- P3 commands with no matrix weight

`reset`, `checksum --ignore-xattrs`, `find-remotes`, `create-usb`, and
`gpg-sign` (an alias for `sign --sign-type=gpg`, per `cli-surface.md`).
`remote add-cookie`/`delete-cookie`/`list-cookies` stay out, per 17e.

- `find-remotes` needs the repo-finder machinery Phase 16d already carries
  for collection-ref-based pull; check whether its public surface covers a
  finder invoked standalone, or add a thin new entry point if not.
- `create-usb` layers `pull-local`/mirror onto a destination-repo target; no
  new library primitive is expected.

The five commands are items `G1` through `G5` of
`phase-17-cli-conformance-plan.md`, where the cookie subcommands stand as `G6`
with the reason they are out.

Deliverables: the five commands.

Verify: each command's basic form is wired and matches the tool's for a case
the matrix does not otherwise cover.

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
  roadmap on the critical path to the Phase 11 CLI. Mitigation: 9a captures
  golden fixtures, 9b surveyed the pure-Rust EROFS/composefs crates and found
  none depend-able under the no-C rule (reproducing the format in-tree in the
  standalone `ostrya-composefs` crate, built in 9c and wired into `ostrya` in
  9d, which isolates the byte-exact work behind a small tree-model surface),
  and the permissively-licensed `composefs-rs`, which emits byte-identical
  images, is available as a second cross-check oracle alongside the tool.
- GVariant byte-exactness (Phase 1): everything downstream depends on it.
  Mitigation: extensive golden fixtures before building on it.
- xz coding (Phases 15a/15b): resolved. Decode (15a) and encode (15b) both go
  through `async-compression`'s xz codec over statically-linked `liblzma`, the
  reference implementation the tool itself uses, so the parts we write are
  ordinary liblzma-produced xz the tool decodes.
- HTTP client (Phase 16a): resolved. `hyper` speaks both versions over its own
  I/O traits, which a ~90-line safe adapter bridges to `futures-io`, so
  `ostrya-rt` stays the only crate that knows the backend. `h2` pulls `tokio`
  and `tokio-util` into the graph under either backend for their I/O traits and
  codec framing; no tokio runtime is driven under smol. The rustls crypto
  provider is `rustls-graviola`, which keeps the no-C rule intact and limits
  supported architectures to x86_64 and aarch64 -- a Linux target outside those
  two needs a provider swap, which is a `ClientConfig` change confined to
  `fetch/tls.rs`.
- GPG semantics ride on the installed GnuPG: the engine drives `gpg`/`gpgv`
  through the documented, stable `--status-fd` interface and pins no
  version; a vocabulary change in a future GnuPG would surface in the
  round-trip tests.
- Conformance scope: the CLI-behavior tier requires a compatible CLI (Phase
  17) and is authored from scratch, since the upstream shell suite is LGPL
  source and out of scope; the admin tier requires the sysroot track
  (Phase 20).

## Decisions

Resolved:

1. Dependency policy: every crate is authorized by the operator before it
   enters a manifest. C libraries are avoided; the two authorized exceptions
   are `liblzma`, statically linked for xz, and PCRE2, statically linked in the
   `ostrya-cli` binary for the `commit --tar-pathname-filter` expression (both
   bundled and built from source, needing no C runtime beyond the libc `std`
   links). `ostrya-cli` sets `publish = false`, so no published crate links
   PCRE2, and CI holds the rule that no other manifest may name `pcre2`
   (`.github/workflows/ci.yml`, "PCRE2 stays in ostrya-cli"). The Rust crate
   ecosystem is in scope (rustix, smol, sha2, ed25519-dalek, rustls,
   miniz_oxide, and so on).
2. GVariant: hand-roll a minimal codec (`ostrya-gvariant`) tailored to
   ostree's fixed type set, fuzzed against golden bytes from the tool.
3. Test-suite scope: phased. Target the library-format-testable subset plus
   format-primitive unit tests first; add the port's own CLI-driven
   conformance suite through Phase 17 (never the upstream shell suite, which
   is LGPL source); treat the admin/sysroot tier (Phase 20) as a separate,
   optional track.
4. Workspace: multi-crate (`ostrya-gvariant`, `ostrya-core`, `ostrya-rt`,
   `ostrya-composefs`, `ostrya`, `ostrya-cli`), with heavier subsystems
   behind feature flags on `ostrya`.
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

9. Repo finders: the config and mount finders land with the phase that brings
   collection refs, which a finder resolves and which is not yet scheduled; they
   were originally slated for Phase 16d and moved out of it. Avahi discovery is
   out of scope.
10. HTTP/2: required for pull. The fetcher is built on `hyper` 1.11
    (`client`, `http1`, `http2`) with ALPN over `rustls` 0.23, the crypto
    provider being `rustls-graviola` (Rust plus formally-verified assembly, no
    C compiler); `futures-rustls` runs the handshake over the `futures-io`
    streams `ostrya-rt` exposes. See Phase 16a for the full set and what it
    rules out.
11. composefs export (Phase 9b): reproduce the composefs/EROFS format in a new
    standalone crate `ostrya-composefs` rather than depend on a crate. No
    pure-Rust crate writes byte-exact composefs EROFS images under the
    no-C-linkage rule -- the `erofs-rs` projects are read-only, `am-fs-erofs`
    is composefs-unaware, and `composefs-rs`, which does emit byte-identical
    images and is permissively licensed, forces a non-optional C-linking
    `zstd` and a full `tokio` with no feature to disable them.
    `ostrya-composefs` reproduces only the metadata subset composefs uses,
    with no EROFS compression, and hand-rolls the fs-verity digest over the
    existing `sha2` dependency. Phase 9c builds the crate; Phase 9d wires it
    into `ostrya`. Neither adds a new crate. `composefs-rs`, permissively
    licensed, serves as a clean-room reference and cross-check oracle. See the
    Phase 9b survey above.

12. spki sign engine: a required signing engine, not deferred. The
    reference tool gates spki on OpenSSL; the port implements it in pure
    Rust (RustCrypto ECDSA over the NIST curve the tool uses, with SPKI
    SubjectPublicKeyInfo PEM public keys) in Phase 13c. The ed25519 and
    dummy engines are always compiled; spki is behind the `sign-spki`
    feature and GPG behind `sign-gpg`, so the core stays free of the
    ECDSA/SPKI crate tree unless opted in (the GPG engine adds no crates;
    see decision 13).

13. GPG engine (Phase 13d): signing and verification run the system `gpg`
    and `gpgv` binaries as short-lived subprocesses over the documented
    `--status-fd` interface, the way git drives them. No OpenPGP crate is
    linked: `sequoia-openpgp` was considered and set aside -- LGPL
    licensing, a heavy transitive tree, and no agent surface, whereas
    agent-held and hardware-token keys work through `gpg` itself with no
    dedicated code path. `Verifier::verify` is async so a verifying engine
    can await a subprocess. Subprocesses go through `rt::Command`
    (`smol::process` / `tokio::process`, no new lockfile crates); the
    `gpg` and `gpgv` binaries are a runtime tool dependency of the
    `sign-gpg` feature only.

14. `#[non_exhaustive]` on the public enums and option structs (Phase 17f):
    the attribute marks a type whose member set the port itself owns and
    expects to grow, and is left off a type whose member set an external
    specification closes.

    `ostrya::Error` carries it: its variants are the port's own error
    vocabulary, and a phase that adds a failure mode adds a variant.
    `TarExportOptions` and `TarImportOptions` carry it: their fields track the
    CLI options the tar commands grow.

    `ostrya_gvariant::Type` and `ostrya_gvariant::Value` do not carry it.
    `Type` names every character of the GVariant type alphabet, which the
    GVariant serialization specification fixes, and `Value` names every
    representation those characters take. Phase 17f completed both sets and
    closed them. An exhaustive `match` over either therefore stays valid, and
    it is the gate that a new type character -- were the alphabet ever to gain
    one -- reaches every site that must answer for it. The attribute has no
    effect inside the defining crate, so adding it would move `ostrya`,
    `ostrya-core`, and `ostrya-cli` from that compile-time gate to a wildcard
    arm resolved at run time, which is the outcome the byte-exact fidelity
    rule argues against. Widening either enum is a breaking change and takes a
    major version.

15. Staging-aware tree handle (deferred, opened in Phase 17f):
    `Transaction::read_dir` returns `TreeEntry::Dir` values holding a
    `RepoTree` that reads back through the transaction alone, so passing one
    to `RepoTree::read_dir` before the commit reaches
    `Error::ObjectNotFound`. The doc comment carries the constraint and the
    one caller honours it. A tree handle that reads the transaction's staged
    objects before `objects/` moves the constraint into the type; it is a
    public API addition and lands with the phase that brings a second
    caller.
