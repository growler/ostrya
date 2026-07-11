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
   composefs/EROFS export, tar import/export.

The port is a library. It is not a drop-in replacement for the `ostree` tool,
though a compatible CLI is planned as a late phase specifically to unlock the
shell-driven part of the test suite.

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
- `ostrya-cli` -- the `ostree`-compatible binary (late phase).

Feature flags on `ostrya`: `pull`, `sign-gpg`, `deltas`, `composefs`, plus
the runtime backend selectors `smol` (default) and `tokio`, forwarded to
`ostrya-rt`. Each
heavier or riskier subsystem is opt-in so the core stays small. Tar
import/export is always compiled (built on `smol-tar`), not feature-gated.

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

## New repository mode: bare-user-split-attrs

A development-only repository mode introduced by this port, offered as an
optional add-on. Production repositories stay `bare`; this mode supports
building images in a shared multi-developer repository and serving as a
composefs backing store. The full format is in `format-reference.md`.

Summary. A `File` is stored as two objects: `.fileb` (raw payload, named
`SHA256(payload)`) and `.filea` (the 6-field file header plus a blob reference,
named by the classic file identity `SHA256(header ‖ payload)`). Object
identity, and therefore dirtree and commit hashes, are unchanged from `bare`,
so a commit developed here is identical when pulled into a bare production
repository. Objects are stored 0664 with setgid object directories and a shared
group, decoupling repository at-rest permissions from logical file permissions
(which resolves the `bare-user` lockout on restrictively-permissioned files in
a shared repository). The logical mode, uid, gid, and xattrs live only in
`.filea`.

Invariant. `ostree.sizes` is hard-disabled in this mode. It is the only
storage-dependent commit-metadata field, and leaving it off preserves the
cross-mode commit identity the development-to-production workflow relies on.

Design thread across phases:

- Phase 3: the `.filea` and `.fileb` encoders and the new `ObjectType::FileBlob`.
- Phase 4: `mode=bare-user-split-attrs` is accepted, validated, and written to
  `[core] mode` on create. Objects and their `objects/xx/` directories are
  first written by the write path, so the setgid object directories, shared
  group, and 0664 objects land in Phase 7.
- Phase 5: mode-aware `load_file` (read `.filea`, then `.fileb`).
- Phase 7: `write_content` splits into blob plus attributes internally, with an
  unchanged signature; `ostree.sizes` is enforced off. Object directories are
  created setgid with a shared group and objects are stored 0664 via explicit
  chmod (never trusting umask).
- Phase 8: copy-based checkout applying the `.filea` mode.
- Phase 9: the `filea -> fileb` reachability edge for prune and fsck, the
  two-level integrity check, and blob-aware commit-completeness.
- Phase 13: two-object fetch and cross-mode re-encoding on the shared identity.
- Phase 15: composefs export uses the real `.filea` attributes and redirects to
  `.fileb`; ownership is presented via composefs uid mapping at mount.

## Testing strategy

The suite is bimodal. Roughly 45-55% is library-format-testable, ~25% needs full
sysroot/deployment (admin), ~20-25% is network/gpg/tar/composefs.

- Every phase ships unit tests plus golden-byte fixtures produced by running the
  `ostree` tool (checked into the repo). Byte-exactness is verified against
  these fixtures and cross-checked by having the tool read what the port writes
  and vice versa.
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

Phases are ordered by dependency. Early phases are small and foundational;
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
`rt::Timer` lands with Phase 6, `rt::spawn` and networking with Phase 13.
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
(Phase 13a).

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

### Phase 7 -- Write path

Split into sub-phases:
- 7a Content and metadata object writers (all modes, O_TMPFILE + linkat,
  dedup early-out, min-free-space accounting, per-mode metadata application).
  Content ingest streams: hashing and compression run over bounded chunks as
  the payload is copied, never over a whole in-memory blob. The primary
  ingestion surface is the push-style `ContentWriter` (`api-sketch.md`),
  with `write_content` as a pull-style convenience over it.
- 7b Mutable tree and `write_mtree` (sorted dirtree assembly, clean-subtree
  short-circuit).
- 7c `write_dfd_to_mtree` (fs-tree walk, devino cache, commit modifier: filter,
  xattr callback, canonical permissions, SELinux label hook, CONSUME/adopt).
- 7d `write_commit` (+ `ostree.sizes` auto-metadata), detached metadata, ref
  queueing, commit ordering and durability.
Verify: commits produced have checksums identical to the tool's for the same
input tree; `ostree fsck` and `ostree show` accept them; run the write-side
tests against captured references.

### Phase 8 -- Checkout path

`checkout_at` for all modes; overwrite modes (none/union-files/add-files/
union-identical); hardlink vs copy decision and fallbacks; devino cache;
whiteout handling; per-file/dir metadata finalize and optional fsync.
Verify: checkout of a tool-created commit matches the tool's checkout (mode,
perms, xattrs, hardlink counts); round-trip commit -> checkout is stable.

### Phase 9 -- Prune, fsck, traverse, diff

Reachability traversal, prune (refs-only, depth, delete-commit), fsck (object
integrity, partial-commit detection), diff.
Verify: the published `test-prune`, `test-fsck-*`, and `test-corruption`
subsets via the CLI harness.

### Phase 10 -- Signing

`Signer`/`Verifier` traits; ed25519 engine (ed25519-dalek); dummy engine; spki
engine (pure-Rust X.509/ECDSA, optional); detached-metadata append; commit
sign and verify. GPG via sequoia-openpgp (RustCrypto backend): keyring loading
(binary and armored), detached verify, per-signature metadata.
Verify: signatures produced verify under the `ostree` tool and the reverse;
`test-signed-commit-{ed25519,spki,dummy}`; `test-gpg-signed-commit` and
`test-commit-sign` once GPG verify lands.

### Phase 11 -- Summary generation and signing

Summary assembly (sorted refs, the host-order size asymmetry, big-endian
timestamps), summary signing and verification, summary cache.
Verify: byte-identical summary versus the tool for the same repo; the tool
verifies our signed summary.

### Phase 12 -- Static deltas

GVariant superblock/part/fallback formats, LEB128 op stream, the endianness
byte handling, rollsum (bupsplit) and bsdiff (pure Rust), xz encode/decode,
delta generation and offline application, indexes, signed deltas.
Verify: apply tool-generated deltas and get correct objects; the tool applies
our deltas; `test-delta`, `test-delta-ed25519`, `test-delta-sign`.

### Phase 13 -- Pull

Split into sub-phases:
- 13a Async fetcher: pure-Rust HTTP/1.1 over the `ostrya-rt` net layer +
  rustls, conditional GET (ETag/If-Modified-Since/304), mirrorlist fallback,
  retry classification, max-size streaming cap, priorities, client certs,
  basic auth. No range. Ships `VerifyingReader`, the stream that checks an
  expected digest at EOF and fails the final read with `InvalidData` on a
  mismatch (the check fires only when the consumer polls through to EOF).
- 13b Local pull (`file://`): object import (hardlink/reflink/copy),
  localcache repos.
- 13c HTTP pull: the scan/fetch state machine (bounded fetch semaphore of 8,
  delta-part cap of 2, write throttle of 3, fixed priority drain order),
  summary/sig verification, commit and content verification, bindings and
  timestamp checks, commitpartial, mirror mode.
- 13d Delta-accelerated pull and repo finders (config/mount; avahi optional).
Verify: pull from a local trivial httpd; the `test-pull-*`, `test-local-pull*`,
`test-signed-pull*` clusters via the harness.

### Phase 14 -- Tar import/export

Built on `smol-tar` (always compiled, not feature-gated). GNU tar with SCHILY
xattr PAX records, numeric ids, commit-timestamp mtimes, content-checksum
hardlink dedup, `/etc` -> `/usr/etc` convention on import, deferred hardlink
resolution. Early task: confirm `smol-tar` can emit and parse the exact
GNU/SCHILY conventions the tool uses; extend or drive headers manually where it
cannot.
Verify: `test-export`, `test-libarchive`; extract our tar with GNU tar and
re-import into the `ostree` tool.

### Phase 15 -- composefs / EROFS export

Highest risk, isolated behind the `composefs` feature. Reproduce the EROFS
output byte-for-byte: EROFS superblock/inodes/dirents/xattrs, composefs redirect
and verity xattrs, the fs-verity Merkle digest (SHA-256, 4096 block, 0 salt).
Store `ostree.composefs.digest.v0` in commit metadata.
Verify: the fs-verity digest matches what the tool (with composefs) produces for
the same commit; the generated `.ostree.cfs` mounts and verifies.

### Phase 16 -- CLI front-end (`ostrya-cli`)

Incremental, driven by which shell tests are targeted. Command-line and
stdout/stderr compatibility with the `ostree` tool for the exercised subcommands
(commit, checkout, refs, rev-parse, ls, cat, show, log, config, prune, fsck,
summary, sign, gpg-sign, static-delta, pull, pull-local, remote, init, export,
diff). Provide a compatible shell-test harness and a TAP producer.
Verify: growing subsets of the shell suite pass unmodified.

### Phase 17 -- Sysroot / deployment (optional, separate track)

Out of the core library scope. If pursued: sysroot layout, deployments, boot
config parsing, bootloader integration, `admin` subcommands. This is the
heaviest cluster (root, mount namespaces, bootloaders) and unlocks the ~25%
admin tests. Recommend deferring or descoping unless explicitly required.

## Risk register

- composefs/EROFS byte-exactness (Phase 15): the EROFS and composefs on-disk
  formats are defined by the composefs and EROFS projects, not by ostree's
  public docs; reproduction is substantial. Mitigation: isolate behind a
  feature, and consider an existing pure-Rust composefs crate if its output
  matches.
- GVariant byte-exactness (Phase 1): everything downstream depends on it.
  Mitigation: extensive golden fixtures before building on it.
- xz encoding in pure Rust (Phase 12): decode is well-supported; encode is
  weaker. Mitigation: delta parts need only valid xz that round-trips (the part
  checksum is over our own compressed bytes), not byte-identity with liblzma.
- HTTP client (Phase 13a): no range/resume is needed, which keeps a hand-rolled
  or small pure-Rust client viable; HTTP/2 multiplexing is optional.
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
   Phase 16; treat the admin/sysroot tier (Phase 17) as a separate, optional
   track.
4. Workspace: multi-crate (`ostrya-gvariant`, `ostrya-core`, `ostrya`,
   `ostrya-cli`), with heavier subsystems behind feature flags on `ostrya`.
5. New `bare-user-split-attrs` development mode: a storage-layout split of
   `File` into `.filea` (attributes plus a blob reference) and `.fileb` (raw
   payload), with object identity preserved for development-to-production
   portability, `ostree.sizes` disabled, and the mode serving as the intended
   composefs backing store. See the dedicated section above.
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

Deferred to their respective phases:

9. composefs (Phase 15): reproduce the composefs/EROFS format ourselves versus
   depend on an emerging pure-Rust composefs crate. Feature-gated and late
   either way.
10. HTTP client (Phase 13a): hand-roll a minimal async HTTP/1.1 client over
    the runtime's net layer + rustls versus a pure-Rust crate such as
    `async-h1`. No range/HTTP2 is required, which keeps the hand-rolled
    option viable.
11. spki sign engine and avahi repo-finder: deferred as optional; ed25519
    and gpg cover the common cases.
