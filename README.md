# Ostrya

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly known 
as _ironwood tree_\] is a from-scratch, pure-Rust, async reimplementation of 
the ostree repository library (libostree). It reproduces ostree's on-disk 
format byte-for-byte while presenting an idiomatic Rust API designed for 
asynchronous use and for multiple concurrent transactions within a single 
process.

## Status

Work in progress. The library is being built along a phased roadmap
(`docs/port-plan.md`), and the API is not yet stable. The following paths are
implemented and verified against golden fixtures produced by the `ostree` tool:

- GVariant codec and the typed object-model codec layer
- Core format primitives: checksums, varint, loose paths, `ostree.sizes`
  packing, xattr canonicalization, keyfile parsing
- Object model: commit, dirtree, dirmeta, and file headers (bare, bare-user,
  bare-user-shared, archive; read-only support for bare-split-xattrs)
- Repository open, create, and config parsing
- Reading path: object, commit, and file-content loading, ref resolution and
  listing, tree traversal
- Runtime backend abstraction and the streaming hashing primitives
- Transactions and the two-layer repository lock
- Write path: object writers, in-memory tree assembly, filesystem ingest with
  a commit modifier, commit assembly and durable publication, overlay
  changeset import, and a path-addressed staging tree with tree merge
- Checkout path
- composefs/EROFS image writer and fs-verity digest (`ostrya-composefs`)

In progress and planned: wiring composefs export into the library, tar
import/export, a minimal `ostrya` CLI, prune/fsck/diff, signing, summaries,
static deltas, pull, an `ostree`-compatible CLI for shell-test conformance,
and the S3 and SSH transport extensions. See `docs/port-plan.md` for the full
roadmap.

## Design

- Pure Rust, with two static C-linking exceptions, each requiring no C runtime
  of its own beyond the libc `std` already links: `liblzma`, which the library
  links for xz in static deltas, and PCRE2, which the `ostrya-cli` binary
  links for the `commit --tar-pathname-filter` expression. PCRE2 belongs to
  that binary alone, which sets `publish = false`. `rustix` provides the
  syscalls a portable async file API cannot express (fd-relative opens and
  metadata, xattrs, statx, FICLONE reflink, `O_TMPFILE` + linkat,
  OFD-compatible record locks). Streaming file I/O goes through the runtime's
  async file.
- Async throughout. The runtime backend sits behind the internal `ostrya-rt`
  crate: `smol` by default, `tokio` under the `tokio` feature.
- Multiple concurrent transactions within a single process. A `Transaction` is
  an owned handle carrying its own staging directory and counters; `Repo` holds
  only shared state and is cheaply clonable. `Repo`, `Transaction`,
  `FileObject`, and the content readers and writers are `Send + Sync`.
- Byte-exact on-disk format. Field layouts, byte orders, sort orders, and
  checksum algorithms match ostree exactly, verified in both directions: the
  `ostree` tool reads what the library writes, and the library reads what the
  tool writes.
- File content is streamed in bounded-size chunks end to end. Hashing,
  compression, object-store writes, checkout, and transfer never buffer an
  unconstrained blob in memory. Whole-buffer handling is reserved for metadata
  objects, whose size the format caps.
- `#![forbid(unsafe_code)]` everywhere except two audited sites documented in
  `CLAUDE.md`.

## Workspace layout

The project is a Cargo workspace of focused crates:

- `ostrya-gvariant` -- byte-exact GVariant codec for the fixed type set ostree
  uses. No ostree knowledge.
- `ostrya-core` -- object model, checksums, varint, loose paths, xattr
  canonicalization, and format serialization. Depends on `ostrya-gvariant`.
- `ostrya-rt` -- internal async-runtime abstraction (`smol` or `tokio`
  backend). The only crate that knows which backend is compiled.
- `ostrya-composefs` -- standalone, synchronous EROFS/composefs image writer
  and fs-verity digest. Takes a tree model and emits image bytes.
- `ostrya` -- the library: repo, transactions, commit, checkout, refs,
  reading, and the paths listed under Status. Feature-gated.
- `ostrya-cli` -- the command-line front-end (builds the `ostrya` binary).

Feature flags on `ostrya`: the runtime selectors `smol` (default) and `tokio`;
later phases add `pull`, `verify-gpg`, `sign-gpg` (which turns on `verify-gpg`),
`deltas`, `s3`, and `ssh`.

## Clean-room provenance and licensing

Ostrya is a clean-room reimplementation. Its design is grounded only in the
public ostree documentation (https://ostreedev.github.io/ostree/) and the
observed behavior of the `ostree` tool run as a black box. The LGPL libostree
source is not consulted, so the resulting code can be distributed under the MIT
license. The on-disk format Ostrya reproduces is an interoperability interface;
every format fact recorded in `docs/format-reference.md` is verifiable by
running the tool and inspecting the bytes it writes.

## Building and testing

The workspace builds on stable Rust (edition 2024, minimum 1.92).

```sh
cargo build
cargo test
```

The test suite runs under both runtime backends:

```sh
cargo test                                        # smol (default)
cargo test -p ostrya --no-default-features --features tokio
```

Generating the golden fixtures requires the `ostree` tool and is done by
`tests/fixtures/generate.sh`. Consuming the checked-in fixtures from a fresh
checkout does not require the tool.

## Documentation

The design documents in `docs/` are the source of truth and are kept in sync
with the code:

- `docs/format-reference.md` -- the byte-exact on-disk format
- `docs/port-plan.md` -- architecture, testing strategy, and the phased roadmap
- `docs/api-sketch.md` -- the target Rust-native async API

## License

MIT.
