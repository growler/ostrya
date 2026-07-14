# ostrya

Project instructions. These layer on top of the global agent guide; where they
conflict, these win.

## What this project is

Ostrya (the botanical genus of the ironwood tree) is a from-scratch, pure-Rust,
async, clean-room reimplementation of ostree
(libostree) as a library. The primary motivation is an async-safe library that
supports multiple concurrent transactions within a single process, which the
reference tool does not allow. It is not a drop-in replacement for the `ostree`
tool;
a minimal `ostrya` CLI lands once the ingest and checkout paths are ready, and
a command-line-compatible CLI is a late phase, built only to run the upstream
shell test suite as an external conformance check. The `ostree` tool is treated
as a black box: its observed behavior and the public documentation are the only
inputs (see "Licensing and clean-room discipline").

## Licensing and clean-room discipline

The library is licensed MIT. The reference implementation (libostree) is LGPL,
so its source code must not be read, copied, translated, or consulted while
working on this project. Deriving MIT-licensed code from LGPL source would
violate the license.

The only permitted sources of design information are:

- the public ostree documentation at https://ostreedev.github.io/ostree/, and
- the observed behavior of the `ostree` tool run as a black box -- its command
  output and the bytes it writes on disk.

The on-disk format this project reproduces is an interoperability interface:
field layouts, byte orders, sort orders, and checksum algorithms are facts
recovered by inspecting the objects and output the `ostree` tool produces, not
by reading its source. When a design doc states such a fact, it must be
verifiable by running the tool and examining its output; it must never cite,
quote, or paraphrase the LGPL source.

If a detail cannot be obtained from the public documentation or by observing the
tool, re-derive it by observation -- do not look it up in the source. Do not add
the libostree source, its headers, or the C tree as a build dependency, a
reference, or reading material.

## Goals

1. Rust-native with no C library linkage beyond what `std` links. `rustix`
   handles the syscalls a portable async file API cannot express (fd-relative
   opens and metadata, xattrs, statx, FICLONE reflink, O_TMPFILE + linkat,
   OFD locks); streaming file I/O goes through the runtime's async file.
2. Async, with a feature-gated runtime backend behind the internal
   `ostrya-rt` crate: `smol` by default, `tokio` optional. Only `ostrya-rt`
   knows the backend.
3. Multiple concurrent transactions within a single process.
4. Capable of passing ostree's test suite, run as an external conformance gate
   (scope is phased: library format and format-primitive unit tests first,
   CLI-driven shell tests later, admin/sysroot optional).
5. Extensions: commit signing via `sequoia-openpgp` (not gpgme), composefs/EROFS
   export, tar import/export, AWS S3 push/pull, and ssh git-style push/pull.
6. A development-only repository mode, `bare-user-shared`, as an optional
   nice-to-have add-on.

Faithful on disk means byte-for-byte identical format, checksums, and
algorithms. The API is redesigned to be idiomatic Rust rather than mirroring the
C GObject surface.

## Authoritative design docs

The design lives in `docs/` and is the source of truth. Keep it in sync with the
code in the same change that alters behavior.

- `docs/format-reference.md` -- the byte-exact on-disk format. The correctness
  gate for every phase.
- `docs/port-plan.md` -- architecture, testing strategy, the phased roadmap, and
  the locked decisions.
- `docs/api-sketch.md` -- the target rust-native async API.

## Requirement: confirm every dependency before adding

Before adding any crate to any `Cargo.toml` -- a regular dependency, a
dev-dependency, a build-dependency, or a feature flag that pulls one in -- stop
and get explicit confirmation from the maintainer first. Do not run `cargo add`
or edit a manifest's dependency list until confirmed.

When proposing a dependency, state:

- the crate name and the version to pin;
- exactly what it is used for and where;
- that it is pure Rust with no C or `*-sys` linkage, and the same for its
  transitive dependencies as far as is knowable;
- any lighter alternative considered, including hand-rolling.

This keeps the dependency surface small and preserves the no-C-linkage
guarantee. The already-agreed foundation crates are listed in
`docs/port-plan.md`; adding even those to a specific manifest still warrants a
confirming note.

At the start of each phase, before writing any code, list the crates that phase
is expected to need and discuss them with the maintainer. Coding for a phase
begins only once its dependency set is agreed.

## Working conventions

- Pure Rust only. No C libraries and no C-linking `*-sys` crates.
- Byte-exact format fidelity is non-negotiable. Verify against golden fixtures
  produced by running the `ostree` tool as a black box, and cross-check both
  directions: the tool reads what the port writes, and the port reads what the
  tool writes.
- Follow the phased roadmap. Each phase is small and is reviewed and approved
  before the next begins.
- `#![forbid(unsafe_code)]` everywhere except two audited sites: a small `sys`
  module that wraps the few `rustix` calls that require it, and the
  allocation-counting test harness (`crates/ostrya-gvariant/tests/alloc.rs`),
  whose `GlobalAlloc` implementation cannot be expressed in safe Rust. That
  harness uses `#![deny(unsafe_code)]` with a scoped `#[allow(unsafe_code)]` on
  the single `impl`.
- Never load an unconstrained file blob into memory. Every operation on file
  content -- hashing, compression, storing, checkout, transfer -- is strictly
  async and streaming, processing bounded-size chunks regardless of object
  size. Whole-buffer handling is reserved for metadata objects, whose size the
  format caps.
- The core public types -- `Repo`, `Transaction`, `FileObject`, and the file
  content readers and writers -- must be `Send + Sync`, so they can be shared
  across tasks and threads. Pin this with compile-time assertions in tests as
  each type lands.
