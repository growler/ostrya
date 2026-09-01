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
a command-line-compatible CLI is a late phase, built only to carry the
project's own CLI-behavior conformance suite as an external conformance
check; the upstream shell test suite ships as part of libostree's LGPL
source and is never read, run, or vendored (see
"Licensing and clean-room discipline"). The `ostree` tool is treated
as a black box: its observed behavior and the public documentation are the only
inputs.

## CLI compatibility is functional, not literal

The CLI aims at functional compatibility. A command the port carries takes the
tool's option names and values, does the same work, and writes the same bytes
into the repository. The commit checksum is the oracle wherever one exists.

Character-for-character compatibility is not a goal, and time must not be spent
pursuing it. Outside the scope, and recorded as a divergence rather than
removed:

- the wording, the punctuation, and the character offsets of a diagnostic;
- the exit path a refusal takes, so long as the port exits non-zero and writes
  no object and no ref;
- the dialect an option's value is read in, where the tool reads it through a C
  library the port does not link, together with that library's limits;
- the order of lines the tool emits from a hash container.

Byte-exact fidelity is required of the repository and never of the terminal.

Two rules follow, and they decide the design of any option the port cannot
reproduce exactly:

1. Refuse rather than reinterpret. Where the port cannot carry a value, it
   refuses it and exits non-zero. Accepting a value under a meaning of the
   port's own writes different bytes, which is the failure this project exists
   to avoid.
2. Do not hand-roll a parser or an engine to imitate a C library. Take an
   authorized crate and record where its dialect parts from the tool's. A
   from-scratch implementation of somebody else's dialect carries the bugs of
   both. `docs/conformance/cli-surface.md`, "Scope of CLI compatibility",
   states this in full.

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
   `ostrya-rt` crate: `smol` by default, `tokio` optional. Only `ostrya-rt`
   knows the backend.
3. Multiple concurrent transactions within a single process.
4. Capable of an external conformance gate matching the scope of ostree's own
   test suite, authored from scratch from black-box observation, never by
   running or vendoring the upstream suite (scope is phased: library format
   and format-primitive unit tests first, the port's own CLI-driven
   conformance suite later, admin/sysroot optional).
5. Extensions: GPG commit signing through the system GnuPG binaries (no
   gpgme linkage), GPG signature verification and key management in the
   process over the `pgp` crate (rPGP), which is permissively licensed and
   links no C library, composefs/EROFS export, tar import/export, AWS S3
   push/pull, and ssh git-style push/pull.
6. A development-only repository mode, `bare-user-shared`, as an optional
   nice-to-have add-on.

Faithful on disk means byte-for-byte identical format, checksums, and
algorithms. The API is redesigned to be idiomatic Rust rather than mirroring the
C GObject surface.

## Advisory exceptions

RUSTSEC-2023-0071 against `rsa` 0.9.10, the Marvin timing attack, has no
patched version and holds a written exception. The advisory covers RSA
private-key operations. This port performs public-key verification alone, RSA
private keys stay with GnuPG and its agent, and no code path in the tree
performs an RSA private-key operation. The exception is reviewed if a later
phase adds such an operation.

RUSTSEC-2024-0447 against `pgp` is patched at 0.14.1. The tree takes 0.20.0,
so the advisory is closed for the version in the graph.

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
- that its license and the licenses of its transitive dependencies are all
  permissive (see "Requirement: permissive licenses only");
- any lighter alternative considered, including hand-rolling.

This keeps the dependency surface small and preserves the no-C-linkage
guarantee. The already-agreed foundation crates are listed in
`docs/port-plan.md`; adding even those to a specific manifest still warrants a
confirming note.

At the start of each phase, before writing any code, list the crates that phase
is expected to need and discuss them with the maintainer. Coding for a phase
begins only once its dependency set is agreed.

### Authorized: the `pgp` crate

`pgp` 0.20.0 (rPGP) is authorized for `crates/ostrya` alone. It supplies
in-process GPG signature verification and key management. Each term below is
measured on the resolved dependency graph.

- License `MIT OR Apache-2.0`.
- Minimum supported Rust version 1.88. The workspace pins 1.92, so the
  requirement holds.
- `default-features = false` is mandatory.
- The `default` feature stays off. It pulls `bzip2` 0.6, whose own default
  feature pulls `libbz2-rs-sys` 0.2.5 under license `bzip2-1.0.6`, which the
  list in "Requirement: permissive licenses only" does not carry, and whose
  `bzip2-sys` feature reaches the C library. A detached signature carries no
  compressed packet, so the verification path has no use for the feature.
- The `asm` feature stays off. It pulls `sha1-asm` and turns on the assembly
  paths in `sha2`.
- With `default-features = false` the graph holds 152 packages under 150
  distinct names, of which 91 are new to `Cargo.lock`. Two names appear at two
  versions: `serdect` 0.2.0 and 0.3.0, `syn` 2.0.119 and 3.0.4. No package in
  the graph declares a `links` key, and no package name in it ends in `-sys`.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only". Nine packages state a permissive choice in the
  legacy slash form, `A/B` or `A / B`. The CI license guard must normalize
  both forms to `A OR B` before it matches, so these nine pass and a copyleft
  license still fails.

## Requirement: permissive licenses only

The library and everything it links -- every crate in the dependency graph,
across all workspace crates and every feature combination -- must be under a
permissive license. This keeps the MIT library free of copyleft obligations
for downstream consumers.

Permissive licenses are: MIT, Apache-2.0 (including the
`Apache-2.0 WITH LLVM-exception` variant), the BSD family (0BSD, BSD-1-Clause,
BSD-2-Clause, BSD-3-Clause), ISC, Zlib, Unlicense, BSL-1.0, and Unicode-3.0. A
crate whose SPDX expression offers a choice (for example `MIT OR Apache-2.0` or
`MIT OR Apache-2.0 OR LGPL-2.1-or-later`) qualifies when at least one option is
permissive.

Copyleft and weak-copyleft licenses are prohibited: GPL, LGPL, AGPL, MPL, EUPL,
CDDL, CeCILL, and any license with comparable reciprocal terms. A crate offered
only under such a license must not enter the graph, not even behind an optional
feature.

This is verifiable with `cargo metadata`: the `license` field of every package
in `cargo metadata --format-version 1 --all-features` must be permissive by the
rule above. Any crate with a null or empty `license` field must be inspected
by hand before it is accepted.

## Working conventions

- Every added crate must be authorized by the operator before it enters any
  manifest. Do not suggest a crate that links a C library unless that library
  is statically linked and requires no C runtime of its own beyond the libc
  `std` already links (as `liblzma` does).
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
