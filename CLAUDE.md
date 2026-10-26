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

1. Rust-native. `liblzma` is the one C library the library links, for xz in
   static deltas. The `lzma-static` feature builds it from source and links it
   statically, requiring no C runtime of its own beyond the libc `std` already
   links. The feature is off by default, and a build without it links the
   system liblzma. `ostrya-cli` carries `lzma-static` in its default set, so
   the shipped `ostrya` binary needs no runtime liblzma. PCRE2 links on the
   same static terms in the `ostrya-cli` binary alone, where it compiles the
   `commit --tar-pathname-filter` expression the tool also compiles with
   PCRE2; that crate sets `publish = false`, so no published crate links it,
   and CI holds the rule that no other manifest may name `pcre2`. Nothing
   else links C. A macOS or Windows build of the portable crates also links
   system libraries of the operating system (see "Exception: system
   libraries of macOS and Windows").
   `rustix` handles the syscalls a portable async file API cannot express
   (fd-relative opens and metadata, xattrs, statx, FICLONE reflink, O_TMPFILE +
   linkat, `fcntl` record locks); streaming file I/O goes through the runtime's 
   async file.
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
patched version in the 0.9 series and holds a written exception. The
advisory covers RSA private-key operations. The fix is merged for the 0.10.0
release candidates of `rsa`. The spki engine performs RSA private-key
operations with `rsa` 0.9.10. In the CLI, `ostrya sign`, `commit`, `summary`,
`remote summary`, and `static-delta generate` sign with an RSA key. On the
receive endpoint, the server signs with the RSA key of an `[ex-ostrya key]`
group. A client can start such a signature and measure its time. The time of
the operation can then disclose information about the private key. The port
accepts this risk. Where a client that is not trusted can reach the endpoint,
use a P-256, a P-384, or an ed25519 key in an `[ex-ostrya key]` group. The
signer blinds each RSA private-key operation with a random value from the
operating system. Blinding makes the time signal smaller, and it does not
remove it.
RSA verification uses the public key alone, and the advisory does not apply
to it. GPG private keys stay with GnuPG and its agent. The exception is
reviewed when the tree takes a release of `rsa` with the fix.

RUSTSEC-2024-0447 against `pgp` is patched at 0.14.1. The tree takes 0.20.0,
so the advisory is closed for the version in the graph.

## Exception: system libraries of macOS and Windows

A macOS or Windows build of the portable crates links system libraries of the
operating system:

- On macOS, `ostrya-fetch` reads the trust store of the operating system
  through `rustls-native-certs`. `security-framework`,
  `security-framework-sys`, `core-foundation`, and `core-foundation-sys` link
  Security.framework and CoreFoundation.
- On Windows, `ostrya-rt` reaches `windows-sys` under both runtime backends:
  through `async-io`, `polling`, and `rustix` under `smol`, and through `mio`,
  `socket2`, and `tokio` under `tokio`. `ostrya-fetch` adds `schannel`, which
  `rustls-native-certs` uses to read the trust store, and `getrandom`, which
  `graviola` reaches. `windows-sys` gets its link attributes from
  `windows-link`, which emits them in the `raw-dylib` form. These crates link
  `ws2_32`, `crypt32`, and other system libraries. `getrandom` links
  `bcryptprimitives` in the `raw-dylib` form itself. `ostrya-sign` reaches
  `getrandom` 0.2.17 through `p256`, `p384`, and `rsa`, and that version
  links `bcrypt` and `advapi32` with `#[link]` attributes.

These libraries are part of the operating system. The build compiles no C
source for them, and the port ships no copy of them. No crate in the list
declares a `links` key, so the CI no-C guard passes them. A Linux build links
none of them.

The exception covers these system libraries on macOS and Windows alone. Any
other system library needs the confirmation of the maintainer before it
enters the graph.

## Authoritative design docs

The design lives in `docs/` and is the source of truth. Keep it in sync with the
code in the same change that alters behavior.

- `docs/format-reference.md` -- the byte-exact on-disk format. The correctness
  gate for every phase. Its part "Port extensions" specifies the formats and
  the protocols of the port alone. Examples are the push and pull protocols,
  the endpoints of `ostrya serve`, and the credential files. Each config key
  is in `ostrya-config(1)`.
- `docs/conformance/cli-behavior.md` -- the observed CLI behavior of the
  `ostree` command. It records the tree that a checkout writes, the tar
  options, the request order of a pull, and the `--fsync` vocabulary. It also
  records the output, the error text, and the exit status of each command in
  its section "CLI output formats".
- `docs/conformance/cli-surface.md` -- the CLI surface that the conformance
  matrix needs, and each difference between the `ostree` command and the
  port.
- `docs/decisions.md` -- the design decisions and the alternatives that were
  rejected, with the reason for each.
- `docs/roadmap.md` -- the work that is not done: planned features, gaps in
  the commands and the library, open decisions, and gaps in the tests.
- `CONTRIBUTING.md` -- the golden fixtures and the test gates.
- The rustdoc of each crate -- the public Rust API. The design principles
  of the API are in `crates/ostrya/README.md`, "Design".

The `spec:` values of the conformance records name headings of these
documents. `ostrya-conformance check` reports a value that names no heading,
so a change to a heading changes those values in the same commit.

## Requirement: package README files follow the crate docs

Each published crate has a `README.md` in its crate directory, and its
manifest sets `readme = "README.md"`. crates.io shows this file on the page of
the crate. `ostrya-cli` takes the workspace `README.md`.

The package `README.md` is a Markdown copy of the crate-level doc in
`src/lib.rs`. A change to one of the two changes the other in the same commit.
The copy differs from the crate-level doc in these points:

- The file starts with a `# <crate name>` heading, then the Ostrya sentence.
- A line before the first section links to the API documentation of the
  crate on docs.rs.
- Each heading is one level lower.
- Each intra-doc link is a code span with no link.
- An example has no hidden `# ` lines, and its code block is marked `rust`.
- The `README.md` of `ostrya` ends with a section "Design", which states
  the design principles of the API and its relation to the C API. This
  section is in the `README.md` alone.

A new published crate gets its `README.md` in the same form.

## Requirement: man pages follow the repository layout and config

Two man pages of the `ostrya` command describe the repository itself:

- `ostrya-repo(5)` describes the layout: the modes, the objects, each file
  and directory of a repository, the permissions, the served files, and the
  files outside the repository that the port reads. Its body is
  `crates/ostrya-cli/man/extra/ostrya-repo.5.roff`.
- `ostrya-config(1)` lists each key of the `config` file, ostree keys and
  port extensions, and the receive policy groups. The list is in
  `crates/ostrya-cli/man/extra/ostrya-config.1.roff`.

A change to the layout or to the config keys changes these pages in the same
commit. Examples are a new file or directory in a repository, a new mode, a
new key or group, a new default, and a new refused value. Write the pages
again after the change:

```sh
OSTRYA_BLESS_MAN=1 cargo test -p ostrya-cli --bin ostrya man_pages
```

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
`docs/decisions.md`, "Foundation crates"; adding even those to a specific manifest still warrants a
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
- With `default-features = false` the graph holds 156 packages under 155
  distinct names, measured with `cargo tree -p pgp -e normal,build`, of which
  91 were new to `Cargo.lock` when the crate was authorized. One name appears
  at two versions, `serdect` 0.2.0 and 0.3.0. No package in the graph declares
  a `links` key, and no package name in it ends in `-sys`.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only". Nine packages state a permissive choice in the
  legacy slash form, `A/B` or `A / B`. The CI license guard must normalize
  both forms to `A OR B` before it matches, so these nine pass and a copyleft
  license still fails.

### Authorized: the `url` crate

`url` 2.5.8 is authorized for `crates/ostrya-fetch` alone. It supplies the
one `Url::parse().join()` call in `crates/ostrya-fetch/src/lib.rs`, which
resolves the `Location` of a redirect against the URL of the response that
carried it. That is the only call the fetcher makes into the crate: a mirror
URL, a request URL, and a proxy URL are read by the `hyper::Uri` parse. Each
term below is measured on the resolved dependency graph.

- License `MIT OR Apache-2.0`.
- The default feature set is taken. `idna` is a mandatory dependency, so
  `default-features = false` drops neither `idna` nor the Unicode tables it
  carries.
- The graph holds 33 packages under 32 distinct names, measured with
  `cargo tree -p url -e normal,build`, which reads the features the workspace
  resolves. `syn` appears at two versions, 2.0.118 and 3.0.3. No package in
  the graph declares a `links` key, and no package name in it ends in `-sys`.
  `cargo metadata --format-version 1 --all-features`, which the license rule
  below prescribes, counts 36 packages under 35 distinct names for the same
  closure. Its resolve graph carries the optional `serde` dependency of `url`
  and the two packages behind it, which no feature set in this workspace turns
  on.
- Four packages carry a build script: `icu_normalizer_data`,
  `icu_properties_data`, `proc-macro2`, and `quote`. The first two compile
  Unicode data tables in Rust, and the last two were already in the graph.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only": 18 packages state `Unicode-3.0`, which is the
  ICU4X set, 11 state `MIT OR Apache-2.0`, 2 state `Apache-2.0 OR MIT`,
  `synstructure` states `MIT`, and `unicode-ident` states
  `(MIT OR Apache-2.0) AND Unicode-3.0`.
- The highest minimum supported Rust version in the graph is 1.88, stated by
  the ICU4X packages. The workspace pins 1.92, so the requirement holds.
- The call costs about 235 KiB of the stripped `target/release/ostrya`, the
  binary `cargo build --release -p ostrya-cli` writes with its default feature
  set. Two builds of one tree under one toolchain are compared. The second
  build stubs the call to give the `Location` value back unresolved and drops
  `url` from the manifest, because the stub alone leaves the crate in the
  link. `cargo tree -p ostrya-cli -i url` confirms that the second build
  reaches no `url` package. The first binary measures 13,491,736 bytes and
  the second 13,251,224, a difference of 240,512 bytes. Rebuilds of one tree
  are a few hundred bytes apart.

### Authorized: the `pkcs8` crate

`pkcs8` 0.10.2 is authorized for `crates/ostrya-fetch` alone. It decrypts an
encrypted PKCS#8 client key in `crates/ostrya-fetch/src/tls.rs` alone. Each
term below is measured on the resolved dependency graph.

- License `Apache-2.0 OR MIT`.
- `default-features = false` is mandatory, with the features `encryption`,
  `pem`, and `std`. `pem` reads the PEM armor, `encryption` supplies the PBES2
  decryption path, and `std` supplies the standard error trait.
- The `3des` and `des-insecure` features stay off. `pkcs5` resolves with
  `alloc` and `pbes2` alone, so no DES or 3DES decryption path is compiled.
  `des` 0.8.1 is in `Cargo.lock` through `pgp`, and no path from `pkcs8`
  reaches it.
- Five packages enter the graph with it: `pkcs5` 0.7.1, `cbc` 0.1.2, `pbkdf2`
  0.12.2, `salsa20` 0.10.2, and `scrypt` 0.11.0. No other crate in the
  workspace reaches any of the five. `sign-spki` and `verify-gpg` already
  reached `pkcs8` itself through `p256` and `pgp`.
- The graph holds 35 packages under 35 distinct names. No package in it
  declares a `links` key, and no package name in it ends in `-sys`. Four carry
  a build script -- `generic-array`, `libc`, `proc-macro2`, and `quote` -- and
  all four were already in the graph.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only": 22 packages state `MIT OR Apache-2.0`, 9 state
  `Apache-2.0 OR MIT`, `generic-array` states `MIT`, `subtle` states
  `BSD-3-Clause`, `unicode-ident` states `(MIT OR Apache-2.0) AND Unicode-3.0`,
  and `version_check` states the legacy `MIT/Apache-2.0` form the CI license
  guard normalizes.
- The highest minimum supported Rust version in the graph is 1.85. The
  workspace pins 1.92, so the requirement holds.

`pkcs8` 0.10.2 is also authorized for `crates/ostrya-sign`, behind each key
feature of the spki engine, now `sign-spki-p256`, `sign-spki-p384`, and
`sign-spki-rsa`. It reads the `PrivateKeyInfo` of a PKCS#8 secret key, so the
spki engine selects the key type from the algorithm OID before it decodes the
key.

- `default-features = false` is mandatory, and no feature is turned on.
- `der` 0.7.10 and `spki` 0.7.3 enter the same manifest behind the same
  features, with `default-features = false`. `der` takes the features
  `alloc`, `oid`, and `zeroize`, and `spki` takes no feature. No record is
  kept for these two crates.
- No package enters `Cargo.lock`. `p256` already reached `pkcs8`, `der`, and
  `spki` in `ostrya-sign`. The one change to the lock file is the three
  entries `der`, `pkcs8`, and `spki` in the dependency list of `ostrya-sign`.

### Authorized: the `rsa` crate

`rsa` 0.9.10 is authorized for `crates/ostrya-sign` alone, as an optional
dependency behind the feature `sign-spki-rsa`. It supplies RSA PKCS#1 v1.5
signatures with SHA-256 to the spki engine in
`crates/ostrya-sign/src/spki/rsa.rs`: the private key from its components,
the signer, and the verifier. Each term below is measured on the resolved
dependency graph.

- License `MIT OR Apache-2.0`.
- `default-features = false` is mandatory, with the features `sha2`,
  `u64_digit`, and `getrandom`. `sha2` supplies the SHA-256 `DigestInfo`
  prefix. `u64_digit` makes `num-bigint-dig` compute with 64-bit limbs.
  `getrandom` supplies `OsRng`, which blinds each private-key operation. The
  default features `std` and `pem` stay off: the engine reads PEM with
  `pem-rfc7468` and gives each error its own message. The features `hazmat`,
  `nightly`, `pkcs5`, and `serde` stay off. `pgp` takes the default features
  of `rsa`, so a build with `verify-gpg` also turns on `std` and `pem`.
- The engine does not use the key decoders of the crate.
  `RsaPublicKey::new` caps the modulus at `RsaPublicKey::MAX_SIZE`, 4096
  bits, and the SubjectPublicKeyInfo decoder calls it. The private-key
  decoders apply no cap, and give general errors, such as `KeyMalformed`,
  that do not state the reason of a refusal. The engine reads the key
  structures with `pkcs1` 0.7.5, which `rsa` re-exports, checks the size and
  the number of primes itself, so that it gives a message for each refusal,
  and calls `RsaPublicKey::new_with_max_size` with 16384 bits.
  `RsaPrivateKey::from_components` applies no cap and accepts more than two
  primes, so the engine checks the number of primes before the call.
- The graph holds 55 packages under 55 distinct names on the host target,
  measured with `cargo tree -p rsa -e normal,build`, which reads the
  features the workspace resolves. With `--target all` it holds 59, adding
  `serde_derive` 1.0.229, `syn` 3.0.3, `wasi` 0.11.1+wasi-snapshot-preview1,
  and `zerocopy-derive` 0.8.56. `cargo metadata --format-version 1
  --all-features` counts the same 59 packages under 58 distinct names for
  the closure, with `syn` at 2.0.118 and 3.0.3.
- A build of `ostrya-sign` with `sign-spki-rsa` alone holds 54 packages
  under 54 distinct names on the host target, measured with
  `cargo tree -p ostrya-sign --no-default-features --features sign-spki-rsa
  -e normal,build`. The count includes `ostrya-sign` and its other
  dependencies. With `--target all` it holds 57. The graph holds no `p256`.
- No package in the graph declares a `links` key, and no package name in it
  ends in `-sys`.
- Ten packages carry a build script: `generic-array`, `libc`, `libm`,
  `num-bigint-dig`, `num-traits`, `proc-macro2`, `quote`, `serde`,
  `serde_core`, and `zerocopy`. All ten were already in the graph.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only". On the host target, 33 packages state
  `MIT OR Apache-2.0`, 13 state `Apache-2.0 OR MIT`, `generic-array`,
  `libm`, and `spin` state `MIT`, `num-bigint-dig` and `version_check` state
  the legacy `MIT/Apache-2.0` form the CI license guard normalizes,
  `zerocopy` states `BSD-2-Clause OR Apache-2.0 OR MIT`, `subtle` states
  `BSD-3-Clause`, `flagset` states `Apache-2.0`, and `unicode-ident` states
  `(MIT OR Apache-2.0) AND Unicode-3.0`. With `--target all`, `serde_derive`
  and `syn` 3.0.3 state `MIT OR Apache-2.0`, `wasi` states
  `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`, and
  `zerocopy-derive` states `BSD-2-Clause OR Apache-2.0 OR MIT`.
- The highest minimum supported Rust version in the graph is 1.85, stated
  by `base64ct`, `zeroize`, and `zeroize_derive`. `rsa` states 1.65. The
  workspace pins 1.92, so the requirement holds.
- `rsa` holds no `unsafe` code. `num-bigint-dig` holds two
  `String::from_utf8_unchecked` calls in its text conversion.
- The crate was in the graph through `pgp`, under `verify-gpg` of
  `crates/ostrya`, so no package enters `Cargo.lock`. The lock file gains two
  entries: `rsa` in the dependency list of `ostrya-sign`, and `sha2` in the
  dependency list of `rsa`, which the feature `sha2` turns on.
- The root `Cargo.toml` sets `opt-level = 3` in `profile.dev` for
  `num-bigint-dig` and `rsa`. The unit test that signs and verifies with
  keys of 2048, 8192, and 16384 bits takes less than 1 second with it, and
  about 10 seconds without it.
- RUSTSEC-2023-0071 applies to the crate. "Advisory exceptions" states the
  terms.

### Authorized: the `p384` crate

`p384` 0.13.1 is authorized for `crates/ostrya-sign` alone, as an optional
dependency behind the feature `sign-spki-p384`. It supplies ECDSA P-384 to
the spki engine: the secret key from a PKCS#8 or a SEC1 key, the signer, and
the verifier. The engine hashes the data with SHA-256 and calls
`sign_prehash` and `verify_prehash`. Each term below is measured on the
resolved dependency graph.

- License `Apache-2.0 OR MIT`.
- `default-features = false` is mandatory, with the features `ecdsa`,
  `pkcs8`, and `std`, as `p256` takes. The features `pem` and `ecdh` stay
  off. `pgp` takes the default features of `p384`, so a build with
  `verify-gpg` also turns on `pem` and `ecdh`.
- The feature `ecdsa` turns on `sha384`, so the default `Signer` and
  `Verifier` of the crate hash with SHA-384. The engine does not call them. `sign_prehash` makes the
  RFC 6979 nonce with HMAC-SHA-384 for each prehash, so a signature of the
  engine is the same bytes on each run for the same key and data.
- The graph holds 61 packages under 61 distinct names on the host target,
  measured with `cargo tree -p p384 -e normal,build`, which reads the
  features the workspace resolves. With `--target all` it holds 64 under 63
  distinct names, adding `serde_derive` 1.0.229, `syn` 3.0.3, and `wasi`
  0.11.1+wasi-snapshot-preview1. `cargo metadata --format-version 1
  --all-features` counts the same 64 packages under 63 distinct names for
  the closure, with `syn` at 2.0.118 and 3.0.3.
- No package in the graph declares a `links` key, and no package name in it
  ends in `-sys`.
- Nine packages carry a build script: `generic-array`, `libc`,
  `proc-macro2`, `quote`, `radium`, `serde`, `serde_core`, `serde_json`, and
  `zmij`. All nine were already in the graph.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only". On the host target, 27 packages state
  `MIT OR Apache-2.0`, 20 state `Apache-2.0 OR MIT`, `bitvec`, `funty`,
  `generic-array`, `radium`, `tap`, `wyz`, and `zmij` state `MIT`, `ff`,
  `group`, and `version_check` state the legacy `MIT/Apache-2.0` form the CI
  license guard normalizes, `memchr` states `Unlicense OR MIT`, `subtle`
  states `BSD-3-Clause`, `flagset` states `Apache-2.0`, and `unicode-ident`
  states `(MIT OR Apache-2.0) AND Unicode-3.0`. With `--target all`, `wasi`
  states `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`.
- The highest minimum supported Rust version in the graph is 1.85, stated
  by `base64ct`, `zeroize`, and `zeroize_derive`. `p384` states 1.65. The
  workspace pins 1.92, so the requirement holds.
- `p384`, `primeorder`, `ecdsa`, and `elliptic-curve` set
  `#![forbid(unsafe_code)]`. `rfc6979` holds no `unsafe` code.
- The crate was in the graph through `pgp`, under `verify-gpg` of
  `crates/ostrya`, so no package enters `Cargo.lock`. The one change to the
  lock file is the entry `p384` in the dependency list of `ostrya-sign`.

### Authorized: the `getrandom` crate

`getrandom` 0.3.4 is authorized for `crates/ostrya-server` alone. It
supplies the one `getrandom::fill` call in
`crates/ostrya-server/src/session.rs`, which fills the 32 random bytes of a
session id of the receive endpoint from the random source of the operating
system. Each term below is measured on the resolved dependency graph.

- License `MIT OR Apache-2.0`.
- No feature is turned on. The default feature set is empty, and the two
  features of the crate, `std` and `wasm_js`, stay off. `cargo tree -i
  getrandom@0.3.4 -e features --workspace` shows the feature `default`
  alone.
- The crate is in the graph through `graviola`, under `rustls-graviola` of
  `crates/ostrya-fetch`, so no package entered `Cargo.lock` with it. The one
  line the lock file gains is the entry `getrandom 0.3.4` in the dependency
  list of `ostrya-server`. `Cargo.lock` also holds `getrandom` 0.2.17,
  through `rand_core`, and 0.4.3, through `jobserver` under the build
  dependency `cc`. The authorization names 0.3.4 alone.
- The graph holds 3 packages under 3 distinct names on the host target,
  measured with `cargo tree -p getrandom@0.3.4 -e normal,build`:
  `getrandom`, `cfg-if` 1.0.4, and `libc` 0.2.186. With `--target all` it
  holds 6, adding `r-efi` 5.3.0, `wasip2` 1.0.4+wasi-0.2.12, and
  `wit-bindgen` 0.57.1. No package in the graph declares a `links` key, and
  no package name in it ends in `-sys`.
- Three packages carry a build script: `getrandom`, `libc`, and
  `wit-bindgen`. All three were already in the graph.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only": `getrandom`, `cfg-if`, and `libc` state `MIT
  OR Apache-2.0`, `r-efi` states `MIT OR Apache-2.0 OR LGPL-2.1-or-later`,
  which qualifies through its permissive options, and `wasip2` and
  `wit-bindgen` state `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR
  MIT`.
- The highest minimum supported Rust version in the graph is 1.87.0,
  stated by `wasip2`, which no Linux build compiles. On the host target it
  is 1.65, stated by `libc`. The workspace pins 1.92, so the requirement
  holds.
- `ostrya-server` builds on Linux alone, so the exception in "Exception:
  system libraries of macOS and Windows" does not change.

### Authorized: the `indicatif` crate

`indicatif` 0.18.6 is authorized for `crates/ostrya-cli` alone. It draws the
progress bar of `ostrya push` and `ostrya push-tree` on standard error. Each
term below is measured on the resolved dependency graph.

- License `MIT`.
- `default-features = false` is mandatory, with the feature
  `unicode-width` alone. The default feature `wasmbind` reaches
  `web-time` on a `wasm32` target, and through it `wasm-bindgen-shared`,
  which declares the `links` key `wasm_bindgen`, so the CI links guard
  fails with the default features. The feature `rayon` stays off: it
  reaches `rayon-core`, which declares a `links` key too.
- The graph holds 6 packages under 6 distinct names on the host target,
  measured with `cargo tree -p indicatif -e normal,build`: `indicatif`
  0.18.6, `console` 0.16.6, `libc` 0.2.186, `portable-atomic` 1.15.0,
  `unicode-width` 0.2.2, and `unit-prefix` 0.5.2. With `--target all` it
  holds 9, adding `encode_unicode` 1.0.0, `windows-sys` 0.61.2, and
  `windows-link` 0.2.1, which `console` reaches on Windows, where
  `ostrya-cli` is not built.
- No package in the graph declares a `links` key. On Linux no package name
  in it ends in `-sys`. `windows-sys` is in the graph on Windows alone.
- Two packages carry a build script: `libc`, which was already in the
  graph, and `portable-atomic`.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only": `indicatif`, `console`, and `unit-prefix` state
  `MIT`, `libc`, `unicode-width`, `windows-sys`, and `windows-link` state
  `MIT OR Apache-2.0`, and `portable-atomic` and `encode_unicode` state
  `Apache-2.0 OR MIT`.
- The highest minimum supported Rust version in the graph is 1.85, stated
  by `indicatif`. The workspace pins 1.92, so the requirement holds.
- Six packages entered `Cargo.lock` with it: `indicatif`, `console`,
  `portable-atomic`, `unicode-width`, `unit-prefix`, and `encode_unicode`.

### Authorized: the `terminal_size` crate

`terminal_size` 0.4.4 is authorized for `crates/ostrya-cli` alone. It enters
the graph through the `wrap_help` feature of `clap`, which wraps the
`--help` text to the width of the terminal. No crate of the workspace names
it directly. Each term below is measured on the resolved dependency graph.

- License `MIT OR Apache-2.0`.
- The crate has no features. On Unix it takes `rustix` with the feature
  `termios`.
- The graph holds 4 packages under 4 distinct names on the host target,
  measured with `cargo tree -p terminal_size -e normal,build`:
  `terminal_size` 0.4.4, `rustix` 1.1.4, `bitflags` 2.13.0, and
  `linux-raw-sys` 0.12.1. With `--target all` it holds 8, adding `errno`
  0.3.14, `libc` 0.2.186, `windows-sys` 0.61.2, and `windows-link` 0.2.1.
  `ostrya-cli` is not built on Windows.
- No package in the graph declares a `links` key. `linux-raw-sys` is the one
  package name on the host target that ends in `-sys`. It holds Rust
  declarations of the Linux syscall interface and links no C library.
  `windows-sys` is in the graph on Windows alone.
- Two packages carry a build script: `rustix` and `libc`. Both were already
  in the graph.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only": `terminal_size`, `bitflags`, `errno`, `libc`,
  `windows-sys`, and `windows-link` state `MIT OR Apache-2.0`, and `rustix`
  and `linux-raw-sys` state
  `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`.
- The highest minimum supported Rust version in the graph is 1.71, stated
  by `terminal_size`, `windows-sys`, and `windows-link`. On the host target
  `terminal_size` alone states it. The workspace pins 1.92, so the
  requirement holds.
- One package entered `Cargo.lock` with it: `terminal_size`.

### Authorized: the `x509-cert` crate

`x509-cert` 0.2.5 is authorized for `crates/ostrya-server` alone. It reads
the subject CN and the URI SANs of a client certificate from the DER bytes
of the certificate. The certificate comes from the TLS handshake or from the
header of a trusted proxy. Each term below is measured on the resolved
dependency graph.

- License `Apache-2.0 OR MIT`.
- `default-features = false` is mandatory, and no feature is turned on. The
  default features `pem` and `std` stay off. The server decodes PEM with
  `rustls-pki-types`, through the re-export of `rustls`, so the crate
  decodes DER alone. With the default features, `Cargo.lock` gains
  `tls_codec` 0.4.2 and `tls_codec_derive` 0.4.2 through the weak feature
  `tls_codec?/std`, and no build compiles them.
- The crate turns on the features `derive` and `flagset` of `der` 0.7.10
  and the feature `db` of `const-oid` 0.9.6. Both packages were already in
  the graph through `pgp` and `pkcs8`.
- Version 0.3.0 is not taken. It takes `der` 0.8, `spki` 0.8, and
  `const-oid` 0.10, so each of the three would be in the graph at two
  versions, and six packages would enter `Cargo.lock`.
- The graph holds 14 packages under 14 distinct names, measured with
  `cargo tree -p x509-cert -e normal,build`: `x509-cert` 0.2.5, `der`
  0.7.10, `der_derive` 0.7.3, `spki` 0.7.3, `const-oid` 0.9.6, `flagset`
  0.4.7, `pem-rfc7468` 0.7.0, `base64ct` 1.8.3, `zeroize` 1.9.0,
  `zeroize_derive` 1.5.0, `proc-macro2` 1.0.106, `quote` 1.0.46, `syn`
  2.0.118, and `unicode-ident` 1.0.24. `pem-rfc7468` and `base64ct` are in
  it because other crates of the workspace turn on the feature `pem` of
  `der`. `zeroize` is in it because other crates turn on the feature
  `zeroize` of `der`. `zeroize_derive` is in it because `pgp` and
  `x25519-dalek` turn on the feature `zeroize_derive` of `zeroize`. With
  `--target all` it holds the same 14.
  `cargo metadata --format-version 1 --all-features` counts the same 14 for
  the closure.
- No package in the graph declares a `links` key, and no package name in it
  ends in `-sys`.
- Two packages carry a build script: `proc-macro2` and `quote`. Both were
  already in the graph.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only": 9 packages state `Apache-2.0 OR MIT`, 3 state
  `MIT OR Apache-2.0`, `flagset` states `Apache-2.0`, and `unicode-ident`
  states `(MIT OR Apache-2.0) AND Unicode-3.0`.
- The highest minimum supported Rust version in the graph is 1.85, stated
  by `base64ct`, `zeroize`, and `zeroize_derive`. `x509-cert`, `der_derive`,
  and `flagset` state 1.65. The workspace pins 1.92, so the requirement
  holds.
- Three packages enter `Cargo.lock` with it: `x509-cert` 0.2.5,
  `der_derive` 0.7.3, and `flagset` 0.4.7.
- The read of the subject CN and of the URI SANs costs about 106 KiB of the
  stripped `target/release/ostrya`, the binary
  `cargo build --release -p ostrya-cli` writes with its default feature
  set. Two builds of one tree under one toolchain are compared. The second
  build stubs the read in `crates/ostrya-server/src/cert.rs` to give no CN,
  no end of the validity period, and no claims, and drops `x509-cert` from
  `crates/ostrya-server/Cargo.toml`, because the stub alone leaves the crate
  in the link. `cargo tree -p ostrya-cli -i x509-cert` confirms that the
  second build reaches no `x509-cert` package. The first binary measures
  20,271,128 bytes and the second 20,162,840, a difference of 108,288 bytes.
  A rebuild of the first tree gives the same byte count.

### Authorized: the `hmac` crate

`hmac` 0.12.1 is authorized for `crates/ostrya-remote` alone, as an optional
dependency behind the feature `s3`. It supplies HMAC-SHA256 to the SigV4
signer in `crates/ostrya-remote/src/s3/sigv4.rs`, which derives the signing
key and the signature with it. `sha2` 0.10, a foundation crate, enters the
same manifest behind the same feature with `default-features = false` and the
feature `std`. Each term below is measured on the resolved dependency graph.

- License `MIT OR Apache-2.0`.
- No feature is turned on. The resolved set holds the feature `reset`,
  which `rfc6979` under `pgp` turns on.
- The crate takes `digest` alone. The graph holds 19 packages under 19
  distinct names on the host target, measured with
  `cargo tree -p hmac -e normal,build`, which reads the features the
  workspace resolves: `hmac` 0.12.1, `digest` 0.10.7, `block-buffer` 0.10.4,
  `generic-array` 0.14.7, `typenum` 1.20.1, `zeroize` 1.9.0,
  `zeroize_derive` 1.5.0, `proc-macro2` 1.0.106, `quote` 1.0.46, `syn`
  2.0.118, `unicode-ident` 1.0.24, `version_check` 0.9.5, `const-oid` 0.9.6,
  `crypto-common` 0.1.7, `rand_core` 0.6.4, `getrandom` 0.2.17, `cfg-if`
  1.0.4, `libc` 0.2.186, and `subtle` 2.6.1. Other crates of the workspace
  turn on the features of `digest`, `crypto-common`, and `generic-array` that
  pull in `const-oid`, `rand_core`, and `zeroize`. With `--target all` it
  holds 20, adding `wasi` 0.11.1+wasi-snapshot-preview1, which `getrandom`
  reaches on a WASI target. `cargo metadata --format-version 1
  --all-features` counts the same 20 for the closure.
- No package in the graph declares a `links` key, and no package name in it
  ends in `-sys`.
- Four packages carry a build script: `generic-array`, `libc`,
  `proc-macro2`, and `quote`. All four were already in the graph.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only": 12 packages state `MIT OR Apache-2.0`, 3 state
  `Apache-2.0 OR MIT`, `generic-array` states `MIT`, `subtle` states
  `BSD-3-Clause`, `unicode-ident` states `(MIT OR Apache-2.0) AND Unicode-3.0`,
  `version_check` states the legacy `MIT/Apache-2.0` form the CI license
  guard normalizes, and `wasi` states
  `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`.
- The highest minimum supported Rust version in the graph is 1.85, stated
  by `zeroize` and `zeroize_derive`. `hmac` states none. The workspace pins
  1.92, so the requirement holds.
- The crate was in the graph through `pbkdf2`, under `pkcs8` of
  `crates/ostrya-fetch`, so no package entered `Cargo.lock` with it. The one
  change to the lock file is the two entries `hmac` and `sha2` in the
  dependency list of `ostrya-remote`.
- The signer is in the binary of `ostrya-cli`, which turns on the feature
  `s3` in its default set. The cost of `hmac` alone is not measured.
  The feature `s3` costs 1,054,848 bytes of the stripped
  `target/release/ostrya`, the binary `cargo build --release -p ostrya-cli`
  writes with its default feature set, which holds `s3`. Two builds of one
  tree under one toolchain are compared. The second build takes the default
  set without `s3`: `--no-default-features --features
  smol,spki,gpg,receive,push,serve,send,lzma-static`. `cargo tree -p
  ostrya-cli -i quick-xml` with these features reaches no `quick-xml`
  package. The first binary measures 22,756,264 bytes and the second
  21,701,416. A rebuild of the first tree gives the same byte count. The
  cost covers each part of the S3 support: the signer, the XML reader, the
  bucket client, the pull, the push, the writer lock, and the commands.

### Authorized: the `quick-xml` crate

`quick-xml` 0.42.0 is authorized for `crates/ostrya-remote` alone, as an
optional dependency behind the feature `s3`. It reads the XML bodies of the
S3 responses: `ListObjectsV2`, `ListMultipartUploads`, the results of
`CreateMultipartUpload` and `CompleteMultipartUpload`, and the S3 `Error`
document. The reader reads a body of at most 4 MiB from a buffer in memory.
Each term below is measured on the resolved dependency graph.

- License `MIT`.
- `default-features = false` is mandatory, and no feature is turned on. The
  default feature set is empty. The features `encoding`, `serialize`,
  `serde-types`, `async-tokio`, `arbitrary`, `document-features`,
  `escape-html`, and `overlapped-lists` stay off. `encoding` pulls
  `encoding_rs` 0.8.42, under `(Apache-2.0 OR MIT) AND BSD-3-Clause`, with
  a build script, and four more packages: `simdutf8`, `core_detect`,
  `multiversion_no_op`, and `scopeguard`. S3 sends UTF-8 alone, so the
  reader has no use for the feature.
- The reader refuses a `DOCTYPE`. The crate does not read entity
  definitions and does not expand an entity. It gives each reference to the
  caller, and the caller accepts the five predefined entities and character
  references alone. The crate has no depth limit, so the caller refuses a
  body whose elements are deeper than 32 levels.
- The graph holds 2 packages under 2 distinct names on the host target:
  `quick-xml` 0.42.0 and `memchr` 2.8.3, measured with
  `cargo tree -p quick-xml -e normal,build`, which reaches the crate through
  the default set of `ostrya-cli`. The subtree of `quick-xml` in
  `cargo tree --all-features -p ostrya-remote -e normal,build` holds the
  same 2. With
  `--target all` it holds the same 2. `cargo metadata --format-version 1
  --all-features` counts the same 2 for the closure.
- No package in the graph declares a `links` key, and no package name in it
  ends in `-sys`.
- No package in the graph carries a build script.
- Every license in the graph is permissive by the rule in "Requirement:
  permissive licenses only": `quick-xml` states `MIT`, and `memchr` states
  `Unlicense OR MIT`.
- The highest minimum supported Rust version in the graph is 1.86, stated
  by `quick-xml`. `memchr` states 1.61. The workspace pins 1.92, so the
  requirement holds.
- `quick-xml` sets `#![forbid(unsafe_code)]`. `memchr` holds `unsafe` code
  for its SIMD paths, and it was already in the graph.
- One package enters `Cargo.lock` with it: `quick-xml` 0.42.0. `memchr`
  2.8.3 was already in the graph through `nom`, `pgp`, `serde_json`, and
  `buffer-redux`. The lock file also gains the entry `quick-xml` in the
  dependency list of `ostrya-remote`.
- The reader is in the binary of `ostrya-cli`, which turns on the feature
  `s3` in its default set. In a test program, the reader of the S3 listing
  and the S3 error costs 45,528 bytes of a stripped release binary.
  The feature `s3` costs 1,054,848 bytes of the stripped
  `target/release/ostrya`, the binary `cargo build --release -p ostrya-cli`
  writes with its default feature set, which holds `s3`. Two builds of one
  tree under one toolchain are compared. The second build takes the default
  set without `s3`: `--no-default-features --features
  smol,spki,gpg,receive,push,serve,send,lzma-static`. `cargo tree -p
  ostrya-cli -i quick-xml` with these features reaches no `quick-xml`
  package. The first binary measures 22,756,264 bytes and the second
  21,701,416. A rebuild of the first tree gives the same byte count. The
  cost covers each part of the S3 support: the signer, the XML reader, the
  bucket client, the pull, the push, the writer lock, and the commands.

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
  `std` already links (as `liblzma` does under the `lzma-static` feature).
- Byte-exact format fidelity is non-negotiable. Verify against golden fixtures
  produced by running the `ostree` tool as a black box, and cross-check both
  directions: the tool reads what the port writes, and the port reads what the
  tool writes.
- Work in phases. Each phase is small and is reviewed and approved before
  the next begins.
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

## Release sequence

A push of a `v*` tag publishes the workspace to crates.io through
`.github/workflows/release.yml`. That workflow depends on no CI job, and
`cargo publish --workspace` cannot roll back. All steps below are local. Do
not push the tag and do not run `cargo publish` without the dry-run flag
until the maintainer asks for that step in words.

1. Set the new version in `[workspace.package] version` and in the path
   versions of `[workspace.dependencies]` in the root `Cargo.toml`.
2. Run `cargo update --workspace`, so that `Cargo.lock` has the new version
   of each member.
3. Write the man pages of the `ostrya` command again from the `clap`
   definition:

   ```sh
   OSTRYA_BLESS_MAN=1 cargo test -p ostrya-cli --bin ostrya man_pages
   ```

   Read the diff of `crates/ostrya-cli/man/`. Each change must come from a
   change to the help text or to a file in `crates/ostrya-cli/man/extra/`.
4. Add an entry for the new version at the top of
   `crates/ostrya-cli/debian/changelog` and of
   `crates/ostrya-mountd/debian/changelog`. Each Debian package takes its
   version from its entry, so each release needs one in each file, and its
   version is the workspace version. Use the form of the entries in the
   file: the line `<source> (<version>) unstable; urgency=medium`, where
   `<source>` is `ostrya` or `ostrya-mountd`, one `*` item for each change
   to the command or its package, and the line of the maintainer with the
   date in the `date -R` format. If the command and the package do not
   change, the one item is `New upstream release.`
5. Run the gates of `.github/workflows/ci.yml`. Run the tests with
   `OSTRYA_REQUIRE_MULTIGROUP=1 OSTRYA_REQUIRE_GNUPG=1 OSTRYA_REQUIRE_S3=1`,
   as CI does.
6. Commit as `chore(release): bump the workspace version to <version>`. The
   commit includes the man pages of step 3 and the changelog entries of
   step 4.
7. Run `cargo publish --workspace --dry-run --locked`. This uploads nothing.
   It refuses an uncommitted tracked file, so it comes after the commit. Fix
   a failure with `git commit --amend`.
8. Make a signed tag: `git tag -s -m 'ostrya <version>' v<version>`.
