# Conformance harness

The harness executes the records in this directory and reports what each cell
proved. `README.md` defines the axes, the outcome vocabulary, the corpora, and
the privilege tiers. This document defines the program that runs them.

## Principles

Four properties govern every design decision below.

- The record is the program. A cell states its invocation, its oracles, and its
  expected results in the record. The runner executes that statement. Adding a
  cell costs a record.
- A verdict states what the run observed. A cell that the run could not observe
  reports as skipped, with the reason. Conformance is reported only when both
  implementations ran and their observations agreed.
- The cost of Rust code grows with the number of verbs, and the verb set is
  closed: corpora, setups, oracles, and probes. M0 and M1 hold 288 cells
  between them today, M10 is growing with Phase 17, and eight families remain
  to write.
- The harness drives the two binaries. It links neither implementation's
  library, so it observes the same surface a user observes.

## Placement

`crates/ostrya-conformance`, a workspace member with `publish = false`. It
builds a library and a binary, both named `ostrya-conformance`.

The crate holds `#![forbid(unsafe_code)]` and follows the workspace edition and
`rust-version`.

The binary runs standalone. Cells at tiers T2 through T4 run under `unshare -r`
or as root, on a machine that holds no cargo installation and no source tree.
The library exists so the cargo test targets described under "Cargo and CI
wiring" can call the same code.

### Dependencies

One dependency, `rustix`, authorized by the maintainer on 2026-08-02:

```
rustix = { version = "1", default-features = false, features = ["std", "fs", "process"] }
```

Tier detection calls `rustix::process::geteuid` for the effective uid and
`rustix::process::getgroups` for the supplementary group list. The `manifest`
oracle calls `fs::llistxattr` and `fs::lgetxattr`, and the corpora call
`fs::lsetxattr`, `fs::mknodat`, and `fs::chownat`. `crates/ostrya` and
`crates/ostrya-sys` already declare `rustix` at the same major version with
`fs`, so the crate adds no package to the dependency graph and `process` is
the only feature added over what those two enable.

SELinux detection reads `/sys/fs/selinux/enforce`. The initial user namespace
is recognized by `/proc/self/uid_map` holding the identity map over the whole
id space. User-namespace availability is probed by running `unshare -r true`.

The harness carries its own SHA-256 for the `manifest` oracle's content
digest, because it links no repository-format code.

No other external crate enters this manifest. `crates/ostrya-cli` takes the
crate as a dev-dependency for the test target under "Cargo and CI wiring".

## What the harness runs

Two implementation handles:

- `port` -- the `ostrya` binary, from `--ostrya PATH`, then `OSTRYA_BIN`, then a
  `PATH` lookup.
- `reference` -- the `ostree` binary, from `--ostree PATH`, then `OSTREE_BIN`,
  then a `PATH` lookup.

Each handle resolves at startup. A handle that does not resolve makes every
cell that names it report as skipped with the reason `reference-absent`.

## Cell identity

Every cell carries a stable identifier. The identifier selects a single cell on
the command line, names its artifact directory, and keys its entry in the JSON
report.

- M0: `m0/<corpus>/<mode>`, for example `m0/C4/bare-user`.
- M1: `m1/<direction>/<op>/<mode>`, for example `m1/d2/checkout-copy/bare-user`.
  The direction comes from the `created-by`, `populated-by`, and `operated-by`
  triple: `t t p` is `d1`, and `p p t` is `d2`.
- Transfer families: `m2/<src-mode>/<dst-mode>`, and the same shape for M3
  through M8.
- M10: `m10/<cell>`, where the record's `cell:` field holds the tail, for
  example `m10/init/mode=bare`.

A record that covers a product of `corpus`, `modes`, and `op` values expands
into one cell per combination, and each expanded cell carries the record's
fields.

## Execution model

For one cell, in order:

1. Compute the required tier: the highest of the record's `tier` and the tier
   each named corpus declares. Report `skip: tier` when the detected tier is
   lower. This comes first, ahead of the record's own state, so a cell the
   host cannot observe at all says so whatever its record holds. The same cell
   run at the tier it needs then reports what its record is missing, and the
   difference between an unprivileged run and a root run is exactly what the
   privilege unlocked.
2. Resolve the implementations the cell names. Report `skip: reference-absent`
   when the cell compares against the reference and the reference handle did
   not resolve.
3. Create the scratch root, `<artifact-dir>/<cell-id>/`, holding `port/` and
   `ref/`. Each implementation gets its own subtree, so the two never share a
   repository or a source tree.
4. Materialize the named setups and corpus into both subtrees, and bind the
   placeholders. `created-by` and `populated-by` select which binary performs
   each setup step; a record naming neither has each side build its subtree
   with its own implementation, which is what an M10 cell wants.
5. Substitute the placeholders into the `run:` line, and into `ref-run:` when
   it is present.
6. Execute the port line in `port/` and the reference line in `ref/`. Capture
   the exit status, stdout, stderr, and elapsed time of each.
7. Apply each oracle named in `oracle:` to each side, producing one artifact per
   oracle per side.
8. Evaluate the assertions: the absolute `expect-*` claims against each side,
   then the equality of each oracle's two artifacts.
9. Emit the verdict. Remove the scratch subtree on a pass, and keep it on any
   other verdict.

A cell that names `probe:` replaces steps 5 through 8 with a call into the
registered probe, and keeps steps 1 through 4 and step 9.

Cells are independent. The runner executes them across `--jobs` threads,
defaulting to the available parallelism, with `--jobs 1` available for
diagnosis.

## Setups and placeholders

A setup builds the state a cell starts from and binds a fixed set of
placeholders. `$SCRATCH`, the side's own subtree and the working directory of
every invocation, is bound for every cell whatever its setups. The setups:

- `empty-dir` binds `$REPO` as a path that does not exist.
- `repo` binds `$REPO`, a repository created in the cell's mode by the
  implementation `created-by` names.
- `repo-with-commit` binds `$REPO`, `$BRANCH`, and `$REV`, with the corpus
  committed by the implementation `populated-by` names.
- `two-repos` binds `$REPO`, `$REPO2`, and `$BRANCH`. Each repository holds one
  commit of a tree holding `which.txt`, whose content is `distinguish-repo-1`
  in the first and `distinguish-repo-2` in the second, so a cell states which
  repository an invocation read by naming the marker it expects.
- `src-dst` binds `$SRC` in the record's `src-mode` and `$DST` in its
  `dst-mode`, for the transfer families.
- `tree` binds `$TREE`, the materialized corpus, outside any repository.
- `out-dir` binds `$OUT`, an empty directory.

The corpus has one path per side, so two setups in one record share the tree the
first of them materialized: `repo-with-commit tree` binds `$TREE` to the tree the
setup already committed, which is what a cell committing a second time onto the
setup's branch wants.

A cell that names no mode gets `bare`, and a cell that names no corpus gets
`C0`. The branch a setup commits to is `conformance`, and the timestamp it
commits with is `@1700000000`, so a setup commit is reproducible: the two sides
commit the same corpus and reach the same checksum. An M10 record states the
mode its invocation needs with a `modes:` field holding one value, a cell being
one invocation; naming two is a static error.

The `setup:` field takes one or more names, and their bindings combine. A setup
that binds a placeholder another setup in the same record already bound is a
static error. A record needs a setup only when its invocation names a
placeholder; a cell that states none runs in an empty `$SCRATCH`.

`$$` in a `run:` line produces a literal dollar sign. A `$` followed by any
name outside the bound set is a static error, which is how the checker keeps a
record and its setup in agreement.

## Argument parsing

The `run:` and `ref-run:` lines split on whitespace. A single-quoted span
becomes one argument and may hold spaces. No other shell syntax is interpreted,
and no shell runs.

Arguments holding a newline, a quote, or a non-UTF8 byte sequence cannot be
written in a `run:` line. Corpus `C10` supplies those names through the
filesystem, and a cell needing such an argument on the command line names a
probe.

## Oracles

An oracle reads one side's post-execution state and produces a comparable
artifact. The set is closed and matches the vocabulary in `README.md`.

- `exit-status` -- the process exit code.
- `stdout-text` -- the captured standard output, normalized.
- `stderr-text` -- the captured standard error, normalized.
- `config-bytes` -- the bytes of the repository's `config` file.
- `refs-bytes` -- every path under `refs/`, sorted, with its contents. The
  contents go through the placeholder substitution and the checksum masking
  under "Normalization" below, so a ref holding the commit a setup made reads
  `$REV` and any other checksum reads `<checksum>`. The masking keeps a cell
  comparable when its own invocation commits without a timestamp, which every
  cell that does not state a checksum as its claim is free to do.
- `inventory` -- every loose object: relative path, extension, and size,
  sorted by path. The size is the stored size, so in `archive` mode the oracle
  carries the DEFLATE divergence between the two implementations: it holds for
  a payload the two encoders compress to one length and parts for the rest
  (`cli-surface.md`, "P2").
- `manifest` -- a checkout walked by the harness and reduced to one line per
  path: path, type, mode, uid, gid, the sorted xattr names and values, and a
  SHA-256 digest of the content. Sorted by path.
- `checksum-agreement` -- the commit checksum the operation produced. Both
  implementations print it as the sole line of `commit`'s standard output, so
  a commit cell reads it there. A cell whose operation is another command
  resolves the checksum through `rev-parse`, against `$BRANCH` when a setup
  bound one and `$REV` otherwise; a cell binding neither reports the oracle as
  unavailable. The artifact is the raw checksum, with none of the masking
  `refs-bytes` applies, so a cell naming this oracle states a timestamp: either
  its own `run:` line passes `commit --timestamp`, or its claim rests on the
  setup commit, which passes one. Without a fixed timestamp two checksums differ
  by wall-clock time and the oracle would fail on every cell.
- `fsck` -- the exit status of each implementation's own `fsck` run against
  its own repository. The two word their progress and summary lines
  differently, and the claim is that both find the repository sound, so the
  captured text goes to the artifact directory and not into the comparison.

Some oracles depend on CLI surface that arrives during Phase 17. A cell whose
oracle is unavailable reports `skip: unimplemented-cli` and names the missing
command, so an unread oracle never reads as a pass on the assertions that did
run. See "Availability by sub-phase".

A cell whose `ref-run` is `n-a` produces its oracle artifacts for the port
alone and reports each oracle as `unpaired`, which states that nothing was
compared.

### Normalization

Every invocation runs with `OSTREE_REPO` and `G_DEBUG` removed from the
environment and `LC_ALL` set to `C.UTF-8`, so a cell that exercises the
environment fallback states that itself, a `fatal-criticals` or
`fatal-warnings` setting on the operator's host cannot turn a GLib critical in
the reference into an abort, and the two implementations' messages compare in
one language and one encoding.

The encoding is part of the comparison. GLib holds its option-parser messages
with U+201C and U+201D around the offending value and converts them to the
locale's codeset on the way to stderr. Under `C` that codeset is ASCII, which
cannot hold those characters, so the reference prints `?` on a host carrying
locale data and prints the characters themselves on a host carrying none -- the
same tool, two renderings, decided by the host rather than by the tool. A UTF-8
locale keeps the conversion lossless, so the reference renders the same bytes on
either host and the port, which writes UTF-8 throughout, matches it. A record
quoting a value in a message therefore states the typographic characters.

Startup reads the codeset `LC_ALL=C.UTF-8` resolves to and refuses the run where
it is not UTF-8, naming the locale as the cause. A host missing the locale would
otherwise report a text difference in every cell that quotes a value. The check
applies where a reference is present, since only the reference converts its
messages through the locale.

The reference tool resolves a repository from the current directory, then
`OSTREE_REPO`, then the compiled-in `/sysroot/ostree/repo`, and the third
source stands outside the environment's reach. The harness reads it from the
host: startup records whether `/sysroot/ostree/repo` is present, and the
`host:` banner line ends with `system repo /sysroot/ostree/repo` or `no system
repo` on every run. Where the host carries one, every invocation the harness
makes binds a repository -- through `--repo`, through `OSTREE_REPO`, or through
a working directory that opens as one -- and an invocation binding none is
refused before the process starts. Declared cells, probes, setups, oracles, and
`observe` all reach the one function that starts a process, which is where the
refusal sits. The argv and the bound environment are read textually, and the
check refuses where the reading is uncertain, as it is for an argv ending in a
bare `--repo`. The working directory is read from disk, since it is the first
source in the chain and an invocation resolving there never reaches the third.

Captured text holds scratch paths, wall-clock values, and checksums, so the text
oracles and `refs-bytes` normalize before comparison:

- a bound placeholder's value becomes the placeholder name, longest value first
  so a value holding another one is rewritten whole. Every placeholder is a
  path but `$BRANCH` and `$REV`, which are a ref name and a checksum;
- a 64-character lowercase hex run becomes `<checksum>`, unless the cell names
  the `checksum-agreement` oracle;
- progress lines carrying a rate or an elapsed time are dropped. This step
  applies to the text oracles alone, a ref name not being a progress line.

The raw bytes go to the artifact directory in every case, so a comparison
failure is diagnosed against what the process actually wrote.

## Assertions

Two kinds, and a record may carry both.

- An oracle named in `oracle:` asserts that the two implementations produced
  equal artifacts. This is the relative claim, and it needs both sides.
- An `expect-*` field asserts a fixed value against one side. This is the
  absolute claim, and it holds with the reference absent.

The fields:

- `expect-exit: N` -- the port's exit status.
- `expect-stdout:` and `expect-stderr:`, each taking `empty`, or
  `contains "TEXT"`, or `equals "TEXT"`.
- `ref-expect-exit:`, `ref-expect-stdout:`, and `ref-expect-stderr:`, the same
  three forms against the reference.

`contains` states that the claim is a substring, which is the honest form where
the two implementations render the same fact in different words. A record
stating `equals` claims the full text.

Two defaults keep a silent crash from reading as a pass. Every executed cell
asserts that each side it ran terminated normally, so a signal is always a
failure. A record that omits `expect-exit` claims exit status 0 for the port,
and a record that omits `ref-expect-exit` claims the same for the reference; a
record expecting a refusal states the status it expects.

### Tolerating a reference crash

`ref-may-abort: N` names one signal the reference build is known to die on. A
reference that crashes states nothing about the port, so where the reference
ends on that signal the cell reports `skip reference-abort` and every oracle
reads `unavailable` for that side. The port's own `expect-*` claims are asserted
either way, so a port regression on such a cell still fails.

The tolerance is narrow by construction:

- It names a single signal. The reference ending on any other signal fails the
  cell.
- It applies to the reference alone. The port aborting is always a failure.
- It costs nothing where the reference works. A build that exits normally is
  held to `ref-expect-exit` and the `ref-expect-*` claims, and the oracles
  compare both sides, so the cell keeps its full strength there.
- `check` refuses the field without a `note:` recording the observed crash, and
  refuses it alongside `ref-run: n-a`.

A cell carrying this field is evidence of a reference defect. The `note:` states
what the crashing build printed, so a later build that stops crashing can be
told apart from one that never did.

## Probes

A record naming `probe:` hands the cell to a registered Rust function. The
probe receives the scratch root, the bound placeholders, and both
implementation handles, and returns the observations it made. Tier gating,
reference resolution, artifact retention, and the verdict rules apply to a
probe cell the same way they apply to a declared one.

A probe is justified when declaring the cell would distort the record: a
command line holding a name the `run:` grammar cannot express, an interleaved
sequence of invocations across two repositories, or a comparison that reads
state between two steps. A cell that a `run:` line and an oracle can state uses
them. The checker fails a probe that no record names, so the registry cannot
outgrow the matrix.

## Records the runner reads

The runner reads these fields in addition to the descriptive fields
`README.md` lists.

- `cell:` -- the identifier tail, for families with no corpus and mode grid.
- `setup:` -- one or more setup names.
- `run:` -- the port's invocation, with everything after the binary name.
- `ref-run:` -- the reference's invocation. Defaults to `run:`. The value `n-a`
  states that the reference has no equivalent invocation, which leaves the
  absolute claims as the cell's only assertions.
- `probe:` -- a registered probe name, in place of `run:`.
- the `expect-*` and `ref-expect-*` fields above.
- `oracle:`, `tier:`, `severity:`, `corpus:`, `modes:`, `src-mode:`,
  `dst-mode:`, `created-by:`, `populated-by:`, `operated-by:`.

Every executable field is optional. A record carrying none of `run:`, `probe:`,
or `evidence:` is a declaration, and its cells report `skip: declaration` with
the outcome the record states. Every declared cell therefore appears in every
run, and the summary counts how much of the matrix is still declaration.

A record carrying `evidence:` and no `run:` cites proof that lives in a
library test. Its cells report `skip: proved-elsewhere` with the test name.
`check --verify-evidence` confirms the named test exists by matching it against
`cargo test --workspace --all-features -- --list` output, at the cost of a
compile.

## Verdicts

Three verdicts. A cell reports exactly one.

- `pass` -- every assertion held.
- `fail` -- an assertion did not hold. The report names the assertion, the two
  values, and the artifact directory.
- `skip` -- the cell was not observed, with one reason: `tier`,
  `reference-absent`, `unimplemented-cli`, `proved-elsewhere`, `declaration`,
  `filtered`, or `system-repo`.

A `system-repo` skip states that the host carries `/sysroot/ostree/repo` and
the cell holds an invocation binding no repository, which the reference tool
resolves against that path, so the claim the cell states cannot be made here.
The skip names the path and the invocation. It is decided for both
implementation handles together, so a cell whose premise fails for either side
skips whole. The host decides it, and `--require` carries no flag that promotes
it, so the cell is observed on a host carrying no system repository.

The `tier` skip is the one an operator lifts by re-running, so the summary
breaks it down by the tier each skipped cell needs and states what lifting it
takes: a user namespace for T2, root for T3, and root on an SELinux-enforcing
kernel for T4. An unprivileged run therefore reports how much of the matrix a
privileged run would add, before that run happens.

`--require` promotes a class of skips to failures:

- `--require tool=ostree` fails on `reference-absent`;
- `--require tier=T3` fails on `tier` for any cell needing T3 or lower.

This is how a machine that holds the reference tool, or the privilege, enforces
what a machine without it cannot. A promoted cell is counted with the failures
and leaves the `skip tier` breakdown. `system-repo` has no promotion, since the
host that carries a system repository is the host on which the claim cannot be
stated.

A `proved-elsewhere` skip is as strong as the cited test's own gating. The
tool-comparison tests return without an assertion where `ostree` is absent, so
the citation stands on a harness that carries the tool and states nothing on one
that does not. `OSTRYA_REQUIRE_OSTREE` turns that skip into a failure, the way
`--require tool=ostree` does for a `run:` cell. The host that runs the interop
gate sets it; the CI job installs no reference tool and leaves it unset, so its
`check --verify-evidence` step resolves the citation's test name alone.

An optional engine in the tool gates the same way. The ed25519 tests return
without an assertion where `ostree --version` lists no `sign-ed25519` feature,
which the Debian build omits, because such a tool answers every ed25519
invocation with `Requested signature type is not implemented`. That answer
describes the tool's build and states nothing about the port, and it would
otherwise satisfy a test asserting the tool rejects a signature.
`OSTRYA_REQUIRE_OSTREE_ED25519` turns the skip into a failure.

## Severity and exit status

A record's `severity:` is `interop` or `identity`. An `interop` failure fails
the run. An `identity` failure appears in the report and leaves the exit status
alone, so a byte-level regression is visible without blocking a change that
keeps interoperability. `--strict-identity` promotes them.

Binary exit status:

- 0 -- no `interop` failure.
- 1 -- at least one `interop` failure, or a skip a `--require` flag promoted.
- 2 -- a static error: an unparsable record, an unknown field, an unbound
  placeholder, an unregistered probe or oracle, or a usage error.

## Subcommands

- `check` -- static validation, running no binaries. It confirms deb822
  syntax, that every field name is recognized, that every value drawn from a
  vocabulary is in it, that the completeness rule in `README.md` holds for each
  family, that no two records state the same cell, that every placeholder in a
  `run:` line is bound by the record's setups, that every `expect-*` claim
  parses, that every named corpus, setup, oracle, and probe is registered,
  that every registered probe is named by some record, and that every `spec:`
  value names a heading its document holds.
- `run` -- executes the selected cells. Selection comes from `--family`,
  `--cell`, `--corpus`, `--mode`, and `--tier`.
- `observe` -- runs the reference alone against a cell's setup, writes the raw
  artifacts, and prints a record skeleton with the observed exit status,
  standard error, and oracle values filled in. `--cell` names the cell;
  `--run` and `--setup` supply the invocation and the setups a declaration
  states none of. This is the path from a declaration to an executable record,
  and the cells the matrix still declares need it.
- `report` -- reads a `check --format json` or `run --format json` document and
  writes the per-family mode grids as Markdown.

## Output formats

`--format` takes `human`, `tap`, or `json`.

- `human` is the default: one line per cell, grouped by family, followed by a
  summary counting passes, failures, and skips per reason. A cell the selection
  excluded is counted under `skip filtered` and is not listed.
- `tap` emits TAP13. A skip emits `ok N - <cell-id> # SKIP <reason>`.
- `json` emits one document holding a `cells` array and a `summary` object. A
  cell entry carries its identifier, verdict, skip reason, severity, the result
  of each oracle, the artifact path, and the elapsed time. This document is
  what `report` renders and what a future status page reads.

## Artifacts

`--artifact-dir`, defaulting to `target/conformance/<run-id>`, where `<run-id>`
is the run's start time in `YYYYmmdd-HHMMSS` form. Each cell owns
`<artifact-dir>/<cell-id>/`, holding the `port/` and `ref/` subtrees, the raw
stdout and stderr of each side, and each oracle's artifact from each side.

A passing cell's directory is removed. `--keep` retains it. Any other verdict
retains it, and the report names the path.

A run as root writes root-owned files, so a privileged run against a source
tree names an `--artifact-dir` outside it. The path is made absolute at
startup, because every invocation runs with its working directory inside a
cell's scratch tree.

## Cargo and CI wiring

- `crates/ostrya-conformance/tests/check.rs` holds one `#[test]` that runs
  `check`. It needs no built binaries and gates every record on every run of
  `cargo test --workspace`. Evidence verification stays outside it, because it
  runs `cargo` itself.
- `.github/workflows/ci.yml` runs
  `cargo run -p ostrya-conformance -- check --verify-evidence` as a step of its
  own, after the test step has built the test targets it lists. A citation
  naming no test fails the workflow, so a renamed library test cannot void the
  cells that cite it silently.
- `crates/ostrya-cli/tests/conformance.rs` holds one `#[test]` that calls the
  library with `env!("CARGO_BIN_EXE_ostrya")` as the port handle, runs the T0
  selection, fails on any `interop` failure, and prints the skip summary. This
  keeps the workspace test run as the gate with no workflow change.
- A machine holding the reference tool runs
  `ostrya-conformance run --require tool=ostree`.
- Privileged tiers run
  `sudo ostrya-conformance run --tier T3 --require tier=T3`, and
  `unshare -r ostrya-conformance run --tier T2 --require tier=T2`. `--tier`
  selects the cells needing exactly that tier, so a privileged run states the
  cells the privilege exists for; dropping `--tier` runs everything the host
  admits.
- A machine with no source tree names the records with `--matrix DIR` or
  `OSTRYA_MATRIX_DIR`, and the binaries with `--ostrya` and `--ostree` or
  `OSTRYA_BIN` and `OSTREE_BIN`.

The GitHub workflow installs rustup alone, so its run reports every cell that
needs the reference tool as `skip: reference-absent`, and its summary states
that count.

## Availability by sub-phase

Oracle and setup availability follows the CLI surface `cli-surface.md` orders.

- Available to a cell now: `exit-status`, `stdout-text`, `stderr-text`,
  `config-bytes`, `refs-bytes`, `inventory`, `manifest` (walked by the harness
  from a `checkout`), and `fsck`, each since Phase 17a.
- Phase 17b completed the `checksum-agreement` resolution path with `rev-parse`:
  a cell whose operation is not a commit resolves the checksum instead of
  reporting the oracle unavailable. Phase 17b also added `refs` and `cat`, so a
  cell can state a ref listing or a file's content as `stdout-text` alongside the
  `refs-bytes` files on disk.
- Phase 17b1 made a setup able to build a parent chain: `ostrya commit -b BRANCH`
  carries the tool's implicit parent, so two commits onto one branch leave an
  ancestry both implementations resolve. A cell that reads a parent still needs a
  second invocation, so those cells cite `evidence:`.
- Phase 17c opened `checksum-agreement` to cells: `commit --timestamp` makes a
  commit reproducible, so every setup that commits states a timestamp and a cell
  may compare raw checksums. It also added `--owner-uid`, `--owner-gid`, and
  `--no-xattrs` on `commit`, which corpus `C3` states through the CLI and corpus
  `C13` will, and `checkout -U` and `--subpath`. No oracle reads a cell's own
  checkout destination -- `manifest` checks the setup's revision out itself --
  so the two checkout options state their destination trees through
  `evidence:`.
- Phase 17d added the GVariant text-form printer, which `show --raw` and the
  `--print-*` forms need, and the four reading commands over it: `show`, `log`,
  `ls`, and `config get`. A cell can now state a metadata object, a commit
  report, a parent-chain walk, a tree listing, or a configuration value as
  `stdout-text`, so the harness's own readers -- decoding a commit's GVariant and
  reading `config` by hand -- have a CLI equivalent to be held against. The
  `repo-with-commit` setup binds one root commit, so a walk over a parent chain
  and a listing carrying an xattr are stated through `evidence:` instead.

A cell whose oracle or option is not yet available reports
`skip: unimplemented-cli` and names what is missing, so the matrix reports the
CLI gap rather than hiding it.

Two corpus builders are absent. `C5` needs a `security.capability` value in
the form real root writes, which the harness does not synthesize, and `C7`
needs an SELinux-enforcing kernel, which this development host is not. Both
corpora sit at tier T3 or above, so a host below that tier reports their cells
as `skip: tier` and never reaches the builder; a host at that tier gets a
failure naming what is missing.

## Constraints

- The harness links neither `ostrya` nor any repository-format code. Every
  observation comes from a process's exit status, its output, or the bytes on
  disk.
- No shell interprets a `run:` line.
- The upstream shell test suite is never read, run, or vendored. See
  CLAUDE.md, "Licensing and clean-room discipline".
