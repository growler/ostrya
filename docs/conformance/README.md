# Interoperability conformance matrix

This directory records what a repository custody handover between `ostree` and
`ostrya` guarantees. A cell states one of two things: the two implementations
agree, or interoperability is limited for a named reason.

The goal is full interoperability wherever it is possible:

- a repository `ostree` created and populated is operated by `ostrya`;
- a repository `ostrya` created and populated, in every mode except
  `bare-user-shared`, is operated by `ostree`;
- either implementation serves as a `pull-local` source for the other;
- the same holds for HTTP pull, static deltas, tar, composefs, and signatures.

Scope is repository and commit management. The sysroot and deployment surface
(`ostree admin`) is out of scope, in line with Phase 20 of `../port-plan.md`.

Two companion documents sit beside the record files. `harness.md` specifies the
program that executes the records and reports what each cell proved.
`cli-surface.md` lists the CLI capabilities that execution needs, ordered by
what each one unblocks.

## Axes

A cell is identified by these axes.

- `created-by` -- the implementation that ran the repository creation: `t` for
  `ostree`, `p` for `ostrya`.
- `populated-by` -- the implementation that wrote the objects and refs.
- `operated-by` -- the implementation that then performs the operation under
  test.
- `mode` -- one of `archive`, `bare`, `bare-user`, `bare-user-only`,
  `bare-user-shared`, `bare-split-xattrs`.
- `src-mode` and `dst-mode` -- replace `mode` for the transfer families, where
  the source and destination repositories carry independent modes.
- `op` -- the operation the operator applies.
- `corpus` -- the content the repository holds. See "Corpora" below.

Creation and population are separate axes because `ostree init` is the only way
to create a repository that `ostrya` then populates. That combination is a
custody case in its own right, and it is the bootstrap the harness uses while
the `ostrya` CLI has no `init` (see `cli-surface.md`).

## Outcome vocabulary

Every cell carries exactly one outcome. This vocabulary is what makes "when
possible" precise.

- `full` -- the operation succeeds, and every observable equals the
  same-implementation baseline.
- `lossy` -- the operation succeeds, and the format cannot carry part of the
  content. The record names what is lost in a `loss:` field.
- `needs-priv` -- possible only at the privilege tier the record states.
- `refused-both` -- both implementations refuse, and the refusal is the
  conformance requirement.
- `refused-clean` -- the operator refuses, leaves the repository unmodified,
  and reports why.
- `impossible` -- excluded by the format or the transport. The record names the
  reason.
- `unobserved` -- the reference behavior is not yet recovered. The record
  carries a `question:` field stating what to observe. These cells are the work
  queue.
- `unimplemented-cli` -- the library supports the operation and the CLI does not
  expose it. The record names the missing command in a `cli-gap:` field.

## Severity

Each cell is judged at two levels.

- `interop` -- the level that must hold for the other implementation to use the
  repository: checksum agreement, structural validity, refs resolution, config
  acceptance.
- `identity` -- byte-for-byte equality of the stored objects. This level exceeds
  what interoperability requires. It holds today for archive content objects and
  for every metadata object. A regression at this level is reported and does not
  fail the run; a regression at the `interop` level fails the run.

The `identity:` field takes `full`, `not-required`, `n-a`, or `unobserved`.

## Privilege tiers

A tier is a property of the (mode, corpus) pair, not of a test.

- `T0` -- unprivileged. The invoking user's own ids and `user.*` xattrs.
- `T1` -- unprivileged, with the process in two or more groups.
- `T2` -- user namespace with mapped root. Grants arbitrary ids inside the
  namespace, and the special mode bits.
- `T3` -- real root in the initial namespace. Grants `trusted.*`, device nodes,
  and the capability xattr in the form real root writes.
- `T4` -- real root on an SELinux-enforcing kernel.

Two boundaries constrain the runner. A `security.capability` xattr written from
a non-initial user namespace is stored in a namespaced revision carrying a
rootid, so its bytes and the resulting object checksum differ from the real-root
form; corpus `C5` therefore runs at `T3` and never at `T2`. An SELinux-enforcing
kernel is absent from the current development host, so corpus `C7` is blocked
there and needs a Fedora or CentOS Stream environment.

## Corpora

Each corpus is a source tree the harness materializes. The tier is the lowest
tier at which the tree can be built.

- `C0` basic -- a regular file at 0644, an empty file, a nested regular file,
  and a symlink. Tier T0.
- `C1` modes -- regular files at 0644, 0755, 0400, 0000, and 0664; directories
  at 0755, 0700, and 0711. Tier T0.
- `C2` special mode bits -- a setuid file at 04755, a setgid file at 02755, a
  file with the sticky bit at 01755, a setgid directory at 02775, and a sticky
  directory at 01777. Tier T0.
- `C3` declared ownership -- the `C0` tree committed with the owner uid and gid
  forced to 0:0 by command-line option, so no `chown` is needed to record
  foreign ids. Tier T0. Paired with `C13`.
- `C4` user xattrs -- one `user.*` xattr; three whose stored order differs from
  their creation order; one with an empty value; one with a 1024-byte value.
  Tier T0.
- `C5` capability xattr -- an executable carrying `security.capability`. Tier T3.
- `C6` trusted xattrs -- a file carrying `trusted.demo`. Tier T3.
- `C7` SELinux label -- a file carrying `security.selinux`. Tier T4.
- `C8` hardlinks -- two paths sharing one inode, plus a third path with the same
  content on a separate inode. Tier T0.
- `C9` payload sizes -- a file above the payload-link threshold, and a sparse
  file. Tier T0.
- `C10` names -- a name holding a non-UTF8 byte sequence, a 255-byte name, a
  name holding a newline, a name holding a quote and a backslash, and a path 40
  levels deep. Tier T0.
- `C11` unsupported types, unprivileged -- a fifo and a unix socket. Tier T0.
  The expected outcome is a refusal from both implementations.
- `C12` unsupported types, privileged -- a character device and a block device.
  Tier T3. The expected outcome is a refusal from both implementations.
- `C13` real ownership -- a tree whose files are owned by 0:0, 1:1, and
  65534:65534 on the filesystem, so the ingest path reads the ids from the
  inodes. Tier T2, and T3 for ids outside the namespace map. Paired with `C3`.

The `C3` and `C13` pair separates two properties. `C3` shows whether a mode can
carry foreign ids at all, and it needs no privilege. `C13` shows whether the
ingest path reads real ids from the filesystem. Only `bare` mode places the ids
on the object inode, so only `bare` needs privilege to store them; the other
modes hold the ids in a header or an xattr and store any ownership
unprivileged.

Interoperability comparison does not require canonical ownership. Both
implementations run in the same environment, so a checksum that embeds the
invoking user's ids compares validly between them.

## Families

- `m0-content.matrix` -- content fidelity: corpus against mode, judged by commit
  checksum agreement.
- `m1-operate.matrix` -- operating a repository the other implementation created
  and populated: operation against mode, in both directions.
- `m10-cli-behavior.matrix` -- `ostrya`'s CLI surface against the `ostree`
  tool's: option acceptance, stdout/stderr text, and exit status, per
  subcommand. This is the family Phase 17 (`../port-plan.md`) builds out and
  gates on. The reference behavior is the tool's own observed output, recorded
  the same way every other fact in this directory is. A cell is one CLI
  invocation, so a record carries a `subcommand` and a `cell` identifier tail
  in place of M0/M1's corpus and mode grid.

These families are planned and not yet written:

- `m2-pull-local.matrix` -- source mode against destination mode, both
  directions.
- `m3-pull-http.matrix` -- a statically served archive repository, crossed with
  summary presence, mirror mode, and delta use.
- `m4-static-delta.matrix` -- generator against applier, crossed with source
  mode and delta shape.
- `m5-tar.matrix` -- exporter against importer.
- `m6-composefs.matrix` -- image producer against digest oracle.
- `m7-sign.matrix` -- signer against verifier, across the four engines.
- `m8-custody.matrix` -- interleaved mutation sequences.
- `m9-config.matrix` -- config key acceptance and semantics.

## Oracles

The primary oracle is commit checksum agreement. Object identity is independent
of repository mode, an invariant `tests/fixtures/generate.sh` already asserts
across modes for one tree. Extending it across the corpus set gives one
comparison per (corpus, mode, implementation), and a disagreement names the
corpus feature that diverged.

Four supporting artifacts are collected per combination:

- the object inventory: loose path, extension, and size for every object;
- the `fsck` outcome from both implementations;
- a normalized checkout manifest: path, type, mode, uid, gid, xattrs, and
  content digest;
- the `config` and `refs/` bytes.

The `oracle:` field of a record names which of these decides the cell:
`checksum-agreement`, `inventory`, `fsck`, `manifest`, `config-bytes`,
`refs-bytes`, `exit-status`, `stdout-text`, or `stderr-text`. Each name states
that the two implementations produced an equal artifact. `harness.md` defines
what each one reads and how its text is normalized before comparison.

## Record format

Each family file holds records in deb822 form: blank-line separated, `key: value`
per line, continuation lines indented by one space. The `modes`, `corpus`, and
`op` fields each hold one or more values, and the record covers the product of
them, so a single record states an outcome shared by many cells.

```
family: M0
corpus: C0
modes: archive bare-user
tier: T0
outcome: full
severity: interop
identity: full
oracle: checksum-agreement inventory
evidence: ostrya::commit::commit_matches_the_tool
spec: format-reference.md#checksum-computation
```

Recognized descriptive fields: `family`, `corpus`, `op`, `modes`, `src-mode`,
`dst-mode`, `created-by`, `populated-by`, `operated-by`, `tier`, `outcome`,
`severity`, `identity`, `oracle`, `evidence`, `spec`, `loss`, `question`,
`cli-gap`, `subcommand`, `note`.

A record carries executable fields as well once its claim is observed:
`cell`, `setup`, `run`, `ref-run`, `probe`, `expect-exit`, `expect-stdout`,
`expect-stderr`, `ref-expect-exit`, `ref-expect-stdout`, and
`ref-expect-stderr`. `harness.md` defines each one, together with the setup and
placeholder vocabulary the `run` line draws on. A record carrying none of them
is a declaration, and the harness reports its cells as skipped with the reason
the `outcome` field states.

Completeness rule: within one family, for each row key -- the corpus for M0, the
operation and direction for M1 -- the `modes` values of the records cover all six
modes exactly once. A missing mode and a mode named twice are both errors. This
makes the matrix provably complete rather than merely long.

## M10 record format

A cell is one CLI invocation, so an M10 record carries a `subcommand`, a
`cell` identifier tail, and the invocation itself.

```
family: M10
subcommand: init
cell: init/mode=bare
setup: empty-dir
run: init --repo=$REPO --mode=bare
expect-exit: 0
oracle: exit-status config-bytes
outcome: full
severity: interop
spec: cli-surface.md#p0-blocks-the-harness
```

The harness substitutes `$REPO` with the cell's own scratch repository path,
runs the line under both implementations, and compares the artifacts the
`oracle` field names. `ref-run` overrides the line for the reference tool, and
`ref-run: n-a` states that the tool has no equivalent invocation, which leaves
the record's absolute `expect-*` claims as the cell's only assertions.
`harness.md` holds the setup and placeholder vocabulary, the assertion forms,
and the verdict rules.

## Clean-room note

Every claim in these files traces to `../format-reference.md` or to the observed
behavior of the `ostree` tool run as a black box. The upstream shell test suite
ships as part of libostree's LGPL source distribution and is out of scope like
the rest of that source: it is never read, copied, run, or vendored, and no
record here is authored from it. See `../../CLAUDE.md`, "Licensing and
clean-room discipline".
