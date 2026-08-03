# CLI surface required by the conformance matrix

This file states the command-line surface Phase 17 implements. It is derived
from two roles:

- harness driver -- the interoperability harness invokes the command to build or
  operate a repository in a matrix cell;
- conformance target -- the upstream shell suite invokes the command, so the
  option set, the output format, and the exit status must agree.

The comparison below is against `ostree` 2026.1, recorded by running
`<command> --help` as a black box. The port side is `ostrya` at commit 16d19ed.

The harness reads the repository directly where a command is absent: refs from
`refs/heads/<ref>`, the mode and keys from `config`, the object inventory by
walking `objects/`, commit and dirtree content by decoding the GVariant in the
harness, and the checkout manifest by walking a checked-out tree. So the absence
of the reading commands costs conformance coverage and does not block the matrix.
One command has no substitute.

## P0 -- blocks the harness

Done, Phase 17a.

`init --repo=PATH --mode=MODE --collection-id=ID` now exists, wired to the
already-existing `Repo::create`/`Repo::create_at`. Every matrix cell whose
`created-by` is `p` -- every cell in the D2 direction of `m1-operate.matrix`
and half of every transfer family -- is reachable through the CLI.

The accepted `--mode` values are `archive`, `archive-z2`, `bare`, `bare-user`,
`bare-user-only`, and the port extension `bare-user-shared`; `archive` and
`archive-z2` name the same mode, and the config always serializes as
`archive-z2`. `bare-split-xattrs` is deliberately excluded even though the
tool's own `init --mode` accepts it (see "Global conventions" below): the port
reads that mode and does not write it (`format-reference.md`, "Repository
modes and on-disk storage"), so exposing it here would create a repository
nothing in the port could subsequently commit into. An unrecognized mode, and
`bare-split-xattrs`, are both rejected the way "Global conventions" describes.

## P1 -- reading and resolution

These are absent. Each has a harness substitute, so they block conformance
coverage rather than the matrix itself. They are the postcondition checks in
nearly every cell, so implementing them removes a large amount of harness
special-casing.

- `refs` -- `--list`, `--delete`, `--create=NEWREF`, `-r/--revision`,
  `-A/--alias`, `-c/--collections`, `--force`, and the optional `PREFIX`
  argument.
- `rev-parse` -- `-S/--single`.
- `show` -- `--raw`, `--print-related`, `--print-variant-type=TYPE`,
  `--list-metadata-keys`, `--print-metadata-key=KEY`, `--print-hex`,
  `--list-detached-metadata-keys`, `--print-detached-metadata-key=KEY`,
  `--print-sizes`, `-B/--no-byteswap`, `--gpg-homedir=HOMEDIR`,
  `--gpg-verify-remote=REMOTE`.
- `log` -- `--raw`.
- `ls` -- `-d/--dironly`, `-R/--recursive`, `-C/--checksum`, `-X/--xattrs`,
  `--nul-filenames-only`.
- `cat` -- no options beyond the common set.
- `config` -- the `get`, `set`, and `unset` operations, and `--group`.

## P2 -- options missing from commands that exist

The command exists and the matrix exercises an option it does not accept.

`commit` accepts `--repo`, `--parent`, `-b/--branch`, `-s/--subject`, and
`--canonical-permissions`. Missing: `-m/--body`, `-F/--body-file`,
`-e/--editor`, `--orphan`, `--no-bindings`, `--bind-ref=BRANCH`, `--base=REV`,
`--tree`, `--add-metadata-string=KEY`, `--add-metadata=KEY`,
`--keep-metadata=KEY`, `--add-detached-metadata-string=KEY`, `--owner-uid=UID`,
`--owner-gid=GID`, `--bootable`, `--mode-ro-executables`, `--no-xattrs`,
`--selinux-policy=PATH`, `-P/--selinux-policy-from-base`,
`--selinux-labeling-epoch`, `--link-checkout-speedup`, `-I/--devino-canonical`,
`--tar-autocreate-parents`, `--tar-pathname-filter=REGEX`,
`--skip-if-unchanged`, `--statoverride=PATH`, `--skip-list=PATH`, `--consume`,
`--table-output`, `--gpg-sign=KEY-ID`, `--gpg-homedir=HOMEDIR`, `--sign=KEY`,
`--sign-from-file=PATH`, `--sign-type=NAME`, `--generate-sizes`,
`--generate-composefs-metadata`, `--fsync=POLICY`, `--timestamp=TIMESTAMP`.

`--owner-uid` and `--owner-gid` are needed by corpus C3. `--timestamp` is needed
by every reproducible cell. `--tree` is needed because the port reads a tar
stream from standard input where the tool takes `--tree=tar=PATH`; the two forms
must converge.

`checkout` accepts `--repo`, `-H/--require-hardlinks`, `-C/--force-copy`, and
`--composefs`. Missing: `-U/--user-mode`, `--disable-cache`, `--subpath=PATH`,
`--union`, `--union-add`, `--union-identical`, `--whiteouts`,
`--process-passthrough-whiteouts`, `--allow-noent`, `--from-stdin`,
`--from-file=FILE`, `--fsync=POLICY`, `-M/--bareuseronly-dirs`,
`--skip-list=FILE`, `--selinux-policy=PATH`, `--selinux-prefix=PREFIX`,
`--composefs-noverity`.

`export` accepts `--repo`. Missing: `--no-xattrs`, `--subpath=PATH`,
`--prefix=PATH`, `-o/--output=PATH`.

`prune` accepts `--repo`, `--refs-only`, `--depth`, `--no-prune`, and
`--delete-commit`. Missing: `--keep-younger-than=DATE`, `--static-deltas-only`,
`--retain-branch-depth=BRANCH`, `--only-branch=BRANCH`, `--commit-only`.

`fsck` accepts `--repo` and the port extension `--no-mark-partial`. Missing:
`--add-tombstones`, `-q/--quiet`, `-a/--all`, `--delete`, `--verify-bindings`,
`--verify-back-refs`.

`diff` accepts `--repo`. Missing: `--stats`, `--fs-diff`, `--no-xattrs`,
`--owner-uid=UID`, `--owner-gid=GID`.

`summary` accepts `--repo`, `-u/--update`, `--verify`, `-s/--sign-type`, and the
port extensions `--last-modified`, `--metadata-commit-timestamp`, `--keys-file`,
`--keys-dir`, `--gpg-homedir`, `--remote`. Missing: `-v/--view`, `--raw`,
`--list-metadata-keys`, `--print-metadata-key=KEY`, `-m/--add-metadata=KEY`,
`--gpg-sign=KEY-ID`, `--sign=KEY-ID`. Note that on this command the tool binds
`-v` to `--view`, and `--verbose` has no short form.

`static-delta` accepts the subcommands `list`, `generate`, `apply-offline`, and
`reindex`. Missing: `show`, `delete`, `verify`, `indexes`.

`pull` accepts a large set already. Missing: `--cache-dir`, `--disable-fsync`,
`--per-object-fsync`, `--disable-retry-on-network-errors`, `--subpath`,
`--untrusted`, `--http-trusted`, `--dry-run`, `--update-frequency=FREQUENCY`,
`--low-speed-limit-bytes=N`, `--low-speed-time-seconds=N`. The port adds
`--force-copy`, `--sign-verify`, and `--sign-verify-summary`.

`pull-local` accepts `--repo`, `--remote`, `--depth`, `--commit-metadata-only`,
`--untrusted`, `--bareuseronly-files`, `--disable-verify-bindings`, and the port
extensions `--force-copy` and `-L/--localcache-repo`. Missing:
`--disable-fsync`, `--per-object-fsync`, `--require-static-deltas`,
`--disable-static-deltas`, `--gpg-verify`, `--gpg-verify-summary`.

`sign` accepts the whole tool option set and adds `--gpg-homedir` and
`--remote`. No change is required.

## P3 -- shell-suite surface with no matrix weight

No matrix cell needs these. The shell suite invokes them.

- `reset` -- reset a ref to an earlier commit.
- `remote` -- `add`, `delete`, `show-url`, `list`, `gpg-import`,
  `gpg-list-keys`, `add-cookie`, `delete-cookie`, `list-cookies`, `refs`,
  `summary`.
- `checksum` -- `--ignore-xattrs`.
- `find-remotes` -- `--cache-dir`, `--disable-fsync`, `--finders=FINDERS`,
  `--pull`, `--mirror`.
- `create-usb` -- `--disable-fsync`, `--destination-repo=DEST`,
  `--commit=COMMIT`.
- `gpg-sign` -- `-d/--delete`, `--gpg-homedir=HOMEDIR`. The port folds GPG
  signing into `sign --sign-type=gpg`, so this is an alias with its own option
  names.

## Global conventions

Observed by running the tool (2026.1).

- `--repo=PATH` is accepted both before and after the subcommand, but the
  leading (pre-subcommand) position accepts only the `=`-joined form: `ostree
  --repo=R refs` works, `ostree --repo R refs` fails with `error: Unknown
  option --repo`. The subcommand (trailing) position accepts both `--repo=R`
  and `--repo R`. When a leading and a trailing `--repo` are both given, the
  subcommand-position value wins: `ostree --repo=r1 refs --repo=r2` resolves
  `r2`. The port is more lenient here: it accepts both forms in both
  positions, which is a superset of the tool's syntax, not a divergence any
  matrix cell exercises.
- With no `--repo`, the precedence is: the current directory, when it is a
  repository the tool can open; otherwise `OSTREE_REPO`, when set and openable;
  otherwise the tool prints the subcommand's usage text to standard error,
  followed by `error: Command requires a --repo argument`, and exits 1. A
  current directory that opens (has a `[core]` section with a recognized
  `mode` key) is preferred even when `OSTREE_REPO` names a different, valid
  repository; a current directory whose `config` exists but does not parse as
  a repository (no `[core]` section, or no `mode` key) falls through to
  `OSTREE_REPO` the same as a current directory with no `config` at all. A
  current directory whose `config` has a `[core]` section with an
  unparseable `mode` value is a third case: the tool treats that directory as
  the intended repository and reports the specific open failure (see below)
  rather than falling through; the port does not reproduce this third case,
  since it is not exercised by any `cli-surface.md`-required option and adds a
  parse-depth distinction with no matrix weight.
- `init` uses this same precedence, not a special case: with no explicit
  `--repo`, a current directory or an `OSTREE_REPO` target that already opens
  as a repository is reused (an idempotent re-init, same as passing that path
  to `--repo` explicitly); one that does not open falls through to the
  `Command requires a --repo argument` form, the same as every other
  subcommand -- `init` never creates a brand-new repository at a cwd- or
  env-resolved path, only at an explicit `--repo`. A quirk specific to this
  fallback path: reusing an existing repository through the cwd or
  `OSTREE_REPO` fallback crashes with `error: Key file does not have key
  "collection-id" in group "core"` when that repository's config has no
  `collection-id` key, even though the very same reuse through an *explicit*
  `--repo` succeeds cleanly (exit 0, config untouched) on the identical
  repository. The port does not reproduce this crash: its cwd/`OSTREE_REPO`
  fallback resolution and its explicit-`--repo` path share one idempotent
  `Repo::create` call, so both succeed uniformly regardless of whether
  `collection-id` was ever set.
- When `--repo` is given explicitly (either position) and fails to open, the
  tool reports `error: opening repo: <reason>` (no usage text) and exits 1.
  Confirmed for a missing path (`opening repo: opendir(...): No such file or
  directory`) and for a rejected mode value (`opening repo: Invalid mode
  '<mode>' in repository configuration`). The cwd-default and `OSTREE_REPO`
  fallbacks do not get this specific-reason treatment: an open failure there
  is folded into the generic `Command requires a --repo argument` case above.
- `init --mode=<mode>` rejects a mode it does not recognize with `error:
  Invalid mode '<mode>' in repository configuration` and exits 1, before
  writing anything to the target directory. Confirmed for an unknown string
  and for `bare-user-shared`, the port's own extension, which the tool does
  not accept as an `--mode` value at all (`--help` documents `bare`,
  `bare-user`, `bare-user-only`, `archive`; `archive-z2` and
  `bare-split-xattrs` are also accepted though undocumented in `--help`).
- A subcommand that takes a nested subcommand (`static-delta`) reports a
  missing one with its own usage text and `error: No command specified`, exit
  1, the same shape a bare `ostree` gets. That check comes before the
  repository check: `ostree static-delta --repo=<missing path>` reports the
  missing subcommand, not `opening repo`. The port matches this order and this
  text, for every combination of the global options.
- Options are not abbreviated. `--rep=PATH` fails with `error: Unknown option
  --rep=PATH`.
- Every subcommand accepts `-v/--verbose` and `--version`.
- An error goes to standard error with an `error: ` prefix, and the exit status
  is 1. Confirmed for a repository whose mode the tool rejects, and for a
  command-line syntax error (`error: Unknown option --rep=PATH`).
- `ostree --version` prints a multi-line block: a `libostree:` header, a
  `Version:` line, and a `Features:` list naming the C build's own options
  (`gpgme`, `selinux`, `libcurl`, and so on). The port's `--version` prints one
  line, `ostrya <version>`, and does not replicate the tool's block: the
  feature list names libostree's C build options, which the port does not
  share, so matching it byte for byte would not carry meaning.
- For every subcommand with a required positional (`checkout`, `export`,
  `diff`, `sign`, `pull`, `pull-local`), the tool checks for a resolvable
  repository before it checks that the positional was given: omitting both
  reports `error: Command requires a --repo argument`, the same as omitting
  only the repository. The port matches this order for `export`, `diff`,
  `sign`, `pull`, and `pull-local`: each subcommand's positional is optional at
  the argument-parsing layer and is checked only after the repository
  resolves, printing the tool's own message (`error: A COMMIT argument is
  required` for `export`; `error: REV must be specified` for `diff`; `error:
  Need a COMMIT to sign or verify` for `sign`; `error: REMOTE must be
  specified` for `pull`; `error: DESTINATION must be specified` for
  `pull-local` -- the tool's own message names DESTINATION there even though
  the missing positional is SRC_REPO, an observed quirk in the tool, not a
  transcription error here). `checkout` is deliberately left unfixed: its
  second positional, DESTINATION, is not simply required in the tool -- given
  a COMMIT but no DESTINATION and a resolvable repository, the tool succeeds
  and checks the commit out into a directory it names after the COMMIT
  argument in the current directory, rather than erroring. Reproducing that
  needs its own black-box observation and design pass (does the tool use the
  given revision string verbatim, or its resolved checksum; how is a ref name
  with slashes handled), so `checkout` still reports the same clap-generated,
  repo-check-comes-second error as the other five did before this fix.

## Output formats to recover before Phase 17

The shell suite reads standard output, so the format is part of the surface. None
of these formats is recorded in `../format-reference.md` yet. Each needs a
black-box observation pass, and the results belong in a new section of that
document.

- `refs --list` and `refs -r`, `rev-parse`, `cat`.
- `ls` in each of its five option combinations, including the NUL-separated
  form.
- `show`, `show --raw`, and each `--print-*` form. The `--raw` and metadata-key
  forms print GVariant in the GLib text form, so the port needs a variant
  printer that matches it. This is a distinct piece of work inside Phase 17 and
  is easy to overlook.
- `log` and `log --raw`.
- `config get`.
- `diff`, including the per-path change prefixes and `--stats`.
- `fsck` progress output and its `-q` form.
- `prune` totals.
- `summary -v`, `--raw`, and `--list-metadata-keys`.
- `static-delta list`, `show`, and `indexes`.
- `commit`, including the checksum line and `--table-output`.
- `pull` progress output.
- `remote list`, `show-url`, `refs`, and `summary`.

## Ordering

1. `init`, which unblocks every port-created cell.
2. `--repo` in the leading position, the current-directory default, and
   `OSTREE_REPO`, so one command template serves both implementations and the
   harness stops carrying a per-implementation option table.
3. `refs` and `rev-parse`, the postcondition checks in nearly every cell.
4. The P2 option gaps on `commit` and `checkout`, which the corpora need:
   `--owner-uid`, `--owner-gid`, `--timestamp`, `--no-xattrs`, `-U`, `--subpath`.
5. `show`, `log`, `ls`, `cat`, `config`, together with the variant printer.
6. The remaining P2 gaps.
7. P3.
