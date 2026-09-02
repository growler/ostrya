# CLI surface required by the conformance matrix

This file states the command-line surface Phase 17 implements. It is derived
from two roles:

- harness driver -- the interoperability harness invokes the command to build or
  operate a repository in a matrix cell;
- conformance target -- the port's own CLI-behavior suite invokes the command,
  so the option set, the output format, and the exit status are compared
  against the tool. The upstream shell suite is never read, run, or vendored
  (`CLAUDE.md`, "Licensing and clean-room discipline").

The comparison below is against `ostree` 2026.1, recorded by running
`<command> --help` as a black box. The port side is `ostrya` at commit 16d19ed.

The harness reads the repository directly where a command is absent: refs from
`refs/heads/<ref>`, the mode and keys from `config`, the object inventory by
walking `objects/`, commit and dirtree content by decoding the GVariant in the
harness, and the checkout manifest by walking a checked-out tree. So the absence
of the reading commands costs conformance coverage and does not block the matrix.
One command has no substitute.

## Scope of CLI compatibility

The goal is functional compatibility. A command the port carries does the work
the tool's command does, over the same option names and values, and writes the
same bytes into the repository. The commit checksum is the oracle wherever one
exists.

The goal is not character-for-character compatibility. These are outside the
scope, and a difference in any of them is recorded rather than removed:

- the wording, the punctuation, and the character offsets of a diagnostic;
- the exit path a refusal takes, so long as the port exits non-zero and writes
  no object and no ref;
- the dialect an option's value is read in, where the tool reads it through a C
  library the port does not link;
- the compile-time and run-time limits such a library imposes;
- the order of lines the tool emits from a hash container.

Byte-exact fidelity is required of the repository, and never of the terminal.
`format-reference.md` states what must match byte for byte. Where an output
format is reproduced exactly, that is because a matrix cell reads it, and the
cell states it.

This scope decides the shape of an option the port cannot reproduce exactly.
The port refuses a value it cannot carry, rather than accepting it under a
meaning of its own. Refusing costs the caller a command line; accepting under a
different meaning writes different bytes, which is the failure this project
exists to avoid.

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

These are the postcondition checks in nearly every cell, so each one
implemented removes harness special-casing. The ones still absent have a
harness substitute, so they block conformance coverage rather than the matrix
itself.

Done, Phase 17b:

- `refs` -- `--list`, `--delete`, `--create=NEWREF`, `-r/--revision`,
  `-A/--alias`, `-c/--collections`, `--force`, and the `PREFIX` positional,
  which the tool takes one or more of.
- `rev-parse` -- `-S/--single`, and the `REV` positional, which the tool also
  takes one or more of.
- `cat` -- `COMMIT` and one or more `PATH`.

Their output formats are recorded in `../format-reference.md`, "CLI output
formats". Sixteen tool behaviors around them are observed and deliberately not
reproduced:

- the tool names an `-A` alias that lives under `refs/remotes/<remote>/` by its
  path below the remote, dropping the remote and printing a name that resolves
  to nothing; the port prints the `remote:name` refspec, so `refs -A` output
  differs for a remote alias and agrees for every local one. `refs -A --delete`
  removes each alias nested under a prefix by that same name, so the tool
  removes no remote alias a prefix reached and removes a local ref carrying the
  name instead where one exists: against the remote alias
  `refs/remotes/origin/zz/q` and the local ref `refs/heads/zz/q`,
  `refs -A --delete origin:zz` removes the local ref and keeps the alias, where
  the port removes the alias the prefix named. Both exit 0 and print nothing, so
  the refs tree is the only witness. A prefix naming a remote alias exactly
  removes it in both, and every local alias agrees;
- `refs -A --create` naming a target under `refs/remotes` makes the tool write
  the `remote:name` refspec as the link body, which names no file under
  `refs/heads`, so the tool leaves an alias it cannot resolve: its own
  `rev-parse xal` reports `error: Refspec 'xal' not found` and its own default
  listing stops on the link. The port writes the path to the target ref's file,
  which resolves under both implementations, and prints the target ref's refspec
  in the `-A` listing wherever a link leaves the alias's own ref root. Both
  implementations therefore print `xal -> origin:rr/x` for an alias each wrote
  itself, and the tool reading the port's link prints the path below `refs/`
  (`remotes/origin/rr/x`) instead;
- a whole-remote `PREFIX` -- `<remote>:` or `<remote>:.` -- selects every ref of
  that remote in both implementations, and the tool names each selected ref by
  joining the prefix's ref half with the name below it, so the `.` of that join
  stays in the name: `refs --list origin:` prints `origin:./rr/x`, `refs -A
  origin:` prints `./rr/remal`, and `refs --delete origin:` is refused on the
  joined name with `error: Invalid refspec origin:./rr/x`, naming one matched ref
  in directory order. The port prints the `origin:rr/x` refspec in both listings,
  and refuses the same delete naming the prefix as given. `refs -A --delete
  origin:` takes the same shape over the aliases the prefix selects: the tool
  refuses on `./rr/remal` and the port on the prefix, and where the remote holds
  no alias both exit 0 and remove nothing. The default listing and
  `-r` agree verbatim, both refuse the delete and remove nothing, and a
  whole-remote prefix matching no ref exits 0 in both, including where a prefix
  ahead of it in the same `--delete` removed the remote's last ref;
- `refs --delete` refuses a ref under `refs/heads` that an alias names, with
  `error: Ref '<refspec>' has an active alias: '<alias>'`, in both
  implementations. Where one prefix matches more than one guarded ref, or more
  than one alias names one matched ref, each names the pair its own enumeration
  reaches first: the port takes the first in refspec order on both sides, and the
  tool's order is neither refspec nor directory order throughout -- with the
  guarded refs `test/zzz` and `test/aaa` it names `test/zzz`, the earlier
  directory entry, and with the aliases `zal` and `aal` both naming `main` it
  names `aal`, the later one. Both refuse the same invocations and exit 1. The
  port removes none of what that prefix matched, in the plain form and in the
  `-A` form alike, and the tool removes the members of the prefix's selected set
  its own removal order reached ahead of the guarded one, so the two leave
  different refs trees wherever that order puts an unguarded member first: over
  the refs `test/main` and `test/other` with `test/al -> ../test/main` and
  `topal -> test/other`, `refs --delete test` refuses on `test/main` and removes
  `test/al`, and over one guarded ref among sixteen unguarded ones it removes
  some of the sixteen. That removal order is the order the pair above is named
  in, so a prefix whose guarded member it reaches first removes nothing in the
  tool as well. A guarded member stands in both, and the refs a prefix ahead of
  the refused one matched are removed in both;
- one dangling alias -- a symlink under `refs/` whose target ref does not exist
  -- makes the tool fail every invocation whose enumeration reaches it, with
  `error: Listing refs: openat(<path>): No such file or directory` and exit 1:
  the default listing, `--list`, and `-r`; a `PREFIX` naming a directory that
  holds the link, in a listing and in a `--delete`, which then removes nothing;
  and `--create`, `--create --force`, and `-A --create`, each of which writes no
  ref. A link under `refs/mirrors` reaches the `-c` listing alone, and
  `-c --create=<id>:<ref>` completes over a link under `refs/heads`. `-A` lists
  the dangling alias, and `-A` with a `PREFIX` naming it exactly prints nothing.
  The port skips the dangling entry everywhere else: it lists the rest, writes
  every `--create` form, and removes what a prefix matched. `--delete` naming
  the link itself exits 0 and leaves the link in place in both;
- an invalid collection id aborts the tool on a GLib assertion when it names a
  directory under `refs/mirrors`, and is rejected with `error: Listing refs:
  Invalid collection ID <id>` when it is given as a `-c` positional; the port
  validates a collection id only where `-c --create` writes one, so a `-c`
  positional the tool refuses matches no collection ref in the port, which
  prints nothing and exits 0 where the tool exits 1;
- `refs -c --create=<id>`, whose NEWREF holds no `:` and therefore no ref name,
  makes the tool print a GLib assertion line (`g_regex_match_full: assertion
  'string != NULL' failed`) ahead of its own `error: Invalid ref name (null)`;
  the port prints the error line alone, so the two agree on the message, the
  exit status, and the refs tree, and the tool writes one line more on standard
  error;
- a symlink chain has no depth bound in `cat`: the tool resolves 20000 links,
  dies on a signal at 100000, and dies the same way on a self-referencing link
  (recovered with a link whose target is its own name). The port follows 256
  links, above the depth any real tree holds, and reports `error: Too many
  levels of symbolic links` beyond it;
- `refs --create=NEWREF` where NEWREF ends in `^` and its base names no ref kills
  the tool on a signal (exit 139), with `--force`, with `-A`, and with `-c` as
  `--create=<id>:<ref>^` alike, after leaving `refs/` untouched. The port
  reports `error: Invalid refspec NEWREF`, which is the tool's own refusal for
  that name at the step a resolvable base reaches (`../format-reference.md`,
  "refs");
- an empty refspec is the zero-length case of the abbreviated-checksum scan in
  the tool, and the count that decides it is of commits: `rev-parse ''` resolves
  in a repository holding exactly one commit, reports `error: Refspec  not
  unique` where it holds more, and reports `error: Invalid refspec ` in a
  repository holding no commit, where the empty name reaches the ref store and
  fails the refspec rule. `refs --create= REV` reads the same scan as an
  existence check, so it reports `error: --create specified but ref  already
  exists` against the one-commit repository and `error: Refspec  not unique`
  against a repository holding two commits. The port refuses the empty name in
  every repository with `error: Invalid refspec `, which is the tool's own text
  for the repository holding no commit, and exits 1 wherever the tool exits 1;
- a `PREFIX` the ref rule refuses is reported by the tool as `error: Listing
  refs: Invalid refspec <PREFIX>` and by the port as `error: Invalid refspec
  <PREFIX>`, in every listing form and in `--delete`. Both exit 1, print the same
  standard output, and leave the same refs tree, so the two lines differ by the
  tool's `Listing refs: ` context prefix, which the port carries nowhere: one
  condition has one message wherever a name reaches the library
  (`../format-reference.md`, "refs"). A prefix the tool's narrower ref-name class
  refuses and the port's rule accepts, such as `tes~t` or `origin::rr`, belongs
  to the character-class divergence below;
- a `PREFIX` whose path under `refs/` runs through a ref file -- `plain/x` over
  the ref `plain`, `origin:rr/x/y` over the ref `origin:rr/x`, `al/x` through an
  alias symlink -- is refused by both, in every listing form and in `--delete`,
  before the prefix matches anything. The tool reports `error: Listing refs:
  fstatat(<path>): Not a directory`, naming the path below the repository, and the
  port reports `error: i/o error: Not a directory (os error 20)`, the one message
  it gives that condition. Both exit 1, print the same standard output, and leave
  the same refs tree, so the two lines differ by the path and the syscall the
  tool names. With `-c` the positional is a collection id and no path is read,
  which is the collection-id divergence above;
- a ref name that names a directory under `refs/` draws one message from the port,
  `error: i/o error: Is a directory (os error 21)`, and three from the tool, two
  of which carry a name the port cannot reproduce. Against `refs/heads/d`, a
  directory holding the ref `d/inner`, the tool reports `error: Conflict: inner
  exists under d when attempting write` for `refs --create=d`, naming one ref read
  in directory order, with `--force` and without it; `error:
  renameat(tmplink.<random>, d): Is a directory` for `refs -A --create=d`, naming
  its own temporary file; and `error: Couldn't open ref 'd': Is a directory` for
  `rev-parse d` and `cat d PATH`, which names the ref half of a refspec alone, so
  `rev-parse origin:rr` reports `'rr'`. Each of those exits 1 and leaves `refs/`
  unchanged, the tool's temporary link included. The tool's `--create` refusal is
  a scan for a ref below the name, run under `refs/heads` alone, so four shapes
  the scan passes are replaced by the ref file at exit 0 with nothing printed and
  the tree below them removed: an empty directory, which `refs --delete` leaves
  behind in both implementations when it removes a directory's last ref, so `refs
  --delete deep/nest/ing` and then `refs --create=deep/nest plain` writes the ref
  file; a directory holding directories alone, so `refs --create=deep plain` after
  that same delete replaces `deep` and removes `nest`; any directory under
  `refs/remotes`, so `refs --create=origin:rr plain` removes the refs
  `origin:rr/x` and `origin:rr/deep/y`; and any directory under `refs/mirrors`
  through `-c --create=<id>:<name>`. The port refuses all four and writes nothing.
  Under `-A` a NEWREF naming a remote reaches no directory check in either
  implementation, the tool refusing at its remote-alias step and the port at the
  existence check ahead of it, so `refs -A --create=origin:rr plain` reports
  `error: Cannot create alias to remote ref: origin` and `error: i/o error: Is a
  directory (os error 21)`, both exiting 1 and writing nothing. A directory named
  as an `-A --create` target draws a fourth message from the tool, its own
  existence check's `error: Cannot create alias to non-existent ref: <target>`,
  so `refs -A --create=al deep` and `refs -A --create=al deep/nest` report that
  line where the port reports its `Is a directory` one;
- a ref name whose path under `refs/` runs through a ref file -- `plain/x` over
  the ref `plain`, `origin:rr/x/y` over the remote ref `origin:rr/x`, `al/x`
  through an alias symlink -- is the `ENOTDIR` sibling of that case, refused by
  both wherever a ref name is resolved or written. The tool names the path below
  the repository and the syscall, `error: openat(refs/heads/plain/x): Not a
  directory`, for `refs --create=plain/x`, `refs -A --create=plain/x`, the
  positional revision of a plain `--create`, `rev-parse plain/x`, and
  `cat plain/x PATH`; under `-c --create=<id>:<ref>` the write reaches the
  mirror path and it reports `error: open(O_TMPFILE): Not a directory`, naming
  no path; and as an `-A --create` target it reports the target as a name no ref
  holds, `error: Cannot create alias to non-existent ref: plain/x`, the existence
  check standing ahead of the name at that one site. The port reports `error: i/o
  error: Not a directory (os error 20)`
  for every one of them, the one message it gives that condition, which is also
  the message the `PREFIX` form above draws. Both exit 1 and leave `refs/`
  unchanged;
- a revision resolving to a commit the store does not hold is refused in
  different words: the tool names the loose object file it looked for, `error: No
  such metadata object <checksum>.commit`, and the port names the object type the
  library looked up, `error: object not found: Commit <checksum>`. Both exit 1
  and write nothing, at `cat` and at a revision carrying a `^` suffix, whose walk
  loads the base commit, and `checkout` and `export` give the same pair on
  surfaces later sub-phases compare. The port's line is the one message the
  library gives any absent object, and the tool words the family per command --
  the same absent checksum reports `error: Couldn't find file object
  '<checksum>'` from `ostree show` -- so the wording for a dirtree, a dirmeta, or
  a file object belongs with the phase that lands the commands reading them.
  Phase 17d settled it: `show` reaches a bare checksum with no object type and
  reports the tool's own `Couldn't find file object` line, which the port
  reproduces, while `log` and `ls` resolve a commit and so draw the pair above.
  The checksum is
  refused nowhere else: `rev-parse <checksum>` prints it at exit 0, `refs
  --create=NEWREF <checksum>` writes the ref file, and `commit
  --parent=<checksum>` writes a commit naming it, in both implementations, so a
  ref pointing at an absent commit arrives through either CLI and reading a
  revision through it reports the same pair;
- a ref file holding a checksum in any rendering other than the 64 lowercase hex
  characters is refused by the tool wherever that ref is resolved, with `error:
  Invalid character '<byte>' in rev '<content>'`, naming the first character it
  refuses by byte value, and the port's reader takes either case and resolves it.
  `commit -b BRANCH` is one of those sites, reached through the implicit parent,
  and the one site where the divergence changes what a write produces: over a ref
  file holding the uppercase rendering of a commit checksum the tool reports that
  line and exits 1, and the port exits 0 and writes a commit carrying the
  lowercased checksum as its parent. Content that is no checksum at all is
  refused by both in different words, each exiting 1 and leaving the ref file in
  place: the tool names the content, `error: Invalid rev <content>`, and the port
  gives the library's own rendering, `error: invalid checksum: hex checksum is
  not 64 characters`, rather than the capitalized resolution wording this site
  otherwise carries, because `report_resolution_failure`
  (`crates/ostrya-cli/src/main.rs`) maps `RefNotFound` and `NoParentCommit`
  alone. Both implementations write the lowercase form, so only an out-of-band
  write puts such content in a ref file, and the port keeps the tolerant reader
  because the same parser reads a checksum out of delta metadata. The rule for a
  64-character name agrees in both, and is in `../format-reference.md`,
  "Revision syntax".

Abbreviated checksum resolution is shared: a run of one to 63 lowercase hex
characters names the one commit object whose checksum starts with it, wherever a
revision is taken, and a prefix more than one commit carries reports `error:
Refspec <prefix> not unique` at exit 1 in both. The scan of `objects/` inside
`Repo::resolve_rev` landed in Phase 17f as item `X1`, with the `commit -b`
consequence as `F10a`: a branch name prefixing a commit and naming no ref parents
its commit on that commit in both implementations. The rule, the sites it reaches,
and the observations that recovered it are in `../format-reference.md`, "Revision
syntax".

One resolution behavior the tool has and the port does not, recorded in
`../format-reference.md` with the observation that recovered it:

- the tool validates a ref name against a character class the port's own check
  does not, so `ostrya refs --create` writes some names the tool then refuses
  to resolve. Adopting the rule tightens `Repo::resolve_rev`, `commit -b`, and
  every pull path at once, so it belongs with a phase that reviews those. Four
  consequences the surface carries today. A name of that shape draws `error:
  Invalid refspec <name>` from the tool wherever it is taken as a revision or a
  NEWREF, and `error: Refspec '<name>' not found` from the port at a resolution
  site, the message both give a name that resolves to nothing, so `rev-parse
  <name>~1` and `rev-parse <name>^2` -- the two non-syntaxes of
  `../format-reference.md`, "Revision syntax" -- differ in words while both exit
  1 and write nothing. As a `PREFIX` the same name ends the tool's listing with
  `error: Listing refs: Invalid refspec <PREFIX>` at exit 1, and matches nothing
  in the port, which prints nothing and exits 0. And the tool's
  ref enumeration skips such a name without a word: `refs`, `refs --list`, `refs
  -r`, a `PREFIX` above it, `fsck`, and `summary -u` each print the other refs
  and exit 0, and `prune --refs-only` reads the commit that ref holds as
  unreachable and deletes it, so after `ostrya commit -b 'odd~1'` and `ostree
  prune --refs-only` the ref file stands over an absent commit object and
  `ostrya cat 'odd~1' PATH` reports `error: object not found`. The port
  enumerates the name everywhere. A branch name ending in `^` carries the same
  consequence and is recorded under "P2", where the write-side guard that keeps
  it out of a port-written repository stands; the two are one class. `prune`
  belongs to a later sub-phase, which is where that pair is compared. And the tool holds such a name to name no ref as
  an `-A --create` target, so over the ref `tes~t` written by
  `ostrya commit -b 'tes~t'` the port writes `refs -A --create=al 'tes~t'` and the
  tool reports `error: Cannot create alias to non-existent ref: tes~t` at exit 1,
  the one case at that site where the two leave different refs trees.

Done, Phase 17d:

- `show` -- `--raw`, `--print-related`, `--print-variant-type=TYPE`,
  `--list-metadata-keys`, `--print-metadata-key=KEY`, `--print-hex`,
  `--list-detached-metadata-keys`, `--print-detached-metadata-key=KEY`,
  `--print-sizes`, `-B/--no-byteswap`, `--gpg-homedir=HOMEDIR`,
  `--gpg-verify-remote=REMOTE`.
- `log` -- the default form and `--raw`.
- `ls` -- `-d/--dironly`, `-R/--recursive`, `-C/--checksum`, `-X/--xattrs`,
  `--nul-filenames-only`, `COMMIT`, and zero or more `PATH`.
- `config get` -- the dotted key and `--group=GROUP`.

Their output formats, and the GVariant text form they share, are recorded in
`../format-reference.md`, "The GVariant text form", "`show`", "`log`", "`ls`",
and "`config get`". `show --print-variant-type=TYPE` takes every definite
GVariant type string in both implementations: Phase 17f widened
`ostrya-gvariant`'s `Type` to `n`, `q`, `i`, `x`, `h`, `d`, `o`, `g`, and the
maybe types, which `commit --add-metadata` writes into a commit's metadata dict.
`Value` carries the matching variants -- `I16`, `U16`, `I32`, `I64`, `Double`,
and `Maybe` -- with `o` and `g` held as `Str` and `h` as `I32`; the two enums
are listed in `../api-sketch.md`, "GVariant types and values".
The indefinite characters part the two. The tool takes `r`, `*` and `?` and
prints `**` for each, where the port refuses the type string with `error:
invalid format: invalid type signature "<type>" at offset <n>: unsupported type
character` at exit 1. Six tool behaviors around these commands are observed and
deliberately not reproduced:

- a `--print-variant-type` signature that is not a type at all kills the tool
  with a signal (`--print-variant-type=zz` exits 139 after two GLib assertions),
  and the port refuses it with `error: invalid format: invalid type signature
  "<type>" at offset 0: unsupported type character` at exit 1;
- `show --print-variant-type` memory-maps the file in the tool and the port reads
  it whole, up to sixteen mebibytes, refusing a larger one by name. A metadata
  object the format defines stays far below that;
- the tool takes more than one `OBJECT` and reads the first, ignoring the rest;
  the port refuses the second with clap's `error: unexpected argument '<value>'
  found`. Both exit 1 only in the port's case, so an invocation naming two
  objects reports in one and reads in the other;
- a revision resolving to a commit the store does not hold is refused in the
  words "P1 -- reading and resolution" above records, now at `log` and `ls` as
  well: the tool names the loose object file and the port names the object type.
  `show` is the one command of the three where the two agree, the tool's own
  wording there being `error: Couldn't find file object '<checksum>'`, which the
  port reproduces because a bare checksum reaches `show` with no type;
- the GPG signature report a signed commit draws carries five differences from
  the tool's, none of them a repository fact. The instant the signature was
  made is rendered by the tool through gpgme in the host's locale and time zone
  (`Wed 05 Aug 2026 17:11:19 CEST`) and by the port in UTC in the shape its own
  `Date:` line carries (`2026-08-05 15:11:19 +0000`); matching the tool would
  need a locale database and the host time zone, neither of which the port
  carries. The port writes one blank line more before the `Found N signatures:`
  heading. For a signature a signing subkey made, the tool writes a `Primary
  key ID <key-id>` line after the verdict line, and the port writes the signing
  subkey's key id alone; over a signature the cryptography refuses the tool
  writes that line whichever key made the signature, the primary key included,
  and the port draws no such line in either case. The fourth difference is the
  line a key state draws. The port states three verdict lines: `Can't check
  signature: public key not found`, `Good signature from "<user id>"`, and `BAD
  signature from "<user id>"`. Over a good signature, over an absent key, and
  over a signature that does not verify, the tool states the same line word for
  word. Over a revoked key the tool states `Key revoked` and the port states
  `BAD signature from "<user id>"`. Over a key that states an expiry the tool
  adds one line after the verdict line -- `Key expires <instant>` while the key
  is live, and `Key expired <instant>` from the instant it has passed -- which
  the port leaves out. The fifth difference stands over a signature the
  cryptography refused, where neither implementation holds the instant or the
  algorithm name: the tool draws the Unix epoch in the host locale and time
  zone (`Thu 01 Jan 1970 01:00:00 CET`) and `[unknown name]`, and the port
  draws an empty instant and `unknown`. Over a good signature the algorithm
  name, the short key id, and the user id are the same in both, measured
  against `ostree` 2026.1 over a commit each implementation signed with the
  same key, read back through the other's `show --gpg-verify-remote=<remote>`.
  The short key id and the user id are the same in both over a signature that
  does not verify as well: both name the signing key by its trailing sixteen
  hex digits, and the tool names the certificate that holds that key on its
  `Primary key ID` line. The key the port names there is the one its own
  trusted keyring resolved for the signature. `ostree gpg-sign --delete` in
  2026.1 removes such a signature under four selectors -- the key id and the
  whole fingerprint of the signing key, and the key id and the whole
  fingerprint of the certificate -- measured over a signature a signing subkey
  made. The port holds both keys in its own record, so `ostrya sign --delete`
  reaches the same signature under the key id of either key
  (`crates/ostrya-cli/tests/cli.rs`,
  `sign_delete_reaches_a_signature_that_does_not_verify`). It matches a KEY-ID
  against the tail of either fingerprint, so the whole fingerprint of either
  key reaches it as well;
- the verdict the report states rests on the port's own trust and validity
  policy, which `../port-plan.md`, "Phase 13d", enumerates against GnuPG 2.4.9.
  Seven differences stand there, and each one can make a `show` verdict part
  from the tool's: the fixed digest policy, the GnuPG keybox refusal, the
  refusal a keyring the parser rejects draws, the 256-bit minimum digest an
  Ed25519 key carries, the keyring and signature-blob input caps, a revocation
  read over every certificate the trusted set holds for the key rather than over
  the first alone, and the key expiry read as the newest statement two exports
  of one certificate carry rather than as the statement the first export makes.

`config set` and `config unset` write the document through the config write path
Phase 17e landed. Both accept what the tool accepts and word every refusal the
same way, and the file each writes holds the same bytes
(`../format-reference.md`, "`config set` and `config unset`"). One divergence
stands, at a key naming an empty group or an empty key: `config set .k v` and
`config set g. v` reach GLib's own key-file assertions in the tool, which prints
a `GLib-CRITICAL` line, writes nothing, and exits 0, where the port refuses the
name (`keyfile: group name is empty`, `keyfile: key is empty`), writes nothing,
and exits 1. Both leave the file as it stands.

Nothing in this section is absent.

## P2 -- options missing from commands that exist

The command exists and the matrix exercises an option it does not accept.

`commit` accepts `--repo`, `--parent`, `-b/--branch`, `--orphan`, `-s/--subject`,
`--canonical-permissions`, since Phase 17c `--owner-uid=UID`,
`--owner-gid=GID`, `--no-xattrs`, and `--timestamp=TIMESTAMP`, and since Phase
17f `--fsync=POLICY`, `--table-output`, `-m/--body=BODY`,
`-F/--body-file=FILE`, `-e/--editor`, `--no-bindings`, `--bind-ref=BRANCH`,
`--add-metadata-string=KEY=VALUE`, `--add-metadata=KEY=VALUE`,
`--keep-metadata=KEY`, `--add-detached-metadata-string=KEY=VALUE`,
`--statoverride=PATH`, `--skip-list=PATH`, `--mode-ro-executables`,
`--skip-if-unchanged`, `--link-checkout-speedup`, `-I/--devino-canonical`,
`--generate-sizes`, `--bootable`, `--generate-composefs-metadata`,
`--base=REV`, `--tree=dir=PATH or tar=TARFILE or ref=COMMIT`, `--consume`,
`--tar-autocreate-parents`, `--tar-pathname-filter=REGEX,REPLACEMENT`,
`--gpg-sign=KEY-ID`, `--gpg-homedir=HOMEDIR`, `--sign=KEY_ID`,
`--sign-from-file=PATH`, and `--sign-type=NAME`.
Missing:
`--selinux-policy=PATH`, `-P/--selinux-policy-from-base`,
`--selinux-labeling-epoch`.

The five tree-source options carry seven divergences between them. The
composition rule, the source list, the two type-change refusals, `--base`,
`--consume`, `--generate-sizes` over any source list, and the two tar options
otherwise agree with the tool over every form the cells and the tests hold, each
accepted form checked by the commit checksum and each refusal by its text
(`../format-reference.md`, "CLI output formats", `commit`, and that file's
"The tar import").

The first is the source a command line naming neither `--tree` nor a positional
`PATH` states. The tool walks the current working directory; the port reads a
tar stream from standard input, which is the form it has carried since Phase 10.
`--tree=tar=-` and `--tree=tar=/dev/stdin`, the spellings the tool reaches
standard input by, are accepted by both and are how a script states the stdin
source in either. The port keeps its own default because an omitted argument
would otherwise walk and commit whatever directory the caller happens to stand
in, which is the class of accident the omitted `/sysroot/ostree/repo` fallback
is left out for ("Global conventions"). Two consequences: `ostrya commit -b b
--base=REV` with no source reads standard input where `ostree commit -b b
--base=REV` overlays the working directory on the base, and `ostrya commit -b b`
with standard input on a terminal waits for that input where `ostree commit -b b`
commits the working directory. `--tree=dir=.` states the tool's default source in
either implementation.

The second is the wording of an archive that opens and does not parse. An
archive that does not open reports `error: archive_read_open_filename: Failed to
open '<path>'` from both. Past that the two readers part: the tool reads
whatever libarchive detects -- uncompressed tar, `.tar.gz` by content, `newc`
cpio -- and reports `error: archive_read_open_filename: Unrecognized archive
format` for anything else and `error: archive_read_open_filename: Error reading
'<path>'` for a directory, where the port reads uncompressed tar alone and
reports the reader's own line under `error: i/o error:` for everything else.
Both exit 1 and write no commit.

The third is the expression `--tar-pathname-filter` compiles. Both
implementations compile it with PCRE2: the tool through GLib's `GRegex`, which
links the host's `libpcre2-8`, and the port through the `pcre2` crate, which
vendors PCRE2 10.46 and links it statically. One pattern reaches one engine
family, and the option parts from the tool in four places: the reason string in
a compile failure, the unit that same line's offset counts in, the exit path a
match-time refusal takes, and the PCRE2 version each side carries ("Scope of CLI
compatibility"). The cited test for this option is
`ostrya_cli::cli::commit_tar_pathname_filter_matches_the_tool` in
`crates/ostrya-cli/tests/cli.rs`.

Every construct the cited test states reaches the tool's commit checksum:
literal characters, `.`, the anchors `^`, `$`, `\A`, `\Z`, and `\z`, `\b` and
`\B`, `[...]` classes with ranges and negation, the POSIX class names in the
plain and the `[[:^alpha:]]` form, the `\d`, `\w`, `\s`, `\h`, `\R`, and `\N`
classes and their negations, the character escapes `\n`, `\t`, `\r`, `\f`, `\a`,
`\0`, `\101`, `\xHH`, and `\x{...}`, the Unicode property `\p{...}`, the
single-code-unit `\C`, capturing, non-capturing, named, atomic, and comment
groups, the duplicate-name flag `(?J)`, the literal span `\Q...\E`, the four
lookarounds, the match reset `\K`, alternation, the quantifiers `*`, `+`, `?`,
and `{n}` in greedy, lazy, and possessive form, the backreferences `\1` to `\9`
and `\g{1}`, recursion `(?R)`, a subroutine call `(?1)`, a conditional
`(?(1)a|b)`, a callout `(?C1)`, the backtracking verbs `(*SKIP)` and
`(*ACCEPT)`, the inline options `(?i)`, `(?s)`, `(?m)`, and `(?x)` at any
position, the inline-option group `(?i:...)`, and the start-of-pattern options
`(*UTF)`, `(*UCP)`, `(*NUL)`, `(*LIMIT_MATCH=N)`, `(*LF)`, `(*CRLF)`, and
`(*ANYCRLF)`. The value splits at its first comma, so an expression this option
carries holds no `{n,}`, `{n,m}`, or `{,m}` bound. `(?J)` is measured on both
halves of the value: the expression declares one name on two groups, and the
replacement reads that name back with `\g<name>`.

The compile options are recovered by observation, one probe per option: a
one-member archive committed under one expression, the committed member name
stating whether the expression matched.

- UTF is on. `^.` over the member `é.txt` consumes one character, and `\C`
  consumes one code unit, so it can split that character.
- UCP is on. `\d` matches `U+0663`, `^\w` and `[[:alpha:]]` match `é`, and `\s`
  matches `U+00A0`.
- The newline convention is `any`. A carriage return, a line feed, the pair, a
  vertical tab, a form feed, `U+0085`, `U+2028`, and `U+2029` each end a line,
  so `$` and `\Z` match before one final terminator, `(?m)^` matches after one
  inside a name, and `.` consumes none of them. `\z` matches at the end of the
  name alone.
- Caseless, dotall, extended, and multi-line matching are off, and each is
  reachable inline.

The port states UTF and UCP through the crate's builder. The crate states no
option for the newline convention, so the compiled pattern carries PCRE2's own
`(*ANY)` start-of-pattern option ahead of the value; a convention the value
states itself follows it and wins, in both implementations. The JIT is off in
the port: the interpreter and the JIT part in how they account the match limits
and not in what they match, and the tool's own use of it is not observable.

An empty match advances the splice past one whole character, which leaves that
character in the name, so `(?<=.)x*,Q` over the member `aébc` writes `aQéQbQcQ`
in both.

The replacement syntax is GLib's, which the port reads itself: `\0` to `\9`,
`\g<name>` and `\g<number>`, `\\`, the seven control escapes, and `$` as a
literal; a group the expression does not declare contributes nothing, a name
that `(?J)` puts on several groups resolves to the first of them, by number,
that the match set, and any other replacement escape is refused. A malformed
replacement ends the tool at exit 134 on an assertion whose printed message
names `ot-builtin-commit.c` and `handle_translate_pathname`;
`--tar-pathname-filter='.*,\q'` over any archive reaches it. The port reports
its own line at exit 1.

An expression neither engine compiles is refused by both at exit 1 with no
commit written, and both report `error: --tar-pathname-filter: Error while
compiling regular expression '<expression>' at char N: <reason>`. The line
parts in two places.

The reason string is the first. GLib passes some of PCRE2's own reasons through
and rewords others. The reword set is wider than the five the cited test
compares:

- `[[:bogus:]]` at char 10 reads `unknown POSIX class name` from both, character
  for character.
- `f{65536}` at char 7 reads `number too big in {} quantifier` from both.
- `dir1((` at char 6 reads `missing closing parenthesis` from the port and
  `missing terminating )` from the tool.
- `\q` at char 1 reads `unrecognized character follows \` from the port and
  `unrecognised character following \` from the tool.
- `(*BOGUS)f` at char 7 reads `(*VERB) not recognized or malformed` from the
  port and `(*VERB) not recognised` from the tool.

The unit `N` counts is the second. The port reports the code-unit offset PCRE2
answers, which is a byte offset for the 8-bit library, and the tool reports a
character offset. The two answer the same offset for an expression that holds
ASCII characters alone ahead of the error point, which is every expression
above. Past that the port's offset runs ahead by the extra bytes the characters
before the error point occupy. Each probe below carries one error the list above
already states, so the count rule is measured apart from the error kind. The
port's offset stands first.

- `é\q` reads 3 and 2, and `éé\q` reads 5 and 3.
- The four-byte `U+1F600` ahead of `\q` reads 5 and 2.
- `é[[:bogus:]]` reads 12 and 11, `édir1((` reads 8 and 7, `éf{65536}` reads 9
  and 8, and `é(*BOGUS)f` reads 9 and 8.
- `ééédir1((` reads 12 and 9.

A match spends a step budget PCRE2 accounts. An expression that requires a
literal ends without spending it: `^(a+)+b` against a member name of 250 `a`
characters needs a `b` the name does not hold, so both answer at exit 0 and
write one commit. `(a+)+\d`, `(a+)+[0-9]`, and `(a|aa)+\d` require no literal
and reach the limit over that name. Both refuse, writing no object and no ref,
and the exit path is the difference: the port reports `error: tar:
--tar-pathname-filter: Error while matching regular expression '<expression>':
match limit exceeded` at exit 1, and the tool ends on a GLib assertion at exit
134 whose printed message names `ot-builtin-commit.c` and
`handle_translate_pathname` and reads `Error while matching regular expression
<expression>: match limit exceeded (g-regex-error-quark, 3)`. A `\C` rewrite
that splits a character reaches the same pair of exit paths: the port stores a
pathname as text and reports `error: tar: --tar-pathname-filter: the rewritten
name of '<name>' is not valid UTF-8` at exit 1, and the tool's assertion reads
`bad offset into UTF string`.

The PCRE2 version is the last difference. The port carries the 10.46 the
`pcre2-sys` crate vendors, pinned to the vendored static build in
`.cargo/config.toml` so a host that installs `libpcre2-dev` cannot supply
another, and the tool carries whatever the host GLib links, which is 10.46 on
the host these probes ran on.

The fourth is a reference defect over a member the filter maps to the empty
string. A directory member mapped onto the empty string names the tree root in
both, which is what makes the prefix strip `^dir1/(.*)$,\1` work, and both
write the same commit for it. A regular file, a symlink, or a hardlink mapped
onto the empty string names the root as a file, and the shape of the archive
decides what reference build 2026.1 does with it. Each outcome below is
reproducible under `--tar-pathname-filter='.*,'`, which maps every member name
onto the empty string, over the archive shape named beside it.

- An archive that holds a directory member together with a regular file member
  or a symlink member commits at exit 0 and writes a dirtree holding an entry
  whose name is empty, which the tool's own `ls` then renders as a second `/`
  line. `dir1/` plus `dir1/file.txt`, `./` plus `./file.txt`, and `d/` plus
  `d/l -> f` each reach it.
- An archive that holds a hardlink member whose link target is also mapped onto
  the empty string aborts on an assertion whose printed message names
  `ostree-mutable-tree.c`, ends on SIGABRT at exit 134, and writes no ref.
  `a.txt` plus a hardlink `b.txt` reaches it, at the top level
  and inside a directory member alike. The link target decides the outcome:
  `^a\.txt$,` aborts and `^b\.txt$,` reports the empty tree.
- An archive that holds no directory member reports `error: Can't commit an
  empty tree` at exit 1. One regular file, one symlink, two regular files, and
  a regular file plus a symlink each reach it.

The aborting run prints the assertion twice, once on stderr behind a line
holding `**` and once on stdout behind `Bail out! `. The source file name in it
is the tool's own output:

```
OSTree:ERROR:src/libostree/ostree-mutable-tree.c:550:ostree_mutable_tree_walk: assertion failed (start < split_path->len): (0 < 0)
```

The port refuses the first such member at exit 1 and writes no commit. The
message names the entry kind: `error: tar: regular file entry has an empty
path`, and `symlink` and `hardlink` in place of `regular file` for those two
kinds. The archive's own root member is the empty string already, so an
expression that leaves it empty is a match on nothing and is not this case.

The fifth is the wording of an entry the tar reader refuses. Both refuse a
device node and a FIFO; the tool reports `error: Unsupported file type for path
"<name>"` and the port reports its own line under `error: tar:`. A member whose
pathname is not valid UTF-8 is refused by both with the same line,
`error: Archive entry pathname is not valid UTF-8`, at exit 1, and a member whose
parent no member names is refused by both with `error: No such file or directory:
<name>`.

A file member that lands where an earlier member made a directory is refused by
both at exit 1, with no commit written and with the same message body,
`Can't replace directory with file: <name>`. The tool prefixes the frames its
importer unwound through, and which frames those are depends on the member: a
regular file or a symlink carries `ostree-tar: Failed to handle file:
ostree-tar: Failed to import file:`, and a hardlink placed after its group's
first member carries `ostree-tar: Processing deferred hardlink <first member>:
Failed to replace file:`. The port places each member as it reads it and holds no
deferred pass, so it reports the body alone and reproduces neither chain. The
collision needs no `--tar-pathname-filter`: an archive holding a directory member
and a file member of one name reaches it, and so does a rewrite that maps two
members onto one name. The same collision between two `dir=` sources carries the
bare body from both.

The other direction is a reference defect. A directory member that lands where an
earlier member made a file loses the tool's error and aborts it at exit 134 on an
assertion whose printed message names `ot-main.c` and reads `ostree_run:
assertion failed: (success || error)`. An archive holding a file member `f` and a
directory member `x/`, committed under `--tar-pathname-filter='^x/$,f'`, reaches
it. The port reports `error: Can't replace file with directory: <name>` at exit 1
and writes no commit.

The sixth is the `--table-output` counters over a `ref` source that is not the
first source in the list. The tool counts that source's content objects into
`Content Total` and the port does not, so `--tree=tar=a.tar --tree=ref=only1`
reports `Content Total: 4` from the tool and `3` from the port. A `ref` source
that opens the list reports `0` content objects from both and one metadata object
from the tool against the port's two, the tool assigning the whole tree wholesale
where the port reads the root's entries. Those two counts belong to a run that
reads the root alone. The tool counts into both totals the objects the source
contributes wherever it reads them, and `--generate-sizes` makes it read the
whole tree, so under that option `Metadata Total` and `Content Total` rise with
the source tree's object count and reach the counts a fresh commit of that tree
reports: `3` and `4` over a tree of one directory and four regular files, and `9`
and `7` over a tree of four directories and seven regular files. The port reports
`2` and `0` over each. The commit checksum, `Metadata Written`,
`Content Written`, `Content Cache Hits`, and `Content Bytes Written` agree in
every case; the counters are the only difference, and no cell states the
combination.

The seventh is the wording of a filesystem entry whose name holds a byte that is
not valid UTF-8. Both refuse the commit at exit 1, with standard output empty and
no ref written. The tool reports `error: Invalid UTF-8 in filename <name>`, the
name carrying the replacement character where the invalid byte stands, and the
port reports `error: invalid format: directory entry name is not valid UTF-8`.
The refusal stands ahead of the walk callbacks in both, so a `--skip-list` or a
`--statoverride` path that spells the replacement character reaches no such
entry: each control file holds UTF-8 alone and the walk compares a control-file
path against the walk path by bytes.

Two wordings the port reproduces here are the tool's own C-library shape:
`opendir(<path>): <reason>` for a `dir=` source or a positional `PATH` that
does not open, and `archive_read_open_filename: Failed to open '<path>'` for a
`tar=` source. Both implementations open a `dir=` source no-follow, so a
symlink naming a directory is `Not a directory` in both.

The one divergence the four Phase 17c options carry sits at the values
`--timestamp` takes. The tool reads a date with a full natural-language reader:
`@SECONDS` since the epoch, an absolute date and time with or without a UTC
offset (a value without one naming the tool's own local time), a ctime-style
rendering, a relative expression such as `now` or `yesterday`, and an empty value
(today's midnight). The port reads two of those forms -- `@SECONDS`, and an
absolute date and time carrying `Z` or `±HH[:MM]` -- because the rest need a
time-zone database or a natural-language date reader. A value the port does not
hold reports `error: Could not parse '<value>'` and exit 1, which is the tool's
own text for a value neither holds, so the two part on acceptance and not on
wording. Both refuse a bare count of seconds (`--timestamp=1234567890`), the `@`
being what states one. Each accepted form was checked against the tool by commit
checksum, the pre-epoch `@-1` and the leap day among them.

The two Phase 17f options carry four divergences between them. One of the four
parts on the text of a parse refusal; none parts on the set of values either
reader accepts, on the checksum a commit reaches, or on the seven
`--table-output` lines. The first is the order in which two refusable option
values are read. Both implementations refuse a `--fsync` value
neither reader holds with `error: Invalid boolean argument '<value>'` at exit 1,
and both refuse it in the same step: while the options are read, ahead of the
repository, ahead of the missing-branch check, ahead of the tree, and ahead of
the timestamp (`../format-reference.md`, "CLI output formats"). Inside that step
the tool reads the options in command-line order, where the port reads
`--owner-uid`, then `--owner-gid`, then `--fsync`. One refusable value alone
parts the two nowhere; two on one command line report the tool's leftmost and
the port's fixed first, so `commit --fsync=on --owner-uid=abc` reports the fsync
value from the tool and the id from the port.

The second is `--disable-fsync`, which `commit --help` does not list and which
the tool accepts there as `--fsync=false`. The port implements the documented
`--fsync=POLICY` alone, that being the option this file listed as missing. The
scope was chosen with the alias observed. `ostrya commit --disable-fsync`
reports `error: unexpected argument '--disable-fsync' found` from `clap` and
exits 1, where the tool commits. The valueless spelling stays with `pull` and
`pull-local`, which document it (`../format-reference.md`, "The fsync
vocabulary").

The third is a reference defect that no cell states. `--table-output` beside
`--skip-if-unchanged` over an unchanged tree prints uninitialized counters from
the tool, at exit 0 with standard error empty. The `Commit:` line names the
unchanged parent and is correct, and `Content Total` and `Content Written` are
zero. The four other counters carry values the run did not produce.
`Metadata Total` and `Metadata Written` hold a different value on every run.
`Content Cache Hits` and `Content Bytes Written` hold one value each across
runs: 58 and 3365424192 over five runs of one archive repository over one tree,
and the same two values over a second `bare-user` repository and a second tree,
so a cell pinning them would state a property of the host and of the build. The
combination is excluded from the matrix for that reason. The port prints the
same seven lines with the parent's checksum and zero for each of the six
counters, which is the count of the work a skipped run did and is the same text
on every run.

The fourth is the wording when `--fsync` ends the command line, with no word
after it to take as its value:

```
$ ostree commit -b c -s x --fsync
error: Missing argument for --fsync
$ ostrya commit -b c -s x --fsync
error: a value is required for '--fsync <POLICY>' but none was supplied
```

Both exit 1. This is `clap`'s own text for a missing option value, which every
valued option of the port reports, `--timestamp` among them, so the divergence
belongs to the parser and not to `--fsync`.

The count of sync calls a policy-on commit makes is not among the four. The two
resolve the same policy from the same inputs -- the configured `[core] fsync`
narrowed by the option value, so a repository configured off syncs nothing under
`--fsync=true` -- and both then sync the objects, the publication, and the ref.
The port issues one call more over an eleven-object tree, syncing the directory
holding the ref beside the ref file (`../format-reference.md`, "The fsync
vocabulary").

The nine Phase 17f options that carry the message, the metadata, and the ref
bindings agree with the tool over every form the cells and the unit tests hold.
Each accepted form was checked against the tool by commit checksum, which is what
the subject, the body, the metadata dict, and that dict's entry order all reach,
and each refusal by its text (`../format-reference.md`, "CLI output formats").
The set covered: the body forms and their five refusals; the editor's template
bytes, its file mode, its environment precedence, its shell-command handling, its
place in the fault order, the twenty-three message-parse cases, and the two
refusals; the editing session, which holds no repository lock in either
implementation, so an exclusive operation on the same repository runs while the
message is being written; the `--keep-metadata` parent rules and its two refusals; the detached
dict's own bytes; and the binding sort, the names it applies no rule to, and the
collapse `--no-bindings` makes.

`--add-metadata` carries the GVariant text reader, which was measured apart from
the cells by giving both implementations the same 776 distinct value texts and
comparing the commit checksum for an accepted one and the exact standard-error
line and exit status for a refused one. 749 of the 776 agree. The 366 values both
accept were then read back in four modes -- `--raw`, `-B --raw`,
`--print-metadata-key`, and `-B --print-metadata-key` -- 1464 comparisons of
which 1416 agree. Both sets of differences fall in the four classes
`../format-reference.md`, "Reading the text form back" records: a `\u` escape
naming a surrogate or a code point past U+10FFFF, which aborts the tool with a
signal and is refused by the port; the offset the nesting refusal carries for
`<`, `just`, a type keyword and a `@` declaration, which the tool prints as an
uninitialized number; a string holding a code point GLib does not count as
printable, which the tool escapes and the port prints as itself; and a value
nested past 123 levels, where the two part first on the printed text and then on
whether the commit is written at all. A `\u` or `\U` escape naming U+0000 is
refused by both in the same words and at the same offset, and the cells cover it
in a string, an object path, a signature, a dictionary key, an array, a variant,
a maybe and a tuple. A raw NUL byte in a string literal is refused by the port
alone; the tool takes its value through `argv`, which carries no NUL, so the
case reaches no cell. A fifth class stands at the subnormal rule:

- A decimal literal that states a subnormal exactly. The tool stores it and the
  port refuses it with `number too big for any type` at exit 1. The exact
  decimal form of a subnormal needs at least 716 significant digits, the
  shortest being the form of 2**-1023, so a literal any shorter rounds to its
  subnormal and both refuse it. The exact forms of 2**-1074 (751 digits),
  2**-1023 (716 digits), and 3 * 2**-1074 (752 digits) were each given to both
  implementations: the tool wrote the commit at exit 0 and the port refused. A
  hexadecimal body states its value in binary, so the port keeps the subnormal
  such a body states exactly and the two agree there. The port does not
  reproduce the decimal case because deciding it needs an exact comparison
  between the decimal literal and the binary value the reader does not carry,
  and refusing keeps it from storing a value of its own (`CLAUDE.md`, "CLI
  compatibility is functional, not literal").

The hexadecimal double reader was measured the same way with a further 1140
value texts: 400 random hexadecimal bodies over the whole exponent range, 530
across the subnormal edge and the overflow edge, and 210 decimal bodies. All
1140 agree, 889 accepted values by commit checksum and 251 refusals by text and
exit status.

Two further divergences sit outside that reader:

- `-F/--body-file` reads at most 128 mebibytes in the port and the whole file in
  the tool. A file past that reports `error: Commit body larger than 134217728
  bytes` at exit 1 where the tool writes the commit. Such a commit is a metadata
  object no reader in the port would load back, so no repository either
  implementation can read reaches the difference (`CLAUDE.md`, "Working
  conventions", which bars an unbounded read).
- The `-e/--editor` file is read back under the same 128-mebibyte bound, the
  editor being free to leave any bytes in it. A file past that reports
  `error: Commit message larger than 134217728 bytes` at exit 1 where the tool
  writes the commit. A file of exactly 134217728 bytes is accepted by both and
  reaches one commit checksum. No cell reaches the bound; the boundary is held
  by `commit_editor_file_is_capped`, which the normal suite skips and
  `cargo test -p ostrya-cli --test cli -- --ignored` runs.

A tree path that does not open reports `error: opendir(<path>): <reason>` from
both, at the same step: after the editor has run, after `--base` resolves, and
before the timestamp is read.

The six Phase 17f options that shape the filesystem walk -- `--statoverride`,
`--skip-list`, `--mode-ro-executables`, `--skip-if-unchanged`,
`--link-checkout-speedup`, and `-I/--devino-canonical` -- agree with the tool
over every form the cells and the tests hold, less the spend rule below. The
file formats, the mode arithmetic, the ordering against the other mode
modifiers, the unmatched-entry checks, and the skip path's output and exit
status are recorded in `../format-reference.md`, "CLI output formats", `commit`;
the devino rules are in that file's "Commit modifier: canonical permissions,
consume, and devino". Both control files are read ahead of everything else
`commit` does, the statoverride file first, and each reports a path it cannot
open as `error: openat(<path>): <reason>`, a directory as `error: Is a
directory`, and a byte that is not UTF-8 or is NUL as `error: Invalid UTF-8`.
Every form both implementations accept was checked against the tool by commit
checksum, over `archive`, `bare-user`, and `bare` for the two devino options;
the two mode-field classes below are the forms one accepts and the other does
not. Nine divergences stand:

- The order of the `Unmatched statoverride path:` and `Unmatched skip-list path:`
  lines. The tool emits them in a hash order: a file holding `/z1 /a2 /m3 /b4
  /y5` reports `/z1 /a2 /b4 /m3 /y5`. The port emits them in the order the file
  first names each path. Both emit one line per unmatched path, then the same
  summary line, at exit 1 with standard output empty, so the two agree on the
  set and part on the sequence.
- The mode a `--statoverride` value naming a file type the object model does not
  hold lands on. The rule both apply is `(mode & S_IFMT) | value` for an `=`
  entry and `mode | value` otherwise, so a value carrying bits inside the
  file-type field renames the type the mode holds. The class has three arms and
  the two implementations part on two of them, in the same direction: the tool
  writes the renamed mode and the port refuses it.
  - Over a regular file. `=8192` gives mode `0o120000`, a symlink type, and one
    commit checksum for both, an object the tool then renders as a symlink with
    an empty target. Any other renamed type parts: `=4096` gives `0o110000` and
    `=-1` gives `0xffffffff`, which the tool writes at exit 0 in an `archive`
    repository (its own `ls` then refuses the object with `Corrupted archive
    file; invalid mode 36864`) and which aborts it on a signal in a `bare-user`
    one, where the port refuses with `error: invalid file header: mode is not a
    regular file or symlink` at exit 1 in every mode.
  - Over a symlink. A value whose file-type bits land inside `0o120000` leaves a
    symlink and the two agree: `=32768` and `=8192` both give `l00000`, `=33261`
    gives `l00755`, and `=448` gives `l00700`. `=4096` gives `0o130000` and both
    `=16384` and `=49152` give `0o160000`, which the tool writes at exit 0 (its
    own `ls` then refuses the object with `Corrupted archive file; invalid mode
    45056` and `57344`) and which the port refuses with the same
    `invalid file header` line at exit 1.
  - Over a directory, the walk root included. Both refuse at exit 1 and word it
    differently: the tool `error: Invalid directory metadata mode <decimal>; not
    a directory` and the port `error: invalid dirmeta: mode is not a directory
    mode`, checked over `=33261`, `=32768`, `=4096`, `=8192`, `=40960`, and
    `=49152` against `/dir1` and against `/`.
  Beside `--canonical-permissions` the class collapses for the two arms the
  reduction reaches: the reduction records the file type the walk found, so the
  regular-file and directory arms reach the same commit in both, and the symlink
  arm, which the reduction leaves alone, still parts. Values in `0..=07777`,
  `0o100000 | perm` over a regular file, and `0o120000 | perm` over any entry
  reach the same bytes in both.
- The mode field of a `--statoverride` entry. The tool reads it through a C
  `double` reader and the port reads the leading decimal run. Over a 0644 file,
  both exit 0 and land on different commits for `0x1ff` and `0X1FF` (tool
  `-00777`, port `-00644`), `0x10` (`-00664` against `-00644`), `1e3` (`-01754`
  against `-00645`), `2e1` (`-00664` against `-00646`), `.7e3` (`-01674` against
  `-00644`), and `inf`, `nan`, `-inf`, `1e100`, and `4294967296`, which the tool
  turns into `0x80000000` for a mode of `-020000000644` where the port leaves the
  mode alone. `4294967295` is the one member of the class the port refuses,
  through the type-renaming rule above. Every form the documented format states
  -- a mode in decimal, with or without a sign or leading zeros -- agrees, and a
  field holding no digit is the value zero in both. The port does not reproduce
  the reader because the forms it takes sit outside the documented format and its
  out-of-range conversion is platform-defined.
- Either control file is read to at most 128 mebibytes in the port and whole in
  the tool. A file past that reports `error: Control file larger than 134217728
  bytes` at exit 1, the same bound and the same shape `-F/--body-file` takes
  above (`CLAUDE.md`, "Working conventions", which bars an unbounded read). No
  cell reaches the bound.
- `--skip-if-unchanged` beside `--parent=<a commit the repository does not
  hold>`. The tool ends on a signal, exit 139, with standard error empty; the
  port reports `error: object not found: Commit <checksum>` at exit 1. Without
  `--skip-if-unchanged` the two agree, both writing a commit that names the
  absent parent at exit 0.
- The wording when a content object cannot be written. `--owner-uid`,
  `--owner-gid`, and `--canonical-permissions` against a `bare` repository record
  the ownership on the inode, which a non-root user cannot set: the tool reports
  `error: Writing content object: fchown: Operation not permitted`, or the same
  line naming `fchownat`, and the port reports `error: i/o error: Operation not
  permitted (os error 1)`, both at exit
  1. `-I` masks the failure in both, no content object being written for a source
  file the cache resolves, so the same command line succeeds under `-I` and fails
  under `--link-checkout-speedup` and under neither.
- The work a root-pruning skip list still reaches. A skip list holding `/` prunes
  the walk root, so the port opens each source and reads none of it. With no
  `--base` the pruned walk leaves nothing to commit, so over a `dir=` source that
  opens and over a well-formed archive both report `error: Can't commit an empty
  tree` at exit 1. With `--base` the base is the whole tree and both write the
  same commit. The tool carries two further steps under the pruned walk, and the
  port carries neither:
  - Beside `--consume` the tool attempts the source removal. Over an empty source
    directory it removes the directory and reports the empty tree, where the port
    reports the empty tree and leaves the directory in place. Over a source
    directory holding one regular file the removal fails and the tool reports
    `error: unlinkat(<path>): Directory not empty`, where the port reports the
    empty tree; both leave the tree and its content in place. Under `--base` both
    write the same commit and the removal alone parts them.
  - Over `--tree=tar=<path>` the tool reads the stream, the archive format being
    detected only by the read the pruned walk skips. A file that is not an
    archive reports `error: archive_read_open_filename: Unrecognized archive
    format`, where the port reports the empty tree. Under `--base` the same file
    refuses the tool at exit 1 and the port writes the commit the base states at
    exit 0, which is the one arm where a root-pruning skip list parts the two on
    what reaches the repository.
  With no `--base` both exit 1 in every arm and neither writes an object or a
  ref.
- A `--skip-list` entry is spend-once in the tool and reaches every source in
  the port. Over `--skip-list=/f.txt --tree=dir=A --tree=dir=B` the tool prunes
  the path from `A` alone; the port prunes it from both. With a directory in
  place of the file the port reports `error: No such file or directory: dir1` at
  exit 1 where the tool commits at exit 0.
- `--table-output` beside `--skip-if-unchanged`, recorded with the `--fsync`
  divergences above.

`--statoverride=` and `--skip-list=` with an empty value belong to the parser
class the `--fsync` note above records: `clap` reports `error: a value is
required for '--statoverride <PATH>' but none was supplied` where the tool takes
the empty path to `openat` and reports `error: openat(): No such file or
directory`. Both exit 1 and write nothing. Every valued option of the port
reports that line, so the difference is the parser's and not these options'.

The claim that neither devino option changes a commit's checksum holds in twelve
of the fourteen checkout variants across the three repository modes, and fails in
two: a `bare-user` repository checked out with `-U`, with or without `-H`. That
checkout hardlinks the stored objects, which carry the repository's own
`user.ostreemeta` xattr, and the plain walk reads it as a real xattr of the source
file and commits it. There the plain commit is the outlier and the flagged one is
the faithful result; `--no-xattrs` on the plain walk reaches the flagged
checksum. The two implementations agree on all four commits over that variant, so
what parts is the flagged commit from the unflagged one and not one
implementation from the other. Three of the fourteen variants are checkouts the
tool refuses and the port performs, which is a `checkout` difference and not one
of these options'; the eleven both perform were compared, and the two
implementations agree on every one.

Two wordings the port reproduces are the tool's own and read as defects. The
first is the editor-failure line, which carries no separator between the closing
quote and the reason: `error: There was a problem with the editor
'<EDITOR>'Child process exited with code <N>`. The second is the
`--keep-metadata` missing-parent line, `error: Either --branch or --parent must
be specified when using --keep-metadata`, which is issued whenever the resolved
parent is absent, `--branch` having been given among those cases.

One `commit` divergence sits at the values `--parent` takes, the parenting
behavior itself being shared (`../format-reference.md`, "CLI output formats").
The tool reads the value with a reader that takes a 64-character lowercase
checksum or the literal `none`, and the port resolves any revision there, which is
a superset of that syntax like the leading `--repo` form above. Each side refuses
what it cannot read, at exit 1, writing nothing:

- an abbreviated checksum and a refspec report `error: Invalid rev <value>` from
  the tool, where the port resolves both. A refspec naming a ref, and an
  abbreviated checksum naming one commit, each reach the parent field; one naming
  nothing reports `error: Refspec '<value>' not found`, and a prefix more than one
  commit carries reports `error: Refspec <value> not unique`. The tool refuses
  every one of those values at this site alone: it resolves an abbreviated
  checksum wherever else a revision is taken (`../format-reference.md`, "Revision
  syntax"), so `--parent` is the narrower reader and not the narrower rule;
- an empty value reports `error: Invalid rev ` from the tool and `error:
  Invalid refspec ` from the port, the one refusal at this site the port words
  with its refspec validator;
- a non-lowercase rendering reports `error: Invalid character '<byte>' in rev
  '<value>'` from the tool, naming the first byte it refuses by decimal value,
  where the port reads a 64-character uppercase name as a refspec and reports
  `error: Refspec '<value>' not found`. `--parent=NONE` parts the two the same
  way, the literal being lowercase in both;
- an ancestry suffix reports the base alone, `--parent=<checksum>^` giving `error:
  Invalid rev <checksum>` from the tool, where the port walks it and carries the
  resolution wording every subcommand taking a revision gives, so the ancestry of
  a root commit reports `error: Commit <checksum> has no parent`.

A second `commit` divergence sits beside the branch-name guard both
implementations carry: `commit -b <64 lowercase hex>` is refused in the same
words at the same step (`../format-reference.md`, "Revision syntax"), and what
each leaves behind differs. The tool writes the tree and the commit object before
it reads the branch name, so the refusal leaves them in `objects/` -- seven loose
objects for corpus `C0` in mode `bare`, the commit among them, which its own
`fsck` then validates -- where the port publishes a transaction's objects at
commit and therefore publishes none. Neither writes a ref, so the refs tree is
the oracle the two share and `inventory` is no oracle for that cell. The two
faults that stand ahead of the guard are worded per implementation as well: an
unresolvable `--parent` reports the pair above, and a tree path that does not
open reports `error: opendir(<path>): No such file or directory` from the tool
and `error: i/o error: No such file or directory (os error 2)` from the port.
Two boundaries the guard does not cross, for the sub-phases that land the
options they belong to: `--bind-ref=<64 lowercase hex>` writes that name into
the commit's `ostree.ref-binding` metadata at exit 0, so the tool guards the ref
it writes and not the name it records, and `pull-local` reaches no name rule at
all -- against a source holding a ref of that shape it reports `error: Importing
<name>.commit: linkat: No such file or directory`, reading the ref name as a
checksum, where the port copies the ref. Such a source arrives by an out-of-band
write alone once the guard is in place.

A third `commit` divergence sits at that guard's second arm, the branch name
ending in `^` which resolution reads as ancestry (`../format-reference.md`,
"Revision syntax"). Both implementations refuse it, neither writes a ref, and
neither publishes an object; the words and the step part. The port refuses at the
ref write with `Invalid refspec <name>`, one message for every base. The tool
reads the branch name as a revision ahead of the tree and reports that walk:
`Invalid refspec <name>` where the base resolves to a commit holding a parent,
`Commit <checksum> has no parent` where it resolves to a root commit, and a
SIGSEGV where the base names no ref. That crash site is a second one beside the
`refs --create=NEWREF` site "P1" records, and `commit -b 'main^'` and `commit -b
'a^^'` both reach it. An empty base is the zero-length case of the
abbreviated-checksum scan, and the count that decides it is of commits:
against a repository holding no commit `-b '^'` reports `Invalid refspec `,
naming the base it split off, and against one holding a single commit the base
resolves to that root commit, so the walk reports `Commit <checksum> has no
parent`. Reading the name ahead of the tree also moves one fault order: a tree
path that does not open is reported by the port, which reads the tree first,
and never reached by the tool.

The guard is what keeps a ref of that shape out of a repository the port writes.
Where one stands, the tool's ref enumeration skips it without a word and its
`prune --refs-only` reads the commit that ref holds as unreachable and deletes
it, leaving the ref file over an absent object, where the port enumerates the
name and keeps the commit. That is the destructive class the `odd~1` item of
"P1" records for the ref-name character class, and the two read as one class:
an out-of-band write is the only arrival for either name. The character class
itself stays deferred, so a `^` inside the name parts the two -- the port writes
`a^b` and the tool refuses it with `Invalid refspec a^b`.

Four `commit` divergences sit at the three options that derive a metadata key
from the committed tree, `--generate-sizes`, `--bootable`, and
`--generate-composefs-metadata` (`../format-reference.md`, "CLI output formats",
`commit`). The keys themselves agree: over corpus `C0`, a kernel tree, and a
nested tree, in `archive`, `bare`, `bare-user`, and `bare-user-only`, both
implementations reach one commit checksum for each option, and the packed
`ostree.sizes` records agree entry by entry. The `ostree.sizes` half of that
holds for those three trees, whose payloads the two DEFLATE encoders compress to
equal lengths; the first divergence below gives the general case.

- The metadata dict order parts when either `--bootable` or
  `--generate-composefs-metadata` is combined with a caller-supplied metadata
  key. The port writes the four-group order the key-order rule states. The tool
  holds the dict in a hash-ordered container while either option is given, so
  its order follows the key set: with `--bootable` and one
  `--add-metadata-string=user.k=v` it writes `ostree.linux`, `user.k`,
  `ostree.bootable`, `ostree.ref-binding`, and with the key named `a` instead it
  writes `ostree.linux`, `ostree.bootable`, `a`, `ostree.ref-binding`, which is
  the port's order. The order is part of the checksum, so the two commits differ
  wherever the hash order does. Reproducing it means reproducing one GLib
  version's hash-table iteration, which is the same class as the hash-ordered
  `Unmatched statoverride path` lines this section already records.
  `--generate-sizes` alone keeps the insertion order in both.
- `ostree.sizes` records the size each object takes in the repository, so its
  values follow the writer's DEFLATE encoder. The two encoders reach two lengths
  for most payloads. Measured by committing one tree into an archive repository
  of each implementation and comparing the stored `.filez` size of every file
  object: 41 of 45 objects differ over the port's own Rust sources, 9 of 10 over
  `docs/`, 36 of 40 over a set of distinct system binaries, and 13 of 60 over
  runs of the byte `a` of length 1 to 60. Named payloads, tool size first: a
  payload of 50 `a` bytes stores as 40 and 50, corpus `C9`'s 1 MiB `large.bin`
  as 4424 and 4421, and 20000 random bytes as 20044 and 20039. An archive commit
  under `--generate-sizes` therefore reaches two checksums for any tree holding
  such a payload, which is the case for a real tree; the same tree without the
  option reaches one. The object identity is over the uncompressed bytes, so the
  two repositories stay interoperable. The harness's own `inventory` oracle
  reports the stored size of each loose object, so it parts on the same payloads
  wherever an archive-mode cell names it. The cause is `miniz_oxide` against
  zlib, and the no-C rule keeps the port on `miniz_oxide` (`../port-plan.md`,
  "Decisions").
- The kernel search's place in the fault order parts. The tool runs it after the
  tree walk and before the timestamp is read and before the empty-key check, so
  `--bootable --timestamp=bogus` over a kernel-less tree reports `error: No such
  file or directory: /usr/lib` there and `error: Could not parse 'bogus'` in the
  port, and `--bootable --add-metadata-string==v` parts the same way. Each fault
  alone is reported identically, and the faults the walk itself raises -- an
  unmatched control-file entry, the empty tree, and a `--skip-if-unchanged`
  match -- stand ahead of the search in both.
- A tree whose `/usr/lib/modules` is a non-directory is refused by the port with
  `error: Not a directory`, the message the tool gives for `/usr/lib`. Reference
  build 2026.1 dies there instead: it prints a GLib assertion failure and ends on
  SIGABRT at exit 134, having written nothing. The rule is the entry type at
  that one path: a regular file, a dangling symlink, and a symlink resolving to
  a directory that holds a kernel each reach the abort, and the same assertion
  line. A symlink at `/usr` or at `/usr/lib` stays outside it, and both
  implementations answer `error: Not a directory` there. No matrix cell states
  the aborting shape as a comparison.

The five signing options agree with the tool over their key grammars, their
refusals, their multiplicity and their ordering
(`../format-reference.md`, "Signing details"). The signature stands before the
ref in both: a key that cannot sign leaves the ref where it stood and publishes
nothing, and a ref write that cannot happen leaves the commit and its
`.commitmeta` durable in `objects/` with no ref. Both write the same
`.commitmeta` bytes for a given ed25519 key set, and each one's GPG signature
verifies through the other's `show --gpg-verify-remote`. Nine divergences
stand.

- `--sign-type` names an engine the port carries and this tool build does not.
  The tool's build reports `error: Requested signature type is not implemented`
  for `spki` and for `gpg`, where the port signs under `spki` when it is built
  with the `spki` feature and under `gpg` when it is built with the `gpg`
  feature. This is the rule `remote --sign-verify=spki=...` already carries:
  each refuses an engine it does not carry in those same words. Every other
  name parts in neither implementation -- `dummy` reports `error: dummy
  signature type is only for ostree testing`, and a name no engine carries,
  the empty string, `ED25519`, and a whitespace-padded name each report
  `error: Requested signature type is not implemented`. Because the tool
  carries no `gpg` engine here, `--gpg-sign` and `--sign --sign-type=gpg`
  cannot be compared tool-side at all, and no cell states that comparison.
- A `--sign-from-file` file whose first line is empty, and a file with no bytes
  at all, both die on a signal in the tool: the first prints a GLib assertion
  about `g_base64_decode_inplace` and ends on SIGSEGV (exit 139), the second
  prints an OSTree assertion failure and ends on SIGABRT (exit 134). The port
  reads the empty first line as a key of zero bytes and reports `error: Invalid
  ed25519 secret key: Ill-formed input: expected 64 bytes, got 0 bytes` at exit
  1, which is the tool's own wording for the same key given on the command line
  as `--sign=`. Both leave the repository as it stands.
- What becomes of the staging directory after a run parts. The port leaves none
  behind, on any path: a transaction removes its `tmp/staging-<bootid>-XXXXXX`
  directory and the `-lock` sibling when it commits, when it aborts, and when it
  drops, which covers every return that unwinds, and a refusal that ends the
  process instead runs the same removal immediately ahead of the exit. The rule
  holds for every subcommand that opens a transaction -- `commit`, `pull`,
  `pull-local`, `summary -u` over a repository carrying a collection id, and
  `static-delta apply-offline` -- and a run of any of them that exits non-zero
  leaves `tmp/` holding no `staging-` entry. The tool keeps one
  `staging-<bootid>-XXXXXX` entry across a refusal and reuses it for every
  transaction of the boot, so a repository it refuses a commit on carries that
  entry beside `tmp/cache`. Measured over one `commit --tree=dir=` naming an
  absent path against a fresh archive repository of each: the tool's `tmp/`
  holds `cache` and one `staging-` entry, the port's holds `cache` alone, both
  at exit 1. A `commit` refusal leaves no published state on either side: no
  object in `objects/`, no `.commitmeta`, and the ref where it stood. This holds
  for a sign failure, for a `dir=` source that does not open, for a `tar=`
  source that does not open, for a `--consume` removal that fails, for a
  `--tar-pathname-filter` value the reader refuses, for a `--base` revision that
  does not resolve, for a `--tree=ref=REV` value that does not resolve, for a
  timestamp the reader refuses, for a branch name the revision syntax shadows,
  and for a branch name the refspec grammar refuses. No matrix cell states the
  comparison: `tmp/` carries no published state and the oracles read `objects/`
  and the refs tree.
- The ref write's failure line parts. Forcing one by making `refs/heads`
  read-only reports `error: open(O_TMPFILE): Permission denied` from the tool
  and `error: i/o error: Permission denied (os error 13)` from the port. The
  state each leaves is the same, and that state is the ordering claim.
- A 64-byte `--sign` value whose halves are not an ed25519 key pair signs in the
  tool and is refused by the port. The port's engine requires the trailing 32
  bytes to be the public key of the leading 32-byte seed: one key's seed
  followed by another key's public key reports `error: signature: ed25519 secret
  key: signature error: Mismatched Keypair detected`, and a trailing half that
  is not a curve point reports `Cannot decompress Edwards point`. The tool signs
  both and the signature it stores does not verify against the public half the
  value stated -- `sign --verify --keys-file` over that half reports `error:
  ed25519: Signature couldn't be verified`. The shape is reachable from a
  mistyped key: over a 666-input base64 corpus these two are the only inputs the
  two implementations answer differently.
- A `--sign-from-file` first line longer than 65536 bytes is refused by the port
  with `error: Error reading file <path>: the first line is longer than 65536
  bytes`. The tool reads a line of any length: a first line of 100000 `A`
  characters reports `got 75000 bytes` there. The port bounds the read (see
  `../../CLAUDE.md`, "Working conventions"), and it refuses rather than cut, so
  no run reports a length shorter than the file holds. Both leave the repository
  as it stands.
- The path a `--sign-from-file` open failure names. The tool names the absolute
  path and the port names the path as the command line spelled it, so a relative
  `adir` reports `error: Error opening file <cwd>/adir: Is a directory` from the
  tool and `error: Error opening file adir: Is a directory` from the port. Both
  carry the same reason, exit 1, and write no object and no ref; an absolute
  path reaches one line from both.
- The branch-name term of the signing step's fault order is observable only over
  a name both ref-name grammars refuse. `-b 'bad//name' --sign=zzz` reports
  `error: Invalid refspec bad//name` in both. The port's `validate_refspec`
  covers path safety alone -- an empty name, a `.` or `..` component, a NUL --
  where the tool's grammar is wider, so `-b 'bad name' --sign=zzz` and
  `-b 'a^b' --sign=zzz` report the refspec in the tool and the key in the port.
  The ref-name grammar is the item deferred in Phase 17b.
- The order the `.commitmeta` dict stores its keys in parts over some key sets.
  The port stores insertion order always. The tool stores that same order over
  most sets and a name-dependent order over some of them: with
  `--add-detached-metadata-string=<name>=1 --sign=<key> --gpg-sign=<id>` it
  stores `<name>`, `ostree.sign.ed25519`, `ostree.gpgsigs` for `zzz`, `aaa`,
  `bar` and `user1`, and `ostree.gpgsigs`, `<name>`, `ostree.sign.ed25519` for
  `foo`, `qqq` and `user.first` -- 6 of 40 generated names. Its order is stable
  per name and ignores the command line: two user keys `foo` and `zzz` store as
  `ostree.gpgsigs`, `zzz`, `foo`, `ostree.sign.ed25519` in either command-line
  order. The stored order carries no meaning, every reader looking keys up by
  name, and `show --list-detached-metadata-keys` sorts, so the two agree there.
  With one engine, or with both engines and no user key, the two agree on the
  stored order too.

`checkout` accepts `--repo`, `-H/--require-hardlinks`, `-C/--force-copy`,
`--composefs`, `--composefs-noverity`, and, since Phase 17c, `-U/--user-mode`
and `--subpath=PATH`. Missing: `--disable-cache`,
`--union`, `--union-add`, `--union-identical`, `--whiteouts`,
`--process-passthrough-whiteouts`, `--allow-noent`, `--from-stdin`,
`--from-file=FILE`, `--fsync=POLICY`, `-M/--bareuseronly-dirs`,
`--skip-list=FILE`, `--selinux-policy=PATH`, `--selinux-prefix=PREFIX`.

The destination trees `-U` and `--subpath` produce agree with the tool's file for
file, in `archive`, `bare-user`, and `bare` (`../format-reference.md`,
"Checkout"). The two composefs switches are independent, and the no-verity one
decides whatever the command-line order: `--composefs`, `--composefs-noverity`,
and the two orders of the pair each write the tool's image bytes over a
`bare-user` repository
(`ostrya_cli::cli::checkout_composefs_switches_match_the_tool`). Three
divergences stand at the values `--subpath` takes, one at `-H`, and two at the
composefs switches:

- a subpath naming nothing ends the checkout at exit 1 in both, leaving no
  destination, and the words part: the tool reports `error: No such file or
  directory: <path>`, naming the path with a leading slash it adds, and a path
  running through a regular file reports `error: Not a directory`. The port
  reports its own `error: checkout: subpath not found: <path>` for both;
- `--subpath=.` and a trailing-slash form such as `--subpath=/sub/` are refused
  by the tool, which reads the whole value as a name to look up (`No such file or
  directory: /.`). The port reads a path, so `.` names the tree root and the
  trailing slash names the same directory as the form without it. Both accept a
  leading-slash and a relative spelling of a name that exists, and `/` names the
  whole tree in both;
- the tool takes `-H` only where the repository mode can hardlink under the
  checkout mode in force, and refuses it at exit 1 elsewhere. Measured over the
  four modes, `-H` alone is taken by `bare` and `bare-user-only` and refused by
  `archive` (`error: Bare repository mode cannot hardlink in user checkout
  mode`) and by `bare-user` (`error: User repository mode requires user checkout
  mode to hardlink`); `-U -H` together is taken by `bare-user` and
  `bare-user-only` and refused by `archive` and `bare` (`error: Bare repository
  mode cannot hardlink in user checkout mode`). The port's `-H` is a no-op, so
  it accepts every combination and hardlinks wherever a copy is not forced.
  Giving `-H` its refusal is `-H` semantics, which belongs with the remaining
  `checkout` options. Where the tool takes `-H`, the two hardlink the same
  objects: `ostrya_cli::cli::commit_checkout_speedup_matches_the_tool` checks a
  `bare` repository out with `-H` on both sides and reads 14 devino-cache hits
  out of each side's own `--table-output` block, against 13 for a `bare-user`
  repository checked out with `-U` and 0 for the two forms that hardlink
  nothing;
- the tool exports a composefs image from any repository mode, and from an
  `archive` repository it writes `trusted.overlay.redirect` values naming
  `.file` loose paths that repository does not hold, whose objects are
  `.filez`, so the image cannot be mounted against the repository that produced
  it. The port refuses a repository outside the composefs backing modes
  (`bare-user` and `bare-user-shared`) at exit 1 and leaves no destination
  behind, naming the mode it got: `error: unsupported: composefs export
  requires a bare-user or bare-user-shared repository, not Archive`. `commit
  --generate-composefs-metadata` is unaffected and works in every mode in both,
  the digest path applying no mode check (`../format-reference.md`,
  "composefs"). Both sides of the divergence stand in
  `ostrya_cli::cli::checkout_composefs_refuses_an_archive_repository`;
- the tool writes the image through a temporary file it creates in the working
  directory and links to the destination, so a destination on another
  filesystem ends the export at exit 1 with `error: linkat: Invalid
  cross-device link`. The port writes its temporary file in the destination's
  own directory and renames it over the destination, so the rename stays inside
  one filesystem and every destination is taken. The two agree on what the
  temporary file buys: an export that finishes replaces the destination rather
  than writes into it, so the image carries the process umask and not the mode
  the destination held
  (`ostrya_cli::cli::checkout_composefs_switches_match_the_tool`), and an
  export that does not finish leaves a destination that already existed as it
  was, byte for byte and at its own mode
  (`ostrya_cli::cli::checkout_composefs_refuses_an_archive_repository`).

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
- `remote add-cookie`, `delete-cookie`, and `list-cookies` -- see the cookie-jar
  note at the end of this section.
- `checksum` -- `--ignore-xattrs`.
- `find-remotes` -- `--cache-dir`, `--disable-fsync`, `--finders=FINDERS`,
  `--pull`, `--mirror`.
- `create-usb` -- `--disable-fsync`, `--destination-repo=DEST`,
  `--commit=COMMIT`.
- `gpg-sign` -- `-d/--delete`, `--gpg-homedir=HOMEDIR`. The port folds GPG
  signing into `sign --sign-type=gpg`, so this is an alias with its own option
  names.

`remote` landed in Phase 17e: `add`, `delete`, `list`, `show-url`, `refs`,
`summary`, `gpg-import`, and `gpg-list-keys`, with the option set the tool
carries on each and the output formats `../format-reference.md`, "`remote`",
records. Ten divergences stand:

- the tool's `remote` accepts no `--repo` of its own -- `ostree remote --repo=R
  list` reports `error: Unknown option --repo=R`, where the leading position
  (`ostree --repo=R remote list`) and the nested subcommand's own `--repo` both
  work. The port accepts `--repo` in every position, the leniency "Global
  conventions" already records;
- a nested subcommand the tool does not know reports `error: Unknown "remote"
  subcommand '<name>'` at exit 1, where the port reports clap's own
  `unrecognized subcommand` text. A missing nested subcommand agrees in both;
- `remote delete` removing the last `[remote "<name>"]` section of the document
  leaves the tool's file with one trailing blank line, where the section's
  separator was, and the port's with none. Removing a section any other section
  follows leaves the two files identical, and both documents reparse to the same
  configuration;
- `--sign-verify=spki=...` reports `error: Requested signature type is not
  implemented` from the tool, whose build carries the ed25519 engine alone, and
  the port accepts it where it is built with the `spki` feature. Each refuses an
  engine it does not carry in those same words;
- `remote gpg-list-keys` reports the key fingerprint, the creation instant, and
  the user ids in the tool's own shape, and leaves out the `(revoked)` marker
  the tool prints after a revoked key's fingerprint and after each of its
  revoked user ids, and the `Advanced update URL` and `Direct update URL` lines
  the tool prints per user id: they name the key's OpenPGP Web Key Directory
  location, derived from a hash of the address, and
  state no repository fact. It also leaves out the `Subkey:` line and the
  `Created:` line under it that the tool prints for each subkey a key carries:
  the port reports a certificate by its primary key, and a subkey reaches the
  trusted set through the certificate holding it. The creation instant parts the
  same way the GPG signature report in "P1" does -- the tool renders it in the
  host locale and time zone and the port in UTC. `remote summary` renders its
  `Timestamp` and `Last-Modified` lines the same way, so a report compares byte
  for byte with `TZ=UTC` set;
- `remote gpg-import` writes a keyring that carries no Trust packet, where the
  tool's own import writes one after the primary key packet, after each user id
  packet, and after each signature packet. A Trust packet holds a GnuPG-local
  trust value and carries no part of a transferable public key: with those
  packets dropped, the tool's keyring holds the packets the port's holds, in the
  same order, measured byte for byte over a key carrying a signing subkey
  (`crates/ostrya/src/gpg.rs`, `the_trust_packets_are_the_whole_difference`).
  The tool's file is the longer one by those packets alone, whose size varies
  from one to the next. Each implementation reads the keyring the other
  wrote: `ostree remote gpg-list-keys` and
  `gpg --no-default-keyring --keyring <file> --list-keys` both list the keys of a
  keyring the port wrote, and `ostrya remote gpg-list-keys` lists the keys of a
  keyring the tool wrote. The port also verifies a signature against a keyring
  carrying those packets, which `crates/ostrya/tests/verify_gpg_agreement.rs`
  states against `gpgv` over the same file;
- a `KEY-ID` operand of `remote gpg-import` is read as a fingerprint, a key id,
  or a user id substring, which is the dialect `gpg --export -- <selector>`
  carries. Hex digits alone name a key -- 8 digits a short key id, 16 a key id,
  and 32, 40, or 64 a fingerprint, each read over the primary key and over every
  subkey -- and so do the same digits under a lower-case `0x` prefix and a
  printed v4 fingerprint in its ten groups of four. Every other selector is a
  substring of a user id, folded over ASCII case alone. The tool resolves a
  narrower set through gpgme, and each implementation therefore takes a key the
  other does not. Over a keyring holding `Alpha <alpha@ostrya.example>`,
  `Umlaut Ärger <u@ostrya.example>`, and one more key:
  - the tool takes the key for `=Alpha <alpha@ostrya.example>` and for the
    fingerprint with a `!` suffix, and the port reports
    `error: signature: no key matching '<selector>' among the keys to import` at
    exit 1 for both, writing no keyring;
  - the port takes the key for `alpha`, for `Ärger`, and for `ÄRGER`, where the
    tool reports `error: GPG: Unable to find key "<selector>": GPGME: Invalid
    value` at exit 1 and writes no keyring; and it takes both keys for
    `ostrya.example`, where the tool reports
    `error: GPG: Unable to find key "ostrya.example": GPGME: Ambiguous name`,
    refusing a selector that names more than one key;
  - both refuse `ärger`, an upper-case `0X` before a key id or a fingerprint, a
    key id carrying a space, a fingerprint spaced in groups of two, a
    fingerprint carrying a tab, a `0x` prefix carrying a space, and a selector
    holding no character other than whitespace. Both read a hex selector as a
    key alone: over a certificate whose user id opens `DEADBEEF`, neither takes
    the key for `DEADBEEF`
    (`crates/ostrya/src/gpg.rs`,
    `a_selector_the_key_reader_does_not_carry_names_nothing` and
    `a_user_id_selector_folds_ascii_case_alone`, hold the port against
    `gpg --export` over each of those forms);
- a certificate offered for a key the keyring already holds leaves that key as
  the keyring holds it, where the tool merges the offered user ids, signatures,
  and subkeys into it. Both report `Imported 0 GPG keys`. Over a keyring holding
  a one-user-id key, importing that key again with a second user id added leaves
  the port's keyring at the packet stream it held and grows the tool's, whose
  listing then reports both user ids where the port's reports one. An armored
  keyring keeps that packet stream and is written back in the binary form. A new
  subkey and a subkey revocation part the same way, and reach the port's keyring
  through `remote delete` and a fresh import. Two statements are the exceptions,
  a key revocation and a later key expiry, and both are recorded below.

  A key revocation is one of the two certificates both implementations carry
  in. An offered certificate holding a key revocation signature that verifies
  under the key it revokes replaces the certificate the keyring holds for that
  key, and the count stays `Imported 0 GPG keys`. Each implementation holds a
  commit signed with `$FPR`, a remote `origin`, and `cert1.gpg` imported into
  that remote:

      gpg --export "$FPR" > cert1.gpg
      printf 'y\n1\n\ny\n' | gpg --command-fd 0 --no-tty --yes \
        --output revoke.asc --gen-revoke "$FPR"
      gpg --import revoke.asc
      gpg --export "$FPR" > cert2.gpg
      ostrya remote gpg-import origin --keyring cert2.gpg  # Imported 0 GPG keys
      ostree remote gpg-import origin --keyring cert2.gpg  # Imported 0 GPG keys
      ostrya show --gpg-verify-remote=origin main   # BAD signature from "..."
      ostree show --gpg-verify-remote=origin main   # Key revoked

  Each implementation refuses the signature, and the two verdict lines are the
  report wording "P1" above records. `ostrya sign --verify -s gpg --remote
  origin <commit>` reports `verification FAILED` over either implementation's
  keyring.

  The bytes part where the packets do. The port writes the offered certificate
  where the held one stood and drops every Trust packet the keyring carried,
  which is the Trust-packet difference above measured over a rewrite; the tool
  merges the offered signature packets into the held certificate run and keeps
  its Trust packets. Measured over the re-export of a revoked RSA-2048 key
  carrying one user id, each keyring holds one certificate run, in the same
  packet order -- the primary key, the key revocation, the user id, the user id
  self-signature -- and the tool's file is the longer one by five Trust
  packets, 52 bytes: one after the primary key, one after each of the two
  signatures, one after the user id, and one more at the end. With the Trust
  packets dropped the two files are byte-identical, and the port's
  keyring is the `gpg --export` stream of the revoked key byte for byte. Each
  implementation reads the keyring the other wrote: `ostree remote gpg-list-keys`
  over the port's file reports the key and marks it `(revoked)`, and
  `ostrya remote gpg-list-keys` over the tool's file reports the key
  (`crates/ostrya/src/gpg.rs`,
  `a_revoked_re_export_replaces_the_held_certificate`, states the same
  comparison against the keyring GnuPG writes for the same two imports).

  A later key expiry is the other. An offered certificate that states a later
  key expiry than the held one replaces the certificate the keyring holds for
  that key, an absent expiry counting as later than any instant, and the count
  stays `Imported 0 GPG keys`. Each implementation holds a commit signed with
  `$FPR`, whose lifetime was one day and whose signature was made while the key
  was live, a remote `origin`, and `cert1.gpg` imported into that remote.
  Measured against `ostree` 2026.1 and `gpg` 2.4.9:

      gpg --quick-set-expire "$FPR" 10y
      gpg --export "$FPR" > cert2.gpg
      ostrya remote gpg-import origin --keyring cert2.gpg  # Imported 0 GPG keys
      ostree remote gpg-import origin --keyring cert2.gpg  # Imported 0 GPG keys
      ostrya show --gpg-verify-remote=origin main   # Good signature from "..."
      ostree show --gpg-verify-remote=origin main   # Good signature from "..."

  Over the same commit before that import each implementation reported `BAD
  signature from "..."`, the tool adding the `Key expired <instant>` line the
  report wording in "P1" above records. Each implementation reads the keyring
  the other wrote and reports the good signature over it
  (`crates/ostrya-cli/tests/cli.rs`,
  `remote_gpg_import_carries_a_key_expiry_extension`).

  The bytes part here as well, and by more than the Trust packets. The port
  writes the offered certificate where the held one stood, so its keyring is the
  `gpg --export` stream of the extended key byte for byte; the tool merges the
  offered packets into the held certificate run, so its file keeps the
  self-signature the earlier export carried along with its own Trust packets and
  is the longer one -- 439 bytes against 235 over an ed25519 key carrying one
  user id. Both files state the extended expiry, which is why the two reports
  agree.

  The expiry rule holds in one direction. An offered certificate stating an
  expiry no later than the held one leaves the port's keyring at the bytes it
  held, so a shortened expiry does not reach a remote's trusted set, and a held
  certificate that revokes its key takes no expiry replacement
  (`crates/ostrya/src/gpg.rs`,
  `an_expiry_extension_replaces_the_held_certificate`,
  `an_earlier_expiry_leaves_the_held_certificate`, and
  `a_revoked_key_takes_no_expiry_replacement`).

  A revocation another key made carries no weight. The signature is verified
  under the key it revokes before it is honored, so a key revocation signature
  anyone stapled onto an offered certificate leaves the keyring at the bytes it
  held (`crates/ostrya/src/gpg.rs`,
  `a_stapled_revocation_does_not_replace_the_held_certificate`). Without that
  rule an offered keyring would be a way to strike any trusted key out of a
  repository.

  A bare revocation certificate -- the single signature packet
  `gpg --gen-revoke` writes -- carries no public-key packet, so it holds no
  certificate, and both implementations refuse it: the port reports
  `error: signature: the keyring to import holds no OpenPGP certificate` and the
  tool `error: GPG: Unable to export keys: GPGME: No data`, each at exit 1 and
  neither writing a keyring. The re-export of the revoked key is the path that
  carries a revocation in.

  A keyring carrying bytes past its last framed packet takes no import. The
  port reads the keyring the remote holds with the reader a verification load
  uses, and that reader reads a keyring whole or refuses it. Every import into
  such a keyring reports `error: signature: the keyring '<name>' is not
  readable as an OpenPGP keyring` at exit 1 and leaves the file byte for byte
  as it stood -- a revoked re-export of a key it holds, a re-export stating a
  later expiry, and a certificate for a key it does not hold alike
  (`crates/ostrya/src/gpg.rs`, `an_unframeable_keyring_takes_no_import`).
  Measured over a keyring the tool's own import wrote with one `0xff` byte
  appended, the tool reports `Imported 0 GPG keys` at exit 0 and writes
  nothing, `ostree remote gpg-list-keys` prints nothing at exit 0, and
  `ostree show` reports `Can't check signature: public key not found`. Neither
  implementation trusts a key out of that file, and the two answers part in the
  exit status and the diagnostic: `ostrya remote gpg-list-keys` reports the
  same refusal over such a file, since it reads the keyring with the same
  reader. Where the bytes the packet walk stops at stand inside a later
  certificate run, the answers part further: the port refuses the whole file,
  and the tool reads the certificates standing ahead of that point and trusts
  them (`../port-plan.md`, "Phase 13d", the divergence for a keyring the parser
  rejects).

  Both rules hold inside one offered stream as well: where a stream carries two
  states of one key the port keeps the first, unless a later one revokes the key
  or states a later expiry. The revoked export alone and the two exports
  concatenated in either order therefore reach one keyring, which the port's own
  test states, and every `--keyring` option of one invocation reaches the import
  as one stream. The tool answers the same way: over each of those three streams
  it reported `Imported 1 GPG key`, wrote three byte-identical keyrings, and
  reported the signature `Key revoked`.

  A trusted set holding both certificates parts a second way -- `cert1.gpg` in
  the remote's keyring and `cert2.gpg` in the `OSTREE_GPG_HOME` directory. The
  tool answers on which certificate it reads first. The port reads the
  revocation whichever one stands first, and reads the newest expiry statement
  of the two whichever one stands first. Those are the sixth and the seventh
  verify divergences `../port-plan.md`, "Phase 13d", records;
- a `gpg --export-secret-keys` stream offered to `remote gpg-import` is refused
  by the port and taken by the tool, which imports the public part of each key it
  holds and lists it afterwards. The port reads a keyring as transferable public
  keys, so such a stream holds none: it reports
  `error: signature: the keyring to import holds no OpenPGP certificate` at exit
  1 and writes no keyring. `gpg --export` of the same keys is what a keyring for
  a remote holds, and both implementations take it;
- a certificate carrying no user id is taken by the port and refused by the tool.
  The port reads a certificate as the packets one Public-Key packet opens and
  verifies no self-signature over them, so a stream holding a Public-Key packet
  alone -- the first 53 bytes of an exported ed25519 certificate -- reports
  `Imported 1 GPG key to remote "<name>"`, writes a 53-byte keyring, and lists
  the key. The tool reports `error: GPG: Unable to export keys: GPGME: No data`
  at exit 1 and writes no keyring, which is also what it answers over a
  certificate whose self-signature does not verify.

Three messages the port words for itself, each reporting a condition the tool
reports through gpgme: `remote gpg-import` with no `--keyring` and no `--stdin`
(the tool's `GPG: Unable to export keys: GPGME: No data`), a `KEY-ID` naming
no key in the source (the tool's `GPG: Unable to find key "<id>": GPGME: End of
file`), and a keyring the certificate parser does not read -- one holding no
OpenPGP packet, one cut short of a packet boundary, and a GnuPG keybox -- which
the tool reports as `GPG: Unable to export keys: GPGME: No data`. Both refuse all
three at exit 1 and write no keyring.

`--cache-dir`, which the tool's `remote refs` and `remote summary` accept, is not
carried: the port fetches a summary without a cache directory of its own. The
port's fetcher serves `http` and `https` alone, where the tool also reads a
`file://` remote, so a `file://` URL reports `fetch url scheme file: only http
and https are fetched` (`../port-plan.md`, Phase 16a).

`remote add-cookie`, `remote delete-cookie`, and `remote list-cookies` stay out.
`fetch.rs` refuses any `Cookie` header at construction whenever a mirror is
cleartext `http`, a deliberate choice, and cookie-jar support needs its own design
pass against that refusal.

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
  otherwise the compiled-in path `/sysroot/ostree/repo`, when the host carries
  one; otherwise the tool prints the subcommand's usage text to standard error,
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
- The third source is a path the tool compiles in, and its help text states the
  chain: `--repo=PATH   Path to OSTree repository (defaults to current
  directory or /sysroot/ostree/repo)`, with `OSTREE_REPO` sitting between the
  two paths that line names. An `OSTREE_REPO` value that does not open as a
  repository leaves the chain running: with `OSTREE_REPO` set to an empty
  directory and to an absent path, the tool reports `error: Command requires a
  --repo argument` on a host with no system repository, so it passes over the
  value and continues. No environment variable closes the third source. A
  repo-less tool invocation on an ostree-managed host therefore resolves the
  system repository, and a writing subcommand acts on it. The port's chain is
  the current directory, then `OSTREE_REPO`, and it ends there. Resolving no
  third source keeps `ostrya` from acting on a live system repository through
  an omitted `--repo`, and it costs `ostrya prune` an explicit `--repo` where
  `ostree prune` needs none on an ostree-managed host. The port holds this
  divergence by intent.
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
  `collection-id` key, even though the very same reuse through an explicit
  `--repo` succeeds (exit 0, config untouched) on the identical
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
- A typed `[core]` value is read more strictly by the port than by the tool,
  so a set of malformed values opens under the tool and is refused by the port.
  The tool's key-file reader takes the leading run of decimal digits from an
  integer value and ignores the rest, and reads no value at all where there is
  no leading digit, in which case the key's default applies with no diagnostic;
  its boolean reader ignores a run of trailing space, tab, or form feed before
  it matches the four literals (`../format-reference.md`, "Config file"). So
  `ostree` opens a repository holding `lock-timeout-secs=bogus`,
  `tmp-expiry-secs=bogus`, `min-free-space-percent=bogus`,
  `min-free-space-percent=101x` (read as 101), or `fsync=true `, and `ostrya`
  refuses each of them at exit 1, naming the group, the key, and the value.
  Three reasons hold the refusal:
  - The tolerance belongs to the dialect of the C key-file library the tool
    links and the port does not. Reproducing it means hand-rolling that
    dialect, which `CLAUDE.md`, "CLI compatibility is functional, not literal",
    rule 2, refuses.
  - The value the tool proceeds with has no oracle. A non-integer
    `lock-timeout-secs` or `tmp-expiry-secs` changes no byte the tool writes,
    so which value it fell back to cannot be recovered by observation, and
    picking one would be reinterpretation. Rule 1 of that same section refuses
    it and requires the port to exit non-zero having written nothing, which is
    what it does.
  - The tolerance differs by type. The boolean reader ignores a trailing form
    feed and refuses a trailing vertical tab; the integer reader accepts both;
    `min-free-space-size` refuses a trailing space or tab outright. A partial
    imitation would agree with the tool on some values and not others.

  Neither implementation writes a value of this shape as part of its own work,
  so a repository reaches it only by a hand edit or by `config set` being told
  to write one, which both accept. On such a repository the write commands part
  as above: the tool proceeds and the port refuses. Both agree on every value
  in the format's own vocabulary, and both refuse a `[core] fsync`, `locking`,
  or `per-object-fsync` value that is not one of the four boolean literals and
  a `min-free-space-size` the size grammar does not hold.
- The step a `[core]` value refusal is reported at differs, in the other
  direction. The tool reads these keys when it opens the repository, so its
  refusal precedes every check a subcommand makes and reaches every subcommand:
  `ostree refs` over a repository holding `fsync=bogus` exits 1. The port reads
  each key where it is used, so a read-only subcommand that never reads it runs
  to completion: `ostrya refs` over that repository lists the refs at exit 0.
  Within `commit` the port reads the whole `[core]` set the transaction needs
  in one place, after the `--statoverride` and `--skip-list` files and after
  the missing-branch check, and before `--parent`, the metadata options, the
  editor, and the repository lock. One fault on a `commit` line parts the two
  nowhere, since both refuse it and exit 1. Two faults report the tool's config
  refusal and the port's earlier check, so `commit --statoverride=no-such-file`
  against a repository holding `fsync=bogus` names the config from the tool and
  the file from the port. Both exit 1 with no object and no ref written.
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
  with slashes handled), so `checkout` reports clap's own missing-argument error
  at the argument-parsing layer, ahead of the repository check.

## Output formats still to recover

A script reads standard output, so the format is part of the surface. The
formats of `commit`, including its `--table-output` block, `refs`, `rev-parse`,
`cat`, `show`, `log`, `ls`, and
`config get`, together with the GVariant text form the reading commands share,
are recovered and recorded in `../format-reference.md`, "CLI output formats" and
"The GVariant text form". Each format below still needs a black-box observation
pass, and the results belong in that same section.

- `diff`, including the per-path change prefixes and `--stats`.
- `fsck` progress output and its `-q` form.
- `prune` totals.
- `summary -v`, `--raw`, and `--list-metadata-keys`, whose formats are the ones
  `remote summary` reports and whose flags the local command still lacks.
- `static-delta list`, `show`, and `indexes`.
- `pull` progress output.

`remote list`, `show-url`, `refs`, and `summary` are recovered, in
`../format-reference.md`, "`remote`".

## Ordering

1. `init`, which unblocks every port-created cell. Done, Phase 17a.
2. `--repo` in the leading position, the current-directory default, and
   `OSTREE_REPO`, so one command template serves both implementations and the
   harness stops carrying a per-implementation option table. Done, Phase 17a.
3. `refs`, `rev-parse`, and `cat`, the postcondition checks in nearly every
   cell. Done, Phase 17b. `cat` joined this step rather than step 5: it needs no
   variant printer, and it reads a file object over the same path `refs` and
   `rev-parse` opened.
4. `commit` parenting, which `rev-parse REV^` and `log` both read and which
   step 3 exposed. Done, Phase 17b1.
5. The P2 option gaps on `commit` and `checkout`, which the corpora need:
   `--owner-uid`, `--owner-gid`, `--timestamp`, `--no-xattrs`, `-U`, `--subpath`.
   Done, Phase 17c.
6. `show`, `log`, `ls`, and `config get`, together with the variant printer.
   Done, Phase 17d.
7. `config set`/`unset`, `remote`, and the two GPG keyring commands, which need
   the config write path. Done, Phase 17e.
8. The remaining P2 gaps. Phase 17f, decomposed per command in
   `../phase-17-cli-conformance-plan.md`.
9. The rest of P3. Phase 17g, decomposed in the same file.

That file holds the per-option status of both sub-phases, including any option
deliberately skipped. An option marked `skip` there is moved out of the
`Missing:` list above and stated as a divergence in its command's text, the way
`remote add-cookie` and `remote refs --cache-dir` already stand.
