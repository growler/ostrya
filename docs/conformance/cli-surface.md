# CLI surface required by the conformance matrix

This file states the command-line surface of the `ostrya` command. It is
derived from two roles:

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
reads that mode and does not write it (`format-reference.md`,
"bare-split-xattrs mode"), so exposing it here would create a repository
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

Their output formats are recorded in `cli-behavior.md`, "CLI output
formats", `refs`, `rev-parse`, and `cat`. Seventeen tool behaviors around them
are observed and deliberately not reproduced:

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
- a symlink under `refs/` that names a directory. Such a link comes from an
  out-of-band change alone, because `refs -A --create` validates its target as
  a ref in both implementations. In both implementations, `-A` lists the link
  as `lnk -> deep`. In each implementation, a link that names its own
  directory (`refs/heads/selfdir -> .`) gives the same results as a link to
  another directory. The other results part as follows:
  - The tool reports `error: Listing refs: Is a directory` and exits 1 from
    the default listing, `--list`, `-r`, `fsck`, `summary -u`, and `prune
    --refs-only`. The default `prune` of the tool reads no ref and exits 0.
  - The prefix forms of the tool complete over the link. A `PREFIX` that
    names the link enumerates the directory that the link points at. So `refs
    lnk` prints `nest/ing` where `refs/heads/lnk` links to `deep` and
    `deep/nest/ing` is a ref. A `--delete PREFIX` that matches other refs
    removes them and exits 0. A `--delete` that names the link reports `error:
    Listing refs: opendir(lnk): Not a directory` and exits 1.
  - The port reads each symlink under `refs/` as an alias, and descends into a
    real directory alone. So the read of the link fails with `EISDIR` wherever
    an enumeration reaches it. The port reports `error: i/o error: Is a
    directory (os error 21)` and exits 1 from each listing form other than
    `-A`. It does the same from `--delete`, whatever the prefix matches, and
    from `fsck`, `prune`, and `summary -u`;
- an invalid collection id aborts the tool when it names a directory under
  `refs/mirrors`. The tool prints `ostree_collection_ref_new: assertion
  'collection_id == NULL || ostree_validate_collection_id (collection_id,
  NULL)' failed`, and a signal ends it. The port lists what that path holds.
  The tool refuses an invalid id given as a `-c` positional with `error:
  Listing refs: Invalid collection ID <id>` and exit 1. The port validates a
  collection id only where `-c --create` writes one. So a `-c` positional that
  the tool refuses matches no collection ref in the port, which prints nothing
  and exits 0;
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
  that name at the step a resolvable base reaches (`cli-behavior.md`, "CLI
  output formats", `refs`, "NEWREF check order");
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
  (`cli-behavior.md`, "CLI output formats", `refs`, "Listing and prefixes");
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
  in directory order, with `--force` and without it; over the ref
  `deep/nest/ing`, `refs --create=deep plain` reports `error: Conflict:
  nest/ing exists under deep when attempting write`, so the line names the
  path below the directory that the scan reached; `error:
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
  `cat plain/x PATH`, and the same line for a name that reaches the ref file
  through an alias symlink; for `origin:rr/x/y` it reports `error:
  openat(refs/remotes/origin/rr/x/y): Not a directory`; under
  `-c --create=<id>:<ref>` the write reaches the
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
its commit on that commit in both implementations. The rule and the sites it
reaches are in `../format-reference.md`, "Abbreviated checksums".

One resolution behavior the tool has and the port does not, recorded in
`../format-reference.md`, "Branch names no revision reaches":

- the tool's ref enumeration skips a ref whose name fails the ref-name rule
  without a word, and the port enumerates it. Only an out-of-band write puts
  such a name in a repository, because both implementations refuse it on every
  write path. Over a ref of that shape, `refs`, `refs --list`, `refs -r`, a
  `PREFIX` above it, `fsck`, and `summary -u` each print the other refs and exit
  0 in the tool. The port's `fsck` enumerates the name and loads the commit it
  holds, so a ref of that shape over an absent commit ends the port's run at
  exit 1 where the tool's run passes, which is one of the divergences the
  `fsck` entry under "P2" records. And `prune --refs-only` in the tool reads the
  commit that ref holds as unreachable and deletes it, so after an out-of-band
  write of the ref `odd~1` and `ostree prune --refs-only` the ref file stands
  over an absent commit object and `ostrya cat 'odd~1' PATH` reports `error:
  object not found`. The port enumerates the name, so its own `prune
  --refs-only` over the same repository keeps the commit and leaves the ref file
  standing over it, which is the pair
  `ostrya_cli::cli::prune_refs_only_parts_on_a_shadowed_ref_name` states over the
  names `odd~1` and `main^`. A ref name ending in `^` carries the same
  consequence and is recorded under "P2"; the two are one class.

One class of non-ASCII characters in a ref name parts the two implementations,
recorded in `../format-reference.md`, "Ref name validation":

- the tool accepts a nonspacing combining mark (Unicode category Mn), such as
  `U+0301`, and a non-ASCII connector punctuation character (category Pc), such
  as `U+203F`, in a component of a ref name. The port refuses them with `error:
  Invalid refspec <name>` at exit 1 and writes no ref. The port accepts a
  non-ASCII character only if `char::is_alphanumeric` is true for it, and it
  also refuses the characters of that kind that the tool refuses (spacing
  combining marks, circled and enclosed letters, and characters that the Unicode
  tables of the tool do not hold). So the port never writes a name that the
  tool might skip, and the difference is a refusal alone. The set of characters
  that the port refuses over `char::is_alphanumeric` stands in a table in
  `ostrya-core`, taken from a probe of the tool 2026.1 against the Unicode
  version of Rust 1.92.

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
`cli-behavior.md`, "The GVariant text form", "`show`", "`log`", "`ls`",
and "`config get`". `show --print-variant-type=TYPE` takes every definite
GVariant type string in both implementations: Phase 17f widened
`ostrya-gvariant`'s `Type` to `n`, `q`, `i`, `x`, `h`, `d`, `o`, `g`, and the
maybe types, which `commit --add-metadata` writes into a commit's metadata dict.
`Value` carries the matching variants -- `I16`, `U16`, `I32`, `I64`, `Double`,
and `Maybe` -- with `o` and `g` held as `Str` and `h` as `I32`; the two enums
are listed in the rustdoc of `ostrya_gvariant::Type` and `Value`.
The indefinite characters part the two. The tool takes `r`, `*` and `?` and
prints `**` for each, where the port refuses the type string with `error:
invalid format: invalid type signature "<type>" at offset <n>: unsupported type
character` at exit 1. Nine tool behaviors around these commands are observed and
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
  In that measurement, the trusted set holds one export of the key. Two
  exports of one key with different primary user ids can part the user id,
  when a `gpgkeypath` keyring holds one export and another keyring of the
  trusted set holds the other. The port reports the user id of the export
  that it loads first. In each load order measured, the tool reported the
  primary user id of the export that `gpg` made later.
  The short key id and the user id are the same in both over a signature that
  does not verify as well: both name the signing key by its trailing sixteen
  hex digits, and the tool names the certificate that holds that key on its
  `Primary key ID` line. The key the port names there is the one its own
  trusted keyring resolved for the signature. `ostree gpg-sign --delete` in
  2026.1 removes such a signature under four selectors -- the key id and the
  whole fingerprint of the signing key, and the key id and the whole
  fingerprint of the certificate -- measured over a signature a signing subkey
  made. The port holds both keys in its own record. No command of the port
  removes a signature (`sign`, "`-d/--delete`");
- a `--gpg-verify-remote=REMOTE` that is not a valid remote name parts the
  two. A build of the port with the `gpg` feature refuses it at exit 1 with
  `error: invalid input: invalid remote name: REMOTE`, after the commit
  report and before it reads a keyring. A build without the `gpg` feature
  verifies no GPG signature, and it prints the commit report at exit 0 for
  each `--gpg-verify-remote` value: a name that is not valid, a remote with
  no config section, and a `gpgkeypath` entry that does not exist. The
  tool reads `<repo>/REMOTE.trustedkeys.gpg` when the config holds a section
  of that name, so a name such as `../x` reads a keyring outside the
  repository. Both commands check the remote only for a commit that carries
  a GPG signature;
- a `gpgkeypath` entry of the `--gpg-verify-remote` remote that does not
  exist parts the wording. Both commands print the commit report and then
  exit 1. The tool writes `error: opendir(ENTRY): No such file or
  directory`. The port writes `error: signature: gpgkeypath entry 'ENTRY'
  cannot be read: No such file or directory (os error 2)`;
- a `gpgkeypath` entry that names a directory parts the two. The tool reads
  each file of the directory as a keyring, whatever its name. The port reads
  only the regular `*.gpg` files of the directory, as a pull of the port
  does. So a
  directory that holds only `a.keyring` gives `Good signature from "<user
  id>"` in the tool and `Can't check signature: public key not found` in the
  port;
- the verdict the report states rests on the port's own trust and validity
  policy, which "GPG verification differences" compares with GnuPG 2.4.9.
  Seven differences stand there, and each one can make a `show` verdict part
  from the tool's: the fixed digest policy, the GnuPG keybox refusal, the
  refusal a keyring the parser rejects draws, the 256-bit minimum digest an
  Ed25519 key carries, the keyring and signature-blob input caps, a revocation
  read over every certificate the trusted set holds for the key rather than over
  the first alone, and the key expiry read as the newest statement two exports
  of one certificate carry rather than as the statement the first export makes.

`show --gpg-verify-remote=REMOTE` reads `REMOTE.trustedkeys.gpg` in the
repository and in `/etc/ostree/remotes.d/`, the global trusted set, and each
`gpgkeypath` entry. The tool reads keyrings from the same kinds of source.
Both commands load `REMOTE.trustedkeys.gpg` of the repository before the
global trusted set. So when these two sources hold two exports of one key,
the export in the repository keyring supplies the user id in both. Both
commands also read the repository keyring before the `gpgkeypath` entries.
When a directory is at the path of the repository keyring and a `gpgkeypath`
entry does not exist, the refusal names the repository keyring in the port,
and the tool writes `error: Is a directory`. The read of
`/etc/ostree/remotes.d/` by the tool is not observed (`cli-behavior.md`,
"`show`"). `sign --verify --remote` reads no global trusted set (`sign`,
"`--remote` of `--verify`"), so a key of the global trusted set verifies a
commit in `show` and not in `sign`.

Not observed: the answer of the tool to a repeated `show
--print-metadata-key` or `--print-detached-metadata-key`. No test runs the
tool with a repeated key option. The port refuses the repeat with `error: the
argument '--print-metadata-key <KEY>' cannot be used multiple times`, or the
same line for `--print-detached-metadata-key <KEY>`, at exit 1.

A dirtree that holds one name in both its file list and its directory list
parts the two. The format lets the two lists hold one name, and the
tool reads such an object, put in a repository by hand: `ostree fsck` reports
no error, `ostree ls` prints both entries, and `ostree ls -R` aborts on an
internal assertion when it resolves the name as a directory. The port writes
no such object, and each port reader that loads the whole dirtree refuses it
with `invalid dirtree: a name appears in both the file and directory lists`
(`../format-reference.md`, "Dirtree -- `(a(say)a(sayay))`").

`config set` and `config unset` write the document through the config write path
Phase 17e landed. Both accept what the tool accepts and word every refusal the
same way, and the file each writes holds the same bytes
(`cli-behavior.md`, "`config set` and `config unset`"). One divergence
stands, at a key naming an empty group or an empty key: `config set .k v` and
`config set g. v` reach GLib's own key-file assertions in the tool, which prints
a `GLib-CRITICAL` line, writes nothing, and exits 0, where the port refuses the
name (`keyfile: group name is empty`, `keyfile: key is empty`), writes nothing,
and exits 1. Both leave the file as it stands.

`config get` unescapes a value by the rules of `../format-reference.md`,
"Config file (`<repo>/config`, GKeyFile / INI)". Not observed: the answer of
the tool to two values. The first value holds an escape that these rules do
not name. The second value ends in a lone backslash. The port refuses the
first value at exit 1 with `error: keyfile: invalid escape '\X'`, where `X` is
the character after the backslash. The port refuses the second value at exit 1
with `error: keyfile: value ends with a lone backslash`.

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
`--sign-from-file=PATH`, `--sign-type=NAME`, and the port extensions
`--tag=NAME`, `--generate-composefs`, and `--related=NAME=CHECKSUM`.
Missing:
`--selinux-policy=PATH`, `-P/--selinux-policy-from-base`,
`--selinux-labeling-epoch`.

`--tag=NAME` of the port is one `--bind-ref=NAME` of the tool, and the
creation of the local ref `NAME` at the new commit. `NAME` goes into
`ostree.ref-binding` as a `--bind-ref` name does, so the commit has the
checksum that the tool gives for `--bind-ref=NAME`. After the port publishes
the objects, it writes the `-b` ref and then each tag ref, one ref at a time.
A name that is also a `--bind-ref` name occurs two times in
`ostree.ref-binding`. The tool refuses the option with
`error: Unknown option --tag=NAME` at exit 1. The port refuses these values at
exit 1, before it takes the repository lock:

- a name with `:`;
- a name that the ref-name rule refuses, with `error: Invalid refspec <name>`;
- a name of 64 lowercase hex characters, with `error: Rev name '<name>' looks
  like a checksum`;
- the `-b` name, and a name given two times;
- a name that is a path below another name of `-b` and `--tag`, with
  `error: --tag <name> names a path below --branch <branch>`, `error: --tag
  <name> names a path below --tag <tag>`, or `error: --branch <branch> names
  a path below --tag <tag>`. A `-b` name with `:` is a ref under
  `refs/remotes`, and this check does not include it;
- a name that has an entry under `refs/heads`: a ref, an alias (also a
  dangling one), or a directory of refs. A name below a ref is refused too.
  The message is `error: --tag specified but ref <name> already exists`. The
  port reads the path again before it publishes the objects, and refuses an
  entry that came after the first read. If another writer creates a ref at
  the path after the second read, the port replaces that ref.

A refusal writes no object and no ref. Without `-b`, the option needs
`--orphan`, as each commit does. `--orphan --tag=NAME` creates `NAME` and
moves no branch. `--tag` conflicts with `--no-bindings` and with
`--skip-if-unchanged`, and `clap` refuses each pair at exit 1.

`--related=NAME=CHECKSUM` of the port names one dependency of the commit in
field 2 of the commit object (`../format-reference.md`, "Commit --
`(a{sv}aya(say)sstayay)`"). The option can occur more than once. The port
splits the value at its last `=`, so `NAME` can hold `=`. `CHECKSUM` is 64
lowercase hex characters. The commit holds the entries sorted by name in byte
order, so the order of the options does not change the commit checksum. The
tool has no option that writes field 2. `ostree show --print-related` prints
the entries that the port writes, and `ostree fsck` accepts the commit. The
port refuses these values at exit 1:

- a value with no `=`, with `error: Missing '=' in NAME=CHECKSUM argument
  '<value>'`, before it takes the repository lock;
- a `CHECKSUM` that is not 64 lowercase hex characters, with `error: Checksum
  '<checksum>' in '<value>' is not 64 lowercase hexadecimal characters`,
  before it takes the repository lock;
- an empty `NAME`, and a `NAME` given two times, before it reads the tree;
- a dependency that the repository does not hold, or holds partial, before it
  reads the tree;
- a dependency whose own field 2 is not empty, before it reads the tree.

A refusal writes no object and no ref. `--related` conflicts with
`--skip-if-unchanged`, and `clap` refuses the pair at exit 1.

`--add-detached-metadata-string=ostrya.related=VALUE` gives the detached
metadata key `ostrya.related` a string value. The key is a port extension
that holds the build sources of the commit, and its value must be an
`a(say)` (`../format-reference.md`, "Related commits"). The port refuses the
option at exit 1 with ``error: related commits in ostrya.related of commit
<checksum>: type is `s`, not `a(say)` ``, and writes no object and no ref. The
refusal comes at the end of the command, after the signatures.

The five tree-source options carry seven divergences between them, and the
walk of a filesystem source carries the divergences its own paragraph states
below. The composition rule, the source list, the two type-change refusals,
`--base`, `--consume`, `--generate-sizes` over any source list, and the two tar
options otherwise agree with the tool over every form the cells and the tests
hold, each accepted form checked by the commit checksum and each refusal by its
text (`cli-behavior.md`, "CLI output formats", `commit`, and that file's
"The tar import options").

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
compatibility"). `../decisions.md`, "The expression engine of
`--tar-pathname-filter`", states why the port takes PCRE2. The cited test for
this option is
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
compiling regular expression ‘<expression>’ at char N: <reason>`. The line
parts in two places.

The reason string is the first. GLib passes some of PCRE2's own reasons through
and rewords others. The reword set is wider than the five the cited test
compares:

- `[[:bogus:]]` reads `unknown POSIX class name` from both, character for
  character.
- `f{65536}` reads `number too big in {} quantifier` from both.
- `dir1((` reads `missing closing parenthesis` from the port and `missing
  terminating )` from the tool.
- `\q` reads `unrecognized character follows \` from the port and
  `unrecognised character following \` from the tool.
- `(*BOGUS)f` reads `(*VERB) not recognized or malformed` from the port and
  `(*VERB) not recognised` from the tool.

The offset `N` is the second. The port reports the code-unit offset PCRE2
answers, which is a byte offset for the 8-bit library. The tool reads the
offset from the PCRE2 the host links and counts it in characters, and the value
follows that PCRE2 version.
With PCRE2 10.48 the tool reports char 2 for `\q`, and the port, with its
compiled-in PCRE2 10.46, reports char 1. The cited test compares the port's
line exactly and the tool's line exactly except for the offset digits.

The port's offset is 10 for `[[:bogus:]]`, 7 for `f{65536}`, 6 for `dir1((`, 1
for `\q`, and 7 for `(*BOGUS)f`. A non-ASCII character ahead of the error
point adds the extra bytes it occupies to the port's offset. Each probe below
carries one error the list above already states, so the count rule is measured
apart from the error kind. The port's offset stands first, and the tool's
offset with PCRE2 10.48 stands second.

- `é\q` reads 3 and 3, and `éé\q` reads 5 and 4.
- The four-byte `U+1F600` ahead of `\q` reads 5 and 3.
- `é[[:bogus:]]` reads 12 and 11, `édir1((` reads 8 and 7, `éf{65536}` reads 9
  and 8, and `é(*BOGUS)f` reads 9 and 8.
- `ééédir1((` reads 12 and 9.

A match spends a step budget PCRE2 accounts. An expression that requires a
literal ends without spending it: `^(a+)+b` against a member name of 250 `a`
characters needs a `b` the name does not hold, so both answer at exit 0 and
write one commit. `(a+)+\d`, `(a+)+[0-9]`, and `(a|aa)+\d` require no literal
and reach the limit over that name. Both refuse, writing no object and no ref,
and the exit path is the difference: the port reports `error: tar:
--tar-pathname-filter: Error while matching regular expression ‘<expression>’:
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
another, and the tool carries whatever the host GLib links, which is 10.48 on
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

A missing parent that `--tar-autocreate-parents` creates for a hardlink member
takes the owner `0:0` in the port (`TarImportOptions::autocreate_parents` in
`crates/ostrya/src/tar.rs`). No observation of the tool covers a hardlink
member that creates a parent, so this case is not counted among the seven
above (`cli-behavior.md`, "The tar import options").

Not observed: the xattrs that the tool records under `--canonical-permissions`
over a `tar=` source. No observation of the tool covers an archive that
carries xattrs, so this case is not counted among the seven above. The port
keeps the xattrs that the archive carries under the option (`shape` in
`crates/ostrya/src/tar.rs`). Over a filesystem walk, both record no xattrs
under the option (`../format-reference.md`, "Canonical permissions").

The walk of a filesystem source carries divergences apart from the seven
above: the wording of each refusal of an entry, and two outcomes. The walk
reads each entry with `fstatat` and checks its type ahead of `--skip-list` in
both implementations, and it opens an entry after that check
(`cli-behavior.md`, "CLI output formats", `commit`, "The walk of a filesystem
source"). Both refuse a fifo and a unix socket at
exit 1, with no object and no ref, and a skip list that names the entry does
not prevent the refusal. Both refuse a regular file or a directory that does
not open, and an entry of a directory at mode 0644, whose `fstatat` fails. The
wording parts: the tool names the entry and the call, as in `openat(<name>):
Permission denied`, `opendir(<name>): Permission denied`, `fstatat(<name>):
Permission denied`, and `Not a regular file or symlink: <name>`, and the port
reports `i/o error: Permission denied (os error 13)` and `unsupported:
unsupported file type for entry "<name>"`. The walk root that does not open
reads `opendir(<path>): Permission denied` in both. Observed with `ostree`
2026.1 as uid 1000 in `archive`, `bare`, `bare-user`, and `bare-user-only`.
Two outcomes part:

- a symlink whose target is not valid UTF-8. The tool commits it at exit 0,
  writes GLib criticals to standard error, two in `archive` and one in `bare`,
  `bare-user`, and `bare-user-only`, and hashes the target as the literal
  string `[Invalid UTF-8]`, so the commit checksum stands for a target the
  source does not hold. In `archive` the stored object holds that string, and
  in the other three modes it holds the original target bytes. The port
  refuses the commit with `error: invalid format: symlink target is not valid
  UTF-8` at exit 1 and writes no object and no ref. This is the rule "refuse
  rather than reinterpret": the file header stores the target as a GVariant
  string, and the port does not store a value of its own in place of the
  target. No matrix cell states the case;
- a skip list that names a regular file or a directory that does not open. The
  tool does not open the entry and commits the tree without it. Without
  `--no-xattrs` the port reads the xattrs of each entry when it lists the
  directory, ahead of the skip list. That read opens the entry, so it fails, and
  the port refuses at exit 1 with no object and no ref. With `--no-xattrs` the
  port commits, and the commit checksum equals the tool's. This is a defect of
  the port, and no matrix cell states it yet.

The port lists a whole directory before it enters a subdirectory. The walk of
the tool enters a subdirectory when it reaches it (`cli-behavior.md`, "CLI
output formats", `commit`, "The walk of a filesystem source"). So over a tree
with more than one failing entry, the two can report different entries.
The port reports an entry that does not open with `error: i/o error: <reason>
(os error <n>)`, which names no path. A directory at mode 0644 opens, so a skip
list that names one gives a commit in both.

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
values are read. Both implementations refuse a `--fsync` value neither reader
holds with `error: Invalid boolean argument '<value>'` at exit 1, and both
refuse it in the same step: while the options are read, ahead of the repository,
ahead of the branch check of `-b` and `--orphan`, ahead of the tree, and ahead
of the timestamp (`cli-behavior.md`, "CLI output formats", `commit`, "Fault
order"). Inside that step the tool reads the options in command-line order,
where the port reads `--owner-uid`, then `--owner-gid`, then `--fsync`. One
refusable value alone parts the two nowhere; two on one command line report the
tool's leftmost and the port's fixed first, so `commit --fsync=on
--owner-uid=abc` reports the fsync value from the tool and the id from the port.

The second is `--disable-fsync`, which `commit --help` does not list and which
the tool accepts there as `--fsync=false`. The port implements the documented
`--fsync=POLICY` alone, that being the option this file listed as missing. The
scope was chosen with the alias observed. `ostrya commit --disable-fsync`
reports `error: unexpected argument '--disable-fsync' found` from `clap` and
exits 1, where the tool commits. The valueless spelling stays with `pull` and
`pull-local`, which document it (`cli-behavior.md`, "The fsync
vocabulary", "Spellings per command").

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
The port issues one call more over corpus `C0`, an eight-object commit, syncing
the directory holding the ref beside the ref file (`cli-behavior.md`, "The fsync
vocabulary", "Sync counts of a commit"). One commit with the branch `main`
issues 11 sync calls in the tool and 12 in the port. The extra call is the
`fsync` of `refs/heads` (`commit_fsync_policy_controls_the_syscalls` and
`commit_syncs_every_created_ref_directory` in `crates/ostrya-cli/tests/cli.rs`).

Under `[core] per-object-fsync=true`, one commit of corpus `C0` issues 15 sync
calls in the tool and 16 in the port in `archive` and in `bare-user`. In `bare`
it issues 14 in the tool and 15 in the port. The extra call is the same `fsync`
of `refs/heads` (`commit_per_object_fsync_syncs_content_objects_alone`).

The port runs `fsync` on the directory that holds a ref after it renames a ref
file or an alias link over the ref name, and after it removes a ref. A write
that creates directories for a ref name with `/` also syncs the directory that
holds each created directory, deepest first. The tool syncs no directory in a
ref write, an alias write, or a ref removal. In the port, the name that a
completed ref operation created or removed survives a crash, and so does the
content of the file. No published byte differs, and `fsync=false` turns off
these syncs in the port. `../format-reference.md`, "Ref durability", states the
rule of each side.

The nine Phase 17f options that carry the message, the metadata, and the ref
bindings agree with the tool over every form the cells and the unit tests hold.
Each accepted form was checked against the tool by commit checksum, which is what
the subject, the body, the metadata dict, and that dict's entry order all reach,
and each refusal by its text (`cli-behavior.md`, "CLI output formats",
`commit`).
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
which 1416 agree. The first two classes below come from the 776 value texts.
The last two come from the read-back of the 366 values. Both sets of
differences fall in four classes:

- A `\u` or `\U` escape that names a surrogate or a code point past
  U+10FFFF. The tool accepts it and builds a string that is not UTF-8. It
  then prints `GLib-CRITICAL **: g_variant_new_string(): requires valid
  UTF-8`, aborts with a signal, and writes no commit. `'\uD800'` and
  `'\U00110000'` both give this result. The port refuses the escape with
  `3-7:invalid 4-character unicode escape` and `3-11:invalid 8-character
  unicode escape`, at exit 1.
- The offset of the nesting refusal. For `[`, `(`, and `{`, both
  implementations name the token at level 128. For `<`, `just`, a type
  keyword, and a `@` declaration, the tool prints an offset with no relation
  to the text. The offset is `18446646599957580430` for one input and
  `18446642783772371598` for another, so the value is not reproducible. The
  port names the token as it does for the brackets. The reason text and the
  exit status are the same in both.
- A string that holds a code point that GLib does not count as printable: an
  unassigned code point, a non-character, or a control. The tool prints it as
  a `\uXXXX` or `\UXXXXXXXX` escape, and the port prints the character
  itself. A run of the tool records `'\uffff'`, `'\ud7ff'`, and
  `'\U0010ffff'`. Both store the same bytes, so the commit checksum agrees.
  The difference is in the printed text alone.
- The deepest nesting that the two carry through a commit. The codec of the
  port holds a value-depth budget of 128 levels, counted from the commit
  object. The tool counts from the metadata value. With
  `--add-metadata=k=` and an array nested to each depth, the results are:
  - Through 123, the two write the same commit and read the same text back.
  - At 124 and 125, the commits agree and the read-back differs. The tool
    prints `()` for the value. The port prints the value at 124, and reports
    `error: gvariant: container nesting exceeds the supported depth` at 125.
  - At 126 and 127, the tool writes the commit, and the port reports that
    same line at exit 1.
  - At 128 and more, both readers refuse in the same words.

A `\u` or `\U` escape naming U+0000 is
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
status are recorded in `cli-behavior.md`, "CLI output formats", `commit`;
the devino rules are in `../format-reference.md`, "Commit modifier:
canonical permissions, consume, and devino". The declared ids and the fsync
policy are read and the repository opened first. Both control files are read
next, ahead of everything else `commit` does, the statoverride file first, and
each reports a path it cannot open as `error: openat(<path>): <reason>`, a
directory as `error: Is a directory`, and a byte that is not UTF-8 or is NUL as
`error: Invalid UTF-8`.
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
the faithful result; `--no-xattrs` on the plain walk reaches a third checksum.
The two implementations agree on all four commits over that variant, so
what parts is the flagged commit from the unflagged one and not one
implementation from the other. Three of the fourteen variants are checkouts
both implementations refuse under `-H`, which the "checkout" paragraph below
states; the eleven both perform were compared, and the two implementations
agree on every one.

The fs-verity seal of a content object whose logical mode has no owner-write
bit (0444, 0555, or 0400) parts the two on `commit`, in a repository that
holds `[ex-integrity] fsverity=yes`. `FS_IOC_ENABLE_VERITY` needs write
permission on the inode, and a writer without `CAP_DAC_OVERRIDE` has that
permission only before the logical mode goes on. The tool applies the logical
mode before the seal, so an unprivileged writer gets `EACCES` and the write
fails:

```
error: Writing content object: fsverity: ioctl(FS_IOC_ENABLE_VERITY): Permission denied
```

The port seals before it applies the logical mode and the owner, and writes
the object: the bytes, the inode mode, the owner, and the xattrs that the tool
writes where its write succeeds, as root. With `fsverity=maybe` the port seals
these objects, and the tool ignores each enable failure under `maybe`.
`../format-reference.md`, "Write path: fs-verity (ex-integrity)", gives the
write order of each. The port gives no value a meaning of its own here, so the
refusal rule of "Scope of CLI compatibility" does not apply.

Two wordings the port reproduces are the tool's own and read as defects. The
first is the editor-failure line, which carries no separator between the closing
quote and the reason: `error: There was a problem with the editor
'<EDITOR>'Child process exited with code <N>`. The second is the
`--keep-metadata` missing-parent line, `error: Either --branch or --parent must
be specified when using --keep-metadata`, which is issued whenever the resolved
parent is absent, `--branch` having been given among those cases.

One `commit` divergence sits at the values `--parent` takes, the parenting
behavior itself being shared (`cli-behavior.md`, "CLI output formats",
`commit`, "The parent").
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
  checksum wherever else a revision is taken (`../format-reference.md`,
  "Abbreviated checksums"), so `--parent` is the narrower reader and not the
  narrower rule;
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
words at the same step (`../format-reference.md`, "Branch names no revision
reaches"), and what each leaves behind differs. The tool writes the tree and the
commit object before it reads the branch name, so the refusal leaves them in `objects/` -- seven loose
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
checksum, with the ref named and with every ref pulled. The port reads a named
ref of that shape as a checksum and refuses it at exit 1, and copies the ref
when every ref is pulled. Such a source arrives by an out-of-band write alone
once the guard is in place.

A third `commit` divergence sits at the branch name ending in `^`, which
resolution reads as ancestry (`../format-reference.md`, "Branch names no
revision reaches"). Both implementations refuse it, neither writes a ref, and
neither publishes an object; the words and the step part. The ref-name rule
refuses the name, so the port refuses at the ref write, after the tree is
read, with `Invalid refspec <name>`, one message for every base. A tree error
such as a path that does not open can come first. The tool
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
"P1" records for a name outside the ref-name rule, and the two read as one class:
an out-of-band write is the only arrival for either name.
`ostrya_cli::cli::prune_refs_only_parts_on_a_shadowed_ref_name` states the pair
over both names. A `^` inside the name is refused by both implementations, with
`Invalid refspec a^b`.

Four `commit` divergences sit at the three options that derive a metadata key
from the committed tree, `--generate-sizes`, `--bootable`, and
`--generate-composefs-metadata` (`cli-behavior.md`, "CLI output formats",
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
  zlib, and the no-C rule keeps the port on `miniz_oxide` (`../decisions.md`,
  "Foundation crates").
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
verifies through the other's `show --gpg-verify-remote`. Fifteen divergences
stand.

- The engine of each key. This difference is in the bytes of the repository.
  The tool applies the last `--sign-type` to each `--sign` and
  `--sign-from-file` key. The port gives each key the engine of the nearest
  `--sign-type` before it on the command line, and gives `ed25519` to a key
  before the first `--sign-type`. For `--sign-type=spki --sign=A
  --sign-type=ed25519 --sign=B`, the tool signs A and B with ed25519, and the
  port signs A with spki and B with ed25519. For `--sign=K --sign-type=spki`,
  the tool signs K with spki, and the port refuses the run (the next item).
  The order of the signatures is the same in both: the `--sign` keys, then the
  `--sign-from-file` keys, then the `--gpg-sign` keys.
- A `--sign-type` with no key of its own. The port refuses a `--sign-type`
  that has no key after it and before the next `--sign-type`, at exit 1, with
  `error: --sign-type=NAME has no key of its own; give a key after it and
  before the next --sign-type`. It writes no object and moves no ref.
  Examples are `--sign-type=spki` with no key, `--sign=K --sign-type=spki`,
  and `--sign-type=spki --sign-type=ed25519 --sign=A`. `--gpg-sign` is not a
  key of a `--sign-type`, so the port also refuses `--sign-type=gpg
  --gpg-sign=K` with no other key, where the tool signs with K. The tool
  reads `--sign-type` only where a key needs an engine, so a `--sign-type`
  with no key commits (`commit/sign-type-unread-without-a-key`). The port
  reads each name in command-line order before this check. So it refuses a
  name that no engine carries also with no key, and also before a name of an
  engine. The tool reads the last name alone, so `--sign-type=nosuch
  --sign-type=ed25519 --sign=K` commits in the tool and is refused by the port
  (`commit/sign-type-last-occurrence-decides`).
- The step that reads the `--sign-type` values. The port reads each
  `--sign-type` value as the first step of the command, after the repository
  resolves. This step comes before the control files, the branch check, the
  editor, the tree, and the repository lock. The refusal of a name that no
  engine carries and the refusal of a `--sign-type` with no key of its own
  come at this step. The tool reads the name in its signing step, after it
  writes the tree (`cli-behavior.md`, "CLI output formats", `commit`, "Fault
  order"). So, for a refused name beside an earlier fault, the port gives the
  refusal of the name. An example of an earlier fault is a tree path that does
  not open. A run with a `--sign-type` value that the port refuses at this
  step, and with a `--skip-if-unchanged` that matches, exits 0 in the tool.
  The port refuses that run at exit 1. In a run with a refused name and a key,
  the tool runs the editor of `-e`, and `--consume` empties each filesystem
  source. The tool then refuses the name in its signing step. The port refuses
  that run before these steps, so it runs no editor and deletes no source
  file. The port reads and decodes the keys in the signing step, as the tool
  does. A refusal at the first step writes no object and moves no ref
  (`ostrya_cli::cli::commit_checks_the_sign_type_before_the_tree`).

- `--sign-type=gpg` names an engine the port carries and the tool build does
  not. The tool's build reports `error: Requested signature type is not
  implemented` for `gpg`, where the port signs under `gpg` when it is built
  with the `gpg` feature. Under `spki` both sign: the `ostree` 2026.1 build
  with OpenSSL on the NixOS development host, and the port when it is built
  with the `spki` feature. A tool build without the features `openssl` and
  `sign-spki` refuses `spki` with the same `not implemented` line. Every other
  name parts in neither implementation -- `dummy` reports `error: dummy
  signature type is only for ostree testing`, and a name no engine carries,
  the empty string, `ED25519`, and a whitespace-padded name each report
  `error: Requested signature type is not implemented`. Because the tool
  carries no `gpg` engine here, `--gpg-sign` and `--sign --sign-type=gpg`
  cannot be compared tool-side at all, and no cell states that comparison.
  Under `--sign-type=gpg` the port obeys these rules:
  - The port resolves each `--sign` and `--sign-from-file` key as it resolves
    a `--gpg-sign` selector, before the first signature, and gives the same
    refusals.
  - The port signs with the fingerprint that the lookup gives.
  - `--gpg-homedir` also names the home directory of `--sign` and
    `--sign-from-file`.
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
  timestamp the reader refuses, and for a branch name the refspec grammar
  refuses. A branch name of 64 lowercase hex characters parts the two: the tool
  writes the tree and the commit object before it reads the name, so its
  refusal leaves them in `objects/`, and the port publishes none
  (`ostrya_cli::cli::commit_checksum_branch_name_matches_the_tool`). For a
  branch name that ends in `^` over a repository with no commit, neither writes
  an object (`ostrya_cli::cli::commit_ancestry_branch_name_matches_the_tool`).
  The tool side of the other refspec refusals, such as `a^b`, needs
  observation. No matrix cell states the comparison: `tmp/` carries no
  published state and the oracles read `objects/` and the refs tree.
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
- The blocks of an spki `--sign-from-file` file. This difference is in the
  bytes of the repository. Observed with the `ostree` 2026.1 build with OpenSSL
  on the NixOS development host (`cli-behavior.md`, "CLI output formats",
  `static-delta`, "spki secret key files"). Both read PEM `PRIVATE KEY` blocks
  and ignore the text outside them. The tool signs with the first block alone,
  so a file of three blocks gives one signature, and a second block of another
  label or a second block that does not decode does not stop the commit. The
  port signs with a file of one block. It refuses a file of more than one
  block at exit 1 with `error: signature: the key file '<path>' holds more
  than one PEM PRIVATE KEY block`, and moves no ref. It refuses the whole file
  at exit 1, and moves no ref, for a block of another label, a block that does
  not decode, a block that holds no valid PKCS#8 key, and a block with no END
  line, at any position. The message is `error: signature: the key file
  '<path>', line <n>: <reason>`, where the tool reports `error: Unexpected
  label "<label>"` for a first block of another label. The body rules of a public key file apply, so
  the port refuses a body with a blank line, which the tool reads. The body
  rules are those of a `PUBLIC KEY` block under `static-delta`.
- An spki `--sign-from-file` file that holds no `PRIVATE KEY` block: an empty
  file, a file of white space only, and a file of one base64 PKCS#8 line. The
  tool ends on SIGABRT, exit 134. The port reports `error: signature: the key
  file '<path>' holds no PEM PRIVATE KEY block` at exit 1. Both move no ref.
  The port reads the spki file as a key source of the library: a regular file
  of at most 1 MiB. It refuses a directory, a fifo, and a larger file with
  `error: signature: the key file '<path>' is not a regular file` or `is over
  the 1048576-byte ceiling`, and does not wait on a fifo. A missing file gives
  `error: Error opening file <path>: No such file or directory`. The
  65536-byte first-line rule and the NUL rule apply to `ed25519` and `gpg`
  alone.
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
- An inline `spki` secret key of `--sign` parts in its decode and in the
  wording of its refusal. Observed with the `ostree` 2026.1 build with
  OpenSSL on the NixOS development host (`cli-behavior.md`, "CLI output
  formats", `static-delta`, "spki inline keys"). The tool skips each
  character outside the base64 alphabet, and it signs with a value that
  holds `!`, or text after the padding. The port removes each space,
  horizontal tab, LF, form feed, and CR, and decodes the rest by the rule of
  `format-reference.md`, "Signing details", "spki". It refuses a value with
  another character outside the alphabet at exit 1 with an `error: invalid
  base64:` line, and moves no ref. The port signs with a key whose base64
  ends in `==` and has no `=` or one `=` at the end, where the tool refuses
  that key at exit 1. Both sign with three or four `=` at the end of that
  key, and with a last character whose unused low bits are not zero. Both
  sign with a PKCS#8 key or a SEC1 key whose base64 holds LF or CRLF line
  breaks, with the base64 of a PKCS#1 key of an RSA key, with the base64
  of a SEC1 key of a P-384 key (`cli-behavior.md`, "spki P-384 keys"), and
  with the base64 of a PKCS#8 key of an Ed25519 key of version 1 or of
  version 2 (`cli-behavior.md`, "spki Ed25519 keys"). Both
  sign with a SEC1 key or a PKCS#8 key of P-256 or of P-384 whose
  `privateKey` is shorter than the field size of the curve and that holds no
  public point, and read the scalar with zero bytes on the left. Both refuse
  a raw 32-byte scalar, a SEC1 key with no `parameters` field, the SEC1 key
  of a P-256 key that holds its public point and whose `parameters` field
  names secp384r1 or secp521r1, and the base64 of the full PEM text at exit
  1, and move no ref.
  The tool reports `error: Not able to sign the cobject: openssl: Failed to
  initialize spki key`. The port reports `error: signature: spki secret key:
  expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER`, also for the P-256 key that
  names secp384r1. For a SEC1 key with no `parameters` field it reports
  `error: signature: spki secret key: the SEC1 key does not name its curve`,
  and for a SEC1 key of a curve outside its set, such as secp521r1, `error:
  signature: spki secret key: the curve P-521 is not supported`.
- An spki secret key with explicit curve parameters, of `--sign` or of
  `--sign-from-file`, in a PKCS#8 key, in the `ECPrivateKey` of a PKCS#8 key,
  or in a SEC1 key. The tool signs with such a key ("P2", `sign`). The port
  refuses it at exit 1 with `error: signature: spki secret key: the EC key
  has explicit curve parameters`, or the same reason after `error:
  signature: the key file '<path>', line <n>: `, and moves no ref. A key of a
  type or on a curve outside the set of the port, an RSA key that the port
  refuses, and a PKCS#8 key that the port refuses for its version or for its
  Ed25519 public key, are refused the same way, as `sign` records.

The branch-name term of the signing step's fault order is observable only over
a name the ref-name rule refuses. `-b 'bad//name' --sign=zzz` reports
`error: Invalid refspec bad//name` in both, and so do `-b 'bad name'
--sign=zzz` and `-b 'a^b' --sign=zzz`.

`[core] auto-update-summary` and its deprecated alias `commit-update-summary`
part the two on `commit`. The tool reads the two keys together. Over the nine
combinations of each key absent, `true`, and `false`, `ostree commit -b x` into
an archive repository writes `summary` exactly when one of the two keys is
`true`. So `auto-update-summary=false` with `commit-update-summary=true` writes
it, and so does the reverse. A value that is not a boolean in either key, `yes`
for example, makes the commit exit 1 with `error: Key file contains key
“auto-update-summary” which has a value that cannot be interpreted.`, also when
the other key is `true`. The ref is written and the summary is not.
`ostrya commit` and `ostrya pull` read neither key and write no `summary`, so
the port leaves `summary` as it stands and exits 0 over each of these values.
`ostrya receive` and `ostrya serve` read the two keys by the rule of the
tool. They refuse a value that is not a boolean in either one
(`ostrya-config(1)`).

Not observed: the answer of the tool to a repeated `-s/--subject`. No test
runs the tool with a repeated `-s`. The port refuses a repeated `-s` with
`error: the argument '--subject <SUBJECT>' cannot be used multiple times` at
exit 1, and it takes the last value of a repeated `-m/--body`.
`cli-behavior.md`, "CLI output formats", `commit`, "The subject and the
body", records that the tool takes the last value of a repeated `-m`.

`checkout` accepts `--repo`, `-H/--require-hardlinks`, `-C/--force-copy`,
`--composefs`, `--composefs-noverity`, and, since Phase 17c, `-U/--user-mode`
and `--subpath=PATH`, and, since Phase 17f, `--union`, `--union-add`,
`--union-identical`, `--allow-noent`, `--whiteouts`,
`--process-passthrough-whiteouts`, `--from-stdin`, `--from-file=FILE`,
`--skip-list=FILE`, `-M/--bareuseronly-dirs`, `--disable-cache`, and
`--fsync=POLICY`. Missing: `--selinux-policy=PATH`, `--selinux-prefix=PREFIX`.

The destination trees `-U` and `--subpath` produce agree with the tool's file for
file, in `archive`, `bare-user`, and `bare` (`cli-behavior.md`,
"Checkout", "Checkout modes", and `cli-behavior.md`, "Checkout", "Subpath").
The two composefs switches are independent, and the no-verity one
decides whatever the command-line order: `--composefs`, `--composefs-noverity`,
and the two orders of the pair each write the tool's image bytes over a
`bare-user` repository
(`ostrya_cli::cli::checkout_composefs_switches_match_the_tool`).

A composefs image holds a child name of at most 255 bytes. A tar archive
commits a longer name, which a filesystem cannot hold. At 255 bytes both
composefs switches write the tool's image bytes, and `commit
--generate-composefs-metadata` writes the tool's commit. At 256 bytes each of
the three forms exits 1 in both and writes no image, no commit, and no ref
(`ostrya_cli::cli::checkout_composefs_child_name_bound_matches_the_tool`). The
words part, which the standing wording rule covers: the tool reports `error:
Checking out composefs: Processing <checksum>: File name too long`, and the port
reports `error: unsupported: a child name of 256 bytes is longer than the 255
bytes that a composefs image holds`.

A composefs image holds a symlink target inside the block of its inode, so a
target with no extended attributes holds at most 4063 bytes
(`../format-reference.md`, "Inodes"). At 4063 bytes `checkout --composefs`
writes the image in both. At 4064 and at 4095 bytes the tool ends on
`lcfs_write_erofs_to: Assertion 'ctx_erofs->current_end ==
ctx->bytes_written' failed` and writes nothing. The port refuses the same
trees with `Error::Unsupported` and writes nothing: `error: unsupported: a
symlink target of 4064 bytes does not fit its inode's block, which holds 4063
bytes of target, and a composefs image states a target inline` at exit 1
(`ostrya::composefs::holds_a_symlink_target_to_its_inode_block`, which runs the
port alone). The way the tool ends is the whole of the difference, which the
standing exit-path rule covers.

An inode whose extended attributes spend more than 32755 bytes, counting the
full name, the value, and 7 bytes for each attribute, has no composefs image
(`../format-reference.md`, "Inode extended attributes and the name filter").
The tool writes no image, records no digest, and exits non-zero. The port
refuses the tree with `Error::Unsupported`: `error: unsupported: xattr <name>
takes the inode to <n> bytes of extended attributes, above the 32755 bytes a
composefs image holds` at exit 1
(`ostrya::composefs::holds_an_inode_to_the_composefs_xattr_budget`,
`ostrya::composefs::the_composefs_xattr_budget_covers_the_inode`, and
`ostrya::composefs::the_composefs_xattr_budget_covers_a_regular_file`, which
run the port alone). At the budget both write the same image. The words are
the whole of the difference, which the standing wording rule covers. The port
also refuses an attribute name above 255 bytes, prefix included: `error:
unsupported: xattr <name> is <n> bytes long, above the 255 bytes a composefs
image states a name in`
(`ostrya::composefs::holds_an_xattr_name_to_the_erofs_length_field`). The tool
side needs observation: no test runs the tool with such a name.

The three union modes and `--allow-noent` agree with the tool over a
destination the test pre-populates, in `archive`, `bare-user`, and `bare`
(`ostrya_cli::cli::checkout_union_modes_match_the_tool`). Two union options on
one command line are refused as a pair, and `--union-identical` is refused
without `-H`, both after the repository opens and the revision resolves, which
is the tool's own order; the port reproduces the tool's four wordings there --
`Cannot specify both --union and --union-add`, `Cannot specify both --union and
--union-identical`, `Cannot specify both --union-add and --union-identical`,
and `--union-identical requires --require-hardlinks`. What `--union-identical`
calls identical is stated in `cli-behavior.md`, "Checkout", "Overwrite
policy", and held against the tool case by case in
`ostrya_cli::cli::checkout_union_identical_identity_matches_the_tool`.

`-H/--require-hardlinks` refuses rather than falling back to a copy, and the
refusal is raised at the entry the checkout would have to copy. The two
implementations agree on the whole table: a directory never refuses, a
zero-length regular file never refuses, a regular file of non-zero length
refuses wherever the repository mode and the checkout mode in force give a copy
-- `archive` under either mode, `bare` under `-U`, and `bare-user` without `-U`
-- and a symlink refuses in `archive` under either mode and in `bare` under
`-U`. A commit holding none of the
refusing shapes is written whole at exit 0 in every mode, an empty commit and a
directory-only commit among them. The refusal stands ahead of the destination
disposition, so an entry `--union-add` would keep and an entry
`--union-identical` would call identical are refused all the same; it stands
behind the whiteout verdict, so a marker that removes a name and a marker that
writes a character device are both taken. A destination directory on another
filesystem than the repository is refused before any entry of it is written,
whatever the subtree holds; the destination root reaches the refusal and so does
every directory below it, fresh or reused. The tables are stated in
`cli-behavior.md`, "Checkout", "Required hardlinks" and "Cross-device
destinations", and held against the tool in
`ostrya_cli::cli::checkout_require_hardlinks_refusals_match_the_tool`,
`ostrya_cli::cli::checkout_require_hardlinks_refuses_at_the_entry`,
`ostrya_cli::cli::checkout_require_hardlinks_and_skip_list_and_subpath_match_the_tool`,
and `ostrya_cli::cli::checkout_require_hardlinks_refuses_across_devices`. Where
both take `-H`, the two hardlink the same objects and leave the same entries on
inodes of their own, the zero-length file among the second set
(`ostrya_cli::cli::checkout_require_hardlinks_hardlinks_the_same_objects`);
`ostrya_cli::cli::commit_checkout_speedup_matches_the_tool` checks a `bare`
repository out with `-H` on both sides and reads 14 devino-cache hits out of
each side's own `--table-output` block, against 13 for a `bare-user` repository
checked out with `-U` and 0 for the two forms that hardlink nothing. A
destination directory below the root is reached by a destination symlink into a
second filesystem, which a union mode follows, and the two implementations agree
there on the exit status and on the destination. A `--subpath` naming a file or
a symlink reaches no directory walk and takes no such check: the two agree that
a zero-length regular file is written at exit 0 and that a shape the mode pair
hardlinks is refused at the link.

Not observed: the `-H` table of the tool in `bare-split-xattrs`.
`bare-user-shared` is a mode of the port alone (`../format-reference.md`,
"bare-user-shared mode"). The port copies a regular file in `bare-user-shared`
and `bare-split-xattrs` under both checkout modes. So under `-H` the port
refuses a regular file of non-zero length in these two modes. `bare-user-shared`
stores a symlink the way `bare-user` does, and `bare-split-xattrs` stores a real
symlink the way `bare-user-only` does. So the port refuses a symlink in neither
of the two modes.

`-M/--bareuseronly-dirs` reduces every directory the checkout creates to
`mode & 0775`, at the destination root and at every depth below it. A directory
the checkout reuses under a union mode keeps its own mode, a regular file and a
symlink are unaffected, and the process umask reduces nothing further. The
switch is accepted in every repository mode and under both checkout modes, and
it is a no-op in `bare-user-only`, whose directory modes are already below the
mask at commit time. The two implementations produce the same destination tree
in every combination
(`ostrya_cli::cli::checkout_bareuseronly_dirs_matches_the_tool`), and the mask
is stated in `cli-behavior.md`, "Checkout", "Directory mode mask".

`--disable-cache` changes no byte and no metadata of the destination. The tool
keeps an uncompressed-object cache at `<repo>/uncompressed-objects-cache/` and
writes it for an `archive` repository checked out with `-U` and for no other
combination, hardlinking that destination's regular files out of it; the switch
stops it writing one and stops it reading one, so each destination file gets its
own inode. The port keeps no such cache, so its destination already carries the
inode identity the switch asks for and the switch decides nothing. The
destinations compare equal with the switch and without it, on both sides
(`ostrya_cli::cli::checkout_disable_cache_matches_the_tool`).

`--whiteouts` reads two marker names and `--process-passthrough-whiteouts`
reads a third. Each switch reads its own names and no others, and the marker
rules, the type gate per marker, and the destination disposition per union mode
are stated in `cli-behavior.md`, "Checkout", "Whiteouts". The two switches
agree with the tool over every repository mode, every union mode, and a
destination the test pre-populates
(`ostrya_cli::cli::checkout_whiteouts_match_the_tool`,
`ostrya_cli::cli::checkout_passthrough_whiteouts_match_the_tool`,
`ostrya_cli::cli::checkout_passthrough_whiteout_dispositions_match_the_tool`,
`ostrya_cli::cli::checkout_whiteout_markers_act_on_regular_files_only`,
`ostrya_cli::cli::checkout_whiteouts_off_materialize_the_markers`). Three
refusals agree at the exit status and part at the words, which the wording rule
covers: a marker named exactly `.wh.` or exactly `.ostree-wh.` under its own
switch (`ostrya_cli::cli::checkout_whiteout_empty_names_are_refused`), and a
passthrough marker whose target the destination holds as a directory under
`--union`
(`ostrya_cli::cli::checkout_passthrough_whiteout_dispositions_match_the_tool`).
`--whiteouts` also widens the union-files disposition over a type conflict, for
every entry and not only for a marker, and the two agree over the destination
root, a nested path, and a destination entry of every type, under both switches
and every union mode
(`ostrya_cli::cli::checkout_whiteouts_widen_a_union_type_conflict`). The rule is
stated in `cli-behavior.md`, "Checkout", "Whiteouts". Either switch alongside
`--composefs` or `--composefs-noverity` is refused at exit 1 with no image
written, under the tool's own words, `Specified options are incompatible with
--composefs`.

The three path-selection options split into two families. `--skip-list=FILE`
names tree paths to prune. `--from-stdin` and `--from-file=FILE` read a batch of
checkouts: the input is a stream of NUL-separated records read as
`(REFSPEC, SUBPATH)` pairs, and each pair checks its own revision out into one
destination, which the invocation's first positional names.
`cli-behavior.md`, "Checkout", "Path selection", states the match rule of the
list. `cli-behavior.md`, "Checkout", "Batch checkouts", states the record format
of the stream.

The list's path forms agree with the tool over `archive`, `bare-user`, and
`bare`: a file and a symlink match under their own path, a directory matches
under its trailing-slash spelling alone, the root is `/` and prunes everything,
and no other spelling matches -- a missing leading slash, a doubled slash, a
leading `.`, a surrounding space, and a trailing slash on a file each name
nothing (`ostrya_cli::cli::checkout_skip_list_matches_the_tool`). A trailing
`\r` names nothing either, under the line syntax, which agrees too: blank lines
are ignored, a final line needs no newline, a duplicate changes nothing, a path
that matches nothing is not reported, and there is no comment syntax
(`ostrya_cli::cli::checkout_skip_list_line_syntax_matches_the_tool`). A pruned
root reads nothing of the destination path, so a destination under a directory
that does not exist is accepted at exit 0 in both and that directory is not
created (`ostrya_cli::cli::checkout_skip_list_root_needs_no_destination_parent`).
The list is rooted at the `--subpath` root where one is given, and no spelling
reaches the single object a file subpath names
(`ostrya_cli::cli::checkout_skip_list_under_a_subpath_matches_the_tool`). It
decides a whiteout marker on the marker's own tree path and ahead of the
whiteout decision, and it does not decide the opaque clear
(`ostrya_cli::cli::checkout_skip_list_precedes_the_whiteout_decision`). Four
refusals -- a file that is absent, one that is a directory, one that cannot be
read, and one holding a NUL byte or a byte sequence that is not UTF-8 -- agree
at the exit status and at the words, the port reproducing the tool's
`openat(<path as spelled>): <reason>`, `Is a directory`, and `Invalid UTF-8`
(`ostrya_cli::cli::checkout_skip_list_refusals_match_the_tool`). A composefs
switch alongside `--skip-list` is refused in both under the tool's own words,
`Specified options are incompatible with --composefs`
(`ostrya_cli::cli::checkout_batch_ignores_subpath_and_takes_composefs`).

An agreement worth stating: `checkout --skip-list` matches a directory under its
trailing-slash spelling alone, where `commit --skip-list` matches it under the
spelling with no trailing slash alone. Each command follows its own rule in both
implementations.

The batch record format agrees as well: the records are NUL-separated, a final
record with no terminator counts, an empty record in the refspec position ends
the stream, a trailing refspec with no record after it names the whole tree, one
trailing `\n` and then one trailing `\r` are dropped from a refspec record and
nothing is dropped from a subpath record, and a subpath record that is not UTF-8
reaches the lookup as the bytes it holds
(`ostrya_cli::cli::checkout_batch_pairs_match_the_tool`). Every pair writes into
the destination the first positional names, under the invocation's own overwrite
mode, so pairs layer under `--union` and a second pair is a collision without one
(`ostrya_cli::cli::checkout_batch_destination_matches_the_tool`). `--from-stdin`
wins over `--from-file` whatever the command-line order, a repeated `--from-file`
takes the last value, and standard input is left unread where neither switch is
given (`ostrya_cli::cli::checkout_batch_sources_and_precedence_match_the_tool`).
A refspec record that does not resolve ends the run at exit 1 with nothing
written, under the tool's own `Refspec '<value>' not found`; `--allow-noent` acts
per pair and the stream continues, and without it the run stops at the first
failing pair with the earlier pairs' output left in place
(`ostrya_cli::cli::checkout_batch_refusals_match_the_tool`). `--subpath` is
dropped under a batch option, the pair's second record carrying the subpath
instead, and both composefs switches are taken with a batch option, each pair
writing the image of its own revision
(`ostrya_cli::cli::checkout_batch_ignores_subpath_and_takes_composefs`).

A stream that carries no pair reaches none of the refusals the command line
carries into one checkout. The union-option pair, the composefs
incompatibility, the `--union-identical` requirement, and a destination value of
no bytes all stand inside the scope of one checkout in the tool, which the
`Processing tree <checksum>: ` prefix on each of them shows, so an empty stream
exits 0 in both whatever the rest of the line holds and a populated stream is
refused at exit 1 in both, with no destination created either way
(`ostrya_cli::cli::checkout_batch_refusals_stand_inside_the_pair_scope`). The
tool resolves the first pair's refspec ahead of those refusals and the port
makes them ahead of the resolution, so a line holding both a refusal and an
unresolvable first refspec draws one message in the tool and the other in the
port. Both exit 1 with no destination, which the standing wording rule covers.

A pair's subpath record is a `--subpath` value, so the two `--subpath` value
divergences below reach it unchanged. An explicitly empty subpath record is one
of them: the tool looks the empty value up and exits 1 (`No such file or
directory: /`), and the port reads a value carrying no name component as the
whole tree and exits 0.

Two divergences stand at the values `--subpath` takes, one at the wording of
the `-H` refusals, two at the composefs switches, two at `--allow-noent`, one
at a repeated boolean flag, four at the path-selection options, and three at
the durability policy:

- a subpath naming nothing ends the checkout at exit 1 in both, leaving no
  destination, and the words part: the tool reports `error: No such file or
  directory: <path>`, naming the path with a leading slash it adds, and a path
  running through a regular file reports `error: Not a directory`. The port
  reports its own `error: checkout: subpath not found: <path>` where the value
  names nothing and `error: checkout: subpath is not a directory: <path>` where
  it runs through an entry that is not a directory, which is the split
  `--allow-noent` acts on;
- `--subpath=.` and a trailing-slash form such as `--subpath=/sub/` are refused
  by the tool, which reads the whole value as a name to look up (`No such file or
  directory: /.`). A leading `.` component (`/./d`), a doubled slash (`//d` and
  `/d//g`), and an embedded `.` component (`/d/./g`) are refused the same way,
  each naming in the message the prefix the tool looked up. The port reads a
  path, so `.` names the tree root, the trailing slash names the same directory
  as the form without it, and a `.` component and a doubled slash resolve to the
  node behind them. A `..` component parts from the `.` forms: the port refuses
  a value that carries one after a name, `--subpath=/dir/..` and
  `--subpath=/dir/../f` among them, at exit 1 with `subpath not found`, which is
  the tool's answer. A value carrying no name
  component at all, `--subpath=..` among them, names the whole tree in the port
  and exits 1 in the tool. Both accept a leading-slash and a relative spelling
  of a name that exists, and `/` names the whole tree in both. Under `--allow-noent`
  every one of these spellings reaches exit 0 on both sides, the tool having
  written nothing and the port having written the tree the value names. An empty
  `--subpath=` is refused by the port at exit 1 whatever else the command line
  carries, since `clap` requires a value for the option (`error: a value is
  required for '--subpath <PATH>' but none was supplied`); the tool refuses it
  at exit 1 on its own (`No such file or directory: /`) and exits 0 under
  `--allow-noent`;
- the wording of each `-H` refusal. The tool writes `error: Bare repository
  mode cannot hardlink in user checkout mode` for `archive` under either
  checkout mode and for `bare` under `-U`, `error: User repository mode
  requires user checkout mode to hardlink` for `bare-user` without `-U`, and
  `error: Unable to do hardlink checkout across devices (src=<dev>
  destination=<dev>)` for a destination on another filesystem. The first text
  fires for `archive` under a faithful checkout, where it names neither `bare`
  nor a user checkout, so the port writes its own words naming the entry and
  the reason instead. Both exit 1, and both leave the same destination state:
  the destination directory created and empty for the cross-device refusal and
  for a tree whose first entry refuses, and the entries already written for one
  that refuses part-way through
  (`ostrya_cli::cli::checkout_require_hardlinks_leaves_the_same_destination_on_a_refusal`);
- the tool writes the image through an anonymous temporary file (`O_TMPFILE`)
  that it opens relative to the working directory and links to the
  destination, so a destination on another
  filesystem ends the export at exit 1 with `error: linkat: Invalid
  cross-device link`. The port writes its temporary file in the destination's
  own directory and renames it over the destination, so the rename stays inside
  one filesystem and every destination is taken. The two agree on what the
  temporary file buys: an export that finishes replaces the destination rather
  than writes into it, and the image lands at mode 0644 whatever the process
  umask and whatever mode the destination held
  (`ostrya_cli::cli::checkout_composefs_switches_match_the_tool`), and an
  export that does not finish leaves a destination that already existed as it
  was, byte for byte and at its own mode
  (`ostrya_cli::cli::checkout_composefs_failure_leaves_no_destination`);
- the tool takes `--composefs` alongside `--union` and `--allow-noent` and
  refuses it alongside `--union-add` or `--union-identical` at exit 1
  (`error: Specified options are incompatible with --composefs`), writing no
  image. The port takes a single union option alongside `--composefs` and
  writes the image, since a composefs export reads the commit tree and takes no
  destination entry for any of them to decide. Two union options on one line
  are refused by the port ahead of the export, so the pair the port calls
  mutually exclusive is refused whatever else the line carries. The tool
  refuses `-H`, `-C`, `-M`, and `--disable-cache` there under the same words,
  and the port refuses all four with it: each decides how a checkout
  materializes an entry, which an export performs none of, so the refusal
  reinterprets no value
  (`ostrya_cli::cli::checkout_materialization_switches_refuse_composefs_in_both`);
- `--allow-noent` reaches every command line in the port and only some in the
  tool. The tool honors it when the line holds none of `-H`, `-C`, `-M`,
  `--union-add`, `--disable-cache`, `--whiteouts`,
  `--process-passthrough-whiteouts`, and `--skip-list`, and ignores it when the
  line holds any of them, refusing an absent `--subpath` at exit 1 as though
  the switch were absent; `-U`, `--union`, `--fsync`, `-v`, `--from-file`, and
  `--from-stdin` keep it. `--union-identical` needs `-H`, so the switch never
  reaches it in the tool. Neither side writes anything or creates the
  destination in either case, so the exit status is the whole of the
  difference. The port honors the switch uniformly, the split carrying no
  semantic rule the port could adopt without reinterpreting it
  (`ostrya_cli::cli::checkout_allow_noent_reach_diverges_from_the_tool`,
  `ostrya_cli::cli::checkout_skip_list_drops_allow_noent_in_the_tool`);
- the switch reaches a second refusal in the tool that it does not reach in the
  port: a `--subpath` naming a regular file whose loose content object has been
  deleted out of band. The tool exits 0 and creates no destination, where
  without the switch it exits 1 (`Opening content object <checksum>: Couldn't
  find file object '<checksum>'`); the port exits 1 either way (`error: object
  not found: File <checksum>`) and leaves behind the destination directory it
  created, empty. The same commit checked out whole keeps the refusal on both
  sides. Only an out-of-band deletion reaches this pair, so it is recorded and
  no gate is added: a repository the port writes and prunes holds every object
  its commits name;
- a union option, `--allow-noent`, `--whiteouts`,
  `--process-passthrough-whiteouts`, `--from-stdin`, `-H`, `-M`, or
  `--disable-cache` given twice is taken by the tool and refused by the port,
  as the port refuses every repeated boolean flag
  (`ostrya_cli::cli::checkout_union_options_are_mutually_exclusive`).
  `--from-file` and `--skip-list` take the last value in both;
- the `Processing tree <checksum>: ` prefix. The tool puts it in front of every
  refusal a batch pair reaches, `<checksum>` being the pair's resolved commit.
  The port reports its own message with no prefix. Both exit 1 and both leave
  the same destination state, so the wording is the whole of the difference,
  which the standing wording rule covers. The refspec refusal carries no prefix
  in either, the commit not having resolved yet;
- the path a `--from-file` open failure names. The tool writes `Error opening
  file <path>: <reason>`, where `<path>` is the value made absolute against the
  working directory and lexically normalized. The port writes `openat(<value as
  spelled>): <reason>`, which is the wording it already gives a `--skip-list`
  open failure. Both exit 1 and neither creates the destination
  (`ostrya_cli::cli::checkout_batch_refusals_match_the_tool`);
- the bound. The port reads at most 128 mebibytes of the batch stream, the
  batch file, and the skip-list file, and refuses a larger one with `Control
  file larger than 134217728 bytes`; the tool reads the whole of each. This is
  the cap `-F/--body-file` and the two `commit` control files already take;
- a third and later positional. The tool ignores every positional past the
  first two, with a batch option and without one, so `checkout REV DEST extra`
  writes `DEST` and nothing else. The port refuses a third with clap's own
  `error: unexpected argument '<value>' found` at exit 1. The difference stands
  on the plain path as well and becomes visible under a batch option, where the
  second positional is itself ignored;
- `--disable-fsync`. Both refuse it at exit 1 and neither creates the
  destination, and the words part: the tool writes `error: Unknown option
  --disable-fsync`, and the port writes clap's `error: unexpected argument
  '--disable-fsync' found`. The standing wording rule covers it, and the
  valueless spelling stays with `pull` and `pull-local`, which document it
  (`ostrya_cli::cli::checkout_fsync_policy_matches_the_tool`);
- `--fsync` given twice. The tool takes the line and reads the last
  occurrence, so `--fsync=false --fsync=true` syncs and
  `--fsync=true --fsync=false` does not; the two orders reach one exit status,
  so the syscall count is what states the rule
  (`ostrya_cli::cli::checkout_fsync_policy_controls_the_syscalls`). The port
  refuses the repeat with `error: the argument '--fsync <POLICY>' cannot be
  used multiple times` at exit 1 and creates no destination, whichever values
  the two occurrences carry. The port takes `commit --fsync` once as well, so
  the two commands hold one rule. The tool validates each occurrence, so a
  value it does not hold exits 1 from either position
  (`ostrya_cli::cli::checkout_fsync_policy_matches_the_tool`);
- a `[core] fsync` value the reader refuses, under `--composefs`. The port
  reads the key where the checkout path uses it, which is after the composefs
  export decision, so a composefs export never reaches the read: the port
  writes the image and exits 0 where the tool refuses the repository at exit 1,
  naming the key on standard error and writing nothing. The quotation marks the
  tool sets around the key name follow the locale, so the line is held to the
  key name and the exit status. Every other `checkout` line reaches the read
  and refuses such a repository in both
  (`ostrya_cli::cli::checkout_refuses_a_bad_configured_fsync_under_every_override`).

The sync calls a policy-on checkout makes stand outside the list above. The two
resolve the same policy from the same inputs -- the configured `[core] fsync`
narrowed by the option value, so a repository configured off syncs nothing
under `--fsync=true` -- and the calls each then makes follow from what each
writes. The tool syncs the temporary files of the uncompressed object
cache it keeps in the repository, and syncs no part of the destination. The
port keeps no such cache and syncs the files and the directories of the
destination (`cli-behavior.md`, "The fsync vocabulary", "Sync counts of a
checkout").

The step the value reader stands at also sits outside the list. In both the
reader runs ahead of the repository and ahead of the revision, so a value
neither holds is reported where a bad repository path or a bad revision would
otherwise answer. The argument-count check `clap` makes stands ahead of the
port's reader, so a plain-path line that omits DESTINATION names a different
fault in each: `ostree checkout --fsync=on REV` reports the value and
`ostrya checkout --fsync=on REV` reports the missing positional. Both exit 1
and create nothing, so the standing wording rule covers it. Under a batch
option the port's reader stands ahead of its own `error: DESTINATION must be
specified`, and both report the value
(`ostrya_cli::cli::checkout_fsync_policy_matches_the_tool`).

`export` accepts `--repo`, `--no-xattrs`, `--subpath=PATH`, `--prefix=PATH`,
and `-o/--output=PATH`, and nothing is missing.

The tar stream is a transport interface, so the two implementations are held to
the member list, the member metadata, and the tree the stream extracts to, and
never to the bytes (`../format-reference.md`, "tar"). Over corpora `C0`, `C4`,
and `C8` in `bare-user` mode the two agree on all three under each option and
under the `--subpath` and `--prefix` pair, and `--no-xattrs` is the form whose
stream both implementations import into one commit checksum
(`ostrya_cli::cli::export_options_match_the_tool`,
`ostrya_cli::cli::export_no_xattrs_imports_to_one_commit`). Eight divergences
stand:

- the member order, and with it which path of a content-sharing group is
  written in full. The two sides part as follows:
  - The tool emits the members in the order that `../format-reference.md`,
    "tar", states. The port emits each entry of a directory in one name order.
    Neither `--subpath` nor `--prefix` changes either side's order, which
    `ostrya_cli::cli::export_options_match_the_tool` states by holding each
    side's member order under every option to the order that side set with no
    option at all.
  - The first member the walk reaches for a content object is the one written
    in full, so a group whose paths lie in one directory coalesces the same way
    in both, and a group spanning two directories coalesces in opposite
    directions: over a tree holding `/z.txt` and `/adir/a.txt` on one content
    object, the tool writes `z.txt` in full and `adir/a.txt` as the hardlink,
    and the port writes `adir/a.txt` in full and `z.txt` as the hardlink
    (`ostrya_cli::cli::export_hardlink_direction_parts_from_the_tool`).
    Extraction resolves a hardlink against the member it names, so the
    extracted tree is the same.
  - Not observed: the header that the tool writes for a hardlink member, which
    no test compares. In the port, the header of a hardlink member carries
    mtime 0, mode 0, and owner 0:0;
- the extended attributes. The port emits one `SCHILY.xattr.<name>` record per
  stored xattr and this tool version emits none
  (`../format-reference.md`, "tar"). `--no-xattrs` drops the port's records, so
  the option is what brings the two streams into agreement over an
  xattr-bearing tree, and it leaves the tool's stream unchanged;
- the value dialect `--subpath` takes, on the terms `checkout --subpath`
  already parts on. The tool reads each `/`-separated span of the value as a
  child name to look up, so `--subpath=/dir/`, `--subpath=.`, `--subpath=..`,
  and `--subpath=/dir/..` all name nothing and end the export at exit 1 (`error:
  No such file or directory:` and the value, with a leading slash the tool
  adds). The port reads a path, so a trailing slash names the same directory as
  the form without it. The two agree on `--subpath=/dir/..`, which the port
  refuses at exit 1. A `..` component that follows a name component names an
  entry no directory holds. A `.` component falls
  away, and a value that carries no name component names the whole tree. Of
  those values the tool takes `/` alone, so `--subpath=.`, `--subpath=..`, and
  `--subpath=/..` write a tree in the port where the tool exits 1. The two
  agree on the empty value, which both refuse at exit 1: the tool looks up `/`
  and the port refuses the value before the export starts. Both accept a
  leading-slash and a relative spelling of a name that exists;
- a `--subpath` naming a regular file or a symlink, which has no tree to walk.
  The port refuses it at exit 1 with `error: tar: subpath is not a directory:
  <path>` and writes nothing. The reference build ends on SIGABRT: it prints
  `ostree_repo_file_tree_query_child: assertion failed: (self->tree_contents)`
  on standard error and a `Bail out!` line carrying the same text on standard
  output, so the port's refusal has no counterpart;
- an empty `-o` value. The tool reads it as standard output and writes the
  stream there at exit 0; the port refuses the value at exit 1 and writes
  nothing. An empty `--prefix` value is taken by both and leaves the `./` root
  and the bare relative names;
- a repeated `--no-xattrs`. The tool takes a second occurrence of the flag and
  exports as it does for one; the port refuses it at exit 1 with `error: the
  argument '--no-xattrs' cannot be used multiple times`. The port refuses a
  repeated boolean flag throughout its CLI. The three `export` options that
  take a value each take the last occurrence, which is what the tool does for
  all four (`cli-behavior.md`, "The tar export options");
- what the destination holds after a refusal. Both implementations open the
  destination before the revision resolves, so both truncate a `-o` destination
  that already existed and keep its inode and its mode, and neither writes a
  tar member. The tool then leaves the two trailing zero blocks of the archive
  it had opened, all NUL -- 1024 bytes in a `-o` file, and 10240 on standard
  output, where those blocks are padded up to one record -- and the port leaves
  nothing. A stream that finishes carries the same difference on standard
  output alone: the tool pads standard output up to a multiple of 10240 bytes
  and the port ends it at the two zero blocks, which is what both write to a
  `-o` destination;
- the words a destination that cannot be opened is refused in. The tool reports
  `error: Failed to open '<path>'` for a path whose parent directory is absent
  and for a path naming a directory; the port reports the system's own reason
  for each. Both exit 1 and neither creates the parent.

`prune` accepts `--repo`, `--refs-only`, `--depth`, `--no-prune`,
`--delete-commit`, `--keep-younger-than=DATE`, `--static-deltas-only`,
`--retain-branch-depth=BRANCH=DEPTH`, `--only-branch=BRANCH`, and
`--commit-only`. Nothing is missing. The tool refuses `--delete-commit`
together with `--no-prune`
(`error: Cannot specify both --delete-commit and --no-prune`, exit 1, no object
removed), and the port refuses the same pair in the same words. The totals text
the command writes is in `cli-behavior.md`, "CLI output formats",
`prune`.

A symlink under `refs/` that names a directory ends `prune --refs-only` of the
tool with exit 1. It ends each `prune` of the port with exit 1, in different
words ("P1", `refs`). The default `prune` of the tool exits 0.

The static-delta sweep of a prune removes each delta directory it selects
whole, nested directories included, and follows no symlink at the fanout, at
the delta path, or below it. An entry at the fanout or at the delta path that
is not a directory, a symlink or a regular file, stays in both, and so do the
deltas behind a symlinked fanout. A regular file directly under `deltas/` is
skipped, and the run exits 0 in both. A delta directory that holds no
`superblock` is not a delta, so it stays in both, also where its commit is the
one the prune deletes. A symlink at `deltas` itself is followed in both, and
the deltas behind it that the sweep selects are removed. A dangling symlink at
`deltas` holds no delta, and the run exits 0 in both.

The port's prune also removes, on every run without `--no-prune` and without
`--static-deltas-only`, each static delta whose target commit is absent from
the store and each `state/<commit>.commitpartial` marker whose commit is
absent. These are the leftovers of a run that stopped part way through. Every
prune skips a delta name that does not decode and leaves that entry in place.
This is a port behavior. The tool's handling of the two leftovers is not
observed. `../format-reference.md`, "Prune removal order", states the rule
and the order in which the port's prune removes a commit and its content.

Both implementations hold the repository lock for the whole of a prune, and
both take it exclusive. Measured against `ostree` 2026.1 on an archive
repository holding one commit, with a helper process holding a POSIX record
lock on `<repo>/.lock` through `fcntl.lockf`, which is the lock space the port
takes; `../format-reference.md`, "Repository lock and staging", records the
lock file and the lock kind the tool uses, recovered by tracing.

- `ostree prune --refs-only` blocks under a foreign exclusive lock.
- `ostree prune --refs-only` blocks under a foreign shared lock as well.
- `ostree prune --refs-only --no-prune` blocks under the same lock, so a dry
  run takes the lock too.
- With `core.lock-timeout-secs` at 2 the tool writes `error: Locking repo
  exclusive failed: Resource temporarily unavailable` and exits 1.
- With `core.locking` false the tool proceeds under a held foreign exclusive
  lock, writes nothing to standard error, and exits 0. Against the same
  repository with the key absent it writes the same standard-output lines and
  leaves the same loose objects, so the key decides the lock alone.

That the tool takes the lock exclusive rather than shared is an inference over
the first two observations: a shared acquirer blocks on an exclusive holder and
not on a shared one, and the tool blocks on both. The port takes the lock
exclusive over the whole run, a `--no-prune` dry run and a
`--static-deltas-only` run included, reads `[core] locking` and
`[core] lock-timeout-secs` as the tool does, and proceeds under a held foreign
lock where `[core] locking` is false. With `lock-timeout-secs=-1` the port
waits with no limit, as the tool does. The port uses a non-blocking retry loop,
and the tool uses a blocking request with `F_OFD_SETLKW`. At a value less than
`-1`, such as `-2`, `-3`, or `-100`, the tool does not open `.lock` and takes
no lock. It then completes while another process holds the lock. The port
refuses such a value. At a positive value the tool requests the lock with
`F_OFD_SETLK` about once each second, and the port retries every 100 ms. `0`
makes one attempt in both. Every port command that takes `.lock` or
`.update.lock` reads the key by this rule (`../format-reference.md`,
"Repository lock and staging"). At the timeout the port exits 1 with its
own wording, `error: timed out acquiring repository lock after <N>s`, which is
the diagnostic carve-out of "Scope of CLI compatibility" above.

Eight divergences stand at `prune`:

- the `--keep-younger-than` value dialect. The port takes `@SECONDS` and an
  absolute date and time carrying a UTC offset, and refuses the tool's
  local-time, relative, and empty forms with the tool's own
  `Could not parse '<value>'` text at exit 1, removing nothing. That is the same
  subset and the same words `commit --timestamp` carries, one date reader
  serving both sites, and the reason is the one stated there: reading the
  refused forms needs a time-zone database or a natural-language date reader,
  and both are the dialect of a C library the port does not link. The value
  `2023-11-15`, the value `1 hour ago`, and an empty value each exit 0 in the
  tool and 1 in the port;
- the `--retain-branch-depth` depth dialect. The value splits at its first `=`
  in both, and both refuse a value carrying no `=`
  (`Invalid value <value>, must specify BRANCH=DEPTH`) and a depth holding no
  digits (`Invalid depth <text>`), in the same words at exit 1. The tool reads
  the depth with the leading-digit-run reader "Global conventions" records for
  its key-file values, so `main=0x1` and `main=0=1` read as depth 0, `main=+1`,
  `main= 1`, and `main=1 ` read as depth 1, and `main=99999999999999999999`
  reads as a very large depth. The port reads a decimal integer with an optional
  leading `-` and refuses each of those five at exit 1 with
  `Invalid depth <text>`, removing nothing;
- the words `--static-deltas-only` is refused in without `--delete-commit`. Both
  exit 1 and remove nothing; the tool's line ends with a URL naming its own
  issue tracker and the port's line ends at the sentence the two share,
  `--static-deltas-only requires --delete-commit`;
- the words `--delete-commit` refuses a commit a ref names in. The tool reports
  `Commit '<checksum>' is referenced by '<ref>'` and the port
  `invalid format: cannot delete commit <checksum>: it is the target of a ref`.
  Both exit 1 and remove nothing. `--static-deltas-only` reaches no such refusal
  in either: it keys its deltas on the commit and deletes no object, so a branch
  head is a value both accept there;
- a repeated `--refs-only`, `--commit-only`, `--no-prune`, or
  `--static-deltas-only`, which the tool takes and the port refuses. This is the
  repeated-boolean-flag class already recorded for `export --no-xattrs`. A
  repeated `--depth` and a repeated `--keep-younger-than` take the last
  occurrence in both, and `--only-branch` and `--retain-branch-depth` are
  repeatable options in both;
- the values `--delete-commit` takes. The tool reads the value as a
  64-character checksum and uses it as the object path, so `--delete-commit=
  main^` reports `error: Deleting object main^.commit: unlinkat(ma/in^.commit):
  No such file or directory` at exit 1 and an abbreviated checksum reports the
  same line over its own text. Neither run removes an object. The port resolves
  the value as a revision, so both spellings name a commit, the run removes it
  and sweeps what it orphaned, and the run exits 0. This is the revision
  superset the port carries at every site that takes a revision, and `prune` is
  the one site where the superset removes objects: a value the tool refuses
  deletes here;
- the line the port writes where the repository config sets `[core] locking`
  false. With that key set the tool takes no lock, prunes beside a held foreign
  lock, exits 0, and writes nothing to standard error. The port does the same
  work and writes one line to standard error before the run, in its own name:
  `ostrya: [core] locking is false, so this prune holds no repository lock.
  Another writer can change the repository while the prune runs.` Both exit 0.
  The key decides whether the run takes the repository lock and decides nothing
  else, so each implementation writes the two standard-output lines it writes
  with the key absent and leaves the same objects
  (`ostrya_cli::cli::prune_warns_where_locking_is_disabled` holds the port
  half: the two arms write one standard-output text and leave one object
  inventory). No matrix cell reaches the line, because no harness setup edits
  `config` (`harness.md`, "Constraints"), so every cell runs against a
  repository whose `[core] locking` holds its default of true;
- the related commits. `ostree prune --refs-only` keeps no commit that field
  2 of a kept commit names (`cli-behavior.md`, "Related commits in a prune").
  The port keeps each commit that field 2 or the detached metadata key
  `ostrya.related` of a reached commit names, and the related commits of
  that commit in turn (`../format-reference.md`, "Related commits"). For each
  defective related value, the port writes one line `warning: related
  commits in <field> of commit <checksum>: <reason>` to standard error, and
  exits 0. The port also reads the `.commitmeta` of each commit that the
  walk reaches. It parses the file only if its bytes hold the key
  `ostrya.related` and its terminating NUL. So a file that does not hold the
  key and does not parse gives no error. A `.commitmeta` that holds the key
  and does not parse as an `a{sv}` dict fails the port's run at exit 1. A
  `.commitmeta` that is larger than the size cap of a metadata object fails
  the run in the same way, with or without the key. A failed run deletes
  nothing. No observation records how the tool treats such a file. On a
  repository where no commit names a related commit and each `.commitmeta`
  that holds the key parses, the two commands delete the same objects.

Two corners at `prune` are not settled by an observation this host can make:

- two refs naming one commit, where the two carry different bounds. The tool
  applies one of the two and drops the other, and which one it applies follows
  the enumeration and not a rule a black-box run states: over one local ref
  `alpha` and one local ref `beta` at one commit, `--only-branch=alpha
  --depth=0` cuts the shared history and `--only-branch=beta --depth=0` keeps
  it, and over one local ref and one remote ref at one commit the remote ref's
  bound decides both directions. The port applies both bounds and keeps what
  either of them reaches, which is deterministic, independent of the ref names,
  and never removes an object a ref's own bound retains. No matrix cell states
  the corner;
- the decimal separator the size in the totals line renders with. The port
  always writes `.`. Only the `C`, `C.utf8`, `en_GB.utf8`, `en_US.utf8`, and
  `POSIX` locales are installed on the conformance host, so every run of the
  tool falls back to the C separator and the two agree. Whether the tool follows
  a locale that renders a different separator is unverified here.

`-v` parts the two as well. The tool writes `OT: ` trace lines to standard error
and leaves standard output unchanged. The port writes the line `ostrya: using
repository PATH` to standard error and no `OT: ` line, as on each subcommand
that opens a repository other than `receive` and `send`.

A ref name the tool's ref enumeration skips is read by the tool's
`prune --refs-only` as unreachable, so the tool deletes a commit the port keeps.
That is the out-of-band ref name of "P1", and the pair is stated there.

One repository config key in the `[ex-ostrya]` group is a port extension
with no option and no counterpart in the tool. It parts `ostrya` from
`ostree` on a repository that sets it, and the divergence is by intent
(`format-reference.md`, "Configuration keys of the port"):

- `keep-detached-related=false` drops `ostrya.related` from each detached
  metadata dict that a transfer stores in the repository: `ostrya pull`,
  `ostrya pull-local`, `ostrya receive`, and the receive endpoint of
  `ostrya serve`. `ostrya push` to an `s3://` address reads the key from the
  `config` of the bucket. The tool's pull writes what the source holds. The
  commit checksum does not cover detached metadata, so the objects both
  write stay identical. A local write, for example `ostrya commit`, keeps
  the key (`format-reference.md`, "The switch of the destination").

No harness repository sets the key (`harness.md`, "Constraints"), so every
matrix cell reads the tool's own behavior.

`fsck` accepts `--repo`, `--add-tombstones`, `-q/--quiet`, `-a/--all`,
`--delete`, `--verify-bindings`, `--verify-back-refs`, and the port extension
`--no-mark-partial`. Nothing is missing. The phase, finding, and summary text
the command writes, the two binding checks, and the exit statuses are in
`cli-behavior.md`, "CLI output formats", `fsck`, together with the
progress line the tool writes and the port does not. A symlink under `refs/`
that names a directory ends an `fsck` run with exit 1 in both implementations,
in different words ("P1", `refs`).

The port's object walk runs to its end whatever the switches carry, so one run
reports every fault it reaches and marks every commit an absent object leaves
incomplete. A run ends early at three conditions alone, each of which stops the
port from reading what it must read next: a ref over a commit object the store
does not hold, because the phase cannot checksum a commit it cannot load; a
dirtree that is absent, because the objects beneath it cannot be named, so a
run that went on would state an object set it never had; and a
`--verify-bindings` or `--verify-back-refs` failure, because it states a fact
about the ref graph rather than about an object, marks nothing, and leaves the
phase that found it with nothing further to decide. The tool ends a run at the
same three conditions and at the first faulty object as well, unless `-a` or
`--delete` carries it on. In the tool, `-a` also carries phase 1 and phase 2
past a commit object whose checksum does not match. It carries
the object walk past such an object in the same way.

`-a` therefore carries a meaning of the port's own. In the tool it decides
where a run ends; in the port the walk runs to its end without it, and the
switch selects one thing: whether `--add-tombstones` may act after a walk that
found an object whose bytes do not match its name. The tombstone step deletes
a commit object and writes a `.tombstone-commit`, so the port holds it to the
walk the tool holds it to.

`--delete` carries the same permission alone, because it also carries the object
walk of the tool to its end. A walk whose findings are absent content objects or
absent dirmeta objects alone needs neither switch. An absent content object or
an absent dirmeta never ends a run in either implementation. An absent dirtree
ends the run: it is one of the three conditions that end a run early. The
repository the two leave therefore agrees in every combination of `-a`,
`--delete`, and `--add-tombstones`, over a sound repository and over a faulty
one alike. `--delete` takes no such gate of its own: the objects it unlinks and
the commits it marks are the same set with `-a` and without it in both
implementations.

Nine divergences stand at `fsck`:

- the progress line. The tool writes `fsck objects (n/total) pct%` to standard
  output: the first update, the last one, and about one more a second between
  them, so a short run writes two lines and a long run writes more, their
  numerators following the host's throughput. On a tty it draws a `[=  ]` bar
  sized to the terminal and repaints it in place with `ESC 7` and `ESC 8`. The
  port writes no progress line at all, on a tty or off one. The object count
  the line reports is `FsckReport::objects_checked`, which a library caller
  reads. The repository is unaffected, and the cited tests drop the block from
  both sides before comparing;
- the order of the findings, and the order of the commits inside one. The tool
  emits both in the iteration order of its own hash containers; the port emits
  the findings sorted by object checksum and each commit list sorted. The same
  reaches the back-reference check: where more than one commit fails it, the
  two name different commits. This is the hash-container carve-out of
  `CLAUDE.md`, "CLI compatibility is functional, not literal", and the cited
  tests sort both before comparing;
- a faulty repository run with neither `-a` nor `--delete`. The tool ends at
  the first fault its own walk order reaches, writes that one finding as its
  own `error: ` line, and writes no closing line. Where no condition ends the
  run (`cli-behavior.md`, "CLI output formats", `fsck`, "Where a run ends"),
  the port carries the walk to its end, writes every finding plain, and closes
  with `error: Repository corruption encountered`. The port's finding set and
  its `state/` markers are therefore a superset of the tool's over a repository
  holding more than one fault, and they do not follow a walk order: one
  repository gives one finding set. `-a` and `--delete` carry the tool to the
  end of the object set and the two agree again, which is the form the cited
  tests compare; a no-switch run is compared on its exit status and its object
  and `state/` inventory, and the port's own text is stated beside it;
- what `-a` selects. The tool reads it as "do not stop at the first fault",
  which decides where a run ends. The port's walk reaches its end without it,
  so the port reads it as the permission `--add-tombstones` needs to act after
  a walk that found a corrupt object. The two meanings pick out the same runs:
  the tool's walk reaches the tombstone step under `-a` and the port's step is
  released by it, so the repository agrees in both arms;
- an object whose own framing is broken. Over a content object the two part in
  wording alone -- the tool's `File header size 1476395034 exceeds size 38`
  against the port's `content header exceeds the size cap`, over one `.filez`
  whose first byte was flipped -- and the exit status and the repository
  agree. Over a metadata object they part further, because the two readers
  part. The port's GVariant reader takes normal-form input alone, so an object
  whose framing is broken is reported and left where it stands: `--delete`
  unlinks nothing and no commit is marked. The tool's reader takes data that
  is not in normal form and yields default values for the parts it cannot
  frame, so what the tool does next follows what those defaults are. Where the
  shifted offset reads as an entry, the tool refuses the object before it
  checksums anything (`error: Invalid checksum of length 5 expected 32`),
  exits 1, and writes nothing, which is the outcome the port reaches by its
  own path. Where the shifted offset reads past the object's own end, the tool
  sees an empty dirtree, checksums the object, and under `--delete` unlinks it
  and marks the commit partial, where the port keeps both. The two exit 1
  either way;
- a dangling ref whose name the tool's ref enumeration skips. The tool never
  reads the name, so its run passes; the port enumerates it, loads the commit
  the ref names, and ends the run at exit 1. This is the out-of-band ref name of
  "P1" reaching a second command. A ref of that shape whose commit is
  present parts the two in neither direction;
- a positional argument. The tool accepts one and ignores it; `clap` refuses it
  with `error: unexpected argument '<value>' found` at exit 1. This is the
  class already recorded for the other commands that take no positional;
- a repeated boolean flag. The tool takes a second `-a`, `-q`, `--delete`,
  `--add-tombstones`, `--verify-bindings`, or `--verify-back-refs`; the port
  refuses it with `error: the argument '<flag>' cannot be used multiple times`
  at exit 1. This is the repeated-boolean-flag class already recorded for
  `export --no-xattrs` and the four `prune` flags;
- a dependency in field 2 that is absent, partial, or defective. The tool
  reports no finding for an entry of field 2 and exits 0 (`cli-behavior.md`,
  "CLI output formats", `fsck`, "Related commits in fsck"). The port writes
  one line for each such entry on standard error, marks the commit that names
  an absent or a partial dependency as partial unless `--no-mark-partial` is
  given, and exits 1 with `error: Repository corruption encountered`. A
  defective entry gets no marker. `../format-reference.md`, "Dependencies in
  the fsck", states the rules. Over a repository whose dependencies are
  complete, the two agree.

`fsck --add-tombstones` deletes a commit object and leaves a branch ref
standing over it, so repeated runs walk a broken branch backwards one commit
per run until the ref cannot resolve. The port reproduces that: the object
inventory is the oracle and the port writes the bytes the tool writes.

`diff` accepts `--repo`, `--stats`, `--fs-diff`, `--no-xattrs`,
`--owner-uid=UID`, and `--owner-gid=GID`. Ten differences stand.

- a third positional argument. The tool accepts one and ignores it; `clap`
  refuses it with `error: unexpected argument '<value>' found` at exit 1. This
  is the class already recorded for the other commands;
- a repeated boolean flag. The tool takes a second `--stats`, `--fs-diff`, or
  `--no-xattrs`; the port refuses it with `error: the argument '<flag>' cannot
  be used multiple times` at exit 1. This is the repeated-boolean-flag class
  already recorded for `export --no-xattrs` and the four `prune` flags;
- the order of a directory side's lines. Both implementations name the entries
  in the order the directory returns them, so the two agree wherever the two
  copies of one tree are returned in one order and part where they are not.
  This is the hash-container carve-out of `CLAUDE.md`, "CLI compatibility is
  functional, not literal". A cited test that builds two copies of one tree
  sorts both sides before comparing; a cited test that reads one pair of
  directories through both implementations compares the lines as they stand,
  since the order is then the directories' own;
- the wording of a directory side's read failure. The tool writes `Error when
  getting information for file “<path>”: No such file or directory`, `Error
  opening file <path>: Permission denied`, and `Error opening directory
  '<path>': Permission denied`, each naming the lexically absolute path; the
  port writes its own sentence naming the call and the path as the command line
  spelled it. Both exit 1 and write no object;
- a path argument naming a regular file. The tool opens it as a directory and,
  where the file is the second side, reports the first child it queried, so its
  message names a path that was never given (`“<file>/<first entry of the other
  side>”: Not a directory`); where the file is the first side it names the
  argument. The port names the argument in both positions. Both exit 1;
- a `--stats` run over a repository missing a content object. The tool writes
  the three count lines and then `error: Querying object <checksum>.file: No
  such file or directory`; the port writes no line of the block, `Repo::diff_stats`
  returning the counts and the size together. Both exit 1 and change nothing on
  disk;
- `-v`. The tool writes `OT: ` trace lines to standard error and leaves
  standard output unchanged. The port's `-v` writes the line `ostrya: using
  repository PATH` to standard error and no `OT: ` line, as on each subcommand
  that opens a repository other than `receive` and `send`;
- an extended attribute whose value is zero bytes long, on a directory side.
  The tool's reader drops such an attribute and the port keeps it, so the port
  reports a modification the tool does not. Two directories differing in one
  such attribute alone report `M` in the port and nothing in the tool, and no
  ingest takes place on either side. The same rule at ingest is recorded in
  `m0-content.matrix`, row `C4`, and left undecided there;
- the rendering of a directory side's entry name that is not valid UTF-8. The
  tool writes the bytes the directory returned; the port writes U+FFFD for each
  invalid byte, `DiffEntry::path` being a `String`. Both list the entry, descend
  into it, report every other change, and exit 0;
- a symlink target that is not valid UTF-8, on a directory side. The tool reads
  every such target as one value, so two of them of one name report nothing and
  it writes two GLib criticals to standard error; the port compares the bytes,
  so two targets that differ report `M`. A valid target held against one that is
  not valid UTF-8 reports `M` in both.

`summary` accepts `--repo`, `-u/--update`, `-v/--view`, `--raw`,
`--list-metadata-keys`, `--print-metadata-key=KEY`, `-m/--add-metadata=KEY`,
`--gpg-sign=KEY-ID`, `--gpg-homedir`, `--sign=KEY-ID`, `--sign-type`, and the
port extensions `-s` (the short form of `--sign-type`), `--verify`,
`--last-modified`, `--metadata-commit-timestamp`, `--keys-file`, `--keys-dir`,
`--remote`, `--auth-group=NAME`, `-c/--client-groups`, and a positional
`KEY_ID...`. Nothing is missing. `--auth-group=NAME` reads the summary of the
auth item of the client group `NAME` with `-v`, `--raw`,
`--list-metadata-keys`, and `--print-metadata-key` (`../format-reference.md`,
"Summaries of auth items"). The port refuses it at exit 1 for a group that does
not exist, a group with `summary=false`, a group whose `auth` list holds more
than one item, and with `-u`, `--verify`, a signing key, or no read option.
With no client group, `NAME` is `anonymous` or `anonymous-collections`, the
implicit groups. `-c/--client-groups` needs `-u`. With it, `-u` writes and
signs the summary of each auth item, removes the files of each item with no
summary, and leaves `summary` and `summary.sig` as they are. In a repository
with a collection id it writes no anchor commit. The port refuses `-c` with no
`-u` at exit 1. The tool refuses `--verify`, `--keys-file`, `--keys-dir`, `-s`,
`-c`, and `--client-groups` with `error: Unknown option <arg>` at exit 1, and
verifies a summary signature through a remote alone. A signing `--keys-file`
of the spki engine holds PEM `PRIVATE KEY` blocks, the form of a `sign
--keys-file`, and each block adds one signature
(`../format-reference.md`, "Signing details"). A symlink under `refs/`
that names a directory ends `summary -u` with exit 1 in both implementations,
in different words ("P1", `refs`). The port's `summary
--verify` reads the key sources of its `sign --verify` (`cli-behavior.md`, "CLI
output formats", `sign`, "The key sources of `sign`"), with one verifier for
each engine, and refuses `--sign` and `--gpg-sign`. With `--remote`, it reads
the keys of the remote alone, for the engines that `gpg-verify-summary` and
`sign-verify-summary` of the remote turn on. A `-s` with no key selects its
engine, and the port then reads the keys of the selected engines alone. With no
key, no `--remote`, and no `-s`, the port skips an engine that finds no
signature, as its `sign --verify` does. The multi-engine report reads `summary`
and `summary.sig` one time, so each engine checks the same bytes. The port
refuses `--remote` in each mode other than `--verify`, `-u` and the read
options included, with `error: signature: --remote applies to --verify alone`.
It refuses `--keys-dir` in the same modes with `error: signature: --keys-dir
applies to --verify alone`. In a `--verify` run with a KEY-ID or a
`--keys-file`, it refuses `--keys-dir` with `error: signature: a KEY-ID or a
--keys-file gives the keys of the verify; it reads no --keys-dir`. A
`--verify` run refuses `--gpg-homedir` with `error: signature: --gpg-homedir
applies to signing alone`.
On this command the tool binds `-v` to `--view`, and `--verbose` has no short
form. The port carries the same shape: `summary` declares `-v/--view` and a
long-only `--verbose`, and every other subcommand, together with the top level,
keeps `-v/--verbose`. `-m`, `--sign`, and `--gpg-sign` are read with `-u`
alone, and both implementations check every one of them before the
regeneration, so a refusal leaves `summary` and `summary.sig` as they stood
(`cli-behavior.md`, "CLI output formats", `summary`, "The `-u` checks").
Sixteen differences stand.

- `-v` does not turn on the debug stream. The tool binds `-v` to `--view` and
  `--verbose` together and writes `OT: using fuse: 0` for a read-only view; the
  port binds `-v` to `--view` alone and writes nothing to standard error.
  `clap` gives one short form to one argument, so the port carries `-v/--view`
  as one flag and `--verbose` as another. Standard output is unaffected, and
  `ostrya summary --verbose` still writes the repository-resolution line the
  port's global `--verbose` writes everywhere;
- a positional argument. `summary` takes none in the tool, which accepts one
  and ignores it, writing the report as if it were absent. The port keeps the
  positional as a signing key identifier, a port extension beside
  `--sign=KEY-ID` read under the same `--sign-type`. With `-u` the positional
  keys sign after every `--sign` key. Without `-u` they sign each summary that
  stands, the root `summary` and each summary of an auth item, and signing
  precedes every reading option, so
  `summary --view <word>` signs where the word is a key and refuses at exit 1
  where it is not. The tool writes the report and the port writes none;
- a repeated switch. The tool takes a second `-v`, `--view`, `--raw`, or
  `--list-metadata-keys` and runs the command, and takes the last occurrence of
  a repeated `--print-metadata-key`; the port refuses each with `error: the
  argument '<flag>' cannot be used multiple times` at exit 1. This is the
  repeated-flag class already recorded for `export --no-xattrs` and the four
  `prune` flags;
- the absent-summary wording. The tool reports `error: openat(summary): No such
  file or directory` and the port reports `error: opening summary: No such file
  or directory`. Both exit 1 and write nothing to standard output;
- the no-option refusal wording. The tool reports `error: No option specified;
  use -u to update summary`; the port reports `error: invalid format: nothing
  to do: pass --update, --verify, a reading option, or a signing key`, naming
  the options it carries, two of which the tool does not. Both exit 1. The
  refusal is also what `--sign`, `--gpg-sign`, or `-m` draws without `-u` and
  without a reading option, in both, before any value is read. The port
  reaches it before a positional key is read;
- the place a signing key takes among the reading options. The observation
  that settles it is `summary --sign=K --view`: both write the report and sign
  nothing, and `--sign`, `--gpg-sign`, and `-m` are inert beside every reading
  option in both. The port's extensions order the other way. A positional key
  or a `--keys-file` signs and returns before any reading option is read, so
  `summary --view --keys-file=F` writes a signature and no report. The tool
  carries neither surface;
- the entry order of the metadata dict after `-m`. With any `-m`, the tool
  stores the whole dict, its own keys included, in the order of a hash table,
  which follows the key set and not the command line: `-m b=1 -m n=2` stores
  `mode, n, b, last-modified, indexed-deltas, tombstone-commits`. The port
  stores the standard order and then the user keys in first-occurrence order.
  Rebuilding a hash-table order is the engine rule 2 forbids, and
  `commit --bootable` carries the same class of divergence ("P2", `commit`). The key set and every value agree, the
  report follows the stored order, and some key sets keep the standard order in
  the tool, where the two `summary` files agree byte for byte;
- the entry order of the `ostree.static-deltas` map of a summary that lists two
  or more deltas. The tool writes the entries in the order of a hash table,
  which follows the set of delta names and, for some names, the order it read
  them, and which can differ from the order of an index file over the same
  set. The order is the same over runs on one tree, and removing deltas can
  swap the order of two that stay. The port writes them in name order, the
  rule 2 decision the
  `static-delta` entry below records for the index files. The entries and each
  digest agree. For some sets the tool's order is name order by chance, and
  the two maps then agree;
- the engine of each key, the rule `commit --sign-type` records. The tool
  applies the last `--sign-type` to each `--sign`, positional, and
  `--keys-file` key. The port gives each key the engine of the nearest
  `--sign-type` before it, and `ed25519` to a key before the first
  `--sign-type`. `--gpg-sign` is not a key of a `--sign-type`;
- a `--sign-type` with no key of its own, the rule `commit --sign-type`
  records. The port refuses it at exit 1 in each mode of `summary` other than
  `--verify`, the read options included, and keeps `summary` and
  `summary.sig`. It reads each name first, so a name that no engine carries
  gets the refusal of the name. The tool reads `--sign-type` only where a key
  needs an engine: `-u --sign-type=ed25519` with no key signs nothing and
  removes `summary.sig` (`summary/update-without-sign-drops-sig`), and `-u
  --sign-type=bogus` with no key runs (`summary/sign-type-unread-without-a-key`).
  A `--verify` run with no key takes each `--sign-type` as a selection of its
  engine;
- `--sign-type=gpg` names an engine the port carries and the tool build does
  not, the rule `commit --sign-type` already records. The tool's build reports
  `error: Requested signature type is not implemented` for `gpg` beside
  `--sign`, where the port reads a key after `--sign-type=gpg` under `gpg` when
  it is built with the `gpg` feature. The port looks up a `gpg` selector given to `--sign` or as a
  positional key before the regeneration, the way it looks up a `--gpg-sign`
  selector. Under `spki` both read the key before the regeneration: the
  `ostree` 2026.1 build with OpenSSL on the NixOS development host, and the
  port when it is built with the `spki` feature. A tool build without the
  features `openssl` and `sign-spki` refuses `spki` with the same `not
  implemented` line;
- `-m` in a repository with a collection id. The tool adds the caller keys to
  the metadata of the `ostree-metadata` anchor commit as well. The two
  bindings win over a caller key of the same name, a repeated caller key takes
  its last value, and the tool keeps any other caller key,
  `ostree.summary.mode` among them. With a caller key present the tool stores
  the anchor dict in the order of a hash table, even for one key: `-m k=1`
  stores `ostree.collection-binding`, `k`, `ostree.ref-binding`, and
  `-m b=1 -m n=2` stores `n`, `b`, `ostree.collection-binding`,
  `ostree.ref-binding`. The anchor checksum follows that order. The port
  refuses the run at exit 1 before the regeneration with
  `error: unsupported: summary metadata keys in a repository with a collection
  id`, and `summary`, `summary.sig`, and the anchor ref keep their state. Rule
  1 decides it: carrying the keys in the port's own order writes an anchor
  with another checksum (`../format-reference.md`, "The `ostree-metadata`
  anchor commit");
- a 64-byte `--sign` value whose halves are not an ed25519 key pair, the class
  `commit --sign` records above. 64 zero bytes are one such value. The tool
  signs with it at exit 0. The port refuses it at exit 1 before the
  regeneration with `error: signature: ed25519 secret key: signature error:
  Mismatched Keypair detected`, and `summary` and `summary.sig` keep their
  state;
- an inline `spki` secret key of `--sign`, the class `commit --sign` records
  above. The decode parts as there. The tool reports `error: openssl: Failed
  to initialize spki key` where the port reports its `error: signature: spki
  secret key:` line. Both exit 1 before the regeneration, and `summary` and
  `summary.sig` keep their state;
- the summaries of the client groups. The tool reads no client group, and
  `summary -u` writes one `summary` of each local ref and each mirror ref.
  The port writes the same root `summary`, which holds each ref whatever the
  client groups. It also writes one summary for each auth item that a group
  with `summary=true` carries, `anonymous` included, under
  `extensions/ostrya/summary/`, with an `.access` file for each item
  (`../format-reference.md`, "Summaries of auth items"). `ostrya serve` and
  `ostrya send` serve these summaries, and never the root `summary`.
  `summary -u -c` writes these summaries alone. A malformed client group
  refuses
  `summary -u` at exit 1 before any write, and the tool ignores the group.
  For each directory under `refs/mirrors/` whose name is not a collection
  id, the port writes one `warning:` line to standard error and leaves the
  directory out of each summary;
- a `summary` file whose bytes are not a document of the summary type. Such a
  file reaches a repository only through a write that is neither
  implementation's. The tool reads it as an empty document, so `--raw` writes
  `(@a(s(taya{sv})) [], @a{sv} {})`, `-v/--view` and `--list-metadata-keys`
  write nothing, all three exit 0, and `--print-metadata-key=KEY` refuses at
  exit 1 with `error: No such metadata key '<key>'`. The port refuses the
  document itself at exit 1 with nothing on standard output, for all four
  options. A zero-length `summary` file reads the same way on each side.

The time zone a `summary -v` report renders an instant in is the divergence
"P3" records for `remote summary`, reached here by the local command: the tool
renders in the host zone with that zone's offset and the port renders in UTC.

`static-delta` accepts the subcommands `list`, `generate`, `apply-offline`,
`reindex`, `show`, `delete`, `indexes`, and `verify`. `show` and `verify` take
a delta name or the path of a superblock file, `delete` takes a delta name
alone, `list` lists the deltas under `deltas/`, and `indexes` lists the
`delta-indexes/` cache (`cli-behavior.md`, "CLI output formats",
`static-delta`). `apply-offline` takes a path, a superblock file or a
directory that holds `superblock`, and the key options of `verify`. Both
implementations fold the path as text before they open it. Each `..` removes
the component before it, so `<link>/../<dir>` names `<dir>` beside the link
and `<dir>/superblock/..` names `<dir>`. `verify` and `apply-offline` take
`spki` in a build that carries the engine, the sign-type rule this section
states for `commit --sign-type`. `reindex` takes `--to=REV`, which rewrites or
removes the index file of one target and reads REV by the rule of one half of a
delta name; the last `--to` wins. A `--keys-file` and each key-store file of
the spki engine hold PEM `PUBLIC KEY` blocks (`format-reference.md`, "Signing
details", "spki"). Forty-nine differences stand on `show`,
`delete`, `list`, `indexes`, `verify`, `apply-offline`, and `reindex`.

- a superblock file over 128 MiB (134217728 bytes). The port refuses it in
  `show`, `verify`, and `apply-offline`, and a pull refuses the fetched
  superblock, with `error: i/o error: static delta file <path> exceeds the
  size ceiling` or the fetcher's size refusal. The tool has no such ceiling:
  it writes a 140,007,544-byte superblock with `--inline` and applies it
  offline at exit 0. Only an inline delta whose parts add up to more than 128
  MiB reaches the ceiling. The ceiling is the bound the port holds for
  metadata that it reads whole;

- a part that fails its checksum or passes its declared size. The port refuses
  it at exit 1 after the `PartMeta<i>` line, before it decompresses a byte of
  it, with `error: invalid format: static delta part checksum mismatch` or
  `error: invalid format: static delta: a stream passed the <n> byte(s)
  declared for it`. The tool checks neither. Where the tampered part
  still decodes, the tool prints the counts of what it decodes at exit 0. A
  truncated xz part makes the tool fail with `Input buffer too small` at exit 1.
  Only a write that is neither implementation's reaches this;
- a part the superblock carries inline. The port reads it from the metadata
  dict, in the name form and the path form. The tool reads no inline part: in
  both forms it opens `deltas/<fanout>/<rest>/<i>` in the repository and
  refuses at exit 1 after the `PartMeta<i>` line where that file is absent;
- the part files of a superblock named by path. The port reads them from the
  directory that holds the superblock file. The tool reads the repository's
  part files for the delta the superblock names, and refuses where the
  repository holds none. Over a superblock inside the repository's own
  `deltas/` tree the two read the same files;
- a superblock that does not parse. The tool prints the lines it read before
  the failure, for example `Delta:`, `Signed:`, and `From <scratch>`, and then
  `error: Invalid checksum of length 0 expected 32`. The port prints no line
  and its own `error: invalid format:` sentence. `apply-offline` over such a
  file reports the same tool line, and the port's own `error: invalid format:`
  or `error: gvariant:` sentence. Both exit 1 and write no object. Only a
  write that is neither implementation's makes such a superblock;
- an operation stream that both refuse, in a part that passes its checksum: an
  unknown opcode, a stream that ends inside an operation, an operand the port
  reads as past 64 bits, an `S` range past the data-source blob, and an `r`
  range past the blob. The port prints no `PartPayload<i>` line and refuses
  with its own `error: invalid format: static delta:` or `error: invalid
  varint:` sentence. The tool prints the line and then refuses, for example
  with `error: Unknown opcode 88 at offset 0` or `error: opcode
  open-splice-and-close: Invalid offset/length 0/100`. Both exit 1. A `w`
  range past the blob with no read source set and a `B` range past the blob
  are no refusal: both count the operation and exit 0. A publisher's own bytes
  alone reach this;
- an `o` whose mode index or xattr index is outside its table. The tool prints
  the `PartPayload<i>` line and then aborts on a GLib error, `Attempt to
  access item 0 in a container with only 0 items` for an empty mode table, and
  dies on `SIGABRT`. The port reads no table entry to count the operation, so
  it counts the `o` and exits 0. A publisher's own bytes alone reach this;
- a part whose xz stream states a dictionary that needs more than 128 MiB of
  decoder memory. The port refuses it at exit 1 after the `PartMeta<i>` line
  with `error: invalid format: static delta: part payload needs more than 128
  MiB of xz decoder memory`. The tool allocates what the stream states: a
  234,413-byte part stating a 1.5 GiB dictionary reports at exit 0 with 1,549
  MiB of resident memory. A part the tool's generator or the port's writes
  states a 32 MiB dictionary;
- the line order of `indexes`. The tool prints the targets in the order the
  directory returns them, and the port sorts them. This is the hash-container
  carve-out of `CLAUDE.md`, "CLI compatibility is functional, not literal";
- the line order of `list`. The tool prints the delta names in the order the
  directories return them, and the port sorts them. This is the same
  hash-container carve-out;
- a `deltas/<fanout>/<rest>` name that does not decode, where `<rest>` holds a
  `superblock`. The tool lists a lenient decode at exit 0: for
  `deltas/zz/garbage` it prints a line that starts `cf381aadb6a07b`, and the
  bytes after the decoded ones change from run to run. The port refuses the
  listing at exit 1 with `error: invalid checksum:` and nothing on standard
  output. Where `<rest>` holds no `superblock`, both skip the entry. Only a
  write that is neither implementation's makes such a name;
- an index name outside the modified-base64 form: a character outside the
  alphabet, or a last character whose low bits are not zero. The tool lists a
  lenient decode, and for some such names bytes the name does not determine.
  The port skips the entry. Only a write that is neither implementation's makes
  such a name;
- the wording of an `indexes` read failure. The tool writes `error: opendirat:
  Not a directory` and `error: opendir(<fanout>): Permission denied`, and the
  port writes the library's `error: i/o error:` sentence. For a
  `delta-indexes` that is a regular file, the port writes `error: i/o error:
  Not a directory (os error 20)`. Both exit 1;
- the wording of a `list` read failure. For a `superblock` that is a symlink
  loop, the tool writes `error: fstatat(<rest>/superblock): Too many levels of
  symbolic links`. For an entry that cannot be searched, it writes `error:
  fstatat(<rest>/superblock): Permission denied`. For a `deltas` that is a
  regular file, it writes `error: opendirat: Not a directory`. The port writes
  the library's `error: i/o error:` sentence, with `Too many levels of
  symbolic links (os error 40)`, `Permission denied (os error 13)`, and `Not a
  directory (os error 20)`, and both exit 1;
- the wording of a `delete` failure other than an absent delta. The tool
  writes `error: fstatat(<path>): <reason>`, `error: open(<path>): <reason>`,
  and `error: Removing <path>: unlinkat(<name>): <reason>`, and the port writes
  the library's `error: i/o error:` sentence. Both exit 1, and both leave the
  entries the removal did not reach;
- an extra positional argument. The tool ignores it on `show`, `delete`,
  `list`, `indexes`, and `reindex`, and `clap` refuses it with
  `error: unexpected argument '<value>' found` at exit 1. For `delete` the port
  removes nothing. For `reindex` the tool runs the pass the options select,
  the full pass with no `--to` and the pass over one target with it, and the
  port writes nothing. This is the class already recorded for `diff`;
- `reindex --to` with no value. The tool writes `error: Missing argument for
  --to`. The port writes `error: a value is required for '--to <REV>' but none
  was supplied`. This is the parser text that `commit` records for `--fsync`.
  Both exit 1;
- the entry order of an index file that lists two or more deltas. The tool
  writes the entries in the order of a hash table, which follows the set of
  delta names and, for some names, the order it read them. The port writes
  them in name order. Rebuilding a hash-table order is the engine rule 2
  forbids, so this is a difference in the repository bytes, the class
  `summary -m` records. The entries and each digest agree, an index file of
  one entry is byte-identical, and the tool pulls with
  `--require-static-deltas` from a repository the port indexed. For some sets
  the tool's order is name order by chance, and the two files are then
  byte-identical;
- a directory at the index path under `reindex`, or a path component that is
  no directory. For a directory at the index path of a target with deltas the
  tool reports `error: renameat(<temp>, <index>): Is a directory`, and for a
  target with no delta `error: unlink(<index>): Is a directory`. The port
  reports `error: i/o error: Is a directory (os error 21)` in both cases. The
  port reports the same line in the full pass. For a target with no delta, a
  regular file at the fanout or at `delta-indexes`,
  or a symlink at the fanout to a regular file, makes the tool report `error:
  unlink(<index>): Not a directory`, and the port reports `error: i/o error:
  Not a directory (os error 20)`. Both exit 1 and leave no temp file;
- `Endianness:` for a superblock with no `ostree.endianness` key, or a byte
  other than `l` and `B`. The port prints `little` and reads the size fields as
  little-endian in all three cases. With the key absent over a delta whose
  sizes are little-endian, the tool prints `Endianness: invalid`. With the key
  absent over a delta the tool wrote under `B`, the tool prints `Endianness:
  big (heuristic)` and swaps the sizes, by a size-ratio heuristic
  (`../format-reference.md`, "Endianness"). With the byte `x`,
  the tool prints `Endianness: invalid`. Only a write that is neither
  implementation's makes such a superblock: both generators write the key;
- the decimal separator of the size wording. The port always writes `.`. The
  tool formats through the C library's locale, and only the `C` and `C.UTF-8`
  behavior is observed on this host;
- `verify --sign-type=dummy`. The tool reads the keys and reports
  `Verification fails` with a reason, for example `no signature for
  'ostree.sign.dummy' in static-delta superblock`. With no key source, the
  tool reports `error: not implemented`. Both exit 1. With
  `OSTREE_DUMMY_SIGN_ENABLED=1`, the tool verifies a dummy-signed delta, and
  only that variable lets the tool write such a delta. The port refuses before
  it reads a key, with `error: dummy signature type is only for ostree
  testing` and nothing on standard output, at exit 1;
- `apply-offline --sign-type=dummy`. The port refuses at exit 1 with the same
  line as for `verify` and writes no object. The tool applies the delta at
  exit 0 with no key source, and applies an unsigned delta at exit 0 under a
  key. Over a signed delta under a key, the tool reports `error: no signature
  for 'ostree.sign.dummy' in static-delta superblock` at exit 1;
- the GLib warning before the unknown-sign-type error of `apply-offline`. The
  tool writes a GLib warning block on standard error and then `error:
  Requested signature type is not implemented`. The port writes the last line
  alone. Both exit 1 with nothing on standard output and write no object;
- a part file that does not open under `apply-offline`, for example a
  superblock copied away from its parts. The tool reports `error: Opening
  deltapart '<i>': <reason>`. The port reports the library's `error: i/o
  error:` sentence. Both exit 1 and write no object;
- the detached metadata of the target under `apply-offline`. Where the
  superblock carries a copy of the detached metadata of the target
  (`../format-reference.md`, "Superblock fields"), the tool writes the
  `.commitmeta` of the target from that copy (`cli-behavior.md`, "CLI output
  formats", `static-delta`, "`apply-offline`"). The port writes no
  `.commitmeta`. Both exit 0 and write the same objects, and neither writes a
  ref. `../roadmap.md`, "Gaps in the library", lists the work;
- the deltas `apply-offline` takes. `ostree static-delta apply-offline`
  refuses a delta whose fallback array is not empty, with `Cannot execute
  delta offline: contains nonempty http fallback entries`. To the tool,
  fallbacks are a pull mechanism. The dispatch of its `open` opcode asserts a
  repository of the bare family. So a delta that carries rollsum or bspatch
  objects applies offline into `bare`, `bare-user`, or `bare-user-only`
  alone. A delta of splices alone applies into each mode. The limits are in
  the applier, so they also apply to a delta that the tool generates. The
  port has neither limit. It applies rollsum and bspatch objects into an
  `archive` repository. It applies a delta with fallbacks where the objects
  that they name are already in the repository. A fallback entry of the
  composefs image need not be present (`../format-reference.md`, "The
  composefs image in a static delta");
- the dependencies of the target under `apply-offline`. The port reads field
  2 of the target commit before it writes an object
  (`../format-reference.md`, "Object delivery"). It refuses a defective
  entry, and a dependency that the repository does not hold complete or that
  is nested, at exit 1 with `error: related commits in field 2 of commit
  <target>: <reason>` and nothing on standard output. It writes no object.
  The check also runs if the repository holds the target. The tool applies
  the delta with no check of field 2, also if the repository holds the
  target;
- a 32-byte `apply-offline` key that decodes to no curve point. The port
  refuses every run that carries such a key at exit 1 with the error it gives
  for `verify` and writes no object. The tool applies an unsigned delta at
  exit 0. Over a signed delta, the tool applies at exit 0 where another key
  verifies the signature, in either order of the keys. Where no key verifies
  it, the tool names each key in the failure line at exit 1 and writes no
  object;
- an ed25519 `verify --keys-file` line of the wrong length beside a valid
  line. A line
  of two or more whitespace bytes is a key of 0 bytes and counts as such a
  line. The tool loads the valid lines, prints `Verification OK` or
  `Verification fails`, and then exits 1 with the invalid-key error. The port
  refuses the run with the same error and nothing on standard output. Both
  exit 1. Where the file holds one line of two or more bytes and that line is
  not a valid key, the two agree byte for byte. Where the file holds two or
  more such lines, the tool writes a GLib warning and names the first line in
  an error that carries the `Invalid ed25519 public key:` prefix twice. The
  port names the first line with the prefix once;
- an ed25519 `--keys-file` line of 0 or 1 byte, a lone `\r` included, under
  `verify`,
  `sign --verify`, or `summary --verify`. The tool's `verify` and `sign
  --verify` die on `SIGSEGV` after a GLib assertion. The port skips an empty line and a
  lone `\r` line. It refuses any other 1-byte line, whitespace included, at
  exit 1 with `error: Invalid ed25519 public key: Ill-formed input: expected
  32 bytes, got 0 bytes` and nothing on standard output;
- an ed25519 key-store line of 0 or 1 byte, under `verify`, `sign --verify`, or
  `summary --verify`. The tool's `verify` and `sign --verify` die on `SIGSEGV`
  after a GLib assertion. The port skips an empty line and a line of whitespace, and
  refuses any other 1-byte line with its strict base64 error;
- a `--keys-file` over 1 MiB (1048576 bytes), under `verify`, `sign --verify`,
  or `summary --verify`. The tool's `verify` and `sign --verify` read the whole
  file and verify with its keys. The port refuses the run at exit 1 with
  `error: signature: the key file '<path>' is over the 1048576-byte ceiling`
  and nothing on standard output. The ceiling is the one the port's key store
  applies to each of its files;
- a key-store file that cannot be read, for example a file of mode 000. The
  tool skips the file. It verifies with the other keys, and a skipped file
  that holds the only key reports `error: signature: ed25519: no keys loaded`.
  A skipped `revoked.ed25519` revokes nothing, so the tool reports
  `Verification OK` at exit 0 with a key that file revokes. The port refuses
  the run at exit 1 with `error: signature: the key file '<path>' cannot be
  opened: Permission denied (os error 13)` and nothing on standard output. The
  port's `sign --verify` and `summary --verify` refuse such a file the same
  way;
- an ed25519 key-store line (`--keys-dir` or the system key directories) that
  does not
  decode to a valid key, in the trusted or the revoked set. The tool skips the
  line with a GLib warning and verifies with the other keys. The port refuses
  the run with `error: signature: ed25519 public key must be 32 bytes, got
  <n>` and nothing on standard output. The store reader also decodes strictly,
  where the tool decodes leniently. The port's `sign --verify` and `summary
  --verify` read the store with the same reader;
- an empty `--keys-file` of the spki engine, or a file of white space only
  (space, horizontal tab, LF, form feed, and CR), under `verify`,
  `sign --verify`, or `summary --verify`. The tool refuses the
  run with `error: signature: spki: no valid keys in file '<path>'`. The port
  reads the file as no keys, so the run reports `error: signature: spki: no
  keys loaded` when no other source holds a key. An empty
  `verification-spki-file` of a remote is the same case: the tool refuses each
  pull with `error: Failed loading 'spki' keys from '<path>`, and the port
  adds no keys;
- an spki key-store file that the reader refuses: a file with no block, a
  block of another label, a block with no END line, or an END label that is
  not the BEGIN label. In the trusted set, the tool drops the file with no
  message and loads the other files. In `revoked.spki` and the files of
  `revoked.spki.d/`, the tool revokes no key of the file, or the keys of the
  blocks before the first error, with no message. A `revoked.spki` of base64
  lines thus revokes nothing. The port refuses the run at exit 1 with an
  `error: signature:` line that names the file, in the trusted and the
  revoked set;
- a BEGIN line in an spki block. The tool reads the body lines before the
  inner BEGIN line as the block. The port refuses the file;
- an spki `PUBLIC KEY` block that does not decode: a body that is not a key
  DER, a header line, text that is not base64, or an empty body. The tool
  loads the file and fails when a verify reaches the key of that block, so
  the result depends on the order of the keys. The port refuses the file
  when it loads the keys;
- the body form of an spki `PUBLIC KEY` block. The tool reads a body of any
  line width, with blank lines, white space in a body line, characters that
  are not base64, and data after the padding. The port refuses a body line
  that is empty, or that holds a CR after it removes the one CR at the end of
  the line. The crate `pem-rfc7468` then decodes the body in the form of RFC
  7468: lines of 64 base64 characters, the last line shorter or equal, and no
  headers. The port refuses each other body;
- the wording of the refusal of an spki key file. The tool writes `error:
  signature: spki: no valid keys in file '<path>'` for a `--keys-file` with no
  block, and `error: Unexpected label "<label>"` for a block of another label.
  The port writes `error: signature: the key file '<path>' holds no PEM
  PUBLIC KEY block` and `error: signature: the key file '<path>', line <n>:
  unexpected label "<label>"`. Both exit 1 with nothing on standard output;
- an spki positional key of `verify` that is not the base64 of a
  SubjectPublicKeyInfo DER: the base64 of a raw SEC1 point, of the full PEM
  text, or of a PKCS#8 secret key. Observed with the `ostree` 2026.1 build with OpenSSL on the NixOS development host
  (`cli-behavior.md`, "CLI output formats", `static-delta`, "spki inline
  keys"). Before a valid key, the tool prints `Verification OK` at exit 0.
  Alone, or after a valid key, it prints `Verification fails` and reports
  `error: openssl: Failed to initialize spki key` at exit 1. The port refuses
  the run at exit 1 before it reads the superblock, in each position of the
  key, with `error: signature: spki public key: expected SubjectPublicKeyInfo
  DER` and nothing on standard output. A key with explicit curve parameters,
  a key of a type or on a curve outside the set of the port, and an RSA key
  that the port refuses, are refused in each key source of `verify`, `generate`, and `apply-offline`, as "P2",
  `sign`, records. A line of the `--keys-file` of `generate` gives the reason
  after `error: signature: the key file '<path>', line <n>: spki secret key:
  `;
- `--keys-dir` naming a regular file, under `verify`, `sign --verify`, or
  `summary --verify`. The tool's `verify` and `sign --verify` report `error:
  signature: ed25519: no keys loaded`, and a later `--keys-dir` replaces the
  file. The port reports `error: signature: the
  key file '<path>/trusted.ed25519' cannot be opened: Not a directory (os
  error 20)`, and a later `--keys-dir` does not change the refusal, because
  the port reads each `--keys-dir`. Both
  exit 1 with nothing on standard output;
- a 32-byte `verify` key that decodes to no curve point. The port refuses
  every run that carries such a key before standard output with `error:
  signature: ed25519 public key: signature error: Cannot decompress Edwards
  point` at exit 1. Where another key verifies the signature, in either order
  of the keys, the tool prints `Verification OK` at exit 0. Where no key
  verifies it, the tool reports `Verification fails` and names each key in the
  failure line at exit 1;
- a superblock file that does not parse, given to `verify`. The tool reads the
  8-byte magic alone: a file with no magic, an empty file, and a truncated
  unsigned superblock report `no signatures in static-delta`, a truncated
  signed envelope aborts on `SIGABRT` after `Verification fails`, and a validly
  signed envelope around a payload that is not a superblock reports
  `Verification OK` at exit 0. The port parses the whole superblock and refuses
  each after `Verification fails` with its own `error: invalid format:` or
  `error: gvariant:` sentence at exit 1. Only a publisher's own bytes reach the last
  case;
- the engine of each key of `verify` and `apply-offline`. The tool applies the
  last `--sign-type` to each KEY-ID and `--keys-file` key. The port gives each
  key the engine of the nearest `--sign-type` before it, and `ed25519` to a
  key before the first `--sign-type`. It reads the last `--keys-file` of each
  engine, and verifies with one verifier for each engine. Each engine that
  finds a signature must have a valid one. An engine that finds no signature
  fails the run, except in a run with no key and no `--sign-type`, which
  skips it if another engine finds a signature (the item on the key
  directories below). `verify` prints `Verification OK` one time, or the
  failure line of the first engine that fails. The tool reads one engine;
- a `--sign-type` of `verify` and `apply-offline` with no key of its own. With
  a key on the command line, the port refuses it at exit 1 before standard
  output. `verify` with no key takes each `--sign-type` as a selection of its
  engine, and verifies with the selected engines alone. Each selected engine
  must have a valid signature. `apply-offline` refuses it also with no key and
  with a `--keys-dir`, where the tool applies an unsigned delta and, with no
  key source, a signed delta with no check. The refusal of a name comes first,
  so `apply-offline --sign-type=nosuch` keeps the line of the tool
  (`static-delta/apply-offline-sign-type-unknown`);
- the key directories of `verify` and `apply-offline`. The tool reads the last
  `--keys-dir` alone, and the system key directories `/etc/ostree` and
  `/usr/share/ostree` where no `--keys-dir` is given. The port reads the
  system key directories and then each `--keys-dir`, and a revoked key of one
  directory applies to the keys of each directory. With no key, it verifies
  with each engine that has a trusted key in them. Without a `--sign-type`, if
  one of these engines finds a signature, the port skips each engine that finds
  none. Each engine that finds a signature must have a valid one, and a run
  where no engine finds a signature fails. A delta with an spki signature alone
  then verifies and applies with a key directory that also holds an ed25519
  key. A run that finds no engine is refused at exit 1 with `error: signature:
  no keys loaded: the key directories hold no ed25519 or spki key`, where the
  tool writes `error: signature: ed25519: no keys loaded`
  (`static-delta/verify-no-keys`). `apply-offline` with a `--keys-dir` and no
  key reads the system key directories as well;
- a `--keys-dir` beside a KEY-ID or a `--keys-file`, under `verify` and
  `apply-offline`. The tool reads no key directory in such a run, and
  verifies with the other keys
  (`static-delta/verify-keys-file-overrides-keys-dir`). The port refuses the
  run at exit 1 before standard output with `error: signature: a KEY-ID or a
  --keys-file gives the keys of the verify; it reads no --keys-dir`, and
  `apply-offline` writes no object.

The key-file entries under `verify` also hold for `apply-offline`, and each
refusal writes no object.

`static-delta generate` accepts `--inline`, `--set-endianness=l|B`, and
`--swap-endianness`, which take the tool's rules (`cli-behavior.md`,
"CLI output formats", `static-delta`). The byte order starts from the host
order, as in the tool. Only a little-endian host is observed.

`static-delta generate` carries twenty-four differences. Two of them are open.

- the composefs image of the target commit. The port puts the stored image
  of a commit that carries `ostree.composefs.digest.v0` in the delta, in a
  part or as a fallback entry of the type 100 (`../format-reference.md`,
  "The composefs image in a static delta"). A delta of `--inline` lists the
  image as a fallback entry. The tool has no image object. A delta of a
  commit with no key or with no stored image has no image entry, and this
  rule changes none of its bytes;

- an inline superblock over the 128 MiB ceiling. The port refuses at exit 1
  after the block, with one of two messages. The inline parts share the
  ceiling with the embedded commit, 33 bytes for each object, and 49 bytes for
  each fallback. The part that passes what they leave is refused with `error:
  invalid format: static delta inline parts pass the 134217728-byte
  superblock ceiling`. Where the parts fit and the framing, the detached
  metadata copy, or a signature takes the serialized superblock past the
  ceiling, the refusal is `error: invalid format: static delta superblock is
  <n> bytes, over the 134217728-byte ceiling`. The port writes no file on
  either path, and a delta that an earlier run wrote at the same location
  stays as it was. The tool writes the superblock, 140,007,544 bytes for one
  140 MB file, and applies it;
- the part files an earlier delta left at the repository location. The tool
  never removes a part file when it writes a delta again: a 13-part delta
  written again with `--inline` keeps `0` to `12` beside the new superblock,
  and one written again as 3 parts keeps `3` to `12`. The port removes every
  numbered part file the new superblock does not name, all of them under
  `--inline`. A reader takes the parts the superblock names, so the objects a
  delta delivers are the same. Under `--filename` and `--output-dir` neither
  removes a file;

- the `usize` of a part's meta-entry. This difference is open. The port's
  generator counts the target length of each symlink the part carries, and the
  tool's generator does not. A from-scratch part holds a 300,000-byte file, a
  6-byte file, a symlink with the 1-byte target `a`, and two metadata
  objects. For this part, the tool's generator reports `usize=300129` and the
  port's reports `usize=300130`. The objects the delta produces are the
  same. The port's application reads no `usize`, and `show` prints the value
  the superblock holds. The port's generator keeps its rule until a change to
  it is decided;
- the part boundaries. This difference is open. Both generators start a new
  part where the next object would push the payload past `--max-chunk-size`
  (`../format-reference.md`, "Part packing"). The port decides before it
  appends the object. It adds the content size of the incoming object to the
  data-source blob and the operation stream already in the part. The
  operation bytes of that object, the mode table, the xattr table, and the
  tuple framing are outside the estimate. So a part can pass the ceiling by
  those bytes. The first object of a part goes in with no check. So a spliced
  object larger than the ceiling goes into a part of its own, and that part
  passes the ceiling. The content size is exact for the data of a spliced
  object and an upper bound for a diffed one. A diffed object whose payload
  comes out small thus still closes the part it fits in. This costs one more
  xz stream and one more pair of mode and xattr tables, and the part
  boundaries then differ from the tool's. The delta bytes differ. The objects
  the delta delivers are the same, because a meta-entry names the contents of
  its part;
- the diff-source pairing. The tool pairs a modified content object with the
  object at the same path in the source commit, and skips the pair where the
  two sizes differ by a large ratio (`../format-reference.md`, "Diff-source
  pairing"). The port pairs by path alone and has no size-ratio rule. A pair
  the ratio rule skips costs the port a diff attempt whose result it
  discards, and the object then travels whole, as in the tool. The port
  bounds the diff attempt by the maximum chunk size of its chunker, so an
  unrelated same-path rewrite of a large object is spliced with no suffix
  sort first (`crates/ostrya/src/deltagen.rs`, `BSDIFF_CONTENT_LIMIT`). The pairing decides the size of
  a delta and the delta bytes. The objects that the delta delivers are the
  same. The pairing is the port's own choice, in the same sense as the
  parameters of the chunker;
- signing with a repeated `--keys-file`. This difference is in the bytes of
  the repository, and the port keeps it. The tool signs with the last
  `--keys-file` alone. The port signs with each key of every file, so the
  superblock bytes differ. A `--sign` value beside one `--keys-file` signs
  with both keys in both implementations. `sign` carries the same difference;
- the lines of an spki `--keys-file`. Observed with the `ostree` 2026.1 build
  with OpenSSL on the NixOS development host (`cli-behavior.md`, "CLI output
  formats", `static-delta`, "spki secret key files"). Both read one base64
  secret key on each line, a PKCS#8, a SEC1, or a PKCS#1 DER, with LF or CRLF
  line ends, and refuse an empty line
  and a line that is not base64. These lines and files part:
  - An empty file. The tool writes a superblock whose `ostree.sign.spki`
    entry holds no signature, at exit 0. The port refuses the run at exit 1
    after the block with `error: signature: the key file '<path>' holds no
    key`, and writes no superblock. This difference is in the bytes of the
    repository.
  - A line of two base64 keys with a space between them, and a line with a
    space before or after the key. The tool signs with the first key of the
    line. The port refuses the run at exit 1 after the block with `error:
    signature: the key file '<path>', line <n> holds white space`, and
    writes no superblock.
  - The wording of a refused line. The tool writes `error: openssl: Failed
    to initialize spki key` and leaves part `0`. The port writes `error:
    signature: the key file '<path>', line <n> is empty` or `error:
    signature: the key file '<path>', line <n>: <reason>`, before it writes a
    part. Both exit 1 and write no superblock;
- a signing `--keys-file` that is not a regular file, or that is over 1 MiB
  (1048576 bytes), under each engine. The port reads the file as a key source
  of the library and refuses it at exit 1 after the block with `error:
  signature: the key file '<path>' is not a regular file` or `error:
  signature: the key file '<path>' is over the 1048576-byte ceiling`. It does
  not wait on a fifo. A missing file gives `error: i/o error: No such file or
  directory (os error 2)`. The tool side is not observed;
- the statistics. The tool writes seven or more lines to standard error on
  every run that reaches generation (`cli-behavior.md`, "CLI output
  formats", `static-delta`). The port writes nothing to standard error on
  success. The terminal is outside the compatibility scope;
- a size value outside whole decimal digits, and a value whose byte count is
  past `u64::MAX`. The tool reads `abc` as 0 and accepts `1.5`, `-1`, ` 3`,
  `+3`, and `3x`. `clap` refuses each with `error: invalid value` at exit 1,
  before the repository reads, and nothing is written. `clap` reads every
  option value before the port checks `--set-endianness`, so
  `--set-endianness=q --max-chunk-size=abc` gets the `clap` refusal where the
  tool writes `error: Invalid endianness 'q'`. The port reads each
  `--sign-type` value before `--set-endianness`, so an unknown `--sign-type`
  beside an invalid endianness value gets the refusal of the name. Both exit 1
  and write nothing;
- `--max-chunk-size=0`. The tool writes one object in each part and exits 0.
  The port refuses at exit 1 after the block with `error: invalid format:
  static delta max chunk size must be positive`, and writes nothing;
- an extra positional argument. The tool ignores it, and `clap` refuses it
  with `error: unexpected argument '<value>' found` at exit 1. This is the
  class recorded for `show` and `diff`;
- a `--filename` PATH that is a directory, that ends in `/`, or whose last
  component is `.` or `..` after a directory. The tool writes part `0` and
  then refuses at the rename with `error: renameat(<temp>, <name>):
  <reason>`. The port refuses before it writes a file with `error: i/o error:
  Is a directory (os error 21)`. Both exit 1 after the block. The port reads
  the last component from the bytes of PATH, and it refuses a last component
  that is empty, `.`, or `..`. It refuses a PATH that names a directory, and it
  follows no symlink for this check;
- a `--filename` PATH whose name is a part file name, `0` for example. The
  tool renames the superblock over that part and exits 0, which gives a delta
  that `show` and `apply-offline` refuse. The port refuses at exit 1 after the
  block with `error: invalid format: static delta superblock file name <name>
  is a part file name`, and writes nothing;
- the wording of a missing `--filename` parent. The tool writes `error:
  opendir(<dir>): No such file or directory`, and the port writes the
  library's `error: i/o error:` sentence. Both exit 1 after the block and
  create nothing. A PATH `X/.` where `X` is absent or is not a directory takes
  the same outcome: the tool writes `error: opendir(X): <reason>`, and the
  port writes `error: i/o error: Is a directory (os error 21)`;
- a `--filename` name that is not UTF-8. The tool writes the delta under that
  name and exits 0. The port refuses at exit 1 after the block with `error:
  invalid format: static delta superblock file name <path> is not UTF-8`,
  and writes nothing;
- an empty `--filename` value. The tool prints the block and then `error:
  Invalid 'filename' parameter`. `clap` refuses it with `error: a value is
  required for '--filename <PATH>' but none was supplied` before the block.
  Both exit 1 and write nothing. Standard output differs, since the port
  prints no block;
- the wording of a source commit the repository does not hold, for example
  the default parent in a shallow repository. The tool writes `error: No such
  metadata object <hex>.commit` and leaves an empty delta directory. The port
  writes `error: object not found: Commit <hex>` and creates no directory.
  Both exit 1 after the block, and neither lists a delta;
- a bad signing key. The tool writes the parts and then refuses the key, so it
  leaves part `0` and writes no superblock. Both exit 1 after the block. For
  an ed25519 key, the error line is the same. The other results part as
  follows:
  - The port reads the keys before it writes a part, and it signs the
    superblock before it writes it. So a bad ed25519 or spki key writes no
    file.
  - At a location that holds no delta, neither lists a delta. At a location
    that holds one, both keep the earlier superblock, and the tool also
    rewrites the parts.
  - The tool does not carry the `gpg` engine. The port tests a
    `--sign-type=gpg` key only when it signs, after it writes the parts. A
    failure there writes no superblock. Outside `--inline`, the port removes
    the earlier superblock at the delta location before it writes the first
    part. So that superblock is gone too. Under `--inline`
    the port writes no part, so the earlier superblock and its parts stay;
- an inline `spki` secret key of `--sign`, the class `commit --sign` records
  ("P2", `commit`). The decode parts as there. The tool reports `error:
  openssl: Failed to initialize spki key` after its statistics lines, where
  the port reports its `error: signature: spki secret key:` line after the
  block. Both exit 1 and write no superblock;
- an unknown `--sign-type`. The tool ignores it where no key is given, and
  refuses it with `error: Requested signature type is not implemented` after
  the parts are written where a key is given. The port reads each
  `--sign-type` value as the first step of the command, after the repository
  resolves and before the block, also where no key is given. It refuses the
  name with the same line at exit 1, and writes nothing;
- the engine of each key of `generate`, the rule `commit --sign-type` records
  ("P2", `commit`). This difference is in the bytes of the repository. The
  tool applies the last `--sign-type` to each `--sign` and `--keys-file` key.
  The port gives each key the engine of the nearest `--sign-type` before it,
  and `ed25519` to a key before the first `--sign-type`. The superblock of
  the port then holds the signatures of each engine, the `--sign` keys first;
- a `--sign-type` of `generate` with no key of its own, the rule `commit
  --sign-type` records. The port refuses it at exit 1 before the block, and
  writes nothing. The tool reads `--sign-type` only where a key is given.

The port adds `--output-dir=DIR`, which writes the superblock and the parts to
DIR, `--timestamp`, `--reindex`, `--gpg-homedir`, and `-s` for
`--sign-type`. `-n` reads the repository's superblock also under
`--output-dir`. The port reads an ed25519 `--sign` key with the lenient base64
reader `commit --sign` uses.

`pull` accepts a large set already. Missing: `--cache-dir`, `--dry-run`. The
port adds `--force-copy`, `--sign-verify`, and `--sign-verify-summary`. It also adds the valued forms
`--gpg-verify[=BOOL]` and `--gpg-verify-summary[=BOOL]`, which the tool refuses
with `error: Unknown option --gpg-verify` (or the option as written, value
included) at exit 1. The port's fetcher serves `http` and `https` alone, so a
`file://` remote, which the tool pulls from, reports `error: unsupported: fetch
url scheme file: only http and https are fetched` at exit 1 and writes nothing.
The port reads the remote key `trust=NAME`, and the trust group
`[ex-ostrya trust "NAME"]` then checks the commits of the pull
(`ostrya-config(1)`, "REMOTE KEYS"). The tool keeps the key and ignores it
(`cli-behavior.md`, "Signature verification during a pull").

`pull` and `pull-local` also take the composefs image of each commit that
carries `ostree.composefs.digest.v0`, unless the pull is commit-only or has a
subpath (`format-reference.md`, "The pull over HTTP and over a stream"). A
remote of the tool holds no image and answers 404, and the pull goes on.
`pull-local` copies the image with a reflink or a byte copy and never with a
hardlink. On `pull`, the image adds its bytes to the transferred count of the
statistics line. On `pull-local`, it adds its bytes there only when the pull
reads static deltas, under `--require-static-deltas` or a list of deltas,
because only that pull counts the bytes that it reads. The image adds no
object to a count. A static delta of the port can carry the image in a part.
The pull then stores the image from the part and requests no `.cfs`, a pull
with a subpath included (`format-reference.md`, "The composefs image in a
static delta").

`pull` also fetches the dependencies that field 2 of each pulled commit
names, each at depth 0 and with no ref, unless the pull is commit-only or has a
subpath (`../format-reference.md`, "Dependencies in a pull from a remote"). A
dependency that neither the repository, a localcache repository, nor the
remote holds, a field 2 entry with an empty name or with a checksum that is
not 32 bytes, and a nested dependency fail the pull at exit 1, and the pull
writes no object and no ref. The pull looks for a static delta of each
dependency, from the entry of the same name in the commit that the local ref
names before the pull (`../format-reference.md`, "Static deltas of
dependencies"). The tool fetches no dependency (`cli-behavior.md`, "Related
commits in a pull").

The port adds `--collection=ID`, the pull of the refs of the collection ID
from each remote whose `collection-id` is ID (`format-reference.md`, "The
pull of collection refs"). With it, each operand is a ref of the collection,
and the command takes no REMOTE. `clap` refuses it together with `--url`,
`--mirror`, or `--disable-verify-bindings`. A collection pull always checks
the bindings of each commit. The command reads the `collection-id` key of
each remote, so a value with a malformed escape sequence in any remote fails
the command at exit 1. With no ref operand, a pull in which no candidate
lists a ref of ID fails at exit 1 and writes nothing. The counterpart in the
tool is `find-remotes --pull` ("P3").

The keys `tls-ca-path`, `tls-client-cert-path`, and `tls-client-key-path` of
a remote name TLS files. For each address other than an ssh address, the port
reads at most 1 MiB and one byte of each such file. Under
`tls-permissive=true`, the port does not read `tls-ca-path`. The port reads
the files before the fetcher refuses a `file://` address. A file larger than
1 MiB is refused at exit 1
before any request, and the message names the key and the path: `error:
invalid input: tls-ca-path 'PATH' is over 1 MiB`. A file that cannot be read
is refused with a message that names the key and the path too.

`tls-permissive=true` takes the certificate chain as the server presents it,
and keeps the host name check. The tool was measured on two terms of the key
(`cli-behavior.md`, "HTTP pull surface", "`tls-permissive`"): the host name
check stays, and `tls-ca-path` is ignored. The port follows both. It also
drops the expiry check of the chain, which was not measured: libcurl peer
verification that ignores the CA path also ignores the validity dates.
`ostree.repo-config(5)` states that with the key "any certificate will be
accepted". The port follows the measurement, so it refuses a certificate that
does not name the host of the request.

The port reads the proxy of a pull by the rules of the tool (`cli-behavior.md`,
"HTTP pull surface", "Proxy"). `remote refs` and `remote summary` read it by
the same rules. Two differences stand:

- A `no_proxy` entry that matches the origin host does not exempt the origin
  from the remote `proxy` key. In the port, a pull through the key reaches each
  origin through the proxy that the key names.
- The port checks each proxy variable that it reads for white space at the
  start or the end, when it builds the fetcher. The tool checks only the
  variable that a request uses. So the port refuses a padded variable that the
  request does not use: a padded `http_proxy` that `no_proxy` exempts, a
  padded `https_proxy` or `HTTPS_PROXY` for an `http` origin, and a padded
  `all_proxy` beside a clean `http_proxy`. A padded `ALL_PROXY` beside a clean
  `all_proxy` and a padded `HTTP_PROXY` fail the pull in neither. The message
  of the port names the variable and holds no part of the value. The tool
  writes `[5] Could not resolve proxy name`.

The port also pulls over ssh, which the tool does not do. The address of a
pull is `--url`, then the `pull-url` key of the remote, then its `url` key. A
value that starts with `ssh://`, or that holds no `://`, is an ssh address.
A value that starts with `s3://` is the address of a bucket repository
("Bucket repositories"). Any other value goes to the fetcher as written. For an ssh address, `pull`
runs the ssh client with the remote command `ostrya send --repo='PATH'`
(`send`). `pull` has no option for the ssh command or for the remote
command: the `OSTRYA_SSH_COMMAND` environment variable, and then the
`ssh-command` key of the remote, give the ssh command, and the
`send-command` key gives the remote command. `ostrya-config(1)`, "REMOTE
KEYS", states the keys. A remote with `pull-url` and no `url` pulls in the
port. The tool fails on such a remote: `pull`, `remote list -u`,
`remote show-url`, `remote refs`, and `remote summary` each exit 1 with
`error: No "url" option in remote "NAME"`, and `remote list` exits 0. Over
ssh:

- `--http-header`, `--network-retries` with a value above 0,
  `--low-speed-limit-bytes`, and `--low-speed-time-seconds` are refused at
  exit 1 before the ssh client starts. The message names the option without
  `--`: `error: invalid input: http-header applies to a pull over HTTP, and
  'ADDRESS' is an ssh address`. `ADDRESS` is the address in the `ssh://`
  form with no user. `--disable-retry-on-network-errors` is
  accepted, because a pull over ssh never sends a request again.
- The pull reads no `tls-*` key, no `contenturl` key, no `metalink` key,
  and no `proxy` key of the remote. A pull over HTTP reads neither
  `ssh-command` nor `send-command`.
- An ssh address in the `url` key is refused at exit 1, and no ssh client
  starts: `error: pull: remote 'NAME': url 'SHOWN' is an ssh address; the
  port reads an ssh address from pull-url alone`. `SHOWN` is the value
  without the text up to its last `@`. The tool refuses the same `url` in
  `pull`, `remote refs`, and `remote summary` with `error: Invalid URI scheme
  in VALUE`, where `VALUE` is the value, and makes no `connect` call. A
  scp-form `url` such as `h:/srv/repo` gets the same refusal from `pull`.
  `remote list -u` prints the `url` at exit 0.
- A malformed ssh address in `--url` or in `pull-url` is refused at exit 1
  with the text of the address parser, for example `error: invalid input:
  address 'ssh://HOST': an ssh:// address needs a path`.
- The statistics line has the form of the line of a pull over HTTP.

`--url` with an ssh address is a divergence. Observed with `ostree` 2026.1 on
2026-10-04, in a `bare-user` repository with the remote `origin` at
`http://127.0.0.1:1/`: `ostree pull --url=ssh://localhost/x origin main` and
`ostree pull --url=localhost:/x origin main` each write nothing to standard
output, write `error: Invalid URI scheme in VALUE` to standard error, and
exit 1. Under `strace -f -e trace=%network,execve`, neither makes a `connect`
call, and the one `execve` is that of `ostree`. The port pulls over ssh from
both values. A value with no `://` that the parser refuses, such as
`--url=/srv/repo`, is refused with `error: invalid input: address
'/srv/repo': not an address`. A scp-form value such as `--url=host:8080` is
an ssh address of the host `host` and the path `8080`, and the port starts
the ssh client.

`--network-retries=N`, `--disable-retry-on-network-errors`,
`--low-speed-limit-bytes=N`, and `--low-speed-time-seconds=N` make the requests
the tool makes, counted per object against a server that answers 503, cuts a
body, or sends a body slowly:

- a retryable failure, a 503 among them, is repeated up to the
  `--network-retries` count, 5 by default, so an object that keeps failing is
  asked for six times. A 404 is not repeated;
- a body that fails in transit is fetched again from its first byte, and each
  refetch spends one repeat of the same count. A cut connection, a peer that
  stays silent, and a transfer below the low-speed rate each fail a body in
  transit. A body the port refuses for its content, a checksum mismatch among
  them, is not fetched again;
- `--disable-retry-on-network-errors` sets the count to zero, whatever
  `--network-retries` says and in either order;
- every transfer is held to a low-speed rule. The rate is sampled once a
  second, as the bytes of the last five seconds divided by five, and a
  transfer whose rate stays at or below the limit for the time without a break
  fails, as a retryable failure. A sample above the limit starts the count
  again, so bursts whose rate stays above the limit complete, though a
  whole second carries no byte. The default is 1000 bytes per second for 30
  seconds, and it applies to a pull that names neither option. A 0 in either
  option turns the rule off, and a negative value keeps the default of that
  option. `cli-behavior.md`, "CLI output formats", `pull`, gives the
  rule and the measurements.

The two low-speed values are read as a C `int` with the reader of `commit
--owner-uid`, and a value that reader refuses reports the same messages, ahead
of the repository (`cli-behavior.md`, "CLI output formats", `pull`, "The
low-speed options"). Five differences stand:

- an object that exhausts its retries. The port ends the pull at the first such
  object and drops the transfers still in flight. It writes no object and no
  ref, and it removes the commit's `state/<commit>.commitpartial` marker. Its
  staging directory goes with the transaction; where the removal races a write
  still in flight, the directory stays for the next transaction to reap. The
  tool lets the other transfers
  finish. It writes no object and no ref either, and it keeps what it fetched
  in a staging directory under `tmp/`, with the marker in place. A remote of
  one commit and six content objects, with a 503 on one object and
  `--network-retries=0`, shows this: the tool's staging directory holds the
  commit, its dirtrees and dirmeta, and every other content object;
- the timing of a repeat. The port waits 250 milliseconds before the first
  repeat, and doubles the wait up to two seconds, where the tool repeats at
  once. A refetch starts again at the first mirror. These change how long a
  failing pull takes, and no byte the pull writes;
- where the low-speed rule starts to measure a body. The tool measures one
  rate from the start of the request, the wait for the response head included.
  The port measures the head alone, with the same rule, and then measures the
  body from its first read, from zero bytes. A head that arrives late thus
  lowers the tool's rate of the body, and not the port's. A body slow enough
  that the tool abandons it can complete in the port where its head took part
  of the time. The port never abandons a transfer the tool completes for this
  reason;
- when the low-speed rule samples a body. The port takes a sample one second
  after the previous one, and only while a read waits for bytes: a pause of the
  consumer between two reads counts as one second, however long it is. The
  pull reads each body without a pause other than its writes to disk. The
  tool's samples fall at moments of its own. A burst that arrives within the
  timing noise of a sample can thus count in different samples of the two,
  and where that sample decides whether the rate is above the limit, the
  outcome can differ. The measured cases in `cli-behavior.md`, "CLI
  output formats", `pull`, have bursts away from the sample moments, and the
  port abandons each at the second the tool does, or completes each where the
  tool does;
- the message of a transfer that the low-speed rule fails. The tool writes
  `error: While fetching <url>: [28] Timeout was reached`. The port writes
  `error: i/o error: fetched body averaged below <limit> bytes per second for
  <time>` for a body. It writes `error: fetch: <url>: transfer below <limit>
  bytes per second for <time>` for a response head. Both exit 1 and write no
  ref.

`--disable-fsync` turns off every sync of the pull, and `--per-object-fsync`
syncs the file of each content object the pull stages and no metadata object,
as in the tool. `[core] fsync=false` and `--disable-fsync` each win over
`--per-object-fsync`. Neither switch changes a byte the pull writes, and
`cli-behavior.md`, "The fsync vocabulary", "Sync counts of a pull", gives
the counts. A configured `[core] fsync` or `[core] per-object-fsync` value the
reader refuses is refused at exit 1 under every state of the two switches, in
both. Three differences stand:

- syncs by default. The port syncs `refs/remotes/<remote>`, which holds the
  ref, and `refs/remotes`, where the ref write creates `refs/remotes/<remote>`.
  A later pull from the same remote syncs `refs/remotes/<remote>` alone. Under
  `--mirror` the port also syncs the summary file and the repository root. The
  tool makes none of these syncs. The count over corpus `C0` is 13 in the port
  and 11 in the tool, and 14 and 11 under `--mirror`. For a pulled commit that
  carries detached metadata, the port syncs the fanout directory of the
  `.commitmeta` file after the rename into `objects/`, which the tool does not,
  and neither syncs the file itself: 14 in the port and 11 in the tool, and 15
  and 11 under `--mirror`. `--disable-fsync` turns every one of them off;
- a value given to either switch. The tool reads and discards an `=VALUE`
  suffix, so `--disable-fsync=false` disables fsync and
  `--per-object-fsync=bogus` is accepted. `clap` refuses the suffix with
  `error: unexpected value '<value>' for '<switch>' found; no more were
  expected` at exit 1, and the port writes no object and no ref. The open
  decision on a value given to a switch covers it;
- a repeated switch. The tool takes a second `--disable-fsync` or
  `--per-object-fsync`; the port refuses it with `error: the argument
  '<switch>' cannot be used multiple times` at exit 1. This is the
  repeated-boolean-flag class.

`--subpath=PATH`, repeatable, fetches the part of each commit's tree the rules
in `cli-behavior.md`, "HTTP pull surface", "The subpath option", state, and
the port leaves the same objects, the same ref, and the same zero-length
`state/<commit>.commitpartial` marker as the tool for each form: a directory, a
file, a name the tree does not hold, `/`, a trailing `/`, an empty or a `.` or
`..` component, several values, and each under `--depth`,
`--commit-metadata-only`, and `--mirror`, into `archive` and `bare-user`. A
later pull without the option completes the commit and removes the marker in
both. Into `bare-user` both apply a delta whole for a commit the destination
does not hold and keep the marker. Into `archive` both take no delta and fetch
the subpath loose. Into `bare-user` a destination whose ref names the commit it
holds partial leaves an advertised from-scratch delta alone and fetches loose,
and where the remote serves no summary both ask for that delta by name and apply
it whole. `--untrusted` changes no byte of an HTTP pull in either, and a corrupt
object fails the pull with and without it. Four differences stand:

- a relative or an empty value. The tool ends on an assertion
  (`ostree_repo_pull_with_options: assertion 'dir_to_pull[0] == '/'' failed`,
  `SIGABRT`, exit 134 from a shell) and writes nothing. The port refuses the
  value with `error: pull: subpath '<value>' is not an absolute path` at exit 1
  before the first request, and writes nothing;
- one dirtree reached at two positions, which is two directories of identical
  content. The tool walks it once, under the first walk to reach it, so what
  it fetches under the dirtree follows the order its fetches complete in: with
  `/other/x/` beside `/sub/x` it fetched the file of `x` over one server and not
  over another. The port walks it under every position that reaches it, so it
  fetches what each value names whatever the order;
- `--http-trusted`. The tool skips the checksum check under `--mirror` into an
  `archive` destination: it stores a corrupt `.filez`, writes the ref, and
  exits 0, and a later `fsck` fails. The port accepts the switch and checks
  every object all the same, so it refuses that object at exit 1 and writes no
  object and no ref. Elsewhere both refuse the object;
- a value given to `--untrusted` or `--http-trusted`, and a repeat of either.
  The tool reads and discards an `=VALUE` suffix and takes a repeat. `clap`
  refuses both at exit 1, and the port writes no object and no ref. The open
  decisions on a value given to a switch and on a repeated boolean flag cover
  it.

A `--depth` below `-1` is refused in both, by different exit paths. The tool
ends on an assertion (`ostree_repo_pull_with_options: assertion
'pull_data->maxdepth >= -1' failed`, `SIGABRT`, exit 134 from a shell). The
port refuses the value with `error: invalid input: depth <depth> is below -1`
at exit 1. Both stop before the first request, and neither writes an object
or a ref (`cli-behavior.md`, "HTTP pull surface", "Depth less than -1").

`--untrusted` over a `file://` remote changes what the tool does; the port
fetches no `file://` remote. Under `--require-static-deltas` into `archive`
the tool refuses with `error: Can't use static deltas in an archive repo`, and
the port takes the delta, with or without `--subpath`. This is a capability
difference: the delta applier of the port writes each object through the
content writer of the transaction, which stores the object in the form that
the destination mode needs.

The tool cannot pull a signed delta. A from-scratch delta and a from-to delta
that `static-delta generate --sign` signed both fail a pull of the tool with
`error: Invalid checksum of length 0 expected 32`. The pull fails with
verification configured and with verification off (`cli-behavior.md`,
"Signature verification during a pull", "Static deltas and signatures").

The port verifies the fetched delta of a target or of a step of a chain
with the sign-api engines that the commit policy names, before it requests a
part. It applies such a delta that a trusted key signed, and refuses such a
delta that another key signed. It accepts such a delta with no signature
under those engines. The summary advertisement names the superblock, the
superblock names what the delta writes, and the pull checks the commit that
the delta delivers as it checks the target or the commit of the chain. So a
delta with its signature removed gets nothing past the checks.

The port verifies no superblock of the delta of a dependency. Field 2 of the
signed commit names the dependency by its checksum, and the superblock gives
that commit.

The port checks a commit that a delta delivers against the `.commitmeta` that
the pull fetches and stores, which is the metadata that a later verify of the
stored commit reads. The tool checks it against the copy of the detached
metadata in the superblock (`../format-reference.md`, "Superblock fields").
So a delta that was generated before its commit was signed again fails a tool
pull that the current `.commitmeta` satisfies. The port writes the copy when
it generates a delta, so a tool pull that verifies accepts a delta that the
port generated for a signed commit.

`--require-static-deltas` refuses where the tool refuses
(`cli-behavior.md`, "HTTP pull surface", "Delta selection in a pull"): a
remote with no summary, and a commit the destination does not hold for which no
advertised delta can be taken, with the tool's words behind `pull: `. Where the
superblock of the delta taken is absent, the tool writes the checksum of the
start commit of the delta in place of `<ref>`. For a from-scratch delta it
writes `(null)`, and the port writes the ref name in both cases. Both take a
from-to delta from any commit the destination holds complete, under a ref or
not. Two differences stand:

- both delta switches together. The tool ends on an assertion (`SIGABRT`,
  exit 134 from a shell) and writes nothing. `clap` refuses the pair with
  `error: the argument '--require-static-deltas' cannot be used with
  '--disable-static-deltas'` at exit 1, and the port writes nothing. The
  library keeps `disable_static_deltas` in charge where a caller sets both;
- a ref naming a commit other than the target that the destination holds
  partial, or a commit it does not hold. The tool leaves an advertised
  from-scratch delta alone and fetches loose, and the port takes the delta.
  Both land the same objects, and neither refuses.

The requirement also applies to each dependency that the port fetches and
that the destination does not hold complete. A dependency with no delta fails
the pull at exit 1 with `error: pull: Static deltas required, but none found
for <name> of <ref> to <checksum>`, where `<name>` is the name of the field 2
entry, and the pull writes no ref (`../format-reference.md`, "Static deltas
of dependencies", which also gives the rule of `<name>` and `<ref>`). The
tool fetches no dependency, so it has no such refusal.

A pull that returns an error removes the `state/<commit>.commitpartial` marker
of each commit it marked whose commit object the destination does not hold, a
marker it found in place included, and keeps the marker of a commit the
destination holds. In the tool, a pull that fails part way leaves its
zero-length marker in place.

The port requests the remote `config` in every pull, with or without a
summary, and parses the whole file as a repository config. It refuses a
`config` with no `[core]` group, with `repo_version` absent or other than `1`,
with no `mode` key, with an unknown mode, or that does not parse, and a mode
that is not an archive mode. It reads a `config` that answers 404 as an
archive repository. The tool requests `config` only after a summary arrives
and reads `[core] mode` alone: it proceeds with `repo_version` absent, `0`,
`2`, and `abc`, it fails the pull on a `config` that answers 404, and with no
summary it pulls from an archive remote whose `config` does not parse or
states `mode=bare-user` (`cli-behavior.md`, "HTTP pull surface", "The remote
config"). No test covers the port's refusal; the code is `check_remote_mode` in
`crates/ostrya/src/pull/http.rs` and `RepoConfig::from_keyfile` in
`crates/ostrya/src/config.rs`.

The statistics line a pull prints to a pipe takes the tool's forms, words, and
counts (`cli-behavior.md`, "CLI output formats", `pull`), and
`--update-frequency=FREQUENCY` is read with the reader and the messages of the
low-speed values. The same line agrees for a loose pull into `bare-user`, a
repeat pull into `archive` that reads no body byte, a delta pull into
`bare-user`, and `pull-local` between the modes the port imports. Six
differences stand:

- a pull into `archive`, loose or by a delta. From a remote whose summary
  states `ostree.summary.indexed-deltas: true`, the tool asks for no delta
  index into `archive`, and the port asks for it and counts it in `M`. This
  holds also when the remote publishes no delta and the index gets 404. For
  a commit of four metadata objects the port prints `5 metadata` over HTTP
  and over ssh, where the tool prints `4 metadata` over HTTP (observed with
  `ostree` 2026.1 on 2026-10-04). Into `bare-user` both ask for the index
  and count it. From a remote with no summary the port asks for the
  superblock by name into `archive` and counts it in the same way, where the
  tool asks for none. From a remote that publishes a delta the port takes it
  into `archive`, as the capability difference above states, and prints the
  delta form where the tool prints the loose form and a nonzero written
  figure;
- the delta index on a repeat pull. Into a destination other than `archive`,
  the tool asks for the delta index again for a commit it holds complete, and
  counts it: `1 metadata, 0 content objects fetched`. The port asks for no
  delta for a commit it holds complete and prints `0 metadata`;
- the body of an error answer. The tool adds the body of a 404 to `T`, and
  the port adds the bodies of successful answers alone. Against a server that
  answers 404 with an empty body the two agree;
- one pull that reaches the same objects by a loose walk and by a delta part.
  Where a delta carries one ref and the tree of a second ref pulled loose in
  the same run shares objects with it, the loose count and the written figure
  change from run to run in both. In the port the objects the walk fetches
  depend on which of its concurrent steps stores each shared object first.
  Over one such remote into `bare-user` the tool printed `7 loose fetched` in
  seven of eight runs and `8` in one, each with `0 bytes content written`,
  and the port printed `8` or `9`, with `0 bytes`, `3 bytes`, or `5 bytes`.
  The port keeps its own walk order and concurrency;
- `pull-local` from `bare-user` into `bare-user-only`. The tool hardlinks each
  object and prints `0 bytes content written`. The port writes each object
  afresh where it accepts it, as the `pull-local` paragraph below states, and
  counts its payload;
- the terminal progress line. The port pads each line to 80 bytes and does not
  read the terminal width, where the tool pads to the width counted in bytes.
  The port counts its progress totals over the units of work its own walk
  handles, so the percentages, the moments the form changes, and the moment
  its rate replaces `-/s` are its own. It always ends on the statistics line,
  where the tool at a redraw interval of a few milliseconds was seen to end on
  a progress line. `pull-local` writes no progress line in the port. The port
  writes the progress line by these rules:
  - The port writes the escape sequences and the three forms of the progress
    text that `cli-behavior.md`, "CLI output formats", `pull`, "The pull
    progress line", states.
  - The port writes `ESC 7` with its first redraw, or with the last line when
    the pull ends before the first redraw. So a pull that draws no progress
    line writes the bytes that the tool writes.
  - The rate of the port is the bytes transferred over the whole time of the
    pull. The rate reads `-/s` until one whole second passes.

`pull-local` accepts `--repo`, `--remote`, `--depth`, `--commit-metadata-only`,
`--untrusted`, `--bareuseronly-files`, `--disable-verify-bindings`,
`--disable-fsync`, `--per-object-fsync`, `--gpg-verify`,
`--gpg-verify-summary`, `--require-static-deltas`, `--disable-static-deltas`,
and the port extensions `--force-copy`, `-L/--localcache-repo`,
`--sign-verify`, `--sign-verify-summary`, `--no-gpg-verify`,
`--no-gpg-verify-summary`, `--no-sign-verify`, `--no-sign-verify-summary`, and
`--trust`. `--sign-verify` checks the commits and `--sign-verify-summary`
checks the summary of the source. Each one selects each engine of the build, as
`--sign-verify` of `pull` does, and takes no value. Each `--no-` switch turns
off one verification key of the remote that `--remote` names, and conflicts
with its positive switch. `--trust=NAME` takes the keys of the commits from the
trust group `[ex-ostrya trust "NAME"]`, and wins over the key `trust` of the
remote. It needs no `--remote`. Without `--remote`, the pull checks no
summary. The port refuses `--trust` together with `--gpg-verify` or
`--sign-verify` at exit 1, and refuses a name that names no group at exit 1
before it reads a ref or an object of the source. The two sign switches,
`--no-gpg-verify-summary`, and `--no-sign-verify-summary` need `--remote`.
`--no-gpg-verify` and `--no-sign-verify` need `--remote` or `--trust`. `clap`
refuses a sign switch or a `--no-` switch with no such option, a sign switch
with a value, and a switch together with its `--no-` switch at exit 1. The tool
refuses each of these seven options with `error: Unknown option <option>` at exit 1. The two durability switches follow the `pull` paragraph above. An
object hardlinked from the source is not synced, in both, so from `archive`
into `archive` `--per-object-fsync` adds no call. The same three differences
stand, with `refs/heads` in place of `refs/remotes/<remote>` and no summary:
the count over corpus `C0` is 12 in the port and 11 in the tool, and 13 and 11
for a commit that carries detached metadata. `pull-local` takes neither
`--subpath` nor `--http-trusted` in either: the tool reports `error: Unknown
option <option>` at exit 1, and `clap` refuses the option at exit 1. The
library's local pull refuses a subpath with `unsupported: a local pull takes no
subpath`. A `--depth` below `-1` is refused in both, as on `pull`: the tool
ends on the same assertion (`SIGABRT`, exit 134 from a shell), and the port
refuses the value at exit 1. The port opens the source repository and each
`--localcache-repo` first, and refuses the value before it reads a ref or an
object of the source. Neither writes an object or a ref.

The two GPG switches check what the tool checks and refuse where it refuses
(`cli-behavior.md`, "Signature verification during a pull"), with the
port's own words. `--require-static-deltas` applies the delta the source's
summary advertises, with the objects, the refs, and the statistics line of the
tool, and refuses where the tool refuses (`cli-behavior.md`, "HTTP pull
surface", "Static deltas over pull-local"). `--disable-static-deltas` changes
nothing, since `pull-local` reads no delta by default. Ten differences stand:

- the verification keys of the remote. The port reads `gpg-verify`,
  `gpg-verify-summary`, `sign-verify`, `sign-verify-summary`, and `trust` of
  the `[remote "NAME"]` group that `--remote` names, as `pull` does. A name
  with no group gives no check. The tool reads none of these keys, and makes
  only the checks that its switches ask for. So over an unsigned commit, a
  group with `sign-verify=ed25519` and a trusted key, a group that leaves
  `gpg-verify` at its default, or a group with `trust=NAME` and a trust group
  that checks the commits, makes the port refuse the commit that the tool
  imports. The port writes no object and no ref;
- a value given to a GPG switch. The tool reads and discards the value, so
  `--gpg-verify=false` turns the check on. The port's `pull-local` takes both
  switches with no value, and `clap` refuses the suffix at exit 1. The port
  writes no object and no ref. The valued form stays on `pull`, where it reads
  the value;
- a delta into `archive`. The tool refuses with `error: Can't use static
  deltas in an archive repo`, and the port applies the delta, as it does over
  HTTP. The tool's `fsck` accepts what the port wrote;
- both delta switches together, as on `pull`;
- the delta index on a repeat pull, as on `pull`. Under
  `--require-static-deltas`, the tool reads the index again on a repeat pull
  of a commit that the destination holds, and prints `1 metadata`. The port
  reads no delta for a commit that the destination holds complete, and prints
  `0 metadata`, as it does over HTTP;
- the parents `--depth` reaches, as a loose walk and a delta part reaching
  the same objects on `pull`. With the from-scratch delta of a commit and its
  parent at `--depth=1`, the tool printed `6 loose fetched` and the port
  prints `4 loose fetched`;
- an import into a repository that seals its objects. Into a repository that
  holds `[ex-integrity] fsverity=yes`, the tool (built with `ex-fsverity`)
  hardlinks the objects of the source and seals none of them. A
  commit into the same repository is sealed. fs-verity is a property of the
  inode, so a seal of a hardlinked object also seals the copy in the source
  repository. The port links no object into a repository whose `fsverity` is
  not `no`. It copies each object and seals the copy
  (`../format-reference.md`, "Write path: fs-verity (ex-integrity)"). A
  repository that is sealed in part keeps its integrity guarantee only for the
  objects that it wrote itself. The object bytes agree;
- an import from `bare-user` into `bare-user-only`. The tool hardlinks each
  content object, whatever its mode and owner. The destination then shares an
  inode whose mode and `user.ostreemeta` xattr `bare-user-only` does not
  describe, and `ostree fsck` of the destination reports the imported object
  corrupt. The port copies the payload onto a new inode with the canonical
  mode and no xattr. It refuses an object whose logical header is not in the
  canonical form of `bare-user-only` -- a non-zero uid or gid, an xattr, or a
  regular-file mode with bits outside `0755` -- because the object would get a
  name that its stored form does not hash to. What the port imports passes its
  own `fsck` and the `fsck` of the tool;
- the dependencies of a commit. The port imports the dependencies that field
  2 of each pulled commit names, each at depth 0 and with no ref, unless the
  pull is commit-only (`../format-reference.md`, "Dependencies in a local
  pull"). A dependency that neither the source, a localcache repository, nor
  the destination holds, a field 2 entry with an empty name or with a
  checksum that is not 32 bytes, and a nested dependency fail the pull at
  exit 1, and the pull writes no object and no ref. Under
  `--require-static-deltas`, the port also looks for a delta of each
  dependency, and a dependency with no delta fails the pull at exit 1 before
  it writes an object (`../format-reference.md`, "Static deltas of
  dependencies"). The tool imports no dependency (`cli-behavior.md`,
  "Related commits in a pull");
- a `--remote=REMOTE` that is not a valid remote name, such as `../x`. The
  port refuses it at exit 1 with `error: invalid input: invalid remote name:
  REMOTE`, before it reads a ref or an object of the source. It reads no
  keyring, and writes no object and no ref. The `ostree` 2026.1 tool copies
  the objects of the commit into a staging directory under `tmp/` and writes
  a `.commitpartial` marker under `state/`. It then refuses with `error:
  Invalid refspec REMOTE:REF` at exit 1. It writes no object under
  `objects/` and no ref, and leaves the staging directory and the marker.
  With `--gpg-verify` over a signed commit, the tool refuses with `error:
  Commit CHECKSUM: Remote "REMOTE" not found` at exit 1 when the config holds
  no section of that name. When the config holds a section of that name, the
  tool verifies the commit with `<repo>/REMOTE.trustedkeys.gpg`, so a name
  such as `../x` reads a keyring outside the repository. The tool then
  refuses the refspec.

`sign` accepts the tool option set except `-d/--delete`, and adds
`--gpg-homedir`, `--remote`, and the `gpg` engine. The `ostree` 2026.1 build
with OpenSSL on the NixOS development host carries `-s spki` in signing and
`--verify`. A tool build without the features `openssl` and `sign-spki`
refuses `-s spki` in each with `error: Requested signature type is not
implemented` at exit 1. Each key takes the engine of the nearest `-s` before
it ("the engine of each key" below). Under `-s gpg` each `--keys-file` of a
verify is a keyring, and every keyring given is read; a gpg signing run
refuses `--keys-file`. A gpg verify refuses a `--keys-file` that names no
regular file at exit 1 with `File object '<path>' is not a regular file`, the
refusal that the ed25519 and spki engines give for their last `--keys-file`.
Under `ed25519` and `spki`, `--verify` reads the key sources of `static-delta
verify`: the positionals and the last `--keys-file` of the engine, the key
directories, an empty `--keys-dir` naming the working directory, and the
trusted keys judged before revocation (`cli-behavior.md`, "CLI output
formats", `static-delta`, "Key sources"). The port refuses a `--keys-dir`
beside a positional or a `--keys-file` (an item below). Over a commit either
implementation signed, the verdict and the exit status agree for the other
rules where one `--keys-dir` is given, and so do the refusals `File
object '<path>' is not a regular file` and `no valid keys in file '<path>'` of
`ed25519`, byte for byte. Under `spki`, a `--keys-file` and each key-store file
hold PEM `PUBLIC KEY` blocks, the form that the `ostree` 2026.1 build with
OpenSSL on the NixOS development host reads. The key-file entries under
`static-delta` above, the spki entries included, also hold for `sign --verify`.
Under `spki`, a signing `--keys-file` holds PEM `PRIVATE KEY` blocks, each a
PKCS#8 DER, and each block adds one signature. Twenty-six differences stand.

- the verdict report. The exit status agrees. The two reports part as
  follows:
  - The tool writes one line on success, `ed25519: Signature verified
    successfully with key '<hex>'`, naming the key that verified. On failure
    it writes nothing to standard output and one `error:` line: `No valid
    signatures found` where the keys are positionals alone, over a signed
    commit and over an unsigned one. Where a keys file or a key store supplies
    keys, the line is `ed25519: commit have no signatures of my type` over a
    commit with no signature of the engine, `ed25519: no signatures found`
    over a signed commit where every trusted key of the store is revoked, and
    `ed25519: Signature couldn't be verified with: key '<hex>'; ...` over a
    signed commit where no key verifies.
  - The port writes one line for each signature: `signature <n>: good`,
    `signature <n>: no public key`, or `signature <n>: BAD`. It then writes
    `verification OK` at exit 0 or `verification FAILED` at exit 1. A commit
    with no signature of the engine gives `no signatures found` at exit 1. All
    of these lines go to standard output. The port's `summary --verify` and
    its gpg engine write the same report.
  - Under the gpg engine of the port, a line also has ` key <fingerprint>`
    where the signature names its key. It has ` (<name> <email>)` where the
    key has a user id. A user id with no address gives ` (<name>)`. A user id
    with an address alone gives ` (<<email>>)`;
- a key that is not a valid key. The tool skips a positional that does not
  decode to 32 bytes with no message, so `COMMIT AAAA P1` verifies at exit 0.
  It also ignores a keys-file line of that kind, a line of whitespace
  included, where another line verifies. The port refuses the run at exit 1
  before verification with `error: Invalid ed25519 public key: Ill-formed
  input: expected 32 bytes, got <n> bytes` and nothing on standard output.
  Where no key verifies, both exit 1. A 64-byte secret key is a key of this
  kind: `--verify COMMIT <secret key>` alone gives `error: No valid
  signatures found` from the tool and the error above with `got 64 bytes`
  from the port;
- a keys-file line that is not UTF-8. The tool decodes a line of the bytes
  `\xff\xfe` followed by a valid key as that key and verifies at exit 0. The
  port decodes a line that is not UTF-8 to no byte and refuses the run with
  the invalid-key error above at exit 1;
- the time the keys file is read. The tool tries the positionals first and
  reads the last `--keys-file` only where no positional verifies, so a missing
  or empty keys file beside a verifying positional is never opened and the run
  verifies at exit 0. The port loads every key source before verification and
  refuses such a file at exit 1 with `File object '<path>' is not a regular
  file` or `no valid keys in file '<path>'`;
- a key-store line of whitespace of two or more bytes. The tool skips it with
  a GLib warning on standard error. The port skips it with no message. Both
  verify with the other keys;
- the engine of each key, the rule `commit --sign-type` records ("P2",
  `commit`). This difference is in the bytes of the repository. The tool
  applies the last `-s` to each KEY-ID and `--keys-file` key, in signing and
  in `--verify`. The port gives each key the engine of the nearest `-s` before
  it, and `ed25519` to a key before the first `-s`. So `sign COMMIT K -s spki`
  signs K with spki in the tool, and the port refuses the run (the next
  item). A signing run of the port signs in the order of the KEY-IDs and then
  of the keys of each `--keys-file`. It builds each signer before the first
  signature, and looks up each gpg key in the GnuPG home directory, so a
  refused key writes no signature. A gpg key that names no secret key gives
  `error: signature: No gpg key found with ID <key> (homedir: <dir>)`;
- a `-s/--sign-type` with no key of its own, the rule `commit --sign-type`
  records. The port refuses it at exit 1 before it reads the commit, in
  signing and in a `--verify` run with a key on the command line, and writes
  nothing. Examples are `sign COMMIT -s gpg` and `sign --verify COMMIT K -s
  spki`, which the tool reads as an spki verify of K. A `--verify` run with no
  key on the command line takes each `-s` as a selection of its engine (the
  item on the engines of a verify below);
- the engines of a `--verify` run. The tool verifies with one engine, the
  engine of the last `-s`. The port verifies with one verifier for each engine
  of the run. It prints the report of each engine, after a line with the
  engine name and a colon where the report has more than one engine. With a
  key on the command line, the engines are the engines of the keys, and each
  engine must have a valid signature. With `--remote`, each engine of the
  remote must have a valid signature. With no key and no `--remote`, the
  engines are the engines that have a trusted key in the key directories, and
  the gpg engine if the GPG system trust holds a certificate. With no `-s`, if
  one of these engines finds a signature, the port skips each engine that finds
  none, and prints nothing for it. Each engine that finds a signature must have
  a valid one. If no engine finds a signature, the port reports each engine and
  exits 1. On a host with keys of two engines, `sign --verify COMMIT` over a
  commit with an ed25519 signature alone then prints the ed25519 report alone
  and exits 0. A `-s ENGINE` with no key selects its engine, and each selected
  engine must have a valid signature. A run that finds no engine is refused at
  exit 1 with `error: signature: no keys loaded: the key directories hold no
  ed25519 or spki key, and the system trust holds no gpg key`
  (`sign/verify-no-keys`), where the tool writes `error: signature: ed25519: no
  keys loaded`. A selected engine with no trusted key is refused with `error:
  signature: <engine>: no keys loaded`. A run that looks for the gpg engine
  reads each keyring of the GPG system trust, and a keyring that cannot be read
  refuses the run at exit 1. A `-s` that selects the other engines does not
  read the GPG system trust;
- the key directories of `--verify`. The tool reads the last `--keys-dir`
  alone, and the system key directories `/etc/ostree` and `/usr/share/ostree`
  where no `--keys-dir` is given (`sign/verify-keys-dir-last-wins`). The port
  reads the system key directories and then each `--keys-dir`, and a revoked
  key of one directory applies to the keys of each directory. The port reads
  `--keys-dir` under each engine of a verify, and the gpg engine reads no key
  directory;
- `--remote` of `--verify`. The tool reads `--remote` only in a verify of its
  gpg engine and adds the keyrings of the remote to its global trusted set.
  The port verifies with the engines that the config of the remote turns on
  for its commits: `gpg-verify` and `sign-verify`, or the trust group that
  the key `trust` names, as a pull reads them. The keys are the keys of the
  remote alone: `<remote>.trustedkeys.gpg` in the repository and in
  `/etc/ostree/remotes.d/`, each `gpgkeypath` entry, and the
  `verification-<engine>-key` and `verification-<engine>-file` keys, or the
  keys of the trust group. The port reads no global GPG trusted directory and
  no system key directory for `--remote`. It refuses a remote with no section,
  a remote whose config turns on no check, and a remote whose config turns on
  the GPG check with no certificate in its keyrings. A `-s` with no key
  selects its engine. The port then reads the keys of the selected engines
  alone, and refuses an engine that the config does not turn on with `error:
  signature: remote '<remote>' turns on no <engine> check of its commits`.
  The port refuses `--remote` at exit 1 in these cases:
  - with a KEY-ID or a `--keys-file`: `error: signature: --remote verifies
    with the keys of the remote; it takes no KEY-ID and no --keys-file`;
  - with a `--keys-dir`: `error: signature: --remote verifies with the keys
    of the remote; it reads no --keys-dir`;
  - without `--verify`: `error: signature: --remote applies to --verify
    alone`;
- `--keys-dir` in a signing run, and in a `--verify` run with a KEY-ID or a
  `--keys-file`. The tool ignores `--keys-dir` in these runs
  (`sign/verify-keys-file-overrides-keys-dir`). The port refuses `--keys-dir`
  in these runs at exit 1, after the refusals of `--remote`, and writes
  nothing:
  - without `--verify`: `error: signature: --keys-dir applies to --verify
    alone`;
  - with a KEY-ID or a `--keys-file`: `error: signature: a KEY-ID or a
    --keys-file gives the keys of the verify; it reads no --keys-dir`. This
    refusal comes before the refusal of a gpg KEY-ID and before the port reads
    a `--keys-file`;
- a gpg KEY-ID in a `--verify` run. The tool reads no KEY-ID in a gpg verify.
  The port refuses it at exit 1 with `error: signature: a gpg verify takes its
  keyrings from --keys-file, --remote, or the system trust; it takes no
  KEY-ID`. The port refuses `--gpg-homedir` in a `--verify` run at exit 1
  with `error: signature: --gpg-homedir applies to signing alone`, before the
  refusals of `--remote` and `--keys-dir`. In a signing run, the port refuses
  `--gpg-homedir` where no key and no `-s` names the gpg engine. The tool has
  no `--gpg-homedir` on `sign`, and refuses it in each run with `error:
  Unknown option --gpg-homedir` at exit 1;
- signing with a repeated `--keys-file`. This difference is in the bytes of
  the repository, and the port keeps it. The tool reads the last
  `--keys-file` when it signs, so `sign COMMIT --keys-file=s1 --keys-file=s2` writes one signature,
  by the key of `s2`. The port reads every file and writes one signature for
  each key, so the `.commitmeta` bytes differ. A positional secret key beside
  one `--keys-file` signs with both keys in both implementations;
- `-d/--delete`. The tool reads a `-d` KEY-ID and each line of its keys file
  as an ed25519 secret key and signs with it: `sign -d COMMIT <secret key>`
  exits 0 and writes the `.commitmeta` bytes `sign COMMIT <secret key>`
  writes, one more signature, over a signed commit and over an unsigned one.
  It refuses a public key with `error: Invalid ed25519 secret key: Ill-formed
  input: expected 64 bytes, got 32 bytes` at exit 1, and with no KEY-ID and
  no `--keys-file` it writes its usage text and `error: Need at least one
  KEY-ID to sign with` (`cli-behavior.md`, "CLI output formats", `sign`,
  "Delete mode"). Under `spki` it signs with a positional secret key and
  with a `PRIVATE KEY` block of a `-d` `--keys-file`. The port has no
  `-d/--delete`: `clap` refuses `-d` and `--delete` with `error: unexpected
  argument '<arg>' found` at exit 1, and the port writes nothing. No command
  of the port removes a signature (`gpg-sign` in "P3");
- a signing `--keys-file` that is not a regular file, an empty
  `--keys-file=` included. With no positional KEY-ID both refuse at exit 1
  and write nothing. The tool writes the GLib warning `Can't open file
  '<path>' with keys` and `error: File object '<path>' is not a regular
  file`. The port reads a signing file as a key source of
  the library: a regular file of at most 1 MiB, with no wait on a
  fifo. It writes `error: i/o error: No such file or directory (os error 2)`
  for a missing file, `error: signature: the key file '<path>' is not a
  regular file` for a directory or a fifo, and `error: signature: the key
  file '<path>' is over the 1048576-byte ceiling` for a larger file. Beside a
  positional secret key, the tool
  writes the warning, signs with the positional key, and exits 0. The port
  refuses at exit 1 and writes nothing;
- an spki signing `--keys-file`. Observed with the `ostree` 2026.1 build with
  OpenSSL on the NixOS development host (`cli-behavior.md`, "CLI output
  formats", `static-delta`, "spki secret key files"). Both read PEM `PRIVATE
  KEY` blocks, ignore the text outside them, and sign once with each block.
  These files part:
  - An empty file, a file of white space only, and a file of one base64
    PKCS#8 line. The tool ends on SIGABRT, exit 134. The port refuses the run
    at exit 1 with `error: signature: the key file '<path>' holds no PEM
    PRIVATE KEY block`.
  - A block that does not decode after a valid block. The tool writes the
    signature of the valid block, then reports `error: Not able to sign the
    cobject: openssl: Failed to initialize spki key` at exit 1. The port reads
    every block before the first signature. It refuses the run at exit 1 with
    an `error: signature: the key file '<path>', line <n>:` line and writes no
    signature. A block of another label gives `error: Unexpected label
    "<label>"` from the tool and the port line `unexpected label "<label>"`,
    and neither writes a signature.
  - A body with a blank line. The tool signs, and the port refuses the file.
    The body rules are those of a `PUBLIC KEY` block under `static-delta`.
  - A positional key beside a refused file. The port writes no signature,
    also for the positional key;
- an spki positional key of `--verify` that is not the base64 of a
  SubjectPublicKeyInfo DER: the base64 of a raw SEC1 point, compressed or
  uncompressed, of the full PEM text, or of a PKCS#8 secret key. Observed
  with the `ostree` 2026.1 build with OpenSSL on the NixOS development host
  (`cli-behavior.md`, "CLI output formats", `static-delta`, "spki inline
  keys"). The tool skips the key with no message. Beside a valid key it
  verifies at exit 0, and alone it reports `error: No valid signatures
  found` at exit 1. The port refuses the run at exit 1 before verification,
  with `error: signature: spki public key: expected SubjectPublicKeyInfo DER`
  and nothing on standard output;
- an inline spki secret key of a signing run, the class `commit --sign`
  records ("P2", `commit`). The decode parts as there. The tool reports
  `error: Not able to sign the cobject: openssl: Failed to initialize spki
  key` where the port reports its `error: signature: spki secret key:` line.
  Both exit 1 and write no signature;
- a signature blob that no trusted key verifies, under `-s spki`. Observed on
  2026-10-24 with the build above. Against one trusted P-256 key, the tool
  verifies at exit 0 a commit whose only spki signature is one of these
  blobs: 64 random bytes, 1 random byte, a valid DER signature with one more
  byte after it, a DER `SEQUENCE` whose second integer is shorter than its
  length field, the fixed-width `r || s` form of a valid signature, and that
  form with one bit changed. 64 random bytes also verify against a P-384, an
  SM2, a DSA, and a sect163k1 key. A commit signed by an untrusted Ed25519,
  Ed448, RSA, RSA-PSS, ML-DSA, or SLH-DSA key verifies against a P-256,
  P-384, secp256k1, SM2, or DSA key. A pull from a remote that trusts a P-256
  key accepts a commit whose only signature is 64 random bytes, and a commit
  signed by an untrusted Ed25519 key. With `sign-verify-summary=true`, the
  same remote accepts a `summary.sig` whose only signature is 64 random
  bytes. A well-formed DER signature with wrong `r` and `s` fails, and 64
  random bytes fail against an Ed25519, an RSA, and an ML-DSA-44 key. The
  port accepts a blob only when a trusted key of the key type of the blob
  verifies it (`format-reference.md`, "Signing details", "spki"). For each
  blob above it writes `signature 1: no public key` and `verification
  FAILED` at exit 1. The pull and the summary verify of the port use the
  same rule;
- an spki key with explicit curve parameters, a `SEQUENCE` in the place of
  the curve OID. Observed on 2026-10-24 with the build above: the tool signs
  with a P-256 key made with `ec_param_enc:explicit`, and verifies the
  signature with its public key. The port refuses such a key in each form, a
  public key, a PKCS#8 key, the `ECPrivateKey` in a PKCS#8 key, and a SEC1
  key, at exit 1 before it signs or verifies. An inline key gives `error:
  signature: spki public key: the EC key has explicit curve parameters` or
  `error: signature: spki secret key: the EC key has explicit curve
  parameters`. A key file and a key-store file give `error: signature: the
  key file '<path>', line <n>: the EC key has explicit curve parameters`, also
  when the other blocks of the file are valid. A line of the `--keys-file` of
  `static-delta generate` gives `error: signature: the key file '<path>', line
  <n>: spki secret key: the EC key has explicit curve parameters`;
- an spki key of a type or on a curve outside the set of the port. Observed
  on 2026-10-24 with the build above: the tool signs and verifies with each
  signature key type of OpenSSL 3.6.4, ECDSA on 85 named curves, SM2,
  Ed25519, Ed448, RSA, RSA-PSS, DSA, ML-DSA, and SLH-DSA. The port takes
  ECDSA on the P-256 and the P-384 curves, Ed25519, and RSA with the key
  type `rsaEncryption`. It
  refuses another key at exit 1 before it signs or verifies, with `error:
  signature: spki public key: the key type <name> is not supported` or
  `error: signature: spki public key: the curve <name> is not supported`,
  and with `spki secret key` for a secret key. `<name>` is a name such as
  `RSASSA-PSS`, `Ed448`, or `P-521`, or the dotted OID. The `ostrya`
  command carries the four key types. A key file and a key-store file give
  the reason after `error:
  signature: the key file '<path>', line <n>: `, also when the other blocks
  of the file are valid. A line of the `--keys-file` of `static-delta
  generate` gives the reason after `error: signature: the key file '<path>',
  line <n>: spki secret key: `. The RSA keys that the port refuses follow;
- an RSA key with a modulus of fewer than 2048 bits or more than 16384 bits.
  Observed on 2026-10-26 with the build above and keys of OpenSSL 3.6.4
  (`cli-behavior.md`, "CLI output formats", `static-delta`, "spki RSA keys"):
  the tool signs and verifies with a 512-bit and a 1024-bit key at exit 0.
  With a 16386-bit key, the tool signs at exit 0, and its verify of the
  signature reports `error: spki: Signature couldn't be verified with: key
  '<hex>'` at exit 1. OpenSSL verifies no signature of a modulus above 16384
  bits. The port refuses such a key, a public key and a secret key, at exit 1
  before it signs or verifies, with the reason `the RSA modulus has <bits>
  bits; the engine takes 2048 to 16384 bits`, in the forms of the entries
  above;
- an RSA secret key of more than two primes. Observed on 2026-10-26 with the
  build above ("spki RSA keys"): the tool signs with a 2048-bit key of 3
  primes, a 4096-bit key of 4 primes, and an 8192-bit key of 5 primes, and
  verifies each signature at exit 0. The port refuses such a secret key, in
  PKCS#8 and in PKCS#1 form, at exit 1 before it signs, with the reason `the
  RSA key has more than two primes`. The port takes the public key of such a
  key, and verifies a signature that the tool makes with it;
- an `rsaEncryption` public key whose parameters are not `NULL`. Observed on
  2026-10-26 with the build above ("spki RSA keys"): the tool verifies a
  signature at exit 0 with an SPKI that has no parameters field, and with an
  SPKI that has an OID in the field. The port refuses such a key at exit 1
  before it verifies, with the reason `the rsaEncryption parameters are not
  NULL`. It refuses a PKCS#8 secret key with such parameters the same way;
- an Ed25519 PKCS#8 secret key of version 2 whose public key is not the
  public key of its seed. Observed on 2026-10-26 with the build above
  (`cli-behavior.md`, "CLI output formats", `static-delta`, "spki Ed25519
  keys"): the tool signs with the seed at exit 0, and the public key of the
  seed verifies the signature. The port compares the 32 bytes of the two
  keys, and refuses such a key at exit 1 before it signs, with the reason
  `the public key of the PKCS#8 key is not the key of its secret key`, in
  the forms of the entries above;
- a PKCS#8 secret key with the `version` 1 (version 2) and no public key.
  Observed on 2026-10-26 with the build above, with an Ed25519 key ("spki
  Ed25519 keys"): the tool signs at exit 0, and the public key of the key
  verifies the signature. The port refuses such a key of each key type at
  exit 1 before it signs. An inline key gives `error: signature: spki secret
  key: expected PKCS#8 DER, SEC1 DER, or PKCS#1 DER`. A key file gives
  `error: signature: the key file '<path>', line <n>: the PRIVATE KEY block
  holds no valid PKCS#8 key`. A PKCS#8 key with the `version` 0 and a public
  key is refused by both.

## P3 -- shell-suite surface with no matrix weight

No matrix cell needs these. The shell suite invokes them.

- `reset` -- reset a ref to an earlier commit.
- `remote add-cookie`, `delete-cookie`, and `list-cookies` -- see the cookie-jar
  note at the end of this section.
- `checksum` -- `--ignore-xattrs`.
- `find-remotes` -- `--cache-dir`, `--disable-fsync`, `--finders=FINDERS`,
  `--pull`, `--mirror`. The port's counterpart of `find-remotes --pull` is
  `pull --collection=ID [REF]...` ("P2", `pull`). It differs from the tool in
  these points:
  - The port reads the candidates from the config alone. It has no
    `--finders`, no mount finder, and no LAN (Avahi) finder.
  - The operands are refs of one collection. The tool takes
    `COLLECTION-ID REF` pairs.
  - The port prints the statistics line of a pull, and one warning line for
    each candidate that it skips.
  - The port has no `--mirror` for a collection pull, and no command that
    finds the remotes and pulls nothing.
- `create-usb` -- `--disable-fsync`, `--destination-repo=DEST`,
  `--commit=COMMIT`.
- `gpg-sign` -- `-d/--delete`, `--gpg-homedir=HOMEDIR`. The port folds GPG
  signing into `sign --sign-type=gpg`, so this is an alias with its own option
  names. `ostree gpg-sign --delete` in 2026.1 removes a GPG signature. No
  command of the port removes a signature, so `--delete` has no counterpart
  in the port. The library keeps `Repo::delete_signatures`.

`remote` landed in Phase 17e: `add`, `delete`, `list`, `show-url`, `refs`,
`summary`, `gpg-import`, and `gpg-list-keys`, with the option set the tool
carries on each and the output formats `cli-behavior.md`, "`remote`",
records. Thirteen divergences stand:

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
- a `verification-spki-key` that is not the base64 of a SubjectPublicKeyInfo
  DER: the base64 of a raw SEC1 point, of the full PEM text, or of a PKCS#8
  secret key. The `ostree` 2026.1 build with OpenSSL on the NixOS development
  host fails each pull with `error: Can't verify commit <checksum>: openssl:
  Failed to initialize spki key` (`cli-behavior.md`, "Signature verification
  during a pull", "The verification keys"). The port refuses each pull at exit 1 before it fetches, with
  `error: signature: spki public key: expected SubjectPublicKeyInfo DER`.
  Both fail also when `verification-spki-file` holds the valid key. A key
  with explicit curve parameters, a key of a type or on a curve outside the
  set of the port, and an RSA key that the port refuses, in
  `verification-spki-key` or
  `verification-spki-file`, refuse each pull of the port the same way, as
  "P2", `sign`, records;
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
  host locale and time zone and the port in UTC. The port writes a `Key:
  <fingerprint>` line, then a `Created:` line and one `UID:` line for each
  user id, each indented by two spaces. Over a keyring that is absent or holds
  no key, both print nothing at exit 0. `remote summary` renders its
  `Timestamp` and `Last-Modified` lines the same way, so a report compares byte
  for byte with `TZ=UTC` set;
- `remote gpg-import` writes a keyring that carries no Trust packet, where the
  tool's own import writes one after the primary key packet, after each user id
  packet, and after each signature packet. A Trust packet holds a GnuPG-local
  trust value and carries no part of a transferable public key: with those
  packets dropped, the tool's keyring holds the packets the port's holds, in the
  same order, measured byte for byte over a key carrying a signing subkey
  (`crates/ostrya-sign/src/gpg/verifier.rs`,
  `the_trust_packets_are_the_whole_difference`).
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
    (`crates/ostrya-sign/src/gpg/verifier.rs`,
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
  replaces the certificate the keyring holds for that key, and the count stays
  `Imported 0 GPG keys`. Two keys sign a revocation the port honors: the key it
  revokes, and a key a verified self-signature of that certificate designates
  as a revoker. The designated-revoker case carries two conditions of its own
  and is recorded under "A revocation another key made" below. Each
  implementation holds a commit signed with `$FPR`, a remote `origin`, and
  `cert1.gpg` imported into that remote:

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
  (`crates/ostrya-sign/src/gpg/verifier.rs`,
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
  (`crates/ostrya-sign/src/gpg/verifier.rs`,
  `an_expiry_extension_replaces_the_held_certificate`,
  `an_earlier_expiry_leaves_the_held_certificate`, and
  `a_revoked_key_takes_no_expiry_replacement`).

  A revocation another key made carries weight where a verified self-signature
  of the revoked certificate designates that key as a revoker through signature
  subpacket 12, and the certificate of that revoker stands in the keyring under
  edit or in the offered stream. Those are the two streams the import reads, so
  one import writes the same bytes on every host. The revoker is resolved among
  every certificate the two streams hold, whatever key each of them states and
  whether or not a `KEY-ID` selector names it: a selector governs what the
  import writes and not what the import knows.

  Two states carry such a revocation into the tool's keyring and not into the
  port's, since the tool merges the offered packets into its keyblock whether
  or not it can verify them:

  - the revoker's certificate stands in the global trusted directory or in a
    `gpgkeypath` entry rather than in either stream. The port writes nothing,
    since the import reads the two streams alone, and the tool merges the
    revocation. Both then report a good signature, for reasons that part: the
    port's keyring states no revocation, and the tool holds one and passes it
    over. Over the keyring the tool's own import wrote, with the revoker's
    certificate in the global trusted directory, the port reports `BAD
    signature from` and the tool `Good signature from`: the port's verify path
    resolves a revoker among every certificate it loads, whichever source
    carried it, and the tool resolves none standing in another keyring source.
    The port is the stricter of the two here;
  - the revoker is absent everywhere when the re-export is offered and is
    imported after. The tool's merged packet then speaks and the port has
    written none, so the port reports `Good signature from` where the tool
    reports `Key revoked`.

  Each implementation holds a commit signed with `$K`, a remote `origin`, and a
  certificate of `$K` designating `$R` imported into that remote. Measured
  against `ostree` 2026.1 and `gpg` 2.4.9:

      gpg --desig-revoke "$K" > rev.asc     # signed with $R's secret key
      gpg --homedir merge --import k.gpg rev.asc   # exits 2, merges the packet
      gpg --homedir merge --export "$K" > revoked.gpg
      # the keyring holds $K and $R
      ostrya remote gpg-import origin --keyring revoked.gpg # Imported 0 GPG keys
      ostree remote gpg-import origin --keyring revoked.gpg # Imported 0 GPG keys
      ostrya show --gpg-verify-remote=origin main   # BAD signature from "..."
      ostree show --gpg-verify-remote=origin main   # Key revoked
      # the keyring holds $K alone, and the offered stream states $R
      cat revoked.gpg r.gpg > offered.gpg
      ostrya remote gpg-import origin --keyring offered.gpg # Imported 1 GPG key
      ostree remote gpg-import origin --keyring offered.gpg # Imported 1 GPG key
      ostrya show --gpg-verify-remote=origin main   # BAD signature from "..."
      ostree show --gpg-verify-remote=origin main   # Key revoked
      # the same offered stream with the selector naming $K alone
      ostrya remote gpg-import origin --keyring offered.gpg "$K"
      ostree remote gpg-import origin --keyring offered.gpg "$K"
      # both Imported 0 GPG keys, both keyrings hold one key and state the
      # revocation, and both report Good signature from "..."
      # $R in the global trusted directory and the keyring holding $K alone
      OSTREE_GPG_HOME=global ostrya remote gpg-import origin         --keyring revoked.gpg                       # Imported 0 GPG keys
      OSTREE_GPG_HOME=global ostree remote gpg-import origin         --keyring revoked.gpg                       # Imported 0 GPG keys
      # both report Good signature from "...", and the port's keyring is the
      # one it held while the tool's grew by the revocation packet
      cp tool/origin.trustedkeys.gpg port/origin.trustedkeys.gpg
      OSTREE_GPG_HOME=global ostrya show --gpg-verify-remote=origin main
      # BAD signature from "...", where the tool over that same keyring and
      # the same global directory reports Good signature from "..."
      # $R absent everywhere, offered, then imported after
      ostrya remote gpg-import origin --keyring revoked.gpg # Imported 0 GPG keys
      ostrya remote gpg-import origin --keyring r.gpg       # Imported 1 GPG key
      ostrya show --gpg-verify-remote=origin main   # Good signature from "..."
      ostree show --gpg-verify-remote=origin main   # Key revoked

  `gpg --desig-revoke` writes the revocation, and `gpg --import` of it exits 2
  while merging the class 0x20 signature into the certificate it holds, whether
  or not the home holds the revoker's certificate
  (`crates/ostrya-cli/tests/cli.rs`,
  `remote_gpg_import_carries_a_designated_revokers_revocation` and
  `remote_gpg_import_leaves_an_unverifiable_revocation_out`).

  Every revocation is verified before it is honored. A key revocation signature
  anyone stapled onto an offered certificate leaves the keyring at the bytes it
  held: one no self-signature designates, and one a designation names whose
  signature does not verify over the certificate it stands on
  (`crates/ostrya-sign/src/gpg/verifier.rs`,
  `a_stapled_revocation_does_not_replace_the_held_certificate`,
  `a_designated_revokers_revocation_replaces_the_held_certificate`,
  `an_offered_revoker_certificate_resolves_the_revocation`, and
  `a_revocation_over_another_key_strikes_out_no_held_key`). Without that rule an
  offered keyring would be a way to strike any trusted key out of a repository,
  since the port's replacement writes the offered packets where the held run
  stood.

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
  (`crates/ostrya-sign/src/gpg/verifier.rs`,
  `an_unframeable_keyring_takes_no_import`).
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
  them ("GPG verification differences", item 3).

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
  of the two whichever one stands first. Those are items 6 and 7 of
  "GPG verification differences";
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
  certificate whose self-signature does not verify;
- a NAME of `remote gpg-import` or `remote gpg-list-keys` that is not a valid
  remote name, such as `../x`, when the config holds a section of that name
  that was written by hand. The tool writes the keyring of the import to
  `<repo>/../x.trustedkeys.gpg`, outside the repository: it writes a
  temporary file beside the repository and renames it. It reports `Imported
  1 GPG key to remote "../x"` at exit 0. `remote gpg-list-keys` reads that
  file and lists its keys at exit 0. A build of the port with the `gpg`
  feature refuses both commands at exit 1 with `error: invalid input:
  invalid remote name: ../x`, before it reads or writes the keyring of the
  remote. `remote gpg-import` first reads and checks the offered keys. A
  build without the `gpg` feature refuses both commands for each name.
  `remote delete ../x` refuses the name in both, with `error: Invalid remote
  name ../x` at exit 1, and removes no file;
- `remote add` with `--sign-verify` and `--no-sign-verify` together. Not
  observed: the answer of the tool to the pair. The port refuses the pair with
  `error: Cannot specify both --sign-verify and --no-sign-verify` at exit 1,
  and writes nothing;
- `remote add --gpg-import=FILE`. Not observed: the answer of the tool to
  `--gpg-import`. The port imports the keys of `FILE` into the keyring of the
  remote after it writes the section, the same way as `remote gpg-import` with
  `--keyring`. It then prints `Imported <n> GPG key to remote "<name>"`, with
  `keys` for each count other than 1. If `--if-not-exists` leaves the section
  in place, the port imports nothing.

Three messages the port words for itself, each reporting a condition the tool
reports through gpgme: `remote gpg-import` with no `--keyring` and no `--stdin`
(the tool's `GPG: Unable to export keys: GPGME: No data`), a `KEY-ID` naming
no key in the source (the tool's `GPG: Unable to find key "<id>": GPGME: End of
file`), and a keyring the certificate parser does not read -- one holding no
OpenPGP packet, one cut short of a packet boundary, and a GnuPG keybox -- which
the tool reports as `GPG: Unable to export keys: GPGME: No data`. Both refuse all
three at exit 1 and write no keyring. For `remote gpg-import` with no
`--keyring` and no `--stdin`, the port writes `error: No keys to import; pass
--keyring or --stdin`.

`--cache-dir`, which the tool's `remote refs` and `remote summary` accept, is not
carried: the port fetches a summary without a cache directory of its own. The
port's fetcher serves `http` and `https` alone, where the tool also reads a
`file://` remote, so a `file://` URL reports `fetch url scheme file: only http
and https are fetched`.

`remote refs` and `remote summary` find the remote by the address rule of
`pull`, with no `--url`: the `pull-url` key, then the `url` key. For an ssh
address they read `summary.sig` and `summary` over ssh from `ostrya send`,
with the ssh command and the remote command of `pull`. For an `s3://`
address they read the two files from the bucket repository with signed
requests, and take the S3 options of `pull` ("Bucket repositories"). The
tool reads `url` alone. `remote summary -u` writes the summary of a bucket
repository, and is a port extension ("Bucket repositories"). The tool has
no `-u` on `remote summary`.

`remote add-cookie`, `remote delete-cookie`, and `remote list-cookies` stay out.
The fetcher refuses a `Cookie` header at construction when a mirror is
cleartext `http`, unless the caller sets
`FetcherOptions::allow_cleartext_credentials`. `pull` takes
`--allow-cleartext-credentials` for an `s3://` address alone, and refuses it
for each other address. `pull --collection` refuses it when a candidate
has an HTTP or an ssh address. So no option of `pull` sets it for an HTTP
remote.
Cookie-jar support needs its own design pass against that refusal.

## GPG verification differences

The port verifies a GPG signature in the process, under its own trust and
validity policy. The rustdoc of `GpgVerifier` and of the module
`gpg::verifier::verify` in `crates/ostrya-sign` states each rule of the
policy, and the `gpgv` 2.4.9 behavior that the rule reproduces.
`crates/ostrya/tests/verify_gpg_agreement.rs` compares the port with `gpgv`
over a fixture matrix, and declares each difference that its fixtures reach.

Seven differences from GnuPG 2.4.9 stand. None of them is a fact of the
repository. Each one can make a verdict of the port part from the verdict of
the tool, in `show`, in a `pull` that verifies, and in the keyring reads of
`remote gpg-import` and `remote gpg-list-keys`.

1. The digest policy. The port refuses MD5 and accepts SHA-1, which are the
   answers of `gpgv` 2.4.9 at its defaults. The port set is fixed. The GnuPG
   set is configurable and changes between versions.
   `gpg --verify --allow-weak-digest-algos <sig> <data>` reports `GOODSIG`
   over an MD5 data signature that the port refuses.
   `gpgv --weak-digest SHA1 --keyring <ring> <sig> <data>` reports
   `ERRSIG ... 5` over a SHA-1 data signature that the port accepts.
2. The GnuPG keybox. The port refuses a keyring file or a keyring blob that
   carries the `KBXf` magic at byte offset 8, and the message names the path
   or the blob. `gpgv --keyring <homedir>/pubring.kbx <sig> <data>` reads the
   keybox and reports `GOODSIG`.
3. A keyring that the parser refuses. The port refuses the whole file if the
   parser refuses the keyring, or if the packet stream of the keyring does not
   frame to its end. A command that reads the file exits non-zero, and the
   message names the keyring. No key of the file gets into the trusted set.
   The tools read such a keyring up to the packet at which they stop, and what
   they trust then depends on the position of that packet:
   - A keyring holds one intact certificate and then 40 bytes of a second
     certificate. `ostree show --gpg-verify-remote=<remote> <ref>` reports
     `Can't check signature: public key not found` and exits 0.
     `gpgv --keyring <keyring> <sig> <data>` reports
     `keyring_get_keyblock: read error: Invalid packet`,
     `keydb_search failed: Invalid keyring`, `ERRSIG ... 9`, and `NO_PUBKEY`,
     and exits 2. Neither tool trusts the intact certificate.
   - A keyring holds one intact certificate and then a second certificate
     whose primary key packet is followed by a Trust packet with an
     indeterminate length. Over a signature of the first certificate, `gpgv`
     reports `GOODSIG` at exit 0. Over a signature of the second certificate,
     it reports `[don't know]: indeterminate length for invalid packet type
     12`, `keydb_search failed: Invalid packet`, `ERRSIG`, and `NO_PUBKEY` at
     exit 2. `gpg --list-keys` over the file lists the first key alone.
     `ostree show --gpg-verify-remote=<remote> <ref>` reports
     `Good signature from "..."` for the first certificate and
     `Can't check signature: public key not found` for the second.
4. The digest of an Ed25519 key. An Ed25519 key or an EdDSA-legacy key with a
   digest of less than 256 bits verifies nothing in the port. So a SHA-1 or a
   SHA-224 data signature of such a key gives the fields of a signature that
   does not verify. The `pgp` crate requires a digest of at least 256 bits for
   this verification (0.20.0, `src/crypto/ed25519.rs`, `MIN_HASH_LEN_BITS`).
   `gpg --digest-algo SHA1 --detach-sign --local-user <ed25519 key>` writes
   such a signature, and `gpgv --keyring <ring> <sig> <data>` reports
   `GOODSIG` over it.
5. The input limits. The port refuses, by name, a stored signature blob over
   1 MiB or with more than 64 signature packets, and a keyring over 4 MiB or
   with more than 256 certificates. `gpgv` reads an input of each of these
   four shapes and reports on it.
6. A revocation in a second certificate of a key. The trusted set can hold
   several certificates for one key. The port reads each of them for a
   revocation, so a revocation in any one of them refuses the signature.
   `gpgv` and the tool read the first certificate that their keyrings hold for
   the key:
   - A keyring holds an export of a key with no revocation, and then a revoked
     export of the same key. `gpgv --keyring <keyring> <sig> <data>` reports
     `GOODSIG`, and `ostree show <ref>` reports `Good signature from "..."`.
     With the two exports in the opposite order, each tool reports the
     revocation.
   - Two keyring files of the `OSTREE_GPG_HOME` directory hold the two
     exports. The tool answers on the sort order of the two file names.
   - The `<remote>.trustedkeys.gpg` of the remote holds the export with no
     revocation, and the `OSTREE_GPG_HOME` directory holds the revoked export.
     `ostree show --gpg-verify-remote=<remote> <ref>` reports
     `Good signature from "..."`, and `ostrya show` reports that the signature
     is not good.

   The port refuses the signature in each of these orders.
7. The key expiry of two exports of one certificate. The two exports can
   state two key expiries, and the port takes the newest statement of the two.
   `gpgv --keyring` over a file that holds both exports answers on their load
   order:
   - An export whose expiry is in the past, and then an export that removes
     the expiry: `gpgv` reports `EXPKEYSIG`, and the port reports a good
     signature. Here the port accepts where `gpgv` refuses.
   - The two exports in the opposite order: both report a good signature.

   `gpg --import` of the two exports merges them into one keyblock, and the
   merged keyring answers on the newest statement, as the port does. `gpgv
   --keyring` over the merged keyring gives the same verdict for each import
   order. Three pairs of exports of one certificate were measured: a one-day
   expiry extended to ten years, the same expiry removed, and an expiry in the
   past given to a key that stated no expiry. The merged keyring and the port
   agree on all three pairs. `gpgv` over the two exports concatenated answers
   on the export that is first.

## Port extensions with no counterpart in the tool

The tool has no push, no pull over ssh, no server, no composefs image
object, and no bucket repository. `receive`, `push`, `push-tree`, `serve`,
`send`, `composefs-image`, `remote init`, `remote fsck`, and `remote prune`
are commands of the port alone, so no matrix cell compares them with the
tool. `pull`, `remote
refs`, and `remote summary` also read a remote over ssh, for an ssh address
in the `pull-url` key or in `--url` of `pull` (`pull`), and a bucket
repository in an S3 bucket, for an `s3://` address in the same places
("Bucket repositories"). The receiving repository stays a normal
repository: the tool reads it, checks it with `ostree fsck`, and pulls from
it with `ostree pull-local`. The tool pulls from `serve` with `ostree
pull`.

### `receive`

```text
ostrya receive [--repo=PATH] [--client=NAME]
```

- The `receive` feature of `ostrya-cli` builds the command. It is in the
  default set.
- The command runs one push session over standard input and standard
  output. At start it reads and checks the client groups, the server group,
  the trust groups, and the key groups of the repository config
  (`ostrya-config(1)`, "CLIENT AND SERVER GROUPS"). It builds each trust
  group and each key group. A bad group ends the command with
  `error: MESSAGE` at exit 1, before it reads its input.
- The client name is `--client`, else the value of `LOGNAME`, which sshd
  sets from the password entry of the user. An empty `LOGNAME` counts as
  absent. With no name, the command writes `error: receive needs a client
  name: give --client, or set LOGNAME` and exits 1 before it opens the
  repository. A name that an `ssh:` item cannot hold, for example a name
  with white space at its start, ends the command with `error: MESSAGE` at
  exit 1 at the same step. The message shows the name in escaped form, so a
  name with a line feed gives one line.
- `Hello` names the namespace of the session: the local refs, or one
  collection. The collection id of the repository names the local refs. The
  session takes the policy of the client group of that namespace that
  carries `ssh:NAME`. For a collection, a group that names the collection
  wins over a group with `collection=*`. With no such group, the `Hello`
  gets `ref-denied`, and the command exits 1. A session of a collection
  reads and writes the refs under `refs/mirrors/ID/`. The session uses no
  `anonymous` item and no `net:` item.
  `../format-reference.md`, "Authentication of the receive endpoint",
  states the rules.
- `--client` is safe only under a forced `command=` in `authorized_keys`,
  because a user with a shell can give any name.
- The command takes no `--policy`, and the option parser refuses it at
  exit 1.
- Standard output carries the frames of the session alone. The command
  writes one `warning: STEP: MESSAGE` line to standard error for each
  warning of the session, and `error: MESSAGE` on failure. It writes
  nothing else, also under `-v`.
- It exits 0 after a committed session, also with warnings, and 1
  otherwise.

### `push`

```text
ostrya push [--repo=PATH] REMOTE SRC[:DST]...
            [--collection=ID] [--tag=NAME]...
            [--depth=N] [--force] [--compress[=LEVEL]]
            [--ssh-command=CMD] [--receive-command=CMD]
            [--push-token-file=FILE] [--push-user=NAME]
            [--tls-client-cert-path=FILE] [--tls-client-key-path=FILE]
            [--tls-ca-path=FILE] [--allow-cleartext-credentials]
ostrya push [--repo=PATH] REMOTE|s3://BUCKET[/PREFIX] SRC[:DST]...
            [--collection=ID] [--depth=N] [--force] [--break-lock]
            [--s3-region=REGION] [--s3-endpoint=URL]
            [--s3-addressing=path|virtual] [--s3-profile=PROFILE]
            [--allow-cleartext-credentials]
ostrya push [--repo=PATH] REMOTE REF --onto=BRANCH
            [--collection=ID] [--tag=NAME]... [--bind-ref=NAME]...
            [--orphan] [--timestamp=TIME] [--compress[=LEVEL]]
            [the transport options of the first form]
```

- The `push` feature of `ostrya-cli` builds the command. It is in the
  default set.
- `REMOTE` is a remote of the repository config with a push address, an
  ssh address, an `http://` or `https://` address, or an `s3://` address.
  To an ssh address the push runs the ssh client with the remote command
  `ostrya receive --repo='PATH'`. To an HTTP address the push sends its
  requests to the receive endpoint of `serve`. To an `s3://` address the
  push writes a bucket repository ("Bucket repositories").
- Each refspec is `SRC[:DST]`. `SRC` is a revision of the local repository.
  `DST` is the ref of the server, and it defaults to `SRC` when `SRC` is a
  ref. `:DST` deletes the ref `DST` of the server.
- A `DST` that the ref-name rule refuses, which includes a `DST` that holds
  `^`, and a `DST` of 64 lowercase hex characters after a `SRC`, which a
  revision reads as a commit checksum, are refused with `error: Invalid
  refspec DST` at exit 1. The refusal comes after `REMOTE` resolves and before the ssh client
  starts or the first HTTP request. A delete `:DST` of a `DST` of 64
  lowercase hex characters passes, and the server removes the ref where the
  client group has `r` and `d` on it.
- The command checks its operands after the repository opens. With no
  `REMOTE` it writes the usage text and `error: REMOTE must be specified`.
  With no refspec it writes the usage text and `error: REFSPEC must be
  specified`. Both exit 1. No ssh client starts, and no HTTP request is
  sent.
- The push then resolves `REMOTE` and makes the transport ready, before it
  reads `--depth` and the refspecs. It refuses an option of the other
  transport and a bad HTTP option. It reads the token file of an HTTP push,
  and the TLS files of an `https://` push. So
  `push --push-user=bob https://HOST/ nosuchref` fails with the refusal of
  `--push-user`, and does not name the refspec.
- The push reads the `ostree.collection-binding` of each source commit
  before the ssh client starts and before the first HTTP request. The
  bindings, or `--collection=ID`, give the namespace on the server. A commit
  with no binding goes to the local refs, and a commit bound to `ID` goes to
  the refs of `ID`. The server writes the refs of its own collection id
  under `refs/heads/`, and the refs of each other collection under
  `refs/mirrors/ID/`. So a commit of a repository with a collection id goes
  to `refs/mirrors/ID/NAME` of a server with another collection id or with
  none.
- Two source commits with different bindings, and a binding that differs
  from `--collection`, are refused with `error: binding-mismatch: ...` at
  exit 1, before the ssh client starts and before the first HTTP request.
  An `ID` that fails the collection-id rule or is longer than 255 bytes is
  refused with `error: Invalid collection ID ID` at exit 1, at the same
  step. A binding of a source commit that fails the collection-id rule or is
  longer than 255 bytes is refused with `error: invalid input: ...` at exit
  1, at the same step. A commit with no binding in the namespace of a
  collection is refused with `error: binding-mismatch: ...` after the server
  reports the namespace, and before the push sends an object.
- The push offers the composefs image of each commit whose tree it walks,
  where the local repository holds the image, also for a source commit that
  the server holds (`../format-reference.md`, "Have and HaveReply"). A push
  with `--onto` sends no image. A server that does not accept the object
  type 100 refuses the session with `protocol`, so the server must accept
  the type before a push with images goes to it.
- `--tag=NAME` creates the ref `NAME` on the server at the source commit.
  The option can repeat. The refspecs that are not deletes must give one
  commit, and its `ostree.ref-binding` must hold `NAME`. `NAME` passes the
  ref-name rule, holds no `:`, is not 64 lowercase hex characters, is not a
  `DST`, and is named once. Each of these refusals comes before the ssh
  client starts and before the first HTTP request. A tag is an update that
  expects no ref, also under `--force`. So a tag that exists gets
  `error: ref-mismatch: ...` after the server reports its refs, and before
  the push sends an object. The client group of the push needs `t` or `w`
  on `NAME`.
- `--onto=BRANCH` makes a server commit
  (`../format-reference.md`, "Server commit"). The push sends the objects of
  the tree of the local commit of `REF` that the server does not hold. The
  server then makes a new commit over the tree, moves `BRANCH` to it, and
  creates each `--tag` at it, in one transaction. The parent is the commit
  of `BRANCH` on the server, or none when the server does not hold
  `BRANCH`. The new commit takes the subject, the body, the metadata, and
  the timestamp of the local commit. The push drops the local
  `ostree.ref-binding` and `ostree.collection-binding`, and the server
  writes the bindings of its namespace. The push sends no parent, no commit
  object, and no detached metadata, so the server signs the new commit with
  the keys of the client group.
- Under `--onto`:
  - The command takes exactly one `REF`, a revision of the local
    repository, and does not split it at `:`. A second operand is refused
    with `error: --onto takes one REF, and N were given` at exit 1, before
    `REMOTE` resolves.
  - `--onto` with `--depth` or with `--force` is refused by the option
    parser at exit 1. `--bind-ref`, `--orphan`, and `--timestamp` without
    `--onto` are refused in the same way.
  - `--tag=NAME` creates the ref `NAME` at the new commit, and the server
    binds `NAME`. A tag equal to `BRANCH` is refused with `error: invalid
    input: ...`. A tag that exists gets `error: ref-mismatch: ...` before
    the push sends an object.
  - `--bind-ref=NAME` binds `NAME` and creates no ref. It can repeat. `NAME`
    passes the ref-name rule and holds no `:`.
  - `--orphan` makes a commit with no parent. On a `BRANCH` that exists,
    the server refuses it with `error: non-fast-forward: ...` unless the
    client group has `c` and `d` on `BRANCH`.
  - `--timestamp=TIME` takes the value forms of `commit --timestamp`.
    Without it, the new commit takes the timestamp of the local commit.
  - `--collection=ID` alone names the namespace. Without it, the server
    commit goes to the local refs of the server. The bindings of the local
    commit do not select the namespace.
  - A `BRANCH` or a tag that the ref-name rule refuses, that holds `:`, or
    that is 64 lowercase hex characters is refused with `error: Invalid
    refspec NAME` after `REMOTE` resolves and before the ssh client starts or
    the first HTTP request. So is a bound name that the ref-name rule
    refuses or that holds `:`.
  - A local commit that the repository marks partial, and a local commit
    with related objects, are refused with `error: invalid input: ...` at
    the same step.
  - After the server reports its refs, the push checks the `Commit` frame of
    the server commit and the longest reply, which names `BRANCH` and each
    tag, against the frame limit of the server, 1 MiB for an ostrya server.
    A longer frame is refused with `error: limit-exceeded: ...` before the
    push sends an object.
  - The client group needs `c` on `BRANCH`, and `t` or `w` on each tag. A
    server whose receive hooks take no server commit refuses the push, and
    the push fails with `error: ref-denied: ...`.
- `--depth=N` sends `N` parents of each source commit, and `-1` the whole
  chain. Without it, the push sends the chain back to the commit of the ref
  on the server. When the server does not hold the ref, or the local chain
  does not hold the commit of the ref on the server, the push then sends the
  source commit alone. `--depth=-1` sends the whole local chain. A value
  below `-1` is refused before the ssh client starts and before the first
  HTTP request.
- The push also sends the dependencies that field 2 of each offered commit
  names, each at depth 0 and with no ref (`../format-reference.md`,
  "Dependencies in a push"). It sends no build source. It refuses at exit 1
  a field 2 entry with an empty name or with a checksum that is not 32
  bytes, in a source commit and in each parent that the push walks: `N`
  parents with `--depth=N`, and the whole local chain with `--depth=-1` or
  without `--depth`. It also refuses a dependency that the local repository
  does not hold or marks partial, and a dependency whose own field 2 is not
  empty, also if that field 2 holds a defective entry. Each of these
  refusals comes before the ssh client starts, before the first HTTP
  request, and before the first request to a bucket. Without `--depth`, the
  push checks the dependencies of the history commits after the server
  reports its refs, or under the writer lock of a bucket. A refusal there
  comes before the push sends an object.
- `--force` sends each update with any expected state, and asks the server
  to allow an update that is not a fast-forward. The server refuses such an
  update unless the client group of the push has `w` and `d` on the ref
  (`ostrya-config(1)`, "Access modes and patterns").
- `--compress` sends content objects deflated at level 6, and
  `--compress=LEVEL` at `LEVEL`, 1 to 9. The value needs the `=` form.
  Without the option, the push sends them raw. An `archive` repository
  sends each stored content object as it is, at the zlib level the
  repository wrote it with, whatever `LEVEL` is.
- `--ssh-command=CMD` is the ssh command, split at ASCII whitespace. It wins
  over the `OSTRYA_SSH_COMMAND` environment variable, and that wins over
  the `ssh-command` key of the remote. `--receive-command=CMD` is the
  remote command, and it wins over the `receive-command` key of the remote.
- `--push-token-file=FILE` names the file whose first line is the token of
  an HTTP push. `--push-user=NAME` sends the token as the password of a
  Basic credential with that name. Without it, the push sends a bearer
  token. `--tls-ca-path=FILE` names the CA certificates that verify the
  server, in place of the trust store of the host.
  `--tls-client-cert-path=FILE` and `--tls-client-key-path=FILE` name a
  client certificate and its key, and the two come together. The key must
  need no passphrase. Each of these options wins over the key of the remote
  with the same name. A relative path is relative to the current directory,
  and `~` is not expanded.
  `ostrya-config(1)`, "REMOTE KEYS", states the keys.
  `../format-reference.md`, "The push token file of a client", states the
  grammar of the token file.
- A token to an `http://` address is refused before any request. With
  `--allow-cleartext-credentials`, the push sends it. Use the switch for a
  server on a loopback address or behind a proxy that terminates TLS.
- An option of the other transport is refused at exit 1 before the ssh
  client starts and before any request: an HTTP option with an ssh address,
  and `--ssh-command` or `--receive-command` with an HTTP address. The
  message names the option without `--`. Where a remote key backs the
  option, this is the name of the key. The message shows an ssh address in
  the `ssh://` form, with no user. Example: `error: invalid input:
  tls-ca-path applies to an HTTP address, and 'ssh://HOST/PATH' is an ssh
  address`. The keys of a remote apply to the transport of its push address
  alone, and the push ignores the other keys. `tls-permissive=true` on a
  remote with an `https://` push address is refused at exit 1 before any
  request. With an `http://` push address, the push uses no TLS. It ignores
  `tls-permissive`, and it reads no file that `tls-ca-path`,
  `tls-client-cert-path`, `tls-client-key-path`, or their options name.
- For an `http://` or `https://` push address, the push reads the `proxy`
  key of the remote. An empty or absent key gives the proxy environment
  variables, and a push to an address reads them too. A `proxy` value with
  white space at its start or its end is refused at exit 1 before any
  request: `error: unsupported: remote 'NAME': the proxy key has white space
  at the start or the end of its value`.
- On success the command writes one line for each ref to standard output,
  in the order of the refspecs and then of the tags, and exits 0. A line
  holds the `DST` name, the old state, and the new state, separated by one
  space. A commit is its full 64-character checksum:
  - `main (new) C1` -- the server did not hold the ref;
  - `main C1 C2` -- the ref moved from `C1` to `C2`;
  - `main C2 (unchanged)` -- the ref was at `C2` already;
  - `main C2 (deleted)` -- the push deleted the ref;
  - `main (absent) (unchanged)` -- a delete of a ref that the server does
    not hold.

  With `--onto`, the command writes the checksum of the new commit as one
  line, and nothing else.
- Under `-v` the command writes one statistics line to standard error: the
  objects offered, needed, and sent, the bytes sent, and the elapsed time.
- While the push runs, the command draws a progress bar on standard error
  when standard error is a terminal and `TERM` is set and is not `dumb`.
  Standard output carries the ref lines, so the bar goes to standard error.
  The bar shows nothing until the `Have` rounds start, so a prompt of the
  ssh client stays readable. It then shows a spinner with `Negotiating`, and
  a bar of the content bytes with `SENT/NEEDED objects`, the bytes, the
  rate, and the time left while the objects go. The content bytes are the
  payload bytes of the file objects before compression, or the stored bytes
  of the `.filez` files that an `archive` repository sends as they are. When
  the total is 0 the bar shows the bytes and the rate alone. The bar draws
  at most 20 frames a second, so its last frame can show less than 100%.
- The command clears the bar when it sends `Commit`, and draws nothing
  after that. A line that the server writes on standard error at the
  commit, for example `error: non-fast-forward: ...` or a
  `warning: summary-build ...` line, starts on a clean line. The command
  also clears the bar before it writes a ref line, the statistics line, or
  an error line.
- On a pipe, a file, or a dumb terminal the command writes no byte of the
  bar, and the push asks for no byte total, so it reads no object metadata
  for the bar. Standard error then carries the statistics line and the
  error line alone. The tool has no `push` command, so the bar is no
  conformance item.
- Known gaps of the bar:
  - The ssh client writes the standard error of the server on the same
    terminal. A line that the server writes while the objects go can show
    in the middle of the bar, and the next frame of the bar draws over the
    end of that line.
  - Ctrl-C, another signal that stops the process, or a panic leaves the
    last frame of the bar on the terminal.
- On failure the command writes `error: MESSAGE` to standard error and
  nothing to standard output, and exits 1. A refusal of the server gives
  its wire code first, for example `error: non-fast-forward: ...` or
  `error: delete-denied: ...`. No ref changes. After an unknown outcome of
  the commit, the refs of the server may have changed. A repeat push is
  safe, because each ref update is a compare-and-swap.
- When the command cannot write a ref line to standard output, it writes
  `error: MESSAGE` to standard error and exits 1. The refs of the server
  have changed at that point.

### Bucket repositories

```text
ostrya remote init [--repo=PATH] NAME|s3://BUCKET[/PREFIX]
                   [--collection-id=ID] [--zlib-level=LEVEL] [--break-lock]
                   [the S3 options] [--allow-cleartext-credentials]
ostrya remote fsck [--repo=PATH] NAME|s3://BUCKET[/PREFIX]
                   [--delete [--break-lock]] [-q|--quiet]
                   [the S3 options] [--allow-cleartext-credentials]
ostrya remote prune [--repo=PATH] NAME|s3://BUCKET[/PREFIX]
                    [--refs-only] [--depth=DEPTH] [--keep-younger-than=DATE]
                    [--no-prune] [--break-lock]
                    [the S3 options] [--allow-cleartext-credentials]
ostrya remote summary -u [--repo=PATH] NAME|s3://BUCKET[/PREFIX]
                      [--gpg-sign=KEY-ID] [--gpg-homedir=DIR]
                      [--sign=KEY-ID] [-s|--sign-type=NAME]
                      [--keys-file=PATH] [--break-lock]
                      [--last-modified=SECONDS]
                      [the S3 options] [--allow-cleartext-credentials]
```

A bucket repository is a repository in `archive` form in an S3 bucket, at
the address `s3://BUCKET[/PREFIX]` (`../format-reference.md`, "The S3
bucket repository"). The tool has no such repository, so no matrix cell
compares these commands with the tool. The `s3` feature of `ostrya-cli`
builds the S3 options, `--break-lock`, `remote init`, `remote fsck`,
`remote prune`, and `remote summary -u`. It is in the default set.

The S3 options are `--s3-region=REGION`, `--s3-endpoint=URL`,
`--s3-addressing=path|virtual`, and `--s3-profile=PROFILE`. `push`,
`push-tree`, `pull`, `remote refs`, `remote summary`, `remote init`,
`remote fsck`, and `remote prune` take them. Each one wins
over the remote key of the same name, then the environment, then the
profile in the shared AWS config file, then the default
(`ostrya-config(1)`, "REMOTE KEYS"). A profile that `--s3-profile` or
`s3-profile` names skips the key pair, the region, and the endpoint of the
environment. The option parser refuses an `--s3-addressing` value other
than `path` and `virtual`. An `http://` S3 endpoint needs
`--allow-cleartext-credentials`, because the signature of each request is
a credential: `error: invalid input: the S3 endpoint 'URL' is http://, so
the signature of each request would travel in cleartext: use https, or set
allow-cleartext-credentials`.

- `remote init` writes the `config` of a new bucket repository, with
  `collection-id=ID` for `--collection-id=ID`, and with the group
  `[archive]` and `zlib-level=LEVEL` for `--zlib-level=LEVEL`. The option
  parser refuses a `LEVEL` outside 1 to 9 before any request. A push builds
  each `.filez` at that level, and at level 6 with no `[archive]` group.
  With an address, the command
  opens no repository. With a remote name, the address is the `push-url`
  key when it holds an `s3://` address, else the `pull-url` key when it
  holds one. The command never reads `url`, and refuses each other remote
  with `error: invalid input: remote 'NAME' holds no s3:// address in
  push-url or pull-url`. It refuses an address that is not `s3://`, a
  collection id that fails the collection-id rule before any request, and
  a bucket repository that holds a `config`, which stays as it is. It
  writes nothing to standard output.
- `remote fsck` checks a bucket repository (`../format-reference.md`, "The
  fsck of a bucket repository"). It takes the address of its operand as
  `remote init` does, with no repository for an address. Unless `-q` is
  given, it first writes `Listed N objects`, `Checked C commits and O
  objects, B bytes`, and `N objects not reached by a commit` to standard
  output, then `N composefs images with no commit` and `N partial commits`
  when the count is not zero. It writes one line for each finding to
  standard error, sorted by key and then by kind: `KIND KEY: DETAIL`, then
  `; in commits C1, C2` when the finding names commits. A note starts with
  `note: `. A dependency in field 2 of a commit that is absent, partial, or
  defective gives a `dependency` error on the key of that commit, with the
  reason of the finding of `fsck` as its detail (`../format-reference.md`,
  "Dependencies in the fsck"). A report with an error ends with `error: Bucket
  repository corruption encountered` and exit status 1. Else the command
  writes `fsck of the bucket repository ADDRESS: no errors found` and exits 0.
  Notes alone give exit status 0. A failed write to standard output, for example
  on a full device, gives `error: i/o error: ...` and exit status 1. With
  a remote name, the command verifies the signature of the summary with
  the summary keys of the remote, `gpg-verify-summary` and
  `sign-verify-summary`. A remote with `trust=NAME` keeps this check. The
  command checks the trust group and the keys beside `trust` as a pull does,
  and reads no key of the group. With an address, it verifies no signature,
  and no option changes this.
- `remote fsck --delete` takes the writer lock, writes the marker
  `state/<checksum>.commitpartial` of each commit that reaches a missing or
  a bad object of a tree, deletes the marker of each commit whose tree is
  whole, and deletes each bad object. It checks the dependencies against
  the state after the repair: a dependency whose marker the repair deletes
  is not partial, a dependency that gets a marker is partial, a dependency
  whose commit object the repair deletes is absent, and a commit whose own
  object the repair deletes gets no check. It writes and deletes no key for
  a `dependency` error. It writes `Marking commit as partial:
  COMMIT (REF, ...)`, `Deleted the partial-commit marker of commit COMMIT`,
  `Deleted KEY`, and `Deleted the commit object of a ref: COMMIT (REF,
  ...)` lines to standard output. A bucket repository with no valid
  `config` refuses the repair: the run writes a `config` line and changes
  nothing. The option parser refuses `--break-lock` without `--delete`. A
  push of a ref whose commit has a marker uploads the missing objects and
  removes the marker. A repair that fails after its first change writes
  the report with the changes that completed, then `error: the repair of
  the bucket repository ADDRESS is incomplete: REASON; run the fsck with
  delete again before a push`, and exits 1.
- `remote prune` deletes the objects of a bucket repository that no root
  reaches (`../format-reference.md`, "The prune of a bucket repository").
  It takes the address of its operand as `remote init` does, with no
  repository for an address. `--refs-only`, `--depth`,
  `--keep-younger-than`, and `--no-prune` have the meaning and the values
  of `prune`, and the command refuses a `--keep-younger-than` value that
  `prune` refuses, with the same message, before any request. The option
  parser refuses the other options of `prune`. The commits that the summary
  names are roots with no parent. The dependencies in field 2 of each
  reached commit, also of a commit of the summary, are roots, as in
  `prune`, and the command reads no build source. For each defective
  field 2 entry, the command writes one
  `warning: related commits in field 2 of commit CHECKSUM: REASON` line to
  standard error before the lines on standard output. The command writes
  the lines of `prune` to standard output: `Total objects: N`, then
  `Deleted N objects, SIZE freed`, `Would delete: N objects, freeing SIZE`
  with `--no-prune`, or `No unreachable objects`. Then, for each count
  that is not zero, it writes `Deleted N static deltas`, `Deleted N
  partial-commit markers`, and `Aborted N incomplete multipart uploads`, or
  with `--no-prune` `Would delete N static deltas`, `Would delete N
  partial-commit markers`, and `Would abort N incomplete multipart
  uploads`. It exits 0. The command takes the writer lock, also with
  `--no-prune`, writes no summary, and refuses a bucket repository whose
  `config` sets `[core] tombstone-commits=true`. The option parser refuses
  `--break-lock` with `--no-prune`. A commit or a dirtree whose bytes do
  not match its name fails the command before its first delete.
- `remote summary -u` writes the summary of a bucket repository
  (`../format-reference.md`, "The summary of a bucket repository"). It
  takes the address of its operand as `remote init` does, with no
  repository for an address. The summary holds the refs of `refs/heads/`
  in field 0 and the refs of each `refs/mirrors/ID/` in the collection map,
  and names each static delta with a superblock. With the same
  `--last-modified`, its `summary` holds the bytes that `ostrya summary -u`
  writes in a copy of the bucket repository with no collection id. With the
  same ed25519 keys, `summary.sig` holds the same bytes too. The command
  takes the writer lock, writes `summary` and then, with a key,
  `summary.sig`, writes nothing to standard output, and exits 0. The
  signing options are those of `ostrya summary -u`: each `--gpg-sign` key,
  each `--sign` key, and each `--keys-file` key signs, in this order. Each
  `--sign` and `--keys-file` key takes the engine of the nearest
  `-s`/`--sign-type` before it, and `ed25519` if no `-s` comes before it. The
  command refuses a `-s` with no key of its own, and gives the other refusals
  of `ostrya summary -u`. Two of these refusals name the options
  of `remote summary -u`: `--keys-file` under the gpg engine gives
  `error: signature: gpg signing takes --gpg-sign and --sign KEY-ID
  arguments; --keys-file serves the other engines`, and an ed25519 key file
  with no key gives `error: signature: no signing key given; pass --sign or
  --keys-file`. An spki `--keys-file` holds PEM `PRIVATE KEY` blocks, the
  form of a `sign --keys-file`, and each block adds one signature. The
  command reads each key file before the first request. The option parser refuses each signing option and
  `--break-lock` without `-u`, and refuses `-u` with `--raw`,
  `--list-metadata-keys`, and `--print-metadata-key`. A bucket repository
  that holds a `summary.sig` refuses an update with no key: `error: invalid
  input: the bucket repository ADDRESS holds a summary.sig, and an update of
  its summary with no summary signer would leave a summary that no
  signature covers; give a summary signer`. The command refuses a ref whose
  commit the bucket does not hold, a key under `refs/` that is no ref key,
  and a ref name that is a directory of another ref name, before it changes
  the bucket. With a key, a write of `summary.sig` that fails after the
  write of `summary` gives ``error: the summary update of the bucket
  repository ADDRESS wrote summary, and the write of summary.sig failed:
  REASON; summary.sig can be absent or not cover the new summary, so a pull
  that verifies the summary can refuse it; run `ostrya remote summary -u`
  again with the same summary signers``, and exits 1. With a key, a write of
  `summary` with an unknown outcome gives ``error: the summary update of the
  bucket repository ADDRESS failed to write summary with an unknown
  outcome: REASON; summary.sig can be absent or not cover the summary of
  the bucket, so a pull that verifies the summary can refuse it; run
  `ostrya remote summary -u` again with the same summary signers``, and
  exits 1. The command tries to remove its writer lock before either
  error, and a run again with the same keys writes a matching pair.
  The command does not carry these options of `ostrya summary`:
  `-m`/`--add-metadata`, `-c`/`--client-groups`,
  `--metadata-commit-timestamp`, `--keys-dir`, and the positional KEY-ID.
- `push` to an `s3://` address, or to a remote whose push address is one,
  writes the objects that the bucket does not hold, then the ref files,
  under the writer lock of the bucket repository. It writes no summary,
  and a summary of the bucket stays as it is until `remote summary -u`
  writes it. The bucket repository needs
  a `config`, else `error: invalid input: the bucket repository ADDRESS has
  no config; init it first`. `--collection` selects the namespace with the
  `config` of the bucket in the role of the server: the collection id of
  the bucket, or no collection, gives `refs/heads/NAME`, and each other
  collection gives `refs/mirrors/ID/NAME`. The push refuses `--tag`,
  `--compress`, `--onto`, a delete refspec, `--push-token-file`,
  `--push-user`, the keys `push-token-file` and `push-user`, and the ssh
  options. It reads the environment and the shared AWS files before it
  refuses `--tag` and `--compress`, and sends no request for either
  refusal. The ref lines and the exit status are those of a push over a
  session. The push uploads the stored `.filez` of an `archive` repository
  as it is, and builds the `.filez` of each other mode at the
  `[archive] zlib-level` of the `config` of the bucket. With
  `[ex-ostrya] keep-detached-related=false` in the `config` of the bucket,
  the push drops `ostrya.related` from each `.commitmeta` that it uploads.
  A value that is not a boolean refuses the push before it uploads an
  object or a ref file. The refusal changes nothing in the bucket but the
  probe key of the writer lock.
- `push-tree` to an `s3://` address, or to a remote whose push address is
  one, makes the commit on the client and writes it to the bucket
  repository (`push-tree`).
- `--break-lock` of `push`, `push-tree`, `remote init`, `remote fsck
  --delete`, `remote prune`, and `remote summary -u` removes the writer lock
  of another writer, then takes a new lock. After a command
  that succeeds, the holder of the removed lock goes to standard error in
  one line: `warning: removed the writer lock of HOLDER`. `remote summary
  -u` also writes this line before the error of a summary and a
  `summary.sig` that can fail to match. Without the
  option, a locked bucket repository refuses the command with `error: the
  bucket repository ADDRESS is locked: another writer holds the writer
  lock: HOLDER`. `--break-lock` of `push` conflicts with `--onto`, and
  `--break-lock` of `remote prune` conflicts with `--no-prune`.
- `push` and `push-tree` refuse `--break-lock` and each S3 option for an
  HTTP or an ssh destination, before the remote resolves: `error: OPTION
  applies to an s3:// address, and the push address of 'REMOTE' is not
  one`. `REMOTE` is the operand without its userinfo. The destination of a
  remote name is its `push-url`, else its `url`.
- `pull`, `remote refs`, and `remote summary` take the S3 options and
  `--allow-cleartext-credentials`, and refuse each of them when the pull
  address is an HTTP or an ssh address: `error: OPTION applies to an s3://
  address, and the pull address of remote 'NAME' is not one`. The pull
  address is `--url`, else `pull-url`, else `url`. A pull address that the
  resolver refuses, for example `s3://` in `url` or a remote that the
  config does not describe, gives the refusal of the resolver, also with
  these options. `pull --collection` refuses each S3 option: `error: OPTION
  applies to one remote, and a pull with --collection takes the S3 settings
  of each candidate from the config`. It refuses
  `--allow-cleartext-credentials` when the pull address of a candidate is
  an HTTP or an ssh address: `error: --allow-cleartext-credentials applies
  to an s3:// address, and the pull address of remote 'NAME' is not one`.
  `NAME` is the first such candidate in the config. A candidate whose pull
  address the resolver refuses gives the refusal of the resolver, also with
  this option, and the pull sends no request.
- `pull --collection` reads the refs of a candidate at an `s3://` address
  from the summary of its bucket repository alone, and sends it no ref
  listing request. A candidate with no summary is skipped with a warning
  (`format-reference.md`, "The pull of collection refs").
- A pull of a named ref reads the ref file of the bucket when the summary
  does not list the ref, so a bucket repository with no summary serves
  `pull REMOTE REF`. `remote refs`, `remote summary`, a pull with
  `--mirror` and no ref, a pull that verifies the signature of the summary,
  and `pull --collection` need a summary, and a push writes none:
  `remote summary -u` writes it. A pull of a ref that the summary lists
  takes the commit of the summary. So after a push moves that ref, the pull
  takes the old commit until `remote summary -u` writes the summary again.
- `s3://` in the key `url` is refused by `pull`, `remote refs`, `remote
  summary`, and `push`: the tool also reads `url`, and it reads no `s3://`
  address.
- `remote add NAME s3://BUCKET[/PREFIX]` writes the address to `pull-url`
  and `push-url`, after the branches, and writes no `url`. It does not check
  the address, also in a build without the feature `s3`. `--set` writes the
  S3 keys. A pull or a push refuses a bad address or a bad key when it uses
  the remote. `remote show-url` and `remote list -u` refuse such a remote
  with `error: No "url" option in remote "NAME"`, as for each remote with
  no `url`.
- A push to a bucket repository shows no progress bar while it lists the
  bucket and walks the commits. The bar starts with the uploads.
- A build without the feature `s3` has no S3 option, no `--break-lock`, no
  `--allow-cleartext-credentials` on `pull`, `remote refs`, and `remote
  summary`, and no `remote init`, `remote fsck`, `remote prune`, and
  `remote summary -u`. It
  refuses an `s3://` address with
  `error: unsupported: the pull address 'ADDRESS' is an s3:// address, and
  this build of ostrya has no S3 support: turn on the feature s3 of
  ostrya`, and with the same text for a push address.

### `push-tree`

```text
ostrya push-tree [--repo=PATH] REMOTE DIR --onto=BRANCH
                 [--tag=NAME]... [--bind-ref=NAME]... [--orphan]
                 [--collection=ID]
                 [-s SUBJECT] [-m BODY] [--body-file=FILE]
                 [--add-metadata-string=KEY=VALUE]... [--add-metadata=KEY=VALUE]...
                 [--timestamp=TIME]
                 [--owner-uid=UID] [--owner-gid=GID] [--canonical-permissions]
                 [--compress[=LEVEL]]
                 [--ssh-command=CMD] [--receive-command=CMD]
                 [--push-token-file=FILE] [--push-user=NAME]
                 [--tls-client-cert-path=FILE] [--tls-client-key-path=FILE]
                 [--tls-ca-path=FILE] [--allow-cleartext-credentials]
                 [--s3-region=REGION] [--s3-endpoint=URL]
                 [--s3-addressing=path|virtual] [--s3-profile=PROFILE]
                 [--break-lock]
```

- The `push` feature of `ostrya-cli` builds the command. It is in the
  default set. The feature `s3` adds the S3 options and `--break-lock`.
- The command walks the directory `DIR` and sends the objects of its tree
  that the server does not hold. The server then makes one commit over the
  tree, moves `BRANCH` to it, and creates each `--tag` at it, in one
  transaction (`../format-reference.md`, "The commit of `push-tree`"). The
  parent is the commit of `BRANCH` on the server, or none when the server
  does not hold `BRANCH`. The server writes the bindings and signs the
  commit with the keys of the client group.
- The option names and value forms of the commit options are those of
  `commit`.
- The command reads `--owner-uid` and `--owner-gid` first, as `commit`
  does. It refuses a bad value before every other check.
- The command then checks its operands, before it opens a repository. With
  no `REMOTE` it writes the usage text and `error: REMOTE must be
  specified`. With no `DIR` it writes the usage text and `error: DIR must be
  specified`. With no `--onto` it writes the usage text and `error: A branch
  must be specified with --onto`. Each exits 1. No ssh client starts, and
  no HTTP request is sent.
- The command then reads the metadata options and the timestamp, in this
  order. It refuses a bad value before it opens a repository.
- The timestamp is `--timestamp`, else the `SOURCE_DATE_EPOCH` environment
  variable. A `SOURCE_DATE_EPOCH` that is not a count of seconds is refused
  with `error: SOURCE_DATE_EPOCH is not a Unix timestamp: ...` at exit 1.
  With neither, the push sends no timestamp, and the server takes its own
  clock. A push to a bucket repository then takes the clock of the host.
- The command then refuses `--break-lock` and the `--s3-*` options for a
  push address that is not an `s3://` address, as `push` does: `error:
  OPTION applies to an s3:// address, and the push address of 'REMOTE' is
  not one`. A build without the feature `s3` refuses an `s3://` address in
  the resolve, with the message of the feature.
- The command then resolves `REMOTE` and makes the transport ready, or
  builds the client of the bucket repository. It refuses an option of the
  other transport and a bad HTTP option. It reads the token file of an HTTP
  push, and the TLS files of an `https://` push.
- The command then reads `--body-file`. So a refusal of the remote or of
  its options reads no body file.
- Each of these refusals comes before the walk. No ssh client starts, and
  no HTTP request is sent.
- `REMOTE` is an ssh address, an `http://` or `https://` address, an
  `s3://BUCKET[/PREFIX]` address, or a remote name that the config of the
  local repository holds with a push address. The command reads the local
  repository for a remote name alone, from `--repo`, then the current
  directory, then `OSTREE_REPO`. For an address the command opens no
  repository, and it ignores `--repo`.
- The command refuses a `BRANCH` or a `--tag` that holds `:`, a name that
  the ref-name rule refuses, which includes a name that holds `^`, a tag
  equal to `BRANCH`, and a tag given twice. It refuses a name of 64
  lowercase hex characters with the wording of `commit`, before it reads
  the metadata options. The other names are refused after `--body-file` is
  read, and before the walk. A name that holds `^` is refused with `branch
  'NAME' is not a valid ref name` or `tag 'NAME' is not a valid ref name`.
- `--bind-ref=NAME` binds `NAME` and creates no ref. It can repeat. `NAME`
  passes the ref-name rule and holds no `:`.
- `--orphan` makes a commit with no parent. On a `BRANCH` that exists, the
  server refuses it with `error: non-fast-forward: ...` unless the client
  group has `c` and `d` on `BRANCH`.
- `--collection=ID` names the namespace on the server. Without it, the push
  writes the local refs of the server. An `ID` that fails the collection-id
  rule or is longer than 255 bytes is refused before the walk.
- The metadata dict holds every `--add-metadata-string` entry, then every
  `--add-metadata` entry, then the binding keys that the server writes.
  `ostree.ref-binding` holds `BRANCH`, each `--tag`, and each `--bind-ref`,
  sorted. `ostree.collection-binding` holds the collection of the namespace.
  An empty key is refused. The keys `ostree.ref-binding` and
  `ostree.collection-binding` are refused, because the server writes them.
- `--owner-uid`, `--owner-gid`, and `--canonical-permissions` have the
  meaning they have in `commit`, and they apply to the root directory too.
  `--canonical-permissions` beside a non-zero owner id is refused with the
  wording of `commit`.
- After the server reports its refs, a tag that exists gets `error:
  ref-mismatch: ...`. A `--add-metadata` value that a commit cannot hold
  gets `error: invalid input: ...`. In a commit, a value can hold two levels
  of containers fewer than a variant, so an array nested to 126 levels is
  refused. A
  `Commit` frame or a longest reply over the frame limit of the server gets
  `error: limit-exceeded: ...`. The reply names `BRANCH` and each tag. Each
  refusal comes before the push sends an object.
- The client group needs `c` on `BRANCH`, and `t` or `w` on each tag. A
  server whose receive hooks take no server commit refuses the push, and the
  push fails with `error: ref-denied: ...`.
- `--compress`, `--ssh-command`, `--receive-command`, and the HTTP options
  have the meaning they have in `push`.
- On success the command writes the checksum of the new commit as one line
  to standard output and exits 0. Under `-v` it writes the statistics line
  of `push` to standard error.
- To an `s3://` destination, the command writes the bucket repository that
  `remote init` created, through `BucketRepo::push_tree`
  (`../format-reference.md`, "The tree push to a bucket repository"). The
  push makes the commit on the client, with the rules of the server
  commit and the `config` of the bucket in the role of the server:
  - The parent is the commit of `BRANCH` in the bucket. `--orphan` makes a
    commit with no parent, and on a `BRANCH` that exists it replaces the
    commit of `BRANCH` with no check.
  - `--collection=ID` selects the namespace as `push` does: the collection
    id of the bucket, or no `ID`, writes `refs/heads/BRANCH`, and each other
    `ID` writes `refs/mirrors/ID/BRANCH`. `ostree.collection-binding` holds
    the collection id of the namespace.
  - `--tag` is refused with `error: invalid input: a push to an s3://
    address creates no tag, and the push names tags`, before any request.
    `BRANCH` `ostree-metadata` in `refs/heads/` of a bucket with a
    collection id is refused with `error: ref-denied: ...`.
  - The push uploads each `.filez` at `--compress=LEVEL`, else at the
    `[archive] zlib-level` of the bucket, else at level 6.
  - `--break-lock` removes the writer lock of another writer, and writes
    `warning: removed the writer lock of HOLDER` to standard error after a
    push that succeeds.
  - `--allow-cleartext-credentials` permits an `http://` S3 server, as for
    `push`.
  - The push signs no commit and writes no summary. A file that changes
    after the hash pass fails the push, and no ref changes.
- While the push runs, the command draws the progress bar of `push` on
  standard error, with the same rules and the same known gaps. The bar
  shows nothing during the walk and the hash pass.
- On failure the command writes `error: MESSAGE` to standard error and
  nothing to standard output, and exits 1. A refusal of the server gives
  its wire code first, for example `error: mode-refused: ...`.
- The commit checksum equals the checksum of `ostree commit --no-xattrs -b
  BRANCH` over the same tree with the same options and the same parent.
  Each `--tag` and each `--bind-ref` is one `--bind-ref` of the tool, and
  `--orphan` is `--parent=none`. Each test that compares the two runs the
  tool with the same `SOURCE_DATE_EPOCH`, in
  `crates/ostrya-cli/tests/push_ssh.rs`.

### `serve`

```text
ostrya serve [--repo=PATH] [--listen=ADDR:PORT]...
             [--tls-cert=FILE] [--tls-key=FILE] [--tls-client-ca=FILE]
             [--trusted-proxy=CIDR]... [--trusted-proxy-header=HEADER]
             [--trusted-proxy-client-cert=HEADER]
             [--proxy-protocol[=BOOL]]
             [--allow-cleartext-credentials[=BOOL]]
             [--session-timeout=SECONDS] [--max-sessions=N]
             [--parallel-uploads=N] [--body-timeout=SECONDS]
```

- The `serve` feature of `ostrya-cli` builds the command. It is in the
  default set, and it needs neither the `receive` feature nor the `push`
  feature.
- The command serves the repository over HTTP as an archive repository, for
  pull, in every mode the port reads. The served `config` is
  `[core]\nrepo_version=1\nmode=archive-z2\n`, followed by
  `collection-id=ID\n` when the repository config sets it. In an `archive`
  repository, `indexed-deltas=VALUE\n` comes next when the repository config
  sets it. In a mode other than `archive` each `.filez` object is built on
  request at `[archive] zlib-level`, and `deltas/` and `delta-indexes/` are
  not served. The `.cfs` composefs image of a commit is served as stored in
  every mode. A path the server refuses and a path it does not find both get
  404. `../format-reference.md`, "The archive view", states the rules.
- The command also answers `GET /_ostrya/refs/v1?pattern=P&collection=C`.
  The body is the ref listing, a summary GVariant built for each request, of
  the refs that the entries of the query select. Each entry is a ref pattern
  with an optional leading `!`. A `pattern` entry selects local refs, and no
  `pattern` pair takes all local refs. A `collection` entry selects the
  collection refs under `refs/mirrors/` by `ID/NAME`, and the listing holds
  them in `ostree.summary.collection-map`. With no `collection` pair, the
  listing holds no collection ref. A bad pair of the query, a query of more
  than 256 pairs, an entry of more than 256 parts or 4096 bytes, and an entry
  that is not a ref pattern get 400, and a method other than `GET` gets 405
  with `Allow: GET`. The command holds at most 4 listings at the same time. A
  request over this limit gets 503 with `Retry-After: 1`. For each directory
  under `refs/mirrors/` whose name is not a collection id, a listing writes
  one `warning:` line to standard error, one time in each run.
  `../format-reference.md`, "The ref listing", states the rules.
- The command always runs the receive endpoint of a push. The client
  groups of the config give the push rights.
- The command takes its settings from `[ex-ostrya server]`
  (`ostrya-config(1)`, "Server keys"). Each option of the command has the
  name of a key, and the option replaces the key. A `--listen` option
  replaces the whole `listen` list. The command has no option for
  `sign-summary`, because `ostrya receive` reads it too. A relative path in
  a key is relative to the repository directory, and a relative path in an
  option is relative to the current directory. A bad key value ends the
  command at exit 1, also when an option replaces the key.
- `--trusted-proxy` takes a network, `ADDR/LEN` or a bare `ADDR`, once for
  each network, and the options replace the whole `trusted-proxy` key. A
  network with host bits set is refused at exit 1. `--trusted-proxy-header`
  takes `forwarded`, `x-forwarded-for`, or `x-real-ip`, in lowercase, and
  each needs the other, from a key or from an option.
  `--trusted-proxy-client-cert` takes a header name, an HTTP token, and
  needs `tls-client-ca` and `trusted-proxy`. `--proxy-protocol` reads a
  PROXY protocol header at the start of each connection, and
  `--proxy-protocol=false` does not, also when the key is `true`. No option
  removes a set `trusted-proxy`, `trusted-proxy-header`, or
  `trusted-proxy-client-cert` key. A start check that fails ends the command
  with `error: invalid format: MESSAGE` at exit 1, for example
  `trusted-proxy is set, and the server has no trusted-proxy-header`.
  `../format-reference.md`, "Authentication of the receive endpoint", states
  the PROXY header, the walk of the hops, the scheme `https` of a trusted
  proxy, and the forms of a forwarded certificate.
- The server identifies the client of each request by the auth items of the
  client groups: a bearer token, a Basic credential, a client certificate,
  the client address, or `anonymous`. This applies to the reads of the
  archive view and of the ref listing too. A read that identifies no item
  gets 401 or 403 with an empty body. A ref under `refs/heads/` or
  `refs/mirrors/ID/` is served when the group of the item has `r` on its
  name, and the ref listing holds these refs alone. `refs/remotes/` and
  `extensions/ostrya/` get 404. `summary` and `summary.sig` are the files of
  the summary of the identified item, which `summary -u` writes. An item
  with no summary gets 404. A summary whose `.access` file does not hold the
  access digest of the current client groups gets 404, and the command
  writes one `error:` line that names the item, one time for each item in
  each run. A 200 and a 404 of the two paths carry `Cache-Control:
  private`. The command never serves the root `summary`, so it serves no
  `summary` that the tool writes.
  `../format-reference.md`, "Read access" and "Summaries of auth items",
  state the rules. The tool has no such rights. A `session` request
  takes the policy of the client group that carries the item in the
  namespace of its `Hello`: the local refs, or one collection. An item with
  no such group gets 403 with `unauthorized` and the message `no client
  group of the request covers the local refs`, or `no client group of the
  request covers the collection 'ID'`. A group
  that opens no push session gets 403 with `unauthorized` and the message
  `client group 'NAME' opens no push session`. With no client group in the
  config, the implicit group `anonymous` reads each ref and opens no push
  session, so each push gets 403. `../format-reference.md`, "Authentication
  of the receive endpoint", states the order of the steps and the owner key
  of a session.
- With `tls-client-ca`, a client certificate that the CA signed can match a
  `tls:*`, `tls:NAME`, or `tls-sha256:HEX` item.
- Without `allow-cleartext-credentials`, a request with a bearer or Basic
  credential over plain HTTP gets 403, also when a group has the
  `anonymous` item. `allow-cleartext-credentials=true` and
  `--allow-cleartext-credentials` take such a credential. Use them for a
  server on a loopback address, or behind a proxy that terminates TLS and
  is not in `trusted-proxy`. A trusted proxy that reports the scheme `https`
  needs neither.
  `--allow-cleartext-credentials=false` refuses such a credential, also when
  the key is `true`. The rule applies to a read of the archive view too.
- A refusal of the receive endpoint that comes before the request body is
  read, as a 401, a 403, a 404, or a 405, reads and drops up to 1 MiB of the
  body within the session timeout, from `session-timeout` or
  `--session-timeout`, or 5 seconds, whichever is shorter, and then answers.
  On HTTP/1.1 a body that did not reach its end gets `Connection: close`.
- At start, before it binds a listener, the command reads and checks the
  client groups, the server group, the trust groups, and the key groups of
  the repository config (`ostrya-config(1)`, "CLIENT AND SERVER GROUPS").
  The start checks take each TLS file from its option, else from its key.
  A bad group, or a key group whose key the command cannot read, ends the
  command with `error: MESSAGE` at exit 1. The command reads the groups and
  the repository settings of the endpoint once, and a change applies at the
  next start. The command takes no `--policy`, `--push-credentials`,
  `--allow-anonymous-push`, `--read-only`, or `--client-ca`, and the option
  parser refuses each at exit 1.
- `--session-timeout` takes a positive number of seconds, and the default
  is 300. A push session with no request in progress for that time is
  aborted, and so is a push session with a request body that delivers no
  byte for that time. A value of 0 is refused at exit 1.
- `--max-sessions` takes a positive number, and the default is 16. A
  request that opens a session past it gets 503. A `session` request whose
  `Hello` fails its checks gets 422 also when the sessions are at the
  limit, because the checks run before a slot is taken.
- `--parallel-uploads` takes a number from 1 to 31, and the default is 4.
  `HelloReply` announces it, and a push session runs that many object
  streams at the same time. Over HTTP/2 the receive window of a stream is
  2 MiB, and the window of a connection is 2 MiB times this value. Another
  value is refused at exit 1.
- For each push session that commits, the command writes one `warning:
  STEP: MESSAGE` line to standard error for each warning of the session, as
  `ostrya receive` does. `reply-not-delivered` states that the connection
  did not take the `CommitReply` response.
- The paths, the methods, the status codes, and the order of the
  authentication checks of the receive endpoint are in
  `../format-reference.md`, "The receive endpoint" and "Authentication of the
  receive endpoint".
- `--listen` takes an IP address and a port. Give it once for each address.
  The default is `127.0.0.1:8080`, and port 0 lets the kernel choose a port.
  A host name is refused.
- `tls-cert` and `tls-key` serve HTTPS. Each needs the other, from a key or
  from an option. ALPN selects HTTP/2 or HTTP/1.1, and plain HTTP serves
  HTTP/1.1. An encrypted key is refused: the command has no option for a
  passphrase.
- `tls-client-ca` needs `tls-cert` or `trusted-proxy-client-cert`, from a
  key or from an option. A client that presents a certificate in the TLS
  handshake must present one the CA signed. A client that presents none
  completes the handshake, and the other auth items identify it. The CA
  also verifies the
  certificate that a trusted proxy forwards, also on a plain HTTP listener.
- `--body-timeout` takes a positive number of seconds, and the default is
  60. A connection ends when a response waits longer than that time for the
  client to take its next bytes. An HTTP/2 client that does not answer a
  ping within that time also loses its connection. A value of 0 is refused
  at exit 1.
- A `HEAD` gets the status and the `Content-Length` of a `GET`, and no
  body. For a `.filez` built on request it reads no xattr and no byte of
  the object.
- The command reads each TLS file once at start, up to 1 MiB. A file it
  cannot read, a larger file, or TLS material that gives no server
  configuration ends the command with `error: MESSAGE` at exit 1.
- When every listener is bound, the command writes one line for each to
  standard output, `http://ADDR:PORT/` or `https://ADDR:PORT/`, in the order
  of the addresses, and serves until the process ends. Standard output carries
  these lines alone, and warnings and errors go to standard error. SIGINT and
  SIGTERM end the process with the default action. A push session that did not
  start its commit does not commit, and the next transaction of the repository
  removes its staging directory. The commit of a push session writes its refs
  one by one, so a commit that runs when the process ends can stop after it
  wrote some of its refs and before it wrote the others.
- `ostree pull` from the command, over HTTP and HTTPS, from a repository in
  each mode the port reads, with a summary, passes `ostree fsck` on the
  pulled repository, in `crates/ostrya-cli/tests/serve.rs`. The served
  summary states `archive-z2` in `ostree.summary.mode` in each mode,
  `bare-user-shared` included.
- In a `bare-user` repository with a static delta, `ostrya summary --view`
  of the root summary names the delta. The served summary names no delta.
  A `bare-user` client of the tool pulls the objects loose, and
  `--require-static-deltas` fails the pull with `error: Fetch configured to
  require static deltas, but no summary deltas or delta index found`, in
  `crates/ostrya-cli/tests/serve.rs`.
- When the group of `anonymous` has `summary=false`, the command serves no
  summary, so `ostree pull` requests `refs/heads/NAME`. A pull of a ref that
  the group of `anonymous` reads succeeds and passes `ostree fsck`. A ref
  that the group does not read gets 404, and the tool 2026.1 exits 1 with
  `error: While fetching URL/refs/heads/NAME: Server returned HTTP 404`, in
  `crates/ostrya-cli/tests/serve.rs`.
- `ostree remote refs` and `ostree pull` read the summary of the
  `anonymous` item of a group with a deny item. The summary lists the refs
  that the group reads, the pull passes `ostree fsck`, and a pull of a
  denied ref exits 1. Over HTTPS with `tls-client-cert-path` and
  `tls-client-key-path` on the remote, the tool reads the summary of a
  `tls:NAME` item and pulls through it. A client with no certificate gets
  401 for the summary, and its pull exits 1. Both pulls are in
  `crates/ostrya-cli/tests/serve.rs`.
- In a repository with a collection id, `ostrya summary -u` and `ostree
  summary -u` give the same refs in field 0 and the same collection map,
  other than the anchor commit, with the mirror refs of the own id in
  field 0, in `crates/ostrya-cli/tests/serve.rs`.

### `send`

```text
ostrya send [--repo=PATH] [--client=NAME]
```

- The `send` feature of `ostrya-cli` builds the command. It is in the
  default set. `Repo::send` takes no feature of `ostrya`, so the command
  builds without `receive`, `push`, and `serve`.
- The session serves the `.cfs` composefs image of a commit as stored, as
  `serve` does.
- The client name is `--client`, else the value of `LOGNAME`, as for
  `receive`. With no name, the command writes `error: send needs a client
  name: give --client, or set LOGNAME` and exits 1 before it opens the
  repository. A name that an `ssh:` item cannot hold gets the error line of
  `receive` and exit 1. The session serves the refs that the client group
  of `ssh:NAME` reads, as `serve` serves them to that item
  (`../format-reference.md`, "Read access"). In a repository with client
  groups, a name that no group carries gets `error: no client group carries
  the item ssh:NAME` and exit 1 before the command reads its input. In a
  repository with no client group, the session takes the item `anonymous`,
  so it serves each local ref, each mirror ref, and the summary. At start,
  the command reads and checks the client groups and the server group. It
  reads no key of a trust group or a key group, and a bad group ends it
  with `error: MESSAGE` at exit 1.
  `--client` is safe only under a forced `command=` in `authorized_keys`,
  because a user with a shell can give any name.
- The command serves one pull session over standard input and standard
  output, through `Repo::send_with`. An ssh pull runs it on the remote side. It answers each
  `Get` path as the archive view of `serve` answers a `GET` of that path. A
  path that the view refuses, and a path that the client cannot read, get
  the reply of a path that is not found.
- The command takes no lock and writes no file in the repository. An
  account with read access to the repository serves an `archive`,
  `bare-user`, `bare-user-only`, or `bare-user-shared` repository. A `bare`
  or `bare-split-xattrs` repository needs an account that can read every
  object and its extended attributes. A file that the account cannot read
  ends the session with `internal`.
- Standard output carries the frames of the session alone. The command
  writes `error: MESSAGE` to standard error on failure. For each directory
  under `refs/mirrors/` whose name is not a collection id, a `ListRefs` with
  the key `collections` writes one `warning:` line to standard error, one
  time in each session. When the summary of the item does not match the
  client groups, `summary` and `summary.sig` get the reply of a path that is
  not found, and the command writes one `error:` line that names the item,
  one time in each session. The command writes nothing else to standard
  error, also under `-v`.
- It exits 0 when standard input ends at a frame boundary, an empty input
  included. It exits 1 after an `Error` frame and after a failed write.
- The input is read through a read-ahead ring of 256 KiB and a buffer of
  64 KiB. Under the smol backend, standard output goes through a write pipe
  of 8 MiB, and a flush waits until each byte reached the descriptor. So
  the command flushes only when its input buffer holds no complete `Get`
  frame, and after `Error`. The output buffer is 64 KiB, and each chunk of
  a body holds 64 KiB less 4 bytes. With the reader of one body, a session
  holds about 9 MiB under the smol backend. A `Get` frame at the limit adds
  about 2 MiB, because the frame body and the decoded path are in memory at
  the same time.
- The command installs no signal handler. It holds no transaction, so its
  end leaves no staging directory.
- An `authorized_keys` entry restricts an ssh key to pull from one
  repository:

  ```text
  restrict,command="ostrya send --repo=/srv/repo" ssh-ed25519 AAAA...
  ```

  sshd runs the forced command and ignores the command of the client. So a
  key forced to `ostrya send` pulls and cannot push, and a key forced to
  `ostrya receive` pushes and cannot pull. A user that pulls and pushes
  holds two keys.
- `crates/ostrya/tests/send.rs` and `crates/ostrya-cli/tests/send.rs` hold
  the tests.

### `composefs-image`

```text
ostrya composefs-image [--repo=PATH] (--add=REV | --get-path=REV | --check=REV)
```

- The command takes no feature. It takes exactly one of `--add`,
  `--get-path`, and `--check`. With none or with two, the option parser
  writes the usage text and the error, and the command exits 1.
- `--add` builds the composefs image of the commit and stores it as
  `objects/<xx>/<commit>.cfs`. The commit must carry
  `ostree.composefs.digest.v0`. A commit without the key, or with a value
  that is not an `ay` of 32 bytes, gets `error: MESSAGE` at exit 1, and the
  command stores nothing. The command checks the digest of the image
  against the key before it installs the image. A valid stored image stays,
  and an image whose digest is not the key or that does not read is
  replaced. A partial commit is
  not refused, and the build fails if an object of its tree is absent. On
  success the command writes nothing.
- `--get-path` prints the absolute path of the image, also for a relative
  `--repo`. It does not read the image. If the image is absent, the command
  writes `error: commit CHECKSUM has no composefs image` and exits 1.
- `--check` reads the whole image and computes its fs-verity digest. It
  writes nothing and exits 0 if the digest is the key. It writes one
  `error:` line and exits 1 if the image is absent, if the commit does not
  carry the key, or if the digests are different. The line for different
  digests names both digests.
- `commit --generate-composefs` stores the image with a new commit. The
  option turns on `--generate-composefs-metadata`, so the commit is the
  commit that the tool writes with `--generate-composefs-metadata`. The tool
  refuses `--generate-composefs` as an unknown option.
- The tool has no image object. A repository that holds an image is a port
  repository, and the cross-checks with the tool run on repositories with
  no image. `../format-reference.md`, "The composefs image object", states
  the object.
- `prune` removes an image with its commit and removes an image whose
  commit is absent. No count of its output includes an image.
- `fsck` checks each image against the key of its commit after the object
  walk. For an image whose digest is not the key, an image that does not
  read, or an image whose commit has no key or a malformed key, it writes
  one `composefs image of commit CHECKSUM: REASON` line to standard error,
  and the run ends with `error: Repository corruption encountered` at exit
  1. `--delete` unlinks such an image, and no image marks a commit as
  partial. If the commit of an image is present and does not load, `fsck`
  writes the same line and keeps the image. For an image whose commit is
  absent, it writes `Composefs image with no commit: CHECKSUM` to standard
  output, and this line is not an error. A repository with no image gets
  none of these lines.
- `pull`, `pull-local`, `push`, `send`, and `serve` carry the image
  (`../format-reference.md`, "The composefs image object").
- `static-delta generate` puts the image of the target commit in the delta,
  and `static-delta apply-offline` stores it after it checks the digest
  against the key (`../format-reference.md`, "The composefs image in a
  static delta").
- `crates/ostrya/tests/composefs_image.rs`,
  `crates/ostrya/tests/composefs_transfer.rs`, and
  `crates/ostrya-cli/tests/cli.rs` hold the tests.

### ssh access with `authorized_keys`

An `authorized_keys` entry restricts an ssh key to push into one
repository:

```text
restrict,command="ostrya receive --repo=/srv/repo" ssh-ed25519 AAAA...
```

- sshd runs the forced command and ignores the command of the client. The
  `ostrya receive --repo='PATH'` of the client reaches the server only in
  the `SSH_ORIGINAL_COMMAND` environment variable. So the key pushes into
  the forced repository, whatever path the address holds.
- Give an absolute path to `--repo`. The client groups that must hold
  against the pusher are in a repository config that the pusher cannot
  write.
- sshd runs the `command=` string through the login shell of the user, with
  `-c`. The shell and its startup files must write nothing to standard
  output, because standard output carries the frames of the session.

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
  it matches the four literals (`../format-reference.md`, "Config file
  (`<repo>/config`, GKeyFile / INI)"). So
  `ostree` opens a repository holding `lock-timeout-secs=bogus`,
  `lock-timeout-secs=+101`, `tmp-expiry-secs=bogus`,
  `min-free-space-percent=bogus`,
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
  each key where it is used, so a subcommand that never reads a key runs to
  completion whatever that key holds, whether the subcommand writes or not:
  `ostrya refs` over that repository lists the refs at exit 0, and `ostrya
  checkout` over a repository holding `locking=bogus`, `per-object-fsync=bogus`,
  or a `min-free-space-size` the size grammar does not hold checks the tree out
  at exit 0, where the tool refuses each of those three at exit 1. The reach of
  the port's refusal is therefore per key and per subcommand, and the list of
  the keys a subcommand reads is the list of the values it can refuse. Within
  `commit` the port reads the whole `[core]` set the transaction needs in one
  place, after the `--statoverride` and `--skip-list` files and after the branch
  check of `-b` and `--orphan`, and before `--parent`, the metadata options, the
  editor, and the repository lock. One fault on a `commit` line parts the two
  nowhere, since both refuse it and exit 1. Two faults report the tool's config
  refusal and the port's earlier check, so `commit --statoverride=no-such-file`
  against a repository holding `fsync=bogus` names the config from the tool and
  the file from the port. Both exit 1 with no object and no ref written.
  Within `checkout` the port reads `[core] fsync` alone, and it reads it after
  the composefs export decision, which applies no durability policy, and ahead
  of the first checkout. A record stream carrying no pair reaches the read and
  refuses such a value too. A `--composefs` line reaches it nowhere, so the port
  exports the image at exit 0 where the tool refuses the repository, which
  "checkout" above records as a divergence. Within `prune` the port reads
  `[core] locking` first, in the `prune` handler, for the line it writes where
  that key is false. The library reads `[core] locking` a second time, together
  with `[core] lock-timeout-secs`, as it takes the repository lock, and it
  reads `[core] tombstone-commits` and `[core] fsync` inside the run. All of
  them come after every option refusal and after the
  revision `--delete-commit` names, so a line the port refuses on its options
  refuses the same way whatever those values hold. The timeout is read even
  where `locking` is false, so a malformed `lock-timeout-secs` refuses a prune
  on a repository that takes no lock. A `--static-deltas-only` run returns
  before the last two, so it refuses neither of them.
- The port reads at most 1048576 bytes of `config`. It refuses a larger file
  with `config exceeds the 1048576-byte size cap` when it opens a repository,
  and at each later read of the file. The tool reads a `config` of any size.
  The cap bounds the memory of a read of `config` (`../../CLAUDE.md`,
  "Working conventions").
- Every subcommand that opens a transaction reaps `tmp/`, in the port and in
  the tool. Both skip `cache`, and both remove an entry that is not a staging
  entry once its mtime is older than `tmp-expiry-secs`: a directory as a whole
  tree judged by its own mtime, and a symlink as the link itself.
  `../format-reference.md`, "Old entries in `tmp/`", states the tool's rule
  and the port's rule. `commit` over the same aged `tmp/` leaves the same
  entries on both sides (`commit_reaps_aged_tmp_entries_as_the_tool_does` in
  `crates/ostrya-cli/tests/cli.rs`). No matrix cell states the comparison,
  because `tmp/` carries no published state and the oracles read `objects/`
  and the refs tree. Three divergences stand:
  - The port exempts a `staging-*-lock` file from the age test, and it removes a
    staging directory with no lock file only once its age exceeds
    `tmp-expiry-secs`. The tool unlinks a held lock file that is older than
    `tmp-expiry-secs`, and the next transaction then removes the lockless
    staging directory at any age. The tool's rule removes the staging
    directory of a live transaction that runs longer than `tmp-expiry-secs`,
    and it can remove a directory that another process creates before its lock
    exists.
  - The port reaps at the start of a transaction, and the tool reaps at the end
    of a transaction, on a commit and on an abort. A run that opens one
    transaction therefore reaps before it writes in the port and after it
    writes in the tool.
  - The tool reuses a staging directory of the current boot whose lock it can
    take. The port creates a new staging directory for each transaction and
    reuses none. "P2", in the signing divergences, records what each leaves
    in `tmp/` after a run.
- The port creates the temp file of a ref write in `tmp/`, and the tool
  creates it in the directory that holds the ref. The `fdatasync` of a ref
  write therefore reaches a file under `tmp/` in the port and a file under
  `refs/` in the tool (`commit_fsync_policy_controls_the_syscalls` in
  `crates/ostrya-cli/tests/cli.rs`). The port also creates the temp symlink
  of an alias write in `tmp/`. It writes each `.commitmeta` it does not
  stage, and each `.tombstone-commit`, through a temp file in `tmp/`. No
  published byte differs.
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

## Output formats

`cli-behavior.md`, "CLI output formats", records the output format, the error
text, and the exit status of each command that it lists. Its subsection "The
GVariant text form" records the text form that the reading commands share.
The cells of `m10-cli-behavior.matrix` compare the output of the port with the
output of the tool. This file records each difference in output at its
command.

## Open work

`../roadmap.md`, "P3 commands", lists the commands of "P3" that the port does
not carry. An option that the port does not carry by decision is not in a
`Missing:` list. The text of its command states it as a difference, as it
states `remote add-cookie` and `remote refs --cache-dir`.
