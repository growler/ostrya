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
- an empty refspec searches the ref store in the tool, so `rev-parse ''`
  resolves in a repository holding exactly one ref, reports `error: Refspec
  not unique` where it holds more, and reports `error: Invalid refspec ` where
  it holds none. `refs --create= REV` reads the same search as an existence
  check, so it reports `error: --create specified but ref  already exists`
  against the one-ref repository. The port refuses the empty name in every
  repository with `error: Invalid refspec `, which is the tool's own text for
  the empty repository, and exits 1 wherever the tool exits 1;
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

Two resolution behaviors the tool has and the port does not, each recorded in
`../format-reference.md` with the observation that recovered it:

- an abbreviated commit checksum resolves in the tool, from a hex prefix as
  short as one character, wherever a revision is taken. Reproducing it needs a
  scan of `objects/` inside `Repo::resolve_rev`, which is library work outside
  Phase 17b's CLI wiring, and it changes resolution for every subcommand. One
  consequence reaches `commit`'s implicit parent, observed while Phase 17c
  compared its options: a branch name that is a hex prefix of an object the
  repository already holds resolves for the tool, so `commit -b <prefix>` on a
  fresh branch parents its commit on that object, where the port writes a root
  commit. Against a repository holding one commit, `commit -b <the commit's first
  two characters>` reproduces it;
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
and "`config get`". Five tool behaviors around them are observed and
deliberately not reproduced:

- `show --print-variant-type=TYPE` takes any GVariant type string in the tool,
  and the port takes the set its codec models -- booleans, bytes, `u`, `t`,
  strings, variants, arrays, tuples, and dict entries
  (`ostrya-gvariant`, `Type::parse`). A type outside it, `d` and `q` among them,
  reports `error: invalid format: invalid type signature "<type>" at offset 0:
  unsupported type character` and exits 1 where the tool prints the value. The
  port's set covers every type the on-disk format uses, so no metadata object
  is out of reach; a wider set would need value kinds nothing in the format
  stores. A signature that is not a type at all kills the tool with a signal
  (`--print-variant-type=zz` exits 139 after two GLib assertions), and the port
  refuses it with the same line;
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
- the GPG signature report a signed commit draws agrees line for line except the
  instant the signature was made: the tool renders it through gpgme in the host's
  locale and time zone (`Wed 05 Aug 2026 17:11:19 CEST`) and the port renders it
  in UTC in the shape its own `Date:` line carries (`2026-08-05 15:11:19 +0000`).
  Matching the tool would need a locale database and the host time zone, neither
  of which the port carries, and the rendering states no repository fact. The
  algorithm name, the short key id, the user id, and the three verdict lines are
  the same in both.

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
`--canonical-permissions`, and, since Phase 17c, `--owner-uid=UID`,
`--owner-gid=GID`, `--no-xattrs`, and `--timestamp=TIMESTAMP`. Missing:
`-m/--body`, `-F/--body-file`,
`-e/--editor`, `--no-bindings`, `--bind-ref=BRANCH`, `--base=REV`,
`--tree`, `--add-metadata-string=KEY`, `--add-metadata=KEY`,
`--keep-metadata=KEY`, `--add-detached-metadata-string=KEY`,
`--bootable`, `--mode-ro-executables`,
`--selinux-policy=PATH`, `-P/--selinux-policy-from-base`,
`--selinux-labeling-epoch`, `--link-checkout-speedup`, `-I/--devino-canonical`,
`--tar-autocreate-parents`, `--tar-pathname-filter=REGEX`,
`--skip-if-unchanged`, `--statoverride=PATH`, `--skip-list=PATH`, `--consume`,
`--table-output`, `--gpg-sign=KEY-ID`, `--gpg-homedir=HOMEDIR`, `--sign=KEY`,
`--sign-from-file=PATH`, `--sign-type=NAME`, `--generate-sizes`,
`--generate-composefs-metadata`, `--fsync=POLICY`.

`--tree` is needed because the port reads a tar stream from standard input where
the tool takes `--tree=tar=PATH`; the two forms must converge. The port's stdin
form honors `--owner-uid`, `--owner-gid`, and `--no-xattrs`; it ignores
`--canonical-permissions`, which reaches the filesystem walk alone, so that
option and the stdin form are not combined until `--tree` lands.

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

One `commit` divergence sits at the values `--parent` takes, the parenting
behavior itself being shared (`../format-reference.md`, "CLI output formats").
The tool reads the value with a reader that takes a 64-character lowercase
checksum or the literal `none`, and the port resolves any revision there, which is
a superset of that syntax like the leading `--repo` form above. Each side refuses
what it cannot read, at exit 1, writing nothing:

- an abbreviated checksum and a refspec report `error: Invalid rev <value>` from
  the tool, where the port resolves a refspec naming a ref and reports `error:
  Refspec '<value>' not found` for one naming none;
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
implementations now carry: `commit -b <64 lowercase hex>` is refused in the same
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
'a^^'` both reach it. An empty base searches the tool's ref store, so `-b '^'`
against a repository holding no ref reports `Invalid refspec `, naming the base
it split off. Reading the name ahead of the tree also moves one fault order: a
tree path that does not open is reported by the port, which reads the tree
first, and never reached by the tool.

The guard is what keeps a ref of that shape out of a repository the port writes.
Where one stands, the tool's ref enumeration skips it without a word and its
`prune --refs-only` reads the commit that ref holds as unreachable and deletes
it, leaving the ref file over an absent object, where the port enumerates the
name and keeps the commit. That is the destructive class the `odd~1` item of
"P1" records for the ref-name character class, and the two read as one class:
an out-of-band write is the only arrival for either name. The character class
itself stays deferred, so a `^` inside the name parts the two -- the port writes
`a^b` and the tool refuses it with `Invalid refspec a^b`.

`checkout` accepts `--repo`, `-H/--require-hardlinks`, `-C/--force-copy`,
`--composefs`, and, since Phase 17c, `-U/--user-mode` and `--subpath=PATH`.
Missing: `--disable-cache`,
`--union`, `--union-add`, `--union-identical`, `--whiteouts`,
`--process-passthrough-whiteouts`, `--allow-noent`, `--from-stdin`,
`--from-file=FILE`, `--fsync=POLICY`, `-M/--bareuseronly-dirs`,
`--skip-list=FILE`, `--selinux-policy=PATH`, `--selinux-prefix=PREFIX`,
`--composefs-noverity`.

The destination trees `-U` and `--subpath` produce agree with the tool's file for
file, in `archive`, `bare-user`, and `bare` (`../format-reference.md`,
"Checkout"). Three divergences stand at the values `--subpath` takes and one at a
flag pair:

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
- `-U -H` together are refused by the tool in a repository whose mode cannot
  hardlink under a user-mode checkout (`error: Bare repository mode cannot
  hardlink in user checkout mode`, observed for `bare`, and accepted for
  `archive`, `bare-user`, and `bare-user-only`). The port's `-H` is a no-op, so
  it accepts the pair everywhere and copies. Giving `-H` its refusal is `-H`
  semantics, which belongs with the remaining `checkout` options.

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
records. Five divergences stand:

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
  the user ids in the tool's own shape, and leaves out the `Advanced update URL`
  and `Direct update URL` lines the tool prints per user id: they name the key's
  OpenPGP Web Key Directory location, derived from a hash of the address, and
  state no repository fact. The creation instant parts the same way the GPG
  signature report in "P1" does -- the tool renders it in the host locale and
  time zone and the port in UTC. `remote summary` renders its `Timestamp` and
  `Last-Modified` lines the same way, so a report compares byte for byte with
  `TZ=UTC` set.

Two messages the port words for itself, each reporting a condition the tool
reports through gpgme: `remote gpg-import` with no `--keyring` and no `--stdin`
(the tool's `GPG: Unable to export keys: GPGME: No data`), and a `KEY-ID` naming
no key in the source (the tool's `GPG: Unable to find key "<id>": GPGME: End of
file`).

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

## Output formats still to recover

A script reads standard output, so the format is part of the surface. The
formats of `commit`, `refs`, `rev-parse`, `cat`, `show`, `log`, `ls`, and
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
- `commit --table-output`.
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
8. The remaining P2 gaps.
9. The rest of P3.
