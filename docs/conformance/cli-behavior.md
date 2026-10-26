# CLI behavior of the ostree command

This document records the behavior of the `ostree` command. Each observed
fact about the tool comes from runs of the tool as a black box. These runs give
its output, its error text, its exit status, and the files that it writes. No
fact derives from the libostree source (`../../CLAUDE.md`, "Licensing and
clean-room discipline").

The document records:

- the destination tree that a checkout writes
- the options of `export` and the options of a `tar=` source of `commit`
- the request order of a pull, the effect of the pull options, and the
  signature checks during a pull
- the `--fsync` vocabulary and the sync calls that it controls
- the output format, the error text, and the exit status of the commands
  that "CLI output formats" lists

The tool is `ostree` 2026.1, built with the `sign-ed25519` feature. This build
refuses the `spki` signature engine with `error: Requested signature type is
not implemented`. A statement about the tool with no label is observed
behavior: a run of this build records the fact. Two labels mark the other
statements:

- Not observed: no run of the tool records the item that follows the label.
  Where the port has a rule for the item, the next sentence states it and
  names the port.
- Design target: the fact comes from the documentation and the standards. No
  run of the tool confirms it.

The port behaves as this document states, except where `cli-surface.md`
records a difference. A sentence about the port names the port.

The `spec:` values of the conformance records name the headings of this
document. `../format-reference.md` specifies the on-disk format, the tar
member format, and the files that a repository serves. `cli-surface.md`
records the divergences between the tool and the port.

## Checkout

A checkout writes the tree of a commit to a filesystem. The destination is not
part of the on-disk format, so the durability choices (whether to fsync) carry
no byte-exact requirement. This section states the metadata that each checkout
writes and when a checkout hardlinks a loose object. These rules hold for
commits that the tool wrote, checked out with `checkout`, `checkout -U`, and
`checkout -C`.

### Checkout modes

The tool has two checkout modes. The faithful checkout (`checkout`) restores
the full metadata. The unprivileged checkout (`checkout -U`) restores no
ownership and no extended attributes (xattrs).

- Faithful: the checkout chowns a regular file to the logical uid and gid. It
  sets the full logical permission bits (`mode & 0o7777`) and applies the
  logical xattrs. A symlink is a real symlink. The checkout lchowns it to the
  logical uid and gid and applies the logical xattrs of the link. A directory
  gets the logical uid and gid, the full logical mode (`mode & 0o7777`), and
  the logical xattrs.
- Unprivileged: no chown and no xattrs. A regular file that the checkout
  writes takes `mode & 0o1777`. So the checkout clears the setuid and setgid
  bits, and keeps the sticky bit and the rwx bits, group write and other write
  included
  (`4755` and `6755` become `0755`, `1755` and `7755` become `1755`, `1644`
  stays `1644`, `0666` stays `0666`). A directory takes the full
  `mode & 0o7777`, so all three special bits stay (`2755` stays `2755`, `1644`
  stays `1644`). A symlink is a real symlink with no chown and no xattrs.

The tool keeps `security.capability` on a file that it writes under the
faithful checkout. A checkout from an `archive` repository and a `-C` checkout
from a `bare` repository both keep a `cap_net_raw=ep` value. A file recorded
at 04755, owner 1234:5678, with a capability and a `user.*` xattr, keeps its
mode, its owner, and both xattrs.

The port applies the owner, then the xattrs, then the mode to each regular
file that it writes under the faithful checkout.
`../format-reference.md`, "Write path: loose-object inode modes and
durability", gives the reason: a chown of a regular file removes
`security.capability` and clears special bits. A chown of a directory removes
no xattr and keeps the special bits.

The mask of the unprivileged checkout applies to a regular file that the
checkout writes. A regular file that the checkout hardlinks keeps the mode of
the object inode. In `bare-user` that inode carries no special bit
(`../format-reference.md`, "Write path: loose-object inode modes and
durability"). So an unprivileged checkout of a `bare-user` object drops the
sticky bit where it hardlinks, and keeps it where `-C` forces a copy.

These rules hold for the modes `1644`, `1755`, `2755`, `4755`, `6755`,
`7755`, and `3755`, on files and on directories. They hold for `archive`,
`bare`, `bare-user`, and `bare-user-only` repositories, under `checkout`,
`checkout -U`, and `checkout -U -C`. Under `-U -C` the result is the mask of
the unprivileged checkout in each of these repository modes.

Examples from a `bare` repository:

- A file at `0666` checks out at `0666` under both checkout modes.
- A file at `4755` checks out at `4755` under the faithful checkout and at
  `0755` under the unprivileged checkout.
- A directory at `2755` checks out at `2755` under both checkout modes.
- A file with a `user.demo` xattr keeps the xattr under the faithful checkout
  and loses it under the unprivileged checkout.

### Hardlink and copy

The tool hardlinks the loose object into the destination when the stored inode
form of the object is already byte-identical to the destination file. The
hardlink raises the link count of the object inode. In each other
case the tool copies. For a regular file, by repository mode and checkout
mode:

- `bare` and faithful: hardlink. `bare` and unprivileged: copy.
- `bare-user` and faithful: copy. `bare-user` and unprivileged: hardlink. The
  hardlinked file carries `user.ostreemeta`, because it shares the object
  inode. So a byte-exact unprivileged checkout of a `bare-user` repository
  needs the hardlink: a copy omits that xattr.
- `bare-user-only` and either checkout mode: hardlink. The object carries no
  ownership and no xattrs, and its inode mode is the canonical form
  (`../format-reference.md`, "Write path: loose-object inode modes and
  durability"). So the tool never chowns the file that it checks out, and the
  owner of the file is the user that wrote the object. A faithful and an
  unprivileged checkout of a `bare-user-only` repository give identical trees.
  The port checks out a `bare-user-only` repository under the unprivileged
  checkout, whatever checkout mode the command line asks for.
- `bare-user-shared`: a mode of the port alone. The port copies under both
  checkout modes. The object inode does not carry the logical mode
  (`../format-reference.md`, "bare-user-shared mode"), so the port never
  hardlinks it. The copy applies the logical mode from `user.ostreemeta`.
- `bare-split-xattrs`. Not observed: the result of the tool. The port copies
  under both checkout modes.
- `archive`: copy under both checkout modes. Under the unprivileged checkout
  the tool hardlinks from its uncompressed object cache.

The uncompressed object cache is the directory `uncompressed-objects-cache/`
at the top level of the repository. It is outside the on-disk format. It uses
the loose fanout and holds one uncompressed `.file` for each content object.
The tool creates it for an `archive` repository checked out with `-U`, and for
no other repository mode and no other checkout mode. The tool hardlinks each
regular file of that destination to its file in the cache.

`checkout --disable-cache` stops the tool from writing and reading the cache,
so each destination file gets an inode of its own. The cache changes the link
count of a destination file alone. The bytes and the metadata of the
destination are the same with the cache and without it. `cli-surface.md`,
"P2", `checkout`, records the port side.

The tool hardlinks a symlink only under `bare` and the faithful checkout. The
destination link count is then 2. In each other case the tool creates the
symlink again, with link count 1. This includes `bare-user-only`, whose object
is a real symlink. `bare-user` and `bare-user-shared` store a symlink as a
regular file (`../format-reference.md`, "Repository modes and on-disk
storage"), so a real destination symlink cannot share their inode.

The tool hardlinks an object if and only if the object inode is already
exactly the target inode. `checkout -C` forces a copy and stops every
hardlink.

A zero-length regular file is the one exception. The tool writes it as a new
file, so its destination has its own inode at link count 1. A checkout of a
`bare` repository with `checkout -H` shows this. The tree holds a
zero-length file at 0644, a zero-length file at 0600, a one-byte file, a
100-byte file, and a 100-kibibyte file. The two zero-length destinations get
link count 1 on inodes of their own. The other three get link count 2 on the
inodes of the loose objects.

Not observed: the link count of a zero-length destination file in the other
repository modes and without `-H`. The port writes a zero-length file as a new
file in each repository mode and under both checkout modes. The content and
the metadata of the destination do not depend on this rule.

### Required hardlinks

`checkout -H/--require-hardlinks` makes the tool refuse each entry that the
checkout must copy. The refusal comes at the entry. So the tool writes a
commit that holds no such entry whole at exit 0 in each repository mode,
`archive` included. An empty commit and a commit of directories alone are
among these commits.

The refusal comes before the destination disposition. So the tool refuses an
entry that `--union-add` keeps and an entry that `--union-identical` calls
identical. The refusal comes after the whiteout verdict. So the tool takes a
marker that removes a name and a marker that writes a character device. A
`--skip-list` entry that prunes an entry, or a `--subpath` that does not
select it, keeps the walk away from the entry.

The tool treats each shape as follows:

- The tool refuses no directory, in any repository mode.
- The tool refuses no zero-length regular file, in any repository mode
  ("Checkout", "Hardlink and copy").
- The tool refuses a regular file of non-zero length wherever "Checkout",
  "Hardlink and copy", gives a copy. This includes `archive` under both
  checkout modes.
- The tool refuses a symlink in `archive` under both checkout modes and in
  `bare` under the unprivileged checkout, and nowhere else. The tool creates a
  symlink again in `bare-user` and in `bare-user-only` under both checkout
  modes, and refuses neither under `-H`.

Not observed: the `-H` result of the tool in `bare-split-xattrs`.
`cli-surface.md`, "P2", `checkout`, records the port rule for
`bare-split-xattrs` and `bare-user-shared`.

These rules hold for four commits of one shape each: one directory, one
zero-length file, one one-byte file, and one symlink. They hold for `archive`,
`bare`, `bare-user`, and `bare-user-only` repositories under both checkout
modes.

A refusal part-way through a walk leaves the entries that the walk already
wrote. For example, a commit holds `a/empty`, `a/link`, and `b/real`, and the
tool checks it out of a `bare` repository with `-U -H`. The destination then
holds `a` and `a/empty`, and the walk stops at the symlink.

### Cross-device destinations

Under `-H`, the tool refuses a destination directory on another filesystem
than the repository. The refusal comes before the tool writes any entry of the
directory, whatever the subtree holds. The check comes after the tool creates
the directory. With a directory-only commit, the tool exits 1 with
`Unable to do hardlink checkout across devices (src=<dev> destination=<dev>)`,
and the destination directory exists and is empty. The check comes before the
refusal at an entry, so an `archive` repository checked out across devices
reports the device refusal.

The tool does the check at each destination directory that the walk enters:
the destination root and each directory below it, new or reused. A union mode
follows a destination symlink, so a symlink to a second filesystem can put a
subtree there. The tool then refuses whatever the subtree holds, and writes
nothing into the directory on the second filesystem. Each of these subtrees
gives the device refusal: one empty directory, one zero-length file, one
symlink, or one regular file. A zero-length file together with a regular file
gives it too.

The refusal comes where the walk enters the directory. So it comes after a
refusal at an entry in a directory that the walk reads first. It comes before
a refusal at an entry in a directory that the walk reads later. For example, a
commit holds `aa/real` and `zz/sub`. With `zz` of the destination on the second
filesystem, the tool reports the refusal at the entry. With `aa` on the second
filesystem, it reports the device refusal.

The device refusal does not depend on the repository mode: `archive`, `bare`,
`bare-user`, and `bare-user-only` each give it.

Under `-H`, a `--subpath` that names a file or a symlink reaches no directory
walk and gets no such check. The tool creates the destination directory and
tries the link. Where the repository mode and the checkout mode hardlink the
shape, the tool reports `Hardlinking <object> to <name>: Invalid cross-device
link` at exit 1. The destination directory then stays empty. No mode hardlinks a
zero-length regular file, so the tool writes it into the destination at exit 0.
These rules hold for a `bare` repository under the faithful checkout, which
hardlinks a regular file and a symlink.

### Destination directories

The tool always creates a directory as a new directory and never hardlinks
one. A directory gets its full logical mode under both checkout modes. The
tool applies the metadata after it writes the children of the directory, so a
restrictive mode does not block these writes.

The destination root gets the dirmeta of the root of the checked-out tree or
subtree. A root committed at mode `0750` gives a destination root at `0750`.
A subpath to a directory at `0755` gives a destination root at `0755`.

### Directory mode mask

`checkout -M/--bareuseronly-dirs` reduces the mode of each directory
that the checkout creates to `mode & 0o775`. The mask reaches the destination
root and each directory below it, in each repository mode and under both
checkout modes. A directory that the checkout reuses under a union mode keeps
its own mode, with the option and without it. The option does not change a
regular file or a symlink. The tool applies the mode explicitly, so the
process umask does not reduce it further.

In `bare-user-only` the option changes nothing, because the mask keeps each
directory mode that a `bare-user-only` commit records. The option changes
nothing in the repository, and `commit` has no matching option.

The tool gives these results for thirteen directory modes:

- `0700`, `0705`, `0774`, and `0775` stay as they are.
- `0666` gives `0664`, `0776` gives `0774`, and `0777` gives `0775`.
- `1755`, `2755`, `4755`, and `6755` give `0755`.
- `3775` and `7777` give `0775`.

Each result equals `mode & 0o775`.

### Overwrite policy

The overwrite mode decides how the tool treats an existing destination. The
tool has four overwrite modes. The last three are the union modes.

- Default (`checkout`): the destination must not exist. An existing
  destination directory is an error (`mkdirat: File exists`), empty or not.
  The tool creates each subdirectory with `mkdirat`, and an existing
  subdirectory is an error. A symlink at the destination is an error
  (`mkdirat: File exists`), as each other existing destination is.
- Union-files (`checkout --union`): the tool reuses an existing
  directory and does not apply its metadata again. It overwrites an existing
  file or symlink, whatever its content, mode, or target. It adds new entries
  and leaves in place each existing entry that the commit does not hold. An
  existing directory where the commit holds a regular file or a symlink is an
  error.
- Add-files (`checkout --union-add`): the tool writes only the entries
  that do not exist. It keeps an existing entry of any type. This includes a
  directory where the commit holds a regular file, and an entry that the
  commit does not hold. An existing regular file where the commit holds a
  directory is an error, because the walk goes into the name. The tool follows
  a symlink at that name.
- Union-identical (`checkout --union-identical`): the tool adds new
  entries and keeps an existing entry that is identical to the entry that the
  checkout writes. A different existing entry is an error. The tool takes the
  option only together with `--require-hardlinks`, in each repository mode.
  Without that option the tool exits 1 and writes nothing.

The three union modes take an existing destination and create an absent one.
A destination that an overwrite mode creates takes the dirmeta of the root of
the checked-out tree. A destination that already existed keeps its own
metadata. A destination whose parent does not exist is an error in each
overwrite mode (`mkdirat: No such file or directory`).

The three union modes follow a symlink to a directory at each directory name:
the destination itself and each directory name inside the tree. They write
into the target and leave the link in place. The tool follows the link
wherever it points. So a union checkout writes outside the destination tree
where a symlink inside the destination leads there. For example, a commit
holds `d/g`, and the destination holds an absolute symlink `d` to a directory
elsewhere on the filesystem. The checkout exits 0 and creates `g` in that
directory.

A symlink that resolves to nothing, to a non-directory, or to itself ends the
checkout at exit 1 with the error of the open:

- `opendir(d): No such file or directory`
- `opendir(d): Not a directory`
- `opendir(d): Too many levels of symbolic links`

Under union-files with `--whiteouts`, the tool removes the link and creates a
directory in its place ("Checkout", "Whiteouts").

Under union-identical, a regular file is identical to the object in two
cases:

- Its `(st_dev, st_ino)` equals that of the loose object.
- Its file-object checksum equals the checksum of the object, and its
  permission bits equal those of the loose object inode. The checksum covers
  the content bytes, the uid, the gid, the permission bits, and the xattrs.
  The repository mode reduces them as it reduces an ingested entry.

The tool reads neither the modification time nor the link count. In
`bare-user`, the inode rule `(logical_perm & 0o775) | 0o400` drops some bits
of the logical mode (`../format-reference.md`, "Write path: loose-object inode
modes and durability"). So the permission-bit condition makes an object
identical to nothing when its logical mode carries such a bit. These modes are
`0666`, `0777`, and each mode with a setuid, setgid, or sticky bit. In `bare`
the inode carries the full logical mode. So there the checksum condition gives
the permission-bit condition, and a setuid object is identical to a setuid
destination.

In `bare-user-only`, the reduction drops the ownership and the xattrs and
masks the permission bits. So a destination that the invoking user owns, with
an unrelated xattr, is identical. A destination whose raw permission bits
differ from those of the object inode is not identical. The tool compares a
symlink by its target alone, whatever the ownership of the object. It reuses a
directory with no comparison, as the other union modes do.

The rules of union-identical hold for `bare`, `bare-user`, and
`bare-user-only`. The content bytes, the permission bits, the uid, the gid, and
the xattr set each make the entry different. The modification time, the inode,
and the link count do not. These rules hold for each logical mode from `0400`
through `04755`, against a destination of the same mode and against a
destination of `0755`.

### Type conflicts

A type conflict between the destination and the commit stops the checkout. No
overwrite mode changes the type of an entry. `--whiteouts` is the one
exception ("Checkout", "Whiteouts"). The conflicts are these:

- A regular file at a destination name where the commit holds a directory is
  a conflict in each overwrite mode. The tool goes into the existing name to
  merge the children of the committed directory, so it reports
  `opendir(<name>): Not a directory`. The three union modes follow a symlink
  at that name, with the outcome that "Checkout", "Overwrite policy", states.
- A destination directory where the commit holds a non-directory is a conflict
  under the default, union-files, and union-identical modes. Under union-files
  the tool reports `renameat(...): Is a directory`. Under add-files the tool
  keeps the existing directory and writes nothing for that name.

### Whiteouts

The tool reads three marker names, under two independent options. Each option
reads its own names and no others. With both options off, each marker checks
out as an ordinary entry under its own name, and the tool removes nothing.

`checkout --whiteouts` reads two Docker-style names:

- `.wh.<name>` removes `<name>` from the destination directory, and the tool
  does not write the marker. The removal reaches an entry of any type. It goes
  into a directory and removes the whole subtree. A target that the
  destination does not hold is a no-op at exit 0.
- `.wh..wh..opq` clears the destination directory before the tool writes any
  entry of the directory. The tool does not write the marker.

`checkout --process-passthrough-whiteouts` reads one overlayfs name,
`.ostree-wh.<name>`. The marker becomes a character device with device number
0:0 at `<name>`, and the tool does not write it under its own name. The tool
ignores the content of the marker. `.ovl.wh.`, `.overlay.wh.`, and
`.ostree.wh.` are ordinary name prefixes with no meaning.

The removal and the clear take different orders. The clear is a pre-pass over
the destination directory, and the name decides it across the whole
file-entry list. So an entry at a cleared name that the commit also holds
arrives new, whatever the union mode keeps otherwise. The per-name removal
runs in order among the file entries of the directory. So a marker that sorts
after its target removes the entry that the same checkout wrote. A marker that
sorts before its target leaves the target that the checkout writes later.

The tool writes the file entries of a directory before its directory entries.
So a marker never removes a directory that the same tree writes at the target
name of the marker.

Each marker has its own type test. The per-name marker and the passthrough
marker act only on a regular-file entry. The tool writes a symlink or a
directory with such a name as it is, and the entry acts on nothing. The name
alone decides the opaque clear, and the type of the marker decides whether the
tool writes the marker:

- A symlink named `.wh..wh..opq` clears the directory, and the tool writes it.
- A regular file with that name clears the directory, and the tool does not
  write it.
- A directory with that name clears nothing, and the tool writes it.

The whiteout device takes the permission bits of the marker. The bits reach
`mknod`, so the process umask reduces them. Under the faithful checkout, the
checkout then applies the recorded mode in full, with the ownership and the
xattrs of the marker. The order is the xattrs, then the ownership, then the
mode.

A `chown` of a device node clears the setuid bit, and the setgid bit when group
execute is set. This holds for root and where the ids do not change. A chown
of a regular file follows the same rule (`../format-reference.md`, "Write
path: loose-object inode modes and durability"). So a marker recorded at 04755
or 02755 keeps its bits only where the mode comes after the ownership. The
chown after the xattrs also removes `security.capability` from the device,
which has no use for a file capability.

A character device with device number 0:0 needs no capability to create, so
the whole mechanism runs unprivileged. Under the faithful checkout, a `user.*`
xattr on a marker causes a refusal. Linux does not permit a `user.*` xattr on
a device node (xattr(7)). The device then stays at the mode that `mknod` gave
it: the umask applies, and the recorded mode does not. This places the xattrs
before the mode.

Before that refusal, the tool reports its own `GError` misuse on standard
error. This report is not part of the refusal message.

The disposition of the device at the target name, by union mode:

- Under union-files, the tool unlinks an existing regular file, symlink, or
  device and creates the device. It refuses an existing directory
  (`unlink(<name>): Is a directory`).
- Add-files keeps an existing entry of any type.
- Union-identical keeps an existing entry of any type with no comparison. This
  is the one place where its identity rule does not run.

With no union option, the tool refuses an existing destination before it
reaches any entry ("Checkout", "Overwrite policy"). So the disposition of the
default mode at the target name of a marker is not observable. The per-name
removal and the opaque clear do not depend on the union mode.

`--whiteouts` widens the union-files disposition over a type conflict. This
applies to each entry, a marker or not. Under `--union` with the option, the
tool removes a destination entry whose type differs from the type in the tree
at that name. It then writes the entry. It removes a directory with its
whole subtree, empty or not, where the tree holds a regular file or a symlink.
It removes a regular file, a symlink of any kind, a fifo, a device, or a
socket where the tree holds a directory.

For a symlink, the tool removes the link alone. So it unlinks a link to a
directory that the checkout follows without the option. The directory that
the link resolved to stays as it is and gets nothing. A directory that the
widening creates takes the dirmeta of the tree, as a directory that the
checkout creates in an empty destination does. Without the option, the same
conflict ends the checkout, except at a link to a directory that the checkout
follows.

The widening reaches the destination root and each depth below it. So a
destination path that holds a regular file, a symlink of any kind, or a fifo
becomes the directory of the checkout. The widening does not depend on the
checkout mode, the repository mode, or `--subpath`. A `--subpath` that names a
file or a symlink needs a destination directory, which is outside the
widening. The tool refuses a destination that is not a directory there, under
either option.

`--process-passthrough-whiteouts` widens nothing. The tool refuses a
destination directory at the target name of a whiteout device, under either
option. The widening does not reach
`--union-add` and `--union-identical`. With no union option, the tool refuses
an existing destination before it reaches any entry ("Checkout", "Overwrite
policy"). So no type conflict is reachable there.

A `--subpath` that names a marker file follows the same rules. The selection
does not make the tool write the marker under its own name. `.wh.<name>`
removes `<name>` from the destination that the subpath writes into, and
`.ostree-wh.<name>` writes the device there. The opaque clear is the pre-pass
of the directory, so a subpath that names `.wh..wh..opq` drops the entry and
clears nothing.

The tool refuses two names at exit 1:

- a regular file named exactly `.wh.` under `--whiteouts`: `Invalid empty
  whiteout ''`
- a regular file named exactly `.ostree-wh.` under
  `--process-passthrough-whiteouts`: `Invalid empty overlayfs whiteout ''`

Each refusal answers to its own option alone. The tool writes a symlink with
such a name under either option. The refusal comes during the walk, after the
opaque clear of the directory. So the destination directory stays, and holds
what the walk wrote before the refusal.

Both options are independent of the repository mode, `-U`, `-H`, and `-C`. The
tool refuses either option together with `--composefs` or
`--composefs-noverity` at exit 1
(`Specified options are incompatible with --composefs`), and writes no image.

### Subpath

A subpath selects a node of the commit tree, and the tool checks that node out
as the destination root. A subpath to a directory gives the dirmeta of that
directory to the destination root, and the tool writes its children. A
subpath to a regular file or a symlink makes the tool create the destination
directory, at the default mode `0700`. The tool puts the one object in that
directory under its name. An absent subpath is an error.

The tool reads the value of `--subpath` as follows:

- The leading slash is optional: `/dir` and `dir` name the same node.
- `/` names the whole tree.
- A nested path resolves through its directories.
- The tool looks the value up as given. So it refuses `.`
  (`No such file or directory: /.`) and a trailing slash
  (`No such file or directory: /sub/`).

A value that the tool cannot resolve ends the checkout at exit 1, and the tool
creates no destination (`cli-surface.md`, "P2", `checkout`). The messages are
these:

- an absent path: `error: No such file or directory: <path>`, with a leading
  slash that the tool adds
- a path that runs through a regular file: `error: Not a directory`

`--allow-noent` turns the refusal of an absent subpath into exit 0 with
nothing written. The tool creates no destination, and a destination that
already existed stays as it was. Over a well-formed repository, this is the
one refusal that the option reaches. An unresolvable COMMIT and a subpath that
runs through an entry that is not a directory keep their refusals and their
exit status. The tool applies the option only on some command lines. On the
other lines it ignores the option, and an absent subpath gets its refusal
(`cli-surface.md`, "P2", `checkout`).

If an out-of-band deletion removed the loose content object that a
`--subpath` names, the tool also suppresses that refusal. It exits 0 and
creates no destination. The same commit checked out whole keeps the refusal
(`cli-surface.md`, "P2", `checkout`).

### Path selection

A filter for each path decides which entries a checkout writes.
`checkout --skip-list=FILE` reads the filter from a file. The file holds
one path on each line. The tool ignores blank lines, and a final line needs no
newline. The tool strips and normalizes nothing else. The tool reports nothing
for a line that matches no entry.

The file must hold UTF-8 with no NUL byte. The tool refuses a NUL byte or a
byte sequence that is not UTF-8 at exit 1 with `Invalid UTF-8`, and creates no
destination.

The key of the filter is the path of the entry from the checkout root, with a
leading slash. The checkout root is the `--subpath` root where the command line
gives one. A directory has a trailing slash, and the root is `/`. A file and a
symlink have no trailing slash. The match is an exact string comparison:

- `/a/` prunes the directory `a` and its whole subtree.
- `/a`, `//a/`, `/a//`, ` /a/ `, and `./a/` match nothing.
- `/f1` prunes the file `f1`.
- `f1` and `/f1/` match nothing.

The filter decides the checkout root before the tool touches the destination
path. So a pruned root writes nothing and creates no destination. Under a
union mode, it leaves an existing destination as it is. The tool does not read
the parent directory of the destination either. So a pruned root exits 0 where
that parent does not exist.

The filter decides a whiteout marker by the tree path of the marker, before
either whiteout option reads it. So a pruned `.wh.<name>` removes nothing, and
a pruned `.ostree-wh.<name>` writes no device. The filter does not decide the
opaque clear, which is the pre-pass of the directory walk over the names of
the destination. It also does not decide the one object that a file or
symlink subpath names.

`checkout --skip-list` matches a directory under the trailing-slash
spelling alone. `commit --skip-list` matches a directory under `/a`
alone, and `/a/` matches nothing there (`commit`, "The skip list").

### Batch checkouts

`checkout --from-stdin` and `checkout --from-file=FILE` read a
stream of NUL-separated records. The tool takes the records two at a time as
`(REFSPEC, SUBPATH)` pairs. A final record with no terminator is a record, so
a stream that ends in NUL has no trailing empty record. An empty record in the
refspec position ends the stream. A refspec record with no record after it has
no subpath and names the whole tree. An empty record in the subpath position
is an empty subpath value (`cli-surface.md`, "P2", `checkout`).

The tool drops one trailing `\n` from a refspec record, and then one trailing
`\r`. It drops nothing from a subpath record, and strips no whitespace from
either record. It validates neither record as UTF-8: a subpath record reaches
the tree lookup as the bytes it holds.

The refspec takes each form that the `COMMIT` positional takes: a branch name,
a full checksum, an abbreviated checksum, and a `^` ancestry suffix. The
subpath record is a `--subpath` value and follows the rules of "Checkout",
"Subpath".

Each pair checks out into one destination, which the first positional of the
invocation names, under the overwrite mode of the invocation. So pairs layer
under `--union`, and without it a second pair over the same name is a
collision. A `--subpath` on the command line decides nothing under a batch
option. A `--skip-list` applies to each pair, from the subpath of that pair.
The tool opens the skip list inside the scope of each pair, so a stream that
holds no pair leaves the file unread.

The refusals that the command line carries into one checkout also stand inside
that scope: the union-option pair, the composefs incompatibility, and the
`--union-identical` requirement. So a stream that holds no pair reaches none
of them and exits 0. A destination value of no bytes follows the same rule. A
pair creates a path, so the tool refuses the empty value at a pair, and an
empty stream exits 0 (`cli-surface.md`, "P2", `checkout`).

`--allow-noent` acts on each pair, and the stream continues. Without it, the
run stops at the first failing pair, and the pairs already written stay. The
tool takes a composefs option with a batch option. Each pair then writes the
image of its own revision, and the subpath of the pair decides nothing.

## tar options

### The tar export options

Four options shape the tar stream that `../format-reference.md`, "tar",
states. None of them changes the member order.

`--no-xattrs` skips the xattrs. The stream of the tool holds none
(`cli-surface.md`, "P2", `export`).

`--subpath=PATH` makes the directory that `PATH` names the archive root. The
dirmeta of that directory becomes the metadata of the `./` member, and each
member under it takes a name relative to it. The tool reads the value as
"Checkout", "Subpath", states: each `/`-separated span is a child name to look
up. The tool refuses a span that no directory holds as a name at exit 1 with
`error: No such file or directory: <path>`. `<path>` carries a leading slash
that the tool adds.

The refusal covers these values:

- a trailing `/`: `--subpath=/dir/` reports `/dir/`
- the empty value, which reports `/`
- the spans `.` and `..` at any position: `--subpath=.` reports `/.`,
  `--subpath=..` reports `/..`, `--subpath=/./dir` reports `/.`, and
  `--subpath=/dir/..` reports `/dir/..`

A `PATH` that names a regular file or a symlink ends the process on SIGABRT
with `ostree_repo_file_tree_query_child: assertion failed:
(self->tree_contents)`. The tool prints that text on standard error, and a
`Bail out!` line with the same text on standard output (`cli-surface.md`,
"P2", `export`).

`--prefix=PATH` puts `PATH` in front of each member name. The name of the root
member is `PATH`, with one `/` added where `PATH` does not end in one. The
name of each other member is `PATH` joined to the relative path of the member,
with no separator between them. So `--prefix=pre` names the root `pre/` and a
root file `prefile.txt`. `--prefix=pre/` names them `pre/` and `pre/file.txt`.

The link name of a hardlink member carries the prefix. The target of a symlink
is the stored target and carries no prefix. An empty value leaves the `./`
root and the bare relative names. The option names the members that
`--subpath` rerooted. So `--subpath` applies first, and `--prefix` applies to
its result.

`-o PATH`, also spelled `--output=PATH`, writes the stream to `PATH` and writes
nothing to standard output. The tool opens the destination with create and
truncate after the repository resolves and before the revision resolves. So
an existing destination keeps its inode and its mode, and the tool truncates
it whether the export continues or not. A new destination takes `0o666`
reduced by the umask.

A refusal after that open leaves the two trailing zero blocks at the
destination, and no tar member (`cli-surface.md`, "P2", `export`). On standard
output these blocks get the record padding that `../format-reference.md`,
"tar", states.

A destination that does not open reports `error: Failed to open '<path>'` at
exit 1. This covers a path whose parent directory is absent and a path that
names a directory. The tool does not create the parent. The value `-` names a
file called `-`, and the empty value names standard output. The tool refuses
an absent positional before the open, so `export -o PATH` with no revision
creates nothing.

Each of `--subpath`, `--prefix`, and `-o` takes the last value where the
command line names it more than once:

- `--prefix=a --prefix=b` names the root `b/`.
- `--subpath=/nope --subpath=/` exports the whole tree at exit 0.
- `-o o1.tar -o o2.tar` writes `o2.tar` and creates no `o1.tar`.

The tool accepts a repeated `--no-xattrs` (`cli-surface.md`, "P2", `export`).

### The tar import options

`--tar-autocreate-parents` creates each absent parent directory of a member.
Without the option, the tool refuses such a member (`../format-reference.md`,
"The tar import"). The option acts by these rules:

- The tool creates an absent intermediate parent with mode `0755`, an empty
  xattr set, and the ownership of the member whose import created it. A
  created parent also sets the metadata of the tree root to the same mode and
  ownership, whatever the root member of the archive recorded. For each
  ancestor that the members share, the last member that causes a creation
  decides the metadata.
- Not observed: a parent that a hardlink member creates (`cli-surface.md`,
  "P2", `commit`).
- Where no member creates a parent, an absent root gets mode `0755`, owner
  `0:0`, and an empty xattr set.
- A created directory takes no part in the commit modifiers. So `--owner-uid`
  sets the owner of the member and does not set the owner of the parent that
  its import created.

`--tar-pathname-filter=REGEX,REPLACEMENT` splits its value at the first comma.
The part before the comma is the expression. The part after it, with any
further commas, is the replacement. The replacement is global: it replaces
each match in the name. The tool imports a member that the expression does not
match with no change, so the option renames members and drops none.

The link name of a hardlink member is the name of another member, so it also
goes through the filter. The target of a symlink is not a member name, and the
tool keeps it as it is. The tool takes the last value of a repeated option. The
tool reads the value when it loads an archive. So a command line that names no
`tar=` source exits 0, also with a value that the tool refuses over an archive.

The tool refuses two kinds of value at exit 1:

- a value with no comma: `error: Missing ',' in --tar-pathname-filter`
- an expression that does not compile:
  `error: --tar-pathname-filter: Error while compiling regular expression
  ‘<expression>’ at char N: <reason>`

The tool counts `N` in characters (`cli-surface.md`, "P2", `commit`).

The expression is a PCRE2 pattern. The tool compiles it with UTF and UCP on and
the newline convention `any`. Each other compile option stays at the PCRE2
default. The replacement uses the GLib syntax:

- `\0` to `\9`, `\g<name>`, and `\g<number>`
- `\\`
- the seven control escapes `\n`, `\t`, `\r`, `\a`, `\b`, `\f`, and `\v`
- `$` as a literal

A group that the expression does not declare adds nothing. The tool refuses
each other replacement escape. An empty match moves past one whole character,
which stays in the name. `cli-surface.md`, "P2", `commit`, states the dialect
in full.

The commit modifiers act on an archive as they act on a filesystem walk. Over
a `tar=` source, `--canonical-permissions` records owner `0:0` and
`mode & 0o755`. Over a filesystem walk the option drops the xattrs
(`../format-reference.md`, "Canonical permissions"). `--no-xattrs` drops them
for both sources.

Not observed: the xattrs that the tool records under `--canonical-permissions`
over an archive that carries xattrs. `cli-surface.md`, "P2", `commit`, records
the port side.

## Pull over HTTP

### HTTP pull surface

An HTTP server serves a published repository as the directory tree that
`../format-reference.md`, "Object store layout", states. The request lists in
this section are the requests that the tool sends to a static HTTP server. The
server serves an archive repository that the tool built.

#### Request order with a summary

One pull of one ref, with a summary on the remote, sends these requests in this
order:

```
summary.sig
summary
config
delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index
objects/<commit>.commitmeta
objects/<commit>.commit
objects/<...>.dirtree, .dirmeta, .filez, .filez, .dirtree, .filez
```

- The tool requests `summary.sig` before `summary`, and both before `config`.
- With no summary on the remote, `summary` answers 404, and the tool fetches
  `refs/heads/<ref>` in its place. The delta probe then requests
  `deltas/<b64>/superblock`, and no delta index. So a summary that advertises
  `indexed-deltas` selects the index path.
- The tool always requests a content object as `objects/<..>.filez`, whatever
  mode the remote stores. A metadata object keeps `.commit`, `.dirtree`, or
  `.dirmeta`. The detached metadata is `.commitmeta`. The tool requests it
  before the commit object that it belongs to, and reads a 404 as a commit with
  no detached metadata.

#### Request order with no summary

The two pulls that follow pull one ref into a `bare-user` client. The remote is
an archive remote with no summary and no file under `delta-indexes/`. The first
pull, with no ref on the client, sends these requests in this order, with
these statuses:

```
summary.sig                                         404
summary                                             404
refs/heads/<ref>                                    200
deltas/<to_b64[0:2]>/<to_b64[2:]>/superblock        404
objects/<to>.commitmeta                             404
objects/<to>.commit                                 200
objects/<...>.dirtree, .dirmeta, .filez, .filez     200
```

For the second pull, the remote holds a new commit `to`. The parent of `to` is
the commit `from` of the first pull. The remote also holds the delta
`<from>-<to>` that `static-delta generate --from=<from> --to=<to>` wrote. The
ref of the client names `from`, and the client holds `from` complete. The
second pull sends these requests:

```
summary.sig                                                404
summary                                                    404
refs/heads/<ref>                                           200
deltas/<from_b64[0:2]>/<from_b64[2:]>-<to_b64>/superblock  200
deltas/<from_b64[0:2]>/<from_b64[2:]>-<to_b64>/0           200
objects/<to>.commitmeta                                    404
```

#### Delta selection in a pull

A delta pull from a client that holds the previous commit of the ref sends
these requests:

```
summary.sig
summary
config
delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index
deltas/<from_b64[0:2]>/<from_b64[2:]>-<to_b64>/superblock
objects/<fallback>.filez          (only where the delta names fallbacks)
deltas/<from_b64[0:2]>/<from_b64[2:]>-<to_b64>/0
objects/<commit>.commitmeta
```

The tool selects a delta and requests the delta files by these rules:

- The tool takes the delta `<from>-<to>` for a commit `from` that the client
  holds complete, whether a ref names that commit or not. It takes the
  from-scratch delta `<to>` where the client holds no ref for the branch of the
  pull.
- The remote can advertise the from-scratch delta and no from-to delta from a
  commit that the client holds. Then a client whose ref names a commit fetches
  every object loose. A fresh client fetches every object loose when the remote
  advertises only a from-to delta.
- For the from-scratch delta, the tool reads the ref alone. A ref that names a
  commit that the client holds partial, or does not hold, also makes the tool
  leave the from-scratch delta alone. `cli-surface.md`, "P2", `pull`, records
  the port side.
- The tool takes no delta for a target commit that the client holds complete.
  For a target commit that the client holds partial, the tool looks for a delta
  as for a commit that it does not hold.
- After `--commit-metadata-only` or a `--subpath` pull, the ref names that
  commit. A later pull of the same commit then requests the delta index. It
  takes no superblock where the index names only the from-scratch delta, and it
  fetches the absent objects loose. It takes a from-to delta from another
  commit that it holds complete. From a remote with no summary, it requests the
  from-scratch superblock by name and applies the delta.
- Where the remote has a summary, the tool requests the delta index, except
  into an `archive` client. Where the index answers 404, the tool reads the
  `ostree.static-deltas` map of the summary and fetches the superblock that the
  map names. Where neither names the delta, the tool requests no superblock.
- No `objects/<commit>.commit` request follows a delta, because the target
  commit is in the superblock. The tool still fetches the `.commitmeta`. In a
  delta pull, it requests the `.commitmeta` after the parts.
- The tool fetches the fallback objects of a delta loose, as
  `objects/<..>.filez`. It queues them as soon as it reads the superblock. It
  requests no dirtree, no dirmeta, and no content object of the contents of the
  delta. So the tool does not walk the tree of the target commit after it
  applies a delta.
- A superblock whose bytes do not hash to the digest that the summary
  advertised fails the pull with `error: Invalid checksum for static delta
  <name>`. The tool requests no part.
- A superblock that the remote does not hold answers 404. The pull then
  continues with loose objects and no error, unless the pull requires static
  deltas. A remote that answers 404 for each path under `deltas/` and
  `delta-indexes/`, with a summary that names the delta, takes this path. The
  pull reads the delta from the map of the summary, gets 404 for the
  superblock, and fetches the objects loose.
- A part that answers 404 after its superblock fails the pull with `error:
  While fetching <url>/deltas/<name>/0: Server returned HTTP 404`. The pull
  fetches no object loose in its place and does not move the ref. This rule
  applies to a from-to delta and to a from-scratch delta that the index names.
  It applies whether the map of the summary names the delta or not.
- Under `--require-static-deltas`, the tool refuses a remote that serves no
  summary, with no delta probe: `error: Fetch configured to require static
  deltas, but no summary deltas or delta index found`. This refusal also applies
  where the client holds the commit, and under `--commit-metadata-only`. The
  same message ends a pull into `bare-user` from a remote whose summary has
  no `ostree.static-deltas` and that answers 404 for each path under
  `delta-indexes/`.
- With a summary, under `--require-static-deltas`, the tool refuses a commit
  that the client does not hold complete in two cases. In the first case, the
  pull can take no delta that the index or the summary names. In the second
  case, the superblock of the delta taken is absent. The message is `error:
  Static deltas required, but none found for <ref> to <commit>`. In the second
  case, the tool writes in place of `<ref>` the checksum of the start commit of
  the delta. For a from-scratch delta, it writes `(null)`.
- For a client whose ref names a commit, a remote that names the from-scratch
  delta satisfies `--require-static-deltas`, and the pull fetches loose. The
  tool does not refuse a commit that the client already holds complete.
  `cli-surface.md`, "P2", `pull`, records the port side.
- `--disable-static-deltas` requests no delta index and no superblock. The pull
  fetches every object loose.
- The tool takes no delta into an `archive` client. A plain pull into `archive`
  requests no delta index and fetches every object loose. Into `archive`, the
  tool refuses `--require-static-deltas` with `error: Can't use static deltas in
  an archive repo` before the first request. `cli-surface.md`, "P2", `pull`,
  records the port side.

#### The remote config

The tool requests `config` only after a summary arrives. Then the `[core] mode`
of `config` decides whether the pull proceeds. The tool reads `[core] mode`
alone from the remote `config`:

- `mode=archive-z2` and `mode=archive` proceed. The tool refuses `mode=bare`,
  `bare-user`, `bare-user-only`, and `bare-split-xattrs` before the first object
  request: `error: Can't pull from archives with mode "<mode>"`.
- A `config` with no `mode` key, with no `[core]` group, or with no bytes reads
  as mode `bare`. The tool refuses it: `error: Can't pull from archives with
  mode "bare"`.
- The tool refuses an unknown mode: `error: Invalid mode 'bogus' in repository
  configuration`.
- The tool refuses a file that does not parse: `error: Parsing config: Key file
  contains line “this is not a key file” which is not a key-value pair, group,
  or comment`.
- The tool does not check `repo_version`. A `config` with `repo_version`
  absent, `0`, `2`, or `abc` proceeds.
- No other key and no other group changes the requests or the result.
- After a summary, a `config` that answers 404 fails the pull, and no request
  follows: `error: While fetching <url>/config: Server returned HTTP 404`.

The rule for the other keys and groups holds for these values:

- the `[core]` keys `min-free-space-percent`, `min-free-space-size`, `fsync`,
  `add-remotes-config-dir`, `lock-timeout-secs`, `zlib-level`,
  `payload-link-threshold`, and `parent`
- `indexed-deltas` `true`, `false`, and absent, where each value keeps the
  index request of a summary that states `indexed-deltas` true
- `collection-id` present, absent, and different from that of the summary
- the groups `[remote "x"]`, `[ex-ostrya]`, and `[sysroot]`

With no summary, the tool requests no `config`. So a `bare-user` remote with no
summary fails the pull on a 404 for an `objects/<...>.filez` request. An
archive remote with no summary pulls with no error when its `config` is absent,
does not parse, or states `mode=bare-user`. `remote refs` and `remote summary`
request no `config`.

A collection id fails a pull only through the remote of the client. The tool
checks that remote against the binding of the commit:

- a binding that differs from the remote: `error: Commit <c>: Commit has
  collection ID ‘<bound>’ in collection binding metadata, while the remote it
  came from has collection ID ‘<found>’`
- a commit with no binding: `error: Commit <c>: Expected commit metadata to
  have collection ID binding information, found none`

`cli-surface.md`, "P2", `pull`, records the port side.

#### A 403 for an optional file

S3 answers a read of an absent key with 403 `AccessDenied` when the caller
has no `s3:ListBucket` on the bucket. These records come from libostree
2026.1. The server is an HTTP server that answers 403 for the keys of each
case. The remote is a bucket repository that `ostrya push` wrote, with one
commit, no detached metadata, and no static delta. A case "with a summary"
also has the summary that `ostrya remote summary -u` writes. The client is
a `bare-user` repository that pulls one ref.

- A 403 for `summary.sig`, with a summary: the pull sends the requests of
  "Request order with a summary", and exits 0.
- A 403 for the delta index, with a summary: the same requests, and exit 0.
- A 403 for `objects/<commit>.commitmeta`, with a summary: the same
  requests, and exit 0. The commit gets no detached metadata.
- A 403 for the superblock `deltas/<to_b64[0:2]>/<to_b64[2:]>/superblock`,
  with no summary: the pull sends the requests of "Request order with no
  summary", and exits 0.
- A 403 for each absent key, with a summary: `summary.sig`, the delta index,
  and the `.commitmeta` get 403. The pull sends the requests of "Request
  order with a summary", and exits 0.
- A 403 for each absent key, with no summary: `summary.sig`, `summary`, the
  superblock, and the `.commitmeta` get 403. The pull fetches
  `refs/heads/<ref>` in place of the summary, sends the requests of "Request
  order with no summary", and exits 0.
- A 403 for `config`, with a summary: the pull requests `summary.sig`,
  `summary`, and `config`, and no request follows. It exits 1 with
  `error: While fetching <url>/config: Server returned HTTP 403`.

So the tool reads a 403 for `summary.sig`, `summary`, a delta index, a
superblock, and a `.commitmeta` as a 404. In each case, no request carries
an `Authorization` header, and the tool requests no key under
`extensions/`. The request path holds each `+` of a modified base64
checksum as `+`, with no percent-encoding.

#### Content objects in an archive destination

A pull from an archive remote into an archive repository stores each `.filez`
with the bytes that the remote serves. The tool does not inflate and compress
the object again. Measured with `cmp` over a pull between two archive
repositories: the four content objects of the destination are byte-identical
to the objects of the remote. The port stores the same bytes
(`ostrya::pull_http::an_archive_pull_reproduces_filez_bytes_from_a_tool_built_remote`).

#### Proxy

These records come from libostree 2026.1, against a local origin server and a
local forward proxy that logs each request line.

- `http_proxy` applies to an `http` origin. The request carries the
  absolute-form target and the `Host` header of the origin.
- The tool does not read `HTTP_PROXY`. It reads each other variable in upper
  case too: `ALL_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` all apply.
- If a variable is set in both cases, the tool reads the lower case. With
  `all_proxy` naming a proxy that answers and `ALL_PROXY` naming a dead port,
  the pull goes through the proxy. With the two values exchanged, the pull
  fails.
- `all_proxy` applies to each scheme. `https_proxy` does not apply to an
  `http` origin, and `http_proxy` does not apply to an `https` origin.
- The tool reaches an `https` origin behind `https_proxy` through a `CONNECT`
  tunnel. TLS ends at the origin.
- `no_proxy` matches the host text of the URL, and not the address that the
  host resolves to. So `no_proxy=localhost` does not exempt a `127.0.0.1`
  origin. A comma list, an entry equal to the host, and `*` each exempt an
  origin. An empty value exempts nothing.
- The remote `proxy` key wins over the environment in both directions. With
  the key naming a proxy that answers and `http_proxy` naming a dead port, the
  pull goes through the proxy of the key. With the key naming a dead port and
  `http_proxy` naming a proxy that answers, the pull fails with `[7] Could not
  connect to server`, and the proxy of the variable logs no request. A
  `no_proxy` entry that matches the origin host exempts the origin from the
  key too.
- A proxy value with white space at its start or end fails the pull with
  `[5] Could not resolve proxy name`. The tool writes no ref and sends no
  request to the proxy. This holds for the remote `proxy` key, with trailing
  spaces or with a `\s` escape at the start, and for `http_proxy` with
  trailing spaces. In the list below, a padded value is a value with white
  space at its start or end.
  - A leading or trailing space, tab, LF, CR, VT, FF, U+00A0, or U+2003 is
    refused.
  - A value of white space alone counts as set. It hides the upper-case name,
    and the tool refuses it.
  - The message holds no part of the value.
  - The tool trims each `no_proxy` entry. `no_proxy=" 127.0.0.1 "` exempts a
    `127.0.0.1` origin, and `no_proxy=" "` exempts nothing.
  - A remote `proxy` key with a clean value wins, and the tool does not read
    the variable.
  - The tool refuses only the variable that the request uses. These cases do
    not fail the pull: a padded `http_proxy` with a `no_proxy` entry that
    matches the origin or with `no_proxy=*`, a padded `https_proxy` or
    `HTTPS_PROXY` for an `http` origin, a padded `all_proxy` beside a clean
    `http_proxy`, a padded `ALL_PROXY` beside a clean `all_proxy`, and a
    padded `HTTP_PROXY`.

`cli-surface.md`, "P2", `pull`, records the port side.

#### `tls-permissive`

These records come from libostree 2026.1, against a local TLS origin server.

- `tls-permissive=true` ignores `tls-ca-path`. A CA that signed nothing in the
  chain serves, and so does a path that names an absent file. Without
  `tls-permissive`, the same absent path fails the pull with `[77] Problem
  with the SSL CA cert (path? access rights?)`.
- `tls-permissive=true` keeps the host name check. A leaf certificate with
  `SAN DNS:localhost` alone serves `https://localhost:PORT` and fails
  `https://127.0.0.1:PORT`. A chain failure and a name failure give the same
  text, `[60] SSL peer certificate or SSH remote key was not OK`, so the
  message of the tool does not tell them apart.
- The tool reads `tls-permissive` as a key-file boolean. It accepts `true`
  and `1`. `yes` and `TRUE` fail before any network work.

The page `ostree.repo-config(5)` states a wider rule: "If this variable is
set, any certificate will be accepted." The measurement shows that the host
name check stays. `cli-surface.md`, "P2", `pull`, records the port side.

#### Ref list and mirror pulls

The tool resolves an empty ref list by the kind of pull:

- A plain pull uses the `branches` key of the remote. When the key is absent,
  the pull fails with `error: No configured branches for remote origin`.
- A mirror pull takes each ref that the summary lists. From a remote with no
  summary, the pull fails with `error: Fetching all refs was requested in
  mirror mode, but remote repository does not have a summary`.

Under `--mirror`, the tool writes `refs/heads/<ref>`. A plain pull writes
`refs/remotes/<remote>/<ref>`.

A mirror pull of the tool that fetched every ref copies the bytes of the remote
summary to `<repo>/summary` with no change. It copies the bytes of the remote
`summary.sig` to `<repo>/summary.sig` in the same way. Where the remote holds
no `summary.sig`, the pull writes `<repo>/summary` alone. Then a
`<repo>/summary.sig` that an earlier pull wrote stays as it is. A mirror pull of
named refs writes neither file, and a plain pull writes neither file.

A repeat pull of an unchanged ref fetches `summary.sig`, `summary`, `config`,
the delta index, and `.commitmeta` again, and then stops. Into an `archive`
client, the tool does not request the delta index ("Delta selection in a
pull"). `cli-surface.md`, "P2", `pull`, records the port side.

#### Timestamp check

`-T` fails the pull only on a timestamp that is strictly older. An equal
timestamp passes. `--timestamp-check-from-rev=REV` compares against REV and
turns on the check. The message names both revisions and both timestamps.

#### Checksum verification

By default, an HTTP pull of the tool verifies the checksum of each object that
it fetches. The help of `--untrusted` reads "Verify checksums of local sources
(always enabled for HTTP pulls)". Over HTTP the option changes nothing: a
corrupt `.filez` fails the pull with and without the option.

The help of `--http-trusted` reads "Do not verify checksums of HTTP sources
(mostly useful when mirroring)". The tool skips the check only under
`--mirror` into an `archive` destination:

- There the tool stores a corrupt `.filez` with no change, writes the ref, and
  exits 0. A later `fsck` fails with `Corrupted file object`.
- Without `--mirror`, into a `bare-user` destination, or with `--untrusted`
  beside `--http-trusted`, the corrupt object fails the pull with `Writing
  content object: Corrupted file object`. The tool writes no ref.

`cli-surface.md`, "P2", `pull`, records the port side.
`pull-local` takes neither `--subpath` nor `--http-trusted` (`Unknown option`).

#### The subpath option

`--subpath=PATH` fetches a part of the tree of each commit. The option is
repeatable. The tool splits the value on `/` after its leading `/`, and keeps
each component, the empty components included. The tool fetches these objects:

- the commit, the root dirtree, and the root dirmeta, always
- the dirtree and the dirmeta of each directory on the path before the last
  component, and the walk continues inside it
- for the entry that the last component names, the whole entry: a file, or a
  directory with all of its contents

The tool fetches nothing else: no sibling, no dirmeta of a sibling, and no file
of a directory that the path goes through. Examples:

- `/sub/f1/x`, with `f1` a file, fetches the `sub` dirtree and dirmeta alone.
- `/nonexist`, `/`, `/a/` with `a` a file, `//sub`, and `/./sub` fetch the root
  alone. No entry has an empty name, `.`, or `..` as its name.
- `/sub/` fetches the `sub` dirtree and dirmeta, and no entry of `sub`.
- Several values fetch the union.

The tool walks a dirtree that two positions reach one time, under the first
walk that reaches it. So what the tool fetches under that dirtree follows the
order in which its fetches complete. So the order depends on the server. Over
one static HTTP server, the tool follows the directory that sorts first in the
tree, whatever the order of the values.

Over another server, `/other/x/` beside `/sub/x` fetches the file of `x`. The
rule of the directory that sorts first fetches no file there. `cli-surface.md`,
"P2", `pull`, records the port side.

The tool writes the ref, under `refs/heads` for `--mirror`. Each commit that the
pull reaches keeps a marker, each parent that `--depth` reaches included
(`../format-reference.md`, "Commit-state markers"). A subpath pull of a commit
that is already complete writes no marker. With `--commit-metadata-only`, the
tool fetches the commit alone.

Into `bare-user`, the tool applies a delta whole, from-scratch or from-to, for a
commit that it does not hold. It keeps the marker. Into `archive`, the tool
takes no delta and fetches the subpath loose.

A value that does not start with `/`, the empty value included, ends the tool on
an assertion (`SIGABRT`, exit 134 from a shell). The tool writes nothing.
`cli-surface.md`, "P2", `pull`, records the port side.

#### Static deltas over pull-local

`pull-local` reads no delta by default. A source whose `deltas/` directory is
corrupt, or that the tool cannot read, pulls as it does with
`--disable-static-deltas`.

With `--require-static-deltas`, `pull-local` reads the source as a fetch reads a
remote. The rules of "HTTP pull surface" then apply, and each request reads its
file from the source directory. The source must be an `archive` repository with
a summary. A source with no summary gets the no-summary refusal of
`--require-static-deltas` ("HTTP pull surface", "Delta selection in a pull"). A
source in another mode that has a summary gets `error: Can't pull from archives
with mode "<mode>"`.

Where more than one refusal applies, the tool refuses in this order:

1. the summary signature checks
2. a source with no summary
3. a source in another mode
4. a ref that the source does not hold: `error: No such branch '<ref>' in
   repository summary`
5. the none-found refusal
6. the commit signature checks

The tool applies the delta taken. The objects that the delta produces are the
objects that a plain `pull-local` imports. The tool imports loose the objects
and the `.commitmeta` that the delta leaves out. It imports loose the parents
that `--depth` reaches.

`--require-static-deltas` and `--disable-static-deltas` together end the tool on
an assertion, on `pull-local` and on `pull`. The tool writes nothing. The tool
reports `ostree_repo_pull_with_options: assertion
'!(pull_data->disable_static_deltas && pull_data->require_static_deltas)'
failed`, then ends with `SIGABRT`, exit 134 from a shell.

#### Depth less than -1

A `--depth` less than `-1` ends the tool on an assertion, on `pull-local` and on
`pull`. The tool reports `ostree_repo_pull_with_options: assertion
'pull_data->maxdepth >= -1' failed`, then `ostree_run: assertion failed:
(success || error)`. Then it ends with `SIGABRT`, exit 134 from a shell. The
tool sends no request and writes no object and no ref. A remote that the
repository does not configure gives the same abort. These rules hold for
`--depth=-2`.

`cli-surface.md`, "P2", `pull`, and `cli-surface.md`, "P2", `pull-local`,
record the port side.

### Signature verification during a pull

The pulls in this section are HTTP pulls of the tool from an archive repository
that the tool built. Each refusal in this section leaves the
destination with no ref and no object.

#### The verification keys

Each configuration key selects one check:

- `gpg-verify`, default true. Each commit that the pull carries must have a GPG
  signature from the trusted keyrings of the remote.
  - A commit with no signature: `error: Commit <hex>: GPG verification
    enabled, but no signatures found (use gpg-verify=false in remote config to
    disable)`.
  - A commit signed by a key that the keyrings do not hold: `error: Commit
    <hex>: Signature made <date> using EdDSA key ID <keyid>`, followed by
    `Can't check signature: public key not found`.
- `gpg-verify-summary`, default false. `summary.sig` must hold a valid GPG
  signature over the bytes of the summary.
  - A remote that serves no summary: `error: GPG verification enabled, but no
    summary found`.
  - A remote that serves a summary and no `summary.sig`, or a `summary.sig`
    with no GPG signature: `error: GPG verification enabled, but no signatures
    found`.
- `sign-verify`, default off. The value is a boolean, or a list of engine names
  split on `,` and `;`. `remote`, "`remote add`", states the keys that
  `--sign-verify` and `--no-sign-verify` of `remote add` write. For an engine
  given twice, `remote add` writes the name two times
  (`sign-verify=ed25519,ed25519`), and the tool accepts that value. The tool
  does not trim a name.
  - `sign-verify=ed25519, ed25519`, and each name that no engine answers to:
    `error: Requested signature type is not implemented`.
  - A commit with no signature under the named engines: `error: Can't verify
    commit: No signatures found`.
  - A commit signed by an untrusted key: `error: Can't verify commit: ed25519:
    Signature couldn't be verified with: key '<hex of the trusted key>'`.
- `sign-verify-summary`, default off. The tool reads this key alone:
  `sign-verify=false` beside it still verifies the summary.
  - A `summary.sig` that the trusted keys do not verify: the engine message of
    `sign-verify`, with no `Can't verify commit` prefix.
  - No `summary.sig`, and a remote that serves no summary: `error: Signatures
    verification enabled, but no summary.sig found (use
    sign-verify-summary=false in remote config to disable)`.
- `verification-<engine>-key` holds one key. A list under either separator
  fails with `error: Failed loading 'ed25519' keys from inline
  verification-key`.
- `verification-spki-key` is the base64 of a SubjectPublicKeyInfo DER, also
  with line breaks, which `ostree config set` writes as the escape `\n`. A key
  in another form fails each pull with `error: Can't verify commit
  <checksum>: openssl: Failed to initialize spki key`, also when
  `verification-spki-file` holds the valid key. The base64 of a raw SEC1
  point, of the full PEM text, and of a PKCS#8 secret key are such keys.
  `static-delta`, "spki inline keys", names the tool build.
- `verification-ed25519-file` holds one key on each line. The tool accepts a
  commit that the key of any line signed.
- `verification-spki-file` holds PEM `PUBLIC KEY` blocks, under the rules of
  `static-delta`, "spki public key files". A file that the tool reads as no
  key, for example an empty file or a file of base64 lines, fails each pull
  with `error: Failed loading 'spki' keys from '<path>`, with no closing quote.
- `gpgkeypath` is a list of keyring files and directories, separated by `;`.
  The tool adds each entry to the trusted set. A remote with an imported
  `<remote>.trustedkeys.gpg` and a `gpgkeypath` that names an empty directory
  still accepts a commit of the imported key.
  - An entry that does not exist: `error: Commit <hex>: opendir(<entry>): No
    such file or directory`.

#### Rules common to the verification axes

- The GPG axis and the sign axis are independent, and the tool applies both. A
  remote with `gpg-verify` at its default and `sign-verify=ed25519` with the
  right key still fails on GPG.
- Inside `sign-verify`, one engine is sufficient. `sign-verify=ed25519;dummy`
  with a key for each engine accepts a commit that ed25519 alone signed.
- An engine that `sign-verify` names with no key fails with `error: No keys
  found for required signapi type <engine>`. `sign-verify=true` with no key for
  any engine fails with `error: Can't verify commit: signature: ed25519: no keys
  loaded`.
- `verification-<engine>-key` alone verifies nothing. The check runs only where
  `sign-verify` or `sign-verify-summary` asks for it.
- The tool checks each commit that the pull carries, the parents that `--depth`
  follows included. On a repeat pull, the tool checks again a commit that the
  destination already holds.

`pull-local` makes no check unless an option asks for it. It has the options
`--gpg-verify` and `--gpg-verify-summary`. Each option needs `--remote`, or the
tool refuses with `error: Must specify remote name to enable gpg verification`.
The `gpg-verify=true` of the named remote does not turn on a check. A remote
that the configuration does not describe holds no key. So its name satisfies
`--remote`, and the tool refuses each signature.

The summary check of `pull-local` reads the `summary` and the `summary.sig` of
the source repository. The refusals of `pull-local` are these:

- an unsigned commit: `error: Commit <c>: GPG verification enabled, but no
  signatures found (use gpg-verify=false in remote config to disable)`
- a signature from a key that the remote does not hold: `Can't check
  signature: public key not found`
- a source with no `summary.sig`: `error: GPG verification enabled, but no
  summary.sig found (use gpg-verify-summary=false in remote config to
  disable)`
- a source with no `summary`: `... but no summary found ...`

Each refusal writes no object and no ref. The tool reads and discards a value
given to either option, so `--gpg-verify=false` turns on the check.
`cli-surface.md`, "P2", `pull-local`, records the port side.

#### Static deltas and signatures

The tool checks a commit that a delta delivers against the copy of the detached
metadata in the superblock (`../format-reference.md`, "Superblock fields"). So
a delta generated while the commit carried an older signature fails the pull
under a policy that the current `.commitmeta` satisfies.

The tool cannot pull a signed delta. A from-scratch delta and a from-to delta
that `static-delta generate --sign` signed both fail the pull with `error:
Invalid checksum of length 0 expected 32`. The pull fails with verification
configured and with verification off. `static-delta apply-offline` applies the
same delta, and `static-delta show` reports `Signed: yes`. `cli-surface.md`,
"P2", `pull`, records the port side.

## The fsync vocabulary

One durability option has two spellings. Each command that takes one of the
two spellings reads the rules of this section.

### The valued spelling

The valued spelling is `--fsync=POLICY`. `POLICY` is a boolean word. The tool
matches the word without regard to case:

- `true`, `yes`, and `1` turn fsync on.
- `false`, `no`, and `0` turn fsync off.

The tool refuses every other value with `error: Invalid boolean argument
'<value>'` on standard error, and exits 1. The message quotes the value
verbatim, and it quotes the empty value too. The refused values include the
other boolean spellings: `on`, `off`, and the single letters `t`, `f`, `y`, and
`n`.

The option requires a value. If `--fsync` has no `=` and no value, the tool
takes the next word of the command line as the value, and refuses that word.
If that word is an option, each later word moves one position. The tool reads
the rest of the line in the moved positions. It still reaches the value reader,
and the refusal names the taken word. This is true for each of these kinds of
word:

- an option that the command has: `--orphan`, `--table-output`, `-I`
- an option that the command does not have: `--nosuch`, `-Z`
- an option with a value: `--timestamp=@1700000000`, `--owner-uid=abc`

The option narrows the configured policy and never widens it. The resolved
policy is the logical AND of the configured value and the option value. A
repository with `[core] fsync=false` makes no `fsync`, `fdatasync`, or `syncfs`
call under `--fsync=true`.

### The valueless spelling

The valueless spelling is `--disable-fsync`. It is equal to `--fsync=false`. It
takes no argument. The tool reads an `=VALUE` suffix and discards it, so
`--disable-fsync=false` disables fsync.

Both spellings default to fsync on. Neither spelling changes a byte that the
command writes to the repository. The same
commit under `--fsync=true` and under `--fsync=false` gives one checksum and one
object store. The count of `fsync`, `fdatasync`, and `syncfs` calls is the only
observable difference.

### Spellings per command

The commands of the tool take these spellings:

- `commit` and `checkout` document `--fsync=POLICY`. The two commands share the
  value set and the refusal text.
- `commit` also accepts `--disable-fsync`. `commit --help` does not list it
  (`cli-surface.md`, "P2", `commit`).
- `checkout` refuses `--disable-fsync` with `error: Unknown option
  --disable-fsync` at exit 1.
- `pull` and `pull-local` document `--disable-fsync`. They refuse `--fsync` with
  `error: Unknown option --fsync=<value>` at exit 1.
- `commit` refuses `--per-object-fsync` with `error: Unknown option
  --per-object-fsync` at exit 1.

`--per-object-fsync` is a separate valueless option of `pull` and `pull-local`.
It controls write scheduling, outside this vocabulary. It turns on the
per-object sync of `[core] per-object-fsync`, whatever value the key has. Its
scope is the scope of the key, which `../format-reference.md`, "Durability and
staging", states. It cannot turn off a configured `per-object-fsync=true`.
`[core] fsync=false` and `--disable-fsync` each have precedence over it.

`--per-object-fsync` takes no value. The tool reads an `=VALUE` suffix and
discards it, as for `--disable-fsync`, so the tool accepts
`--per-object-fsync=bogus`. The tool also accepts a repeat of `--disable-fsync`
or of `--per-object-fsync` on `pull` and on `pull-local` (`cli-surface.md`,
"P2", `pull`).

### Order of the configured and the option value

The tool reads the configured `[core] fsync` under each state of the option:
under `--fsync=true`, under `--fsync=false`, and with no option. Then the option
value narrows the configured value. So an option value never hides a
configured value that the reader refuses. The tool refuses a repository with a
`[core] fsync` value that is not a key-file boolean at exit 1 in each of the
three states. It writes no object and no ref.

The narrowing rule of "The valued spelling" applies to the value that the
reader returns. So the reader runs each time.

For `pull` and `pull-local`, the tool reads `[core] fsync` and `[core]
per-object-fsync` under each state of the two options. It refuses a value of
either key that the reader refuses at exit 1 under each state. It writes no
object and no ref.

In the tool, `checkout` reads the option value in the step that reads the
options. This step comes before the repository and before the revision.
`commit` reads the option value in the same step (`commit`, "Fault order"). On
a plain-path `checkout` line with no DESTINATION, the tool reports the value at
exit 1 and creates nothing (`cli-surface.md`, "P2", `checkout`).

Under `--composefs`, the tool also refuses a repository with a `[core] fsync`
value that the reader refuses. It exits 1 and writes nothing
(`cli-surface.md`, "P2", `checkout`).

For `commit`, the port reads `[core] fsync` with the other `[core]` keys,
before the editor and before the repository lock. In the port, each checkout
of a `--from-stdin` or `--from-file` batch runs under the one resolved value.

### Sync counts of a commit

Each count in the four "Sync counts of ..." sections is a count of `fsync`,
`fdatasync`, and `syncfs` calls. The conformance matrix reads standard output,
standard error, the exit status, and the repository bytes alone. So no `run:`
line can state a count, and a cell cites a test in
`crates/ostrya-cli/tests/cli.rs`.

The input is a `commit` of corpus `C0` into a new `archive` repository, under
the single-component branch name `main`. `C0` is the tree that `corpus::basic`
builds in `crates/ostrya-conformance/src/corpus.rs`, and `README.md` lists it.
It holds a 0644 regular file, a 0644 empty file, a 0755 directory with one 0644
regular file, and a symlink. The commit writes 8 objects into 8 different
fanout directories. The counts of the tool:

```
[core] fsync   option           sync calls
unset (on)     --fsync=true     11  (9 fsync, 1 fdatasync, 1 syncfs)
true           --fsync=false     0
false          (none)            0
false          --fsync=true      0
```

The nine `fsync` calls are one for each of the 8 fanout directories and one for
`objects/`. The `fdatasync` is on the temp file of the ref.
`../format-reference.md`, "Durability and staging" and "Ref durability", state
the rules of these calls. So the count on the syncing row follows from the
corpus. It is a property of the writer.

The port makes the same calls, and it adds the directory syncs of a ref write
(`../format-reference.md`, "Ref durability"). Under `main` the ref write
creates no directory. So the count of the port on the syncing row is 12 (10
fsync, 1 fdatasync, 1 syncfs). Under `deep/nest/leaf` the write creates `deep`
and `nest`. This gives three directory syncs and a count of 14 (12 fsync, 1
fdatasync, 1 syncfs).

The three rows that sync nothing state the narrowing rule. The port also makes
0 calls on each of these rows.

Test `commit_fsync_policy_controls_the_syscalls` asserts this table for both
binaries. It asserts 0 calls on the three rows that sync nothing. On the
syncing row it asserts the target of each call and the totals: 11 for the tool
and 12 for the port. Cell `commit/fsync-syscalls` cites this test.

Under `[core] per-object-fsync=true`, `commit` syncs with the scope of the key
("Spellings per command"). Over `C0` the tool makes 15 calls in `archive` and
in `bare-user`, and 14 in `bare`. In `bare` the symlink object is a symlink
inode. The port makes 16, 16, and 15 calls (`cli-surface.md`, "P2", `commit`).

### Sync counts of a checkout

The input is `checkout -U main DEST` of the commit of "Sync counts of a
commit", into a new destination, from an `archive` repository that holds the
commit. The `tool` column holds the calls of the tool, and the `port` column
holds the calls of the port:

```
[core] fsync   option           tool   port
unset (on)     --fsync=true      2      5
unset (on)     (none)            2      5
true           --fsync=false     0      0
false          --fsync=true      0      0
```

The two calls of the tool are `fsync` calls on the temporary files that its
uncompressed object cache writes under `tmp/` in the repository. There is one
call for each regular file with content. "Checkout", "Hardlink and copy",
describes the cache. `--disable-cache` makes the count 0. A `bare-user`
repository keeps no such cache and gives 0 on every row. The tool syncs no file
and no directory of the destination.

The port syncs the destination. It makes one `fsync` on the temporary inode of
each file that it copies, before it links the inode into place. It makes one
`fsync` on each directory that it writes, after the entries of that directory.
The resolved policy controls each of these calls. Over `C0` this gives the 5
calls of the table in `archive` mode, where the port copies each regular file.
In `bare-user` mode under `-U` it gives 3: the port hardlinks the two files with
content and writes the zero-length file new.

The target and the lifetime of each call are different in the two
implementations:

- The calls of the tool target the uncompressed object cache in the
  repository, and that cache persists. The first `archive` checkout of a commit
  makes one call for each regular file with content. A second checkout of the
  same commit from the same repository makes no call. A `bare-user` checkout
  makes no call on any run, because that mode keeps no such cache.
- The calls of the port target the destination, which each checkout writes
  new. So each checkout makes the full count. This is one call for each file
  that the copy path writes, plus one for each directory that it writes.

In the port, neither policy changes a byte of the destination.

Test `checkout_fsync_policy_controls_the_syscalls` asserts the four rows of
this table for both binaries. It asserts 0 calls on the two rows that sync
nothing. On the two syncing rows it asserts the totals: 2 for the tool and 5
for the port. Each target of the port is under the destination, and each
target of the tool is under the repository. Cell `checkout/fsync-syscalls`
cites this test.

The tool reads the last of a repeated `--fsync` on `checkout`.
`--fsync=false --fsync=true` gives the 2 calls of the syncing row, and
`--fsync=true --fsync=false` gives 0. Both orders exit 0, so only the sync
calls show the rule. The same test asserts it (`cli-surface.md`, "P2",
`checkout`).

### Sync counts of a pull

The input is a `pull` of corpus `C0`. The remote is an `archive` repository,
served over HTTP, that holds the commit on `main` and a summary. The pull writes
`refs/remotes/origin/main` into a new destination. The counts are the same in
an `archive` destination and in a `bare-user` destination:

```
switch or [core] key                         tool   port
(none)                                        11     13
--per-object-fsync                            15     17
per-object-fsync=true                         15     17
--disable-fsync                                0      0
--per-object-fsync --disable-fsync             0      0
fsync=false with --per-object-fsync            0      0
```

The 11 calls of the tool are the 11 calls of the table in "Sync counts of a
commit". The per-object rows add one `fsync` for each content object, which is
4 over `C0` (`../format-reference.md`, "Durability and staging").

The port adds two directory syncs for the ref (`../format-reference.md`, "Ref
durability"). `init` creates `refs/remotes`, and the ref write creates
`refs/remotes/origin`. So the port syncs `refs/remotes/origin`, which holds
the ref, and `refs/remotes`, which holds the created `origin` entry. A later
pull from the same remote finds `refs/remotes/origin` in place, and the port
syncs that directory alone.

A `--mirror` pull of each ref copies the summary of the remote. The tool makes
11 calls and syncs no summary file. The port makes 14 calls:

- the 11 calls of the tool
- one `fsync` of `refs/heads`
- one `fdatasync` of the temp file of the summary
- one `fsync` of the repository root

Under `--disable-fsync`, both make 0 calls.

A pulled commit with detached metadata adds a `.commitmeta` file to the pull.
The tool makes no sync call for this file. The input is `C0` committed with
`--add-detached-metadata-string`, pulled into `archive`. The tool makes 11
calls on `pull-local`, on `pull`, and on a `--mirror` pull. The port makes 13,
14, and 15 calls. Under `--disable-fsync`, both make 0 calls.

`../format-reference.md`, "Durability and staging", states how the port makes a
pulled `.commitmeta` durable.

In the port, `--disable-fsync` turns off each sync of the pull. This includes
the per-object syncs, the publication step, and the ref writes. It also
includes the detached metadata of each pulled commit and the summary that a
mirror pull copies.

### Sync counts of a local pull

The input is a `pull-local` of the same commit from an `archive` source:

```
switch or [core] key                  archive dest    bare-user dest
                                      tool   port     tool   port
(none)                                 11     12       11     12
--per-object-fsync                     11     12       15     16
per-object-fsync=true                  11     12       15     16
--disable-fsync                         0      0        0      0
fsync=false with --per-object-fsync     0      0        0      0
```

Into `archive`, the pull hardlinks each object from the source, so no row syncs
an object. Into `bare-user`, the pull ingests the content objects again and
hardlinks the metadata objects. So the per-object rows add one sync for each
content object. The port adds one `fsync` of `refs/heads`, the directory that
holds the ref (`../format-reference.md`, "Ref durability").

The port extension `--force-copy` changes the count. Under `--force-copy
--per-object-fsync` into `archive`, the port copies each object and makes 16
calls. It syncs the 4 content objects, and it does not sync the 4 metadata
objects.

## CLI output formats

The reading commands write to standard output. So their output format is
part of the interoperability surface that a script depends on. `commit`
reports the commit that it made on standard output in the same way.
`m10-cli-behavior.matrix` holds the cells that require the output of the port
to match the output of the tool.

### `commit`

`commit` prints the 64-character checksum of the new commit and a newline. It
writes nothing to standard error and exits 0.

A commit names a branch with `-b BRANCH`, or it has `--orphan`, which permits a
commit that names no branch. A commit with neither reports `error: A branch must
be specified with --branch, or use --orphan` and exits 1. This check comes
before `--parent`, before the tree, and before each object publication
(`commit`, "Fault order"). So the same line answers a commit whose `--parent`
does not resolve and a commit whose tree path does not open.

A commit that names a branch writes the ref of that name: `refs/heads/BRANCH`
for a bare name, and `refs/remotes/REMOTE/NAME` for a `REMOTE:NAME` value. A
commit that names no branch writes no ref.

#### The parent

- `-b BRANCH` with no `--parent` takes as its parent what BRANCH resolves to as
  a revision (`../format-reference.md`, "Branch names no revision reaches" and
  `../format-reference.md`, "Abbreviated checksums"):
  - A BRANCH of lowercase hex that prefixes one commit object takes that
    commit.
  - The command refuses a BRANCH that prefixes more than one commit object,
    with `error: Refspec BRANCH not unique` at exit 1, and no ref moves.
  - Each other BRANCH takes the tip that the ref file holds.
- A branch that names no ref and prefixes no commit has no tip. So the first
  commit onto a new branch is a root commit.
- The command reads the tip from the ref file and does not load the commit
  object. So a ref over an absent commit object gives its checksum as the
  parent, unread.
- The command reads the tip before the transaction publishes. So the tip that a
  commit takes as its parent is the tip that its own ref write then replaces.
- `--parent=none` gives a root commit on a branch that has a tip. The ref still
  moves to the new commit.
- `--orphan` also removes the implicit parent. With `-b`, the ref still moves,
  so the absent parent is the only observable effect there. An explicit
  `--parent` beside `--orphan` sets the parent to the value given.
- `--parent` takes a 64-character lowercase checksum or the literal `none`. The
  command does not check that the checksum exists, so a `--parent` that names
  no object gives a commit at exit 0. `none` is a literal in lowercase alone, so
  `NONE` is a revision.
- The reader of the tool at `--parent` takes a checksum alone, so the tool
  refuses each other value at exit 1:
  - An abbreviated checksum, a refspec, and an empty value report `error:
    Invalid rev <value>`.
  - A checksum with an ancestry suffix reports its base: `--parent=<checksum>^`
    gives `error: Invalid rev <checksum>`.
  - A rendering that is not lowercase reports `error: Invalid character
    '<byte>' in rev '<value>'`. The message names the first refused byte by
    its decimal value.

`cli-surface.md`, "P2", `commit`, records the port side.

#### The subject and the body

The subject and the body are fields of the commit object. So each option of
this section changes the commit checksum.

- `-s/--subject=SUBJECT` sets the subject, and `-m/--body=BODY` sets the body.
  The command stores each value verbatim. It trims nothing and does not
  normalize newlines, and embedded newlines stay. The tool takes the last value
  of a repeated `-m`. Not observed: the value that the tool takes from a
  repeated `-s` (`cli-surface.md`, "P2", `commit`). The command accepts a
  commit with a body and no subject, and the subject field holds the empty
  string.
- `-F/--body-file=FILE` reads the whole file as the body, byte for byte. It
  strips no trailing newline and no comment. An empty file gives an empty body.
  The command accepts `-F` and `-m` together, and `-F` has precedence over `-m`
  in each order. `-F -` opens
  a file with the name `-` and does not read standard input. Each refusal exits
  1:
  - A path that does not open reports `error: openat(<path>): <reason>`, with
    the path as given.
  - A directory opens and then fails to read, so the reason has no path:
    `error: Is a directory`.
  - Content that is not UTF-8 or that holds a NUL reports `error: Invalid
    UTF-8`.

#### The editor

`-e/--editor` writes a template to a temporary file and runs an editor on it.
The command then takes the subject and the body from the file that the editor
leaves. The editor result replaces both, so the command discards `-m` and `-F`,
and it does not read the `-F` file. Only `-s` reaches the template, as a
prefill.

The editor is the value of the first variable of `OSTREE_EDITOR`, `VISUAL`, and
`EDITOR` that is set. A variable set to the empty string counts as set. If none
is set, the editor is `vi`. The command does not read `GIT_EDITOR`.

The value is a shell command line. The command appends the shell-quoted path of
the temporary file to the value and runs the whole line under `/bin/sh -c`. So
the shell expands variables and globs in the value and reports its own faults.

The temporary file is in `TMPDIR` (`/tmp` by default). Its name is `.` and six
characters. The command removes it after the run. The file has mode 0600, so no
other local user can read the message during the edit. The editor runs after
the branch check, the `--parent` resolution, and the metadata options. It runs
before the tree opens and before the timestamp (`commit`, "Fault order").

For a commit on branch `BR`, the template is:

```
\n
# Please enter the commit message for your changes. The first line will\n
# become the subject, and the remainder the body. Lines starting\n
# with '#' will be ignored, and an empty message aborts the commit.\n
#\n
# Branch: BR\n
```

With `--orphan`, the last two lines are absent, and the file ends after
`commit.\n`. The command appends a `-s` value and one newline after the block.
So the prefilled subject is at the end of the file.

The command reads the file that the editor leaves by the rules of
`-F/--body-file`. A byte that is not UTF-8 and a NUL both report `error: Invalid
UTF-8`. If the editor removed the file, the command reports `error:
openat(<path>): <reason>` with the path of the temporary file. Each exits 1.

The command reads the edited text by these rules, in this order:

1. Each line loses its trailing whitespace.
2. The command removes each line whose first character is `#`. A `#` after
   leading whitespace does not start a comment.
3. The command removes the leading blank lines. The first line that stays is the
   subject.
4. The lines after the subject, without their own leading and trailing blank
   lines, are the body. Newlines join them, and the interior blank lines stay.

An empty subject reports `error: Aborting commit due to empty commit subject.`
and exits 1. An unmodified template and a message of whitespace alone both give
this refusal.

A non-zero exit of the editor aborts the commit and discards what the editor
wrote. No ref and no commit object result. The message has no separator between
the quoted editor value and the reason:

```
error: There was a problem with the editor '<EDITOR>'Child process exited with code <N>
```

The process exits 1 for each value of `<N>`.

#### The commit metadata

The order of the entries in the commit metadata dict is part of the commit
checksum (`../format-reference.md`, "Commit -- `(a{sv}aya(say)sstayay)`"). The
tool writes the entries in this order, whatever the order of the command line:

1. The keys that the tree walk derives before the command assembles the
   commit: `ostree.linux`, then `ostree.bootable`.
2. The user keys, group by group: each `--add-metadata-string` in command-line
   order, then each `--add-metadata`, then each `--keep-metadata`.
3. The binding keys: `ostree.ref-binding`, then `ostree.collection-binding`.
4. The keys that the commit assembly appends: `ostree.composefs.digest.v0`,
   then `ostree.sizes`.

The tool holds the dict in a hash-ordered container while `--bootable` or
`--generate-composefs-metadata` is given. With either option, the order of the
whole dict follows the key set (`cli-surface.md`, "P2", `commit`).

The command writes a key given twice two times, so the dict holds two entries
of that name.
A user key can have the name of a binding key, and the dict then holds both
entries. Two derived keys are exceptions:

- `--bootable` removes each entry that the command line supplied under
  `ostree.linux` or `ostree.bootable`. So a commit with `--bootable
  --add-metadata-string=ostree.linux=9.9.9` gives the same object as a commit
  with `--bootable` alone.
- `--generate-composefs-metadata` stores the digest in the slot of the first
  `ostree.composefs.digest.v0` entry of group 2. It removes each later entry of
  that name. So the dict holds the derived digest one time, before the binding
  keys. Group 4 gets the entry only if no option supplied the name.
  `--add-metadata-string`, `--add-metadata`, and `--keep-metadata` can each
  supply it.

`--generate-sizes` has no such exception. It appends its `ostree.sizes` entry
whatever the dict holds. So a commit with the option and
`--add-metadata-string=ostree.sizes=...` holds two entries of that name.

The metadata options are these:

- `--add-metadata-string=KEY=VALUE` splits at the first `=`, so a value can hold
  more `=` characters. It stores the value as an `s`. It accepts an empty
  value.
- `--add-metadata=KEY=VALUE` splits in the same way and reads the value in the
  GVariant text form ("The GVariant text form"). On a little-endian host, the
  command stores the parsed value in host byte order with no conversion. So a
  numeric value reads back byteswapped through `show --raw` and `show
  --print-metadata-key`, and as the given number under `-B` ("The GVariant
  text form", "Byte order").
- `--keep-metadata=KEY` copies a key from the resolved parent, byte for byte.
  The resolved parent is the `--parent` value where one is given, `--orphan
  --parent=<checksum>` included. Otherwise it is the branch tip.
- `--add-detached-metadata-string=KEY=VALUE` writes an `a{sv}` to the
  `.commitmeta` file of the commit, in command-line order, with duplicates kept.
  It does not change the commit checksum. So the same tree with and without the
  option gives one object.

The metadata options have these refusals, each at exit 1:

- An argument with no `=` reports `error: Missing '=' in KEY=VALUE metadata
  '<argument>'`. Each of the three `KEY=VALUE` options gives this line.
- An empty key reports `error: Empty metadata key` from `--add-metadata-string`
  and `--add-metadata`. `--add-detached-metadata-string` accepts an empty key.
- A value that the GVariant text reader refuses reports `error: Parsing
  <KEY>=<VALUE>: <spans>:<reason>`. The message names the whole argument, and
  its offsets count into the value alone.
- A `--keep-metadata` key that the parent does not hold reports `error: Missing
  metadata key '<key>' from commit '<checksum>'`.
- A `--keep-metadata` with no resolved parent reports `error: Either --branch or
  --parent must be specified when using --keep-metadata`. No branch, a branch
  with no tip, and `--parent=none` all give this line.

`commit`, "Fault order", gives the order of these refusals.

#### The ref bindings

`ostree.ref-binding` is an `as`. It holds the branch that `-b` names and each
`--bind-ref=BRANCH` value, sorted byte-wise in ascending order, with duplicates
kept. The sort compares bytes, so uppercase sorts before lowercase and `10`
before `2`. A commit that names no branch holds the empty array, and the key is
present in that case too.

The command applies no character check to a `--bind-ref` value. It records each
of these values as given:

- a name that holds a space, a double slash, a caret, or a tab
- a name with a leading `-`, a leading dot, or a trailing slash
- the empty name
- the 64 lowercase hex characters that `-b` refuses

The branch-name guard applies to the ref that the command writes. It does not
apply to the names that the key records. `The command accepts `--bind-ref`
beside `--orphan`, and the array then holds the bound names alone. `--bind-ref`
alone names no branch. So a commit with `--bind-ref` and with neither `-b` nor
`--orphan` gets the refusal of a commit with no branch.

`--no-bindings` writes neither binding key: the dict holds no
`ostree.ref-binding` entry and no `ostree.collection-binding` entry. It
overrides `--bind-ref`. So over one tree at one timestamp, `commit -b X
--no-bindings`, `commit --orphan --no-bindings`, and `commit -b X --no-bindings
--bind-ref=Y` give one commit object. It removes only the keys that the command
adds itself. A binding that `--add-metadata-string` adds or that
`--keep-metadata` copies stays.

`ostree.collection-binding` is an `s` that holds the `[core] collection-id` of
the repository. The command writes it after `ostree.ref-binding`, in a
repository that has a collection id. `--bind-ref` does not change it.

#### The declared ownership

`--owner-uid=UID` and `--owner-gid=GID` replace the ownership that each entry
records. The two options are independent of each other. Over a filesystem
source, they reach the metadata of the tree root, each nested directory, each
regular file, and each symlink. The permission bits and the xattr set do not
change. Not observed: the ownership that the tool records for the root and for
the parent directories that the import creates in a `tar=` source.

The command reads each value as a C `int`. The base comes from the text: a `0x`
prefix gives hexadecimal, a leading `0` gives octal, and other text gives
decimal. Optional leading whitespace and an optional sign can come first, and
the reader must consume the whole text. So `0x2a` is the id 42, `053` is 43,
and `010` is 8.

The default of both options is `-1`. So a negative value declares nothing, and
the ownership of the source stays. `--owner-uid=-1` and `--owner-uid=-2` give
the same result. `-0` is the id zero.

In each repository mode except `bare-user-only`, a declared id changes the
commit checksum. In `bare-user-only` the checksum is the same with and without
the two options, because the mode discards the ownership
(`../format-reference.md`, "Canonical permissions").

The command refuses a value that no C `int` holds while it reads the options,
at exit 1. This refusal comes before the repository opens and before each other
check of the command. The two messages quote the value in typographic quotes
(U+201C and U+201D):

- a syntax that the reader cannot read (`abc`, an empty value, `5x`, a trailing
  space, `0x`, and `--5`): `error: Cannot parse integer value “<value>” for
  --owner-uid`
- a value more than `2147483647` or less than `-2147483648`: `error: Integer
  value “<value>” for --owner-gid out of range`

`--no-xattrs` records the empty xattr set for each entry, the tree root
included, whatever the source holds.

#### The timestamp and the fsync policy

`--timestamp=TIMESTAMP` sets the commit timestamp. It has precedence over
`SOURCE_DATE_EPOCH`, which the tool reads when the option is absent. The tool
reads the value with a full natural-language date reader. The tool accepts these
forms:

- `@SECONDS` since the epoch, with an optional sign and an optional fractional
  part. The command drops the fractional part. Examples: `@1234567890`, `@-1`,
  `@0.5`, `@ 0`, `@+5`.
- An absolute date and time in ISO 8601, or in a form with spaces as
  separators, with or without a UTC offset. A value without an offset names the
  local time of the tool.
- A date in the form of ctime.
- A relative expression: `now`, `yesterday`.
- An empty value, which is midnight of the current day.

The tool refuses a bare count of seconds (`--timestamp=1234567890`), `@` alone,
and `@1e3`. A refused value reports `error: Could not parse '<value>'` at exit
1. This message uses single quotes, and the integer messages use the
typographic pair. The command records a time before the epoch as the
two's-complement form of the unsigned timestamp field. So `@-1` and
`1969-12-31T23:59:59Z` give one commit. `cli-surface.md`, "P2", `commit`,
records the port side.

`--fsync=POLICY` sets the durability of the writes of the commit. It takes the
values of "The fsync vocabulary". The policy reaches the write of each object,
the publication step, and the ref write. It changes no byte that the repository
stores ("The fsync vocabulary", "The valueless spelling").

#### The table output

`--table-output` replaces the checksum line with a block of seven `KEY: VALUE`
lines on standard output. The field names, their order, and their count are
fixed. Each field has one space after its colon, no padding, and no unit. Each
line ends with a newline and has no trailing space. Standard error stays empty,
and the exit status is 0.

The block for corpus `C0`, committed into an empty `bare` repository with `-b
conformance -s x --timestamp=@1700000000`:

```
Commit: 7f00c81575e97a12c9d34d44c232e56236d40be76fd457abd2d6d829d7f05592
Metadata Total: 5
Metadata Written: 4
Content Total: 4
Content Written: 4
Content Cache Hits: 0
Content Bytes Written: 45
```

The three regular files of `C0` hold 23, 0, and 22 bytes, and its two
directories share one dirmeta.

The block has these fields:

- `Commit` -- the checksum of the new commit. The plain form prints this value
  alone.
- `Metadata Total` -- the metadata objects that the commit offered to the
  object store, counted before deduplication. Each directory counts its own
  dirmeta. Here: two dirtree objects, two dirmeta objects, and the commit
  object.
- `Metadata Written` -- the metadata objects stored. The two directories share
  one dirmeta, so the count is two dirtree objects, one dirmeta object, and the
  commit object.
- `Content Total` -- the content objects that the commit offered, counted before
  deduplication. The commit does not offer an object that a devino-cache hit
  resolves, so that object is not in this count.
- `Content Written` -- the content objects stored.
- `Content Cache Hits` -- the content objects that a devino-cache hit resolved.
- `Content Bytes Written` -- the sum of the payload lengths of the stored
  regular files, before the compression of the mode: 23 + 0 + 22 here. A
  symlink adds nothing. The count uses the payload length. For a random
  payload, the stored `.filez` file is larger.

A second commit of a tree that the repository already holds keeps both totals.
It prints `Metadata Written: 1` for the commit object, and zero for `Content
Written` and `Content Bytes Written`. The block has the same shape in
`archive`, `bare`, and `bare-user`.

#### The statoverride file

`--statoverride=PATH` names a file of mode changes, one entry on each line:

```
[=]<decimal mode><one space><absolute in-tree path>
```

A sample file, and its effect on a tree that holds `/plain.txt` at 0644,
`/dir2/b.txt` at 0644, `/grpx` at 0754, and `/dir1` at 0700:

```
=384 /plain.txt
=448 /dir2/b.txt
8 /grpx
=511 /dir1
```

`/plain.txt` becomes 0600, and `/dir2/b.txt` becomes 0700. `/grpx` stays 0754,
because decimal 8 is 0o10, which its mode already holds. `/dir1` becomes 0777.

The command reads the file by these rules:

- The mode is in base 10, with an optional leading sign. A leading `=` states
  the permission bits and gives `(mode & S_IFMT) | value`. Without `=`, the
  value goes into the mode by OR and gives `mode | value`. So the file-type
  bits stay in both forms. A value with bits in the file-type field changes the
  file type of the mode.
- The tool reads the field through a C `double` reader, so it also takes a
  hexadecimal literal: `0x1ff` gives decimal 511, which is 0777. It takes a
  decimal point and an exponent: `1e3` gives decimal 1000 and `.7e3` gives
  decimal 700. Over a 0644 file, these two give 01754 and 01674. It turns a
  value out of the 32-bit range into `0x80000000`. `inf`, `nan`, `1e100`,
  `4294967296`, and `4294967295` all give mode 020000000644 over a 0644 file.
  `cli-surface.md`, "P2", `commit`, records the port side.
- The separator is exactly one space (0x20). All text after it is the path,
  more spaces included. A tab is not a separator.
- The path is absolute, starts at the root of the committed tree, and has no
  trailing slash. `/`, `/plain.txt`, and `/dir1/sub/deep.txt` all match.
  `plain.txt`, `./plain.txt`, and `/dir1/` never match.
- An entry applies to exactly one tree entry and does not recurse. The `=` form
  applies to regular files, directories, symlinks, and the walk root. It
  applies in each source that offers the path.
- A mode field with no digit is the value zero. So `abc /plain.txt` changes
  nothing, and `= /plain.txt` gives mode 0.
- The command ignores blank lines and accepts an absent final newline. The file
  has no comment syntax.
- Given more than once, the option takes the last value. The command does not
  read the earlier files.

The OR form reaches one tree entry in each run. The first tree entry that a
source offers under the path spends the statoverride entry. A later source under
that path keeps the mode that it brought. A directory under the walk root
spends the entry and takes no value from it, so its mode stays as the source has
it. An archive member is the exception: the OR value reaches a directory member
too. A spent entry counts as reached, so it gets no unmatched report.

Over `/dir1` at 0700, `16 /dir1` gives 0700 from a `dir=` walk and from a
`ref=` source, and 0720 from a `tar=` source. `=8 /dir1` gives 0010 from all
three. Over two sources that both hold `/dir1` at 0700, `16 /dir1` gives these
results:

- With `--tree=dir=A --tree=tar=B`, 0700. The walk spends the entry before the
  archive offers the path.
- With `--tree=dir=C --tree=tar=B`, where `C` holds no `/dir1`, 0720.

A path can occur on more than one line. Each form keeps one entry for each
path, with the value of the last line that names the path. The OR form comes
before the `=` form. Where a path has an entry of each form, the OR value alone
reaches the mode, in each line order. Over a 0644 file:

- `8 /f` then `16 /f` gives 0664.
- `=448 /f` then `=511 /f` gives 0777.
- `448 /f` then `=511 /f` gives 0744.
- `=511 /f` then `448 /f` gives 0744.
- `=511 /f` then `0 /f` gives 0644.
- `1 /f`, `=448 /f`, `2 /f` gives 0646.

In a `dir=` walk and in a `ref=` source, the OR form states no mode for a
directory under the walk root. So the `=` entry reaches the directory. Over
`/dir1` at 0700, `16 /dir1` then `=8 /dir1` gives 0010. Over an archive member,
the OR form states a mode and comes first, as on other entries. There the same
pair gives 0720.

#### The skip list

`--skip-list=PATH` names a file of paths to leave out, one absolute in-tree path
on each line:

```
/plain.txt
/dir2
```

A listed directory prunes its whole subtree, so `/dir2` also removes
`/dir2/b.txt`. The list can name a symlink. The command ignores blank lines.
Given more than once, the option takes the last value. A path that occurs more
than once counts as one entry, and the unmatched report states it one time.

The tool spends a skip-list entry one time. Over `--tree=dir=A --tree=dir=B`,
the tool prunes a listed path from `A` alone (`cli-surface.md`, "P2",
`commit`).

The spelling of a path is exact. A trailing space, an absent leading slash, and
a trailing slash all match nothing. A list of each child of the root gives a
commit whose tree holds the root alone. A listed `/` prunes the walk root and
leaves nothing to commit, so the command gives the empty-tree refusal of
`commit`, "The tree sources". With `--base`, the base is still the bottom layer
under a pruned walk root. So the command writes the commit, and the commit
holds the base tree unchanged.

The pruned walk adds no object to `ostree.sizes`. So such a commit has no
`ostree.sizes` key,
also under `--generate-sizes`. Under a pruned walk root, the tool also does two
steps (`cli-surface.md`, "P2", `commit`):

- `--consume` tries to remove the source. It removes an empty source directory.
  Over a source directory that holds an entry, it reports `error:
  unlinkat(<path>): Directory not empty`.
- The tool reads a `tar=` source. So a file that is not an archive reports
  `error: archive_read_open_filename: Unrecognized archive format`.

#### Unmatched control-file entries

The command checks both control files for entries that the walk never reached.
It checks each `--skip-list` entry. It checks only the `--statoverride` entries
without `=`, so the command ignores an `=` entry that matches nothing. These
rules decide which entries the walk reached:

- A path that the skip list prunes counts as reached, because the walk reaches
  the entry and prunes it there. Over a skip list that holds `/dir1`, that entry
  and a `16 /dir1` statoverride entry both match.
- A path inside a directory that the skip list pruned is unmatched, because the
  walk never enters the directory. Over the same skip list, `/dir1/a.txt`,
  `/dir1/sub`, and `/dir1/sub/deep.txt` are unmatched in either file.
- A path that the walk does not reach is unmatched. So a path that both files
  name and that the tree does not hold gets a report.
- The walk root counts as reached. So over a skip list that holds `/`, a `16 /`
  statoverride entry matches, and the empty-tree refusal alone reports.

The order of the two options on the command line changes none of these rules.

The report is one line for each unmatched path, then a summary line, on standard
error, at exit 1. Standard output stays empty, and the command writes no ref:

```
Unmatched statoverride path: /nope.txt
error: Unmatched statoverride paths
```

```
Unmatched skip-list path: /nope.txt
error: Unmatched skip-list paths
```

The `<path>` is the raw text after the first space, so ` 448 /plain.txt`
reports `Unmatched statoverride path: 448 /plain.txt`. A path that a file names
more than once gets one line. An `=` entry for a path that an OR entry also
names adds no line. The statoverride check comes before the skip-list check, in
each command-line order, and both come before the empty-tree refusal. The tool
writes the lines for each path in a hash order (`cli-surface.md`, "P2",
`commit`).

The command refuses a statoverride line with no space before the walk, with
`error: Malformed statoverride file (no space found)`. A control file that does
not open gives `error: openat(<path>): <reason>`, with the path as the command
line spells it. A directory gives `error: Is a directory`, with no path. The
command accepts an empty file of either kind, and the file changes nothing.

Each control file must hold UTF-8, and a NUL byte counts as invalid. One invalid
byte anywhere in the file reports `error: Invalid UTF-8` at exit 1. The report
names neither the file nor the line. The command checks both files. This check
comes before the walk, before the unmatched report of the other control file,
and before a tree path that does not open (`commit`, "Fault order").

#### The walk of a filesystem source

The walk of the tool reads each directory in the order that the filesystem
lists it, and it enters a subdirectory when it reaches it. The first entry that
fails in that order decides the refusal. For each entry, the tool does these
steps in this order:

1. It reads the entry with `fstatat`, no-follow. A failure reports `error:
   fstatat(<name>): <reason>`. So a directory with read permission and no
   search permission, mode 0644, stops at its first entry. A skip list that
   names only that entry does not prevent the refusal.
2. It checks the type. A fifo and a unix socket report `error: Not a regular
   file or symlink: <name>`. A skip list that names the entry does not prevent
   the refusal. Not observed: a device node.
3. It applies `--skip-list`. The tool does not open an entry that the skip list
   names.
4. It opens the entry. A regular file that does not open reports `error:
   openat(<name>): <reason>`. A directory that does not open reports `error:
   opendir(<name>): <reason>`. A walk root that does not open reports `error:
   opendir(<path>): <reason>`.

`<name>` is the last path component of the entry, so `sub/d/y` reports `y`.
Each refusal exits 1, with standard output empty, no object in `objects/`, and
no ref written. The tool gives these results:

- A regular file at mode 0000, an empty file at mode 0000, and a file at mode
  0200 each report `openat(<name>): Permission denied`. `--no-xattrs`,
  `--canonical-permissions`, and `--owner-uid=0 --owner-gid=0` do not change
  this result.
- A directory at mode 0000, empty or not, and a directory at mode 0311 each
  report `opendir(<name>): Permission denied`.
- A skip list that names one of these entries gives a commit at exit 0, with
  the commit checksum of the tree without the entry:
  - the file at mode 0000
  - the directory at mode 0000
  - the directory at mode 0311
  - the directory at mode 0644

These rules hold for uid 1000 in `archive`, `bare`, `bare-user`, and
`bare-user-only`. In `bare`, for a user other than root,
`--canonical-permissions` and `--owner-uid=0` fail first on the owner change of
an earlier object. The message is `error: Writing content object: fchown:
Operation not permitted`.

The tool commits a symlink whose target is not valid UTF-8, at exit 0. It writes
`g_variant_new_string(): requires valid UTF-8` to standard error on a
`GLib-CRITICAL` line. It writes the line two times in `archive`, and one time in
`bare`, `bare-user`, and `bare-user-only`. It hashes the target as the 15-byte
string `[Invalid UTF-8]`. So in each of the four modes, the commit checksum is
that of the same tree with the literal target `[Invalid UTF-8]`.

In `archive`, the stored object holds that string, so a checkout gives a symlink
to `[Invalid UTF-8]`. In `bare`, `bare-user`, and `bare-user-only`, the object
stored under that name holds the original target bytes. `ls` reads the
original target back, and a checkout gives a symlink to it. `fsck` passes
in each mode. `cli-surface.md`, "P2", `commit`, records the port side.

#### The mode modifiers

`--mode-ro-executables` removes the write bits of each executable regular file:
where `mode & 0o111` is not zero, `mode &= ~0o222`. Any one of the three execute
bits starts it, and the option clears all three write bits. So 0766 becomes
0544, and 0621 becomes 0401. The setuid, setgid, and sticky bits stay: 04755
becomes 04555, and 01777 becomes 01555. The option does not change a regular
file with no execute bit, a directory (a world-writable one included), or a
symlink.

The three mode modifiers run in a fixed order: `--mode-ro-executables`, then
`--statoverride`, then the `--canonical-permissions` reduction.
`--mode-ro-executables` and the reduction commute. The reduction is an AND mask,
and `--mode-ro-executables` tests bits that the mask keeps. `--statoverride`
sets or ORs bits, so its pair with each of the other two shows the order. Over a
tree that holds `/f0644` at 0644, `/f0700` at 0700, `/f0555` at 0555, and
`/dir1` at 0700, with `--canonical-permissions`:

- `=511 /f0644` gives `-00755`, because the reduction masks the 0777 that the
  entry states.
- `=2048 /f0700` gives `-00000`, because the mask removes the setuid bit that
  the entry states.
- `146 /f0555` (decimal 146 is 0o222) gives `-00755`.
- `=511 /` gives `d00755` for the root, and `=511 /dir1` gives `d00755`.

In the opposite order, the four results are 0777, 04000, 0777, and 0777. With
`--mode-ro-executables` and without `--canonical-permissions`, the
`--statoverride` line `146 /roexec` over a 0555 file gives 0777. In the opposite
order of these two, the result is 0555.

#### Skip if unchanged

`--skip-if-unchanged` compares the walked tree with the resolved parent. This is
the commit that `--parent` names, else the implicit parent that `-b` gives
(`commit`, "The parent"). The root contents checksum and the root metadata
checksum both take part. The metadata of the commit does not take part. So the
command also skips a commit with a different `-s` or an added
`--add-metadata-string` over an unchanged tree.

If the two match, the command prints the checksum of the parent and a newline on
standard output. Standard error stays empty, and the exit status is 0. The
command writes no ref: an existing ref stays where it was, and an absent ref
stays absent. If there is no parent (a new branch, `--parent=none`, or
`--orphan`), the command writes the commit as usual. The walk runs in both
cases, so an unmatched `--statoverride` entry still fails the command at exit 1.

#### The derived metadata

Three options read the tree of the commit and store what they find in the
metadata dict of the commit.

`--generate-sizes` writes `ostree.sizes` (`../format-reference.md`, "The
`ostree.sizes` key"). Only an `archive` repository holds the key. In `bare`,
`bare-user`, and `bare-user-only`, the command accepts the option, writes no
key, prints nothing on standard error, and exits 0. There the commit checksum
is the same as without the option.

Over a single source, the key covers the whole tree. So a second commit onto a
branch also lists the objects that deduplicated against the first commit. The
option also applies to the tar form: `--tree=tar=PATH` gives the key in the
same way.

Over a list of sources, the key has a scope, and the checksum of a
multi-source commit depends on this scope. These rules hold for ten source
lists:

- A content object counts if the last `--tree` source contributed it. A content
  object that an earlier source contributed is not in the key, also when it
  stays in the committed tree. So `--tree=dir=t1 --tree=dir=t2` lists only the
  files of `t2`, and `--tree=dir=t1 --tree=dir=<empty directory>` lists no file.
- A directory object counts if a source contributed it or the tree
  serialization wrote it. It stays in the key when a later source opens.
- A `--base` layer contributes nothing. So a subtree that comes from the base
  unread is not in the key.
- A `ref=` source contributes each object of its own tree, whether the overlay
  reads the object or uses the stored checksum again.
- The key then keeps only the objects that the committed root reaches. So an
  object that a later source replaced is not in the key, whatever source
  contributed it.

`--bootable` writes `ostree.linux` and `ostree.bootable`
(`../format-reference.md`, "Commit -- `(a{sv}aya(say)sstayay)`"). The value of
`ostree.linux` is the name of the one directory under `/usr/lib/modules` of the
committed tree that holds an entry with the name `vmlinuz`. The search rules:

- The search is exactly one level deep. It does not find a `vmlinuz` directly
  under `/usr/lib/modules` or a `vmlinuz` one more level down.
- The search does not read the type of the entry. A regular file, a
  directory, and a symlink whose target the tree does not hold, each with the
  name `vmlinuz`, count as a kernel.
- An entry under `/usr/lib/modules` that is not a directory takes no part. So
  the search ignores a stray file there and a symlink to a kernel directory.
- The search does not need or read an initramfs.

The option reads the committed tree. So a `--skip-list` that prunes
`/usr/lib/modules` leaves no kernel to find. The option has five refusals.
Each one goes to standard error at exit 1, with standard output empty and no
object published:

```
error: No such file or directory: /usr
error: No such file or directory: /usr/lib
error: No such file or directory: /usr/lib/modules
error: No kernel found in /usr/lib/modules
error: Multiple kernels found in /usr/lib/modules
```

The first three name the first component of the path that the tree does not
hold. A component that the tree holds as a non-directory reports `error: Not a
directory`, which has no path. The tool gives that message for `/usr` and
`/usr/lib`. If `/usr/lib/modules` itself is a regular file or a symlink, the
tool stops on an assertion (`cli-surface.md`, "P2", `commit`).

`--generate-composefs-metadata` writes `ostree.composefs.digest.v0`, an `ay`
that holds the 32-byte fs-verity digest of the composefs image of the tree
(`../format-reference.md`, "Export path" and `../format-reference.md`,
"fs-verity digest").

The three options run after the walk. The control-file reports, the empty-tree
refusal, and `--skip-if-unchanged` all come before the kernel search. So an
unchanged tree under `--bootable --skip-if-unchanged` prints the checksum of the
parent and exits 0, also when the tree holds no kernel. In the tool, the kernel
search comes before the timestamp and before the empty-key check
(`cli-surface.md`, "P2", `commit`). `commit`, "Fault order", gives the full
order.

#### The tree sources

The command builds the tree of a commit from an ordered list of sources:

1. `--base=REV`, if given, is the bottom layer.
2. Each `--tree=KIND=VALUE`, in command-line order, goes on top of the result.
3. If no `--tree` is given, the positional `PATH` is the one source.

The command ignores a positional `PATH` beside a `--tree`. It does not open or
stat the path, and it exits 0. It ignores each positional argument after the
first in the same way.

`--tree` splits its value at the first `=`. The part before it names the kind,
and the part after it is the value:

- `dir=PATH` -- a directory on the filesystem, opened no-follow. So the command
  refuses a symlink to a directory. The command accepts a trailing slash.
- `tar=PATH` -- an archive. `-` and `/dev/stdin` name standard input.
- `ref=REV` -- each revision that `rev-parse` reads: a ref name, a checksum, or
  either with a `^` ancestry suffix. The `REF:/path` subtree syntax is not a
  revision, and the command refuses it as an invalid refspec.

The overlay is a recursive merge for each path, and the later source has
precedence:

- Directory over directory: the result holds the children of both. So a child
  that only the earlier source held stays.
- Directory metadata: the dirmeta of the later source replaces the earlier one
  whole. The xattrs of the later source replace those of the earlier one. The
  command never merges them.
- File over file: the later file replaces the earlier one whole.
- The command refuses a name that is a directory in one source and a file in
  another. If the later source holds the file, the refusal is `error: Can't
  replace directory with file: <name>`. If the later source holds the
  directory, the refusal is `error: Can't replace file with directory:
  <name>`. The name is the last path
  component, so `n1/a/b/p` against `n2/a/b/p` reports `p`. Both refusals exit 1
  and write no commit.

`--base=REV` and `--tree=ref=REV` differ in one way: no commit modifier reaches
an entry that comes from the base. Such an entry keeps the mode, the ownership,
and the xattrs that the base recorded. These modifiers shape an
entry from each `--tree`, `ref=` included: `--owner-uid`, `--owner-gid`,
`--canonical-permissions`, `--no-xattrs`, `--statoverride`, `--skip-list`, and
`--mode-ro-executables`.

The command applies `--base` first, whatever its position on the command line.
Given more than once, `--base` takes the last value. It is valid with no
`--tree`.

`--consume` empties each filesystem source when the walk reads that source.
This occurs before the command writes the commit object and before the ref
moves. So a later failure leaves the files deleted and no commit. The option
also removes the source directory, unless the path is exactly `.`. The test
reads the text of the value, so the command removes `./` and an absolute path
to the working directory.

`--consume` empties the source whatever a walk filter kept out of the commit.
It removes a path that `--skip-list` names with the rest, and also the tree
that holds it. So the command writes the commit and deletes the whole source.
A removal that fails aborts the commit and reports the name of the
entry as `unlinkat(<name>): <reason>`. The option has no effect on a `ref=`
source or a `tar=` source.

These examples show the removal failures:

- A source that holds a directory at mode 0500 reports `unlinkat(<entry inside
  it>): Permission denied` at exit 1.
- `--consume .` from the parent directory succeeds.
- `--consume ./` from inside the directory reports `unlinkat(./): Invalid
  argument` at exit 1.

A list of sources that supplies no root directory leaves nothing to write. The
command then reports `error: Can't commit an empty tree` at exit 1.

The command opens each source when it reaches it, one at a time and in order.
So a source that `--consume` already emptied stays deleted when a later source
does not open. A refused timestamp does not restore what `--consume` removed.
`commit`, "Fault order", gives the full order.

#### Signing

Five options sign the commit that the command writes. The signatures go into
the detached metadata of the commit by the rules of `../format-reference.md`,
"Signing details". They go in before the ref moves (`../format-reference.md`,
"Signing sequence").

- `--gpg-sign=KEY-ID` adds one `ostree.gpgsigs` element for each occurrence, in
  command-line order, with no deduplication. The GnuPG installation resolves the
  key id in the home directory that `--gpg-homedir` names. Without that option,
  GnuPG resolves its own home directory, and it reads `GNUPGHOME`. The selector
  must be at least eight bytes long and must name exactly one secret key. Each
  of the three outcomes has its own line in the refusal list of this section.
- `--gpg-homedir=HOMEDIR` names the home directory where `--gpg-sign` resolves
  its keys. It has precedence over `GNUPGHOME`. Alone, with no key to resolve,
  the command accepts it, and it changes nothing.
- `--sign=KEY_ID` adds one signature for each occurrence under the engine that
  `--sign-type` names, in command-line order, with no deduplication. For
  `ed25519` the value is the base64 form of the 64-byte secret key
  (`../format-reference.md`, "ed25519"). For `spki` the value is the base64
  of a secret key DER (`static-delta`, "spki inline keys").
- `--sign-from-file=PATH` adds one signature for each occurrence. It reads the
  key from the first line of the file. The command ignores the rest of the
  file. A trailing newline is optional, and the decode skips surrounding
  whitespace.
- `--sign-type=NAME` names the engine of `--sign` and `--sign-from-file`. The
  default is `ed25519`. The match is exact and case-sensitive, with no trimming,
  and the command takes the last value. It does not apply to `--gpg-sign`, whose
  engine is fixed.

`--sign` and `--sign-from-file` make two separate lists. Each `--sign` key signs
first and each `--sign-from-file` key after it, whatever the order of the
command line. Both lists come before the `--gpg-sign` keys.

The base64 decode of a `--sign` value skips each character outside the
alphabet. So a value that holds prose decodes to some byte count, and the
decode does not fail on the text. A padding character counts toward its group
and has the value zero. Each complete group of four characters gives three
bytes. Each of the last two characters of the group that is a padding character
removes one of these bytes. A trailing group of less than four characters adds
nothing.

So padding acts for each group and for each position in the group:

- `AAAA=` decodes to three bytes. The padding character starts an incomplete
  group.
- `AAA=` decodes to two bytes, and `AA==` decodes to one byte.
- `AA=A` decodes to two bytes, because the padding character is third in a
  complete group. `A=AA` decodes to three bytes, because the padding character
  is second.
- `AA==AA==` decodes to two bytes, one byte from each of its two groups.
- `AAAAAAA====` decodes to five bytes.

A decoded length other than 64 reports `error: Invalid ed25519 secret key:
Ill-formed input: expected 64 bytes, got N bytes`, with the length that the
decode gave. So `--sign=zzz` reports zero bytes, and `--sign=not-base64!!!`
reports six. One stray character after a pasted 88-character key starts an
incomplete group. So the key still decodes to 64 bytes and signs.

`--sign-from-file` reads the first line as bytes and applies no encoding rule to
it. So a line with a byte sequence that is not UTF-8 reaches the decode, and its
alphabet characters give the result. A NUL byte ends the line before the
newline. A file whose first line is `AAAA\0BBBB` gives the key `AAAA`, and the
command reports three bytes.

The signing options have these other refusals. Each one exits 1, with standard
output empty and no object published:

```
error: Requested signature type is not implemented
error: dummy signature type is only for ostree testing
error: Unable to lookup key ID <KEY-ID>: GPGME: Invalid value
error: No gpg key found with ID <KEY-ID> (homedir: <path>)
error: gpg key id <KEY-ID> ambiguous (homedir: <path>). Try the fingerprint instead
error: Error opening file <path>: No such file or directory
error: Error opening file <path>: Is a directory
error: Operation not supported
```

`../format-reference.md`, "Dummy engine", states when the tool enables the
`dummy` engine.

The three GPG lines answer the three `--gpg-sign` outcomes:

- A selector of less than eight bytes gets the "Invalid value" line, with no key
  lookup, whatever it names. So `--gpg-sign=` and a short user-id substring both
  get this line.
- A selector of eight bytes or more goes to the key lookup. The lookup accepts
  each spelling that GnuPG accepts. These include a short key id, a long key id,
  a fingerprint in either case, a `0x` prefix, a trailing `!`, and a bare email.
  They also include a `<email>` or `=uid` exact form and a user-id substring.
- A selector that names no secret key gets the "No gpg key found" line. A
  selector that names more than one secret key gets the "ambiguous" line.

A selector in the form of a GnuPG option is a key selector as each other
selector is. It names no secret key and gets the "No gpg key found" line. The
command does not open the home directory that such a selector states, and that
directory gets no keybox and no trust database. The port passes the selector
after a `--` terminator, so GnuPG reads it as a key name.

The homedir term of the two lookup lines is the `--gpg-homedir` path, or the
literal `<default>` if the option is absent. These home directories each get
the "No gpg key found" line:

- a directory that does not exist
- a directory that the command cannot read
- a directory with no matching key

The line `error: Operation not supported` answers `--sign-from-file=` with an
empty path. In the tool, the `<path>` term of the two file-open lines is the
absolute path (`cli-surface.md`, "P2", `commit`).

The signing step has its own fault order. The command reads `--sign-type`
first, then each `--sign` key in order, then each `--sign-from-file` path in
order, then each `--gpg-sign` key in order. The command reads `--sign-type`
only if `--sign` or `--sign-from-file` names a key. So a name that no engine
has gives a commit in a run that signs nothing. `--gpg-sign` alone does not read
`--sign-type`.

The signing step comes after the tool writes the tree and after the branch-name
guard. It comes before the publication and the ref write (`commit`, "Fault
order", and `../format-reference.md`, "Signing sequence"). So each of these
faults comes before a key that cannot sign:

- a tree path that does not open
- a refused timestamp
- a branch name that the ref-name rule refuses

A key that cannot sign comes before a ref write that cannot occur.

#### Fault order

The tool reports the faults of `commit` in this order. The order holds for each
fault alone and for each pair of faults. Each step names the side where the
port differs.

1. The option parse. The command reads `--owner-uid`, `--owner-gid`, and
   `--fsync`, and it refuses a value that it cannot read. This step comes
   before the repository opens. The tool reads these options in command-line
   order. So a command line with a refusable id and a refusable policy reports
   the leftmost of the two (`cli-surface.md`, "P2", `commit`).
2. The repository opens.
3. The control files: first the `--statoverride` file, then the `--skip-list`
   file. Their open, read, UTF-8, and syntax faults come here.
4. The branch check of `-b` and `--orphan`.
5. The declared-id conflict. A non-zero declared id beside
   `--canonical-permissions` reports `error: Cannot specify both
   --canonical-permissions and non-zero --owner-uid`. The message names
   `--owner-uid` if both ids are non-zero. The command accepts a declared zero.
6. The `--parent` resolution.
7. The metadata options, in this order:
   - the absent parent of `--keep-metadata`
   - the absent `=` of `--add-metadata-string`
   - the absent `=` and the value parse of `--add-metadata`
   - the absent `=` of `--add-detached-metadata-string`
   - the absent key of `--keep-metadata`
8. The body file.
9. The editor. It runs after step 8 and before step 11. Not observed: the
   order of the editor and step 10.
10. The `--base` resolution.
11. The sources, one at a time and in order. The command opens each source
    when it reaches it.
12. The walk reports: the unmatched statoverride report, then the unmatched
    skip-list report, then the empty-tree refusal. A `--skip-if-unchanged`
    match comes after the unmatched statoverride report and ends the command
    at exit 0. Not observed: the order of a match and the unmatched skip-list
    report, and the order of a match and the empty-tree refusal.
13. In the tool, the kernel search of `--bootable` (`cli-surface.md`, "P2",
    `commit`).
14. The timestamp. A refused timestamp publishes no object.
15. The empty-key check, which the dict assembly makes.

Then the tool writes the tree and the commit object, and these steps follow:

16. The branch-name guard for a name that the ref-name rule refuses
    (`../format-reference.md`, "Ref name validation"). Examples are
    `bad//name`, a name with a space, and `a^b`. The refusal leaves no object
    in `objects/`. Not observed: the objects that the tool leaves for `a^b`.
    A branch name that ends in `^` has an earlier position in the tool
    (`cli-surface.md`, "P2", `commit`).
17. The signing step, in the order of `commit`, "Signing".
18. The publication and the ref write (`../format-reference.md`, "Signing
    sequence").

The tool refuses a branch name of 64 lowercase hex characters after the
publication and before the ref write (`../format-reference.md`, "Branch names
no revision reaches"). So the tree and the commit object stay in `objects/`
(`cli-surface.md`, "P2", `commit`). Not observed: the order of this refusal and
a key that cannot sign.

### `refs`

#### Listing and prefixes

The default form prints one refspec on each line. The listing covers
`refs/heads` and `refs/remotes`. A ref under `refs/heads` prints as its ref
name, and a ref under `refs/remotes` prints as `remote:name`. The listing
excludes `refs/mirrors`. A ref stored as an alias prints under its own name,
resolved through the link.

The listing sorts the whole set in one byte-wise order over the refspec
strings. It does not group the refs by ref root. So `alias1`, `deep/nest/ing`,
`origin:test/main`, `other`, and `test/main` print in that order.

A `PREFIX` argument keeps the refs that are equal to it or nested under it. The
printed name drops the prefix and the `/` after it. An exact match prints the
whole refspec: `refs test` prints `main` for `test/main`, and `refs test/main`
prints `test/main`.

A remote refspec keeps its `remote:` part, and the listing strips the ref name
after it. So `refs origin:rr` prints `origin:x` for `origin:rr/x` and
`origin:deep/y` for `origin:rr/deep/y`, and neither printed name names a ref.
`--list` turns the stripping off and prints the whole refspec.

The command accepts more than one `PREFIX`. The output groups the rows by
prefix, in the order of the prefixes on the command line, and sorts the rows in
each group. A ref that two prefixes match prints one time for each match. So
`refs mid zulu alpha` prints `one`, `two`, `zulu`, `alpha`, and `refs mid mid`
prints `one`, `two`, `one`, `two`. The prefix that selected a row strips the
name of that row, so `refs test test/main` prints `main` and then `test/main`. A
prefix that matches nothing prints nothing and exits 0.

The default listing, `--list`, `-r`, `-A`, and `--delete` validate each
`PREFIX` as a refspec, by the rule of `../format-reference.md`, "Ref name
validation". A name that the rule refuses ends the invocation with exit 1. The
tool reports `error: Listing refs: Invalid refspec <PREFIX>`
(`cli-surface.md`, "P1", `refs`). The tool refuses these prefixes:

- `test/`, `/test`, `a//b`, `.`, `..`, `test/main/`, and `test/../main`
- an empty argument, `:`, `:rr`, `origin:rr/`, and `origin:..`
- a remote half that holds a `/`, such as `or/igin:rr`

By that rule, the tool also refuses `tes~t`, `te st`, `.test`, `a*`, `-a`, and
`origin::rr`.

The check runs where the command takes each prefix. So a valid prefix ahead of
a refused one keeps its effect. `refs test 'bad/'` prints the rows that `test`
matched and then the refusal. `refs --delete deep 'bad/'` removes what `deep`
matched and leaves the rest.

A `PREFIX` also names a path under `refs/`:

- the ref name under `refs/heads`
- the ref name under `refs/remotes/<remote>`
- the directory of the remote, for a whole-remote prefix

That path is the directory that the listing enumerates. The command reads it
before the prefix filters anything, in the default listing, `--list`, `-r`,
`-A`, and `--delete`. A path that runs through a ref file ends the invocation
with exit 1. The tool reports `error: Listing refs: fstatat(<path>): Not a
directory`, with the path under the repository (`cli-surface.md`, "P1",
`refs`). The tool refuses these forms:

- a prefix whose last component is under a ref file: `plain/x` over the ref
  `plain`
- a prefix whose inner component is under a ref file: `plain/x/y`
- a prefix that reaches the ref file through an alias symlink: `al/x`, where
  `refs/heads/al` links to `test/main`
- the same forms under `refs/remotes/<remote>`: `origin:rr/x/y` over the ref
  `origin:rr/x`

A path that names nothing prints nothing and exits 0, as a prefix that matches
no ref does. This check also runs for each prefix, after the refspec rule. So
`refs test plain/x` prints the `test` rows and then the refusal, and `plain/x/`
gets the refspec refusal.

With `-c`, a positional argument is a collection id, and the command reads no
path. The tool validates the id by its collection-id rule. It refuses an invalid
id with `error: Listing refs: Invalid collection ID <id>` and exit 1
(`cli-surface.md`, "P1", `refs`).

A whole-remote prefix is a `<remote>:` prefix whose ref half is empty or `.`.
It names each ref of that remote, so `refs origin:` and `refs origin:.` each
print every ref of `origin`. The ref half stands for the root of the remote. So
the listing strips no ref name, and each row keeps its whole refspec. A
whole-remote prefix that matches no ref prints nothing and exits 0.

Under `--delete`, the command refuses a whole-remote prefix that matches a ref,
with exit 1, and that prefix removes nothing. The command matches each prefix
against the ref set as the prefixes ahead of it left it. So `refs --delete
origin:rr origin:` empties the remote with the first prefix, and the invocation
exits 0. `refs --delete origin:rr/deep origin:` leaves `origin:rr/x` for the
whole-remote prefix to match, and the command refuses the invocation.

For a whole-remote prefix, the tool joins the ref half and the name under it to
build each name that it prints or deletes. The `.` of that join stays in the
name:

- `refs --list origin:` prints `origin:./rr/x`.
- `refs -A origin:` prints `./rr/remal`.
- `refs --delete origin:` reports `error: Invalid refspec origin:./rr/x`,
  exits 1, and removes nothing. The message names one matched ref, in the
  directory order of the tool.

`cli-surface.md`, "P1", `refs`, records the port side.

`-r`/`--revision` adds one tab and the 64-character commit checksum to each
line.

#### Aliases

`-A`/`--alias` lists the aliases alone, as `<name> -> <target>`. The target is
the symlink body with its leading `../` components removed. So an alias at
`refs/heads/test/al2` that points at `../zulu` prints `zulu`, and one that
points at `sub/deep` prints `sub/deep`. The command never strips the name, and
`-r` adds nothing.

A `PREFIX` that names a ref exactly selects that one ref, printed as
`<PREFIX> -> <commit checksum>`. This holds for each kind of ref. `refs -A al`
prints `al -> <checksum>` for an alias. `refs -A test/main` and
`refs -A origin:rr/x` print the same shape for a plain ref and for a remote
ref, and neither of these refs is an alias. A bare 64-character checksum names
no ref here, so it prints nothing (`../format-reference.md`, "Revision
syntax").

Each other prefix is a filter that keeps the aliases nested under it. With an
alias at `grp/deep/z`, `refs -A grp` and `refs -A grp/deep` both print
`grp/deep/z -> test/other`. A prefix that names an alias whose target ref is
absent names no ref and holds no alias under it. So it prints nothing.

The tool names an alias under `refs/remotes/<remote>/` by its path under the
remote. So an alias at `refs/remotes/origin/rr/remal` prints as `rr/remal`. This
name drops the remote and resolves to nothing (`cli-surface.md`, "P1", `refs`).
Such an alias comes from an out-of-band change alone, because `-A --create`
refuses a NEWREF that names a remote.

The ref root of an alias is `refs/heads` for a local alias and
`refs/remotes/<remote>` for a remote one. The tool prints the stripped body also
for a link that leaves this root. So an alias at `refs/heads/xal` that points
at `../remotes/origin/rr/x` prints `remotes/origin/rr/x`, and this body names no
ref. `cli-surface.md`, "P1", `refs`, records the port side. A link that stays
inside its own root prints the stripped body.

#### Collection refs

`-c`/`--collections` lists the collection refs as `(<collection-id>, <ref>)`.
It sorts them by collection id and then by ref name. The set holds these refs:

- the own refs of the repository under `refs/heads`, qualified by its
  `[core] collection-id`
- each ref under `refs/mirrors`, qualified by the collection component of its
  path

The set excludes `refs/remotes`. A repository with no `collection-id` lists its
mirror refs alone. `-c` has precedence over `-A`, so the two together list
collection refs.

A directory under `refs/mirrors` can have a name that is not a valid collection
id. Such a directory makes the tool abort on a GLib assertion, and a signal ends
the tool. The assertion line is
`ostree_collection_ref_new: assertion 'collection_id == NULL ||
ostree_validate_collection_id (collection_id, NULL)' failed`
(`cli-surface.md`, "P1", `refs`).

#### Creating a ref

`--create=NEWREF` points a new ref at the commit that the single positional
argument names. It writes `refs/heads/<NEWREF>`, or
`refs/remotes/<remote>/<name>` for a `remote:name` NEWREF, and creates the
parent directories. `--create` has precedence over `--delete` when both are
given.
`--force` replaces an existing ref. It also replaces a regular ref file with an
alias symlink, and an alias symlink with a regular ref file.

With `-A`, `--create` writes a relative symlink. For a target under
`refs/heads`, the link body is the path from the directory of the alias to the
file of the target ref. So `--create=p/q` with the target `one` writes `../one`,
and `--create=al` with the target `test/main` writes `test/main`. For a target
under `refs/remotes`, the tool writes the `remote:name` refspec as the body. So
`--create=xal` with the target `origin:rr/x` writes
`refs/heads/xal -> origin:rr/x`, a body that names no file under `refs/heads`.

The tool then fails on its own link. Its `rev-parse xal` reports `error:
Refspec 'xal' not found`. Its default listing stops on the link with `error:
Listing refs: openat(xal): No such file or directory`. `cli-surface.md`, "P1",
`refs`, records the port side.

The command reports these errors, each with exit 1:

- No positional argument: `error: You must specify a revision when creating a
  new ref`.
- More than one positional argument: `error: You must specify only 1 existing
  ref when creating a new ref`.
- An unresolvable positional: `error: Refspec '<rev>' not found`.
- An existing NEWREF without `--force`: `error: --create specified but ref
  <NEWREF> already exists`.
- With `-A`, a NEWREF that names a remote: `error: Cannot create alias to remote
  ref: <remote>`. The message names the remote half alone, as given. So
  `--create=origin:al` and `--create=origin:rr/al` both report `origin`. This
  holds whether the repository holds refs for the remote or holds none.
- With `-A`, a positional that names anything other than an existing ref:
  `error: Cannot create alias to non-existent ref: <rev>`.

At this one site, the existence check of the target comes before the ref-name
rule. So the check answers for a bare checksum (`../format-reference.md`,
"Revision syntax"), an ancestry suffix, and a name that no ref holds. It also
answers for each name that the ref rule refuses, and reports the target as
given. These names each get it: `a/../b`, `a//b`, `.`, `..`, the empty
argument, `origin:`, `a:b:c`, `a/b:x`, `te st`, `.test`, `origin::rr`, and
`tes~t`. The tool also reports this line for a target whose path runs through a
ref file or names a directory (`cli-surface.md`, "P1", `refs`).

The command refuses a NEWREF or a positional revision whose path under `refs/`
runs through a ref file, before it writes anything. The tool also refuses a
NEWREF or a positional revision that names a directory under `refs/`. The
exception is four directory shapes that the write of the tool replaces at exit
0. `../format-reference.md`, "Ref name validation", states the messages of the
port. `cli-surface.md`, "P1", `refs`, records the messages of the tool and the
four shapes.

#### NEWREF check order

The command checks NEWREF in three steps. All three come before the resolution
of the positional. So the command reports a NEWREF fault before an unresolvable
revision.

1. The positional count.
2. The existence check. It resolves NEWREF as a revision in each case, by the
   rule of `../format-reference.md`, "Revision syntax". `--force` suppresses
   the refusal that a resolved NEWREF causes, and the resolution still runs.
3. The ref-name check, by the rule of `../format-reference.md`, "Ref name
   validation". The rule refuses a `^` in NEWREF.

Step 2 reads a trailing `^` as ancestry:

- `--create=NAME^` reports `error: --create specified but ref NAME^ already
  exists` where the base resolves to a commit that has a parent.
- `--create=NAME^` reports `error: Commit <checksum> has no parent` where the
  base is a root commit. `--create=NAME^ --force` reports the same line there.
- A NEWREF that ends in `^` and whose base names no ref kills the tool with a
  signal before it writes anything. This holds with and without `--force`, with
  and without `-A`, and with `-c` as `--create='<id>:<ref>^'`
  (`cli-surface.md`, "P1", `refs`).

Step 3 reports these:

- `--create=NAME^ --force` reports `error: Invalid refspec NAME^` where the
  ancestry resolves.
- `--create=a/../b --force nosuch` reports `error: Invalid refspec a/../b`
  before the unresolvable positional. Step 2 gives the same words for a name
  that a traversal component makes invalid. So the step that answers for such a
  name is not observable.
- A `^` inside the name gets the same message with and without `--force`,
  because step 2 reads no ancestry there. `--create=a^b` reports `error: Invalid
  refspec a^b`.
- A NEWREF that holds a second `:` stops at step 3. `-A --create=a:b:c` reports
  `error: Invalid refspec a:b:c`, exits 1, and writes nothing.

`-A` takes the same three steps in the same order and adds two steps:

4. The remote refusal. It also comes before the resolution of the positional.
5. The existence check of the target, which reports `error: Cannot create alias
   to non-existent ref: <rev>`.

Examples of step 4:

- `-A --create=origin:al nosuch` reports `error: Cannot create alias to remote
  ref: origin`.
- `-A --create=origin:rr/x --force test/main` reports the same refusal. Without
  `--force`, the command refuses this NEWREF at step 2, because the ref
  `origin:rr/x` exists.
- `-A --create=origin:bad/ test/main` stops at step 3, one step before step 4,
  with `error: Invalid refspec origin:bad/`.

Step 5 comes before the ref-name rule for the target. So the target is the one
site where a refused name gets no `Invalid refspec` line. Step 5 comes last. So
the command reports a NEWREF fault before a refused target. `-A
--create=origin:al a/../b` names the remote, and `-A --create=a/../b a/../b`
names the NEWREF.

With `-c`, step 4 is absent, because `-c` has precedence over `-A`. So
`-c -A --create=<id>:<ref>` writes a collection ref in either option order.

#### Creating a collection ref

With `-c`, `--create=NEWREF` writes a collection ref. NEWREF is a
`<collection-id>:<ref>` pair, and the write goes to
`refs/mirrors/<collection-id>/<ref>`. The command creates the parent
directories. `-c` has precedence over `-A` here too, so the two together write
a ref file.
The steps come in this order:

1. the positional count
2. the existence check
3. the ref-name check of the whole NEWREF
4. the shape of the pair
5. the resolution of the positional
6. the collection id

So the shape comes before the revision, and the collection id comes after it.
The steps apply these rules:

- A NEWREF that holds no `:` names no ref, and the command reads the whole
  argument as the collection id. `--create=fresh` reports `error: Invalid
  collection ID fresh`. `--create=org.example.Foo`, whose text is a collection
  id, reports `error: Invalid ref name (null)`. Before this line, the tool
  prints the GLib assertion line `g_regex_match_full: assertion 'string !=
  NULL' failed` (`cli-surface.md`, "P1", `refs`).
- A pair with an empty half, a second `:`, a `^` in either half, or a ref half
  that fails the ref-name rule reports `error: Invalid refspec <NEWREF>`. This
  refusal comes before the positional resolves. The message holds the whole
  pair, so `--create=<id>:a/../b` names both halves.
- A collection id is two or more elements separated by `.`. Each element starts
  with an ASCII letter or `_`, and continues with ASCII letters, digits, or `_`.
  So the command writes `a.b`, `A.b`, `_a.b`, `a._b`, `a_b.c`, and `a.b.c.d`.
  `fresh`,
  `a..b`, `a.b.`, `1a.b`, `a.1b`, `a-b.c`, and `a.b-c` report `error: Invalid
  collection ID <id>`. The id is one path component, so the filesystem alone
  limits its length.
- The existence check reads NEWREF as an ordinary refspec. So it looks up
  `<id>:<ref>` under `refs/remotes/<id>/<ref>`, and a collection ref of the same
  spelling does not count as existing. So a second `--create=<id>:<ref>`
  succeeds without `--force`. A remote ref of that spelling gets `error:
  --create specified but ref <NEWREF> already exists`.

#### Deleting refs

`--delete` removes each ref that its prefixes match and prints nothing. It exits
0 also when a prefix matches nothing. With `-c`, the prefixes are collection
ids, and the command removes the refs of each named collection. The command
leaves in place each parent directory that a removal empties. With no prefix, it
reports `error: At least one PREFIX is required when deleting refs` and exits 1.
The command refuses a whole-remote prefix that matches a ref, and the prefix
removes nothing (`refs`, "Listing and prefixes").

Under `-c`, the id that is equal to the `[core] collection-id` of the repository
removes the refs under `refs/heads` alone. It keeps the mirror refs that carry
that id. So `refs -c --delete org.example.Coll` over a repository whose
`collection-id` is `org.example.Coll` leaves `refs/mirrors/org.example.Coll/mm`
in place. A foreign id removes the mirror refs of that id. A repository with no
`collection-id` owns no id, so the command removes each mirror ref that a prefix
names.

The `-c` listing prints both sets for either id. So the two ids share one
selection and differ in the removal. The own id removes nothing and exits 0
where the local refs are absent. The command removes a local ref that carries
the name of a mirror ref, and the mirror ref of that name stays.

With `-A`, each prefix removes the set that a `-A` listing prints for it. This
set is the ref that the prefix names exactly, or the aliases nested under it.
Against the refs `test/main` and `test/other` and the alias `test/al`,
`refs -A --delete test` removes `test/al` and leaves both refs.
`refs --delete test` removes all three.

A prefix that names a ref exactly removes that one ref, for each kind of ref, as
the listing selects it. `refs -A --delete test/al` removes the alias. `refs -A
--delete other` and `refs -A --delete origin:rr/x` remove a plain ref and a
remote ref, and neither of these refs is an alias.

A prefix that holds no alias under it removes nothing and exits 0, so
`refs -A --delete deep` leaves `deep/nest/ing` in place. The prefix rules, the
whole-remote refusal, and the alias guard each read the set that the prefix
selected. Each prefix reads the aliases as the prefixes ahead of it left them.
With no prefix, the message is the message of the plain form. `-c` has
precedence over `-A` here too, in either option order.

The tool removes each alias nested under a prefix by the name that it prints
for that alias. For an alias under `refs/remotes`, that name drops the remote.
So `refs -A --delete origin:zz` removes no alias of `origin`, and removes a
local ref that carries that name where one exists. Against the remote alias
`refs/remotes/origin/zz/q` and the local ref `refs/heads/zz/q`, the tool removes
the local ref and keeps the alias (`cli-surface.md`, "P1", `refs`). The tool
refuses a whole-remote prefix that holds an alias with `error: Invalid refspec
./rr/remal`, and removes nothing.

An alias holds the ref that it names in place. A prefix that matches a ref
under `refs/heads` that an alias names ends the invocation with exit 1 and
`error: Ref '<refspec>' has an active alias: '<alias>'`. The tool removes the
members of the selected set that its removal order reaches before the guarded
member (`cli-surface.md`, "P1", `refs`). The guarded member stays. The guard
runs for each prefix. So `refs --delete deep test`
removes what `deep` matched and then reports the refusal for `test`.

The guard reads the target of an alias as the `-A` listing prints it (`refs`,
"Aliases"), from the `refs/heads` root. So an alias at `refs/heads/test/al2`
whose body is `other` names the ref `other`, although the link resolves to
`refs/heads/test/other`. So the command refuses `refs --delete other`, and
`refs --delete test/other` removes the ref. A matched ref that is itself an
alias has the same guard. So the command refuses `refs --delete test/al` where
`refs/heads/alal` links to `test/al`. The removal of an alias that no alias
names succeeds, so `refs --delete alal test/al` removes both.

Outside `refs/heads`, the removal continues. The command removes a ref under
`refs/remotes` that an alias names. This holds for an alias with a path body
(`ral -> ../remotes/origin/rr/x`) and for an alias with a refspec body
(`ral -> origin:rr/x`). An alias under `refs/remotes` or `refs/mirrors` names
nothing for the guard. With `-c` the guard does not apply. So
`refs -c --delete <collection-id>` removes the refs of that collection with the
aliases among them.

A prefix can match more than one guarded ref, or more than one alias can name
one matched ref. The message then names one pair. `cli-surface.md`, "P1",
`refs`, records the pair that each side names.

#### Symlinks under refs

A dangling alias is a symlink under `refs/` whose target ref does not exist.
The tool fails each invocation whose enumeration reaches a dangling alias. It
reports `error: Listing refs: openat(<path>): No such file or directory` and
exits 1. `<path>` is the path of the link under `refs/heads` or under
`refs/remotes/<remote>`. These invocations of the tool fail:

- the default listing, `--list`, and `-r`
- a `PREFIX` that names a directory that holds the link, in a listing and in a
  `--delete`, which then removes nothing
- `--create`, `--create --force`, and `-A --create`, which each write no ref

These forms of the tool read a dangling alias as follows:

- A link under `refs/mirrors` reaches the `-c` listing alone. For such a link,
  the default listing and `--create` complete.
- `-c --create=<id>:<ref>` completes over a link under `refs/heads`.
- `-A` lists the dangling alias. `-A` with a `PREFIX` that names the alias
  exactly prints nothing.

A `--delete` that names the link itself exits 0 and leaves the link in place.
`cli-surface.md`, "P1", `refs`, records the port side.

A symlink under `refs/` that names a directory makes the tool report `error:
Listing refs: Is a directory` and exit 1. These forms give that refusal: the
default listing, `--list`, `-r`, `fsck`, `summary -u`, and `prune --refs-only`.
These forms of the tool complete over the same link:

- A `PREFIX` that names the link enumerates the directory that the link points
  at. So `refs lnk` prints `nest/ing`, where `refs/heads/lnk` links to `deep`
  and `deep/nest/ing` is a ref.
- A `--delete PREFIX` that matches other refs removes them and exits 0.
- The default `prune` reads no ref and exits 0.

A `--delete` that names the link reports `error: Listing refs: opendir(lnk):
Not a directory` and exits 1. `-A` lists the link as `lnk -> deep`. A link that
names its own directory (`refs/heads/selfdir -> .`) gives the same results as a
link to another directory. Such a link comes from an out-of-band change alone,
because `refs -A --create` validates its target as a ref. `cli-surface.md`,
"P1", `refs`, records the port side.

### `rev-parse`

The command prints the resolved 64-character commit checksum and a newline for
each `REV` argument, in the order given. The first argument that does not
resolve reports `error: Refspec '<rev>' not found` and exits 1. The checksums of
the arguments before it are printed at that time. With no argument, the command
prints its usage text to standard error, then `error: REV must be specified`,
and exits 1.

The command refuses a `REV` whose path under `refs/` runs through a ref file or
names a directory (`../format-reference.md`, "Ref name validation").
`cli-surface.md`, "P1", `rev-parse`, records the messages.

`-S`/`--single` takes no argument and prints the one commit checksum of the
repository. The count is of the commit objects in `objects/`, and the refs do
not count. The option has these refusals, each with exit 1:

- An empty repository reports `error: No commit objects found`.
- A repository that holds more than one commit reports `error: Multiple commit
  objects found`.
- An argument with `-S` reports the usage text and `error: Cannot specify
  arguments with --single`.

### `cat`

The command writes the content of each named file to standard output, in the
order of the paths. It writes nothing between the files and adds nothing. A
leading `/` on a path is optional.

Path resolution splits the path at each `/` and looks up each component in the
commit tree literally. `.`, `..`, and an empty component each name nothing. So
`cat REV /./a.txt` reports `error: No such file or directory: /.`, and
`cat REV //a.txt` reports `error: No such file or directory: /`. The reported
path is absolute for an absolute and for a relative argument. It holds the
components up to the one that failed, and leaves out the rest of the argument.

An empty argument reaches no component and reports the commit root as absent:
`cat REV ''` reports `error: No such file or directory: /`. The argument `/`
reaches the root and gets the directory refusal.

The command follows a symlink in the final position. The target resolves
against the directory of the link, or against the commit root when the target
is absolute. The components of the target are looked up literally too, so a
target that holds `..` fails. A symlink at `/sub/rel` that points at `../a.txt`
reports `error: No such file or directory: /sub/..`. The command does not follow
a symlink in another position: `cat REV /dlink/b.txt`, where `dlink` links to
the directory `sub`, reports `error: Not a directory`.

The command follows a chain of symlinks to its end. The tool sets no depth
limit. A chain of 20000 links resolves, and a chain of 100000 links kills the
tool with a signal (exit 139). A self-referencing symlink also kills the tool
with a signal. `cli-surface.md`, "P1", `cat`, records the port side.

The command has these refusals, each with exit 1:

- A path that names a directory, or the commit root: `error: Can't open
  directory`.
- An absent path: `error: No such file or directory: <absolute path>`.
- A non-final component that is a file: `error: Not a directory`.
- An unresolvable `COMMIT`: `error: Refspec '<rev>' not found`.
- A `COMMIT` that resolves to a commit that the store does not hold: the tool
  reports `error: No such metadata object <checksum>.commit`
  (`cli-surface.md`, "P1", `cat`).
- A `COMMIT` whose path under `refs/` runs through a ref file, or names a
  directory: the command refuses it before it reads the tree
  (`../format-reference.md`, "Ref name validation"). `cli-surface.md`, "P1",
  `cat`, records the messages.
- An absent `COMMIT` or an empty path list: the usage text and `error: A COMMIT
  and at least one PATH argument are required`.

### The GVariant text form

The reading commands write a metadata value as text in the GVariant text form.
The tool writes it with the GLib printer. These forms write it: `show --raw`,
`show --print-metadata-key`, `show --print-detached-metadata-key`,
`show --print-variant-type`, `log --raw` (`log`), `ls -X`, and `summary --raw`.

#### Printing a value

The printer applies these rules:

- A value whose literal does not state its own type carries a type annotation:
  `byte 0x2a`, `int16 -5`, `uint16 5`, `uint32 42`, `int64 -5`, `uint64 42`,
  `handle 5`, `objectpath '/a/b'`, `signature 'ay'`. A byte is two lowercase
  hex digits after `0x`.
- A boolean prints `true` or `false`, and a string prints quoted. An `i` prints
  as the bare number. A `d` prints as the bare `%.17g` form of the double. None
  of these four types carries an annotation.
- The printer adds `.0` to the form of a `d` where that form holds no `.`, no
  exponent, and no `n`. So `nan`, `-nan`, `inf`, and `-inf` take no suffix.
  Examples: `1.5`, `1000.0`, `-0.0`, `0.10000000000000001`,
  `1.7976931348623157e+308`.
- A maybe states no type in either of its literals. So an annotated maybe
  carries its whole signature, and its child then prints bare: `@ms 'just'`,
  `@ms nothing`, `@mi 5`. An unannotated maybe prints the child alone, or
  `nothing`.
- A chain of nested maybes prints the value alone when each level of the chain
  is set, because the type states the level count. `@mmi 5` names a chain of
  two set levels over `5`, and `@mmmv <'x'>` a chain of three set levels over a
  variant. A chain that ends at `nothing` states its own set levels, with one
  `just ` for each level. `@mmi just nothing` has the outer level set and the
  inner level unset, and `@mmi nothing` has neither level set. The count runs to
  the depth of the type in `@mmmi just just nothing` and
  `@mmmmi just just just nothing`.
- The `just ` prefixes belong to the value, so they stay where the annotation
  is dropped: `[@mmi just nothing, nothing, 5]` and
  `{'a': @mmi just nothing, 'b': nothing, 'c': 5}`. As a result, the printed
  text reads back as the value that it came from.
- A container that holds at least one element gives its annotation to its first
  element, and the elements after it print unannotated. So `aay` that holds two
  byte arrays prints `[[byte 0x63], [0x62]]`. A tuple annotates each member,
  because the types of its members are independent: `(byte 0x01, byte 0x02)`.
  A one-member tuple keeps a trailing comma, `(byte 0x01,)`, and the empty tuple
  prints `()`.
- A container that holds no element has no element to take the annotation. So
  it carries its own signature: `@ay []`, `@a(say) []`, `@a{sv} {}`. An empty
  container in an unannotated position prints the bare literal. So `aay` that
  holds a byte array and then an empty one prints `[[byte 0x63], []]`.
- An array of dict entries prints as one list of `key: value` pairs in braces:
  `{'a': byte 0x01, 'b': 0x02}`. A dict entry outside an array prints
  `{key, value}`, with a comma.
- A variant prints `<child>`. The child always carries an annotation, because a
  variant states no child type: `<byte 0x2a>`.
- A byte array whose last byte is its only NUL prints as a bytestring literal,
  `b'user.foo'`. This literal states its own type and carries no annotation.
  Each other byte array prints as the element list, `[byte 0x01, 0x02, 0xff]`.
  The empty array has no trailing NUL, so it prints `@ay []`. The rule applies
  to real metadata: an xattr name holds a NUL terminator and prints as
  a bytestring, and its value does not. A 64-byte ed25519 signature whose last
  byte is zero also prints as a bytestring.

#### String and bytestring escapes

The two literal forms escape differently. One value with the same bytes shows
this: as a string it is `'a"b'`, and as a bytestring it is `b'a\"b'`.

- The printer writes a string in single quotes, or in double quotes when it
  holds a single quote. So the quote that it holds needs no escape. The printer
  escapes only the quote in use, so `"` stays literal inside single quotes.
  `\a`, `\b`, `\f`, `\n`, `\r`, `\t`, `\v`, and `\\` take their short escape.
  Each other C0 control and DEL takes `\uXXXX`, in four lowercase hex digits.
  The printer writes each other printable character through, ASCII or not, so
  UTF-8 stays readable.
- The tool writes a code point that GLib does not count as printable as a
  `\uXXXX` or `\UXXXXXXXX` escape (`cli-surface.md`, "P2", `commit`).
- The printer writes a bytestring in single quotes, or in double quotes when
  its content holds a single quote. It always escapes a backslash and a double
  quote, also inside single quotes. `\b`, `\f`, `\n`, `\r`, `\t`, and `\v`
  take their short escape. Each byte outside printable ASCII takes a three-digit
  octal escape: `b'\377'`, `b'h\303\251'`.

#### Byte order

The format stores its numeric fields in the variant as big-endian values, and
the framing stays little-endian (`../format-reference.md`, "GVariant
serialization rule (applies to every metadata object)"). On a little-endian
host, a value parsed from those bytes holds each numeric field byte-reversed.
One byte swap of the whole value tree gives the numbers that the fields state.
The default report makes this swap.

So the commit whose stored timestamp field is `1700000000` big-endian reports
`uint64 1700000000`. `-B` reports the stored form, `uint64 67927162644070400`.
The swap reaches a numeric field inside a variant. So a `t`-valued metadata key
that `commit --add-metadata` wrote in host order reports byte-reversed. The swap
applies to `--print-metadata-key` and `--print-detached-metadata-key` too. It
does not apply to `--print-variant-type`, whose report is byte-reversed with and
without `-B`.

#### Reading the text form back

`commit --add-metadata=KEY=VALUE` takes a value in this form. The tool reads it
by these rules.

The reader reads strings and bytestrings by these rules:

- A quoted literal is a string. Single and double quotes both open one, and the
  quote in use is the one that needs an escape. `\a`, `\b`, `\f`, `\n`, `\r`,
  `\t`, `\v`, and `\\` take their short escape. `\uXXXX` and `\UXXXXXXXX` name a
  character by code point. Each other escape drops the backslash and keeps the
  character, so `'\x41'` is the three characters `x41`.
- A backslash before a line feed is a line continuation. Both characters leave
  the value, so `'a\<LF>b'` is the two characters `ab`. This rule holds in a
  bytestring too.
- The tool accepts a `\u` or `\U` escape that names a surrogate or a code point
  past U+10FFFF. It then aborts with a signal and writes no commit
  (`cli-surface.md`, "P2", `commit`).
- The reader refuses a `\u` or `\U` escape that names U+0000, because a string
  value carries no NUL. The refusal is `invalid 4-character unicode escape` for
  `\u` and `invalid 8-character unicode escape` for `\U`, at the offset of the
  digits. So `'\u0000'` gives `3-7:invalid 4-character unicode escape`, and
  `'\U00000000'` gives `3-11:invalid 8-character unicode escape`.
- This refusal comes from the reader. So the offset follows the literal where
  it stands, whatever type is around it. Examples: `@o '/a\u0000b'` gives
  `8-12`, `@g '\u0000'` gives `6-10`, and `{'\u0000': 1}` gives `4-8`.
- The port refuses a raw NUL byte in a string literal at that byte, with
  `NUL byte in string constant`. The tool takes the value through `argv`, which
  carries no NUL byte.
- `b'...'` and `b"..."` are bytestrings, which name a NUL-terminated `ay`. An
  octal escape of up to three digits names one byte. The value ends at the
  first NUL that these escapes produce. So `b'\0'`, `b'\400'`, and `b'\0001'`
  are each the one-byte array that holds the terminator alone.
- A bytestring has no `\u` or `\U` escape. So `b'\u0000'` is the six-byte array
  that holds `u0000` and the terminator. In the port, a raw NUL byte in a
  bytestring literal ends the value, as an octal escape that names NUL does.

The reader reads numbers by these rules:

- A number is hexadecimal after `0x`, binary after `0b`, octal after a leading
  `0`, and decimal in other cases. Both prefix letters take either case.
- The double reader takes a literal with no type from its context if the body
  holds a decimal point or the word `nan` or `inf`. It also takes a body that
  holds a lowercase `e`, outside a hexadecimal body. Each other body goes to the
  integer reader. So `1e3` is 1000.0, the reader refuses `1E3` at the `E`,
  `0x1e5` is 485, and `0x1.8p1` is 3.0. An integer literal with no other context
  is an `i`.
- The type that a literal goes into selects the reader again, so the same text
  can carry two values. `@d 017` is 17.0, and `017` alone is 15. An integer
  type over a literal that the double reader takes reports the character where
  the integer reader stopped: `byte 1.5` gives `6-7:invalid character in
  number`.
- `nan`, `inf`, `-inf`, and `-infinity` are doubles. The spelling is lowercase,
  and `infinity` needs a sign. The reader refuses a magnitude outside the
  double range as out of range. It also refuses a value that rounds to a
  subnormal that the literal does not state exactly. So it refuses `5e-324` and
  `1e-308`, `1e-400` is 0.0, and it keeps `2.2250738585072014e-308`.
- The exact decimal form of a subnormal needs at least 716 significant digits.
  The tool keeps such a literal (`cli-surface.md`, "P2", `commit`).
- A hexadecimal body states its value in binary. The reader rounds it to the
  nearest double, ties to even, over a mantissa of any length.
  `0xffffffffffffffffffffffffffffffffffffffffp0` is 1.461501637330903e+48, and
  `0x1.0000000000000000000000000000000000001p0` is 1.0.
- The reader keeps a subnormal that a hexadecimal body states exactly.
  `0x1p-1023` is 1.1125369292536007e-308, and `0x1p-1074` is
  4.9406564584124654e-324. `0x1.8p-1074` and `0x1.0000000000001p-1030` round to
  a subnormal that they do not state, so the reader refuses them. `0x1p-1075` is
  at the tie that the rounding takes to even, so it is 0.0. Each smaller
  magnitude is 0.0 too.
- A zero mantissa is 0.0 under any exponent, `0x0.0p2147483647` and
  `0x0.0p-9999999999` included. At the top of the range,
  `0x1.fffffffffffff7ffffffffp1023` rounds down to the largest double and is
  kept. The reader refuses `0x1p1024` and `0x1.fffffffffffff8p1023`.
- The reader reads a leading `-` before the body, and the body can carry a sign
  of its own. `-` alone is zero, and `-+5` is -5. `--5` is the magnitude
  `2**64-5` with a negative sign, which no target type holds.

The reader reads the other literals and the keywords by these rules:

- `true` and `false` are booleans.
- `nothing` and `just <value>` are maybes.
- `[...]` is an array, `{key: value, ...}` is an array of dict entries, and
  `{key, value}` is one dict entry.
- `(...)` is a tuple. A one-member tuple is `(x,)`. The comma is required, and
  the reader refuses `(x)` with `expected ',' after first tuple element`. A
  trailing comma closes that one member alone, so `(1,2,)` reports `expected
  value`.
- `<value>` is a variant.
- A type keyword (`boolean`, `byte`, `int16`, `uint16`, `int32`, `handle`,
  `uint32`, `int64`, `uint64`, `double`, `string`, `objectpath`, `signature`)
  or a `@<signature>` declaration gives its type to the value after it.
- A keyword token is two or more characters long, starts with two letters, and
  starts in lowercase. Each other token that is not a literal is a place where a
  value was expected.

The reader reads a `@` declaration by these rules:

- A `@` declaration ends at the first character that can close something around
  it. These characters are whitespace, `,`, `:`, `>`, `]`, and a `)` or `}`
  that matches no `(` or `{` inside the declaration. So the reader reads `@i5`
  and `@**` whole and reports each as one invalid declaration. `@i)` ends at the
  bracket.
- A declaration that names one complete but indefinite type reports `type
  declarations must be definite`. Each other invalid declaration reports
  `invalid type declaration`.

The reader reads a declaration in three steps, and each step reports before the
next:

1. The signature must spell one complete type of at most 129 levels. A leaf is
   one level. `m`, `a`, a tuple, and a dict entry each add one level over their
   deepest member. A longer signature reports `invalid type declaration`.
2. The type must fit in the nesting that is left where the declaration stands.
   The limit is 128 levels in all, counted from the level of the declaration,
   with the levels of the type included. A type past that limit reports `type
   declaration recurses too deeply`.
3. The type must be definite.

So the reader refuses `@<128 array codes>y` for its depth, and `@<129 array
codes>y` as an invalid signature. With a trailing `r` in place of the `y`,
`@<128 array codes>r` reports the depth, which comes before the definiteness.
`@<129 array codes>r` reports `invalid type declaration`.

Under the depth rule, the empty tuple has no level of its own. So the reader
accepts `@<128 array codes>()` and refuses `@<128 array codes>y`. The depth
rule counts a dict entry by its value alone. So the reader accepts
`@<127 array codes>{s()}` and refuses `@<127 array codes>{sy}`.

A declaration inside containers counts from their level. So the reader refuses
`[@<127 array codes>y []]` and accepts the same declaration alone. The value
beside the declaration takes one level, whatever the levels of the declared
type.

The reader types the values by these rules:

- An `o` value must be a valid object path. That is `/`, or `/` followed by one
  or more elements of letters, digits, and underscores. Single slashes separate
  the elements.
- A `g` value must be zero or more complete types. This excludes the maybe and
  the indefinite characters. So the reader accepts `signature 'ii'` and refuses
  `signature 'ms'`. Each of those types has the same limit of 129
  levels as the signature of a declaration. So the reader accepts
  `signature '<128 array codes>y'`, and one more array code gives `not a valid
  signature`. The levels
  are inside the string, so the level of the signature value does not reduce
  them.
- A container with no declaration takes one common type over its elements. So
  `[2, 1.5]` is an array of doubles, and `['a', @ms 'b']` is an array of maybe
  strings: the maybe absorbs the bare string beside it.
- The reader refuses a literal that states no type and has no context (`[]`,
  `{}`, `nothing`). The refusal names the whole value that the reader types. A
  variant child is a whole value of its own, so `[<[]>]` names the `[]`.
- A declaration drives the check down into the value: `@as [1]` names the
  element `1` against `s`. Two members of an undeclared container that do not
  meet are both named, so `['a', 5]` reports the two spans. The reader checks
  the keys of an undeclared dictionary the same way.
- The first entry of an undeclared dictionary sets the value type alone. The
  reader reads each later value against that type, as a declaration drives the
  check down. `{'a': 1, 'b': uint32 2}` is `a{si}`, and
  `{'a': uint32 2, 'b': 1}` is `a{su}`.
- The reader names a later value that does not fit against the set type.
  `{'a': 1, 'b': just 2}` gives `14-20:can not parse as value of type 'i'`.
  `{'a': 1, 'b': 1.5}` gives `15-16:invalid character in number`, at the
  character where the integer reader stops. `{'a': 1, 'b': ['x', 5]}` gives
  `14-22:can not parse as value of type 'i'`, which names the whole array.
- The reader names a first value that states no type against the whole value
  that it types, and a later entry does not change that. So `{'a': [], 'b': 5}`
  is `0-17:unable to infer type`, and `{'a': nothing, 'b': 'y'}` is
  `0-24:unable to infer type`. The reader reports a key that does not meet the
  set key type before the value type, which then stays unresolved:
  `{'a': [], [1]: 5}` gives `1-4,10-13:unable to find a common type`.
- A type already in force takes the value beside a declaration and drops the
  declaration. `@as [@o '/a']` stores a string, and `{'a': 'x', 'b': @o '/y'}`
  is `a{ss}`. The reader accepts `{'a': 'x', 'b': @o 'notapath'}`, because the
  object-path check of `@o` does not run under a type in force.
- The reader reads the value beside such a declaration against the type in
  force. So
  `@as [@i 5]` names the `5` with `8-9:can not parse as value of type 's'`, and
  `{'a': 'x', 'b': @ms nothing}` names the `nothing` with `20-27:can not parse
  as value of type 's'`.
- A value nests inside at most 127 containers. A `[`, `(`, `{`, `<`, a `just`, a
  type keyword, and a `@` declaration each add one level. The reader refuses the
  value at level 128 with `variant nested too deeply`, and the offset names the
  token at that level. For `<`, `just`, a type keyword, and a `@` declaration,
  the tool prints an offset that has no relation to the text (`cli-surface.md`,
  "P2", `commit`). The reader also holds a `@` declaration to the levels of its
  own type, by the three steps of a declaration.

#### Refusal spans

A refusal reports `<spans>:<reason>`. A span is one byte offset for a place
where a value was expected, and `<start>-<end>` for a token. Where the reason
names two places, the two spans are separated by a comma. Examples:

- `0-2:unable to infer type`
- `0:expected value`
- `0-7:unknown keyword`
- `1-2:invalid character in number`
- `0-13:unterminated string constant`
- `4:expected ',' or ')' to follow tuple element`
- `4:expected ':' or ',' to follow dictionary entry key`
- `3:expected end of input`
- `0-1:invalid type declaration`
- `3-8:can not parse as value of type 'i'`
- `0-10:number out of range for type 'i'`
- `7-27:integer too big for any type`
- `1-4,6-7:unable to find a common type`
- `11-21:not a valid object path`
- `10-14:not a valid signature`
- `0-10:dictionary keys must have basic types`

The offsets count into the value alone. The `commit` message puts the whole
`KEY=VALUE` argument before the spans (`commit`, "The commit metadata").

The reader parses, types, and builds the whole value before it checks for
trailing input. So `@i 'x' 5` reports the member that does not fit, and
`nothing 5` reports the type that the reader cannot infer. Each of these reports
comes before the trailing `5`.

`cli-surface.md`, "P2", `commit`, records the divergences of the text form.

### `show`

#### The reporting modes

The reporting modes are mutually exclusive. If a command line gives more than
one, the first mode of this list has precedence over the others. The others
have no effect:

1. `--print-detached-metadata-key=KEY`
2. `--print-metadata-key=KEY`
3. `--list-detached-metadata-keys`
4. `--list-metadata-keys`
5. `--print-related`
6. `--print-variant-type=TYPE`
7. `--print-sizes`
8. the report of the object, which `--raw` and `-B` extend

#### The object argument

A 64-character lowercase checksum names an object. The command looks for the
object in the store in this order: commit, dirtree, dirmeta, file. So the
argument carries no type. Each other argument is a revision, which the command
resolves to a commit.

A checksum that names no object reports the failure of the last look-up, the
file object, at exit 1:

- In `archive`, whose object carries its own header, the line is `error:
  Couldn't find file object '<checksum>'`.
- In `bare`, `bare-user`, and each other mode that stores the payload in the
  object file, the line has a prefix that names the open: `error: Opening
  content object <checksum>: Couldn't find file object '<checksum>'`.

A revision that resolves to nothing reports `error: Refspec '<rev>' not
found`. With no argument, the usage text and `error: An object argument is
required` go to standard error at exit 1.

#### The metadata object report

A metadata object reports its type and its checksum on one line: `commit
<checksum>`, `dirtree <checksum>`, or `dirmeta <checksum>`. `--raw` adds the
value in the text form on the next line and reports nothing more. So `--raw`
suppresses the commit report. `-B` adds the same line with the numeric fields
as stored. The commit report then follows, with or without `--raw`.

#### The commit report

The commit report has these lines, in this order:

1. `Parent:  <checksum>`, if the commit has a parent.
2. `ContentChecksum:  <checksum>`, the SHA-256 over the two root checksums
   that `../format-reference.md`, "Checksum computation", defines.
3. `Date:  <YYYY-MM-DD HH:MM:SS +0000>`, the timestamp in UTC.
4. `Version: <value>`, if the commit metadata holds a `version` key.

The `Version:` line has one space after the colon. The `Parent:`,
`ContentChecksum:`, and `Date:` lines have two. The command reads the timestamp
as a signed count of seconds. So the instant one second before the epoch,
stored in the unsigned field as its two's-complement form, reports
`1969-12-31 23:59:59 +0000`.

The subject comes next: a blank line, then each line of the subject indented
four spaces. An empty subject reports `(no subject)`, with no blank line before
it. If the body is not empty, it comes next: a blank line, then each line of
the body indented four spaces. One blank line closes the report.

#### The file object report

A file object reports its header, one field on each line:

- `Object: <checksum>`
- `Type: file`
- `File Type: regular` and `Size: <bytes>`, or `File Type: symlink` and
  `Target: <target>`
- `Mode: 0<octal st_mode>`, the full mode with the file-type bits, after a
  literal `0`
- `Uid: <id>`
- `Gid: <id>`
- `Extended Attributes: { <a(ayay) in the text form> }`

`--raw` and `-B` change nothing in this report.

#### The metadata key modes

`--print-related` prints one line for each entry of the related-objects array
of the commit: `<ref> <checksum>`. Over a commit that holds two entries, the
tool prints one line for each entry. No `commit` option of the tool or the
port writes such an entry (`../format-reference.md`, "Commit --
`(a{sv}aya(say)sstayay)`", field 2). So the array is empty on each commit that
the tool or the port writes. Over such a commit, the mode prints nothing at
exit 0.

`--list-metadata-keys` and `--list-detached-metadata-keys` print one key on
each line, in sorted order. A commit with no `.commitmeta` reports `error: No
detached metadata for commit <checksum>` at exit 1 under either detached mode.

`--print-metadata-key=KEY` and `--print-detached-metadata-key=KEY` print the
value of the key, unwrapped from its `v` and annotated as a value of its own
type. A key that the dict does not hold reports `error: No such metadata key
'<key>'` at exit 1.

Not observed: the answer of the tool to a repeated `--print-metadata-key` or
`--print-detached-metadata-key`. `cli-surface.md`, "P1", `show`, records the
port side.

`--print-hex` applies to a key whose value type is `ay` alone. The bytes print
as unquoted lowercase hex with no separator. An empty array prints an empty
line. A value of each other type, `aay` included, ignores the option.

#### `--print-sizes`

`--print-sizes` totals the `ostree.sizes` metadata of the commit
(`../format-reference.md`, "The `ostree.sizes` key") over three lines:

```text
Compressed size (needed/total): <n> bytes/<n> bytes
Unpacked size (needed/total): <n> bytes/<n> bytes
Number of objects (needed/total): <n>/<n>
```

The "needed" figures cover the recorded objects that the local store does not
hold. So they are zero in a complete repository, and they count the absent
objects in a partial one. A commit that holds no such key reports `error: No
metadata key ostree.sizes in commit` at exit 1.

#### `--print-variant-type`

`--print-variant-type=TYPE` reads the object argument as a filename. It reports
the bytes of the file as a value of that type. A path that does not open
reports `error: openat(<path>): <reason>` at exit 1.

#### GPG signatures

A commit that carries GPG signatures reports them after the commit report. The
tool writes these lines:

- a blank line, then `Found <n> signature:`, or `signatures:` for more than
  one
- for each signature, a blank line, then `  Signature made <date> using
  <algorithm> key ID <the last sixteen hex digits of the fingerprint>`
- for each signature, one verdict line

Over a good signature, an absent key, and a signature that does not verify,
the verdict line is one of these:

- `  Good signature from "<user id>"`
- `  BAD signature from "<user id>"`
- `  Can't check signature: public key not found`

The tool writes `<date>` in the host locale and time zone. The tool writes a
different verdict line, or more lines, for these cases:

- a revoked key
- a key that states an expiry
- a signature that a subkey made
- a signature that does not verify

`cli-surface.md`, "P1", `show`, records the port side.

The exit status stays 0 for each verdict. The keyring is the `gpgkeys.gpg` of
the repository. With `--gpg-verify-remote=REMOTE`, the command reads the
trusted keyrings of that remote in place of `gpgkeys.gpg`
(`../format-reference.md`, "GPG").
`--gpg-homedir=HOMEDIR` adds the `*.gpg` files of the named directory as
keyrings.

### `log`

The command walks the parent chain from the given revision, newest first. It
reports each commit the same way as `show`: `commit <checksum>`, then the
commit report (`show`, "The commit report"). `--raw` reports only `commit
<checksum>` and the value in the text form for each commit, the same
suppression that `show --raw` makes.

A parent whose commit object is absent ends the walk with the line `<< History
beyond this commit not fetched >>`, at exit 0. So a partial history reports
the commits that it holds. A `.commitpartial` marker changes nothing.

A revision that resolves to nothing reports `error: Refspec '<rev>' not found`
at exit 1. With no argument, the usage text and `error: A rev argument is
required` go to standard error at exit 1.

### `ls`

#### The line format

The command prints one line for each entry:

```text
<type><mode> <uid> <gid> <size>[ <checksum>...][ { <xattrs> }] <path>[ -> <target>]
```

- The type is `d` for a directory, `-` for a regular file, and `l` for a
  symlink.
- The mode is the permission bits alone (`mode & 07777`) in five octal digits:
  `00755`, `00644`, and `00777` for a symlink.
- The uid and the gid are decimal, with no padding.
- The size is right-aligned in six columns. It is the payload size of a
  regular file, and zero for a directory and for a symlink.
- The path is absolute. A symlink adds ` -> ` and its target.

`-C`/`--checksum` inserts the checksums after the size. A file has one, its
content checksum. A directory has two, its dirtree and then its dirmeta.
`-X`/`--xattrs` inserts the `a(ayay)` xattr set of the entry after them, in
`{ ` and ` }`. So an entry with no xattrs reports `{ @a(ayay) [] }`.

`--nul-filenames-only` prints the paths alone, each followed by a NUL. It
prints no columns, no target, and no newline. It overrides `-C` and `-X`.

#### Order and recursion

A directory reports itself, then its files, then its subdirectories. Each group
is in the order of its list in the dirtree (`../format-reference.md`, "Dirtree
-- `(a(say)a(sayay))`"). So a directory `aaa` comes after a file `zzz`.
`-R`/`--recursive` prints the contents of each subdirectory directly after the
line that names it. `-d`/`--dironly` reports the directory alone.

#### The `PATH` and `COMMIT` arguments

With no `PATH`, the command lists the tree root. It lists each `PATH` in turn,
and a leading `/` is optional. A `PATH` that names a file reports that one
line.

A `PATH` that names nothing reports `error: Inspecting path '<argument>': No
such file or directory: <absolute path>` at exit 1. The message quotes the
argument as given and names the absolute path that it resolved to. An empty
`PATH` resolves to the root, and the command refuses it the same way: `error:
Inspecting path '': No such file or directory: /`.

With no `COMMIT`, the usage text and `error: An COMMIT argument is required` go
to standard error at exit 1.

### `config get`

The command prints the value and a newline at exit 0. The key is
`sectionname.keyname`, split at its first `.`. So `config get a.b.c` reads the
key `b.c` in the group `a`. With `--group=GROUP`, the option names the group,
and the argument is a whole key name, dots included.

#### The value

The command prints the value after the reader unescapes it and removes the
whitespace after the `=` (`../format-reference.md`, "Config file
(`<repo>/config`, GKeyFile / INI)"). A `"` in the value is an ordinary
character. A value with nothing after the `=` prints an empty line.

Not observed: the answer of the tool to a value with an escape that the rules do
not name, or with a final lone backslash. `cli-surface.md`, "P1", `config get`,
records the port side.

#### Refusals of `config get`

Each refusal of this list exits 1 with no usage text:

- A key with no `.` and no `--group`: `error: Key must be of the form
  "sectionname.keyname"`, in ASCII double quotes.
- A group that the file does not hold: `error: Key file does not have group
  “<group>”`.
- A key that the group does not hold: `error: Key file does not have key
  “<key>” in group “<group>”`.
- No key: `error: KEY must be specified`, or `error: Group name and key must be
  specified` with `--group`.
- An operation other than `get`, `set`, and `unset`: `error: Unknown operation
  <operation>`.

The two messages that name a group or a key quote it in typographic quotes
(U+201C and U+201D), the pair that GLib uses.

Two checks come before the check of the operation name. Both run after the
repository resolves. Each prints the usage text and then its error line, at
exit 1:

- No operation: `error: OPERATION must be specified`.
- More arguments than the operation takes: `error: Too many arguments given`.

`set` takes two arguments, a key and a value. Each other operation takes one.
So the command refuses `get KEY EXTRA`, `unset KEY EXTRA`, and `set KEY VALUE
EXTRA`, and it accepts `set KEY VALUE`. An operation that the tool does not
know also takes one argument. So `<unknown> KEY EXTRA` reports the argument
count, and `<unknown> KEY` reports the unknown operation.

### `config set` and `config unset`

Both commands write the whole document back and print nothing at exit 0. They
read the key the same way as `config get`: `sectionname.keyname` split at its
first `.`, or a whole key name with `--group=GROUP`.

`set` takes a key and a value. The command puts the key by these rules:

- A group that the document does not hold goes at the end, after a blank line.
- A key that its group does not hold goes at the end of that group.
- A key that the group holds keeps its position and takes the new value.

The command escapes the value with the writer escapes of
`../format-reference.md`, "Config file (`<repo>/config`, GKeyFile / INI)".

`unset` takes a key. If the command removes the last key of a group, the group
header stays in the file with no entries. If the document does not hold
the key or the group, the command succeeds and does not change the file.
`unset` removes each key that it is given, `core.mode` included. The command
does not check the document that it writes.

The rewritten document keeps the groups and the keys that the operation did
not touch, in the order that it read them. It drops the comment lines and the
blank lines of the input. The command replaces the file atomically, at mode
`0644`.

Each refusal of this list exits 1 with no usage text:

- `set` with less than two arguments: `error: KEY and VALUE must be
  specified`, or `error: GROUP name, KEY and VALUE must be specified` with
  `--group`.
- `unset` with no argument, and a key with no `.` and no `--group`: the texts
  of `config get`, "Refusals of `config get`".

The argument-count check and the absent-operation check of `config get` come
before each of these refusals.

### `remote`

`remote` takes a nested subcommand. If the nested subcommand is absent, the
command reports the usage text of `remote` and `error: No "remote" subcommand
specified` at exit 1. This refusal comes before the command resolves a
repository.

#### `remote add`

`remote add NAME URL [BRANCH...]` writes the section `[remote "NAME"]` and
prints nothing at exit 0. It writes the keys in this order:

- `url`, or `metalink` if the URL has the `metalink=` prefix. The command
  removes that prefix. A `mirrorlist=` prefix stays in the `url` value.
- `branches`, if the command line gives branches. A `;` follows each branch,
  the last one included.
- `contenturl`, from `--contenturl=URL`.
- `custom-backend`, from `--custom-backend=NAME`.
- each `--set=KEY=VALUE` pair, in the order given.
- `gpg-verify=false`, from `--no-gpg-verify`, and from `--no-sign-verify`,
  which turns off both checks.
- `sign-verify=false`, from `--no-sign-verify`.
- `verification-<engine>-key` for each `--sign-verify=KEYTYPE=inline:PUBKEY`,
  or `verification-<engine>-file` for each `--sign-verify=KEYTYPE=file:PATH`.
  Then `sign-verify` names the engines, separated by commas, in the order
  given.
- `collection-id`, from `--collection-id=ID`.

Not observed: the answer of the tool to `--sign-verify` together with
`--no-sign-verify`. The port refuses the pair (`cli-surface.md`, "P3",
`remote`).

Not observed: the answer of the tool to `--gpg-import=FILE`. The port takes
the option. After the port writes the section, it imports the keys of `FILE`
into the keyring of the remote, the same way as `remote gpg-import` with
`--keyring`. It then prints the import count in the form of `remote
gpg-import`. If `--if-not-exists` leaves the section in place, the port
imports nothing (`cli-surface.md`, "P3", `remote`).

#### Remote names

The tool takes a remote name by these rules:

- The name has one character or more.
- Each character is alphanumeric, or one of `-`, `_`, and `.`.
- The first character is alphanumeric or `_`.

So `_`, `1o`, and `a..b` are names. The empty name, `-`, `.`, `..`, `a b`,
`a/b`, and `a+b` are not names. A refused name reports `error: Invalid remote
name <name>` at exit 1, and the command writes nothing.

Not observed: the answer of the tool to a non-ASCII letter. The port takes a
non-ASCII letter as alphanumeric, so such a letter is a name in the port.

`add` and `delete` refuse a name that breaks these rules. The reading
subcommands take a name of each shape, and a name that breaks the rules names
no section.

#### Existing sections and option refusals

A section that is already in the file reports `error: Remote configuration for
"<name>" already exists: (in config)` at exit 1. `--if-not-exists` leaves the
section as it is, at exit 0. `--force` replaces the whole section. Both options
together report the usage text and `error: Can only specify one of
--if-not-exists and --force`.

Each refusal of this list exits 1 with no usage text:

- A `--set` value with no `=`: `error: Missing '=' in KEY=VALUE for --set`.
- A `--sign-verify` value other than `KEYTYPE=inline:DATA` and
  `KEYTYPE=file:DATA`: `error: Failed to parse KEYTYPE=[inline|file]:DATA in
  <value>`.

An absent NAME or URL reports the usage text and `error: NAME and URL must be
specified`.

#### `remote delete`

`remote delete NAME` removes the section and the keyring
`<remote>.trustedkeys.gpg` of the remote, and prints nothing at exit 0. A
section that the document does not hold reports `error: Remote "<name>" not
found` at exit 1. `--if-exists` changes that refusal to exit 0. The port
removes the keyring before it writes `config`. So if the write of `config`
fails, the section stays and the keyring is gone.

#### `remote list` and `remote show-url`

`remote list` prints one name on each line, sorted by name. The order of the
sections in the file has no effect. `-u`/`--show-urls` pads each name with
spaces to the length of the longest name of the list plus two, counted in
bytes. The `url` of the remote follows. A section that has no `url`, for
example a metalink remote, reports `error: No "url" option in remote
"<name>"` at exit 1 at its turn. The names before it are then already printed.

`remote show-url NAME` prints the `url` value and a newline. It reports the
same two refusals:

- `error: Remote "<name>" not found`
- `error: No "url" option in remote "<name>"`

#### `remote refs`

`remote refs NAME` fetches the summary of the remote. It prints one `NAME:REF`
line for each ref that the summary lists, in the order of the summary.
`-r`/`--revision` adds a tab and the commit checksum to each line. A remote
that publishes no summary reports `error: Remote refs not available; server has
no summary file` at exit 1.

#### `remote summary`

`remote summary NAME` fetches the same summary and reports it. It takes the
reading options `--raw`, `--list-metadata-keys`, and `--print-metadata-key=KEY`
of `summary` (`summary`, "The reading options"). A remote that publishes no
summary reports `error: Remote server has no summary file`.

The default report prints each ref of field 0, then the refs of each
collection that `ostree.summary.collection-map` lists, then the global
metadata. One ref reads:

```
* main
    Latest Commit (150 bytes):
      21386ebf0c349ce54f2196fb4ec77f5a4dc57d03d4a4d5a97c61a9542c9e5e23
    Version (ostree.commit.version): 1.2.3
    Timestamp (ostree.commit.timestamp): 2023-11-14T22:30:00+00
```

A blank line follows each ref. If the summary states
`ostree.summary.collection-id`, the report names each ref of field 0 as a
pair, `* (org.example.C, main)`. The report names each collection-map ref as a
pair with its own collection. The `Version` line is present only if the ref
metadata holds the key, and its string prints unquoted.

The `Timestamp` line converts the stored big-endian field. It renders the
instant as `YYYY-MM-DDTHH:MM:SS`, then the offset of the time zone. The tool
uses the host time zone (`cli-surface.md`, "P3", `remote`). The examples show
the form under `TZ=UTC`.

A run of `summary -m` with no mirror ref writes no map of its own. Such a run
can store each value under `ostree.summary.collection-map`
(`../format-reference.md`, "Summary and summary signature"). The report reads
such a map with no refusal.

A map value of type `a{sa(s(taya{sv}))}` lists its refs. A value of each other
type lists no refs, and the metadata line still prints `(printed above)`. A
commit checksum in the map that is not 32 bytes prints `Invalid checksum of
length <n> expected 32` in place of the hex. The other lines of the ref print
as usual.

The global metadata prints in the order of the summary, one line for each
entry, with a label for each key that the format defines:

```
Repository Mode (ostree.summary.mode): archive-z2
Last-Modified (ostree.summary.last-modified): 2026-08-05T19:40:49+00
Has Tombstone Commits (ostree.summary.tombstone-commits): No
Static Deltas (ostree.static-deltas): {'<from>-<to>': <[byte 0xeb, 0x57]>}
Collection Map (ostree.summary.collection-map): (printed above)
Collection ID (ostree.summary.collection-id): org.example.C
Expires (ostree.summary.expires): 2023-11-14T22:13:20+00
ostree.summary.indexed-deltas: true
```

`Last-Modified` and `Expires` convert their big-endian field the same way as
the `Timestamp` line. The three lines read the field as a signed count of
seconds. They write the year with no zero padding, so the first second of year
1 reads `1-01-01T00:00:00+00`. An instant before year 1 or after year 9999
prints `invalid`.

The other lines of the global metadata follow these rules:

- `Has Tombstone Commits` prints `Yes` or `No`.
- `Collection Map` prints `(printed above)`, because the report gives its refs
  with the other refs.
- A key that the format does not define, `ostree.summary.indexed-deltas`
  included, prints its own name and its value.
- A string value prints unquoted if the key has a label, and quoted if the key
  has no label. The report reads `Static Deltas` as a whole value, so a string
  under its key also prints quoted.
- Each value outside the labeled set prints in the GVariant text form, with no
  type annotation and no byte-order conversion. So a `t` value stored
  little-endian reads as the number that it holds.

#### `remote gpg-import`

`remote gpg-import NAME [KEY-ID...]` adds the keys of each
`-k`/`--keyring=FILE`, or of standard input under `--stdin`, to the keyring
`<remote>.trustedkeys.gpg` of the remote. It prints `Imported <n> GPG key to
remote "<name>"`, with `keys` for each count other than 1. The count is the
number of keys that the keyring did not hold before, so a repeated import
reports `0`.

The keyring that the tool writes obeys these rules:

- A Trust packet follows the primary key packet, each user id packet, and each
  signature packet.
- A certificate for a key that the keyring holds adds its user ids, its
  signatures, and its subkeys to the held certificate. The import counts that
  key as held, so it reports `0`.
- If the held keyring has bytes after its last framed packet, the tool reports
  `Imported 0 GPG keys` at exit 0 and writes nothing.

`cli-surface.md`, "P3", `remote`, records the port side.

A `KEY-ID` selects the keys that it names from the source: a fingerprint, a
key id, or a substring of a user id. `cli-surface.md`, "P3", `remote`, records
the selector dialect of each side.

The command has these refusals:

- Both sources: the usage text and `error: --keyring and --stdin are mutually
  exclusive`.
- A `--keyring` that names no file: `error: Error opening file <path>:
  <reason>`. The command opens the file before it looks for the remote.
- A remote that the configuration does not describe: `error: GPG: Remote
  "<name>" not found`. This message is the only refusal of the command with the
  `GPG: ` prefix.

#### `remote gpg-list-keys`

`remote gpg-list-keys NAME` reports each key of the keyring of the remote in
this form. The `Created` line of the example shows the instant in UTC:

```
Key: FA2B2317C9966572B5D729EDCA965442280A3BB5
  Created: 2026-08-05 20:04:00 +0000
  UID: Ostrya Test <test@example.invalid>
```

A key with more than one user id has one `UID` line for each id. A keyring that
is absent or holds no key prints nothing at exit 0.

The tool renders `Created` in the host locale and time zone. The tool writes
these lines too:

- an `Advanced update URL` line and a `Direct update URL` line after each
  `UID` line, which name the Web Key Directory location of the key
- a `Subkey:` line, and a `Created:` line under it, for each subkey
- a `(revoked)` marker after the fingerprint of a revoked key and after each
  revoked user id

`cli-surface.md`, "P3", `remote`, records the port side.

### `export`

The command writes the tar stream and no line of its own.
`../format-reference.md`, "tar", states the member names, the metadata
conventions, and the member order of the stream. "The tar export options"
states the four options that shape the stream and the effect of `-o` on its
destination.

### `prune`

The command writes two lines to standard output. Without `-v`, the tool writes
nothing to standard error. This is also true over a repository whose config
sets `[core] locking` false. Under `-v`, the tool adds `OT: ` trace lines on
standard error and does not change standard output. `cli-surface.md`, "P2",
`prune`, records the standard error of the port under `-v` and under `[core]
locking` false.

#### The totals line

The first line states how many objects the run examined:

```
Total objects: <count>
```

Under `--commit-only`, the first line names the restriction and counts commit
objects alone:

```
Total (commit only) objects: <count>
```

The count covers the loose objects that the run read. Detached commit metadata
(`.commitmeta`), tombstone markers (`.tombstone-commit`), and static deltas are
not in the count. The run takes the count after `--delete-commit` removes its
target. So the deletion of one commit decreases the count by one.

The second line states the result:

```
No unreachable objects
Deleted <count> objects, <size> freed
Would delete: <count> objects, freeing <size>
```

The run writes the first form if it deletes nothing, with or without
`--no-prune`. It writes the third form under `--no-prune`, and the second form
in each other case. `<count>` has no singular form: a run that deletes one
object writes `Deleted 1 objects`.

`<size>` is the number of bytes that the deleted objects occupied on disk, in
the form of "The size wording". The bytes that a deleted `.commitmeta` freed
are not in the sum, because that object is not in the count.

#### The size wording

The size wording is a decimal (SI) rendering of a byte count:

- Less than 1000 bytes: the byte count, an ASCII space, and the word `byte` or
  `bytes`. The word is singular at 1 alone: `0 bytes`, `1 byte`, `673 bytes`.
- 1000 bytes or more: a number with one fractional digit, then U+00A0
  NO-BREAK SPACE (bytes `C2 A0`), then the unit. The unit is the largest of
  `kB`, `MB`, `GB`, `TB`, `PB`, and `EB` whose factor the byte count reaches.
  Each factor is a power of 1000. The number is the count divided by that
  factor.

The quotient is a double. The tool rounds its exact value to one fractional
digit, with ties to even. So 1250 bytes render as `1.2 kB`, and 1750 bytes as
`1.8 kB`. The byte count selects the unit before the rounding. So 999950 and
999999 bytes render as `1000.0 kB`, and 1000000 bytes as `1.0 MB`. The largest
count, 18446744073709551615, renders as `18.4 EB`.

```
0          -> 0 bytes
1          -> 1 byte
673        -> 673 bytes
999        -> 999 bytes
1000       -> 1.0 kB
1073       -> 1.1 kB
1172       -> 1.2 kB
100172     -> 100.2 kB
999999     -> 1000.0 kB
1000000    -> 1.0 MB
1500173    -> 1.5 MB
1000000173 -> 1.0 GB
```

The tool formats the number through the locale of the C library. The rows of
the table are `prune` output under `LC_ALL=C.UTF-8`. `static-delta show` gives
the same wording under `LC_ALL=C` and `LC_ALL=C.UTF-8`. Both locales render the
decimal separator as `.`.

Not observed: the separator of the tool under a locale with a different
decimal separator. `cli-surface.md`, "P2", `prune`, and `cli-surface.md`,
"P2", `static-delta`, record the port side.

### `fsck`

`fsck` writes its phase lines and its summary lines to standard output. It
writes each finding and each `error: ` line to standard error.

#### The phase lines

A run writes four phase lines, in this order. It writes each line when it
enters the phase.

```
Validating refs...
Validating refs in collections...
Enumerating commits...
Verifying content integrity of <N> commit objects...
```

A run that ends inside a phase writes the lines up to and including the line
of that phase. `-q`/`--quiet` suppresses these four lines and no other line.
The tombstone lines, the partial-commit line, the summary line, and each
finding stay.

`<N>` is the number of commit objects in the store that have no
`state/<commit>.commitpartial` marker (`../format-reference.md`, "Commit-state
markers").

Phase 1 reads each ref under `refs/heads` and `refs/remotes`. It loads the
commit object that each ref names. Phase 2 reads each collection ref: the local
refs, qualified by the `[core] collection-id` of the repository, and the refs
under `refs/mirrors/<collection-id>/`. It loads the commit objects in the same
way. Phase 1 and phase 2 verify the checksum of each commit object that they
load. Phase 3 lists the commit objects and separates the commit objects that
are already marked partial.

Phase 4 is the object walk. It walks the objects that the verified commits
reference, and verifies each object.

#### The progress line

The tool writes a progress line to standard output (`cli-surface.md`, "P2",
`fsck`).

```
fsck objects (<n>/<total>) <pct>%
```

`<n>` is the number of objects verified. `<total>` is the number of distinct
objects that the verified commits reference. `<pct>` is
`floor(n * 100 / total)`.

The tool writes the first update, the last update, and about one more update
each second between them. So a short run writes two lines, and a long run
writes more. A run that ends before it verifies an object writes no progress
line. A run over a store of zero objects also writes no progress line.

`<total>` counts the objects that the verified commits reach, present or
absent. The loose objects on disk do not set the count.

- An object that only a skipped commit reaches is outside the count.
- An object that a verified commit references and that is absent is inside
  the count.
- Detached commit metadata (`.commitmeta`) is outside the count.
- A static delta is outside the count.

#### The summary lines

```
object fsck of <N> commits completed successfully - no errors found.
<N> partial commits not verified
```

The first line ends a run that found no fault and skipped no commit. It goes to
standard output, and the run exits 0.

The second line states the number of commits that phase 3 skipped. It goes to
standard output. If the run reported no finding, standard error then holds
`error: <N> partial commits from fsck-detected corruption`, and the run exits
1. A run with a finding ends with `error: Repository corruption encountered` in
place of that error line. `--add-tombstones` suppresses the second line and
keeps the error line.

#### The findings

A faulty object gives one line. The line names the commits that reach the
object.

```
In commits <c>, <c>: fsck content object <checksum>: Corrupted file object; checksum expected='<name>' actual='<computed>'
In commits <c>, <c>: fsck <checksum>.<type>: Corrupted <type> object; checksum expected='<name>' actual='<computed>'
Object missing in commits <c>, <c>: <checksum>.<type>
```

`<type>` is the type string, which is the same in each repository mode. So a
content object is `file` in an `archive` repository too, where the loose object
is a `.filez`.

Phase 1 or phase 2 reads a commit object that a ref names. These phases reach
no commit through the ref. So the finding of such a commit object has no
`In commits <list>: ` prefix.

A corrupt object is an object whose checksum does not match its name. A
corrupt object alone marks no commit. Under `--delete`, the run unlinks the
corrupt object, and then marks the commits that reach it.

The run reports an absent object, and marks each commit that reaches it as
partial. Each marking writes this line:

```
Marking commit as partial: <commit>
```

A metadata object can hold bytes that do not read as the type of its name.
The tool reads such an object under the GVariant rules for data that is not in
normal form. The next action of the tool follows from the values that those
rules give (`cli-surface.md`, "P2", `fsck`).

An absent dirtree ends the run (`fsck`, "Where a run ends"). The run marks
nothing and writes this line:

```
error: No such metadata object <checksum>.dirtree
```

A ref over a commit object that the store does not hold ends the run in the
phase that read the ref. The run writes these lines:

```
Object missing: <checksum>.commit
error: Loading commit for ref <name>: No such metadata object <checksum>.commit
```

Under `--delete`, the run unlinks a commit object that a ref names and that
fails its checksum. The run writes the finding `fsck <checksum>.commit:
Corrupted commit object; ...`. It then ends with the `error: Loading commit for
ref ...` line, and writes no `Object missing` line.

For a ref under `refs/heads` or `refs/remotes`, `<name>` is the bare ref name,
without the remote prefix. For a ref under `refs/mirrors`, `<name>` is
`(<collection-id>, <name>)`.

#### Where a run ends

Three conditions end a run of `fsck`, whatever the options:

- A ref over a commit object that the store does not hold. The run ends in the
  phase that read the ref.
- An absent dirtree. The run cannot read the objects under it.
- A `--verify-bindings` failure or a `--verify-back-refs` failure.

A run that one of these conditions ends closes with the `error: ` line of the
condition (`fsck`, "The findings", and `fsck`, "The binding checks").

An absent content object or an absent dirmeta never ends a run, whatever the
options. The run reports the object, and the object walk continues.

The tool also ends a run at the first corrupt object, unless `-a/--all` or
`--delete` is given. Such a run writes that finding as its own `error: ` line
(`cli-surface.md`, "P2", `fsck`). In the tool, `--delete` carries the run past
a corrupt object, with or without `-a`. `-a` carries the object walk past a
corrupt object. `-a` also carries phase 1 and phase 2 past a commit object
whose checksum does not match.

Each other run of the tool writes each finding plain. It closes with
`error: Repository corruption encountered`, unless one of the three conditions
ends it first.

#### The binding checks

`--verify-bindings` adds one check to phase 1 and one check to phase 2. Each
check ends the run at its first failure, whatever the other options (`fsck`,
"Where a run ends"). A commit that has no `ostree.ref-binding` key passes.

```
error: Commit <c>: Commit has no requested ref ‘<ref>’ in ref binding metadata (‘a’, ‘b’)
error: Commit <c>: Commit has collection ID ‘<bound>’ in collection binding metadata, while the remote it came from has collection ID ‘<found>’
```

The parenthetical lists the stored bindings in stored order. Each binding is in
U+2018 and U+2019 quotes, and `, ` separates the bindings. For an empty list,
the parenthetical is `(no refs)`.

`--verify-back-refs` adds a check for each commit to phase 3, over each commit
object in the store. Each name in the `ostree.ref-binding` of a commit must
name a ref that resolves to that commit. A ref under `refs/remotes` counts by
its bare name. If the commit has an `ostree.collection-binding`, the collection
ref `(binding, name)` must also exist and resolve to the commit.

```
error: Ref ‘<name>’ in bindings for commit <c> does not exist
error: Ref ‘<name>’ in bindings for commit <c> does not resolve to that commit
error: Collection–ref (<id>, <name>) in bindings for commit <c> does not exist
error: Collection–ref (<id>, <name>) in bindings for commit <c> does not resolve to that commit
```

The dash in `Collection–ref` is U+2013 EN DASH. The check fails on each branch
that holds more than one commit. The parent commit holds the branch name, and
the name resolves to the tip.

The two options are independent. `--verify-back-refs` alone runs the
back-reference check alone. The order of the two options has no effect. The
bindings check runs first, because its phase runs first.

#### `--add-tombstones`

The option acts on a commit object whose `parent` names a commit object that
the store does not hold. It deletes that commit object and writes the
`.tombstone-commit` that names it. It writes one line after the object walk:

```
Adding tombstone for commit <commit>
```

The step runs after the object walk. A run of the tool that ends at its first
corrupt object does not reach the step, and writes no tombstone (`fsck`,
"Where a run ends"). Under `-a` or `--delete`, the object walk of the tool runs
to its end, and the step acts beside the findings (`cli-surface.md`, "P2",
`fsck`). So the step acts beside an absent content object or an absent dirmeta
with neither option (`fsck`, "Where a run ends").

The step reads the absence against the object list that the run took at its
start. So one run removes one generation, and a branch with a broken history
loses one commit in each run. The run exits 0. An absent parent commit is not a
fault, and a run with no option over the same repository reports nothing. The
option needs no `[core] tombstone-commits` setting. An existing tombstone for
the absent parent does not stop the action.

The branch ref stays over the deleted commit. So the next run ends in the
phase that reads the ref.

#### Exit status

- 0 -- the repository is sound, or the only condition found is an absent
  parent commit.
- 1 -- a faulty object, a commit skipped as already partial, a ref over an
  absent commit, an absent dirtree, and a binding failure.

`-q` changes no exit status. `-a` changes no exit status. `fsck`, "Where a run
ends", states the conditions that end a run.

### `diff`

`diff` compares two sides and writes the paths that changed. A side is a commit
in the repository or a directory on the filesystem.

The per-path lines and the stats block go to standard output. Each `error: `
line goes to standard error.

#### The per-path line

```
<prefix><four spaces><path>
```

The prefix is one of three characters:

- `A` -- the path is on the second side alone.
- `D` -- the path is on the first side alone.
- `M` -- the path is on both sides, and its stored form differs.

#### What a change is

`M` covers these changes:

- a content change
- a mode change
- an ownership change
- an xattr change
- a symlink target change
- a directory metadata change
- a name whose type is different on the two sides

The modification time is outside the comparison.

For a commit side, the comparison reads the checksums that the dirtree objects
hold. It reads no payload.

- A regular file or a symlink differs where its content object checksum
  differs. That checksum covers the uid, the gid, the mode, the xattrs, the
  symlink target, and the payload (`../format-reference.md`, "Checksum
  computation").
- A directory differs where its dirmeta checksum differs. That checksum covers
  the uid, the gid, the mode, and the xattrs.
- A device node, a fifo, and a socket have no prefix of their own. Such an
  entry is `A` where it is on the second side alone, and `D` where it is on the
  first side alone. It is `M` where the other side holds a regular file or a
  symlink of the same name. Two such entries of one name differ where their
  mode differs.
- Not observed: the result of the tool for two such entries of one name that
  differ in the uid, the gid, or the xattrs.
- A name that a directory holds on one side and a file holds on the other side
  differs. The comparison does not descend into it.

The metadata of the root directory is outside the comparison.

#### Directory sides

`diff` reads a directory side as the filesystem holds it.

Not observed: a directory side of the tool in a `bare-user-only` repository.
In the port, a commit of such a repository records the reduced form
(`../format-reference.md`, "Checksum computation"). The comparison holds these
reduced objects against the full form that the directory has.

In the tool, a directory side names an entry with the bytes that the directory
returned. So the tool lists a name that is not valid UTF-8, descends into it,
and writes it to standard output as those bytes. A symlink target that is not
valid UTF-8 reaches the comparison as one value. So two such targets of one
name compare equal, and a valid target differs from each of them
(`cli-surface.md`, "P2", `diff`).

#### The groups and the order

A run collects three lists. It prints them in the order `M`, `D`, `A`. In one
list, the order is the order in which the walk found the entries.

The walk starts at the two root directories. At each pair of directories of one
name, it runs two passes:

1. The first pass reads the entries of the first side, in the order of that
   side. An entry that the second side does not hold is `D`. The pass does not
   list the children of a removed directory. An entry that both sides hold is
   `M` where its stored form differs. Where both sides hold a directory of that
   name, the pass descends into the pair at once. Then it reads the next entry
   of the first side.
2. The second pass reads the entries of the second side, in the order of that
   side. An entry that the first side does not hold is `A`. An added directory
   lists itself, then its own entries in the order of that side. It descends
   into each subdirectory at the position of the subdirectory.

The order of a side is:

- For a commit side, the files of the directory in stored order, then the
  subdirectories of the directory in stored order. The dirtree object holds
  both arrays sorted by name (`../format-reference.md`, "Dirtree --
  `(a(say)a(sayay))`"). So the order is the sorted file names, then the
  sorted subdirectory names.
- For a directory side, the order in which the directory returns its entries.
  The files and the subdirectories mix in that order.

#### How a path prints

An `M` path or a `D` path has the name that the first side gives it. An `A`
path has the name that the second side gives it. A commit side names a path
with a leading `/`. A directory side names a path relative to the directory
that the argument gave, with no leading separator.

#### The stats block

```
[A] Object Count: <count>
[B] Object Count: <count>
Common Object Count: <count>
Common Object Size: <size>
```

`[A]` and `[B]` are literal. The first two counts are the sizes of the object
sets of the two commits. The object set of a commit holds these objects:

- the commit object
- the root dirmeta object
- each dirtree object
- each other dirmeta object
- each content object that the tree of the commit reaches

The set does not hold the parents of the commit or its detached metadata
object.

`Common Object Count` is the size of the intersection of the two sets.
`Common Object Size` is the sum of the on-disk sizes of the loose object files
of that intersection. So an `archive` repository counts the compressed size,
and a `bare` repository counts the payload size. `<size>` has the size wording
of `prune` (`prune`, "The size wording"). An empty intersection prints
`0 bytes`.

#### The arguments

The command takes one or two positional arguments.

An argument that begins with `/` or with `./` is a directory on the filesystem.
Each other argument is a revision. The rule reads the spelling of the argument
alone. So a relative path without `./` is a revision, also where the
directory exists. `.` and `..` are revisions.

With one argument, the first side is that argument with `^` appended. The
second side is the argument as given. The directory rule applies to the form
with `^`.

`--stats` reads both arguments as revisions, whatever their spelling. Thus
`--stats` refuses a directory side. The run writes all per-path lines before
the stats pass. So a run with `--fs-diff` and a directory side writes the
per-path lines and then the refusal.

#### The options

- `--stats` -- the stats block.
- `--fs-diff` -- the per-path lines.
- `--no-xattrs` -- no xattrs from a directory side. The option applies to both
  directory sides and to no commit side.
- `--owner-uid=UID` -- the user id `UID` for the entries of the second side,
  where that side is a directory. The option does not apply to the first side
  or to a commit side. A negative value declares nothing. The value reader is
  the C `int` reader of `commit` (`commit`, "The declared ownership").
- `--owner-gid=GID` -- the same for the group id.

With neither `--stats` nor `--fs-diff`, the per-path lines print. With
`--stats` and no `--fs-diff`, they do not print. With `--stats`, the stats
block prints after the per-path lines, whatever the order of the two options.

#### Exit status

- 0 -- both sides were read, whether or not a difference was found.
- 1 -- a side that cannot be read, a revision that does not resolve, and an
  object that the store cannot supply.

### `sign`

`sign --verify COMMIT [KEY-ID...]` verifies the signatures of one commit. The
options are `-s`/`--sign-type=NAME`, `--keys-file=PATH`, and
`--keys-dir=PATH`.

#### The key sources of `sign`

Under the `ed25519` engine, `sign --verify` takes the key sources that
`static-delta`, "Key sources", states. The port also applies them to the
`spki` engine. The tool decodes a KEY-ID and an ed25519 `--keys-file` line
with the lenient base64 reader of `commit --sign` (`commit`, "Signing"). An
spki `--keys-file` and each spki file of the key store hold PEM `PUBLIC KEY`
blocks (`static-delta`, "spki public key files"). An spki KEY-ID is the
base64 of a SubjectPublicKeyInfo DER (`static-delta`, "spki inline keys").

Where a key source does not load, the tool refuses the run at exit 1, with
nothing on standard output. The refusals are:

- `no keys loaded`
- `File object '<path>' is not a regular file`
- `no valid keys in file '<path>'`

The tool tries the positional keys first. It reads the last `--keys-file` only
where no positional key verifies. The tool skips a KEY-ID that does not decode
to 32 bytes, with no message. It ignores a `--keys-file` line of that kind where
another line verifies. It decodes a line of the bytes `\xff\xfe` and a valid key
as that key. `cli-surface.md`, "P2", `sign`, records the port side.

Under `ed25519` and `spki`, the port reads each `--keys-file` given when it
signs and under `-d`/`--delete` (`cli-surface.md`, "P2", `sign`).

#### The gpg engine

The port has a `gpg` engine on `sign`. Under this engine, each `--keys-file` of
a verify or of a `-d`/`--delete` is a keyring, and the port reads each keyring
given. The port refuses `--keys-file` in a gpg signing run with this line:

```
error: signature: gpg signing takes KEY-ID arguments; --keys-file keyrings serve verify and delete
```

The port refuses `--keys-dir` under this engine.

#### The verify report

On success, the tool writes one line, `ed25519: Signature verified
successfully with key '<hex>'`. The line names the key that verified. On
failure, the tool writes nothing to standard output and one `error: ` line:

- the keys are positional keys alone: `No valid signatures found`, over a
  signed commit and over an unsigned commit
- a keys file or a key store supplies the keys, and the commit has no
  signature of the engine: `ed25519: commit have no signatures of my type`
- each trusted key of the store is revoked: `ed25519: no signatures found`
- no key verifies: `ed25519: Signature couldn't be verified with: key
  '<hex>'; ...`

`cli-surface.md`, "P2", `sign`, records the port side.

Under the gpg engine, the port writes the report that `cli-surface.md`, "P2",
`sign`, records, with one line for each signature. A line also has ` key
<fingerprint>` where the signature names its key. It has ` (<name> <email>)`
where the key has a user id. A user id with no address gives ` (<name>)`. A
user id with an address alone gives ` (<<email>>)`.

### `summary`

`summary` writes the repository summary, signs it, or reads it.

The writing options are `-m`/`--add-metadata=KEY=VALUE`, `--sign=KEY-ID`, and
`--gpg-sign=KEY-ID`. Only `-u` reads them. `-u` also reads `--sign-type`. In
the port, `--sign-type` also names the engine of `--verify`, and of a
positional key or a `--keys-file` key.

The four reading options are `-v`/`--view`, `--raw`, `--list-metadata-keys`,
and `--print-metadata-key=KEY`. Each reading option reads `<repo>/summary` and
no other file. No reading option opens `summary.sig`. So a signed summary and
an unsigned summary give the same text.

#### The precedence

The precedence is fixed. The order of the options on the command line does
not change it.

1. `--verify` reports the signatures and returns. It takes the key sources of
   `sign --verify` (`sign`, "The key sources of `sign`"). It writes the port
   report of `sign --verify` (`cli-surface.md`, "P2", `sign`).
2. `-u`/`--update` checks the writing options, regenerates the summary, signs
   it, and returns. It writes no report.
3. A signing key given as a positional argument or with `--keys-file` signs
   the summary that is in place, and returns (`cli-surface.md`, "P2",
   `summary`).
4. `--raw`.
5. `-v`/`--view`.
6. `--list-metadata-keys`.
7. `--print-metadata-key=KEY`.

Steps 1 and 3 are port extensions. The tool takes steps 2 and 4 to 7 in this
order.

With no option, the command refuses at exit 1. Without `-u`, no step reads the
writing options. Beside a reading option, the writing options have no effect,
and the command writes the report. Alone, they get the no-option refusal before
the command reads a value. The port gives this refusal before it reads a
positional key.

In a repository that holds no `summary` file, the command refuses each reading
option at exit 1, with nothing on standard output.

#### The `-u` checks

Under `-u`, each check runs before the regeneration, in this order. So a
refusal leaves `summary` and `summary.sig` as they were. The summary then lists
no ref that was added after the last regeneration.

1. Each `-m` argument, in command-line order. The argument splits at its first
   `=`. An argument with no `=` reports `error: Missing '=' in KEY=VALUE
   metadata '<arg>'`. The command parses the value in the GVariant text form
   before it reads the next argument. A parse failure reports `error: Error
   parsing variant ‘<value>’: : <offsets>:<reason>`, with U+2018 and U+2019
   around the value. `-m` accepts the empty key.
2. Each `--gpg-sign` lookup, in command-line order, in the home directory that
   `--gpg-homedir` names. The refusals are the three lookup refusals of
   `commit` (`commit`, "Signing"). Without `--gpg-sign`, the command does not
   open `--gpg-homedir`.
3. `--sign-type`. The command reads it only where `--sign` names a key. The
   command takes the last value. The refusals of `dummy` and of a name that no
   engine has are the ones of `commit` (`commit`, "Signing"). With no key, the
   command does not read the name.
4. Each `--sign` key, in command-line order. A key that is not a 64-byte
   ed25519 secret key gets the secret-key length refusal of `commit`
   (`commit`, "Signing"). The tool signs with a 64-byte value whose trailing 32
   bytes are not the public key of the leading 32-byte seed. 64 zero bytes are
   one such value (`cli-surface.md`, "P2", `commit`, and `cli-surface.md`,
   "P2", `summary`). In the port, under `--sign-type=gpg`, this check looks up
   each key with the refusals of check 2 (`cli-surface.md`, "P2", `summary`).
5. In the port, the positional keys and the `--keys-file` keys, under the same
   engine. The port looks up a gpg selector here with the refusals of check 2.
6. In the port, each `-m` key in a repository with a collection id. The port
   refuses it with `error: unsupported: summary metadata keys in a repository
   with a collection id` (`../format-reference.md`, "The `ostree-metadata`
   anchor commit"). The tool adds such keys to the anchor commit
   (`cli-surface.md`, "P2", `summary`).
7. In the port, the client groups of the config (`ostrya-config(1)`, "Start
   checks"). A malformed group gets one `error:` line.

The regeneration then removes `summary.sig`. The port then writes all
signatures in one write of `summary.sig`. The order of the signatures is the
order that `../format-reference.md`, "Summary signature -- `a{sv}`", states.
The port writes one summary for each auth item of the client groups, with
the same signatures, as `../format-reference.md`, "Summaries of auth items",
states. With the port extension `-c`, the port writes the summaries of the
auth items alone, and leaves `summary` and `summary.sig` as they are
(`cli-surface.md`, "P2", `summary`).

#### The reading options

The reading options read `summary`. With the port extension
`--auth-group=NAME`, they read the summary of the auth item of the client
group `NAME` (`cli-surface.md`, "P2", `summary`).

`-v`/`--view` writes the report of `remote summary`, byte for byte. The report
holds each ref of field 0, then the refs of each collection that
`ostree.summary.collection-map` lists, then the global metadata in stored
order. The ref block, the label set, the `(printed above)` line, and the quote
rule for a string value are the rules of `remote`, "`remote summary`".

`--raw` writes one line: the whole document in the annotated GVariant text
form, with the big-endian fields converted, and one newline.

`--list-metadata-keys` writes the global metadata keys, one key on each line,
sorted.

`--print-metadata-key=KEY` writes one value, unwrapped from its `v`, in the
annotated text form, with the same conversion. A key that the dict does not
hold reports `error: No such metadata key '<key>'` at exit 1, with nothing on
standard output. Over a summary that holds no empty key,
`--print-metadata-key=` reports the same refusal for the empty key.

Not observed: a read by the tool of a summary that holds the empty key.

#### Byte order in the reports

`--raw` byte-swaps each scalar of the whole document, and
`--print-metadata-key` each scalar of the value that it prints ("The GVariant
text form", "Byte order").

The report converts each labeled `t` field, and reads each other value in host
order (`remote`, "`remote summary`"). `summary -m` stores a value in host
order. The `t` fields of the format are big-endian
(`../format-reference.md`, "Summary -- `(a(s(taya{sv}))a{sv})`"). So the
report and the annotated forms state different numbers for a value from `-m`.

On a little-endian host, a summary that holds `zzz.last` as the `u` value 42
reports `zzz.last: 42` in the report and `uint32 704643072` under `--raw`.

#### Exit status

- 0 -- the summary was written, signed, or reported.
- 1 -- one of these conditions:
  - no option given
  - a writing option given without `-u` and without a reading option
  - an absent `summary` file
  - a key that the metadata dict does not hold
  - each refusal of `summary`, "The `-u` checks"
  - in the port, each refusal of `--auth-group`
  - in the port, `-c` with no `-u`

A `summary` file can hold bytes that are not a document of the summary type.
Only a program other than the tool and the port writes such a file into a
repository. The tool reads such a file as an empty document
(`cli-surface.md`, "P2", `summary`).

### `static-delta`

`static-delta` has eight subcommands:

- `show DELTA` reports the superblock of one delta and the contents of each of
  its parts.
- `list` lists the deltas under `deltas/`.
- `indexes` lists the `delta-indexes/` cache.
- `delete DELTA` removes one delta.
- `verify DELTA [KEY-ID...]` checks the signatures of the superblock of one
  delta.
- `generate [TO]` writes one delta.
- `apply-offline PATH [KEY-ID...]` applies one delta into the repository and
  prints nothing.
- `reindex [--to=REV]` rewrites the `delta-indexes/` cache, or the index file
  of one target, and prints nothing.

`show`, `list`, `indexes`, and `verify` read the repository and write nothing
to it.

#### The arguments

The rules of this section apply to `show`, `delete`, and `verify`.
`apply-offline` takes a path alone, and `static-delta`, "`apply-offline`",
states how it reads the path.

The tool opens the repository before it reads the argument. So with no
repository, `verify` reports `Command requires a --repo argument` before an
absent `DELTA`. `generate` reports the same line before an absent `TO`.

An argument that holds a `/` is the path of a superblock file. The path is
relative to the working directory, or absolute. Each other argument is a delta
name, also where a file of that name exists in the working directory:

- `show sbfile` reports `error: Invalid rev sbfile`.
- `show dd` reports `error: Invalid rev dd` for a directory `dd` that holds a
  `superblock`.

A name is `TO` or `FROM-TO`, split at the first `-`. Each half must be 64
lowercase hex characters:

- A half whose byte length is not 64 reports `error: Invalid rev <half>`, with
  the half cut to its first 64 bytes. The empty half of `C-` and `-C` reports
  `error: Invalid rev ` with nothing after the space. The `TO` half of
  `C1-C2-C2` reports the first 64 bytes, `C2`.
- A half of 64 bytes that holds a byte outside `[0-9a-f]` reports `error:
  Invalid character '<n>' in rev '<half>'`. `<n>` is the decimal value of the
  first such byte: `70` for `F`, `71` for `G`, `65` for `A`, and `103` for
  `g`.

A name in the valid form reads `deltas/<fanout>/<rest>/superblock` in the
repository. `../format-reference.md`, "Static delta directories", states this
directory. A failed read reports one of these lines:

- An absent delta reports `error:
  openat(deltas/<fanout>/<rest>/superblock): No such file or directory`.
- An absent path reports `error: openat(<path>): No such file or directory`.
- A path that names a directory reports `error: Is a directory`.

A name reads its part files at `deltas/<fanout>/<rest>/<i>`. For a path, the
tool reads the part files from the repository, at `deltas/<fanout>/<rest>/<i>`
for the source and the target that the superblock names. The tool opens no
file beside the path. `cli-surface.md`, "P2", `static-delta`, records the port
side.

In `show`, `delete`, and `verify`, the tool reads no inline part
(`../format-reference.md`, "Inline parts"). In both forms it opens the part
file, and it refuses where the repository holds none. `cli-surface.md`, "P2",
`static-delta`, records the port side.

#### `show`

`show` writes these lines, one field on each line, in this order:

```
Delta: <argument as given>
Signed: no|yes
From <scratch>            or   From: <hex>
To: <hex>
Endianness: little|big|invalid|big (heuristic)
Timestamp: <n>
Number of parents: <n>
Number of fallback entries: <n>
  <fallback checksum>     (one line each, two-space indent)
Total Fallback Size: <n> (<size>)
Total Fallback Uncompressed Size: <n> (<size>)
Number of parts: <n>
PartMeta<i>: nobjects=<n> size=<n> usize=<n>
PartPayload<i>: nmodes=<n> nxattrs=<n> blobsize=<n> opsize=<n>
PartPayloadOps<i>: openspliceclose=<n> open=<n> write=<n> setread=<n> unsetread=<n> close=<n> bspatch=<n>
Total Part Size: <n> (<size>)
Total Part Uncompressed Size: <n> (<size>)
Total Size: <n> (<size>)
Total Uncompressed Size: <n> (<size>)
```

The `From <scratch>` line has no colon. The `From: <hex>` line has a colon.
The three `Part` lines repeat for each part, in part order. Each field comes
from the superblock (`../format-reference.md`, "Static delta wire format"):

- `Signed` is `yes` for a superblock in the signed envelope.
- `Endianness` is `big` where the `ostree.endianness` byte is `B`, and
  `little` where it is `l`. The tool prints `invalid` where the key is absent
  over a delta whose sizes are little-endian. It also prints `invalid` where
  the byte has another value, such as `x`. It prints `big (heuristic)` where
  the key is absent over a delta written under `B`, and then swaps the sizes.
  `../format-reference.md`, "Endianness", states the heuristic.
  `cli-surface.md`, "P2", `static-delta`, records the port side for these
  three cases.
- `Timestamp` is field 1, read big-endian (`../format-reference.md`,
  "Endianness").
- `Number of parents` is the byte length of field 5, the recursion array,
  divided by 64 and rounded down. `../format-reference.md`, "Static delta wire
  format", states that this array is always empty.
- The fallback line prints each fallback checksum. The two fallback totals add
  the compressed size and the uncompressed size of each fallback.
- `PartMeta<i>` prints the object count, `size`, and `usize` of meta entry `i`.
- `PartPayload<i>` and `PartPayloadOps<i>` read part `i`. They print the table
  counts and the member sizes that the payload framing states
  (`../format-reference.md`, "Part framing"). They also print the count of each
  opcode in the operation stream (`S`, `o`, `w`, `r`, `R`, `c`, `B`).
- `Total Part Size` adds the `size` of each part, and `Total Part Uncompressed
  Size` adds the `usize`. `Total Size` is the part size plus the fallback size.
  `Total Uncompressed Size` is the part `usize` plus the fallback uncompressed
  size.

Under `B`, the tool swaps each size field before it prints it. The `<size>` term
has the wording of `prune`, "The size wording". A 4-part delta with one
5,000,000-byte fallback prints `Total Size: 8602260 (8.6 MB)` and `Total
Uncompressed Size: 8600163 (8.6 MB)`. The space before `MB` is U+00A0.

`show` writes the lines one at a time, so the lines before a refusal reach
standard output. The tool refuses an absent part after its `PartMeta<i>` line.

#### Part checks

The tool does not check a part against the size and the checksum that its meta
entry declares. Where the part still decodes, the tool prints the counts of
what it decodes. `cli-surface.md`, "P2", `static-delta`, records the port
side.

The tool prints the `PartPayload<i>` line and then refuses an operation stream
with one of these faults:

- an unknown opcode
- a stream that ends inside an operation
- an `S` range past the data-source blob
- an `r` range past the blob

The tool does not check the range of a `w` with no read source set, or the
range of a `B`. It counts the operation. An `o` whose mode index or xattr index
is outside its table makes the tool abort on `SIGABRT` after the
`PartPayload<i>` line. `cli-surface.md`, "P2", `static-delta`, records the port
side for these streams.

The tool allocates the xz decoder memory that the xz stream of a part states.
`cli-surface.md`, "P2", `static-delta`, records the 128 MiB limit of the port.

#### `indexes`

`indexes` prints the target commit of each index file in full hex, one on each
line. With no index file, it prints `(No static deltas indexes)`. This includes
an absent `delta-indexes/`.

An index file is a regular file with a 41-byte stem and the suffix `.index`. It
is in a fanout directory with a 2-byte name, directly under `delta-indexes/`. A
symlink is neither an index file nor a fanout directory. The tool skips each
other entry:

- a fanout of 1, 3, or 44 bytes
- a stem of 40 or 42 bytes
- the suffixes `.INDEX`, `.index.index`, `.index~`, and `.idx`
- a directory named `*.index`
- a symlink
- a regular file in the fanout position
- a file directly under `delta-indexes/`

`indexes` reads no delta directory. So it lists a target whether or not a delta
for it exists.

The tool prints the targets in the order that the directory returns them. The
tool does not check the characters of a name. It lists a name from a lenient
decode where the name has a character outside the modified-base64 alphabet. It
does the same where the last character of the name has low bits that are not
zero. For some such names, the tool prints bytes that the name does not
determine. `cli-surface.md`, "P2", `static-delta`, records the port side for
the order and for such a name.

The tool refuses a `delta-indexes` that is a regular file at exit 1, with
`error: opendirat: Not a directory`. It refuses a fanout that does not open at
exit 1. `cli-surface.md`, "P2", `static-delta`, records the port side.

#### Delta selection

An entry `deltas/<fanout>/<rest>` is a delta when `<fanout>` and `<rest>` are
directories and `<rest>/superblock` resolves. The tool follows no symlink at
`<fanout>` or at `<rest>`. It follows a symlink at `superblock`. It does not
read the superblock, so an empty file or a directory named `superblock`
counts.

The tool skips these entries:

- an empty directory
- a directory that holds parts and no superblock
- a regular file
- a directory whose `superblock` is a dangling symlink
- a symlink at `<fanout>` or at `<rest>`, also where it points to a directory
  that holds deltas, or where it is a loop
- a regular file directly under `deltas/`

The tool follows a symlink at `deltas` itself, also where it points to a
directory outside the repository. A dangling symlink at `deltas` holds no delta.
`show`, `verify`, `delete`, and `generate` also follow the symlink at `deltas`.
`generate` writes the new delta below the target of that symlink.

This rule selects the deltas that `list`, `reindex`, the
`ostree.static-deltas` map of a summary, and a prune read:

- A prune leaves a delta directory that holds no superblock, also where its
  commit is the one that the prune deletes.
- A prune leaves the deltas behind a symlink at `<fanout>` or at `<rest>`.
- A prune follows a symlink at `deltas` and removes the deltas behind it that
  it selects. The link stays.

`cli-surface.md`, "P2", `prune`, records two more rules of the port prune. One
is for a delta name that does not decode. The other is for a delta whose target
commit is absent. `../format-reference.md`, "Prune removal order", states the
two rules.

#### `list`

`list` prints the name of each delta that `static-delta`, "Delta selection",
selects, one on each line. The name of a from-scratch delta is the target
commit in full hex. The name of a delta from a source commit is
`<from-hex>-<to-hex>`. With no delta, `list` prints `(No static deltas)` at
exit 0. This includes an absent `deltas/` and an empty fanout directory.

The tool prints the names in the order that the directories return them, as
for `indexes`. Where the entry holds a superblock, the tool lists a name that
does not decode from a lenient decode. The line then holds bytes that the name
does not determine. Where such an entry holds no superblock, the tool skips
it.
`cli-surface.md`, "P2", `static-delta`, records the port side for the order and
for such a name.

The tool refuses these faults at exit 1:

- A `superblock` that is a symlink loop. The tool reports `error:
  fstatat(<rest>/superblock): Too many levels of symbolic links`.
- An entry that cannot be searched. The tool reports `error:
  fstatat(<rest>/superblock): Permission denied`.
- A `deltas` that is a regular file. The tool reports `error: opendirat: Not a
  directory`.

`cli-surface.md`, "P2", `static-delta`, records the port side of these
refusals.

#### `delete`

`delete` takes a delta name alone. The rules of `static-delta`, "The
arguments", apply. `delete` reads an argument that holds a `/` as a name too.
So
`delete ./x` reports `error: Invalid rev ./x`, and `delete` refuses the path of
a superblock file the same way.

The existence check reads `deltas/<fanout>/<rest>` and follows symlinks. Where
nothing resolves there, `delete` reports `error: Can't find delta <name>`, with
the name in full hex. An absent `deltas/`, an absent fanout, and a dangling
symlink at the path report this text. The dangling symlink stays.

`delete` removes the entry at `deltas/<fanout>/<rest>` and each entry below it:

- a delta directory, with its nested directories
- a regular file, or a directory with no superblock
- a symlink, as a link, with its target left in place

`delete` reads a directory at or below the path with read permission alone. It
removes an empty directory with no search permission. A directory with no
search permission that holds an entry makes the removal fail. A directory with
no read permission also makes the removal fail.

`delete` follows no symlink below the path. It follows a symlink in the fanout
position, and a symlink at `deltas`, as `static-delta`, "Delta selection",
states. So `delete` removes the delta behind a symlink at `deltas`, and the
link stays. The fanout directory stays, also where it becomes empty.

`delta-indexes/` and `summary` stay as they are. So they can still name the
removed delta, and `indexes` still lists its target. A `reindex` and a new
summary refresh them. `delete` writes nothing to standard output or standard
error, and it takes no repository lock.

A removal that fails stops where it failed, and leaves the entries that it did
not reach. The tool reports one of these lines:

- a failed existence check: `error: fstatat(<path>): <reason>`
- a directory that it cannot open: `error: open(<path>): <reason>`
- an entry that it cannot remove: `error: Removing <path>: unlinkat(<name>):
  <reason>`

`cli-surface.md`, "P2", `static-delta`, records the port side.

#### `verify`

`verify` takes a delta name or a superblock path, under the rules of
`static-delta`, "The arguments". It reads the superblock alone and opens no
part. So a copy of a superblock under any file name, away from its parts,
verifies. The options are `--sign-type=NAME`, `--keys-file=PATH`, and
`--keys-dir=PATH`. The tool takes the last value of a repeated option.

Standard output holds one line. It is `Verification OK` at exit 0, or
`Verification fails` at exit 1 with the reason on standard error. The checks run
in this order. A refusal before step 4 writes nothing to standard output. The
exceptions are the `Sign-type not supported` line of step 2 and the verdict line
of step 3.

1. No `DELTA` reports `error: DELTA must be specified` at exit 1. This check
   comes before the sign type.
2. The sign type. `ed25519` is the default, and the name follows the rule of
   `commit`, "Signing". `gpg`, the empty name, and each name that no engine of
   the build carries print `Sign-type not supported` on standard output. They
   then report `error: Requested signature type is not implemented`.
   `cli-surface.md`, "P2", `static-delta`, records the port side for
   `spki`.

   The tool takes `dummy` at this step. It reads the keys and then reports
   `Verification fails` with a reason, for example `no signature for
   'ostree.sign.dummy' in static-delta superblock`. With no key source, it
   reports `error: not implemented`. `cli-surface.md`, "P2", `static-delta`,
   records the port side for `dummy`.
3. The keys load, under the rules of `static-delta`, "Key sources". The tool
   refuses here a keys file that is not a regular file or that holds no key. It
   also refuses here a key of the wrong length, and a key source with no trusted
   key. A `--keys-file` line of the wrong length beside a valid line is the
   exception. The tool then writes the verdict line, and exits 1 with the
   invalid-key error (`cli-surface.md`, "P2", `static-delta`). The keys load
   before the argument resolves, so an invalid name with no key source reports
   `no keys loaded`.
4. The argument resolves and the superblock reads. `Invalid rev`, `Invalid
   character`, `openat(<path>): <reason>`, and `Is a directory` come after
   `Verification fails`.
5. The tool checks the signatures. One of these lines reports a failure:
   - A superblock with no signed envelope reports `error: no signatures in
     static-delta`.
   - An envelope with no signature under the key of the engine reports
     `error: no signature for 'ostree.sign.<type>' in static-delta
     superblock`.
   - Where no signature verifies, the line is `error: <type>: Signature
     couldn't be verified with: key '<hex>'`. The line holds one `key
     '<hex>'` for each effective key, joined by `; `, in reverse load order.
     A key that loaded more than once is in the line one time, at its first
     place in load order. The tool reverses the order after it removes the
     repeats.
   - Where the revoked set removed each trusted key, the line is `error:
     <type>: no signatures found`.

#### Key sources

These rules apply to the `ed25519` engine. The port also applies them to the
`spki` engine, where a `--keys-file` and each file of the key store hold PEM
`PUBLIC KEY` blocks ("spki public key files"), and a KEY-ID is the base64 of
a SubjectPublicKeyInfo DER ("spki inline keys").

- The tool trusts each positional KEY-ID and each key of the last
  `--keys-file`, in that load order. It does not read an earlier
  `--keys-file`.
- With a KEY-ID or a `--keys-file`, the tool reads no `--keys-dir` and no
  system key directory, and it revokes no key.
- With neither, the last `--keys-dir` supplies `trusted.<type>`,
  `revoked.<type>`, and their `.d` directories. `../format-reference.md`,
  "Signing details", states this key store. Without `--keys-dir`, the system
  key directories supply them. An empty `--keys-dir` names the working
  directory.
- No trusted key reports `error: signature: <type>: no keys loaded`. This check
  comes before revocation. So a store whose trusted keys are all revoked
  reaches step 5 of `verify` and reports `no signatures found`.

The tool decodes a KEY-ID and a `--keys-file` line with the lenient base64
reader of `commit`, "Signing". A line that is not UTF-8 decodes to no byte. An
ed25519 key with a length other than 32 bytes reports `error: Invalid ed25519
public key: Ill-formed input: expected 32 bytes, got <n> bytes`. A line of the
key store follows the rules that `cli-surface.md`, "P2", `static-delta`,
states.

A `--keys-file` must be a regular file, with symlinks followed. An absent path,
a directory, a FIFO, and the empty path report `error: File object '<path>' is
not a regular file`. In an ed25519 file, each line is one key, with a trailing
`\r` removed. A file with no key line reports `error: signature: <type>: no
valid keys in file '<path>'`.

A line of two or more whitespace bytes is a key of 0 bytes. Over a line of 0 or
1 byte, `verify` and `sign --verify` of the tool stop on `SIGSEGV` after a GLib
assertion. A lone `\r` is such a line. The tool reads a file of more than 1 MiB
whole and verifies with its keys. `cli-surface.md`, "P2", `static-delta`,
records the port side.

#### spki public key files

The `ostree` 2026.1 build with OpenSSL on the NixOS development host reads a
`--keys-file` of the spki engine, each spki file of the key store, and
`verification-spki-file` as PEM `PUBLIC KEY` blocks. Observed on 2026-10-25:

- The tool removes the leading and trailing spaces and tabs of a line, then
  compares the line with a boundary. A boundary line with other text on it is
  plain text.
- The label compare is exact and case-sensitive. A block of another label
  refuses the run with `error: Unexpected label "<label>"`, also beside a valid
  `PUBLIC KEY` block.
- A BEGIN line with no END line refuses the run with `PEM trailer not found`.
  A file with CR line ends only gives the same error.
- An END label that is not the BEGIN label refuses the run with `Unmatched PEM
  header`. An END line and a BEGIN line on one line give the same error.
- Base64 lines and other text outside the blocks are ignored.
- A BEGIN line in a block: the tool reads the body lines before the inner
  BEGIN line as the block.
- The tool reads a body of any line width, with blank lines, white space in a
  body line, characters that are not base64, and data after the padding.
- A `PUBLIC KEY` block that does not decode: the tool loads the file and fails
  when a verify reaches the key of that block. The result depends on the order
  of the keys.
- An empty `--keys-file`, or a file of white space only, reports `error:
  signature: spki: no valid keys in file '<path>'`.
- A trusted file of the key store with one of the errors above, or with a
  block of another label, is dropped with no message. The tool loads the other
  files.
- A revoked file of the key store with one of these errors revokes no key, or
  the keys of the blocks before the first error, with no message. A
  `revoked.spki` of base64 lines revokes no key.

`cli-surface.md`, "P2", `static-delta`, records the port side.

#### spki inline keys

The `ostree` 2026.1 build with OpenSSL on the NixOS development host reads an
inline key of the spki engine as base64 text. Observed on 2026-10-25, with
P-256 keys:

- A secret key of `sign`, `commit --sign`, and `static-delta generate --sign`
  is the base64 of a PKCS#8 DER or of a SEC1 DER. The tool signs with each of
  the two, also when the base64 text holds LF or CRLF line breaks.
- Observed on 2026-10-26 with a 2048-bit RSA key: `sign -s spki COMMIT KEY`,
  where `KEY` is the base64 of a PKCS#1 `RSAPrivateKey` DER, signs at exit 0.
  `sign --verify` verifies the signature.
- The decode of a secret key skips characters outside the base64 alphabet,
  by the rule of `commit`, "Signing". A space, a tab, a form feed, or a `!`
  at any position, the end included, does not stop the signature. Text after
  the padding does not stop it either. A key whose base64 ends in `==` is
  refused with no `=` and with one `=`. The tool signs with three or four `=`
  at the end, and with a last character whose unused low bits are not zero.
- These secret keys refuse the run at exit 1: a SEC1 key with no
  `parameters` field, a SEC1 key with its public point whose `parameters`
  field names secp384r1, the base64 of a raw 32-byte scalar, and the base64 of the full PEM text.
  `sign` and `commit` report `error: Not able to sign the cobject: openssl:
  Failed to initialize spki key`, and `commit` moves no ref. `static-delta
  generate` writes its statistics lines, then reports `error: openssl: Failed
  to initialize spki key`, and writes no superblock.
- `summary -u --sign-type=spki --sign=KEY` with each of these secret keys
  reports `error: openssl: Failed to initialize spki key` at exit 1, with
  nothing on standard output. The repository holds a signed `summary`, and a
  new ref that a regeneration adds to it. The SHA-256 of `summary` and of
  `summary.sig` is the same before and after the run. A `summary -u` with no
  key then writes a different `summary` and removes `summary.sig`.
- A public key of `sign --verify` and `static-delta verify` is the base64 of
  a SubjectPublicKeyInfo DER, also with the line breaks of a PEM body.
- `sign --verify` with a positional key in another form: the base64 of a raw
  SEC1 point, compressed or uncompressed, of the full PEM text, or of a
  PKCS#8 secret key. Beside a valid key, in either order, the tool verifies
  at exit 0 and writes no message for the other key. Alone, it reports
  `error: No valid signatures found` at exit 1.
- `static-delta verify --sign-type=spki` with a positional key of these forms.
  Before a valid key, the tool prints `Verification OK` at exit 0. Alone, or
  after a valid key, the tool prints `Verification fails` and reports
  `error: openssl: Failed to initialize spki key` at exit 1.

`cli-surface.md`, "P2", `commit`, `summary`, `static-delta`, `sign`, and
`remote`, records the port side.

#### spki secret key files

The `ostree` 2026.1 build with OpenSSL on the NixOS development host reads a
secret key file of the spki engine. Observed on 2026-10-25, with P-256 keys:

- `sign --keys-file` reads PEM `PRIVATE KEY` blocks, which hold PKCS#8 DER.
  The tool writes one signature for each block. A file of three blocks gives
  three signatures.
- `commit --sign-from-file` reads PEM `PRIVATE KEY` blocks and signs with the
  first block alone. A file of three blocks gives one signature, by the key of
  the first block. A second block that does not decode, or a second block of
  another label, does not stop the commit, which exits 0.
- Text outside the blocks is ignored. A body with a blank line between two
  base64 lines, and a body on one line of 184 characters, sign.
- A first block of the label `EC PRIVATE KEY`, `RSA PRIVATE KEY`, or `PUBLIC
  KEY` refuses the run with `error: Unexpected label "<label>"` at exit 1.
  `sign` writes no signature, and `commit` moves no ref. `sign` refuses a block
  of another label after a valid block in the same way. Observed on
  2026-10-26 with a 2048-bit RSA key: `sign --keys-file` with an `RSA PRIVATE
  KEY` block reports `error: Unexpected label "RSA PRIVATE KEY"` at exit 1.
- `sign` with a valid block, then a `PRIVATE KEY` block that does not decode,
  writes the signature of the first block, then reports `error: Not able to
  sign the cobject: openssl: Failed to initialize spki key` at exit 1. With
  the two blocks in the other order, both commands report this error at exit
  1, and write no signature and move no ref.
- An empty file, a file of white space only, and a file of one base64 PKCS#8
  line stop `sign` and `commit` with SIGABRT, exit 134. The tool writes
  `OSTree:ERROR:src/ostree/ot-main.c:324:ostree_run: assertion failed:
  (success || error)` on standard error. `commit` moves no ref.
- `sign -d --keys-file` with a `PRIVATE KEY` block exits 0 and writes one more
  signature, by the key of the block. With a `PUBLIC KEY` block it reports
  `error: Unexpected label "PUBLIC KEY"` at exit 1.
- `summary` has no `--keys-file` option. `summary -u --keys-file=<path>`
  reports `error: Unknown option --keys-file=<path>` at exit 1.
- `static-delta generate --keys-file` reads one base64 secret key on each
  line, and signs once with each line. Three lines give three signatures. LF
  and CRLF line ends both work, and the last line can have no line end. A
  line of the base64 of a SEC1 DER signs. Observed on 2026-10-26 with a
  2048-bit RSA key: a line of the base64 of a PKCS#1 `RSAPrivateKey` DER
  signs at exit 0, and `static-delta verify --sign-type=spki
  --keys-file=<path>` with the PEM `PUBLIC KEY` file of the key prints
  `Verification OK`.
  - A PEM `PRIVATE KEY` file, an empty line at any position, the first line
    included, a line of one space, and a line that is not base64 refuse the
    run with `error: openssl: Failed to initialize spki key` at exit 1. No
    superblock is written, the part file stays in `deltas/`, and
    `static-delta list` prints `(No static deltas)`.
  - A line of two base64 keys with a space between them signs with the first
    key alone. A line with a space before or after the key signs with the key.
  - An empty file gives exit 0. The superblock holds an `ostree.sign.spki`
    entry with no signature, and `static-delta show` prints `Signed: yes`.
  - With two `--keys-file` options, the tool signs with the keys of the last
    file alone. `--keys-file` and `--sign` add up, in either order.

`cli-surface.md`, "P2", `commit`, `summary`, `static-delta`, `sign`, and
`remote`, records the port side.

#### spki RSA keys

The `ostree` 2026.1 build with OpenSSL on the NixOS development host signs
and verifies with RSA keys of the spki engine. Observed on 2026-10-26, with
OpenSSL 3.6.4. `openssl genpkey -algorithm RSA` makes the keys. Each probe
signs the commit of a new `archive` repository with `sign -s spki
--keys-file=<path>` and a PEM `PRIVATE KEY` file, and verifies it with `sign
--verify -s spki --keys-file=<path>` and a PEM `PUBLIC KEY` file:

- A key of 512 bits and a key of 1024 bits sign and verify at exit 0.
- A key of 16386 bits signs at exit 0. The verify of the signature reports
  `error: spki: Signature couldn't be verified with: key '<hex>'` at exit 1.
  `openssl dgst -sha256 -verify` with the same key reports
  `rsa_ossl_public_decrypt:modulus too large` at exit 1. `genpkey` with
  `rsa_keygen_bits:16385` writes a key of 16384 bits.
- A 2048-bit key of 3 primes, a 4096-bit key of 4 primes, and an 8192-bit key
  of 5 primes sign and verify at exit 0.
- An `rsaEncryption` SubjectPublicKeyInfo with no parameters field verifies a
  signature of its key at exit 0. A SubjectPublicKeyInfo with an OID in the
  parameters field also verifies at exit 0. A SubjectPublicKeyInfo with no
  parameters field and the key of another 2048-bit key does not verify the
  signature, and the verify exits 1.

`cli-surface.md`, "P2", `sign`, records the port side.

#### spki P-384 keys

The `ostree` 2026.1 build with OpenSSL on the NixOS development host signs
and verifies with P-384 keys of the spki engine. Observed on 2026-10-26, with
OpenSSL 3.6.4. `openssl genpkey -algorithm EC -pkeyopt
ec_paramgen_curve:secp384r1 -pkeyopt ec_param_enc:named_curve` makes the
keys. Each probe signs the commit of a new `archive` repository, and a key of
another P-384 key verifies no signature of a probe, at exit 1:

- `sign -s spki COMMIT KEY`, where `KEY` is the base64 of a SEC1
  `ECPrivateKey` DER with the curve in its `parameters` field, signs at exit
  0. `sign --verify -s spki --keys-file=<path>` with the PEM `PUBLIC KEY`
  file of the key verifies the signature at exit 0.
- `static-delta generate --empty --to=COMMIT --sign-type=spki
  --keys-file=<path>`, where the file holds one line of the base64 of a
  PKCS#8 DER, or one line of the base64 of a SEC1 DER, signs at exit 0.
  `static-delta verify --sign-type=spki --keys-file=<path>` with the PEM
  `PUBLIC KEY` file of the key prints `Verification OK`.
- A PEM `PUBLIC KEY` file whose SubjectPublicKeyInfo holds the compressed
  point of the key, from `openssl pkey -pubout -ec_conv_form compressed`,
  verifies a signature of the key at exit 0.
- The digest is SHA-256. `openssl dgst -sha256 -verify` verifies the
  signature of the commit over the bytes of the commit object, and the
  signature of the delta over the signed superblock payload. `openssl dgst
  -sha384 -verify` reports `Verification failure` at exit 1.
- `sign -s spki COMMIT KEY`, where `KEY` is the base64 of the SEC1 DER of a
  P-256 key with secp521r1 in its `parameters` field, reports `error: Not
  able to sign the cobject: openssl: Failed to initialize spki key` at exit
  1.
- A secret key whose `privateKey` is shorter than the field size signs, on
  P-384 and on P-256. The probe key of P-384 holds the 32 low bytes of the
  scalar of a P-384 key in 32 bytes, and the probe key of P-256 holds the 24
  low bytes of the scalar of a P-256 key in 24 bytes. Each probe key has the
  curve in its `parameters` field and no `publicKey` field. A control key
  holds the same value with zero bytes on the left, in 48 and in 32 bytes.
  For each key, these runs sign at exit 0: `sign -s spki COMMIT KEY` with the
  base64 of the SEC1 DER and of the PKCS#8 DER, `sign -s spki
  --keys-file=<path>` with a PEM `PRIVATE KEY` file, and `static-delta
  generate --empty --to=COMMIT --sign-type=spki --keys-file=<path>` with one
  line of the base64 of the SEC1 DER or of the PKCS#8 DER. The PEM `PUBLIC
  KEY` file of the control key from `openssl pkey -pubout` verifies each
  signature at exit 0, and the key of another key verifies none at exit 1.
  So the tool reads a short scalar with zero bytes on the left. `openssl pkey
  -inform DER -noout -text` prints the short key with the zero bytes on the
  left.

`cli-surface.md`, "P2", `sign`, records the port side.

#### spki Ed25519 keys

The `ostree` 2026.1 build with OpenSSL on the NixOS development host signs
and verifies with Ed25519 keys of the spki engine. Observed on 2026-10-26,
with OpenSSL 3.6.4. `openssl genpkey -algorithm ED25519` makes the keys.
Each probe signs the commit of a new `archive` repository, and the PEM
`PUBLIC KEY` file of another Ed25519 key verifies no signature of a probe:

- `sign -s spki COMMIT KEY`, where `KEY` is the base64 of the PKCS#8 DER of
  the key, signs at exit 0. `sign -s spki --keys-file=<path>` with the PEM
  `PRIVATE KEY` file of the key, and `commit --sign-type=spki
  --sign-from-file=<path>` with the same file, sign at exit 0.
- The signature is 64 bytes. It is the pure Ed25519 signature of RFC 8032
  over the bytes of the commit object, with no prehash: `openssl pkeyutl
  -sign -rawin` over these bytes writes the same 64 bytes. Two runs with one
  key write the same `.commitmeta` bytes. The inline key and the key file
  write the same bytes.
- `sign --verify -s spki --keys-file=<path>` with the PEM `PUBLIC KEY` file
  of the key writes `spki: Signature verified successfully with key
  '302a300506032b6570032100<hex>'` at exit 0, where `<hex>` is the 32 bytes
  of the key. The file of another key writes `error: spki: Signature
  couldn't be verified with: key '<hex of its DER>'` at exit 1. The base64 of
  the SubjectPublicKeyInfo DER as a positional key verifies the signature.
- `static-delta generate --empty --to=COMMIT --sign-type=spki
  --keys-file=<path>`, where the file holds one line of the base64 of the
  PKCS#8 DER, signs at exit 0. `static-delta verify --sign-type=spki
  --keys-file=<path>` with the PEM `PUBLIC KEY` file of the key prints
  `Verification OK`. The file of another key prints `Verification fails` and
  an `error: spki: Signature couldn't be verified with:` line, at exit 1.
- `summary -u --sign-type=spki --sign=KEY` signs at exit 0. `summary.sig`
  holds the signature of `openssl pkeyutl -sign -rawin` over the `summary`
  file.

The verify of the tool gives these results. Each blob is the only spki
signature of the commit:

- A public key of small order: the identity point, the 32 bytes `01 00 ..
  00`. The blob of `R` = the identity point and `S` = 0 verifies at exit 0.
  `openssl pkeyutl -verify -rawin` verifies it too.
- The identity point in a non-canonical encoding, y = p + 1, the 32 bytes
  `ee ff .. ff 7f`. The same blob verifies at exit 0. The verify line names
  the key with these 32 bytes.
- The identity point with x = 0 and the sign bit set, the 32 bytes `01 00 ..
  00 80`. RFC 8032 refuses this encoding. The same blob verifies at exit 0,
  and the verify line names the key with these 32 bytes. `openssl pkeyutl
  -verify -rawin` verifies it too. With this key, the blob of `R` = these 32
  bytes and `S` = 0 gives `error: spki: Signature couldn't be verified
  with:` at exit 1.
- A signature that verifies only under the cofactored equation: `R' = [r]B +
  T`, where `T` is the point of order 2, and `S' = r + H(R' || A || M) a`,
  for the key of secret scalar `a`. The tool reports `error: spki: Signature
  couldn't be verified with:` at exit 1, and `openssl pkeyutl -verify
  -rawin` refuses it.
- A valid signature with `S + L` in place of `S`, where `L` is the order of
  the group, so `S` is not reduced. The tool reports the same error at exit
  1, and `openssl pkeyutl -verify -rawin` refuses it.

The tool reads these PKCS#8 forms of the secret key:

- A key of version 2, with the `version` 1, that holds the public key of the
  seed in its `[1]` field signs at exit 0, inline and from a PEM `PRIVATE
  KEY` file. The `.commitmeta` bytes are those of the version 1 form.
- A key of version 2 that holds the public key of another key signs with the
  seed at exit 0. The public key of the seed verifies the signature, and the
  other public key does not.
- A key with the `version` 1 and no public key signs at exit 0, and the
  public key of the seed verifies the signature.
- These keys refuse the run at exit 1 with `error: Not able to sign the
  cobject: openssl: Failed to initialize spki key`: a key with the `version`
  0 and a public key, a key with `NULL` parameters, a key whose `privateKey`
  holds the bare seed with no inner `OCTET STRING`, the bare DER `04 20` and
  the seed, and the 64 bytes of the seed and the public key, the form of the
  ed25519 engine.
- A PEM `PUBLIC KEY` file whose SubjectPublicKeyInfo has `NULL` parameters
  refuses the verify at exit 1 with `error: openssl: Failed to initialize
  spki key`.

`cli-surface.md`, "P2", `sign`, records the port side.

#### `apply-offline`

`apply-offline PATH [KEY-ID...]` applies one delta into the repository. The
tool reads PATH as a path in all forms, and it reads a delta name as a path:

- A directory, with symlinks followed, holds `superblock` and the part files
  `0`, `1`, and more.
- Each other file is a superblock under any name. The tool reads the part
  files from the directory that holds it. For a bare name, that directory is
  the working directory.

The tool folds PATH as text before it opens it:

- The fold removes empty components, `.` components, and a trailing `/`.
- Each `..` removes the component before it, also where that component is a
  symlink or a file.
- A `..` at the start of a relative path stays.
- The fold removes a `..` directly after the root of an absolute path.
- A PATH that folds to nothing names the working directory.

So `<link>/../<dir>` names `<dir>` in the directory that holds the link.
`<dir>/superblock/..` and `<dir>/superblock/.` name `<dir>`.
`<dir>/superblock/` names the superblock file, and `/..` names `/`. The
directory of the part files comes from the folded PATH.

The tool reads a part that the superblock carries inline from the superblock
in both PATH forms (`../format-reference.md`, "Inline parts"). The options are
the options of `verify`, under the same last-value rule.

On success, both streams are empty and the exit status is 0. The objects of the
target commit are in the repository, and no ref is written. The checks run in
this order, and each refusal writes no object and no ref:

1. No PATH reports `error: PATH must be specified`. The tool opens the
   repository before this check.
2. The sign type, also with no key source. `ed25519` is the default, and
   `ed25519` with no key source checks nothing. `gpg`, the empty name, and each
   name that no engine of the build carries report `error: Requested signature
   type is not implemented`. Nothing goes to standard output. The tool writes a
   GLib warning block on standard error before that line. `cli-surface.md`,
   "P2", `static-delta`, records the port side for the warning, for `spki`,
   and for `dummy`.
3. The keys load where a key source is given. A key source is a positional
   KEY-ID, a `--keys-file`, or a `--keys-dir`. The keys load under
   `static-delta`, "Key sources". The tool refuses here with the text of each
   refusal of step 3 of `verify`, also for an unsigned delta. With no key
   source, the tool reads no key file and no system key directory.
4. The path resolves. A path that is absent reports `error:
   openat(O_DIRECTORY): <reason>`. A directory with no `superblock` reports
   `error: openat(superblock): <reason>`.
5. The superblock reads and parses. A superblock file that does not open
   reports `error: openat(<name>): <reason>`. `<name>` is the last component of
   the folded PATH.
6. With a key source, the tool checks the signatures of a signed superblock
   before it writes an object. A failure reports one of these lines of step 5 of
   `verify`, with no `Verification fails` line:
   - `error: no signature for 'ostree.sign.<type>' in static-delta superblock`
   - `error: <type>: Signature couldn't be verified with: key '<hex>'`
   - `error: <type>: no signatures found`

   An unsigned superblock applies with no check. So under a key source,
   `apply-offline` authenticates a signed delta only.
7. The delta applies. The tool reads the superblock one time, so the bytes
   that verify are the bytes that apply. The tool refuses a part file that
   does not open.

#### `generate`

`generate` writes the delta from FROM to TO. It takes these options:

- `--from=REV` -- the source commit.
- `--empty` -- a from-scratch delta.
- `--to=REV` -- the target commit. It has precedence over the positional `TO`.
  The tool ignores a second positional argument (`cli-surface.md`, "P2",
  `static-delta generate`).
- `-n`, `--if-not-exists` -- generate only where the delta is absent.
- `--filename=PATH` -- the superblock file.
- `--min-fallback-size=MB`, `--max-bsdiff-size=MB`, `--max-chunk-size=MB` --
  the three size thresholds, default 4, 64, and 32.
- `--disable-bsdiff`, `--sign=KEY`, `--sign-type=NAME`, and
  `--keys-file=PATH`.
- `--inline` -- the parts go into the superblock, and the tool writes no part
  file (`../format-reference.md`, "Inline parts").
- `--set-endianness=l|B` and `--swap-endianness` -- the `ostree.endianness`
  byte and the order of the four size fields.

With neither `--from` nor `--empty`, FROM is the parent of TO. A revision takes
the forms that `rev-parse` takes: a ref, a checksum or its abbreviation, and a
trailing `^`.

The checks run in this order:

1. No TO reports `error: TO revision must be specified`, also with `--empty`
   and `--from`.
2. `--empty` with `--from` reports `error: Cannot specify both --empty and
   --from=REV`. No revision resolves before this check.
3. The revisions resolve. An absent ref reports `error: Refspec '<rev>' not
   found`.
4. A TO with no parent, where FROM is the default, reports `error: Commit
   <hex> has no parent`.
5. The `-n` check.
6. An endianness value other than `l` or `B` reports `error: Invalid
   endianness '<value>'`, and the tool writes nothing.
7. Standard output receives the block that follows this list.
8. The tool generates the delta. Each later failure comes after the block, so a
   run that fails there prints the block too.

```
Generating static delta:
  From: <hex>|empty
  To:   <hex>
```

`-n` reads `deltas/<fanout>/<rest>/superblock` of the repository for the delta,
with symlinks followed, whatever location the run writes to. Where the file
exists, standard output holds `Delta <name> already exists.`, with `<name>` in
the form that `list` prints. The run then exits 0 and writes nothing. A delta
directory that holds parts and no superblock counts as absent. Without `-n`, the
tool writes the delta again over the delta that is present. The tool keeps the
part files of the earlier delta that the new superblock does not name
(`cli-surface.md`, "P2", `static-delta generate`).

The tool writes statistics to standard error on each run that reaches step 8:

```
modified: 0
new reachable: metadata=2 content regular=1 symlink=0
rollsum for 0/0 modified
part 1 n:2 compressed:169 uncompressed:83
uncompressed=83 compressed=169 loose=119
rollsum=0 objects, 0 bytes
bsdiff=0 objects
```

`cli-surface.md`, "P2", `static-delta generate`, records the port side of
standard error.

#### Byte order of a generated delta

The byte order starts from the byte order of the host. `--set-endianness`
replaces it. The tool takes the last value of a repeated `--set-endianness`.
The value also takes the separate-argument form `--set-endianness B`.
`--swap-endianness` then swaps the order one time, at any position on the
command line and for any count of occurrences. On a little-endian host,
`--swap-endianness` alone writes `B`, and `--swap-endianness
--set-endianness=B` writes `l`.

The tool compares the value as given, so it refuses `b`, `L`, `little`, `big`,
`Bx`, and the empty value. It checks the value after `-n` and after the
default parent. So `-n` over a delta that exists exits 0 whatever the value.
The tool checks the value before it opens the `--filename` directory.

Not observed: a run on a big-endian host.

#### Size options

The three size options are decimal megabytes, with the factor 1,000,000. The
tool reads a value leniently. `abc` reads as 0. The tool accepts `1.5`, `-1`,
` 3`, `+3`, `3x`, and values past the largest byte count. The tool takes
`--max-chunk-size=0` as one object for each part. `cli-surface.md`, "P2",
`static-delta generate`, records the port side.

#### `--filename`

`--filename=PATH` writes the superblock to PATH and the part files to the
directory that holds PATH. Where PATH holds no `/`, that directory is the
working directory. The tool does not create the directory.

The tool takes the directory and the name from the text of PATH. It opens the
directory before it writes a part. The tool refuses these PATH forms:

- An absent parent reports `error: opendir(<dir>): No such file or
  directory`.
- For `X/.`, the tool opens `X`. Where `X` is absent or is not a directory, the
  tool reports `error: opendir(X): <reason>` and writes nothing.
- Three PATH forms fail at the final rename, after part `0` is written. They
  are a directory, a PATH that ends in `/`, and a PATH whose last component is
  `.` or `..` after a directory. The line is `error: renameat(<temp>,
  <name>): <reason>`, with `Is a directory` or `Device or resource busy` as
  the reason.
- An empty PATH reports `error: Invalid 'filename' parameter` after the block.

The tool accepts a PATH whose name is a part file name, `0` for example. The
superblock then replaces that part, and `show` and `apply-offline` refuse the
delta. The tool accepts a name that is not UTF-8. `cli-surface.md`, "P2",
`static-delta generate`, records the port side of each PATH form of this
section.

Only the final rename replaces a file that is already at PATH. So a run that
fails leaves that file as it was.

#### Signing keys of `generate`

The tool writes the parts, then reads the signing keys, then writes the
superblock. So an invalid key leaves the parts and writes no superblock:

- At a location that holds no delta, `list` does not show the delta.
- At a location that holds a delta, the tool keeps the earlier superblock
  beside the parts that it wrote again, and `list` shows it.

An ed25519 key of the wrong length reports the secret-key length error of
`commit`, "Signing". `cli-surface.md`, "P2", `static-delta generate`, records
the key order of the port and its `--sign-type=gpg` case.

The port signs with each `--sign` value. It decodes each key with the lenient
base64 reader of `commit`, "Signing" (`cli-surface.md`, "P2", `static-delta
generate`).

#### `reindex`

`reindex` with no option runs the full pass that `../format-reference.md`,
"Static delta index files", states. `reindex --to=REV` rewrites the index file
of REV alone, by the rule of `static-delta`, "Delta selection". A delta
directory that holds no `superblock` does not count. With no delta into REV, the
tool removes the index file of REV. The fanout directory that the removal
empties stays.

The index files of other targets stay as they are. This includes stale index
files, also one whose deltas are all gone. A target with no delta and no index
file changes nothing. A repository with no `deltas/` gets no `delta-indexes/`.
The file that `--to` writes is byte-identical to the file of REV that the full
pass writes. `../format-reference.md`, "Static delta directories", states its
mode.

On success, both streams are empty and the exit status is 0. The tool opens the
repository first. An absent `--repo` path reports the error of the repository
open. No repository reports the usage text and `Command requires a --repo
argument`.

The tool reads REV by the rule of one half of a delta name, `static-delta`,
"The arguments". A refusal goes to standard error alone, at exit 1:

- `--to=main` reports `error: Invalid rev main`, and `--to=^main` reports
  `error: Invalid rev ^main`. The tool does not resolve a ref name.
- The tool does not split REV at a `-`. So `--to=C1-C2` reports the first 64
  bytes, `error: Invalid rev <C1>`.

The tool does not check REV for a commit object. So the 64 zeros of a target
that the repository does not hold exit 0 and change nothing. The tool takes
the last value of a repeated `--to`:

- `--to=C2 --to=C3` touches the index file of C3 alone.
- `--to=bad --to=C2` exits 0.
- `--to=C2 --to=bad` reports `error: Invalid rev bad`.

The tool refuses a `--to` with no value at exit 1, with `error: Missing
argument for --to`. `cli-surface.md`, "P2", `static-delta`, records the port
side.

The tool takes a positional argument after `reindex`, ignores it, and runs the
pass that the options select. `cli-surface.md`, "P2", `static-delta`, records
the port refusal.

The tool refuses a directory at the index path at exit 1 and leaves no temp
file. The tool reports one of two lines:

- For a target with deltas, `error:
  renameat(delta-indexes/<fanout>/tmp.<suffix>, delta-indexes/<fanout>/<rest>.index):
  Is a directory`.
- For a target with no delta, `error:
  unlink(delta-indexes/<fanout>/<rest>.index): Is a directory`.

For a target with no delta, the tool also refuses a path to the index file
through a component that is not a directory. This applies to a regular file at
the fanout, a symlink at the fanout to a regular file, and a regular file at
`delta-indexes`. The tool reports `error:
unlink(delta-indexes/<fanout>/<rest>.index): Not a directory` at exit 1. A
dangling symlink at the fanout is an absent file, and the run exits 0.
`cli-surface.md`, "P2", `static-delta`, records the port side of these refusals.

#### Exit status

- 0 -- the subcommand completed. For `verify`, this is `Verification OK`. For
  `generate`, it includes a delta that `-n` found.
- 1 -- a refusal or a failure that the section of the subcommand states, or
  that `static-delta`, "The arguments", states.

No `DELTA` reports `error: DELTA must be specified` at exit 1, with no usage
text.

Over a superblock that does not parse, the tool prints the lines that it read
before the failure. `cli-surface.md`, "P2", `static-delta`, records the port
side.

### `pull`

#### The low-speed options

The tool reads `--low-speed-limit-bytes=N` and `--low-speed-time-seconds=N` as a
C `int`, with the reader of `commit --owner-uid`. The tool refuses a value that
this reader cannot hold at exit 1. It refuses the value while it reads the
options, ahead of the repository and ahead of the remote. The messages are
those of `--owner-uid`:

- a syntax that the reader cannot hold (`abc`, an empty value, a trailing
  space): `error: Cannot parse integer value “<value>” for
  --low-speed-limit-bytes`
- a value more than `2147483647` or less than `-2147483648`: `error: Integer
  value “<value>” for --low-speed-time-seconds out of range`

A value of 0 in either option turns off the low-speed rule. A negative value
keeps the default of its option: 1000 bytes per second for the limit, and 30
seconds for the time. These cases show the negative values, with a server that
sends one object at about 100 bytes per second:

- `--low-speed-limit-bytes=-1 --low-speed-time-seconds=1` fails after one
  second, as a limit of 1000 does. The same options at about 2000 bytes per
  second complete.
- `--low-speed-limit-bytes=1000 --low-speed-time-seconds=-1` fails after 30
  seconds, as the default time does.
- `-2147483648` and `-5` read as `-1` does.

The tool samples the rate of a transfer once a second. A sample is the bytes of
the last five seconds divided by five. In the first five seconds, a sample is
the bytes so far divided by the time so far.

The transfer fails when each sample is less than the limit for the time, with no
break. One sample more than the limit starts the count again. The count starts
at the start of the request. Before the response head arrives, the tool counts
no byte, so the rate is less than any limit.

In the cases that follow, the limit is 1000 bytes per second. The server sends
the response head at once, unless the case states a delay. Then it sends one
object on a schedule. Each time is a time at the server, from the head to the
moment when the tool closes the connection.

- With no byte after the head, the transfer fails after 1.0, 2.0, and 3.0
  seconds at a time of 1, 2, and 3 seconds.
- At a time of 2 seconds, a head sent after 1.5 seconds with no byte after it
  fails 0.5 seconds after the head. A head sent after 1.5 seconds and followed
  by the whole object completes. A head sent after 3 seconds fails after 2
  seconds, before the server sends it.
- One burst in the first half second with no byte after it, at a time of 2
  seconds, fails after these times:
  - 2 seconds for 1000 bytes
  - 5 seconds for 3000 bytes
  - 6 seconds for 3500 bytes
  - 7 seconds for 5000 bytes
  - 8 seconds for 8000, 20000, and 60000 bytes

  With 8000 bytes or more, the rate stays more than the limit until the burst
  leaves the five seconds of the sample.
- 6000 bytes after 0.5 seconds and 6000 more after 6.5 or 7.5 seconds complete
  at a time of 2 seconds. The second burst lifts a sample to more than the limit
  within 2 seconds of the first sample less than the limit. The same second
  burst after 8.5 seconds is too late, and the transfer fails after 8 seconds.
- 2100 bytes every 2 seconds completes at a time of 1 second. 2000 bytes every
  1.9 seconds also completes. These transfers complete, although a whole second
  between two bursts carries no byte.

A sample of exactly the limit counts as less than the limit. 1000 bytes in the
first second, 3000 in three seconds, and 5000 in five seconds each count as less
than the limit. The span of each sample is slightly more than its whole number
of seconds.

The tool reports a transfer that the low-speed rule fails with `error: While
fetching <url>: [28] Timeout was reached`. The pull exits 1 and writes no ref.
`cli-surface.md`, "P2", `pull`, records the port side.

#### `--update-frequency`

The tool reads `--update-frequency=FREQUENCY` with the same reader, at the same
step, and with the same two messages, with `--update-frequency` as the option
name. The value sets the redraw interval of the terminal progress line in
milliseconds. 0 and a negative value keep the default of 1000 ms. To a pipe, the
value changes no byte of the output. The tool reads the values in this way:

- refused as a syntax: `abc`, an empty value, and `1.5`
- refused as out of range: `99999999999`, `2147483648`, and `-2147483649`
- accepted: `-1`, `0x10`, `010`, ` 5`, `+5`, and `2147483647`

#### The statistics line

A pull of the tool that succeeds prints one statistics line on standard output.
To a pipe, this line is the whole output, and the tool writes nothing to
standard error. A pull that fails prints no statistics line. The line has one of
four forms:

- `M metadata, C content objects fetched; T transferred in S seconds; W content
  written`, for an HTTP pull that fetched no delta part as a file.
- `P delta parts, L loose fetched; T transferred in S seconds; W content
  written`, for an HTTP pull that fetched at least one delta part as a file. `L`
  is `M` plus `C`.
- Either of these two forms with `; T transferred in S seconds` left out. The
  tool prints this form for an HTTP pull that read no body byte after the
  summary, the config, and the ref files.
- `M metadata, C content objects imported; W content written`, for `pull-local`,
  and for a `file://` remote. `cli-surface.md`, "P2", `pull`, records the port
  side. `pull-local --require-static-deltas` prints the forms of an HTTP pull,
  with the counting rules that this section states for it.

The words `delta parts` and `content objects` stay plural for a count of 1. The
figures are these:

- `M` counts each loose metadata object and each `.commitmeta` that the remote
  served. It also counts each delta index request and each delta superblock
  request, whatever the remote answered. A `.commitmeta` request that answered
  404 does not count.
- `C` counts each content object fetched loose from the remote.
- `P` counts each delta part fetched as a file. A part that the superblock
  carries inline does not count. So a delta with only inline parts takes the
  first form, and `M` counts the index and the superblock.
- `T` is the bytes of the response bodies that the pull read after the summary,
  the config, and the ref files. The `summary.sig`, `summary`, and `config`
  requests do not count. From a remote with no summary, the `refs/heads`
  request of each ref does not count either. The tool also counts the body of
  an error answer (`cli-surface.md`, "P2", `pull`).
- For less than 1024 bytes, `T` is `N B`. For more, `T` is the whole KiB
  rounded down, `N KiB`. For example, 3842 bytes print as `3 KiB`.
- `S` is the whole seconds of the pull, rounded down.
- `W` is the total payload size of the regular-file content objects written,
  before any compression of the destination mode. A symlink, an object shared
  by hardlink, and an object that a static delta produced count nothing. An
  object that `pull-local` copies between two `archive` repositories counts
  nothing. An object that an HTTP pull fetches into `archive` counts its
  payload. `W` takes the size wording of `prune` (`prune`, "The size
  wording"), for example `3.0 kB`.

One pull can reach the same objects by a loose walk and by a delta part. Then
`L` and `W` change from run to run in the tool (`cli-surface.md`, "P2",
`pull`).

The tool prints these lines with standard output a pipe. The first two cases
pull a tree of a 3000-byte file, a 6-byte file, a 1-byte file, and a symlink.

- A loose pull into `archive`: `4 metadata, 4 content objects fetched; 3 KiB
  transferred in 0 seconds; 3.0 kB content written`.
- The same loose pull into `bare-user`: `5 metadata`, because the pull adds the
  delta index request.
- A tree of one 1-byte file: `1 byte content written`.
- A from-scratch delta of one part into `bare-user`: `1 delta parts, 2 loose
  fetched; 6 KiB transferred in 0 seconds; 0 bytes content written`.
- The same delta generated with `--inline`: `2 metadata, 0 content objects
  fetched`.
- A repeat pull into `archive` whose requests all answer 404 with an empty
  body: `0 metadata, 0 content objects fetched; 0 bytes content written`.
- A repeat pull into `bare-user`: `1 metadata`, because the tool requests the
  delta index again (`cli-surface.md`, "P2", `pull`).
- From a remote with no summary, a loose pull of one ref into `archive`, whose
  five objects total 233 bytes: `4 metadata, 1 content objects fetched; 233 B
  transferred`. So the 65-byte `refs/heads` body does not count.

`pull-local --require-static-deltas` counts each file that it reads from the
source directory as the response body of that file:

- `M` counts the delta index read and the superblock read of each delta taken,
  whether the file is there or not. It also counts each loose metadata object
  and each `.commitmeta` read from the source.
- `C` counts each content object read loose.
- `T` adds the sizes of those files as the source stores them, and the size of
  each part file. `T` leaves out the summary.

From an `archive` source, `pull-local --require-static-deltas` of the tool
prints these lines:

- A from-scratch delta of one part, into `bare-user`: `1 delta parts, 2 loose
  fetched; 294 KiB transferred in 0 seconds; 0 bytes content written`. The 294
  KiB are the index, the superblock, and the part.
- A delta with a fallback object and a `.commitmeta`: `4 loose fetched`. `W`
  counts the payload of the fallback.
- The same delta generated with `--inline`: `3 metadata, 0 content objects
  fetched`.
- A commit-only pull: `1 metadata, 0 content objects fetched; 150 B
  transferred`. The 150 bytes are the commit object.
- A repeat pull of a commit that the destination holds: `1 metadata`, because
  the tool reads the index again (`cli-surface.md`, "P2", `pull-local`).

`pull-local` of the tool prints these written figures:

- from `archive`: `0 bytes content written` into `archive`, and `3.0 kB content
  written` into `bare-user`.
- from `bare-user`: `0 bytes content written` into `bare-user`, and `3.0 kB
  content written` into `bare` and into `archive`.

#### The pull progress line

Standard output that is a terminal also carries a progress line. The tool
writes these bytes:

1. `ESC 7` when the pull starts.
2. Each redraw as `ESC 8` and the progress text, padded with spaces to the
   terminal width.
3. Last, `ESC 8`, the statistics line padded in the same way, and a newline.

The tool counts the width in bytes, so each U+00A0 in the line takes two of the
columns. The tool writes a line longer than the width whole. A pull that fails
writes a newline after the last line, and the error follows on standard error.
The rate reads `-/s` until the tool has its first rate.

The progress text has three forms:

- `Receiving metadata objects: 5/(estimating) 237 bytes/s 948 bytes`
- `Receiving objects: 38% (59/155) 454.8 kB/s 1.4 MB`
- `Receiving delta parts: 0/1 0 bytes/3.4 MB 356.2 kB/s 9 seconds remaining`

These rules hold at terminal widths of 60, 80, and 100 columns. At 100
columns, the progress line and the statistics line each take 100 bytes. A pull
that ends before the first redraw writes `ESC 7`, `ESC 8`, and the statistics
line. At a redraw interval of 1 or 50 ms, the tool also writes a
`Writing objects: N` form. At these intervals the tool can end on a progress
line with no statistics line after it.

The progress line is outside the byte-exact scope. `cli-surface.md`, "P2",
`pull`, records the port side.
