# OSTree On-Disk Format Reference

This document specifies the on-disk repository format that the Rust port
reproduces byte for byte. Each field width, byte order, and sort order is a
compatibility requirement, because the object checksum covers the serialized
bytes. The part "Port extensions" specifies the formats and the protocols that
only the port writes.

The facts come from the public ostree documentation
(https://ostreedev.github.io/ostree/) and from the objects and output of the
`ostree` tool. No fact derives from the LGPL source (see CLAUDE.md,
"Licensing and clean-room discipline"). The GVariant serialization is the
format that GLib documents. `conformance/cli-behavior.md` records the CLI
behavior of the tool. `conformance/cli-surface.md` records each difference
between the tool and the port.

Three labels give the source of a statement:

- Observed behavior: `ostree` 2026.1, run as a black box. A run of the tool
  and a check of the bytes that it writes can verify the fact.
- Not observed: no run of the tool records the fact. The text states the
  port alone.
- Design target: the fact comes from the documentation and the standards. No
  run of the tool confirms it.

## Foundational constants

- SHA-256 digest: 32 raw bytes, 64 lowercase hex characters (`[0-9a-f]`).
- Metadata size cap: 128 MiB (limit on fetched or loaded metadata).
- File mtime: the content model holds no timestamp. No file header and no
  dirmeta holds an mtime. The port sets no mtime on a stored object or on a
  checkout file. A composefs image gives each inode mtime 0 ("composefs"). A
  tar export gives each member the commit timestamp, except a hardlink member,
  which gets mtime 0 ("tar"). Not observed: the mtime that the tool gives a
  stored object, a checkout file, and a tar hardlink member.

## GVariant serialization rule (applies to every metadata object)

The writer stores each metadata object as normal-form GVariant. It converts
each big-endian field at the value level, so the stored bytes have no
whole-variant byte swap. The raw text reports (`summary --raw`, `show` without
`-B`, `log --raw`) byte-swap the whole loaded variant for display
(`conformance/cli-behavior.md`, "CLI output formats", "The GVariant text form",
"Byte order").

- Container framing (element offsets and framing bytes) is little-endian. Each
  scalar that the next item does not name is also little-endian. This is the
  GVariant normal form on a little-endian host, and the port writes it on
  every host.
- These scalar integer fields are big-endian: uid, gid, mode, rdev, the
  timestamps, and the uncompressed size `t` of the archive header. The writer
  converts each one to big-endian before it puts the value in the variant, and
  the reader converts it back.
- Other size fields have their own rules. The per-ref commit size in the
  summary is little-endian (host order). The `ostree.sizes` values are LEB128
  varints. The size fields of a static-delta superblock follow its
  `ostree.endianness` byte ("Static delta wire format").

The object structs of the port hold host-order values. Each serialize site and
each parse site converts the big-endian fields, and the encoder then writes
standard normal-form GVariant. The checksum covers these bytes, so the output
must be byte-identical normal form.

## Object types

The numeric value of an object type is wire-significant. One byte holds the
type in an `ostree.sizes` entry, in each object entry of a static-delta
superblock meta-entry, and in a superblock fallback entry.

- 1 `FILE` -- `.file` / `.filez` -- content: header plus payload.
- 2 `DIR_TREE` -- `.dirtree` -- sorted lists of child files and subdirs.
- 3 `DIR_META` -- `.dirmeta` -- directory uid/gid/mode/xattrs.
- 4 `COMMIT` -- `.commit` -- metadata plus root tree/meta references.
- 5 `TOMBSTONE_COMMIT` -- `.tombstone-commit` -- marks a deleted commit.
- 6 `COMMIT_META` -- `.commitmeta` -- detached, mutable commit metadata.
- 7 `PAYLOAD_LINK` -- `.payload-link` -- symlink to a `.file`, keyed by
  payload-only checksum (reflink dedup).
- 8 `FILE_XATTRS` -- `.file-xattrs` -- detached xattrs blob (bare-split-xattrs).
- 9 `FILE_XATTRS_LINK` -- `.file-xattrs-link` -- hardlink to a `.file-xattrs`,
  keyed by the `.file` checksum.

The is-meta predicate is `t` in 2..=6, and the checksum rules use it ("Checksum
computation"). Types 7, 8, and 9 are auxiliary types outside the metadata set.
The port also has the type 100, `.cfs`, the composefs image of a commit. The
tool does not know it. "The composefs image object" in "Port extensions"
states it.
The string form of an object name is `<hexchecksum>.<typestr>`. "Repository
modes and on-disk storage" states which objects take the `z` suffix.

A `.tombstone-commit` object marks a commit that a prune removed. It holds an
`a{sv}` with one entry. The key is `commit`. The value is a variant of type
`ay` that holds the commit checksum in 64 lowercase hex characters and one
NUL. The object is 78 bytes for every commit. Its permission bits are `0644`,
as for every metadata object. The marker for commit
`5a7db91c4984baa542cb29238cd86a54497303c82cbed2f0af3c44606c0d482f`:

```
00000000: 636f 6d6d 6974 0000 3561 3764 6239 3163  commit..5a7db91c
00000010: 3439 3834 6261 6135 3432 6362 3239 3233  4984baa542cb2923
00000020: 3863 6438 3661 3534 3439 3733 3033 6338  8cd86a54497303c8
00000030: 3263 6265 6432 6630 6166 3363 3434 3630  2cbed2f0af3c4460
00000040: 3663 3064 3438 3266 0000 6179 074d       6c0d482f..ay.M
```

The `0x07` offset byte at 76 states that the key of the dict entry ends at
offset 7. The separator NUL of the variant is at 73, and the type string `ay`
is at 74. The `0x4d` offset byte at 77 states that the one element of the
array ends at offset 77.

A prune writes the marker for every commit that it removes when the command line
has `--delete-commit` or the config sets `[core] tombstone-commits`. A prune
never removes a marker. `conformance/cli-behavior.md`, "CLI output formats",
`prune`, states what the counts of a prune cover. `fsck --add-tombstones` writes
the same bytes (`conformance/cli-behavior.md`, "CLI output formats", `fsck`).
Observed behavior: `fsck` reports no error over a repository that holds markers,
and `log` does not read them.

## Metadata object formats (GVariant type strings, verbatim)

### Commit -- `(a{sv}aya(say)sstayay)`

0. `a{sv}` metadata dict.
1. `ay` parent commit checksum: 32 raw bytes, empty array for a root commit.
2. `a(say)` related objects. The port uses this field for the dependencies
   of a commit. Each entry is a name and the 32 raw bytes of the checksum of
   a commit. The name is not empty. By convention, it has the form
   `<class>/<name>`, for example `container/fe` or `boot/uki`. The `ostree`
   command writes an empty array. The port writes the entries sorted by name
   in byte order, with no name two times, so one set of entries gives one
   commit checksum. A dependency names no dependency of its own. The commit
   write of the port refuses a dependency whose field 2 is not empty, and a
   dependency that the repository or the writing transaction does not hold
   complete. A dependency can have a parent.
3. `s` subject (empty string if none).
4. `s` body (empty string if none).
5. `t` timestamp, seconds since Unix epoch UTC, big-endian.
6. `ay` root dirtree checksum, 32 raw bytes.
7. `ay` root dirmeta checksum, 32 raw bytes.

The metadata dict is an array of key-value tuples. It holds the entries in the
order that its writer produced, and this order is part of the commit checksum.
The port serializes the dict in insertion order. A caller that reproduces a
tool commit gives the keys in the order of the tool
(`conformance/cli-behavior.md`, "CLI output formats", `commit`, "The commit
metadata"). A reader finds
a key by name, in any slot. A name can occur twice, and a lookup by that name
finds the first entry.

These metadata keys are well known:

- `version` (`s`), the only key without the `ostree.` prefix.
- `ostree.architecture` (`s`).
- `ostree.ref-binding` (`as`) and `ostree.collection-binding` (`s`).
- `ostree.endoflife` and `ostree.endoflife-rebase` (`s`).
- `ostree.source-title` (`s`).
- `ostree.linux` (`s`) and `ostree.bootable` (`b`).
- `ostree.composefs.digest.v0` (`ay`, see "composefs").
- `ostree.sizes` (`aay`).

The commit write of the port adds neither binding key. The caller supplies
them as normal metadata entries. For example, `commit -b` writes
`ostree.ref-binding`.

`ostree.linux` and `ostree.bootable` mark a commit that holds a kernel.
`ostree.linux` holds the name of the directory under `/usr/lib/modules` that
holds the kernel, and `ostree.bootable` holds true. `commit --bootable` writes
the two together (`conformance/cli-behavior.md`, "CLI output formats",
`commit`).

#### The `ostree.sizes` key

The value type is `aay`. Each entry is a packed byte buffer:

```
[32 bytes checksum][varuint64 compressed size][varuint64 unpacked size][1 byte objtype]
```

The entries are sorted by the raw 32-byte checksum, read as a byte string. The
hex form gives the same order. Each varuint64 is protobuf-style LEB128
(little-endian base-128, the high bit is the continuation flag). The encoding
is canonical: each value has one minimal form. A reader refuses a multi-byte
form whose last byte is `0x00`, which adds no value bits, so unpack-then-pack
of an entry is byte-identical. Some commits hold entries without the objtype
byte. A reader accepts such an entry.

Over a single tree source, the key holds an entry for each object that the
commit reaches. These are the content objects, the dirtree objects, and the
dirmeta objects. The trailing byte of each entry holds the type of its object
(`File`=1, `DirTree`=2, `DirMeta`=3). The commit object has no entry, because
it does not exist when the key is computed. The writer appends the key after
every other entry of the dict. `conformance/cli-behavior.md`, "CLI output
formats", `commit`, states which objects the key holds over a source list, and
the order of the keys in the dict.

Each entry holds two sizes:

- The compressed size is the size of the file of the object under `objects/`.
  For a content object, this is the `.filez` size.
- The uncompressed size (the second varuint64) is the logical `st_size`. This
  is the payload length of a regular file and the target length of a symlink.

For a metadata object, each size is its serialized length. The two sizes are
equal, because a metadata object is stored uncompressed ("Repository modes and
on-disk storage"). The compressed size of a content object can be larger than
its uncompressed size.

This is a decoded key from `commit --generate-sizes` over a tree of four
directories, one symlink, and three regular files. The last column gives the
length of each entry in bytes. The 20000-byte file of random bytes stores 20044
bytes:

```
checksum (first 8 bytes)   compressed  unpacked  type          length
0cad59c0775ee80f...        80          80        2 dirtree     35
1b6ba70951395486...        12          12        3 dirmeta     35
1c16bd4554d0fb08...        41          51        1 file        35
6e340b9c...                1           1         2 dirtree     35
6e4aa995...                145         145       2 dirtree     37
8c7b8dd4...                36          2         1 file        35
8d81d4ff...                148         148       2 dirtree     37
abadce0d...                48          12        1 file        35
fe657422...                20044       20000     1 file        39
```

The bytes of the first entry:

```
0c ad 59 c0 77 5e e8 0f 24 1e c8 58 2d 9c 1e 64
6b 4f b5 59 8c 1a 6e 7a 9e 09 7a 61 20 d4 41 b5   32 checksum bytes
50                                                compressed = 80
50                                                unpacked   = 80
02                                                dirtree
```

Only an archive-mode repository writes `ostree.sizes`. The compressed size is
the `.filez` size, so the key is the only commit-metadata field that depends on
the storage. Observed behavior: in a bare or bare-user repository,
`commit --generate-sizes` writes no key and no warning. The commit checksum is
then the same as without the option. In an archive repository the option adds
the key and changes the commit checksum. A commit thus has one checksum in all
modes only when the archive side has size generation off.

The compressed size records the output of the writer's DEFLATE encoder. Two
writers agree on the key only where their compressed payloads have equal
lengths (`conformance/cli-surface.md`, "P2", `commit`).

### Dirtree -- `(a(say)a(sayay))`

0. `a(say)` files: (filename `s`, content checksum `ay`=32 bytes), sorted by
   filename with byte-wise comparison.
1. `a(sayay)` dirs: (dirname `s`, dirtree checksum `ay`=32, dirmeta checksum
   `ay`=32), sorted by dirname with byte-wise comparison.

The sort order is mandatory for reproducible checksums. Each list is strictly
sorted, so a name occurs at most once in one list. The two lists are
independent, so the format lets one name occur in both lists. The port
refuses these dirtrees:

- A list that is not strictly sorted.
- A name that is empty, `.`, or `..`, that holds `/`, or that is not valid
  UTF-8. This is the path-traversal defense.
- A name in both lists. The write path and the owned parse refuse it. The
  borrowed read iterators read each list alone.

`conformance/cli-surface.md`, "P1", records how the tool reads a name in both
lists.

### Dirmeta -- `(uuua(ayay))`

0. `u` uid (big-endian).
1. `u` gid (big-endian).
2. `u` mode, full `st_mode` including `S_IFDIR` (big-endian).
3. `a(ayay)` xattrs, sorted by name.

A dirmeta has no rdev field and no symlink field.

### File content object header

A content object (`.file` or `.filez`) is a header GVariant and a payload.

Uncompressed stream header `(uuuusa(ayay))`, for bare-mode streams and for the
checksum: 0. `u` uid (BE), 1. `u` gid (BE), 2. `u` mode (BE), 3. `u` rdev (must
be 0), 4. `s` symlink target (empty for an object that is not a symlink), 5.
`a(ayay)` xattrs (sorted).

Compressed archive header `(tuuuusa(ayay))`, stored on disk in archive mode.
Its field 0 is `t`, the uncompressed size (BE). Fields 1 to 6 hold the six
fields of the uncompressed header, in the same order.

A parse refuses an rdev that is not 0 and a mode that is not a regular file or
a symlink.

On-disk framing of a content stream (the length-prefixed header):

```
[4 bytes BE u32: variant length][4 bytes 0x00 padding to 8-byte align][header variant bytes]
```

The 4-byte NUL pad aligns the variant to 8 bytes for a memory map.

The raw payload of a regular file comes directly after the framed header. In
archive mode the payload is raw DEFLATE. A bare-mode object stores the payload
alone, with no framing. The framing exists in a stream and in the checksum
input.

### bare-user metadata xattr -- `(uuua(ayay))`

The value of the `user.ostreemeta` xattr on a `.file` object in bare-user
mode. The layout is the dirmeta layout.

### Detached commit metadata (`.commitmeta`) -- `a{sv}`

A bare dict, with no tuple around it. It is not part of the commit checksum. It
is a separate loose file, it is mutable, and it holds the signatures. A write
with no metadata gives a zero-length file, which deletes the metadata.
"Signing details" lists the signature keys and their values. The key
`ostrya.related` of the port holds the build sources of the commit ("Related
commits").

## Summary and summary signature

### Summary -- `(a(s(taya{sv}))a{sv})`

The file `summary` at the repository root. The outer tuple is
`(refs, global_metadata)`.

Field 0, `a(s(taya{sv}))`, is the ref array. It holds the local refs
(`refs/heads`), sorted by ref name with byte-wise comparison. In a repository
with `[core] collection-id=ID`, it also holds the refs of
`refs/mirrors/ID/`, as the paragraph below states. It holds no remote ref.
Each entry is `(s, (t, ay, a{sv}))`:

- `s` ref name.
- `t` size of the commit object in bytes, in host order, which is its on-disk
  length.
- `ay` commit checksum, 32 raw bytes.
- `a{sv}` per-ref metadata, in insertion order: `ostree.commit.version` (`s`),
  present only when the commit has a `version` metadata key, then
  `ostree.commit.timestamp` (`t`, big-endian), always present.

Observed behavior: in a repository with `[core] collection-id=ID`,
`ostree summary -u` of the tool 2026.1 puts each ref of `refs/mirrors/ID/`
into field 0 under its plain name. When `refs/heads/NAME` and
`refs/mirrors/ID/NAME` both exist, field 0 holds one entry `NAME`, with the
checksum of the mirror ref. `ID` is not a key of
`ostree.summary.collection-map`. The summary writer of the port does the
same.

The file `summary` at the repository root is the root summary. It holds
each local ref and each collection ref, whatever the client groups, and it
is the summary that the tool writes for the same refs. A local reader reads
it, for example `summary -v` and a local pull. `ostrya serve` and
`ostrya send` never serve it. The port also writes one summary for each auth
item of the client groups. "Summaries of auth items" states these summaries
and the refs of each one.

Field 1, `a{sv}`, is the global metadata. GVariant does not sort a dict again,
so the insertion order is the on-disk order. The writer writes the keys in
this order, and a key is absent when its condition is false:

- `ostree.summary.mode` -> `s`, the repository mode string (for example
  `archive-z2`, `bare`, `bare-user`). The root summary states the mode of
  the repository. The summary of an auth item states `archive-z2`, the mode
  of the archive view that serves it ("The archive view").
- `ostree.summary.last-modified` -> `t` big-endian, the generation time. It is
  wall-clock time, and `SOURCE_DATE_EPOCH` does not set it.
- `ostree.summary.tombstone-commits` -> `b`, the `[core] tombstone-commits`
  value (default false). Always present.
- `ostree.static-deltas` -> `a{sv}`: delta name (`FROM-TO` or `TO`, in hex) ->
  `ay`, the SHA-256 of the `superblock` file of the delta (32 bytes). Present
  only when the repository has static deltas. A summary of the port that does
  not hold each ref lists fewer deltas ("Summaries of auth items"). Outside
  the `archive` mode, the summary of an auth item has no such key ("The refs
  and the deltas of a summary"). The port
  writes the entries in
  name order (`conformance/cli-surface.md`, "P2", `summary`, records the order
  of the tool). Observed behavior: the tool writes the key between
  `tombstone-commits` and `indexed-deltas`. Not observed: the order of the key
  relative to `ostree.summary.collection-map` in the tool.
- `ostree.summary.collection-map` -> `a{sa(s(taya{sv}))}`, present only when
  the repository holds mirror refs (`refs/mirrors/<collection>/<ref>`) of a
  collection other than `[core] collection-id`. It maps each collection id to
  a ref array with the shape of field 0. Both levels are byte-wise sorted. A
  directory under `refs/mirrors/` whose name fails the collection-id rule is
  not in the map of the port.
- `ostree.summary.indexed-deltas` -> `b`, the `[core] indexed-deltas` value
  (default true). Always present in the root summary. Outside the `archive`
  mode, the summary of an auth item has no such key.
- `ostree.summary.collection-id` -> `s`, present only when
  `[core] collection-id` is set.
- `ostree.summary.expires` -> `t` big-endian, which the summary reports read.
  The port's writer does not write it. A caller gives it with
  `summary -m`, as a caller key. A caller value is stored in host order, so a
  caller gives the byte-swapped number to store a big-endian value.

A regeneration of the summary does not write or refresh `delta-indexes/`
("Static delta index files"). A repository can thus list deltas in its summary
and serve no index.

The keys that a caller adds with `summary -m` come after the keys of the
writer. When the writer writes a key in the same run, its value has precedence
over the caller value. These keys are `ostree.summary.mode`,
`ostree.summary.last-modified`, and `ostree.summary.tombstone-commits`, which
are always present, and `ostree.static-deltas`, `ostree.summary.collection-map`,
`ostree.summary.indexed-deltas`, and `ostree.summary.collection-id` in a
summary that holds them. The writer keeps each other caller key, whatever its
name, and the empty key. Outside the `archive` mode, the summary of an auth
item drops the caller keys `ostree.static-deltas` and
`ostree.summary.indexed-deltas`, so it names no delta.

A repeated caller key is stored once, with its last value. The value is the
GVariant text form. The port appends the caller keys in the order of their
first occurrence (`conformance/cli-surface.md`, "P2", `summary`, records the
order of the tool).

For a repository with a collection id, see "The `ostree-metadata` anchor
commit".

### The `ostree-metadata` anchor commit

When `[core] collection-id` is set, a regeneration of the summary first
refreshes an anchor commit on `refs/heads/ostree-metadata`. The anchor is an
empty-tree commit:

- Root dirtree
  `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d` (no
  entries).
- Root dirmeta
  `446a0ef11b7cc167f3b603e585c7eeeeb675faa412d5ec73f62988eb0b6c5488` (uid 0,
  gid 0, mode `040755`, no xattrs).
- Metadata dict, in this order: `ostree.collection-binding` (`s`, the
  collection id of the repository), then `ostree.ref-binding` (`as`, the
  single element `ostree-metadata`).
- Empty subject and body.

The timestamp resolves as for any commit: the explicit value, then
`SOURCE_DATE_EPOCH`, then the current time. Each regeneration commits a new
anchor with the previous anchor as its parent, so the checksum changes on each
run. The first generation on a new repository has no parent and is
reproducible. The anchor ref is in field 0 by name, as any other local ref.
`ostrya summary -u -c` writes no anchor commit.

The port adds no caller key to the anchor. In a repository with a collection
id it refuses any caller key before the anchor advances and before any write
(`conformance/cli-surface.md`, "P2", `summary`).

### Summary signature -- `a{sv}`

The file `summary.sig` at the repository root, a bare `a{sv}` with the
signature keys that "Signing details" lists. The signed payload is the exact
byte content of the `summary` file. A regeneration of the summary removes
`summary.sig`, because the old signature does not cover the new summary. A
caller that wants a signed summary regenerates it and then signs it.

`summary -u` writes its signatures after the regeneration: every `--gpg-sign`
signature under `ostree.gpgsigs` first, then every `--sign` signature under
`ostree.sign.<type>`. A file with both engines thus stores `ostree.gpgsigs`
first, whatever the command-line order. In each array the signatures follow
the command-line order, and a key given twice signs twice. A GPG signature
holds its creation instant, so two runs with one GPG key write different
bytes. Two runs with one ed25519 key over one `summary` write the same bytes.

The port makes every signature of a summary before it writes the summary.
Then it removes the old signature file, writes the summary, and writes the
new signature file. A signer that fails thus leaves that summary and its
signature file as they were. A signing with no regeneration
(`conformance/cli-surface.md`, "P2", `summary`) makes every signature of
each summary of the port, and then replaces each signature file.

## Checksum computation

The object checksum is the SHA-256 of specific bytes, as a 64-character
lowercase hex string.

- Metadata objects (dirtree, dirmeta, commit): the hash of the canonical
  normal-form GVariant serialization bytes and nothing else. A
  `.tombstone-commit` and a `.commitmeta` take the checksum of their commit.
- File content objects: SHA-256( uncompressed-file-header bytes ||
  raw-payload bytes ). The header bytes include the 4-byte BE length prefix and
  the 4-byte NUL padding of the framing. The payload is the uncompressed
  content. In archive mode the `.filez` file is compressed, so its stored
  bytes do not hash to the object name.
- Symlinks: the header holds the target in the `s` field, and there is no
  payload. The hash covers the framed header bytes.

The `bare-user-only` mode records a reduced header. The reduced header has
uid 0, gid 0, and no xattrs. It reduces the permission bits of a regular file
or directory to `perm & 0o755`. A symlink keeps its mode. The object checksum
covers that reduced header. Each other mode hashes the header unchanged.

The commit content checksum is SHA-256( root-dirtree-csum-binary ||
root-dirmeta-csum-binary ). It is a content identity that does not depend on
the commit metadata or the timestamp.

A checksum has four representations: hex (64 characters), binary (32 bytes),
GVariant `ay` (32 elements), and modified base64. Modified base64 is standard
base64 with `_` in place of `/` and without the trailing `=`, 43 characters.
Only the static-delta directory names use modified base64.

The port decodes a base64 checksum strictly and per alphabet, so each digest
has exactly one accepted spelling:

- The length is exact: 44 characters that end in one `=` for the standard
  form, 43 for the modified form.
- The `/` glyph and the `_` glyph at index 63 are valid only in their own
  alphabet.
- The two unused low bits of the last significant sextet must be zero.

## Repository modes and on-disk storage

Mode strings: `bare`, `bare-user`, `bare-user-only`, `archive-z2` (alias
`archive`), `bare-split-xattrs`, and the port extension `bare-user-shared`.
ARCHIVE always serializes back as `archive-z2`.

- `bare`: real files with the logical uid, gid, mode, and xattrs on the inode.
  A write that puts the logical uid and gid on the inode needs root.
- `bare-user`: the logical metadata is in the `user.ostreemeta` xattr, and a
  symlink is stored as a regular file. An unprivileged user can write it.
- `bare-user-only`: no xattr metadata. The uid and gid are discarded and read
  back as 0, and the checksum has its own variant ("Checksum computation"). It
  works on a filesystem without xattr support.
- `bare-split-xattrs`: bare inode storage, with the xattrs in separate objects.
  "bare-split-xattrs mode" states which implementation reads and writes it.
- `archive` (`archive-z2`): content raw-DEFLATE-compressed as `.filez`, with
  uid, gid, mode, and xattrs in the header. An HTTP server can serve it. A
  checkout never hardlinks its objects.
- `bare-user-shared`: a development-only port extension. It is `bare-user`
  storage with a fixed inode mode 0644, for group-shared repositories
  ("bare-user-shared mode").

"Write path: loose-object inode modes and durability" states the inode mode
and the owner in each mode. `conformance/cli-behavior.md`, "Checkout",
"Hardlink and copy", states when a checkout hardlinks an object.

Metadata objects are always stored uncompressed. The `z` suffix applies only to
a `File` content object in archive mode (`.filez`). The auxiliary objects
(`.payload-link`, `.file-xattrs`, `.file-xattrs-link`) are stored uncompressed
and never take the suffix. Observed behavior: an archive repository that
`commit` fills, and that `pull-local` fills from bare and archive sources,
holds only `.filez` content objects and uncompressed metadata.

## Object store layout

```
<repo>/
  config                          GKeyFile INI, repo root
  .lock                           repository lock file (advisory)
  .update.lock                    port-only update lock file (lazy)
  objects/<c0c1>/<c2..c63>.<ext>[z]   loose objects
  refs/heads/<ref>                local refs (ref may contain '/')
  refs/remotes/<remote>/<ref>     remote refs
  refs/mirrors/<collection>/<ref> collection refs (<collection>/ lazy)
  state/<checksum>.commitpartial  incomplete-commit markers
  tmp/                            staging (staging-<bootid>-XXXXXX + -lock), cache/
  tmp/.ostrya-ref-<pid>-<n>-XXXXXX  port temp entry of a ref or alias write
  tmp/.ostrya-meta-<pid>-<n>-XXXXXX port temp file of a .commitmeta or .tombstone-commit
  tmp/cache/summaries/            summary cache
  extensions/                     reserved, created empty
  deltas/                         static deltas (lazy)
  delta-indexes/                  delta indexes (lazy)
  uncompressed-objects-cache/     archive checkout cache (lazy)
  summary                         (lazy)
  summary.sig                     (lazy)
```

Loose object path: `objects/<first 2 hex>/<remaining 62 hex>.<typestr>`, with
the `z` suffix that "Repository modes and on-disk storage" states. The checksum
must be exactly 64 hex characters.

### Ref files

A ref file holds 64 lowercase hex characters and a single `\n` (65 bytes). Each
ref is an individual loose file, and the format has no packed-refs mechanism.
The refspec `remote:ref` maps to `refs/remotes/remote/ref`, and a bare `ref`
maps to `refs/heads/ref`. A NULL rev deletes the ref. An alias is a relative
symlink.

Both implementations write the 64 lowercase hex characters, and the port reads a
ref file in either case. Only an out-of-band write puts other content in a ref
file. `conformance/cli-surface.md`, "P1", records how the tool reads it, and
"P2" records the same reader at `commit --parent`.

A write of a ref whose file is an alias symlink replaces the symlink with a
regular ref file, and the alias target stays unchanged. Both implementations
rename a new temp file over the ref name, and the rename replaces the symlink at
that name. Example: `refs/heads/foo` is a relative symlink to the sibling `bar`.
A commit onto `foo`, or `ostree refs --create --force` on it, makes
`refs/heads/foo` a 65-byte regular file that holds the new checksum.
`refs/heads/bar` keeps its old checksum.

### Ref name validation

A ref name is one or more `/`-separated components. A component is not empty and
does not begin with `-` or `.`. It holds only ASCII alphanumerics, `-`, `.`,
`_`, and the non-ASCII characters that this section states. One optional `:`
separates a remote name from the ref name, and a second `:` is invalid. The
remote is one component and follows the rule of a component.

The tool accepts `a-b`, `a.b`, `a_b`, `a..b`, `a.`, `0ab`, and `té`, and the
remotes of `é:main`, `o.:main`, and `_o:main`. It refuses these names with
`error: Invalid refspec <name>` and exit 1:

- a component that holds a space or one of
  ``! " # $ % & ' ( ) * + , ; < = > ? @ [ \ ] ^ ` { | } ~``;
- a component that starts with `-`, `.`, `~`, or `+`: `-a`, `.a`, `~a`, `+a`;
- an empty component (`a//b`, `/a`, `a/`), and a second `:` (`a:b:c`);
- the remotes of `o r:main`, `o*:main`, `-o:main`, `.o:main`, `o~:main`, and
  `a/b:x`.

The port applies the same rule to the remote and to the name part of every ref
name and refspec. It refuses an empty name and a name part with a `:`. The ref
store takes a collection id that is one path component. The id is not empty, is
neither `.` nor `..`, and holds no `/` and no NUL. `refs -c --create` first
applies the collection-id rule of the tool, which is stricter
(`conformance/cli-behavior.md`, "CLI output formats", `refs`).

For non-ASCII characters, the tool accepts letters, numbers, nonspacing
combining marks (Unicode category Mn), and non-ASCII connector punctuation
(category Pc). It refuses controls, spaces, format characters, symbols, other
punctuation, private use characters, `U+FFFD`, and emoji. It also refuses
spacing combining marks (category Mc), enclosing marks (category Me), circled
and enclosed letters, and characters that its Unicode tables do not hold.
`U+00E9`, `U+00B5`, `U+02D0`, `U+4E2D`, `U+00B2`, `U+2160`, `U+0660`, `U+00AA`,
`U+00BA`, and `U+00BC` are accepted. `U+0080`, `U+0085`, `U+00A0`, `U+00AD`,
`U+00D7`, `U+2013`, `U+200B`, `U+20AC`, `U+FEFF`, `U+E000`, `U+1F600`, and
`U+FFFD` are refused.

The port accepts a non-ASCII character if `char::is_alphanumeric` is true for
it, except for 571 of these characters. The 571 characters are spacing combining
marks, circled and enclosed letters, and letters outside the Unicode tables of
the tool. The port refuses each other non-ASCII character
(`conformance/cli-surface.md`, "P1", records the characters that the tool
accepts and the port refuses). The port reads a name as UTF-8. Both
implementations refuse an argument that is not valid UTF-8 with exit 1 and write
no ref. The port refuses it when it decodes the arguments.

Both implementations report a refused name as `error: Invalid refspec <refspec>`
and exit 1. This applies at each site that takes a name: a revision, a NEWREF,
and the `-b` branch of a commit. The message holds the refspec as given, with
its `<remote>:` or `<collection-id>:` prefix, and without a trailing run of `^`.
So `rev-parse a/../b^` and `rev-parse a/../b` report the same line. At the
target of `refs -A --create`, an existence check comes before the rule. There a
refused name is reported as a name that no ref holds
(`conformance/cli-behavior.md`, "CLI output formats", `refs`).

A name that passes the rule also names a path below `refs/`. An implementation
opens that path where it resolves or writes the name: `rev-parse <name>`, `cat
<name> PATH`, the positional revision of `refs --create`, `refs
--create=<name>`, and `refs -A --create=<name>`. If the path runs through a ref
file, both implementations exit 1 and write no ref. The port reports `error: i/o
error: Not a directory (os error 20)` at each site. If the name names a
directory under `refs/`, the port refuses it at each site with `error: i/o
error: Is a directory (os error 21)` and writes nothing.

`refs --delete` leaves an empty directory behind in both implementations when it
removes the last ref of a directory. `conformance/cli-surface.md`, "P1", records
the messages of the tool, and the four directory shapes that the write of the
tool replaces. The `PREFIX` form of the path rule is in
`conformance/cli-behavior.md`, "CLI output formats", `refs`.

### Revision syntax

A revision names a commit in four ways:

- a 64-character lowercase hex checksum;
- an abbreviated checksum ("Abbreviated checksums");
- a refspec;
- one of these three, followed by one or more `^` characters.

Each `^` steps one generation back along the `parent` field of the commit. A
walk past a root commit reports `error: Commit <checksum> has no parent` and
exits 1.

`~N` and `^N` are not revision syntax. `ostree rev-parse test/main~1` and
`test/main^2` each report `error: Invalid refspec <rev>`. The ref-name rule
refuses `~` and `^` inside a name, so the port reads the whole revision as a
refspec and reports the same line. This applies at `rev-parse`, at `cat`, and at
the positional of `refs --create`. A checksum with either suffix takes the same
path, because the name holds more than 64 characters. Both implementations exit
1 and write nothing.

The case of the 64 characters is part of the rule. A name is a checksum in
lowercase hex alone, and one uppercase character makes it a ref name. So both
implementations report `error: Refspec '<rev>' not found` for
`rev-parse <UPPER>`, `cat <UPPER> PATH`, `checkout <UPPER> DEST`, and
`rev-parse <UPPER>^`, where the same 64 characters in lowercase resolve. A name
that holds one uppercase character reads as the all-uppercase name does. The
positional revision of `refs --create` reports the same not-found line, so
`refs --create=fresh <UPPER>` writes nothing. Three sites of `refs` apply the
case rule in their own way:

- The existence check of `refs --create=NEWREF` resolves NEWREF. A NEWREF of 64
  lowercase hex characters is a checksum and reports `error: --create specified
  but ref <NEWREF> already exists`, whether or not the store holds that commit.
  A NEWREF that prefixes a commit reports the same line. An uppercase NEWREF is
  a free ref name, and the write lands at `refs/heads/<NEWREF>`. A revision of
  that name then resolves through the ref file. `refs -A --create` records an
  alias to it, and `refs --delete` guards it under the name that the alias body
  holds.
- `refs -A --create` takes a ref name. A lowercase 64-character target reports
  `error: Cannot create alias to non-existent ref: <rev>`, and a hex prefix
  reports `error: Cannot create alias to non-existent ref: <prefix>`.
- A `PREFIX` argument is matched and not resolved, so neither case of a
  64-character name matches a ref there.

A revision resolves whether or not the store holds the commit that it names. An
absent commit is reported where the commit is read: at `cat`, `checkout`, and
`export`. A revision with a `^` suffix also reads it, because the walk loads the
base commit. Both implementations exit 1 and write nothing there, and
`conformance/cli-surface.md`, "P1", records the two messages.

These sites take a checksum, do not read the commit, and accept an absent one
at exit 0:

- `rev-parse <checksum>` prints it.
- The positional revision of `refs --create` writes a ref file that holds it.
- `commit --parent=<checksum>` writes a commit that names it.

So a ref that points at an absent commit can come from either CLI. A revision
read through that ref reports the same two messages.

### Abbreviated checksums

An abbreviated checksum is a run of one to 63 lowercase hex characters. It names
the one commit object whose checksum starts with it. Both implementations
resolve it by one rule:

- The match set holds commit objects alone. A prefix that only a dirtree, a
  dirmeta, or a file object carries matches nothing and takes the refspec path.
  Such an object does not stop a commit with the same prefix from resolving.
- If exactly one commit matches, the prefix resolves to it, at each length from
  one character to 63.
- If more than one commit matches, the prefix reports `error: Refspec <prefix>
  not unique` at exit 1, with the prefix unquoted. The failure stands at each
  site that takes the revision, `commit -b` included. A following `^` reports
  the same line, because nothing resolved to walk back from.
- The scan comes before the ref store. A ref name that prefixes a commit
  resolves to that commit, and the target of the ref is not read. The ambiguous
  case also stops at the scan.
- A prefix that no commit carries goes to the ref store. So a hex name is an
  ordinary ref name while no commit begins with it. `refs --create=dddd <rev>`
  writes such a ref, and `rev-parse dddd` reads it back.
- One uppercase character makes the name a refspec, so `rev-parse
  <UPPER-PREFIX>` reports the not-found line.

The rule starts at one character. The port refuses the empty name in every
repository with `error: Invalid refspec ` (`conformance/cli-surface.md`, "P1",
records how the tool reads an empty revision).

### Branch names no revision reaches

`commit -b` refuses a branch name of 64 lowercase hex characters with `error:
Rev name '<name>' looks like a checksum`, and names the branch as given. Each
site that takes a revision reads a ref of that shape as a checksum, so no
revision reaches the commit behind it. The guard refuses this one shape. A name
one character shorter or longer is written. A name of that length with a
character outside the hex class, in uppercase, or with a single uppercase
character is written too.

The refusal runs at the ref write, so a fault before it is reported first. An
unresolvable `--parent` and a tree path that does not open each end the
invocation, in the words of each implementation (`conformance/cli-surface.md`,
"P2"). `--orphan` keeps the refusal in both implementations, because `-b` also
writes the ref under it.

Both implementations write a branch whose name prefixes a commit, and no
revision reaches that ref. The guard does not cover this shape, because what a
hex name hides depends on the commits that the store holds at that time. A guard
for this shape must refuse a name that is free now, because the next commit can
hide it. The implicit parent of `commit -b BRANCH` is what BRANCH resolves to as
a revision. So each commit onto such a branch takes the prefixed commit as its
parent (`conformance/cli-behavior.md`, "CLI output formats", `commit`, "The
parent").

A branch name that ends in `^` is the second hidden shape. Resolution reads the
suffix as ancestry, so no revision reaches the commit that a ref of that name
holds. The ref-name rule refuses every name that holds a `^`. Both
implementations refuse `a^b` as a ref name, whatever the store holds, and
report `error: Invalid refspec a^b`.

The port refuses a branch name that ends in `^` with `error: Invalid refspec
<name>`, the message it gives that shape at `refs --create`. It refuses at the
ref write, after it reads the tree. So a tree error, such as a path that does
not open, can come first. A branch name that the rule refuses is not read as
the implicit parent. The port thus refuses the name after it writes the commit,
and it aborts the transaction (`conformance/cli-surface.md`, "P2", `commit`,
records the order of the tool).

A push guards the checksum shape at each site where it writes a commit to a
target ref:

- `push` refuses a `DST` of that shape after a `SRC` with `error: Invalid
  refspec <name>` before the transport starts. `push --onto` refuses a branch
  or a `--tag` of that shape with the same error.
- `push-tree` refuses a branch of `--onto` or a `--tag` of that shape with
  `error: Rev name '<name>' looks like a checksum`.
- `commit --tag` refuses a tag of that shape with `error: Rev name '<name>'
  looks like a checksum` before it takes the repository lock.
- In the library, `Repo::push`, `Repo::push_onto`, `Repo::export_stream`, and
  `push_tree` refuse the name before they send a byte.
- The server of a push session or of a one-way stream refuses an update that
  writes a commit to such a ref at `Commit` ("Commit and CommitReply"). It
  refuses a server commit whose branch or tag has that shape with
  `invalid-ref`.

`Hello` names the refs of a session and does not tell a write from a delete, so
the server does not check the shape at `Hello`. The client passes a push delete
(`:<name>`) of a ref of that shape. Check 1 of "Commit and CommitReply" states
the server side. A remote ref `REMOTE:<name>`
is not 64 characters, so a revision reads it as a refspec, and each push site
takes it. Ref reads, local ref deletes, pull, and prune do not apply the guard.

A ref of either hidden shape can arrive in these ways:

- a direct ref write of the library: `Transaction::set_ref` and
  `Repo::set_ref_immediate` write both shapes;
- a pull of every ref of a source that holds a ref of the checksum shape, which
  the port copies (`conformance/cli-surface.md`, "P2");
- an out-of-band write into `refs/`.

Over a ref of the checksum shape, the tool lists the ref and its `fsck`
validates it. Its `prune --refs-only` reads the commit of the ref as reachable
and keeps it. The port enumerates a ref of either shape.
`conformance/cli-surface.md`, "P1", records how the tool lists, checks, and
prunes a ref of the ancestry shape.

### Ref durability

The tool writes a ref in one sequence for `refs --create` and for the ref write
of a commit. It creates a temp file in the directory that holds the ref, runs
`fdatasync` on it, and runs `renameat` over the ref name. It syncs no directory.
This includes the parent of the ref, `refs/heads`, and the repository root.
`fsync=false` removes the `fdatasync` and keeps the rename. An alias write
(`refs -A --create`) runs `symlinkat` into `<repo>/tmp` and `renameat` over the
ref name, with no sync. `refs --delete` runs `unlinkat` alone.

The port creates the temp file of a ref write, and the symlink of an alias
write, in `<repo>/tmp`. It creates `<repo>/tmp` if it is absent. It runs
`fdatasync` on the temp file of a ref write, and renames the temp entry over the
ref name. Then it runs `fsync` on the directory that holds the ref. A ref
removal does not use `tmp/`, and the port runs the same directory `fsync` after
it.

A ref listing reads every entry under `refs/`, so the port keeps no temp entry
there. If `<repo>/tmp` is on a different filesystem from the ref, the rename
fails with `EXDEV`. The write then fails, the port removes the temp entry, and
the ref stays unchanged.

A ref name with a `/` can make the write create directories. A `mkdirat` records
a name in the directory where it is called, so for a created
`refs/heads/deep/nest` the directory to sync is `refs/heads/deep`. The port
syncs the directory that holds the ref first. Then it runs `fsync` on the
directory that holds each parent directory that the write created, deepest
first. This is the child-before-parent order of the object fanout.

A crash part way through leaves a prefix of the path recorded. It never leaves a
directory entry that names a directory whose own contents are not recorded.
The write does not sync a directory that it found in place, unless that
directory holds an entry that the write created. The name of a directory found
in place is already durable.

A write whose parent directories all exist, such as a single-component
local ref, creates no directory. The first ref of a remote creates
`refs/remotes/<remote>`, and the first ref of a collection creates
`refs/mirrors/<collection>`. A ref write runs one directory sync plus one for
each directory that it created.

A transaction that writes several refs renames every ref file first. Then,
before its commit returns, it runs `fsync` once on each directory that gained or
lost a name, deepest first. So two refs in one directory share one sync. Each
ref file gets `fdatasync` before its rename. The objects and the detached
metadata that the refs name are durable before the first rename. So the order
guarantee is the same as for one ref.

`fsync=false` makes all of these syncs no-ops. The syscall sequence carries no
byte-exact requirement, and the ref bytes are identical either way.
`conformance/cli-surface.md`, "P2", `commit`, records the directory `fsync` of
the port.

### Repository lock and staging

The tool opens `<repo>/.lock` with `O_RDWR|O_CREAT` and mode `0660`. It takes an
`fcntl` OFD lock on the file: shared (`F_RDLCK`) for the duration of a commit,
and exclusive (`F_WRLCK`) for destructive maintenance. It releases the lock
(`F_UNLCK`) at the end.

A transaction stages objects in `tmp/staging-<bootid>-XXXXXX` (mode `0775`).
`<bootid>` is `/proc/sys/kernel/random/boot_id` verbatim, dashes kept, and
`XXXXXX` is a six-character `mkdtemp` suffix. The transaction holds an exclusive
OFD lock on a sibling file `tmp/staging-<bootid>-XXXXXX-lock` (mode `0600`)
while it uses the staging directory. So a later transaction can tell a live
staging directory from one that a dead transaction left. The port requests the
same names and modes. In `bare-user-shared` it then sets the modes that
"bare-user-shared mode" states. These locks are advisory and
cross-process, and the checksums and the object bytes do not depend on them.

The port takes a classic `fcntl` record lock (`F_SETLK`) on `.lock` and on
the staging lock sibling, in the same kinds. Record locks and OFD locks share
one lock space, so the port and the tool exclude each other on one
repository. This was verified in both directions: each side held its lock
while the other side tried to take the lock. A record lock belongs to the
process, so the port keeps one descriptor for each lock file in a process
(`crates/ostrya/src/lock.rs`).

`[core] lock-timeout-secs` sets the limit of the wait for `.lock`. The port
reads the value in this way:

- a positive value: it retries a non-blocking request every 100 ms, and fails
  at the timeout;
- `0`: it makes one attempt;
- `-1`: it retries with no deadline, and it never makes a blocking lock request;
- a value less than `-1`: it refuses the value, because it does not run a
  repository write with no lock.

`conformance/cli-surface.md`, "P2", `prune`, records how the tool reads the
value.

The port removes its staging directory and the lock sibling on every path out of
a transaction, the refusals included. So a run that exits non-zero leaves `tmp/`
with no `staging-` entry (`conformance/cli-surface.md`, "P2"). A transaction
that commits, aborts, or drops removes the pair itself. A process that ends
without unwinding removes the pair of every transaction that it still holds
immediately before the exit.

### The update lock

The file `<repo>/.update.lock` holds the update lock of the port. The port takes
an exclusive `fcntl` record lock on it, after it takes the repository lock
shared. Under `[core] locking=false` it takes the update lock alone, because the
update lock ignores that key. The lock serializes every port write of refs and
ref aliases, `config` and the remote keyrings, `summary` and `summary.sig`, the
files under `extensions/ostrya/summary/` ("Summaries of auth items"), and
`.commitmeta` files. The writers are an update guard (`Repo::begin_update`),
each writer outside a transaction, and the step of a transaction commit that
writes detached metadata and refs.

A transaction commit outside a receive publishes its objects before it takes
the lock. A receive takes the lock before its transaction commit ("Locks and
on-disk state of a receive"). A transaction that writes no ref and no detached
metadata takes no lock. So two port processes that
sign one commit at the same time keep both signatures. The port creates the file
on the first acquire with the rules of `.lock`, and never unlinks it. A file
that already exists keeps its mode. The tool never opens this file, so the lock
excludes port processes alone.

### Commit-state markers

A commit-state marker is the file `state/<checksum>.commitpartial`. The reader
only tests that the marker is present, which makes the commit `Partial`. The
marker is local state and does not enter any checksum.

- `fsck` writes the marker as a single byte `0x66` when it finds a commit that
  misses a referenced object.
- A pull writes the marker zero-length, and removes it when the objects of the
  commit are published. `pull-local --commit-metadata-only` keeps the 0-byte
  marker, and a later full pull removes it.
- A pull with `--subpath` keeps the zero-length marker of each commit that it
  reaches, because it fetched part of the tree. A later pull of the commit
  without `--subpath` removes the marker.
- A pull does not write over a marker that is present. A pull over a commit that
  `fsck` marked keeps the one-byte state.

`conformance/cli-surface.md`, "P2", `pull`, records the markers that a failed
pull leaves.

No writer syncs a marker or the `state/` directory. A pull creates every marker
before its transaction stages an object. So the `syncfs` at the start of
publication makes the marker durable before the first object rename. The removal
is the last operation of the pull, and no barrier follows it. So a crash
immediately after a successful pull can restore the marker of a complete commit.
`fsck` writes its marker with no barrier, and a new `fsck` run writes it again.
The tool `pull-local` runs these syscalls in this order:

1. `openat(state/<checksum>.commitpartial, O_WRONLY|O_CREAT|O_EXCL, 0644)`;
2. a `syncfs` of the repository;
3. the object renames into `objects/`;
4. an `fsync` of each touched fanout and of `objects/`;
5. the ref write;
6. the `unlinkat` of the marker, as its last syscall.

The tool `fsck` runs no `fsync`, `fdatasync`, or `syncfs` in a run that writes a
marker.

### Old entries in `tmp/`

The tool reaps `tmp/` at the end of each transaction, after it removes its own
staging directory, on a commit and on an abort. `commit`, `reset`, `pull-local`,
`summary -u` over a repository with a collection id, and `static-delta
apply-offline` reap. `prune`, `fsck`, `summary -u` over a repository with no
collection id, `refs`, `checkout`, and `static-delta generate` do not. The reap
reads the top level of `tmp/` and runs `lstat` on each entry:

- It skips `cache` by name, and touches nothing below it, at any age.
- For a directory whose name starts with `staging-`, it opens `<name>-lock` with
  `O_RDWR|O_CREAT` and tries an exclusive OFD lock. If it gets the lock, it
  removes the directory tree and the lock file at any age. So the reap removes
  a staging directory with no lock file at any age. If another process holds the
  lock, the directory stays at any age. An `flock` hold does not protect it.
- It removes each other entry, a `staging-*-lock` file and a `staging-*` entry
  that is not a directory included, when its age is more than `tmp-expiry-secs`.

The age is the current time minus `st_mtime`. An old atime does not remove an
entry, and a new ctime does not keep it. The reap removes a directory as a
whole tree, and only its own mtime counts. So an old directory with a new child
is removed, and a new directory with old children stays. The reap removes each
other entry, a fifo and a symlink included, with one `unlinkat`, so the target
of a symlink stays.

The age test counts whole seconds. At `tmp-expiry-secs=0` an entry created in
the current second stays, and an entry one second old or more is removed. At
`tmp-expiry-secs=5` an entry up to five seconds old stays, and an entry six
seconds old is removed.

At the start of a transaction, the tool also reuses a
staging directory of the current boot whose lock it can take. It sets the times
of that directory with `utimensat`. The age test unlinks a held lock file that
is older than `tmp-expiry-secs`. The next transaction then takes that staging
directory, which now has no lock file, for its own.

The port reaps `tmp/` at the start of each transaction, with the same top-level
read:

- It skips `cache`.
- It applies three rules of the tool to each entry that is not a `staging-*`
  directory or a `staging-*-lock` file:
  - the age test;
  - the removal of a directory as a whole tree;
  - the removal of a symlink as the link.
- It does not apply the age test to a staging lock file. The lock of a
  transaction that lives longer than `tmp-expiry-secs` is still held.
- It removes a `staging-*` directory when it can take its lock.
- It removes a staging directory with no lock file only when its age is more
  than `tmp-expiry-secs`. Another process can be between the directory create
  and the lock create.

Each transaction creates a new staging directory, and the port reuses none.
`conformance/cli-surface.md`, "Global conventions", records the differences
between the two reaps.

The port writes a ref, an alias, a `.commitmeta`, and a `.tombstone-commit`
through the temp entries `.ostrya-ref-*` and `.ostrya-meta-*`. These entries get
the age test like each other entry. With a very small or negative
`tmp-expiry-secs`, the reap of another transaction can unlink such an entry
before its rename. The write then fails with `ENOENT`, and the ref or the object
stays unchanged.

### Prune removal order

The port's prune removes what it dooms in the order below. Thus a run that
stops part way through leaves no commit object whose tree it started to
remove. A pull reads a commit with no `.commitpartial` marker as complete, so
such a commit is damage that no reader reports.

1. The commit phase. For each doomed commit, the port writes the tombstone
   where the run writes tombstones, unlinks the commit object, and then
   unlinks its `.commitmeta` and its composefs image. Then it unlinks each
   `.commitmeta` and each composefs image whose commit is absent.
2. The barrier. If `[core] fsync` is true, the port syncs each `objects/`
   fanout directory in which the commit phase removed an entry, one time for
   each directory. If `[core] fsync` is false, a crash gives no guarantee of
   the order in which the removals reach the disk.
3. The content phase. The port removes each other doomed object, in any
   order.
4. The leftover sweep. See below.

The commit goes before its `.commitmeta`. A `.commitmeta` with no commit is
unreachable, and the next prune removes it. The reverse order leaves a commit
with no signatures.

A `--delete-commit` run removes the named commit in the order of the commit
phase, and syncs its fanout directory before the other phases start.

No phase before the leftover sweep removes a `state/<commit>.commitpartial`
marker. The commit can already be partial. If a crash made the unlink of the
marker durable and not the unlink of the commit, a partial commit would look
complete.

The order changes no count. The port reads the size of each doomed object
before its unlink and counts the object one time. A `.commitmeta` or a
composefs image that the commit phase removes with its commit is in no count.
An object that is absent when the port reads its size is in no count. A
`--no-prune` run goes through the same phases, removes nothing, and reports
the counts that the removal would give.

A run that stops part way through leaves two kinds of entries that no later
walk finds: the static deltas of the commits it removed, and the markers of
these commits. Each run with no `--no-prune` and no `--static-deltas-only`
removes them after the content phase:

- each static delta whose target commit is absent from the store. A delta
  whose source commit is absent and whose target commit is present stays. A
  delta name that does not decode names no commit, and its entry stays.
- each `state/<commit>.commitpartial` marker whose commit is absent from the
  store. A name that is not a marker name in lowercase hex stays.

The prune of a bucket repository deletes its keys in the same order
("The prune of a bucket repository").

A `--static-deltas-only` run removes the deltas of the commit it names and
nothing more. It removes no marker, and it keeps a delta name that does not
decode.

The leftover sweep depends on the repository lock. Each pull writes its
marker inside its transaction, which holds the lock shared until the commit
is published. The prune holds the lock exclusive. Thus no pull is between the
write of a marker and the store of its commit while the sweep runs. `fsck`
writes a marker with no lock, but only for a commit that it read from the
store. If `[core] locking` is false, a prune can remove the marker of a
concurrent pull, and the static delta of a commit that another writer stores
after the prune lists the store.

The leftover sweep is a port behavior. The tool's handling of a static delta
whose target commit is absent, and of a marker whose commit is absent, is not
observed.

### Static delta directories

Static delta directories use a fanout of the modified-base64 checksum (see
"Checksum computation"). A from-scratch delta is at
`deltas/<to_b64[0:2]>/<to_b64[2:]>/<target>`, and a from->to delta at
`deltas/<from_b64[0:2]>/<from_b64[2:]>-<to_b64>/<target>`. The targets are
`superblock` and one numeric part file per part, `0`, `1`, ..., and nothing
else. This holds for a from-scratch delta, a from->to delta, a four-part delta
(`--max-chunk-size=0.1`), and a delta with a fallback object
(`--min-fallback-size=1`). A fallback object adds no file here ("Object
delivery").

The `superblock`, each part file, and each index file have mode 0644 at any
umask. This applies at the repository location and in a `--filename` directory,
and to `reindex` with and without `--to`. The directories that the writer
creates get mode 0755, reduced by the umask.

### Static delta index files

An index file is at `delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index`. It is an
`a{sv}` with one entry, `ostree.static-deltas`, whose variant is the `a{sv}` map
that the summary holds under the same key ("Summary --
`(a(s(taya{sv}))a{sv})`"). One index file per
target commit lists every delta into that commit.

`static-delta generate` does not write or refresh an index, and `reindex` writes
the index files. `reindex` with no option rebuilds the index files from the
deltas present. It writes one index file per target and removes the index file
of a target with no delta left. The fanout directory that the removal empties
stays. `conformance/cli-behavior.md`, "CLI output formats", `static-delta`,
states `reindex --to`, `indexes`, and `delete`. `static-delta delete` does not
refresh the index files.

The port writes the entries of an index file in name order. An index file of one
entry is byte-identical between the two writers. `conformance/cli-surface.md`,
"P2", records the order of an index file with two or more entries.

### Config file (`<repo>/config`, GKeyFile / INI)

The file `config` is a key file. A new repository gets a `[core]` group with
`repo_version=1`, `mode=<mode>`, and an optional `collection-id`. The `config`
of a new archive repository is exactly
`[core]\nrepo_version=1\nmode=archive-z2\n`.

`ostrya-config(1)` lists each key of `config`, its type, and its default. The
list includes the keys of the port, the client groups, and the server group.
`conformance/cli-behavior.md`, "Signature verification during a pull", states
what the verification keys of a remote select and how each value is spelled.
`conformance/cli-surface.md`, "Global conventions", records the size cap that
the port applies to `config`.

`RepoConfig::auto_update_summary` reads `auto-update-summary` and
`commit-update-summary` together. Its caller in the port is the reader of the
receive policies, `ReceivePolicies::from_config`.
`conformance/cli-surface.md`, "P2", `commit`, records the effect of the two
keys on a commit.

Observed behavior: the tool reads and writes `config` by these rules.

- The reader splits the file into lines at each newline. It removes a trailing
  carriage return, so it accepts CRLF input.
- White space is ASCII space and tab alone. The reader ignores a leading space
  or tab before it classifies a line. A line of only spaces and tabs is blank.
  The reader trims a space or tab around a key. It never trims a non-breaking
  space (U+00A0) or other non-ASCII white space. A line whose only content is
  such a character is a parse error, and the whole file fails.
- A line whose first non-blank character is `#` is a comment. `;` does not
  start a comment. A line that starts with `;` and is not a `key=value` pair
  is a parse error.
- The reader ignores a blank line.
- A group header starts with `[`, and a leading space or tab can come before
  it. The name runs from `[` to the first `]`. Only white space can follow that
  `]`, so text after it, as in `[a]b]`, fails the whole file. An empty name
  (`[]`) fails the whole file. A name that holds `[`, as in `[a[b]`, is
  reported as an invalid group name. A name with a control character fails the
  whole file with `Invalid group name: <name>`. A `"` in a group name has no
  special meaning. A repeated header merges into the existing group.
- A `key=value` entry splits at the first `=`. The reader trims space and tab
  around the key. In the value, it removes leading space and tab, and it keeps
  trailing white space. A `#` in a value is literal, so a value has no inline
  comment. A repeated key takes the last value.
- A boolean is one of `true`, `false`, `1`, and `0`. The reader refuses each
  other spelling with a "value that cannot be interpreted" error: `yes`, `no`,
  `on`, `off`, mixed case such as `True`, an out-of-range number such as `2`,
  and the empty string. Before the match, the reader ignores a run of trailing
  space, tab, or form feed. So `fsync=true ` reads as `true`, and
  `ostree config get core.fsync` still prints the trailing byte. A trailing
  vertical tab fails the match.
- An integer is the leading run of decimal digits, with an optional `-` sign.
  The reader ignores the bytes that follow, so `101x`, `101 x`, and `101.9`
  all read as `101`. The out-of-range refusal of `min-free-space-percent`
  quotes the value as written, and it shows this rule. A value with no leading
  digit (`bogus`, `x101`, `+101`, the empty string) reads as no value. Then the
  default of the key applies, and the tool writes no diagnostic:
  `lock-timeout-secs=bogus` and `tmp-expiry-secs=bogus` both open.
- The value of `min-free-space-size` must match `^([0-9]+)(G|M|T)B$`. The
  reader takes the value as written, with no trim of trailing bytes. So
  `min-free-space-size=1MB ` is refused with `error: opening repo: Invalid
  min-free-space-size '1MB '`. The port refuses the same value.
- The reader unescapes a string value. `\s` becomes a space, `\n` a newline,
  `\t` a tab, `\r` a carriage return, `\\` a backslash, and `\;` a `;`.
- The writer escapes a backslash as `\\`, a newline as `\n`, and a carriage
  return as `\r` anywhere in a string value. In the leading run of white space,
  it writes each space as `\s` and each tab as `\t`. It writes a space or tab
  in another place, a trailing space or tab, and a `;` as they are.
- The writer puts each group as `[name]`, followed by its `key=value` lines. It
  puts a blank line between groups and no spaces around `=`.

`conformance/cli-surface.md`, "Global conventions", states how the port reads a
boolean and an integer.

## Write path: loose-object inode modes and durability

The checksum of an object does not depend on the repository mode, except in
`bare-user-only` ("Checksum computation"). The inode of a loose object does: its
permission bits, its owner, and the syscalls that make it durable. This section
gives these rules.

Inode permission bits, by object class and repository mode:

- Metadata objects (`.dirtree`, `.dirmeta`, `.commit`, and the other metadata
  types) are 0644 in every repository mode.
- `archive`: every content object (`.filez`) is 0644. The `.filez` header holds
  the logical uid, gid, mode, and xattrs.
- `bare`: the inode of a content object carries the full logical uid, gid,
  mode, and xattrs. A symlink is a real symlink that the logical uid/gid own.
  The port applies the owner first, then the xattrs, then the mode:
  - A chown of a regular file removes `security.capability` and clears the
    setuid bit, also when the ids do not change. When group execute is set, it
    also clears the setgid bit.
  - A mode change keeps `security.capability`.
  - The kernel checks a `user.*` xattr against the write permission of the
    inode. A logical mode with no owner-write bit (0444, 0555) does not give
    that permission, so the mode goes on last.

  Observed behavior: the tool keeps the `security.capability` value of a file
  on its `bare` object, with and without `--owner-uid` and `--owner-gid`. The
  port gives the same commit checksum.
- `bare-user`: the inode mode of a regular-file content object is
  `(logical_perm & 0o775) | 0o400`. The owner bits and the group and other read
  and execute bits stay, owner read is set, and other write is removed (`0666`
  stores as `0664`, `0777` as `0775`). A symlink is a regular file whose inode
  is 0644. The writing process owns the inode. `user.ostreemeta` holds the
  logical uid, gid, mode, and xattrs. A logical mode with no owner-write bit
  (0444, 0555) gives an inode with no write permission. The kernel checks a
  `user.*` xattr against that permission, so `user.ostreemeta` goes on before
  the mode.
- `bare-user-shared`: `bare-user` storage, with every content inode at a fixed
  0644 ("bare-user-shared mode").
- `bare-user-only`: the inode mode of a regular-file content object is the
  canonical `logical_perm & 0o755`. Group write and other write are removed,
  and no special bit stays (`0664` stores as `0644`, `0666` as `0644`, `0775`
  as `0755`). The uid/gid are discarded and no xattrs are stored. A symlink is
  a real symlink, and its mode stays `S_IFLNK | 0o777`.

  This mode stores no header. The identity of an object covers the reduced
  header that "Checksum computation" states, and the dirmeta of a directory
  takes the same reduction. An entry already in that form keeps the identity
  it has in the other modes. Any other entry gets a different identity.

  Observed behavior: a tree holds a 0777 file with a `user.demo` xattr, a 04755
  file, a 0640 file, and a 0777 subdirectory. The tree is committed in
  `bare-user-only` with no ownership options. This commit gives the content,
  dirmeta, and dirtree checksums of a `bare-user` commit of the tree with
  canonical modes and owner 0:0. The 0777 file gets the checksum of the 0755
  file, and the file with the xattr gets the checksum of the same file without
  it. The checksums are the same with and without `--owner-uid`/`--owner-gid`,
  because the mode discards the ownership.

Observed behavior: in `bare-user`, a symlink object stored as a regular file
holds the target bytes followed by one NUL. The `user.ostreemeta` value is
the `(uuua(ayay))` stat form with the uid/gid of the symlink, the mode
`S_IFLNK | 0o777` (`0o120777`), and its xattr set.

Archive `.filez` layout (the framing is in "File content object header"):

- A regular file is the framed archive header `(tuuuusa(ayay))` followed by the
  raw-DEFLATE payload. An empty payload compresses to the two-byte empty
  DEFLATE stream `03 00`.
- A symlink is the framed archive header alone: the target is in field 5 and
  the uncompressed size is 0. No payload byte follows, and there is no empty
  DEFLATE stream.
- The object checksum covers the uncompressed bytes, so the stored compressed
  bytes can differ between writers. For the small fixture payloads, the
  raw-DEFLATE bytes of the port (miniz_oxide) are the bytes of the tool's zlib
  at each level 1-9. `conformance/cli-surface.md`, "P2", records the stored
  lengths over a real tree.
- Golden SHA-256 vectors pin the bytes of the port's encoder
  (`crates/ostrya-core/src/deflate.rs`, `tests`). There is one vector per level
  1-9, over a payload of one and a half output chunks. The nine vectors differ,
  so a change to the map from `[archive] zlib-level` to the encoder parameters
  fails the gate. A tenth vector holds a flush in the middle of a payload. The
  flush ends the DEFLATE block, so the stored bytes change and the object
  checksum does not. The vectors also hold for a sink that `reset` started on a
  new stream. They hold for writes of one byte, of 4093 bytes, and of the
  whole payload, so the write size does not change the stored bytes. The ingest
  path streams through a 64 KiB copy buffer, and one larger buffer given to
  `write_regfile_inline` stores the same bytes.

The fanout directories `objects/<xx>/` are created with the request mode 0777,
which the umask reduces. `objects/` itself is 0775. This is the same in every
mode the tool writes. In `bare-user-shared` the port sets each directory it
creates to 02770 with an `fchmod` after the create, whatever the umask
("bare-user-shared mode").

### Durability and staging

Observed behavior: the tool ingests each object into an unnamed temp file
(`O_TMPFILE` in the staging directory). It then links the file with
`linkat("/proc/self/fd/N", ..., AT_SYMLINK_FOLLOW)`. The keys `[core] fsync`
and `[core] per-object-fsync` set the syncs:

- Default (`fsync=true`, `per-object-fsync=false`): the objects are linked into
  the staging directory under their loose path. Then `syncfs(repo)` runs once.
  Then the tool runs `renameat` on each object into `objects/<xx>/`. Then each
  touched `objects/<xx>` and `objects/` gets an `fsync`.
- `per-object-fsync=true`: the temp file of each content object gets an
  `fsync` at ingest. A metadata object gets no sync at ingest, and neither does
  an object that `pull-local` links from another repository. The
  `syncfs(repo)` and the directory `fsync`s still run at publication.
- `fsync=false`: the tool issues no `syncfs`, `fsync`, or `fdatasync`.

`conformance/cli-behavior.md`, "The fsync vocabulary", gives the command
switches of the two keys and the sync counts.

The port always stages and then renames, and it applies these three rules to
the syncs it issues. At ingest it does not sync an object that it hardlinks
from another repository. It also does not sync a content object that it stores
as a symlink inode (a symlink in `bare` and `bare-user-only`). The `syncfs`
that starts publication makes every staged object durable, metadata included.

A push session that receives objects runs that `syncfs` before it takes the
update lock ("The update lock"). When fsync is on, it then syncs the file of
each metadata object that it stages under the lock. Its publication runs no
second `syncfs`. Every other transaction takes the update lock after
publication ("The update lock").

A pull stages each `.commitmeta` that it copies as a file in the staging
directory, with no sync of its own. At the step that writes detached metadata
and refs, it renames the file into `objects/<xx>/`. When fsync is on, the
`syncfs` that starts publication makes the staged file durable. Where
publication runs no `syncfs`, the step runs one before the rename. After the
renames, the step syncs each fanout directory that gained a `.commitmeta` once,
and `objects/` once if the step created a fanout directory.

Every other `.commitmeta` write, and each `.tombstone-commit` write, creates a
temp file in `tmp/` and renames it into `objects/<xx>/`
(`conformance/cli-surface.md`, "Global conventions"). If `tmp/` is on a
different filesystem from `objects/`, the rename fails with `EXDEV` and the
write fails.

The layout of the staging directory is transient and is not part of the
on-disk format ("Repository lock and staging" gives its place).

## Write path: fs-verity (ex-integrity)

A repository can seal its loose objects with fs-verity when it writes them. A
seal makes the inode immutable and gives the kernel a digest that it enforces
on reads. The object bytes and the checksums do not change. A verity
repository is thus a normal repository whose regular-file objects are sealed.

The keys `fsverity` and `composefs` of the group `[ex-integrity]` set the
policy: `no`, `maybe`, or `yes`. `ostrya-config(1)`, "INTEGRITY KEYS", gives
the keys, their defaults, and the refused values. In the tool, `composefs` also
controls deployments.

The write seals each loose object that is a regular file, in every repository
mode, `archive-z2` included:

- content objects: `.file` (bare family) and `.filez` (archive);
- metadata objects: `.dirtree`, `.dirmeta`, and `.commit`;
- symlink objects stored as regular files: `bare-user`, `bare-user-shared`, and
  `archive` keep the content of a symlink in a regular file, so these objects
  are sealed.

fs-verity applies to regular files, so the write skips the real symlink
objects of `bare` and `bare-user-only`. A deduplicated write (the object is
already in `objects/`) does not touch the object. fs-verity is a property of
the inode, and a seal of a hardlinked object also seals the copy in the source
repository. The port does not hardlink an object that it imports into a
repository whose effective `fsverity` is not `no`. It copies the object and
seals the copy (`conformance/cli-surface.md`, "P2", `pull-local`).

Under `no`, the write seals nothing, and the staging path does not change. On a
filesystem without verity, `FS_IOC_ENABLE_VERITY` returns `ENOTTY`. Under
`maybe`, a commit then completes with unsealed objects. Under `yes`, the write
fails. The tool then reports that fs-verity is required and that the
filesystem does not support it.

`FS_IOC_ENABLE_VERITY` needs write permission on the inode, also through a
read-only descriptor. Without it the kernel returns `EACCES`. A caller with
`CAP_DAC_OVERRIDE` passes the check. For a content object with the logical
mode 0444, 0555, or 0400, the order of the mode and the seal thus decides the
result (`conformance/cli-surface.md`, "P2", `commit`).

The argument of `FS_IOC_ENABLE_VERITY` is `fsverity_enable_arg { version 1,
hash_algorithm 1 (SHA-256), block_size 4096, salt_size 0 }`. It is a 128-byte
struct with the other fields zero. "fs-verity digest" (under "composefs")
gives the digest. The kernel's `FS_IOC_MEASURE_VERITY` result for a sealed
object equals the `FsVerityHasher` digest of the on-disk bytes of that object.
A `.file` outside `archive` holds the raw payload, so its measured digest is
the digest that the composefs export records ("File backing"). An `archive`
`.filez` holds compressed bytes, so its measured digest is a different value.

Observed behavior: the tool writes each object in this order, while the inode
is still an anonymous `O_TMPFILE` staging file:

1. open `O_TMPFILE|O_WRONLY` in the staging directory;
2. write or reflink the payload;
3. apply `fchmod`/`fchown` and the xattrs;
4. reopen the inode read-only through `/proc/self/fd/N`;
5. close the writable descriptor (the kernel refuses `FS_IOC_ENABLE_VERITY`
   while a writable descriptor to the inode is open);
6. `ioctl(ro_fd, FS_IOC_ENABLE_VERITY)`;
7. `linkat` the read-only descriptor into the staging directory.

The tool uses a named temp file where the filesystem refuses `O_TMPFILE`. It
also uses one for the small bodies of symlink and metadata objects that the
caller holds. The
named temp file follows the same close, reopen, and seal steps. The tool then
renames it into place.
Publication into `objects/` does not change.

The port writes a regular-file content object in this order:

1. Before the seal, on the writable descriptor: `user.ostreemeta` in
   `bare-user`, the fixed mode 0644 in `archive`, and the fixed mode 0644 and
   `user.ostreemeta` in `bare-user-shared`. In `bare`, `bare-user`, and
   `bare-user-only`, the port first sets the temp to 0600 if its create mode
   has no owner read or no owner write.
2. The seal, on a read-only reopen, after the writable descriptor closes.
3. After the seal, on the read-only descriptor and before the link:
   - in `bare`: the owner, then the logical xattrs, then the logical mode;
   - in `bare-user` and `bare-user-only`: the canonical mode.

`fork` copies the file descriptor table. A child process thus holds a copy of
the writable staging descriptor until its `exec` closes it. While that copy is
open, the kernel refuses `FS_IOC_ENABLE_VERITY` with `ETXTBSY`, also after the
writer closes its own descriptor. A process that spawns children from one
thread while another thread stages objects meets this window. The port retries
a seal that fails with `ETXTBSY` for up to 50 ms, which is longer than a
fork-to-exec gap. It
reports every other error on the first attempt.

The `FS_IOC_ENABLE_VERITY` ioctl is the one syscall in the write path that
needs `unsafe`. It is in the audited `ostrya-sys` crate. This crate also holds
`FS_IOC_MEASURE_VERITY` and `FS_IOC_READ_VERITY_METADATA` for the read path,
and the read-only memory map that static-delta apply uses.

## Commit modifier: canonical permissions, consume, and devino

The tool's `ostree commit` options shape the tree that a commit ingests. The
port models them as a commit modifier. Two of these options change the object
bytes. The others are ingest mechanics with no effect on disk.

### Canonical permissions

The tool's `--canonical-permissions` option (the port's `CANONICAL_PERMISSIONS`)
sets the owner to 0:0 and reduces each permission set to a canonical form.
Over a filesystem walk, the option records no xattrs. Observed behavior: the
tool records these results. Not observed: the xattrs that the tool records
under the option over a `tar=` source. `conformance/cli-surface.md`, "P2",
`commit`, states the port rule over a `tar=` source.

- uid and gid become 0. The tool refuses a non-zero `--owner-uid`/`--owner-gid`
  together with `--canonical-permissions`, so canonical ingest always owns the
  objects 0:0.
- The permission bits of a regular file or a directory become `perm & 0o755`.
  The owner bits and the group and other read and execute bits stay. The group
  and other write bits, and the setuid, setgid, and sticky bits, are removed.
  For regular files, `0664`, `0666`, `01644`, and `02644` become `0644`.
  `0775`, `0777`, and `04755` become `0755`. `0640`, `0600`, `0644`, `0700`,
  and `0755` do not change. For directories, `0775`, `0777`, and `02755` become
  `0755`, and `0700` does not change.
- The reduction does not change the mode of a symlink. The walk finds a symlink
  at `S_IFLNK | 0o777` and records that. If a `--statoverride` entry for the
  symlink ran first, the symlink keeps the mode that the entry set. This
  includes the bits that the reduction removes from a regular file: `=448 /link`
  gives `l00700` and `2048 /link` gives `l04777`. `conformance/cli-behavior.md`,
  "CLI output formats", `commit`, "The mode modifiers", gives the order of the
  mode modifiers.
- The reduction records the file type that the walk found. `--statoverride` is
  the one modifier that can set file-type bits. When an entry changes the
  file type of a mode, the reduction puts back the type that the walk found.
  Over a 0644 regular file, each of `=4096`, `=16384`, `=40960`, `=49152`, and
  `=32768` beside `--canonical-permissions` gives the same commit, whose
  `/plain.txt` is `-00000`. Over a 0700 directory each of them gives one commit
  whose `/dir1` is `d00000`, and `=33261` gives `d00755`.
- The recorded xattr set is empty. A 0644 file with `user.demo=1` has the
  checksum `a5ee0b1b...` under `--owner-uid=0 --owner-gid=0` and `fe042781...`
  under `--canonical-permissions`. `fe042781...` is the checksum of the same
  file without the xattr under `--owner-uid=0 --owner-gid=0`. The xattr of a
  directory is removed in the same way: the dirmeta is `6c9fefc6...` with the
  xattr and the canonical `446a0ef1...` under the option.

`bare-user-only` applies this ownership, permission, and xattr rule to all that
it records, with or without the option ("Write path: loose-object inode modes
and durability"). The canonical header goes into the file-content header and
the dirmeta. Canonical ingest thus changes the identity of each input entry
that is not already in that form, and with it the dirtree and commit
checksums. Observed behavior: the canonical commit checksum differs from the
checksum of the same tree committed 0:0 without the option.

### Consume

The tool's `--consume` option (the port's `CONSUME`) deletes the source content
after the commit ingests it. Observed behavior: under `--consume base/src`,
the commit deletes each file when it ingests it. It deletes each directory when
its entries are deleted, bottom up. The parent of the walk root stays.
`conformance/cli-behavior.md`, "The tree sources", gives the walk-root rule,
the entries that a walk filter skips, and the failures.

The tool can adopt a source inode by a rename into the object store. It does
so when the inode already has the on-disk form of the target mode and the
source is on the filesystem of the store. The port copies the content and
then unlinks the source. The objects are the same with and without the
adoption.

### Devino cache

The tool's `--link-checkout-speedup` builds a map from `(device, inode)` to
checksum. A source entry that is a hardlink to an object of the repository
then resolves by its inode, and the commit does not read it.
`--devino-canonical` (`-I`, which implies the speedup) takes a resolved object
as the whole identity of the entry. Observed behavior: the tool gives these
results.

- The commit builds the cache from the repository that `--repo` names, at commit
  time, in the process that runs the commit. A checkout from an earlier process
  resolves through it, and no checkout in the same process is necessary. The
  build reads each fanout directory under `objects/` and does a stat of each
  `.file` entry in it. Both options thus cost one pass over the loose content
  objects of the repository before the commit reads a source.
- The key is `(st_dev, st_ino)`. A `cp -al` copy of a checkout resolves. A
  `cp -a` copy of the same tree, with the same modes and content, does not.
- The cache holds that repository alone. A tree hardlinked into the objects of
  repository A and committed into repository B resolves nothing.
- An `archive` repository stores each content object compressed, and no
  checkout hardlinks a `.filez`, so both options do nothing there. The
  decompressed copies of an archive checkout in
  `<repo>/uncompressed-objects-cache` are outside `objects/` and are not in the
  map. The port attaches no commit modifier for an empty cache. Under
  `--link-checkout-speedup` alone the port thus merges a `ref` source with no
  modifier: the merge records the committed checksums and reads no file object.
- A directory never resolves. A symlink resolves where the repository stores
  symlink objects as symlinks and the checkout hardlinked them, that is, in a
  `bare` repository. There `-I --owner-uid=7` keeps the stored ownership of the
  symlink and gives the directories owner 7.
- A resolved entry is taken whole: content and metadata come from the stored
  object, and the commit does not read the file on disk. A rewrite of a
  hardlinked file in place, or a change of its mode, size, or mtime, changes
  nothing for either option.

The two options differ in whether the commit modifiers reach a resolved entry.
Under `--link-checkout-speedup` the stored object supplies the metadata, and
the modifiers apply over it: `--owner-uid`, `--owner-gid`, `--statoverride`,
`--mode-ro-executables`, `--canonical-permissions`, and `--no-xattrs`. Where the
shaped metadata differs from the stored metadata, the commit writes the object
again from the stored payload. Under `-I` the commit takes the object as it is
and skips the filter and the modifiers for that entry. A `--statoverride` or
`--skip-list` entry for a resolved path stays unmatched, and `--owner-uid`
reaches only the entries that resolve nothing. A resolved regular file writes no
content object under `-I`, so `-I` also masks a failure of the content write
(`conformance/cli-surface.md`, "P2", `commit`).

Neither option changes the commit checksum in twelve of the fourteen checkout
variants of `archive`, `bare-user`, and `bare`. The two others are a
`bare-user` checkout with `-U`, with or without `-H`. That checkout hardlinks
the stored objects, which carry the `user.ostreemeta` xattr of the repository.
The plain walk reads this xattr as a real xattr of the source file and commits
it, so each file object and each dirtree changes. There the commit with either
option gives the checksum of the source tree. `--no-xattrs` on the plain walk
gives a third checksum: it drops the xattr and keeps the permission bits of the
inode, `(logical_perm & 0o775) | 0o400`. The xattr payload is `(uuua(ayay))`:
`uid(be32) gid(be32) mode(be32)` and the xattr array, 12 bytes when the array
is empty.

## Extended attributes

The storage form is the GVariant `a(ayay)`: an array of (name bytes, value
bytes). A stored name holds the namespace prefix and one terminating NUL. The
name before the NUL is not empty and holds no NUL. Observed behavior: a file
with a `user.demo` xattr is committed into a `bare-user` repository. In its
`user.ostreemeta` blob, the name bytes `user.demo` are followed by one `\0`.

Canonicalization sorts the names by byte-wise comparison. It runs before each
serialization and each hash. It refuses a duplicate name and a name that is not
in the stored form. "Write path: loose-object inode modes and durability" and
"bare-split-xattrs mode" give the place of the xattrs in each repository mode.

When a commit modifier carries a label callback, the commit removes an existing
`security.selinux` xattr and applies the label that the callback returns. The
checksum thus counts the label once. With no label callback, the commit records
a `security.selinux` xattr read from disk as it is. The port has no SELinux
policy backend (`conformance/cli-surface.md`, "P2", `commit`).

## Static delta wire format

Type strings (verbatim):

```
PART_PAYLOAD_FORMAT_V0  (a(uuu)aa(ayay)ayay)
    modes a(uuu), xattrs aa(ayay), raw-data-source ay, operations ay
META_ENTRY_FORMAT       (uayttay)
    version u, part-checksum ay, size t, usize t, objtype+csum array ay
FALLBACK_FORMAT         (yaytt)
    objtype y, checksum ay, compressed-size t, uncompressed-size t
SUPERBLOCK_FORMAT
    (a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))
    metadata a{sv}, timestamp t (BE), from ay, to ay, to-commit,
    recursion array ay (always empty), meta-entry array, fallback array
SIGNED_FORMAT           (taya{sv})
    magic t (0x4F535453474E4454 "OSTSGNDT"), superblock bytes ay, signatures a{sv}
```

### Part framing

A part file is `(y@ay)` before decompression: one compression byte, then the
body. The byte is 0 for none or `x` for xz (lzma). `x` is the only compression
a writer uses, and a reader accepts 0 and `x` alone.

A `PART_PAYLOAD_FORMAT_V0` payload of `n` bytes ends with three framing offsets
of `z` bytes each. `z` is the offset width of a GVariant container of `n` bytes
(1, 2, 4, or 8). Read from the end, the offsets state the end of the mode
table, of the xattr table, and of the data-source blob. The operation stream
runs from the end of the blob to `n - 3z`.

The mode count is the end of the mode table divided by 12. The blob size is the
end of the blob less the end of the xattr table. The operation size is `n - 3z`
less the end of the blob. The xattr count is 0 for an empty table. For a table
of `x` bytes, take the offset width `w` for `x` bytes. The last `w` bytes of
the table state where its own framing starts, and the count is `x` less that
value, divided by `w`.

A reader that streams the payload reads it to the end to find the framing. Then
it reads again the parts of the tables and the operations that it did not keep.

### Superblock fields

The metadata dict starts with the `ostree.endianness` byte, `l` on a
little-endian host (see "Endianness"). The inline parts follow in part order
(see "Inline parts"). Last, where the target commit has detached metadata, a
copy of it follows under the key `deltas/<fanout>/<rest>/commitmeta`. The key
is the relative directory of the delta with `/commitmeta` appended, and the
value is the `a{sv}` of the `.commitmeta` file. Observed behavior: a tool pull
checks a commit that a delta delivers against this copy. It does not check the
commit against the `.commitmeta` that it fetches and stores.

The tool writes the wall-clock time of the generation as the timestamp, and
`SOURCE_DATE_EPOCH` does not pin it. The port writes the current time unless the
caller gives `DeltaOptions::timestamp`. `from` is an empty `ay` for a
from-scratch delta. The version field of a meta-entry, the delta part version,
is 0. The objtype+csum stride is 33 bytes: 1 objtype byte and 32 checksum bytes.

The `SIGNED_FORMAT` magic is the eight ASCII bytes `OSTSGNDT`:
`0x54444E475354534F` read as a little-endian `t`, and `0x4F535453474E4454` read
big-endian. A superblock file that starts with the magic is a signed envelope.
The `ay` it wraps holds the raw `SUPERBLOCK_FORMAT` bytes, the payload that the
signatures cover. The trailing `a{sv}` holds the signatures under the key of
each engine, for example `ostree.sign.ed25519 -> aay`, as in commit and summary
signing. An unsigned delta stores the raw `SUPERBLOCK_FORMAT` bytes.

### Inline parts

`static-delta generate --inline` puts each part into the metadata dict, under
the key `deltas/<fanout>/<rest>/<i>`. The key is the relative directory of the
delta with the part number appended. The value is a `(yay)` variant that holds
the exact bytes of the part file, the compression byte and the body. The `size`
of the meta-entry is the length of these bytes. Under `--filename` the key is
also the repository-relative name. The tool writes no part file, at the
repository location and under `--filename`.

The parts are in insertion order with no string sort: `/0` to `/12` over a
13-part delta. An inline part applies also where a part file of the same number
is present. Observed behavior: the tool applies an inline superblock beside a
`0` file of arbitrary bytes at exit 0, and its `fsck` passes. The tool pulls an
inline delta over HTTP and requests the superblock alone.

The port reads an inline part in `apply-offline`, in a pull, and in `show`. It
checks the part against the size and the checksum of its meta-entry before it
decompresses it. It refuses a value under a part key that is not a `(yay)`
variant. An inline superblock is as large as its parts, and the port reads and
writes a superblock of 128 MiB at most (`conformance/cli-surface.md`, "P2",
`static-delta`).

### Object delivery

The superblock embeds the target commit object whole, in the
`(a{sv}aya(say)sstayay)` field. No part carries it, and its serialization
hashes to the `to` checksum. A part produces each other object, except a
fallback object. The meta-entry of a part carries the ordered objtype+csum
array. The operation stream produces the objects in that order. The object type
at the current position selects how an operation decodes.

The `part-checksum` is the SHA-256 of the part file on disk, the `(y@ay)`
framing bytes. A fallback object travels outside the parts as a plain loose
object. A reader takes the fallback array as the superblock lists it, with no
threshold. An offline application requires each fallback object to be present
already. `conformance/cli-surface.md`, "P2", `static-delta`, records the limits
of the tool's `apply-offline`.

A delta of the port can also list the composefs image of the target commit,
the object type 100, in the object array of a part or in the fallback array.
The tool writes no such entry. "The composefs image in a static delta" states
the rules.

### Fallback selection

The generator makes an object a fallback when its compared size is at least the
threshold of `--min-fallback-size`. It puts the object into a part otherwise.
The unit is the decimal megabyte, 1,000,000 bytes. The default is 4, so the
default threshold is 4,000,000 bytes. An object whose size equals the threshold
is a fallback. The value is read as a whole number of megabytes, and 0 turns
fallbacks off. The composefs image that a delta of the port carries has a
selection rule of its own, and an inline delta lists the image as a fallback
always ("The composefs image in a static delta").

Observed behavior: over a commit that holds one 5,000,000-byte object,
`--min-fallback-size=0.1` reports `Number of fallback entries: 0`, and
`--min-fallback-size=1` reports 1. `--min-fallback-size=0` packs the object:
`PartMeta0: nobjects=3 size=5000405 usize=5000055`.

The compared size is the file header variant of the object, plus seven bytes,
plus the content. The seven bytes are the same for each header shape. Thus the
offset table of the header counts, and the constant does not change with the
header size. The on-disk content-stream framing is eight bytes, a big-endian
`u32` length and four NUL bytes. This is one more than the count compared here.

Observed behavior: at a 4,000,000-byte threshold, 3,999,974 bytes of content is
packed and 3,999,975 is a fallback. The overhead, the threshold less 3,999,975,
is 25 bytes. This is the 18-byte header of a `uid=gid=0` regular file with no
xattr, plus 7. The same offset holds at other thresholds, for example 2,000,000.
At a 1,000,000-byte threshold the switch points are 999,974/999,975 for the same
18-byte header, an overhead of 25. They are 999,953/999,954 for a file with one
8-byte xattr and a 39-byte header, an overhead of 46. They are 999,658/999,659
for a file with a 300-byte xattr, an overhead of 341: its 334-byte header
crosses the GVariant offset-width boundary.

The port compares the same size (`FALLBACK_FRAMING` in `deltagen.rs`). The test
`the_fallback_threshold_classifies_an_object_as_the_tool_does` compares the
fallback count of the two generators on the two sides of the boundary.

The compressed size of a fallback entry is the on-disk size of the loose object
in the source repository. The uncompressed size is the content size alone, with
no header. Observed behavior: for a 5,000,000-byte object in an archive
repository, the entry states 5,001,564 bytes (the size of the `.filez` file)
and 5,000,000.

### Part meta-entry sizes

The generator of the tool leaves the target of a symlink and the file header out
of `usize`. `usize` is the uncompressed payload of the part, summed over its
objects. A metadata object adds its serialized length, and a regular file its
content length. The generator of the port also counts the target length of each
symlink (`conformance/cli-surface.md`, "P2", `static-delta generate`). `size` is
the on-disk byte size of the part file, compression byte included. It is the
length that the part checksum covers, and the field that bounds a part.

For a part of splices alone, the `usize` of the tool is the size of the
data-source blob less the symlink targets in it. For a rollsum or bspatch part
this is not true, because the blob holds patch streams. Observed behavior: a
from-scratch part of a 300,000-byte file, a 6-byte file, a 1-byte symlink
target, and two metadata objects reports `usize=300129` and `blobsize=300130`. A
part with one 8,192-byte file and its one-entry dirtree (41 bytes, with dirmeta
12) reports `usize=8233`. A part of two 1,000,000-byte splices reports
`usize=2000000`.

The `usize` of the tool is less than the size of the part payload. Observed
behavior: a from-scratch part of three files (8,192, 20,000 and 6 bytes), one
symlink, and three metadata objects reports `usize=28453`. Its payload
decompresses to 28,531 bytes. These are the data-source blob (28,462, which
holds the 9-byte symlink target), the operation stream (38), the mode table
(24), the xattr table, and the tuple framing.

### Part packing

The tool starts a new part where the next object pushes the payload past
`--max-chunk-size`, in decimal megabytes, default 32 (32,000,000 bytes).
Metadata objects come before content objects. Observed behavior:
`--max-chunk-size=2` over five 1,000,000-byte objects gives payloads of
1,000,218 (the two metadata objects and one file), 2,000,000, and 2,000,000. A
meta-entry names the contents of its part, so a delta applies with any part
boundaries, and the boundaries change its size alone. The part boundaries of
the port are in `conformance/cli-surface.md`, "P2", `static-delta generate`.

### Diff-source pairing

The tool pairs a modified content object with the object at the same path in
the source commit. A file that was renamed and edited is not paired
(`modified: 0`) and travels whole. The tool also skips the pair when the two
sizes differ by a large ratio. For a pair, the tool uses rollsum chunking where
chunking finds any shared chunk, and bsdiff only where chunking finds nothing.

Observed behavior: a 40,000-byte object pairs after it grows to 40,800 or
56,000 bytes. It does not pair after it grows to 59,600 or shrinks to 26,800.
An 8,192-byte object whose chunking matches 1,133 bytes uses rollsum. A
1,024-byte object with a small edit uses bsdiff.
`conformance/cli-surface.md`, "P2", `static-delta generate`, records the
pairing of the port.

### Opcodes

The opcodes are ASCII bytes: `S` open-splice-and-close, `o` open, `w` write,
`r` set-read-source, `R` unset-read-source, `c` close, `B` bspatch. The
operands are LEB128 varints. An offset is an absolute byte offset into the
raw-data-source blob of the part. The exception is the offset of a `w` while a
read source is set (between `r` and `R`), which reads the read-source object.
The `c` (close) opcode takes no operand and asserts that the SHA-256 of the
produced object equals the expected checksum.
The operands, as the tool writes them:

- `S` for a metadata object (dirtree/dirmeta): `(length, offset)`. It splices
  `length` bytes at `offset` in the data source as the serialized object, and
  closes it.
- `S` for a content object (file/symlink):
  `(mode-index, xattr-index, length, offset)`. The mode and xattr tables supply
  the metadata of the object. A symlink (mode `S_IFLNK`) takes the spliced
  bytes as its target, and a regular file as its content.
- `S` for the composefs image, the object type 100 of the port: `(length,
  offset)`, as for a metadata object. The image travels in one `S` alone, and
  the port refuses an `o` for it.
- `o` (open) for a content object: `(mode-index, xattr-index, output-size)`.
- `r` (set-read-source): `(offset)`. The 32 bytes at `offset` in the data
  source are the checksum of a source object. The content of that object is the
  read source for the next `B` or `w` operations.
- `R` (unset-read-source): no operand.
- `B` (bspatch): `(stream-offset, stream-length)`. The bspatch stream is
  `stream-length` bytes at `stream-offset`, which is the preceding `r` offset
  plus 32. It applies against the read source to fill the open object, and `c`
  then closes it.
- `w` (write, rollsum): `(length, offset)`. It appends `length` bytes to the
  open object, read at `offset` in the current source. The current source is
  the read-source object when a preceding `r` set one, and the data source of
  the part otherwise. The output is written forward only, so the destination is
  the implicit output cursor, and only the read offset is carried. A `w` with a
  read source set copies an unchanged content-defined chunk out of the source
  object. A `w` with no read source writes a changed run from the payload.

The tool emits `w` for from->to deltas of larger objects. The stream of a
rollsum object is `o`, then `r`/`w`.../`R` groups interleaved with payload `w`
operations, then `c`. The tool emits one `r`/`R` pair for each contiguous run
that it copies out of a source object. An object made from scattered runs thus
names the same source checksum once for each run. Example: a 4 MiB object with
forty scattered 512-byte edits carries 41 `r` operations and 41 `R` operations
against one source object.

The embedded bspatch stream is in the bsdiff patch format, with its three
streams interleaved and stored uncompressed. xz compresses the enclosing part as
a whole. The stream is a sequence of blocks, read until the output reaches the
size of the opened object. Each block holds a 24-byte control block, then
`diff-length` bytes, then `extra-length` verbatim bytes. The control block is
three signed 64-bit integers in bsdiff `offtin` sign-magnitude little-endian
encoding: `diff-length`, `extra-length`, and the source `seek`. Each
`diff-length` byte is added, with wrap, to the source byte at the current source
position. After the block, the source position advances by `diff-length` and
then by `seek`.

### Endianness

The `t` size fields of the meta-entries and the fallbacks are in host byte
order. The `ostree.endianness` byte (`l`/`B`) in the superblock metadata states
that order. Where the byte is missing, the tool finds the order with a
size-ratio heuristic. The superblock timestamp and the `(uuu)` mode triple are
always big-endian, whatever the byte states.

Under `B` the tool swaps four size fields: the `size` and `usize` of a
meta-entry, and the two sizes of a fallback. Nothing else changes. Observed
behavior: a delta generated with `--set-endianness=B` over a 5,000,000-byte
fallback object holds 5,001,564 and 5,000,000 as big-endian `u64` values.
`static-delta show` prints 5001564 and 5000000. The `l` and the `B`
superblock of one delta differ in the endianness byte and in the four fields,
each byte-reversed. The timestamp and part `0` of the two deltas are
the same.

The port's generator writes the byte and swaps the same four fields under
`DeltaEndianness::Big`. An application reads one of the four, the `size` of a
meta-entry, as the ceiling a part is read under. `static-delta show` reads all
four, and the port swaps each where the byte states `B`, and reads it as
little-endian otherwise (`conformance/cli-surface.md`, "P2", `static-delta`).
No other read depends on the byte, so a big-endian delta applies through the
same path. An application reads the parts by name and checks the SHA-256 of
each. The modes
have a fixed big-endian form, and the embedded commit is normal-form
little-endian.

## Signing details

The signing engines share one framing for commits and summaries. The signed
payload of a commit is the canonical serialized commit GVariant bytes. These
are the bytes of the normal-form commit object, which hash to the commit
checksum. The signed payload of a summary is the raw byte content of the
`summary` file, read as opaque bytes. GPG and the sign-api engines are
independent, and both can sign one commit.

A signature is one `ay` element, appended to the `aay` of its engine in the
`a{sv}` dict. The value of each signature key is thus an append-only array of
signature blobs:

- `ostree.gpgsigs` -- OpenPGP detached-signature blobs over the commit bytes.
- `ostree.sign.ed25519` -- raw 64-byte ed25519 signatures.
- `ostree.sign.spki` -- SPKI signatures: ECDSA over P-256 or P-384, Ed25519,
  or RSA PKCS#1 v1.5. The tool carries this engine only in a build with
  OpenSSL.
- `ostree.sign.dummy` -- the test engine.

### Signing sequence

A signature that a commit write produces stands before the ref that names the
commit. The writer stages the tree and the commit object, then produces each
signature that the invocation asks for. Then it publishes the staged objects
into `objects/`, writes the `.commitmeta` beside the commit, and last writes
the ref. If a signature cannot be produced, no object goes into `objects/` and
no `.commitmeta` is written. The ref stays where it was, so a run that names
several keys is all or nothing. If the ref write fails, the commit and its
`.commitmeta` stay durable, and no ref points at them.

### Detached-metadata key order

The keys of the `a{sv}` dict keep the order in which the writer stored them.
`ostree show --list-detached-metadata-keys` sorts them. The port stores
insertion order. A `commit` inserts in a fixed order, whatever the command
line: the detached-metadata keys of the caller in command-line order, then
`ostree.sign.<type>`, then `ostree.gpgsigs`. The stored order carries no
meaning, because each reader looks up keys by name. The order the tool stores
is in `conformance/cli-surface.md`, "P2", `commit`.

A detached-metadata key replaces the whole dict stored for a commit checksum. A
signature appends to the dict that stands at that moment. Two commits of one
checksum with one signing key each thus leave two elements in the array of the
engine. A run with a detached-metadata key and a signing key writes the caller
key over the stored dict. Then it appends the signature to the new dict, and a
signature of an earlier run is lost. A run that skips its write (an unchanged
tree under `--skip-if-unchanged`) signs nothing and leaves the dict as it is.

### ed25519

The public key is 32 bytes, and the signature is 64 bytes. The secret key is 64
bytes: the 32-byte seed, then the 32-byte public key. A key is given as a
base64 string or as raw `ay`, and a key file holds one base64 key per line. The
system key directories are `/etc/ostree` and `<datadir>/ostree`. They hold the
files `trusted.ed25519` and `trusted.ed25519.d/`, plus `revoked.ed25519` and
`revoked.ed25519.d/`. The effective trusted set is the trusted set minus the
revoked set, so a key in both sets is refused.

### spki

The signature key is `ostree.sign.spki`. The data is the commit bytes of the
other engines. The key type selects the algorithm and the signature form:

- P-256: ECDSA over NIST P-256 with SHA-256. The signature is DER-encoded
  ECDSA: an ASN.1 `SEQUENCE` of the two integers `r` and `s`, about 70 to 72
  bytes. The port signs with RFC 6979 nonces.
- P-384: ECDSA over NIST P-384 with SHA-256, the digest of P-256. The
  signature is DER-encoded ECDSA in the form of P-256, about 102 to 104
  bytes. The port signs the SHA-256 of the data with RFC 6979
  nonces that HMAC-SHA-384 makes from this hash, so its signatures differ
  from the RFC 6979 test vectors for P-384 with SHA-256.
- Ed25519: pure Ed25519 of RFC 8032, with no prehash and no context. The key
  signs the data itself. The signature is 64 bytes, `R || S`, and the form
  is deterministic. The ed25519 engine writes the same bytes for the same
  seed and the same data, under the key `ostree.sign.ed25519`.
- RSA: RSASSA-PKCS1-v1_5 with SHA-256. The signature is the raw signature, an
  unsigned big-endian integer with the length of the modulus in bytes, for
  example 256 bytes for a 2048-bit key. The signature form is deterministic.

The port gives the same signature bytes for one key and one data.

A signature blob carries no key type. A trusted key tries a blob only when the
blob parses in the signature form of the key type. For a P-256 or a P-384
key, the form is DER, and the parse is strict: a blob with bytes after the
`SEQUENCE`, and a blob with a length that does not agree with its content, do
not parse. Each of the two integers must fit the field of the curve of the
key, 32 bytes for P-256 and 48 bytes for P-384. So a P-384 key also tries a
DER blob whose integers fit 32 bytes, such as the signature of a P-256 key.
This verify fails, and the result does not change. An Ed25519 key tries a
blob of 64 bytes, and no other blob. It checks `[S]B = R + [k]A` with no
cofactor, refuses an `S` that is not below the group order, and accepts a
public key of small order. An RSA key tries a blob
whose length is the length of its modulus, and no other blob. A store can hold keys of each type together. A blob
is valid only when a trusted key verifies it. A blob that no trusted key
verifies is not valid. It is not an error, because the commit can carry other
signatures. The fixed-width `r || s` form of a valid signature, 64 bytes for
P-256 and 96 bytes for P-384, a
signature by a key of another type, and random bytes are such blobs.

A public key is the X.509 SubjectPublicKeyInfo DER, the base64 body of a PEM
`PUBLIC KEY` block. The EC point in it is compressed (first byte `02` or
`03`) or uncompressed (first byte `04`). The port refuses each other point
form, such as the compact form (first byte `05`). A raw SEC1 point is not a
public key. The key of an Ed25519 SubjectPublicKeyInfo is 32 bytes that must
decode to a point on the curve. The port also accepts the encodings that
RFC 8032 refuses: a y coordinate that is not below p, and x = 0 with the sign
bit set. The port keeps the 32 bytes as they are given. The key of an RSA
SubjectPublicKeyInfo is a PKCS#1 `RSAPublicKey` DER, the modulus and the
public exponent.

A secret key is one of these forms:

- a PKCS#8 `PrivateKeyInfo` DER;
- a SEC1 `ECPrivateKey` DER with a `parameters` field that names the P-256
  or the P-384 curve;
- a PKCS#1 `RSAPrivateKey` DER. A PKCS#1 key is RSA.

The port tells the three forms apart by their ASN.1 structure. Each form is
a `SEQUENCE` that starts with an `INTEGER` version. After the version, a
PKCS#8 key holds an `AlgorithmIdentifier`, a PKCS#1 key holds the modulus,
an `INTEGER`, and a SEC1 key holds the secret scalar in an `OCTET STRING`.
The version of a PKCS#1 key is 0 for two primes and 1 for more primes. A raw
32-byte scalar is refused.

An Ed25519 secret key is a PKCS#8 key alone. Its `privateKey` `OCTET STRING`
holds an `OCTET STRING` of the 32-byte seed. A key of version 1, with the
`version` 0, holds no public key. A key of version 2, with the `version` 1,
holds the public key of the seed in its `[1]` field. Both forms give the
same key and the same signatures. The port refuses a key of version 2 whose
public key is not the public key of the seed, by a compare of the 32 bytes.
It refuses a key of version 1 with a public key, a key of version 2 with no
public key, a bare seed in the `privateKey` field, and a seed that is not 32
bytes. A raw 32-byte seed, the `OCTET STRING` of the seed alone, and the
64-byte secret key of the ed25519 engine are in no accepted form.

The `privateKey` `OCTET STRING` of a SEC1 key holds the secret scalar as an
unsigned big-endian integer. It can be shorter than the field size of the
curve, 32 bytes for P-256 and 48 bytes for P-384. The port reads a shorter
scalar with zero bytes on the left, as the tool does. The port refuses a
scalar of fewer than 24 bytes and a scalar longer than the field size. The
`publicKey` field can be absent. When it is present, it holds the point of
the scalar. The `ECPrivateKey` in a PKCS#8 key follows the same rules.

The algorithm OID of a SubjectPublicKeyInfo or of a PKCS#8 key selects the key
type. For an EC key, the curve OID in the `parameters` field of the
`AlgorithmIdentifier` selects the curve. The engine takes these key types:

- `id-ecPublicKey` (1.2.840.10045.2.1) on the curve `prime256v1`
  (1.2.840.10045.3.1.7);
- `id-ecPublicKey` on the curve `secp384r1` (1.3.132.0.34);
- `id-Ed25519` (1.3.101.112) with no `parameters` field;
- `rsaEncryption` (1.2.840.113549.1.1.1) with `NULL` parameters, with a
  modulus of 2048 to 16384 bits. The secret key has two primes. The public
  key of a key of more primes is a modulus and an exponent, and the engine
  takes it.

The port refuses these keys:

- a key of another type, for example RSASSA-PSS (1.2.840.113549.1.1.10) or
  Ed448 (1.3.101.113);
- a key of a type that the build has no code for. A build has the code for
  P-256 with the feature `sign-spki-p256`, for P-384 with the feature
  `sign-spki-p384`, for Ed25519 with the feature `sign-spki-ed25519`, and for
  RSA with the feature `sign-spki-rsa`;
- an `id-Ed25519` key with a `parameters` field, for example a `NULL`, in a
  SubjectPublicKeyInfo and in a PKCS#8 key;
- an `rsaEncryption` key with no `parameters` field, or with a value other
  than `NULL` in it;
- an RSA key with a modulus of fewer than 2048 bits or more than 16384 bits;
- an RSA secret key of more than two primes, in PKCS#8 and in PKCS#1 form;
- an EC key on another curve, for example P-521 (1.3.132.0.35);
- an EC key with no curve OID, or with a `NULL` in the `parameters` field;
- an EC key with explicit curve parameters, a `SEQUENCE` in the place of the
  curve OID. This applies to a SubjectPublicKeyInfo, to the
  `AlgorithmIdentifier` of a PKCS#8 key, to the `ECPrivateKey` in a PKCS#8
  key, and to a SEC1 key;
- a SEC1 key with no `parameters` field, a SEC1 key whose `parameters` field
  holds a value that is not a curve, such as a `NULL`, and a SEC1 key whose
  `parameters` field names another curve. The version of a SEC1 key is 1;
  a structure with another version is in no accepted form;
- a PKCS#8 key whose `ECPrivateKey` has a `parameters` field that names a
  curve other than the curve of its `AlgorithmIdentifier`, or that holds a
  value that is not a curve. The
  `ECPrivateKey` in a PKCS#8 key can have no `parameters` field.

A key file, an inline key, or a file of the key store that holds one such key
is refused whole, also when other keys in it are valid. A file of revoked keys
that holds a key of a type that the build has no code for is refused, so the
revocation fails closed.

The key store has the layout of the ed25519 store: `trusted.spki`,
`revoked.spki`, and their `.d` directories under `/etc/ostree` and
`<datadir>/ostree`. Its effective trusted set is also the trusted set minus
the revoked set. The port compares a trusted key with a revoked key by the
decoded key: it encodes the SubjectPublicKeyInfo DER of each key again, with
an uncompressed EC point, with no parameters and the 32 bytes of an Ed25519
key, or with `NULL` parameters and the modulus and the exponent of an RSA
key, and compares these bytes. So the compressed and the uncompressed form of
one key match, and two RSA keys of one modulus and one exponent match. The
DER of an Ed25519 key holds the 32 bytes of the key as they were given. The
port does not encode the point again, so two encodings of one point, such as
a canonical encoding and an encoding with a y coordinate of p or more, do
not match. The fingerprint of a verified signature is the SHA-256 of the
same DER.

An inline secret key, as a positional key of `sign` or the value of a
`--sign`, is the base64 of the secret key DER. The base64 text can hold the
line breaks of a PEM body, LF or CRLF: the reader removes each space,
horizontal tab, LF, form feed, and CR, then decodes the text. The decode
removes each `=` at the end of the text, so the padding is optional, and more
`=` than the padding is accepted. The decode does not check the unused low bits
of the last character. It refuses an `=` at another position, one character
after the last full group of four, and each other character outside the base64
alphabet. The base64 of the full PEM text, with its `-----BEGIN` line, is
refused.

An inline public key, as a positional key of a verify or
`verification-spki-key`, is the base64 of the SubjectPublicKeyInfo DER, also
with the line breaks of a PEM body. In the config file, a line break of
`verification-spki-key` is the escape `\n`. The base64 of the full PEM text,
the base64 of a raw SEC1 point, and the base64 of a secret key are refused.

A public key file holds PEM `PUBLIC KEY` blocks, and each block holds one
SubjectPublicKeyInfo DER. These files are public key files: each file of the
key store, a `--keys-file` of a verify, and `verification-spki-file`. The
rules of a public key file:

- A line ends at LF. One CR at the end of a line is removed, so CRLF line
  ends are read. A CR at another position is a byte of the line.
- The reader removes the leading and trailing spaces and tabs of a line, then
  compares the line with a boundary. A block starts at the line
  `-----BEGIN LABEL-----` and stops at the line `-----END LABEL-----`, where
  `LABEL` is not empty. A line with other text is not a boundary line.
- Text outside the blocks is ignored. The text can hold any byte. A stray END
  line and a line of base64 text outside a block are also ignored.
- A body line is not empty and holds no CR. The crate `pem-rfc7468` decodes
  the body in the form of RFC 7468: lines of 64 base64 characters, the last
  line shorter or equal, and no headers.
- An empty file, or a file of white space only, holds no key. White space is
  space, horizontal tab, LF, form feed, and CR.

The reader refuses the whole file, also when other blocks of the file are
valid, in these conditions:

- A block has a label other than `PUBLIC KEY`. The label compare is exact and
  case-sensitive.
- An END line has a label other than the label of its block.
- A BEGIN line is in a block.
- A block has no END line. A file with CR line ends only is one line, so it
  has no END line.
- A `PUBLIC KEY` block does not decode, or it holds no public key of the
  engine.
- The file is not empty or white space, and holds no block. A file of base64
  lines is in this group.

A refused file of the key store fails the verify, also a file of the revoked
set. `conformance/cli-surface.md`, "P2", `static-delta`, records the
differences from the tool.

A secret key file holds PEM `PRIVATE KEY` blocks, and each block holds one
PKCS#8 `PrivateKeyInfo` DER of a P-256, a P-384, an Ed25519, or an RSA key. Each block
gives one signer, in the order of the file. These files are secret key files: a `--keys-file` of
`sign`, of `summary`, and of `remote summary -u`, a `--sign-from-file` of
`commit` under `--sign-type=spki`, and the `secret-key-file` of an
`[ex-ostrya key]` group of type `spki`. A `--sign-from-file` file holds one
block. `commit` refuses a file of more than one block, and makes no
signature. The reader reads a regular file alone,
of at most 1 MiB. The lines, the boundary lines, the text outside the blocks,
and the block bodies follow the rules of a public key file. The reader refuses
the whole file, also when other blocks of the file are valid, in these
conditions:

- The file is empty, holds white space only, or holds no block. A file of
  base64 lines is in this group.
- A block has a label other than `PRIVATE KEY`. `EC PRIVATE KEY`,
  `RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, and `PUBLIC KEY` are such
  labels.
- An END line has a label other than the label of its block, a BEGIN line is
  in a block, or a block has no END line.
- A `PRIVATE KEY` block does not decode, or it holds no PKCS#8 key that the
  engine takes. A SEC1 DER, a PKCS#1 DER, and a raw scalar in a
  `PRIVATE KEY` block are refused.

A command reads each secret key file before it makes the first signature, so
a refused file gives no signature.

A `--keys-file` of `static-delta generate` under `--sign-type=spki` holds one
secret key on each line, the base64 of a PKCS#8 DER, of a SEC1 DER that
names the P-256 or the P-384 curve, or of a PKCS#1 DER. A line ends at LF, and one CR at the end of a line is
removed. The last line can have no line end. The reader decodes each line
strictly. It refuses the whole file if the file is empty, if a line is empty,
if a line holds white space, or if a line is not the base64 of a secret key.
Each line gives one signer, in the order of the file, after the signers of
`--sign`. Each `--keys-file` adds its signers.

Observed behavior: the spki signatures are checked against the `ostree`
command in both directions, for ECDSA P-256, ECDSA P-384, Ed25519, and RSA.
The port verifies the signatures of a commit, a summary, and a static delta
that the tool wrote. The tool verifies the signatures of a commit, a summary,
and a static delta that the port wrote. The fixtures are in
`tests/fixtures/spki/`. The curve, the hash, the DER signature encoding, and
the key DER containers are the standard OpenSSL and RFC forms. The RSA
signature and the RSA key structures are those of RFC 8017. The Ed25519
signature is that of RFC 8032, and the Ed25519 key structures are those of
RFC 8410.

### GPG

The signature key is `ostree.gpgsigs`. Each `ay` element is one detached
OpenPGP signature: the binary signature packet stream, with no armor. A blob
can hold more than one signature packet, and each packet is verified
independently. The port signs through the system GnuPG installation
(`gpg --detach-sign`, driven over the machine-readable `--status-fd`
interface). It verifies in the process with the `pgp` crate (rPGP). The stored
blobs are thus the OpenPGP interchange form that GnuPG produces and reads.

A signature is valid only where it verifies against a trusted key whose
bindings hold. A signature by an expired, revoked, or unknown key is invalid.
Trust is membership in the given keyrings, and the ownertrust model of GnuPG
has no part in it. The result of each signature states the fingerprints of the
signing key and of the primary key, and the creation and expiry timestamps. It
also states the expiry time of the key when it has passed, and the expired,
revoked, and missing flags. Last, it states the names of the public-key and
digest algorithms, and the user id of the signer, split into name and email.

A GPG keyring is binary or ASCII-armored and holds one or more certificates.
All keyrings merge into one trusted set. Where the set holds several
certificates for one key, it keeps each of them. The verdict reads each
certificate that answers for the issuer of a signature, whatever the load order
of the keyrings:

- A revocation in any of them refuses the signature.
- Two exports of one certificate are read as one certificate. The key expiry
  that the newest self-signature of either export states applies.
- Across certificates with different primary keys, the key expires at the
  earliest instant that any of them states.

A self-signature whose own expiration time has passed states no key expiry,
binds no subkey, and ranks no user id. The first certificate that answers
supplies the reported fingerprints and user id.

The keyring trusted for a remote is `<remote>.trustedkeys.gpg` in the repo or
under `/etc/ostree/remotes.d/`. Each `*.gpg` keyring in the global
trusted-keyring directory is trusted for all remotes. That directory is
`<datadir>/ostree/trusted.gpg.d/` (`/usr/share/ostree/trusted.gpg.d/`). The
`OSTREE_GPG_HOME` environment variable replaces it with the directory that it
names.

Observed behavior: the `--gpg-sign` signature of each implementation verifies
through `show --gpg-verify-remote` of the other, with the exported public
keyring on the remote. All four pairings pass (conformance record
`commit/gpg-sign-round-trip`).

### Dummy engine

The dummy engine is for tests only. Its signature key is `ostree.sign.dummy`,
with the value type `aay`. The tool signs with the engine when the
`OSTREE_DUMMY_SIGN_ENABLED` environment variable is set. With the variable
unset, `commit` and `summary -u` refuse `--sign-type=dummy` with "dummy
signature type is only for ostree testing". With the variable unset,
`static-delta apply-offline --sign-type=dummy` applies a delta at exit 0.
`static-delta verify --sign-type=dummy` reports `Verification fails` at exit 1,
with the reason `no signature for 'ostree.sign.dummy' in static-delta
superblock` (`conformance/cli-surface.md`, "P2", `static-delta`).

A dummy signature is the raw bytes of the key identifier, and the secret key
and the public key are the same byte string. Signing appends these bytes as one
`ay` signature blob and ignores the signed payload. Verification succeeds when
a stored signature blob equals a trusted public-key byte string. Observed
behavior: `ostree sign --sign-type=dummy COMMIT KEY-ID` with the key
`mysecretkey` stores a blob of exactly the 11 ASCII bytes `mysecretkey`, with
no trailing NUL, for each commit.

## composefs

`ostree` built with composefs exports the tree of a commit to an EROFS image in
the composefs format (EROFS, format version 0). The deployed image has the file
name `.ostree.cfs`. The commit metadata stores the fs-verity digest of the
image under `ostree.composefs.digest.v0` (type `ay`, 32 bytes), and the target
machine verifies it at boot. Thus the port must write the image byte-for-byte.

The EROFS and composefs projects define the EROFS and composefs formats. The
golden images come from `ostree` built with composefs 1.0.8, and they are the
byte contract ("Golden fixtures"). The subsections that follow describe what
these images hold.

### Export path

`ostree checkout --composefs COMMIT DESTINATION` writes the image at
DESTINATION. `--composefs-noverity` writes the same structure without the
fs-verity digests of the files. `ostree commit --generate-composefs-metadata`
stores the digest of the image in the commit ("fs-verity digest").

The image depends on the commit tree alone. The `ostree.composefs.digest.v0` key
and the repository mode change no byte of it. Each composefs switch exports from
every repository mode. The file backing is the same in every mode ("File
backing"). Observed behavior: one tree committed into `archive`, `bare`, and
`bare-user` gives one commit checksum, one digest, and under each switch one
image. `bare-user-only` canonicalizes the tree, so it gives another commit and
another digest. A `bare-split-xattrs` repository exports the same image (see
"bare-split-xattrs mode").

The image file at the destination has mode 0644, whatever the process umask
and whatever mode an earlier file at the destination held.
`conformance/cli-surface.md`, "P2", `checkout`, records the temporary file
that each side writes the image through.

### fs-verity digest

The digest is fs-verity with SHA-256, 4096-byte blocks, and a zero-length salt.
`composefs-info measure-file <image>` reports it. A commit records the digest
of the verity image, which `--composefs` writes. The noverity image has its own
digest, and no commit records it. For the golden fixture (the deterministic
source tree) the recorded digest is
`c91bad0285efab4453562cadf7a22f2dc3714dee81dbe002ded71318e18384d9`.

The digest is a Merkle tree over the data:

- Each 4096-byte block is hashed with SHA-256. The final block is zero-padded
  to 4096 bytes.
- The block hashes are concatenated and grouped into 4096-byte parent blocks
  (128 SHA-256 hashes per block, the tail parent zero-padded). The parent
  blocks are hashed again, up to a single root hash.
- For data of one block or less, the root is the hash of that block. For empty
  data, the root is all zero.

The digest is the SHA-256 of a 256-byte little-endian descriptor:

- version byte 1, hash-algorithm byte 1 (SHA-256), log2-block-size byte 12,
  salt-size byte 0;
- 4 reserved bytes 0;
- data size, 8 bytes, the byte length of the data;
- the 32-byte root hash, followed by 32 zero bytes (the root-hash field is 64
  bytes wide);
- 32 zero salt bytes;
- 144 reserved bytes 0.

### Injected top-level directories

The image root holds the entries of the commit and five empty directories that
the tool injects: `boot`, `etc`, `sysroot`, `usr`, and `var`. Each has mode
040755 and owner 0:0. The commit tree does not hold them (`ostree ls` does not
list them), and every exported image holds them.

### Image layout and the composefs header

The image is composefs format version 0. Bytes 0..1024 hold a 32-byte composefs
header, zero-padded to 1024:

- magic, 4 bytes, `9a 62 78 d0` (little-endian `0xD078629A`);
- version 1, 4 bytes;
- flags, 4 bytes, `0x00000001` when any inode carries a POSIX ACL xattr and 0
  otherwise;
- composefs version 0, 4 bytes;
- 16 reserved bytes 0.

The regions follow in this order:

1. the composefs header and its padding;
2. the EROFS superblock;
3. the inode table;
4. the shared-xattr area;
5. the directory and file data blocks.

A node id is the byte offset divided by 32.

### EROFS superblock

The superblock is at byte offset 1024 and is 128 bytes. Its fields:

- magic, 4 bytes, `e2 e1 f5 e0` (little-endian `0xE0F5E1E2`);
- checksum 0 (unused);
- feature_compat `0x06` (MTIME `0x02` and XATTR_FILTER `0x04`);
- blkszbits 12 (block size 4096), extra superblock slots 0;
- root_nid, the node id of the root inode;
- inos, the total inode count, the overlay whiteout stubs included;
- build_time and build-time nanoseconds, the minimum inode mtime. For an
  exported commit this is 0, because every inode mtime is 0;
- blocks, the image size in 4096-byte blocks;
- meta_blkaddr 0, xattr_blkaddr the block that holds the shared-xattr area
  (the block that contains the end of the inode table);
- UUID all zero.

The zero UUID and the zero build times make the image deterministic for a fixed
input tree and composefs version.

### Inodes

The writer collects the inodes breadth-first from the root. The root comes
first, then the children of each directory in name-sorted order. The children of
one directory come before those of the next. The `i_ino` field is the collection
index (root 0). The inodes are written in that order, so the node id increases
with `i_ino`.

An inode is compact (32 bytes) when its mtime equals the superblock build_time,
its nlink and ownership fit 16 bits, and its size fits 32 bits. Otherwise it is
extended (64 bytes). An exported commit uses compact inodes throughout, unless
an id is more than 16 bits or a file is more than 4 GiB. The low bit of the
format field selects compact (0) or extended (1). Bits 1..3 hold the datalayout:
0 flat-plain, 2 flat-inline, 4 chunk-based, which puts 0, 4, or 8 into the
format field. The inode mode is the EROFS file-type bits combined with the
logical permission bits.

A directory inode is flat-inline when its entries leave an inline tail
("Directory blocks and dirents") after zero or more whole blocks. It is
flat-plain when the entries are all in whole blocks and leave no inline tail.
An empty regular file is flat-plain with size 0. A symlink is flat-inline with
the target stored inline. A whiteout stub is a character device, flat-plain,
with `i_u` 0.

The target of a symlink shares the block of its inode with the inode header
and the extended attributes of the inode. The header, the attributes, and the
target together stay less than 4096 bytes, so the target is at most 4095 bytes
less those two. A header is 32 bytes, or 64 bytes for an inode that the compact
form does not hold. Thus a target with no attributes holds at most 4063 bytes.
At 4064 bytes the header and the target first fill a block. No image holds a
symlink target outside the block of its inode.

No export writes an image for a tree with a longer target. Observed behavior:
the tool writes the image at 4063 bytes and writes nothing at 4064 and 4095
bytes. `conformance/cli-surface.md`, "P2", `checkout`, records how each side
fails. `PATH_MAX` is 4096, so a checkout produces no tree that reaches the
bound. A tar import can produce one.

### Overlay whiteout table

The image writer adds a 256-entry overlay whiteout table to the root. It is one
character-device inode for each two-digit lowercase hex name `00` through
`ff`. Each inode has device 0:0 and mode 0644, the owner of the root, and the
mtime of the root.
The writer skips a name that the root already holds. It also sets
`trusted.overlay.opaque` to `y` on the root. `composefs-info dump` hides these
entries, so `tree.dump` does not show them. They are inodes and entries of the
root directory in the image, and the superblock `inos` counts them.

### Directory blocks and dirents

The entries of a directory are `.` (the directory), `..` (the parent), and the
children. They are sorted together by name as raw bytes. The port sorts a child
name that starts with a byte less than `0x2E` before `.`. Not observed: the
order that the tool gives such a name.

The entries are packed into 4096-byte blocks. Whole blocks are written as data
blocks. A tail of 2048 bytes or less is stored inline after the inode, and a
larger tail gets its own data block. The size of a directory is the byte count
of its whole blocks plus the inline tail. Its nlink is the count of entries of
directory type, which is 2 plus the number of child subdirectories.

In a block, the fixed-size dirent headers come first, then the names with no
separators. Each dirent header is 12 bytes:

- node id, 8 bytes;
- name offset in the block, 2 bytes;
- file type, 1 byte (1 regular, 2 directory, 3 character device, 7 symlink);
- 1 reserved byte.

The name offset of the first dirent divided by 12 gives the entry count.

A child name is at most 255 bytes. The bound holds for a regular file, a
directory, a symlink, and an entry in a subdirectory. Each composefs switch and
`commit --generate-composefs-metadata` refuse a longer name and write no image,
no commit, and no ref (`conformance/cli-surface.md`, "P2", `checkout`). At 255
bytes the port image is byte-identical to the tool image. The object store holds
a longer name: `fsck`, `ls`, and a plain `commit` take such a tree. A Linux
filesystem stores no name of more than 255 bytes, so a checkout produces no tree
that reaches the bound. A tar import can produce one, from a pax `path` record.

`composefs-info ls` refuses an image that holds a name of 256 bytes or more
with `File name too long`. `composefs-info ls` and `composefs-info dump` refuse
an image that holds an empty child name: each exits 1 on `Failed to load
'<image>': Invalid argument`.

### Inode extended attributes and the name filter

The xattr area of an inode follows the inode header. It is present only when
the inode has at least one xattr:

- a 12-byte header: a 4-byte name filter, a shared-count byte, 7 reserved bytes;
- shared-xattr references, 4 bytes each;
- inline entries, sorted by full name, then by value length, then by value
  bytes.

`i_xattr_icount` encodes the area size: 0 when the area is absent, otherwise
`1 + (size - 12) / 4`. Each inline entry is a 4-byte header (name-length byte,
name-index byte, 2-byte value size), then the name suffix, then the value,
padded to a 4-byte boundary. The value size is 2 bytes, so an entry holds at
most 65535 bytes of value. The name length is 1 byte, so an entry holds at most
255 bytes of name suffix.

An xattr, name and value together, that more than one inode holds moves to the
shared-xattr area after the inode table. The inode holds a reference in place
of the inline entry. An inode holds at most 128 shared-xattr references. The
writer takes the repeated attributes of the inode in ascending full-key order.
It stops when the inode holds 128 of them, and the rest stay inline. The key
decides the order, and the repeat count does not. The shared table holds every
repeated entry, also an entry that no inode references.

In a `--composefs-noverity` export, the empty `trusted.overlay.metacopy` value
repeats across the backed inodes. It sorts before `user.`, so it takes one of
the 128 references. The `tree-rich` pair holds the case ("Golden fixtures").

Observed behavior: two files that carry the same 10, 100, 127, 128, 129, 200,
or 256 attributes, and three trees that set key order against repeat count,
follow these rules in the tool image. The port writes the image bytes of the
tool for `tree-rich.cfs` and `tree-rich-noverity.cfs` ("Golden fixtures").

The tool holds the attributes of an inode to a budget that is smaller than the
limit of the value field. Each attribute spends its full name, its value, and 7
bytes from a budget of 32755 bytes for the inode. The budget counts the full
name, prefix included: `system.posix_acl_access` spends 22 bytes of name. A
regular file has the same budget as a directory. The `trusted.overlay.redirect`
and `trusted.overlay.metacopy` attributes that the export adds to a backed inode
are outside the budget. Past the budget, an export writes no image and a commit
records no digest (`conformance/cli-surface.md`, "P2", `checkout`). At the
budget, the tool and the port write the same image. Observed behavior: the tool
holds to this budget in each of these cases:

- one attribute with a name of 6, 8, 37, or 200 bytes;
- 2, 3, 8, and 100 attributes;
- a directory and a regular file.

The budget does not bind the name-length field: 255 bytes of name fit in 32755
bytes. The port holds the full name, prefix included, to 255 bytes and refuses
a longer name, so it writes no field behind a truncated length. Not observed:
the tool with an attribute name of more than 255 bytes. The kernel caps an
attribute name at 255 bytes. A Linux filesystem thus stores no attribute name
of more than 255 bytes.

A name is stored as a prefix index and the remaining suffix. The prefixes are: 0
empty (full name in the suffix), 1 `user.`, 2 `system.posix_acl_access`, 3
`system.posix_acl_default`, 4 `trusted.`, 6 `security.`. The version-0 prefix
table has no index 5 (`lustre.`), so a `lustre.` name uses prefix 0. The writer
uses the longest matching prefix. A name that begins with `trusted.overlay.` is
escaped to `trusted.overlay.overlay.` before indexing.

The name filter is a 32-bit Bloom filter over the xattr names of the inode.
Each name sets the bit `xxh32(suffix, seed) % 32`, where `suffix` is the name
after its prefix and `seed` is `0x25BBE08F` plus the prefix index. The stored
word is the bitwise complement of the filter, so a cleared bit means that the
name is present.

### File backing

A regular file with content is backed by a bare loose object, through overlay
xattrs (name index 4, the `trusted.` prefix). The inode is chunk-based. The
datalayout is 4 (format-field value 8), the size is the logical file size, and
`i_u` holds the chunk format derived from the size. The inline data is one
4-byte chunk index of `0xffffffff` per chunk. The chunk size is the file size
rounded up to a power of two, at least 4096 bytes and at most 2^43 bytes. Thus
a file of up to 8 TiB has one chunk. The xattrs are:

- `trusted.overlay.redirect`, the loose path of the backing object with a
  leading slash, `/<xx>/<rest>.file`, in every repository mode (for example
  `/cf/ffd52f38d14c87cf46e18d5260074421ba5961f0895954e9921f165f9c91db.file`);
- `trusted.overlay.metacopy`. In the verity image it is a 36-byte record. The
  record holds version byte 0, length byte 36, flags byte 0, and
  digest-algorithm byte 1 (SHA-256). Then it holds the 32-byte fs-verity digest
  of the content payload of the backing object, in every repository mode,
  `archive` included. The digest
  parameters are those of "fs-verity digest".
  `composefs-info measure-file <object>.file` reports the same 32 bytes. In the
  noverity image it is a zero-length value on every backed file.

The sharing rule of "Inode extended attributes and the name filter" applies to
the metacopy value. A verity record is common to the files with identical
content and stays local otherwise. Thus the verity image of a tree of distinct
file contents carries one record per backed inode. The one empty value is common
to every backed file, so a tree with two or more backed files shares it. The
sharing changes the offsets of the inodes and of the xattr areas.
`composefs-info dump` prints the digest column as `-` for a file in the noverity
image.

An empty regular file carries no overlay xattrs and has no backing object. A
symlink stores its target inline (mode 0120777) and has no redirect.
`composefs-info objects <image>` lists exactly the backing `.file` paths, one
per distinct redirected content object.

### Golden fixtures

`tests/fixtures/generated/composefs/` holds four images, each with its
`composefs-info dump` text:

- `tree.cfs` and `tree.dump`: the verity image of the deterministic source
  tree. The MANIFEST records `composefs_commit` (the commit made with
  `--generate-composefs-metadata`) and `composefs_digest` (the digest of the
  image that the commit records, "fs-verity digest").
- `tree-noverity.cfs` and `tree-noverity.dump`: the same commit exported with
  `checkout --composefs-noverity`. The MANIFEST records
  `composefs_noverity_digest`, the fs-verity digest of this image.
- `tree-rich.cfs` and `tree-rich.dump`: a second verity image, of a source tree
  that carries user xattrs. The dump shows the xattrs as trailing `name=value`
  tokens. Its commit is made without `--no-xattrs`, so it is generated on a
  host that applies no SELinux labels. The MANIFEST records
  `composefs_rich_commit` and `composefs_rich_digest`.
- `tree-rich-noverity.cfs` and `tree-rich-noverity.dump`: the noverity export of
  that tree. The MANIFEST records `composefs_rich_noverity_digest`.

The rich tree holds:

- shared-xattr promotion (`user.shared` on six inodes) and inline xattrs;
- an inode past the 128-reference cap (`user.m000` through `user.m149` on both
  files under `manyshared/`);
- a multi-block directory with an inline dirent tail;
- xattr values of varied length;
- a 4063-byte inline symlink, the longest target of an inode with no
  attributes.

The two pairs hold the two cases of the metacopy sharing rule:

- The mixed case. `tree-rich.cfs` carries 314 backed inodes over eleven
  distinct verity records. Two records are shared, by 300 inodes and by 5, and
  nine are local to one inode each. All 314 inodes reference the one empty
  value in `tree-rich-noverity.cfs`. Thus the nine local records move into the
  shared area, and the shared area holds one metacopy entry in place of two.
- The plain case. `tree.cfs` has two local records and no shared metacopy
  entry. `tree-noverity.cfs` has one shared entry and no local one.

## tar

`ostree export` writes a plain filesystem tar of the tree of a commit. The
stream embeds no repository objects. The "ostree-in-tar" OCI format is a
separate `ostree-ext` (Rust) construct and is out of scope here.

Tar is a transport interface. Its contract is interoperability and round-trip
stability: GNU tar and the `ostree` tool read what the port writes, and the
port reads what they write. The bytes of the stream are outside the contract
(`conformance/cli-surface.md`, "P2", `export`).

Observed behavior: the stream of `ostree export` has these properties.

- The archive is old-GNU-format tar. The header magic field at offset 257 is
  `ustar\x20\x20\x00` (`ustar`, two spaces, and a NUL). The POSIX form is
  `ustar\x00` and the version `00`.
- The tree root is the member `./`. Each other member is a bare relative path
  with no `./` prefix. A directory member has a trailing slash.
- uid and gid are numeric. The octal mode field holds the permission bits
  alone, and the tar typeflag gives the type.
- Each member other than a hardlink member has the commit timestamp as its
  mtime, with a zero nanosecond part. Not observed: the mtime, the mode, and
  the owner in the header of a hardlink member.
- Identical content becomes hardlinks. The first member for a content object
  is written in full (typeflag `0`). A later member with the same content is a
  hardlink (typeflag `1`), and its link name is the first member. A symlink is
  typeflag `2`, with the target in the link name.
- The stream holds no PAX extended header and no xattr. A file that carries a
  `user.demo` xattr, committed without `--no-xattrs`, gives no `SCHILY.xattr.*`
  record in any encoding.
- On standard output the stream is padded up to a multiple of 10240 bytes,
  more than the two trailing zero blocks that POSIX requires. 8192 bytes of
  members give 10240 bytes, and 41472 bytes of members give 51200. A `-o`
  destination holds the members and the two zero blocks alone, with no record
  padding: the same two archives give 9216 and 42496 bytes. The shorter stream
  is the longer one with fewer trailing NUL bytes.
- In a directory, the non-directory entries come first in name order, then the
  subdirectories in name order. The members of each subdirectory follow it. The
  first member that the walk reaches for a content object is the one written
  in full.

`conformance/cli-behavior.md`, "The tar export options", states the four
options that shape this stream.

`Repo::export_tar` writes POSIX ustar and pax through the `smol-tar` writer. It
uses the member naming of `ostree export` (`./` root, bare relative names, a
trailing slash on a directory), numeric ownership, and the commit timestamp as
the mtime. It writes a regular file as a hardlink when an earlier member has
the same content checksum. It never writes a symlink as a hardlink. A hardlink
member header carries mtime 0, mode 0, and owner 0:0.

The export writes each extended attribute of an entry as a `SCHILY.xattr.<name>`
PAX record with the exact value bytes. Thus an xattr-bearing tree survives an
export and an import. The record drops the terminating NUL of a stored xattr
name, and the import adds it again. The `ostree` tool imports a port export into
a byte-identical tree (the same dirtree and dirmeta objects).

`TarExportOptions` carries `subpath`, `prefix`, and `skip_xattrs`.
`skip_xattrs` drops every xattr record. The CLI adds `-o`.
`conformance/cli-surface.md`, "P2", `export`, records where the stream and the
option values of the port part from the tool.

`ostree commit --tree=tar=FILE` commits an arbitrary filesystem tar into the
repository. It resolves the hardlinks at the end of the import, and it can
apply the `/etc` -> `/usr/etc` convention.

### The tar import

The import name of a member drops one leading `./` and one leading `/`. A
directory member keeps its trailing `/`. The root member of the archive (`./`,
or `/` before the strip) gets the empty string. `--tar-pathname-filter` receives
this name, and the import places the member by it.

The import places each member under the directory that the tree already holds.
An earlier member of the same archive or an earlier source in the list can
create this directory. A member whose parent directory is absent is refused
with `error: No such file or directory: <name>`. The name is the own name of
the first absent ancestor. The tree root is not one of these ancestors. An
archive with no root member supplies no root metadata.
`conformance/cli-behavior.md`, "The tree sources", states when the commit then
refuses.

Each member records the numeric ownership of its header. It also records the low
12 bits of its octal mode field, `mode & 0o7777`, under the file type that the
typeflag states. The import drops the higher bits, so a mode field that holds a
full `st_mode` records the permission part alone: `0120777` gives `0777`,
`0100644` gives `0644`, and `0040755` gives `0755`. The setuid, setgid, and
sticky bits are kept.

A symlink member follows the same rule. Its mode is the permission bits of the
header under `S_IFLNK`: header mode `0000` gives `l00000`, `0600` gives
`l00600`, `0755` gives `l00755`, `04777` gives `l04777`, and `07777` gives
`l07777`. GNU tar writes `0777` for every symlink member it packs, so an
archive from that writer carries that one value. The import reads the old-GNU,
ustar, and pax header forms alike: one archive written in the three formats
commits to one tree checksum. `--canonical-permissions` leaves the mode of a
symlink as the member set it, as the filesystem walk does, so each of these
values stays unchanged.

`Repo::import_tar_into` follows each rule of this section. It reads into a
tree that an earlier source filled. So one archive composes with a filesystem
source and with a committed tree under one modifier.
`TarImportOptions::owner_uid` and `owner_gid` also set the owner of a parent
that the import creates and of the created root. `ostrya commit --owner-uid`
goes through the commit modifier and leaves these fields unset. The import
refuses a device node and a FIFO member, because a tree stores regular files,
symlinks, and directories alone.

## bare-split-xattrs mode

The public documentation states that this mode stores the xattrs as separate
repository objects and does not reflect them to the filesystem. The mode serves
transport through lossy environments (tar streams, containers). It carries
security-sensitive xattrs (SELinux labels) out of band.

The `ostree` tool reads this mode and refuses a commit into it
(`Writing content object: Not allowed due to repo mode`). The port reads this
mode and does not write it. Observed behavior: `ostree fsck`, `ostree ls -X`,
and `ostree checkout` accept the layout of this section and reproduce the
xattrs. The tool exports a composefs image from it, and the port writes the same
image (`ostrya::read_split_xattrs::composefs_export_matches_the_tool`).

The object identity is the same as in every other mode:
`SHA256(6-field header ‖ payload)`. The header
`(uid, gid, mode, rdev=0, symlink-target, xattrs)` carries the logical xattrs.
The split changes the storage alone.

Storage:

- `.file`: bare inode storage. A regular file holds the raw payload on an inode
  with the logical uid, gid, and mode. A symlink is a real symlink. The inode
  carries no xattrs, and there is no `user.ostreemeta`. The inode carries the
  uid, gid, and mode of the identity. So a write that keeps the identity on the
  inode needs the ownership that the identity encodes, as with `bare`.
- `.file-xattrs`: the GVariant `a(ayay)` xattr array in normal form, the same
  bytes that the identity header embeds. Its name is the `SHA256` of these
  bytes. The empty set serializes to zero bytes, so its shared object is named
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  (`SHA256` of the empty input).
- `.file-xattrs-link`: a hardlink to the `.file-xattrs` object of the file,
  named by the `.file` checksum. Each `.file` has one, symlinks and files with
  no xattrs included, which link to the shared empty-set object. The link is
  mandatory: a missing link is a corrupt repository, and a reader treats its
  absence as a format error. Observed behavior: over an otherwise
  self-consistent commit with the link removed, `ostree fsck` marks the commit
  partial and fails (`Repository corruption encountered`). `ostree ls -X` fails
  to open the object.

A read recovers the uid, gid, mode, and kind from the inode, and the xattrs
from the bytes at `<file-checksum>.file-xattrs-link`, parsed as `a(ayay)`. A
read of the bytes at the link name needs no knowledge of the hardlink topology.

# Port extensions

This part specifies the formats and the protocols that the port alone writes
or speaks. The `ostree` tool has none of them. A run of the port and a check of
the bytes on the wire or on disk can verify each fact.

The part holds these items:

- the config keys of the port;
- the related commits of a commit and the rules of the local prune;
- the ref patterns of the client groups and of the ref listing;
- the push protocol and the pull protocol, over HTTP and over a byte stream;
- the ref listing;
- the summaries of the auth items and the access digest;
- the endpoints of `ostrya serve`;
- the credential file of a push over HTTP;
- the ssh transport;
- the commit of `push-tree`;
- the composefs image object;
- the protocol of the composefs mount daemon;
- the mode `bare-user-shared`;
- the S3 bucket repository.

The push protocol, the pull protocol, and the protocol of the mount daemon
each have a version number. All three versions are 1. The numbers are
separate, and each one changes on its own.
Over HTTP, the paths `/_ostrya/receive/v1/` and `/_ostrya/refs/v1` hold the
version. The pull over HTTP sends no version message.

## Configuration keys of the port

The `[ex-ostrya]` group, the server group, the client groups, the trust
groups, the key groups, and eight keys of a `[remote "NAME"]` group are
extensions of the port. The eight keys are `push-url`, `ssh-command`,
`receive-command`, `push-token-file`, `push-user`, `pull-url`,
`send-command`, and `trust`. The `ostree` tool defines none of them and reads
none.
`ostrya-config(1)` states each key, its type, its default, its precedence,
each refusal, and the operations that read it. "EXTENSION KEYS" and "CLIENT
AND SERVER GROUPS" state the groups, and "REMOTE KEYS" states the keys of a
remote. "The push token file of a client" states the grammar of the file that
`push-token-file` names.

The receive path of a server reads the client groups, the server group, the
trust groups, and the key groups from `<repo>/config`. It also reads
`[ex-ostrya] keep-detached-related` and `[core] auto-update-summary` from
`<repo>/config`. A pull from a remote with the key `trust` reads the one trust
group that the key names. A pull with `PullOptions::trust_group`, which
`ostrya pull-local --trust=NAME` sets, reads the one trust group that the
field names, and does not read the key `trust`.

The tool gives a quote no meaning in a group name, so the port splits the name
of a group itself. The server group has the exact name `ex-ostrya server`. The
name of each other group starts with one of the literal prefixes
`ex-ostrya client "`, `ex-ostrya trust "`, and `ex-ostrya key "`, with one
space between the words. After the prefix, the quoted part and a `"` end the
name. The port refuses each other group name that starts with `ex-ostrya `,
and it refuses `[ex-ostrya receive]` and `[ex-ostrya receive "PATTERN"]` with a
message that names `[ex-ostrya client "NAME"]`. `ostrya-config(1)`, "CLIENT AND
SERVER GROUPS", states the refusals of a group name. "Ref patterns" states the
grammar of a pattern of an allow item and of a deny item.

No key changes the encoding or the checksum of an object.
`keep-detached-related` and the key `sign` of a client group change the bytes
of a `.commitmeta` file. The commit checksum does not cover detached
metadata, so these keys change no commit checksum.

Observed behavior: the tool keeps the `[ex-ostrya]` group and the groups
whose names start with `ex-ostrya `, and ignores them.

- `commit` and `prune --refs-only` exit 0 and act as they do without the
  groups.
- `refs`, `fsck`, and `summary -u` exit 0 and write nothing to standard error.
  `summary -u` writes `summary`.
- `config get` (dotted and with `--group`), `config set`, `remote list`, and
  `remote list -u` exit 0. `config get` prints a value as written, for example
  the list `app.roots;app.other;`. `config set` keeps each group and its keys in
  order. `remote list` shows no such group as a remote.
- Dotted `config get` splits `GROUP.KEY` at the first `.`
  (`conformance/cli-behavior.md`, "`config get`"). So
  `config --group=GROUP get KEY` reads a key of a group whose pattern holds a
  `.`.

Observed behavior: the tool keeps the push and pull keys of a remote, and
ignores them. The keys form three sets:

- the ssh push keys: `push-url`, `ssh-command`, and `receive-command`;
- the token keys: `push-user` and `push-token-file`;
- the pull keys: `pull-url` in the ssh form or the scp form, and
  `send-command`.

In each observation, the remote also has an HTTP `url`:

- With each set, `remote list -u` and `remote show-url` print the `url`.
  `config get` prints each key as written. `config set` rewrites `config` and
  keeps the keys in order. Each of these commands exits 0.
- With the token keys or the pull keys, `config set` also keeps the keys as
  written. `pull` fetches the commit from `url`, and `fsck` then passes. With
  the pull keys, `remote refs` and `remote summary` also exit 0. No command
  writes a diagnostic to standard error.
- With the token keys, no system call of `remote list -u`, `remote show-url`,
  or `pull` names the token file.
- With the pull keys, no system call of `remote list -u`, `remote show-url`,
  or `pull` names the ssh address or the `send-command` value. The pull runs
  no other program.

Observed behavior: the tool keeps the remote key `trust` and ignores it. A
`pull` from a `file://` URL and a `pull-local --remote=NAME` import an
unsigned commit with `trust=grp`, with and without the group
`[ex-ostrya trust "grp"]`, and with `trust=` (`conformance/cli-behavior.md`,
"Signature verification during a pull").

`conformance/cli-surface.md`, "P2", `pull`, records how the tool and the port
treat a remote with `pull-url` and no `url`, and an ssh address in `url`.
`conformance/cli-behavior.md`, "`remote`", states how `remote list -u` stops
at a remote with no `url`.

## Related commits

A commit names its related commits in two fields. Each field is an `a(say)`
array. Each entry is a name and the 32 raw bytes of the checksum of a commit.

- Field 2 of the commit object holds the dependencies ("Commit --
  `(a{sv}aya(say)sstayay)`"). The commit checksum and each signature of the
  commit cover the field.
- The key `ostrya.related` of the detached metadata (`.commitmeta`) holds the
  build sources. The value is a variant of type `a(say)`. The commit checksum
  does not cover the key, so a build source can be added after the commit.

The name of an entry has the form `<class>/<name>` by convention, for example
`container/fe`, `boot/uki`, or `layer/base`. Each write of the port refuses an
empty name and checks nothing else in the name.

A defective related value is an `ostrya.related` value that is not a variant
of type `a(say)`, or an entry of either field with an empty name or with a
checksum that is not 32 bytes. For a transfer, a field 2 entry that names a
nested dependency is defective too. A nested dependency is a dependency whose
own field 2 is not empty.

### Dependencies

A dependency names no dependency: the relation is one level deep. The commit
write of the port sorts the entries by name in byte order. It refuses two
entries with one name, a dependency that the repository or the writing
transaction does not hold, a dependency that is partial, and a dependency
whose own field 2 is not empty. A dependency can have a parent and build
sources.

### Build sources

The add of a build source (`Repo::add_detached_related` and
`Transaction::add_detached_related`) edits the first `ostrya.related` entry
of the dict:

- It replaces the element with the same name, or adds a new element.
- It sorts the elements by name in byte order.
- If the dict has no such entry, it appends one after the other entries. If
  the commit has no detached metadata, it writes a dict with the one entry.
- Each other entry of the dict stays as it is.

The add checks the format of the new element alone: a name that is not empty
and a checksum of 32 bytes. It does not check that the repository holds the
named commit. If the stored value of the first entry is defective, the add
refuses it, and the `.commitmeta` file stays as it was. A build source can
name build sources of its own, so the add can make a cycle.

`Repo::write_commit_detached_metadata`, and the commit of a transaction for a
dict that `Transaction::set_commit_detached_metadata` queued, check each
`ostrya.related` entry of the dict, also a second entry with the key. A
defective value fails the write with `Error::InvalidRelated`, and the write
changes no file. The check accepts elements that are not sorted, two
elements with one name, and a checksum of a commit that the repository does
not hold. A signature, a pull, and a receive store a dict with no check of
the key.

A reader of the build sources reads the first `ostrya.related` entry of the
dict.

### The switch of the destination

`[ex-ostrya] keep-detached-related` is a boolean with the default `true`. If
it is `false`, each transfer that writes into the repository drops
`ostrya.related` from each detached metadata dict that it stores:

- a pull from a remote, also through a static delta;
- a local pull;
- a receive: the push session and the one-way stream;
- a push to a bucket repository.

The repository that stores the dict reads its own switch. A push to a bucket
reads the key from the `config` of the bucket. The sender has no option for
the key. A distribution repository sets `false`.

Under `false`, the transfer parses each `.commitmeta` that it stores, so a
`.commitmeta` that is not an `a{sv}` dict fails the transfer.

A pull, also a local pull and a pull through a static delta, and a push to a
bucket replace the whole stored `.commitmeta` with the dict that the switch
leaves. So a stored `ostrya.related` value stays only if that dict is empty. If
`ostrya.related` is the only key of a dict, the transfer writes nothing for the
commit, and the destination keeps the `.commitmeta` that it holds. A receive
merges the incoming dict into the stored dict, so a stored `ostrya.related`
value stays.

A local write ignores the switch and stores `ostrya.related`: a commit write,
`Repo::write_commit_detached_metadata`, the commit of a transaction,
`Repo::add_detached_related`, `Transaction::add_detached_related`, and a
signature. The host entries of the receive hooks are local writes of the
server, and the switch does not apply to them. The offline apply of a static
delta writes no detached metadata, so the switch does not apply to it.

A value that is not a boolean fails each transfer that reads it before the
transfer writes an object or a ref. A pull fails before its first request,
and a receive fails at `Hello` with `internal`. A push to a bucket fails
before it uploads an object or a ref file, and changes nothing in the bucket
but the probe key of the writer lock ("The config of a bucket repository").

### The local prune

`ostrya prune` and `Repo::prune` keep the related commits of each commit
that they reach:

- The prune reads both fields of each commit that the walk reaches. It walks
  each commit that they name as a root of its own, at the global bound of the
  run: `--depth`, or `--keep-younger-than`.
- The prune reads the two fields of each related commit too. So it keeps the
  dependencies of a dependency and the build sources of a build source. The
  walk reads the fields of each commit one time, so a cycle ends the walk.
- A related entry that names a commit that the repository does not hold
  gives no error, and the walk reads nothing below it. The prune keeps the
  name of that commit, as it keeps the name of an absent parent within the
  bound. So the prune keeps the `.commitmeta` and the `.cfs` of that commit
  if the store holds them.
- The prune accepts field 2 entries that are not sorted, two entries with one
  name, and a dependency whose own field 2 is not empty. It roots on each
  such entry.
- A defective related value gives one warning for each defective entry, or
  one warning for a defective `ostrya.related` value. The defective entry or
  value roots nothing, and the other entries of the field root as usual. The
  text of a warning is `related commits in <field> of commit <checksum>:
  <reason>`, where `<field>` is `field 2` or `ostrya.related`. `ostrya prune`
  writes each warning on standard error after `warning: `, and exits 0.
- The prune reads the two fields also if each commit in the store is a root,
  so a run without `--refs-only` gives the same warnings.
- A `.commitmeta` that does not parse as an `a{sv}` dict, or that is larger
  than the size cap of a metadata object, fails the prune. The prune then
  deletes nothing.

The prune of a bucket repository reads field 2 alone ("The prune of a
bucket repository").

The `ostree` command keeps no commit for an entry of field 2
(`conformance/cli-behavior.md`, "Related commits in a prune").

### Dependencies in a pull from a remote

A pull from a remote follows the dependencies of each commit that it reads:
each target and each parent that the depth of the pull takes, also a commit
that the repository holds complete. These rules apply to a pull over HTTP,
over ssh, and from an `s3://` address, to a pull through a session of the
caller, and to a pull of collection refs:

- The pull fetches each dependency at depth 0, so a dependency entry adds no
  parent to the pull. The pull fetches a dependency one time, also if several
  commits name it. A prune of the destination accepts the parents that the
  pull did not fetch, as after a pull with a small depth.
- The pull writes no ref for a dependency.
- The signature policy of the pull applies to each dependency. The pull makes
  no ref-binding check, no collection-binding check, and no timestamp check
  on a dependency.
- For a dependency that the repository holds complete, the pull requests the
  `.commitmeta` and checks the signatures. It requests no object of the tree.
  A dependency that the repository holds partial gets its whole tree, and the
  pull removes its `.commitpartial` marker.
- A localcache repository can supply a dependency.
- A dependency entry adds no static delta to the pull, also if the pull
  requires static deltas. The pull fetches the objects of a dependency loose,
  unless a static delta of the pull delivers that commit.
- The pull does not follow a build source.
- A commit-only pull and a pull with subpaths fetch no dependency.

The pull checks the format of field 2 of each commit that it reads. A
commit-only pull and a pull with subpaths check it too. A defective related
value in field 2 fails the pull: an entry with an empty name, an entry with a
checksum that is not 32 bytes, and an entry that names a nested dependency. A
dependency that neither the repository, a localcache repository, nor the
remote holds fails the pull too. This is also true for a parent that none of
them holds, if a commit of the pull names it as a dependency. A failure of the
pull writes no object and no ref, and leaves no `.commitpartial` marker that
the pull wrote.

The pull of the `ostree` command fetches no dependency
(`conformance/cli-behavior.md`, "Related commits in a pull").

### Dependencies in a local pull

A local pull follows the dependencies of each commit that it walks: each
target and each parent that the depth of the pull takes, also a commit that
the repository holds complete. It also follows the dependencies of each
intermediate commit of a chain of static deltas. Discovery reads field 2 of
such a commit from the superblock of its step. These rules apply to a pull of
refs and to a pull of collection refs:

- The pull imports each dependency at depth 0, so a dependency entry adds no
  parent to the pull. The pull imports a dependency one time, also if
  several commits name it.
- The pull writes no ref for a dependency.
- The signature policy of the pull applies to each dependency. The pull makes
  no ref-binding check on a dependency.
- The pull reads the commit object of a dependency from the source, then
  from each localcache repository, then from the repository. It reads no
  commit object of a dependency that a chain of static deltas makes.
- For a dependency that the repository holds complete, the pull checks the
  signatures and walks no tree. A dependency that the repository holds
  partial gets the walk of its whole tree, and the pull removes its
  `.commitpartial` marker.
- A dependency entry adds no static delta to the pull, also if the pull
  requires static deltas. The pull imports the objects of a dependency loose,
  unless a chain of static deltas of the pull makes that commit.
- The pull does not follow a build source.
- A commit-only pull imports no dependency.

The pull checks the format of field 2 of each commit that it walks, and of
each commit of a chain of static deltas. A commit-only pull checks it too. A
defective related value in field 2 fails the pull: an entry with an empty
name, an entry with a checksum that is not 32 bytes, and an entry that names
a nested dependency. A dependency that neither a source nor the repository
holds fails the pull too. This is also true for a parent that the source does
not hold, if a commit of the pull names it as a dependency. The pull finds
each of these failures before its transaction opens, so it writes no object,
no ref, and no `.commitpartial` marker.

The `pull-local` command of `ostree` imports no dependency
(`conformance/cli-behavior.md`, "Related commits in a pull").

### Dependencies in a push

A push follows the dependencies of each commit that it offers: each source
commit and each history commit of the offer. These rules apply to a push over
ssh and over HTTP, to a push over the streams of the caller, and to a push to
a bucket repository:

- The push sends each dependency at depth 0, so a dependency entry adds no
  parent to the push. The push offers a dependency one time, also if several
  commits name it. A prune of the server accepts the parents that the push
  did not send, as after a push with a small depth.
- The push writes no ref for a dependency.
- The push makes no ref-binding check and no collection-binding check on a
  dependency.
- A dependency is an offered commit for each other rule. For a dependency
  that the server lacks, the push sends the commit object, the objects of
  its tree, its composefs image, and its `.commitmeta`. The push walks no
  tree of a dependency that the server holds. A dependency that a bucket
  repository holds with a partial-commit marker gets the walk of its whole
  tree, and the push deletes the marker.
- The push does not follow a build source. `ostrya.related` goes with the
  `.commitmeta` of its commit.

The push checks the format of field 2 of each commit of its walk: each source
commit, and each parent that the depth takes, or each parent of the local
chain with no depth. This is also true for a history commit that the push
does not offer. A defective related value in field 2 refuses the push: an
entry with an empty name, an entry with a checksum that is not 32 bytes, and
an entry that names a nested dependency. A dependency whose own field 2 is
not empty is nested, also if that field 2 holds a defective entry. A
dependency that the local repository does not hold, or marks partial,
refuses the push too. This is also true for a parent that ends a chain, if a
commit of the push names it as a dependency.

With a depth, the push finds each of these failures before it writes a byte
or sends a request. With no depth, the push finds the failures of the
dependencies of the history commits after the cut at the tip of the
destination ref: after `HelloReply` in a session, and under the writer lock
of a bucket repository. The push then sends no object. A session ends with
`Abort`, and a push to a bucket repository uploads nothing and releases the
lock. The push reads no dependency of a history commit that it does not
offer.

`ostrya push --onto` and `ostrya push-tree` send no dependency. The field 2 of
a server commit is empty ("Server commit").

The server checks the dependencies of the commits that it stages, and applies
its signature rules to them ("Commit and CommitReply", checks 6, 8, and 9).

### Dependencies in a one-way stream

An ostrya sender of a one-way stream follows the dependencies of each new
commit of the stream: each commit that an update of `Commit` sets.

- The sender sends each dependency at depth 0, so a dependency entry adds no
  parent to the stream. The stream carries a dependency one time, also if
  several new commits name it, or if it is also a new commit.
- `Commit` holds no update for a dependency.
- The sender makes no ref-binding check on a dependency.
- For each dependency, the stream carries the commit object, the objects of
  its tree, and its `.commitmeta`. If the repository of the sender holds the
  composefs image of the dependency, the stream carries it. An object that a
  new commit and a dependency share goes in the stream one time.
- The sender does no negotiation, so it sends a dependency that the server
  holds. The server accepts that dependency and drops its `.commitmeta`
  ("Commit and CommitReply", check 5).
- The sender does not follow a build source. `ostrya.related` goes with the
  `.commitmeta` of its commit.

The sender checks the format of field 2 of each new commit. A defective
related value in field 2 refuses the export: an entry with an empty name, an
entry with a checksum that is not 32 bytes, and an entry that names a nested
dependency. A dependency whose own field 2 is not empty is nested, also if
that field 2 holds a defective entry, and also if the dependency is a new
commit. The format check of field 2 of each new commit runs first, so a
dependency that is a new commit with a defective entry in its field 2 gives
the failure of that entry. A dependency that the repository of the sender
does not hold, or marks partial, refuses the export too. The sender finds
each of these failures before it writes the first byte of the stream.
`Repo::export_stream` then gives `Error::ObjectNotFound` for a dependency
that the repository does not hold, and `Error::InvalidRelated` for each other
failure.

The server checks the dependencies of the commits that it stages, as in a
push session ("The one-way stream"). A server that holds a dependency with a
partial-commit marker refuses the stream with `missing-objects` and no
`missing` detail, also though the stream carries the whole tree of the
dependency ("Commit and CommitReply", check 6). To complete the dependency
at the server, a sender sends it as the new commit of an update, in that
stream or in an earlier one. The server then checks the tree of the
dependency and removes its marker.

## Ref patterns

The port selects refs by name with two grammars. A pattern of a client group
names the refs of an allow item or a deny item ("Access modes and patterns" of
`ostrya-config(1)`). A ref selector selects the refs of a ref listing. The two
grammars share the part grammar. A pattern of a client group is one pattern of
the part grammar, with no remote part and no negative form. An entry of a ref
selector takes one leading `!`.

### The part grammar

A pattern is split at `/` into parts. Each part is one of these:

- A literal. It is a component of a ref name ("Ref name validation"), and it
  matches a part of a name that is equal to it.
- `*`. It matches exactly one part of a name.
- `**`. It matches one or more parts of a name.

`*` and `**` are valid only as a whole part, so the parser refuses `b*c`, `x**`,
and `***`. A pattern is not empty and has no empty part. A pattern holds no `!`.
A name matches a pattern when the parts of the pattern, in order, cover all
parts of the name.

For example, `apps/*` matches `apps/web` and does not match `apps` or
`apps/web/db`. `apps/**` matches `apps/web` and `apps/web/db`, and does not
match `apps`. `apps/**/db` matches `apps/web/db` and `apps/a/b/db`, and does
not match `apps/db`.

A match compares parts. It does not check that the name passes the ref-name
rule. The cost of one match is at most the number of pattern parts times the
number of name parts.

### Ref selectors

An entry of a ref selector is a pattern with an optional first character `!`.
An entry with the `!` is a negative entry, and each other entry is a positive
entry. A selector selects a name when both of these conditions are true:

- The selector has no positive entry, or a positive entry matches the name.
- No negative entry matches the name.

The order of the entries has no effect. So `["!a/**", "a/b"]` does not select
`a/b`. An empty list selects every name. The parser refuses an entry with a
second `!`, such as `!!a`.

A request for a ref listing holds at most 256 entries. Positive and negative
entries count together, and the entries of the local refs and of the
collection refs count together ("The ref listing"). A server counts each
entry of the request, also an entry that the request holds more than one
time. An entry has at most 256
parts and 4096 bytes. A part is one element of the entry split at each `/`.
The `!` of a negative entry counts as one byte and adds no part. A server
checks the limits of an entry before it parses the entry.

## Wire conventions

The push sends frames over a byte stream or over HTTP. The pull sends frames
over a byte stream ("The pull over HTTP and over a stream"). These rules apply
to each message:

- The frame length and the chunk length are big-endian `u32` values.
- A message body is a GVariant in normal form. Each integer in a body is
  little-endian, whatever the byte order of the machine. The protocol applies
  no byte swap to a value.
- Each checksum in a body is an `ay` of exactly 32 bytes. A checksum of
  another length is `protocol`.
- A ref name in a message is `NAME` for a local ref and `REMOTE:NAME` for a
  remote ref.
- An object type is one byte. The values are 1 for a file, 2 for a dirtree,
  3 for a dirmeta, 4 for a commit, 6 for detached metadata, and 100 for a
  composefs image.
- An encoding is one byte: 0 for `raw` and 1 for `deflate`. In the
  `encodings` list of `HelloReply`, the names are `raw` and `deflate`.

In this part, the reader of a message is the side that reads it, a server or
a client. A word in code font that names an error code, such as `protocol`,
means that the reader refuses the message with that code ("Error codes"). A
server that refuses a message sends an `Error` with the code. An `Error` goes
from a server to a client alone, so a client that refuses a message ends the
session and sends no `Error`.

These rules apply to each dict (`a{sv}`) in a body:

- A reader ignores a key that it does not know. The value of that key must
  still be in normal form.
- A known key whose value has another type is `protocol`.
- If a key occurs two times, the first one counts. The reader checks a later
  duplicate for normal form alone.
- The order of the keys has no effect.

## Frames and the object stream

### Frame layout

A frame has this layout:

```text
u32   length, big-endian, of the bytes that follow (kind byte + body)
u8    message kind
...   GVariant body, normal form, of the type that the kind names
```

A frame holds at least the kind byte, so a frame length of 0 is `protocol`. A
frame length greater than the current limit ("Frame limits") is
`limit-exceeded`. The reader checks the length before it reads the body.

Each of these is `protocol`:

- a kind that "Messages" does not list;
- a body that is not in normal form for the type of its kind;
- a body with bytes after its value;
- an `ObjectsEnd` body that is not empty;
- an `Abort` body other than the one byte `0x00`.

### Chunks and the abandon marker

A body of bytes follows two kinds of frame: an `ObjectHeader` of the push, and
a `GetReply` of the pull whose `found` is true. The body is a sequence of
chunks. A chunk has no kind byte. It has this layout:

```text
u32   length, big-endian
...   that number of bytes
```

The length of a chunk has these meanings:

- 0 ends the body. Then frames follow again.
- `0xFFFFFFFF` is the abandon marker. It ends a body that the sender cannot
  complete. After the marker, the next frame must be `Abort` in the push and
  `Error` in the pull. Each other frame is `protocol`. "Abort, abandon, and
  end of input" states the answer of the server to the marker in the push.
- Each other length greater than the current limit is `limit-exceeded`. The
  chunk limit and the frame limit are the same number.

The sender selects the length of each chunk, up to the limit. A body has no
limit on its number of chunks. The body of a composefs image (type 100) has
no size limit of the protocol. The free-space reserve of the receiving
repository is its only bound ("Object streams"). In the push, after the end
chunk of an object, the next frame is one of these:

- the `ObjectHeader` of the next object;
- `ObjectsEnd`, which closes the object stream;
- `Abort` ("Abort, abandon, and end of input").

### Frame limits

- Before an announcement, the frame limit is 1 MiB (1,048,576 bytes) in both
  directions.
- The server of a push session announces its limit in the key `max-frame` of
  `HelloReply`. The announced limit applies to each frame and each chunk that
  the client then sends.
- The value of `max-frame` is from 1 MiB to `0xFFFFFFFE`, both included. A
  value out of this range is `protocol`. `0xFFFFFFFE` is one less than the
  abandon marker, so a chunk length that a limit allows never equals the
  marker.
- An ostrya server announces 1 MiB, and it sends frames of at most 1 MiB.
- A one-way stream and a pull session carry no announcement. The frame limit
  and the chunk limit of a one-way stream are 1 MiB. In a pull session, they
  are 1 MiB in both directions.

An `ObjectHeader` frame is always 40 bytes: the length, the kind, and a body
of 35 bytes. A `GetReply` frame is 21 bytes with a `len` and 13 bytes with no
`len`.

## Messages

Each message kind has a number, a direction, a protocol, and a body type:

- 1 `Hello` -- client to server, push, `(ua{sv}as)`.
- 2 `HelloReply` -- server to client, push, `(ua{sv}a(smay))`.
- 3 `Have` -- client to server, push, `a(yay)`.
- 4 `HaveReply` -- server to client, push, `ay`.
- 5 `ObjectHeader` -- client to server, push, `(yayy)`.
- 6 `ObjectsEnd` -- client to server, push, a body of zero bytes with no
  GVariant type.
- 7 `ObjectsReply` -- server to client, push, `(ut)`.
- 8 `Commit` -- client to server, push, `(a(symaymay)a{sv})`.
- 9 `CommitReply` -- server to client, push, `a(smaymay)`.
- 10 `Error` -- server to client, push and pull, `(ssa{sv})`.
- 11 `Abort` -- client to server, push, `()`, which is the one byte `0x00` in
  normal form.
- 12 `PullHello` -- client to server, pull, `(ua{sv})`.
- 13 `PullHelloReply` -- server to client, pull, `(ua{sv})`.
- 14 `Get` -- client to server, pull, `s`.
- 15 `GetReply` -- server to client, pull, `(bmt)`.
- 16 `ListRefs` -- client to server, pull, `(asa{sv})`.

A session refuses a kind of the other protocol with `protocol`.

`Hello` holds the protocol version, a dict, and the ref names of the session.
The dict holds these keys:

- `agent` (`s`, optional): the name and the version of the client.
- `collection` (`s`, optional): the collection id of the namespace that the
  session writes. Without the key, the session writes the local refs. A
  writer puts the key in the dict only when it names a collection.
- `one-way` (`b`, optional): true for a one-way stream. A writer puts the key
  in the dict only when its value is true.

`HelloReply` holds the protocol version, a dict, and one `(name, commit)`
entry for each ref of `Hello`, in the order of `Hello`. An absent commit is an
absent ref. The dict holds these keys:

- `mode` (`s`, required): the mode of the repository.
- `collection-id` (`s`, optional): the collection id of the repository.
- `collection` (`s`, optional): the collection of the namespace that the
  server selected for the session. The key is absent for the local refs.
- `max-frame` (`u`, required): the frame limit ("Frame limits").
- `max-have` (`u`, required): the most entries of one `Have`.
- `encodings` (`as`, required): the encodings that the server accepts.
- `parallel-uploads` (`u`, required): the most object streams that run at the
  same time in one session over HTTP.

A `HelloReply` with no value for a required key is `protocol`. A `max-have` or
a `parallel-uploads` of 0 is `protocol`. A client drops an encoding name that
it does not know.

A client refuses a `HelloReply` whose `collection` does not agree with its
`Hello`, with `protocol`. A `Hello` with no `collection` needs a reply with
no `collection`. A `Hello` with the collection `ID` needs a reply with the
`collection` `ID`, or a reply with no `collection` and the `collection-id`
`ID`.

`Have` is a list of object names: the object type (1 to 4, or 100) and the
checksum. Another type is `protocol`. `HaveReply` is a bitmap with one bit for each entry
of the `Have`:

- Bit `i` is bit `i % 8` of byte `i / 8`, with bit 0 the least significant.
- A set bit means that the server needs the object.
- For `n` entries, the bitmap has `ceil(n / 8)` bytes, and each bit after the
  last entry is zero.

A client refuses a `HaveReply` of another length, or with a set bit after the
last entry, with `protocol`.

`ObjectHeader` holds the object type, the checksum, and the encoding. For type
6, the checksum is the checksum of the commit that the detached metadata
belongs to. For type 100, the checksum is the checksum of the commit that the
composefs image belongs to. Only type 1 can have the encoding `deflate`. These
headers are `protocol`:

- a type other than 1, 2, 3, 4, 6, and 100;
- an encoding byte other than 0 and 1;
- the encoding `deflate` with a type other than 1.

The body of the object follows as chunks:

- `raw` -- for a file, the framed header and the payload of "File content
  object header". For a composefs image, the bytes of the stored image
  ("The composefs image object"). For each other type, the bytes of the
  object.
- `deflate` -- the framed archive header and the payload in raw DEFLATE, as a
  `.filez` object stores them.

`ObjectsReply` holds two counts of one object stream: `objects` (`u`) and
`payload_bytes` (`t`). "Object streams" states what they count.

`Commit` holds a list of ref updates and a dict. Each update is
`(name, state, expected, new)`:

- `state` 0: the ref must be absent. `expected` is absent.
- `state` 1: the ref must point at the commit `expected`.
- `state` 2: the ref can be in any state. `expected` is absent.
- `new` is the new commit. An absent `new` deletes the ref.

A `state` greater than 2, and an `expected` that does not agree with its
`state`, are `protocol`. The dict holds these keys:

- `force` (`b`, optional): A writer puts the key in the dict only when its
  value is true.
- `server-commit` (`(sasas(ayay)ssa{sv}a{sv})`, optional): a commit that the
  server makes from a tree and the fields of the client ("Server commit").
  A writer puts the key in the dict only for a server commit, and the list of
  updates is then empty.

The value of `server-commit` holds these members, in this order:

1. `s`: the branch.
2. `as`: the tags, in the order of the client.
3. `as`: the bound names, in the order of the client.
4. `(ayay)`: the checksums of the root dirtree and of the root dirmeta.
5. `s`: the subject.
6. `s`: the body.
7. `a{sv}`: the metadata of the client. This dict is data, and the dict rules
   of "Wire conventions" do not apply to it. A reader keeps each entry in
   order, also a key that occurs two times. Each value must be a `v` in
   normal form, else the message is `protocol`.
8. `a{sv}`: the options, with the dict rules of "Wire conventions". The dict
   holds these keys:
   - `timestamp` (`t`, optional): the commit time in seconds since the Unix
     epoch, UTC.
   - `orphan` (`b`, optional): true for a commit with no parent. A writer
     puts the key in the dict only when its value is true.

`CommitReply` holds one `(name, old, new)` entry for each update, in the order
of `Commit`. `old` is the commit of the ref before the write, and `new` is the
commit after it. An absent commit is an absent ref. For a server commit, the
reply holds one entry for the branch, then one entry for each tag, in the
order of `server-commit`. `new` of each entry is the new commit, and `old` of
each tag is absent. A bound name has no entry.

`Error` holds the code, a message for a person, and a dict of details:

- `missing` (`a(yay)`): the objects that a `missing-objects` error names, of
  the types 1 to 4 and 100. An entry of another type is `protocol`.
- `ref` (`s`) and `current` (`may`): the name and the current commit of the
  ref of a `ref-mismatch` error.

`ref` and `current` come together. One of them alone is `protocol`, and a
`ref-mismatch` without them is `protocol`.

`PullHello` holds the highest pull version of the client and a dict with the
optional key `agent` (`s`). `PullHelloReply` holds the version of the session
and a dict. In version 1 the dict of `PullHelloReply` is empty.

`Get` holds a path. `ListRefs` holds the entries of the ref selector of the
local refs ("Ref selectors") and a dict. The dict holds the key
`collections` (`as`, optional): the entries of the ref selector of the
collection refs ("The ref listing"). A writer puts the key in the dict only
when the client asks for collection refs, also for an empty list. A reader
ignores a key that it does not know. A `ListRefs` body of the type `as`
alone is `protocol`. `GetReply` holds `found` and `len`. `len` is the length of the
body, and it is absent when the server does not know the length. A `GetReply`
with `found` false and a `len` is `protocol`.

## Error codes

An `Error` message carries one of these codes. Each entry gives the main
causes of the code. "The push session" and "The pull session over a stream"
give the condition of each refusal.

- `version-unsupported` -- the server does not speak the protocol version of
  the client.
- `locking-disabled` -- the repository of the server sets
  `[core] locking=false`.
- `unauthorized` -- the server refuses the credential of an HTTP request.
- `protocol` -- a frame is malformed, a kind is unknown, a message comes out
  of order, or a message breaks a rule of the session.
- `limit-exceeded` -- a frame, a chunk, a batch, a reply, a metadata object,
  a listing, or a session is over its limit.
- `checksum-mismatch` -- the bytes of an object do not hash to its name, or
  the fs-verity digest of a composefs image is not the key of its commit.
- `mode-refused` -- the repository mode cannot store the content, or the
  client group does not allow privileged content.
- `missing-objects` -- a commit reaches objects that the server does not hold.
- `ref-mismatch` -- a ref is not in the state that its update expects, an
  update with `t` and no `w` writes a commit to a ref that exists, or a tag of
  a server commit exists.
- `non-fast-forward` -- the new commit does not descend from the commit of the
  ref, and the client group or the request does not allow it. A server commit
  with `orphan` on a branch that exists, without `d` on the branch, gets this
  code too.
- `delete-denied` -- the client group has no `d` on a ref that an update
  deletes.
- `invalid-ref` -- the server refuses a ref name, or the collection id of
  `Hello`: an id longer than 255 bytes, or one that fails the collection-id
  rule.
- `ref-denied` -- no client group covers the namespace of `Hello`, the client
  group opens no push session, a ref of `Hello` has no `r`, an update writes
  a commit without `w` or `t`, or an update names a ref that a push does not
  write. A server commit gets this code without `c` on its branch, or without
  `t` or `w` on a tag. A hook of a host application can also refuse a commit
  with ref updates or a server commit with this code.
- `signature-required` -- a commit has a signature that does not verify, or
  has no signature and the client group requires one.
- `binding-mismatch` -- the ref binding of a commit does not name its target
  ref, or its collection binding does not name the collection of the
  namespace of the session.
- `internal` -- a failure on the server side, for example an I/O error. A
  hook of a host application can also refuse a commit with ref updates or a
  server commit with this code.

An unknown code in a received `Error` is `protocol`. A server error with no
wire code goes out as `internal` with the text of the error. "Abort, abandon,
and end of input" states the exceptions.

Over HTTP, the code of an `Error` sets the status of the response:

- `ref-mismatch` and `non-fast-forward` get 409.
- `internal` gets 500.
- `unauthorized` gets 403. A refusal of the authentication gets 401 or 403
  ("Authentication of the receive endpoint").
- Each other code gets 422.
- A `session` request that the endpoint cannot take, because the most
  sessions are open or the endpoint stops, gets 503 with `limit-exceeded`.

A ref listing over HTTP sends no `Error` message. "GET /_ostrya/refs/v1"
states its statuses.

## The push session

A push session has this sequence:

1. `Hello`, which the server answers with `HelloReply`.
2. Any number of `Have` messages and object streams, in any order. The server
   answers each `Have` with `HaveReply` and each object stream with
   `ObjectsReply`.
3. `Commit`, which the server answers with `CommitReply`, or `Abort`.

A first message other than `Hello` is `protocol`. An object stream is one or
more objects, each one an `ObjectHeader` and its chunks, then `ObjectsEnd`. An
empty object stream, `ObjectsEnd` alone, gets an `ObjectsReply` with the
counts 0 and 0.

The server enforces these rules, or depends on them, so a client must keep
them:

- The refs of `Commit` are a subset of the refs of `Hello`. The subset is not
  empty and names no ref two times. The refs of a server commit are its
  branch and its tags.
- `Have` and `missing` name objects of the types 1 to 4 and 100.
- An object has the encoding `deflate` only if it is a file and `HelloReply`
  lists `deflate`.
- A `Have` holds at most `max-have` entries, and its frame fits in
  `max-frame`.
- A session sends at most one detached metadata dict for each commit. The
  commit is a commit that the session sends, or the new commit of an update.
- A session sends at most one composefs image for each commit. The commit is
  a commit that the session sends, or a commit that the server holds.
- Before `Commit`, a session sends each object that the tree of a commit of
  the session reaches, unless the server holds the object. The commits of the
  session are the commits that it sends and the new commits of the updates.
  The session does not need to send the parent commits. A session with a
  server commit sends the objects of its tree.
- A session with a server commit sends no commit object, no detached
  metadata, and no composefs image.
- To cancel an object, a client sends the abandon marker and then `Abort`.
- On a stream, a client sends one request and reads its reply before it sends
  the next one.

A push of a repository (`ostrya push`, `Repo::push`, and
`Repo::push_over_stream`) offers its commits in the first `Have`: each source
commit, its history, and then the dependencies of each offered commit
("Dependencies in a push"). With no depth, the history ends before the
current commit of the ref in `HelloReply`. If the server does not hold the
ref, or the local chain does not hold the commit of the ref, the push offers
no history commit. The client then offers the objects of the trees of the
commits that the server lacks, and of each source commit.

### Hello and HelloReply

The server runs these checks of `Hello` in this order. The checks do no I/O:

1. `one-way` true is `protocol`. A one-way stream starts with that `Hello`
   ("The one-way stream").
2. A version other than 1 is `version-unsupported`. The server offers no
   lower version.
3. A repository in the mode `bare-split-xattrs` is `mode-refused`.
4. A repository with `[core] locking=false` is `locking-disabled`. A
   malformed `[core] locking` value is `internal`.
5. A ref name that fails the refspec rule ("Ref name validation") is
   `invalid-ref`.
6. A `collection` that is longer than 255 bytes, or that fails the
   collection-id rule, is `invalid-ref`. The id is one name under
   `refs/mirrors/`, and a file system takes a name of 255 bytes at most.
7. A `HelloReply` with a commit for each ref that needs a frame over 1 MiB is
   `limit-exceeded`. The reply holds the `collection` of the namespace.

`collection` names the namespace of the session. No `collection`, and the
collection id of the repository, name the local refs, under `refs/heads/`.
Each other id names the refs of that collection, under `refs/mirrors/ID/`.
The session reads and writes the refs of its namespace alone, so a session
of a collection does not touch `refs/heads/`.

Then the server runs the checks of the client group of the session. They do
no I/O, and each failure is `ref-denied`:

8. The session needs a client group whose `collection` key covers the
   namespace.
9. A client group with no allow item that has `w`, `c`, `t`, or `d` opens no
   push session.
10. A remote ref `REMOTE:NAME` in `Hello` is refused, because a push writes
    no remote ref.
11. A ref of `Hello` needs `r` in the effective rights of the group
    (`ostrya-config(1)`, "Access modes and patterns"). `d` does not add `r`.
    `HelloReply` gives the current commit of each ref of `Hello`, so this
    check keeps a client from reading a ref through a push session.

`ostrya receive` and `ostrya serve` give a session the client group that
carries the auth item of the client in the namespace of `Hello`
("Authentication of the receive endpoint"). For a collection, the group is
the group that names the collection, else the group with `collection=*`.
With no such group, `ostrya receive` answers `Hello` with `ref-denied` at
check 8, and `ostrya serve` answers the `session` request with 403.

A `Hello` with no ref, and a `Hello` that names one ref two times, pass
checks 1 to 7. A `Hello` with no ref also passes checks 10 and 11, so a
client group that opens a push session accepts it. A session whose `Hello`
names no ref cannot commit, because `Commit` names refs of `Hello` alone
(check 1 of "Commit and CommitReply").

Then the server opens the transaction of the session, and the transaction
takes the repository lock shared ("Locks and on-disk state of a receive"). A
wait for the lock past its time limit is `internal`. These steps follow, in
this order:

1. The server reads `[core] lock-timeout-secs`, `[core] tmp-expiry-secs`,
   `[core] min-free-space-percent`, and `[core] min-free-space-size`. A
   malformed value is `internal`.
2. The server reads `[core] fsync`, `[core] per-object-fsync`,
   `[ex-integrity] fsverity`, `[ex-ostrya] keep-detached-related`, and, in
   an `archive` repository, `[archive] zlib-level`. A malformed value is
   `internal`.
3. In a `bare` repository, a new file in the staging directory must get the
   owner uid 0. Only root can store the owner of each file. Else the session
   is `mode-refused`.
4. The server reads the ref of each name of `Hello` in the namespace of the
   session. A failed read, and a ref file that does not parse, are
   `internal`.

An ostrya server announces these values in `HelloReply`:

- version 1;
- `mode`: the mode of the repository, with `archive` sent as `archive-z2`;
- `collection-id`: the collection id of the repository, when it has one;
- `collection`: the collection of the namespace of the session. The key is
  absent for the local refs, also when `Hello` names the collection id of the
  repository;
- `max-frame`: 1 MiB;
- `max-have`: 16384;
- `encodings`: `raw` and `deflate`, in every mode;
- `parallel-uploads`: 1 on a stream, and the `parallel-uploads` setting of
  the endpoint over HTTP ("The receive endpoint");
- the refs: the current commit of each ref of `Hello` in the namespace of the
  session, in the order of `Hello`, with one entry for each name that `Hello`
  repeats. A ref name that
  names a directory, or a path through a file, reads as absent. An alias gets
  the commit of its target.

### Have and HaveReply

A `Have` of more than 16384 entries is `limit-exceeded`. The server sets the
bit of an object when the session did not stage the object and `objects/`
does not hold it. Each entry gets its own bit, also an entry that the `Have`
holds two times. An empty `Have` gets an empty bitmap.

For a composefs image (type 100), the object is `<commit>.cfs`. The server
does not read a stored image, so it does not set the bit of an image that
`objects/` holds, also when its digest is not the key of its commit.

A session of version 1 can carry the type 100. A receiver that does not
accept the type 100 refuses a session that offers it, in a `Have` or in an
`ObjectHeader`, with `protocol`. So a receiver must accept the type 100
before a sender that holds composefs images pushes to it or sends it a
one-way stream.

### Object streams

The server reads, hashes, and checks each object of a stream, also an object
that the repository or the session holds already. It stages an object that it
does not hold, and it drops the other objects. These conditions refuse an
object:

- A dirtree, dirmeta, or commit object larger than 128 MiB is
  `limit-exceeded`.
- The dirtree, dirmeta, and commit objects that the streams of a session read
  at the same time share one budget of 128 MiB. The bytes of an object count
  from its arrival to its stage step. The read that takes the session past
  the budget is `limit-exceeded`.
- An object of the types 1 to 4 whose bytes do not hash to its checksum is
  `checksum-mismatch`.
- The framed header of a file holds a length and 4 zero bytes ("File content
  object header"). A non-zero pad byte is `protocol`, and a header larger
  than 1 MiB is `limit-exceeded`. A file object that ends inside its header,
  or whose header does not parse, is `protocol`.
- These are `protocol`:
  - a symlink with a payload;
  - a corrupt DEFLATE stream;
  - a payload of another size than the header states;
  - bytes after the end of an object;
  - a `deflate` payload of more than `D + D / 1024 + 65536` compressed bytes,
    where `D` is the payload size that the header states, with integer
    division.
- In a `bare` repository, these are `mode-refused`:
  - a file with the setuid or setgid bit;
  - a file or a dirmeta with a `security.capability` or `security.selinux`
    xattr.

  The key `allow-privileged` of the client group turns this check off
  (`ostrya-config(1)`, "Client keys").
- In a `bare-user-only` repository, a file that the canonical rule of the mode
  does not allow is `mode-refused` ("Repository modes and on-disk storage").
- An I/O error of the operating system is `internal`. An object that the
  free-space reserve of the repository refuses (`[core] min-free-space-*`) is
  `internal` too.

In an `archive` repository the server stores a `deflate` body as sent. In each
other mode it inflates the body.

A detached metadata object (type 6) follows these rules:

- A second dict for one commit is `protocol`, also from another stream.
- All detached metadata of a session has one cap of 128 MiB. The read that
  takes the session past the cap is `limit-exceeded`. This cap is separate
  from the budget of the other metadata objects.
- The dict is an `a{sv}` in normal form that holds each key once. The value
  under `ostree.gpgsigs`, `ostree.sign.ed25519`, `ostree.sign.spki`, and
  `ostree.sign.dummy` is an `aay`. Each other dict is `protocol`.

A composefs image (type 100, "The composefs image object") follows these
rules:

- The encoding is `raw`, and the body is the bytes of the image. The image
  has no size limit beyond the free-space reserve of the repository.
- A second image for one commit is `protocol`, also from another stream.
- If `objects/` holds an image of the commit, the server reads the body to
  its end and drops it. It does not read the stored image.
- Else the server streams the image to its staging directory and computes
  its fs-verity digest as it writes it. It seals the image as it seals a new
  image. No step holds the whole image. The commit of the image need not be
  staged or held when the image arrives.
- At `Commit`, the server checks each image against its commit (check 5 of
  "Commit and CommitReply").

The server writes no object and no dict to `objects/` before `Commit`.

`ObjectsReply` counts the objects of one stream that the server staged and
the dicts that it kept. `payload_bytes` counts the body bytes of these
objects, with the chunk framing removed, in the encoding of the wire. An
object that the server held already does not count. A composefs image that
the server staged adds its bytes to `payload_bytes` and does not count in
`objects`. Over HTTP, an object that two `objects` requests send at the same
time can count in both replies.

### Commit and CommitReply

The server runs these checks of a `Commit` with no server commit in this
order. "Server commit" states the checks of a `Commit` with a server commit.
Each failed check ends the session, and the session writes nothing:

1. Each ref name passes the refspec rule ("Ref name validation"). An update
   that writes a commit to a name of 64 lowercase hex characters fails this
   check too. A delete of such a name passes. A failure is `invalid-ref`.
   Then a request with no update, an update of a ref that `Hello` does not
   name, and two updates of one ref are `protocol`.
2. A `CommitReply` with a commit in each `old`, and the `new` of each
   update, that needs a frame over 1 MiB is `limit-exceeded`.
3. A detached metadata dict for a commit that the session did not stage,
   that no update names as `new`, and that the repository does not hold is
   `protocol`.
4. The server reads the effective rights of the ref of each update in the
   client group. These updates are `ref-denied`:
   - an update of `ostree-metadata` in the local refs of a repository with a
     collection id. In a collection namespace, `ostree-metadata` is a ref
     like the other refs;
   - an update of a remote ref `REMOTE:NAME`;
   - an update that writes a commit to a ref with neither `w` nor `t`.

   The server checks a delete at check 11.
5. The server reads the new commits in the order of the updates. A staged
   commit that does not parse is `protocol`, and a stored one is `internal`.
   Such a commit fails the check at once. A `new` commit that the session did
   not stage and that the repository does not hold is `missing-objects`. The
   absent commits fail together, after the read of the other commits. Then
   the server takes each detached metadata dict for a commit that the
   repository holds, that the session did not stage, and that no update
   names as `new`. If an entry of field 2 of a commit of the session names
   that commit, the commit is a dependency that the repository holds, and
   the server drops the dict with no merge and no write. An entry with an
   empty name or with a checksum that is not 32 bytes names no commit. Each
   other such dict is `protocol`. Then the server checks each composefs
   image of the session, in the order of the checksums of their commits. An
   image for a commit that the session did not stage and that the repository
   does not hold is `protocol`. For an image that the session staged, a
   commit without
   `ostree.composefs.digest.v0`, or with a value that is not a variant of
   type `ay` with 32 bytes, is `protocol`. An image whose fs-verity digest is
   not that value is `checksum-mismatch`.
6. Each object that the tree of a commit of the session reaches must be
   staged or present, else `missing-objects`. The parents of a commit are not
   required. The `missing` detail names at most 16384 objects. A staged
   dirtree that does not parse is `protocol`, and a stored one is
   `internal`.

   Then the server checks the dependencies of each staged commit: the field
   2 entries of each commit that the session staged, the staged parents of a
   new commit included ("Related commits"). A new commit that the repository
   holds with a partial-commit marker gets the same check, because the walk
   above completes its tree and the session removes its marker. The server
   takes the new commits that it checks in the order of the updates, then
   the other staged commits in the order of their checksums. An entry with an empty
   name or with a checksum that is not 32 bytes is `protocol`. A dependency
   that the session did not stage and that the repository does not hold is
   `missing-objects`. The absent dependencies fail together, and the
   `missing` detail names each one. Then, in the order of the commits that
   name them, a dependency that the repository holds with a partial-commit
   marker is `missing-objects` with no `missing` detail, and a dependency
   whose own field 2 is not empty is `protocol`. The message names the
   commit that holds the entry, field 2, and the defect. A dependency that
   the session staged, and a dependency that is a new commit, are complete
   through the walk above, also with a partial-commit marker. The server
   does not check field 2 of a new commit that the repository holds with no
   partial-commit marker.
7. The bindings of each new commit must agree with the session, else
   `binding-mismatch`:
   - A non-empty `ostree.ref-binding` must hold the name of each ref that the
     commit is the new value of. For a remote ref of a one-way stream, the
     name is the part after `REMOTE:`.
   - If the commit has `ostree.collection-binding`, the value must be the id
     of the namespace: the collection of a collection namespace, or the
     collection id of the repository for the local refs. In the local refs of
     a repository with no collection id, a commit with the key fails. A
     one-way stream checks the key against the collection id of the
     repository, and does not check it in a repository with no collection
     id.
   - The server does not check a binding key that the commit does not have,
     so a commit with no binding passes in each namespace.
8. A new commit that the client built must pass the signature verification
   of the client group, else `signature-required`. The verification reads the stored detached
   metadata of the commit and the incoming dict together, before the switch
   of step 9. A group with no `verify`
   checks no signature. A group with `verify=trust:NAME` checks each axis of
   the trust group. With `allow-unsigned=true`, a commit whose dict holds no
   blob under `ostree.gpgsigs`, `ostree.sign.ed25519`, `ostree.sign.spki`, and
   `ostree.sign.dummy` passes. A commit with a blob under one of these keys
   must pass the check, so a signature of an engine that the trust group does
   not read fails.

   Each staged dependency must pass the verification of the rule of each
   update whose new commit names it in its staged chain, else
   `signature-required`. The staged chain of a new commit is the commit and
   its parents as far as the session staged them. Field 2 of a new commit
   that the repository holds also counts. The message names the dependency
   and the first new commit, in the order of the updates, whose staged chain
   names it. A staged dependency that is also a new commit gets one
   verification under the rules of both roles. A dependency that the
   repository holds, and a staged dependency that only commits outside each
   staged chain name, get no verification.
9. If `[ex-ostrya] keep-detached-related` is `false`, the server drops
   `ostrya.related` from each incoming dict ("The switch of the
   destination"). The server then makes the staged objects durable, and signs each new commit one time with each key
   of the key `sign` of the client group. It signs each staged dependency
   that the staged chain of a new commit names, as check 8 states, one time
   with each distinct key of the rules of these new commits. A dependency
   that the repository holds gets no signature. It walks the history of each update
   that needs the fast-forward check. The walk starts at the new commit and
   follows the parents until it reaches the commit of the ref, an absent
   commit, or a root commit. An update of an absent ref needs no walk, so the
   parent chain of a new branch can stop at any depth. With `force` in the
   request and `w` and `d` on the ref, no walk runs. With `t` and no `w` on
   the ref, no walk runs: check 11 refuses the update if the ref is present.
   A host application is a program that embeds the receive path of the port.
   Its hook before the update can refuse with `ref-denied` or `internal`.
10. The server takes the update lock and reads the refs again, in the
    namespace of the session. These are `ref-denied`:
    - a ref that is an alias;
    - a ref path that a ref write cannot replace;
    - two updates that write a commit, where one names a directory of the
      other.
11. For each update, in this order:
    - A ref that is not in the expected state is `ref-mismatch`, with `ref`
      and `current`.
    - An update that writes a commit to a ref that is present, with `t` and
      no `w` on the ref, is `ref-mismatch`, with `ref` and `current`. This
      applies also when the commit is the current commit.
    - A delete of a ref that is present is `delete-denied` unless the ref has
      `d`. A delete of an absent ref changes nothing.
    - A new commit whose parent chain stops at an absent commit or a root
      commit before it reaches the commit of the ref is `non-fast-forward`.
      With `force` in the request and `w` and `d` on the ref, this check does
      not run.
12. A merged detached metadata dict larger than 128 MiB is `limit-exceeded`.
    The hooks of a host application can add entries to the dict. Their merge
    can give this error before the update lock, at step 9. Then the server
    commits the transaction.

`CommitReply` has one entry for each update, in the order of `Commit`.
"Locks and on-disk state of a receive" states when the server sends it.

#### Server commit

A server commit is a commit that the server makes from a tree and the fields
that the client sends in `server-commit` ("Messages"). Its parent is the tip
of the branch on the server. The server runs these checks in this order. Each
failed check ends the session, and the session writes nothing:

1. The branch and each tag pass the refspec rule ("Ref name validation"), and
   none is 64 lowercase hex characters. Each bound name passes the refspec
   rule and holds no `:`. A failure is `invalid-ref`. Then a `Commit` with an
   update, a `Commit` with `force`, a branch or a tag that `Hello` does not
   name, and a ref that occurs two times among the branch and the tags are
   `protocol`. A metadata value of the client that the commit cannot hold is
   also `protocol`. The port reads and writes the metadata dict of a commit
   with at most 128 levels of containers. In that dict, the `v` of each value
   is under two containers, the dict and its entry, so the `v` can hold two
   levels fewer than in the message.
2. A `CommitReply` with a commit in `old` of the branch that needs a frame
   over 1 MiB is `limit-exceeded`.
3. A detached metadata dict of the session, a composefs image of the
   session, and a commit object that the session staged, are `protocol`.
4. These are `ref-denied`:
   - a branch or a tag `ostree-metadata` in the local refs of a repository
     with a collection id;
   - a remote ref `REMOTE:NAME`;
   - a branch without `c`;
   - a tag with neither `t` nor `w`.

   A bound name gets no ref and needs no right.
5. Each object that the tree of the commit reaches must be staged or
   present, else `missing-objects`.

Checks 7 and 8 of a `Commit` with no server commit do not apply. The server
writes the binding keys, and `verify` and `allow-unsigned` of the client group
do not apply. The trust in a server commit comes from the authentication of
the client and from `sign`. A client group that must verify the commits of
its clients takes a mirror push.

The server then makes the staged objects durable. In a session with the
hooks of a host application, the hook of the host gets the server commit
next. The hook can refuse with `ref-denied` or `internal`, and no ref
changes. A host whose hooks take no server commit refuses with `ref-denied`
at this step.

The server then takes the update lock. Under the lock it reads the branch and
the tags in the namespace of the session, and check 10 applies, with a write
to each of these refs. Then the server checks the branch, and then each tag,
in order:

- A server commit with `orphan` on a branch that is present is
  `non-fast-forward`, unless the branch has `d`.
- A tag that is present is `ref-mismatch`, with `ref` and `current`. This
  applies also with `w` on the tag.

Then the server builds the commit under the update lock:

- The parent is the commit of the branch. With `orphan`, or when the branch
  is absent, the commit has no parent.
- The subject, the body, and the root dirtree and root dirmeta are the values
  of the client. The list of related objects is empty.
- The timestamp is the value of `timestamp`, else the system clock of the
  server. The server does not read `SOURCE_DATE_EPOCH`.
- The metadata dict holds these entries, in this order, which is the order of
  `commit` (`conformance/cli-behavior.md`, "CLI output formats", `commit`):
  1. each entry of the client, in order, with duplicate keys kept. The server
     drops each entry under `ostree.ref-binding` and
     `ostree.collection-binding`, and moves each entry under
     `ostree.composefs.digest.v0` and `ostree.sizes` to items 4 and 5;
  2. `ostree.ref-binding` (`as`): the branch, each tag, and each bound name,
     sorted byte-wise, with duplicates kept;
  3. `ostree.collection-binding` (`s`): the collection of a collection
     namespace, or the collection id of the repository for the local refs.
     The key is absent for the local refs of a repository with no collection
     id;
  4. each entry of the client under `ostree.composefs.digest.v0`, in order;
  5. each entry of the client under `ostree.sizes`, in order.

  The server adds no `ostree.sizes` of its own.

Inputs that equal those of a commit that the repository holds give the
checksum of that commit. Then the commit object stays as it is.

The server signs the commit under the update lock with each key of `sign` of
the client group, each key one time. A key that signed the commit in its
stored detached metadata adds no signature. Check 12 applies to the merged
dict. The server then moves the branch to the commit and creates each tag at
the commit, in one transaction commit. If the branch already names the
commit, the branch does not change. A bound name gets no ref. The steps of
"Locks and on-disk state of a receive" follow.

A failure of the build is `internal`, for example a system clock before the
Unix epoch, or an I/O error.

With equal inputs, the checksum of a server commit is equal to the checksum
of `ostree commit --no-xattrs -b BRANCH --bind-ref NAME ...` with the same
parent, in a repository whose `collection-id` is the collection of the target.
Each tag and each bound name is one `--bind-ref`, and `orphan` is
`--parent=none`.

Observed behavior: the tool version 2026.1 makes each commit in an `archive`
repository with `SOURCE_DATE_EPOCH=1700000000`. The commit has a subject, a
body, two `--add-metadata-string` entries with one key, and one
`--add-metadata` entry. The server commit carries the fields of the commit of
the tool and its metadata without the binding keys. The checksums are equal
in these cases:

- no collection id in either repository;
- the local refs of a repository whose collection id is that of the tool;
- the collection of the tool in a repository with another collection id, and
  in a repository with no collection id;
- one `--bind-ref` as a tag and one as a bound name;
- a second commit on the branch, with the tip as its parent;
- `--parent=none` and `orphan` on a branch that exists.

`ostree fsck` passes on the repository of the port after these commits.
`ostree refs -c` lists the collection refs that the port writes, and
`ostree show` reads the commit.

The clients of a server commit are `ostrya push --onto` and `ostrya
push-tree` ("The commit of `push-tree`"). Each client follows these rules:

- `Hello` names the branch, then each tag. The namespace is the collection
  of `--collection`, else the local refs of the server.
- After `HelloReply`, a tag that the server reports at a commit is
  `ref-mismatch` on the client. Then the client runs the checks of the
  server at `Commit` that need no state of the server:
  - The client refuses a metadata value that a commit cannot hold
    (check 1) as invalid input. Bytes that are not a `v` in normal form are
    `protocol` on the client.
  - The client encodes the `CommitReply` with an old commit on the branch
    and each tag (check 2). If its frame is longer than the `max-frame` of
    the server, the client refuses the server commit with
    `limit-exceeded`. A tag adds about 40 bytes and its name to the reply.
  - The client encodes the `Commit` frame of the server commit. A frame
    longer than the `max-frame` of the server is `limit-exceeded` on the
    client.

  An ostrya server announces 1 MiB. Thus the names, the subject, the body,
  and the metadata of the server commit must fit in one frame of 1 MiB, and
  so must the reply. These checks come before the first `Have`, so a
  refused server commit sends no object.
- The client offers the objects of the tree and sends the objects that the
  server lacks. It sends no commit object and no detached metadata.
- A host whose hooks take no server commit answers `ref-denied`. The client
  has no fallback to a commit that it builds.
- The `CommitReply` must hold the branch, then each tag, in order. Each entry
  must have one new commit, the same for each entry, and a tag must have no
  old commit. Any other reply is `CommitOutcomeUnknown` on the client. The
  client prints the new commit.

`ostrya push --onto BRANCH REF` makes the server commit from the local commit
of the revision `REF`. The client does not split `REF` at `:`. The server
commit holds these fields of the local commit:

- the root dirtree, the root dirmeta, the subject, and the body;
- each metadata entry, in order, with the bytes of its value, except each
  entry under `ostree.ref-binding` and `ostree.collection-binding`. The
  entries under `ostree.sizes` and `ostree.composefs.digest.v0` pass
  unchanged. The bindings of the local commit do not select the namespace,
  and the server writes the bindings of its own namespace;
- the timestamp of the local commit, or the value of `--timestamp`.

The client sends no parent, no commit object, and no detached metadata. So
a signature of the local commit does not reach the server, and the server
signs the new commit with `sign`. The client refuses a local commit that the
repository marks partial, and a local commit with related objects, before it
writes a byte.

Observed behavior: a local commit of `ostrya commit --no-xattrs` in a
repository with a collection id, with a `--bind-ref` of its own, goes to a
server with no collection id. With `SOURCE_DATE_EPOCH=1700000000` on both
sides, the checksum of the server commit is equal to the checksum of
`ostree commit --no-xattrs -b BRANCH` over the same tree with the same
subject, body, and metadata options. A second push with `--tag`,
`--bind-ref`, and `--timestamp` gives the second commit of the tool with
`--bind-ref` for each name and the same `--timestamp`.

### Abort, abandon, and end of input

On a stream, these events end a session, and the server sends no `Error`:

- `Abort` between two messages;
- the abandon marker in an object, and then `Abort`;
- an end of the input before `Commit`, at a frame boundary or inside a frame
  or a chunk;
- a read error or a write error of the stream.

Over HTTP, `DELETE` takes the place of `Abort`. An `Abort` frame and an early
end in the body of an `objects` request get an `Error` with `protocol` ("The
receive endpoint").

Each other failure ends the session after one `Error` frame. The server then
drops the transaction. The server reads no more input of the session after
the `Error` frame.

A failure before the transaction commit does not change the repository. A
failure in the transaction commit can leave objects, detached metadata, and
some refs written. An error of the hook after the update comes after the
server wrote the refs ("Locks and on-disk state of a receive").

### Locks and on-disk state of a receive

"Repository lock and staging", "The update lock", "Commit-state markers",
"Ref durability", and "The `ostree-metadata` anchor commit" state the files
that a receive uses. A receive uses them in this order:

1. The transaction of the session opens after the `Hello` checks. It takes
   the repository lock shared, and it holds the lock to the end of the
   transaction commit. Under `[core] locking=false`, a one-way stream takes
   no repository lock.
2. At `Commit`, after check 9, the server takes the update lock. Under the
   lock it reads the refs again and runs checks 10 to 12. For a server commit,
   the server takes the update lock after check 5 of "Server commit" and
   after the hook of the host application. The server also builds, writes,
   and signs the commit under the lock, because the commit bytes exist only
   after the read of the tip ("Server commit"). A GPG signature then holds the
   lock for the time of the `gpg` run.
3. The server queues the detached metadata and the ref writes in the
   transaction. The policy regenerates the summary when
   `[core] auto-update-summary` is true ("Config file (`<repo>/config`,
   GKeyFile / INI)"). The server can also stage the anchor commit of
   `ostree-metadata` in the transaction. It does so if the policy regenerates
   the summary, a ref changes, and the repository has a collection id. The
   server reads the tip of `ostree-metadata` under the update lock. A failure
   of the anchor commit is `internal`, and the server publishes nothing.
4. The server commits the transaction. The transaction releases the
   repository lock at the end of this step.
5. The server removes `state/<commit>.commitpartial` of each commit of the
   session.
6. If the policy regenerates the summary and a ref changed, the server builds
   the summary. It signs the summary with each key of `sign-summary` of
   `[ex-ostrya server]`, GPG keys first. Then it removes
   `summary.sig`, writes `summary`, and writes `summary.sig` if
   `sign-summary` names keys. A failed build or signature leaves the old
   `summary` and `summary.sig`.
7. The server releases the update lock. In a session with the hooks of a host
   application, the hook after the update runs next. Then the server sends
   `CommitReply`.

A failure in step 5 or 6 does not fail the commit. The server reports it as a
warning, and the warning does not go on the wire.

The server holds no lock for each ref. Two sessions that update one ref
serialize at step 2: each one reads the refs again and checks the expected
state under the update lock. The transaction commit is not atomic as a whole.
A failure in it can leave the detached metadata and some refs written.

If the send of `CommitReply` fails, the refs stay written, and the report of
the server holds the warning `reply-not-delivered`. If the hook after the
update returns an error, the server sends `internal` in place of
`CommitReply`, and the refs stay written.

## The one-way stream

A one-way stream carries a push in one direction, from a client to a server.
The server sends no message. The stream holds these parts, in this order:

1. one `Hello` with `one-way` true;
2. zero or more object streams, each one closed by `ObjectsEnd`;
3. one `Commit`;
4. the end of the input.

"Frame limits" states the frame limit and the chunk limit. These are
`protocol`:

- a first message other than a `Hello` with `one-way` true;
- a `Have`, and each other message out of this order;
- an `Abort` frame between two objects;
- a byte after `Commit`;
- an update whose state is 1, an update with no `new`, and a `Commit` with
  `server-commit`. The server refuses them when it reads `Commit`.

If a client cannot complete an object, it sends the abandon marker and then
`Abort` ("Abort, abandon, and end of input"). The server then ends the session
with no change.

An ostrya sender also sends the dependencies of each new commit, with no
ref update ("Dependencies in a one-way stream"). An object stream can carry
the composefs image of a sent commit. An ostrya sender sends the image of
each new commit and of each dependency that its repository holds, after the
trees of the commits. The server reads and checks the image as in a push
session ("Object streams").

The server runs `Hello` checks 2, 3, and 5 of a push session ("Hello and
HelloReply"). In place of check 1, a `Hello` with no `one-way` true is
`protocol`, and so is a `Hello` with a `collection`: a one-way stream writes
the local refs and the remote refs. Checks 8 to 11 do not apply. The server
then opens the transaction as in a push session, with the same config reads
and the same `bare` owner check. It reads no ref of `Hello` and sends no
`HelloReply`.

The server accepts a repository with `[core] locking=false`. It then takes no
repository lock, and `Commit` still takes the update lock ("The update lock").

The size check of `CommitReply` (check 2 of "Commit and CommitReply")
applies. The server runs the other `Commit` checks after the end of the
input. Check 6 checks the dependencies of the staged commits as in a push
session. A one-way stream adds no server signature, also to a dependency,
writes no anchor commit, and does not regenerate the summary. It calls no hook of a host application.

A one-way stream keeps rules of its own, and a client group does not apply to
it. A host application gives the rules in code. Each rule has a pattern with
an optional remote part, so a one-way stream can write a remote ref
`REMOTE:NAME`. A rule states if it accepts an update, the trusted keys of
check 8, if it allows a delete, and if it allows an update that is not a
fast-forward under `force`. Check 4 refuses an update that no rule covers
and an update whose rule does not accept it, with `ref-denied`. Check 8 with
trusted keys refuses a commit with no signature. The trusted keys of the rule
of an update also apply to each staged dependency that the staged chain of
its new commit names, so a dependency that two new commits name must pass the
rules of both. Check 11 refuses a delete
that the rule does not allow with `delete-denied`.

## The pull session over a stream

A pull session over a stream gets files of the archive view and ref listings.
The server reads one request, answers it to the end of its body, and then
reads the next request. A reply carries no request id, so the replies come in
the order of the requests.

A client can send a request before the reply to the request before it
arrives. The server flushes its output before each read that can wait, that
is, when its input holds no whole frame.

### PullHello and the version

The first frame of the client must be `PullHello`, else `protocol`. An end of
the input at a frame boundary ends the session with no error, also before
`PullHello`. These ends of the input send an `Error`, and the session ends:

- an end inside a frame is `protocol`;
- a read error of the input is `internal`.

A `PullHello` with version 0 is `version-unsupported`. For each other version,
the server answers with a `PullHelloReply` that holds the lower of the version
of the client and 1. Each side ignores a key of the dict that it does not
know.

Then the client sends any mix of `Get` and `ListRefs`. Each other kind is
`protocol`.

### Get and GetReply

The path of `Get` is relative to the repository root, with no leading `/`.
The server does not percent-decode it. The server answers it as "The archive
view" states, with the read rights of the client of the session ("Read
access"):

- An absent path, a refused path, and a path that the client cannot read
  get a `GetReply` with `found` false. The session goes on.
- A path that the view serves gets a `GetReply` with `found` true, then the
  body as chunks, then a chunk of length 0. `len` is the length of the body.
  A `.filez` built on request has no `len`.
- If the view fails before the reply, the server sends `Error` with
  `internal` in place of the reply, and the session ends.
- If the body fails after the reply, the server ends the body with the
  abandon marker. Then it sends `Error` with `internal` and ends the session.
  A read error, and a stored file that holds fewer or more bytes than `len`,
  are examples. A `.filez` built on request can fail in the same way.

`Get _ostrya/refs/v1` is an absent path. A client gets a ref listing with
`ListRefs`.

### ListRefs

The server answers a `ListRefs` with a `GetReply` with `found` true and
`len`, and then the listing as chunks. The listing holds the refs that the
client of the session reads ("The ref listing"). The entries of field 0
select the local refs. The entries of `collections` select the collection
refs, and with no such key the listing holds no collection ref. The listing
has the same bytes as the body of `GET /_ostrya/refs/v1` for the same
entries and the same rights. A reply to a `ListRefs` with `found` false or
with no `len` is `protocol`.

In these cases, the server sends an `Error` in place of the reply, and the
session ends:

- `protocol`: more than 256 entries in the two lists together, an entry over
  the limits of one entry, or an entry that is not a selector entry ("Ref
  selectors"). The message of a refused entry of `collections` names the
  key.
- `limit-exceeded`: a listing larger than 128 MiB.
- `internal`: each other failure of the build of the listing.

"Ref selectors" states how the server counts the entries.

`ostrya send` writes one warning line to standard error for each directory
that a listing leaves out for its name ("The ref listing"), one time in each
session. The session goes on.

### The pull over HTTP and over a stream

The pull over HTTP sends no frame. A client gets a file with a `GET` of the
archive view, and a ref listing with a `GET` of `/_ostrya/refs/v1`. The
response bodies hold the same bytes as the stream bodies. The answers map in
this way:

- 404 is a `GetReply` with `found` false.
- 500 is an `Error` with `internal`. For a ref listing larger than 128 MiB,
  500 is an `Error` with `limit-exceeded`.
- `Content-Length` is `len`.
- 400 is an `Error` with `protocol`.
- 405 and 503 have no counterpart on a stream.

Over HTTP, the server keeps one copy of an entry that the query repeats ("GET
/_ostrya/refs/v1"). The selection and the bytes of the listing are the same.

A pull of collection refs reads the ref listing or the summary of a remote,
over both transports ("The pull of collection refs").

A pull of the port requests the dependencies of a commit over both
transports, as `.commitmeta` and `.commit` requests of their own ("Dependencies
in a pull from a remote").

A pull of the port requests the composefs image of a commit,
`objects/<first 2 hex>/<remaining 62 hex>.cfs`, over both transports when
each of these is true:

- The commit carries `ostree.composefs.digest.v0`, and its value is a
  variant of type `ay` with 32 bytes. A malformed value counts as no key.
- The pull is not commit-only and has no subpath.
- The repository does not hold an image of the commit, and the transaction
  of the pull did not stage one. The pull does not read a stored image.

The pull requests the image also for a commit that the repository holds
complete. The requests of the images come after the requests of all other
objects of the pull: the pull sends the first image request when no request
of another object is queued or in flight. In a pull
through a chain of static deltas, the images of all commits of the chain
wait for the last step. A 404, or a `GetReply` with `found` false, leaves
the commit with no image, and the pull goes on. A remote of the tool holds
no image, so it answers 404.

A static delta can carry the image of its target commit in a part ("The
composefs image in a static delta"). The application of the part stages the
image, so the pull sends no request for it. The pull does not fetch a
fallback image entry as a fallback object. The image of the commit follows
the rules above. A pull with a subpath requests no image, and stages the
image that a part carries.

After the first image that the remote does not serve, the pull requests no
image of a commit that the repository holds complete. The pull requests the
image of each commit whose objects it takes all the same. The images of the
held commits come after the images of the other commits, and the pull sends
one request for a held commit at a time until the remote serves one. So a
remote that serves no image gets at most one request for the held commits
of a pull. A local pull reads each source for each image, because a source
that holds no image costs only a failed open.

The pull streams the body to its staging directory, computes the fs-verity
digest as it writes it, and installs the image only when the digest is the
key ("The composefs image object"). A digest that is not the key fails the
pull, and the pull writes no ref. The pull fetches that image no second
time. A local pull takes the image from the first source repository that
holds it, with a `FICLONE` reflink or a byte copy, never with a hardlink, and
checks the digest of the copy in the same way.

## The ref listing

A ref listing is a summary GVariant `(a(s(taya{sv}))a{sv})` with no signature.
The server builds it for each request, from the refs that the entries of the
request select ("Ref selectors") and that the client of the request reads
("Read access"). The format is that of "Summary --
`(a(s(taya{sv}))a{sv})`".

A request has two lists of entries:

- The entries of the local refs select local refs by name.
- The entries of the collection refs select the refs under
  `refs/mirrors/ID/` of each other collection by the path `ID/NAME`, for
  example `org.example.Os/stable`, `*/stable`, or `org.example.Os/**`. The
  list is optional. An empty list selects each collection ref. An entry of
  one part, such as `org.example.Os`, selects no ref, and an entry of the
  collection id of the repository selects no ref.

Field 0 holds the local refs:

- The local refs are the refs under `refs/heads` and, in a repository with
  `[core] collection-id=ID`, the refs under `refs/mirrors/ID/`, under their
  plain names. When `refs/heads/NAME` and `refs/mirrors/ID/NAME` both exist,
  field 0 holds one entry `NAME` with the checksum of the mirror ref, and the
  server does not read `refs/heads/NAME`. This is
  the field 0 that the tool writes into a summary ("Summary --
  `(a(s(taya{sv}))a{sv})`"). So a request with no list of the collection
  refs gets the bytes of a listing of `refs/heads` alone in each repository
  with no `refs/mirrors/ID/` of its own id.
- Field 0 is sorted byte-wise by name and holds each ref one time. It holds
  no remote ref.

`ostree.summary.collection-map` holds the collection refs, in the form of
the summary: the collections sorted byte-wise by id, and the refs of each
collection sorted byte-wise by name. A collection with no selected ref is not
in the map. With no selected collection ref, and with no list of the
collection refs, the dict holds no map. The collection id of the repository
is not a key of the map.

These rules apply to each ref of the two parts:

- The listing holds a selected ref when the client group of the item has `r`
  on its name in its namespace: the local namespace for field 0, and the
  namespace of the collection for the map ("Read access"). The rules of two
  groups never combine. The server checks the name before it reads the ref
  file. So it reads no ref file that the client cannot read, and the content
  of such a file fails no listing. The server reads no directory of a
  collection whose group gives no `r`. When the entries of a part hold no
  positive entry, the server reads only the directories that the pattern of
  an allow item of the group that gives `r` can match, and no directory that
  a deny item of the group covers.
- An alias is in the listing under its own name, with the commit of its
  target, when the client reads its name and its target. The alias resolves
  by the rules of "The archive view": the body is relative and stays inside
  `refs/`, and the server follows one link and no symlink on the path of the
  target. The path of the target gives its namespace. These aliases are not
  in the listing: an alias that breaks one of these rules, an alias of an
  alias, an alias to a ref under `refs/remotes/`, and an alias whose target
  is no regular file, for example a directory.
- An alias whose target is absent, and a ref file that a write removes during
  the walk, are not in the listing.
- These refs fail the whole listing when the client reads them, and the
  server leaves out no ref for these causes:
  - a ref file that is not UTF-8, or that holds no checksum;
  - a ref whose commit is not in the object store, or does not parse.
- Each entry has the bytes of the entry of the same ref in a summary of the
  same repository state.

With a list of the collection refs, the server reads the top level of
`refs/mirrors/` one time, whatever the rights of the client. A directory
whose name fails the collection-id rule is left out of the listing, and the
server reads no file in it. The server writes a warning for each such
directory. A name that is not UTF-8, and a file or a symlink at the top level,
are left out with no warning. With no list of the collection refs, the server
reads `refs/mirrors/ID/` of the collection id of the repository alone.

The global metadata dict holds these entries, in this order:

1. `ostree.summary.mode`: `archive-z2`, the mode of the archive view ("The
   archive view").
2. `ostree.static-deltas`: when the walk below finds a delta.
3. `ostree.summary.collection-map`: when the listing holds a collection ref.
4. `ostree.summary.collection-id`: when the repository has a collection id.

This is the order of the same keys in a summary. The dict holds no
`ostree.summary.last-modified`.

In an `archive` repository, the deltas come from the index files under
`delta-indexes/` ("Static delta index files"). The server reads the index
file of the commit of each listed
ref, in field 0 and in the map. Then it reads the index file of each source
commit that an index file names, until it finds no new commit. The map is
sorted by delta name. These index files fail the listing:

- an index file that does not decode, or that is larger than 128 MiB;
- an index file with no `ostree.static-deltas` map;
- an index file that names a delta to another commit.

A `delta-indexes` path that is not a directory also fails the listing. An
absent `delta-indexes/` gives no delta. A commit with no index file adds no
delta, and an index path that is not a regular file counts as no index file.
If an index file names one delta two times, the first entry applies.

In every other mode, the listing names no delta, and the server reads nothing
under `delta-indexes/`. The archive view serves no file under `deltas/` and
`delta-indexes/` in these modes.

A listing is at most 128 MiB. The server refuses a larger listing and never
cuts it short. The collection map counts toward this size. The server checks
a lower bound of the size from the names of the refs and from the collection
ids after each ref that it selects, before it reads a commit. It reads no more
ref file when the bound passes the size. It writes the map one ref entry at a
time, so a listing over the size fails before it is whole in memory.

## The pull of collection refs

`ostrya pull --collection ID [REF]...` pulls refs of the collection `ID` from
the remotes that serve it. The candidates are the `[remote "NAME"]` groups
with `collection-id=ID`, in the order of the config. The `ostree` command does
this work with `find-remotes --pull`.

Before its first request, the pull refuses a `REF` whose entry `ID/REF` is
longer than 4,096 bytes or has more than 256 parts, or whose request target
alone over HTTP (item 2 below) is longer than 16 KiB. It resolves the address
and the trust of each candidate. It also builds the HTTP client of each HTTP
candidate and of each candidate at an `s3://` address, and checks the ssh
command and the send command of each ssh candidate. An error in the config of
any candidate stops the pull.

The pull asks each candidate in turn for the commit of each ref. It opens one
session to each candidate: an ssh client over ssh, or the HTTP client over
HTTP and to an `s3://` address. The pull from a selected candidate uses the
same session.

1. If the remote config asks for a signature on the summary
   (`gpg-verify-summary`, `sign-verify-summary`), the pull reads `summary.sig`
   and `summary`, verifies the summary, and reads the refs from it. No
   signature covers a ref listing, so the pull reads no listing from such a
   candidate.
2. Otherwise, the pull reads a ref listing ("The ref listing"). The entries of
   the local refs are the names `REF`. The entries of the collection refs are
   the names `ID/REF`. A request holds at most 128 names, so it holds at most
   256 entries ("Ref selectors"). Over HTTP, the request target of a request
   is also at most 16 KiB, from `_ostrya/refs/v1` to the end of the query. A
   longer list of names takes more requests.
3. A pull with no `REF` first sends the one entry `!**` of the local refs,
   which selects no ref, and the one entry `ID/**` of the collection refs. If
   the listing states `ID` in `ostree.summary.collection-id`, a second request
   sends no entry of the local refs, which selects each local ref, and no
   selector of the collection refs.
4. If the server answers a listing request with a status from 400 to 499, for
   example 404 from a static server, the pull reads `summary`. A remote with
   no listing and no summary lists no ref. Over a stream session, the server
   always serves the listing.

A candidate at an `s3://` address is a bucket repository ("The S3 bucket
repository"), which serves no ref listing. The pull sends it no listing
request, and reads the refs from its summary alone. It reads `summary`
through the bucket client, as a pull from that remote does. Under a summary
policy it also reads `summary.sig`: it asks for `summary.sig` first, and if
the fetcher admits two requests at once, the two requests are in flight
together. A bucket repository with no `summary` is skipped.
The pull takes the commit that the summary lists for a ref, also when the ref
file of the bucket names another commit.

In the listing or the summary, the refs of `ID` are in field 0 when
`ostree.summary.collection-id` is `ID`. Otherwise they are in
`ostree.summary.collection-map` under `ID`, and the pull ignores field 0. The
timestamp of each ref is its `ostree.commit.timestamp`, a big-endian `t`.

A candidate is skipped, with a warning, when a request fails, when a listing
request gets a status from 500 to 599, when the listing or the summary does
not parse, when the summary fails its signature check, when a listed name
fails the ref-name rule, when a listed ref has no `ostree.commit.timestamp` of
type `t`, or when a bucket repository has no `summary`. The pull fails when
each candidate is skipped, when no candidate lists a requested `REF`, and,
with no `REF`, when no candidate lists a ref of `ID`. These failures come
before the first object request.

For each ref, the pull selects the candidate with the newest listed
timestamp. A tie goes to the first candidate in the config. After the
selection, the pull ends the session of each candidate with no selected ref.
The pull then takes the objects of the refs of each selected candidate, in
the order of the config, as a pull from that remote does at the listed commit
(`conformance/cli-behavior.md`, "HTTP pull surface"). It uses one transaction
for each such candidate. If the probe read the refs from the summary, the pull
uses those bytes. Otherwise it reads the `summary.sig` and the `summary` of
the candidate. It reads the `config` of the candidate, and no ref file. It
reads the `config` of a bucket repository through the bucket client. The
keys of that candidate verify its commits. A failure of a selected candidate
stops the pull, and the refs of the earlier candidates stay written.

The pull refuses a commit:

- whose `ostree.collection-binding` is not `ID`, or that has no such key;
- whose `ostree.ref-binding` is present and does not hold `REF`;
- whose timestamp is not the listed timestamp of `REF`.

The pull writes `refs/mirrors/ID/REF`. In a repository with
`[core] collection-id=ID`, it writes `refs/heads/REF`. It writes no ref under
`refs/remotes/`.

## Summaries of auth items

The port writes the root summary ("Summary -- `(a(s(taya{sv}))a{sv})`") and
one summary for each auth item that has a summary. An auth
item has a summary when one or more of its client groups has
`summary=true` (`ostrya-config(1)`, "Client keys"). Each other item has no
summary. The two implicit groups of a repository with no client group set
`summary=true`, so the `anonymous` item there has a summary.

### The refs and the deltas of a summary

The summary of an item is a summary GVariant with the format of "Summary --
`(a(s(taya{sv}))a{sv})`". It holds the refs of a ref listing whose two lists
of entries are empty ("The ref listing"), with these changes:

- In each namespace, the server first selects the group of the item, as
  "Read access" states. When that group has `summary=false`, the summary
  holds no ref of the namespace. No other group takes its place.
- No group takes the claims of a client certificate. A group with
  `tls-accept-claim=true` cannot set `summary=true`.

So field 0 holds the local refs that the item reads, with the refs of
`refs/mirrors/ID/` of `[core] collection-id` under their plain names. The
collection refs go into `ostree.summary.collection-map`, and a collection
with no such ref is not in the map. A directory under `refs/mirrors/` whose
name fails the collection-id rule is in no summary. `ostree-metadata` is a
local ref, and a summary holds it only when the item reads it.

The global metadata has the keys and the order of "Summary --
`(a(s(taya{sv}))a{sv})`". Each summary of one run has the same
`ostree.summary.last-modified`. The summary of an item states `archive-z2` in
`ostree.summary.mode` in each mode, because the archive view serves the
repository as an `archive` repository. The caller keys of `summary -m` go into
each summary.

Outside the `archive` mode, the summary of an item has no
`ostree.static-deltas` and no `ostree.summary.indexed-deltas`, and it drops
these two caller keys. The archive view serves no file under `deltas/` and
`delta-indexes/` in these modes. In an `archive` repository,
`[core] indexed-deltas` sets `ostree.summary.indexed-deltas` in the summary
of each item, and `ostree.static-deltas` lists these deltas:

- When the summary holds each local ref and each collection ref of the
  repository, the map lists each delta.
- Else the map lists the deltas whose `TO` commit is the commit of a ref in
  the summary. Another delta can name a commit that the item does not read,
  and the checksum of a commit is enough to fetch it.

### The files of a summary

`HEX` below is the SHA-256 digest, in 64 lowercase hex digits, of the text of
the item in its parsed form (`ostrya-config(1)`, "Authentication items"). For example,
the text of `net:2001:0db8::/56` is `net:2001:db8::/56`.

- The root summary is `summary` and `summary.sig` in the repository root,
  where the tool writes them. It has no `.access` file.
- The summary of each item, `anonymous` included, is
  `extensions/ostrya/summary/HEX` and `extensions/ostrya/summary/HEX.sig`.
  The signature file has the format of "Summary signature -- `a{sv}`".
- Each item with a summary, `anonymous` included, has
  `extensions/ostrya/summary/HEX.access`. The file holds the access digest of
  the item in 64 lowercase hex digits and a newline.

`ostrya-repo(5)` states the modes of the files and of the directories.

### The access digest

The access digest of an item is the SHA-256 digest of this text:

```
collection-id=ID
namespace=NS
allow=ITEMS
deny=PATTERNS
summary=BOOL
```

- The text starts with the line `collection-id=ID`. `ID` is
  `[core] collection-id`, and it is empty when the repository has no
  collection id.
- Then each group of the item adds the four lines `namespace=`, `allow=`,
  `deny=`, and `summary=`, a group with `summary=false` too. The groups come
  in the byte-wise order of their `namespace=` lines.
- `NS` is empty for the local refs, `*` for `collection=*`, and else the
  collection ids, sorted byte-wise and joined by `;`.
- `ITEMS` is the allow items in the form `MODES:PATTERN`, with the modes in
  the order `r`, `w`, `c`, `t`, `d`. Each distinct item occurs one time. The
  items are sorted byte-wise and joined by `;`.
- `PATTERNS` is the deny patterns, in the same way.
- `BOOL` is `true` or `false`, the value of `summary` of the group.
- Each line ends with a newline.

For example, the text of the `anonymous` item of the two implicit groups in
a repository with no collection id is:

```
collection-id=
namespace=
allow=r:**
deny=
summary=true
namespace=*
allow=r:**
deny=
summary=true
```

The text holds each group that the item can select in a namespace. A group
with `summary=false` gives no ref, and it also keeps a group of `*` from the
refs of its collection. So the access digest changes when a change to the
config can change the refs of the summary. The group names are not in the
text, so a new group name keeps the digest.

### The write of the summaries

`ostrya summary -u` first writes the root summary. It builds the summary
and makes each signature, removes the old `summary.sig`, writes `summary`,
and writes the new `summary.sig` when a key signs. With
`[core] fsync=true`, it then syncs the repository root.

Then it writes the summary of each item that has a summary, one item at a
time, in the order of the first group of each item in the config:

1. It builds the summary and makes each signature. A summary with the bytes
   of an earlier summary of the run takes the signatures of that summary.
2. When the `.access` file of the item holds another digest, it removes
   that file.
3. It removes the old signature file, writes the summary, and writes the new
   signature file when a key signs.
4. When the `.access` file of the item does not hold the access digest of
   the item, it writes the `.access` file.

So while the `.access` file of an item holds a digest, the summary next to
it is a summary of that digest. With `[core] fsync=true`, the command syncs
the directory of the `.access` file after the removal of step 2 and after
the write of step 4, and the directory of the summary before step 4. A crash
then cannot leave an `.access` file next to a summary of another digest.

A summary is at most 64 MiB (67108864 bytes). The command refuses a larger
summary before it writes a file of the summary, and each reader of a
summary in the port refuses a larger file. The summaries before the refusal
keep their new files, and the summary of the refusal and the summaries after
it keep their old files. The root summary comes first.

Then it removes the files under `extensions/ostrya/summary/` of each item
that has no summary, the `.access` files first. It removes the temp files of
these names. It leaves each other entry of the directory.

`ostrya summary -u -c` writes the summaries of the items alone. It does not
build, sign, or write the root summary, so `summary` and `summary.sig` stay
as they are. The steps for each item and the removal are the same.

The command checks every `-m` value, every key, and the client groups before
it writes a file. A refusal leaves each summary as it was. The command holds
the repository lock shared and the update lock for the whole run ("The
update lock").

With `[core] auto-update-summary=true`, a push through `ostrya serve` or
`ostrya receive` that changes a ref writes the root summary and each
summary of an item again, as `ostrya summary -u` does. The key groups of `sign-summary` sign them, GPG
keys first. A one-way stream writes no summary.

A mirror pull that writes `summary` writes no file under
`extensions/ostrya/summary/`.

### The serve of a summary

The server computes the access digest of each item at start. A request for
`summary` or `summary.sig`, over HTTP and over a stream, gets the file of the
summary of the identified item under `extensions/ostrya/summary/` ("The
files of a summary"). The server never serves the root summary. The request
gets the answer of an absent path in these cases:

- The item has no summary.
- The file does not exist.
- The `.access` file of the item holds another digest than the access
  digest of the item, or does not exist while the file exists.
  `ostrya serve` writes an error to stderr one time for each item in each
  run, and `ostrya send` one time in each session. The error names the item
  and tells the operator to run `ostrya summary -u`.

The server reads the files for each request, so `ostrya summary -u` takes
effect while the server runs. It opens the file first and then reads the
`.access` file. Before it serves the file, it checks that the name of the
file still names the file that it opened. When a write replaced the file
during the request, the server starts again, at most three times, and then
answers as for an absent path. Over HTTP, a 200 and a 404 of `summary` and
`summary.sig` carry `Cache-Control: private`, because the body depends on
the client. A 401 and a 403 do not. The server opens each component of the
paths with no symlink followed. A request for a path under
`extensions/ostrya/` gets 404.

## The endpoints of `ostrya serve`

`ostrya serve` answers HTTP requests with three endpoints: the archive view,
the ref listing at `/_ostrya/refs/v1`, and the receive endpoint of a push
under `/_ostrya/receive/v1/`. No repository layout uses a path under
`/_ostrya/`. Each endpoint identifies the client of a request
("Authentication of the receive endpoint"). With `proxy-protocol=true`, each
connection starts with a PROXY protocol header before the TLS handshake and
the first request ("Authentication of the receive endpoint" states its
rules).

### Routing

The server routes a request by these rules, in this order:

1. With a receive endpoint, a request whose raw path starts with
   `/_ostrya/receive/v1/` goes to the receive endpoint, if its method is not
   `GET` or `HEAD`.
2. A request whose raw path is `/_ostrya/refs/v1` goes to the ref listing, for
   each method.
3. Each other request goes to the archive view. A method other than `GET` and
   `HEAD` gets 405 with `Allow: GET, HEAD` and `Content-Length: 0`. Then the
   server identifies the client ("Read access"). Then a path that does not
   decode gets 404.

The first two rules compare the raw path, with no percent-decoding. A path
under `/_ostrya/` that matches neither rule gets the rules of the archive
view, for example `/_ostrya/receive/v2/session`.

A `GET` and a `HEAD` under `/_ostrya/receive/v1/` go to the archive view and
get 404. `ostrya serve` always has the receive endpoint. A server of
`ostrya-server` with no receive policies has no receive endpoint, so a `POST`
and a `DELETE` under that prefix go to the archive view and get 405.

A host application can mount the receive endpoint in a router of its own
("Commit and CommitReply", check 9, defines the term). There, each method
other than the method of a known route of the endpoint, `GET` and `HEAD`
included, gets 405 with `Allow: POST` or `Allow: DELETE`.

### The archive view

`ostrya serve` serves a repository of any mode as an archive repository, so
that the tool can pull from it. `ostrya send` serves the same view over a
stream ("Get and GetReply"). The view answers a path relative to the
repository root in this way:

- The view builds `config`: `[core]\nrepo_version=1\nmode=archive-z2\n`, then
  `collection-id=ID\n` when the repository config sets it. In an `archive`
  repository, `indexed-deltas=VALUE\n` comes next when the repository config
  sets it. Each value is as the repository config writes it. The
  view serves no other key and no other group. The view parses the
  repository config again when its inode number, size, modification time, or
  change time differs from the last parse. The next answer then shows the
  change.
- The view serves these files as stored: the files under `refs/` and
  `extensions/`, and the `.commit`, `.dirtree`, `.dirmeta`, `.commitmeta`,
  and `.cfs` objects. A `.cfs` object is the composefs image of a commit, in
  every mode. In an `archive` repository, it also serves the
  `.filez` objects and the files under `deltas/` and `delta-indexes/` as
  stored. "Read access" states which of these files a client gets.
  `extensions/ostrya` and each path under it are absent.
- `summary` and `summary.sig` are the files of the summary of the auth item
  of the client, as stored ("The serve of a summary"). The root summary is
  never served.
- In each other mode, the view builds a `.filez` object on request. The
  object is the framed archive header of the logical metadata that the mode
  stores, then the payload in raw DEFLATE at `[archive] zlib-level`. An
  `archive` repository of the port stores the same bytes for the same object
  at the same level. A symlink object is the header alone.
- The file of a built `.filez` can hold another size than its header states.
  Then the body fails during the transfer, after the status and the headers
  went out.
- In these modes, `deltas/` and `delta-indexes/` are absent. The summary of
  an item and the ref listing name no delta ("The refs and the deltas of a
  summary", "The ref listing"), so a pull fetches the objects loose.
- The view serves a ref alias under `refs/` as the ref that it names, when
  that ref is a regular file under `refs/`. The view resolves `.` and `..` in
  the alias body by name, from the directory of the alias, with no lookup in
  the file system. These paths are absent:
  - an alias of an alias;
  - an alias with an absolute body, also one that names a file under
    `refs/`;
  - an alias body that is not UTF-8;
  - an alias body with a `..` that goes above `refs/` at any step, also when
    the end result is under `refs/`;
  - an alias body with an empty component, as a trailing `/` gives;
  - an alias body with a component that the view refuses by name, for example
    a component that starts with `.`, other than `.` and `..`;
  - a symlink at another place on a path.

  The walk starts at the `objects/` directory that the repository handle
  opened, so the view follows a symlink at `objects/` itself.
- The view refuses these paths:
  - `.lock` and `.update.lock`;
  - `tmp` and `state`, and each path under them;
  - each path with an empty component or with a component that starts with
    `.`;
  - a `.file` path, and each path outside the families above;
  - a name longer than the kernel accepts.

  A refused path and an absent path get the same answer.
- A directory on the path that the server cannot search, and a file that the
  server cannot open, are errors of the view.

Observed behavior: with no summary, a pull of an alias name succeeds when the
commit has no ref binding.

One view deflates at most 16 `.filez` objects at the same time. The payload
of another built `.filez` waits until a compressor is free. `ostrya serve`
has one view. Each `ostrya send` session has its own view.

Over HTTP, `ostrya serve` applies these rules:

- The server removes the leading `/` of the request path and percent-decodes
  the rest. An escape takes hex digits in either case, and `+` stays `+`. A
  path with a bad escape, a NUL, or bytes that are not UTF-8 gets 404. A
  request path with no leading `/` gets 404.
- The server ignores the query. It identifies the client with the headers of
  the request ("Read access").
- A path that the view serves gets 200 with its bytes. The response carries
  `Content-Length` when the view knows the length. A `.filez` built on
  request has no `Content-Length`.
- An absent path and a refused path get 404 with an empty body and
  `Content-Length: 0`. An error of the view gets 500 with an empty body and
  `Content-Length: 0`.
- No response of the view carries `Content-Type`.

A `HEAD` gets the status and the `Content-Length` of a `GET`, with no body.
For a `.filez` built on request, a `HEAD` reads no byte of the object, no
xattr, and no `config`. So the two methods give different statuses in these
cases:

- In a `bare-split-xattrs` repository, a `HEAD` checks the
  `.file-xattrs-link` entry before the object. A `GET` checks the object
  first. A missing object in a fan-out directory that exists gets 500 for
  `HEAD` and 404 for `GET`. A present object with no `.file-xattrs-link`
  entry gets 500 for both methods.
- These cases get 200 for `HEAD` and 500 for `GET`:
  - xattrs of a `bare-split-xattrs` object that do not parse;
  - an object whose metadata does not parse, or whose archive header the
    view cannot write;
  - a `config` that the server cannot read as a repository config;
  - an `[archive] zlib-level` value that is not a signed 64-bit decimal
    integer, a value with a leading `+` included. The view clamps a value in
    that range to the range 1 to 9.

For a built `.filez`, the result of the `config` read of a `GET` has
precedence over the result of the object lookup. So a missing object in a
repository with a bad `config` or `zlib-level` gets 404 for `HEAD` and 500
for `GET`.

The summary of an item states `archive-z2` in `ostree.summary.mode` in each
mode, `bare-user-shared` included. Observed behavior: the tool refuses a
summary that states `bare-user-shared`. So the tool pulls with a summary from
a `bare-user-shared` repository only because the summary states
`archive-z2`. The root summary states `bare-user-shared`,
and the view never serves it.

### Read access

`ostrya serve` and `ostrya send` serve the files of the archive view and the
ref listing to an identified client alone. `ostrya serve` identifies the
client of each request by the steps of "Authentication of the receive
endpoint". `ostrya send` identifies the client of a session by its name
(same section). A request that identifies no item gets the status of its
refusal, 401 or 403, with an empty body and `Content-Length: 0`. A 401
carries the two `WWW-Authenticate` headers. The server sends no message of
the refusal. The steps also apply in a repository with no client group: a
credential over plain HTTP gets 403, and a credential that matches no item
gets 401.

A client certificate whose claims do not parse gets 403 for each read, also
for an object and `config`, when a group with `tls-accept-claim=true`
carries its item. For each such read, `ostrya serve` writes the error line of
"Claims of a client certificate".

The client group of the item then gives the rights (`ostrya-config(1)`,
"Access modes and patterns"):

- `refs/heads/NAME` is in the local namespace. `refs/mirrors/ID/NAME` is in
  the namespace of the collection `ID`. When `ID` is `[core] collection-id`,
  the path is in the local namespace: the group of the local refs gives the
  rights of `NAME`, and a group of `collection=*` does not apply.
- The server serves such a ref when the group of the item in its namespace
  has `r` on `NAME`. `w`, `c`, and `t` include `r`, and `d` alone does not.
  In a group with `tls-accept-claim=true`, the claims of the namespace
  replace the rules of the group ("Claims of a client certificate").
- An alias needs `r` on its name and on its target. A target in another
  namespace takes the group of the item in that namespace.
- `refs/remotes/`, each other path under `refs/`, and `extensions/ostrya/`
  are not served. An id under `refs/mirrors/` that fails the collection-id
  rule selects no group, so its refs are not served, and the ref listing
  leaves out its directory ("The ref listing").
- `summary` and `summary.sig` are the files of the summary of the item
  ("The serve of a summary"). An item with no summary gets the answer of an
  absent path.
- Objects, `deltas/`, `delta-indexes/`, `config`, and the other files under
  `extensions/` are served to each identified client. The checksum of an
  object is the capability.

A path that the client cannot read gets the answer of an absent path: 404
over HTTP, and a `GetReply` with `found` false over a stream. The server
checks the rights before it opens a file, so it reads no ref that the client
cannot read.

A repository with no client group has two implicit groups
(`ostrya-config(1)`, "No client group"). Each client then reads each local
ref and each mirror ref, and gets the summary of the `anonymous` item. A
server of `ostrya-server` with no
receive policies identifies no client. Each read there gets the rights of
the `anonymous` item under the two implicit groups. `ostrya serve` always
reads the client groups.

### GET /_ostrya/refs/v1

A `GET` of `/_ostrya/refs/v1` gets a ref listing ("The ref listing"). The
server serves it with and without a receive endpoint, and the listing holds
the refs that the client of the request reads ("Read access"). The version of
the listing is the `v1` in the path, and no request negotiates it.

The query holds the entries of the two ref selectors of "The ref listing":

- `&` splits the query into pairs.
- Each pair is `pattern=VALUE`, an entry of the local refs, or
  `collection=VALUE`, an entry of the collection refs. The key is the raw
  bytes `pattern` or `collection`, with no decoding, and the case counts.
  The pair splits at its first `=`. The pairs of the two keys can come in
  any order.
- The value is percent-decoded as a path is ("The archive view"), so `+`
  stays `+`. The decoded value is one entry.
- No `pattern` pair gives an empty selector of the local refs, which selects
  every local ref.
- A query with one or more `collection` pairs holds the list of the
  collection refs. A query with no `collection` pair holds no such list, so
  the listing holds no collection ref. A client sends an empty list as the
  one pair `collection=**`, which selects each collection ref.
- The server keeps one copy of an entry that more than one pair of the same
  key gives. Each pair of the two keys counts toward the limit of 256
  entries ("Ref selectors").

The HTTP layer of the server can refuse a request with a long target before
these checks. The rustdoc of `Server` in `ostrya-server`, "HTTP behavior",
states the limits of the HTTP layer. The server checks a request in this
order:

1. A method other than `GET`, `HEAD` included, gets 405 with `Allow: GET`.
2. The server identifies the client. A refusal gets its status ("Read
   access").
3. A bad query gets 400. A query is bad when it holds one of these:
   - an empty pair, a pair with no `=`, or a pair with a key other than
     `pattern` and `collection`;
   - a raw value larger than 12288 bytes, or a value that does not decode;
   - more than 256 pairs of the two keys together, or an entry over the
     limits of "Ref selectors";
   - an entry that is not a selector entry.

   The server refuses the 257th pair before it decodes it.
4. If 4 listings are in flight over all connections, the request gets 503
   with `Retry-After: 1`. A listing is in flight from the start of its build
   until its response body drops.
5. Each error of the build gets 500, a listing larger than 128 MiB included.

`ostrya serve` writes one warning line to standard error for each directory
that a listing leaves out for its name ("The ref listing"), one time in each
run.

A listing gets 200 with `Content-Length`. The body is the raw listing, with
no frame. A 400, a 405, a 500, and a 503 have an empty body and
`Content-Length: 0`. No response carries `Content-Type`.

### The receive endpoint

Each request under the raw path prefix `/_ostrya/receive/v1/` is one step of a
push session. The endpoint does not percent-decode the path, and it ignores
the query. The routes are these:

- `POST session` opens a session. The body is one `Hello` frame. The answer
  is 200 with the `HelloReply` frame and the header `ostrya-session`, which
  holds the session id.
- `POST session/ID/have`: the body is one `Have` frame. The answer is 200 with
  `HaveReply`.
- `POST session/ID/objects`: the body is one object stream. The answer is 200
  with `ObjectsReply`.
- `POST session/ID/commit`: the body is one `Commit` frame. The answer is 200
  with `CommitReply`.
- `DELETE session/ID` ends the session and its requests in flight. The answer
  is 204 with no body and no `Content-Length`.

The steps of a session map to the messages of a push session over a stream.
`DELETE` takes the place of `Abort`, and the status of an error follows its
code ("Error codes").

A session id is 32 bytes from the random source of the operating system,
written as 64 lowercase hex digits. The endpoint accepts an id in that form
alone. If the random source fails, `POST session` gets 500 with `internal`.

`POST session` runs these steps in this order:

1. It reads the `Hello` frame. The whole body must arrive within the idle
   time of the endpoint, else the request gets 422 with `protocol`.
2. A `Hello` with `one-way` true gets 422 with `protocol`.
3. It runs checks 2 to 7 of "Hello and HelloReply". Step 2 is check 1.
   These checks do not read the client group.
4. It takes a place in the session table. The open sessions, the sessions
   that open now, and the sessions that commit count toward the session
   limit of the endpoint. If they reach the limit, or if the endpoint stops,
   the request gets 503 with `limit-exceeded`.
5. It makes the session id.
6. It gets the setup of the session from the authentication of the
   endpoint. A refusal gets 401 or 403 with `unauthorized`, and the place in
   the table becomes free. Under `ostrya serve`, an item that no client group
   of the namespace of `Hello` carries, and a client group that opens no push
   session, give a refusal with 403.
7. It runs checks 8 to 11 of "Hello and HelloReply" with the client group of
   the setup. Then it opens the session transaction, as "Hello and
   HelloReply" states. If the endpoint stopped during these steps, the
   request gets 503 with `limit-exceeded`.

The idle time, the session limit, and `parallel-uploads` are settings of the
endpoint. `ostrya-serve(1)` states the options that set them for
`ostrya serve`, with their defaults.

These requests get 404 with an empty body:

- a path under the prefix that names no route;
- an id that is not a session of the owner of the request
  ("Authentication of the receive endpoint");
- a session that ended.

These events end a session:

- a commit, a failed step, and a `DELETE`;
- a request that ends before its response;
- a request body that sends no byte for the idle time;
- the idle time with no request in progress;
- a stop of the endpoint.

A known route with another method that reaches the endpoint gets 405 with an
empty body and `Allow: POST` or `Allow: DELETE`. Under `ostrya serve`, a `GET`
and a `HEAD` do not reach the endpoint ("Routing").

The body of `session`, `have`, and `commit` is exactly one frame of at most
1 MiB. An empty body, a short body, a frame length of 0, bytes after the
frame, and a frame of another kind get 422 with `protocol`. A larger frame
gets 422 with `limit-exceeded`. The body of `objects` is one object stream,
from the first `ObjectHeader` or `ObjectsEnd` to `ObjectsEnd`, and then the
end of the body. These bodies of `objects` get 422 with `protocol`, and the
session ends:

- a body that ends before `ObjectsEnd`;
- a byte after `ObjectsEnd`;
- an `Abort` frame in the body, with or without the abandon marker before it.

The body of `objects` has no size limit of its own. It can carry a composefs
image of any size ("Object streams").

A request body that fails, for example with a malformed chunked encoding,
gets 500 with `internal`. The session ends as for a request that ends before
its response.

Each response body that is not empty is one frame, and the response carries
`Content-Length`. The endpoint adds no `Content-Type` and no `Retry-After` to
a response. An `Error` frame larger than 1 MiB is replaced with a short
`internal` frame and the status 500.

The endpoint drains the request body before some answers: a 404, a 405, a
refusal of the authentication, and the answer to a `DELETE`. It reads and
drops the body until the body ends, until more than 1 MiB has arrived, or
until a time limit ends. A failed step answers at once, with no drain, so
bytes of the request can stay unread.

One session runs its steps by these rules:

- Up to `parallel-uploads` `objects` requests run at the same time. One more
  gets 422 with `limit-exceeded`, and the session ends.
- One `have` request runs next to them. A second one gets 422 with
  `limit-exceeded`, and the session ends.
- A `commit` request needs no other request of the session in flight. Else
  it gets 422 with `protocol`, and the session ends.
- An `objects` request counts from its start. A `have` request counts from
  the end of its body. A `DELETE` does not count.
- A failed step ends the session, unless the session commits. Each other
  request of the session in flight then gets 422 with `protocol` and the
  message `the session was aborted: CAUSE`.
- A request that ends before its response ends the session, unless the
  session commits.
- The endpoint aborts a session with no request in progress for the idle time
  of the endpoint. It also aborts a session whose request body sends no byte
  for that time.

The commit runs in a task of its own. A `DELETE`, a disconnect, and the idle
time do not stop it. A host application that stops the endpoint and keeps
its process running lets the commit go on to its end. `ostrya serve` has no
graceful shutdown: when its process ends, a commit in progress ends with it.
While the commit runs, each other request of the session gets 422 with
`protocol`, and the commit goes on. These requests are a `have`, an
`objects`, a second `commit`, and a `DELETE`. After the commit, each request
of the session and a `DELETE` get 404.

### Authentication of the receive endpoint

The endpoint checks the route and the method before it authenticates a
request. So a client with no credential gets 404 or 405 for a bad route or
method. The endpoint authenticates a request before it reads a byte of the
body.

`ostrya serve` identifies the client of a request by the auth items of the
client groups (`ostrya-config(1)`, "Authentication items"). The steps apply
to each request of `ostrya serve`: the requests of the receive endpoint, and
the reads of the archive view and of the ref listing ("Read access"). The
identification gives one auth item. The server takes the first step that
applies:

1. A request with more than one `Authorization` header gets 401.
2. Over plain HTTP, a `Bearer` or `Basic` credential gets 403, unless
   `allow-cleartext-credentials` is true, from the key or from the option of
   `ostrya serve`, or a trusted proxy reports the scheme `https`. This step
   also applies when a group has the `anonymous` item.
3. A request with an `Authorization` header gets the item of its
   credential. A credential that matches no item gets 401, also when the
   request has a client certificate. A header with another scheme gets 401.
4. A request with a client certificate gets the first item that matches, in
   this order: `tls-sha256:HEX`, `tls:NAME`, `tls:*`. A certificate that
   matches no item gets 403. From a trusted proxy with
   `trusted-proxy-client-cert`, the certificate comes from that header
   alone, and never from the TLS handshake. A server with no
   `tls-client-ca` gets no client certificate, so its `tls-sha256:HEX`,
   `tls:NAME`, and `tls:*` items match no request. The other items of
   their groups still match. `ostrya serve` with no `tls-cert` and no
   `trusted-proxy-client-cert` ignores the `tls-client-ca` key, so a plain
   HTTP server and an HTTPS server can serve one repository.
5. A request whose client address is in the network of a `net:` item gets
   that item. When two items match, the item with the longer prefix wins.
6. A request gets the `anonymous` item, if a group has it.
7. Else the request gets 401 when a `token-sha256` or a `basic-sha256` item
   exists, and 403 when none exists.

The server splits `Authorization` at its first space, and removes the ASCII
white space at the start of the rest. The scheme compares with no regard to
case.

- A bearer token gets the item `token-sha256:HEX`. `HEX` is the SHA-256
  digest of the token. The first field of the output of
  `printf %s "$TOKEN" | sha256sum` gives it.
- A Basic credential is the base64 of `USER:PASSWORD`. `USER` runs to the
  first `:`, so `PASSWORD` can hold `:`. The padding of the base64 is
  optional. The credential gets the item `basic-sha256:USER:HEX`, where
  `HEX` is the digest of the password.
- These credentials match no item:
  - an empty token, also `Bearer` with no space after it;
  - a Basic value that is not base64, for example a value that holds a
    `!`;
  - a Basic credential with no `:` or with an empty password;
  - a Basic credential whose user name is not UTF-8.

The server compares the digest of a bearer token with every `token-sha256`
item in constant time. It compares the digest of the user name and the digest
of the password of a Basic credential with every `basic-sha256` item in
constant time. It does not stop at a match.

With `tls-client-ca`, the TLS handshake verifies a client certificate against
the CA. A client with no certificate also connects. The server reads the
end-entity certificate one time for each connection:

- `tls-sha256:HEX` compares the SHA-256 digest of the DER bytes of the
  certificate.
- `tls:NAME` compares the CN of the subject with `NAME`, byte for byte. The
  subject must hold exactly one CN, in any RDN, of type UTF8String or
  PrintableString. A subject with no CN, with two CNs, or with a CN of
  another type matches no `tls:NAME` item. A certificate whose bytes do not
  parse matches no `tls:NAME` item, and can match `tls-sha256:HEX` and
  `tls:*`.

The client address is the TCP peer address, with the changes of the PROXY
protocol and of the trusted proxies below. An IPv4-mapped IPv6 address
counts as its IPv4 address.

With `proxy-protocol=true`, each listener reads a PROXY protocol header at
the start of each connection, before the TLS handshake. The source address
of the header replaces the peer address. A connection with no valid header,
a connection that ends or fails in the header, and a connection with no
header within 30 seconds close with no byte of response. The bytes after the
header go to the TLS handshake or to the first request. Each peer that can
connect states its own client address in the header, so only the proxy must
be able to reach the listener. The header is one of these forms:

- Version 1, a text line. The line starts with `PROXY ` and ends at its
  first CRLF, with at most 107 bytes, the CRLF included. `TCP4 SRC DST SPORT
  DPORT` and `TCP6 SRC DST SPORT DPORT` give the address `SRC`. One space
  separates two fields, each address is of the family of the protocol, and
  each port is decimal digits alone, at most 65535. `UNKNOWN`, with any rest
  of the line, gives no address. Each other line is not valid, for example
  `UDP4` or a protocol in lowercase.
- Version 2, binary. The header is the 12-byte signature
  `\r\n\r\n\0\r\nQUIT\n`, a byte with the version 2 and the command, a
  family byte, a 16-bit big-endian length, and that number of bytes. The
  command `LOCAL` gives no address, and the server ignores its family.
  Under the command `PROXY`, the family `0x00` gives no address, `0x11`
  gives the IPv4 source address of an address block of at least 12 bytes,
  `0x21` gives the IPv6 source address of a block of at least 36 bytes, and
  `0x31` gives no address, with a block of at least 216 bytes. Under
  `PROXY`, each other family is not valid, for example a datagram family.
  Each other version and command is not valid. The server ignores the TLVs
  after the address block.

A header with no address keeps the peer address. The check of
`trusted-proxy` below uses the source address of the header, so the server
does not read the forwarding headers and the forwarded certificate of a proxy
that states the address of its client in the PROXY header.

`trusted-proxy` lists the networks of the trusted proxies, and
`trusted-proxy-header` names the one request header from which the server
reads the client address of a request from a trusted proxy: `forwarded`,
`x-forwarded-for`, or `x-real-ip`. Each key needs the other. When the peer
address is in `trusted-proxy`, the server reads that header and no other
header of a client address:

- `Forwarded` (RFC 7239): each element of the list is one hop. A pair is
  `NAME=VALUE`, the names compare with no regard to case, and a value is a
  token or a quoted string with `\` escapes. The `for` value of a hop is
  `IPV4`, `"IPV4:PORT"`, `"[IPV6]"`, or `"[IPV6]:PORT"`. `unknown`, an
  obfuscated name such as `_hidden`, a hop with no `for`, and another value
  give a hop with no address. An IPv6 address with no quotes, an
  unterminated quoted string, and another value that does not tokenize give
  a client with no address.
- `X-Forwarded-For`: each item of the comma list is one hop, with the white
  space around it removed: `ADDR`, `IPV4:PORT`, or `[IPV6]:PORT`. Another
  item is a hop with no address.
- `X-Real-IP`: one hop, in the forms of an `X-Forwarded-For` item.

In each form, `PORT` is decimal digits with a value of 65535 at most. A hop
with a larger port is a hop with no address.

The lines of the header join in their order. The server walks the hops from
the right, and skips each hop whose address is in `trusted-proxy`. The first
other hop is the client. When all hops are trusted, the client is the
leftmost hop. A hop with no address gives a client with no address, which
matches no `net:` item: the server does not take the address of the proxy in
its place. A header that is absent, or that has one line of white space
alone, keeps the peer address. A header with other text and no hop, for
example `X-Forwarded-For: , ,` or `Forwarded: ;`, gives no address. A header
that is not UTF-8 gives no address.

From a trusted proxy, the request counts as TLS for step 2 when the proxy
reports the scheme `https`, in any case. With `trusted-proxy-header=forwarded`,
the report is the `proto` of the selected hop. With the other two headers,
it is the rightmost value of `X-Forwarded-Proto`: the last comma item of its
last line, with no white space around it. The server reads the scheme also
when the header of the client address is absent.

`trusted-proxy-client-cert` names the request header that carries the
client certificate from a trusted proxy. It needs `tls-client-ca` and
`trusted-proxy`. The server reads the header for each request and never
keeps the result for a connection, because a proxy sends the requests of
many clients over one connection. The server percent-decodes the value, and
`+` stays `+`. Then the value is one of:

- a PEM certificate that starts with `-----BEGIN`, as nginx
  `$ssl_client_escaped_cert` gives it URL-escaped;
- the base64 of the DER bytes, as HAProxy `ssl_c_der,base64` gives it, or
  URL-escaped, as Traefik `passTLSClientCert` gives it.

An empty value, or white space alone, is no certificate. These values get
403 with `unauthorized`: a value with a comma, as the chain of Traefik holds;
more than one line of the header; PEM with more than one `CERTIFICATE`
section; a value that does not decode; and a certificate that does not
verify. The server builds one verifier from `tls-client-ca` at start, and
the TLS handshake and each forwarded certificate use it, also on a plain
HTTP listener. The verifier checks the chain to a CA of `tls-client-ca`, the
validity period, and the `clientAuth` extended key usage. The server uses
no intermediate certificate from the proxy, so `tls-client-ca` must hold
each intermediate CA. The server keeps each verified certificate in a cache
of 1024 entries, keyed by the SHA-256 digest of its DER bytes, until the
notAfter time of the certificate. A full cache removes its oldest entry. The
cache keeps no refusal.

From a trusted proxy, the header of `trusted-proxy-client-cert` alone gives
the certificate. The server does not use the certificate of the TLS
handshake, which is the certificate of the proxy. A request with no such
header gives no certificate. From a peer that is not in `trusted-proxy`, or
with no `trusted-proxy-client-cert`, the certificate of the TLS handshake
applies.

From a peer that is not in `trusted-proxy`, the server reads no forwarding
header, no `X-Forwarded-Proto`, and no forwarded certificate. A trusted
proxy must set or remove the header of `trusted-proxy-header`,
`X-Forwarded-Proto`, and the header of `trusted-proxy-client-cert` in each
request. Else a client can send these headers through the proxy, and take
another address, the scheme `https`, or another certificate.

A `session` request then selects the client group that carries the item in
the namespace of its `Hello` ("Hello and HelloReply"). For a collection, a
group that names the collection wins over a group with `collection=*`. The
server does not try another item: a certificate that gets a `tls:NAME` item
gets no group of `tls:*`. These requests get 403 with `unauthorized`:

- a request whose item no group of the namespace carries. The message is
  `no client group of the request covers the local refs`, or
  `no client group of the request covers the collection 'ID'`.
- a request whose group opens no push session. The message is
  `client group 'NAME' opens no push session`. With no client group, the
  implicit group `anonymous` reads each ref and opens no push session.
- a request whose group has `tls-accept-claim=true`, when the claims of the
  certificate do not parse, or when they replace the rules of the group and
  open no push session ("Claims of a client certificate").

Each 401 of `ostrya serve` carries two headers:
`WWW-Authenticate: Bearer realm="ostrya"` and
`WWW-Authenticate: Basic realm="ostrya"`.

The owner key of a request is the text of its auth item, for example
`token-sha256:HEX` or `net:10.0.1.0/24`. A bearer token and a Basic
credential are two items, so they give two owner keys. The endpoint gives a
session to its owner alone. A request of another owner gets 404 for that
session id. All clients with one item share one owner key. So each anonymous
client that knows a session id reaches the session, and so does each client
of one `net:` item. A client certificate that gets a `tls:*`, `tls:NAME`, or
`tls-sha256:HEX` item of a group with `tls-accept-claim=true` gives
`tls-sha256:HEX`, the SHA-256 digest of the DER bytes of the certificate. So
two certificates with different claims never share a session. This key is
the key of no other client. The certificate sets the item that it matches,
and only the certificate of that digest matches the item `tls-sha256:HEX`.

A refusal of the authentication gets its status, 401 or 403, and an `Error`
frame with `unauthorized`. A host application can mount the endpoint with an
authentication of its own. That authentication sets the status of a refusal,
401 or 403, its message, and its headers. The endpoint keeps these headers,
also a `Content-Type` or a `Retry-After`. It drops `Content-Length`,
`Transfer-Encoding`, and `Connection`, because it sets the framing and the
connection state itself. It cuts the message of the refusal to 4096 bytes at
a character boundary.

`ostrya receive` and `ostrya send` identify the client of an ssh session by
its name: `--client NAME`, else the value of `LOGNAME`, which sshd sets from
the password entry of the user. An empty `LOGNAME` counts as absent.
`ostrya receive` gives the session the policy of the client group that
carries `ssh:NAME` in the namespace of `Hello`. With no such group, `Hello`
gets `ref-denied`. `ostrya send` serves the refs
that the client groups of `ssh:NAME` read ("Read access"). When the
repository has client groups and no group carries `ssh:NAME`, `ostrya send`
writes one `error: MESSAGE` line and exits 1 before it reads its input. An
ssh session uses no `anonymous` item and no `net:` item, with one exception:
in a repository with no client group, an `ostrya send` session gets the
`anonymous` item, so the implicit groups apply. `--client` is safe only
under a forced `command=` in `authorized_keys`, because a user with a shell
can give any name.

### Claims of a client certificate

A claim is a URI SAN of a client certificate that states an allow item or a
deny item. A client group with `tls-accept-claim=true` reads the claims of
the certificate that gives the item of a request. A claim has one of these
forms:

- `ostrya:ref:[MODES:]PATTERN` -- an allow item of the local refs.
- `ostrya:ref:!PATTERN` -- a deny item of the local refs.
- `ostrya:collection:ID:[MODES:]PATTERN` -- an allow item of the collection
  `ID`.
- `ostrya:collection:ID:!PATTERN` -- a deny item of the collection `ID`.

`[MODES:]PATTERN` has the grammar of an `allow` item, and `PATTERN` has the
grammar of a `deny` item (`ostrya-config(1)`, "Access modes and patterns").
A claim with no `MODES` has the mode `r`. `ID` passes the collection-id
rule. The server reads the URI SANs alone. It does not percent-decode a
URI, and it removes no white space.

- A group of the local refs reads the `ostrya:ref:` claims, and the
  `ostrya:collection:ID:` claims whose `ID` is `[core] collection-id`. A
  group of a collection reads the `ostrya:collection:ID:` claims of the
  collection of the request.
- When the certificate holds one or more claims for the namespace, they
  replace `allow` and `deny` of the group. Deny claims alone leave no allow
  item, so they give no right.
- When the certificate holds no claim for the namespace, `allow` and `deny`
  of the group apply.
- A URI whose scheme is not `ostrya`, in any case, has no effect. So do the
  SANs of other types, for example a DNS name.

The claims set the access alone. `verify`, `allow-unsigned`, `sign`, and
`allow-privileged` still come from the group, and so does the group name of
the report. The claims can give more rights than `allow` of the group, so
the CA of `tls-client-ca` grants the rights of each certificate that it
signs.

The claims of a certificate do not parse in these cases:

- A URI whose scheme is `ostrya`, in any case, is no claim form. The scheme
  and the kind, `ref` or `collection`, are lowercase in a claim, so
  `OSTRYA:ref:a` and `ostrya:Ref:a` do not parse.
- The certificate holds more than 256 URIs whose scheme is `ostrya`.
- The certificate does not decode. The reason is
  `the certificate does not decode`.
- The certificate holds more than one subjectAltName extension. The reason
  is `the certificate holds more than one subjectAltName extension`.
- The subjectAltName extension does not decode. The reason is
  `the subjectAltName extension of the certificate does not decode`.

The server refuses such a request with 403 and `unauthorized`, when the
selected group has `tls-accept-claim=true`. A claim of another namespace
that does not parse also refuses the request. A read gets 403 when a group
with `tls-accept-claim=true` carries the item of the certificate ("Read
access"). The message starts with
`the claims of the client certificate do not parse: `. `ostrya serve` writes
an error to standard error, which names the SHA-256 digest of the DER bytes
of the certificate and the URI:

```text
error: refused the client certificate tls-sha256:HEX: malformed claim 'URI': REASON
```

When no one URI is at fault, the line has the reason after the digest. The
line writes each control character of the URI and of the reason as an
escape sequence, for example `\n`. A group with `tls-accept-claim=false`
reads no claim, so claims that do not parse have no effect in it.

When the claims replace the rules of the group and open no push session, a
`session` request gets 403. The message is `the claims of the client
certificate open no push session in client group 'NAME'`.

The server reads the claims of the certificate of a TLS handshake one time
for each connection, and the claims of a forwarded certificate one time for
each entry of the cache of forwarded certificates. A cache entry keeps
claims that do not parse too. Claims never apply to a credential, a `net:`
item, an ssh client, or the `anonymous` item, also when the request has a
client certificate.

## Credential files

### The push token file of a client

The key `push-token-file` of a remote and the option `--push-token-file` name
a file that holds the token of a push over HTTP. The token is on the first
line of the file:

- The push takes the bytes before the first LF (0x0a). With no LF, the token
  is the whole file. The push reads at most 1 MiB and one byte of the file,
  and it refuses a first line of more than 1 MiB.
- The push refuses the token in these cases:
  - it holds a CR (0x0d);
  - it is empty;
  - it is not UTF-8;
  - it is not token68.
- A token68 value is one or more ASCII letters, digits, `-`, `.`, `_`, `~`,
  `+`, or `/`, then zero or more `=`.
- The push ignores the bytes after the first LF.
- No message of the push holds the token. The push checks no permission of
  the file.

## Stream transports

### The remote command over ssh

A push or a pull to an ssh address runs the ssh client with this command
line:

```text
SSH_COMMAND... [-p PORT] [USER@]HOST "REMOTE_COMMAND --repo=QUOTED_PATH"
```

- The last argument is one string, and the remote shell parses it.
  `QUOTED_PATH` is the path in POSIX single quotes, and each `'` in the path
  is written as `'\''`. So the path gets no expansion.
- The standard input and the standard output of the ssh client are pipes of
  the session. Its standard error is the standard error of the client.
- `REMOTE_COMMAND` is `ostrya receive` for a push and `ostrya send` for a
  pull by default. `SSH_COMMAND` is `ssh` by default. `ostrya-config(1)`,
  "REMOTE KEYS" and "ENVIRONMENT", states the keys and the environment
  variable that replace them. The man page of each command states its
  options.

A user holds only ASCII letters, digits, `.`, `-`, and `_`. A host holds the
same characters, or it is a host in brackets. A host in brackets holds only
hex digits, `:`, and `.`, then an optional `%ZONE` of ASCII letters and
digits. The client does not check the IPv6 syntax. A user and a host do not
start with `-`. The client gives a host in brackets to ssh without the
brackets.

The address maps to the `--repo` value in this way:

- `ssh://[USER@]HOST[:PORT]/ABSOLUTE/PATH` gives `--repo='/ABSOLUTE/PATH'`.
- `ssh://[USER@]HOST[:PORT]/~/RELATIVE/PATH` gives `--repo='RELATIVE/PATH'`,
  which the remote side reads from its home directory.
- In the scp form `[USER@]HOST:PATH`, a `PATH` that starts with `~/` or `/~/`,
  or with neither `/` nor `~`, is relative to the home directory. Each other
  `PATH` that starts with `/` is absolute.
- After a `~/` or `/~/` prefix, the client removes each further leading `/`
  of the path, so `~//r` gives `--repo='r'`.
- The client refuses a path that starts with `/~` and not with `/~/`, for
  example `/~USER/r`. In the scp form, it also refuses a path that starts
  with `~` and not with `~/`.
- The client refuses a `USER:PASSWORD@` user in the `ssh://` form. In the scp
  form, the first `:` outside brackets ends the host, so `u:p@host:path` gives
  the host `u`.
- The client decodes no percent escape.

The client refuses other malformed addresses too, for example an address
with an empty path or a port out of the range 1 to 65535. The rustdoc of
`SshAddress::parse` in `ostrya-remote` lists each refusal.

### Standard streams and exit status

On the remote side, the standard output of `ostrya receive` and of
`ostrya send` holds the frames of the session alone. Standard error holds an
`error: MESSAGE` line for a failure. For each warning of a session that
committed, `ostrya receive` writes one `warning: STEP: MESSAGE` line.

- `ostrya receive` exits 0 after a session that committed, also with
  warnings. It exits 1 in each other case.
- `ostrya send` exits 0 when its input ends at a frame boundary. It exits 1
  in each other case.

`ostrya receive` and `ostrya send` need a client name ("Authentication of the
receive endpoint"). With no name, each command writes one `error: MESSAGE`
line and exits 1 before it opens the repository. Each command does the same
with a name that an `ssh:` item cannot hold. The message shows the name in
escaped form, so a control character in the name does not split the line. A
refusal writes no frame.

`ostrya receive` reads the client groups, the server group, the trust groups,
and the key groups before it reads `Hello`. If a group does not load, it writes
no frame and exits 1. The exit closes the
standard output, so the client reads the end of the stream with no `Error`
frame.

`ostrya send` reads the client groups and the server group before it reads
`PullHello`. It reads no key of a trust group or of a key group. If a group
does not load, or if the repository has client groups and no group carries
`ssh:NAME`, it writes one `error: MESSAGE` line and no frame, and exits 1.

## The commit of `push-tree`

`ostrya push-tree` walks a local directory on the client, and the server
makes one commit over its tree. The tool has no such command. The commit is a
server commit ("Commit and CommitReply", "Server commit"), and its bytes
follow the rules of that section. `ostrya-push-tree(1)` states the options and
the output of the command.

The client does these steps:

1. It walks and hashes the tree. It builds no commit object and no detached
   metadata.
2. It opens the session with the branch of `--onto`, then each `--tag`, and
   with `--collection` in `Hello`.
3. It sends the objects of the tree that the server does not hold.
4. It sends a `Commit` with the server commit: the branch, the tags, the
   names of `--bind-ref`, the root dirtree and the root dirmeta, the subject,
   the body, the metadata entries in order, the timestamp, and `orphan`.

These rules are specific to `push-tree`:

- The metadata entries are each `--add-metadata-string` entry, then each
  `--add-metadata` entry. The command has no `--keep-metadata`, so no entry
  comes from a parent. The command refuses the keys `ostree.ref-binding` and
  `ostree.collection-binding`, because the server writes them.
- The timestamp is the value of `--timestamp`, else the value of the
  `SOURCE_DATE_EPOCH` environment variable. When neither is set, the server
  commit holds no timestamp, and the server takes its system clock.
- The server writes `ostree.ref-binding` with the branch, each tag, and each
  bound name, sorted. It writes `ostree.collection-binding` with the
  collection of the namespace of the session. The collection id of a local
  repository has no effect.
- The parent is the tip of the branch on the server. With `--orphan`, the
  commit has no parent.
- `--owner-uid`, `--owner-gid`, and `--canonical-permissions` apply to each
  entry of the walk, the root directory included, so they change the root
  dirmeta too. The canonical rule comes first: owner 0:0, no extended
  attributes, and the mode `type | (perm & 0o755)` for each entry other than
  a symlink. Each declared owner id comes after it. The tool applies the
  options to the root dirmeta in the same way.
- The walk reads no extended attributes. The commit checksum depends on the
  tree, the owner, the modes, the subject, and the body. It also depends on
  the metadata options, the timestamp, the parent, the bound names, and the
  collection of the namespace. With equal inputs, the commit checksum is
  equal to the checksum of `ostree commit --no-xattrs -b BRANCH` with the
  same parent, in a repository whose `collection-id` is the collection of the
  namespace. Each tag and each bound name is one `--bind-ref`, and `--orphan`
  is `--parent=none`.

Observed behavior: with `SOURCE_DATE_EPOCH=1700000000` on both sides and no
collection id on either side, both checksums are equal. The checks cover
`--canonical-permissions`, `--owner-uid=0 --owner-gid=0`, `--body-file` alone
and next to `-m`, an explicit `--timestamp`, a second push onto the same
branch, `--tag` and `--bind-ref` against `--bind-ref` of the tool, and
`--orphan` on a new branch against `--parent=none`.

## The composefs image object

A repository of the port can store the composefs image of a commit as a
loose object. The tool has no such object type. A run of `ostrya commit
--generate-composefs` or `ostrya composefs-image --add` and a check of the
stored file can verify each fact below.

The object:

- The type number is 100. The type string is `composefs-image`, and the
  extension is `cfs` in every mode. So the string form of the object name is
  `<commit>.composefs-image`.
- The object name is the checksum of its commit, as for `.commitmeta`. The
  loose path is `objects/<first 2 hex>/<remaining 62 hex>.cfs`.
- The content is the image that an export of the commit with the verity
  digests of the files writes ("composefs"). The repository stores it raw in
  every mode, `archive` included, with no header and no compression. The
  image depends on the tree alone, so `bare`, `bare-user`, and `archive`
  store the same bytes for the same tree.
- The file has the mode `0644` in every mode, whatever the umask, and no
  extended attribute.

The key rule:

- An image exists only for a commit that carries `ostree.composefs.digest.v0`.
  The fs-verity digest of the image is the value of that key.
- The write reads the first entry of the key. Its value must be a variant of
  type `ay` with 32 bytes. The write refuses a commit without the key, a value
  of another form, and an image whose digest is not the value. It checks the
  digest before it installs the image.
- A stored image whose digest is the value stays as it is. The write replaces
  a stored image whose digest is not the value and a stored image that does
  not read.

The write:

- The writer computes the fs-verity digest of the bytes as it writes them, so
  no step holds the whole image.
- With `[ex-integrity] fsverity` not `no`, the write seals the image as it
  seals the other objects ("Write path: fs-verity"). After the seal, it
  compares the digest that the kernel measures with the digest of the writer.
- A transaction renames its images into `objects/` after all its other
  objects and before its refs. The rename replaces a stored image of the same
  commit in one step.

The transfer:

- A pull, a push, and a one-way stream carry the image as the object type
  100, after the other objects of the transfer. "The pull over HTTP and over
  a stream", "Have and HaveReply", and "Object streams" state the rules. A
  push with a server commit carries no image.
- Each receiver computes the fs-verity digest of the bytes and installs the
  image only when the digest is the key of the commit. A local pull copies
  the image with a reflink or a byte copy, never with a hardlink, and checks
  the copy in the same way.
- A receiver that holds an image of the commit takes no second copy. It does
  not read the stored image.
- No key of a client group applies to the image. A push session that may
  write a commit may also send its image.
- A pull and a push send the image also for a commit that the receiver holds
  with no image.
- No object count of a pull, a push, or a receive includes the image. Each
  byte count that the transfer keeps includes it. A local pull keeps a
  byte count only when it reads static deltas.

`ostree.sizes` has no entry for the image, and the decoder refuses the type
byte 100.

Prune removes the image with its commit, and removes an image whose commit is
absent. A kept commit keeps its image. No prune count and no byte count of
freed space includes the image. "Prune removal order" states the order of
the removals.

### The composefs image in a static delta

A static delta to a commit `T` carries the image of `T` if `T` carries a
valid `ostree.composefs.digest.v0` and the repository stores the image. A
delta of a commit with no key or with no stored image has no image entry,
and the image rule changes none of its bytes. A run of `ostrya static-delta
generate` and a check of the superblock and the parts that it writes can
verify the facts of the entry and the selection. `ostrya static-delta show`
prints the count of fallback entries and the object count of each part, and
no type byte. A run of `ostrya static-delta apply-offline` and of a pull can
verify the facts of the application.

The entry:

- The image entry has the type byte 100, and its checksum is `T`. The object
  array of a part or the fallback array can hold it, and the superblock holds
  one image entry at most. The parser refuses an image entry that names
  another commit and a second image entry.
- The image goes into the delta whole. The generator makes no rollsum and no
  bspatch against the image of the source commit, and it does not read the
  image to check its digest.

The selection, where `n` is the size of the image in bytes:

- The image is a fallback entry if `--min-fallback-size` is not 0 and `n` is
  at least its threshold. It is also a fallback entry if `n` is larger than
  `--max-chunk-size` or larger than 128 MiB. So the bound applies also when
  `--min-fallback-size` is 0. The applier holds a whole part in memory, so
  the bound limits the memory that an image in a part needs.
- The image is a fallback entry in each delta of `--inline`, whatever `n`
  is. The generator and the applier hold an inline part in memory, so no
  inline part carries the image.
- Else the image is the last object that the parts carry, under the part
  packing rule ("Part packing"). It can share the last part with other
  objects. Its `S` has the operands `(n, offset)` ("Opcodes").
- A fallback entry states `n` as its compressed size and as its uncompressed
  size.

The application:

- An image in a part needs the key of `T`. An application refuses the delta
  if `T` has no key or a malformed key, or if the `S` of the image states
  more than 128 MiB.
- If the destination stages or holds an image of `T`, the application does
  not read the image in the part.
- Else the application streams the image from the part to the staging
  directory, computes its fs-verity digest, and installs it only when the
  digest is the key. A digest that is not the key fails the application,
  and it writes no commit and no ref.
- The image is optional. An offline application does not need a fallback
  image to be present. A pull does not fetch a fallback image as a fallback.
  It requests the image of the commit by the rules of "The pull over HTTP and
  over a stream".

## The mount daemon protocol

`ostrya-mountd` mounts a commit as a composefs tree for a client in its own
user namespace. The client is the `Helper` mounter of `ostrya-mount`. The
tool has no such daemon. A run of the daemon and a client, with a trace of
the system calls of both, can verify each fact.

The transport:

- The socket is a Unix socket of the type `SOCK_SEQPACKET`. The path of the
  packaged socket is `/run/ostrya/mountd.sock`. A client that is not root in
  the initial user namespace reads another path from the environment
  variable `OSTRYA_MOUNTD_SOCKET`.
- Each packet holds one message. The first byte of a message is its kind.
  Each integer is big-endian.
- A connection carries one request. The client closes the connection after
  the reply. The daemon serves one connection at a time.
- A connection has 60 seconds from the accept to the reply. The daemon
  waits for each message of the client at most until the end of that time.
  At the end of that time, it stops the request, kills its worker process,
  and sends `Error` with `timeout`. The daemon does not wait for the close
  after the reply.

The messages:

- `Hello`, from the client: `[0x01][version: u8]`.
- `HelloReply`, from the daemon: `[0x02][version: u8]`.
- `Request`, from the client: `[0x03][op: u8][access: u8][commit: 32
  bytes][repo_len: u16][source_len: u16][target_len: u16][repo][source]
  [target]`. One `SCM_RIGHTS` control message goes with the bytes. It holds
  two descriptors in this order: a user namespace and a mount namespace.
  - `op` is 1 for the stored image of the commit and 2 for an image that
    the daemon builds.
  - `access` is 0 for read-only and 1 for read-write.
  - `commit` is the binary checksum of the commit.
  - `repo` and `target` are absolute paths, as the client sees them.
    `source` is the source label of the mount in UTF-8. An empty `source`
    is the checksum of the commit in hex.
  - `repo` and `target` are at most 4096 bytes each, and `source` is at
    most 255 bytes, the longest string option that the kernel takes. No
    field holds a NUL byte.
- `Mounted`, from the daemon: `[0x04]`. One `SCM_RIGHTS` control message
  holds a read-only descriptor of the root of the mount.
- `Error`, from the daemon: `[0x05][code: u8][errno: i32][text]`. `errno`
  is the error number of the call that failed, or 0. `text` is UTF-8 and at
  most 4096 bytes. The client reads an `errno` outside the range from 1 to
  4095 as no error number.

`Hello`, `HelloReply`, and `Error` carry no descriptor.

The codes of `Error`:

- 1, `protocol`: a message that breaks the protocol.
- 2, `version`: the client speaks another version.
- 3, `namespace`: the namespaces of the request fail a check.
- 4, `access`: the caller cannot open the repository, its `objects`
  directory, or the target, or the daemon refuses one of them. Examples
  are a target on FUSE and an `objects` directory that is the root of a
  mount.
- 5, `repository`: the repository refuses the mount. Examples are a
  repository on FUSE, an `archive` repository, a commit without
  `ostree.composefs.digest.v0`, an absent image, an image whose digest is
  not the key, and a built image larger than the limit of the daemon.
- 6, `mount`: a system call of the mount failed.
- 7, `internal`: the daemon failed for another reason.
- 8, `timeout`: no message of the client in time, or a request that does
  not complete in the 60 seconds of its connection.

The exchange:

1. The client sends `Hello` with its version.
2. If the daemon does not speak that version, it sends `Error` with
   `version`. Else it sends `HelloReply` with its version.
3. If the version of `HelloReply` is not the version of the client, the
   client closes the connection.
4. The client sends `Request`.
5. The daemon sends `Mounted` or `Error`.

Each side refuses a message that the kernel truncated (`MSG_TRUNC` or
`MSG_CTRUNC`), a message longer than the longest message of its kind, a
message with a wrong count of descriptors, a message of an unknown kind, and
a field that breaks a rule above. The daemon answers such a message with
`Error` and `protocol`. A first message that is not `Hello` is `protocol`.
Each side receives descriptors with the close-on-exec flag.

The checks of the daemon, in order:

1. It sets the receive timeout of the socket (`SO_RCVTIMEO`) to the end of
   the time of the connection. Then it reads the user, the group, and the
   supplementary groups of the client from the socket (`SO_PEERCRED` and
   `SO_PEERGROUPS`). A client with more than 4096 supplementary groups is
   `access`.
2. The first descriptor must be a user namespace and the second a mount
   namespace. The user namespace must not be the user namespace of the
   daemon, which is the initial one. It must own the mount namespace. The
   daemon compares the namespaces by device and inode. A failed check is
   `namespace`. The daemon does not check that the client is a member of the
   two namespaces.
3. In the mount namespace of the request, with the user, the group, and the
   supplementary groups of the client, it opens `target`, `repo`, and the
   `objects` directory in `repo`. The opens of `repo` and `objects` follow
   no symlink in the last component. A failed open is `access`.
4. A target on FUSE (`statfs` type `0x65735546`) is `access`. A repository
   on FUSE is `repository`.
5. The `objects` directory must not be the root of a mount, and it must be
   on the mount of `repo`. The daemon compares the mount ids that `statx`
   gives. A failed check is `access`.
6. The daemon reads the repository through an `open_tree(OPEN_TREE_CLONE)`
   copy of the mount of `repo`, which holds no mount below `repo`. The
   `objects` directory that the repository opens must have the device and
   the inode of the directory that the client opened. Else the request is
   `access`. The reads of `config`, of the metadata objects, and of the
   image open each file with `O_NOFOLLOW` and `O_NONBLOCK`, and refuse a
   file that is not a regular file.
7. A stored image must have the digest that the commit key records. The
   daemon checks no signature of the commit.
8. A built image larger than the limit of the daemon is `repository`. The
   daemon computes the size before it writes the image. The default limit
   is 104857600 bytes.

The mount:

- The image goes on a read-only, auto-clearing loop device with 4096-byte
  blocks.
- The EROFS mount has the flags `ro`, `nosuid`, `nodev`, and `noatime`, and
  the ID mapping of the user namespace of the request.
- The composefs overlay has the flags `ro`, `nosuid`, `nodev`, and
  `noatime`, and the options `metacopy=on`, `redirect_dir=on`, the `verity`
  value that the repository selects, `lowerdir+` with the EROFS mount, and
  `datadir+` with the `objects` directory. Its source is the label.
- User 0 and group 0 of the user namespace of the request mount the top
  overlay in that namespace. It has the flags `nosuid`, `nodev`, and
  `noatime`, and the options `userxattr`, `metacopy=off`,
  `redirect_dir=nofollow`, and `lowerdir+` with a copy of the composefs
  overlay. Its source is the label. Each layer goes to the kernel as a
  descriptor (`FSCONFIG_SET_FD`).
  - A read-only request adds the flag `ro` and a second `lowerdir+` with an
    empty, read-only tmpfs. overlayfs refuses one lower layer with no upper
    directory.
  - A read-write request adds the upper directory `<target>/overlay` and
    the work directory `<target>/work`.
- The daemon moves the top overlay onto `target` in the mount namespace of
  the request.

The superblock of the top overlay belongs to the user namespace of the
request. The client can clear `nosuid` and `nodev` on the mount. The kernel
then still refuses to open a device node in the tree, and a setuid file
changes no id outside that user namespace.

If `target` is the root of an overlay mount whose line in
`/proc/self/mountinfo`, found by the mount id that `statx` gives, has the
label as its source and `ro` (read-only) or `rw` (read-write) in its
superblock options, the daemon mounts nothing and sends `Mounted` with the
root of that mount.

The client unmounts in its own process. The protocol has no unmount
message.

## bare-user-shared mode

`bare-user-shared` is a repository mode of the port for development. The
tool has no such mode. A production repository (`/sysroot/ostree`) stays
`bare`. The mode lets several users build images in one group-shared
repository on a build machine, and it serves as a composefs backing store.

In `bare-user`, the inode permission bits of a regular-file object come from
the logical mode of the file: `(mode & (S_IFREG|0775)) | S_IRUSR`. So a file
with a restrictive logical mode, for example `/etc/shadow` with 0600, gives an
object that the other users of the repository cannot read. The next user
then cannot load the object, and the shared build fails. `bare-user-shared`
keeps the permissions of the repository separate from the logical
permissions of the files.

Each byte that carries identity is the same as in `bare-user`:

- The content of an object is the raw payload. The `user.ostreemeta` xattr
  holds the logical uid, gid, mode, and xattrs as `(uuua(ayay))`: uid, gid,
  and mode big-endian, and the xattrs sorted.
- A symlink is stored as a regular file with the mode 0644. Its content is
  the target and one NUL. Linux permits a `user.*` xattr only on a regular
  file and a directory (xattr(7)), so a real symlink cannot carry
  `user.ostreemeta`. The port also reads a content with no trailing NUL as
  the target. It refuses a content with a NUL before the last byte.
- The object identity is `SHA256(6-field header ‖ payload)`, as in each other
  mode. So the dirtree and commit checksums are equal to those of `bare`. A
  commit built in this mode and pulled into a `bare` repository is the same
  commit.

The port never applies the logical mode to the inode of an object. It writes
each new object with the mode 0644 through an explicit `fchmod`, so the umask
has no effect. A `.commitmeta` gets 0644 in the same way. This includes a
`.commitmeta` that a pull stages in the staging directory before the rename
into `objects/`.

A local pull can hardlink an object from the source repository. It does so
when the source inode has the uid and the gid that a new write gets. The
linked inode keeps the mode and the group of the source. The pull can link
these objects:

- a metadata object from a source of any mode;
- a content object from a `bare-user-shared` source;
- a symlink object from a `bare-user` source.

The port forces the permission bits of each directory and each lock file that
it creates inside the repository. It runs an `fchmod` after the create, so
the file-creation mask of the process has no effect:

- A directory gets 02770. This rule applies to these directories:
  - the repository root and each layout directory at `init`;
  - the `objects/<xx>` fanout directories;
  - the parent directories under `refs/`;
  - `tmp/`, and each staging directory of a transaction.

  So each member of the repository group can read, deduplicate, and write
  objects, and can publish a ref.
- The setgid bit is part of the forced mode, so each directory that a member
  creates below gets the group. The sticky bit stays off, because the reaper
  of old staging directories removes staging trees that other members own.
- A ref file, an alias symlink, a `.commitmeta`, and a `.tombstone-commit`
  start as a temp entry in `tmp/` or in a staging directory. So each one gets
  the group of that directory.
- `.lock`, `.update.lock`, and the lock file next to each staging directory
  get 0660. So each group member can open them `O_RDWR`, take the repository
  lock and the update lock, and remove a staging tree whose owner is dead.
- The `state/<commit>.commitpartial` marker gets 0644.

The port forces a mode only on an entry that it creates. An entry that exists
keeps its mode and its group. This includes the repository root: the caller
sets the group and the mode of a root that the port did not create. The port
sets no group owner.

A staging lock file and a `.commitpartial` marker have a second open after an
exclusive create fails. Another process can remove the entry between the two
opens. Then the second open creates the entry, and the port does not force
its mode.

02770 gives no permission to others. The objects are 0644, which each user
can read. So the directory permissions keep other users out of the
repository.

The directories and the files under `deltas/` and `delta-indexes/` are outside
this rule. They get the modes of each other mode ("Object store layout"). The
directories get 0755 reduced by the umask. The files get 0644, whatever the
umask is.

The mode string is `[core] mode=bare-user-shared`. The separate string keeps
the tool out of the repository. Observed behavior: the tool refuses a
repository with an unknown mode string. Not observed: the tool opens a
repository with the string `bare-user`. Its hardlink checkout then gives each
file the inode mode 0644 of its object, in place of the logical mode.

A user with access to the repository can read each object, so the repository
does not keep the confidentiality of a file through its permissions. A
checkout restores the restrictive logical permissions. The permissions of the
repository root directory control access from outside. This is an accepted
property of a shared development repository.

As in `bare-user`, the port never writes `ostree.sizes` in this mode. Only an
`archive` repository writes the key ("The `ostree.sizes` key"), so the
identity of a commit across modes needs no rule for this mode.

A checkout never hardlinks a regular file of this mode, because the inode
does not carry the logical mode (`conformance/cli-behavior.md`, "Checkout",
"Hardlink and copy").

`fsck` and prune act as in `bare-user`. `fsck` checks
`SHA256(header-from-xattr ‖ payload) == object name`. The mode has no
auxiliary objects and no extra reachability edges. `fsck` does not check the
inode mode.

This mode is the composefs backing store of the port. Its `.file` objects
hold the raw payload at the loose paths that each image redirect names. So
the repository serves as the lower layer of an image exported from any mode
that holds the same tree. The fs-verity digest of each file covers the
payload. The composefs uid mapping presents the owner at mount time, so the
root-owned metadata is correct also inside a rootless container.

## The S3 bucket repository

A bucket repository is a repository in `archive` form in an S3 bucket. Each
file of the repository is one object of the bucket. The key of the object is
the path of the file under the prefix of the address. The bucket client of
the port (`ostrya_remote::s3::Bucket`) reads and writes the objects with the
S3 API. It signs each request with AWS Signature Version 4.

The keys have the layout of a static `archive` repository, which the
`ostree` command reads over HTTP with no signature, at the URL of the bucket
followed by `/PREFIX`. The `ostree` command reads no key under
`extensions/`. `conformance/cli-behavior.md`, "A 403 for an optional
file", records the reads of the `ostree` command with a bucket policy that
gives no `s3:ListBucket`.

### The address

The address of a bucket repository is `s3://BUCKET[/PREFIX]`.

- `BUCKET` is 3 to 63 characters: lowercase ASCII letters, digits, `.`, and
  `-`. It starts and ends with a letter or a digit. It holds no `..`, and it
  is not four decimal numbers that `.` separates.
- `PREFIX` is one or more segments that `/` separates. Each segment is not
  empty, is not `.` or `..`, and holds the characters `A-Z a-z 0-9 - . _ ~`
  alone. One trailing `/` is dropped.
- The address holds no userinfo, no port, no query, and no fragment.

The endpoint and the addressing style give the URL of the bucket:

- With no endpoint, the endpoint is AWS, `https://s3.REGION.amazonaws.com`.
- An endpoint is an `http://` or an `https://` URL with no path, no query, no
  fragment, and no userinfo.
- Path style puts the bucket in the path: `ENDPOINT/BUCKET`. Virtual-host
  style puts the bucket in the host: `SCHEME://BUCKET.HOST[:PORT]`.
- The default style is virtual-host for AWS and path for an endpoint of the
  caller. A bucket name that holds a `.` gets path style by default. A style
  that the caller sets wins.
- Virtual-host style is refused for a bucket name that holds a `.` over
  `https`, and for an endpoint whose host is an IP address.

### The keys of a bucket repository

The keys are relative to the prefix, and each key starts with `PREFIX/`.
With no prefix, a key has no leading `/`. The keys of a bucket repository
are:

- `config`, `summary`, `summary.sig`, `extensions/ostrya/lock`, and
  `extensions/ostrya/lock-probe`
- `objects/XX/<62 hex digits>.<ext>`, in lowercase hex, with `XX` the first
  two digits of the checksum, and `<ext>` one of `commit`, `commitmeta`,
  `dirtree`, `dirmeta`, `filez`, `tombstone-commit`, and `cfs`
- `refs/heads/<name>`, with a ref name of "Ref name validation"
- `refs/mirrors/<id>/<name>`, with a collection id of at most 255 bytes that
  the collection id rule of "Ref name validation" accepts, and a ref name of
  "Ref name validation"
- `deltas/<2>/<41>/<target>` and `deltas/<2>/<41>-<43>/<target>`, the layout
  of "Static delta directories", with the checksums in modified base64 and
  the target `superblock` or a part number with no leading zero
- `delta-indexes/<2>/<41>.index`, the layout of "Static delta index files"
- `state/<64 hex digits>.commitpartial`, in lowercase hex: the
  partial-commit marker of a commit ("The fsck of a bucket repository").

The bucket client refuses each other key before it sends a request. A key
from a listing that is not one of these keys is a stray key.

Each request of the bucket client and of an S3 pull sends the path of a key
in the canonical form of SigV4: each byte other than `A-Z a-z 0-9 - . _ ~ /`
goes as `%XX` with uppercase hex digits. A `+` of a delta key goes as `%2B`,
and a non-ASCII character of a ref name goes as the `%XX` of each of its
UTF-8 bytes. The path is the canonical URI of SigV4, so the signature covers
the path on the wire. The signer refuses a request whose path is in another
form.

A list of a bucket repository is `ListObjectsV2` with the encoding type
`url`. The `prefix` parameter of each list ends in `/`: `PREFIX/objects/XX/`,
`PREFIX/objects/`, `PREFIX/refs/`, `PREFIX/deltas/`, `PREFIX/state/`, and
`PREFIX/` for the list of the multipart uploads. The fsck lists
`PREFIX/objects/` with `delimiter=/` too, and lists in full each common prefix
of that list that is not a fan-out prefix. Without the `/`, a list for `s3://b/repo`
also gives the keys of `s3://b/repo2`. With no prefix, the list of the
multipart uploads covers the whole bucket, and the bucket client keeps an
upload only when its key is a key of a bucket repository.

In a listing with the encoding type `url`, each `%XX` is the byte that it
names and each `+` is a space. `rclone serve s3` 1.75.1 writes the key
`a+b` as `a%2Bb`, the key `sp ace` as `sp+ace`, and the key `ü` as `%C3%BC`.

The bucket client follows the pages of a list with `continuation-token`,
and the pages of the list of the multipart uploads with `key-marker` and
`upload-id-marker`. Each page must move forward, or the list fails:

- Each decoded key and common prefix of a page of `ListObjectsV2` comes
  after each one of the earlier pages, in the byte order of UTF-8.
- A truncated page of `ListObjectsV2` with no key and no common prefix gives
  a continuation token that no page gave after the last page with a key or
  a common prefix, that page included. A run of more than 1000 such pages
  fails the list.
- The `NextKeyMarker` of each truncated page of `ListMultipartUploads` does
  not come before the key marker of the page before it, in the byte order
  of UTF-8. While the key marker stays the same, the `NextUploadIdMarker` is
  one that no earlier page gave for that key marker. S3 sorts the uploads of
  one key by the time of their start, so the upload id markers of one key
  have no order.

### The config of a bucket repository

The `config` of a bucket repository is a key file. The init of the port
writes it, and each writer reads it. A push to a bucket repository with no
`config` is refused, so the init comes first.

The init writes these lines. The line `collection-id` comes only with a
collection id, and the empty line and the group `[archive]` come only with
a zlib level:

```text
[core]
repo_version=1
mode=archive-z2
collection-id=<id>

[archive]
zlib-level=<level>
```

A bucket repository with a collection id is the primary server of that
collection. Its refs of that collection are under `refs/heads/`. The init
refuses a bucket that holds a `config`, so the collection id of a bucket
repository never changes.

A writer refuses a `config` that does not parse as a repository config,
that states a mode other than `archive-z2` and `archive`, whose
`collection-id` fails the collection id rule or is longer than 255 bytes,
whose `tombstone-commits`, `indexed-deltas`, or `[ex-ostrya]
keep-detached-related` is not a boolean, or whose `zlib-level` is not an
integer. The refusal changes nothing in the bucket but the probe key of the
writer lock.
The summary takes `mode`, `tombstone-commits`, `indexed-deltas`, and
`collection-id` of `[core]` ("The summary of a bucket repository").

A push builds each `.filez` that it uploads at the `[archive] zlib-level`
of the `config`, as a local `archive` repository writes its `.filez`
objects. A `config` with no `zlib-level` gives the level 6. A value outside
1 to 9 is clamped to that range, as for a local repository.

A push reads `[ex-ostrya] keep-detached-related` of the `config`, with the
default `true`. If it is `false`, the push drops `ostrya.related` from each
`.commitmeta` that it uploads ("The switch of the destination"). The init
writes no `[ex-ostrya]` group.

### Object uploads

The bucket client writes an object from a stream with one `PUT` or with a
multipart upload. It reads the stream in parts of one part size:

- A body of at most one part goes in one `PUT KEY`.
- A longer body goes in a multipart upload. `POST KEY?uploads` starts the
  upload, and its answer gives the upload id in the element `UploadId`.
  `PUT KEY?partNumber=N&uploadId=ID` sends each part, one part after the
  other, with the part numbers 1 to the number of parts and no gap. Each
  part other than the last one holds the part size. `POST KEY?uploadId=ID`
  completes the upload. In the query, the upload id has the encoding of a
  query value of SigV4.
- A failure after the start of the upload sends one
  `DELETE KEY?uploadId=ID`, which aborts the upload. A failure whose last
  answer is a 404 with the code `NoSuchUpload` sends no abort, because the
  server holds no such upload.

The part size of an object of `N` bytes is the larger of 8 MiB and
`(2N + 1 MiB) / 10,000`, rounded up to a whole MiB. It is 8 MiB up to
41,942,515,712 bytes. An object that needs a part size over 5 GiB, more
than 26,843,545,075,712 bytes, is refused. A part size is at least 5 MiB
and at most 5 GiB, and an upload has at most 10,000 parts. These are the
S3 limits.

The body of the request that completes the upload is one line with no XML
declaration:

```xml
<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Part><PartNumber>1</PartNumber><ETag>"ETAG1"</ETag></Part><Part><PartNumber>2</PartNumber><ETag>"ETAG2"</ETag></Part></CompleteMultipartUpload>
```

Each `ETag` is the `ETag` header of the answer to the part, with its
quotes, and with `&`, `<`, and `>` escaped. The request has no
`Content-Type`.

The answer that starts an upload has the root
`InitiateMultipartUploadResult`. `rclone serve s3` 1.75.1 writes the root
`InitiateMultipartUpload` with no namespace, and the bucket client reads
both. The answer that completes an upload has the root
`CompleteMultipartUploadResult`, or the root `Error` after the head of a
200. The `ETag` of the result is `"<MD5 of the MD5 values of the parts>-N"`,
with `N` the number of parts, on `rclone serve s3` 1.75.1 and on
SeaweedFS 4.36. A later read of the key on `rclone serve s3` 1.75.1 gives
the MD5 of the whole object, and SeaweedFS 4.36 gives the value of the
result.

A push to a bucket repository takes the part size of the size of each
object: the size of the stored file, or for a `.filez` that the push builds
from a repository of another mode, the size of the payload. A `.filez` of
`N` bytes of content is smaller than `2N + 1 MiB`. The push holds one part
buffer for each upload in flight, and runs at most `max_outstanding`
uploads, 8 by default. With parts of 8 MiB, the part buffers then hold
about 64 MiB. A part can take a new buffer while the fetcher still holds the
buffer of the part before it, so the bound is not exact.

### The writer lock

The key `PREFIX/extensions/ostrya/lock` holds the writer lock of a bucket
repository. A writer holds the lock while it changes the repository: an
init, a push, a prune, an update of the summary, and an fsck that deletes
objects.
A read takes no lock. The `ostree` command does not read the key.

The key `PREFIX/extensions/ostrya/lock-probe` holds the probe of the writer
lock. Its body is 18 ASCII bytes: the text `ostrya lock probe` and a line
feed, in hex `6f 73 74 72 79 61 20 6c 6f 63 6b 20 70 72 6f 62 65 0a`. Each
version of the port writes the same bytes. A take writes the key if it is
absent, and no writer deletes it. Do not delete the key, and do not
set an expiry rule on it. A delete between the two requests of a probe
gives a false result of no exclusion. The result is safe, because the
writer then writes no lock. The `ostree` command does not read the key.

The lock is a key file with one group, in this order:

```text
[lock]
id=<64 lowercase hex digits>
host=<host name>
pid=<process id>
operation=push
started=<seconds since the epoch, UTC>
```

- `id` identifies one run of one writer. A reader compares it with its own
  id alone. The port writes the SHA-256, in lowercase hex, of the text
  `HOST\nPID\nNANOS\nCOUNTER`: the host name, the process id, the time in
  nanoseconds since the epoch, and a counter of the process. Two runs give
  the same id only with the same host, process id, nanosecond, and counter
  value.
- `host` is the host name, with the escapes of a string value of a key
  file: `\s` for a space at the start, and `\\` for a backslash. The value
  is empty if the host name cannot be read.
- `operation` is `init`, `push`, `prune`, `summary`, or `fsck`.
- `started` is the time of the take.

A body that is not UTF-8, that is not a key file, that has no group
`[lock]`, or that is larger than 64 KiB is the lock of an unknown writer.
An `id` that is not 64 lowercase hex digits names no writer. A take fails
on such a lock, and a break removes it.

A writer sends these requests:

- Probe: before a request to the lock key, `PUT` of the probe body to the
  probe key with `If-None-Match: *`. A 412 shows that the server honors the
  header. A 2xx gives a second `PUT` of the same body. A 412 to the second
  request shows that the server honors the header. A 2xx to it shows that
  the server ignores the header, so the lock gives no exclusion. The writer
  then fails, and it wrote no lock. A lock that the key holds does not
  change. After a request with an unknown outcome, the writer reads the
  probe key. The probe body there after the first request gives the second
  request. The probe body there after the second request fails the
  operation with an unknown outcome, and the writer writes no lock. Other
  bytes there count as a 412. Only a program other than the port writes
  other bytes to the probe key. A 412 to a request after an unknown outcome
  shows that the server honors the header. Each take runs the probe, and a
  writer keeps no result of an earlier probe.
- Take: after the probe, `PUT` of the body with `If-None-Match: *`. A 412
  fails the operation. A take with no break then writes only the probe key.
  After a request with an unknown outcome, the writer reads the key. The
  body of the take there means that the take holds the lock, because no
  other run writes its `id`.
- Check: `GET` of the lock, and a compare of its `id` with the own `id`.
  Another `id`, no `id`, or no lock stops the writer before its next change.
- Release: `GET` of the lock. With the own `id`, `DELETE` with `If-Match`
  and the `ETag` of the `GET`. A 412 leaves the lock, and the writer reports
  that its lock was broken. A `GET` with no `ETag` gives a `DELETE` with no
  condition. A `DELETE` that removed the lock, but whose answer did not
  arrive, is sent again. If another writer took the lock between the two
  requests, the second one gets 412, and the writer reports that its lock
  was broken, although its release was complete.
- Break: after the probe, `GET` of the lock, `DELETE` with `If-Match` and
  the `ETag` of the `GET`, and then a take. The break removes the lock that
  it read, whatever its `id`. A `GET` with no `ETag` fails the break, and
  the writer deletes no lock. After a 412, the writer reads the lock
  again. A lock there fails the break, because another writer changed the
  lock after the `GET`. No lock there means that its holder removed it,
  and the writer goes on to the take. If the take fails, the lock that the
  break deleted stays deleted.

The lock has no expiry time. A lock that a writer leaves when it ends with
no release stays until a break removes it.

The lock has two windows:

- A writer that breaks the lock and takes its own after a check, and before
  the change that the check guards, does not stop that change.
- On a server that ignores `If-Match`, a writer that breaks the lock and
  takes its own between the `GET` and the `DELETE` of a release or of a
  break loses its lock.

Observed behavior of the servers:

- `rclone serve s3` 1.75.1 ignores `If-None-Match: *` on `PUT`: a second
  conditional `PUT` gives 200 and writes the object. It ignores `If-Match`
  on `DELETE`: a wrong `ETag` gives 204 and deletes the object, and an
  absent key gives 204. So the probe refuses each writer on this server
  before a request to the lock key.
- SeaweedFS 4.36 honors both headers. A conditional `PUT` to a key that
  holds an object gives 412 `PreconditionFailed`, and the object stays. A
  `DELETE` with a wrong `ETag` gives 412, and the object stays. A `DELETE`
  with the `ETag` of a `GET`, with its quotes or without them, gives 204.
  A `DELETE` with `If-Match` on an absent key gives 412, also with
  `If-Match: *`.
- On both servers, a `PUT` gives a quoted `ETag`, and a later `GET` of the
  same bytes gives the same value.

### Init of a bucket repository

The init writes the `config` of a new bucket repository, with an optional
collection id and an optional zlib level. `ostrya remote init` runs it,
with the `s3://` address of its operand or of a remote:

1. It refuses a collection id that fails the collection id rule or is
   longer than 255 bytes, and a zlib level outside 1 to 9. It sends no
   request before these checks.
2. It takes the writer lock with `operation=init`.
3. It writes `config` with `If-None-Match: *`. A key that holds a `config`
   refuses the init, and the `config` stays as it is.
4. It releases the writer lock.

The init writes no summary and no ref. A failure before the write of
`config` changes nothing but the lock and the probe key, and the init
releases the lock. A failure after the write leaves the `config`, and the
bucket repository is then ready for a push. A crash leaves the lock, as for
each writer.

### The push to a bucket repository

A push writes the commits of a set of refspecs to a bucket repository with
no session. Each object goes up in the bytes of an `archive` repository:
the stored file of an `archive` repository, and for each other mode a
`.filez` that the push builds at the `[archive] zlib-level` of the `config`
of the bucket ("The config of a bucket repository"). The steps of a push
are:

1. The local checks: the depth, the collection, the refspecs, the source
   commits, and the bindings, as for a push over a session. A local refusal
   changes nothing in the bucket. The push refuses tags, a compression, and
   a refspec that deletes a ref.
2. The take of the writer lock with `operation=push`.
3. The read of `config` and the selection of the namespace. Then, at the
   same time, the listing and the read of the ref files of the ref
   directory of the namespace, `refs/heads/` or `refs/mirrors/ID/`, the
   listing of `refs/mirrors/` of the collection id of the bucket, and the
   listing of the objects of the 256 fan-out prefixes. The push reads no
   ref file of another namespace, and does not check the keys under
   `refs/` outside its ref directory. A key under
   `refs/mirrors/` of the collection id of the bucket refuses the push. The
   push trusts the listing of the objects alone. A bucket repository with
   no `config` refuses the push.
4. The check of the bindings, then the check of each ref update. Each tip of a ref in the bucket must be an
   ancestor of the new commit in the local repository, unless the push is
   forced. A tip that the local repository does not hold, or marks partial,
   is no ancestor. The fast-forward rule and the force apply to each ref in
   its own namespace.
5. The walk: each source commit, its history, cut at the tip of the ref in
   the bucket, and the dependencies of each offered commit, as a push over a
   session offers them ("Dependencies in a push"). The trees of the
   commits that the bucket lacks and of the offered commits with a
   partial-commit marker under `state/`, and the composefs image of each
   source commit and of each walked commit, if the local repository holds
   the image. The walk reads no tree of another commit that the listing
   holds, because a commit object in the bucket has its whole tree in the
   bucket. The push lists `state/` only if the listing holds an offered
   commit. Each ref of the new ref set of the ref directory of the
   namespace must name a commit that the bucket holds or that the push
   uploads, else the push is refused.
6. The upload of each tree object and image that the listing lacks, and of
   the `.commitmeta` of each commit that the bucket lacks and of each source
   commit, at most `max_outstanding` uploads at a time. The bytes of a
   `.commitmeta` are the stored `.commitmeta`, without `ostrya.related` if
   `[ex-ostrya] keep-detached-related` of the `config` of the bucket is
   `false`. The push skips a
   `.commitmeta` that the bucket holds with the same bytes: the listing
   holds its key with the same size, and a read of the key gives the same
   bytes. A commit with no detached metadata after the switch uploads
   nothing, and the bucket keeps its copy. After a failed upload, the push
   starts no new upload and waits for the uploads in flight.
7. The upload of each commit object that the bucket lacks.
8. A check of the writer lock, the delete of the marker of each walked
   commit with a marker, at most `max_outstanding` deletes at a time, then
   the write of each ref file that changes, in
   the order of the refspecs. A ref file holds the checksum in lowercase hex
   and a newline. A marker of a commit that the push does not offer stays.
9. The release of the writer lock.

The push writes no `summary` and no `summary.sig`. A `summary` and a
`summary.sig` that the bucket holds stay as they are, so they do not show
the refs that the push writes, as in a local `archive` repository with no
`auto-update-summary`. A pull of a named ref reads the ref file
`refs/heads/<name>` when the summary does not list the ref.

The namespace of a push is the collection of the push, else the
`ostree.collection-binding` of the source commits, else none. The `config`
of the bucket takes the role of the server of a push over a session:

| Namespace | Collection id of the bucket | Ref keys | A bound commit names |
| --- | --- | --- | --- |
| none | any | `refs/heads/DST` | the collection id of the bucket |
| `ID` | `ID` | `refs/heads/DST` | `ID` |
| `ID` | another id, or none | `refs/mirrors/ID/DST` | `ID` |

A commit with no binding goes to `refs/heads/` alone. Each other commit
refuses the push.

A push refuses an update whose new ref set holds, in the ref directory of
its namespace, a name that is a directory of another name, for example `a`
and `a/b` in `refs/heads/`. Each `refs/mirrors/ID/` is a ref directory of
its own.

A commit object goes up only after each object of its tree. So a commit
object in the bucket has its whole tree in the bucket at each point of a
push, also of a push that failed, or it has a partial-commit marker
`state/<checksum>.commitpartial`. The repair of the fsck writes the marker
before it deletes an object of the tree of the commit. A push of the commit
uploads the objects of the tree that the bucket lacks before it deletes the
marker.

A push that fails leaves one of these states:

- A failure before the ref writes changes no ref. The objects that went up
  stay, and a run again uploads only the rest. The push releases its lock.
- A failure of a ref write leaves some refs moved. A run again finds those
  refs at their new commits, and writes the other refs.
- A check of the lock that finds another lock, or no lock, stops the push
  before its next write. The push then releases no lock.
- A failure of the release, or a crash, leaves the lock. The next writer
  fails and names the holder, and a break of the lock removes it.
- A crash during a multipart upload leaves the upload open. It holds
  storage until a lifecycle rule of the bucket aborts it. A failed upload
  aborts its own multipart upload.

### The tree push to a bucket repository

A tree push writes a local directory to a bucket repository as one new
commit, with no session. `ostrya push-tree` with an `s3://` destination
runs it. The bucket has no server, so the client makes the commit. The
commit is the server commit of "Server commit" and "The commit of
`push-tree`", with the `config` of the bucket in the role of the server:

- The parent is the commit of the ref file of the branch in the namespace,
  which the push reads under the writer lock. With `orphan`, or when the
  branch is absent, the commit has no parent. With `orphan` on a branch
  that exists, the new commit replaces the tip with no check.
- `ostree.ref-binding` holds the branch and each bound name, sorted.
- `ostree.collection-binding` holds the collection id of the bucket in
  `refs/heads/`, and the collection id of the namespace in
  `refs/mirrors/ID/`. The key is absent in `refs/heads/` of a bucket with no
  collection id. The namespace follows the table of "The push to a bucket
  repository", with the collection of the push as the namespace.
- The timestamp is the value of the push, else the system clock of the
  client.
- The metadata entries, the subject, the body, and the root dirtree and
  root dirmeta are those of the push, in the order of "Server commit".

With equal inputs, the commit is the commit that the receive side of a
session tree push writes, byte for byte.

The steps of a tree push are:

1. The local checks of the options, as for a session tree push, and the
   walk and the hash of the tree. A tree push to a bucket refuses tags. A
   local refusal and a failed walk send no request.
2. The take of the writer lock with `operation=push`.
3. The read of `config` and the selection of the namespace, then the read of
   the ref files of the ref directory of the namespace, the listing of
   `refs/mirrors/` of the collection id of the bucket, and the listing of the
   objects, as for a push of commits.
4. The checks of the refs. The branch `ostree-metadata` in `refs/heads/` of
   a bucket with a collection id is refused, as a server refuses it. The
   ref directory must hold no name that is a directory of another name
   after the push. Each ref of the namespace other than the branch, and the
   parent, must name a commit that the listing holds. A failed check
   uploads nothing.
5. The build of the commit object. A commit object larger than the
   metadata size cap of "Foundational constants", 128 MiB, is refused
   before an upload. A tree push to a bucket has no frame, so the 1 MiB
   `Commit` frame of an ostrya server does not limit the commit.
6. The upload of each object of the tree that the listing lacks, at most
   `max_outstanding` uploads at a time. A dirtree and a dirmeta object go
   up as their bytes. A symlink goes up as the framed archive header alone.
   A regular file goes up as the framed archive header, then its payload in
   raw DEFLATE. The level is the level of the compression of the push,
   else the `[archive] zlib-level` of the `config` of the bucket.
7. The upload of the commit object, if the listing lacks it.
8. A check of the writer lock, then the write of the ref file of the branch,
   if the branch moves.
9. The release of the writer lock.

The push reads each file as a stream and hashes its header and its payload
again. A file that changed after the hash pass fails the read at the end of
the payload. The bucket client then has not sent the last part of the
object: a single `PUT` is not sent, and a multipart upload is aborted. The
push uploads no commit object and writes no ref.

A tree push writes no `summary`, no `summary.sig`, and no `.commitmeta`, and
it signs no commit. A signature of the commit comes from a pull of the
commit into a local repository, a sign there, and a push of the commit,
which then uploads the `.commitmeta` alone. The failure states are those of
a push of commits.

### The summary of a bucket repository

The summary update writes the summary of a bucket repository. It is the
one writer of `summary` and `summary.sig`: a push, the init, the fsck, and
the prune write no summary. `ostrya remote summary -u` runs it, with the
`s3://` address of its operand or of a remote.

The summary of a bucket repository is the root summary alone. The update
writes no summary of an auth item, no file under
`extensions/ostrya/summary/`, and no anchor commit.

A pull of collection refs reads the refs of a bucket repository from its
summary alone ("The pull of collection refs"). So a bucket repository with
no summary serves no collection ref.

- Field 0 holds the refs of `refs/heads/`, sorted byte-wise by name. A
  bucket repository with no ref gets a summary with an empty field 0.
- `ostree.summary.collection-map` holds the refs of each `refs/mirrors/ID/`
  with a ref, by collection id. A bucket repository with a collection id
  holds no `refs/mirrors/ID/` of that id: each writer refuses it.
- `ostree.summary.mode`, `ostree.summary.tombstone-commits`,
  `ostree.summary.indexed-deltas`, and `ostree.summary.collection-id` come
  from `mode`, `tombstone-commits`, `indexed-deltas`, and `collection-id` of
  `[core]` in the `config` of the bucket, as the local summary takes them
  from a local `config`. A `config` that sets `tombstone-commits=true` gives
  `ostree.summary.tombstone-commits` the value true.
- `ostree.static-deltas` holds each delta of `deltas/` with a superblock,
  sorted by delta name, with the SHA-256 of its superblock. A delta
  directory with no superblock is not in the map. Each read of a superblock
  takes the strict rule of an absent key. A superblock that is gone at its
  read, with an answer 404 `NoSuchKey`, is not in the map, and each other
  answer 404 refuses the update. A superblock key whose directory names do
  not decode as a delta, and a superblock larger than 128 MiB in the
  listing or in its read, refuse the update.
- `ostree.summary.last-modified` is the time of the write, or the value of
  the caller.
- The facts of a ref entry come from the commit object in the bucket. The
  update reads each commit object of a ref with one `GET`, at most the
  128 MiB cap of a metadata object, and checks its SHA-256 against its
  name. It sends no list of `objects/`. A ref whose commit has a
  partial-commit marker under `state/` is in the summary as each other ref,
  and the update reads no key under `state/`.

These are the bytes of the root summary of a local repository with the same
refs, commits, deltas, `config`, and `last-modified`, with one difference
outside the summary builder. A local repository with a collection id writes
a new `ostree-metadata` anchor commit to `refs/heads/ostree-metadata` before
its summary, so its ref set holds one more ref. A bucket repository writes
no anchor commit.

The steps of the update are:

1. The read of `config`, by the strict rule of an absent key. A bucket with
   no `config` refuses the update before the lock.
2. The take of the writer lock with `operation=summary`.
3. The list of `refs/` with a read of each ref file. An update with no
   summary signer probes `summary.sig` at the same time. The probe is a
   `GET` with `Range: bytes=0-0`, and only an answer 404 `NoSuchKey` is an
   absent key. An update with a summary signer sends no request for
   `summary.sig` before its write.
4. The refusals below.
5. At the same time: the reads of the commit objects, and the list of
   `deltas/` with the read of each superblock as a stream.
6. The build and the signatures of the summary.
7. A check of the lock, the write of `summary`, and then the write of
   `summary.sig` if a summary signer signed the summary.
8. The release of the lock.

These states refuse the update, and the refusal changes nothing in the
bucket but the probe key of the writer lock:

- a ref key under `refs/` other than `refs/heads/<name>` and
  `refs/mirrors/<id>/<name>`;
- a ref file that does not hold 64 lowercase hex digits and a newline;
- a ref name of `refs/heads/` or of one `refs/mirrors/<id>/` that is a
  directory of another ref name of the same directory, as `a` is of `a/b`;
- a ref whose commit the bucket does not hold, and a commit object of a ref
  that does not have the checksum of its name;
- a `summary.sig` in the bucket and no summary signer. The update never
  deletes `summary.sig`, so it never makes a signed bucket repository
  unsigned.

Between the two writes of step 7, a reader sees the new summary and the old
signature, and a reader that verifies the summary refuses it. A reader
never accepts a summary that its signature does not cover. A read after an
update that succeeds finds a matching pair.

An update with a summary signer fails with an error that states the state
of the pair in two cases:

- The write of `summary.sig` fails after the server accepted the write of
  `summary`. The bucket holds the new summary. It can hold the old
  `summary.sig` or no `summary.sig`. A write of `summary.sig` with an
  unknown outcome can also have written the new `summary.sig`, and the pair
  then matches.
- The write of `summary` fails with an unknown outcome: the HTTP client
  failed, or the last answer was 408, 429, or 5xx. The bucket can hold
  the new summary with the old `summary.sig` or with no `summary.sig`.

The error names `ostrya remote summary -u`. Before the error, the update
tries to release its lock. An update again with the same signers writes a
matching pair. A refusal of the write of `summary`, for example an answer
403, gives the error of the bucket client. A refusal of the first request
of that write changes nothing. A refusal of a request that the bucket
client sent again can leave the new summary with the old `summary.sig`,
because an earlier request can have written `summary`. An update with no
summary signer gives the error of the bucket client in each case. A
process that stops between the two writes gives no error. The fsck with
the summary keys reports each such pair as an error on `summary.sig`.

### The fsck of a bucket repository

The fsck checks a bucket repository. `ostrya remote fsck` runs it. Without
a repair, the fsck takes no writer lock and writes no key. Each read of
`config`, of a ref file, of `summary`, of `summary.sig`, of a superblock,
and of an object takes the strict rule of an absent key: only a 404 with
the code `NoSuchKey` is an absent key, and each other 404 fails the run. At
most `max_outstanding` reads run at a time.

The steps of the fsck are:

1. With the repair, the read of `config`. A `config` that is absent or
   breaks a rule of "The config of a bucket repository" refuses the repair,
   and the run then writes no key and takes no lock. Else the take of the
   writer lock with `operation=fsck`. A lock of another writer fails the run
   before the read of an object. Without the repair, the read of the lock.
2. The check of `config`.
3. At the same time: the list of `refs/` and the read of each ref file, the
   listing of the objects of the 256 fan-out prefixes, the list of
   `objects/` with `delimiter=/`, the list of `state/`, and the list of the
   incomplete multipart uploads. Each key under `refs/` must be
   `refs/heads/<name>`, or `refs/mirrors/<id>/<name>` with an id other than
   the collection id of the bucket, and each ref file must hold 64
   lowercase hex digits and a newline. Each key under `objects/` that is
   not an object key is a stray key. Each ref must name a commit of the
   listing. The list of the uploads needs a permission of its own, so a
   refusal of it fails the run before the read of an object.
4. The read of `summary`, and at the same time of `summary.sig` when the
   run verifies the signature of the summary. The list of `deltas/`, and
   the read of the superblock of each delta that the summary advertises.
5. The read of each commit object of the listing, whole, up to its size in
   the listing and to the metadata size cap of 128 MiB. An object that is
   larger than its listed size is read again up to the cap. The SHA-256 of
   the bytes must be the checksum of the name, and the bytes must parse as
   a commit.
6. The walk of the tree of each commit that parses, also of a commit whose
   bytes do not match its name. The run reads each dirtree and each dirmeta
   once, and checks its checksum and its parse. A dirtree that does not
   parse ends its subtree.
7. The read of each `.filez` of the trees as a stream, in chunks of 64 KiB.
   The framed archive header must parse. A symlink has no payload. The
   payload of a regular file must inflate to the size that the header
   declares, with no bytes after its DEFLATE end, and the content checksum
   must be the checksum of the name. A body that fails in transit is read
   again once from its start. A second failure in transit fails the run.
8. The read of each `.cfs` whose commit is in the listing, as a stream. Its
   fs-verity digest must be the value of `ostree.composefs.digest.v0` of the
   commit. A `.cfs` whose commit is not in the listing is counted and is no
   finding. With the repair, so is a `.cfs` whose commit object the repair
   deletes. A body that fails in transit is read again as for a `.filez`.
9. The count of the objects of the listing that no commit reaches. A
   `.commitmeta` and a `.cfs` of a commit of the listing are reached. The
   run reads no such object.
10. Without the repair, the read again of each object of a `missing`
    finding that the listing does not hold, and then of the commits of each
    such object that is still absent. Each read is a `GET` with
    `Range: bytes=0-0`, by the strict rule of an absent key.
11. With the repair, the repair below and the release of the lock. Without
    the repair, the read of the lock again.

When a finding names a missing or a bad object of a tree, the run reads
each dirtree of the trees one more time, and names the commits that reach
the object.

A run without the repair takes no lock, so a writer can change the bucket
during the run. The listing of the 256 fan-out prefixes is no snapshot: a
push can upload an object under a prefix that the run listed before, and
its commit under a prefix that the run lists after. A prune can remove a
commit and its objects after the run read the commit. So before the run
records a `missing` finding for an object that the listing does not hold,
it reads the object again. If the key holds an object now, the finding is a
note. Else the run reads each commit of the finding again, and the finding
names only the commits that the bucket still holds. If the bucket holds
none of them, the run records no finding. A commit or a `.cfs` that is
gone at its read gives no finding. A run with the repair holds the lock, so
no writer changes the bucket during the run.

Each finding has one kind, and is an error or a note:

- `config`, an error: `config` is absent, or breaks a rule.
- `ref`, an error: a key under `refs/` that is no ref key, a ref file that
  does not parse or is gone at its read, a ref under `refs/mirrors/` of the
  own collection id, or a ref whose commit the bucket does not hold.
- `summary`, an error: the summary does not parse, fails the check of its
  signature, names a ref at a commit that the bucket does not hold, or
  names a delta whose superblock is absent or has another SHA-256. With the
  summary keys, an absent `summary` or `summary.sig` is an error too. A
  `summary` or a `summary.sig` larger than 64 MiB is one error. The detail
  of a `summary.sig` that the summary keys do not verify states that a
  summary update with the summary signers writes a matching pair. The
  detail of an absent `summary.sig` states that a summary update with the
  summary signers writes a `summary.sig`.
- `summary`, an error: with a summary in the bucket, a delta map of the
  bucket that the run cannot build. This is a key
  `deltas/<fanout>/<leaf>/superblock` whose directory names do not decode
  as a delta, or a superblock larger than its cap. The run then does not
  compare the deltas. With no summary, the run does not list `deltas/`.
- `summary`, a note: an absent summary with no summary keys, or a summary
  that differs from the ref files or from the deltas of the bucket in
  another way.
- `stray`, an error: a key under `objects/` that is no object key.
- `missing`, an error: an object of a tree that the listing does not hold,
  or that is gone at its read.
- `missing`, a note: without the repair, an object of a tree that the
  listing does not hold, and that the read again finds.
- `mismatch`, an error: an object whose bytes do not have the checksum of
  its name, or a `.cfs` with another fs-verity digest.
- `corrupt`, an error: an object that does not parse, a `.filez` that does
  not inflate as its header declares, an object over the metadata size cap,
  or a `.cfs` whose commit records no digest that the run reads.
- `marker`, a note: without the repair, the partial-commit marker of a
  commit that the run walked, whose tree has no `missing`, `mismatch`, or
  `corrupt` finding, and whose own object has none.
- `upload`, a note: an incomplete multipart upload.
- `lock`, a note: a writer lock at the start or at the end of the run, or a
  lock of the run that is gone at its release.

The summary of a bucket repository changes only with the summary update,
and a push writes no summary. So a summary that lists old refs is a note.
A summary that a pull trusts and that leads the pull to an absent object is
an error.

The repair runs after the checks:

1. A check of the lock, and the write of the partial-commit marker
   `state/<checksum>.commitpartial` for each commit that reaches a tree
   object of a `missing`, a `mismatch`, or a `corrupt` finding. The marker
   holds the one byte `0x66`, as the `.commitpartial` marker of a local
   repository. A commit that holds a marker gets no new one, and a commit
   whose own object is bad gets none. Then the delete of each marker that
   a run without the repair gives a `marker` note. A marker of a commit
   that the listing does not hold stays until a prune ("The prune of a
   bucket repository").
2. A check of the lock, and the delete of each object of a `mismatch` and a
   `corrupt` finding: the commit objects, then the objects of the trees,
   then the composefs images. A bad commit object goes also when a ref names
   it, and the report names each such ref. A bad `.cfs` goes, and its
   commit stays.

At most `max_outstanding` writes and deletes run at a time. After a failed
write or delete, the repair starts no new one, and waits for the ones in
flight. A failure after the first check of the lock gives an error that
holds the report, with each marker and each delete that completed, and
that states that the repair is incomplete. The bucket can then hold the
marker of a commit whose bad objects are still in the bucket. A push of
that commit uploads no object that the listing holds, and then deletes the
marker, so the bad objects stay with no marker. Run the fsck with the repair
again before a push.

The repair deletes no commit because of a bad object of its tree, so each
ref keeps its commit, unless the object of the commit is bad. A ref whose
commit object the repair deleted is a `ref` error in the next run, and a
summary that names the commit is a `summary` error. A push of a ref whose
commit has a marker uploads the objects of the tree that the bucket lacks,
and then deletes the marker ("The push to a bucket repository"). A push of a
ref whose commit object the repair deleted uploads the commit again. The
pull of the port reads no key under `state/`.

### The prune of a bucket repository

The prune deletes the objects of a bucket repository that no root reaches.
`ostrya remote prune` runs it. The prune takes the options `--refs-only`,
`--depth`, `--keep-younger-than`, and `--no-prune` of `ostrya prune`, with
the same meaning. The library refuses each other option of the local prune
before a request. The prune also refuses `--break-lock` together with
`--no-prune` before a request. Thus a run with `--no-prune` removes no
writer lock of another writer. The prune keeps the objects of the listing
that a local prune with the same options keeps in a repository with the
same refs and objects, and also the objects of the commits that the summary
names and of their dependencies, under the bound of the run. Two
differences apply:

- The prune reads field 2 of each commit that the walk reaches, and keeps
  the dependencies as the local prune keeps them ("Related commits"). It
  reads no `.commitmeta`, so it reads no build source. So it deletes a build
  source that no other root reaches, and the objects that only that commit
  reaches. It also deletes the `.commitmeta` and the `.cfs` of a build
  source that the listing does not hold. The local prune keeps these. With
  `--refs-only` or `--keep-younger-than`, the local prune keeps each build
  source of a reached commit. Without these options, each commit of the
  listing is a root, and the difference is the `.commitmeta` and the `.cfs`
  of an absent build source alone.
- Without `--refs-only` and `--keep-younger-than`, the prune also deletes
  the `.commitmeta` and the `.cfs` of a parent commit that the listing does
  not hold. The local prune keeps these when its bound reaches that parent.

The roots are:

- the commit of each ref of `refs/heads/` and `refs/mirrors/<id>/`, under
  the bound of `--depth` or `--keep-younger-than`. A ref whose commit the
  bucket does not hold is no error, and it keeps nothing.
- the commit of each ref of the summary, in field 0 and in
  `ostree.summary.collection-map`, with no parent. A summary that does not
  parse, or that is larger than 64 MiB, fails the run before its first
  delete. With no summary, these roots are absent.
- without `--refs-only` and `--keep-younger-than`, each commit of the
  listing. Each root then keeps no parent, because each parent in the
  listing is a root of its own. The walk reads each commit one time. The
  kept objects of the listing do not change, with one exception: the walk
  does not reach a parent commit that the listing does not hold, so the
  prune deletes the `.commitmeta` and the `.cfs` of that commit.
- the commit of each field 2 entry of a commit that the walk reaches: the
  dependencies. With `--refs-only` or `--keep-younger-than`, a dependency is
  a root under the bound of `--depth` or `--keep-younger-than`, also a
  dependency of a commit of the summary. Without these options, a
  dependency keeps no parent, as each other root, so the walk still reads
  each commit one time.

The walk reads field 2 from the bytes of each commit object that it reads,
and sends no other request for it. It roots on field 2 entries that are not
sorted, on two entries with one name, and on the field 2 entries of a
dependency. A defective field 2 entry, with an empty name or with a
checksum that is not 32 bytes, roots nothing and gives one warning. The
other entries of the field root as usual. The text of the warning is
`related commits in field 2 of commit <checksum>: <reason>`, and
`ostrya remote prune` writes each warning on standard error after
`warning: `, before the lines on standard output, and exits 0. An entry
that names a commit that the listing does not hold roots nothing and gives
no warning. The walk keeps the name of that commit, so the prune keeps its
`.commitmeta` and its `.cfs`.

The walk reads each commit and each dirtree that it reaches with one `GET`.
It reads the commits one at a time. It reads the dirtrees of the tree of
one commit at most `max_outstanding` at a time, and reads the next commit
after the last of these reads. If more than one read fails, the first read
that fails in time gives the error of the run, and the walk drops the other
reads in flight. It reads at most the size of the object in the listing, and
at most the metadata size cap of 128 MiB. Each read holds the bytes of its
object in memory, so the reads in flight hold at most `max_outstanding`
objects. The SHA-256 of the bytes of each commit and dirtree must be the
checksum of its name, and the bytes must parse. Else the run fails before
its first delete, and a run of the fsck with the repair deletes the bad
object. The walk sends no request for an object that the listing does not
hold, and reads it as absent: an absent commit or dirtree keeps its own name
and no object below it. A listed object that is gone at its read fails the
run. With `--keep-younger-than`, the walk reads a commit a second time
when the time bound rejected the commit as a parent and the walk then
reaches the commit as a root, for example as a dependency. The walk reads
each other commit one time.

A kept commit keeps its `.commitmeta` and its `.cfs`. A partial commit that
the prune keeps keeps its marker. An object that only a dirtree that the
fsck deleted reaches is not reachable, so the prune deletes it. A push of
the commit of that dirtree uploads the object again.

The steps of the prune are:

1. The read of `config`, by the strict rule of an absent key. An absent
   `config`, a `config` that breaks a rule of "The config of a bucket
   repository", and a `config` that sets `[core] tombstone-commits=true`
   refuse the run before it takes the lock. The prune writes no tombstone.
2. The take of the writer lock with `operation=prune`. A run with
   `--no-prune` takes the lock too.
3. At the same time: the list of `refs/` and the read of each ref file, the
   listing of the objects of the 256 fan-out prefixes, the list of
   `deltas/`, the list of `state/`, the list of the incomplete multipart
   uploads, and the read of `summary`. A key under `refs/` other than
   `refs/heads/<name>`, and `refs/mirrors/<id>/<name>` with an id other
   than the collection id of the bucket, fails the run. So does a ref file
   that does not hold 64 lowercase hex digits and a newline.
4. The walk. A run with `--no-prune` then releases the lock, and reports
   the counts and the deletes that a run without it does.
5. The commits. One `DELETE` of each commit object to delete, then of its
   `.commitmeta` and then of its `.cfs` if these go too, in one slot for
   each commit. Then the `.commitmeta` and the `.cfs` of each commit that
   the listing does not hold.
6. Each other object to delete. A `.tombstone-commit` stays.
7. The static deltas whose target commit is not in the bucket after the
   run: first the `superblock` of each, and then each other key of these
   deltas. A delta directory with no superblock goes too. A key under
   `deltas/` that is not a key of a bucket repository, and a directory whose
   names do not decode as a delta, stay. `delta-indexes/` does not change.
   Then the `state/<checksum>.commitpartial` marker of each commit that is
   not in the bucket after the run. A marker goes after the commit object of
   its commit. Each other key under `state/` stays.
8. The abort of each incomplete multipart upload of the repository, with
   `DELETE KEY?uploadId=ID`.
9. The release of the lock.

The run checks the lock before each of the steps 5 to 8 that has a key to
delete or an upload to abort, and again after each 1000 deletes or aborts
of a step. A lock with another `id`, or no lock, stops the run before its
next delete, and the run releases no lock. Each delete is one `DELETE` of
one key. At most `max_outstanding` deletes or aborts run at a time. After a
failed delete, the run starts no new one, waits for the ones in flight,
releases the lock, and fails. A `DELETE` of a key that holds no object is a
success.

The counts are the counts of "Prune removal order": the total of the objects
of the listing, the objects to delete, and their size in the listing. The
counts leave out each `.commitmeta`, each `.cfs`, each `.tombstone-commit`,
and the static deltas. A delete of a key that holds no object counts too.
The prune deletes no ref.

A run that stops after its first delete leaves a bucket repository that a
reader can use: the commits go first, so each commit object in the bucket
has each object of its tree that it had before the run. The objects of the
deleted commits, their deltas, and their markers stay until the next run.

The prune writes no summary. The commits of the summary are roots, so the
prune deletes no commit that the summary names. A static delta of the
summary whose target commit is not in the bucket goes, and the summary that
names it stays as it is until the summary update writes the summary again. A
pull that trusts that summary can then ask for an absent delta.
