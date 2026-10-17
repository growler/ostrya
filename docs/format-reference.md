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
2. `a(say)` related objects: written as an empty array.
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
"Signing details" lists the signature keys and their values.

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

The port writes one summary for each auth item of the client groups. The
summary of the `anonymous` item is the file `summary` at the repository
root. A repository with no client group has two implicit groups, and the
summary of their `anonymous` item holds each ref. "Summaries of auth items"
states the summaries of the other items and the refs of each summary.

Field 1, `a{sv}`, is the global metadata. GVariant does not sort a dict again,
so the insertion order is the on-disk order. The writer writes the keys in
this order, and a key is absent when its condition is false:

- `ostree.summary.mode` -> `s`, the repository mode string (for example
  `archive-z2`, `bare`, `bare-user`).
- `ostree.summary.last-modified` -> `t` big-endian, the generation time. It is
  wall-clock time, and `SOURCE_DATE_EPOCH` does not set it.
- `ostree.summary.tombstone-commits` -> `b`, the `[core] tombstone-commits`
  value (default false). Always present.
- `ostree.static-deltas` -> `a{sv}`: delta name (`FROM-TO` or `TO`, in hex) ->
  `ay`, the SHA-256 of the `superblock` file of the delta (32 bytes). Present
  only when the repository has static deltas. A summary of the port that does
  not hold each ref lists fewer deltas ("Summaries of auth items"). The port
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
  (default true). Always present.
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
over the caller value. These keys are the four keys that are always present,
and `ostree.static-deltas`, `ostree.summary.collection-map`, and
`ostree.summary.collection-id` in a run that writes them. The writer keeps each
other caller key, whatever its name, and the empty key.

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
  refspec <name>` before the transport starts.
- `push-tree -b` refuses it with `error: Rev name '<name>' looks like a
  checksum`.
- In the library, `Repo::push`, `Repo::export_stream`, and `push_tree` refuse
  the name before they send a byte.
- The server of a push session or of a one-way stream refuses an update that
  writes a commit to such a ref at `Commit` ("Commit and CommitReply").

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

### Fallback selection

The generator makes an object a fallback when its compared size is at least the
threshold of `--min-fallback-size`. It puts the object into a part otherwise.
The unit is the decimal megabyte, 1,000,000 bytes. The default is 4, so the
default threshold is 4,000,000 bytes. An object whose size equals the threshold
is a fallback. The value is read as a whole number of megabytes, and 0 turns
fallbacks off.

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
- `ostree.sign.spki` -- SPKI/ECDSA signatures. The tool carries this engine
  only in a build with OpenSSL.
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

The signature key is `ostree.sign.spki`, and the algorithm is ECDSA over NIST
P-256 with SHA-256, over the commit bytes of the other engines. The signature
is DER-encoded ECDSA: an ASN.1 `SEQUENCE` of the two integers `r` and `s`,
about 70 to 72 bytes. A public key is the X.509 SubjectPublicKeyInfo DER, the
base64 body of a PEM `PUBLIC KEY` block. A secret key is base64, and the
decoded bytes are a PKCS#8 `PrivateKeyInfo` DER, a SEC1 `ECPrivateKey` DER, or
a raw 32-byte scalar. The key store has the form of the ed25519 store:
`trusted.spki`, `revoked.spki`, and their `.d` directories under `/etc/ostree`
and `<datadir>/ostree`, with one base64 SubjectPublicKeyInfo per line. Its
effective trusted set is also the trusted set minus the revoked set.

Design target: the public ostree documentation gives the public key container
and the key store layout. The curve, the hash, the DER signature encoding, and
the key DER containers are the standard OpenSSL and RFC forms.

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
- the ref patterns of the client groups and of the ref listing;
- the push protocol and the pull protocol, over HTTP and over a byte stream;
- the ref listing;
- the summaries of the auth items and the access digest;
- the endpoints of `ostrya serve`;
- the credential file of a push over HTTP;
- the ssh transport;
- the commit of `push-tree`;
- the mode `bare-user-shared`.

The push protocol and the pull protocol each have a version number. Both
versions are 1. The two numbers are separate, and each one changes on its own.
Over HTTP, the paths `/_ostrya/receive/v1/` and `/_ostrya/refs/v1` hold the
version. The pull over HTTP sends no version message.

## Configuration keys of the port

The `[ex-ostrya]` group, the server group, the client groups, the trust
groups, the key groups, and seven keys of a `[remote "NAME"]` group are
extensions of the port. The seven keys are `push-url`, `ssh-command`,
`receive-command`, `push-token-file`, `push-user`, `pull-url`, and
`send-command`. The `ostree` tool defines none of them and reads none.
`ostrya-config(1)` states each key, its type, its default, its precedence,
each refusal, and the operations that read it. "EXTENSION KEYS" and "CLIENT
AND SERVER GROUPS" state the groups, and "REMOTE KEYS" states the keys of a
remote. "The push token file of a client" states the grammar of the file that
`push-token-file` names.

The receive path of a server reads the client groups, the server group, the
trust groups, and the key groups from `<repo>/config`. It also reads
`[ex-ostrya] detached-metadata-exclude` and `[core] auto-update-summary` from
`<repo>/config`.

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

No key changes the encoding or the checksum of an object. Some keys change
which bytes a repository holds:

- `detached-metadata-exclude` and the key `sign` of a client group change
  the bytes of a `.commitmeta` file.
- `gc-root-metadata-keys` changes which objects a prune keeps.

The commit checksum does not cover detached metadata, so these keys change no
commit checksum.

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

`conformance/cli-surface.md`, "P2", `pull`, records how the tool and the port
treat a remote with `pull-url` and no `url`, and an ssh address in `url`.
`conformance/cli-behavior.md`, "`remote`", states how `remote list -u` stops
at a remote with no `url`.

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
  3 for a dirmeta, 4 for a commit, and 6 for detached metadata.
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

The sender selects the length of each chunk, up to the limit. In the push,
after the end chunk of an object, the next frame is one of these:

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

`Have` is a list of object names: the object type (1 to 4) and the checksum.
Another type is `protocol`. `HaveReply` is a bitmap with one bit for each entry
of the `Have`:

- Bit `i` is bit `i % 8` of byte `i / 8`, with bit 0 the least significant.
- A set bit means that the server needs the object.
- For `n` entries, the bitmap has `ceil(n / 8)` bytes, and each bit after the
  last entry is zero.

A client refuses a `HaveReply` of another length, or with a set bit after the
last entry, with `protocol`.

`ObjectHeader` holds the object type, the checksum, and the encoding. For type
6, the checksum is the checksum of the commit that the detached metadata
belongs to. Only type 1 can have the encoding `deflate`. These headers are
`protocol`:

- a type other than 1, 2, 3, 4, and 6;
- an encoding byte other than 0 and 1;
- the encoding `deflate` with a type other than 1.

The body of the object follows as chunks:

- `raw` -- for a file, the framed header and the payload of "File content
  object header". For each other type, the bytes of the object.
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
`state`, are `protocol`. The dict holds the key `force` (`b`). A writer puts the
key in the dict only when its value is true.

`CommitReply` holds one `(name, old, new)` entry for each update, in the order
of `Commit`. `old` is the commit of the ref before the write, and `new` is the
commit after it. An absent commit is an absent ref.

`Error` holds the code, a message for a person, and a dict of details:

- `missing` (`a(yay)`): the objects that a `missing-objects` error names, of
  the types 1 to 4. An entry of another type is `protocol`.
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
- `checksum-mismatch` -- the bytes of an object do not hash to its name.
- `mode-refused` -- the repository mode cannot store the content, or the
  client group does not allow privileged content.
- `missing-objects` -- a commit reaches objects that the server does not hold.
- `ref-mismatch` -- a ref is not in the state that its update expects, or an
  update with `t` and no `w` writes a commit to a ref that exists.
- `non-fast-forward` -- the new commit does not descend from the commit of the
  ref, and the client group or the request does not allow it.
- `delete-denied` -- the client group has no `d` on a ref that an update
  deletes.
- `invalid-ref` -- the server refuses a ref name, or the collection id of
  `Hello`: an id longer than 255 bytes, or one that fails the collection-id
  rule.
- `ref-denied` -- no client group covers the namespace of `Hello`, the client
  group opens no push session, a ref of `Hello` has no `r`, an update writes
  a commit without `w` or `t`, or an update names a ref that a push does not
  write.
- `signature-required` -- a commit has a signature that does not verify, or
  has no signature and the client group requires one.
- `binding-mismatch` -- the ref binding of a commit does not name its target
  ref, or its collection binding does not name the collection of the
  namespace of the session.
- `internal` -- a failure on the server side, for example an I/O error.

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
  empty and names no ref two times.
- `Have` and `missing` name objects of the types 1 to 4.
- An object has the encoding `deflate` only if it is a file and `HelloReply`
  lists `deflate`.
- A `Have` holds at most `max-have` entries, and its frame fits in
  `max-frame`.
- A session sends at most one detached metadata dict for each commit. The
  commit is a commit that the session sends, or the new commit of an update.
- Before `Commit`, a session sends each object that the tree of a commit of
  the session reaches, unless the server holds the object. The commits of the
  session are the commits that it sends and the new commits of the updates.
  The session does not need to send the parent commits.
- To cancel an object, a client sends the abandon marker and then `Abort`.
- On a stream, a client sends one request and reads its reply before it sends
  the next one.

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
   `[ex-integrity] fsverity`, and, in an `archive` repository,
   `[archive] zlib-level`. A malformed value is `internal`.
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

The server writes no object and no dict to `objects/` before `Commit`.

`ObjectsReply` counts the objects of one stream that the server staged and
the dicts that it kept. `payload_bytes` counts the body bytes of these
objects, with the chunk framing removed, in the encoding of the wire. An
object that the server held already does not count. Over HTTP, an object that
two `objects` requests send at the same time can count in both replies.

### Commit and CommitReply

The server runs these checks of `Commit` in this order. Each failed check ends
the session, and the session writes nothing:

1. Each ref name passes the refspec rule ("Ref name validation"). An update
   that writes a commit to a name of 64 lowercase hex characters fails this
   check too. A delete of such a name passes. A failure is `invalid-ref`.
   Then a request with no update, an update of a ref that `Hello` does not
   name, and two updates of one ref are `protocol`.
2. A `CommitReply` with a commit in each `old`, and the `new` of each
   update, that needs a frame over 1 MiB is `limit-exceeded`.
3. A detached metadata dict for a commit that the session did not stage and
   that no update names as `new` is `protocol`.
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
   absent commits fail together, after the read of the other commits.
6. Each object that the tree of a commit of the session reaches must be
   staged or present, else `missing-objects`. The parents of a commit are not
   required. The `missing` detail names at most 16384 objects. A staged
   dirtree that does not parse is `protocol`, and a stored one is
   `internal`.
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
8. A new commit must pass the signature verification of the client group,
   else `signature-required`. The verification reads the stored detached
   metadata of the commit and the incoming dict together, before the
   `detached-metadata-exclude` filter of step 9. A group with no `verify`
   checks no signature. A group with `verify=trust:NAME` checks each axis of
   the trust group. With `allow-unsigned=true`, a commit whose dict holds no
   blob under `ostree.gpgsigs`, `ostree.sign.ed25519`, `ostree.sign.spki`, and
   `ostree.sign.dummy` passes. A commit with a blob under one of these keys
   must pass the check, so a signature of an engine that the trust group does
   not read fails.
9. The server applies the `detached-metadata-exclude` filter, makes the
   staged objects durable, and signs each new commit one time with each key
   of the key `sign` of the client group. It walks the history of each update
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
   lock it reads the refs again and runs checks 10 to 12.
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
- an update whose state is 1, and an update with no `new`. The server refuses
  them when it reads `Commit`.

If a client cannot complete an object, it sends the abandon marker and then
`Abort` ("Abort, abandon, and end of input"). The server then ends the session
with no change.

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
input. A one-way stream adds no server signature, writes no anchor commit,
and does not regenerate the summary. It calls no hook of a host application.

A one-way stream keeps rules of its own, and a client group does not apply to
it. A host application gives the rules in code. Each rule has a pattern with
an optional remote part, so a one-way stream can write a remote ref
`REMOTE:NAME`. A rule states if it accepts an update, the trusted keys of
check 8, if it allows a delete, and if it allows an update that is not a
fast-forward under `force`. Check 4 refuses an update that no rule covers
and an update whose rule does not accept it, with `ref-denied`. Check 8 with
trusted keys refuses a commit with no signature. Check 11 refuses a delete
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
  collection whose group gives no `r`.
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

1. `ostree.summary.mode`: the mode of the repository.
2. `ostree.static-deltas`: when the walk below finds a delta.
3. `ostree.summary.collection-map`: when the listing holds a collection ref.
4. `ostree.summary.collection-id`: when the repository has a collection id.

This is the order of the same keys in a summary. The dict holds no
`ostree.summary.last-modified`.

The deltas come from the index files under `delta-indexes/` ("Static delta
index files"). The server reads the index file of the commit of each listed
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

A listing is at most 128 MiB. The server refuses a larger listing and never
cuts it short. The collection map counts toward this size. The server checks
a lower bound of the size from the names of the refs and from the collection
ids after each ref that it selects, before it reads a commit. It reads no more
ref file when the bound passes the size. It writes the map one ref entry at a
time, so a listing over the size fails before it is whole in memory.

## Summaries of auth items

The port writes one summary for each auth item that has a summary. An auth
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
`ostree.summary.last-modified`. `[core] indexed-deltas` sets
`ostree.summary.indexed-deltas` in each summary. The caller keys of
`summary -m` go into each summary. `ostree.static-deltas` lists these
deltas:

- When the summary holds each local ref and each collection ref of the
  repository, the map lists each delta.
- Else the map lists the deltas whose `TO` commit is the commit of a ref in
  the summary. Another delta can name a commit that the item does not read,
  and the checksum of a commit is enough to fetch it.

### The files of a summary

`HEX` below is the SHA-256 digest, in 64 lowercase hex digits, of the text of
the item in its parsed form (`ostrya-config(1)`, "Authentication items"). For example,
the text of `net:2001:0db8::/56` is `net:2001:db8::/56`.

- The summary of the `anonymous` item is `summary` and `summary.sig` in the
  repository root, where the tool writes them.
- The summary of each other item is `extensions/ostrya/summary/HEX` and
  `extensions/ostrya/summary/HEX.sig`. The signature file has the format of
  "Summary signature -- `a{sv}`".
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

`ostrya summary -u` writes the summary of each item that has a summary, one
item at a time, in the order of the first group of each item in the config:

1. It builds the summary and makes each signature. A summary with the bytes
   of an earlier summary of the run takes the signatures of that summary.
2. When the `.access` file of the item holds another digest, it removes
   that file.
3. It removes the old signature file, writes the summary, and writes the new
   signature file when a key signs.
4. It writes the `.access` file of the item.

So while the `.access` file of an item holds a digest, the summary next to
it is a summary of that digest. With `[core] fsync=true`, the command syncs
the directory of the `.access` file after the removal of step 2, and the
directory of the summary before step 4. A crash then cannot leave an
`.access` file next to a summary of another digest.

Then it removes the files under `extensions/ostrya/summary/` of each item
that has no summary, the `.access` files first. It removes the temp files of
these names, and `HEX` and `HEX.sig` of the `anonymous` item. It leaves each
other entry of the directory. When the `anonymous` item has no summary, it
removes `summary` and `summary.sig` in the repository root.

The command checks every `-m` value, every key, and the client groups before
it writes a file. A refusal leaves each summary as it was. The command holds
the repository lock shared and the update lock for the whole run ("The
update lock").

With `[core] auto-update-summary=true`, a push through `ostrya serve` or
`ostrya receive` that changes a ref writes each summary again, as
`ostrya summary -u` does. The key groups of `sign-summary` sign them, GPG
keys first. A one-way stream writes no summary.

A mirror pull that writes `summary` removes the `.access` file of the
`anonymous` item under the same hold of the update lock.

### The serve of a summary

The server computes the access digest of each item at start. A request for
`summary` or `summary.sig`, over HTTP and over a stream, gets the file of the
summary of the identified item ("The files of a summary"). The request gets
the answer of an absent path in these cases:

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
  `collection-id=ID\n` and then `indexed-deltas=VALUE\n` when the repository
  config sets them. Each value is as the repository config writes it. The
  view serves no other key and no other group. The view parses the
  repository config again when its inode number, size, modification time, or
  change time differs from the last parse. The next answer then shows the
  change.
- The view serves these files as stored: the files under `refs/` and
  `extensions/`, and the `.commit`, `.dirtree`, `.dirmeta`, and
  `.commitmeta` objects. In an `archive` repository, it also serves the
  `.filez` objects and the files under `deltas/` and `delta-indexes/` as
  stored. "Read access" states which of these files a client gets.
  `extensions/ostrya` and each path under it are absent.
- `summary` and `summary.sig` are the files of the summary of the auth item
  of the client, as stored ("The serve of a summary").
- In each other mode, the view builds a `.filez` object on request. The
  object is the framed archive header of the logical metadata that the mode
  stores, then the payload in raw DEFLATE at `[archive] zlib-level`. An
  `archive` repository of the port stores the same bytes for the same object
  at the same level. A symlink object is the header alone.
- The file of a built `.filez` can hold another size than its header states.
  Then the body fails during the transfer, after the status and the headers
  went out.
- In these modes, `deltas/` and `delta-indexes/` are absent, and the view
  serves a summary that names a delta unchanged. A pull then fetches the
  objects loose (`conformance/cli-behavior.md`, "HTTP pull surface").
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

The summary of a `bare-user-shared` repository states that mode in
`ostree.summary.mode`. `conformance/cli-surface.md`, "P2", `serve`, records
the pull of the tool from this summary.

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
   alone, and never from the TLS handshake.
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
header gives no certificate. From a peer that is not in `trusted-proxy`, and
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

`ostrya push-tree` builds one commit over a local directory on the client
and sends it to the server. The tool has no such command. The commit object
has the format of each other commit, and its bytes follow these rules.
`ostrya-push-tree(1)` states the options and the output of the command.

- The metadata dict holds the entries of the caller and the binding keys, in
  the order of `commit` (`conformance/cli-behavior.md`, "CLI output
  formats", `commit`). These rules are specific to `push-tree`:
  - The command has no `--keep-metadata`, so no entry comes from a parent.
  - `ostree.ref-binding` holds each `-b` name, sorted.
  - `ostree.collection-binding` holds the collection id that the server
    reports for its repository. When the server has no collection id, the
    key is absent. The collection id of a local repository has no effect.
  - `--no-bindings` writes neither key.
- `--owner-uid`, `--owner-gid`, and `--canonical-permissions` apply to each
  entry of the walk, the root directory included, so they change the root
  dirmeta too. The canonical rule comes first: owner 0:0, no extended
  attributes, and the mode `type | (perm & 0o755)` for each entry other than
  a symlink. Each declared owner id comes after it. The tool applies the
  options to the root dirmeta in the same way.
- The walk reads no extended attributes. The commit checksum depends on the
  tree, the owner, the modes, the subject, and the body. It also depends on
  the metadata options, the timestamp, the parent, and the collection id. The
  collection id is that of the server for `push-tree`, and
  `[core] collection-id` of the repository for the tool. With equal inputs,
  the commit checksum is equal to the checksum of
  `ostree commit --no-xattrs -b R1`. With two refs, it is equal to the
  checksum of `ostree commit --no-xattrs -b R1 --bind-ref R2`.
- The detached dict holds the entries of the caller, then the signatures in
  the order of `commit` (`conformance/cli-behavior.md`, "CLI output
  formats", `commit`). The server can change this dict before it stores it
  ("Commit and CommitReply", checks 9 and 12).

Observed behavior: with `SOURCE_DATE_EPOCH=1700000000` on both sides and no
collection id on either side, both checksums are equal. The checks cover
`--canonical-permissions`, `--owner-uid=0 --owner-gid=0`, `--body-file` alone
and next to `-m`, `--parent=none`, `--parent` with a commit, `--no-bindings`,
and an explicit `--timestamp`.

Observed behavior: a check uses `--add-detached-metadata-string` and distinct
ed25519 keys from `--sign` and `--sign-from-file`. With these options, the
`.commitmeta` bytes on the server are equal to the bytes of `ostree commit`. The
server of this check has no detached-metadata filter and no signing key, and
it holds no `.commitmeta` of the commit before the push. The equality needs
keys that are not empty, because `push-tree` refuses an empty key
(`ostrya-push-tree(1)`).

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
