# OSTree On-Disk Format Reference

This document specifies the on-disk repository format that the Rust port must
reproduce byte-for-byte. It is an interoperability specification: every field
width, endianness note, and sort order here is a hard compatibility requirement,
because the object checksum is computed over these exact serialized bytes.

Provenance: this specification is established from the public ostree
documentation (https://ostreedev.github.io/ostree/) and by inspecting the
objects and output the `ostree` tool produces, run as a black box. It does not
derive from the LGPL source (see CLAUDE.md, "Licensing and clean-room
discipline"). Each fact stated here is verifiable by creating a repository with
the tool and examining the bytes it writes; the GVariant serialization it builds
on is GLib's publicly documented format.

## Foundational constants

- SHA-256 digest: 32 raw bytes, 64 lowercase hex chars (`[0-9a-f]`).
- Metadata size cap: 128 MiB (limit on fetched/loaded metadata).
- Stored-file mtime: 0. Files stored and checked out carry mtime 0; file
  timestamps are not part of the content model.

## GVariant serialization rule (applies to every metadata object)

Metadata objects are stored as GVariant in normal form. There is no
whole-variant byte swap anywhere in ostree. Two separate concerns:

- Container framing (element offsets, framing bytes) is written in native byte
  order, which is the standard GVariant normal-form encoding. In practice all
  targets are little-endian.
- Individual scalar integer fields (uid, gid, mode, rdev, timestamps, sizes)
  are converted to big-endian at the value level before being placed in the
  variant, and read back from big-endian.

For the port: store the numeric fields as already-big-endian `u32`/`u64`
values, then emit standard normal-form GVariant. A Rust GVariant serializer
must produce byte-identical normal-form output, because the checksum is taken
over those bytes. Values are written in GVariant normal form before hashing.

## Object types

Object-type numeric values are wire-significant (used in the `(su)` object-name
serialization and in `ostree.sizes`).

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

The is-meta predicate is `t` in 2..=6. Types 7/8/9 are not "meta" despite being
auxiliary. The checksum rules key off the is-meta predicate. The `z` loose-path
suffix applies only to a `FILE` object (type 1) in archive mode, stored
zlib-compressed as `.filez`. The auxiliary non-meta objects carry no suffix:
`.payload-link` is a symlink, `.file-xattrs` holds an uncompressed GVariant
blob, and `.file-xattrs-link` is a hardlink. Object string form is
`<hexchecksum>.<typestr>`. Object-name GVariant is `(su)` = (hex-string,
objtype-as-u32).

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

The metadata dict is an array of key-value tuples, and it holds the order its
writer produced. That order is part of the commit checksum, so the port
serializes the dict in insertion order and a caller reproducing a tool commit
supplies the keys in the order the tool supplies them (see "CLI output
formats", `commit`). A reader addresses the dict by name: it reaches a key
whatever slot the entry stands in. A name may stand twice, and a lookup by that
name reaches the entry standing first.
The `conformance/m10-cli-behavior.matrix` cells state this over commits both
implementations write. `commit/metadata-group-order` and
`commit/metadata-duplicate-key` reach the tool's own checksum over dicts whose
stored order follows neither the command line nor a sort.
`commit/metadata-nonsorted-read-back` reads every key of such a dict back by
name, and the duplicate-key cell reads a repeated name back to its first
entry.

Well-known metadata keys: `version` (`s`, the only key without the `ostree.`
prefix), `ostree.architecture` (`s`), `ostree.ref-binding` (`as`),
`ostree.collection-binding` (`s`), `ostree.endoflife` /
`ostree.endoflife-rebase` (`s`), `ostree.source-title` (`s`), `ostree.linux`
(`s`) and `ostree.bootable` (`b`) (see below), `ostree.composefs.digest.v0`
(`ay`, see "composefs"), and `ostree.sizes` (see below). Ref and collection
bindings are added by higher-level operations, not by the base commit metadata.

`ostree.linux` and `ostree.bootable` mark a commit that carries a kernel.
`ostree.linux` is an `s` holding the name of the directory under
`/usr/lib/modules` that holds the kernel, and `ostree.bootable` is a `b` holding
true. The tool writes the pair together, under `commit --bootable`; the search
that produces the name is recorded in "CLI output formats", `commit`.

`ostree.sizes` value type is `aay`; each entry is a packed byte buffer sorted
by ASCII checksum:

```
[32 bytes checksum][varuint64 compressed size][varuint64 unpacked size][1 byte objtype]
```

The varuint64 is protobuf-style LEB128 (little-endian base-128, high bit is
the continuation flag). The encoding is canonical: each value has one minimal
form, so a multi-byte sequence whose terminating byte is `0x00` (contributing
no value bits) is not accepted. Rejecting non-minimal forms keeps
unpack-then-pack of an entry byte-identical. The trailing objtype byte is
present on newer commits; parsers tolerate its absence.

The key holds an entry for every object reachable in the commit, not only
content objects. Recovered by decoding a `commit --generate-sizes` commit on
ostree 2026.1: the entries cover the content objects and the dirtree and
dirmeta metadata objects, sorted together by ASCII checksum, and each entry's
trailing byte carries that object's own type (`File`=1, `DirTree`=2,
`DirMeta`=3). The commit object itself is absent, as it does not exist when the
key is computed. The compressed size is the object's on-disk size (a content
object's `.filez` storage size, a metadata object's serialized byte length);
the unpacked size is the object's logical `st_size` -- a regular file's payload
length, a symlink's target length, and a metadata object's serialized byte
length -- so for a metadata object, stored uncompressed, the compressed and
unpacked sizes are equal. When the commit carries caller-supplied metadata,
`ostree.sizes` is appended after it (observed: a branch commit's
`ostree.ref-binding` precedes the `ostree.sizes` the tool adds).

The sort key is the raw 32-byte checksum read as a byte string, which is the
order the hex form gives as well. A decoded key, from a `commit
--generate-sizes` of a tree holding four directories, one symlink, and three
regular files, with each entry's length in bytes:

```
checksum (first 8 bytes)   archived  unpacked  type          length
0cad59c0775ee80f...        80        80        2 dirtree     35
1b6ba70951395486...        12        12        3 dirmeta     35
1c16bd4554d0fb08...        41        51        1 file        35
6e340b9c...                1         1         2 dirtree     35
6e4aa995...                145       145       2 dirtree     37
8c7b8dd4...                36        2         1 file        35
8d81d4ff...                148       148       2 dirtree     37
abadce0d...                48        12        1 file        35
fe657422...                20044     20000     1 file        39
```

The first entry reads, byte for byte:

```
0c ad 59 c0 77 5e e8 0f 24 1e c8 58 2d 9c 1e 64
6b 4f b5 59 8c 1a 6e 7a 9e 09 7a 61 20 d4 41 b5   32 checksum bytes
50                                                archived  = 80
50                                                unpacked  = 80
02                                                dirtree
```

Every archived value equals the size of the object's file under `objects/`, so
an entry's first size field grows past the second where the payload inflates
under compression (the 20000-byte random file above stores 20044 bytes).

`ostree.sizes` is written only by archive-mode repositories; the compressed
size is the `.filez` storage size, which makes it the only storage-dependent
commit-metadata field. Observed on ostree 2026.1: requesting size generation
(`commit --generate-sizes`) in a bare or bare-user repository is a silent
no-op -- no key is written, no warning is emitted, and the commit checksum is
byte-identical to the same commit without the request -- while in an archive
repository it adds the key and changes the commit checksum. Cross-mode commit
identity therefore holds exactly when size generation is off on the archive
side.

Because the archived size is the stored size, the key records what the writing
implementation's DEFLATE encoder produced. Two implementations agree on the key
exactly where their compressed payloads have equal length. The port and the tool
reach two lengths for most payloads, so the key parts over a real tree;
`conformance/cli-surface.md`, "P2" records the measured frequency and the named
payloads.

### Dirtree -- `(a(say)a(sayay))`

0. `a(say)` files: (filename `s`, content checksum `ay`=32 bytes), sorted by
   filename with byte-wise comparison.
1. `a(sayay)` dirs: (dirname `s`, dirtree checksum `ay`=32, dirmeta checksum
   `ay`=32), sorted by dirname with byte-wise comparison.

Sort order is mandatory for reproducible checksums. Each filename is validated
(not `.`, not `..`, no `/`, valid UTF-8): this is the path-traversal defense.

The two lists are independent, so a name can appear in both. The tool does not
guard against this: observed by injecting a root dirtree that carries one name
in both lists (built with the port's encoder so framing and per-list sort stay
valid, then spliced into the commit and ref), `ostree fsck` reports no errors
and `ostree ls` prints both entries, and `ostree ls -R` aborts on an internal
assertion when it resolves the name as a directory. The port never mints such
an object: the write path and the owned-parse path reject a name shared between
the two lists, while the borrowed read iterators stay per-list.

### Dirmeta -- `(uuua(ayay))`

0. `u` uid (big-endian).
1. `u` gid (big-endian).
2. `u` mode, full `st_mode` including `S_IFDIR` (big-endian).
3. `a(ayay)` xattrs, sorted by name.

No rdev, no symlink field.

### File content object header

Content objects (`.file`/`.filez`) are a header GVariant followed by payload.

Uncompressed stream header `(uuuusa(ayay))`, used for bare-mode streams and for
checksum computation:

0. `u` uid (BE), 1. `u` gid (BE), 2. `u` mode (BE), 3. `u` rdev (must be 0),
4. `s` symlink target (empty for non-symlinks), 5. `a(ayay)` xattrs (sorted).

Compressed archive header `(tuuuusa(ayay))`, stored on disk in archive mode:

0. `t` uncompressed size (BE), 1. `u` uid (BE), 2. `u` gid (BE), 3. `u` mode
(BE), 4. `u` rdev (must be 0), 5. `s` symlink target, 6. `a(ayay)` xattrs.

On parse, rdev != 0 and non-REG/non-LNK modes are rejected.

On-disk framing of a content stream (the length-prefixed header):

```
[4 bytes BE u32: variant length][4 bytes 0x00 padding to 8-byte align][header variant bytes]
```

For regular files the raw payload follows immediately (archive: raw-deflate
compressed; bare on-disk: the payload is stored without this framing -- the
framing is used transiently and for checksum). The 4-byte NUL pad aligns the
variant for mmap.

### bare-user metadata xattr -- `(uuua(ayay))`

Value stored in the `user.ostreemeta` xattr on `.file` objects in bare-user
mode. Same layout as dirmeta.

### Detached commit metadata (`.commitmeta`) -- `a{sv}`

A bare dict, not wrapped in a tuple. Not part of the commit checksum: stored in
a separate loose-path file, mutable, holds signatures. Writing with no metadata
produces a zero-length file (deletion). Signature keys, all value type `aay`
(array of signature blobs, append-only):

- `ostree.gpgsigs` -- OpenPGP detached-signature blobs over the commit bytes.
- `ostree.sign.ed25519` -- raw 64-byte ed25519 signatures.
- `ostree.sign.spki` -- SPKI/ECDSA signatures (OpenSSL-only in the reference
  tool).
- `ostree.sign.dummy` -- test engine.

## Summary and summary signature

### Summary -- `(a(s(taya{sv}))a{sv})`

Lives at repo root as `summary`. Outer tuple `(refs, global_metadata)`.

Field 0 `a(s(taya{sv}))` ref array holds the local refs (`refs/heads`), sorted
by ref name with byte-wise comparison; remote refs are excluded. Each entry
`(s, (t, ay, a{sv}))`:

- `s` ref name.
- `t` size of the commit object in bytes, written host-order (NOT
  byte-swapped). This is the one asymmetry versus the big-endian timestamps.
  The commit object is stored uncompressed, so this equals its on-disk length.
- `ay` commit checksum, 32 raw bytes.
- `a{sv}` per-ref metadata, in insertion order: `ostree.commit.version` (`s`),
  present only when the commit records a `version` metadata key, then
  `ostree.commit.timestamp` (`t`, big-endian), always present.

Field 1 `a{sv}` global metadata, written in this insertion order (a key is
absent when its condition does not hold; GVariant does not re-sort dicts, so
insertion order is the on-disk order):

- `ostree.summary.mode` -> `s`, the repository mode string (for example
  `archive-z2`, `bare`, `bare-user`).
- `ostree.summary.last-modified` -> `t` big-endian, the generation time. It is
  wall-clock and is NOT pinned by `SOURCE_DATE_EPOCH`.
- `ostree.summary.tombstone-commits` -> `b`, the `[core] tombstone-commits`
  value (default false); always emitted.
- `ostree.static-deltas` -> `a{sv}`: delta-name (`FROM-TO` or `TO`) -> `ay`
  32-byte superblock digest. Present only when the repository has static deltas.
  Observed here, between `tombstone-commits` and `indexed-deltas`, by running
  `ostree summary -u` on a repository holding one from-scratch and one from-to
  delta. Its order relative to `ostree.summary.collection-map` is not yet
  observed, since that needs a collection repository carrying deltas. The map's
  own entry order is the order the writer walked `deltas/`, which is the order
  the filesystem returned: a repository holding four deltas of one target lists
  them in neither name order nor any other stable one, so the entries of a
  summary carrying deltas are reproducible and their order is not. The digest is
  the SHA-256 of the delta's `superblock` file, confirmed against `sha256sum`.
  `ostree summary -u` does not write or refresh `delta-indexes/`, so a repository
  can advertise deltas in its summary while serving no index at all.
- `ostree.summary.collection-map` -> `a{sa(s(taya{sv}))}`, present only when
  the repository holds mirror refs (`refs/mirrors/<collection>/<ref>`). It maps
  each collection id to a ref array shaped exactly like field 0. Both levels are
  byte-wise sorted.
- `ostree.summary.indexed-deltas` -> `b`, the `[core] indexed-deltas` value
  (default true); always emitted.
- `ostree.summary.collection-id` -> `s`, present only when
  `[core] collection-id` is set.
- `ostree.summary.expires` -> `t` big-endian. Emitted only when an expiry is
  requested.

Endianness summary: all `t` timestamps and `expires` are big-endian; the
per-ref commit-object size `t` is host-order.

### The `ostree-metadata` anchor commit

When `[core] collection-id` is set, regenerating the summary first refreshes an
anchor commit on `refs/heads/ostree-metadata`. The anchor is an empty-tree
commit: root dirtree `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`
(no entries) and root dirmeta
`446a0ef11b7cc167f3b603e585c7eeeeb675faa412d5ec73f62988eb0b6c5488`
(uid 0, gid 0, mode `040755`, no xattrs). Its metadata dict carries, in this
order, `ostree.collection-binding` (`s`, the repository's collection id) and
`ostree.ref-binding` (`as`, the single element `ostree-metadata`); subject and
body are empty. The timestamp resolves like any commit (explicit,
`SOURCE_DATE_EPOCH`, then the current time). Each regeneration commits a new
anchor with the previous anchor as its parent, so the checksum advances on every
run; the first generation on a fresh repository is parentless and reproducible.
The anchor ref appears in field 0 by name like any other local ref.

### Summary signature -- `a{sv}`

File `summary.sig` at repo root, a bare `a{sv}` with the same signature keys as
detached commit metadata. The signed payload is the exact byte content of the
`summary` file. Regenerating the summary removes any existing `summary.sig`,
since a new summary invalidates the old signature; a caller that wants a signed
summary regenerates and then signs.

## Checksum computation

Object ID is SHA-256 over specific bytes, as a 64-char lowercase hex string.

- Metadata objects (dirtree, dirmeta, commit, tombstone, commitmeta): hash the
  canonical normal-form GVariant serialization bytes and nothing else.
- File content objects: hash = SHA-256( uncompressed-file-header bytes ||
  raw-payload bytes ). The header bytes fed to the hasher include the 4-byte BE
  length prefix and 4-byte NUL padding produced by the length-prefix framing.
  The payload is the uncompressed content. In archive mode the on-disk `.filez`
  is compressed, so the stored bytes do not match the object name.
- Symlinks: header carries the target in the `s` field, no payload; hash is the
  framed header bytes.

Checksum variants: one omits xattrs from the header; one zeroes uid/gid and
canonicalizes mode (used for bare-user).

The commit content checksum is SHA-256( root-dirtree-csum-binary ||
root-dirmeta-csum-binary ): a content identity independent of commit metadata
and timestamp.

Representations: hex (64 chars), binary (32 bytes), GVariant `ay` (32-element),
and modified-base64 (standard base64 with `/` replaced by `_` and trailing `=`
dropped, 43 chars) used only for static-delta directory names.

Base64 decoding of a checksum is strict and per-alphabet, so each digest has
exactly one accepted spelling: the length is exact (44 characters ending in one
`=` for the standard form, 43 for the modified form), the `/` and `_` glyphs at
index 63 are accepted only for their own alphabet, and the two unused low bits
of the final significant sextet must be zero.

## Repository modes and on-disk storage

Mode strings: `bare`, `bare-user`, `bare-user-only`, `archive-z2` (alias
`archive`), `bare-split-xattrs`, and the port extension `bare-user-shared`.
ARCHIVE always serializes back as `archive-z2`.

- bare: real files, real uid/gid/mode/xattrs on the inode; root-only for
  faithful writes; checkout hardlinks directly.
- bare-user: metadata in `user.ostreemeta` xattr; inode is root-owned with mode
  forced to `(mode & (S_IFREG|0775)) | S_IRUSR`; symlinks stored as regular
  files; writable unprivileged.
- bare-user-only: no xattr metadata; uid/gid discarded (read back as 0);
  canonical mode on the inode, regular-file bits limited to 0775; works on
  filesystems without xattr support; user-checkout only.
- bare-split-xattrs: bare inode storage (a regular file's payload on the inode,
  the logical uid/gid/mode on the inode, symlinks as real symlinks, no
  `user.ostreemeta`) with the logical xattrs relocated to separate objects. The
  inode carries no xattrs; the set lives in a `.file-xattrs` object reached
  through a `.file-xattrs-link` object keyed by the `.file` checksum. The tool
  reads this mode fully; its write support is experimental, gated, and
  incomplete. The port reads this mode and does not write it. Recovered shape
  is in the dedicated section below.
- archive (archive-z2): content zlib-RAW-compressed as `.filez`; header holds
  uid/gid/mode/xattrs; object file itself is chmod 0644; HTTP-servable;
  never hardlinked on checkout.
- bare-user-shared (port extension, development-only): `bare-user` storage
  with a fixed inode mode 0644, for group-shared repositories. See the
  dedicated section at the end.

Metadata objects are always stored uncompressed. The `z` suffix applies only to
a `File` content object in archive mode (`.filez`). The auxiliary non-meta
objects (`.payload-link`, `.file-xattrs`, `.file-xattrs-link`) are stored
uncompressed and never carry it. Observed by driving the tool as a black box:
an archive repo populated by commit, and by `pull-local` from bare and archive
sources, holds only `.filez` content objects alongside uncompressed metadata;
`.file-xattrs`/`.file-xattrs-link` belong to `bare-split-xattrs` mode, into
which the tool refuses every write ("Not allowed due to repo mode").

## Object store layout

```
<repo>/
  config                          GKeyFile INI, repo root
  .lock                           repository lock file (advisory)
  objects/<c0c1>/<c2..c63>.<ext>[z]   loose objects
  refs/heads/<ref>                local refs (ref may contain '/')
  refs/remotes/<remote>/<ref>     remote refs
  refs/mirrors/<collection>/<ref> collection refs (lazy)
  state/<checksum>.commitpartial  incomplete-commit markers
  tmp/                            staging (staging-<bootid>-XXXXXX + -lock), cache/
  tmp/cache/summaries/            summary cache
  extensions/                     reserved, created empty
  deltas/                         static deltas (lazy)
  delta-indexes/                  delta indexes (lazy)
  uncompressed-objects-cache/     archive checkout cache (lazy)
  summary                         (lazy)
  summary.sig                     (lazy)
```

Loose object path: `objects/<first 2 hex>/<remaining 62 hex>.<typestr>` with a
trailing `z` only on a `File` content object in archive mode. Checksum must be
exactly 64 hex chars.

Ref file format: 64 lowercase hex chars plus a single `\n` (65 bytes). A NULL rev deletes;
an alias is written as a relative symlink. Refspec `remote:ref` maps to
`refs/remotes/remote/ref`; a bare `ref` maps to `refs/heads/ref`. Every ref is
an individual loose file; there is no packed-refs mechanism.

Ref name validation. A ref name is one or more `/`-separated components. Each
component is non-empty, does not begin with `-` or `.`, and holds only
alphanumerics, `-`, `.`, `_`, and bytes at or above `0x80`. One optional `:`
separates a remote name from the ref name, and a second `:` is invalid.
Recovered by feeding `ostree rev-parse` one candidate name per ASCII
punctuation character: the tool accepts `a-b`, `a.b`, `a_b`, `a..b`, `a.`,
`0ab`, and `té`, and rejects each of `! " # $ % & ' ( ) * + , ; < = > ? @ [ \ ]
^ ` { | } ~` and space in a component, `-a` and `.a` and `~a` and `+a` at the
start of one, an empty component (`a//b`, `/a`, `a/`), and `a:b:c`, each with
`error: Invalid refspec <name>` and exit 1. The remote is one component, so
`a/b:x` is refused too. The port's own check is narrower -- it rejects an empty
name, an empty, `.`, or `..` component, a `/` in the remote name or in the
collection id, and an interior NUL, and accepts the rest -- so `ostrya refs
--create` writes some names the tool then refuses to resolve
(`conformance/cli-surface.md`, "P1 -- reading and resolution").

Both implementations report a name they refuse as `error: Invalid refspec
<refspec>` and exit 1, wherever the name is taken: a revision, a NEWREF, or the
`-b` branch of a commit. The refspec is reported as given, holding the
`<remote>:` or `<collection-id>:` prefix and dropping a trailing run of `^`, so
`rev-parse a/../b^` and `rev-parse a/../b` report the same line. The target of
`refs -A --create` is the one site the rule does not report at, an existence
check standing ahead of it there, so a refused name is reported as a name no ref
holds, in the words "refs" below states.

A ref name that passes the rule also names a path below `refs/`, and that path
is opened where the name is resolved or written. A path running through a ref
file ends the invocation with exit 1 in both implementations, and neither writes
a ref: `rev-parse <name>`, `cat <name> PATH`, the positional revision of `refs
--create`, `refs --create=<name>`, and `refs -A --create=<name>`. The tool names
the path below the repository and the syscall -- `error:
openat(refs/heads/plain/x): Not a directory` for the name `plain/x` over the ref
`plain`, the same line for a name reaching the ref file through an alias
symlink, and `error: openat(refs/remotes/origin/rr/x/y): Not a directory` for
`origin:rr/x/y` over the remote ref `origin:rr/x`. Under `-c
--create=<id>:<ref>` the existence check reads the absent
`refs/remotes/<id>/<ref>` and the write reaches the mirror path, so the tool
reports `error: open(O_TMPFILE): Not a directory` and names no path. The port
reports `error: i/o error: Not a directory (os error 20)` at every one of those
sites, the one message it gives that condition. The target of `refs -A --create`
is answered by the existence check ahead of the rule, so the tool reports the
target as a name no ref holds there and the port reports its own `Not a
directory` line (`conformance/cli-surface.md`, "P1").

A ref name that names a directory under `refs/` is refused at those same sites in
the port, with `error: i/o error: Is a directory (os error 21)`. The tool refuses
it where the name is resolved and where `-A --create` writes a link, in three
messages of its own, and its plain `--create` refuses a directory under
`refs/heads` that holds a ref below the name: `refs --create=deep plain` over the
ref `deep/nest/ing` reports `error: Conflict: nest/ing exists under deep when
attempting write`, with `--force` and without it
(`conformance/cli-surface.md`, "P1"). Where that scan reaches no ref below the
name, the tool's write replaces the directory, removes what stood below it, and
exits 0 printing nothing. Four shapes take that path:

- an empty directory, which `refs --delete` leaves behind in both implementations
  when it removes a directory's last ref, so `refs --delete deep/nest/ing` and
  then `refs --create=deep/nest plain` writes the ref file over
  `refs/heads/deep/nest`;
- a directory holding directories alone, so after that same delete
  `refs --create=deep plain` replaces `deep` and removes `nest`;
- any directory under `refs/remotes`, so `refs --create=origin:rr plain` over the
  refs `origin:rr/x` and `origin:rr/deep/y` leaves the ref file
  `refs/remotes/origin/rr` alone in their place;
- any directory under `refs/mirrors`, which `-c --create=<id>:<name>` reaches the
  same way.

The port refuses all four and writes nothing. A directory named as the target of
`refs -A --create` reaches the same existence check, so the tool reports the
target as a name no ref holds and the port reports its `Is a directory` line
(`conformance/cli-surface.md`, "P1"). The `PREFIX` form of the path rule is under
"CLI output formats", "refs".

An empty revision is the zero-length case of the abbreviated-checksum scan
below: every commit object carries the empty prefix. The tool resolves it to
the repository's one commit where exactly one commit exists, reports
`error: Refspec  not unique` where more than one does, and falls through to the
ref store in a repository holding no commit, where the empty name fails the
refspec rule and reports `error: Invalid refspec `. The count is of commits and
not of refs, recovered by resolving the empty revision in a repository holding
three refs and one commit, which resolves, and in one holding one ref and two
commits, which reports the not-unique line. The port refuses the empty name in
every repository (`conformance/cli-surface.md`, "P1 -- reading and resolution").

Revision syntax. A revision names a commit four ways: a 64-character lowercase
hex checksum, an abbreviated checksum, a refspec, or any of those followed by
one or more `^` characters, each stepping one generation back along the
commit's `parent` field. `~N` and `^N` are not revision syntax: `ostree
rev-parse test/main~1` and `test/main^2` each report `error: Invalid refspec
<rev>`. The port's ref rule accepts both names, so it reads the whole revision
as a refspec and reports `error: Refspec '<rev>' not found`, the message the
two implementations share for a name that resolves to nothing, wherever a
revision is taken: `rev-parse`, `cat`, and the positional of `refs --create`. A
checksum carrying either suffix takes that same path, the name holding more
than 64 characters. Both implementations exit 1 and write nothing, and the
wording follows from the ref-name character class the port does not validate
(`conformance/cli-surface.md`, "P1"). Walking past a root commit reports
`error: Commit <checksum> has no parent` and exits 1.

An abbreviated checksum is a run of one to 63 lowercase hex characters, and it
names the one commit object whose checksum starts with it. Both implementations
resolve one, under one rule:

- the match set holds commit objects alone. A prefix carried by a dirtree, a
  dirmeta, or a file object and by no commit matches nothing and takes the
  refspec path, and such an object sharing a prefix with a commit leaves that
  commit's prefix resolvable (recovered by resolving the prefixes of every loose
  object in a two-commit `archive` repository, and again over the `file` objects
  of a `bare-user` one);
- exactly one commit matching resolves to it, at any length from one character up
  to 63;
- the tool takes the zero-length prefix through the same scan, so an empty
  revision resolves where the repository holds one commit. The port's rule
  starts at one character and refuses the empty name in every repository, the
  divergence the paragraph above records;
- more than one commit matching reports `error: Refspec <prefix> not unique` at
  exit 1, the prefix unquoted, and resolves to nothing thereafter -- the failure
  stands wherever the revision was taken, `commit -b` included, and a following
  `^` reports it too, nothing having resolved to walk back from;
- the scan stands ahead of the ref store. A name the store carries as a ref
  resolves to the commit it prefixes rather than to that ref's own target, so a
  branch whose name prefixes a commit is unreachable by name as a revision, and
  the ambiguous case stops there as well rather than falling back to the ref;
- a prefix no commit carries falls through to the ref store, so a hex name is an
  ordinary ref name for as long as no commit begins with it. `refs
  --create=dddd <rev>` writes such a ref and `rev-parse dddd` reads it back;
- the case rule of a full checksum holds: one uppercase character makes the name
  a refspec, so `rev-parse <UPPER-PREFIX>` reports the not-found line;
- the existence check of `refs --create=NEWREF` resolves NEWREF, so a NEWREF
  prefixing a commit reports `error: --create specified but ref <NEWREF> already
  exists`, the line a 64-character NEWREF draws below;
- `refs -A --create` takes a ref name and not a revision, so a prefix there
  reports `error: Cannot create alias to non-existent ref: <prefix>`, and a
  `PREFIX` argument is matched rather than resolved.

The branch-name guard below does not reach this shape: both implementations write
a branch whose name prefixes a commit, leaving a ref no revision reaches, where
they refuse a name of 64 lowercase hex characters outright. What a hex name
shadows depends on the commits the store holds at the time, so the guard would
refuse a name that is free today and shadowed after the next commit.

The consequence at `commit -b BRANCH` is the parenting rule below: the implicit
parent is what BRANCH resolves to as a revision, so a BRANCH naming no ref and
prefixing a commit parents the new commit on that commit, and a further commit on
that branch parents on it again rather than on the tip the ref file holds.

The case of those 64 characters is part of the rule: a name is a checksum in
lowercase hex alone, and one uppercase character makes it a ref name. Both
implementations therefore report `error: Refspec '<rev>' not found` for
`rev-parse <UPPER>`, `cat <UPPER> PATH`, `checkout <UPPER> DEST`, and
`rev-parse <UPPER>^`, where the same 64 characters in lowercase resolve, and a
name holding one raised character reads as the uppercase one does. The split runs
wherever a 64-character name is taken:

- the positional revision of `refs --create` reports the not-found line, so
  `refs --create=fresh <UPPER>` writes nothing;
- the existence check of `refs --create=NEWREF` resolves NEWREF, so a NEWREF of
  64 lowercase hex characters is a checksum and reports `error: --create
  specified but ref <NEWREF> already exists` whether or not the store holds that
  commit, and an uppercase NEWREF is a free ref name whose write lands at
  `refs/heads/<NEWREF>`. A revision of that name then resolves through the ref
  file, `refs -A --create` records an alias to it, and `refs --delete` guards it
  under the name the alias body carries;
- `refs -A --create` holds a lowercase name to name no ref, reporting `error:
  Cannot create alias to non-existent ref: <rev>`;
- a `PREFIX` is matched and not resolved, so neither case matches a ref there;
- `commit -b` refuses a branch name of 64 lowercase hex characters with `error:
  Rev name '<name>' looks like a checksum`, naming the branch as given. The rule
  guards the one name this case rule shadows: a ref of that shape is read as a
  checksum wherever a revision is taken, so no revision reaches the commit
  behind it. Every other name of that length is written -- one character short
  or long, one outside the hex class, an uppercase rendering, and one holding a
  single raised character. The refusal runs at the ref write, so a fault ahead of
  it is reported instead: an unresolvable `--parent` and a tree path that does
  not open each end the invocation first, in each implementation's own words
  (`conformance/cli-surface.md`, "P2"). `--orphan` leaves the refusal standing in
  both implementations, since `-b` writes the ref under it too.

The revision syntax shadows two branch-name shapes, and `commit -b` guards both.
Beside the checksum shape above stands a name ending in `^`, which resolution
reads as ancestry, so no revision reaches the commit a ref of that name holds.
The port refuses it with `error: Invalid refspec <name>`, the message it gives
that same shape at `refs --create`, at the step the checksum guard runs at: the
ref write, after `--parent` resolves and after the tree is read. The tool refuses
it a step earlier, reading the branch name as a revision before it commits the
tree, and reports what that walk found. Three outcomes follow from the base the
suffix names:

- a base resolving to a commit that has a parent: `error: Invalid refspec
  <name>`, exit 1, which is the port's own line;
- a base resolving to a root commit: `error: Commit <checksum> has no parent`,
  exit 1;
- a base naming no ref: the tool dies on a signal
  (`conformance/cli-surface.md`, "P2").

An empty base is the zero-length case of the abbreviated-checksum scan, and the
count that decides it is of commits. Against a repository holding no commit the
empty name reaches the ref store, fails the refspec rule, and `-b '^'` reports
`error: Invalid refspec `, naming the empty base. Against one holding a single
commit the base resolves to that commit, a root commit, so the trailing `^`
walks past it and `-b '^'` reports the walk's own line. Since the tool reads
the name before the tree, a tree path that does not open is reported by the
port and reached by the tool only after the name it already refused, and
neither implementation publishes an object for the refusal, where the checksum
guard leaves the tool's tree and commit objects in `objects/`.
A `^` inside the name is a separate rule: the tool refuses `a^b` as a ref name
whatever the store holds, and the port writes it, which is the ref-name
character class `conformance/cli-surface.md`, "P1" records.

A ref of either refused shape therefore arrives by an out-of-band write alone.
Where a checksum-shaped one stands, the tool's listings enumerate it, its `fsck`
validates it, and its `prune --refs-only` reads the commit that ref holds as
reachable and keeps it, while its `pull-local` over that source reads the ref
name as a checksum and reports `error: Importing <name>.commit: linkat: No such
file or directory`, where the port copies the ref. Where an ancestry-shaped one
stands, the tool's ref enumeration skips it without a word, so `refs` prints
nothing and `prune --refs-only` reads the commit as unreachable and deletes it,
leaving the ref file over an absent object; the port enumerates the name. That
is the same destructive class the ref-name character class carries
(`conformance/cli-surface.md`, "P1").

Ref file content is read by a parser that takes either case. Both
implementations write the 64 lowercase hex characters, and the tool refuses a
file holding any other rendering with `error: Invalid character '<byte>' in rev
'<content>'`, naming the first character it refuses by byte value, where the
port's reader resolves it (`conformance/cli-surface.md`, "P1"). Only an
out-of-band write puts such content in a ref file. The tool's `commit --parent`
reads its value with that same parser, so `--parent=<UPPER>` reports that line
where the port reads the value as a revision and reports the ref as missing
(`conformance/cli-surface.md`, "P2").

A revision resolves whether or not the commit it names is in the store, so an
absent commit is reported where the commit is read. The tool names the loose
object file it looked for, `error: No such metadata object <checksum>.commit`,
and the port names the object type the library looked up, `error: object not
found: Commit <checksum>`; both exit 1 and write nothing
(`conformance/cli-surface.md`, "P1"). The sites that read the commit are `cat`,
`checkout`, and `export`, and a revision carrying a `^` suffix, whose walk loads
the base commit. The sites that take a checksum without reading it accept an
absent one at exit 0: `rev-parse <checksum>` prints it, the positional revision
of `refs --create` writes a ref file holding it, and `commit
--parent=<checksum>` writes a commit naming it. A ref pointing at an absent
commit therefore arrives through either CLI, and reading a revision through that
ref reports the same two messages the checksum reports.

Writing a ref whose file is an alias symlink replaces the symlink with a regular
ref file; the alias target is left unchanged. Observed with the tool by
committing onto an alias and by `ostree refs --create --force`: in both cases
`refs/heads/foo` (a relative symlink to sibling `bar`) became a 65-byte regular
file holding the new checksum, and `refs/heads/bar` kept its old checksum. The
tool writes the ref by renaming a fresh temp file over the target name, and the
rename replaces the symlink at that name instead of following it.

Ref durability (traced). The tool's ref write issues `fdatasync` of the temp
file, then `renameat` over the ref name, and no directory sync anywhere: not of
the ref's own parent, of `refs/heads`, or of the repository root. This is the
same sequence for `refs --create` and for a commit's ref write, and
`fsync=false` drops the `fdatasync`, leaving the rename alone. An alias write
(`refs -A --create`) issues `symlinkat` into `<repo>/tmp` and `renameat` over
the ref name, with no sync at all, and `refs --delete` issues `unlinkat` alone.
The port `fdatasync`-es the ref file the same way and adds an `fsync` of the
directory holding the ref after the rename, after an alias rename, and after a
removal, so the name the operation created or removed survives a crash and not
only the file's content.

A ref name carrying `/` needs one more rule, because the write creates the
directories the name passes through. A `mkdirat` records a name in the directory
it is called in, so the directory made durable for a created
`refs/heads/deep/nest` is `refs/heads/deep`, the one that holds the `nest` entry.
The port therefore `fsync`-es the directory holding each parent directory the
write created, after the `fsync` of the directory holding the ref, deepest
first. The order is child before parent, the order the object fanout uses: a
crash part way through leaves a prefix of the path recorded and never a
directory entry naming a directory whose own contents are unrecorded. A
directory the write found already in place is not synced, since its name is
already durable. A single-component name creates no directory and issues this
`fsync` not at all, so the count of directory syncs a ref write makes is one
plus the number of directories it created.

`fsync=false` turns all of that into a no-op. The syscall sequence carries no
byte-exact requirement, and the ref bytes are identical either way.

Repository lock and staging (recovered by tracing the tool). The tool opens
`<repo>/.lock` `O_RDWR|O_CREAT` mode `0660` and takes an `fcntl` OFD lock on it,
shared (`F_RDLCK`) for the duration of a commit and exclusive (`F_WRLCK`) for
destructive maintenance, releasing it (`F_UNLCK`) at the end. A transaction
stages objects in `tmp/staging-<bootid>-XXXXXX` (mode `0775`), where `<bootid>`
is `/proc/sys/kernel/random/boot_id` verbatim, dashes kept, and `XXXXXX` is a
six-character `mkdtemp` suffix. A sibling file `tmp/staging-<bootid>-XXXXXX-lock`
(mode `0600`) is held with an exclusive OFD lock while the staging directory is
in use, so a later transaction can tell a live staging directory from one left
by a dead transaction. These locks are advisory and cross-process; the checksums
and object bytes do not depend on them. The port removes its staging directory
and the lock sibling on every path out of a transaction, the refusals included,
so a run that exits non-zero leaves `tmp/` holding no `staging-` entry
(`conformance/cli-surface.md`, "P2"). A transaction that commits, aborts, or
drops removes the pair itself; a process that ends without unwinding removes the
pair of every transaction it still holds immediately ahead of the exit.

Commit-state markers live at `state/<checksum>.commitpartial`. The reader only
tests the marker's presence, which makes a commit `Partial`. When `fsck` finds a
commit missing a referenced object it writes the marker as a single byte `0x66`
(recovered by observation: feeding the tool a repository with a deleted
referenced object and inspecting the marker it writes shows a 1-byte file
holding `0x66`). A pull writes the marker zero-length instead, and removes it
once the commit's objects are published (observed by running the tool's
`pull-local --commit-metadata-only`, which leaves a 0-byte marker, and then
completing the pull, which removes it; a pull that fails part way leaves the
marker behind). A marker already present is not rewritten: a pull over a commit
`fsck` marked keeps the one-byte state (observed by running `fsck` on a
repository with a deleted referenced object, then `pull-local` from a source
missing that same object, after which the marker still holds `0x66`). The marker
is local state and does not enter any checksum.

No writer syncs a marker or the `state/` directory. A pull creates every marker
before its transaction stages an object, so the `syncfs` that opens publication
makes the marker durable ahead of the first object rename; the removal is the
pull's last operation and no barrier follows it, so a crash immediately after a
successful pull can restore the marker of a commit that is complete. An `fsck`
marker is written with no barrier at all, and re-running `fsck` writes it again.
Recovered by tracing the tool's syscalls: `pull-local` issues
`openat(state/<checksum>.commitpartial, O_WRONLY|O_CREAT|O_EXCL, 0644)`,
`syncfs` of the repository, the object renames into `objects/`, an `fsync` of
each touched fanout and of `objects/`, the ref write, then `unlinkat` of the
marker as its last syscall, with no `fsync` of the marker or of `state/`
anywhere; `ostree fsck` writing a marker issues no `fsync`, `fdatasync`, or
`syncfs` in the entire run.

A leftover directory under `tmp/` whose lock can be taken, or that has no lock
sibling, is removed once its age exceeds `tmp-expiry-secs`. The age test is
strict on whole seconds: feeding the tool aged and freshly created `tmp/`
entries shows that at `tmp-expiry-secs=0` an entry created in the current second
survives and only entries at least one second old are removed, and at
`tmp-expiry-secs=5` an entry aged three seconds survives while one aged eight
seconds is removed.

Static delta directories use base64-checksum fanout. From-scratch:
`deltas/<to_b64[0:2]>/<to_b64[2:]>/<target>`. From->to:
`deltas/<from_b64[0:2]>/<from_b64[2:]>-<to_b64>/<target>`. Targets are
`superblock` and one numeric part file per part, `0`, `1`, ..., and nothing else:
the listing holds exactly those names for a from-scratch delta, a from->to
delta, a four-part delta (`--max-chunk-size=0.1`), and a delta whose largest
object went to a fallback (`--min-fallback-size=1`). Fallback objects are
fetched loose from the repository and add no file here. Indexes live at
`delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index`.

An index file is an `a{sv}` holding one entry, `ostree.static-deltas`, whose
variant is the `a{sv}` map the summary carries under the same key: delta name
(`TO` or `FROM-TO`, in hex) to a 32-byte `ay`, the SHA-256 of that delta's
`superblock` file. One index file per target commit lists every delta producing
it. Recovered by running `ostree static-delta reindex` on a repository with two
deltas and decoding the files it wrote; the digests match `sha256sum` over the
superblocks. `static-delta generate` does not write or refresh an index --
`reindex` does, and `ostree static-delta indexes` lists the indexed targets, one
commit hex per line.

`reindex` rebuilds the cache from the deltas present: after one of two delta
directories is deleted, the pass removes that target's `.index` file and
`static-delta indexes` lists only the remaining target. The fanout directory the
removal empties stays in place.

### HTTP pull surface

A repository published over HTTP is served as the directory tree above. What a
pull requests, and in what order, was recovered by running `ostree` 2026.1
against a static HTTP server over a tool-built archive repository and reading the
server's request log.

One pull of one ref, with a summary present on the remote:

```
summary.sig
summary
config
delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index
objects/<commit>.commitmeta
objects/<commit>.commit
objects/<...>.dirtree, .dirmeta, .filez, .filez, .dirtree, .filez
```

- `summary.sig` is requested before `summary`, and both before `config`.
- With no summary on the remote, `summary` answers 404 and `refs/heads/<ref>` is
  fetched in its place. The delta probe becomes `deltas/<b64>/superblock` rather
  than the index, so a summary advertising `indexed-deltas` is what selects the
  index path.

A delta-accelerated pull, recovered the same way -- one static file server, one
request log -- against a client holding the ref's previous commit:

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

- The delta name is `<from>-<to>` when the client holds a commit for the ref being
  pulled, and `<to>` when it holds none. Exactly one name is tried: a client
  holding the ref's commit against a remote advertising only the from-scratch
  delta fetches every object loose, and so does a fresh client against a remote
  advertising only the from-to delta.
- The index is requested whenever a summary is present. Where it answers 404 the
  pull reads the summary's own `ostree.static-deltas` map instead and fetches the
  superblock the map names. Where neither names the delta, no superblock is
  requested.
- No `objects/<commit>.commit` request follows a delta: the target commit rides in
  the superblock. The `.commitmeta` is still fetched, after the parts rather than
  before the commit.
- The objects a delta hands over as fallbacks are fetched loose as
  `objects/<..>.filez`, queued as soon as the superblock is read. No dirtree,
  dirmeta, or content object of the delta's own contents is requested, so the tool
  does not walk the target commit's tree after applying a delta.
- A superblock whose bytes do not hash to the digest the summary advertised fails
  the pull: `error: Invalid checksum for static delta <name>`, with no part
  requested. A superblock the remote does not hold answers 404 and the pull
  continues with loose objects, with no error.
- `--require-static-deltas` fails only where the remote advertises no delta at
  all: `error: Fetch configured to require static deltas, but no summary deltas or
  delta index found`, which is what a remote serving no summary produces, and no
  delta probe is made in that case. A remote that advertises deltas satisfies it
  even where none of them produces the commit being pulled.
- The destination has to be non-archive: an archive client refuses with `error:
  Can't use static deltas in an archive repo` before any request is made.
- A content object is always requested as `objects/<..>.filez`, whatever mode the
  remote actually stores. Metadata keeps `.commit`, `.dirtree`, and `.dirmeta`.
  Detached metadata is `.commitmeta`, requested before the commit object it
  belongs to, with a 404 treated as the commit carrying none.
- `config` is requested after a summary arrives, and its `[core] mode` decides
  whether the pull proceeds: a `bare-user` remote produces `error: Can't pull
  from archives with mode "bare-user"`. The same remote with no summary, where no
  config is fetched, instead fails on a 404 for an `objects/<...>.filez` request.
- An empty ref list resolves differently per mode. A plain pull uses the remote's
  `branches` config key and fails with `error: No configured branches for remote
  origin` when it is absent. A mirror pull takes every ref the summary lists and
  fails with `error: Fetching all refs was requested in mirror mode, but remote
  repository does not have a summary`.
- `--mirror` writes `refs/heads/<ref>`; a plain pull writes
  `refs/remotes/<remote>/<ref>`.
- A mirror pull that fetched every ref copies the remote summary bytes verbatim
  to `<repo>/summary`, confirmed byte-identical with `cmp`, and copies the remote
  `summary.sig` bytes to `<repo>/summary.sig` the same way. Where the remote
  holds no `summary.sig`, the pull writes `<repo>/summary` alone and leaves a
  `<repo>/summary.sig` an earlier pull wrote as it stands. A mirror pull of named
  refs writes neither file, and a plain pull writes neither.
- A repeat pull of an unchanged ref re-fetches `summary.sig`, `summary`,
  `config`, the delta index, and `.commitmeta`, then stops.
- `-T` fails only on a strictly older timestamp; an equal timestamp passes.
  `--timestamp-check-from-rev=REV` compares against REV and implies the check.
  The message names both revisions and both timestamps.
- HTTP pulls always verify checksums. The tool's `--untrusted` help reads "Verify
  checksums of local sources (always enabled for HTTP pulls)".

### Signature verification during a pull

Recovered by running `ostree` 2026.1 against a static HTTP server over a
tool-built archive repository, with the destination's remote section written by
`ostree remote add` and by `ostree config set`. Every refusal below leaves the
destination with no ref and no object.

What each configuration key selects:

- `gpg-verify`, default true. Every commit the pull carries has to have a GPG
  signature from the remote's trusted keyrings. A commit with none:
  `error: Commit <hex>: GPG verification enabled, but no signatures found (use
  gpg-verify=false in remote config to disable)`. A commit signed by a key the
  keyrings do not hold: `error: Commit <hex>: Signature made <date> using EdDSA
  key ID <keyid>` followed by `Can't check signature: public key not found`.
- `gpg-verify-summary`, default false. `summary.sig` has to hold a valid GPG
  signature over the summary bytes. A remote serving no summary: `error: GPG
  verification enabled, but no summary found`. One serving a summary and no
  `summary.sig`, or a `summary.sig` holding no GPG signature: `error: GPG
  verification enabled, but no signatures found`.
- `sign-verify`, default off. Either a boolean or a list of engine names split
  on `,` and `;`. `ostree remote add --sign-verify=ed25519=inline:<key>` writes
  `verification-ed25519-key=<key>` and `sign-verify=ed25519`; the `file:` form
  writes `verification-ed25519-file=<path>`; `--no-sign-verify` writes
  `sign-verify=false`; the same engine given twice writes it twice
  (`sign-verify=ed25519,ed25519`), which is accepted. A name is not trimmed:
  `sign-verify=ed25519, ed25519` fails with `error: Requested signature type is
  not implemented`, as does any name no engine answers to. A commit with no
  signature under the named engines: `error: Can't verify commit: No signatures
  found`. One signed by an untrusted key: `error: Can't verify commit: ed25519:
  Signature couldn't be verified with: key '<hex of the trusted key>'`.
- `sign-verify-summary`, default off, and read on its own: `sign-verify=false`
  alongside it still verifies the summary. A `summary.sig` the trusted keys do
  not verify fails with the engine message above and no `Can't verify commit`
  prefix. No `summary.sig` at all: `error: Signatures verification enabled, but
  no summary.sig found (use sign-verify-summary=false in remote config to
  disable)`, which is also what a remote serving no summary produces.
- `verification-<engine>-key` holds one key. A list under either separator fails
  with `error: Failed loading 'ed25519' keys from inline verification-key`.
  `verification-<engine>-file` holds one key per line and accepts the commit any
  line's key signed.
- `gpgkeypath` is a `;`-separated list of keyring files and directories, added
  to the trusted set rather than replacing it: a remote with an imported
  `<remote>.trustedkeys.gpg` and a `gpgkeypath` naming an empty directory still
  accepts the imported key's commit. An entry that does not exist fails the pull
  with `error: Commit <hex>: opendir(<entry>): No such file or directory`.

Behavior common to the axes:

- The axes are independent and both apply: a remote with `gpg-verify` left at its
  default and `sign-verify=ed25519` configured with the right key still fails on
  GPG. Within `sign-verify` one engine is enough: `sign-verify=ed25519;dummy`
  with a key for each accepts a commit signed by ed25519 alone.
- An engine named by hand with no key fails with `error: No keys found for
  required signapi type <engine>`, while `sign-verify=true` with no key for any
  engine fails with `error: Can't verify commit: signature: ed25519: no keys
  loaded`.
- `verification-<engine>-key` alone verifies nothing: the check runs only where
  `sign-verify` or `sign-verify-summary` asks for it.
- Every commit the pull carries is checked, the parents `--depth` follows
  included, and a commit the destination already holds is checked again on a
  repeat pull.
- `pull-local` makes no check unless asked: it has `--gpg-verify` and
  `--gpg-verify-summary` flags, each needing `--remote` (`error: Must specify
  remote name to enable gpg verification`), and the named remote's own
  `gpg-verify=true` does not turn a check on by itself. The summary check reads
  the source repository's `summary` and `summary.sig`.
- A static delta carries a copy of the target commit's detached metadata in its
  superblock metadata dict, under the key `deltas/<fanout>/<rest>/commitmeta`
  holding the same `a{sv}` the `.commitmeta` file holds. A delta pull checks the
  commit against that copy while storing the `.commitmeta` it fetched: a delta
  generated while the commit carried an older signature fails the pull under a
  policy the current `.commitmeta` satisfies.
- `ostree` 2026.1 cannot pull a signed delta. A from-scratch and a from-to delta
  signed with `static-delta generate --sign` both fail the pull with `error:
  Invalid checksum of length 0 expected 32`, with verification configured or off,
  while `static-delta apply-offline` applies the same delta and
  `static-delta show` reports `Signed: yes`.

### Config file (`<repo>/config`, GKeyFile / INI)

Created with `[core]` `repo_version=1`, `mode=<mode>`, optional
`collection-id`. Selected `[core]` keys: `repo_version` (must be 1), `mode`,
`min-free-space-percent` (default 3) / `min-free-space-size` (regex
`^([0-9]+)(G|M|T)B$`, size wins over percent), `fsync` (default true),
`per-object-fsync` (default false), `locking` (default true),
`lock-timeout-secs` (default 300), `tmp-expiry-secs` (default 86400),
`disable-xattrs`, `collection-id`, `parent`, `default-repo-finders` (default
`config;mount`). `[archive] zlib-level` (1-9, default 6). Remote sections are
`[remote "<name>"]` with keys `url`, `contenturl`, `metalink`, `gpg-verify`
(default true), `gpg-verify-summary` (default false), `gpgkeypath`, TLS keys,
`collection-id`, `sign-verify`, `sign-verify-summary` (both default off),
`verification-<engine>-key` / `verification-<engine>-file`. What the
verification keys select, and how each value is spelled, is in "Signature
verification during a pull".

Parsing rules, recovered by feeding crafted config files to the tool, reading
back with `ostree config get` and commands that consume config, and inspecting
the bytes `ostree config set` writes:

- Lines split on newlines; a trailing carriage return is stripped, so CRLF
  input is accepted.
- Whitespace handling uses ASCII space and tab only. A leading space or tab on
  a line is ignored before the line is classified, a line of only spaces or
  tabs is treated as blank, and a space or tab around a key is trimmed. A
  non-breaking space (U+00A0) or other non-ASCII whitespace is kept: it is
  never trimmed, and a line whose only content is such a character is a parse
  error that fails the whole file.
- A line whose first non-blank character is `#` is a comment. `;` does not
  start a comment; a line that begins with `;` and is not a `key=value` pair
  is a parse error.
- A blank line is ignored.
- A group header starts with `[`; a leading space or tab before `[` is
  allowed. The name runs from `[` to the first `]`, and only whitespace may
  follow that `]`; text after it (as in `[a]b]`) fails the whole file. The
  name may not be empty (`[]` fails the whole file) and may not contain `[`
  (as in `[a[b]`, reported as an invalid group name). A repeated header merges
  into the existing group.
- A `key=value` entry splits on the first `=`. The key is trimmed of
  surrounding space and tab. In the value, leading space and tab are removed
  and trailing whitespace is kept. A `#` inside a value is literal; there are
  no inline comments. A repeated key takes the last value.
- A boolean is one of `true`, `false`, `1`, `0`. Any other spelling (`yes`,
  `no`, `on`, `off`, mixed case such as `True`, an out-of-range number such as
  `2`, or the empty string) is rejected with a "value that cannot be
  interpreted" error. A run of trailing space, tab, or form feed is ignored
  before the match, so `fsync=true ` reads as `true` while `ostree config get
  core.fsync` still prints the trailing byte. A trailing vertical tab is not
  ignored and fails the match. The port matches the four
  literals against the value as written and refuses a value carrying any
  trailing byte (`conformance/cli-surface.md`, "Global conventions").
- An integer takes the leading run of decimal digits with an optional `-` sign
  and ignores whatever follows: `101x`, `101 x`, and `101.9` all read as `101`,
  measured through `min-free-space-percent`, whose out-of-range refusal quotes
  the value as written. A value with no leading digit (`bogus`, `x101`,
  `+101`, the empty string) reads as no value at all and the key's default
  applies, silently: `lock-timeout-secs=bogus` and `tmp-expiry-secs=bogus` both
  open. The port reads an integer key as a whole decimal value and refuses
  anything else (`conformance/cli-surface.md`, "Global conventions").
- `min-free-space-size` is read from the value as written, with no trailing
  trim: `min-free-space-size=1MB ` is refused with `error: opening repo:
  Invalid min-free-space-size '1MB '`. The port refuses it too.
- Writing a string value escapes a backslash as `\\`, a newline as `\n`, and a
  carriage return as `\r` anywhere in the value; within the leading whitespace
  run each space becomes `\s` and each tab `\t`. A space or tab elsewhere, a
  trailing space or tab, and a `;` are written literally. Groups are written as
  `[name]` followed by `key=value` lines, a blank line between groups, and no
  spaces around `=`. A freshly initialized archive repo config is exactly
  `[core]\nrepo_version=1\nmode=archive-z2\n`.

## Write path: loose-object inode modes and durability

The bytes an object hashes to are mode-independent, but the permission bits and
ownership the tool puts on the loose object's inode, and the syscall sequence it
uses to publish objects durably, are recovered by black-box observation:
committing files of assorted modes and a symlink with the tool and inspecting
the resulting objects, and tracing the commit's syscalls.

Loose-object inode permission bits, by object class and repository mode:

- Metadata objects (`.dirtree`, `.dirmeta`, `.commit`, and by construction the
  other metadata types) carry mode 0644 in every repository mode.
- `archive`: every content object (`.filez`) is 0644.
- `bare`: a content object's inode carries the full logical uid, gid, mode, and
  xattrs; a symlink is a real symlink owned by the logical uid/gid. The xattrs
  are written before the chown and the mode: the kernel checks a `user.*` xattr
  against the inode's write permission, which a logical mode with no owner-write
  bit (0444, 0555) does not grant, and a chown to another uid takes the ability
  away as well.
- `bare-user`: a regular-file content object's inode mode is
  `(logical_perm & 0o775) | 0o400` -- owner bits and the group/other read and
  execute bits are kept, owner-read is forced on, and other-write is dropped
  (`0666` stores as `0664`, `0777` as `0775`). A symlink is stored as a regular
  file whose inode is 0644. The inode is owned by the writing process; the
  logical uid/gid live in `user.ostreemeta`. A logical mode with no owner-write
  bit (0444, 0555) leaves that inode without write permission, and the kernel
  checks a `user.*` xattr against it, so `user.ostreemeta` is written before the
  mode is applied.
- `bare-user-shared`: every content object's inode is a fixed 0644.
- `bare-user-only`: a regular-file content object's inode mode is the canonical
  `logical_perm & 0o755` -- group-write and other-write are dropped and no
  special bits are kept (`0664` stores as `0644`, `0666` as `0644`, `0775` as
  `0755`). uid/gid are discarded and no xattrs are stored. A symlink is a real
  symlink, and its mode stays `S_IFLNK | 0o777`.

  This mode stores no header, so a write into it records the header it can
  store -- uid 0, gid 0, no xattrs, and a non-symlink's permission bits reduced as
  above -- and an object's identity covers that recorded header rather than the one
  the writer supplied. A directory's metadata is recorded the same way, so a
  commit's dirmeta and dirtree checksums follow from the reduced form too. An
  entry already in that form keeps the identity it has in the other modes; any
  other entry takes a different one.

  Observed: a tree holding a 0777 file carrying a `user.demo` xattr, a 04755
  file, a 0640 file, and a 0777 subdirectory, committed by a non-root user with
  no ownership options, produces in `bare-user-only` exactly the content,
  dirmeta, and dirtree checksums the same tree produces in `bare-user` when its
  modes are already canonical and it is committed 0:0 -- the 0777 file lands as
  0755 under the 0755 file's checksum, and the xattr-bearing file lands under the
  checksum of the same file without the xattr. Committing that tree with and
  without `--owner-uid`/`--owner-gid` gives identical checksums, which is the
  discarded ownership.

Symlink storage detail (confirmed for `bare-user`): a symlink is a regular file
whose content is the target bytes followed by one NUL; its `user.ostreemeta` is
the `(uuua(ayay))` stat form with the symlink's uid/gid, mode `S_IFLNK | 0o777`
(`0o120777`), and xattr set; the inode is 0644.

Archive `.filez` layout (extends "File content object header"):

- A regular file is the framed archive header `(tuuuusa(ayay))` followed by the
  raw-DEFLATE payload. An empty payload compresses to the two-byte empty DEFLATE
  stream `03 00`.
- A symlink is the framed archive header alone (target in field 5, uncompressed
  size 0); no payload bytes follow, not even the empty-DEFLATE stream.
- The raw-DEFLATE bytes the port emits (via miniz_oxide) match the tool's zlib
  output byte-for-byte for the small fixture payloads at every level 1-9. Over a
  real tree most payloads reach two encodings of two lengths (`conformance/
  cli-surface.md`, "P2"). The object identity is over the uncompressed bytes, so
  byte-identity of the stored compressed payload is not required for
  interoperability.

Object store fanout directories `objects/<xx>/` are created with request mode
0777 (reduced by the umask); `objects/` itself is 0775. This is the same in
every mode. Group sharing of a `bare-user-shared` repository is arranged at the
filesystem level (see the bare-user-shared section): with the repository
directory setgid and carrying a default group ACL, the OS propagates the group,
the setgid bit, and the group-write permission to each fanout directory as it is
created.

Durability and staging (traced): the tool ingests each object into an unnamed
temp file (`O_TMPFILE` in the staging directory) and materializes it with
`linkat("/proc/self/fd/N", ..., AT_SYMLINK_FOLLOW)`.

- Default (`fsync=true`, `per-object-fsync=false`): objects are linked into the
  staging directory under their loose path, then `syncfs(repo)` runs once, then
  each object is `renameat`-ed into `objects/<xx>/`, then each touched
  `objects/<xx>` and `objects/` is `fsync`-ed.
- `per-object-fsync=true`: each object's temp file is `fsync`-ed at ingest; the
  `syncfs(repo)` and directory `fsync`s still run at publication.
- `fsync=false`: no `syncfs`, `fsync`, or `fdatasync` is issued.

The port always stages then renames (the default path) and honors the two
settings for the syncs it issues: `fsync=false` makes every sync a no-op,
`per-object-fsync=true` `fsync`s each object at ingest, and otherwise a single
`syncfs` precedes the renames with directory `fsync`s after. The staging
directory layout is transient and is not part of the on-disk format.

## Write path: fs-verity (ex-integrity)

A repository can seal its loose objects with fs-verity as they are written. The
behavior was recovered by tracing `ostree` 2026.1 (built with `ex-fsverity`) on
a btrfs repository, probing objects on a verity-capable and a non-capable
filesystem, and cross-checking the kernel's measured digest against the port's
`FsVerityHasher`. fs-verity enablement seals an inode against modification and
gives the kernel a digest it can enforce on reads; the object bytes and their
checksums are unchanged, so a verity repository is byte-for-byte a normal
repository whose regular-file objects happen to be sealed.

Config. The `[ex-integrity]` group carries two tri-state keys, each spelled
`no`, `maybe`, or `yes`:

- `fsverity` -- whether loose objects are sealed. Defaults to `no`.
- `composefs` -- governs deployment behavior elsewhere; here it is read only for
  its effect on the `fsverity` default. `composefs` set to `yes` or `maybe`
  raises the `fsverity` default to `maybe`.

An explicit `fsverity` value overrides the composefs-derived default. A value
that is not `no`/`maybe`/`yes` is a malformed-config error.

Scope. Verity is enabled on every loose object stored as a regular file, in
every repository mode including archive-z2:

- content objects: `.file` (bare family) and `.filez` (archive),
- metadata objects: `.dirtree`, `.dirmeta`, and `.commit`,
- symlink objects stored as regular files: bare-user, bare-user-shared, and
  archive keep a symlink's content in a regular file, so those objects are
  sealed.

Only real symlink objects are skipped, because fs-verity applies to regular
files. Real symlink objects occur in `bare` and `bare-user-only`. A deduplicated
write (the object already present in `objects/`) is left untouched.

The scope above is what the tool's write path does. Its local-import path leaves
sealing out: `ostree pull-local` into a repository carrying `fsverity=yes`
hardlinks the source's objects and seals none of them, while a commit written into
that same repository is sealed (observed on btrfs with `ostree` 2026.1 built with
`ex-fsverity`). fs-verity is a per-inode property, so a hardlinked object cannot
be sealed without sealing the source repository's copy. The port applies the scope
to every write including an import, which means it copies where the tool links;
see `port-plan.md`, Phase 16b.

Semantics.

- `no`: nothing is sealed; the staging path is unchanged.
- `maybe`: best effort. Every `FS_IOC_ENABLE_VERITY` failure is swallowed, so a
  filesystem without verity (which returns `ENOTTY`) commits normally with
  objects left unsealed.
- `yes`: required. An enable failure fails the write, matching the tool, which
  reports that fsverity is required but the filesystem does not support it.

Digest parameters. SHA-256, 4096-byte blocks, and a zero-length salt. The
enable argument is `fsverity_enable_arg { version 1, hash_algorithm 1 (SHA-256),
block_size 4096, salt_size 0 }`, a 128-byte struct with the remaining fields
zero. The kernel's `FS_IOC_MEASURE_VERITY` result for a sealed object equals the
`FsVerityHasher` digest of that object's on-disk bytes, which is the same value
the composefs export records per backing file. For a bare-user or
bare-user-shared `.file`, whose on-disk bytes are the raw payload, that digest
is the fs-verity digest of the payload.

Write-path order, per object, while the inode is still an anonymous `O_TMPFILE`
staging file:

1. open `O_TMPFILE|O_WRONLY` in the staging directory,
2. write or reflink the payload,
3. apply `fchmod`/`fchown` and xattrs,
4. reopen the inode read-only through `/proc/self/fd/N`,
5. close the writable descriptor (the kernel refuses `FS_IOC_ENABLE_VERITY`
   while any writable descriptor to the inode is open),
6. `ioctl(ro_fd, FS_IOC_ENABLE_VERITY)`,
7. `linkat` the read-only descriptor into the staging directory.

A named temp file (used where the filesystem refuses `O_TMPFILE`, and for the
small caller-held bodies of symlink and metadata objects) follows the same
close-reopen-seal ordering and is then renamed into place rather than linked.
Publication into `objects/` is unchanged.

Closing the writable descriptor is not by itself enough to guarantee the enable
succeeds: `fork` copies the file descriptor table, so a child process carries a
copy of the writable staging descriptor until its `exec` closes it, and the
kernel refuses the enable with `ETXTBSY` while that copy lives. Any process that
spawns children from one thread while another stages objects meets this window.
The port retries an `ETXTBSY` enable for up to 50 ms, which outlasts a
fork-to-exec gap; every other error is reported on the first attempt.

The `FS_IOC_ENABLE_VERITY` and `FS_IOC_MEASURE_VERITY` ioctls are the only
syscalls in the write path that require `unsafe`; they live in the audited
`ostrya-sys` crate.

## Commit modifier: canonical permissions, consume, and devino

A filesystem tree is ingested into a repository under a set of options the
tool exposes on `ostree commit` and the port models as a commit modifier.
Two of these options change the object bytes and are recovered by black-box
observation; the rest are ingest mechanics with no on-disk effect.

Canonical permissions. The tool's `--canonical-permissions` option (the port's
`CANONICAL_PERMISSIONS`) forces owner 0:0, reduces each permission set to a
canonical form, and records no extended attributes. Recovered by committing files
and directories of assorted modes and xattr sets with and without the option into
an archive repository, reading the modes back with `ostree ls -R`, and comparing
object checksums:

- uid and gid become 0. The tool refuses a non-zero `--owner-uid`/`--owner-gid`
  together with `--canonical-permissions`, so canonical ingest always owns
  objects 0:0.
- A regular file's or directory's permission bits become `perm & 0o755`: the
  owner bits and the group and other read and execute bits are kept, the group
  and other write bits are dropped, and the setuid, setgid, and sticky bits are
  dropped. Observed regular-file mappings: `0664`, `0666`, `01644`, and `02644`
  all become `0644`; `0775`, `0777`, and `04755` become `0755`; `0640` stays
  `0640`; `0600`, `0644`, `0700`, and `0755` are unchanged. Directory mappings
  match: `0775`, `0777`, and `02755` become `0755`; `0700` stays `0700`.
- A symlink's mode is left as the reduction found it. The walk finds a symlink
  at `S_IFLNK | 0o777` and records that. Where a `--statoverride` entry over the
  same symlink ran first, the reduction keeps the mode the entry left, the bits
  it drops from a regular file included: `=448 /link` gives `l00700` and
  `2048 /link` gives `l04777`.
- The file-type bits the reduction records are the ones the walk found the entry
  with, so an entry whose mode names another type by the time the reduction runs
  goes back to being the kind it is. This is reachable through `--statoverride`,
  which is the one modifier that can state file-type bits: over a 0644 regular
  file, each of `=4096`, `=16384`, `=40960`, `=49152`, and `=32768` beside
  `--canonical-permissions` reaches the same commit, whose `/plain.txt` is
  `-00000`; over a 0700 directory each of them reaches one commit whose `/dir1`
  is `d00000`, and `=33261` reaches `d00755`.
- The recorded xattr set is empty. Observed on a 0644 file carrying
  `user.demo=1`: its checksum is `a5ee0b1b...` under
  `--owner-uid=0 --owner-gid=0` and `fe042781...` under
  `--canonical-permissions`, and `fe042781...` is the checksum the same file
  without the xattr takes under `--owner-uid=0 --owner-gid=0`. A directory's
  xattr goes the same way: the dirmeta is `6c9fefc6...` with the xattr kept and
  the canonical `446a0ef1...` under the option.

This is the ownership, permission, and xattr rule `bare-user-only` applies to
everything it records, with or without the option (see the loose-object
inode-mode notes above). Because the canonicalized header enters the
file-content header and the dirmeta, canonical ingest changes an object's
identity, and therefore the dirtree and commit checksums, whenever an input entry
is not already in that form (confirmed: the canonical commit checksum differs
from the same tree committed 0:0 without the option).

Consume. The tool's `--consume` option (the port's `CONSUME`) deletes the
source content after it is committed. Recovered by committing `--consume base/src`:
each file is removed as it is ingested and each directory is removed once its
entries are gone, bottom-up, including the walk-root directory itself; the
parent of the walk root is left in place. The tool adopts a source inode by
rename into the object store where the inode already satisfies the target
mode's on-disk form and the source shares a filesystem with the store, which
avoids a copy; adoption is a performance optimization with no on-disk effect,
so the port ingests by copy and then unlinks the source, producing byte-identical
objects.

Devino cache. The tool's `--link-checkout-speedup` builds a `(device, inode)` to
checksum map so a source entry that is a hardlink to one of the repository's own
objects is resolved by its inode without being read, and `--devino-canonical`
(`-I`, which implies the speedup) takes a resolved object as the entry's whole
identity. Recovered by committing a tree, checking it out in each variant each
repository mode accepts, recommitting the checkout three ways, and comparing the
commit checksums and the `ostree ls -R -X` listings:

- The cache is built from the repository `--repo` names, at commit time, by the
  process that runs the commit. A checkout made by an earlier process resolves
  through it, and no checkout in the same process is needed. The build reads
  every fanout directory under `objects/` and stats each `.file` entry it
  holds, so both options cost one pass over the repository's loose content
  objects before any source is read.
- It keys on `(st_dev, st_ino)`. A `cp -al` copy of a checkout resolves; a `cp
  -a` copy of the same tree, with the same modes and the same content, does not.
- It is scoped to that repository. A tree hardlinked into repository A's objects
  and committed into repository B resolves nothing.
- An `archive` repository stores every content object compressed, and no
  checkout hardlinks a `.filez`, so both options are no-ops there. The
  decompressed copies an archive checkout leaves in
  `<repo>/uncompressed-objects-cache` are outside `objects/` and are not part of
  the mapping. The port attaches no commit modifier for a cache that comes back
  empty, so `--link-checkout-speedup` alone leaves a `ref` source on the
  checksum-copy overlay path.
- A directory never resolves. A symlink resolves where the repository stores
  symlink objects as symlinks and the checkout hardlinked them, which is a
  `bare` repository: there `-I --owner-uid=7` leaves the symlink at its stored
  ownership and moves the directories to 7.
- A resolved entry is taken whole: content and metadata come from the stored
  object and what is on disk is not read. Rewriting a hardlinked file in place,
  or changing its mode, its size, or its mtime, changes nothing for either
  option.

The two options part on whether the commit modifiers reach a resolved entry.
Under `--link-checkout-speedup` the stored object supplies the metadata and the
modifiers -- `--owner-uid`, `--owner-gid`, `--statoverride`,
`--mode-ro-executables`, `--canonical-permissions`, `--no-xattrs` -- apply over
it, so the object is rewritten from the stored payload where the shaped metadata
differs from the stored metadata. Under `-I` the object is committed verbatim and
the filter and the modifiers are skipped for that entry: a `--statoverride` or
`--skip-list` entry naming a resolved path goes unmatched, and `--owner-uid`
reaches only the entries that resolved nothing.

Because a resolved regular file writes no content object under `-I`, that option
also masks a write the other two hit. `--owner-uid=0` against a `bare`
repository as a non-root user fails plainly and under
`--link-checkout-speedup` -- `error: Writing content object: fchown: Operation
not permitted`, exit 1 -- and succeeds under `-I`. `--canonical-permissions`
behaves the same way.

Neither option changes a commit's checksum in twelve of the fourteen checkout
variants across `archive`, `bare-user`, and `bare`. The two that differ are a
`bare-user` repository checked out with `-U`, with or without `-H`. That checkout
hardlinks the stored objects, which carry the repository's own `user.ostreemeta`
xattr, and the plain walk reads that xattr as a real xattr of the source file and
commits it, so every file object and every dirtree changes. There the flagged
commit is the faithful one: it reaches the checksum the source tree itself
reaches, and `--no-xattrs` on the plain walk reaches the same. The xattr's
12-byte payload is `uid(be32) gid(be32) mode(be32)`.

## Checkout

Checkout materializes a commit's tree onto a filesystem. The destination is
arbitrary and is not part of the on-disk format, so the durability choices
(whether to fsync) carry no byte-exact requirement. The metadata each checkout
writes, and the decision to hardlink a loose object rather than copy it, are
recovered by black-box observation: checking out tool-created commits of assorted
modes with `ostree checkout`, `ostree checkout -U`, and `ostree checkout -C`, and
inspecting the destination trees (`stat`, `getfattr`, `readlink`) and the object
inodes' link counts.

Checkout modes. The faithful checkout (`ostree checkout`) restores full metadata;
the unprivileged checkout (`ostree checkout -U`) restores no ownership and no
xattrs.

- Faithful: a regular file is chowned to the logical uid/gid, chmodded to the
  full logical permission bits (`mode & 0o7777`), and given the logical xattrs. A
  symlink is a real symlink lchowned to the logical uid/gid with the logical link
  xattrs. A directory is chowned to the logical uid/gid, chmodded to the full
  logical mode (`mode & 0o7777`), and given the logical xattrs.
- Unprivileged: no chown and no xattrs. A regular file the checkout writes takes
  `mode & 0o1777`, so the setuid and setgid bits are dropped, and the sticky bit
  and the rwx bits including group- and other-write are kept (`4755` and `6755`
  become `0755`, `1755` and `7755` become `1755`, `1644` stays `1644`, `0666`
  stays `0666`). A directory's mode is the full `mode & 0o7777`, so all three
  special bits are kept (`2755` stays `2755`, `1644` stays `1644`). A symlink is a
  real symlink with no chown and no xattrs.

The mask applies to a regular file the checkout writes. A regular file it
hardlinks instead adopts the object inode's mode as it stands, which in
`bare-user` carries no special bit, so the sticky bit of a `bare-user` object is
absent from an unprivileged checkout that hardlinks and present in the same
checkout forced to copy. Recovered by checking a tree of the modes `1644`, `1755`,
`2755`, `4755`, `6755`, `7755`, and `3755` -- on files and on directories --
out of `archive`, `bare`, `bare-user`, and `bare-user-only` repositories, with
`ostree checkout`, `ostree checkout -U`, and `ostree checkout -U -C`, and reading
the destination modes back. The `-U -C` result is the mask above in every mode.

Observed further on a `bare` repository holding a tree of assorted modes: `f0666`
checks out `0666` under both modes; `f4755` checks out `4755` faithful and `0755`
unprivileged; `d2755` checks out `2755` under both; a `user.demo` xattr on a file
is present after a faithful checkout and absent after an unprivileged one.

Hardlink versus copy. The tool hardlinks the loose object directly into the
destination -- raising the object inode's link count -- exactly when the object's
stored inode form is already byte-identical to what the checkout would otherwise
write; otherwise it copies. Regular files, by storage mode and checkout mode:

- `bare` + faithful: hardlink. `bare` + unprivileged: copy.
- `bare-user` + faithful: copy. `bare-user` + unprivileged: hardlink. The
  hardlinked file carries `user.ostreemeta` as a side effect of sharing the
  object inode, which is why a byte-exact unprivileged checkout of a `bare-user`
  repository requires the hardlink: a copy would omit that xattr.
- `bare-user-only` + faithful or unprivileged: hardlink. The object carries no
  ownership and no xattrs and its inode mode is the canonical `perm & 0o755`, so
  the tool never chowns the checked-out file (it stays owned by the object
  writer, not 0:0), and a faithful and an unprivileged checkout of a
  `bare-user-only` repository produce identical trees. Checkout therefore treats
  `bare-user-only` storage as forcing unprivileged semantics regardless of the
  requested mode.
- `bare-user-shared`: copy under both modes. The object inode is a fixed 0644
  that matches no checkout form, so it never hardlinks; the copy applies the
  logical mode from `user.ostreemeta`.
- `archive`: copy under both modes. Under unprivileged checkout the tool
  hardlinks from an `uncompressed-objects-cache/` it maintains outside the
  on-disk format; a checkout that does not maintain that cache copies instead and
  differs from the tool only in the object's link count, never in content or
  metadata.

Symlinks are hardlinked only under `bare` + faithful (destination link count 2
observed). Everywhere else the symlink is recreated fresh (link count 1),
including `bare-user-only`, whose object is a real symlink. `bare-user` and
`bare-user-shared` store symlinks as regular files, so a real destination symlink
cannot share their inode.

The unifying rule is: hardlink iff the object inode is already exactly the target
inode. Forcing a copy (`ostree checkout -C`) suppresses every hardlink; the copy
path still attempts a reflink. A hardlink that would cross a filesystem (`EXDEV`)
falls back to a copy.

The copy path writes into a temp file in the destination directory, applies the
checkout-mode metadata, and materializes it under the destination name. For a
non-archive regular file, whose on-disk bytes are exactly the raw payload
(`bare`, `bare-user`, `bare-user-shared`, `bare-user-only`), the copy attempts a
`FICLONE` reflink of the object's extents before falling back to a streamed byte
copy; an archive object is always streamed through its inflating reader. A
hardlink applies no metadata, since it shares the object inode by construction.

Destination directories. A directory is always created fresh, never hardlinked,
and receives its full logical mode under both checkout modes; the metadata is
applied after the directory's children are materialized, so a restrictive mode
does not block writing them. The destination root receives the checked-out
(sub)tree root's dirmeta: committing a root at mode `0750` and checking it out
yields a destination root at `0750`; a subpath to a directory at `0755` yields a
destination root at `0755`.

Overwrite policy over an existing destination:

- Default (`ostree checkout`): the destination is created fresh, and any
  pre-existing destination directory is an error (`mkdirat: File exists`). Each
  subdirectory is created with `mkdirat`, and an existing one is an error.
- Union files (`ostree checkout --union`): an existing directory is reused
  without re-applying its metadata, an existing file is overwritten, new entries
  are added, and existing entries not in the commit are left in place.
- Add files (`ostree checkout --union-add`): only entries that do not already
  exist are written; an existing file or directory is kept.
- Union identical (`ostree checkout --union-identical`): new entries are added
  and an existing entry identical to the object it would receive is left in
  place, while a differing existing entry is an error. The tool establishes
  identity by hardlink; identity is equivalently an existing entry whose
  `(st_dev, st_ino)` equals the repository object it would link. The tool
  accepts `--union-identical` only together with `--require-hardlinks`, since the
  hardlink is what establishes identity. Checkout therefore requires a
  hardlink-eligible repository mode and checkout mode with no forced copy for
  this policy, and rejects it up front otherwise.

A type conflict between the destination and the commit stops the checkout, and
no mode changes an entry's type:

- A destination name held by a non-directory (a file or symlink) when the commit
  carries a directory of that name is a conflict in every mode. The tool errors
  (`opendir(<name>): Not a directory`), since it descends into the existing name
  to merge the committed directory's children.
- A destination directory when the commit carries a non-directory of that name is
  a conflict under the default, union-files, and union-identical modes; the tool
  errors (`renameat(...): Is a directory` under union-files). Under add-files the
  existing directory is kept and nothing is written for that name.

Whiteouts. With whiteout processing enabled (`ostree checkout --whiteouts`),
within each directory an entry named `.wh..wh..opq` marks the directory opaque, so
the destination directory's pre-existing entries are removed before the committed
entries are written, and the marker itself is not materialized; an entry named
`.wh.<name>` removes `<name>` from the destination directory and is not
materialized; all other entries check out normally. With whiteout processing off,
`.wh.`-prefixed entries check out as ordinary files. The
`--process-passthrough-whiteouts` option (extracting overlayfs char 0:0 devices,
which needs `CAP_MKNOD`) is a distinct mechanism and is out of scope here.

Subpath. A subpath resolves a node within the commit tree and checks that node
out as the destination root. A subpath to a directory makes its dirmeta the
destination root's metadata and materializes its children. A subpath to a regular
file or symlink creates the destination directory (a default `0700` observed) and
places the single object inside it under its name. A missing subpath is an error.

The spellings the tool accepts and refuses, recovered with
`ostree checkout --subpath` against a commit holding `file.txt`, `dir/`, and
`dir/link`: the leading slash is optional (`/dir` and `dir` name the same node),
`/` names the whole tree, and a nested path resolves through its directories. A
value the tool cannot resolve ends the checkout at exit 1 with no destination
created: `error: No such file or directory: <path>`, naming the path with a
leading slash the tool adds, and `error: Not a directory` where the path runs
through a regular file. The tool looks the value up as given, so `.` is refused
(`No such file or directory: /.`) and a trailing slash is refused
(`No such file or directory: /sub/`).

## Extended attributes

Storage form is GVariant `a(ayay)`: array of (name-bytes, value-bytes). A
stored name includes the namespace prefix and a single terminating NUL, with a
non-empty prefix and no interior NUL. Confirmed by committing a file bearing a
`user.demo` xattr into a bare-user repo and reading its `user.ostreemeta`
blob: the name bytes `user.demo` are followed by one `\0`. Canonicalization
sorts by name with byte-wise comparison and is applied before every
serialization and hash; duplicate names and names not in this stored form are
rejected. Per-mode disposition: bare on the inode, bare-user and
bare-user-shared inside `user.ostreemeta`, bare-user-only discarded,
bare-split-xattrs in separate `.file-xattrs` objects reached through
`.file-xattrs-link`, archive inside the `.filez` header.
During commit an existing `security.selinux` xattr is dropped and re-applied
from the SELinux policy so it is not double-counted in the checksum.

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

On-disk framing of a part file before decompression is `(y@ay)` = compression
byte plus body. Compression: 0 = none, `x` = xz/lzma (the only real
compression written; the reader accepts only 0 and `x`).

Constants: objtype+csum stride is 33 bytes (1 objtype + 32 csum). Part max size
16 MiB (advisory). Delta part version 0. The `SIGNED_FORMAT` magic is the eight
ASCII bytes `OSTSGNDT`; read as a little-endian `t` that is `0x54444E475354534F`,
read big-endian it is `0x4F535453474E4454`. A superblock file that begins with
those eight bytes is a signed envelope: the `ay` it wraps is the raw
`SUPERBLOCK_FORMAT` bytes (the payload the signatures cover), and the trailing
`a{sv}` holds signatures under the per-engine keys (for example
`ostree.sign.ed25519 -> aay`), the same framing commit and summary signing use.
An unsigned delta stores the raw `SUPERBLOCK_FORMAT` bytes directly.

The superblock's leading `a{sv}` carries `ostree.endianness` and, where the
target commit has detached metadata, a copy of it under the key
`deltas/<fanout>/<rest>/commitmeta` -- the delta's own relative directory with
`/commitmeta` appended -- holding the same `a{sv}` the `.commitmeta` file holds.
Recovered by signing a commit and reading the superblock the tool then generated:
its bytes carry `ostree.sign.ed25519` inside that key. A tool pull checks a
delta-delivered commit against this copy rather than against the `.commitmeta`
it fetches and stores.

Object delivery. The target commit object is embedded whole in the superblock
(the `(a{sv}aya(say)sstayay)` field); it is not carried in any part, and
re-serializing it hashes to the `to` checksum. Every other object is produced by
a part. A part's meta-entry carries the ordered objtype+csum array; the
operation stream produces objects in that order, and the object type at the
current position selects how an operation is decoded. The `part-checksum` is the
SHA-256 of the on-disk part file (the `(y@ay)` framing bytes). Fallback objects
are delivered outside the parts as plain loose objects.

Fallback selection (generation-side; recovered by observing the tool). An object
is delivered as a fallback when the size compared against `--min-fallback-size`
is at least the threshold, and is packed into a part otherwise. The unit is
decimal megabytes (a factor of 1,000,000, not 1,048,576) and the default is 4, so
the default threshold is 4,000,000 bytes, and an object whose size equals the
threshold is a fallback. The value is read as a whole number of megabytes:
`--min-fallback-size=0.1` over a commit holding one 5,000,000-byte object reports
`Number of fallback entries: 0`, where `--min-fallback-size=1` over the same
commit reports 1. A threshold of 0 turns fallbacks off: `--min-fallback-size=0`
over that commit packs the object (`PartMeta0: nobjects=3 size=5000405
usize=5000055`).

The size compared is the object's file header variant, seven bytes, and the
content -- not the content alone. Recovered by finding the content size at which
an object switches sides. At a 4,000,000-byte threshold the largest packed content
is 3,999,974 bytes and 3,999,975 becomes a fallback, an overhead of 25 bytes over
the 18-byte header of a `uid=gid=0` no-xattr regular file, and the same offset
holds at other thresholds (for example 2,000,000). At a 1,000,000-byte threshold
over three header shapes: 999,974/999,975 for that same 18-byte header, an
overhead of 25; 999,953/999,954 for a file carrying one 8-byte xattr, whose header
is 39 bytes, an overhead of 46; and 999,658/999,659 for one carrying a 300-byte
xattr, whose 334-byte header crosses the GVariant offset-width boundary, an
overhead of 341. The overhead is seven bytes over the header variant in every
case, so the header's own offset table counts and the constant does not move with
the header's size. The on-disk content-stream framing is eight bytes (a big-endian
`u32` length and four NUL bytes), one more than the count compared here.

Applying a delta does not use this threshold: the reader delivers whatever the
superblock's fallback array lists and requires those objects to be present
already. The port compares the same size (`FALLBACK_FRAMING` in `deltagen.rs`), so
it classifies every object as the tool does, including one sitting exactly on the
threshold: `the_fallback_threshold_classifies_an_object_as_the_tool_does` runs the
tool's own generation over both sides of the boundary and compares the fallback
count.

A fallback entry's two sizes (recovered by generating a delta over a 5,000,000-
byte object and reading `static-delta show`): the compressed size is the loose
object's on-disk size in the source repository (5,001,564 bytes for the `.filez`
of that object in an archive repo, matching the file), and the uncompressed size
is the content size alone (5,000,000), with no header included.

Part meta-entry sizes. `size` is the part file's on-disk byte size, compression
byte included. `usize` is the uncompressed payload the part delivers, summed over
its objects: a metadata object's serialized length, a file's content length, a
symlink's target length -- the file header is not counted. Recovered by
comparing `static-delta show` against the objects a part carries: a part
delivering one 8,192-byte file plus its one-entry dirtree (41 bytes, with dirmeta
12) reports `usize=8233`, and a part of two 1,000,000-byte splices reports
`usize=2000000`. For an all-splice part this equals the data-source blob size,
which is why the two coincide there; for a rollsum or bspatch part it does not,
since the blob then holds patch streams rather than content.

`usize` states what the part's objects add up to, which is under the size of the
part payload that carries them: a from-scratch part of three files (8,192, 20,000
and 6 bytes), one symlink and three metadata objects reports `usize=28453` where
its payload decompresses to 28,531 bytes -- the data-source blob (28,462, which
holds the 9-byte symlink target `usize` leaves out), the operation stream (38),
the mode table (24), the xattr table, and the tuple framing. `size` is the field
that bounds a part: it is the length of the file the part checksum is taken over.

Part packing. Objects accumulate into one part until adding the next would push
the payload past `--max-chunk-size` (decimal megabytes, default 32), then a new
part starts; metadata objects come before content objects. Observed with
`--max-chunk-size=2` over five 1,000,000-byte objects: payloads of 1,000,218
(the two metadata objects plus one file), 2,000,000, and 2,000,000.

The port applies the rule with the incoming object's content size as the estimate,
which is exact for a spliced object and an upper bound for a diffed one, and
decides before the object is appended, so a part's payload never passes the
ceiling. A diffed object whose payload comes out small therefore still closes the
part it would have fit in, costing one extra xz stream and one extra pair of mode
and xattr tables, and the port's part boundaries differ from the tool's for such an
object. Both layouts are valid: a part's contents are named by its meta-entry, so
where the boundaries fall decides a delta's size, not whether it applies.

Superblock fields the tool writes. The metadata dict holds exactly one entry,
`ostree.endianness` as a byte (`l` on a little-endian host). The timestamp is the
generation wall-clock time, big-endian. `from` is an empty `ay` for a
from-scratch delta. The recursion array is always empty. A meta-entry's version
field is 0.

Diff-source pairing (generation-side). The tool pairs a modified content object
with the object at the same path in the source commit: a file that was renamed
and edited is not paired (`modified: 0`) and travels whole. Pairing is also
skipped when the two sizes differ substantially -- a 40,000-byte object paired
after growing to 40,800 or 56,000 bytes, but not after growing to 59,600 or
shrinking to 26,800. When a pair is found, the tool prefers rollsum chunking
whenever chunking finds any shared chunk at all, however little: an 8,192-byte
object whose chunking matched 1,133 bytes still went to rollsum. bsdiff appears
only where chunking finds nothing, such as a 1,024-byte object with a small edit.

The port pairs by path alone and does not reproduce the size-ratio rule. Pairing
decides how large a delta is, not whether it is valid: a pair the ratio rule
would have skipped costs a diff attempt whose result is discarded, and the object
then travels whole exactly as it would have. This is the port's own choice in the
same sense as the chunker's parameters. What the port bounds instead is the diff
attempt itself, by the chunker's maximum chunk size, so an unrelated same-path
rewrite of a large object is spliced without paying for a suffix sort first.

Offline application limits in the tool (observed while applying port-generated
deltas). `ostree static-delta apply-offline` refuses any delta whose fallback
array is non-empty: "Cannot execute delta offline: contains nonempty http
fallback entries" -- fallbacks are a pull-time mechanism. Its `open` opcode
dispatch also asserts a bare-family repository, so a delta carrying rollsum or
bspatch objects applies offline only into `bare`, `bare-user`, or
`bare-user-only`, not into `archive`; a splice-only delta applies into any mode.
The port's reader has neither restriction: it applies rollsum and bspatch
deltas into an archive repository, and fallbacks apply as long as the objects
they name are already present.

Opcodes (ASCII): `S` open-splice-and-close, `o` open, `w` write, `r`
set-read-source, `R` unset-read-source, `c` close, `B` bspatch. Operands are
LEB128 varints; offsets are absolute byte offsets into the part's
raw-data-source blob. The `c` (close) opcode takes no operand and asserts the
produced object's SHA-256 equals the expected checksum: this is the end-to-end
integrity gate.

Operand grammar (recovered by observing the tool):

- `S` for a metadata object (dirtree/dirmeta): `(length, offset)` -- splice
  `length` bytes at `offset` in the data source as the object's serialized
  bytes, and close.
- `S` for a content object (file/symlink): `(mode-index, xattr-index, length,
  offset)` -- the mode and xattr tables supply the object's metadata; a symlink
  (mode `S_IFLNK`) takes the spliced bytes as its target, a regular file as its
  content.
- `o` (open) for a content object: `(mode-index, xattr-index, output-size)`.
- `r` (set-read-source): `(offset)` -- at `offset` in the data source lie the 32
  bytes of a source object's checksum; that object's content becomes the read
  source for the following `B` or `w` ops.
- The tool emits one `r`/`R` pair per contiguous run it copies out of a source
  object, so an object reconstructed from scattered runs names the same source
  checksum once per run: a 4 MiB object with forty scattered 512-byte edits
  carries 41 `r` ops and 41 `R` ops against one source object.
- `R` (unset-read-source): no operand.
- `B` (bspatch): `(stream-offset, stream-length)` -- the bspatch stream is
  `stream-length` bytes at `stream-offset` (which is the preceding `r` offset
  plus 32), applied against the read source to fill the open object; `c` then
  closes it.
- `w` (write, rollsum): `(length, offset)` -- append `length` bytes to the open
  object, read at `offset` in the current source: the read-source object when a
  preceding `r` set one, the part's data source otherwise. The output is written
  strictly forward, so the destination is the implicit output cursor and only the
  read offset is carried. Emitted for from->to deltas of larger objects, where
  the tool prefers rollsum chunking to bsdiff (smaller objects still use bsdiff
  or splice): a run of `w` ops with a read source set copies the unchanged
  content-defined chunks out of the source object, and a `w` with no read source
  writes the changed run from the payload. A rollsum object's stream is `o`, then
  `r`/`w`.../`R` groups interleaved with payload `w` ops, then `c`.

bspatch stream. The embedded bspatch stream is the classic bsdiff patch with its
three streams interleaved and stored uncompressed (the enclosing part is xz'd as
a whole). It is a sequence of blocks, consumed until the output reaches the
opened object's size, each: a 24-byte control block of three signed 64-bit
integers in bsdiff `offtin` sign-magnitude little-endian encoding (`diff-length`,
`extra-length`, source `seek`); `diff-length` bytes each added, wrapping, to the
source bytes at the current source position; then `extra-length` verbatim bytes;
after which the source position advances by `diff-length` and then by `seek`.

Endianness hazard: the `u`/`t` fields in meta entries, fallbacks, and fallback
headers are host byte order gated by an `ostree.endianness` byte (`l`/`B`) in
superblock metadata (a historical inconsistency, with a size-ratio heuristic
fallback when the byte is missing). The superblock timestamp is always BE; the
`(uuu)` mode triple is always BE regardless of that byte. Applying a delta reads
one host-order-gated field, a meta-entry's `size`, which is the ceiling a part is
read under: the port swaps it where the byte states `B` and reads it as
little-endian where the byte is absent. The rest go unread -- parts are read by
name and checked by their SHA-256, the modes are swapped from their fixed
big-endian form, and the embedded commit is normal-form little-endian -- so a
big-endian delta applies through the same path.

## Signing details

The signing engines share commit/summary framing. What is signed:

- Commit: the canonical serialized commit GVariant bytes (the normal-form
  commit object -- the same bytes that hash to the commit checksum).
- Summary: the raw byte content of the `summary` file (treated as opaque).

Signatures accumulate by appending an `ay` element to the per-engine `aay` in
the `a{sv}` dict. GPG and the sign-api engines are independent and can both
apply to one commit.

A signature produced while a commit is being written stands before the ref that
names the commit. The sequence is: stage the tree and the commit object; produce
every signature the invocation asks for; publish the staged objects into
`objects/` and write the `.commitmeta` beside the commit; write the ref. A
signature that cannot be produced therefore leaves no object in `objects/`, no
`.commitmeta`, and the ref where it stood, and a run naming several keys is all
or nothing. A ref write that cannot happen leaves the commit and its
`.commitmeta` durable with no ref pointing at them.

The keys of the `a{sv}` dict hold the order the writer stored them in, which is
not the order `ostree show --list-detached-metadata-keys` prints: that listing
sorts. The port stores insertion order, and the insertion order a `commit`
invocation produces is fixed and does not follow the command line -- the
caller's own detached-metadata keys in command-line order, then
`ostree.sign.<type>`, then `ostree.gpgsigs`. The reference tool stores that same
order over most key sets and a name-dependent order over some of them, which
`../conformance/cli-surface.md` records under "P2". The stored order carries no
meaning: the dict is a mapping and every reader looks keys up by name.

Adding a detached-metadata key and signing differ in what they do to the dict
already stored for a commit checksum. A detached-metadata key replaces the whole
stored dict; a signature appends to whatever stands at that moment. Committing
the same checksum twice with one signing key each therefore leaves two elements
in the engine's array, and a run naming both a detached-metadata key and a
signing key writes the caller's key over the stored dict and appends the
signature to that new dict, dropping any signature an earlier run left. A run
that skips its write -- an unchanged tree under `--skip-if-unchanged` -- signs
nothing and leaves the stored dict untouched.

ed25519: 32-byte public key, 64-byte signature, 64-byte secret key (32-byte
seed followed by 32-byte public key). Keys are passed as base64 strings or raw
`ay`. Key files hold one base64 key per line. System key directories are
`/etc/ostree` and `<datadir>/ostree`, files `trusted.ed25519` and
`trusted.ed25519.d/`, plus `revoked.ed25519` and `revoked.ed25519.d/`. A key
present in both the trusted and revoked sets is rejected: the effective trusted
set is the trusted set minus the revoked set.

spki (signature key `ostree.sign.spki`). ECDSA over NIST P-256 with SHA-256.
The signed payload is the same commit bytes as the other engines; the engine
hashes them with SHA-256 and produces a DER-encoded ECDSA signature (an ASN.1
`SEQUENCE` of the two integers `r` and `s`, roughly 70 to 72 bytes). Public keys
are the X.509 SubjectPublicKeyInfo DER, the base64 body of a PEM `PUBLIC KEY`
block. Secret keys are base64; the decoded bytes are a PKCS#8 `PrivateKeyInfo`
DER, a SEC1 `ECPrivateKey` DER, or a raw 32-byte scalar. The key store mirrors
ed25519: files `trusted.spki` and `revoked.spki` and their `.d` directories
under `/etc/ostree` and `<datadir>/ostree`, one base64 SubjectPublicKeyInfo per
line, and the effective trusted set is the trusted set minus the revoked set.

The reference tool gates spki on OpenSSL and the build under observation
(libostree 2026.1) was compiled without it, so these spki facts are the design
target: the public key container and the key-store layout are from the public
ostree documentation, and the curve, hash, DER signature encoding, and key DER
containers are the standard OpenSSL/RFC forms confirmed against `openssl`
(a general tool, run as a black box) but not yet cross-verified against an
spki-capable `ostree`. When such a build is available, generate a key pair with
the tool, sign a commit, inspect the PEM and the signature bytes, and reconcile
any difference here.

GPG (signature key `ostree.gpgsigs`). Each `ay` element is one detached
OpenPGP signature: the binary signature packet stream, unarmored. A blob may
hold more than one signature packet, and each packet is verified
independently. The port signs through the system GnuPG installation
(`gpg --detach-sign`, driven over the machine-readable `--status-fd`
interface) and verifies in the process over the `pgp` crate (rPGP), so the
stored blobs are the OpenPGP interchange form GnuPG itself produces and
consumes. A signature is reported valid only where it verifies against a
trusted key whose bindings hold; a signature by an expired, revoked, or
unknown key is invalid, with the state surfaced per signature: the
signing-key and primary-key fingerprints, the creation and expiry timestamps,
the key's expiry time when it has passed, the expired/revoked/missing flags,
the public-key and digest algorithm names, and the signer's user id split into
name and email.
Trust is membership in the supplied keyrings; GnuPG's ownertrust model does
not participate.

GPG keyrings are binary or ASCII-armored, each holding one or more
certificates, all merged into one trusted set. The keyring trusted for a
remote is `<remote>.trustedkeys.gpg` in the repo or under
`/etc/ostree/remotes.d/`; every `*.gpg` keyring in the global trusted-keyring
directory is trusted for all remotes. That directory is
`<datadir>/ostree/trusted.gpg.d/` (`/usr/share/ostree/trusted.gpg.d/`), and
the `OSTREE_GPG_HOME` environment variable overrides it with the directory it
names, observed by running `ostree show` on a signed commit with
`OSTREE_GPG_HOME` set to a directory holding the exported keyring.
End-to-end cross-verification against `ostree gpg-sign` runs with the upstream
shell tests at the CLI-compatibility phase.

Dummy engine (test only). Signature key `ostree.sign.dummy`, value `aay` like
the other engines. The engine is gated in the tool behind the
`OSTREE_DUMMY_SIGN_ENABLED` environment variable; with the variable unset the
tool refuses every dummy operation with "dummy signature type is only for
ostree testing". A dummy signature is the raw bytes of the key identifier: the
secret key and the public key are the same byte string, signing appends those
bytes verbatim as one `ay` signature blob, and the signed payload is ignored.
Verification succeeds when any stored signature blob equals a trusted
public-key byte string. These bytes were recovered by signing a commit with the
tool (`ostree sign --sign-type=dummy COMMIT KEY-ID`) and reading the
`.commitmeta` object: the blob for key `mysecretkey` is exactly the 11 ASCII
bytes `mysecretkey`, with no trailing NUL, independent of the commit.

## composefs

ostree built with composefs exports a commit's tree to an EROFS image in the
composefs project's format (EROFS, format version 0). The deployed image
filename is `.ostree.cfs`. A pure-Rust port reproduces this output byte-for-byte
because the image's fs-verity digest is stored in commit metadata under
`ostree.composefs.digest.v0` (type `ay`, 32 bytes) and verified at boot.

The EROFS and composefs on-disk formats are defined by the EROFS and composefs
projects, not by ostree's documentation. The layout recorded here is recovered
by observing the images the `ostree` tool produces (composefs 1.0.8 under ostree
2026.1), reading them back with `composefs-info`, and inspecting the raw bytes.
The checked-in golden image is the authoritative byte contract; the field-level
notes below describe what that image contains.

### Export path

`ostree checkout --composefs COMMIT DESTINATION` writes the image at
DESTINATION. `--composefs-noverity` writes the same structure without the
per-file fs-verity digests. `ostree commit --generate-composefs-metadata` stores
the image's fs-verity digest in the commit's `ostree.composefs.digest.v0` key.
The image is derived from the commit's tree alone: it is byte-identical whether
or not the commit carries that metadata, and whatever mode the repository holding
the tree uses. Observed over one tree committed with
`--generate-composefs-metadata` into `archive`, `bare`, and `bare-user`, which
reach one commit checksum and so one digest; `bare-user-only` canonicalizes the
tree and reaches another.

The tool builds the image in an anonymous temporary file (`O_TMPFILE`) opened
relative to the current directory and links it into place next to the
destination, so the export runs with a working directory on the destination's
filesystem.

### fs-verity digest

The digest is fs-verity with SHA-256, 4096-byte blocks, and a zero-length salt.
`composefs-info measure-file <image>` reports it, and it equals the
`ostree.composefs.digest.v0` value the tool stores. For the golden fixture (the
deterministic source tree) it is
`c91bad0285efab4453562cadf7a22f2dc3714dee81dbe002ded71318e18384d9`.

The digest is a Merkle tree over the data. Each 4096-byte block is hashed with
SHA-256, the final block zero-padded to 4096. Block hashes are concatenated,
grouped into 4096-byte parent blocks (128 SHA-256 hashes per block, the tail
parent zero-padded), and hashed again, up to a single root hash. Data of one
block or less has that block's hash as the root; empty data has an all-zero
root. The digest is the SHA-256 of a 256-byte little-endian descriptor:

- version byte 1, hash-algorithm byte 1 (SHA-256), log2-block-size byte 12,
  salt-size byte 0;
- 4 reserved bytes 0;
- data size, 8 bytes, the byte length of the data;
- the 32-byte root hash, followed by 32 zero bytes (the root-hash field is 64
  bytes wide);
- 32 zero salt bytes;
- 144 reserved bytes 0.

The same primitive computes the digest of each backing object, over the raw
object bytes.

### Injected top-level directories

The image root holds, alongside the commit's own entries, five empty directories
the tool injects: `boot`, `etc`, `sysroot`, `usr`, `var`, each mode 040755 with
owner 0:0. They are absent from the commit tree (`ostree ls` does not list them)
and present in every exported image.

### Image layout and the composefs header

The image is composefs format version 0. Bytes 0..1024 hold a 32-byte composefs
header, zero-padded to 1024:

- magic, 4 bytes, `9a 62 78 d0` (little-endian `0xD078629A`);
- version 1, 4 bytes;
- flags, 4 bytes, `0x00000001` when any inode carries a POSIX ACL xattr and 0
  otherwise;
- composefs version 0, 4 bytes;
- 16 reserved bytes 0.

The regions follow in order: the composefs header and its padding, the EROFS
superblock, the inode table, the shared-xattr area, and the directory and file
data blocks. Node ids are byte offset divided by 32.

### EROFS superblock

The superblock sits at byte offset 1024 and is 128 bytes. Observed fields:

- magic, 4 bytes, `e2 e1 f5 e0` (little-endian `0xE0F5E1E2`);
- checksum 0 (unused);
- feature_compat `0x06` (MTIME `0x02` and XATTR_FILTER `0x04`);
- blkszbits 12 (block size 4096), extra superblock slots 0;
- root_nid, the node id of the root inode;
- inos, the total inode count, including the overlay whiteout stubs;
- build_time and build-time nanoseconds, the minimum inode mtime, 0 for an
  exported commit (the tool sets every inode mtime to 0);
- blocks, the image size in 4096-byte blocks;
- meta_blkaddr 0, xattr_blkaddr the block holding the shared-xattr area (the
  block that contains the end of the inode table);
- UUID all zero.

The zero UUID and zero build times make the image deterministic for a fixed
input tree and composefs version.

### Inodes

Inodes are collected breadth-first from the root: the root first, then every
directory's children in name-sorted order, each directory's children before the
next directory's. The `i_ino` field is the collection index (root 0). Inodes
are written in that order, so node id increases with `i_ino`.

An inode is compact (32 bytes) when its mtime equals the superblock build_time,
its nlink and ownership fit 16 bits, and its size fits 32 bits; otherwise it is
extended (64 bytes). An exported commit uses compact inodes throughout unless an
id exceeds 16 bits or a file exceeds 4 GiB. The format field's low bit selects
compact (0) or extended (1); bits 1..3 hold the datalayout: 0 flat-plain, 4
flat-inline, 8 chunk-based. Inode mode is the EROFS file-type bits combined with
the logical permission bits.

Directory inodes are flat-inline when their entries fit within one block after
the inode header and xattrs, and flat-plain when the entries occupy one or more
whole blocks. Empty regular files are flat-plain with size 0. Symlinks are
flat-inline with the target stored inline. Whiteout stubs are character devices,
flat-plain, `i_u` 0.

A symlink target shares its inode's block with the inode header and the inode's
extended attributes, so the target is at most 4096 bytes less those two. A
header is 32 bytes, or 64 bytes for an inode the compact form does not hold,
which puts a target carrying no attributes at 4063 bytes. The tool aborts on a
longer one. Measured against libostree 2026.1 over one symlink and no
attributes: at 4063 bytes `checkout --composefs` writes the image, and at 4064
and at 4095 bytes it exits on
`lcfs_write_erofs_to: Assertion 'ctx_erofs->current_end == ctx->bytes_written'
failed` and writes nothing. 4064 bytes is where the header and the target first
fill a block. The port refuses the same trees with `Error::Unsupported`, so no
composefs image either side writes holds a symlink target outside its inode's
block. `PATH_MAX` is 4096, so a checkout produces no tree that reaches the
bound; a tar import does.

### Overlay whiteout table

The image writer adds a 256-entry overlay whiteout table to the root: one
character-device inode, device 0:0, mode 0644, owned like the root and sharing
its mtime, for each two-digit lowercase hex name `00` through `ff`. Any name
already present in the root is skipped. It also sets `trusted.overlay.opaque` to
`y` on the root. `composefs-info dump` hides these entries, so they do not
appear in `tree.dump`, but they are inodes and root directory entries in the
image, and the superblock `inos` counts them.

### Directory blocks and dirents

A directory's entries include `.` (the directory) and `..` (the parent), then
the children, sorted by name as raw bytes. Entries are packed into 4096-byte
blocks: whole blocks are emitted as data blocks, and a tail of 2048 bytes or
less is stored inline after the inode; a larger tail is promoted to its own data
block. A directory's size is the whole-block byte count plus the inline tail.
Its nlink is the count of directory-typed entries, which is 2 plus the number of
child subdirectories.

Within a block, the fixed-size dirent headers come first, then the names with no
separators. Each dirent header is 12 bytes:

- node id, 8 bytes;
- name offset within the block, 2 bytes;
- file type, 1 byte (1 regular, 2 directory, 3 character device, 7 symlink);
- 1 reserved byte.

The first dirent's name offset divided by 12 gives the entry count.

### Inode extended attributes and the name filter

An inode's xattr area, present only when the inode has at least one xattr,
follows the inode header:

- a 12-byte header: a 4-byte name filter, a shared-count byte, 7 reserved bytes;
- shared-xattr references, 4 bytes each;
- inline entries, sorted by full name then by value length then by value bytes.

`i_xattr_icount` encodes the area size: 0 when absent, otherwise
`1 + (size - 12) / 4`. Each inline entry is a 4-byte header (name-length byte,
name-index byte, 2-byte value size), then the name suffix, then the value,
padded to a 4-byte boundary. The value size is 2 bytes, so an entry holds at
most 65535 bytes of value. The name length is 1 byte, so an entry holds at most
255 bytes of name suffix. Both widths are readable in the golden images.

An inode holds at most 128 shared-xattr references. Its repeated attributes are
taken in ascending full-key order until the inode holds 128 of them, and the
rest stay inline. The shared table itself holds every repeated entry, including
entries no inode ends up referencing. Measured against libostree 2026.1 over
two files carrying the same 10, 100, 127, 128, 129, 200, and 256 attributes:
the count field reads back the attribute count up to 128 and 128 from there on,
and the inode's area grows by one inline entry for each attribute past 128. The
ordering was measured over three further trees. Two files carrying 300
attributes of which the even-numbered 150 repeat: the 128 lowest even keys are
shared and the 22 highest even keys join the odd ones inline. Three files where
100 `user.t*` keys repeat three times and 100 `user.d*` keys repeat twice: the
inode carrying both shares all 100 `user.d*` keys and the 28 lowest `user.t*`
keys, so the repeat count does not decide the order and the key does. And a
`--composefs-noverity` export of two files carrying 200 repeated attributes,
where the empty `trusted.overlay.metacopy` value repeats across the backed
inodes and sorts below `user.`, taking one of the 128 and moving one more key
inline. `tree-rich.cfs` holds the case and the port reproduces all six trees
byte-for-byte.

The tool binds an inode's attributes well under the value field. Each attribute
spends its full name, its value, and 7 bytes from a budget of 32755 bytes for
the inode. Past the budget the tool writes no image, records no digest, and
exits non-zero. Measured against libostree 2026.1 over one attribute at name
lengths 6, 8, 37, and 200; over 2, 3, 8, and 100 attributes; over a directory
as well as a regular file; and over `system.posix_acl_access`, whose 22-byte
name shows that the budget counts the full name and not the prefix-stripped
suffix. A regular file is held to the same 32755 bytes as a directory, so the
`trusted.overlay.redirect` and `trusted.overlay.metacopy` attributes the export
adds to a backed inode sit outside the budget. At the budget the tool and the
port write the same image.

The budget leaves the name-length field unbound: 255 bytes of name sit inside
32755 bytes. The port holds a name to that width as well, refusing past it, so
no field is written behind a truncated length. Whether the tool refuses the
same trees is unobserved. A name above 255 bytes is outside what a Linux
filesystem stores, since the kernel caps an attribute name at 255 bytes.

Names are stored with a prefix index and the remaining suffix. The prefixes are:
0 empty (full name in the suffix), 1 `user.`, 2 `system.posix_acl_access`, 3
`system.posix_acl_default`, 4 `trusted.`, 6 `security.`. Index 5 (`lustre.`) is
absent from the version-0 prefix table, so `lustre.` names use prefix 0. The
longest matching prefix wins. A name beginning with `trusted.overlay.` is
escaped to `trusted.overlay.overlay.` before indexing.

The name filter is a 32-bit Bloom filter over the inode's xattr names. Each name
sets the bit `xxh32(suffix, seed) % 32`, where `suffix` is the name after its
prefix and `seed` is `0x25BBE08F` plus the prefix index. The stored word is the
bitwise complement of the filter, so a cleared bit means the name is present.
An xattr value shared by more than one inode is moved to the shared-xattr area
after the inode table; the inode holds a reference in place of the inline entry.

### File backing

A regular file with content is backed by a bare loose object referenced through
overlay xattrs (name index 4, the `trusted.` prefix). The inode is chunk-based:
the datalayout is 8, the size is the logical file size, and `i_u` holds the
chunk format derived from the size. The inline data is one 4-byte chunk index of
`0xffffffff` per chunk (one chunk for a file of 4096 bytes or less). The xattrs
are:

- `trusted.overlay.redirect`, the backing object's loose path with a leading
  slash, `/<xx>/<rest>.file` (for example
  `/cf/ffd52f38d14c87cf46e18d5260074421ba5961f0895954e9921f165f9c91db.file`).
  The `.file` form is what the image names whatever mode the source repository
  holds, an `archive` repository storing that object as `.filez` included;
- `trusted.overlay.metacopy`, a 36-byte record in the verity image: version
  byte 0, length byte 36, flags byte 0, digest-algorithm byte 1 (SHA-256), then
  the 32-byte fs-verity digest of the backing object.
  `composefs-info measure-file <object>.file` reports the same 32 bytes. The
  digest covers the file's content, so an `archive` repository, which stores
  that content compressed, records the same 32 bytes as a `bare-user` one.

The metacopy xattr is present in both images. `--composefs` gives it the
36-byte record above. `--composefs-noverity` gives it a zero-length value on
every backed file.

The value decides the xattr layout. A metacopy value held by more than one inode
moves into the shared-xattr area, and each of those inodes holds a reference in
its place. A verity record is common to the files whose content is identical and
stays local otherwise, so the verity image of a tree of distinct file contents
carries one record per backed inode. The one empty value is common to every
backed file, so a tree with two or more backed files shares it. The inode and
xattr offsets shift accordingly. `composefs-info dump` prints the digest column
as `-` for a file in the noverity image.

The noverity image has its own fs-verity digest, and it differs from the value
a commit records under `ostree.composefs.digest.v0`. The recorded value is the
digest of the verity image, the artifact a target machine reproduces at boot.

Empty regular files carry no overlay xattrs and no backing object. Symlinks
store their target inline (mode 0120777) and are not redirected.
`composefs-info objects <image>` lists exactly the backing `.file` paths, one
per distinct redirected content object.

### Golden fixtures

`tests/fixtures/generated/composefs/tree.cfs` is the verity image of the
deterministic source tree, and `tree.dump` is its `composefs-info dump`. The
MANIFEST records `composefs_commit` (the commit made with
`--generate-composefs-metadata`) and `composefs_digest` (the image's fs-verity
digest, equal to that commit's stored `ostree.composefs.digest.v0`).

`tree-noverity.cfs` is the same commit exported with
`checkout --composefs-noverity`, and `tree-noverity.dump` is its
`composefs-info dump`. The MANIFEST records `composefs_noverity_digest`, the
image's own fs-verity digest, which is unrelated to the commit's stored
`ostree.composefs.digest.v0`.

`tree-rich.cfs` is a second verity image whose source tree carries user xattrs,
and `tree-rich.dump` is its `composefs-info dump` (xattrs appear as trailing
`name=value` tokens). Its commit is made without `--no-xattrs`, so it is
generated on a host that applies no SELinux labels. The MANIFEST records
`composefs_rich_commit` and `composefs_rich_digest`. The tree exercises
shared-xattr promotion (`user.shared` on six inodes), inline xattrs, an inode
past the 128-reference cap (`user.m000` through `user.m149` on both files under
`manyshared/`), a multi-block directory with an inline dirent tail, xattr
values of varied length, and a 4063-byte inline symlink, the longest target an
inode carrying no attributes holds.
`tree-rich-noverity.cfs` and `tree-rich-noverity.dump` are that tree's noverity
export, and the MANIFEST records `composefs_rich_noverity_digest`. The pair
holds the mixed case of the sharing rule. `tree-rich.cfs` carries 314 backed
inodes over eleven distinct verity records: two are shared, by 300 inodes and
by 5, and nine are local to one inode each. All 314 reference the one empty
value in `tree-rich-noverity.cfs`, so the nine local records move into the
shared area and the shared area holds one metacopy entry in place of two. The
minimal pair holds the plain case: `tree.cfs` has two local records and no
shared metacopy entry, and `tree-noverity.cfs` has one shared entry and none
local.

## tar

The `ostree export` command produces a plain filesystem tar of a commit's tree,
not an object-embedding format. The "ostree-in-tar" OCI format is a separate
`ostree-ext` (Rust) construct and is out of scope here.

Tar is a transport interface, not a content-addressed store: the correctness
contract is interoperability -- GNU tar and the `ostree` tool read what the port
writes, and the port reads what they write -- and round-trip stability, not
byte-identity of the tar stream. The tool and the port differ in tar dialect
(see below), so the same tree yields different bytes through each.

Observed `ostree export` output (tool version 2026.1, black-box):

- The archive is old-GNU-format tar: the header magic field at offset 257 is
  `ustar\x20\x20\x00` (`ustar` followed by two spaces and a NUL), not the POSIX
  `ustar\x00` plus `00` version.
- The tree root is the member `./`. Every other member is a bare relative path
  with no `./` prefix; directories carry a trailing slash.
- uid and gid are numeric; the octal mode field holds the permission bits only
  (the type is the tar typeflag). Every member's mtime is the commit timestamp,
  with a zero nanosecond part.
- Identical content is coalesced into hardlinks: the first member for a given
  content object is written in full (typeflag `0`), and a later member with the
  same content is a hardlink (typeflag `1`) whose link name is the first member.
  Symlinks are typeflag `2` with the target in the link name.
- This version emitted no PAX extended headers and no xattrs, even for a file
  that carried a `user.demo` xattr committed without `--no-xattrs`: the exported
  stream contained no `SCHILY.xattr.*` record by any encoding.
- The stream is padded to a full 10240-byte tar record (more than the two
  trailing zero blocks POSIX requires).

`ostree` import (`ostree commit --tree=tar=FILE`) commits an arbitrary
filesystem tar into the repository, deferring hardlink resolution to the end and
optionally applying the `/etc` -> `/usr/etc` convention.

### The tar import

The name a member is imported under drops one leading `./` and one leading `/`.
A directory member keeps its trailing `/`, and the archive's own root member
(`./`, or `/` before the strip) is the empty string. That name is what
`--tar-pathname-filter` receives and what the member is placed by.

Each member is placed under the directory the tree already holds, whether an
earlier member of the same archive or an earlier source in the list created it.
A member whose parent directory is absent is refused with
`error: No such file or directory: <name>`, naming the first absent ancestor by
its own name. The tree's root is not one of those ancestors: an archive naming
no root member leaves the root without metadata, which the commit reports as
`error: Can't commit an empty tree` where no other source supplied one, and
which is no error at all where one did.

Every member records the numeric ownership its header carries and the low 12
bits of its octal mode field, `mode & 0o7777`, under the file type the typeflag
states. Bits above those 12 are dropped, so a mode field holding a full
`st_mode` records the permission part alone: `0120777` gives `0777`, `0100644`
gives `0644`, and `0040755` gives `0755`. The setuid, setgid, and sticky bits
are kept.

A symlink member is read the same way. Its mode is the header's own permission
bits under `S_IFLNK`: header mode `0000` gives `l00000`, `0600` gives `l00600`,
`0755` gives `l00755`, `04777` gives `l04777`, and `07777` gives `l07777`. GNU
tar writes `0777` for every symlink member it packs, so an archive from that
writer carries that one value. The old-GNU, ustar, and pax header forms are
read alike: the same archive written in the three formats commits to one tree
checksum.
`--canonical-permissions` leaves a symlink's mode as the member left it,
matching the filesystem walk, so all of the values above survive the reduction
unchanged.

`--tar-autocreate-parents` supplies those directories instead of refusing:

- A missing intermediate parent is created with mode `0755`, empty extended
  attributes, and the ownership of the member whose import created it. Creating
  one rewrites the tree root's own metadata to the same mode and ownership,
  whatever the archive's root member recorded, and the last member to trigger a
  creation wins for every ancestor they share.
- A missing root with no such member is created with mode `0755`, owner `0:0`,
  and empty extended attributes.
- A synthesized directory takes no part in the commit modifiers, so
  `--owner-uid` shapes the member and not the parent its import created.

`--tar-pathname-filter=REGEX,REPLACEMENT` splits its value at the first comma:
everything before it is the expression, everything after it, further commas
included, is the replacement. The replacement is global -- every match in the
name is replaced -- and a member the expression does not match is imported
unchanged, so the option renames and never drops. A hardlink member's link name
is another member's name and goes through the filter too; a symlink's target is
not a member name and is left as it stands. Given more than once the last value
wins, and the value is read as an archive is loaded, so a command line naming no
`tar=` source carries a value neither reader accepts at exit 0. A value with no
comma reports `error: Missing ',' in --tar-pathname-filter` and an expression
that does not compile reports
`error: --tar-pathname-filter: Error while compiling regular expression
'<expression>' at char N: <reason>`, both at exit 1. The tool counts `N` in
characters and the port in code units, which `conformance/cli-surface.md`,
"P2", records.

The expression is a PCRE2 pattern, compiled with UTF and UCP on and the newline
convention set to `any`, and every other compile option at PCRE2's default. The
replacement is GLib's syntax: `\0` to `\9`, `\g<name>`, `\g<number>`, `\\`, the
seven control escapes `\n`, `\t`, `\r`, `\a`, `\b`, `\f`, and `\v`, and `$` as a
literal. A group the expression does not declare contributes nothing, and any
other replacement escape is refused. An empty match advances past one whole
character, which leaves that character in the name.
(`conformance/cli-surface.md`, "P2", states the dialect in full, together with
the four places the two implementations part.)

The commit modifiers reach an archive the way they reach a filesystem walk, with
one difference: `--canonical-permissions` records owner `0:0` and
`mode & 0o755` and leaves the extended attributes the archive carries, where the
filesystem walk drops them. `--no-xattrs` drops them for both.

Port import (`Repo::import_tar_into`) follows every rule above and reads into a
tree an earlier source already filled, so one archive composes with a filesystem
source and with a committed tree under one modifier.

Port export (`Repo::export_tar`) writes POSIX ustar/pax through the `smol-tar`
writer. It reproduces the tool's member naming (`./` root, bare relative names,
trailing slash on directories), numeric ownership, commit-timestamp mtimes, and
content-checksum hardlink coalescing (regular files only; symlinks are never
coalesced). It additionally emits each entry's extended attributes as
`SCHILY.xattr.<name>` PAX records with byte-exact values, so an xattr-bearing
tree survives an export/import round trip; a stored xattr name drops its
terminating NUL for the record and regains it on import. The `ostree` tool
re-imports a port export into a byte-identical tree (same dirtree and dirmeta
objects). Members the ostree object model cannot represent -- device nodes and
FIFOs -- are rejected on import, since a tree stores only regular files,
symlinks, and directories.

## bare-split-xattrs mode

The public documentation states that in this mode xattrs are stored as separate
repository objects and are not reflected to the filesystem, which serves
transport through lossy environments (tar streams, containers) and carries
security-sensitive xattrs (SELinux labels) out of band. The byte-level layout
below is recovered by observation: the `ostree` tool refuses to write this mode,
so a candidate repository is built by hand and confirmed by `ostree fsck`,
`ostree ls -X`, and `ostree checkout` accepting it and reproducing the xattrs.

Object identity is unchanged from every other mode:
`SHA256(6-field header ‖ payload)`, where the header
`(uid, gid, mode, rdev=0, symlink-target, xattrs)` carries the logical xattrs.
The split is a storage layout, not a new identity.

Storage:

- `.file`: bare inode storage. A regular file holds the raw payload on an inode
  bearing the logical uid, gid, and mode; a symlink is a real symlink. The inode
  carries no xattrs, and there is no `user.ostreemeta`. Because the inode carries
  the identity's uid/gid/mode, faithful writes need the ownership the identity
  encodes, as with `bare`.
- `.file-xattrs`: the GVariant `a(ayay)` xattr array in normal form -- the same
  bytes the identity header embeds -- named `SHA256` of those bytes. The empty
  set serializes to zero bytes, so its shared object is named
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  (`SHA256` of the empty input).
- `.file-xattrs-link`: named by the `.file` checksum, a hardlink to the file's
  `.file-xattrs` object. Present for every `.file`, including symlinks and files
  with no xattrs, which link to the shared empty-set object. The link is
  mandatory: removing it from an otherwise self-consistent commit makes
  `ostree fsck` mark the commit partial and fail (`Repository corruption
  encountered`) and `ostree ls -X` fail opening the object, so a missing link
  is a corrupt repository, not an empty xattr set. A reader treats its absence
  as a format error.

Reading recovers uid, gid, mode, and kind from the inode, and the xattrs from
the bytes at `<file-checksum>.file-xattrs-link` parsed as `a(ayay)`. Reading the
bytes at the link name needs no knowledge of the hardlink topology.

## Port extension: bare-user-shared mode

A development-only repository mode introduced by this port; it is not present
upstream. Production repositories (`/sysroot/ostree`) stay `bare`. This mode
supports building images in a group-shared repository on a multi-user build
host and serving as a composefs backing store.

Motivation. In `bare-user`, a stored object's inode permission bits are
derived from the file's logical mode (`(mode & (S_IFREG|0775)) | S_IRUSR`), so
a file with a restrictive logical mode (for example `/etc/shadow`, 0600)
produces an object other users sharing the repository cannot read: an object
one user commits cannot be loaded by the next, and the shared build fails.
This mode decouples the repository's at-rest permissions from the file's
logical permissions.

Storage. Identical to `bare-user` in every byte that carries identity:

- Object content is the raw payload. The logical uid, gid, mode, and xattrs
  live in the `user.ostreemeta` xattr as `(uuua(ayay))` (uid BE, gid BE, mode
  BE, xattrs sorted), as in `bare-user`.
- A symlink is stored as a regular file (content: target plus one NUL, as in
  `bare-user`). This representation is forced: Linux permits `user.*` xattrs
  only on regular files and directories (xattr(7)), so a real symlink cannot
  carry `user.ostreemeta`.
- Object identity is `SHA256(6-field header ‖ payload)`, unchanged from every
  other mode, so dirtree and commit hashes are byte-identical to `bare`, and
  a commit built in this mode and pulled into a bare production repository is
  the same commit.

The single behavioral difference from `bare-user`: the logical mode is never
applied to the inode. Objects are written with a fixed mode 0644 via explicit
`fchmod` (never trusting umask). Repository directories -- `objects/xx/`,
`tmp/`, staging directories -- are created with request mode 0777 reduced by
the umask. Group sharing of these directories is arranged at the filesystem
level: the operator sets the repository directory setgid 2775 with a default
group ACL (`setfacl -d -m g::rwx`) before `init`, and the OS propagates the
group, the setgid bit, and the group-write permission to every directory
created underneath, so every group member can read, deduplicate, and write
objects. `.lock` is written 0664, so every group member can open it for writing
and take the exclusive lock.

Mode string. `[core] mode=bare-user-shared`. The distinct string is a safety
fence: under a literal `bare-user` string the upstream tool would accept the
repository, and its hardlink checkout would propagate the fixed 0644 inode
mode in place of the logical mode; the unrecognized string makes the tool
refuse the repository outright.

Confidentiality. The repository does not preserve file confidentiality through
unix permissions at rest: any user with repository access can read any object.
The restrictive logical permissions are restored on materialization, and
outside access is gated at the repository root directory. This is an accepted
property of a shared development repository.

`ostree.sizes`. As in `bare-user`: never written. Size generation is an
archive-only mechanism (see the `ostree.sizes` notes in the commit-metadata
section), so cross-mode commit identity needs no mode-specific handling.

Checkout. Copy-based, with reflink (`FICLONE`) where the filesystem supports
it: a fresh copy is made and the `user.ostreemeta` mode is applied to it.
Hardlink checkout is refused, because the inode deliberately does not carry
the logical mode.

Integrity (fsck) and reachability (prune). As `bare-user`:
`SHA256(header-from-xattr ‖ payload) == object name`; no auxiliary objects
and no extra reachability edges. The inode mode is not authoritative and is
not checked.

composefs. This mode is the intended composefs backing store. The EROFS
metadata layer is built from the `user.ostreemeta` attributes (mode, uid,
gid, xattrs), and each regular file redirects to its `.file` loose path.
Per-file fs-verity is computed over the payload. Ownership is presented
through composefs uid mapping at mount time, so the real root-owned metadata
is correct even inside a rootless, non-root container.

## CLI output formats

The reading commands write to standard output, so their format is part of the
interoperability surface a script depends on, and `commit` states the commit it
made the same way. Each format below was recovered by running `ostree` 2026.1 as
a black box against repositories built for the purpose, and
`conformance/m10-cli-behavior.matrix` states the cells that hold the port's
output to the tool's. `conformance/cli-surface.md` lists the commands whose
formats are still to be recovered.

### The fsync vocabulary

One durability switch carries two spellings, and every command that takes
either one reads the rule stated here.

The valued spelling is `--fsync=POLICY`. `POLICY` is a boolean word, matched
without regard to case: `true`, `yes`, and `1` turn fsync on, and `false`, `no`,
and `0` turn it off. Every other value reports `error: Invalid boolean argument
'<value>'` on standard error and exits 1, quoting the value verbatim and the
empty value with it. The boolean spellings outside that set are refused as well:
`on`, `off`, and the single letters `t`, `f`, `y`, and `n`. The option requires a
value, so `--fsync` given none takes the next word on the command line as its
value and refuses that word. Where that word is itself an option, every word
after it shifts one position and the rest of the line is read in the shifted
positions; both readers reach the value reader all the same and name the
swallowed word, whether that word is an option the command holds
(`--orphan`, `--table-output`, `-I`), an option it does not hold (`--nosuch`,
`-Z`), or an option carrying a value (`--timestamp=@1700000000`,
`--owner-uid=abc`).

The option narrows the configured policy and never widens it. A repository
holding `[core] fsync=false` performs no `fsync`, `fdatasync`, or `syncfs` call
under `--fsync=true`; the resolved policy is the configured value and the option
value ANDed.

The counts below were measured with
`strace -y -f -e trace=fsync,fdatasync,syncfs` over a `commit` of corpus `C0`
into a fresh `archive` repository, under the single-component branch name
`main`. `C0` is the tree `corpus::basic` builds in
`crates/ostrya-conformance/src/corpus.rs`, and `conformance/README.md` lists
it: a 0644 regular file, a 0644 empty file, a 0755 directory holding one 0644
regular file, and a symlink. The commit writes 8 objects, which land in 8
distinct fanout directories. The tool's own counts:

```
[core] fsync   option           sync calls
unset (on)     --fsync=true     11  (9 fsync, 1 fdatasync, 1 syncfs)
true           --fsync=false     0
false          (none)            0
false          --fsync=true      0
```

The nine `fsync` calls are one per fanout directory the commit wrote into plus
one of `objects/`, so the count on the one row that syncs follows the corpus
and is a property of the writer and not of the format. The `fdatasync` is of
the ref's temp file, and the tool syncs no directory for the ref.

The port issues that same `syncfs`, those same fanout and `objects/` syncs, and
that same ref `fdatasync`, and adds the directory syncs a ref write needs: one
`fsync` of the directory holding the ref, plus one per directory the ref write
created for a `/`-bearing name, deepest first (see "Ref durability" above).
Under `main` the write creates no directory, so the port's count on the syncing
row is 12 (10 fsync, 1 fdatasync, 1 syncfs). Under `deep/nest/leaf` the write
creates `deep` and `nest`, which makes three directory syncs and a count of 14
(12 fsync, 1 fdatasync, 1 syncfs). The three rows that sync nothing are the
rule, and the port matches them exactly.

The valueless spelling is `--disable-fsync`, which equals `--fsync=false`. It
takes no argument, so an `=VALUE` suffix is read and discarded:
`--disable-fsync=false` disables fsync.

Both spellings default to fsync on. Neither changes a byte the command writes to
the repository. The same commit under `--fsync=true` and under `--fsync=false`
reaches one checksum and one object store; the count of `fsync`, `fdatasync`,
and `syncfs` calls is the whole observable difference.

Which command takes which spelling:

- `commit` and `checkout` document `--fsync=POLICY` and share the value set and
  the refusal text. `commit` also accepts `--disable-fsync`, which its `--help`
  does not list. `checkout` refuses `--disable-fsync` with `error: Unknown
  option --disable-fsync` at exit 1.
- `pull` and `pull-local` document `--disable-fsync` and refuse `--fsync` with
  `error: Unknown option --fsync=<value>` at exit 1.
- `--per-object-fsync` is a separate valueless flag on `pull` and `pull-local`,
  covering write scheduling and standing outside this vocabulary. `commit`
  refuses it with `error: Unknown option --per-object-fsync` at exit 1.

The option value is read after the configured value, so an option value never
conceals a configured one the reader refuses. A repository holding a `[core]
fsync` value that is not a key-file boolean is refused at exit 1 under
`--fsync=true`, under `--fsync=false`, and under no option at all, with no
object and no ref written. The narrowing above applies to the value the reader
returns, which requires that reader to run every time.

The port accepts `--fsync=POLICY` on `commit` with that value set, that refusal
text, and that narrowing rule; the resolved policy reaches the per-object
writes, the publication step, and the ref write alike. It reads the configured
`[core] fsync` under every state of the option, the way the tool does, and it
reads it while the other `[core]` keys are read, ahead of the editor and ahead
of the repository lock. It declines the undocumented `commit --disable-fsync`
(`conformance/cli-surface.md`, "P2").

The syscall counts a policy produces are the whole observable difference, and
the conformance matrix reads standard output, standard error, the exit status,
and the repository bytes alone, so no `run:` line can state them. Cell
`commit/fsync-syscalls` cites `commit_fsync_policy_controls_the_syscalls`
(`crates/ostrya-cli/tests/cli.rs`) instead, which measures the calls of both
binaries over the four rows above with `strace -y`. It holds the three quiet
rows to zero calls and the syncing row to the target of every call and to the
total this table records, 11 for the tool and 12 for the port, so the table and
the test stay one record. It asserts where `strace` is installed.

### `commit`

Prints the new commit's 64-character checksum and a newline, and writes nothing
to standard error, at exit 0.

A commit names a branch with `-b BRANCH` or carries `--orphan`, which permits a
commit that names none. A commit carrying neither reports `error: A branch must
be specified with --branch, or use --orphan` and exits 1. The check stands ahead
of `--parent`, ahead of the tree, and ahead of any object publication, so the same
line answers a commit whose `--parent` does not resolve and one whose tree path
does not open. A commit that names a branch writes the ref that name resolves
to: `refs/heads/BRANCH` for a bare name and `refs/remotes/REMOTE/NAME` for a
`REMOTE:NAME` value. A commit that names none writes no ref.

The parent:

- `-b BRANCH` with no `--parent` takes that branch's current tip. A branch that
  names no ref has no tip, so the first commit onto a fresh branch is a root
  commit. The tip is read from the ref file and not loaded, so a ref standing over
  an absent commit object is inherited unread.
- The tip is read before the transaction publishes, so the tip a commit inherits
  is the one its own ref write then replaces.
- `--parent=none` asks for a root commit on a branch that has a tip. The ref still
  moves to the new commit.
- `--orphan` suppresses the implicit parent the same way. With `-b` given the ref
  still moves, so the suppressed parent is the whole observable effect there. An
  explicit `--parent` alongside `--orphan` parents the commit on the value given.
- `--parent` takes a 64-character lowercase checksum or the literal `none`, and
  the checksum's existence is not checked: a `--parent` naming no object commits
  successfully. `none` is a literal in lowercase alone, so `NONE` is a revision.
- The tool refuses every other `--parent` value with the reader that takes a
  checksum: an abbreviated checksum, a refspec, and an empty value each report
  `error: Invalid rev <value>`, a checksum carrying an ancestry suffix reports its
  base (`--parent=<checksum>^` gives `error: Invalid rev <checksum>`), and a
  non-lowercase rendering reports `error: Invalid character '<byte>' in rev
  '<value>'`, naming the first byte it refuses by decimal value. The port resolves
  any revision there, which is a superset of that syntax, so a value the tool
  refuses is either resolved by the port or reported in the port's own resolution
  words (`conformance/cli-surface.md`, "P2").

The subject and the body are commit-object fields, so each form below reaches the
commit checksum.

- `-s/--subject=SUBJECT` sets the subject and `-m/--body=BODY` the body. Each is
  stored verbatim: no trimming, no newline normalization, and embedded newlines
  survive. Given more than once, the last value wins. A commit carrying a body
  and no subject is accepted, the subject field holding the empty string.
- `-F/--body-file=FILE` reads the whole file as the body, byte for byte, with no
  trailing-newline strip and no comment strip. An empty file gives an empty body.
  `-F` and `-m` together are accepted and `-F` wins, whichever comes first.
  `-F -` names a file called `-` rather than standard input. A path that does not
  open reports `error: openat(<path>): <reason>`, naming the path as it was
  given; a directory opens and then fails to read, so the reason stands alone,
  `error: Is a directory`; and content that is not UTF-8 or holds a NUL reports
  `error: Invalid UTF-8`. Each exits 1.
- `-e/--editor` writes a template to a temporary file, runs an editor over it,
  and takes the subject and the body from what the editor left. It replaces both
  outright, so `-m` and `-F` are discarded and `-F` is not even read; only `-s`
  reaches the template, as a prefill.

The editor is the first of `OSTREE_EDITOR`, `VISUAL`, and `EDITOR` that is set,
an empty value included, and `vi` where none is. `GIT_EDITOR` is not consulted.
The value is a shell command line rather than a program path: the temporary
file's path is appended to it shell-quoted and the whole line runs under
`/bin/sh -c`, so the shell expands variables and globs in it and reports its own
faults. The temporary file lives in `TMPDIR` (`/tmp` by default), is named `.`
and six characters, and is removed after the run. It is created readable and
writable by its owner alone, mode 0600, so no other local user can read the
message while it is being edited. The editor runs after the branch check, after
`--parent` resolution and after the metadata options are read, and before the
tree opens and before the timestamp is read.

The template, for a commit naming branch `BR`:

```
\n
# Please enter the commit message for your changes. The first line will\n
# become the subject, and the remainder the body. Lines starting\n
# with '#' will be ignored, and an empty message aborts the commit.\n
#\n
# Branch: BR\n
```

Under `--orphan` the last two lines are absent and the file ends after
`commit.\n`. A `-s` value and one newline are appended after the block, so the
prefilled subject sits at the end of the file.

The file the editor leaves is read under the rules `-F/--body-file` states: a
byte that is not UTF-8 and a NUL both report `error: Invalid UTF-8`, and a file
the editor removed reports `error: openat(<path>): <reason>`, naming the
temporary file. Each exits 1.

The edited text is read by these rules, in this order: every line loses its
trailing whitespace; a line whose first character is `#` is dropped, so a `#`
behind leading whitespace is not a comment; the leading blank lines go and the
first line left is the subject; and the lines after it, less their own leading
and trailing blank lines, are the body, joined by newlines, with the interior
blank lines kept. An empty subject reports `error: Aborting commit due to empty
commit subject.` and exits 1, which is what an unmodified template and a
whitespace-only message both reach.

A non-zero editor exit aborts the commit and discards what the editor wrote, so
no ref and no commit object are produced. The message carries no separator
between the quoted editor value and the reason, which is the tool's own wording:

```
error: There was a problem with the editor '<EDITOR>'Child process exited with code <N>
```

The process exits 1 whatever `<N>` is.

The commit metadata dict is an `a{sv}`, and its entry order is part of the
commit checksum, the dict being serialized in insertion order rather than
sorted. The order is fixed and does not follow the command line:

1. the keys the tree walk derives before the commit is assembled, `ostree.linux`
   then `ostree.bootable`;
2. the user keys, group by group: every `--add-metadata-string` in command-line
   order, then every `--add-metadata`, then every `--keep-metadata`;
3. the binding keys, `ostree.ref-binding` then `ostree.collection-binding`;
4. the keys the commit assembly appends, `ostree.composefs.digest.v0` then
   `ostree.sizes`.

A key given twice is written twice: the dict really carries two entries of that
name, and a user key may carry a name a binding key uses, which puts the two
side by side. Two of the derived keys are exceptions:

- `--bootable` removes every entry the command line supplied under
  `ostree.linux` or `ostree.bootable`, so a commit carrying `--bootable
  --add-metadata-string=ostree.linux=9.9.9` reaches the same object as one
  carrying `--bootable` alone.
- `--generate-composefs-metadata` stores the digest in the slot an entry named
  `ostree.composefs.digest.v0` already stands in, whichever of groups 2 and 3
  put it there, and removes every later entry of that name. The dict therefore
  holds the derived digest once, ahead of the binding keys, and group 4 gets the
  entry only where nothing else supplied the name. A supplied value reaches this
  through any of `--add-metadata-string`, `--add-metadata`, and
  `--keep-metadata`.

`ostree.sizes` takes no such treatment: `--generate-sizes` appends its entry
whatever the dict holds, so a commit naming both the option and
`--add-metadata-string=ostree.sizes=...` carries two entries of that name.

The tool holds the dict in a hash-ordered container while `--bootable` or
`--generate-composefs-metadata` is given, so with either of those the order of
the whole dict follows the key set rather than the list above. The port keeps
the list above in every case; `conformance/cli-surface.md`, "P2" records the
divergence and the key sets that expose it.

- `--add-metadata-string=KEY=VALUE` splits at the first `=`, so a value may hold
  further ones, and stores the value as an `s`. An empty value is accepted.
- `--add-metadata=KEY=VALUE` splits the same way and reads the value in the
  GVariant text form (see "The GVariant text form" above). The parsed value is
  stored in host byte order and is not converted, so a numeric value reads back
  byteswapped through `show --raw` and `show --print-metadata-key` and correctly
  under `-B`.
- `--keep-metadata=KEY` carries a key over from the resolved parent, byte for
  byte. The resolved parent is `--parent` where it is given, `--orphan
  --parent=<checksum>` included, and the branch tip otherwise.
- `--add-detached-metadata-string=KEY=VALUE` writes an `a{sv}` to the commit's
  `.commitmeta` file, in command-line order and with duplicates kept. It leaves
  the commit checksum alone, so the same tree under it and without it reaches one
  object.

The refusals, each at exit 1:

- an argument holding no `=` reports `error: Missing '=' in KEY=VALUE metadata
  '<argument>'`, from all three options;
- an empty key reports `error: Empty metadata key`, from
  `--add-metadata-string` and `--add-metadata`. An empty key is accepted by
  `--add-detached-metadata-string`;
- a value the GVariant text reader refuses reports `error: Parsing
  <KEY>=<VALUE>: <spans>:<reason>`, naming the whole argument and reporting
  offsets into the value alone;
- a `--keep-metadata` key the parent does not hold reports `error: Missing
  metadata key '<key>' from commit '<checksum>'`;
- a `--keep-metadata` with no resolved parent reports `error: Either --branch or
  --parent must be specified when using --keep-metadata`, whether the parent is
  absent because no branch was named, because the branch has no tip, or because
  `--parent=none` was given.

Their order, each fault observed alone and in pairs, is: the branch check; the
declared-id conflict; `--parent` resolution; the `--keep-metadata` missing-parent
check; the `--add-metadata-string` missing `=`; the `--add-metadata` missing `=`
and its value parse; the `--add-detached-metadata-string` missing `=`; the
`--keep-metadata` missing key; the body file; the editor; the tree; the
timestamp; and last the empty-key check, which the dict assembly makes.

`ostree.ref-binding` is an `as` holding the branch `-b` named together with
every `--bind-ref=BRANCH` value, sorted byte-wise ascending with duplicates kept.
The sort is over bytes rather than a locale collation, so uppercase sorts ahead
of lowercase and `10` ahead of `2`. A commit that names no branch carries the
empty array, and the key is present in that case too. No character-class check
reaches a `--bind-ref` value: a name holding a space, a double slash, a leading
`-`, a caret, a leading dot, a trailing slash, a tab, the empty name, and the 64
lowercase hex characters `-b` refuses are all recorded as they stand, so the
branch-name guard covers the ref the command writes and not the name it records.
`--bind-ref` is accepted beside `--orphan`, where the array holds the bound names
alone; `--bind-ref` alone names no branch, so a commit carrying it and neither
`-b` nor `--orphan` draws the missing-branch line.

`--no-bindings` writes no binding key at all -- an absent key rather than one
holding an empty array -- and removes `ostree.collection-binding` with it. It
overrides `--bind-ref`, so `commit -b X --no-bindings`,
`commit --orphan --no-bindings`, and `commit -b X --no-bindings --bind-ref=Y`
over one tree at one timestamp reach one commit object. It suppresses the
automatic key alone: a binding added by `--add-metadata-string` or carried by
`--keep-metadata` survives it.

`ostree.collection-binding` is an `s` holding the repository's `[core]
collection-id`, written after `ostree.ref-binding` in a repository that has one.
`--bind-ref` does not touch it.

The declared ownership. `--owner-uid=UID` and `--owner-gid=GID` replace the
ownership every ingested entry records, independently of each other: the tree
root's own metadata, every nested directory, every regular file, and every
symlink. The permission bits and the xattr set are untouched. Each value is read
as a C `int` with the base taken from its text -- a `0x` prefix hexadecimal, a
leading `0` octal, decimal otherwise -- after optional leading whitespace and an
optional sign, and the whole text must be consumed. The default for both is `-1`,
so a negative value declares nothing and the source's own ownership stands
(`--owner-uid=-1` and `--owner-uid=-2` alike; `-0` is the id zero). Recovered by
committing one tree under each form and comparing commit checksums: `0x2a` and
`053` are the ids `42` and `43`, `010` is `8`, and a declared id reaches the
checksum in every repository mode, `bare-user-only` included, which stores no
ownership yet hashes what was declared.

A value no C `int` holds is refused while the options are read, ahead of the
repository and ahead of every check the subcommand makes, at exit 1: `error:
Cannot parse integer value “<value>” for --owner-uid` for a syntax the reader
cannot hold (`abc`, an empty value, `5x`, a trailing space, `0x`, `--5`), and
`error: Integer value “<value>” for --owner-gid out of range` above `2147483647`
or below `-2147483648`. Both messages quote the value in typographic quotes
(U+201C and U+201D).

`--no-xattrs` records the empty xattr set for every entry, the tree root
included, whatever the source carries.

`--timestamp=TIMESTAMP` sets the commit timestamp, and wins over
`SOURCE_DATE_EPOCH`, which the tool otherwise honors. The tool reads the value
with a full natural-language date reader; the forms recovered by commit-checksum
comparison are `@SECONDS` since the epoch (an optional sign and an optional
fractional part, which is dropped: `@1234567890`, `@-1`, `@0.5`, `@ 0`, `@+5`),
an absolute date and time in ISO 8601 or a space-separated rendering with or
without a UTC offset (a value without one naming the tool's own local time), a
ctime-style rendering, a relative expression (`now`, `yesterday`), and an empty
value, which is today's midnight. A bare count of seconds is refused
(`--timestamp=1234567890`), as is `@` alone and `@1e3`. A refused value reports
`error: Could not parse '<value>'` at exit 1, in single quotes rather than the
typographic pair the integer messages use. A pre-epoch instant is recorded as the
unsigned timestamp field's two's-complement form, so `@-1` and
`1969-12-31T23:59:59Z` are one commit.

`--fsync=POLICY` sets the durability of the writes the commit makes, and takes
the vocabulary above. The policy reaches the per-object writes, the publication
step, and the ref write, and it changes no byte the repository stores, so a
commit made under either policy prints one checksum and leaves one object store.

`--table-output` replaces the checksum line with a seven-line `KEY: VALUE` block
on standard output. The field names, their order, and their count are fixed. A
field carries one space after its colon, no padding, and no unit; every line
ends with a newline and no trailing space. Standard error stays empty and the
exit status is 0. Corpus `C0` committed into an empty `bare` repository with
`-b conformance -s x --timestamp=@1700000000`:

```
Commit: 7f00c81575e97a12c9d34d44c232e56236d40be76fd457abd2d6d829d7f05592
Metadata Total: 5
Metadata Written: 4
Content Total: 4
Content Written: 4
Content Cache Hits: 0
Content Bytes Written: 45
```

That corpus holds two directories that share one dirmeta, three regular files of
23, 0, and 22 bytes, and one symlink. Corpus `C0` is described in
`conformance/README.md`. The fields:

- `Commit` -- the new commit's checksum, the value the plain form prints alone.
- `Metadata Total` -- the metadata objects the commit offered to the object
  store, counted before dedup, with each directory's dirmeta counted for that
  directory: two dirtree, two dirmeta, and the commit object.
- `Metadata Written` -- the metadata objects stored. The two directories share
  one dirmeta, so the count is two dirtree, one dirmeta, and the commit object.
- `Content Total` -- the content objects the commit offered, counted before
  dedup. An object a devino-cache hit resolves is never offered, so it leaves
  this count.
- `Content Written` -- the content objects stored.
- `Content Cache Hits` -- the content objects a devino-cache hit resolved.
- `Content Bytes Written` -- the payload byte counts of the stored regular
  files, summed before any compression the mode applies: 23 + 0 + 22 here. A
  symlink contributes nothing, and the count is the payload length rather than
  the stored `.filez` length, which for a random payload runs larger.

A second commit of a tree the repository already holds keeps both totals, prints
`Metadata Written: 1` for the commit object, and prints zero for every content
field. The block's shape holds across `archive`, `bare`, and `bare-user`.

`--statoverride=PATH` names a file of mode changes, one entry per line:

```
[=]<decimal mode><one space><absolute in-tree path>
```

A sample, and what it does to a tree holding `/plain.txt` at 0644, `/dir2/b.txt`
at 0644, `/grpx` at 0754, and `/dir1` at 0700:

```
=384 /plain.txt
=448 /dir2/b.txt
8 /grpx
=511 /dir1
```

`/plain.txt` becomes 0600, `/dir2/b.txt` becomes 0700, `/grpx` stays 0754
(decimal 8 is 0o10, which its mode already carries), and `/dir1` becomes 0777.
The reading rules:

- The mode is read in base 10, with an optional leading sign. A leading `=`
  states the permission bits, giving `(mode & S_IFMT) | value`; without it the
  value is ORed into the mode, giving `mode | value`. The file-type bits
  therefore survive both forms, and a value carrying bits inside the file-type
  field renames the type the mode holds.
- The tool reads the field through a C `double` reader, so it also takes a
  hexadecimal literal (`0x1ff` gives decimal 511, which is 0777), a decimal
  point and an exponent (`1e3` gives decimal 1000 and `.7e3` gives decimal 700,
  which over a 0644 file reach 01754 and 01674), and turns a
  value past the 32-bit range into `0x80000000` (`inf`, `nan`, `1e100`,
  `4294967296`, and `4294967295` all give mode 020000000644 over a 0644 file).
  Those forms sit outside the documented format, which is a mode in decimal, and
  the out-of-range conversion is platform-defined. The port reads decimal alone;
  the difference is recorded in `conformance/cli-surface.md`, "P2".
- The separator is exactly one space (0x20). Everything after it is the path,
  further spaces included. A tab is not a separator.
- The path is absolute and rooted at the committed tree, with no trailing slash.
  `/`, `/plain.txt`, and `/dir1/sub/deep.txt` all match; `plain.txt`,
  `./plain.txt`, and `/dir1/` never do.
- An entry applies to exactly one entry of the tree and is not recursive. The
  `=` form applies to regular files, to directories, to symlinks, and to the
  walk root, and it applies in every source that offers the path.
- The OR form reaches one entry of the tree per run. The first entry any source
  offers under the path spends the entry, and a later source under that path
  keeps the mode it brought. A directory below the walk root spends the entry
  and takes no value from it, leaving the mode as the source found it; an
  archive member is the exception, where the OR value reaches a directory as
  well. Over `/dir1` at 0700, `16 /dir1` gives 0700 from a `dir=` walk and from
  a `ref=` source, 0720 from a `tar=` source, and `=8 /dir1` gives 0010 from all
  three. Over two sources that both hold `/dir1` at 0700, `16 /dir1` with
  `--tree=dir=A --tree=tar=B` gives 0700, the walk having spent the entry before
  the archive offered the path, and with `--tree=dir=C --tree=tar=B`, where `C`
  holds no `/dir1`, gives 0720. A spent entry counts as reached, so it draws no
  unmatched report.
- A mode field holding no digit is the value zero, so `abc /plain.txt` changes
  nothing and `= /plain.txt` gives mode 0.
- Blank lines are ignored, a missing final newline is accepted, and there is no
  comment syntax.
- A path may be named more than once. Each form keeps one entry per path, the
  value of the last line naming the path, and the OR form stands ahead of the
  `=` form: where a path carries an entry of each form, the OR value alone
  reaches the mode, whichever order the file states the two lines in. Over a
  0644 file: `8 /f` then `16 /f` gives 0664, `=448 /f` then `=511 /f` gives
  0777, `448 /f` then `=511 /f` gives 0744, `=511 /f` then `448 /f` gives 0744,
  `=511 /f` then `0 /f` gives 0644, and `1 /f`, `=448 /f`, `2 /f` gives 0646.
  Over a directory below the walk root of a `dir=` walk or of a `ref=` source
  the OR form states no mode, so the `=` entry reaches it: over `/dir1` at 0700,
  `16 /dir1` then `=8 /dir1` gives 0010. Over an archive member the OR form
  states a mode, so it stands ahead as it does elsewhere and the same pair gives
  0720.
- The option given more than once takes the last value; the earlier files are
  not read at all.

`--skip-list=PATH` names a file of paths to leave out, one absolute in-tree path
per line:

```
/plain.txt
/dir2
```

A listed directory prunes its whole subtree, so `/dir2` removes `/dir2/b.txt`
with it. A symlink can be listed. Blank lines are ignored, and the option given
more than once takes the last value. A path may be named more than once and
counts as one entry, which the unmatched report below states once. The path
spelling is exact: a trailing space, a missing leading slash, and a trailing
slash all match nothing. Listing every child of the root gives a commit whose
tree holds the root alone. Listing `/` prunes the walk root, which leaves nothing
to commit, and reports `error: Can't commit an empty tree` at exit 1. With
`--base` the base is still the bottom layer under a pruned walk root, so the
commit is written and holds the base tree unchanged. The pruned walk accounts no
object, so such a commit carries no `ostree.sizes` key even under
`--generate-sizes`. The tool carries two steps under the pruned walk that the
port leaves out: `--consume`
attempts the source removal, which takes an empty source directory away and over
one holding an entry reports `error: unlinkat(<path>): Directory not empty`; and
a `tar=` source is read, so a file that is not an archive reports `error:
archive_read_open_filename: Unrecognized archive format`. Both are recorded in
`conformance/cli-surface.md`, "P2".

Both files are checked for entries the walk never reached. Every `--skip-list`
entry is checked; only the `--statoverride` entries without a `=` are, so an `=`
entry matching nothing is ignored. A path the skip list prunes counts as
reached, the walk reaching the entry and pruning it there: over a skip list
holding `/dir1`, both that entry and a `16 /dir1` statoverride entry are
matched. A path inside a directory the skip list pruned counts as unmatched, the
walk never having descended into it: over the same skip list, `/dir1/a.txt`,
`/dir1/sub`, and `/dir1/sub/deep.txt` are unmatched in either file. A path
neither file's walk reaches at all is unmatched, so a path both files name that
the tree does not hold draws a report. The walk root counts as reached, so over
a skip list holding `/` a `16 /` statoverride entry is matched and the
empty-tree refusal is left alone to report. The order the command line gives the
two options changes none of this. The report is one line per unmatched path and
then a summary line, on standard error, at exit 1, with standard output empty
and no ref written:

```
Unmatched statoverride path: /nope.txt
error: Unmatched statoverride paths
```

```
Unmatched skip-list path: /nope.txt
error: Unmatched skip-list paths
```

The `<path>` is the raw text after the first space, so ` 448 /plain.txt` reports
`Unmatched statoverride path: 448 /plain.txt`. A path named more than once by
either file gets one line, and an `=` entry over a path an OR entry also names
adds no line of its own. The statoverride check stands ahead of the skip-list
check whichever order the command line gives the two options, and both stand
ahead of the empty-tree refusal. The tool emits the per-path lines in a hash
order rather than the file order, which `conformance/cli-surface.md`, "P2"
records as a divergence.

A statoverride line with no space is refused before the walk with `error:
Malformed statoverride file (no space found)`. A control file that does not open
is refused with `error: openat(<path>): <reason>`, naming the path as the command
line spelled it, and a directory with `error: Is a directory`, which carries no
path. An empty file of either kind is accepted and changes nothing.

Either control file must hold UTF-8, and a NUL byte counts as invalid. A single
invalid byte anywhere in the file reports `error: Invalid UTF-8` at exit 1, and
that check stands ahead of everything else the command does: ahead of the walk,
ahead of the unmatched-entry report of the other control file, and ahead of a
tree path that does not open. Both files are checked, and the report names
neither the file nor the line.

`--mode-ro-executables` clears the write bits of every executable regular file:
where `mode & 0o111` is non-zero, `mode &= ~0o222`. Any one of the three execute
bits triggers it and all three write bits go, so 0766 becomes 0544 and 0621
becomes 0401. The setuid, setgid, and sticky bits survive: 04755 becomes 04555
and 01777 becomes 01555. A regular file with no execute bit is untouched, and so
are directories, a world-writable one included, and symlinks.

The three mode modifiers run in a fixed order: `--mode-ro-executables`, then
`--statoverride`, then the `--canonical-permissions` reduction. The first two
commute with each other, one being an AND mask and the other testing bits the
mask keeps; `--statoverride` is the one that assigns or ORs, so it is the pair
with the reduction that shows the order. Over a tree holding `/f0644` at 0644,
`/f0700` at 0700, `/f0555` at 0555, and `/dir1` at 0700, beside
`--canonical-permissions`:

- `=511 /f0644` gives `-00755`, the reduction masking the 0777 the entry states.
- `=2048 /f0700` gives `-00000`, the setuid bit the entry states not surviving
  the mask.
- `146 /f0555` (decimal 146 is 0o222) gives `-00755`.
- `=511 /` gives `d00755` for the root, and `=511 /dir1` gives `d00755`.

The reverse order would give 0777, 04000, 0777, and 0777. Without
`--canonical-permissions`, `--statoverride` holding `146 /roexec` over a 0555
file reaches 0777 rather than the 0555 the reverse order against
`--mode-ro-executables` would give.

`--skip-if-unchanged` compares the walked tree against the resolved parent -- the
commit `--parent` names, else the tip of `--branch`. Both the root contents
checksum and the root metadata checksum take part; the commit's own metadata does
not, so a different `-s` or an added `--add-metadata-string` over an unchanged
tree is still skipped. Where the two match, the parent's checksum is printed on
standard output with a trailing newline, standard error stays empty, the exit
status is 0, and no ref is written: a ref that existed stays where it stood and
one that did not is not created. Where there is no parent -- a fresh branch,
`--parent=none`, or `--orphan` -- the commit is written as usual. The walk runs
either way, so an unmatched `--statoverride` entry still fails the command at
exit 1.

The derived metadata. Three options read the tree the commit carries and store
what they find in the commit's own metadata dict.

`--generate-sizes` writes `ostree.sizes` (see "Metadata object formats"). An
archive repository alone holds the key; in `bare`, `bare-user`, and
`bare-user-only` the option is accepted, writes no key, prints nothing on
standard error, exits 0, and leaves the commit checksum equal to the same commit
without it. Over a single source the key covers the whole tree, so a second
commit onto a branch lists the objects that deduplicated against the first as
well. The option reaches the tar form too: `--tree=tar=PATH` produces the key the
same way.

Over a source list the key is scoped, and the scope is what a multi-source
commit's checksum turns on. Recovered by reading the key back over ten source
lists, each entry matched against the objects `ls -R -C` reports for the tree:

- a content object counts where the LAST `--tree` source contributed it. A
  content object an earlier source contributed leaves the key even where it
  survives into the committed tree, so `--tree=dir=t1 --tree=dir=t2` lists only
  `t2`'s files and `--tree=dir=t1 --tree=dir=<empty directory>` lists no file at
  all;
- a directory object counts where any source contributed it or the tree
  serialization wrote it, and it stays as later sources open;
- a `--base` layer contributes nothing, so a subtree that reaches the commit
  from the base unread is absent from the key;
- a `ref=` source contributes every object of its own tree, whether the overlay
  reads it or reuses the stored checksum;
- the key is then narrowed to the objects the committed root reaches, so an
  object a later source replaced is absent whatever contributed it.

The port carries this as `Transaction::begin_tree_source`, called once per
`--tree` source.

`--bootable` writes `ostree.linux` and `ostree.bootable`. The value of
`ostree.linux` is the name of the one directory under `/usr/lib/modules` in the
committed tree that holds an entry named `vmlinuz`. The rule, each shape
observed:

- the search is exactly one level deep: a `vmlinuz` directly under
  `/usr/lib/modules`, and one nested a further level down, are both unseen;
- the entry's type is not read: a regular file, a symlink whose target the tree
  does not hold, and a directory named `vmlinuz` each count as a kernel;
- an entry under `/usr/lib/modules` that is not a directory takes no part, so a
  stray file there and a symlink to a kernel directory are both ignored;
- an initramfs is neither required nor consulted.

The tree the option reads is the committed tree, so `--skip-list` pruning
`/usr/lib/modules` leaves no kernel to find. The five refusals, each on standard
error at exit 1 with standard output empty and no object published:

```
error: No such file or directory: /usr
error: No such file or directory: /usr/lib
error: No such file or directory: /usr/lib/modules
error: No kernel found in /usr/lib/modules
error: Multiple kernels found in /usr/lib/modules
```

The first three name the first component of the path the tree does not hold. A
component the tree holds as something other than a directory reports `error: Not
a directory`, which carries no path. Reference build 2026.1 reaches that message
for `/usr` and `/usr/lib` and dies on an assertion where `/usr/lib/modules`
itself is the non-directory, a regular file and a symlink alike
(`conformance/cli-surface.md`, "P2").

`--generate-composefs-metadata` writes `ostree.composefs.digest.v0`, an `ay`
holding the 32-byte fs-verity digest of the tree's composefs image (see
"composefs"). The image derives from the committed tree alone, so a repository in
`archive`, `bare`, or `bare-user` holding one tree reaches one digest and one
commit checksum; `bare-user-only` canonicalizes the tree and so reaches another.

The three stand after the walk. Their order against the rest, each fault observed
alone and in pairs: the control-file reports, the empty-tree refusal, and
`--skip-if-unchanged` all stand ahead of the kernel search, so an unchanged tree
under `--bootable --skip-if-unchanged` prints the parent's checksum and exits 0
whether or not the tree holds a kernel. The kernel search stands ahead of the
timestamp and ahead of the empty-key check.

#### The tree sources

The tree a commit records is built from an ordered source list:

1. `--base=REV`, where one is given, is the bottom layer.
2. Each `--tree=KIND=VALUE` in command-line order overlays the result.
3. Where no `--tree` is given, the positional `PATH` is the one source.

A positional `PATH` beside any `--tree` is ignored: it is not opened, not
stat'ed, and the command exits 0. Every positional after the first is ignored
the same way.

`--tree` splits its value at the first `=`. The part before it names the kind
and the part after it is the value:

- `dir=PATH` -- a directory on the filesystem, opened no-follow, so a symlink
  naming a directory is refused. A trailing slash is accepted.
- `tar=PATH` -- an archive. `-` and `/dev/stdin` name standard input.
- `ref=REV` -- any revision a `rev-parse` reads: a ref name, a checksum, or
  either with a `^` ancestry suffix. The `REF:/path` subtree syntax is not a
  revision and is refused as an invalid refspec.

Overlaying is a recursive per-path merge, and the later source wins:

- Directory over directory: the children union, so a child only the earlier
  source held survives.
- Directory metadata: the later source's dirmeta replaces the earlier one
  whole. The extended attributes are replaced with it and are never unioned.
- File over file: the later file replaces the earlier one whole.
- A name that is a directory in one source and a file in another is refused:
  `error: Can't replace directory with file: <name>` where the later source
  holds the file, and `error: Can't replace file with directory: <name>` where
  it holds the directory. The name is the entry's own name and not its path, so
  `n1/a/b/p` against `n2/a/b/p` reports `p`. Both exit 1 and write no commit.

`--base=REV` differs from `--tree=ref=REV` in one way: no commit modifier
reaches an entry that survives from the base, so such an entry keeps the mode,
the ownership, and the extended attributes the base recorded, where an entry
from any `--tree` -- `ref=` included -- is shaped by `--owner-uid`,
`--owner-gid`, `--canonical-permissions`, `--no-xattrs`, `--statoverride`,
`--skip-list`, and `--mode-ro-executables`. `--base` is applied first whatever
its position on the command line, given more than once keeps the last value,
and is legal with no `--tree` beside it.

`--consume` empties each filesystem source as that source is walked, before the
commit object is written and before the ref moves, so a later failure leaves the
files gone and no commit made. It removes the source directory itself as well,
unless the path is spelled exactly `.`; the test is on the text the value
carries, so `./` and an absolute path naming the working directory are both
removed. It empties the source whatever a walk filter kept out of the commit: a
path `--skip-list` names is removed with the rest, and the tree it sits in is
removed too, so the commit is written and the whole source is gone. A removal
that fails aborts the commit and reports the entry's own name as
`unlinkat(<name>): <reason>`, so a source holding a mode-0500 directory reports
`unlinkat(<entry inside it>): Permission denied` at exit 1, `--consume .` from
the parent directory succeeds, and `--consume ./` from inside the directory
reports `unlinkat(./): Invalid argument` at exit 1. The option has no effect on a
`ref=` or a `tar=` source, which are left as they stand.

A source list that supplies no root directory leaves nothing to write and
reports `error: Can't commit an empty tree` at exit 1.

The fault order among these options, each fault observed alone and in pairs: the
declared ids and the fsync policy are read first, ahead of the repository and
ahead of the missing-branch check; then the `--statoverride` file and the
`--skip-list` file, in that order, whose open, read, and syntax faults all stand
here; then the missing-branch check; then the
refusal of a non-zero declared id beside `--canonical-permissions` (`error:
Cannot specify both --canonical-permissions and non-zero --owner-uid`, naming
`--owner-uid` where both are non-zero, and accepting a declared zero); then
`--parent` resolution; then the metadata options and the body file; then
`--base` resolution; then the sources, one at a time and in order, each opened
as it is reached, so a source `--consume` has already emptied stays gone when a
later one does not open; then the timestamp. A refused timestamp publishes no
object, so the object store is empty afterwards, unlike the branch-name guard,
which stands after the tree is written. A refused timestamp does not put back
what `--consume` removed. Inside the first step the tool reads the options in
command-line order, so an invocation carrying both a refusable id and a
refusable policy reports the leftmost of the two.

#### Signing

Five options sign the commit the invocation writes. Their signatures land in the
commit's detached metadata under the rules "Signing details" states, before the
ref moves.

- `--gpg-sign=KEY-ID` adds one `ostree.gpgsigs` element per occurrence, in
  command-line order, with no deduplication. The key id is resolved by the
  GnuPG installation, in the home directory `--gpg-homedir` names or the one
  GnuPG resolves for itself, which honors `GNUPGHOME`. The selector must be at
  least eight bytes long and must name exactly one secret key; the three
  outcomes each carry their own line, below.
- `--gpg-homedir=HOMEDIR` names the home directory `--gpg-sign` resolves its
  keys in, and it wins over `GNUPGHOME`. In the port it names the same
  directory for `--sign` and `--sign-from-file` under `--sign-type=gpg`, an
  engine this tool build does not carry
  (`../conformance/cli-surface.md`, "P2"). Alone, with no key to resolve, it is
  accepted and changes nothing.
- `--sign=KEY_ID` adds one signature per occurrence under the engine
  `--sign-type` names, in command-line order, with no deduplication. For
  `ed25519` the value is the base64 of the 64-byte secret key.
- `--sign-from-file=PATH` adds one signature per occurrence, its key read from
  the first line of the file. The rest of the file is ignored, a trailing
  newline is optional, and surrounding whitespace is skipped by the decode.
- `--sign-type=NAME` names the engine `--sign` and `--sign-from-file` use. It
  defaults to `ed25519`, the match is exact and case sensitive with no
  trimming, and the last occurrence wins. It does not reach `--gpg-sign`, whose
  engine is fixed.

`--sign` and `--sign-from-file` are two lists, not one. Every `--sign` key signs
first and every `--sign-from-file` key after it, whatever the command line's
order, and both stand before the `--gpg-sign` keys.

The base64 decode a `--sign` value goes through skips every character outside
the alphabet, so a value holding prose decodes to some byte count rather than
failing as text. A padding character counts toward its group and carries the
value zero. Three bytes come out of each complete four-character group, and each
of that group's last two characters that is a padding character removes one of
them again; a trailing group short of four characters contributes nothing.
Padding therefore acts per group and per position:

- `AAAA=` decodes to three bytes, the padding character opening an incomplete
  group.
- `AAA=` decodes to two and `AA==` to one.
- `AA=A` decodes to two, the padding character sitting third in a complete
  group, and `A=AA` to three, it sitting second.
- `AA==AA==` decodes to two, one byte from each of its two groups.
- `AAAAAAA====` decodes to five.

A decoded length other than 64 reports `error: Invalid ed25519 secret key:
Ill-formed input: expected 64 bytes, got N bytes`, naming the length it reached,
so `--sign=zzz` reports zero bytes and `--sign=not-base64!!!` reports six. One
stray character appended to a pasted 88-character key opens an incomplete group,
so the key still decodes to 64 bytes and signs.

`--sign-from-file` reads the first line as bytes and places no encoding
requirement on it, so a line holding a byte sequence that is not UTF-8 reaches
the decode and its alphabet characters carry the result. A NUL byte ends the
line ahead of the newline: a file whose first line is `AAAA\0BBBB` yields the
key `AAAA` and reports three bytes.

The other refusals, all at exit 1 with standard output empty and no object
published:

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

The three GPG lines answer the three `--gpg-sign` outcomes. A selector under
eight bytes draws the "Invalid value" line without a key lookup, whatever it
would have named, so `--gpg-sign=` and a short user-id substring both draw it. A
selector of eight bytes or more goes to the key lookup, which accepts every
spelling GnuPG accepts -- a short key id, a long key id, a fingerprint in either
case, a `0x` prefix, a trailing `!`, a bare email, a `<email>` or `=uid` exact
form, and a user-id substring. A selector naming no secret key draws the "No gpg
key found" line, and one naming more than one draws the "ambiguous" line. A
selector shaped like a GnuPG option is a key selector like any other: it names no
secret key and draws the "No gpg key found" line, and the home directory such a
selector spells out is not opened and gains no keybox and no trust database. The
port reaches the same outcome by passing the selector after a `--` terminator,
which is what holds it to a key name.

The homedir term of the two lookup lines is the `--gpg-homedir` path, or the
literal `<default>` where the option is absent. A home directory that does not
exist, one that cannot be read, and one holding no matching key all draw the
"No gpg key found" line. The last line answers `--sign-from-file=` with an
empty path. The `<path>` term of the two file-open lines is the absolute path in
the tool and the path as the command line gave it in the port
(`../conformance/cli-surface.md`, "P2").

The signing step's own fault order, each fault observed alone and in pairs:
`--sign-type` is read first, then every `--sign` key in order, then every
`--sign-from-file` path in order, then every `--gpg-sign` key in order.
`--sign-type` is read only where `--sign` or `--sign-from-file` names a key, so
a name no engine carries commits successfully in a run that signs nothing, and
`--gpg-sign` alone is unaffected by it.

The step as a whole stands after the tree is written and after the branch-name
guard, and before the ref write and the publication. So a tree path that does
not open, a refused timestamp, and a branch name the guard refuses each win over
a key that cannot sign, and a key that cannot sign wins over a ref write that
cannot happen. The branch-name term is observable over a name both ref-name
grammars refuse, `bad//name` among them; the port's guard covers path safety
alone, so a name only the tool's wider grammar refuses -- one holding a space or
a caret -- reaches the signing step in the port
(`../conformance/cli-surface.md`, "P2").

### `refs`

The default form prints one refspec per line. The listing covers `refs/heads`,
named by the ref name, and `refs/remotes`, named `remote:name`; `refs/mirrors`
is excluded. A ref stored as an alias is listed by its own name, resolved
through the link. The whole set is sorted by refspec, so `alias1`,
`deep/nest/ing`, `origin:test/main`, `other`, and `test/main` print in that
order: one plain byte-wise ordering over the refspec strings, with no grouping
by ref root.

A `PREFIX` argument keeps the refs equal to it or nested under it, and the
printed name drops the prefix and the `/` after it. An exact match prints the
whole refspec: `refs test` prints `main` for `test/main`, and `refs test/main`
prints `test/main`. A remote's refspec keeps its `remote:` part while the ref
name below it is stripped, so `refs origin:rr` prints `origin:x` for
`origin:rr/x` and `origin:deep/y` for `origin:rr/deep/y` -- neither of which
names a ref. `--list` suppresses the stripping and prints the whole refspec.

More than one `PREFIX` is accepted. The output is grouped by prefix in the order
the prefixes were given, sorted within each group, and a ref two prefixes match
prints once per match: `refs mid zulu alpha` prints `one`, `two`, `zulu`,
`alpha`, and `refs mid mid` prints `one`, `two`, `one`, `two`. The prefix that
stripped a name is the one that selected that row, not the first one matching
it, so `refs test test/main` prints `main` and then `test/main`. A prefix
matching nothing prints nothing and exits 0.

Each `PREFIX` is validated as a refspec, in the default listing, `--list`, `-r`,
`-A`, and `--delete`. A name the ref rule refuses ends the invocation with exit
1: the tool reports `error: Listing refs: Invalid refspec <PREFIX>`, and the port
reports `error: Invalid refspec <PREFIX>`, the one message it gives that rule
wherever a name reaches it. The refusals observed are `test/`, `/test`, `a//b`,
`.`, `..`, `test/main/`, `test/../main`, an empty argument, `:`, `:rr`,
`origin:rr/`, `origin:..`, and a remote half holding a `/` such as `or/igin:rr`.
The tool applies the narrower ref-name class "Ref name validation" above records,
so it also refuses `tes~t`, `te st`, `.test`, and `origin::rr`, which the port's
rule accepts.

The check runs where each prefix is taken, so a valid prefix ahead of a refused
one keeps its effect: `refs test 'bad/'` prints the rows `test` matched and then
the refusal, and `refs --delete deep 'bad/'` removes what `deep` matched and
leaves the rest.

A `PREFIX` also names a path below `refs/`: the ref name under `refs/heads`, the
ref name under `refs/remotes/<remote>`, or the remote's own directory for a
whole-remote prefix. That path is the directory a listing enumerates, and it is
read before the prefix filters anything, in the default listing, `--list`, `-r`,
`-A`, and `--delete`. A path that runs through a ref file ends the invocation
with exit 1: the tool reports `error: Listing refs: fstatat(<path>): Not a
directory`, naming the path below the repository, and the port reports `error:
i/o error: Not a directory (os error 20)`, the one message it gives that
condition (`conformance/cli-surface.md`, "P1"). Both print the same standard
output and leave the same refs tree. The refusals observed are a prefix whose
last component sits under a ref file (`plain/x` over the ref `plain`), one whose
inner component does (`plain/x/y`), one reaching the ref file through an alias
symlink (`al/x`, where `refs/heads/al` links to `test/main`), and the same forms
under `refs/remotes/<remote>` (`origin:rr/x/y` over the ref `origin:rr/x`). A
path naming nothing prints nothing and exits 0, which is what a prefix matching
no ref does. This check runs per prefix too, and after the refspec rule, so
`refs test plain/x` prints the `test` rows and then the refusal, and `plain/x/`
reports the refspec refusal in both.

With `-c` a positional argument is a collection id, so no path is read.

A whole-remote prefix -- a `<remote>:` prefix whose ref half is empty or `.` --
names every ref of that remote, so `refs origin:` and `refs origin:.` each print
every ref of `origin`. The ref half stands for the remote's root, so no ref name
is stripped and every row keeps its whole refspec. A whole-remote prefix matching
no ref prints nothing and exits 0.

Under `--delete` each prefix is matched against the ref set as the prefixes ahead
of it left it: `refs --delete origin:rr origin:` empties the remote with the first
prefix, so the whole-remote prefix matches nothing and the invocation exits 0,
while `refs --delete origin:rr/deep origin:` leaves `origin:rr/x` for the
whole-remote prefix to match and is refused.

For such a prefix the tool builds each name it prints or deletes by joining the
ref half with the name below it, and the `.` of that join stays in the name:
`refs --list origin:` prints `origin:./rr/x`, `refs -A origin:` prints
`./rr/remal`, and `refs --delete origin:` reports `error: Invalid refspec
origin:./rr/x` and exits 1 after removing nothing, naming one matched ref in its
own directory order. The port prints the refspec `origin:rr/x` in both listings,
and refuses the same delete naming the prefix as given (`error: Invalid refspec
origin:`), which leaves the refs tree the tool leaves
(`conformance/cli-surface.md`, "P1").

With `-c` a positional argument is a collection id, and the tool validates it
under the collection-id rule instead (`error: Listing refs: Invalid collection ID
<id>`).

`-r`/`--revision` appends a single tab and the 64-character commit checksum to
each line.

`-A`/`--alias` lists the aliases alone, as `<name> -> <target>`. The target is
the symlink body with its leading `../` components removed, so an alias at
`refs/heads/test/al2` pointing at `../zulu` prints `zulu` and one pointing at
`sub/deep` prints `sub/deep`. The name is never stripped, and `-r` adds nothing.

A `PREFIX` that names a ref exactly is answered by that one ref, printed as
`<PREFIX> -> <commit checksum>`, for every kind of ref: `refs -A al` prints
`al -> <checksum>` for an alias, and `refs -A test/main` and
`refs -A origin:rr/x` print the same shape for a plain ref and for a remote ref,
neither of which is an alias. A bare 64-character checksum resolves to no ref
here, so it prints nothing. Every other prefix filters, keeping the aliases
nested under it: with an alias at `grp/deep/z`, both `refs -A grp` and
`refs -A grp/deep` print `grp/deep/z -> test/other`. A prefix naming an alias
whose target ref is missing resolves to no ref and holds no alias below itself,
so it prints nothing.

The tool names an alias under `refs/remotes/<remote>/` by its path below the
remote, so an alias at `refs/remotes/origin/rr/remal` prints as `rr/remal`,
dropping the remote and producing a name that resolves to nothing; the port
prints the `origin:rr/remal` refspec instead. Such an alias arrives by
out-of-band mutation alone, since `-A --create` refuses a NEWREF naming a remote
in both implementations.

The port applies that rule to the target as well, once the link leaves the
alias's own ref root -- `refs/heads` for a local alias,
`refs/remotes/<remote>` for a remote one -- and prints the target ref's refspec:
an alias at `refs/heads/xal` pointing at `../remotes/origin/rr/x` prints
`origin:rr/x`, where the stripped body `remotes/origin/rr/x` names no ref. A link
that stays inside its own root keeps the stripped body under both
implementations. Each implementation writing such an alias with
`refs -A --create` and reading its own repository back prints `xal ->
origin:rr/x`.

`-c`/`--collections` lists the collection refs as `(<collection-id>, <ref>)`,
sorted by collection id and then by ref name. The set is the repository's own
refs under `refs/heads` qualified by its `[core] collection-id`, plus every ref
under `refs/mirrors` qualified by the collection component of its path;
`refs/remotes` is excluded, and a repository with no `collection-id` lists its
mirror refs alone. With `-c`, a positional argument is a collection id and not a
ref-name prefix. `-c` wins over `-A`: the two together list collection refs.

`--create=NEWREF` points a new ref at the commit the single positional argument
names, and writes `refs/heads/<NEWREF>` (or `refs/remotes/<remote>/<name>` for
a `remote:name` NEWREF), creating the parent directories. With `-A` it writes a
relative symlink instead. For a target under `refs/heads` the link body is the
path from the alias's own directory to the target ref's file, so `--create=p/q`
aliasing `one` writes `../one` and `--create=al` aliasing `test/main` writes
`test/main`. For a target under `refs/remotes` the tool writes the `remote:name`
refspec verbatim, so `--create=xal` aliasing `origin:rr/x` writes
`refs/heads/xal -> origin:rr/x`, a body naming no file under `refs/heads`: the
tool's own `rev-parse xal` then reports `error: Refspec 'xal' not found` and its
own default listing stops on the link with `error: Listing refs: openat(xal): No
such file or directory`. The port writes the path to the target ref's file for
every target, so the same invocation writes `../remotes/origin/rr/x`, which
resolves under both implementations. `--create` wins over `--delete` when both
are given. The errors, each exit 1:

- no positional argument -- `error: You must specify a revision when creating a
  new ref`;
- more than one -- `error: You must specify only 1 existing ref when creating a
  new ref`;
- an unresolvable positional -- `error: Refspec '<rev>' not found`;
- an existing NEWREF without `--force` -- `error: --create specified but ref
  <NEWREF> already exists`;
- with `-A`, a NEWREF naming a remote -- `error: Cannot create alias to remote
  ref: <remote>`. The message names the remote half alone, so `--create=origin:al`
  and `--create=origin:rr/al` both report `origin`, and it names that half as
  given whether the repository holds refs for the remote or none;
- with `-A`, a positional that names anything other than an existing ref --
  `error: Cannot create alias to non-existent ref: <rev>`. The check that reports
  it stands ahead of ref-name validation at this one site, so it answers for a
  bare checksum, an ancestry suffix, a name no ref holds, and every name the ref
  rule refuses: `a/../b`, `a//b`, `.`, `..`, the empty argument, `origin:`,
  `a:b:c`, `a/b:x`, `te st`, `.test`, `origin::rr`, and `tes~t` each report the
  target as given. The tool answers the two i/o conditions with that same line,
  where the port reports the message it gives each of them, and a target the
  tool's narrower character class refuses parts the two where the ref exists
  (`conformance/cli-surface.md`, "P1").

A NEWREF whose path under `refs/` runs through a ref file, or names a directory,
and a positional revision of either shape, are refused before anything is
written, in the words "Ref name validation" above records, which also states the
directory shapes the tool's own write replaces.

NEWREF is checked in three steps, and all three precede the resolution of the
positional, so a NEWREF fault is reported over an unresolvable revision. The
first step is the positional count. The second is the existence check, which
resolves NEWREF as a revision in every case; `--force` suppresses the refusal a
resolved NEWREF draws and leaves the resolution itself in place. That resolution
takes the case rule "Revision syntax" above states, so a NEWREF of 64 lowercase
hex characters is read as a checksum and reported as an existing ref, while an
uppercase one is looked up as a ref name and written. That step reads
a trailing `^` as ancestry, so `--create=NAME^` reports `error: --create
specified but ref NAME^ already exists` where the base resolves to a commit
holding a parent, and `error: Commit <checksum> has no parent` where the base is
a root commit; `--create=NAME^ --force` reports that same `has no parent` line
where the base is a root commit. The third step validates NEWREF as a ref name,
by the rule "Ref name validation" above states, and refuses a `^` in it:
`--create=NAME^ --force` reports `error: Invalid refspec NAME^` where the
ancestry resolves, and `--create=a/../b --force nosuch` reports `error: Invalid
refspec a/../b` rather than the unresolvable positional -- a name a traversal
component makes invalid draws those same words from the second step, so which of
the two answers it is not observable.
A `^` inside the name carries the same message with and without `--force`, since
the second step reads no ancestry there: `--create=a^b` reports `error: Invalid
refspec a^b`. `-A` takes the same three steps in the same order and adds a fourth
of its own, the remote refusal, which also precedes the resolution of the
positional: `-A --create=origin:al nosuch` reports `error: Cannot create alias to
remote ref: origin` and `-A --create=origin:rr/x --force test/main` reports it
where the existence check `--force` suppressed would have named the ref, while
`-A --create=origin:bad/ test/main` stops one step earlier with `error: Invalid
refspec origin:bad/`. With `-c` the fourth step is absent, `-c` winning over `-A`,
so `-c -A --create=<id>:<ref>` writes a collection ref in either flag order. A
NEWREF holding a second `:` reaches the fourth step in the port and the third in
the tool, the port's ref rule being the wider one, so `-A --create=a:b:c` reports
`error: Cannot create alias to remote ref: a` from the port and `error: Invalid
refspec a:b:c` from the tool; both exit 1 and write nothing
(`conformance/cli-surface.md`, "P1"). The port refuses a
NEWREF ending in `^` with that message; a `^` elsewhere in a ref name belongs to
the character class the port does not validate
(`conformance/cli-surface.md`, "P1").

Under `-A` the target is checked in a fifth step, after the remote refusal: the
existence check that reports `error: Cannot create alias to non-existent ref:
<rev>`. That check stands ahead of ref-name validation, which is why the target is
the one site a refused name draws no `Invalid refspec` line, and it is reached
last, so a NEWREF fault is reported over a refused target:
`-A --create=origin:al a/../b` names the remote and `-A --create=a/../b a/../b`
names the NEWREF.

With `-c`, `--create=NEWREF` writes a collection ref: NEWREF is a
`<collection-id>:<ref>` pair and the write lands at
`refs/mirrors/<collection-id>/<ref>`, with the parent directories created. `-c`
wins over `-A` here as it does in a listing, so the two together write a ref
file. The steps are the positional count, the existence check, the pair shape,
the resolution of the positional, and the collection id, in that order, which
puts the shape before the revision and the collection id after it:

- a NEWREF holding no `:` names no ref, and the whole argument is read as the
  collection id -- `--create=fresh` reports `error: Invalid collection ID
  fresh`, and `--create=org.example.Foo`, whose text is a collection id,
  reports `error: Invalid ref name (null)`;
- a pair with an empty half, a second `:`, a `^` in either half, or a ref half
  that fails ref-name validation reports `error: Invalid refspec <NEWREF>`,
  before the positional resolves. The whole pair is the name the message
  carries, so `--create=<id>:a/../b` names both halves;
- a collection id is two or more `.`-separated elements, each starting with an
  ASCII letter or `_` and continuing with ASCII letters, digits, or `_`. So
  `a.b`, `A.b`, `_a.b`, `a._b`, `a_b.c`, and `a.b.c.d` are written, and
  `fresh`, `a..b`, `a.b.`, `1a.b`, `a.1b`, `a-b.c`, and `a.b-c` report `error:
  Invalid collection ID <id>`. The length is bounded by the filesystem alone,
  the id being one path component;
- the existence check reads NEWREF as an ordinary refspec, so `<id>:<ref>` is
  looked up under `refs/remotes/<id>/<ref>` and a collection ref of the same
  spelling does not count as existing. `--create=<id>:<ref>` therefore repeats
  without `--force`, while a remote ref of that spelling reports `error:
  --create specified but ref <NEWREF> already exists`.

`--force` replaces an existing ref, including replacing a regular ref file with
an alias symlink and the reverse.

`--delete` removes every ref its prefixes match, prints nothing, and exits 0
even when a prefix matches nothing. With `-c` the prefixes are collection ids
and the whole collection's refs are removed. The parent directories a removal
empties are left in place. With no prefix it reports `error: At least one PREFIX
is required when deleting refs` and exits 1. A whole-remote prefix matching a ref
is refused by both implementations and removes nothing, as "refs" above records.

Under `-c`, the id equal to the repository's own `[core] collection-id` removes
the refs under `refs/heads` alone and keeps the mirror refs carrying that id, so
`refs -c --delete org.example.Coll` over a repository whose `collection-id` is
`org.example.Coll` leaves `refs/mirrors/org.example.Coll/mm` in place. A foreign
id removes the mirror refs of that id, and a repository with no `collection-id`
owns no id, so every mirror ref a prefix names is removed. The `-c` listing
prints both sets for either id, so the two ids share one selection and differ in
the removal. An id equal to the own id where the local refs are absent removes
nothing and exits 0, and a local ref carrying a mirror ref's name is removed
while the mirror ref of that name stands.

With `-A` the set each prefix removes is the set a `-A` listing prints for it:
the ref the prefix names exactly, or the aliases nested under it. So against the
refs `test/main` and `test/other` and the alias `test/al`, `refs -A --delete
test` removes `test/al` and leaves both refs, where `refs --delete test` removes
all three. A prefix naming a ref exactly removes that one ref for every kind of
ref, the way the listing answers such a prefix: `refs -A --delete test/al`
removes the alias, and `refs -A --delete other` and
`refs -A --delete origin:rr/x` remove a plain ref and a remote ref, neither of
which is an alias. A prefix holding no alias below itself removes nothing and
exits 0, so `refs -A --delete deep` leaves `deep/nest/ing` in place. The prefix
rules, the whole-remote refusal, and the alias guard all read whichever set the
prefix selected, and each prefix reads the aliases as the prefixes ahead of it
left them. With no prefix the message is the one the plain form gives. `-c` wins
over `-A` here as it does in a listing, in either flag order.

The tool removes each alias nested under a prefix by the name it prints for that
alias, and for an alias under `refs/remotes` that name drops the remote, so
`refs -A --delete origin:rr` removes no alias of `origin` and instead removes a
local ref carrying that name where one exists: against the remote alias
`refs/remotes/origin/zz/q` and the local ref `refs/heads/zz/q`, the tool removes
the local ref and keeps the alias. The port removes the alias its own listing
names (`conformance/cli-surface.md`, "P1"). A whole-remote prefix holding an
alias is refused by both, the tool on the joined name (`error: Invalid refspec
./rr/remal`) and the port on the prefix as given, and neither removes anything.

An alias holds the ref it names in place. A prefix matching a ref under
`refs/heads` that an alias names ends the invocation with `error: Ref '<refspec>'
has an active alias: '<alias>'` and exit 1. In the port that prefix removes
nothing, in the plain form and in the `-A` form alike. The tool removes the
members of the selected set its own removal order reached ahead of the guarded
one, so the two leave different refs trees wherever that order puts an unguarded
member first (`conformance/cli-surface.md`, "P1"). A guarded member stands in
both. The guard runs per prefix, so `refs --delete deep test` removes what `deep`
matched and then reports the refusal for `test`. An alias names its target by the
link body with the leading `../` components removed, read from the `refs/heads`
root: an alias at `refs/heads/test/al2` whose body is `other` names the ref
`other`, where the link itself resolves to `refs/heads/test/other`, so
`refs --delete other` is refused and `refs --delete test/other` removes the ref.
A matched ref that is an alias itself is guarded the same way, so
`refs --delete test/al` is refused where `refs/heads/alal` links to `test/al`.
Removing an alias that no alias names succeeds, and each prefix reads the aliases
as the prefixes ahead of it left them, so `refs --delete alal test/al` removes
both.

Outside `refs/heads` the removal proceeds: a ref under `refs/remotes` is removed
with an alias naming it, in the port's body form (`ral ->
../remotes/origin/rr/x`) and in the tool's refspec form (`ral -> origin:rr/x`)
alike, and an alias under `refs/remotes` or `refs/mirrors` names nothing for the
guard. With `-c` the guard does not apply, so `refs -c --delete <collection-id>`
removes the refs of that collection with the aliases among them. Where a prefix
matches more than one guarded ref, or more than one alias names one matched ref,
each implementation names the pair its own enumeration reaches first
(`conformance/cli-surface.md`, "P1").

Five tool behaviors here are not reproduced. A NEWREF ending in `^` whose base
names no ref kills the tool with a signal before it writes anything (recovered
with `--create='nosuch^'` against a repository holding no `nosuch`, with and
without `--force`, and with and without `-A`, and with `-c` as
`--create='<id>:<ref>^'`); the port reports `error: Invalid refspec <NEWREF>`,
the words the tool gives that name at its third step, and writes nothing. A
dangling alias -- a symlink under `refs/` whose target ref does not exist --
makes the tool fail every invocation whose enumeration reaches it, with `error:
Listing refs: openat(<path>): No such file or directory` and exit 1, where
`<path>` is the link's path below `refs/heads` or below `refs/remotes/<remote>`:
the default listing, `--list`, and `-r`; a `PREFIX` naming a directory that
holds the link, in a listing and in a `--delete`, which then removes nothing;
and `--create`, `--create --force`, and `-A --create`, each of which writes no
ref. A link under `refs/mirrors` reaches the `-c` listing alone, leaving the
default listing and `--create` unaffected, and `-c --create=<id>:<ref>`
completes over a link under `refs/heads`. `-A` lists the dangling alias, and
`-A` with a `PREFIX` naming it exactly prints nothing. `--delete` naming the
link itself exits 0 and leaves the link in place. The port skips the dangling
entry everywhere else: it lists the rest, writes every `--create` form, and
removes what a prefix matched.

A symlink under `refs/` that names a directory makes the tool report `error:
Listing refs: Is a directory` and exit 1 from the default listing, `--list`,
`-r`, `fsck`, `summary -u`, and `prune --refs-only`. The tool's prefix-scoped
forms complete over the same link: a `PREFIX` naming the link enumerates the
directory it points at, so `refs lnk` prints `nest/ing` where `refs/heads/lnk`
links to `deep` and `deep/nest/ing` is a ref; a `--delete PREFIX` matching other
refs removes them and exits 0; a `--delete` naming the link reports `error:
Listing refs: opendir(lnk): Not a directory` and exits 1; and the default
`prune`, which reads no ref, exits 0. The port reads every symlink under `refs/`
as an alias and descends into a real directory alone, so reading the link fails
with `EISDIR` wherever an enumeration reaches it: `error: i/o error: Is a
directory (os error 21)` and exit 1 from every listing form, from `--delete`
whatever the prefix matches, and from `fsck`, `prune`, and `summary -u`. `-A`
lists the link on both sides, as `lnk -> deep`. A link naming its own directory
(`refs/heads/selfdir -> .`) takes the same path on both sides. Such a link
arrives by out-of-band mutation alone, since `refs -A --create` validates its
target as a ref in both implementations.

A collection directory under `refs/mirrors` whose
name is not a valid collection
id aborts the tool on a GLib assertion (`ostree_collection_ref_new: assertion
'collection_id == NULL || ostree_validate_collection_id (collection_id, NULL)'
failed`, killed by a signal), and a collection id given as a positional
argument is validated (`error: Listing refs: Invalid collection ID <id>`, exit
1); the port validates a collection id where `-c --create` writes one and lists
what the path holds. On the missing ref name of `-c --create=<id>` the tool
prints a GLib assertion line (`g_regex_match_full: assertion 'string != NULL'
failed`) before its own `error: Invalid ref name (null)`; the port prints the
error line alone.

### `rev-parse`

Prints the resolved 64-character commit checksum and a newline, one line per
`REV` argument, in the order given. The first argument that does not resolve
reports `error: Refspec '<rev>' not found` and exits 1, after the checksums
before it were already printed. With no argument the command prints its usage
text to standard error, then `error: REV must be specified`, and exits 1. A
`REV` whose path under `refs/` runs through a ref file, or names a directory,
is refused in the words "Ref name validation" above records.

`-S`/`--single` takes no argument and prints the repository's one commit
checksum. An empty repository reports `error: No commit objects found`, a
repository holding more than one commit reports `error: Multiple commit objects
found`, and an argument alongside `-S` reports the usage text and `error: Cannot
specify arguments with --single`; each exits 1. The count is over the commit
objects present in `objects/`, not over the refs.

### `cat`

Writes each named file's content to standard output in the order the paths were
given, with nothing between them and nothing added. A leading `/` on a path is
optional.

Path resolution splits the path on `/` and looks up each component in the
commit's tree literally: `.`, `..`, and an empty component each name nothing, so
`cat REV /./a.txt` reports `error: No such file or directory: /.` and
`cat REV //a.txt` reports `error: No such file or directory: /`. The reported
path is absolute whether or not the argument was, and names the prefix that
failed rather than the whole argument.

An empty argument reaches no component and reports the commit root as absent:
`cat REV ''` reports `error: No such file or directory: /`. The argument `/`
reaches the root and gets the directory refusal instead.

A symlink in the final position is followed, its target resolved against the
link's own directory, or against the commit root when the target is absolute.
The target's components are looked up literally too, so a target holding `..`
fails: a symlink at `/sub/rel` pointing at `../a.txt` reports `error: No such
file or directory: /sub/..`. A symlink in any other position is not followed:
`cat REV /dlink/b.txt`, where `dlink` links to the directory `sub`, reports
`error: Not a directory`. A chain of symlinks is followed to its end. The tool
bounds the depth nowhere: a chain 20000 links deep resolves, and one 100000
links deep kills it with a signal (exit 139). The port follows 256 links, above
the depth any real tree holds, and refuses a chain deeper than that.

The errors, each exit 1: a path naming a directory, or the commit root, reports
`error: Can't open directory`; a missing path reports `error: No such file or
directory: <absolute path>`; a non-final component that is a file reports
`error: Not a directory`; an unresolvable `COMMIT` reports `error: Refspec
'<rev>' not found`; a `COMMIT` that resolves to a commit the store does not hold
is refused in each implementation's own words, `error: No such metadata object
<checksum>.commit` from the tool and `error: object not found: Commit
<checksum>` from the port, in the words "Revision syntax" above records; a
`COMMIT` whose path under `refs/` runs through a ref file,
or names a directory, is refused before the tree is read, in the words "Ref name
validation" above records; a missing `COMMIT` or an empty path list prints the
usage text and `error: A COMMIT and at least one PATH argument are required`. A
self-referencing symlink kills the tool with a signal (recovered with a link
whose target is its own name); the port reaches its 256-link bound and reports
`error: Too many levels of symbolic links`, which is also the message a chain of
257 distinct links gets.

### The GVariant text form

The reading commands render a metadata value as text with GLib's own printer, so
the convention belongs to GVariant rather than to ostree and lives in
`ostrya-gvariant` beside the value type. It is the form `show --raw`,
`show --print-metadata-key`, `show --print-detached-metadata-key`,
`show --print-variant-type`, `ls -X`, and `summary --raw` all write. Recovered
by giving the tool one hand-written serialized value per rule through
`show --print-variant-type=TYPE`, which reads any file as a value of a named
type:

- A value whose literal does not state its own type carries a type annotation:
  `byte 0x2a`, `int16 -5`, `uint16 5`, `uint32 42`, `int64 -5`, `uint64 42`,
  `handle 5`, `objectpath '/a/b'`, `signature 'ay'`. A byte is two lowercase hex
  digits behind `0x`. A boolean prints `true` or `false`, a string prints quoted,
  an `i` prints as the bare number, and a `d` prints as the bare `%.17g`
  rendering of the double with `.0` appended where that rendering holds no `.`,
  no exponent, and no `nan`: `1.5`, `1000.0`, `-0.0`,
  `0.10000000000000001`, `1.7976931348623157e+308`. None of the four carries an
  annotation.
- A maybe states no type in either literal it has, so an annotated one carries
  its whole signature and its child then prints bare: `@ms 'just'`,
  `@ms nothing`, `@mi 5`. Unannotated it prints the child alone, or `nothing`.
- A chain of nested maybes prints the value alone when every level of the chain
  is set, since the type states the level count: `@mmi 5` names a chain of two
  set levels over `5`, and `@mmmv <'x'>` a chain of three over a variant. A
  chain that ends at `nothing` states its own set levels instead, one `just `
  for each: `@mmi just nothing` has the outer level set and the inner one unset,
  `@mmi nothing` has neither set, and the count runs to the depth of the type in
  `@mmmi just just nothing` and `@mmmmi just just just nothing`. The prefixes
  belong to the value, so they stay where the annotation is dropped:
  `[@mmi just nothing, nothing, 5]` and
  `{'a': @mmi just nothing, 'b': nothing, 'c': 5}`. This is what makes the
  printed text read back as the value it came from.
- A container holding at least one element delegates its annotation to its first
  element, and the elements after it print unannotated: `aay` holding two byte
  arrays prints `[[byte 0x63], [0x62]]`. A tuple annotates every member, whose
  types do not follow one another: `(byte 0x01, byte 0x02)`. A one-member tuple
  keeps a trailing comma, `(byte 0x01,)`, and the empty tuple prints `()`.
- A container holding no element has nowhere to delegate to, so it carries its
  own signature: `@ay []`, `@a(say) []`, `@a{sv} {}`. An empty container in an
  unannotated position prints the bare literal, so `aay` holding a byte array and
  then an empty one prints `[[byte 0x63], []]`.
- An array of dict entries prints as one brace-enclosed list of `key: value`
  pairs rather than a list of entries: `{'a': byte 0x01, 'b': 0x02}`. A dict
  entry outside an array prints `{key, value}`, with a comma.
- A variant prints `<child>`, and the child is always annotated, since a variant
  states no child type of its own: `<byte 0x2a>`.
- A byte array whose last byte is the only NUL it holds prints as a bytestring
  literal, `b'user.foo'`, which states its own type and carries no annotation.
  Every other byte array prints as the element list, `[byte 0x01, 0x02, 0xff]`;
  the empty one has no trailing NUL and so prints `@ay []`. The rule reaches real
  metadata: an xattr name is stored NUL-terminated and prints as a bytestring
  while its value does not, and a 64-byte ed25519 signature whose last byte
  happens to be zero prints as one too.

The two literal forms escape differently, which one string holding the same
bytes shows: as a string it is `'a"b'` and as a bytestring `b'a\"b'`.

- A string is written in single quotes, or in double quotes when it holds a
  single quote, so the quote it holds needs no escape. Only the quote in use is
  escaped, so `"` stays literal inside single quotes. `\a`, `\b`, `\f`, `\n`,
  `\r`, `\t`, `\v`, and `\\` take their short escape; every other C0 control and
  DEL takes `\uXXXX` in four lowercase hex digits; and every other character,
  ASCII or not, is written through, so UTF-8 stays readable.
- A bytestring is written in single quotes, or in double quotes when its content
  holds a single quote. A backslash and a double quote are always escaped, even
  inside single quotes. `\b`, `\f`, `\n`, `\r`, `\t`, and `\v` take their short
  escape, and every byte outside printable ASCII takes a three-digit octal
  escape: `b'\377'`, `b'h\303\251'`.

Byte order. The on-disk format places its numeric fields in the variant already
big-endian while the framing stays little-endian, so a value parsed from those
bytes holds each numeric field byte-reversed. One byteswap of the whole value
tree recovers the numbers the fields state, and that is what the default report
does: the commit whose stored timestamp field is `1700000000` big-endian reports
`uint64 1700000000`, and `-B` reports the stored form, `uint64
67927162644070400`. The swap reaches a numeric field inside a variant, so a
`t`-valued metadata key written natively reports byteswapped. It reaches
`--print-metadata-key` and `--print-detached-metadata-key` as well, and not
`--print-variant-type`, whose report is byteswapped whether or not `-B` is given.

#### Reading the text form back

`commit --add-metadata=KEY=VALUE` takes a value in this form, so the port reads
it as well as writes it (`ostrya-gvariant`, `from_text`). The reading rules,
recovered by giving the tool one value per rule and reading the stored variant
back with `show -B --print-metadata-key`:

- A quoted literal is a string; single and double quotes both open one, and the
  quote in use is the one that needs escaping. `\a`, `\b`, `\f`, `\n`, `\r`,
  `\t`, `\v`, and `\\` take their short escape, `\uXXXX` and `\UXXXXXXXX` name a
  character by code point, and every other escape drops the backslash and keeps
  the character, so `'\x41'` is the three characters `x41`. A backslash before a
  line feed is a line continuation: both characters leave the value, so
  `'a\<LF>b'` is the two characters `ab`. The rule holds in a bytestring too.
- A `\u` or `\U` escape naming U+0000 is refused, because a string value carries
  no NUL. The refusal is `invalid 4-character unicode escape` for `\u` and
  `invalid 8-character unicode escape` for `\U`, at the offset of the digits, so
  `'\u0000'` gives `3-7:invalid 4-character unicode escape` and `'\U00000000'`
  gives `3-11:invalid 8-character unicode escape`. The refusal comes from the
  reader, so the offset follows the literal wherever it stands and the type
  around it makes no difference: `@o '/a\u0000b'` gives `8-12`, `@g '\u0000'`
  gives `6-10`, and `{'\u0000': 1}` gives `4-8`. A raw NUL byte in a string
  literal is refused the same way, at the byte, with `NUL byte in string
  constant`; the tool takes its value through `argv`, which carries no NUL, so
  this refusal has no counterpart to compare against.
- `b'...'` and `b"..."` are bytestrings, which name a NUL-terminated `ay`. An
  octal escape of up to three digits names one byte, and the value ends at the
  first NUL those escapes produce, so `b'\0'`, `b'\400'` and `b'\0001'` are all
  the one-byte array holding the terminator alone. A bytestring has no `\u` or
  `\U` escape, so `b'\u0000'` is the six-byte array holding `u0000` and the
  terminator. A raw NUL byte in a bytestring literal ends the value the way an
  octal escape naming it does.
- A number is hexadecimal behind `0x`, binary behind `0b`, octal behind a
  leading `0`, and decimal otherwise; both prefix letters take either case. The
  reader a literal goes to when no type states one is the double reader for a
  body carrying a decimal point, for a body carrying a lower-case `e` outside a
  hexadecimal one, and for the words `nan` and `inf`; every other body goes to
  the integer reader. So `1e3` is 1000.0, `1E3` is refused at the `E`, `0x1e5`
  is 485, and `0x1.8p1` is 3.0. An integer literal with no other context is an
  `i`.
- The type a literal lands in picks the reader again, so the same text can carry
  two values: `@d 017` is 17.0 where `017` alone is 15, and an integer type over
  a literal the double reader would take reports the character the integer
  reader stopped at, `byte 1.5` giving `6-7:invalid character in number`.
- `nan`, `inf`, `-inf` and `-infinity` are doubles; the spelling is lower case
  and a sign is needed for `infinity`. A magnitude the double range cannot hold
  is refused as out of range, and so is a value that rounds to a subnormal the
  literal does not state exactly, so `5e-324` and `1e-308` are refused where
  `1e-400` is 0.0 and `2.2250738585072014e-308` is kept. The exact decimal form
  of a subnormal needs at least 716 significant digits, which is where the port
  parts from the tool (`conformance/cli-surface.md`, `commit`).
- A hexadecimal body states its value in binary, and the reader rounds it to the
  nearest double, ties to even, over a mantissa of any length:
  `0xffffffffffffffffffffffffffffffffffffffffp0` is 1.461501637330903e+48 and
  `0x1.0000000000000000000000000000000000001p0` is 1.0. The subnormal such a
  body states exactly is kept, so `0x1p-1023` is 1.1125369292536007e-308 and
  `0x1p-1074` is 4.9406564584124654e-324, where `0x1.8p-1074` and
  `0x1.0000000000001p-1030` round to a subnormal they do not state and are
  refused. `0x1p-1075` sits at the tie the rounding takes to even, so it is 0.0,
  and every smaller magnitude is 0.0 as well. A zero mantissa is 0.0 under any
  exponent, `0x0.0p2147483647` and `0x0.0p-9999999999` included. At the top of
  the range `0x1.fffffffffffff7ffffffffp1023` rounds down to the largest double
  and is kept, where `0x1p1024` and `0x1.fffffffffffff8p1023` are refused.
- A leading `-` is read ahead of the body, and the body may carry a sign of its
  own. `-` alone is zero, `-+5` is -5, and `--5` is the magnitude 2**64-5 with a
  negative sign, which no target type holds.
- `true` and `false` are booleans, `nothing` and `just <value>` are maybes,
  `[...]` is an array, `{key: value, ...}` an array of dict entries,
  `{key, value}` one dict entry, `(...)` a tuple, and `<value>` a variant. A
  one-member tuple is `(x,)`; the comma is required and `(x)` is refused with
  `expected ',' after first tuple element`. A trailing comma closes that one
  member alone, so `(1,2,)` reports `expected value`.
- A type keyword (`boolean`, `byte`, `int16`, `uint16`, `int32`, `handle`,
  `uint32`, `int64`, `uint64`, `double`, `string`, `objectpath`, `signature`) or
  a `@<signature>` declaration gives the value that follows it its type. A
  keyword token is two or more characters long, starts with two letters, and
  starts in lowercase; every other token that is not a literal is a place a
  value was expected.
- A `@` declaration runs to the first character that could close something
  around it -- whitespace, `,`, `:`, `>`, `]`, and a `)` or `}` that matches no
  `(` or `{` inside the declaration -- so `@i5` and `@**` are read whole and
  reported as one bad declaration where `@i)` ends at the bracket. A declaration
  naming one complete but indefinite type reports `type declarations must be
  definite`; every other bad one reports `invalid type declaration`.
- A declaration is read in three steps, each reporting ahead of the next. The
  signature must spell one complete type, which takes 129 levels: a leaf is one
  level, `m`, `a`, a tuple and a dict entry each add one over their deepest
  member, and a signature past that is `invalid type declaration`. The type
  must then fit in the nesting left where the declaration stands, which is 128
  levels in all, counting the levels the type carries from the level the
  declaration sits at; past that the report is `type declaration recurses too
  deeply`. The type must then be definite. So `@<128 array codes>y` is refused
  for its depth and `@<129 array codes>y` as an invalid signature, and the same
  two counts with a trailing `r` in place of the `y` report the depth rather
  than the definiteness. Under the depth rule the empty tuple carries no level
  of its own, so `@<128 array codes>()` is accepted where `@<128 array
  codes>y` is not, and a dict entry is measured by its value alone, so
  `@<127 array codes>{s()}` is accepted where `@<127 array codes>{sy}` is not.
  A declaration inside containers counts from their level, so
  `[@<127 array codes>y []]` is refused where the same declaration alone is
  accepted. The value beside the declaration takes one level, whatever the
  levels the declared type carries.
- An `o` value must be a valid object path: `/`, or `/` and one or more elements
  of letters, digits and underscores separated by single slashes. A `g` value
  must be zero or more complete D-Bus types, which excludes the maybe and the
  indefinite characters, so `signature 'ii'` is accepted and `signature 'ms'` is
  not. Each of those types takes the same 129 levels a declaration's signature
  takes, so `signature '<128 array codes>y'` is accepted and one array code
  more is `not a valid signature`. The levels are inside the string, so the
  level the signature value stands at does not narrow them.
- A container with no declaration takes one common type over its elements, so
  `[2, 1.5]` is an array of doubles and `['a', @ms 'b']` an array of maybe
  strings, the maybe absorbing the bare string beside it. A literal that states
  no type and has no context -- `[]`, `{}`, `nothing` -- is refused, and the
  refusal names the whole value being typed rather than the literal inside it.
  A variant's child is a whole value of its own, so `[<[]>]` names the `[]`.
- A declaration drives the check downwards instead: `@as [1]` names the element
  `1` against `s`. Two members of an undeclared container that do not meet are
  both named, `['a', 5]` reporting the two spans, and the keys of an undeclared
  dictionary are checked that way.
- The first entry of an undeclared dictionary settles the value type on its own,
  and every later value is read against that type the way a declaration drives
  the check downwards. `{'a': 1, 'b': uint32 2}` is `a{si}` and
  `{'a': uint32 2, 'b': 1}` is `a{su}`. A later value that does not fit is named
  against the settled type: `{'a': 1, 'b': just 2}` gives `14-20:can not parse
  as value of type 'i'`, `{'a': 1, 'b': 1.5}` gives `15-16:invalid character in
  number` at the character the integer reader stops on, and
  `{'a': 1, 'b': ['x', 5]}` gives `14-22:can not parse as value of type 'i'`,
  which names the whole array.
  A first value that states no type is named against the whole value
  being typed, and a later entry leaves it that way, so `{'a': [], 'b': 5}` is
  `0-17:unable to infer type` and `{'a': nothing, 'b': 'y'}` is
  `0-24:unable to infer type`. A key that does not meet the settled key type is
  reported ahead of the value type, which then stays unresolved:
  `{'a': [], [1]: 5}` gives `1-4,10-13:unable to find a common type`.
- A type already in force takes the value beside a declaration and drops the
  declaration. `@as [@o '/a']` stores a string, `{'a': 'x', 'b': @o '/y'}` is
  `a{ss}`, and `{'a': 'x', 'b': @o 'notapath'}` is accepted, the object-path
  check that `@o` alone runs staying out of the way. The value beside the
  declaration is read against the type in force, so `@as [@i 5]` names the `5`
  with `8-9:can not parse as value of type 's'` and
  `{'a': 'x', 'b': @ms nothing}` names the `nothing` with `20-27:can not parse
  as value of type 's'`.
- A value nests inside at most 127 containers. A `[`, `(`, `{`, `<`, a `just`, a
  type keyword and a `@` declaration each add one level, and the value at level
  128 is refused with `variant nested too deeply`, the offset naming the token
  at that level. A `@` declaration is held to the levels its own type carries
  as well (see the declaration rule above).

A refusal reports `<spans>:<reason>`, where a span is one byte offset for a
place a value was expected and `<start>-<end>` for a token, and two spans
separated by a comma where the reason names two: `0-2:unable to infer type`,
`0:expected value`, `0-7:unknown keyword`, `1-2:invalid character in number`,
`0-13:unterminated string constant`, `4:expected ',' or ')' to follow tuple
element`, `4:expected ':' or ',' to follow dictionary entry key`,
`3:expected end of input`, `0-1:invalid type declaration`,
`3-8:can not parse as value of type 'i'`, `0-10:number out of range for type
'i'`, `7-27:integer too big for any type`, `1-4,6-7:unable to find a common
type`, `11-21:not a valid object path`, `10-14:not a valid signature`, and
`0-10:dictionary keys must have basic types`. The offsets are into
the value alone; `commit` prefixes the whole `KEY=VALUE` argument
(see "`commit`" below).

The whole value is parsed, typed and built before the text is checked for
trailing input, so `@i 'x' 5` reports the member that does not fit and
`nothing 5` the type it could not infer, each ahead of the trailing `5`.

Four divergences stand between the two implementations here. The first two were
measured over 776 value texts given to both through `commit --add-metadata`, of
which 749 reach the same commit checksum or the same refusal; the last two over
the 366 values both accept, read back in four modes:

- A `\u` or `\U` escape naming a surrogate or a code point past U+10FFFF is
  accepted by the tool, which then builds a string that is not UTF-8, prints
  `GLib-CRITICAL **: g_variant_new_string(): requires valid UTF-8` and aborts
  with a signal, writing no commit. `'\uD800'` and `'\U00110000'` both reach
  that. The port refuses the escape with `3-7:invalid 4-character unicode
  escape` and `3-11:invalid 8-character unicode escape` at exit 1.
- The offset the nesting refusal carries agrees for `[`, `(` and `{`, where both
  name the token at level 128. For `<`, for `just`, for a type keyword and for a
  `@` declaration the tool prints an offset out of any relation to the text --
  `18446646599957580430` for one input and `18446642783772371598` for another,
  so the value is not reproducible -- where the port names the token as it does
  for the brackets. The reason text and the exit status are the same on both
  sides.
- A string holding a code point GLib does not count as printable -- an
  unassigned one, a non-character, or a control -- is printed by the tool as a
  `\uXXXX` or `\UXXXXXXXX` escape and by the port as the character itself.
  `'\uffff'`, `'\ud7ff'` and `'\U0010ffff'` from the tool are the three
  measured. Both store the same bytes, so the commit checksum agrees and the
  divergence is in the printed text alone.
- The deepest nesting the two carry through a commit differs, the port's codec
  holding a value-depth budget of 128 levels counted from the commit object and
  the tool counting from the metadata value. Measured with `--add-metadata=k=`
  and an array nested to each depth: through 123 the two write the same commit
  and read the same text back; at 124 and 125 the commits still agree and the
  read-back parts, the tool printing `()` for the value where the port prints
  the value at 124 and reports `error: gvariant: container nesting exceeds the
  supported depth` at 125; at 126 and 127 the tool writes the commit and the
  port reports that same line at exit 1; and at 128 and past it both readers
  refuse in the same words.

### `show`

The reporting modes are mutually exclusive, and where more than one is given the
highest of this order wins, each printing and exiting 0. The order was recovered
by giving the tool each pair:

1. `--print-detached-metadata-key=KEY`
2. `--print-metadata-key=KEY`
3. `--list-detached-metadata-keys`
4. `--list-metadata-keys`
5. `--print-related`
6. `--print-variant-type=TYPE`
7. `--print-sizes`
8. the object's own report, which `--raw` and `-B` extend

The object argument. A 64-character lowercase checksum names an object whose type
is recovered by probing the store in the order commit, dirtree, dirmeta, file, so
the argument carries no type; anything else is a revision, resolved to a commit.
A checksum naming nothing reports the last probe's failure, `error: Couldn't find
file object '<checksum>'`, at exit 1. A revision that resolves to nothing reports
`error: Refspec '<rev>' not found`. With no argument the usage text and `error: An
object argument is required` go to standard error at exit 1.

A metadata object reports its type and checksum on one line, `commit
<checksum>`, `dirtree <checksum>`, or `dirmeta <checksum>`. `--raw` adds the
value in the text form on the line below it and reports nothing more, so a
commit's own report is suppressed. `-B` adds the same line with the numeric
fields as stored, and a commit's own report still follows it, whether or not
`--raw` was given as well.

A commit's own report, in order, one line each: `Parent:  <checksum>` when the
commit has a parent; `ContentChecksum:  <checksum>`, the SHA-256 over the two
root checksums "Checksum computation" above defines; `Date:  <YYYY-MM-DD
HH:MM:SS +0000>`, the timestamp in UTC, read as a signed count of seconds so a
pre-epoch instant stored as the unsigned field's two's-complement form reports
`1969-12-31 23:59:59 +0000`; and `Version: <value>` when the commit metadata
carries a `version` key, with one space after the colon where the three lines
above it carry two. Then the subject: a blank line, then each of its lines
indented four spaces; an empty subject reports `(no subject)` with no blank line
before it. Then the body, when it is not empty: a blank line, then each of its
lines indented four spaces. Then one blank line, which closes the report.

A file object reports its header instead, one field per line: `Object:
<checksum>`, `Type: file`, `File Type: regular` with `Size: <bytes>` or `File
Type: symlink` with `Target: <target>`, `Mode: 0<octal st_mode>` (the full mode
including the file-type bits, behind a literal `0`), `Uid: <id>`, `Gid: <id>`,
and `Extended Attributes: { <a(ayay) in the text form> }`. `--raw` and `-B`
change nothing here.

`--print-related` prints one line per entry of the commit's related-objects
array, `<ref> <checksum>`. No `commit` option writes such an entry, so the array
is empty on every commit either implementation produces and the mode prints
nothing at exit 0; the line shape was recovered by assembling a commit that
carries two entries and reading it back.

`--list-metadata-keys` and `--list-detached-metadata-keys` print one key per
line, sorted, rather than in the order the dict stores them. A commit with no
`.commitmeta` reports `error: No detached metadata for commit <checksum>` at exit
1 under either detached mode.

`--print-metadata-key=KEY` and `--print-detached-metadata-key=KEY` print the
value the key holds, unwrapped from its `v` and annotated as a value of its own
type. A key the dict does not hold reports `error: No such metadata key '<key>'`
at exit 1. Where the same option is given more than once the last wins.

A checksum naming no object at all reports the file probe's failure, and the line
carries a prefix naming the open in every mode that stores the payload in the
object file itself: `error: Opening content object <checksum>: Couldn't find file
object '<checksum>'` in `bare` and `bare-user`, and the bare refusal alone in
`archive`, whose object carries its own header.

`--print-hex` applies to a key whose value type is exactly `ay`: the bytes print
as unquoted lowercase hex with no separator, and an empty array prints an empty
line. A value of any other type, `aay` included, ignores the switch.

`--print-sizes` totals the commit's `ostree.sizes` metadata over three lines:

```text
Compressed size (needed/total): <n> bytes/<n> bytes
Unpacked size (needed/total): <n> bytes/<n> bytes
Number of objects (needed/total): <n>/<n>
```

The "needed" figures cover the recorded objects absent from the local store, so
they are zero in a complete repository and count the missing objects otherwise. A
commit that carries no such key reports `error: No metadata key ostree.sizes in
commit` at exit 1.

`--print-variant-type=TYPE` reads the object argument as a filename rather than a
revision and reports the file's bytes as a value of that type. A path that does
not open reports `error: openat(<path>): <reason>` at exit 1.

A commit carrying GPG signatures reports them after its own report: a blank
line, `Found <n> signature:` (or `signatures:` for more than one), then per
signature a blank line and two indented lines, `  Signature made <date> using
<algorithm> key ID <the fingerprint's last sixteen hex digits>` and one of
`  Good signature from "<user id>"`, `  BAD signature from "<user id>"`, or
`  Can't check signature: public key not found`. The exit status stays 0 whatever
the verdict. The keyring is the repository's own `gpgkeys.gpg`;
`--gpg-verify-remote=REMOTE` reads that remote's trusted set instead, and
`--gpg-homedir=HOMEDIR` adds the keyrings in the named directory.

### `log`

Walks the parent chain from the given revision, newest first, and reports each
commit exactly as `show` does: `commit <checksum>` and then the commit's own
report. `--raw` reports `commit <checksum>` and the value in the text form for
each commit and nothing else, the same suppression `show --raw` makes. A parent
whose commit object is absent ends the walk with `<< History beyond this commit
not fetched >>` on its own line, at exit 0, so a partial history reports what it
holds; a `.commitpartial` marker changes nothing. A revision that resolves to
nothing reports `error: Refspec '<rev>' not found` at exit 1, and with no
argument the usage text and `error: A rev argument is required` go to standard
error at exit 1.

### `ls`

Prints one line per entry:

```text
<type><mode> <uid> <gid> <size>[ <checksum>...][ { <xattrs> }] <path>[ -> <target>]
```

The type is `d` for a directory, `-` for a regular file, and `l` for a symlink.
The mode is the permission bits alone (`mode & 07777`) in five octal digits, so
`00755`, `00644`, and a symlink's `00777`. The uid and gid are decimal with no
padding. The size is right-aligned in six columns: the payload size of a regular
file, and zero for a directory and for a symlink. The path is absolute, and a
symlink adds ` -> ` and its target.

`-C`/`--checksum` inserts the checksums after the size: one for a file, its
content checksum, and two for a directory, its dirtree and then its dirmeta.
`-X`/`--xattrs` inserts the entry's `a(ayay)` xattr set after them, wrapped in
`{ ` and ` }`, so an entry with none reports `{ @a(ayay) [] }`.
`--nul-filenames-only` prints the paths alone, each followed by a NUL, with no
columns, no target, and no newline; it overrides `-C` and `-X`.

Order and recursion. A directory reports itself and then its entries: its files
in name order, then its subdirectories in name order, which is the order the
dirtree stores them in rather than one merged sort, so a directory `aaa` follows a
file `zzz`. `-R`/`--recursive` follows each subdirectory's contents immediately
after the line naming it. `-d`/`--dironly` reports the directory alone.

With no `PATH` the tree root is the directory listed. Each `PATH` is listed in
turn, a leading `/` optional, and a `PATH` naming a file reports that one line. A
`PATH` naming nothing reports `error: Inspecting path '<argument>': No such file
or directory: <absolute path>` at exit 1, quoting the argument as given and
naming the absolute path it resolved to. An empty `PATH` resolves to the root and
is refused all the same, `error: Inspecting path '': No such file or directory:
/`. With no `COMMIT` the usage text and `error: An COMMIT argument is required`
go to standard error at exit 1, the tool's own wording.

### `config get`

Prints the value and a newline at exit 0. The key is `sectionname.keyname`, split
on its first `.`, so `config get a.b.c` reads the key `b.c` in the group `a`.
`--group=GROUP` names the section instead and the argument is then a whole key
name, dots included.

The value is unescaped as GKeyFile defines: `\n`, `\t`, and `\\` become the
characters they name. Whitespace after the `=` is dropped and trailing whitespace
is kept. A `;` is an ordinary character, a `"` is not a quote, and a value with
nothing after the `=` prints an empty line.

The refusals, each exit 1 with no usage text: a key holding no `.` with no
`--group` reports `error: Key must be of the form "sectionname.keyname"`, in
ASCII double quotes; a group the file does not hold reports `error: Key file does
not have group “<group>”`; a key the group does not hold reports `error: Key file
does not have key “<key>” in group “<group>”`; no key at all reports `error: KEY
must be specified`, or `error: Group name and key must be specified` when
`--group` was given; and an operation that is not `get`, `set`, or `unset`
reports `error: Unknown operation <operation>`. The two messages naming a group
or a key quote it in typographic quotes (U+201C and U+201D), the pair GLib uses.

Two checks stand ahead of the operation name, each printing the usage text and
then its error line at exit 1, and both after the repository resolves. With no
operation at all: `error: OPERATION must be specified`. With more operands than
the operation takes: `error: Too many arguments given`. The allowance is one
operand beside the operation, and two for `set`, which takes a key and a value, so
`get KEY EXTRA`, `unset KEY EXTRA`, and `set KEY VALUE EXTRA` are each refused
while `set KEY VALUE` is not. An operation the tool does not know gets the
one-operand allowance, so `<unknown> KEY EXTRA` reports the count and
`<unknown> KEY` reports the unknown operation.

### `config set` and `config unset`

Both write the whole document back and print nothing at exit 0. The key is read
the way `config get` reads it: `sectionname.keyname` split on its first `.`, or a
whole key name under `--group=GROUP`.

`set` takes a key and a value. A group the document does not hold is appended
after a blank line; a key its group does not hold is appended at the end of that
group; a key already there keeps its position and takes the new value. The value
is escaped as GKeyFile defines on write: a backslash becomes `\\`, a newline
`\n`, and a carriage return `\r` anywhere in the value, and within the leading
whitespace run each space becomes `\s` and each tab `\t`. A space or tab
elsewhere, and a `;`, are written literally.

`unset` takes a key. Removing a group's last key leaves the group header in the
file with no entries. A key the document does not hold, and a group it does not
hold, are both success and leave the file untouched.

The rewritten document keeps the groups and keys the operation did not touch, in
the order it read them, and drops the comment and blank lines the input carried.
The file is replaced atomically at mode `0644`.

The refusals, each exit 1 with no usage text: `set` with fewer than two operands
reports `error: KEY and VALUE must be specified`, or `error: GROUP name, KEY and
VALUE must be specified` when `--group` was given; `unset` with no operand
reports `error: KEY must be specified`, or `error: Group name and key must be
specified` under `--group`; and a key holding no `.` with no `--group` reports
`error: Key must be of the form "sectionname.keyname"`. The operand-count check
and the missing-operation check of `config get` stand ahead of all of these.

### `remote`

`remote` takes a nested subcommand. A missing one reports the subcommand's usage
text and `error: No "remote" subcommand specified` at exit 1, before any
repository is resolved.

`remote add NAME URL [BRANCH...]` writes the `[remote "NAME"]` section and prints
nothing at exit 0. The keys are written in this order:

- `url`, or `metalink` when the URL carries the `metalink=` prefix, which is
  stripped. A `mirrorlist=` prefix is not stripped and stays in the `url` value.
- `branches`, when branches were given: each followed by `;`, the last one
  included.
- `contenturl`, from `--contenturl=URL`.
- `custom-backend`, from `--custom-backend=NAME`.
- each `--set=KEY=VALUE` pair, in the order given.
- `gpg-verify=false`, from `--no-gpg-verify` and from `--no-sign-verify`, which
  turns both checks off.
- `sign-verify=false`, from `--no-sign-verify`.
- `verification-<engine>-key` or `verification-<engine>-file` per
  `--sign-verify=KEYTYPE=inline:PUBKEY` or `--sign-verify=KEYTYPE=file:PATH`,
  followed by `sign-verify` naming the engines, comma separated, in the order
  given.
- `collection-id`, from `--collection-id=ID`.

A remote name is at least one character; every character is alphanumeric or one
of `-`, `_`, `.`; and the first is alphanumeric or `_`. So `_`, `1o`, `a..b`, and
a non-ASCII letter are names, and ``, `-`, `.`, `..`, `a b`, `a/b`, and `a+b` are
not. A refused name reports `error: Invalid remote name <name>` at exit 1 and
writes nothing. `add` and `delete` hold their operand to this rule; the reading
subcommands do not, so a name of any shape simply names no section.

A section already there reports `error: Remote configuration for "<name>" already
exists: (in config)` at exit 1. `--if-not-exists` leaves it as it stands at exit
0, `--force` replaces the section whole, and naming both reports the usage text
and `error: Can only specify one of --if-not-exists and --force`. A `--set` value
holding no `=` reports `error: Missing '=' in KEY=VALUE for --set`, and a
`--sign-verify` value that is not `KEYTYPE=inline:DATA` or `KEYTYPE=file:DATA`
reports `error: Failed to parse KEYTYPE=[inline|file]:DATA in <value>`, both at
exit 1 with no usage text. A missing NAME or URL reports the usage text and
`error: NAME and URL must be specified`.

`remote delete NAME` removes the section and the remote's
`<remote>.trustedkeys.gpg` keyring, and prints nothing at exit 0. A section the
document does not hold reports `error: Remote "<name>" not found` at exit 1,
which `--if-exists` turns into exit 0.

`remote list` prints one name per line, sorted by name, whatever order the
sections appear in. `-u`/`--show-urls` prints each name padded with spaces to the
longest name of the whole list plus two, counted in bytes, followed by the
remote's `url`. A section stating no `url` -- a metalink remote, for one --
reports `error: No "url" option in remote "<name>"` at exit 1 where its turn
comes, so the names before it are already printed.

`remote show-url NAME` prints the `url` value and a newline, and reports the same
two refusals: `error: Remote "<name>" not found` and `error: No "url" option in
remote "<name>"`.

`remote refs NAME` fetches the remote's summary and prints one `NAME:REF` line
per ref the summary lists, in the order it lists them. `-r`/`--revision` adds a
tab and the commit checksum to each line. A remote publishing no summary reports
`error: Remote refs not available; server has no summary file` at exit 1.

`remote summary NAME` fetches the same summary and reports it. `--raw` prints the
whole document in the GVariant text form, with the big-endian fields converted;
`--list-metadata-keys` prints the global metadata keys, sorted;
`--print-metadata-key=KEY` prints one value in the annotated text form, with the
same conversion, and reports `error: No such metadata key '<key>'` at exit 1 for
a key the dict does not hold. A remote publishing no summary reports `error:
Remote server has no summary file`.

The default report prints each ref of field 0, then the refs of every collection
`ostree.summary.collection-map` lists, then the global metadata. One ref reads:

```
* main
    Latest Commit (150 bytes):
      21386ebf0c349ce54f2196fb4ec77f5a4dc57d03d4a4d5a97c61a9542c9e5e23
    Version (ostree.commit.version): 1.2.3
    Timestamp (ostree.commit.timestamp): 2023-11-14T22:30:00+00
```

A blank line follows each ref. A summary stating `ostree.summary.collection-id`
names every ref of field 0 as a pair, `* (org.example.C, main)`, and each
collection-map ref is named as a pair with its own collection. The `Version` line
appears only where the ref metadata carries the key, and its string prints
unquoted. The `Timestamp` line converts the stored big-endian field and renders
it as `YYYY-MM-DDTHH:MM:SS` and a UTC offset.

The global metadata prints in the order the summary stores it, one line per
entry, with a label for each key the format defines:

```
Repository Mode (ostree.summary.mode): archive-z2
Last-Modified (ostree.summary.last-modified): 2026-08-05T19:40:49+00
Has Tombstone Commits (ostree.summary.tombstone-commits): No
Static Deltas (ostree.static-deltas): {'<from>-<to>': <[byte 0xeb, 0x57]>}
Collection Map (ostree.summary.collection-map): (printed above)
Collection ID (ostree.summary.collection-id): org.example.C
ostree.summary.indexed-deltas: true
```

`Last-Modified` converts its big-endian field the way a `Timestamp` line does.
`Has Tombstone Commits` prints `Yes` or `No`. `Collection Map` prints
`(printed above)`, its refs having been reported with the others. A key the
format does not define, `ostree.summary.indexed-deltas` among them, prints its
own name and its value; a string value prints unquoted where the key carries a
label and quoted where it does not. Every value outside the labeled set prints in
the GVariant text form with no type annotation and no byte-order conversion, so a
`t` value stored little-endian reads as the number it holds.

`remote gpg-import NAME [KEY-ID...]` adds the keys of each `-k`/`--keyring=FILE`,
or of standard input under `--stdin`, to the remote's `<remote>.trustedkeys.gpg`
keyring, and prints `Imported <n> GPG key to remote "<name>"` -- `keys` for any
count but one. The count is the keys the keyring did not already hold, so a
repeated import reports `0`. A `KEY-ID` selects the keys it names out of the
source, each resolved the way `gpg` resolves one. Naming both sources reports the
usage text and `error: --keyring and --stdin are mutually exclusive`; a
`--keyring` naming no file reports `error: Error opening file <path>: <reason>`,
which is read before the remote is looked up; and a remote the configuration does
not describe reports `error: GPG: Remote "<name>" not found`, the one message at
this site carrying the prefix.

`remote gpg-list-keys NAME` reports each key of the remote's keyring:

```
Key: FA2B2317C9966572B5D729EDCA965442280A3BB5
  Created: 2026-08-05 20:04:00 +0000
  UID: Ostrya Test <test@example.invalid>
```

A key with more than one user id carries one `UID` line per id, and a keyring
that is absent or holds no key prints nothing at exit 0. The tool follows each
`UID` line with an `Advanced update URL` and a `Direct update URL` line naming
the key's Web Key Directory location, and renders `Created` in the host locale
and time zone; `../conformance/cli-surface.md`, "P3", records both.
