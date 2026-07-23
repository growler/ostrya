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

Well-known metadata keys: `version` (`s`, the only key without the `ostree.`
prefix), `ostree.architecture` (`s`), `ostree.ref-binding` (`as`),
`ostree.collection-binding` (`s`), `ostree.endoflife` /
`ostree.endoflife-rebase` (`s`), `ostree.source-title` (`s`), `ostree.sizes`
(see below). Ref and collection bindings are added by higher-level operations,
not by the base commit metadata.

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

`ostree.sizes` is written only by archive-mode repositories; the compressed
size is the `.filez` storage size, which makes it the only storage-dependent
commit-metadata field. Observed on ostree 2026.1: requesting size generation
(`commit --generate-sizes`) in a bare or bare-user repository is a silent
no-op -- no key is written, no warning is emitted, and the commit checksum is
byte-identical to the same commit without the request -- while in an archive
repository it adds the key and changes the commit checksum. Cross-mode commit
identity therefore holds exactly when size generation is off on the archive
side.

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

Field 0 `a(s(taya{sv}))` ref array, sorted by ref name with byte-wise
comparison, remote refs excluded. Each entry `(s, (t, ay, a{sv}))`:

- `s` ref name.
- `t` size of the commit object in bytes, written host-order (NOT
  byte-swapped). This is the one asymmetry versus the big-endian timestamps.
- `ay` commit checksum, 32 raw bytes.
- `a{sv}` per-ref metadata: `ostree.commit.timestamp` (`t`, big-endian),
  `ostree.commit.version` (`s`).

Field 1 `a{sv}` global metadata:

- `ostree.static-deltas` -> `a{sv}`: delta-name (`FROM-TO` or `TO`) -> `ay`
  32-byte superblock digest.
- `ostree.summary.last-modified` -> `t` big-endian.
- `ostree.summary.expires` -> `t` big-endian.
- `ostree.summary.mode` -> `s` (default `bare`).
- `ostree.summary.tombstone-commits` -> `b`.
- `ostree.summary.indexed-deltas` -> `b` (currently always true).
- `ostree.summary.collection-id` -> `s`.
- `ostree.summary.collection-map` -> `a{sa(s(taya{sv}))}`, both levels
  byte-wise sorted.

Endianness summary: all `t` timestamps and `expires` are big-endian; the
per-ref commit-object size `t` is host-order. GVariant does not re-sort dicts,
so insertion order is the on-disk order.

### Summary signature -- `a{sv}`

File `summary.sig` at repo root. Same signature keys as detached commit
metadata. The signed payload is the exact byte content of the `summary` file.
Summary and summary.sig are staged and renamed together so they always match.

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

Ref file format: 64-char hex plus a single `\n` (65 bytes). A NULL rev deletes;
an alias is written as a relative symlink. Refspec `remote:ref` maps to
`refs/remotes/remote/ref`; a bare `ref` maps to `refs/heads/ref`. Every ref is
an individual loose file; there is no packed-refs mechanism.

Writing a ref whose file is an alias symlink replaces the symlink with a regular
ref file; the alias target is left unchanged. Observed with the tool by
committing onto an alias and by `ostree refs --create --force`: in both cases
`refs/heads/foo` (a relative symlink to sibling `bar`) became a 65-byte regular
file holding the new checksum, and `refs/heads/bar` kept its old checksum. The
tool writes the ref by renaming a fresh temp file over the target name, and the
rename replaces the symlink at that name instead of following it.

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
and object bytes do not depend on them.

Commit-state markers live at `state/<checksum>.commitpartial`. The reader only
tests the marker's presence, which makes a commit `Partial`. When `fsck` finds a
commit missing a referenced object it writes the marker as a single byte `0x66`
(recovered by observation: feeding the tool a repository with a deleted
referenced object and inspecting the marker it writes shows a 1-byte file
holding `0x66`). The marker is local state and does not enter any checksum.

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
`superblock`, `meta`, and numeric part files `0`, `1`, .... Indexes live at
`delta-indexes/<to_b64[0:2]>/<to_b64[2:]>.index`.

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
`collection-id`, `sign-verify`, `verification-<engine>-key` /
`verification-<engine>-file`.

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
- A boolean is one of `true`, `false`, `1`, `0`, matched exactly. Any other
  spelling (`yes`, `no`, `on`, `off`, mixed case such as `True`, an
  out-of-range number such as `2`, or the empty string) is rejected with a
  "value that cannot be interpreted" error.
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
- `bare`: a content object's inode carries the full logical uid, gid, and mode;
  a symlink is a real symlink owned by the logical uid/gid.
- `bare-user`: a regular-file content object's inode mode is
  `(logical_perm & 0o775) | 0o400` -- owner bits and the group/other read and
  execute bits are kept, owner-read is forced on, and other-write is dropped
  (`0666` stores as `0664`, `0777` as `0775`). A symlink is stored as a regular
  file whose inode is 0644. The inode is owned by the writing process; the
  logical uid/gid live in `user.ostreemeta`.
- `bare-user-shared`: every content object's inode is a fixed 0644.
- `bare-user-only`: a regular-file content object's inode mode is the canonical
  `logical_perm & 0o755` -- group-write and other-write are dropped and no
  special bits are kept (`0664` stores as `0644`, `0666` as `0644`, `0775` as
  `0755`). uid/gid are discarded and no xattrs are stored. Because this mode
  stores no header, the object identity is computed over the canonicalized mode,
  so a `bare-user-only` content object's checksum can differ from the same file
  in the other modes when the input mode is not already canonical. A symlink is
  a real symlink.

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
  output byte-for-byte for the small fixture payloads at every level 1-9. The
  object identity is over the uncompressed bytes, so byte-identity of the stored
  compressed payload is not required for interoperability.

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

The `FS_IOC_ENABLE_VERITY` and `FS_IOC_MEASURE_VERITY` ioctls are the only
syscalls in the write path that require `unsafe`; they live in the audited
`ostrya-sys` crate.

## Commit modifier: canonical permissions, consume, and devino

A filesystem tree is ingested into a repository under a set of options the
tool exposes on `ostree commit` and the port models as a commit modifier.
Two of these options change the object bytes and are recovered by black-box
observation; the rest are ingest mechanics with no on-disk effect.

Canonical permissions. The tool's `--canonical-permissions` option (the port's
`CANONICAL_PERMISSIONS`) forces owner 0:0 and reduces each permission set to a
canonical form. Recovered by committing files and directories of assorted modes
with and without the option into an archive repository and reading the modes
back with `ostree ls -R`:

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
- A symlink is unchanged; its mode stays `S_IFLNK | 0o777`.

This is the same permission rule `bare-user-only` applies to its inodes
(`perm & 0o755`, see the loose-object inode-mode notes above). Because the
canonicalized mode enters the file-content header, canonical ingest changes an
object's identity, and therefore the dirtree and commit checksums, whenever an
input mode is not already canonical (confirmed: the canonical commit checksum
differs from the same tree committed 0:0 without the option).

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

Devino cache. The tool's `--link-checkout-speedup` builds a `(device, inode)`
to checksum map so a source file that is a hardlink to an existing repository
object is matched by its inode without being re-read, and `--devino-canonical`
(`-I`, which implies the speedup) additionally assumes a matched object is
unmodified and trusts the mapped checksum outright. The cache is populated by
checkout (which records the inode of each object it writes) and consulted at
ingest. A cache hit contributes the mapped checksum and stages no object. The
mapping is a hashing shortcut with no on-disk effect: the object it names is
identical to what re-hashing the file would produce.

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
- Unprivileged: no chown and no xattrs. A regular file's mode is `mode & 0o777`,
  so the setuid, setgid, and sticky bits are dropped and the rwx bits including
  group- and other-write are kept (`4755` becomes `0755`, `0666` stays `0666`). A
  directory's mode is the full `mode & 0o7777`, so its special bits are kept
  (`2755` stays `2755`). A symlink is a real symlink with no chown and no xattrs.

Observed on a `bare` repository holding a tree of assorted modes: `f0666` checks
out `0666` under both modes; `f4755` checks out `4755` faithful and `0755`
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
16 MiB (advisory). Delta part version 0.

Opcodes (ASCII): `S` open-splice-and-close, `o` open, `w` write, `r`
set-read-source, `R` unset-read-source, `c` close, `B` bspatch. Operands are
LEB128 varints. The `c` (close) opcode asserts the produced object's SHA-256
equals the expected checksum: this is the end-to-end integrity gate.

Endianness hazard: the `u`/`t` fields in meta entries, fallbacks, and fallback
headers are host byte order gated by an `ostree.endianness` byte (`l`/`B`) in
superblock metadata (a historical inconsistency, with a size-ratio heuristic
fallback when the byte is missing). The superblock timestamp is always BE; the
`(uuu)` mode triple is always BE.

## Signing details

The signing engines share commit/summary framing. What is signed:

- Commit: the canonical serialized commit GVariant bytes (the normal-form
  commit object -- the same bytes that hash to the commit checksum).
- Summary: the raw byte content of the `summary` file (treated as opaque).

Signatures accumulate by appending an `ay` element to the per-engine `aay` in
the `a{sv}` dict. GPG and the sign-api engines are independent and can both
apply to one commit.

ed25519: 32-byte public key, 64-byte signature, 64-byte secret key (32-byte
seed followed by 32-byte public key). Keys are passed as base64 strings or raw
`ay`. Key files hold one base64 key per line. System key directories are
`/etc/ostree` and `<datadir>/ostree`, files `trusted.ed25519` and
`trusted.ed25519.d/`, plus `revoked.ed25519` and `revoked.ed25519.d/`. A key
present in both the trusted and revoked sets is rejected: the effective trusted
set is the trusted set minus the revoked set.

GPG verification (to be reimplemented with sequoia): load N keyrings (binary
and ASCII-armored) into one certificate store, parse the `aay` list of detached
OpenPGP signature packets (concatenated), detached-verify against the signed
bytes, and surface per-signature: valid flag, fingerprint, primary fingerprint,
creation/expiry timestamps, key expiry, revoked/expired/missing state, algorithm
names, user name and email. Trusted keyring for a remote is
`<remote>.trustedkeys.gpg` in the repo or `/etc/ostree/remotes.d/`; the global
dir is `<datadir>/ostree/trusted.gpg.d/`.

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
or not the commit carries that metadata.

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
flat-inline with the target stored inline, promoted to a data block only when
the inode header, xattrs, and target would fill a block. Whiteout stubs are
character devices, flat-plain, `i_u` 0.

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
padded to a 4-byte boundary.

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
  `/cf/ffd52f38d14c87cf46e18d5260074421ba5961f0895954e9921f165f9c91db.file`);
- `trusted.overlay.metacopy`, a 36-byte record in the verity image: version
  byte 0, length byte 36, flags byte 0, digest-algorithm byte 1 (SHA-256), then
  the 32-byte fs-verity digest of the backing object.
  `composefs-info measure-file <object>.file` reports the same 32 bytes. The
  noverity image writes an empty metacopy value.

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

`tree-rich.cfs` is a second verity image whose source tree carries user
xattrs, and `tree-rich.dump` is its `composefs-info dump` (xattrs appear as
trailing `name=value` tokens). Its commit is made without `--no-xattrs`, so it
is generated on a host that applies no SELinux labels. The MANIFEST records
`composefs_rich_commit` and `composefs_rich_digest`. The tree exercises
shared-xattr promotion (`user.shared` on six inodes), inline xattrs, a
multi-block directory with an inline dirent tail, xattr values of varied length,
and a 4063-byte inline symlink. A 4064-byte symlink target is the point at which
the tool aborts rather than promote a no-xattr symlink to a data block, so 4063
is the largest reachable inline target.

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
