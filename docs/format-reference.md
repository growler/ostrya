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
0777 (reduced by the umask); `objects/` itself is 0775. In `bare-user-shared`
they are 02775 (setgid, shared group).

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
`trusted.ed25519.d/`, plus `revoked.ed25519` and `revoked.ed25519.d/`.

GPG verification (to be reimplemented with sequoia): load N keyrings (binary
and ASCII-armored) into one certificate store, parse the `aay` list of detached
OpenPGP signature packets (concatenated), detached-verify against the signed
bytes, and surface per-signature: valid flag, fingerprint, primary fingerprint,
creation/expiry timestamps, key expiry, revoked/expired/missing state, algorithm
names, user name and email. Trusted keyring for a remote is
`<remote>.trustedkeys.gpg` in the repo or `/etc/ostree/remotes.d/`; the global
dir is `<datadir>/ostree/trusted.gpg.d/`.

## composefs

ostree generates EROFS/composefs images via the external composefs project's
format (EROFS, format version 0). A pure-Rust port must reproduce that output
byte-for-byte because the resulting image's fs-verity digest is stored in commit
metadata under `ostree.composefs.digest.v0` (type `ay`, 32 bytes) and verified
at boot. The image filename is `.ostree.cfs`. Per-file backing is by
`trusted.overlay.redirect` to the bare loose path `<xx>/<rest>.file`; fs-verity
params are SHA-256, block size 4096, salt size 0. This is the highest-risk
sub-project and depends on the EROFS on-disk format and the composefs metadata
layout, both defined by the composefs and EROFS projects rather than by ostree's
public docs.

## tar

The `ostree export` command produces a plain GNU-format tar of a checked-out
tree, not an object-embedding format. Member names are relative paths (root
becomes `.`), numeric uid/gid/mode, all timestamps set to the commit timestamp
with nanoseconds 0, xattrs as `SCHILY.xattr.*` PAX records, and identical
content objects coalesced into tar hardlinks keyed by content checksum. Import
commits an arbitrary filesystem tar into the repo, deferring hardlink resolution
to the end and optionally applying the `/etc` -> `/usr/etc` convention. The
"ostree-in-tar" OCI format is a separate `ostree-ext` (Rust) construct and is
out of scope here.

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
`tmp/`, staging directories -- are created 2775, setgid with the shared
group, so every group member reads and deduplicates every object. `.lock` is
written 0664, so every group member can open it for writing and take the
exclusive lock.

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
