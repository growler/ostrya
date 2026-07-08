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

Port extension (bare-user-split-attrs mode, not upstream):

- 10 `FILE_BLOB` -- `.fileb` -- raw file payload, keyed by `SHA256(payload)`.
  In this mode a `FILE` is stored on disk as `.filea` (attributes plus a blob
  reference) instead of `.file`. See the dedicated section at the end.

The is-meta predicate is `t` in 2..=6. Types 7/8/9 are not "meta" despite being
auxiliary. The `z` loose-path suffix and the checksum rules both key off the
is-meta predicate. Object string form is `<hexchecksum>.<typestr>`. Object-name
GVariant is `(su)` = (hex-string, objtype-as-u32).

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
the continuation flag). The trailing objtype byte is present on newer commits;
parsers tolerate its absence.

### Dirtree -- `(a(say)a(sayay))`

0. `a(say)` files: (filename `s`, content checksum `ay`=32 bytes), sorted by
   filename with byte-wise comparison.
1. `a(sayay)` dirs: (dirname `s`, dirtree checksum `ay`=32, dirmeta checksum
   `ay`=32), sorted by dirname with byte-wise comparison.

Sort order is mandatory for reproducible checksums. Each filename is validated
(not `.`, not `..`, no `/`, valid UTF-8): this is the path-traversal defense.

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

## Repository modes and on-disk storage

Mode strings: `bare`, `bare-user`, `bare-user-only`, `archive-z2` (alias
`archive`), `bare-split-xattrs`. ARCHIVE always serializes back as
`archive-z2`.

- bare: real files, real uid/gid/mode/xattrs on the inode; root-only for
  faithful writes; checkout hardlinks directly.
- bare-user: metadata in `user.ostreemeta` xattr; inode is root-owned with mode
  forced to `(mode & (S_IFREG|0775)) | S_IRUSR`; symlinks stored as regular
  files; writable unprivileged.
- bare-user-only: no xattr metadata; uid/gid discarded (read back as 0);
  canonical mode on the inode, regular-file bits limited to 0775; works on
  filesystems without xattr support; user-checkout only.
- bare-split-xattrs: like bare-user but xattrs live in `.file-xattrs` objects
  with `.file-xattrs-link` hardlinks keyed by the `.file` checksum. The tool
  reads this mode fully; its write support is experimental, gated, and
  incomplete.
- archive (archive-z2): content zlib-RAW-compressed as `.filez`; header holds
  uid/gid/mode/xattrs; object file itself is chmod 0644; HTTP-servable;
  never hardlinked on checkout.
- bare-user-split-attrs (port extension, development-only): a `File` is split
  into `.filea` (attributes plus a blob reference) and `.fileb` (raw payload,
  content-addressed). See the dedicated section at the end.

Metadata objects are always stored uncompressed. The `z` suffix applies only to
non-meta content objects in archive mode.

## Object store layout

```
<repo>/
  config                          GKeyFile INI, repo root
  objects/<c0c1>/<c2..c63>.<ext>[z]   loose objects
  refs/heads/<ref>                local refs (ref may contain '/')
  refs/remotes/<remote>/<ref>     remote refs
  refs/mirrors/<collection>/<ref> collection refs (lazy)
  state/<checksum>.commitpartial  incomplete-commit markers
  tmp/                            staging (staging-<bootid>-XXXXXX), cache/
  tmp/cache/summaries/            summary cache
  extensions/                     reserved, created empty
  deltas/                         static deltas (lazy)
  delta-indexes/                  delta indexes (lazy)
  uncompressed-objects-cache/     archive checkout cache (lazy)
  summary                         (lazy)
  summary.sig                     (lazy)
```

Loose object path: `objects/<first 2 hex>/<remaining 62 hex>.<typestr>` with a
trailing `z` iff not-meta and archive mode. Checksum must be exactly 64 hex
chars.

Ref file format: 64-char hex plus a single `\n` (65 bytes). A NULL rev deletes;
an alias is written as a relative symlink. Refspec `remote:ref` maps to
`refs/remotes/remote/ref`; a bare `ref` maps to `refs/heads/ref`. Every ref is
an individual loose file; there is no packed-refs mechanism.

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

## Extended attributes

Storage form is GVariant `a(ayay)`: array of (name-bytes, value-bytes). Names
include the namespace prefix and their terminating NUL. Canonicalization sorts
by name with byte-wise comparison and is applied before every serialization and
hash; duplicate and empty names are rejected. Per-mode disposition: bare on the
inode, bare-user inside `user.ostreemeta`, bare-user-only discarded,
bare-split-xattrs as separate objects, archive inside the `.filez` header.
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

## Port extension: bare-user-split-attrs mode

A development-only repository mode introduced by this port; it is not present
upstream. Production repositories (`/sysroot/ostree`) stay `bare`. This mode
supports building images in a shared, multi-developer repository and serving as
a composefs backing store.

Motivation. In `bare-user`, a stored object's inode permission bits are derived
from the file's logical mode, so that a user-mode checkout can hardlink objects
into place. A file with a restrictive logical mode (for example `/etc/shadow`)
therefore produces an object other developers sharing the repository cannot
read. This mode decouples the repository's at-rest storage permissions from the
file's logical permissions.

Object split. A `File` is stored as two on-disk objects:

- `.fileb` -- the raw payload, named `SHA256(payload)`. A content-addressed
  blob with no header.
- `.filea` -- the attributes variant `(uuuusa(ayay)ay)`: the classic 6-field
  file header (uid BE, gid BE, mode BE, rdev must be 0, symlink target, xattrs)
  plus a 7th field `ay` holding the `.fileb` name. Field 6 is present for every
  regular file and empty for symlinks (whose target is in field 4). An empty
  regular file references the shared empty-payload blob (`SHA256("")`).

Identity. The object identity, which is what a dirtree entry stores, is
`SHA256(6-field header ‖ payload)`, unchanged from every other mode. `.filea`
is named by that identity. The split is a storage layout, not a new identity,
so dirtree and commit hashes are byte-identical to `bare`. A commit built in
this mode and pulled into a bare production repository is the same commit. The
new `FILE_BLOB` (`.fileb`) object type is keyed by payload checksum; `.filea`
is how `FILE` is stored in this mode.

Storage permissions. `.filea` and `.fileb` are written with an explicit
`fchmod 0664`; object directories are created setgid with a shared group, so
multiple developers read and write the same repository without lockout.
Duplicate-blob races are harmless (`linkat` with NOREPLACE_IGNORE_EXIST). The
logical mode, uid, gid, and xattrs are held only in `.filea` and are
reconstructed at checkout or composefs export.

Confidentiality. The repository does not preserve file confidentiality through
unix permissions at rest: any user with repository access can read any blob.
The restrictive logical permissions are restored on materialization. This is an
accepted property of a shared development repository.

`ostree.sizes`. Hard-disabled in this mode. It is the only storage-dependent
commit-metadata field, so leaving it off preserves the cross-mode commit
identity the development-to-production workflow relies on.

Checkout. Copy-based: a fresh copy is made and the `.filea` mode is applied to
it. Hardlinking is not used, because a `chmod` on a hardlink would rewrite the
shared blob's uniform mode.

Integrity (fsck). Two levels: `SHA256(header ‖ payload) == filea-name` and
`SHA256(payload) == blobref`.

Reachability (prune). A new edge `filea -> fileb`. A blob is retained while any
`.filea` references it; a commit is fully present only when its referenced
blobs are present.

composefs. This mode is the intended composefs backing store. The EROFS
metadata layer is built from the real `.filea` attributes (mode, uid, gid,
xattrs), and each regular file redirects to its `.fileb` loose path. Per-file
fs-verity is computed over the payload. Ownership is presented through composefs
uid mapping at mount time, so the real root-owned metadata is correct even
inside a rootless, non-root container.
