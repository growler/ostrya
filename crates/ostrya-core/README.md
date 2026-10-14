# ostrya-core

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

The object model and the on-disk format primitives of ostree.

A caller reads and writes the objects of an ostree repository as bytes in
the on-disk format and computes their checksums. The crate also holds the
format rules for loose paths, ref names, and new commits. It re-exports the
GVariant codec of `ostrya-gvariant` for the metadata of a commit. The crate
compiles on Linux, macOS, and Windows.

API documentation: <https://docs.rs/ostrya-core>

## Entry points

- `Checksum` is the SHA-256 id of an object.
- `Commit` reads and writes a commit object.
- `DirTree` and `DirMeta` read and write the objects of a directory.
- `FileHeader` is the header of a content object.
- `Xattrs` is a sorted set of extended attributes.
- `ObjectType` and `RepoMode` select the `loose_path` of an object.
- `DeflateSink` compresses the payload of an archive-mode content object.
- `KeyFile` reads and writes the repository `config` file.
- `RefPattern` checks and matches one ref pattern with `*` and `**`.
- `RefSelector` selects ref names with a list of positive and negative
  patterns.

## Modules

- `base64`: standard base64 for byte strings of any length.
- `filehdr`: the content-object header, its framing, and its checksum.
- `sizes`: the packed entries of the `ostree.sizes` commit metadata.
- `varint`: the LEB128 varints of the format.

## Examples

```rust
use ostrya_core::{Checksum, DirMeta, ObjectType, RepoMode, Xattrs, loose_path};

// The root directory of a commit: uid 0, gid 0, mode 0755, no xattrs.
let meta = DirMeta { uid: 0, gid: 0, mode: 0o040755, xattrs: Xattrs::empty() };
let checksum = Checksum::sha256(&meta.serialize()?);
let hex = "446a0ef11b7cc167f3b603e585c7eeeeb675faa412d5ec73f62988eb0b6c5488";
assert_eq!(checksum.to_hex(), hex);
let path = loose_path(&checksum, ObjectType::DirMeta, RepoMode::Bare);
assert_eq!(path, format!("44/{}.dirmeta", &hex[2..]));
```
