# ostrya-composefs

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

A byte-exact writer of composefs EROFS images, with an fs-verity hasher.

A caller builds a tree of directories, symlinks, and regular files. The
crate writes the EROFS image of the tree and returns the fs-verity digest of
the image. The image is byte-identical to the composefs image of the
`ostree` command, format version 0. The crate is synchronous and does not
read a repository.

API documentation: <https://docs.rs/ostrya-composefs>

## Entry points

- `Directory` is the root of a tree, and `Node` is one entry of it.
- `Metadata` holds the mode, the owner, the mtime, and the xattrs of a node.
- `Content` is the content of a `Regular` file: empty or a loose object.
- `build_image` writes the image into an `Image` in memory.
- `write_image_to` writes the image through a sink and does not keep it.
- `FsVerityHasher` calculates an fs-verity digest of a byte stream.
- `Error` is the error of the two image writers.

## Examples

```rust
use ostrya_composefs::{Content, Directory, FsVerityHasher, Metadata, Node, Regular};

let mut root = Directory::new(Metadata { mode: 0o755, ..Metadata::default() });
let meta = Metadata { mode: 0o644, ..Metadata::default() };
root.insert("empty", Node::Regular(Regular { meta, content: Content::Empty }));

let image = ostrya_composefs::build_image(&root)?;
assert_eq!(FsVerityHasher::hash(&image.bytes), image.fs_verity);

// The streaming writer writes the same bytes and returns the same digest.
let mut sink = Vec::new();
assert_eq!(ostrya_composefs::write_image_to(&root, &mut sink)?, image.fs_verity);
assert_eq!(sink, image.bytes);
```
