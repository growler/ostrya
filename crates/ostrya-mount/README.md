# ostrya-mount

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

Mounts an ostrya commit as a composefs tree on Linux.

A composefs mount has two layers. An EROFS image holds the directories,
the metadata, and the symlinks of the tree, and names the backing object
of each regular file. The object store of the repository holds the
content. overlayfs stacks the two: the EROFS image is the metadata layer,
and `objects/` is the data layer. The mount reads the objects in place and
copies no file. The crate builds on Linux alone.

API documentation: <https://docs.rs/ostrya-mount>

## Requirements

- Linux 6.8 or later, for the `lowerdir+` and `datadir+` options of
  overlayfs.
- EROFS, overlayfs, and the loop device in the kernel.
- `CAP_SYS_ADMIN` in the initial user namespace for `Direct`. The
  kernel makes the EROFS and the overlayfs mounts only with that
  privilege.
- Access to `/dev/loop-control` and to the loop devices, for the loop
  device that carries the image.

## Entry points

- `Direct` makes each mount in the process itself.
- `Direct::mount_stored` mounts the stored image of a commit, after a
  check of its digest against the key of the commit.
- `Direct::mount_built` builds the image of a commit in memory and
  mounts it.
- `Direct::mount_image` mounts an image that the caller gives.
- `Direct::unmount` unmounts a composefs mount.
- `MountOptions` selects the `Access` and the source label of a mount.
- `Error` is the error of each fallible operation of the crate.

## Verity

The `[ex-integrity] fsverity` key of the repository selects the `verity`
option of the overlay:

- `yes`: each object is sealed with fs-verity, and the overlay mounts with
  `verity=require`. The kernel compares the fs-verity digest of each
  backing object with the digest in the image when the file opens. A
  changed object then fails to open with `EIO`. A built image carries the
  digest of each object.
- `maybe` and `no`: the overlay mounts with `verity=off`. A built image
  carries no digest.

## Repository modes

The repository modes `bare`, `bare-user`, `bare-user-only`,
`bare-split-xattrs`, and `bare-user-shared` can be mounted: each of them
stores the raw content of a file at the loose path that the image names.
An `archive` repository can hold and serve images, but it cannot be
mounted.

## Read-write mounts

With `Access::ReadWrite`, a second overlay with an upper directory goes
on the composefs overlay. The upper directory is `<target>/overlay` and
the work directory is `<target>/work`. The mount hides both while it is in
place. Each change goes to the upper directory, and the repository does
not change.

## Memory

`Direct::mount_built` keeps the image in a sealed memory file. The size
of the image grows with the number of entries of the tree, not with the
size of the files. The memory counts against the memory cgroup of the
process until the unmount.

## Features

- `smol` (default): the `smol` backend of `ostrya-rt`.
- `tokio`: the `tokio` backend of `ostrya-rt`, for a host on tokio.

## Examples

```rust
use std::path::Path;

use ostrya::Repo;
use ostrya_mount::{Access, Direct, MountOptions};
let repo = Repo::open(Path::new("/srv/repo")).await?;
let (_, commit) = repo.read_commit("os/main").await?;
let mut opts = MountOptions::default();
opts.access = Access::ReadOnly;
let mounter = Direct::new();
let root = mounter
    .mount_stored(&repo, &commit, Path::new("/mnt/os"), &opts)
    .await?;
// The descriptor of the root keeps the mount in use.
drop(root);
mounter.unmount(Path::new("/mnt/os")).await?;
```
