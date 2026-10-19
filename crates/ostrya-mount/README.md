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
- An overlayfs that takes a detached mount as a layer. Each mount gives
  its EROFS mount to overlayfs as a detached mount. A kernel that refuses
  a detached layer refuses each mount. Linux 7.1 accepts it.
- For `Helper`, a running mount daemon, `ostrya-mountd`, and write
  access to its socket. The daemon also gives each layer of its top
  overlay to overlayfs by its descriptor. A kernel that refuses a layer by
  descriptor refuses each request of the daemon. Linux 7.1 accepts it.

## Entry points

- `Direct` makes each mount in the process itself.
- `Helper` asks the mount daemon for each mount. It serves a caller in
  its own user namespace.
- `Mounter` selects `Direct` or `Helper` for the process.
- `Direct::mount_stored` and `Helper::mount_stored` mount the stored
  image of a commit, after a check of its digest against the key of the
  commit.
- `Direct::mount_built` and `Helper::mount_built` build the image of
  a commit in memory and mount it.
- `Direct::mount_image` mounts an image that the caller gives.
- `Direct::unmount` and `Helper::unmount` unmount a composefs mount.
- `MountOptions` selects the `Access` and the source label of a mount.
- `Error` is the error of each fallible operation of the crate.
  `HelperCode` is the class of a failure that the daemon reports.

## The mount daemon

`Helper` sends each request to `ostrya-mountd` over the Unix socket
`DEFAULT_SOCKET`, one request for each connection. The request carries
the paths of the repository and of the target as the caller sees them,
and descriptors of the user namespace and the mount namespace of the
caller. The daemon runs as root:

- It refuses a request whose user namespace is the initial user
  namespace, or does not own the mount namespace of the request.
- It opens the target, the repository, and its `objects` directory in
  the mount namespace of the caller, with the user, the group, and the
  supplementary groups of the caller. It refuses a target or a repository
  on FUSE, and an `objects` directory that is the root of a mount or that
  is on another mount than the repository directory.
- It reads the repository through a copy of its mount with no mount below
  it. Each read of a file follows no symlink, does not wait on a FIFO, and
  refuses a file that is not a regular file.
- It checks the digest of a stored image against the key of the commit.
  It does not check a signature of the commit.
- Each mount has `nosuid` and `nodev`. The EROFS layer takes the ID
  mapping of the user namespace of the request. User 0 of that user
  namespace mounts the top overlay in it: read-only, or read-write with an
  upper directory. The caller can clear `nosuid` and `nodev` on the top
  overlay. A device node in the tree then still does not open, and a
  setuid file changes no id outside the user namespace.
- If the target already carries an overlay mount with the source label
  and the access of the request, the daemon returns the root of that
  mount.
- A connection has 60 seconds for the request and the reply. At that
  time, the daemon stops the request and replies with an error.

The daemon reads the objects with its own credentials, as overlayfs
reads the data layer with the credentials of the mounter. The access to
the socket is therefore the trust boundary. A member of the group of the
socket can read each file below a directory named `objects` that it can
open in a directory that it can open. The mode of the file does not stop
the read.

## Verity

The `[ex-integrity] fsverity` key of the repository selects the `verity`
option of the overlay:

- `yes`: each object is sealed with fs-verity, and the overlay mounts with
  `verity=require`. The kernel compares the fs-verity digest of each
  backing object with the digest in the image when the file opens. A
  changed object then fails to open with `EIO`. A built image carries the
  digest that the kernel holds for each object. An object with no seal
  fails the build.
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
not change. Through `Helper`, the user 0 of the user namespace of the
request mounts the second overlay, with the `userxattr` option.

## Memory

A built image stays in a sealed memory file. The size of the image grows
with the number of entries of the tree, not with the size of the files.
The memory counts until the unmount against the memory cgroup of the
process that builds the image: the caller for `Direct::mount_built`,
and the daemon for `Helper::mount_built`. The daemon refuses an image
larger than its limit, 100 MiB by default, before it writes the image.

## Features

- `smol` (default): the `smol` backend of `ostrya-rt`.
- `tokio`: the `tokio` backend of `ostrya-rt`, for a host on tokio.
- `server`: the connection handler and the worker of `ostrya-mountd`.
  The module is hidden and is not a stable API.

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

`Mounter::from_env` gives `Direct` to root in the initial user
namespace and `Helper` to each other process:

```rust
use std::path::Path;

use ostrya::Repo;
use ostrya_mount::{MountOptions, Mounter};
let repo = Repo::open(Path::new("/srv/repo")).await?;
let (_, commit) = repo.read_commit("os/main").await?;
let mounter = Mounter::from_env()?;
let root = mounter
    .mount_built(&repo, &commit, Path::new("/mnt/os"), &MountOptions::default())
    .await?;
drop(root);
mounter.unmount(Path::new("/mnt/os")).await?;
```
