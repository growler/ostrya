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

The crate has no features. It depends on `ostrya-core`, `ostrya-sys`,
`rustix`, and `thiserror`. It links no repository code, no async runtime, no
HTTP client, no TLS stack, and no xz library. A caller that opens a
repository or builds an image takes `ostrya` in its own manifest.

## Entry points

- `Direct` makes each mount in the process itself.
  `Direct::mount_image` mounts an image that the caller opens, over the
  `objects` directory that the caller opens, with the `Verity` value
  that the caller gives. The call opens no repository.
- `Helper` asks the mount daemon for each mount. It serves a caller in
  its own user namespace. The two mount calls take the path of the
  repository and the checksum of the commit, `ostrya_core::Checksum`. The
  caller takes the type from `ostrya-core`, or from `ostrya`, which
  re-exports it. The client opens no repository.
- `Helper::mount_stored` mounts the image of the image commit that a
  commit names as the attachment or the supplement `composefs`, after a
  check of its digest against the key of the commit.
- `Helper::mount_built` mounts an image of a commit that the daemon
  builds in memory.
- `Direct::unmount` and `Helper::unmount` unmount a composefs mount.
- `is_privileged` tells if the process is root in the initial user
  namespace. Such a process mounts with `Direct`, and each other
  process asks the daemon with `Helper`.
- `MountOptions` selects the `Access`, the source label, and the
  attribute flags (`MountFlags`) of a mount.
- `Error` is the error of each fallible operation of the crate.
  `HelperCode` is the class of a failure that the daemon reports.

Each call of the crate blocks the calling thread. A caller on an async
runtime runs the calls on the blocking pool of the runtime.

## The mount daemon

`Helper` sends each request to `ostrya-mountd` over the Unix socket
`DEFAULT_SOCKET`, one request for each connection. The request carries
the paths of the repository and of the target as the caller sees them,
the checksum of the commit, and descriptors of the user namespace and the
mount namespace of the caller. The daemon runs as root:

- It refuses a request whose user namespace is the initial user
  namespace, or does not own the mount namespace of the request.
- It opens the target, the repository, and its `objects` directory in
  the mount namespace of the caller, with the user, the group, and the
  supplementary groups of the caller. It refuses a target or a repository
  on FUSE, and an `objects` directory that is the root of a mount or that
  is on another mount than the repository directory.
- It reads the repository through a copy of its mount with no mount below
  it. Each read of a file opens it with `openat2`, `RESOLVE_BENEATH`, and
  `RESOLVE_NO_SYMLINKS`, so a symlink at any component of its path stops
  the read. The read does not wait on a FIFO, and it refuses a file that is
  not a regular file.
- It checks the digest of the image of an image commit against the key of
  the commit. It does not check a signature of the commit.
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

The daemon reads the repository with its own credentials, as overlayfs
reads the data layer with the credentials of the mounter. The access to
the socket is therefore the trust boundary. A member of the group of
the socket can make the daemon read these files of a repository
directory whose `objects` directory it can open:

- each file below `objects`, which holds the commit object and the
  `.commitmeta` file of the commit, and the commit object, the root
  dirtree, and the file object of `/root.cfs` of its image commit;
- the file `config`.

The daemon also checks if the file `state/<checksum>.commitpartial` of
the image commit exists. The modes of these files, and of the directories
between them and the repository directory, do not stop the read. If the
commit carries the key `ostree.composefs.digest.v0`, the daemon mounts
the image of an image commit only if its fs-verity digest is the key. The
caller can write both the image commit and the commit, so the check does
not limit the objects that an image can name. A refusal tells the caller
if the image commit exists.

## Verity

The `verity` option of the composefs overlay has two values:

- `verity=require`: the kernel compares the fs-verity digest of each
  backing object with the digest in the image when the file opens. A
  changed object then fails to open with `EIO`. Each backed file of the
  image must carry a digest, and each object must be sealed with
  fs-verity.
- `verity=off`: the overlay reads no digest.

The `[ex-integrity] fsverity` key of the repository tells which value is
correct. With `yes`, each object is sealed, and the overlay mounts with
`verity=require`. With `maybe` and `no`, an object can be without a seal,
and the overlay mounts with `verity=off`.

- `Direct::mount_image` does not read the key. The caller reads it and
  gives `Verity::Require` for `yes` alone, and `Verity::Off` for each
  other value.
- The daemon reads the key for each request of `Helper`. With `yes`, an
  image that it builds carries the digest that the kernel holds for each
  object, and an object with no seal fails the build. With `maybe` and
  `no`, an image that it builds carries no digest.

## Repository modes

The repository modes `bare`, `bare-user`, `bare-user-only`,
`bare-split-xattrs`, and `bare-user-shared` can be mounted: each of them
stores the raw content of a file at the loose path that the image names.
An `archive` repository can hold images, but it cannot be mounted,
because it stores compressed `.filez` objects.

- `Direct::mount_image` does not read the mode. The caller gives the
  `objects` directory of a repository of a mode that can be mounted. Over
  the `objects` directory of an `archive` repository, each regular file
  with content fails to open.
- The daemon reads the mode for each request of `Helper`, and refuses
  an `archive` repository.

## Read-write mounts

With `Access::ReadWrite`, a second overlay with an upper directory goes
on the composefs overlay. The upper directory is `<target>/overlay` and
the work directory is `<target>/work`. The mount hides both while it is in
place. Each change goes to the upper directory, and the repository does
not change. Through `Helper`, the user 0 of the user namespace of the
request mounts the second overlay, with the `userxattr` option.

## Memory

For `Helper::mount_built`, the daemon builds the image in a sealed
memory file. The size of the image grows with the number of entries of
the tree, not with the size of the files. The memory counts against the
memory cgroup of the daemon until the unmount. The daemon refuses an
image larger than its limit, 100 MiB by default, before it writes the
image.

A caller of `Direct::mount_image` can give an image in a memory file.
The memory of that file counts against the memory cgroup of the caller
until the unmount and the close of each descriptor of the file.

## The protocol and the mount steps

The mount daemon is a program of its own, `ostrya-mountd`. It uses these
items of the crate:

- `proto` holds the protocol of the daemon: the limits, the kind bytes,
  `proto::Request`, `proto::Failure`, and the calls `proto::send`
  and `proto::recv`, which carry one message with its descriptors.
- `Helper::exchange` runs the client side of one request on a connected
  socket.
- `sys` holds the mount steps. `sys::mount_composefs` mounts an EROFS
  image and stacks the read-only composefs overlay on it.
  `sys::top_overlay` stacks the overlay that the caller sees, and
  `sys::move_onto` moves it onto the target. `sys::Plan` holds the
  settings of a mount, and `Verity` is its `verity` option.

Each call of the two modules blocks the calling thread. The items of
`sys` name types of the `rustix` crate, version 1: `MountAttrFlags` in
`sys::Plan` and `sys::UpperOptions`, and `path::Arg` and `io::Result`
in `sys::open_dir`. A caller that builds these values names `rustix` 1
with the feature `mount` in its own manifest.

## Examples

A process that is root in the initial user namespace mounts an image
file over the objects of a repository:

```rust
use std::fs::File;
use std::os::fd::AsFd;
use std::path::Path;

use ostrya_mount::{Direct, MountOptions, Verity};
let image = File::open("/srv/images/os.cfs")?;
let objects = File::open("/srv/repo/objects")?;
let mut opts = MountOptions::default();
opts.flags.nosuid = true;
opts.flags.nodev = true;
let mounter = Direct::new();
let root = mounter.mount_image(
    image.as_fd(),
    objects.as_fd(),
    Verity::Off,
    Path::new("/mnt/os"),
    &opts,
)?;
// The descriptor of the root keeps the mount in use.
drop(root);
mounter.unmount(Path::new("/mnt/os"))?;
```
