# ostrya-sys

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

Wrappers for the Linux fs-verity ioctls, a read-only memory map, the loop
device, a sealed memory file, namespace descriptors, ID-mapped mounts,
and socket credentials.

A caller seals a file with fs-verity and reads the digest and the
parameters that the kernel holds for the sealed file. The seal has the
parameters that ostree uses: SHA-256, 4096-byte blocks, and no salt. A
caller can also map a file read-only. On Linux, a caller attaches a file
to a loop device, and writes bytes to a memory file that it then seals.
It reads the type and the owner of a namespace, sets an ID mapping on a
detached mount, reads the groups of the peer of a Unix socket, and takes
the socket that systemd passes. The crate depends on `rustix`. On Linux
it also depends on `libc`, for the two calls that `rustix` does not give:
`mount_setattr` and `SO_PEERGROUPS`.

API documentation: <https://docs.rs/ostrya-sys>

## Entry points

- `enable_verity` seals a file with fs-verity.
- `measure_verity` returns the fs-verity digest of a sealed file.
- `read_verity_descriptor` returns the parameters of a sealed file.
- `Mmap` is a read-only memory map of a file.
- `LoopDevice::attach` attaches a file to a free loop device with a
  `LoopConfig`. Linux only.
- `sealable_memfd` creates a memory file that accepts seals, and
  `seal_contents` seals its bytes and its size. Linux only.
- `ns_type` returns the type of a namespace, and `ns_owner_userns`
  returns the user namespace that owns it. Linux only.
- `mount_setattr_idmap` sets an ID mapping on a detached mount. Linux
  only.
- `peer_groups` returns the supplementary groups of the peer of a Unix
  socket. Linux only.
- `systemd_listen_fd` takes the one socket that systemd passes. Linux
  only.

## Examples

The example seals a file and reads its parameters and its digest. The file
system of the file must support fs-verity.

```rust
use std::fs::File;

use ostrya_sys::{enable_verity, measure_verity, read_verity_descriptor};

// A read-only descriptor, and no writable descriptor to the file.
let file = File::open("object.file")?;
enable_verity(&file)?;
let desc = read_verity_descriptor(&file)?;
// SHA-256, 4096-byte blocks (2 to the power 12), and no salt.
assert_eq!((desc.hash_algorithm, desc.log_blocksize, desc.salt_size), (1, 12, 0));
let digest: [u8; 32] = measure_verity(&file)?;
```

This crate holds all `unsafe` code of the ostrya library crates. A
`SAFETY` comment on each `unsafe` block gives its reasoning.
