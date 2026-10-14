# ostrya-sys

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

Wrappers for the Linux fs-verity ioctls and for a read-only memory map.

A caller seals a file with fs-verity and reads the digest and the
parameters that the kernel holds for the sealed file. The seal has the
parameters that ostree uses: SHA-256, 4096-byte blocks, and no salt. A
caller can also map a file read-only. The only dependency of the crate is
`rustix`.

API documentation: <https://docs.rs/ostrya-sys>

## Entry points

- `enable_verity` seals a file with fs-verity.
- `measure_verity` returns the fs-verity digest of a sealed file.
- `read_verity_descriptor` returns the parameters of a sealed file.
- `Mmap` is a read-only memory map of a file.

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
