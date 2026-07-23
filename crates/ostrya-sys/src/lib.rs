#![deny(unsafe_code)]

//! Audited `unsafe` syscall wrappers the pure-Rust crates cannot express.
//!
//! The rest of the workspace is `#![forbid(unsafe_code)]`. This crate holds the
//! `rustix` calls that require `unsafe` and cannot be reached through a safe
//! wrapper: the fs-verity ioctls. It is `#![deny(unsafe_code)]` at the crate
//! root with a single scoped `#![allow(unsafe_code)]` on the [`imp`] module, so
//! the audited surface stays confined to one place. Its only dependency is
//! `rustix`.
//!
//! Both entry points target the fs-verity parameters ostree uses: SHA-256,
//! 4096-byte blocks, and a zero-length salt.

mod imp {
    #![allow(unsafe_code)]

    use std::os::fd::AsFd;

    use rustix::io::Result;
    use rustix::ioctl::{Opcode, Setter, Updater, ioctl, opcode};

    /// The SHA-256 fs-verity hash-algorithm identifier.
    const FS_VERITY_HASH_ALG_SHA256: u32 = 1;
    /// The fs-verity block size, in bytes.
    const FS_VERITY_BLOCK_SIZE: u32 = 4096;

    /// The `fsverity_enable_arg` passed to `FS_IOC_ENABLE_VERITY`, matching the
    /// 128-byte `#[repr(C)]` kernel UAPI struct. Every field feeds the ioctl
    /// through the raw pointer; none is read back, so the struct exists for the
    /// kernel ABI rather than for Rust reads.
    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    struct FsverityEnableArg {
        version: u32,
        hash_algorithm: u32,
        block_size: u32,
        salt_size: u32,
        salt_ptr: u64,
        sig_size: u32,
        reserved1: u32,
        sig_ptr: u64,
        reserved2: [u64; 11],
    }

    /// `FS_IOC_ENABLE_VERITY = _IOW('f', 133, struct fsverity_enable_arg)`. The
    /// opcode encodes the 128-byte argument size.
    const FS_IOC_ENABLE_VERITY: Opcode = opcode::write::<FsverityEnableArg>(b'f', 133);

    /// The header of the `fsverity_digest` request. The kernel encodes only
    /// this 4-byte prefix in the `FS_IOC_MEASURE_VERITY` request number, because
    /// the C struct ends in a flexible `digest[]` array.
    #[repr(C)]
    #[allow(dead_code)]
    struct FsverityDigestHeader {
        digest_algorithm: u16,
        digest_size: u16,
    }

    /// `FS_IOC_MEASURE_VERITY = _IOWR('f', 134, struct fsverity_digest)`. The
    /// request number is computed from the flexible-array base header, not from
    /// the digest-sized buffer actually passed.
    const FS_IOC_MEASURE_VERITY: Opcode = opcode::read_write::<FsverityDigestHeader>(b'f', 134);

    /// A `fsverity_digest` sized for a 32-byte (SHA-256) digest.
    #[repr(C)]
    #[allow(dead_code)]
    struct FsverityDigestSha256 {
        digest_algorithm: u16,
        digest_size: u16,
        digest: [u8; 32],
    }

    /// Enable fs-verity on `fd` with SHA-256, 4096-byte blocks, and a zero
    /// salt.
    ///
    /// The kernel refuses `FS_IOC_ENABLE_VERITY` while any writable descriptor
    /// to the inode is open, so `fd` must be a read-only descriptor and the
    /// sole open descriptor to the inode.
    pub fn enable_verity(fd: impl AsFd) -> Result<()> {
        let arg = FsverityEnableArg {
            version: 1,
            hash_algorithm: FS_VERITY_HASH_ALG_SHA256,
            block_size: FS_VERITY_BLOCK_SIZE,
            salt_size: 0,
            salt_ptr: 0,
            sig_size: 0,
            reserved1: 0,
            sig_ptr: 0,
            reserved2: [0; 11],
        };
        // SAFETY: `FS_IOC_ENABLE_VERITY` expects a pointer to a
        // `fsverity_enable_arg`. `FsverityEnableArg` is that 128-byte
        // `#[repr(C)]` struct and the opcode is computed from the same type, so
        // the pointed-to region has the size and layout the kernel reads. The
        // kernel only reads the argument, matching `Setter`, rustix's
        // read-only-pointer pattern for `_IOW` ioctls.
        unsafe {
            let call: Setter<{ FS_IOC_ENABLE_VERITY }, FsverityEnableArg> = Setter::new(arg);
            ioctl(fd, call)
        }
    }

    /// Measure the fs-verity SHA-256 digest the kernel holds for `fd`.
    ///
    /// `fd` must refer to a file with fs-verity enabled; the digest returned is
    /// the same value [`enable_verity`] sealed the inode with.
    pub fn measure_verity(fd: impl AsFd) -> Result<[u8; 32]> {
        let mut digest = FsverityDigestSha256 {
            digest_algorithm: 0,
            // The input `digest_size` is the caller's buffer capacity.
            digest_size: 32,
            digest: [0u8; 32],
        };
        // SAFETY: `FS_IOC_MEASURE_VERITY` reads `digest_size` as the buffer
        // capacity and writes the algorithm, size, and digest bytes back into
        // the same `fsverity_digest`. `FsverityDigestSha256` is that struct
        // sized for a 32-byte digest, so the 32-byte capacity is honest, and
        // the opcode is derived from the flexible-array base header the kernel
        // compares against. `Updater` is rustix's read-write-pointer pattern.
        unsafe {
            let call: Updater<'_, { FS_IOC_MEASURE_VERITY }, FsverityDigestSha256> =
                Updater::new(&mut digest);
            ioctl(fd, call)?;
        }
        Ok(digest.digest)
    }
}

pub use imp::{enable_verity, measure_verity};

#[cfg(test)]
mod tests {
    use super::{enable_verity, measure_verity};
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsFd;

    /// Enabling verity on a filesystem that supports it seals the file (a later
    /// write-open is rejected) and the measured digest is non-zero and stable.
    /// Where the filesystem lacks verity the enable fails and the test skips.
    #[test]
    fn enable_then_measure_roundtrips() {
        let path = std::env::temp_dir().join(format!("ostrya-sys-verity-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(b"hello ostrya verity").unwrap();
            f.sync_all().unwrap();
        }
        // The enable ioctl needs the sole open descriptor to be read-only.
        let ro = File::open(&path).unwrap();
        if enable_verity(ro.as_fd()).is_err() {
            let _ = std::fs::remove_file(&path);
            return;
        }

        let measured = measure_verity(ro.as_fd()).unwrap();
        assert_ne!(measured, [0u8; 32], "a sealed file has a non-zero digest");
        assert_eq!(
            measured,
            measure_verity(ro.as_fd()).unwrap(),
            "the measured digest is stable"
        );
        assert!(
            OpenOptions::new().write(true).open(&path).is_err(),
            "a verity-sealed file rejects write-open"
        );
        let _ = std::fs::remove_file(&path);
    }
}
