#![deny(unsafe_code)]

//! Audited `unsafe` syscall wrappers the pure-Rust crates cannot express.
//!
//! The rest of the workspace is `#![forbid(unsafe_code)]`. This crate holds the
//! `rustix` calls that require `unsafe` and cannot be reached through a safe
//! wrapper: the fs-verity ioctls and a read-only memory map. It is
//! `#![deny(unsafe_code)]` at the crate root with a scoped
//! `#![allow(unsafe_code)]` on each `imp`/`mmap` module, so the audited surface
//! stays confined. Its only dependency is `rustix`.
//!
//! The fs-verity entry points target the parameters ostree uses: SHA-256,
//! 4096-byte blocks, and a zero-length salt. [`read_verity_descriptor`]
//! reports the parameters a sealed file carries, so a caller can accept the
//! kernel's digest only for a file sealed with those parameters. [`Mmap`] backs the static-delta
//! reader, giving it random access to a decompressed part or source object that
//! lives in a temp file rather than on the heap.

mod imp {
    #![allow(unsafe_code)]

    use std::marker::PhantomData;
    use std::os::fd::AsFd;

    use rustix::io::{Errno, Result};
    use rustix::ioctl::{Ioctl, IoctlOutput, Opcode, Setter, Updater, ioctl, opcode};

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
        enable(fd, &[])
    }

    /// Enable fs-verity on `fd` with SHA-256, 4096-byte blocks, and `salt`.
    ///
    /// The tests use this to make a file sealed with parameters other than the
    /// ones ostree uses. The kernel refuses a salt longer than 32 bytes. The
    /// descriptor rules of [`enable_verity`] apply.
    #[doc(hidden)]
    pub fn enable_verity_with_salt(fd: impl AsFd, salt: &[u8]) -> Result<()> {
        enable(fd, salt)
    }

    /// Enable fs-verity on `fd` with SHA-256, 4096-byte blocks, and `salt`. An
    /// empty salt passes a null salt pointer.
    fn enable(fd: impl AsFd, salt: &[u8]) -> Result<()> {
        let salt_size = u32::try_from(salt.len()).map_err(|_| Errno::INVAL)?;
        let arg = FsverityEnableArg {
            version: 1,
            hash_algorithm: FS_VERITY_HASH_ALG_SHA256,
            block_size: FS_VERITY_BLOCK_SIZE,
            salt_size,
            salt_ptr: if salt.is_empty() {
                0
            } else {
                salt.as_ptr() as u64
            },
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
        // read-only-pointer pattern for `_IOW` ioctls. A nonzero `salt_ptr`
        // addresses `salt`, which is borrowed for this whole call, and
        // `salt_size` is its length, so the kernel reads only live bytes. The
        // ioctl is synchronous, so the kernel holds no pointer after it returns.
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
        // A file sealed with another algorithm reports that algorithm. The
        // bytes returned are an ostree digest only for SHA-256 with 32 bytes.
        if u32::from(digest.digest_algorithm) != FS_VERITY_HASH_ALG_SHA256
            || digest.digest_size != 32
        {
            return Err(Errno::INVAL);
        }
        Ok(digest.digest)
    }

    /// The `FS_IOC_READ_VERITY_METADATA` metadata type that selects the
    /// fs-verity descriptor.
    const FS_VERITY_METADATA_TYPE_DESCRIPTOR: u64 = 2;
    /// The size of `struct fsverity_descriptor`, in bytes.
    const DESCRIPTOR_SIZE: usize = 256;

    /// The `fsverity_read_metadata_arg` passed to
    /// `FS_IOC_READ_VERITY_METADATA`, matching the 40-byte `#[repr(C)]` kernel
    /// UAPI struct. The kernel reads every field and writes none of them back.
    #[repr(C)]
    #[allow(dead_code)]
    struct FsverityReadMetadataArg {
        metadata_type: u64,
        offset: u64,
        length: u64,
        buf_ptr: u64,
        reserved: u64,
    }

    /// `FS_IOC_READ_VERITY_METADATA = _IOWR('f', 135, struct
    /// fsverity_read_metadata_arg)`. The opcode encodes the 40-byte argument
    /// size.
    const FS_IOC_READ_VERITY_METADATA: Opcode =
        opcode::read_write::<FsverityReadMetadataArg>(b'f', 135);

    /// The `FS_IOC_READ_VERITY_METADATA` call. The kernel writes into the
    /// buffer `buf_ptr` addresses and returns the number of bytes it wrote,
    /// which no rustix pattern returns. The lifetime ties the call to the
    /// mutable borrow of that buffer, so the buffer outlives the call.
    struct ReadMetadata<'a> {
        arg: FsverityReadMetadataArg,
        buf: PhantomData<&'a mut [u8]>,
    }

    impl<'a> ReadMetadata<'a> {
        /// A request for the file's descriptor into `buf`, from offset 0. The
        /// pointer and length come from the one slice, so the length the
        /// kernel honors is the length of the memory behind the pointer.
        fn descriptor(buf: &'a mut [u8]) -> Self {
            ReadMetadata {
                arg: FsverityReadMetadataArg {
                    metadata_type: FS_VERITY_METADATA_TYPE_DESCRIPTOR,
                    offset: 0,
                    length: buf.len() as u64,
                    buf_ptr: buf.as_mut_ptr() as u64,
                    reserved: 0,
                },
                buf: PhantomData,
            }
        }
    }

    // SAFETY: the opcode is the `_IOWR` number computed from the argument type
    // the kernel expects, and `as_ptr` points at that argument. The kernel
    // writes into the user buffer the argument names, so the call mutates user
    // memory and `IS_MUTATING` is true. `output_from_ptr` reads nothing
    // through the pointer; it converts the non-negative byte count a
    // successful call returns.
    unsafe impl Ioctl for ReadMetadata<'_> {
        type Output = usize;

        const IS_MUTATING: bool = true;

        fn opcode(&self) -> Opcode {
            FS_IOC_READ_VERITY_METADATA
        }

        fn as_ptr(&mut self) -> *mut core::ffi::c_void {
            (&mut self.arg as *mut FsverityReadMetadataArg).cast()
        }

        unsafe fn output_from_ptr(
            out: IoctlOutput,
            _: *mut core::ffi::c_void,
        ) -> Result<Self::Output> {
            usize::try_from(out).map_err(|_| Errno::INVAL)
        }
    }

    /// The fields of a file's `fsverity_descriptor` that name the parameters
    /// the file was sealed with.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VerityDescriptor {
        /// The descriptor format version. The kernel writes 1.
        pub version: u8,
        /// The hash-algorithm identifier. SHA-256 is 1.
        pub hash_algorithm: u8,
        /// The base-2 logarithm of the Merkle-tree block size. 4096 bytes is 12.
        pub log_blocksize: u8,
        /// The salt length in bytes. Zero when the file has no salt.
        pub salt_size: u8,
        /// The size of the file's data in bytes when it was sealed.
        pub data_size: u64,
    }

    /// Read the fs-verity descriptor the kernel holds for `fd`.
    ///
    /// `fd` must refer to a file with fs-verity enabled. A file without
    /// fs-verity returns `ENODATA`, and a kernel without the ioctl returns
    /// `ENOTTY`. A descriptor shorter than the 256-byte struct returns `EIO`.
    pub fn read_verity_descriptor(fd: impl AsFd) -> Result<VerityDescriptor> {
        let mut buf = [0u8; DESCRIPTOR_SIZE];
        // SAFETY: `ReadMetadata::descriptor` takes `buf_ptr` and `length` from
        // the one mutable borrow of `buf`, a local that lives past this call,
        // so the kernel writes at most `buf.len()` bytes into memory this
        // function owns. The borrow ends when `ioctl` consumes the request.
        // The ioctl is synchronous, so the kernel holds no pointer after it
        // returns, and `buf` is read only after the call.
        let n = unsafe { ioctl(fd, ReadMetadata::descriptor(&mut buf))? };
        if n < DESCRIPTOR_SIZE {
            return Err(Errno::IO);
        }
        Ok(VerityDescriptor {
            version: buf[0],
            hash_algorithm: buf[1],
            log_blocksize: buf[2],
            salt_size: buf[3],
            data_size: u64::from_le_bytes(buf[8..16].try_into().expect("8-byte field")),
        })
    }
}

pub use imp::{
    VerityDescriptor, enable_verity, enable_verity_with_salt, measure_verity,
    read_verity_descriptor,
};
pub use mmap::Mmap;

mod mmap {
    #![allow(unsafe_code)]

    use std::os::fd::AsFd;
    use std::ptr::NonNull;

    use rustix::io::{Errno, Result};
    use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};

    /// A read-only, private memory map of an open file.
    ///
    /// The static-delta reader maps a decompressed part or source object that
    /// was spilled to a temp file, so random access (splice offsets, bspatch
    /// source seeks) costs address space and demand-paged file cache rather than
    /// resident heap. The mapping is never written and keeps the underlying
    /// pages alive on its own, so the caller may drop the file descriptor once
    /// the map exists.
    ///
    /// A mapping must not extend past the end of its file: reading a mapped page
    /// with no file bytes behind it raises `SIGBUS`, which no safe API may
    /// expose. [`Mmap::read_only`] therefore measures the file itself and
    /// rejects an over-long request, and [`Mmap::as_slice`] is sound for the map's
    /// whole lifetime as long as nothing truncates the file underneath it. The
    /// static-delta reader maps only anonymous temp files it alone holds, so no
    /// other writer can shrink one.
    pub struct Mmap {
        ptr: NonNull<u8>,
        len: usize,
    }

    // SAFETY: the mapping is read-only and owns its region for its whole
    // lifetime, so handing the immutable byte view to another thread is sound.
    unsafe impl Send for Mmap {}
    unsafe impl Sync for Mmap {}

    impl Mmap {
        /// Map the first `len` bytes of `fd` read-only.
        ///
        /// `len` must be nonzero and must not exceed the file's size. A zero
        /// length returns `EINVAL` from `mmap`, and a length past the end of the
        /// file returns `EINVAL` from the size check below, so a map that would
        /// fault on read cannot be built.
        pub fn read_only(fd: impl AsFd, len: usize) -> Result<Mmap> {
            // A map longer than the file would hand out bytes with no file pages
            // behind them, and touching those raises SIGBUS. Measuring the file
            // here keeps that impossible for every caller of this safe function.
            let size = rustix::fs::fstat(fd.as_fd())?.st_size;
            match i64::try_from(len) {
                Ok(len) if len <= size => {}
                _ => return Err(Errno::INVAL),
            }
            // SAFETY: a null address lets the kernel place the region; PROT_READ
            // with MAP_PRIVATE maps `len` file bytes read-only. The returned
            // pointer is valid for `len` bytes until `munmap`, which `Drop`
            // performs exactly once.
            let ptr = unsafe {
                mmap(
                    core::ptr::null_mut(),
                    len,
                    ProtFlags::READ,
                    MapFlags::PRIVATE,
                    fd,
                    0,
                )?
            };
            let ptr = NonNull::new(ptr.cast::<u8>()).expect("mmap returns non-null on success");
            Ok(Mmap { ptr, len })
        }

        /// The mapped bytes.
        pub fn as_slice(&self) -> &[u8] {
            // SAFETY: `ptr` addresses `len` readable, initialized bytes for the
            // lifetime of `self`, and nothing mutates the region, so a shared
            // slice over it is valid.
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }

        /// The mapped length in bytes.
        pub fn len(&self) -> usize {
            self.len
        }

        /// Whether the map covers zero bytes. Always false in practice, since
        /// callers map only when the blob exceeds the heap threshold.
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
    }

    impl std::fmt::Debug for Mmap {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Mmap").field("len", &self.len).finish()
        }
    }

    impl Drop for Mmap {
        fn drop(&mut self) {
            // SAFETY: `ptr`/`len` are exactly the address and length `mmap`
            // returned, unmapped once here at end of life.
            unsafe {
                let _ = munmap(self.ptr.as_ptr().cast(), self.len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Mmap, enable_verity, enable_verity_with_salt, measure_verity, read_verity_descriptor,
    };
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsFd;

    /// A map of the whole file reads its bytes back; a map longer than the file
    /// is refused, since reading past the last file page would raise `SIGBUS`.
    #[test]
    fn maps_the_file_and_refuses_a_longer_map() {
        let path = std::env::temp_dir().join(format!("ostrya-sys-mmap-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let body = b"ostrya mmap bounds";
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(body).unwrap();
            f.sync_all().unwrap();
        }
        let ro = File::open(&path).unwrap();

        let map = Mmap::read_only(ro.as_fd(), body.len()).unwrap();
        assert_eq!(map.as_slice(), body);
        assert_eq!(map.len(), body.len());
        assert!(!map.is_empty());

        // One byte past the end still lies inside the mapped page, so only the
        // explicit size check can reject it.
        assert!(
            Mmap::read_only(ro.as_fd(), body.len() + 1).is_err(),
            "a map longer than the file must be refused"
        );
        // A page past the end, and an empty map.
        assert!(Mmap::read_only(ro.as_fd(), 8192).is_err());
        assert!(Mmap::read_only(ro.as_fd(), 0).is_err());

        drop(map);
        let _ = std::fs::remove_file(&path);
    }

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

    /// Write `body` to a fresh file named for `tag` and open it read-only, the
    /// descriptor the enable ioctl needs.
    fn read_only_file(tag: &str, body: &[u8]) -> (std::path::PathBuf, File) {
        let path = std::env::temp_dir().join(format!("ostrya-sys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(body).unwrap();
            f.sync_all().unwrap();
        }
        let ro = File::open(&path).unwrap();
        (path, ro)
    }

    /// The descriptor of a file [`enable_verity`] sealed names SHA-256,
    /// 4096-byte blocks, no salt, and the file's size. Skips where the
    /// filesystem lacks verity.
    #[test]
    fn descriptor_reports_the_ostree_parameters() {
        let body = b"ostrya verity descriptor".repeat(300);
        let (path, ro) = read_only_file("verity-descriptor", &body);
        if let Err(e) = enable_verity(ro.as_fd()) {
            eprintln!("skipping descriptor check: filesystem lacks fs-verity ({e})");
            let _ = std::fs::remove_file(&path);
            return;
        }

        let desc = read_verity_descriptor(ro.as_fd()).unwrap();
        assert_eq!(desc.version, 1);
        assert_eq!(desc.hash_algorithm, 1, "SHA-256");
        assert_eq!(desc.log_blocksize, 12, "4096-byte blocks");
        assert_eq!(desc.salt_size, 0);
        assert_eq!(desc.data_size, body.len() as u64);
        let _ = std::fs::remove_file(&path);
    }

    /// A file sealed with a salt reports the salt length, and its digest
    /// differs from the digest of the same bytes sealed without a salt. Skips
    /// where the filesystem lacks verity.
    #[test]
    fn descriptor_reports_a_salt() {
        let body = b"ostrya salted verity";
        let (plain_path, plain) = read_only_file("verity-unsalted", body);
        if let Err(e) = enable_verity(plain.as_fd()) {
            eprintln!("skipping salt check: filesystem lacks fs-verity ({e})");
            let _ = std::fs::remove_file(&plain_path);
            return;
        }
        let (path, ro) = read_only_file("verity-salted", body);
        enable_verity_with_salt(ro.as_fd(), &[0x5a; 8]).unwrap();

        let desc = read_verity_descriptor(ro.as_fd()).unwrap();
        assert_eq!(desc.hash_algorithm, 1);
        assert_eq!(desc.log_blocksize, 12);
        assert_eq!(desc.salt_size, 8);
        assert_ne!(
            measure_verity(ro.as_fd()).unwrap(),
            measure_verity(plain.as_fd()).unwrap(),
            "the salt changes the digest"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&plain_path);
    }

    /// A file without fs-verity has no descriptor to read.
    #[test]
    fn descriptor_of_an_unsealed_file_is_an_error() {
        let (path, ro) = read_only_file("verity-unsealed", b"not sealed");
        assert!(read_verity_descriptor(ro.as_fd()).is_err());
        assert!(measure_verity(ro.as_fd()).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
