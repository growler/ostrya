#![deny(unsafe_code)]

//! Wrappers for the Linux fs-verity ioctls and for a read-only memory map.
//!
//! A caller seals a file with fs-verity and reads the digest and the
//! parameters that the kernel holds for the sealed file. The seal has the
//! parameters that ostree uses: SHA-256, 4096-byte blocks, and no salt. A
//! caller can also map a file read-only. The only dependency of the crate is
//! `rustix`.
//!
//! # Entry points
//!
//! - [`enable_verity`] seals a file with fs-verity.
//! - [`measure_verity`] returns the fs-verity digest of a sealed file.
//! - [`read_verity_descriptor`] returns the parameters of a sealed file.
//! - [`Mmap`] is a read-only memory map of a file.
//!
//! # Examples
//!
//! The example seals a file and reads its parameters and its digest. The file
//! system of the file must support fs-verity.
//!
//! ```no_run
//! use std::fs::File;
//!
//! use ostrya_sys::{enable_verity, measure_verity, read_verity_descriptor};
//!
//! // A read-only descriptor, and no writable descriptor to the file.
//! let file = File::open("object.file")?;
//! enable_verity(&file)?;
//! let desc = read_verity_descriptor(&file)?;
//! // SHA-256, 4096-byte blocks (2 to the power 12), and no salt.
//! assert_eq!((desc.hash_algorithm, desc.log_blocksize, desc.salt_size), (1, 12, 0));
//! let digest: [u8; 32] = measure_verity(&file)?;
//! # let _ = digest;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! This crate holds all `unsafe` code of the ostrya library crates. A
//! `SAFETY` comment on each `unsafe` block gives its reasoning.

// All other library crates of ostrya are `#![forbid(unsafe_code)]`. This crate
// holds the `rustix` calls that need `unsafe` and that no safe `rustix` wrapper
// gives. The crate root is `#![deny(unsafe_code)]`. Each of the modules `imp`
// and `mmap` has a scoped `#![allow(unsafe_code)]`, so the audited `unsafe`
// code stays in these two modules.

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

    /// The `fsverity_enable_arg` argument of `FS_IOC_ENABLE_VERITY`.
    ///
    /// The struct has the layout of the 128-byte kernel UAPI struct. The
    /// kernel reads each field through the raw pointer. No Rust code reads a
    /// field, so the struct exists only for the kernel ABI.
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

    /// The 4-byte header of the `fsverity_digest` request.
    ///
    /// The `FS_IOC_MEASURE_VERITY` request number encodes only the size of
    /// this header, because the C struct ends in a flexible `digest[]` array.
    #[repr(C)]
    #[allow(dead_code)]
    struct FsverityDigestHeader {
        digest_algorithm: u16,
        digest_size: u16,
    }

    /// `FS_IOC_MEASURE_VERITY = _IOWR('f', 134, struct fsverity_digest)`. The
    /// request number comes from `FsverityDigestHeader`, the base header of the
    /// flexible array. The buffer that the call passes is larger.
    const FS_IOC_MEASURE_VERITY: Opcode = opcode::read_write::<FsverityDigestHeader>(b'f', 134);

    /// A `fsverity_digest` with space for a 32-byte SHA-256 digest.
    #[repr(C)]
    #[allow(dead_code)]
    struct FsverityDigestSha256 {
        digest_algorithm: u16,
        digest_size: u16,
        digest: [u8; 32],
    }

    /// Enables fs-verity on `fd` with SHA-256, 4096-byte blocks, and no salt.
    ///
    /// `fd` must be a read-only descriptor. The kernel refuses the call while a
    /// process has the file open for writing, also through a writable memory
    /// map. Other read-only descriptors to the file can stay open. After the
    /// call, an open of the file for writing fails with `EPERM`.
    ///
    /// # Errors
    ///
    /// The function returns the `Errno` of the `FS_IOC_ENABLE_VERITY` ioctl.
    /// The Linux kernel documentation of fs-verity gives these values:
    ///
    /// - `ETXTBSY` if the file is open for writing through `fd`, another
    ///   descriptor, or a writable memory map.
    /// - `EEXIST` if fs-verity is already enabled on the file.
    /// - `EACCES` if the process has no write access to the file.
    /// - `EPERM` if the file is append-only, or if the kernel requires a
    ///   built-in signature. This function gives no signature.
    /// - `EROFS` if the file system is read-only.
    /// - `EISDIR` if `fd` refers to a directory.
    /// - `EINVAL` if the file system does not accept a 4096-byte block, or if
    ///   `fd` refers to neither a regular file nor a directory.
    /// - `ENOTTY` or `EOPNOTSUPP` if the file system or the kernel has no
    ///   fs-verity support.
    /// - `EINTR` if a fatal signal interrupts the call.
    /// - Another `Errno` for other failures.
    ///
    /// If `fd` is open for writing only, Linux 6.18 on btrfs returns `EBADF`.
    /// The kernel documentation does not state this value.
    pub fn enable_verity(fd: impl AsFd) -> Result<()> {
        enable(fd, &[])
    }

    /// Enables fs-verity on `fd` with SHA-256, 4096-byte blocks, and `salt`.
    ///
    /// The tests use this function to seal a file with parameters that are
    /// not the parameters of ostree. The descriptor rules of [`enable_verity`]
    /// apply.
    ///
    /// # Errors
    ///
    /// - `EINVAL` if the length of `salt` does not fit in a `u32`.
    /// - `EMSGSIZE` from the kernel if `salt` is longer than 32 bytes.
    /// - The `Errno` values of [`enable_verity`].
    #[doc(hidden)]
    pub fn enable_verity_with_salt(fd: impl AsFd, salt: &[u8]) -> Result<()> {
        enable(fd, salt)
    }

    /// Enables fs-verity on `fd` with SHA-256, 4096-byte blocks, and `salt`.
    /// An empty `salt` gives a null salt pointer.
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
        // `#[repr(C)]` struct. The opcode comes from the same type, so the
        // memory at the pointer has the size and the layout that the kernel
        // reads. The kernel only reads the argument. This matches `Setter`, the
        // rustix pattern for the read-only pointer of an `_IOW` ioctl. A
        // nonzero `salt_ptr` points to `salt`, which is borrowed for this whole
        // call. `salt_size` is the length of `salt`, so the kernel reads only
        // live bytes. The ioctl is synchronous, so the kernel holds no pointer
        // after it returns.
        unsafe {
            let call: Setter<{ FS_IOC_ENABLE_VERITY }, FsverityEnableArg> = Setter::new(arg);
            ioctl(fd, call)
        }
    }

    /// Returns the fs-verity SHA-256 digest that the kernel holds for `fd`.
    ///
    /// `fd` must refer to a file with fs-verity enabled, for example by
    /// [`enable_verity`]. The function returns the digest of each file sealed
    /// with SHA-256, also with a salt or another block size.
    /// [`read_verity_descriptor`] returns these parameters.
    ///
    /// # Errors
    ///
    /// - `EINVAL` if the kernel reports a hash algorithm that is not SHA-256,
    ///   or a digest size that is not 32 bytes.
    /// - `ENODATA` from the kernel if fs-verity is not enabled on the file.
    /// - `EOVERFLOW` from the kernel if the digest of the file is longer than
    ///   32 bytes. A file sealed with SHA-512 has a 64-byte digest.
    /// - `ENOTTY` or `EOPNOTSUPP` from the kernel if the file system or the
    ///   kernel has no fs-verity support.
    /// - Another `Errno` from the `FS_IOC_MEASURE_VERITY` ioctl.
    pub fn measure_verity(fd: impl AsFd) -> Result<[u8; 32]> {
        let mut digest = FsverityDigestSha256 {
            digest_algorithm: 0,
            // On input, `digest_size` is the capacity of the buffer.
            digest_size: 32,
            digest: [0u8; 32],
        };
        // SAFETY: `FS_IOC_MEASURE_VERITY` reads `digest_size` as the capacity
        // of the buffer. It writes the algorithm, the size, and the digest
        // bytes back into the same `fsverity_digest`. `FsverityDigestSha256`
        // is that struct with space for a 32-byte digest, so the capacity of
        // 32 bytes is correct. The opcode comes from the base header of the
        // flexible array, which is the size that the kernel compares against.
        // `Updater` is the rustix pattern for a read-write pointer.
        unsafe {
            let call: Updater<'_, { FS_IOC_MEASURE_VERITY }, FsverityDigestSha256> =
                Updater::new(&mut digest);
            ioctl(fd, call)?;
        }
        // The kernel reports the algorithm that sealed the file. The bytes are
        // an ostree digest only for SHA-256 with 32 bytes.
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

    /// The `fsverity_read_metadata_arg` argument of
    /// `FS_IOC_READ_VERITY_METADATA`.
    ///
    /// The struct has the layout of the 40-byte kernel UAPI struct. The kernel
    /// reads each field and writes no field back.
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

    /// The `FS_IOC_READ_VERITY_METADATA` call.
    ///
    /// The kernel writes into the buffer at `buf_ptr` and returns the number of
    /// bytes that it wrote. No rustix pattern returns this count. The lifetime
    /// ties the call to the mutable borrow of the buffer, so the buffer lives
    /// longer than the call.
    struct ReadMetadata<'a> {
        arg: FsverityReadMetadataArg,
        buf: PhantomData<&'a mut [u8]>,
    }

    impl<'a> ReadMetadata<'a> {
        /// Returns a request that reads the fs-verity descriptor into `buf`.
        ///
        /// The read starts at offset 0. The pointer and the length come from
        /// the same slice, so the kernel obeys the length of the memory at the
        /// pointer.
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

    // SAFETY: the opcode is the `_IOWR` number that comes from the argument
    // type that the kernel expects, and `as_ptr` points at that argument. The
    // kernel writes into the user buffer that the argument names, so the call
    // changes user memory and `IS_MUTATING` is true. `output_from_ptr` reads
    // nothing through the pointer. It converts the non-negative byte count
    // that a successful call returns.
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

    /// The fs-verity parameters of a sealed file, from its `fsverity_descriptor`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VerityDescriptor {
        /// The format version of the descriptor, which the kernel sets to 1.
        pub version: u8,
        /// The identifier of the hash algorithm, 1 for SHA-256.
        pub hash_algorithm: u8,
        /// The base-2 logarithm of the Merkle-tree block size, 12 for 4096 bytes.
        pub log_blocksize: u8,
        /// The length of the salt in bytes, 0 if the file has no salt.
        pub salt_size: u8,
        /// The size of the file data in bytes at the time of the seal.
        pub data_size: u64,
    }

    /// Returns the fs-verity parameters that the kernel holds for `fd`.
    ///
    /// `fd` must refer to a file with fs-verity enabled. A caller can use the
    /// result to accept the digest of [`measure_verity`] only for a file
    /// sealed with the parameters of ostree: SHA-256, 4096-byte blocks, and no
    /// salt.
    ///
    /// # Errors
    ///
    /// - `ENODATA` from the kernel if fs-verity is not enabled on the file.
    /// - `ENOTTY` from the kernel if the file system does not implement
    ///   fs-verity or the `FS_IOC_READ_VERITY_METADATA` ioctl. The ioctl is
    ///   available since Linux 5.12.
    /// - `EOPNOTSUPP` from the kernel if the kernel or the file system has no
    ///   fs-verity support.
    /// - `EINTR` from the kernel if a signal interrupts the call before it
    ///   reads data.
    /// - `EIO` if the kernel returns fewer than 256 bytes, the size of the
    ///   descriptor struct. An interrupt can give a short read.
    /// - Another `Errno` from the `FS_IOC_READ_VERITY_METADATA` ioctl.
    pub fn read_verity_descriptor(fd: impl AsFd) -> Result<VerityDescriptor> {
        let mut buf = [0u8; DESCRIPTOR_SIZE];
        // SAFETY: `ReadMetadata::descriptor` takes `buf_ptr` and `length` from
        // the same mutable borrow of `buf`. `buf` is a local that lives longer
        // than this call, so the kernel writes at most `buf.len()` bytes into
        // memory that this function owns. The borrow ends when `ioctl`
        // consumes the request. The ioctl is synchronous, so the kernel holds
        // no pointer after it returns. The function reads `buf` only after the
        // call.
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

    // The static-delta reader of the `ostrya` crate maps a decompressed part or
    // a source object that it wrote to a temp file. Random access to these
    // bytes (splice offsets, bspatch source seeks) then costs address space and
    // demand-paged file cache, and no resident heap. The reader maps only
    // anonymous temp files that it alone holds, so no other writer can make
    // one shorter. The reader maps a blob only if the blob is larger than its
    // heap threshold.

    /// A read-only, private memory map of an open file.
    ///
    /// The map is never written. It keeps the mapped pages alive on its own,
    /// so the caller can close the file descriptor after
    /// [`Mmap::read_only`] returns.
    ///
    /// # Truncation
    ///
    /// A read of a mapped page with no file bytes behind it raises `SIGBUS`.
    /// No safe API can expose this signal, so [`Mmap::read_only`] measures the
    /// file and refuses a map longer than the file. [`Mmap::as_slice`] is
    /// sound for the whole life of the map if no writer truncates the file.
    /// The caller must map only a file that no other writer can truncate.
    pub struct Mmap {
        ptr: NonNull<u8>,
        len: usize,
    }

    // SAFETY: the map is read-only and owns its region for its whole life.
    // These two facts make it sound to send the immutable byte view to another
    // thread, or to share it between threads.
    unsafe impl Send for Mmap {}
    unsafe impl Sync for Mmap {}

    impl Mmap {
        /// Maps the first `len` bytes of `fd` read-only.
        ///
        /// `len` must be larger than zero and not larger than the size of the
        /// file. Because the function refuses a `len` larger than the file, a
        /// read of the map cannot raise `SIGBUS` while the file keeps its size.
        ///
        /// # Errors
        ///
        /// - An `Errno` from `fstat` if the function cannot read the size of
        ///   the file.
        /// - `EINVAL` if `len` is larger than the size of the file.
        /// - `EINVAL` from `mmap` if `len` is zero.
        /// - Another `Errno` from `mmap`, for example `EACCES` if `fd` is not
        ///   open for reading.
        ///
        /// # Examples
        ///
        /// ```
        /// use std::fs::File;
        ///
        /// use ostrya_sys::Mmap;
        ///
        /// let path = std::env::temp_dir().join(format!("ostrya-sys-doc-{}", std::process::id()));
        /// std::fs::write(&path, b"ostree")?;
        /// let file = File::open(&path)?;
        /// assert!(Mmap::read_only(&file, 7).is_err(), "longer than the file");
        /// let map = Mmap::read_only(&file, 6)?;
        /// // The map stays valid after the descriptor closes.
        /// drop(file);
        /// assert_eq!(map.as_slice(), b"ostree");
        /// std::fs::remove_file(&path)?;
        /// # Ok::<(), std::io::Error>(())
        /// ```
        pub fn read_only(fd: impl AsFd, len: usize) -> Result<Mmap> {
            // A map longer than the file gives bytes with no file pages behind
            // them, and a read of these bytes raises SIGBUS. The size check
            // here prevents this for each caller of this safe function.
            let size = rustix::fs::fstat(fd.as_fd())?.st_size;
            match i64::try_from(len) {
                Ok(len) if len <= size => {}
                _ => return Err(Errno::INVAL),
            }
            // SAFETY: a null address lets the kernel select the place of the
            // region. PROT_READ with MAP_PRIVATE maps `len` file bytes
            // read-only. The returned pointer is valid for `len` bytes until
            // `munmap`, which `Drop` calls exactly once.
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

        /// Returns the mapped bytes.
        pub fn as_slice(&self) -> &[u8] {
            // SAFETY: `ptr` addresses `len` readable, initialized bytes for the
            // lifetime of `self`, and nothing mutates the region, so a shared
            // slice over it is valid.
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }

        /// Returns the length of the map in bytes.
        pub fn len(&self) -> usize {
            self.len
        }

        /// Returns `true` if the map covers zero bytes.
        ///
        /// The result is always `false`, because [`Mmap::read_only`] refuses a
        /// length of zero.
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
            // SAFETY: `ptr` and `len` are exactly the address and the length
            // of the region that `mmap` returned. This call unmaps the region
            // once, at the end of the life of the map.
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

    /// A map of the whole file gives its bytes back. `Mmap::read_only` refuses
    /// a map longer than the file, because a read past the last file page
    /// raises `SIGBUS`.
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

        // One byte past the end is still inside the mapped page, so only the
        // explicit size check can refuse it.
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

    /// On a file system with fs-verity support, `enable_verity` seals the file,
    /// and a later open for writing fails. The measured digest is nonzero and
    /// stable. If the file system has no fs-verity support, the enable fails
    /// and the test skips.
    #[test]
    fn enable_then_measure_roundtrips() {
        let path = std::env::temp_dir().join(format!("ostrya-sys-verity-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(b"hello ostrya verity").unwrap();
            f.sync_all().unwrap();
        }
        // The enable ioctl needs a read-only descriptor and no writable one.
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

    /// Writes `body` to a new file named for `tag` and opens it read-only, as
    /// the enable ioctl needs.
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

    /// The descriptor of a file that `enable_verity` sealed names SHA-256,
    /// 4096-byte blocks, no salt, and the size of the file. The test skips if
    /// the file system has no fs-verity support.
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

    /// A file sealed with a salt reports the length of the salt. Its digest is
    /// not the digest of the same bytes sealed with no salt. The test skips if
    /// the file system has no fs-verity support.
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
