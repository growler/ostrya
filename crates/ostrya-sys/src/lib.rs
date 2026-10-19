#![deny(unsafe_code)]

//! Wrappers for the Linux fs-verity ioctls, a read-only memory map, the loop
//! device, a sealed memory file, namespace descriptors, ID-mapped mounts,
//! and socket credentials.
//!
//! A caller seals a file with fs-verity and reads the digest and the
//! parameters that the kernel holds for the sealed file. The seal has the
//! parameters that ostree uses: SHA-256, 4096-byte blocks, and no salt. A
//! caller can also map a file read-only. On Linux, a caller attaches a file
//! to a loop device, and writes bytes to a memory file that it then seals.
//! It reads the type and the owner of a namespace, sets an ID mapping on a
//! detached mount, reads the groups of the peer of a Unix socket, and takes
//! the socket that systemd passes. The crate depends on `rustix`. On Linux
//! it also depends on `libc`, for the two calls that `rustix` does not give:
//! `mount_setattr` and `SO_PEERGROUPS`.
//!
//! # Entry points
//!
//! - [`enable_verity`] seals a file with fs-verity.
//! - [`measure_verity`] returns the fs-verity digest of a sealed file.
//! - [`read_verity_descriptor`] returns the parameters of a sealed file.
//! - [`Mmap`] is a read-only memory map of a file.
//! - [`LoopDevice::attach`] attaches a file to a free loop device with a
//!   [`LoopConfig`]. Linux only.
//! - [`sealable_memfd`] creates a memory file that accepts seals, and
//!   [`seal_contents`] seals its bytes and its size. Linux only.
//! - [`ns_type`] returns the type of a namespace, and [`ns_owner_userns`]
//!   returns the user namespace that owns it. Linux only.
//! - [`mount_setattr_idmap`] sets an ID mapping on a detached mount. Linux
//!   only.
//! - [`peer_groups`] returns the supplementary groups of the peer of a Unix
//!   socket. Linux only.
//! - [`systemd_listen_fd`] takes the one socket that systemd passes. Linux
//!   only.
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
// gives. The crate root is `#![deny(unsafe_code)]`. Each of the modules `imp`,
// `mmap`, `loop_dev`, `ns`, and `sock` has a scoped `#![allow(unsafe_code)]`,
// so the audited `unsafe` code stays in these five modules.

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

#[cfg(target_os = "linux")]
pub use loop_dev::{
    LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO, LO_FLAGS_READ_ONLY, LoopConfig, LoopDevice,
};
#[cfg(target_os = "linux")]
pub use memfd::{seal_contents, sealable_memfd};
#[cfg(target_os = "linux")]
pub use ns::{mount_setattr_idmap, ns_owner_userns, ns_type};
#[cfg(target_os = "linux")]
pub use sock::{peer_groups, systemd_listen_fd};

#[cfg(target_os = "linux")]
mod loop_dev {
    #![allow(unsafe_code)]

    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

    use rustix::fs::{CWD, Mode, OFlags, openat};
    use rustix::io::{Errno, Result};
    use rustix::ioctl::{Getter, Ioctl, IoctlOutput, Opcode, Setter, ioctl};

    /// The loop device is read-only.
    pub const LO_FLAGS_READ_ONLY: u32 = 1;
    /// The kernel detaches the backing file at the last close of the device.
    pub const LO_FLAGS_AUTOCLEAR: u32 = 4;
    /// The loop device reads the backing file with direct I/O.
    pub const LO_FLAGS_DIRECT_IO: u32 = 16;

    /// `LOOP_GET_STATUS64`. The loop ioctls use fixed numbers, not the
    /// `_IOC` encoding.
    const LOOP_GET_STATUS64: Opcode = 0x4C05;
    /// `LOOP_CONFIGURE`.
    const LOOP_CONFIGURE: Opcode = 0x4C0A;
    /// `LOOP_CTL_GET_FREE`, an ioctl of `/dev/loop-control`.
    const LOOP_CTL_GET_FREE: Opcode = 0x4C82;
    /// The number of attempts of [`LoopDevice::attach`] when another process
    /// takes the free device first.
    const ATTACH_ATTEMPTS: u32 = 10;

    /// The `loop_info64` struct of the kernel UAPI, 232 bytes.
    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    struct LoopInfo64 {
        lo_device: u64,
        lo_inode: u64,
        lo_rdevice: u64,
        lo_offset: u64,
        lo_sizelimit: u64,
        lo_number: u32,
        lo_encrypt_type: u32,
        lo_encrypt_key_size: u32,
        lo_flags: u32,
        lo_file_name: [u8; 64],
        lo_crypt_name: [u8; 64],
        lo_encrypt_key: [u8; 32],
        lo_init: [u64; 2],
    }

    /// The `loop_config` struct of the kernel UAPI, 304 bytes. The kernel
    /// reads each field through the raw pointer of `LOOP_CONFIGURE`.
    #[repr(C)]
    #[allow(dead_code)]
    struct LoopConfigRaw {
        fd: u32,
        block_size: u32,
        info: LoopInfo64,
        reserved: [u64; 8],
    }

    const _: () = assert!(size_of::<LoopInfo64>() == 232);
    const _: () = assert!(size_of::<LoopConfigRaw>() == 304);
    const _: () = assert!(std::mem::offset_of!(LoopConfigRaw, info) == 8);
    const _: () = assert!(std::mem::offset_of!(LoopInfo64, lo_flags) == 52);

    /// The `LOOP_CTL_GET_FREE` call. The kernel returns the number of a free
    /// loop device as the result of the ioctl. No rustix pattern returns this
    /// value.
    struct GetFree;

    // SAFETY: `LOOP_CTL_GET_FREE` takes no argument and reads no user memory,
    // so the null pointer of `as_ptr` is never read. The call changes no user
    // memory, so `IS_MUTATING` is false. `output_from_ptr` reads nothing
    // through the pointer. It converts the non-negative device number that a
    // successful call returns.
    unsafe impl Ioctl for GetFree {
        type Output = u32;

        const IS_MUTATING: bool = false;

        fn opcode(&self) -> Opcode {
            LOOP_CTL_GET_FREE
        }

        fn as_ptr(&mut self) -> *mut core::ffi::c_void {
            core::ptr::null_mut()
        }

        unsafe fn output_from_ptr(
            out: IoctlOutput,
            _: *mut core::ffi::c_void,
        ) -> Result<Self::Output> {
            u32::try_from(out).map_err(|_| Errno::INVAL)
        }
    }

    /// The configuration of a new loop device.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct LoopConfig {
        /// The logical block size of the device in bytes. The value 0 lets
        /// the kernel choose the default.
        pub block_size: u32,
        /// The device is read-only.
        pub read_only: bool,
        /// The kernel detaches the backing file at the last close of the
        /// device.
        pub autoclear: bool,
        /// The device reads the backing file with direct I/O where the
        /// kernel accepts it. [`LoopDevice::attach`] tells which.
        pub direct_io: bool,
    }

    impl LoopConfig {
        /// Returns the `lo_flags` value of the configuration.
        fn flags(&self) -> u32 {
            let mut flags = 0;
            if self.read_only {
                flags |= LO_FLAGS_READ_ONLY;
            }
            if self.autoclear {
                flags |= LO_FLAGS_AUTOCLEAR;
            }
            if self.direct_io {
                flags |= LO_FLAGS_DIRECT_IO;
            }
            flags
        }
    }

    /// An open loop device with a backing file.
    ///
    /// The value holds an open descriptor of `/dev/loopN`. With
    /// [`LoopConfig::autoclear`], the kernel detaches the backing file at the
    /// last close of the device. A file system that the device holds keeps
    /// the device open until its unmount.
    #[derive(Debug)]
    pub struct LoopDevice {
        fd: OwnedFd,
        number: u32,
    }

    impl LoopDevice {
        /// Attaches `backing` to a free loop device with `cfg`.
        ///
        /// The call asks `/dev/loop-control` for a free device, opens
        /// `/dev/loopN`, and configures it with `LOOP_CONFIGURE` in one step.
        /// The open is read-only for [`LoopConfig::read_only`], and for
        /// reading and writing otherwise. If another process configures the
        /// same device first, the kernel returns `EBUSY`, and the call tries
        /// the next free device, up to 10 times.
        ///
        /// If the kernel refuses [`LoopConfig::direct_io`] with `EINVAL`, the
        /// call configures the same device again without direct I/O. A
        /// backing file that does not accept direct I/O gives this refusal.
        ///
        /// `LOOP_CONFIGURE` is available since Linux 5.8.
        ///
        /// # Errors
        ///
        /// - An `Errno` from the open of `/dev/loop-control` or of
        ///   `/dev/loopN`, for example `EACCES` or `EPERM` for a process with
        ///   no access to the loop devices.
        /// - An `Errno` from `LOOP_CTL_GET_FREE`.
        /// - `EBUSY` if 10 attempts find the device taken.
        /// - `EINVAL` from `LOOP_CONFIGURE` if the kernel refuses a value of
        ///   `cfg` other than [`LoopConfig::direct_io`].
        /// - Another `Errno` from `LOOP_CONFIGURE`.
        pub fn attach(backing: impl AsFd, cfg: &LoopConfig) -> Result<LoopDevice> {
            let control = openat(
                CWD,
                "/dev/loop-control",
                OFlags::RDWR | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            let backing_fd = u32::try_from(backing.as_fd().as_raw_fd()).map_err(|_| Errno::BADF)?;
            let access = if cfg.read_only {
                OFlags::RDONLY
            } else {
                OFlags::RDWR
            };
            let mut attempts = 0;
            loop {
                attempts += 1;
                // SAFETY: `GetFree` is the `LOOP_CTL_GET_FREE` request, which
                // takes no argument. The kernel reads and writes no user
                // memory.
                let number = unsafe { ioctl(&control, GetFree)? };
                let fd = openat(
                    CWD,
                    format!("/dev/loop{number}"),
                    access | OFlags::CLOEXEC,
                    Mode::empty(),
                )?;
                let mut result = configure(&fd, backing_fd, cfg.block_size, cfg.flags());
                if result == Err(Errno::INVAL) && cfg.direct_io {
                    let flags = cfg.flags() & !LO_FLAGS_DIRECT_IO;
                    result = configure(&fd, backing_fd, cfg.block_size, flags);
                }
                match result {
                    Ok(()) => return Ok(LoopDevice { fd, number }),
                    Err(Errno::BUSY) if attempts < ATTACH_ATTEMPTS => continue,
                    Err(e) => return Err(e),
                }
            }
        }

        /// Returns the number `N` of the device `/dev/loopN`.
        pub fn number(&self) -> u32 {
            self.number
        }

        /// Returns the `lo_flags` value that the kernel holds for the device.
        ///
        /// The value is a combination of [`LO_FLAGS_READ_ONLY`],
        /// [`LO_FLAGS_AUTOCLEAR`], [`LO_FLAGS_DIRECT_IO`], and other flags of
        /// the kernel. A kernel can clear [`LO_FLAGS_DIRECT_IO`] when the
        /// backing file does not accept direct I/O.
        ///
        /// # Errors
        ///
        /// - `ENXIO` if the device has no backing file.
        /// - Another `Errno` from `LOOP_GET_STATUS64`.
        pub fn flags(&self) -> Result<u32> {
            // SAFETY: `LOOP_GET_STATUS64` writes one `loop_info64` to the
            // pointer. `LoopInfo64` is that 232-byte `#[repr(C)]` struct, so
            // the kernel writes inside the buffer of `Getter`. Each field is
            // an integer or an integer array, so each bit pattern that the
            // kernel writes is a valid value.
            let info = unsafe {
                let call: Getter<{ LOOP_GET_STATUS64 }, LoopInfo64> = Getter::new();
                ioctl(&self.fd, call)?
            };
            Ok(info.lo_flags)
        }
    }

    /// Runs `LOOP_CONFIGURE` on the loop device `fd` with the backing file
    /// `backing_fd`, the block size `block_size`, and the flags `flags`.
    fn configure(fd: &OwnedFd, backing_fd: u32, block_size: u32, flags: u32) -> Result<()> {
        let raw = LoopConfigRaw {
            fd: backing_fd,
            block_size,
            info: LoopInfo64 {
                lo_device: 0,
                lo_inode: 0,
                lo_rdevice: 0,
                lo_offset: 0,
                lo_sizelimit: 0,
                lo_number: 0,
                lo_encrypt_type: 0,
                lo_encrypt_key_size: 0,
                lo_flags: flags,
                lo_file_name: [0; 64],
                lo_crypt_name: [0; 64],
                lo_encrypt_key: [0; 32],
                lo_init: [0; 2],
            },
            reserved: [0; 8],
        };
        // SAFETY: `LOOP_CONFIGURE` expects a pointer to a `loop_config`.
        // `LoopConfigRaw` is that 304-byte `#[repr(C)]` struct, and the
        // compile-time asserts pin its size and its field offsets. The kernel
        // only reads the argument, which matches `Setter`. `backing_fd` names
        // a descriptor that the caller of `LoopDevice::attach` keeps open for
        // the whole call. The kernel takes its own reference to the backing
        // file, so the caller can close it after the call. The ioctl is
        // synchronous, so the kernel holds no pointer after it returns.
        unsafe {
            let call: Setter<{ LOOP_CONFIGURE }, LoopConfigRaw> = Setter::new(raw);
            ioctl(fd, call)
        }
    }

    impl AsFd for LoopDevice {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }
}

#[cfg(target_os = "linux")]
mod memfd {
    use std::os::fd::{AsFd, OwnedFd};

    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    use rustix::io::Result;

    /// Creates an anonymous memory file that accepts seals.
    ///
    /// The file has the flags `MFD_CLOEXEC`, `MFD_ALLOW_SEALING`, and
    /// `MFD_NOEXEC_SEAL`, so no process can execute it. `name` shows in
    /// `/proc/<pid>/fd` as `/memfd:<name>`. The memory of the file counts
    /// against the memory cgroup of the process until the last reference to
    /// the file closes.
    ///
    /// # Errors
    ///
    /// - `EINVAL` if `name` is longer than 249 bytes, or if the kernel does
    ///   not know `MFD_NOEXEC_SEAL`, which Linux 6.3 adds.
    /// - Another `Errno` from `memfd_create`.
    pub fn sealable_memfd(name: &str) -> Result<OwnedFd> {
        memfd_create(
            name,
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::NOEXEC_SEAL,
        )
    }

    /// Seals the content of a memory file from [`sealable_memfd`].
    ///
    /// The call adds `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK`, and
    /// `F_SEAL_SEAL`. After the call, no process can change the bytes or the
    /// size of the file, and no process can remove a seal.
    ///
    /// # Errors
    ///
    /// - `EBUSY` if a writable shared memory map of the file exists.
    /// - `EPERM` if the file has `F_SEAL_SEAL` already.
    /// - Another `Errno` from `fcntl(F_ADD_SEALS)`.
    pub fn seal_contents(fd: impl AsFd) -> Result<()> {
        fcntl_add_seals(
            fd,
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )
    }
}

#[cfg(target_os = "linux")]
mod ns {
    #![allow(unsafe_code)]

    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};

    use rustix::io::{Errno, Result};
    use rustix::ioctl::{Ioctl, IoctlOutput, Opcode, ioctl, opcode};
    use rustix::thread::LinkNameSpaceType;

    /// The ioctl group of the namespace file descriptors.
    const NSIO: u8 = 0xb7;
    /// `NS_GET_USERNS = _IO(0xb7, 0x1)`: the owner user namespace.
    const NS_GET_USERNS: Opcode = opcode::none(NSIO, 0x1);
    /// `NS_GET_NSTYPE = _IO(0xb7, 0x3)`: the `CLONE_NEW*` type.
    const NS_GET_NSTYPE: Opcode = opcode::none(NSIO, 0x3);

    /// A namespace ioctl that takes no argument and returns an integer as
    /// the result of the call.
    struct NoArg {
        opcode: Opcode,
    }

    // SAFETY: the two namespace requests that use this type take no argument
    // and read no user memory, so the null pointer of `as_ptr` is never read.
    // The calls change no user memory, so `IS_MUTATING` is false.
    // `output_from_ptr` reads nothing through the pointer. It returns the
    // non-negative integer that a successful call returns.
    unsafe impl Ioctl for NoArg {
        type Output = IoctlOutput;

        const IS_MUTATING: bool = false;

        fn opcode(&self) -> Opcode {
            self.opcode
        }

        fn as_ptr(&mut self) -> *mut core::ffi::c_void {
            core::ptr::null_mut()
        }

        unsafe fn output_from_ptr(
            out: IoctlOutput,
            _: *mut core::ffi::c_void,
        ) -> Result<Self::Output> {
            Ok(out)
        }
    }

    /// Returns the type of the namespace that `fd` refers to.
    ///
    /// `fd` is a descriptor of a namespace file, for example an open
    /// `/proc/<pid>/ns/user`.
    ///
    /// # Errors
    ///
    /// - `ENOTTY` if `fd` does not refer to a namespace.
    /// - `EOPNOTSUPP` if the kernel returns a type that rustix does not
    ///   name.
    /// - Another `Errno` from `NS_GET_NSTYPE`.
    pub fn ns_type(fd: impl AsFd) -> Result<LinkNameSpaceType> {
        // SAFETY: `NS_GET_NSTYPE` takes no argument. The kernel reads and
        // writes no user memory and returns the type as the result.
        let raw = unsafe {
            ioctl(
                fd,
                NoArg {
                    opcode: NS_GET_NSTYPE,
                },
            )?
        };
        let raw = u32::try_from(raw).map_err(|_| Errno::INVAL)?;
        [
            LinkNameSpaceType::Time,
            LinkNameSpaceType::Mount,
            LinkNameSpaceType::ControlGroup,
            LinkNameSpaceType::HostNameAndNISDomainName,
            LinkNameSpaceType::InterProcessCommunication,
            LinkNameSpaceType::User,
            LinkNameSpaceType::ProcessID,
            LinkNameSpaceType::Network,
        ]
        .into_iter()
        .find(|ty| *ty as u32 == raw)
        .ok_or(Errno::OPNOTSUPP)
    }

    /// Returns a descriptor of the user namespace that owns the namespace
    /// `fd`.
    ///
    /// The new descriptor has the close-on-exec flag.
    ///
    /// # Errors
    ///
    /// - `ENOTTY` if `fd` does not refer to a namespace.
    /// - `EINVAL` if `fd` refers to a user namespace with no parent, the
    ///   initial user namespace.
    /// - `EPERM` if the owner is outside the user namespace of the process.
    /// - Another `Errno` from `NS_GET_USERNS`.
    pub fn ns_owner_userns(fd: impl AsFd) -> Result<OwnedFd> {
        // SAFETY: `NS_GET_USERNS` takes no argument. The kernel reads and
        // writes no user memory. A successful call returns a new descriptor
        // that no other value owns, so `OwnedFd` takes ownership of it.
        unsafe {
            let raw = ioctl(
                fd,
                NoArg {
                    opcode: NS_GET_USERNS,
                },
            )?;
            Ok(OwnedFd::from_raw_fd(raw as RawFd))
        }
    }

    /// Sets an ID mapping on the detached mount `mount`, with the user
    /// namespace `userns`.
    ///
    /// The call is `mount_setattr(2)` with `AT_EMPTY_PATH` and
    /// `MOUNT_ATTR_IDMAP`. After the call, the mount shows each file owner
    /// through the mapping of `userns`: the owner `0` in the file system
    /// shows as the user that `0` in `userns` maps to. rustix has no
    /// `mount_setattr`, so the call goes through the `syscall` function of
    /// libc.
    ///
    /// # Errors
    ///
    /// - `EPERM` if the process has no `CAP_SYS_ADMIN` in the user namespace
    ///   that owns the mount, or none in `userns`.
    /// - `EINVAL` if `mount` is not a detached mount that was never attached,
    ///   if it has a mapping already, if `userns` is the initial user
    ///   namespace, or if the file system does not support ID-mapped mounts.
    /// - `EBADF` if `userns` is not a descriptor of a user namespace.
    /// - `ENOSYS` before Linux 5.12.
    /// - Another `Errno` from `mount_setattr`.
    pub fn mount_setattr_idmap(mount: impl AsFd, userns: impl AsFd) -> Result<()> {
        let attr = libc::mount_attr {
            attr_set: libc::MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: u64::try_from(userns.as_fd().as_raw_fd()).map_err(|_| Errno::BADF)?,
        };
        // SAFETY: the arguments are the descriptor of the mount, a pointer to
        // an empty C string that lives for the call, the flags, a pointer to
        // a `mount_attr` that lives for the call, and its size. The kernel
        // only reads the path and the struct, and holds no pointer after the
        // call returns. `libc::mount_attr` is the 32-byte UAPI struct. The
        // call creates and closes no descriptor.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                mount.as_fd().as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint,
                &raw const attr,
                size_of::<libc::mount_attr>(),
            )
        };
        if ret < 0 {
            return Err(Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::IO));
        }
        Ok(())
    }

    const _: () = assert!(size_of::<libc::mount_attr>() == 32);
}

#[cfg(target_os = "linux")]
mod sock {
    #![allow(unsafe_code)]

    use std::ffi::OsStr;
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicBool, Ordering};

    use rustix::io::{Errno, FdFlags, Result, fcntl_setfd};

    /// The descriptor of the first socket that systemd passes,
    /// `SD_LISTEN_FDS_START`.
    const LISTEN_FD: i32 = 3;

    /// The number of groups that the first `SO_PEERGROUPS` call has space
    /// for.
    const FIRST_GROUPS: usize = 64;

    /// Returns the raw ids of the supplementary groups of the peer of the
    /// Unix socket `sock`. The peer must have at most `max` groups.
    ///
    /// The kernel records the groups when the peer connects, or when it
    /// creates the socket pair. The list is in the order of the kernel.
    ///
    /// # Errors
    ///
    /// - `ERANGE` if the peer has more than `max` groups.
    /// - `ENODATA` if the socket has no peer credentials, for example a
    ///   listening socket.
    /// - `ENOTSOCK` if `sock` is not a socket, and `ENOPROTOOPT` if it is not
    ///   a Unix socket.
    /// - Another `Errno` from `getsockopt(SO_PEERGROUPS)`.
    pub fn peer_groups(sock: impl AsFd, max: usize) -> Result<Vec<u32>> {
        let fd = sock.as_fd().as_raw_fd();
        let mut groups: Vec<libc::gid_t> = vec![0; FIRST_GROUPS.min(max)];
        loop {
            let mut len = libc::socklen_t::try_from(groups.len() * size_of::<libc::gid_t>())
                .map_err(|_| Errno::RANGE)?;
            // SAFETY: the buffer holds `len` bytes and lives for the call.
            // The kernel writes at most `len` bytes to it, and writes the
            // length of its data or the length that it needs to `len`.
            let ret = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERGROUPS,
                    groups.as_mut_ptr().cast(),
                    &raw mut len,
                )
            };
            let need = len as usize / size_of::<libc::gid_t>();
            if ret == 0 {
                groups.truncate(need);
                return Ok(groups);
            }
            let errno = Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::IO);
            if errno != Errno::RANGE || need <= groups.len() || need > max {
                return Err(errno);
            }
            groups.resize(need, 0);
        }
    }

    /// Set when [`systemd_listen_fd`] takes the descriptor.
    static TAKEN: AtomicBool = AtomicBool::new(false);

    /// Returns the one socket that systemd passes to the process, and sets
    /// its close-on-exec flag.
    ///
    /// systemd passes the socket as descriptor 3 and sets the environment
    /// variables `LISTEN_PID` and `LISTEN_FDS`. The call accepts them only
    /// when `LISTEN_PID` is the process id of this process and `LISTEN_FDS`
    /// is `1`. It returns `None` if neither variable is set. The call takes
    /// the descriptor once in the life of the process. It leaves the
    /// environment as it is, so a child process that the caller starts must
    /// not inherit the two variables.
    ///
    /// # Errors
    ///
    /// - `EINVAL` if only one of the two variables is set, if `LISTEN_PID`
    ///   is not the process id of this process, or if `LISTEN_FDS` is not
    ///   `1`.
    /// - `EALREADY` if an earlier call took the descriptor.
    /// - `EBADF` if descriptor 3 is not open.
    pub fn systemd_listen_fd() -> Result<Option<OwnedFd>> {
        let pid = std::env::var_os("LISTEN_PID");
        let fds = std::env::var_os("LISTEN_FDS");
        if !listen_vars_match(pid.as_deref(), fds.as_deref(), std::process::id())? {
            return Ok(None);
        }
        if TAKEN.swap(true, Ordering::SeqCst) {
            return Err(Errno::ALREADY);
        }
        // SAFETY: `fcntl(F_GETFD)` takes a raw descriptor number and reads no
        // memory of the process. A closed descriptor 3 gives `EBADF` and no
        // other effect. No Rust value holds the descriptor during the call.
        let flags = unsafe { libc::fcntl(LISTEN_FD, libc::F_GETFD) };
        if flags < 0 {
            return Err(Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::IO));
        }
        // SAFETY: the probe shows that descriptor 3 is open. systemd passed
        // it to this process for its own use, and `TAKEN` makes sure that one
        // `OwnedFd` alone takes it.
        let fd = unsafe { OwnedFd::from_raw_fd(LISTEN_FD) };
        fcntl_setfd(
            &fd,
            FdFlags::from_bits_retain(flags as u32) | FdFlags::CLOEXEC,
        )?;
        Ok(Some(fd))
    }

    /// Checks the values of `LISTEN_PID` and `LISTEN_FDS` for the process
    /// `own_pid`. Returns `false` if neither is set.
    pub(crate) fn listen_vars_match(
        pid: Option<&OsStr>,
        fds: Option<&OsStr>,
        own_pid: u32,
    ) -> Result<bool> {
        match (pid, fds) {
            (None, None) => Ok(false),
            (Some(pid), Some(fds)) => {
                let pid_ok = pid.to_str().and_then(|s| s.parse::<u32>().ok()) == Some(own_pid);
                if pid_ok && fds == "1" {
                    Ok(true)
                } else {
                    Err(Errno::INVAL)
                }
            }
            _ => Err(Errno::INVAL),
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

/// Tests of the loop device and the memory-file helpers.
///
/// The tests of the loop device need access to `/dev/loop-control`, which a
/// root process has. Without access, they skip. If `OSTRYA_REQUIRE_MOUNT` is
/// set, a missing access fails them.
#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::{
        LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO, LO_FLAGS_READ_ONLY, LoopConfig, LoopDevice,
        seal_contents, sealable_memfd,
    };
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsFd, OwnedFd};
    use std::time::{Duration, Instant};

    use rustix::fs::SealFlags;
    use rustix::io::Errno;

    /// The environment variable that turns the skip of a test with no access
    /// to the loop devices into a failure.
    const REQUIRE_MOUNT: &str = "OSTRYA_REQUIRE_MOUNT";

    /// The read-only, auto-clearing configuration with 4096-byte blocks.
    const BASE: LoopConfig = LoopConfig {
        block_size: 4096,
        read_only: true,
        autoclear: true,
        direct_io: false,
    };

    /// Attaches `backing` with `cfg`. Returns `None` and prints a message if
    /// the process has no access to the loop devices and
    /// [`REQUIRE_MOUNT`] is not set.
    fn attach_or_skip(backing: impl AsFd, cfg: &LoopConfig) -> Option<LoopDevice> {
        match LoopDevice::attach(backing, cfg) {
            Ok(dev) => Some(dev),
            Err(e @ (Errno::ACCESS | Errno::PERM | Errno::NOENT)) => {
                assert!(
                    std::env::var_os(REQUIRE_MOUNT).is_none(),
                    "{REQUIRE_MOUNT} is set and the process has no access to the loop devices ({e})"
                );
                eprintln!("skipped: no access to the loop devices ({e})");
                None
            }
            Err(e) => panic!("attach failed: {e}"),
        }
    }

    /// Returns the backing file that the kernel names for device `number`,
    /// or `None` if the device has no backing file.
    fn backing_file(number: u32) -> Option<String> {
        std::fs::read_to_string(format!("/sys/block/loop{number}/loop/backing_file"))
            .ok()
            .map(|s| s.trim_end().to_owned())
    }

    /// Waits up to 5 seconds until device `number` no longer has the backing
    /// file `backing`. The release of an auto-clearing device can finish
    /// after the last close returns. Another test can take the same device
    /// after the release, with another backing file.
    fn wait_detached(number: u32, backing: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while backing_file(number).as_deref() == Some(backing) {
            assert!(Instant::now() < deadline, "loop{number} stays attached");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Returns a sealed memory file that holds 16 KiB.
    fn sealed_image() -> OwnedFd {
        let fd = sealable_memfd("ostrya-sys-loop").unwrap();
        let mut file = File::from(fd);
        file.write_all(&[0x5a; 16384]).unwrap();
        seal_contents(&file).unwrap();
        file.into()
    }

    /// A sealed memory file refuses a write, a larger size, a smaller size,
    /// and a removal of the seal, and still reads.
    #[test]
    fn a_sealed_memfd_refuses_each_change() {
        let fd = sealable_memfd("ostrya-sys-seal").unwrap();
        let mut file = File::from(fd);
        file.write_all(b"sealed bytes").unwrap();
        seal_contents(&file).unwrap();

        let seals = rustix::fs::fcntl_get_seals(&file).unwrap();
        assert!(
            seals
                .contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL)
        );
        file.seek(SeekFrom::Start(0)).unwrap();
        assert!(file.write_all(b"x").is_err(), "a write is refused");
        assert_eq!(
            rustix::fs::ftruncate(&file, 64).unwrap_err(),
            Errno::PERM,
            "a larger size is refused"
        );
        assert_eq!(
            rustix::fs::ftruncate(&file, 1).unwrap_err(),
            Errno::PERM,
            "a smaller size is refused"
        );
        assert_eq!(seal_contents(&file).unwrap_err(), Errno::PERM);

        let mut back = String::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_string(&mut back).unwrap();
        assert_eq!(back, "sealed bytes");
    }

    /// A loop device on a regular file holds the flags of its configuration
    /// and names the file. At the last close, the kernel detaches it.
    #[test]
    fn an_auto_clearing_device_detaches_at_the_last_close() {
        let path = std::env::temp_dir().join(format!("ostrya-sys-loop-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 16384]).unwrap();
        let file = File::open(&path).unwrap();
        let Some(dev) = attach_or_skip(&file, &BASE) else {
            let _ = std::fs::remove_file(&path);
            return;
        };
        let flags = dev.flags().unwrap();
        assert_eq!(
            flags & (LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR),
            LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR
        );
        let number = dev.number();
        let backing = backing_file(number).unwrap();
        assert_eq!(backing, path.to_str().unwrap());

        drop(file);
        drop(dev);
        wait_detached(number, &backing);
        let _ = std::fs::remove_file(&path);
    }

    /// A sealed memory file backs a loop device with a request for direct
    /// I/O. If the kernel refuses direct I/O on it, the device attaches
    /// without direct I/O. The test prints the flags that the kernel holds.
    #[test]
    fn a_sealed_memfd_backs_a_loop_device() {
        let image = sealed_image();
        let cfg = LoopConfig {
            direct_io: true,
            ..BASE
        };
        let Some(dev) = attach_or_skip(&image, &cfg) else {
            return;
        };
        let flags = dev.flags().unwrap();
        eprintln!(
            "loop{} flags {flags:#x}, direct I/O {}",
            dev.number(),
            flags & LO_FLAGS_DIRECT_IO != 0
        );
        assert_ne!(flags & LO_FLAGS_READ_ONLY, 0);
        let number = dev.number();
        let backing = backing_file(number).unwrap();
        drop(image);
        drop(dev);
        wait_detached(number, &backing);
    }
}

/// Tests of the namespace, ID-mapping, and socket helpers. They run as any
/// user.
#[cfg(all(test, target_os = "linux"))]
mod ns_sock_tests {
    use super::{
        mount_setattr_idmap, ns_owner_userns, ns_type, peer_groups, sock::listen_vars_match,
        systemd_listen_fd,
    };
    use std::ffi::OsStr;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::process::Command;

    use rustix::fs::{CWD, Mode, OFlags, fstat, openat};
    use rustix::io::{Errno, FdFlags};
    use rustix::thread::LinkNameSpaceType;

    /// The name of the ignored test that the descriptor test runs in a child
    /// process.
    const LISTEN_CHILD: &str = "ns_sock_tests::listen_fd_child";

    /// Opens `/proc/thread-self/ns/<name>`.
    fn own_ns(name: &str) -> OwnedFd {
        openat(
            CWD,
            format!("/proc/thread-self/ns/{name}"),
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// Returns the device and the inode of `fd`.
    fn dev_ino(fd: impl AsFd) -> (u64, u64) {
        let st = fstat(fd).unwrap();
        (st.st_dev, st.st_ino)
    }

    #[test]
    fn a_namespace_has_its_type() {
        assert_eq!(ns_type(own_ns("user")).unwrap(), LinkNameSpaceType::User);
        assert_eq!(ns_type(own_ns("mnt")).unwrap(), LinkNameSpaceType::Mount);
        assert_eq!(ns_type(own_ns("net")).unwrap(), LinkNameSpaceType::Network);
        let file = std::fs::File::open("/proc/self/status").unwrap();
        assert_eq!(ns_type(&file).unwrap_err(), Errno::NOTTY);
    }

    #[test]
    fn the_user_namespace_of_the_process_owns_its_mount_namespace() {
        let owner = ns_owner_userns(own_ns("mnt")).unwrap();
        assert_eq!(dev_ino(&owner), dev_ino(own_ns("user")));
        assert_eq!(ns_type(&owner).unwrap(), LinkNameSpaceType::User);
        let flags = rustix::io::fcntl_getfd(&owner).unwrap();
        assert!(flags.contains(FdFlags::CLOEXEC));
    }

    /// A directory descriptor is not a detached mount. Without the privilege
    /// the kernel refuses the call with `EPERM`. With it, the kernel refuses
    /// the descriptor or the initial user namespace with `EINVAL`.
    #[test]
    fn an_idmap_of_a_plain_directory_is_refused() {
        let dir = openat(
            CWD,
            "/",
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let err = mount_setattr_idmap(&dir, own_ns("user")).unwrap_err();
        assert!(matches!(err, Errno::PERM | Errno::INVAL), "{err}");
    }

    #[test]
    fn the_peer_groups_of_a_socket_pair_are_the_groups_of_the_process() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut got: Vec<u32> = peer_groups(&a, 4096).unwrap();
        got.sort_unstable();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let mut want: Vec<u32> = status
            .lines()
            .find_map(|line| line.strip_prefix("Groups:"))
            .unwrap()
            .split_whitespace()
            .map(|g| g.parse().unwrap())
            .collect();
        want.sort_unstable();
        assert_eq!(got, want);
        if !want.is_empty() {
            assert_eq!(peer_groups(&a, want.len() - 1).unwrap_err(), Errno::RANGE);
        }

        let file = std::fs::File::open("/proc/self/status").unwrap();
        assert_eq!(peer_groups(&file, 4096).unwrap_err(), Errno::NOTSOCK);
    }

    #[test]
    fn the_listen_variables_must_name_this_process_and_one_socket() {
        let s = |v: &'static str| Some(OsStr::new(v));
        assert_eq!(listen_vars_match(None, None, 42), Ok(false));
        assert_eq!(listen_vars_match(s("42"), s("1"), 42), Ok(true));
        assert_eq!(listen_vars_match(s("41"), s("1"), 42), Err(Errno::INVAL));
        assert_eq!(listen_vars_match(s("42"), s("2"), 42), Err(Errno::INVAL));
        assert_eq!(listen_vars_match(s("42"), s("0"), 42), Err(Errno::INVAL));
        assert_eq!(listen_vars_match(s("x"), s("1"), 42), Err(Errno::INVAL));
        assert_eq!(listen_vars_match(s("42"), None, 42), Err(Errno::INVAL));
        assert_eq!(listen_vars_match(None, s("1"), 42), Err(Errno::INVAL));
    }

    /// A child process with the systemd variables and an open descriptor 3
    /// takes the descriptor once.
    #[test]
    fn a_passed_descriptor_is_taken_once() {
        let exe = std::env::current_exe().unwrap();
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"export LISTEN_PID=$$ LISTEN_FDS=1; exec "$0" "$@" 3</dev/null"#)
            .arg(&exe)
            .args([LISTEN_CHILD, "--exact", "--ignored", "--nocapture"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{}\n{stdout}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The body of the child process of [`a_passed_descriptor_is_taken_once`].
    /// Outside that child, the test does nothing.
    #[test]
    #[ignore = "runs in a child process with LISTEN_PID and LISTEN_FDS"]
    fn listen_fd_child() {
        if std::env::var_os("LISTEN_PID").is_none() {
            return;
        }
        let fd = systemd_listen_fd().unwrap().unwrap();
        assert_eq!(fd.as_raw_fd(), 3);
        let flags = rustix::io::fcntl_getfd(&fd).unwrap();
        assert!(flags.contains(FdFlags::CLOEXEC));
        assert_eq!(systemd_listen_fd().unwrap_err(), Errno::ALREADY);
    }
}
