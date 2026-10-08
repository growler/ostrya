//! Static-delta generation: the writer of the superblock and the part files,
//! and the `delta-indexes/` cache.
//!
//! The rules that a caller sees are on `Repo::generate_static_delta`, under
//! `# Object routes`, `# Memory`, and `# Blocking pool`, and on the fields of
//! `DeltaOptions`. The read side is in [`crate::delta`]. The tests check each
//! side against the other and against the `ostree` command.
//!
//! The private items that carry the rules:
//!
//! - [`BSDIFF_CONTENT_LIMIT`] and [`patch_beats_splicing`] decide if a bspatch
//!   stream replaces a splice.
//! - [`Spill`] holds the data source of a part, on the heap up to
//!   [`MMAP_THRESHOLD`] and in a temp file after it.
//! - [`compress_part`] and [`bsdiff_stream`] run the CPU-bound stages on the
//!   blocking pool. [`PART_XZ_LEVEL`] sets the memory of the xz encoder.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::SeekFrom;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_compression::Level;
use async_compression::futures::write::XzEncoder;
use futures_lite::AsyncWriteExt;
use ostrya_core::{
    Checksum, ObjectType, Type, Value, Xattrs, choose_offset_size, from_bytes, to_bytes, varint,
    write_offset,
};
use ostrya_rt::File as RtFile;
use sha2::{Digest, Sha256};

use crate::commit::append_dict_entry;
use crate::delta::{
    Blob, COMMIT_SIG, COMPRESSION_XZ, DeltaEndianness, ENDIANNESS_BIG, ENDIANNESS_KEY,
    ENDIANNESS_LITTLE, IO_CHUNK, MAX_SUPERBLOCK, MAX_TABLE_BYTES, MMAP_THRESHOLD, OP_BSPATCH,
    OP_CLOSE, OP_OPEN, OP_OPEN_SPLICE_CLOSE, OP_SET_READ_SOURCE, OP_UNSET_READ_SOURCE, OP_WRITE,
    SIGNED_MAGIC, SIGNED_SIG, SUPERBLOCK_SIG, dir_child_names, open_rw_temp, read_capped,
    spill_to_blob,
};
use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::hashing::HashingWriter;
use crate::repo::Repo;
use crate::rollsum::{self, Run};
use crate::sign::{Signer, append_signature};

/// The format version of a delta part that the meta-entry records.
const PART_VERSION: u32 = 0;

/// The xz preset of each part.
///
/// The value is fixed, so the part bytes do not depend on the default of the
/// compression crate. Preset 8 is not extreme, and it uses the CRC64 check that
/// xz uses by default. Its LZMA2 dictionary is 32 MiB. `xz -8 -T1 -vv` reports
/// 370 MiB of encoder memory for each concurrent part and 33 MiB to decode. The
/// parts of the `ostree` command carry the same dictionary size.
const PART_XZ_LEVEL: i32 = 8;

/// The largest content size for which a bspatch stream is tried. The smaller
/// of this value and [`DeltaOptions::max_bsdiff_size`] applies.
///
/// bsdiff runs only after chunking found no shared chunk. For an object of many
/// chunks, this result means that no chunk-sized window of the target occurs
/// in the source. That is evidence that the two objects are unrelated. A patch
/// against unrelated content is about as long as the target, so it loses to a
/// splice after the cost of a suffix sort.
///
/// An object smaller than [`rollsum::MAX_CHUNK`] is one chunk or a small
/// number of chunks. One edit anywhere in it defeats chunking, so a failure of chunking
/// is no such evidence. The `ostree` command also emits bspatch at this size.
/// It was observed to emit bspatch for a 1,024-byte object with a small edit.
///
/// The limit applies to the source and to the target, because the suffix sort
/// is over the source. Pairing is by path, with no rule on the size ratio, so a
/// small object can pair with a large object that it replaced.
const BSDIFF_CONTENT_LIMIT: u64 = rollsum::MAX_CHUNK as u64;

/// The name of the superblock file in a delta directory.
pub(crate) const SUPERBLOCK_FILE: &str = "superblock";
/// The tree of delta directories, relative to the repository root.
const DELTAS_DIR: &str = "deltas";
/// The tree of delta index files, relative to the repository root.
const DELTA_INDEXES_DIR: &str = "delta-indexes";
/// The suffix of an index file under `delta-indexes/`.
const INDEX_SUFFIX: &str = ".index";
/// The `a{sv}` key under which an index file and the summary store the delta
/// map.
pub(crate) const STATIC_DELTAS_KEY: &str = "ostree.static-deltas";

/// The mode of the delta files and the index files. The `ostree` command gives
/// them this mode whatever the umask is.
const DELTA_FILE_MODE: u32 = 0o644;
/// The mode of a new delta directory. The umask reduces it, as it does for the
/// `ostree` command.
const DELTA_DIR_MODE: u32 = 0o755;

/// The options of [`Repo::generate_static_delta`].
///
/// The three size thresholds are the thresholds of the `ostree static-delta
/// generate` command, in bytes. The `ostree` command takes decimal megabytes:
/// pass `4 * 1_000_000` where the command takes `--min-fallback-size=4`.
#[derive(Clone)]
pub struct DeltaOptions {
    /// The stream size at which an object travels as a loose fallback.
    ///
    /// The stream is the file header and the content, uncompressed. If the
    /// stream of an object is this size or larger, the object is not packed
    /// into a part and is never diffed. The size compared is the serialized
    /// file header, plus 7 bytes, plus the content, as the `ostree` command
    /// compares it.
    ///
    /// Default 4,000,000. Zero turns fallbacks off, as `--min-fallback-size=0`
    /// of the `ostree` command does. Each object is then packed whatever its
    /// size, and the memory of a diff has no bound from this value.
    pub min_fallback_size: u64,
    /// The largest content size for which a bspatch stream is tried.
    ///
    /// The suffix sort of bsdiff costs several times the source size in
    /// memory, on top of the two objects, so this value bounds the peak.
    /// Default 64,000,000. A second bound of 64 KiB comes from the largest
    /// chunk of the chunker, and the smaller bound applies. At the default,
    /// the 64 KiB bound decides. Both bounds apply to the source object and to
    /// the target object.
    pub max_bsdiff_size: u64,
    /// The payload size at which a part closes and the next part starts.
    ///
    /// Default 32,000,000. Zero is refused with [`Error::InvalidFormat`].
    pub max_chunk_size: u64,
    /// The switch that allows bspatch streams.
    ///
    /// If `false`, an object that chunking cannot express is spliced whole.
    /// Default `true`.
    pub bsdiff: bool,
    /// The superblock timestamp, in seconds since the Unix epoch.
    ///
    /// `None` uses the current time, as the `ostree` command does. A fixed
    /// value makes the output reproducible.
    pub timestamp: Option<u64>,
    /// A directory that receives the superblock and the part files.
    ///
    /// If set, no file goes into the `deltas/` tree. The generation creates
    /// the directory if it is absent.
    ///
    /// The generation replaces the files that this delta writes and removes
    /// no other file. The extra part files of a longer previous delta stay. A
    /// reader takes only the parts that the superblock lists, so these files
    /// cost disk space and cause no error.
    pub output_dir: Option<PathBuf>,
    /// A file path for the superblock, with the part files in its directory.
    ///
    /// If set, no file goes into the `deltas/` tree. A path with no `/` puts
    /// the superblock and the parts in the working directory. The directory
    /// must exist, and the generation does not create it. `None` by default.
    ///
    /// The generation refuses these paths before it writes a file:
    ///
    /// - a path that names a directory
    /// - a path whose last component is empty, `.`, or `..`
    /// - a path whose last component is a part file name, such as `0` or `1`
    ///
    /// Only the rename that puts the superblock in place replaces a file at
    /// the path. If the generation fails, that file stays as it was. If
    /// [`output_dir`](DeltaOptions::output_dir) is also set, the generation is
    /// refused.
    pub superblock_file: Option<PathBuf>,
    /// The engines that sign the superblock before it is written.
    ///
    /// Each engine signs once, in order. Empty by default, which writes an
    /// unsigned superblock. If a signer fails, the generation fails and writes
    /// no superblock.
    pub signers: Vec<Arc<dyn Signer>>,
    /// The switch that puts the parts into the superblock.
    ///
    /// If `true`, the metadata dict of the superblock holds each part under
    /// the key `deltas/<fanout>/<rest>/<i>`, as a `(yay)` variant, and no part
    /// file is written. The value holds the bytes that a part file holds. The
    /// key is the repository-relative name, also with
    /// [`output_dir`](DeltaOptions::output_dir) or
    /// [`superblock_file`](DeltaOptions::superblock_file).
    ///
    /// The parts count toward the superblock limit of 128 MiB. If the
    /// superblock passes the limit, the generation fails before it writes
    /// the superblock. A superblock that an earlier delta left at the same
    /// location then stays in place. Default `false`.
    pub inline: bool,
    /// The byte order of the size fields of the superblock.
    ///
    /// The superblock records the order in `ostree.endianness`. The order
    /// applies to the `size` and the `usize` of a meta-entry and to the two
    /// sizes of a fallback. The timestamp, the parts, and the embedded commit
    /// do not change with it. Default [`DeltaEndianness::Little`], on each
    /// host.
    pub endianness: DeltaEndianness,
}

impl std::fmt::Debug for DeltaOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signers: Vec<&str> = self.signers.iter().map(|signer| signer.name()).collect();
        f.debug_struct("DeltaOptions")
            .field("min_fallback_size", &self.min_fallback_size)
            .field("max_bsdiff_size", &self.max_bsdiff_size)
            .field("max_chunk_size", &self.max_chunk_size)
            .field("bsdiff", &self.bsdiff)
            .field("timestamp", &self.timestamp)
            .field("output_dir", &self.output_dir)
            .field("superblock_file", &self.superblock_file)
            .field("signers", &signers)
            .field("inline", &self.inline)
            .field("endianness", &self.endianness)
            .finish()
    }
}

impl Default for DeltaOptions {
    fn default() -> Self {
        DeltaOptions {
            min_fallback_size: 4_000_000,
            max_bsdiff_size: 64_000_000,
            max_chunk_size: 32_000_000,
            bsdiff: true,
            timestamp: None,
            output_dir: None,
            superblock_file: None,
            signers: Vec::new(),
            inline: false,
            endianness: DeltaEndianness::Little,
        }
    }
}

/// Methods that generate, sign, and index static deltas.
impl Repo {
    /// Generates the static delta from `from` to `to` and returns its directory.
    ///
    /// If `from` is `None`, the delta is a delta from scratch. Both commits and
    /// each object that the delta packs must be present. Set
    /// [`DeltaOptions::signers`] to sign the superblock.
    /// [`sign_static_delta`](Repo::sign_static_delta) adds a signature to a
    /// delta that exists. Call [`reindex_static_deltas`](Repo::reindex_static_deltas)
    /// to publish the new delta in the index cache.
    ///
    /// # Location
    ///
    /// - By default, the files go under `deltas/`, in the base64-fanout
    ///   directory of [`static_delta_relative_dir`]. The `ostree` command uses
    ///   the same directory.
    /// - If [`DeltaOptions::output_dir`] is set, the files go in that
    ///   directory.
    /// - If [`DeltaOptions::superblock_file`] is set, the superblock goes at
    ///   that path, and the parts go in the directory that holds it.
    /// - If [`DeltaOptions::inline`] is set, the parts go into the superblock,
    ///   and no part file is written.
    ///
    /// For the default location, the returned path is relative to the
    /// repository root. The caller supplies the root, because a handle holds
    /// descriptors and no path. `root.join(returned)` is the directory that
    /// [`apply_static_delta_offline`](Repo::apply_static_delta_offline) and
    /// [`sign_static_delta`](Repo::sign_static_delta) take. If
    /// [`DeltaOptions::output_dir`] or [`DeltaOptions::superblock_file`] is
    /// set, the returned path is that option as given. A relative path
    /// resolves against the working directory of the process.
    ///
    /// # Write order
    ///
    /// The part files are written before the superblock, so an interrupted
    /// generation leaves no superblock for a reader to trust. The superblock
    /// is signed before it is written, so a failure of a signer writes no
    /// superblock.
    ///
    /// Each file is written under a temp name. Only the rename that puts the
    /// file in place keeps the temp file. If a generation fails or is
    /// cancelled, the temp file is unlinked, so no partial file stays in the
    /// directory.
    ///
    /// The new parts overwrite the parts of a delta at the same location. For
    /// this reason, the generation unlinks the old superblock before it writes
    /// the first part. The old superblock then cannot describe files that this
    /// run replaced. A file at a [`DeltaOptions::superblock_file`] path
    /// belongs to the caller, and the generation does not unlink it.
    ///
    /// An inline generation replaces no part file. The previous superblock
    /// stays in place until the rename of the new superblock replaces it. If an
    /// inline generation fails, the previous delta stays as it was.
    ///
    /// # Cleanup
    ///
    /// After the new superblock is in place, the generation removes these
    /// files from the delta directory:
    ///
    /// - the part files of a longer previous delta, or each numbered part file
    ///   if the new delta carries its parts inline
    /// - the temp files of a generation that was killed mid-write, when they
    ///   are one hour old or older
    ///
    /// This pass covers the `deltas/` tree of the repository only. A directory
    /// named through [`DeltaOptions::output_dir`] or
    /// [`DeltaOptions::superblock_file`] belongs to the caller. The generation
    /// removes no other file in it.
    ///
    /// # Concurrency
    ///
    /// Two generations of the same delta at the same time, into one directory,
    /// are not supported. Both runs write the same file names, so each run
    /// overwrites the parts and the superblock of the other. Generations of
    /// different deltas can run concurrently, because each delta has its own
    /// directory.
    ///
    /// # Object routes
    ///
    /// The delta carries the objects that `to` reaches and `from` does not
    /// reach. The superblock holds the commit object of `to`. Each other
    /// object reaches the receiver by one of four routes, chosen for each
    /// object:
    ///
    /// - Loose fallback: if the stream of the object is
    ///   [`DeltaOptions::min_fallback_size`] or larger, the delta names the
    ///   object, and the receiver fetches it whole.
    /// - Rollsum delta: the source object is the object at the same path in
    ///   `from`. If content-defined chunking finds chunks that the two objects
    ///   share, the operation stream copies the unchanged runs from the source
    ///   object. The part holds only the changed runs.
    /// - bspatch stream: if chunking finds no shared chunk, the generation
    ///   tries a bspatch stream against the same source object. Both objects
    ///   must be at most 64 KiB and at most [`DeltaOptions::max_bsdiff_size`].
    ///   The patch stays only if its count of nonzero bytes is less than half
    ///   the content size.
    /// - Splice: in all other cases, the part payload holds the object bytes as
    ///   they are. Metadata objects and symlinks always take this route.
    ///
    /// An object smaller than 64 KiB is one chunk or a small number of chunks,
    /// so one edit defeats chunking. In a patch against unrelated high-entropy
    /// content, about 255 bytes in 256 are nonzero. A patch for a small edit
    /// has a few dozen nonzero bytes. If the source object is not present, the
    /// object is spliced.
    ///
    /// # Memory
    ///
    /// The generation holds a bounded amount of memory:
    ///
    /// - The data source of a part collects in a buffer on the heap. Past
    ///   128 KiB, the buffer moves to an anonymous temp file in `tmp/`.
    /// - Spliced content streams into this buffer in 128 KiB pieces, and the
    ///   generation never holds it whole.
    /// - The part payload streams straight into the xz encoder. Its GVariant
    ///   framing goes around the two large byte arrays, which stream from the
    ///   buffer.
    /// - The xz encoder uses most of the memory: about 370 MiB for each part
    ///   that it compresses.
    ///
    /// A diff needs random access to both objects, so a diff does not stream.
    /// The source object and the target object load on the heap, as in the
    /// read path. If they are large, they load in a read-only mapping of a
    /// temp file. Chunking scans both objects from end to end, so each page of
    /// both is resident while the generation plans the pair. The peak resident
    /// set size follows the sum of the two object sizes, in mapped pages of
    /// temp files.
    ///
    /// [`DeltaOptions::min_fallback_size`] bounds the target object of a diff.
    /// The source object has no bound of its own.
    /// [`DeltaOptions::max_bsdiff_size`] bounds the patch attempt alone.
    ///
    /// # Blocking pool
    ///
    /// The CPU-bound stages run on the blocking pool, off the executor
    /// threads:
    ///
    /// - the chunking and the hashing of both objects of a diff candidate
    /// - the suffix sort of bsdiff
    /// - the compression of each part
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] if [`DeltaOptions::max_chunk_size`] is `0`.
    /// - [`Error::InvalidFormat`] if [`DeltaOptions::output_dir`] and
    ///   [`DeltaOptions::superblock_file`] are both set.
    /// - [`Error::ObjectNotFound`] if the commit `to` or the commit `from` is
    ///   not present, or if an object that the delta carries is not present.
    /// - [`Error::Io`] with `EISDIR` if the [`DeltaOptions::superblock_file`]
    ///   path names a directory, or if its last component is empty, `.`, or
    ///   `..`.
    /// - [`Error::InvalidFormat`] if the last component of the
    ///   [`DeltaOptions::superblock_file`] path is not UTF-8 or is a part file
    ///   name.
    /// - [`Error::InvalidFormat`] if the superblock is larger than 128 MiB
    ///   ([`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE)), or if inline parts
    ///   pass this limit.
    /// - [`Error::InvalidFormat`] if the mode table and the xattr table of a
    ///   part are larger than 128 MiB together.
    /// - [`Error::InvalidFormat`] if the temp file of the data source of a part
    ///   holds a byte count other than the count that the generation wrote.
    /// - [`Error::InvalidFormat`] if [`DeltaOptions::timestamp`] is `None` and
    ///   the system clock is before the Unix epoch.
    /// - [`Error::Core`] if the commit or its detached metadata does not parse,
    ///   or if `[core] fsync` in the config is not a boolean.
    /// - [`Error::Signature`] if a signer fails. A signer can also return
    ///   [`Error::InvalidFormat`] or [`Error::Core`].
    /// - [`Error::Io`] if a metadata object is larger than 128 MiB, or if a
    ///   read, a write, or an unlink on the file system fails.
    pub async fn generate_static_delta(
        &self,
        from: Option<&Checksum>,
        to: &Checksum,
        opts: &DeltaOptions,
    ) -> Result<PathBuf> {
        self.generate_static_delta_under(from, to, opts, MAX_SUPERBLOCK)
            .await
    }

    /// Runs [`generate_static_delta`](Repo::generate_static_delta) with
    /// `ceiling` as the superblock size for the budget of inline parts.
    ///
    /// The public call gives [`MAX_SUPERBLOCK`]. A test gives a smaller
    /// ceiling to reach the inline refusal without a 128 MiB part.
    async fn generate_static_delta_under(
        &self,
        from: Option<&Checksum>,
        to: &Checksum,
        opts: &DeltaOptions,
        ceiling: u64,
    ) -> Result<PathBuf> {
        if opts.max_chunk_size == 0 {
            return Err(Error::InvalidFormat(
                "static delta max chunk size must be positive".to_owned(),
            ));
        }
        if opts.output_dir.is_some() && opts.superblock_file.is_some() {
            return Err(Error::InvalidFormat(
                "static delta output_dir and superblock_file cannot both be set".to_owned(),
            ));
        }
        // The superblock embeds the whole target commit, so the commit loads,
        // and must be present, before any write. Its detached metadata goes
        // into the superblock beside it, because a verifying pull of the
        // `ostree` command checks the delivered commit against that copy.
        let commit_bytes = self.load_object_bytes(ObjectType::Commit, to).await?;
        let detached = self.read_commit_detached_metadata(to).await?;
        let commit = Target {
            bytes: &commit_bytes,
            detached: detached.as_ref(),
        };
        if let Some(from) = from
            && !self.has_object(ObjectType::Commit, from).await?
        {
            return Err(Error::ObjectNotFound {
                checksum: *from,
                ty: ObjectType::Commit,
            });
        }

        // A superblock-file target creates nothing when it opens. It opens
        // before the selection walk, so a refused target costs no walk.
        let superblock_target = match &opts.superblock_file {
            Some(file) => {
                let target = file.clone();
                let (fd, name) =
                    ostrya_rt::unblock(move || open_superblock_parent_blocking(&target)).await?;
                Some((file.clone(), fd, name))
            }
            None => None,
        };

        let selection = self.select_objects(from, to, opts).await?;
        let (dir_path, dir_fd, superblock_name) = match superblock_target {
            Some(target) => target,
            None => {
                let (path, fd) = self.open_delta_dir(from, to, opts).await?;
                (path, fd, SUPERBLOCK_FILE.to_owned())
            }
        };
        let tmp_fd = self.open_tmp_dir().await?;
        let fsync = self.config().fsync()?;

        // The new parts overwrite the old parts in place, so the superblock of
        // the previous delta at this location goes before the first part. A
        // file at a superblock-file path belongs to the caller. Only the final
        // rename replaces it, so a failed generation leaves it as it was. An
        // inline generation overwrites no part file. The previous superblock
        // stays until the rename replaces it, and a failed generation leaves
        // the previous delta whole.
        if opts.superblock_file.is_none() && !opts.inline {
            remove_superblock(&dir_fd).await?;
        }

        // The generation holds inline parts until it serializes the
        // superblock, so the parts share the superblock ceiling. Each part
        // compresses into a buffer capped at the space that the rest of the
        // superblock and the earlier parts leave. The count of the rest is its
        // minimum: the embedded commit, 33 bytes for each object in the
        // meta-entries, and 49 bytes for each fallback. A delta whose parts
        // cannot fit is then refused at the part that passes the ceiling. The
        // count leaves out the framing, the copy of the detached metadata, and
        // the signatures. The size check on the serialized superblock refuses
        // a superblock that they push past the ceiling.
        let mut target = if opts.inline {
            let fixed = commit_bytes
                .len()
                .saturating_add(selection.packed.len().saturating_mul(1 + 32))
                .saturating_add(selection.fallbacks.len().saturating_mul(1 + 32 + 8 + 8));
            PartTarget::Inline {
                budget: usize::try_from(ceiling)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(fixed),
            }
        } else {
            PartTarget::File(&dir_fd)
        };
        let mut entries: Vec<PartEntry> = Vec::new();
        let mut part = Part::default();
        for item in &selection.packed {
            // A part closes if the next object can push its payload past the
            // chunk ceiling. The content size of the object is the estimate. It
            // is exact for a splice and an upper bound for a diffed object. The
            // decision comes before the object goes into the part, so the
            // payload of a part with more than one object never passes the
            // ceiling. An object that rollsums down to a small payload still
            // closes the part that it fits in. The cost is one more xz stream
            // and one more pair of mode and xattr tables, and the ceiling holds.
            if !part.is_empty() && part.payload_len() + item.content_size > opts.max_chunk_size {
                entries.push(write_part(&mut target, entries.len(), part, fsync).await?);
                part = Part::default();
            }
            self.add_object(&mut part, item, opts, tmp_fd.as_fd())
                .await?;
        }
        if !part.is_empty() {
            entries.push(write_part(&mut target, entries.len(), part, fsync).await?);
        }
        let part_files = if opts.inline { 0 } else { entries.len() };

        let mut superblock =
            self.build_superblock(from, to, &commit, &mut entries, &selection, opts)?;
        drop(entries);
        if !opts.signers.is_empty() {
            let signers: Vec<&dyn Signer> = opts.signers.iter().map(|s| s.as_ref()).collect();
            superblock = sign_superblock(superblock, Value::Array(Vec::new()), &signers).await?;
        }
        write_delta_file(&dir_fd, &superblock_name, &superblock, fsync).await?;
        // The sweep finds what it removes by name. This is safe only where
        // this code wrote each entry. An output directory of the caller can
        // hold files with the names of delta files.
        if opts.output_dir.is_none() && opts.superblock_file.is_none() {
            clean_delta_dir(&dir_fd, part_files).await?;
        }
        Ok(dir_path)
    }

    /// Signs the superblock of the delta in `dir` with `signer`.
    ///
    /// The signed payload is the raw superblock bytes, and the new superblock
    /// is the signed envelope. If the delta is already signed, the signature
    /// goes at the end of the signature array of the engine. The arrays of the
    /// other engines stay, so one call for each engine collects the signatures.
    ///
    /// The call replaces the superblock atomically. Call
    /// [`reindex_static_deltas`](Repo::reindex_static_deltas) after it,
    /// because the index records the digest of the superblock. The envelope
    /// adds to the superblock size, so the result is held to the 128 MiB
    /// limit of [`generate_static_delta`](Repo::generate_static_delta). If
    /// the signed superblock passes the limit, the call fails. It never
    /// writes a superblock that the read path refuses.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the `superblock` file in `dir` cannot be read, or if
    ///   it is larger than 128 MiB.
    /// - [`Error::Core`] if the superblock starts with the magic of the signed
    ///   envelope and does not parse as one.
    /// - [`Error::Signature`] if the signer fails. A signer can also return
    ///   [`Error::InvalidFormat`] or [`Error::Core`].
    /// - [`Error::InvalidFormat`] if the signed superblock is larger than
    ///   128 MiB.
    /// - [`Error::Core`] if `[core] fsync` in the config is not a boolean.
    /// - [`Error::Io`] if `dir` cannot be opened, or if the write of the
    ///   superblock fails.
    pub async fn sign_static_delta(&self, dir: &Path, signer: &dyn Signer) -> Result<()> {
        let bytes = read_capped(dir.join(SUPERBLOCK_FILE)).await?;
        let (payload, signatures) = split_envelope(bytes)?;
        let encoded = sign_superblock(payload, signatures, &[signer]).await?;

        let dir_fd = open_dir_path(dir).await?;
        let fsync = self.config().fsync()?;
        write_delta_file(&dir_fd, SUPERBLOCK_FILE, &encoded, fsync).await
    }

    /// Rebuilds the `delta-indexes/` cache from the deltas under `deltas/`.
    ///
    /// Each target commit gets one index file. The file lists each delta that
    /// produces the target, keyed by the delta name, with the SHA-256 of its
    /// superblock. The summary carries the same map. The entries are in
    /// delta-name order, and the `ostree` command writes them in hash-table
    /// order.
    ///
    /// The pass removes the index file of a target that has no delta left, so
    /// a stale entry cannot advertise a delta that is gone. The fanout
    /// directory that this removal empties stays, as it does for the `ostree`
    /// command. The pass skips a delta with no superblock, so a half-written
    /// delta does not fail the pass.
    ///
    /// # Errors
    ///
    /// - [`Error::Core`] if a delta directory that holds a superblock has a
    ///   name that does not decode to a checksum.
    /// - [`Error::Core`] if `[core] fsync` in the config is not a boolean.
    /// - [`Error::Io`] if a superblock is larger than 128 MiB.
    /// - [`Error::Io`] if an entry of `delta-indexes/` is not a directory.
    /// - [`Error::Io`] if a scan, a read, a write, or an unlink on the file
    ///   system fails.
    pub async fn reindex_static_deltas(&self) -> Result<()> {
        let mut by_target: BTreeMap<Checksum, BTreeMap<String, Checksum>> = BTreeMap::new();
        for entry in self.static_delta_digests().await? {
            by_target
                .entry(entry.to)
                .or_default()
                .insert(entry.name, entry.digest);
        }

        let fsync = self.config().fsync()?;
        let mut written: BTreeSet<String> = BTreeSet::new();
        for (to, deltas) in &by_target {
            self.write_delta_index(to, deltas, fsync).await?;
            let (fanout, name) = delta_index_parts(to);
            written.insert(format!("{fanout}/{name}"));
        }
        self.prune_delta_indexes(written).await
    }

    /// Rewrites the index file of the target commit `to` alone.
    ///
    /// The file is `delta-indexes/<fanout>/<rest>.index`. It lists the deltas
    /// under `deltas/` whose target is `to`. The scan rule of
    /// [`reindex_static_deltas`](Repo::reindex_static_deltas) finds the
    /// deltas, and the call reads only the superblocks of `to`.
    ///
    /// If no delta for `to` exists, the call removes the index file. An absent
    /// file, fanout directory, or `delta-indexes/` is no error, and the call
    /// creates no directory for it. The fanout directory that the removal
    /// empties stays.
    ///
    /// The index files of other targets stay as they are, stale files
    /// included. The call does not check that `to` names a commit object, so a
    /// target that the repository does not hold is valid.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if the fanout or `delta-indexes` is not a directory, a
    ///   regular file for example.
    /// - [`Error::Io`] if a directory is at the path of the index file.
    /// - [`Error::Io`] if a superblock of `to` is larger than 128 MiB.
    /// - [`Error::Core`] if a delta directory that holds a superblock has a
    ///   name that does not decode to a checksum.
    /// - [`Error::Core`] if `[core] fsync` in the config is not a boolean.
    /// - [`Error::Io`] if a scan, a read, a write, or an unlink on the file
    ///   system fails.
    pub async fn reindex_static_deltas_to(&self, to: &Checksum) -> Result<()> {
        let deltas: BTreeMap<String, Checksum> = self
            .static_delta_digests_of(Some(to))
            .await?
            .into_iter()
            .map(|entry| (entry.name, entry.digest))
            .collect();
        if deltas.is_empty() {
            let repo = self.clone();
            let relative = delta_index_relative_path(to);
            return ostrya_rt::unblock(move || {
                remove_delta_index_blocking(repo.repo_fd(), &relative)
            })
            .await;
        }
        let fsync = self.config().fsync()?;
        self.write_delta_index(to, &deltas, fsync).await
    }

    /// Writes the index file of the target commit `to` from its delta map, and
    /// creates the fanout directory and its parents.
    async fn write_delta_index(
        &self,
        to: &Checksum,
        deltas: &BTreeMap<String, Checksum>,
        fsync: bool,
    ) -> Result<()> {
        let (fanout, name) = delta_index_parts(to);
        let dir_fd = self
            .open_repo_subdir(&format!("{DELTA_INDEXES_DIR}/{fanout}"))
            .await?;
        let index = index_value(deltas)?;
        write_delta_file(&dir_fd, &name, &index, fsync).await
    }

    /// Returns each delta under `deltas/`, sorted by delta name, with the
    /// SHA-256 of its superblock.
    ///
    /// The `delta-indexes/` cache and the `ostree.static-deltas` map of the
    /// summary both advertise this list, so both are built from it. The scan
    /// lists only a directory that holds a superblock, so a half-written delta
    /// stays unadvertised. If a superblock goes away between the scan and the
    /// read, the call skips it and does not fail.
    pub(crate) async fn static_delta_digests(&self) -> Result<Vec<DeltaDigest>> {
        self.static_delta_digests_of(None).await
    }

    /// Returns the deltas of [`static_delta_digests`](Repo::static_delta_digests),
    /// limited to the target commit `to` if it is given.
    ///
    /// The limit applies before a superblock is read, so a pass over one
    /// target reads only the superblocks of that target.
    async fn static_delta_digests_of(&self, to: Option<&Checksum>) -> Result<Vec<DeltaDigest>> {
        let mut out = Vec::new();
        for (from, target) in self.list_static_delta_targets().await? {
            if to.is_some_and(|to| *to != target) {
                continue;
            }
            let relative = format!(
                "{}/{SUPERBLOCK_FILE}",
                delta_relative_dir(from.as_ref(), &target)
            );
            let Some(bytes) = self.read_repo_file(&relative).await? else {
                continue;
            };
            out.push(DeltaDigest {
                name: delta_name(from.as_ref(), &target),
                to: target,
                digest: Checksum::sha256(&bytes),
            });
        }
        // The `ostree` command writes the index files and the summary map in
        // hash-table order, and ostrya does not reproduce that order. A sort by
        // name gives both one order, whatever order the file system returns
        // for the `deltas/` tree.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Returns the `ostree.static-deltas` value of the summary, or `None` if
    /// the repository holds no delta.
    ///
    /// The value is an `a{sv}` that maps the name of each delta to the 32-byte
    /// digest of its superblock.
    pub(crate) async fn static_deltas_summary_value(&self) -> Result<Option<Value>> {
        let entries = self.static_delta_digests().await?;
        if entries.is_empty() {
            return Ok(None);
        }
        let map = delta_map_value(
            entries
                .iter()
                .map(|entry| (entry.name.as_str(), &entry.digest)),
        )?;
        let map_ty = Type::parse("a{sv}").map_err(ostrya_core::Error::from)?;
        Ok(Some(Value::variant(map_ty, map)))
    }

    /// Returns the target commits of the index files in `delta-indexes/`, sorted.
    ///
    /// An index file is a regular file `delta-indexes/<fanout>/<rest>.index`.
    /// Its fanout is a directory with a two-character name, and
    /// `<fanout><rest>` is the 43-character modified-base64 form of the target
    /// checksum. The call skips each other entry, symlinks included.
    ///
    /// The call reads no delta directory, so it lists a target also if no
    /// delta for it exists. A repository with no `delta-indexes/` lists
    /// nothing.
    ///
    /// # Errors
    ///
    /// - [`Error::Io`] if `delta-indexes/` or a fanout directory cannot be
    ///   opened or read.
    pub async fn list_static_delta_indexes(&self) -> Result<Vec<Checksum>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || list_delta_indexes_blocking(repo.repo_fd())).await
    }

    /// Removes the index files under `delta-indexes/` that this pass did not
    /// write.
    ///
    /// `written` holds the `<fanout>/<rest>.index` names that the pass wrote.
    /// The call leaves each name that does not end in [`INDEX_SUFFIX`], so a
    /// temp file of a concurrent write stays.
    async fn prune_delta_indexes(&self, written: BTreeSet<String>) -> Result<()> {
        let repo = self.clone();
        ostrya_rt::unblock(move || prune_delta_indexes_blocking(repo.repo_fd(), &written)).await
    }

    /// Splits the objects that the delta delivers into packed objects and
    /// loose fallbacks.
    ///
    /// Each packed content object pairs with the object at the same path in
    /// the source commit. Objects that `from` reaches are not delivered, and
    /// the superblock carries the target commit object. Metadata objects come
    /// before content objects, and each group is in checksum order, so the
    /// same inputs give the same delta.
    async fn select_objects(
        &self,
        from: Option<&Checksum>,
        to: &Checksum,
        opts: &DeltaOptions,
    ) -> Result<Selection> {
        let mut needed = self.traverse_commit(to, 0).await?;
        if let Some(from) = from {
            for name in self.traverse_commit(from, 0).await? {
                needed.remove(&name);
            }
        }

        let mut metadata: Vec<(ObjectType, Checksum)> = Vec::new();
        let mut content: Vec<Checksum> = Vec::new();
        for name in needed {
            match name.ty {
                // The superblock embeds the target commit, and no other commit
                // object is reachable at depth 0.
                ObjectType::Commit => {}
                ty if ty.is_meta() => metadata.push((ty, name.checksum)),
                _ => content.push(name.checksum),
            }
        }
        metadata.sort_by_key(|(ty, checksum)| (ty.as_u32(), *checksum));
        content.sort();

        let sources = match from {
            Some(from) => self.pair_by_path(from, to).await?,
            None => HashMap::new(),
        };

        let mut selection = Selection::default();
        for (ty, checksum) in metadata {
            // Each repository mode stores metadata objects uncompressed, so
            // the size on disk is the size that the part carries.
            selection.packed.push(PackItem {
                objtype: ty,
                checksum,
                content_size: self.loose_object_size(ty, &checksum).await?,
                source: None,
                file: None,
            });
        }
        for checksum in content {
            let file = self.load_file(&checksum).await?;
            let content_size = content_size(&file);
            if opts.min_fallback_size != 0 && stream_size(&file)? >= opts.min_fallback_size {
                selection.fallbacks.push(FallbackItem {
                    checksum,
                    compressed_size: self.loose_object_size(ObjectType::File, &checksum).await?,
                    content_size,
                });
                continue;
            }
            // A diff needs the source object. If the source object is no
            // longer present, the object is delivered whole.
            let source = match sources.get(&checksum) {
                Some(source) if self.has_object(ObjectType::File, source).await? => Some(*source),
                _ => None,
            };
            selection.packed.push(PackItem {
                objtype: ObjectType::File,
                checksum,
                content_size,
                source,
                file: Some(file),
            });
        }
        Ok(selection)
    }

    /// Maps each content object of `to` to the object at the same path in
    /// `from`.
    ///
    /// Pairing is by path, so a file that moved does not pair with its old
    /// version. An object at more than one path takes the first pairing in
    /// path order.
    async fn pair_by_path(
        &self,
        from: &Checksum,
        to: &Checksum,
    ) -> Result<HashMap<Checksum, Checksum>> {
        let old = self.file_paths(from).await?;
        let mut sources = HashMap::new();
        for (path, new_checksum) in self.file_paths(to).await? {
            if let Some(&old_checksum) = old.get(&path)
                && old_checksum != new_checksum
            {
                sources.entry(new_checksum).or_insert(old_checksum);
            }
        }
        Ok(sources)
    }

    /// Returns each file path in the tree of a commit, with the content object
    /// at that path.
    async fn file_paths(&self, commit: &Checksum) -> Result<BTreeMap<String, Checksum>> {
        let (commit, _) = self.load_commit(commit).await?;
        let mut paths = BTreeMap::new();
        let mut stack = vec![(String::new(), commit.root_dirtree)];
        while let Some((prefix, dirtree)) = stack.pop() {
            let dirtree = self.load_dirtree(&dirtree).await?;
            for (name, checksum) in dirtree.files {
                paths.insert(format!("{prefix}/{name}"), checksum);
            }
            for (name, subtree, _) in dirtree.dirs {
                stack.push((format!("{prefix}/{name}"), subtree));
            }
        }
        Ok(paths)
    }

    /// Adds one object to the part under construction: its bytes go into the
    /// data source, and its operations go onto the stream.
    async fn add_object(
        &self,
        part: &mut Part,
        item: &PackItem,
        opts: &DeltaOptions,
        tmp: BorrowedFd<'_>,
    ) -> Result<()> {
        // Only a content object carries a loaded file object. A metadata
        // object is spliced from its serialized bytes.
        let Some(file) = &item.file else {
            let bytes = self.load_object_bytes(item.objtype, &item.checksum).await?;
            let offset = part.blob.append(&bytes, tmp).await?;
            part.push_op(OP_OPEN_SPLICE_CLOSE, &[bytes.len() as u64, offset]);
            part.finish_object(item.objtype, item.checksum, bytes.len() as u64);
            return Ok(());
        };

        let mode_index = part.mode_index(file.uid, file.gid, file.mode);
        let xattr_index = part.xattr_index(&file.xattrs);

        if let FileKind::Symlink { target } = &file.kind {
            let offset = part.blob.append(target.as_bytes(), tmp).await?;
            part.push_op(
                OP_OPEN_SPLICE_CLOSE,
                &[mode_index, xattr_index, target.len() as u64, offset],
            );
            part.finish_object(item.objtype, item.checksum, target.len() as u64);
            return Ok(());
        }

        // A diff candidate needs random access to both objects, so both load
        // as heap-or-mmap blobs. Without a source, the content streams straight
        // into the data source, and the generation never holds it whole.
        let Some(source) = item.source else {
            let reader = file.reader().await?;
            let (offset, len) = part.blob.append_reader(reader, tmp).await?;
            part.push_op(
                OP_OPEN_SPLICE_CLOSE,
                &[mode_index, xattr_index, len, offset],
            );
            part.finish_object(item.objtype, item.checksum, len);
            return Ok(());
        };

        let target_blob = self.load_content_blob(file, tmp).await?;
        let source_blob = self
            .load_content_blob(&self.load_file(&source).await?, tmp)
            .await?;
        // The chunking and the hashing of both objects from end to end are
        // CPU-bound, so they run on the blocking pool, as the patch attempt
        // does. The blobs are owned values. They move in with the work and
        // come back with the plan.
        let (plan, source_blob, target_blob) = ostrya_rt::unblock(move || {
            let plan = rollsum::plan(source_blob.as_slice(), target_blob.as_slice());
            (plan, source_blob, target_blob)
        })
        .await;
        // The receiver rebuilds the object from these bytes, so its declared
        // output size comes from them. The size in the header is not used.
        let output_size = target_blob.as_slice().len() as u64;

        if plan.copied > 0 {
            part.push_op(OP_OPEN, &[mode_index, xattr_index, output_size]);
            let source_offset = part.blob.append(source.as_bytes(), tmp).await?;
            for run in &plan.runs {
                match *run {
                    Run::Copy {
                        source_offset: from,
                        length,
                    } => {
                        part.push_op(OP_SET_READ_SOURCE, &[source_offset]);
                        part.push_op(OP_WRITE, &[length, from]);
                        part.push_op(OP_UNSET_READ_SOURCE, &[]);
                    }
                    Run::Payload {
                        target_offset,
                        length,
                    } => {
                        let start = target_offset as usize;
                        let end = start + length as usize;
                        let offset = part
                            .blob
                            .append(&target_blob.as_slice()[start..end], tmp)
                            .await?;
                        part.push_op(OP_WRITE, &[length, offset]);
                    }
                }
            }
            part.push_op(OP_CLOSE, &[]);
            part.finish_object(item.objtype, item.checksum, output_size);
            return Ok(());
        }

        // Chunking found nothing shared to copy. If the object is small enough
        // that the failure of chunking says nothing about the relation of the
        // two objects, the code tries a patch. It keeps the patch only if the
        // patch beats a splice of the content. The blobs move into the patch
        // attempt, which gives the target back for the splice.
        let mut target_blob = target_blob;
        // The suffix sort is over the source, so the limit applies to both
        // objects. The limit is the smaller of the chunker bound and the
        // option of the caller.
        let limit = BSDIFF_CONTENT_LIMIT.min(opts.max_bsdiff_size);
        let source_size = source_blob.as_slice().len() as u64;
        if opts.bsdiff && output_size <= limit && source_size <= limit {
            let (stream, returned) = bsdiff_stream(source_blob, target_blob).await?;
            target_blob = returned;
            if patch_beats_splicing(&stream, output_size) {
                part.push_op(OP_OPEN, &[mode_index, xattr_index, output_size]);
                let source_offset = part.blob.append(source.as_bytes(), tmp).await?;
                let stream_offset = part.blob.append(&stream, tmp).await?;
                part.push_op(OP_SET_READ_SOURCE, &[source_offset]);
                part.push_op(OP_BSPATCH, &[stream_offset, stream.len() as u64]);
                part.push_op(OP_UNSET_READ_SOURCE, &[]);
                part.push_op(OP_CLOSE, &[]);
                part.finish_object(item.objtype, item.checksum, output_size);
                return Ok(());
            }
        }

        let offset = part.blob.append(target_blob.as_slice(), tmp).await?;
        part.push_op(
            OP_OPEN_SPLICE_CLOSE,
            &[mode_index, xattr_index, output_size, offset],
        );
        part.finish_object(item.objtype, item.checksum, output_size);
        Ok(())
    }

    /// Loads the payload of a content object for random access.
    ///
    /// A small payload loads on the heap. A large payload loads in a read-only
    /// mapping of a temp file.
    async fn load_content_blob(&self, file: &FileObject, tmp: BorrowedFd<'_>) -> Result<Blob> {
        let reader = file.reader().await?;
        let owned = tmp.try_clone_to_owned()?;
        spill_to_blob(reader, &owned, None).await
    }

    /// Builds the superblock GVariant.
    ///
    /// The metadata dict holds a copy of the detached metadata of the target
    /// commit, under the delta directory with `/commitmeta` added. A pull of
    /// the `ostree` command verifies a commit from a delta against that copy.
    /// A signed commit then reaches a verifying destination only if the copy
    /// is here. A commit with no detached metadata gets no entry.
    ///
    /// The dict entries are in the order of the `ostree` command:
    /// `ostree.endianness`, then each inline part in part order under
    /// `<dir>/<i>`, then `<dir>/commitmeta`. The inline bytes move out of
    /// `entries` into the dict. They are dropped with the dict after the
    /// superblock is serialized.
    fn build_superblock(
        &self,
        from: Option<&Checksum>,
        to: &Checksum,
        target: &Target<'_>,
        entries: &mut [PartEntry],
        selection: &Selection,
        opts: &DeltaOptions,
    ) -> Result<Vec<u8>> {
        let (byte, big_endian) = match opts.endianness {
            DeltaEndianness::Little => (ENDIANNESS_LITTLE, false),
            DeltaEndianness::Big => (ENDIANNESS_BIG, true),
        };
        // The sizes are in host order, which the `ostree.endianness` byte
        // declares. The serializer writes little-endian on each host, so the
        // code swaps a big-endian field here.
        let host = |value: u64| {
            if big_endian {
                value.swap_bytes()
            } else {
                value
            }
        };
        let mut metadata = Value::Array(Vec::new());
        crate::commit::append_dict_entry(
            &mut metadata,
            ENDIANNESS_KEY,
            Value::variant(
                Type::parse("y").map_err(ostrya_core::Error::from)?,
                Value::Byte(byte),
            ),
        )?;
        let inline_ty = Type::parse("(yay)").map_err(ostrya_core::Error::from)?;
        for (index, entry) in entries.iter_mut().enumerate() {
            let Some((compression, body)) = entry.inline.take() else {
                continue;
            };
            crate::commit::append_dict_entry(
                &mut metadata,
                &format!("{}/{index}", delta_relative_dir(from, to)),
                Value::variant(
                    inline_ty.clone(),
                    Value::Tuple(vec![Value::Byte(compression), Value::Bytes(body)]),
                ),
            )?;
        }
        if let Some(detached) = target.detached {
            crate::commit::append_dict_entry(
                &mut metadata,
                &format!("{}/commitmeta", delta_relative_dir(from, to)),
                Value::variant(
                    Type::parse("a{sv}").map_err(ostrya_core::Error::from)?,
                    detached.clone(),
                ),
            )?;
        }

        let commit_ty = Type::parse(COMMIT_SIG).map_err(ostrya_core::Error::from)?;
        let commit = from_bytes(&commit_ty, target.bytes).map_err(ostrya_core::Error::from)?;

        let meta_entries = entries
            .iter()
            .map(|entry| {
                Value::Tuple(vec![
                    Value::U32(PART_VERSION),
                    Value::Bytes(entry.checksum.as_bytes().to_vec()),
                    Value::U64(host(entry.size)),
                    Value::U64(host(entry.uncompressed_size)),
                    Value::Bytes(object_array(&entry.objects)),
                ])
            })
            .collect();

        let fallbacks = selection
            .fallbacks
            .iter()
            .map(|fallback| {
                Value::Tuple(vec![
                    Value::Byte(ObjectType::File.as_u32() as u8),
                    Value::Bytes(fallback.checksum.as_bytes().to_vec()),
                    Value::U64(host(fallback.compressed_size)),
                    Value::U64(host(fallback.content_size)),
                ])
            })
            .collect();

        let superblock = Value::Tuple(vec![
            metadata,
            // The timestamp is big-endian, whatever the endianness byte is.
            Value::U64(resolve_timestamp(opts.timestamp)?.swap_bytes()),
            Value::Bytes(from.map_or_else(Vec::new, |from| from.as_bytes().to_vec())),
            Value::Bytes(to.as_bytes().to_vec()),
            commit,
            // The recursion array is always empty.
            Value::Bytes(Vec::new()),
            Value::Array(meta_entries),
            Value::Array(fallbacks),
        ]);
        let ty = Type::parse(SUPERBLOCK_SIG).map_err(ostrya_core::Error::from)?;
        let bytes = to_bytes(&ty, &superblock).map_err(ostrya_core::Error::from)?;
        check_superblock_size(bytes.len())?;
        Ok(bytes)
    }

    /// Returns the `(from, to)` pair of each delta under `deltas/`.
    async fn list_static_delta_targets(&self) -> Result<Vec<(Option<Checksum>, Checksum)>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || crate::delta::list_delta_targets(repo.repo_fd())).await
    }

    /// Reads a file under the repository root, or returns `None` if it is
    /// absent.
    ///
    /// The metadata ceiling bounds the read, so it serves superblocks and index
    /// files, and no object payloads. A file past the ceiling is an error, as
    /// for [`read_capped`]. A prefix of a superblock gives an index digest that
    /// covers only part of the superblock.
    async fn read_repo_file(&self, relative: &str) -> Result<Option<Vec<u8>>> {
        use std::io::Read;

        let repo = self.clone();
        let relative = relative.to_owned();
        ostrya_rt::unblock(move || {
            let fd = match rustix::fs::openat(
                repo.repo_fd(),
                relative.as_str(),
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(e) => return Err(Error::Io(e.into())),
            };
            let mut file = std::fs::File::from(fd);
            if file.metadata().map_err(Error::Io)?.len() > MAX_SUPERBLOCK {
                return Err(Error::Io(std::io::Error::other(format!(
                    "static delta file {relative} exceeds the size ceiling"
                ))));
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).map_err(Error::Io)?;
            Ok(Some(bytes))
        })
        .await
    }

    /// Opens a directory under the repository root, and creates it and its
    /// parents if they are absent.
    async fn open_repo_subdir(&self, relative: &str) -> Result<OwnedFd> {
        let repo = self.clone();
        let relative = relative.to_owned();
        ostrya_rt::unblock(move || open_subdir_blocking(repo.repo_fd(), &relative)).await
    }

    /// Opens the `tmp/` directory of the repository, which holds the spill
    /// files. [`crate::staging::open_tmp_dir`] creates it if it is absent.
    pub(crate) async fn open_tmp_dir(&self) -> Result<OwnedFd> {
        let repo = self.clone();
        ostrya_rt::unblock(move || {
            crate::staging::open_tmp_dir(repo.repo_fd(), repo.mode()).map_err(Error::Io)
        })
        .await
    }

    /// Creates and opens the directory for the files of the delta, and returns
    /// its path with the descriptor.
    async fn open_delta_dir(
        &self,
        from: Option<&Checksum>,
        to: &Checksum,
        opts: &DeltaOptions,
    ) -> Result<(PathBuf, OwnedFd)> {
        match &opts.output_dir {
            Some(dir) => {
                let path = dir.clone();
                let target = path.clone();
                let fd = ostrya_rt::unblock(move || create_dir_path_blocking(&target)).await?;
                Ok((path, fd))
            }
            None => {
                let relative = delta_relative_dir(from, to);
                let fd = self.open_repo_subdir(&relative).await?;
                Ok((PathBuf::from(relative), fd))
            }
        }
    }
}

/// The target commit as the superblock carries it: the serialized commit
/// object, and its detached metadata if it has any.
struct Target<'a> {
    bytes: &'a [u8],
    detached: Option<&'a Value>,
}

/// The objects that a delta delivers, split by their route.
#[derive(Default)]
struct Selection {
    packed: Vec<PackItem>,
    fallbacks: Vec<FallbackItem>,
}

/// One object that a part carries.
struct PackItem {
    objtype: ObjectType,
    checksum: Checksum,
    /// The payload size of the object: the serialized size of a metadata
    /// object, the content size of a file, or the target length of a symlink.
    content_size: u64,
    /// The object at the same path in the source commit, if one exists for a
    /// diff.
    source: Option<Checksum>,
    /// The content object, loaded once at selection and used again when the
    /// object is packed. `None` for a metadata object, which is packed from
    /// its serialized bytes.
    file: Option<FileObject>,
}

/// One object that the delta names and does not carry.
struct FallbackItem {
    checksum: Checksum,
    compressed_size: u64,
    content_size: u64,
}

/// A written part, as its meta-entry records it.
struct PartEntry {
    checksum: Checksum,
    /// The size of the part file on disk.
    size: u64,
    /// The sum of the uncompressed payloads of the objects of the part.
    uncompressed_size: u64,
    objects: Vec<(ObjectType, Checksum)>,
    /// The bytes of a part file, if the superblock carries the part inline:
    /// the compression byte, and the body after it. The superblock build takes
    /// them.
    inline: Option<(u8, Vec<u8>)>,
}

/// The destination of the bytes of a part in [`write_part`].
enum PartTarget<'a> {
    /// The numbered part file in this delta directory.
    File(&'a OwnedFd),
    /// A buffer that the superblock carries inline. `budget` is the space that
    /// the superblock ceiling leaves for the parts not yet written.
    Inline { budget: usize },
}

/// A part under construction: the mode and xattr tables, the data source, the
/// operation stream, and the objects that the stream produces, in order.
///
/// Each table is a vector in wire order, with a map from entry to index beside
/// it. The lookup of an object then costs one hash, with no scan of the
/// entries.
#[derive(Default)]
struct Part {
    modes: Vec<(u32, u32, u32)>,
    mode_slots: HashMap<(u32, u32, u32), u64>,
    xattrs: Vec<Xattrs>,
    xattr_slots: HashMap<Xattrs, u64>,
    blob: Spill,
    ops: Vec<u8>,
    objects: Vec<(ObjectType, Checksum)>,
    uncompressed_size: u64,
}

impl Part {
    fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Returns the size of the payload so far, to which the chunk ceiling
    /// applies.
    fn payload_len(&self) -> u64 {
        self.blob.len() + self.ops.len() as u64
    }

    /// Appends one operation: its opcode, then its LEB128 operands.
    fn push_op(&mut self, opcode: u8, operands: &[u64]) {
        self.ops.push(opcode);
        for &operand in operands {
            varint::encode(operand, &mut self.ops);
        }
    }

    /// Records that the operations just emitted complete one object.
    fn finish_object(&mut self, objtype: ObjectType, checksum: Checksum, payload: u64) {
        self.objects.push((objtype, checksum));
        self.uncompressed_size += payload;
    }

    /// Returns the index of `(uid, gid, mode)` in the mode table, and appends
    /// the entry if it is new.
    fn mode_index(&mut self, uid: u32, gid: u32, mode: u32) -> u64 {
        let triple = (uid, gid, mode);
        if let Some(&index) = self.mode_slots.get(&triple) {
            return index;
        }
        let index = self.modes.len() as u64;
        self.modes.push(triple);
        self.mode_slots.insert(triple, index);
        index
    }

    /// Returns the index of an xattr set in the xattr table, and appends the
    /// set if it is new.
    fn xattr_index(&mut self, xattrs: &Xattrs) -> u64 {
        if let Some(&index) = self.xattr_slots.get(xattrs) {
            return index;
        }
        let index = self.xattrs.len() as u64;
        self.xattrs.push(xattrs.clone());
        self.xattr_slots.insert(xattrs.clone(), index);
        index
    }
}

/// An append-only buffer for the data source of a part: on the heap up to
/// [`MMAP_THRESHOLD`], then in an anonymous temp file.
///
/// After the move, the payload of a part costs disk space, and only the
/// streaming window is resident.
enum Spill {
    Ram(Vec<u8>),
    File { file: RtFile, len: u64 },
}

impl Default for Spill {
    fn default() -> Self {
        Spill::Ram(Vec::new())
    }
}

impl Spill {
    fn len(&self) -> u64 {
        match self {
            Spill::Ram(buf) => buf.len() as u64,
            Spill::File { len, .. } => *len,
        }
    }

    /// Appends `bytes` and returns the offset at which they were written.
    async fn append(&mut self, bytes: &[u8], tmp: BorrowedFd<'_>) -> Result<u64> {
        let offset = self.len();
        if let Spill::Ram(buf) = self
            && buf.len() + bytes.len() > MMAP_THRESHOLD
        {
            self.spill(tmp).await?;
        }
        match self {
            Spill::Ram(buf) => buf.extend_from_slice(bytes),
            Spill::File { file, len } => {
                file.write_all(bytes).await.map_err(Error::Io)?;
                *len += bytes.len() as u64;
            }
        }
        Ok(offset)
    }

    /// Appends all bytes that `reader` yields, and returns the offset and the
    /// length written.
    ///
    /// The reader drains in [`IO_CHUNK`] pieces, so an object of any size goes
    /// through a bounded buffer.
    async fn append_reader<R: futures_io::AsyncRead + Unpin>(
        &mut self,
        mut reader: R,
        tmp: BorrowedFd<'_>,
    ) -> Result<(u64, u64)> {
        use futures_lite::AsyncReadExt;

        let offset = self.len();
        let mut chunk = vec![0u8; IO_CHUNK];
        let mut total = 0u64;
        loop {
            let n = reader.read(&mut chunk).await.map_err(Error::Io)?;
            if n == 0 {
                break;
            }
            self.append(&chunk[..n], tmp).await?;
            total += n as u64;
        }
        Ok((offset, total))
    }

    /// Moves an in-memory buffer into a temp file.
    async fn spill(&mut self, tmp: BorrowedFd<'_>) -> Result<()> {
        let Spill::Ram(buf) = self else {
            return Ok(());
        };
        let owned = tmp.try_clone_to_owned()?;
        let fd = ostrya_rt::unblock(move || open_rw_temp(owned.as_fd())).await?;
        let mut file = RtFile::from(fd);
        file.write_all(buf).await.map_err(Error::Io)?;
        let len = buf.len() as u64;
        *self = Spill::File { file, len };
        Ok(())
    }

    /// Returns the buffer as a blocking handle at its start, so a blocking-pool
    /// thread can stream the payload of a part.
    async fn into_blocking(self) -> Result<BlockingSpill> {
        match self {
            Spill::Ram(buf) => Ok(BlockingSpill::Ram(buf)),
            Spill::File { mut file, len } => {
                // The async file writes on a background task. The next `flush`
                // reports a failed write, and `write_all` does not. `into_std`
                // completes pending writes and reports no error. This flush
                // turns an `ENOSPC` or `EIO` on the spill file into a failed
                // generation. Without it, the part compresses from a truncated
                // data source, and its framing offsets still count the bytes
                // that the spill accepted.
                file.flush().await.map_err(Error::Io)?;
                // The recovered file shares the open file description. The read
                // starts from an explicit rewind, because the appends moved the
                // offset.
                let mut file = file.into_std().await;
                std::io::Seek::seek(&mut file, SeekFrom::Start(0)).map_err(Error::Io)?;
                Ok(BlockingSpill::File { file, len })
            }
        }
    }
}

/// The data source of a part, ready to stream from a blocking-pool thread, in
/// the same heap or temp-file form that [`Spill`] used.
enum BlockingSpill {
    Ram(Vec<u8>),
    File { file: std::fs::File, len: u64 },
}

impl BlockingSpill {
    /// Streams the contents of the buffer into `out` in [`IO_CHUNK`] pieces, so
    /// a payload of any size goes through a bounded buffer.
    ///
    /// The temp-file form counts the bytes that it streams. It refuses a count
    /// other than the length that the spill recorded, which is the source of
    /// the framing offsets of the part. If the data source lost bytes, the
    /// generation fails, and no part decodes short when it is applied.
    async fn write_into<W: futures_io::AsyncWrite + Unpin>(self, out: &mut W) -> Result<()> {
        match self {
            BlockingSpill::Ram(buf) => out.write_all(&buf).await.map_err(Error::Io),
            BlockingSpill::File { mut file, len } => {
                let mut chunk = vec![0u8; IO_CHUNK];
                let mut streamed = 0u64;
                loop {
                    let n = match std::io::Read::read(&mut file, &mut chunk) {
                        // An interrupted read is retried, as `read_to_end` does.
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        result => result.map_err(Error::Io)?,
                    };
                    if n == 0 {
                        break;
                    }
                    out.write_all(&chunk[..n]).await.map_err(Error::Io)?;
                    streamed += n as u64;
                }
                if streamed != len {
                    return Err(Error::InvalidFormat(format!(
                        "static delta part data source holds {streamed} bytes, not the \
                         {len} its framing counts"
                    )));
                }
                Ok(())
            }
        }
    }
}

/// Writes one part, to its numbered part file or to an inline buffer, and
/// returns its meta-entry.
///
/// The payload GVariant `(a(uuu)aa(ayay)ayay)` goes straight into the xz
/// encoder, in this order:
///
/// 1. The two tables, which are bounded metadata built in memory.
/// 2. The data source, streamed from its spill buffer.
/// 3. The operation stream.
/// 4. The framing offsets of the tuple. Their width follows from the payload
///    length, which is known before the first byte is written.
///
/// The SHA-256 covers the whole file on disk, with the compression byte. The
/// meta-entry records this digest. This function builds the framing and the
/// two tables. [`compress_part`] does the compression and the file write, on
/// the blocking pool.
async fn write_part(
    target: &mut PartTarget<'_>,
    index: usize,
    part: Part,
    fsync: bool,
) -> Result<PartEntry> {
    let modes = mode_table(&part.modes);
    let xattrs = xattr_table(&part.xattrs)?;
    check_table_size(modes.len() + xattrs.len())?;
    let blob_len = part.blob.len();
    let ops_len = part.ops.len() as u64;

    // Field alignments: `a(uuu)` needs 4 and is at offset 0. The xattr table,
    // the data source, and the operation stream align to 1, so no padding
    // falls between the members.
    let body = modes.len() as u64 + xattrs.len() as u64 + blob_len + ops_len;
    let body =
        usize::try_from(body).map_err(|_| Error::InvalidFormat("part payload too large".into()))?;
    let width = choose_offset_size(body, 3);
    let mut offsets = Vec::with_capacity(3 * width);
    // Tuple offsets are the end of each variable-size member except the last,
    // written in reverse member order.
    write_offset(
        &mut offsets,
        modes.len() + xattrs.len() + blob_len as usize,
        width,
    );
    write_offset(&mut offsets, modes.len() + xattrs.len(), width);
    write_offset(&mut offsets, modes.len(), width);

    let dir_fd = match target {
        PartTarget::File(dir_fd) => *dir_fd,
        PartTarget::Inline { budget } => {
            let limit = *budget;
            let blob = part.blob.into_blocking().await?;
            let ops = part.ops;
            let (checksum, size, inline) = ostrya_rt::unblock(move || {
                let mut capped = CappedBuf::new(limit);
                match compress_part(&mut capped, &modes, &xattrs, blob, &ops, &offsets) {
                    Ok((checksum, size)) => Ok((checksum, size, capped.into_parts())),
                    Err(_) if capped.len() == limit => Err(inline_ceiling_error()),
                    Err(err) => Err(err),
                }
            })
            .await?;
            *budget -= 1 + inline.1.len();
            return Ok(PartEntry {
                checksum,
                size,
                uncompressed_size: part.uncompressed_size,
                objects: part.objects,
                inline: Some(inline),
            });
        }
    };

    let name = index.to_string();
    let temp = TempFile::create(dir_fd, &name);
    let fd = {
        let owned = dir_fd.try_clone()?;
        let temp = temp.name().to_owned();
        ostrya_rt::unblock(move || create_file_blocking(owned.as_fd(), &temp)).await?
    };

    // The spill buffer gives a blocking handle, so the payload, its
    // compression, and the file write all run on one blocking-pool thread.
    let blob = part.blob.into_blocking().await?;
    let ops = part.ops;
    let (checksum, size) = ostrya_rt::unblock(move || {
        let file = std::fs::File::from(fd);
        compress_part(file, &modes, &xattrs, blob, &ops, &offsets)
    })
    .await?;

    finish_file(dir_fd, temp.name(), &name, fsync).await?;
    temp.keep();
    Ok(PartEntry {
        checksum,
        size,
        uncompressed_size: part.uncompressed_size,
        objects: part.objects,
        inline: None,
    })
}

/// A buffer that takes at most `limit` bytes.
///
/// A write past the limit fills the buffer to the limit and then fails, so a
/// caller finds the cause from the length. The buffer holds the first byte, the
/// compression byte of a part, apart from the body after it. The superblock
/// carries the part in this form.
struct CappedBuf {
    compression: Option<u8>,
    body: Vec<u8>,
    limit: usize,
}

impl CappedBuf {
    fn new(limit: usize) -> CappedBuf {
        CappedBuf {
            compression: None,
            body: Vec::new(),
            limit,
        }
    }

    /// Returns the count of bytes taken, with the compression byte.
    fn len(&self) -> usize {
        usize::from(self.compression.is_some()) + self.body.len()
    }

    /// Returns the compression byte and the body. A part always starts with
    /// its compression byte, so a buffer that took no byte reads as
    /// uncompressed.
    fn into_parts(self) -> (u8, Vec<u8>) {
        (self.compression.unwrap_or(0), self.body)
    }
}

impl std::io::Write for CappedBuf {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let room = self.limit - self.len();
        if room == 0 && !bytes.is_empty() {
            return Err(std::io::Error::other(
                "static delta inline part passes the superblock ceiling",
            ));
        }
        let n = bytes.len().min(room);
        let mut taken = &bytes[..n];
        if self.compression.is_none()
            && let Some((&first, rest)) = taken.split_first()
        {
            self.compression = Some(first);
            taken = rest;
        }
        self.body.extend_from_slice(taken);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Returns the refusal of inline parts that do not fit in a superblock that the
/// read path accepts.
fn inline_ceiling_error() -> Error {
    Error::InvalidFormat(format!(
        "static delta inline parts pass the {MAX_SUPERBLOCK}-byte superblock ceiling"
    ))
}

/// Compresses the payload of a part into `out`, a part file or an inline
/// buffer, and returns the SHA-256 and the size of the output.
///
/// This is the expensive half of a part write. xz at [`PART_XZ_LEVEL`] costs
/// seconds of CPU for each tens of megabytes and holds about 370 MiB of encoder
/// state. `XzEncoder` compresses inside `poll_write` and never yields. The
/// callers run this function on the blocking pool, off the executor threads, as
/// [`bsdiff_stream`] does for the other CPU-bound stage.
///
/// The encoder streams in both cases, so the payload is never buffered whole.
/// [`SyncWriter`] and [`BlockingSpill`] complete each I/O call in place. The
/// future never returns `Pending`, so `block_on` drives it to completion on
/// this thread with no executor.
fn compress_part<W: std::io::Write + Unpin>(
    out: W,
    modes: &[u8],
    xattrs: &[u8],
    blob: BlockingSpill,
    ops: &[u8],
    offsets: &[u8],
) -> Result<(Checksum, u64)> {
    let mut hashing = HashingWriter::new(Sha256::new(), SyncWriter(out));
    futures_lite::future::block_on(async {
        hashing
            .write_all(&[COMPRESSION_XZ])
            .await
            .map_err(Error::Io)?;
        let mut encoder = XzEncoder::with_quality(&mut hashing, Level::Precise(PART_XZ_LEVEL));
        encoder.write_all(modes).await.map_err(Error::Io)?;
        encoder.write_all(xattrs).await.map_err(Error::Io)?;
        blob.write_into(&mut encoder).await?;
        encoder.write_all(ops).await.map_err(Error::Io)?;
        encoder.write_all(offsets).await.map_err(Error::Io)?;
        encoder.close().await.map_err(Error::Io)?;
        drop(encoder);
        hashing.flush().await.map_err(Error::Io)
    })?;
    Ok(hashing.finalize())
}

/// A `futures-io` writer over a blocking writer: a file or a buffer.
///
/// Each method does its syscall and returns `Ready`, so a future over it never
/// parks. [`compress_part`] can then drive the async xz encoder to completion
/// on a blocking-pool thread.
struct SyncWriter<W>(W);

impl<W: std::io::Write + Unpin> futures_io::AsyncWrite for SyncWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // An interrupted write is retried here. The `write_all` that drives
        // this writer is the futures-io one, which returns `Interrupted` as an
        // error. `std::io::Write::write_all` retries it.
        let file = &mut self.get_mut().0;
        loop {
            match std::io::Write::write(file, buf) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => return Poll::Ready(result),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(std::io::Write::flush(&mut self.get_mut().0))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Returns the mode table `a(uuu)`: fixed-size 12-byte triples, big-endian on
/// the wire whatever the endianness byte of the superblock is.
fn mode_table(modes: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(modes.len() * 12);
    for &(uid, gid, mode) in modes {
        out.extend_from_slice(&uid.to_be_bytes());
        out.extend_from_slice(&gid.to_be_bytes());
        out.extend_from_slice(&mode.to_be_bytes());
    }
    out
}

/// Returns the xattr table `aa(ayay)`: one entry for each distinct xattr set,
/// in the order in which the objects use them.
fn xattr_table(xattrs: &[Xattrs]) -> Result<Vec<u8>> {
    let entries = xattrs
        .iter()
        .map(|set| {
            Value::Array(
                set.iter()
                    .map(|(name, value)| {
                        Value::Tuple(vec![
                            Value::Bytes(name.to_vec()),
                            Value::Bytes(value.to_vec()),
                        ])
                    })
                    .collect(),
            )
        })
        .collect();
    let ty = Type::parse("aa(ayay)").map_err(ostrya_core::Error::from)?;
    Ok(to_bytes(&ty, &Value::Array(entries)).map_err(ostrya_core::Error::from)?)
}

/// Returns the array of 33-byte entries, an object type and a checksum, that a
/// meta-entry carries.
fn object_array(objects: &[(ObjectType, Checksum)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(objects.len() * 33);
    for (objtype, checksum) in objects {
        out.push(objtype.as_u32() as u8);
        out.extend_from_slice(checksum.as_bytes());
    }
    out
}

/// Generates the bspatch stream that turns `source` into `target`, and gives
/// the target blob back.
///
/// A caller that rejects the patch can then splice from the blob. The patch
/// runs on the blocking pool, because bsdiff sorts the suffixes of the source.
/// The sort is CPU-bound and costs several times the source size in memory.
async fn bsdiff_stream(source: Blob, target: Blob) -> Result<(Vec<u8>, Blob)> {
    ostrya_rt::unblock(move || {
        let mut stream = Vec::new();
        bsdiff::diff(source.as_slice(), target.as_slice(), &mut stream).map_err(Error::Io)?;
        Ok((stream, target))
    })
    .await
}

/// Returns the count of novel bytes in a bspatch stream.
///
/// Most of a patch is its diff stream, which holds the byte-wise difference
/// between target and source. It is zero where the two agree. xz compresses
/// the part as a whole, which reduces those zero runs to almost nothing.
///
/// The size that matters is the count of nonzero bytes. A patch against a
/// near-identical source counts a few dozen bytes, whatever the object size.
fn novel_bytes(stream: &[u8]) -> u64 {
    stream.iter().filter(|&&byte| byte != 0).count() as u64
}

/// Returns `true` if a bspatch stream is worth more than a splice of the
/// content.
///
/// The bound is half the content size. A bound of the full content size does
/// not separate the two cases. A patch against unrelated content has diff and
/// extra blocks about as long as the target. Its bytes are nonzero except where
/// target and source agree, about 1 byte in 256 of high-entropy content.
///
/// For such a patch, [`novel_bytes`] is near 0.996 of the output size, which
/// passes a bound of 1.0. The delta from such a patch is larger than the splice
/// and costs several times the CPU. A real small edit counts a few dozen bytes,
/// so it stays far inside a bound of one half at any object size.
fn patch_beats_splicing(stream: &[u8], output_size: u64) -> bool {
    novel_bytes(stream) * 2 < output_size
}

/// The bytes that the `ostree` command adds to a content size when it compares
/// an object against [`DeltaOptions::min_fallback_size`].
///
/// The size compared is the file header variant, plus this constant, plus the
/// content. The content-stream framing on disk is eight bytes: a big-endian
/// `u32` length and four NUL bytes. The count that the `ostree` command
/// compares is one less.
///
/// The observed switch points at a 1,000,000-byte threshold, for three header
/// shapes:
///
/// - A plain file with no xattr and `uid=gid=0` has an 18-byte header. It packs
///   at a content size of 999,974 and falls back at 999,975.
/// - A file with an 8-byte xattr has a 39-byte header. It switches at 999,954.
/// - A file with a 300-byte xattr has a 334-byte header, past the GVariant
///   offset-width boundary. It switches at 999,659.
///
/// The overhead is 25, 46, and 341 bytes, seven more than the header in each
/// case. The offset table of the header counts, and the constant is flat.
const FALLBACK_FRAMING: u64 = 7;

/// Returns the stream size of a content object, as the fallback threshold
/// compares it: the file header variant, [`FALLBACK_FRAMING`], and the payload.
///
/// A large object travels as a loose object, and the part stays small.
fn stream_size(file: &FileObject) -> Result<u64> {
    let header = file.header();
    Ok(FALLBACK_FRAMING + header.serialize()?.len() as u64 + content_size(file))
}

/// Returns the payload size of a content object: the content length of a
/// regular file, or the target length of a symlink.
fn content_size(file: &FileObject) -> u64 {
    match &file.kind {
        FileKind::Regular { size } => *size,
        FileKind::Symlink { target } => target.len() as u64,
    }
}

/// Splits a superblock file into the payload that signatures cover and the
/// signature dict that it carries (an empty dict if the delta is unsigned).
fn split_envelope(bytes: Vec<u8>) -> Result<(Vec<u8>, Value)> {
    if !bytes.starts_with(SIGNED_MAGIC) {
        return Ok((bytes, Value::Array(Vec::new())));
    }
    let ty = Type::parse(SIGNED_SIG).map_err(ostrya_core::Error::from)?;
    let value = from_bytes(&ty, &bytes).map_err(ostrya_core::Error::from)?;
    let fields = crate::delta::tuple(&value)?;
    let payload = crate::delta::bytes_field(&fields[1], "signed superblock payload")?.to_vec();
    Ok((payload, fields[2].clone()))
}

/// Signs `payload` with each signer in order, adds the signatures to
/// `signatures`, and returns the signed envelope.
///
/// The envelope is held to the superblock ceiling.
async fn sign_superblock(
    payload: Vec<u8>,
    mut signatures: Value,
    signers: &[&dyn Signer],
) -> Result<Vec<u8>> {
    for signer in signers {
        let signature = signer.sign(&payload).await?;
        append_signature(&mut signatures, signer.metadata_key(), signature)?;
    }
    let envelope = Value::Tuple(vec![
        Value::U64(u64::from_le_bytes(*SIGNED_MAGIC)),
        Value::Bytes(payload),
        signatures,
    ]);
    let ty = Type::parse(SIGNED_SIG).map_err(ostrya_core::Error::from)?;
    let encoded = to_bytes(&ty, &envelope).map_err(ostrya_core::Error::from)?;
    check_superblock_size(encoded.len())?;
    Ok(encoded)
}

/// One delta under `deltas/`: its name, its target commit, and the SHA-256 of
/// its superblock, which both advertisements carry.
pub(crate) struct DeltaDigest {
    /// The name of the delta in hex, as the `ostree` command names it: `<to>`
    /// for a delta from scratch, and `<from>-<to>` for other deltas.
    pub(crate) name: String,
    /// The target commit, which the index files are keyed by.
    pub(crate) to: Checksum,
    /// The SHA-256 of the `superblock` file of the delta.
    pub(crate) digest: Checksum,
}

/// Returns the `a{sv}` map that both advertisements carry: the name of each
/// delta to the 32-byte digest of its superblock.
///
/// The entries keep the order of the input.
fn delta_map_value<'a>(deltas: impl Iterator<Item = (&'a str, &'a Checksum)>) -> Result<Value> {
    let ay = Type::parse("ay").map_err(ostrya_core::Error::from)?;
    let mut map = Value::Array(Vec::new());
    for (name, digest) in deltas {
        append_dict_entry(
            &mut map,
            name,
            Value::variant(ay.clone(), Value::Bytes(digest.as_bytes().to_vec())),
        )?;
    }
    Ok(map)
}

/// Builds the `a{sv}` of an index file: the delta map under the shared
/// `ostree.static-deltas` key, with the superblock digest of each delta.
fn index_value(deltas: &BTreeMap<String, Checksum>) -> Result<Vec<u8>> {
    let map = delta_map_value(deltas.iter().map(|(name, digest)| (name.as_str(), digest)))?;
    let mut dict = Value::Array(Vec::new());
    let map_ty = Type::parse("a{sv}").map_err(ostrya_core::Error::from)?;
    append_dict_entry(
        &mut dict,
        STATIC_DELTAS_KEY,
        Value::variant(map_ty.clone(), map),
    )?;
    Ok(to_bytes(&map_ty, &dict).map_err(ostrya_core::Error::from)?)
}

/// Returns the name of a delta, as an advertisement keys it and a message
/// names it.
///
/// The name is the hex of the target commit for a delta from scratch, and
/// `<from>-<to>` for other deltas.
pub(crate) fn delta_name(from: Option<&Checksum>, to: &Checksum) -> String {
    match from {
        Some(from) => format!("{}-{}", from.to_hex(), to.to_hex()),
        None => to.to_hex(),
    }
}

/// Returns the fanout directory under [`DELTA_INDEXES_DIR`] and the file name
/// of the delta index of one target commit.
fn delta_index_parts(to: &Checksum) -> (String, String) {
    let b64 = to.to_base64_modified();
    let (fanout, rest) = b64.split_at(2);
    (fanout.to_owned(), format!("{rest}{INDEX_SUFFIX}"))
}

/// Returns the path of the delta index of one target commit, relative to the
/// repository root: `delta-indexes/<fanout>/<rest>.index`.
pub(crate) fn delta_index_relative_path(to: &Checksum) -> String {
    let (fanout, name) = delta_index_parts(to);
    format!("{DELTA_INDEXES_DIR}/{fanout}/{name}")
}

/// Returns the directory of a delta, relative to the repository root.
///
/// The path is `deltas/<fanout>/<rest>`. For a delta from scratch,
/// `<fanout><rest>` is the modified-base64 form of `to`. For a delta from
/// `from`, it is the modified-base64 form of `from`, then `-`, then the form
/// of `to`. The fanout is the first two characters. Modified base64 replaces
/// `/` with `_` and keeps `+`.
pub fn static_delta_relative_dir(from: Option<&Checksum>, to: &Checksum) -> String {
    delta_relative_dir(from, to)
}

/// Returns the directory of a delta, relative to the repository root, by the
/// rule of [`static_delta_relative_dir`].
///
/// A pull requests this path with the names as written. Modified base64
/// replaces `/` with `_` and keeps `+`, which is a path character, so no escape
/// is added here. The `ostree` command was observed to request these paths with
/// `+` unencoded.
pub(crate) fn delta_relative_dir(from: Option<&Checksum>, to: &Checksum) -> String {
    let to_b64 = to.to_base64_modified();
    match from {
        Some(from) => {
            let from_b64 = from.to_base64_modified();
            let (fanout, rest) = from_b64.split_at(2);
            format!("{DELTAS_DIR}/{fanout}/{rest}-{to_b64}")
        }
        None => {
            let (fanout, rest) = to_b64.split_at(2);
            format!("{DELTAS_DIR}/{fanout}/{rest}")
        }
    }
}

/// Returns the superblock timestamp: the explicit value, else the current time.
fn resolve_timestamp(explicit: Option<u64>) -> Result<u64> {
    match explicit {
        Some(timestamp) => Ok(timestamp),
        None => unix_seconds(),
    }
}

/// Writes a whole file into a delta directory atomically.
async fn write_delta_file(dir_fd: &OwnedFd, name: &str, bytes: &[u8], fsync: bool) -> Result<()> {
    let temp = TempFile::create(dir_fd, name);
    let fd = {
        let owned = dir_fd.try_clone()?;
        let temp = temp.name().to_owned();
        ostrya_rt::unblock(move || create_file_blocking(owned.as_fd(), &temp)).await?
    };
    let mut file = RtFile::from(fd);
    file.write_all(bytes).await.map_err(Error::Io)?;
    file.flush().await.map_err(Error::Io)?;
    drop(file);
    finish_file(dir_fd, temp.name(), name, fsync).await?;
    temp.keep();
    Ok(())
}

/// A guard on the temp name of a delta file.
///
/// A drop unlinks the file until the rename that puts the file in place
/// disarms the guard. Each code path from the creation of the temp file to its
/// rename holds a guard. A failed or cancelled write then leaves only the
/// finished files in the directory.
struct TempFile<'a> {
    dir: &'a OwnedFd,
    name: String,
    armed: bool,
}

impl<'a> TempFile<'a> {
    fn create(dir: &'a OwnedFd, name: &str) -> TempFile<'a> {
        TempFile {
            dir,
            name: temp_name(name),
            armed: true,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    /// Disarms the guard, because the file is in place under its final name.
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for TempFile<'_> {
    /// The unlink runs on the thread that drops the guard, which can be an
    /// executor thread. It is one `unlinkat` on an open directory descriptor, a
    /// syscall that the write path also does inline.
    fn drop(&mut self) {
        if self.armed {
            let _ = rustix::fs::unlinkat(
                self.dir.as_fd(),
                self.name.as_str(),
                rustix::fs::AtFlags::empty(),
            );
        }
    }
}

/// Renames a new temp file to its final name, with a sync if `fsync` is set.
async fn finish_file(dir_fd: &OwnedFd, temp: &str, name: &str, fsync: bool) -> Result<()> {
    let owned = dir_fd.try_clone()?;
    let temp_owned = temp.to_owned();
    let name = name.to_owned();
    ostrya_rt::unblock(move || {
        use rustix::fs::{Mode, OFlags, openat, renameat};

        if fsync {
            let fd = openat(
                owned.as_fd(),
                temp_owned.as_str(),
                OFlags::RDONLY,
                Mode::empty(),
            )
            .map_err(|e| Error::Io(e.into()))?;
            rustix::fs::fdatasync(fd.as_fd()).map_err(|e| Error::Io(e.into()))?;
        }
        renameat(
            owned.as_fd(),
            temp_owned.as_str(),
            owned.as_fd(),
            name.as_str(),
        )
        .map_err(|e| Error::Io(e.into()))?;
        if fsync {
            rustix::fs::fsync(owned.as_fd()).map_err(|e| Error::Io(e.into()))?;
        }
        Ok(())
    })
    .await
}

/// Unlinks the superblock that a previous delta left at this location.
///
/// The unlink comes before the first part of the new delta overwrites the old
/// files. A reader trusts the part checksums of a superblock. If the old
/// superblock stayed while the parts change, an interrupted regeneration gives
/// a delta that fails its own checksum test. With the superblock gone first,
/// the directory reads as a delta that was never finished.
async fn remove_superblock(dir_fd: &OwnedFd) -> Result<()> {
    let owned = dir_fd.try_clone()?;
    ostrya_rt::unblock(move || {
        match rustix::fs::unlinkat(owned.as_fd(), SUPERBLOCK_FILE, rustix::fs::AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(e) => Err(Error::Io(e.into())),
        }
    })
    .await
}

/// Removes the files that are not part of the finished delta.
///
/// The sweep removes these files:
///
/// - numbered part files at or past `count`, from a previous delta at the same
///   location with more parts
/// - temp files of a generation that was killed mid-write, at the age
///   [`TEMP_STALE_SECS`] or older
///
/// The delta directory then holds only its superblock and its numbered parts,
/// which is the layout of a delta directory. A temp file that is too young for
/// the sweep to call abandoned can also stay.
///
/// The pass matches by name, so it runs only over a delta directory of the
/// repository, where this code wrote each entry. An output directory of the
/// caller can hold any file. A file there named `0` or `.x.tmp-1-2` does not
/// belong to this delta.
async fn clean_delta_dir(dir_fd: &OwnedFd, count: usize) -> Result<()> {
    let owned = dir_fd.try_clone()?;
    let now = unix_seconds()?;
    ostrya_rt::unblock(move || {
        for name in dir_child_names(&owned)? {
            let remove = match name.parse::<usize>() {
                Ok(index) => index >= count,
                Err(_) => is_temp_name(&name) && temp_is_stale(owned.as_fd(), &name, now),
            };
            if !remove {
                continue;
            }
            match rustix::fs::unlinkat(owned.as_fd(), name.as_str(), rustix::fs::AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(e) => return Err(Error::Io(e.into())),
            }
        }
        Ok(())
    })
    .await
}

/// The age at which the sweep removes a temp file.
///
/// A generation renames each of its own temp files into place before its
/// sweep. Each temp name that the sweep finds belongs to another run. It is an
/// abandoned leftover, or a file that a running generation still writes.
///
/// The process id in a temp name does not separate the two, because two
/// concurrent generations in one process share it. If the sweep unlinks a file
/// in progress, the rename of that run fails with `ENOENT`.
///
/// The age separates the two cases. A temp file lives much less than one hour
/// before its rename: a 200 MB part compresses in about ninety seconds. The
/// sweep then touches no file in progress.
const TEMP_STALE_SECS: u64 = 60 * 60;

/// Returns `true` if a temp file is old enough to be a leftover, and not a
/// write in progress. A file whose metadata cannot be read stays in place.
fn temp_is_stale(dir: BorrowedFd<'_>, name: &str, now: u64) -> bool {
    let Ok(stat) = rustix::fs::statat(dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) else {
        return false;
    };
    let Ok(mtime) = u64::try_from(stat.st_mtime) else {
        return false;
    };
    now.saturating_sub(mtime) >= TEMP_STALE_SECS
}

/// Returns the current time in seconds since the Unix epoch.
fn unix_seconds() -> Result<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidFormat("the system clock is before the Unix epoch".into()))?;
    Ok(now.as_secs())
}

/// Refuses a superblock past the ceiling of the read path.
///
/// The delta then fails at write time, and not later when it is applied or
/// signed.
fn check_superblock_size(len: usize) -> Result<()> {
    if len as u64 > MAX_SUPERBLOCK {
        return Err(Error::InvalidFormat(format!(
            "static delta superblock is {len} bytes, over the {MAX_SUPERBLOCK}-byte ceiling"
        )));
    }
    Ok(())
}

/// Refuses a part whose mode and xattr tables together pass the ceiling of the
/// read path.
///
/// A part that the reader of ostrya refuses then fails at write time.
fn check_table_size(len: usize) -> Result<()> {
    if len > MAX_TABLE_BYTES {
        return Err(Error::InvalidFormat(format!(
            "static delta part mode and xattr tables are {len} bytes, over the \
             {MAX_TABLE_BYTES}-byte ceiling"
        )));
    }
    Ok(())
}

/// Walks `delta-indexes/<fanout>/` and unlinks each index file whose
/// `<fanout>/<name>` is not in `written`.
///
/// A repository with no `delta-indexes/` needs no work.
fn prune_delta_indexes_blocking(repo_fd: BorrowedFd<'_>, written: &BTreeSet<String>) -> Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags, openat, unlinkat};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let indexes = match openat(repo_fd, DELTA_INDEXES_DIR, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(e) => return Err(Error::Io(e.into())),
    };

    for fanout in dir_child_names(&indexes)? {
        let fan_fd = openat(&indexes, fanout.as_str(), flags, Mode::empty())
            .map_err(|e| Error::Io(e.into()))?;
        for name in dir_child_names(&fan_fd)? {
            if !name.ends_with(INDEX_SUFFIX) || written.contains(&format!("{fanout}/{name}")) {
                continue;
            }
            unlinkat(&fan_fd, name.as_str(), AtFlags::empty()).map_err(|e| Error::Io(e.into()))?;
        }
    }
    Ok(())
}

/// Unlinks the index file at `relative` under the repository root.
///
/// An absent file, fanout directory, or `delta-indexes/` is no error. A
/// dangling symlink on the path also counts as absent. Each other failure is an
/// error, as it is for the `ostree` command. This includes a directory at the
/// path. It also includes a path component that is not a directory, such as a
/// regular file at the fanout or at `delta-indexes`.
fn remove_delta_index_blocking(repo_fd: BorrowedFd<'_>, relative: &str) -> Result<()> {
    use rustix::fs::{AtFlags, unlinkat};

    match unlinkat(repo_fd, relative, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(Error::Io(e.into())),
    }
}

/// Walks `delta-indexes/<fanout>/` and collects the target of each index file,
/// by the rule of [`Repo::list_static_delta_indexes`].
fn list_delta_indexes_blocking(repo_fd: BorrowedFd<'_>) -> Result<Vec<Checksum>> {
    use rustix::fs::{Dir, FileType, Mode, OFlags, openat};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let indexes = match openat(repo_fd, DELTA_INDEXES_DIR, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(Error::Io(e.into())),
    };
    let mut indexes = Dir::new(indexes).map_err(|e| Error::Io(e.into()))?;

    let mut out = Vec::new();
    for fanout in entries_of_type(&mut indexes, FileType::Directory)? {
        if fanout.len() != 2 {
            continue;
        }
        let fan_fd = openat(
            indexes.fd().map_err(|e| Error::Io(e.into()))?,
            fanout.as_slice(),
            flags | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|e| Error::Io(e.into()))?;
        let mut fan_dir = Dir::new(fan_fd).map_err(|e| Error::Io(e.into()))?;
        for name in entries_of_type(&mut fan_dir, FileType::RegularFile)? {
            let Some(rest) = name.strip_suffix(INDEX_SUFFIX.as_bytes()) else {
                continue;
            };
            if rest.len() != 41 {
                continue;
            }
            let mut b64 = fanout.clone();
            b64.extend_from_slice(rest);
            let Ok(b64) = std::str::from_utf8(&b64) else {
                continue;
            };
            if let Ok(to) = Checksum::from_base64_modified(b64) {
                out.push(to);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Returns the names of the entries of type `ty` in an open directory, with no
/// symlink followed.
///
/// If the directory reports no type for an entry, a `statat` reads the type.
fn entries_of_type(dir: &mut rustix::fs::Dir, ty: rustix::fs::FileType) -> Result<Vec<Vec<u8>>> {
    use rustix::fs::{AtFlags, FileType, statat};

    let mut out = Vec::new();
    while let Some(entry) = dir.next() {
        let entry = entry.map_err(|e| Error::Io(e.into()))?;
        let name = entry.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let entry_ty = match entry.file_type() {
            FileType::Unknown => match statat(
                dir.fd().map_err(|e| Error::Io(e.into()))?,
                name,
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(stat) => FileType::from_raw_mode(stat.st_mode),
                Err(rustix::io::Errno::NOENT) => continue,
                Err(e) => return Err(Error::Io(e.into())),
            },
            known => known,
        };
        if entry_ty == ty {
            out.push(name.to_bytes().to_vec());
        }
    }
    Ok(out)
}

/// Returns the temp name under which a delta file is written before its rename
/// into place.
fn temp_name(name: &str) -> String {
    format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        crate::write::unique()
    )
}

/// Returns `true` if `name` is a temp name that [`temp_name`] makes.
fn is_temp_name(name: &str) -> bool {
    name.starts_with('.') && name.contains(".tmp-")
}

/// Creates a file for writing and replaces a leftover with the same name.
///
/// The call sets the mode to [`DELTA_FILE_MODE`] whatever the umask is, as the
/// `ostree` command does.
fn create_file_blocking(dir: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, fchmod, openat};

    let _ = rustix::fs::unlinkat(dir, name, rustix::fs::AtFlags::empty());
    let fd = openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(DELTA_FILE_MODE),
    )
    .map_err(|e| Error::Io(e.into()))?;
    fchmod(&fd, Mode::from_raw_mode(DELTA_FILE_MODE)).map_err(|e| Error::Io(e.into()))?;
    Ok(fd)
}

/// Opens a directory relative to `base`, and creates each component that is
/// absent.
fn open_subdir_blocking(base: BorrowedFd<'_>, relative: &str) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, mkdirat, openat};

    let mut current = base.try_clone_to_owned()?;
    for component in relative.split('/').filter(|part| !part.is_empty()) {
        match mkdirat(
            current.as_fd(),
            component,
            Mode::from_raw_mode(DELTA_DIR_MODE),
        ) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(Error::Io(e.into())),
        }
        current = openat(
            current.as_fd(),
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| Error::Io(e.into()))?;
    }
    Ok(current)
}

/// Creates a directory and its parents at an absolute or relative path, and
/// opens it.
///
/// The mode is [`DELTA_DIR_MODE`], the mode that the repository path gives to
/// `mkdirat`. An output directory then does not take its permissions from the
/// umask of the caller alone.
fn create_dir_path_blocking(path: &Path) -> Result<OwnedFd> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DELTA_DIR_MODE)
        .create(path)
        .map_err(Error::Io)?;
    open_dir_blocking(path)
}

/// Opens the directory that holds a superblock file, and returns the
/// descriptor and the file name in it.
///
/// The directory is the parent of the path, or the working directory for a
/// path with no `/`. The call does not create it. A path whose last component
/// is empty, `.`, or `..` is refused with `EISDIR`, for example the empty path,
/// `/`, and `x/.`. A path that names a directory is also refused with `EISDIR`.
///
/// A part file name is refused, because the superblock replaces a part of that
/// name. A symlink at the path is not followed: the rename that puts the
/// superblock in place replaces the link.
fn open_superblock_parent_blocking(path: &Path) -> Result<(OwnedFd, String)> {
    use std::os::unix::ffi::OsStrExt;

    let is_dir = || Error::Io(rustix::io::Errno::ISDIR.into());
    // The last component comes from the bytes. `Path::file_name` skips a
    // trailing `.`, so it gives `x` for `x/.`.
    let bytes = path.as_os_str().as_bytes();
    let (parent, name) = match bytes.iter().rposition(|b| *b == b'/') {
        Some(slash) => (&bytes[..slash], &bytes[slash + 1..]),
        None => (&b""[..], bytes),
    };
    if matches!(name, b"" | b"." | b"..") {
        return Err(is_dir());
    }
    let name = std::str::from_utf8(name).map_err(|_| {
        Error::InvalidFormat(format!(
            "static delta superblock file name {} is not UTF-8",
            path.display()
        ))
    })?;
    if name
        .parse::<usize>()
        .is_ok_and(|index| index.to_string() == name)
    {
        return Err(Error::InvalidFormat(format!(
            "static delta superblock file name {name} is a part file name"
        )));
    }
    let parent = match parent {
        b"" if bytes.first() == Some(&b'/') => Path::new("/"),
        b"" => Path::new("."),
        parent => Path::new(std::ffi::OsStr::from_bytes(parent)),
    };
    let fd = open_dir_blocking(parent)?;
    match rustix::fs::statat(&fd, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat)
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                == rustix::fs::FileType::Directory =>
        {
            return Err(is_dir());
        }
        Ok(_) | Err(rustix::io::Errno::NOENT) => {}
        Err(e) => return Err(Error::Io(e.into())),
    }
    Ok((fd, name.to_owned()))
}

/// Opens an existing directory by path.
fn open_dir_blocking(path: &Path) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::Io(e.into()))
}

/// Opens an existing directory by path, on the blocking pool.
async fn open_dir_path(path: &Path) -> Result<OwnedFd> {
    let path = path.to_owned();
    ostrya_rt::unblock(move || open_dir_blocking(&path)).await
}

/// Checks at compile time that `DeltaOptions` and `DeltaSuperblock` are `Send`
/// and `Sync`.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DeltaOptions>();
    assert_send_sync::<crate::delta::DeltaSuperblock>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    /// Checks the two path shapes against the paths that the `ostree` command
    /// was observed to write and to request. A pull requests the same names on
    /// the wire.
    #[test]
    fn delta_paths_take_the_base64_fanout() {
        let to = checksum(0x11);
        let from = checksum(0x22);
        let to_b64 = to.to_base64_modified();
        let from_b64 = from.to_base64_modified();

        assert_eq!(
            delta_relative_dir(None, &to),
            format!("deltas/{}/{}", &to_b64[..2], &to_b64[2..])
        );
        assert_eq!(
            delta_relative_dir(Some(&from), &to),
            format!("deltas/{}/{}-{to_b64}", &from_b64[..2], &from_b64[2..])
        );
        assert_eq!(
            delta_index_relative_path(&to),
            format!("delta-indexes/{}/{}.index", &to_b64[..2], &to_b64[2..])
        );
    }

    /// A delta is keyed by hex in the advertisement, whichever shape it has.
    #[test]
    fn delta_names_are_hex() {
        let to = checksum(0x11);
        let from = checksum(0x22);
        assert_eq!(delta_name(None, &to), to.to_hex());
        assert_eq!(
            delta_name(Some(&from), &to),
            format!("{}-{}", from.to_hex(), to.to_hex())
        );
    }

    #[test]
    fn the_superblock_ceiling_names_the_size_it_rejects() {
        let over = MAX_SUPERBLOCK as usize + 1;
        check_superblock_size(MAX_SUPERBLOCK as usize).unwrap();
        let err = check_superblock_size(over).unwrap_err();
        let Error::InvalidFormat(message) = err else {
            panic!("an oversized superblock must be an InvalidFormat error: {err}");
        };
        assert!(
            message.contains(&over.to_string()),
            "the error does not name the size: {message}"
        );
    }

    #[test]
    fn the_table_ceiling_names_the_size_it_rejects() {
        check_table_size(MAX_TABLE_BYTES).unwrap();
        let over = MAX_TABLE_BYTES + 1;
        let err = check_table_size(over).unwrap_err();
        let Error::InvalidFormat(message) = err else {
            panic!("oversized part tables must be an InvalidFormat error: {err}");
        };
        assert!(
            message.contains(&over.to_string()),
            "the error does not name the size: {message}"
        );
    }

    #[test]
    fn a_patch_of_unrelated_content_loses_to_splicing() {
        // A diff against unrelated content is nonzero except where the two
        // bytes agree. The bound must reject this shape. It counts just under
        // the output size, so a plain `< output_size` comparison keeps it.
        let output_size = 4_096u64;
        let stream: Vec<u8> = (0..output_size)
            .map(|i| if i % 256 == 0 { 0 } else { 0xa5 })
            .collect();
        assert!(novel_bytes(&stream) < output_size);
        assert!(
            !patch_beats_splicing(&stream, output_size),
            "a patch counting {} novel bytes of {output_size} was kept",
            novel_bytes(&stream)
        );
    }

    #[test]
    fn a_patch_of_a_small_edit_beats_splicing() {
        // A diff against a near-identical source is zero except at the edit,
        // which stays far inside the bound at any object size.
        let mut stream = vec![0u8; 4_096];
        stream[100] = 0x01;
        stream[101] = 0x02;
        assert!(patch_beats_splicing(&stream, 4_096));
    }

    #[test]
    fn an_empty_target_never_keeps_a_patch() {
        assert!(!patch_beats_splicing(&[], 0));
    }

    /// A scratch directory for a test that needs real descriptors.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ostrya-deltagen-{tag}-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A write to the data source of a part that the async file defers to its
    /// next flush must fail the handover to the blocking side.
    ///
    /// The framing offsets of the part come from the length that the spill
    /// counted. Without this check, a data source that lost bytes compresses
    /// into a part that verifies its own checksum and fails only when the
    /// delta is applied.
    #[test]
    fn a_deferred_spill_write_error_fails_the_handover() {
        let dir = scratch("spill-error");
        let path = dir.join("target");
        std::fs::write(&path, b"").unwrap();
        // A read-only descriptor, so the write to it fails with EBADF. The
        // async file writes on a background task, so `write_all` accepts the
        // bytes, and the error comes at the flush.
        let file = std::fs::File::open(&path).unwrap();
        let spill_dir = std::fs::File::open(&dir).unwrap();

        let outcome = ostrya_rt::block_on(async {
            let mut spill = Spill::File {
                file: RtFile::from(file),
                len: 0,
            };
            spill
                .append(b"data source bytes", spill_dir.as_fd())
                .await?;
            spill.into_blocking().await.map(|_| ())
        });
        let _ = std::fs::remove_dir_all(&dir);
        outcome.expect_err("a failed spill write must fail the handover");
    }

    /// A data source with fewer bytes than the length that the framing counts
    /// fails the part. No payload is made whose two byte arrays disagree with
    /// their offsets.
    #[test]
    fn a_short_data_source_fails_the_part() {
        let dir = scratch("short-source");
        let path = dir.join("source");
        std::fs::write(&path, b"seven!!").unwrap();
        let file = std::fs::File::open(&path).unwrap();

        let outcome = ostrya_rt::block_on(async {
            let spill = BlockingSpill::File { file, len: 9 };
            let mut sink: Vec<u8> = Vec::new();
            spill.write_into(&mut sink).await
        });
        let _ = std::fs::remove_dir_all(&dir);

        let err = outcome.expect_err("a short data source must fail the part");
        let Error::InvalidFormat(message) = err else {
            panic!("a short data source must be an InvalidFormat error: {err}");
        };
        assert!(
            message.contains('7') && message.contains('9'),
            "the error does not name both lengths: {message}"
        );
    }

    /// A part whose write fails after its temp file exists leaves the delta
    /// directory as it was. An interrupted generation then leaves no partial
    /// part beside the finished files.
    ///
    /// The failure is the count check of [`BlockingSpill::write_into`] in
    /// [`compress_part`]. The test gives the part a data source whose recorded
    /// length is more than the file length.
    #[test]
    fn a_failed_part_write_leaves_no_temp_file_behind() {
        let root = scratch("part-temp-leak");
        let path = root.join("source");
        std::fs::write(&path, b"seven!!").unwrap();
        let dir = root.join("delta");
        std::fs::create_dir(&dir).unwrap();
        let dir_fd = open_dir_blocking(&dir).unwrap();

        let outcome = ostrya_rt::block_on(async {
            let mut part = Part {
                blob: Spill::File {
                    file: RtFile::from(std::fs::File::open(&path).unwrap()),
                    len: 9,
                },
                ..Part::default()
            };
            part.finish_object(ObjectType::File, Checksum::sha256(b"x"), 9);
            write_part(&mut PartTarget::File(&dir_fd), 0, part, false).await
        });
        let leftovers = dir_child_names(&dir_fd).unwrap();
        let _ = std::fs::remove_dir_all(&root);

        assert!(outcome.is_err(), "a short data source must fail the part");
        assert!(
            leftovers.is_empty(),
            "the failed part left files behind: {leftovers:?}"
        );
    }

    /// Returns `(repo, commit)` for a repository at `root/repo` with one
    /// commit of `files` files, each of `size` bytes of noise.
    async fn noise_commit(root: &Path, files: usize, size: usize) -> (Repo, Checksum) {
        use crate::{
            CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree,
        };

        let tree = root.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for i in 0..files {
            let bytes: Vec<u8> = (0..size)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            std::fs::write(tree.join(format!("f{i}")), bytes).unwrap();
        }
        let repo = Repo::create(
            &root.join("repo"),
            CreateOptions::new(ostrya_core::RepoMode::Archive),
        )
        .await
        .unwrap();
        let txn = repo.transaction().await.unwrap();
        let dfd = std::fs::File::open(&tree).unwrap();
        let mut modifier = Some(CommitModifier::new(
            CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
        ));
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, modifier.as_mut())
            .await
            .unwrap();
        let root_tree = txn.write_mtree(&mut mtree).await.unwrap();
        let commit = txn
            .write_commit(
                CommitOptions {
                    timestamp: Some(1_700_000_000),
                    ..CommitOptions::default()
                },
                &root_tree,
            )
            .await
            .unwrap();
        txn.commit().await.unwrap();
        (repo, commit)
    }

    /// An inline generation whose parts pass the superblock ceiling is
    /// refused, and it changes nothing. The earlier delta at the repository
    /// location keeps its superblock and its part files and stays listed. A
    /// new output directory receives no file.
    #[test]
    fn an_inline_generation_over_the_ceiling_keeps_the_earlier_delta() {
        let root = scratch("inline-ceiling");
        let out = root.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let outcome = ostrya_rt::block_on(async {
            let (repo, commit) = noise_commit(&root, 3, 200_000).await;
            let files = DeltaOptions {
                timestamp: Some(1_700_000_000),
                min_fallback_size: 0,
                max_chunk_size: 150_000,
                ..DeltaOptions::default()
            };
            let relative = repo
                .generate_static_delta(None, &commit, &files)
                .await
                .unwrap();
            let delta = root.join("repo").join(&relative);
            let before = dir_child_names(&open_dir_blocking(&delta).unwrap()).unwrap();
            let superblock = std::fs::read(delta.join(SUPERBLOCK_FILE)).unwrap();
            let listed = repo.list_static_deltas().await.unwrap();
            assert_eq!(listed.len(), 1);

            let inline = DeltaOptions {
                inline: true,
                ..files
            };
            let err = repo
                .generate_static_delta_under(None, &commit, &inline, 100_000)
                .await
                .unwrap_err();
            let Error::InvalidFormat(message) = err else {
                panic!("the ceiling refusal is an invalid-format error: {err}");
            };
            assert!(message.contains("superblock ceiling"), "{message}");
            let mut after = dir_child_names(&open_dir_blocking(&delta).unwrap()).unwrap();
            let mut before = before;
            before.sort();
            after.sort();
            assert_eq!(after, before);
            assert_eq!(
                std::fs::read(delta.join(SUPERBLOCK_FILE)).unwrap(),
                superblock
            );
            assert_eq!(repo.list_static_deltas().await.unwrap(), listed);

            let err = repo
                .generate_static_delta_under(
                    None,
                    &commit,
                    &DeltaOptions {
                        output_dir: Some(out.clone()),
                        ..inline
                    },
                    100_000,
                )
                .await
                .unwrap_err();
            assert!(matches!(err, Error::InvalidFormat(_)), "{err}");
            dir_child_names(&open_dir_blocking(&out).unwrap()).unwrap()
        });
        let _ = std::fs::remove_dir_all(&root);
        assert!(outcome.is_empty(), "{outcome:?}");
    }

    /// The inline part buffer takes bytes up to its limit and refuses the
    /// first byte past it. The part write reports the superblock ceiling where
    /// the buffer filled, so the test checks the ceiling without a 128 MiB
    /// part.
    #[test]
    fn the_capped_part_buffer_refuses_past_its_limit() {
        use std::io::Write;

        let mut capped = CappedBuf::new(4);
        assert_eq!(capped.write(b"abc").unwrap(), 3);
        assert_eq!(capped.write(b"de").unwrap(), 1);
        assert!(capped.write(b"f").is_err());
        assert_eq!(capped.write(b"").unwrap(), 0);
        assert_eq!(capped.len(), 4);
        assert_eq!(capped.into_parts(), (b'a', b"bcd".to_vec()));

        let root = scratch("capped-part");
        let tmp = open_dir_blocking(&root).unwrap();
        let outcome = ostrya_rt::block_on(async {
            let mut part = Part::default();
            part.blob.append(&[7u8; 4096], tmp.as_fd()).await?;
            part.finish_object(ObjectType::File, Checksum::sha256(b"x"), 4096);
            write_part(&mut PartTarget::Inline { budget: 16 }, 0, part, false).await
        });
        let Err(Error::InvalidFormat(message)) = outcome else {
            panic!("an inline part past the budget must be refused");
        };
        assert!(message.contains("superblock ceiling"), "{message}");

        let mut budget = PartTarget::Inline { budget: 1 << 20 };
        let entry = ostrya_rt::block_on(async {
            let mut part = Part::default();
            part.blob.append(&[7u8; 4096], tmp.as_fd()).await?;
            part.finish_object(ObjectType::File, Checksum::sha256(b"x"), 4096);
            write_part(&mut budget, 0, part, false).await
        })
        .unwrap();
        let (compression, body) = entry.inline.expect("an inline part keeps its bytes");
        let mut bytes = vec![compression];
        bytes.extend_from_slice(&body);
        assert_eq!(bytes.len() as u64, entry.size);
        assert_eq!(compression, COMPRESSION_XZ);
        assert_eq!(Checksum::sha256(&bytes), entry.checksum);
        let PartTarget::Inline { budget } = budget else {
            unreachable!();
        };
        assert_eq!(budget, (1 << 20) - bytes.len());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn temp_names_are_recognized_and_part_names_are_not() {
        assert!(is_temp_name(&temp_name("0")));
        assert!(is_temp_name(&temp_name(SUPERBLOCK_FILE)));
        assert!(!is_temp_name("0"));
        assert!(!is_temp_name(SUPERBLOCK_FILE));
    }
}
