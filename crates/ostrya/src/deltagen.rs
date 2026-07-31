//! Static-delta generation (Phase 15b).
//!
//! [`Repo::generate_static_delta`] writes the delta that turns one commit into
//! another (or produces a commit from scratch) in the wire format
//! `format-reference.md` records: a `superblock` carrying the target commit
//! whole plus per-part and fallback tables, and numbered part files carrying the
//! objects. [`Repo::sign_static_delta`] wraps a written superblock in the signed
//! envelope, and [`Repo::reindex_static_deltas`] rebuilds the `delta-indexes/`
//! cache. The read side is in [`crate::delta`], and the two are tested against
//! each other as well as against the `ostree` tool.
//!
//! An object reaches the receiver one of four ways, decided per object:
//!
//! - as a loose fallback, when its stream is at least
//!   [`DeltaOptions::min_fallback_size`] -- the delta names it and the receiver
//!   fetches it whole;
//! - as a rollsum delta against the object at the same path in the source
//!   commit, when content-defined chunking finds shared chunks -- the operation
//!   stream copies the unchanged runs out of the source object and carries only
//!   the changed ones;
//! - as a bspatch stream against that same source object, when the object is
//!   small enough that chunking finding nothing shared is not itself evidence
//!   that the two are unrelated (see [`BSDIFF_CONTENT_LIMIT`]) and the patch
//!   carries substantially less novel data than the content
//!   (see [`patch_beats_splicing`]);
//! - spliced verbatim out of the part payload otherwise, which is also the only
//!   route for metadata objects and symlinks.
//!
//! Generation is memory-bounded. A part's data source accumulates in a
//! [`Spill`] buffer that moves to an anonymous temp file past
//! [`MMAP_THRESHOLD`], spliced content streams into it in [`IO_CHUNK`] pieces
//! without ever being held whole, and the part payload is serialized straight
//! into the xz encoder rather than built in a buffer: its GVariant framing is
//! written around the two large byte arrays, which stream from the spill buffer.
//! The dominant term in the footprint is the xz encoder itself, which holds
//! about 370 MiB per part being compressed (see [`PART_XZ_LEVEL`]).
//!
//! Diffing is the exception to the streaming rule, since both objects need random
//! access: source and target load through the same heap-or-mmap [`Blob`] the read
//! path uses, and chunking scans both end to end, so every page of both is
//! resident while a pair is being planned. Peak resident set size therefore tracks
//! the two objects' sizes together, in mapped temp-file pages rather than heap.
//! [`DeltaOptions::min_fallback_size`] bounds the target -- an object at or past it
//! is handed over loose and never diffed, and a zero threshold removes that bound
//! -- while the source it pairs with is whatever object sits at the same path in
//! the source commit and carries no bound of its own.
//! [`DeltaOptions::max_bsdiff_size`] bounds the patch attempt alone, whose suffix
//! sort costs several times the source size on top of the pair.
//!
//! The CPU-bound stages run on the blocking pool rather than on an executor
//! thread: chunking and hashing both objects of a diff candidate, bsdiff's
//! suffix sort ([`bsdiff_stream`]), and each part's compression
//! ([`compress_part`]).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::SeekFrom;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
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
    Blob, COMMIT_SIG, COMPRESSION_XZ, ENDIANNESS_KEY, ENDIANNESS_LITTLE, IO_CHUNK, MAX_SUPERBLOCK,
    MAX_TABLE_BYTES, MMAP_THRESHOLD, OP_BSPATCH, OP_CLOSE, OP_OPEN, OP_OPEN_SPLICE_CLOSE,
    OP_SET_READ_SOURCE, OP_UNSET_READ_SOURCE, OP_WRITE, SIGNED_MAGIC, SIGNED_SIG, SUPERBLOCK_SIG,
    dir_child_names, open_rw_temp, read_capped, spill_to_blob,
};
use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject};
use crate::hashing::HashingWriter;
use crate::repo::Repo;
use crate::rollsum::{self, Run};
use crate::sign::{Signer, append_signature};

/// The delta part format version the meta-entry records.
const PART_VERSION: u32 = 0;

/// The xz preset every part is compressed with, pinned so part bytes depend on
/// this project rather than on the compression crate's default. Preset 8,
/// non-extreme, with the CRC64 check xz uses by default: an LZMA2 dictionary of
/// 32 MiB, which `xz -8 -T1 -vv` reports as 370 MiB of encoder memory per
/// concurrent part and 33 MiB to decode. The same dictionary size the tool's
/// parts carry.
const PART_XZ_LEVEL: i32 = 8;

/// The largest content size a bspatch stream is attempted for, applied on top of
/// [`DeltaOptions::max_bsdiff_size`].
///
/// bsdiff is reached only after chunking found nothing shared. For an object
/// spanning many chunks that means no chunk-sized window of the target occurs
/// anywhere in the source, which is evidence the two objects are unrelated --
/// and a patch against unrelated content runs about the target's length, so it
/// loses to splicing after paying for a suffix sort. Below the chunker's
/// [`rollsum::MAX_CHUNK`] an object is one chunk or a handful, where an edit
/// anywhere defeats chunking on its own and its failure carries no such
/// evidence. That is also where the tool emits bspatch (`format-reference.md`
/// records a 1,024-byte object with a small edit).
///
/// It bounds the source as well as the target, since the suffix sort is over the
/// source: pairing is by path with no size-ratio rule, so a small object can be
/// paired with a large one it replaced.
const BSDIFF_CONTENT_LIMIT: u64 = rollsum::MAX_CHUNK as u64;

/// The superblock file name inside a delta directory.
pub(crate) const SUPERBLOCK_FILE: &str = "superblock";
/// The delta directory tree, relative to the repository root.
const DELTAS_DIR: &str = "deltas";
/// The delta index tree, relative to the repository root.
const DELTA_INDEXES_DIR: &str = "delta-indexes";
/// The suffix of an index file under `delta-indexes/`.
const INDEX_SUFFIX: &str = ".index";
/// The `a{sv}` key an index file (and the summary) stores the delta map under.
pub(crate) const STATIC_DELTAS_KEY: &str = "ostree.static-deltas";

/// The mode delta files and directories are created with, matching the tool.
const DELTA_FILE_MODE: u32 = 0o644;
const DELTA_DIR_MODE: u32 = 0o755;

/// Knobs for [`Repo::generate_static_delta`].
///
/// The three size thresholds are the ones the tool exposes on
/// `static-delta generate`, in bytes rather than the tool's decimal megabytes:
/// pass `4 * 1_000_000` where the tool takes `--min-fallback-size=4`.
#[derive(Debug, Clone)]
pub struct DeltaOptions {
    /// An object whose uncompressed stream (file header plus content) reaches
    /// this size is delivered as a loose fallback instead of being packed into a
    /// part. Default 4,000,000. Zero turns fallbacks off, as the tool's
    /// `--min-fallback-size=0` does, so every object is packed whatever its
    /// size.
    pub min_fallback_size: u64,
    /// The largest content size bsdiff is attempted for. bsdiff's suffix sort
    /// costs a multiple of the input size in memory, so this bounds the peak.
    /// Default 64,000,000. A second bound derived from the chunker's maximum
    /// chunk size applies as well, and the tighter of the two wins, so at this
    /// default the chunker's 64 KiB is what decides.
    pub max_bsdiff_size: u64,
    /// The payload size at which a part is closed and the next one started.
    /// Default 32,000,000.
    pub max_chunk_size: u64,
    /// Whether bsdiff may be used at all. With bsdiff off, an object that
    /// chunking cannot express is spliced whole.
    pub bsdiff: bool,
    /// The superblock timestamp (seconds since the Unix epoch). `None` uses the
    /// current time, as the tool does; setting it makes the output reproducible.
    pub timestamp: Option<u64>,
    /// Write the delta's files -- the superblock and the numbered part files --
    /// into this directory instead of the repository's `deltas/` tree. The
    /// directory is created if absent, and its other contents are left alone:
    /// files this delta writes are replaced, and nothing else is removed, so a
    /// longer previous delta's extra part files stay behind. A reader takes the
    /// parts the superblock lists, so they cost disk rather than correctness.
    pub output_dir: Option<PathBuf>,
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
        }
    }
}

impl Repo {
    /// Generate the static delta from `from` (or from scratch when `None`) to
    /// `to`, and return the directory it was written to.
    ///
    /// Both commits and every object the delta packs must be present. The
    /// delta's files land under `deltas/` by default, in the base64-fanout
    /// directory the tool uses, or in [`DeltaOptions::output_dir`] when set.
    /// Part files are written before the superblock, so a delta interrupted
    /// part-way leaves no superblock for a reader to trust. Each file is written
    /// under a temp name that is unlinked unless the rename putting it in place
    /// runs, so a generation that fails or is cancelled leaves no partial file
    /// in the directory. Regenerating over an
    /// existing delta overwrites its parts in place, so that delta's superblock
    /// is unlinked before the first part is written rather than being left to
    /// describe files this run has replaced; once the new superblock is in place,
    /// part files left by a longer previous delta are removed, along with temp
    /// files a generation that was killed mid-write left behind once they are an
    /// hour old (see [`TEMP_STALE_SECS`]). That pass covers the repository's own
    /// `deltas/` tree; a directory named through [`DeltaOptions::output_dir`]
    /// belongs to the caller and nothing in it is removed.
    ///
    /// Generating the same delta twice at once, into one directory, is not
    /// supported: both runs write the same file names, so they overwrite each
    /// other's parts and superblock. Generating different deltas concurrently is,
    /// since each has its own directory.
    ///
    /// For the default location the returned directory is relative to the
    /// repository root, which the caller supplies, since a handle carries
    /// descriptors rather than a path: `root.join(returned)` is the directory
    /// [`apply_static_delta_offline`](Repo::apply_static_delta_offline) and
    /// [`sign_static_delta`](Repo::sign_static_delta) take. With
    /// [`DeltaOptions::output_dir`] set the returned path is that option
    /// verbatim, resolved against the process's working directory when
    /// relative, and is passed on unchanged.
    ///
    /// The result is unsigned; pass it to
    /// [`sign_static_delta`](Repo::sign_static_delta) to sign it, and to
    /// [`reindex_static_deltas`](Repo::reindex_static_deltas) to publish it in
    /// the index cache.
    pub async fn generate_static_delta(
        &self,
        from: Option<&Checksum>,
        to: &Checksum,
        opts: &DeltaOptions,
    ) -> Result<PathBuf> {
        if opts.max_chunk_size == 0 {
            return Err(Error::InvalidFormat(
                "static delta max chunk size must be positive".to_owned(),
            ));
        }
        // The target commit is embedded in the superblock whole, so it is
        // loaded (and its presence required) before anything is written.
        let commit_bytes = self.load_object_bytes(ObjectType::Commit, to).await?;
        if let Some(from) = from
            && !self.has_object(ObjectType::Commit, from).await?
        {
            return Err(Error::ObjectNotFound {
                checksum: *from,
                ty: ObjectType::Commit,
            });
        }

        let selection = self.select_objects(from, to, opts).await?;
        let (dir_path, dir_fd) = self.open_delta_dir(from, to, opts).await?;
        let tmp_fd = self.open_tmp_dir().await?;
        let fsync = self.config().fsync()?;

        // Parts are overwritten in place, so a superblock describing the
        // previous delta at this location goes before the first of them.
        remove_superblock(&dir_fd).await?;

        let mut entries: Vec<PartEntry> = Vec::new();
        let mut part = Part::default();
        for item in &selection.packed {
            // A part closes once its payload would pass the chunk ceiling. The
            // object's own content size is the estimate: exact for a splice, an
            // upper bound for a diffed object. The decision comes before the
            // object is appended, so a part's payload never passes the ceiling,
            // and an object that rollsums down to a small payload still closes the
            // part it would have fit in -- one extra xz stream and one extra pair
            // of mode and xattr tables, in exchange for the ceiling holding.
            if !part.is_empty() && part.payload_len() + item.content_size > opts.max_chunk_size {
                entries.push(write_part(&dir_fd, entries.len(), part, fsync).await?);
                part = Part::default();
            }
            self.add_object(&mut part, item, opts, tmp_fd.as_fd())
                .await?;
        }
        if !part.is_empty() {
            entries.push(write_part(&dir_fd, entries.len(), part, fsync).await?);
        }

        let superblock =
            self.build_superblock(from, to, &commit_bytes, &entries, &selection, opts)?;
        write_delta_file(&dir_fd, SUPERBLOCK_FILE, &superblock, fsync).await?;
        // The sweep recognizes what it removes by name, which holds only where
        // every entry is this code's own: an output directory the caller named can
        // hold files whose names a delta's own files also take.
        if opts.output_dir.is_none() {
            clean_delta_dir(&dir_fd, entries.len()).await?;
        }
        Ok(dir_path)
    }

    /// Sign a written delta with `signer`, wrapping its superblock in the signed
    /// envelope.
    ///
    /// The signed payload is the raw superblock bytes. Signing an already-signed
    /// delta appends to the engine's signature array and leaves other engines'
    /// arrays in place, so calling this once per engine accumulates signatures.
    /// The superblock is replaced atomically; re-index afterwards, since the
    /// index records the superblock's digest. The envelope adds to the
    /// superblock's size, so the result is held to the same ceiling
    /// [`generate_static_delta`](Repo::generate_static_delta) applies: signing a
    /// superblock just under it fails rather than producing one the read path
    /// refuses.
    pub async fn sign_static_delta(&self, dir: &Path, signer: &dyn Signer) -> Result<()> {
        let bytes = read_capped(dir.join(SUPERBLOCK_FILE)).await?;
        let (payload, mut signatures) = split_envelope(bytes)?;
        let signature = signer.sign(&payload).await?;
        append_signature(&mut signatures, signer.metadata_key(), signature)?;

        let envelope = Value::Tuple(vec![
            Value::U64(u64::from_le_bytes(*SIGNED_MAGIC)),
            Value::Bytes(payload),
            signatures,
        ]);
        let ty = Type::parse(SIGNED_SIG).map_err(ostrya_core::Error::from)?;
        let encoded = to_bytes(&ty, &envelope).map_err(ostrya_core::Error::from)?;
        check_superblock_size(encoded.len())?;

        let dir_fd = open_dir_path(dir).await?;
        let fsync = self.config().fsync()?;
        write_delta_file(&dir_fd, SUPERBLOCK_FILE, &encoded, fsync).await
    }

    /// Rebuild the `delta-indexes/` cache from the deltas present under
    /// `deltas/`.
    ///
    /// One index file per target commit lists every delta that produces it,
    /// keyed by the delta's name and holding its superblock's SHA-256 -- the
    /// same map the summary carries. The pass removes the index file of a target
    /// that has no delta left, so a stale entry cannot advertise a delta that is
    /// gone; the fanout directory that removal empties stays, as it does for the
    /// tool. A delta whose superblock is missing is skipped, so a half-written
    /// delta does not fail the pass.
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
            let (fanout, name) = delta_index_parts(to);
            let dir_fd = self
                .open_repo_subdir(&format!("{DELTA_INDEXES_DIR}/{fanout}"))
                .await?;
            let index = index_value(deltas)?;
            write_delta_file(&dir_fd, &name, &index, fsync).await?;
            written.insert(format!("{fanout}/{name}"));
        }
        self.prune_delta_indexes(written).await
    }

    /// Every delta under `deltas/`, in delta-name order, with the SHA-256 of its
    /// superblock.
    ///
    /// This is what the `delta-indexes/` cache and the summary's
    /// `ostree.static-deltas` map both advertise, so both are built from it. A
    /// delta whose superblock is missing is skipped, which leaves a half-written
    /// delta unadvertised rather than failing the caller.
    pub(crate) async fn static_delta_digests(&self) -> Result<Vec<DeltaDigest>> {
        let mut out = Vec::new();
        for (from, to) in self.list_static_delta_targets().await? {
            let relative = format!(
                "{}/{SUPERBLOCK_FILE}",
                delta_relative_dir(from.as_ref(), &to)
            );
            let Some(bytes) = self.read_repo_file(&relative).await? else {
                continue;
            };
            out.push(DeltaDigest {
                name: delta_name(from.as_ref(), &to),
                to,
                digest: Checksum::sha256(&bytes),
            });
        }
        // The `deltas/` tree is walked in directory order, which is the order the
        // filesystem hands back. Sorting by name gives the index files and the
        // summary map one order whatever that was.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The summary's `ostree.static-deltas` value: an `a{sv}` mapping each
    /// delta's name to its 32-byte superblock digest, or `None` when the
    /// repository holds no delta.
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

    /// Remove the index files under `delta-indexes/` that this pass did not
    /// write.
    ///
    /// `written` holds the `<fanout>/<rest>.index` names the pass produced. A
    /// name that does not end in [`INDEX_SUFFIX`] is left in place, so a temp
    /// file from a concurrent write survives.
    async fn prune_delta_indexes(&self, written: BTreeSet<String>) -> Result<()> {
        let repo = self.clone();
        ostrya_rt::unblock(move || prune_delta_indexes_blocking(repo.repo_fd(), &written)).await
    }

    /// Split the objects the delta must deliver into the ones packed into parts
    /// and the ones handed over as loose fallbacks, and pair each packed content
    /// object with the object at the same path in the source commit.
    ///
    /// Objects already reachable from `from` are not delivered at all, and the
    /// target commit object itself rides in the superblock. Metadata objects are
    /// emitted before content objects, and both are ordered by checksum, so the
    /// same inputs produce the same delta.
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
                // The target commit is embedded in the superblock, and no other
                // commit object is reachable at depth 0.
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
            // Metadata objects are stored uncompressed in every repository
            // mode, so the on-disk size is the size the part will carry.
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
            // A source object that is no longer present cannot be diffed
            // against, so the object is delivered whole instead.
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

    /// Map each content object of `to` to the object at the same path in `from`.
    ///
    /// Pairing is by path, so a file that moved is not paired with its old self;
    /// an object appearing at several paths takes the first pairing in path
    /// order.
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

    /// Collect every file path a commit's tree holds, with the content object at
    /// that path.
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

    /// Append one object to the part under construction: its bytes into the
    /// data source and its operations onto the stream.
    async fn add_object(
        &self,
        part: &mut Part,
        item: &PackItem,
        opts: &DeltaOptions,
        tmp: BorrowedFd<'_>,
    ) -> Result<()> {
        // Only a content object carries a loaded file object; a metadata object
        // is spliced from its serialized bytes.
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

        // A diff candidate needs random access to both objects, so both load as
        // heap-or-mmap blobs; without a source the content streams straight into
        // the data source and is never held whole.
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
        // Chunking and hashing both objects end to end is CPU-bound, so it runs
        // on the blocking pool like the patch attempt below does; the blobs are
        // owned values, so they move in with the work and come back with the
        // plan.
        let (plan, source_blob, target_blob) = ostrya_rt::unblock(move || {
            let plan = rollsum::plan(source_blob.as_slice(), target_blob.as_slice());
            (plan, source_blob, target_blob)
        })
        .await;
        // The object is reconstructed from these bytes, so its declared output
        // size comes from them rather than from the size the header recorded.
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

        // Nothing shared to copy: try a patch where the object is small enough
        // that chunking's failure says nothing about how related the two are, and
        // keep the patch only when it beats carrying the content itself. The
        // blobs move into the patch attempt, which hands the target back for the
        // splice fallback.
        let mut target_blob = target_blob;
        // The suffix sort is over the source, so both objects are held to the
        // limit: the tighter of the chunker-derived bound and the caller's knob.
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

    /// Load a content object's payload for random access, on the heap when small
    /// and in a read-only mapping of a temp file when large.
    async fn load_content_blob(&self, file: &FileObject, tmp: BorrowedFd<'_>) -> Result<Blob> {
        let reader = file.reader().await?;
        let owned = tmp.try_clone_to_owned()?;
        spill_to_blob(reader, &owned, None).await
    }

    /// Assemble the superblock GVariant.
    fn build_superblock(
        &self,
        from: Option<&Checksum>,
        to: &Checksum,
        commit_bytes: &[u8],
        entries: &[PartEntry],
        selection: &Selection,
        opts: &DeltaOptions,
    ) -> Result<Vec<u8>> {
        let mut metadata = Value::Array(Vec::new());
        crate::commit::append_dict_entry(
            &mut metadata,
            ENDIANNESS_KEY,
            Value::variant(
                Type::parse("y").map_err(ostrya_core::Error::from)?,
                Value::Byte(ENDIANNESS_LITTLE),
            ),
        )?;

        let commit_ty = Type::parse(COMMIT_SIG).map_err(ostrya_core::Error::from)?;
        let commit = from_bytes(&commit_ty, commit_bytes).map_err(ostrya_core::Error::from)?;

        let meta_entries = entries
            .iter()
            .map(|entry| {
                Value::Tuple(vec![
                    Value::U32(PART_VERSION),
                    Value::Bytes(entry.checksum.as_bytes().to_vec()),
                    // Sizes are host order, which the `ostree.endianness` byte
                    // declares as little for everything this serializer writes.
                    Value::U64(entry.size),
                    Value::U64(entry.uncompressed_size),
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
                    Value::U64(fallback.compressed_size),
                    Value::U64(fallback.content_size),
                ])
            })
            .collect();

        let superblock = Value::Tuple(vec![
            metadata,
            // The timestamp is big-endian regardless of the endianness byte.
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

    /// The `(from, to)` pair of every delta under `deltas/`.
    async fn list_static_delta_targets(&self) -> Result<Vec<(Option<Checksum>, Checksum)>> {
        let repo = self.clone();
        ostrya_rt::unblock(move || crate::delta::list_delta_targets(repo.repo_fd())).await
    }

    /// Read a file under the repository root, or `None` when it is absent.
    /// Bounded by the metadata ceiling, so it serves superblocks and index
    /// files but not object payloads. A file past the ceiling is an error, as it
    /// is for [`read_capped`], since a prefix of a superblock would index a
    /// digest that covers part of it.
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

    /// Open a directory under the repository root, creating it and its parents.
    async fn open_repo_subdir(&self, relative: &str) -> Result<OwnedFd> {
        let repo = self.clone();
        let relative = relative.to_owned();
        ostrya_rt::unblock(move || open_subdir_blocking(repo.repo_fd(), &relative)).await
    }

    /// Open the repository's `tmp/` directory, where spill files are created.
    async fn open_tmp_dir(&self) -> Result<OwnedFd> {
        self.open_repo_subdir("tmp").await
    }

    /// Create and open the directory the delta's files are written to, and
    /// return its path as well.
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

/// The objects a delta delivers, split by how they travel.
#[derive(Default)]
struct Selection {
    packed: Vec<PackItem>,
    fallbacks: Vec<FallbackItem>,
}

/// One object a part carries.
struct PackItem {
    objtype: ObjectType,
    checksum: Checksum,
    /// The object's payload size: the serialized bytes of a metadata object, the
    /// content size of a file, the target length of a symlink.
    content_size: u64,
    /// The object at the same path in the source commit, when there is one to
    /// diff against.
    source: Option<Checksum>,
    /// The content object, loaded once during selection and reused when the
    /// object is packed. `None` for a metadata object, which is packed from its
    /// serialized bytes.
    file: Option<FileObject>,
}

/// One object the delta names but does not carry.
struct FallbackItem {
    checksum: Checksum,
    compressed_size: u64,
    content_size: u64,
}

/// A written part: what its meta-entry records.
struct PartEntry {
    checksum: Checksum,
    /// The part file's on-disk size.
    size: u64,
    /// The uncompressed payload the part delivers, summed over its objects.
    uncompressed_size: u64,
    objects: Vec<(ObjectType, Checksum)>,
}

/// A part under construction: the mode and xattr tables, the data source, the
/// operation stream, and the objects the stream produces in order.
///
/// Each table is a vector in wire order beside a map from entry to index, so an
/// object's lookup costs one hash rather than a scan of the entries already
/// there.
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

    /// The payload accumulated so far, which the chunk ceiling applies to.
    fn payload_len(&self) -> u64 {
        self.blob.len() + self.ops.len() as u64
    }

    /// Append one operation: its opcode followed by LEB128 operands.
    fn push_op(&mut self, opcode: u8, operands: &[u64]) {
        self.ops.push(opcode);
        for &operand in operands {
            varint::encode(operand, &mut self.ops);
        }
    }

    /// Record that the operations just emitted complete one object.
    fn finish_object(&mut self, objtype: ObjectType, checksum: Checksum, payload: u64) {
        self.objects.push((objtype, checksum));
        self.uncompressed_size += payload;
    }

    /// The index of `(uid, gid, mode)` in the mode table, appending it if new.
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

    /// The index of an xattr set in the xattr table, appending it if new.
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

/// An append-only buffer for a part's data source: on the heap until it passes
/// [`MMAP_THRESHOLD`], then in an anonymous temp file. Only the streaming window
/// is resident either way, so a part's payload costs disk rather than heap.
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

    /// Append `bytes`, returning the offset they were written at.
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

    /// Append everything `reader` yields, returning the offset and the length
    /// written. The reader is drained in [`IO_CHUNK`] pieces, so an object of any
    /// size passes through a bounded buffer.
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

    /// Move an in-memory buffer into a temp file.
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

    /// Hand the buffer over as a blocking handle, positioned at its start, so a
    /// part's payload can be streamed from a blocking-pool thread.
    async fn into_blocking(self) -> Result<BlockingSpill> {
        match self {
            Spill::Ram(buf) => Ok(BlockingSpill::Ram(buf)),
            Spill::File { mut file, len } => {
                // The async file performs its writes on a background task, so a
                // write that fails is reported by the next `flush` rather than by
                // `write_all`, and `into_std` settles pending writes without
                // reporting. Flushing here is what turns an `ENOSPC` or `EIO` on
                // the spill file into a failed generation: otherwise the part
                // would be compressed from a truncated data source while its
                // framing offsets still counted the bytes the spill accepted.
                file.flush().await.map_err(Error::Io)?;
                // The recovered file shares the open file description, so the
                // read starts from an explicit rewind rather than wherever
                // appending left the offset.
                let mut file = file.into_std().await;
                std::io::Seek::seek(&mut file, SeekFrom::Start(0)).map_err(Error::Io)?;
                Ok(BlockingSpill::File { file, len })
            }
        }
    }
}

/// A part's data source ready to stream from a blocking-pool thread: the same
/// heap-or-temp-file split [`Spill`] accumulated it under.
enum BlockingSpill {
    Ram(Vec<u8>),
    File { file: std::fs::File, len: u64 },
}

impl BlockingSpill {
    /// Stream the buffer's contents into `out` in [`IO_CHUNK`] pieces, so a
    /// payload of any size passes through a bounded buffer.
    ///
    /// The temp-file form counts what it streams and refuses a count other than
    /// the length the spill recorded, which is the length the part's framing
    /// offsets were derived from. A data source that lost bytes then fails
    /// generation instead of producing a part that decodes short when it is
    /// applied.
    async fn write_into<W: futures_io::AsyncWrite + Unpin>(self, out: &mut W) -> Result<()> {
        match self {
            BlockingSpill::Ram(buf) => out.write_all(&buf).await.map_err(Error::Io),
            BlockingSpill::File { mut file, len } => {
                let mut chunk = vec![0u8; IO_CHUNK];
                let mut streamed = 0u64;
                loop {
                    let n = match std::io::Read::read(&mut file, &mut chunk) {
                        // Retried rather than reported, as `read_to_end` does.
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

/// Write one part file and return its meta-entry.
///
/// The payload GVariant `(a(uuu)aa(ayay)ayay)` is emitted straight into the xz
/// encoder: the two tables first (bounded metadata, built in memory), then the
/// data source streamed out of its spill buffer, then the operation stream, then
/// the tuple's framing offsets, whose width follows from the payload length that
/// is known before the first byte is written. The SHA-256 covers the whole
/// on-disk file, compression byte included, which is what the meta-entry
/// records. Framing and the two tables are assembled here; the compression and
/// the file write happen in [`compress_part`], on the blocking pool.
async fn write_part(dir_fd: &OwnedFd, index: usize, part: Part, fsync: bool) -> Result<PartEntry> {
    let modes = mode_table(&part.modes);
    let xattrs = xattr_table(&part.xattrs)?;
    check_table_size(modes.len() + xattrs.len())?;
    let blob_len = part.blob.len();
    let ops_len = part.ops.len() as u64;

    // Field alignments: `a(uuu)` needs 4 and sits at offset 0; the xattr table,
    // the data source, and the operation stream all align to 1, so no padding
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

    let name = index.to_string();
    let temp = TempFile::create(dir_fd, &name);
    let fd = {
        let owned = dir_fd.try_clone()?;
        let temp = temp.name().to_owned();
        ostrya_rt::unblock(move || create_file_blocking(owned.as_fd(), &temp)).await?
    };

    // The spill buffer hands over a blocking handle, so the payload, its
    // compression, and the file write all happen on one blocking-pool thread.
    let blob = part.blob.into_blocking().await?;
    let ops = part.ops;
    let (checksum, size) =
        ostrya_rt::unblock(move || compress_part(fd, &modes, &xattrs, blob, &ops, &offsets))
            .await?;

    finish_file(dir_fd, temp.name(), &name, fsync).await?;
    temp.keep();
    Ok(PartEntry {
        checksum,
        size,
        uncompressed_size: part.uncompressed_size,
        objects: part.objects,
    })
}

/// Compress a part's payload into `fd`, returning the file's SHA-256 and its
/// size.
///
/// This is the expensive half of writing a part: xz at [`PART_XZ_LEVEL`] costs
/// seconds of CPU per tens of megabytes and holds about 370 MiB of encoder state,
/// and `XzEncoder` compresses inside `poll_write` without ever yielding. Running
/// it here keeps it off the executor threads, as [`bsdiff_stream`] does for the
/// other CPU-bound stage.
///
/// The encoder is the same streaming one either way, so the payload is still
/// never buffered whole. [`SyncWriter`] and [`BlockingSpill`] complete every I/O
/// call in place, so the future never returns `Pending` and `block_on` drives it
/// to completion on this thread with no executor behind it.
fn compress_part(
    fd: OwnedFd,
    modes: &[u8],
    xattrs: &[u8],
    blob: BlockingSpill,
    ops: &[u8],
    offsets: &[u8],
) -> Result<(Checksum, u64)> {
    let mut hashing = HashingWriter::new(Sha256::new(), SyncWriter(std::fs::File::from(fd)));
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

/// A `futures-io` writer over a blocking file.
///
/// Every method performs its syscall and returns `Ready`, so a future built over
/// it never parks. That is what lets [`compress_part`] drive the async xz encoder
/// to completion on a blocking-pool thread.
struct SyncWriter(std::fs::File);

impl futures_io::AsyncWrite for SyncWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // An interrupted write is retried here, since the `write_all` driving
        // this is the futures-io one, which surfaces `Interrupted` as an error
        // rather than retrying it the way `std::io::Write::write_all` does.
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

/// The mode table `a(uuu)`: fixed-size 12-byte triples, big-endian on the wire
/// regardless of the superblock's endianness byte.
fn mode_table(modes: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(modes.len() * 12);
    for &(uid, gid, mode) in modes {
        out.extend_from_slice(&uid.to_be_bytes());
        out.extend_from_slice(&gid.to_be_bytes());
        out.extend_from_slice(&mode.to_be_bytes());
    }
    out
}

/// The xattr table `aa(ayay)`: one entry per distinct xattr set, in the order
/// the objects referenced them.
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

/// The stride-33 objtype-plus-checksum array a meta-entry carries.
fn object_array(objects: &[(ObjectType, Checksum)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(objects.len() * 33);
    for (objtype, checksum) in objects {
        out.push(objtype.as_u32() as u8);
        out.extend_from_slice(checksum.as_bytes());
    }
    out
}

/// Generate the bspatch stream that turns `source` into `target`, handing the
/// target blob back so a caller that rejects the patch can still splice from it.
///
/// The patch is produced off the async threads: bsdiff sorts the suffixes of the
/// source, which is CPU-bound and costs several times the source size in memory.
async fn bsdiff_stream(source: Blob, target: Blob) -> Result<(Vec<u8>, Blob)> {
    ostrya_rt::unblock(move || {
        let mut stream = Vec::new();
        bsdiff::diff(source.as_slice(), target.as_slice(), &mut stream).map_err(Error::Io)?;
        Ok((stream, target))
    })
    .await
}

/// How much novel data a bspatch stream carries.
///
/// A patch's bulk is its diff stream, which holds the byte-wise difference
/// between target and source and so is zero wherever the two agree. The
/// enclosing part is xz'd as a whole, which reduces those zero runs to almost
/// nothing, so the size that matters is the count of nonzero bytes rather than
/// the stream length: a patch against a near-identical source counts a few dozen
/// bytes whatever the object's size.
fn novel_bytes(stream: &[u8]) -> u64 {
    stream.iter().filter(|&&byte| byte != 0).count() as u64
}

/// Whether a bspatch stream is worth keeping over splicing the content itself.
///
/// The bound is half the content's size. It has to be a fraction rather than the
/// content size itself, because the two cases sit too close together at 1.0: a
/// patch against unrelated content has diff and extra blocks running about the
/// target's length, and its bytes are nonzero except where target and source
/// coincide -- about 1 byte in 256 of high-entropy content -- so
/// [`novel_bytes`] lands near 0.996 of the output size and clears any bound at
/// 1.0, while the delta it produces comes out larger than the splice for several
/// times the CPU. A genuine small edit counts a few dozen bytes, so it stays far
/// inside a one-half bound at any object size.
fn patch_beats_splicing(stream: &[u8], output_size: u64) -> bool {
    novel_bytes(stream) * 2 < output_size
}

/// The bytes the tool adds to a content size when it compares an object against
/// [`DeltaOptions::min_fallback_size`]: the size compared is the file header
/// variant plus this constant plus the content.
///
/// The on-disk content-stream framing is eight bytes -- a big-endian `u32`
/// length and four NUL bytes -- and the count the tool compares is one below it.
/// Measured at a 1,000,000-byte threshold over three header shapes: a plain
/// no-xattr `uid=gid=0` file packs at a content size of 999,974 and falls back at
/// 999,975 with an 18-byte header; one carrying an 8-byte xattr switches at
/// 999,954 with a 39-byte header; and one carrying a 300-byte xattr, whose header
/// crosses the GVariant offset-width boundary at 334 bytes, switches at 999,659.
/// The overhead is 25, 46, and 341 bytes, seven above each header in every case,
/// so the header's own offset table counts and the constant is flat.
const FALLBACK_FRAMING: u64 = 7;

/// The stream size of a content object as the fallback threshold compares it:
/// the file header variant, [`FALLBACK_FRAMING`], and the payload. A large object
/// travels as a loose object instead of inflating a part.
fn stream_size(file: &FileObject) -> Result<u64> {
    let header = file.header();
    Ok(FALLBACK_FRAMING + header.serialize()?.len() as u64 + content_size(file))
}

/// The payload size of a content object: a regular file's content length, or a
/// symlink's target length.
fn content_size(file: &FileObject) -> u64 {
    match &file.kind {
        FileKind::Regular { size } => *size,
        FileKind::Symlink { target } => target.len() as u64,
    }
}

/// Split a superblock file into the payload signatures cover and the signature
/// dict it already carries (an empty dict when the delta is unsigned).
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

/// One delta present under `deltas/`: its name, its target commit, and the
/// SHA-256 of its superblock, which is what both advertisements carry.
pub(crate) struct DeltaDigest {
    /// The delta's tool name: `<to>` for a from-scratch delta, `<from>-<to>`
    /// otherwise, in hex.
    pub(crate) name: String,
    /// The target commit, which the index files are keyed by.
    pub(crate) to: Checksum,
    /// The SHA-256 of the delta's `superblock` file.
    pub(crate) digest: Checksum,
}

/// The `a{sv}` map both advertisements carry: each delta's name to the 32-byte
/// digest of its superblock, in the order the entries arrive.
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

/// Build an index file's `a{sv}`: the delta map under the shared
/// `ostree.static-deltas` key, each delta naming its superblock's digest.
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

/// A delta's name as an advertisement keys it and as a message names it: the
/// target commit's hex for a from-scratch delta, `<from>-<to>` otherwise.
pub(crate) fn delta_name(from: Option<&Checksum>, to: &Checksum) -> String {
    match from {
        Some(from) => format!("{}-{}", from.to_hex(), to.to_hex()),
        None => to.to_hex(),
    }
}

/// The delta index of one target commit, split into the fanout directory under
/// [`DELTA_INDEXES_DIR`] that holds it and its file name.
fn delta_index_parts(to: &Checksum) -> (String, String) {
    let b64 = to.to_base64_modified();
    let (fanout, rest) = b64.split_at(2);
    (fanout.to_owned(), format!("{rest}{INDEX_SUFFIX}"))
}

/// The delta index of one target commit, relative to the repository root:
/// `delta-indexes/<fanout>/<rest>.index`.
pub(crate) fn delta_index_relative_path(to: &Checksum) -> String {
    let (fanout, name) = delta_index_parts(to);
    format!("{DELTA_INDEXES_DIR}/{fanout}/{name}")
}

/// The delta's directory relative to the repository root: base64-checksum
/// fanout, with the source checksum leading a from-to delta's name.
///
/// The names reach the wire as written when a pull requests this path. Modified
/// base64 replaces `/` with `_` and keeps `+`, which is a path character, so no
/// escaping enters here -- the tool was observed to request these paths with `+`
/// unencoded.
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

/// Resolve the superblock timestamp: an explicit value, else the current time.
fn resolve_timestamp(explicit: Option<u64>) -> Result<u64> {
    match explicit {
        Some(timestamp) => Ok(timestamp),
        None => unix_seconds(),
    }
}

/// Write a whole file into a delta directory atomically.
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

/// A delta file's temp name, unlinked on drop until the rename that puts the
/// file in place disarms it. Every path between creating the temp file and
/// renaming it goes through one, so a write that fails or is cancelled leaves
/// the directory holding the finished files alone.
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

    /// Give up ownership: the file is in place under its final name.
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for TempFile<'_> {
    /// The unlink runs on whatever thread drops the guard, which can be an
    /// executor thread. It is one `unlinkat` against an open directory
    /// descriptor, the syscall the write path already performs inline.
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

/// Sync a freshly written temp file into place under its final name.
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

/// Unlink the superblock a previous delta left at this location, before the
/// first part of the new delta overwrites its files.
///
/// A reader trusts a superblock's part checksums, so leaving the old one in place
/// while parts are replaced would turn an interrupted regeneration into a delta
/// that fails its own checksum test. With the superblock gone first, the
/// directory reads as a delta that was never finished.
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

/// Remove what the finished delta does not consist of: numbered part files at or
/// past `count`, left by a previous delta at the same location that had more
/// parts, and temp files left by a generation that was killed mid-write, once they
/// have aged past [`TEMP_STALE_SECS`]. A delta directory then holds exactly its
/// superblock and its numbered parts, which is what `format-reference.md` records,
/// apart from a temp file too young for the sweep to judge abandoned.
///
/// The pass matches by name, so it runs only over a repository-managed delta
/// directory, whose every entry this code wrote. A caller-supplied output
/// directory can hold anything, and a file there named `0` or `.x.tmp-1-2` is not
/// this delta's to remove.
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

/// The age a temp file has to reach before the sweep removes it.
///
/// A generation renames each of its own temp files into place as it goes, so
/// every temp name the sweep meets belongs to another run: either an abandoned
/// leftover, or the file a generation running right now is still writing. The
/// process id in a temp name does not separate the two, since two concurrent
/// generations in one process share it, and unlinking a file that is still being
/// written fails that run's rename with `ENOENT`. Age separates them. An hour is
/// far past the time a temp file lives before its rename -- a 200 MB part
/// compresses in about ninety seconds -- so nothing in flight is touched.
const TEMP_STALE_SECS: u64 = 60 * 60;

/// Whether a temp file is old enough to be a leftover rather than a write in
/// progress. A file whose metadata cannot be read is left in place.
fn temp_is_stale(dir: BorrowedFd<'_>, name: &str, now: u64) -> bool {
    let Ok(stat) = rustix::fs::statat(dir, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) else {
        return false;
    };
    let Ok(mtime) = u64::try_from(stat.st_mtime) else {
        return false;
    };
    now.saturating_sub(mtime) >= TEMP_STALE_SECS
}

/// The current time in seconds since the Unix epoch.
fn unix_seconds() -> Result<u64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::InvalidFormat("the system clock is before the Unix epoch".into()))?;
    Ok(now.as_secs())
}

/// Refuse a superblock past the ceiling the read path enforces, so the delta
/// fails at write time rather than when it is applied or signed.
fn check_superblock_size(len: usize) -> Result<()> {
    if len as u64 > MAX_SUPERBLOCK {
        return Err(Error::InvalidFormat(format!(
            "static delta superblock is {len} bytes, over the {MAX_SUPERBLOCK}-byte ceiling"
        )));
    }
    Ok(())
}

/// Refuse a part whose mode and xattr tables together pass the ceiling the read
/// path collects them under, so a part the port's own reader would reject fails
/// at write time instead.
fn check_table_size(len: usize) -> Result<()> {
    if len > MAX_TABLE_BYTES {
        return Err(Error::InvalidFormat(format!(
            "static delta part mode and xattr tables are {len} bytes, over the \
             {MAX_TABLE_BYTES}-byte ceiling"
        )));
    }
    Ok(())
}

/// Walk `delta-indexes/<fanout>/` and unlink every index file whose
/// `<fanout>/<name>` is absent from `written`. A repository with no
/// `delta-indexes/` yields nothing to do.
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

/// The temp name a delta file is written under before being renamed into place.
fn temp_name(name: &str) -> String {
    format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        crate::write::unique()
    )
}

/// Whether `name` is one of the temp names [`temp_name`] produces.
fn is_temp_name(name: &str) -> bool {
    name.starts_with('.') && name.contains(".tmp-")
}

/// Create a file for writing, replacing any leftover of the same name.
fn create_file_blocking(dir: BorrowedFd<'_>, name: &str) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, openat};

    let _ = rustix::fs::unlinkat(dir, name, rustix::fs::AtFlags::empty());
    openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(DELTA_FILE_MODE),
    )
    .map_err(|e| Error::Io(e.into()))
}

/// Open a directory relative to `base`, creating each component that is absent.
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

/// Create a directory at an absolute or relative path (with its parents) and
/// open it. The mode is [`DELTA_DIR_MODE`], the same one the repository path
/// passes to `mkdirat`, so an output directory does not take its permissions
/// from the caller's umask alone.
fn create_dir_path_blocking(path: &Path) -> Result<OwnedFd> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DELTA_DIR_MODE)
        .create(path)
        .map_err(Error::Io)?;
    open_dir_blocking(path)
}

/// Open an existing directory by path.
fn open_dir_blocking(path: &Path) -> Result<OwnedFd> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::Io(e.into()))
}

/// Open an existing directory by path, off the async threads.
async fn open_dir_path(path: &Path) -> Result<OwnedFd> {
    let path = path.to_owned();
    ostrya_rt::unblock(move || open_dir_blocking(&path)).await
}

/// `DeltaOptions` moves freely across tasks and threads.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DeltaOptions>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(byte: u8) -> Checksum {
        Checksum::from_bytes([byte; 32])
    }

    /// The two path shapes, against the paths the tool was observed to write
    /// and to request. A pull requests these same names on the wire.
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
        // A diff against unrelated content is nonzero except where the two bytes
        // happen to coincide, which is the shape the bound has to reject: it
        // counts just under the output size, so a bare `< output_size`
        // comparison would keep it.
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
        // A diff against a near-identical source is zero everywhere but the edit,
        // which stays far inside the bound however large the object is.
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

    /// A write to a part's data source that the async file defers until its next
    /// flush has to fail the handover to the blocking side. The part's framing
    /// offsets come from the length the spill counted, so a data source that lost
    /// bytes would otherwise be compressed into a part that verifies its own
    /// checksum and fails only when the delta is applied.
    #[test]
    fn a_deferred_spill_write_error_fails_the_handover() {
        let dir = scratch("spill-error");
        let path = dir.join("target");
        std::fs::write(&path, b"").unwrap();
        // A read-only descriptor, so the write against it fails with EBADF. The
        // async file performs writes on a background task, so `write_all` accepts
        // the bytes and the error surfaces at the flush.
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

    /// A data source holding fewer bytes than the length the framing counts fails
    /// the part rather than producing a payload whose two byte arrays disagree
    /// with their offsets.
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
    /// directory as it found it, so an interrupted generation does not leave a
    /// partial part beside the finished files. The failure is the count check
    /// [`BlockingSpill::write_into`] performs from inside [`compress_part`],
    /// reached by giving the part a data source whose recorded length overstates
    /// the file.
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
            write_part(&dir_fd, 0, part, false).await
        });
        let leftovers = dir_child_names(&dir_fd).unwrap();
        let _ = std::fs::remove_dir_all(&root);

        assert!(outcome.is_err(), "a short data source must fail the part");
        assert!(
            leftovers.is_empty(),
            "the failed part left files behind: {leftovers:?}"
        );
    }

    #[test]
    fn temp_names_are_recognized_and_part_names_are_not() {
        assert!(is_temp_name(&temp_name("0")));
        assert!(is_temp_name(&temp_name(SUPERBLOCK_FILE)));
        assert!(!is_temp_name("0"));
        assert!(!is_temp_name(SUPERBLOCK_FILE));
    }
}
