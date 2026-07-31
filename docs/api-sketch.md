# Ostrya -- API Sketch

A rust-native, async API for the port. This is a design sketch to agree the
shape, not final code. It is idiomatic where the existing C API is a GLib
GObject god-object: owned handles, `Result`, typed values, traits, and builders
replace out-parameters, `glib::Variant` options dicts, raw `dfd: i32`, and
`gio::Cancellable`. On-disk behavior stays faithful (see `format-reference.md`).

Provenance: this is the port's own API design. Where it contrasts with the
existing C API, that contrast is drawn from the public API documentation at
https://ostreedev.github.io/ostree/, not from the LGPL source (see CLAUDE.md,
"Licensing and clean-room discipline").

Guiding choices:

- `Repo` is cheaply clonable (an `Arc` inner) so handles move freely across
  tasks. Opening does the fd/config work once; clones share it.
- The runtime backend is feature-gated behind the internal `ostrya-rt`
  crate: `smol` by default, `tokio` optional. Concrete stream types
  (`ContentReader`, `ContentWriter`, the hashing streams) implement the
  `futures-io` traits unconditionally and the tokio traits under the
  `tokio` feature, so neither backend needs a caller-side adapter.
  `AsyncRead`/`AsyncWrite` bounds in argument position (`write_content`,
  tar import/export) are the `futures-io` traits; a tokio caller adapts
  those with `tokio_util::compat`.
- I/O entry points are `async fn`. Filter/xattr callbacks are synchronous.
- Cancellation is via dropping the future, optionally racing it against a
  cancel signal, rather than a cancellable object.
- Errors are one `ostrya::Error` enum with `thiserror`, not `glib::Error`.
- File content is never loaded into memory whole. Content operations --
  hashing, compression, storing, checkout, transfer -- consume and produce
  async streams in bounded-size chunks. Whole-buffer handling is reserved
  for metadata objects, whose size the format caps.
- `Repo`, `Transaction`, `FileObject`, and the file content readers and
  writers are `Send + Sync`, pinned by compile-time assertions as each type
  lands.

## Core value types

```rust
/// 32-byte SHA-256 object id.
pub struct Checksum([u8; 32]);
impl Checksum {
    pub fn from_hex(s: &str) -> Result<Self>;
    pub fn from_bytes(b: [u8; 32]) -> Self;
    pub fn to_hex(&self) -> String;                 // 64 lowercase hex
    pub fn to_base64_modified(&self) -> String;     // delta dir naming
    pub fn as_bytes(&self) -> &[u8; 32];
}

pub enum ObjectType {
    File = 1, DirTree = 2, DirMeta = 3, Commit = 4, TombstoneCommit = 5,
    CommitMeta = 6, PayloadLink = 7, FileXattrs = 8, FileXattrsLink = 9,
}
// extension() is mode-aware for File: `.file` / `.filez`.
impl ObjectType { pub fn is_meta(self) -> bool; pub fn extension(self, mode: RepoMode) -> &'static str; }

pub struct ObjectName { pub checksum: Checksum, pub ty: ObjectType }

pub enum RepoMode {
    Bare, BareUser, BareUserOnly, BareSplitXattrs, Archive,
    BareUserShared,   // port extension: bare-user storage, logical mode never on the inode
}

pub struct CollectionRef { pub collection_id: Option<String>, pub ref_name: String }

/// Sorted xattr set, canonicalized on construction.
pub struct Xattrs(Vec<(Vec<u8>, Vec<u8>)>);

pub type Result<T> = std::result::Result<T, Error>;

#[non_exhaustive]
pub enum Error {
    Io(std::io::Error),
    NotFound { object: ObjectName },
    RefNotFound(String),
    CorruptObject { object: ObjectName, detail: String },
    ChecksumMismatch { expected: Checksum, actual: Checksum },
    InvalidFormat(String),
    Signature(SignatureError),
    Lock(LockError),
    // ...
}
```

## Repo

```rust
#[derive(Clone)]
pub struct Repo { /* Arc<RepoInner> */ }

pub struct OpenOptions { /* future-proofing: version checks, cache dir */ }
pub struct CreateOptions { pub mode: RepoMode, pub collection_id: Option<String> }

impl Repo {
    pub async fn open_at(dir: BorrowedFd<'_>, path: &Path) -> Result<Repo>;
    pub async fn open(path: &Path) -> Result<Repo>;
    pub async fn create_at(dir: BorrowedFd<'_>, path: &Path, opts: CreateOptions) -> Result<Repo>;

    pub fn mode(&self) -> RepoMode;
    pub fn config(&self) -> &Config;                       // parsed, read-only view
    pub async fn reload_config(&self) -> Result<()>;
    pub fn is_writable(&self) -> bool;

    // --- reading ---
    pub async fn resolve_rev(&self, refspec: &str, allow_noent: bool)
        -> Result<Option<Checksum>>;
    pub async fn list_refs(&self, prefix: Option<&str>)
        -> Result<Vec<(String, Checksum)>>;
    pub async fn list_refs_ext(&self, prefix: Option<&str>, flags: ListRefsFlags)
        -> Result<Vec<(String, Checksum)>>;

    pub async fn load_commit(&self, c: &Checksum) -> Result<(Commit, CommitState)>;
    pub async fn load_dirtree(&self, c: &Checksum) -> Result<DirTree>;
    pub async fn load_dirmeta(&self, c: &Checksum) -> Result<DirMeta>;
    pub async fn load_variant(&self, ty: ObjectType, c: &Checksum) -> Result<Variant>;
    pub async fn has_object(&self, obj: &ObjectName) -> Result<bool>;

    /// Open a committed file's metadata plus an async content reader.
    pub async fn load_file(&self, c: &Checksum) -> Result<FileObject>;

    /// A traversable, read-only view of a commit's root tree.
    pub async fn read_commit(&self, rev: &str) -> Result<(RepoTree, Checksum)>;

    // --- detached metadata / signing (see Signing) ---
    pub async fn read_commit_detached_metadata(&self, c: &Checksum) -> Result<Option<Variant>>;
    pub async fn write_commit_detached_metadata(&self, c: &Checksum, meta: Option<&Variant>) -> Result<()>;

    // --- transactions ---
    pub async fn transaction(&self) -> Result<Transaction>;
    pub async fn transaction_with_lock(&self, lock: LockKind) -> Result<Transaction>;

    // --- checkout ---
    pub async fn checkout(&self, opts: &CheckoutOptions,
        dest_dir: BorrowedFd<'_>, dest_path: &Path, commit: &Checksum) -> Result<()>;

    // --- immediate ref writes (outside a transaction) ---
    pub async fn set_ref_immediate(&self, refspec: &str, checksum: Option<&Checksum>) -> Result<()>;

    // --- maintenance ---
    pub async fn prune(&self, opts: &PruneOptions) -> Result<PruneStats>;
    pub async fn fsck(&self, opts: &FsckOptions) -> Result<FsckReport>;
    pub async fn traverse_commit(&self, c: &Checksum, depth: i32)
        -> Result<HashSet<ObjectName>>;
    pub async fn regenerate_summary(&self, signers: &[&dyn Signer]) -> Result<()>;
}
```

## Commit / tree value types

```rust
pub struct Commit {
    pub metadata: Variant,                 // a{sv}
    pub parent: Option<Checksum>,
    pub related: Vec<(String, Vec<u8>)>,   // written empty; retained on parse
                                           // for byte-exact reserialization
    pub subject: String,
    pub body: String,
    pub timestamp: u64,                    // seconds UTC
    pub root_dirtree: Checksum,
    pub root_dirmeta: Checksum,
}
impl Commit {
    pub fn version(&self) -> Option<&str>;
    pub fn ref_bindings(&self) -> Vec<&str>;
    pub fn collection_binding(&self) -> Option<&str>;
    pub fn content_checksum(&self) -> Checksum;   // sha256(dirtree||dirmeta)
}

pub struct DirMeta { pub uid: u32, pub gid: u32, pub mode: u32, pub xattrs: Xattrs }

pub struct DirTree {
    pub files: Vec<(String, Checksum)>,           // name-sorted
    pub dirs:  Vec<(String, Checksum, Checksum)>, // name-sorted (dirtree, dirmeta)
}

pub enum CommitState { Normal, Partial, FsckPartial }

pub struct FileObject {
    pub uid: u32, pub gid: u32, pub mode: u32,
    pub xattrs: Xattrs,
    pub kind: FileKind,                    // Regular { size } | Symlink { target }
}
impl FileObject {
    /// Regular files: streams the payload in bounded chunks.
    pub async fn reader(&self) -> Result<ContentReader>;
}

/// Streaming reader over a regular file's payload: raw for the bare family,
/// on-the-fly raw-DEFLATE inflate for archive (a streaming decoder over
/// bounded chunks), empty for symlinks. Streams from `rt::File`. Implements
/// `futures_io::AsyncRead` unconditionally and `tokio::io::AsyncRead` under
/// the `tokio` feature, so neither backend needs a caller-side adapter.
pub struct ContentReader { /* empty | rt::File | inflate adapter */ }
```

## Runtime backend and streaming I/O

The runtime backend is feature-gated behind the internal `ostrya-rt` crate
(`smol` by default, `tokio` optional; policy in `port-plan.md`, "Async
model"). It is the only crate that knows which backend is compiled.

```rust
// ostrya-rt -- the whole surface at this phase.
pub async fn unblock<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static) -> T;   // the only pool entry

pub fn block_on<F: Future>(future: F) -> F::Output; // test/doctest driver

/// Async file over an already-open fd (`smol::fs::File` or
/// `tokio::fs::File` underneath). Opens happen through rustix (fd-relative
/// `openat`); this type only streams. Presents the `futures-io` traits
/// under both backends; the tokio traits additionally under the `tokio`
/// feature.
pub struct File;    // From<std::fs::File> / From<OwnedFd>;
                    // AsyncRead + AsyncWrite + AsyncSeek + Send + Sync
impl File {
    pub async fn sync_all(&mut self) -> std::io::Result<()>;
    pub async fn sync_data(&mut self) -> std::io::Result<()>;
    pub async fn into_std(self) -> std::fs::File;   // settles pipelined ops
}

pub struct Timer;   // lands with Phase 6 (lock retry); spawn/net with pull
```

The hashing streams live in `ostrya` and are generic over the inner stream,
so they compose with `rt::File`, `ContentReader`, and network streams. Each
implements the `futures-io` trait its inner type provides, plus the tokio
counterpart under the `tokio` feature.

```rust
/// Feeds a SHA-256 digester with every byte it passes through. ostree hashes
/// with SHA-256 throughout, so the digester is fixed. It arrives by value and
/// may be pre-seeded: a file object id covers the framed file header before
/// the payload.
pub struct HashingReader<R> { /* Sha256, count, inner */ }
impl<R> HashingReader<R> {
    pub fn new(hasher: Sha256, inner: R) -> Self;   // hasher may be pre-seeded
    pub fn size(&self) -> u64;                   // bytes seen so far
    pub fn finalize(self) -> (Checksum, u64);    // digest + size, at EOF
}

/// Symmetric writer: hashes what it forwards; `finalize` after flush.
pub struct HashingWriter<W> { /* Sha256, count, inner */ }

/// Passes bytes through and checks an expected digest at EOF: the final
/// read fails with `std::io::ErrorKind::InvalidData` on a mismatch, and so
/// does every read after it. The check fires only when the consumer polls
/// through to EOF; an empty-buffer read neither observes bytes nor latches
/// EOF.
pub struct VerifyingReader<R> { /* expected Checksum over a HashingReader */ }
impl<R> VerifyingReader<R> {
    pub fn new(expected: Checksum, hasher: Sha256, inner: R) -> Self;
    pub fn expected(&self) -> &Checksum;
    pub fn size(&self) -> u64;
}
```

`ContentWriter` (see Transactions) stages content through a `HashingWriter`
over the staging `rt::File`; pull wraps fetched payloads in
`VerifyingReader`.

## Borrowed object views (read path)

Views decode a serialized metadata object in place, borrowing the loaded
object buffer (the Phase 1a typed codec; see `port-plan.md`). `parse`
validates the container framing; array iteration decodes lazily from the
framing offsets and yields borrowed slices, so a full dirtree walk performs
no heap allocation. Entry-level checks (checksum length, name sort order)
run as entries are visited, which is why the iterators yield `Result`.
`Checksum` values are yielded by copy; a 32-byte copy involves no heap.

```rust
pub struct DirTreeRef<'a>(/* &'a [u8] */);
impl<'a> DirTreeRef<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self>;
    pub fn files(&self) -> impl Iterator<Item = Result<(&'a str, Checksum)>>;
    pub fn dirs(&self) -> impl Iterator<Item = Result<(&'a str, Checksum, Checksum)>>;
    pub fn to_owned(&self) -> Result<DirTree>;
}

pub struct DirMetaRef<'a>(/* &'a [u8] */);
impl<'a> DirMetaRef<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self>;
    pub fn uid(&self) -> u32;                    // big-endian decoded
    pub fn gid(&self) -> u32;
    pub fn mode(&self) -> u32;
    pub fn xattrs(&self) -> XattrsRef<'a>;
    pub fn to_owned(&self) -> Result<DirMeta>;
}

pub struct XattrsRef<'a>(/* &'a [u8] */);
impl<'a> XattrsRef<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self>;
    pub fn iter(&self) -> impl Iterator<Item = Result<(&'a [u8], &'a [u8])>>;
    pub fn to_owned(&self) -> Result<Xattrs>;
}

impl Repo {
    /// Serialized bytes of a metadata object; views borrow this buffer.
    pub async fn load_object_bytes(&self, ty: ObjectType, c: &Checksum)
        -> Result<Vec<u8>>;
}
```

The owned `DirTree` and `DirMeta` values returned by `load_dirtree` and
`load_dirmeta` are built through `to_owned`. Callers that only traverse --
checkout, pull object scanning, `RepoTree::read_dir` -- hold the object
buffer and iterate the view. `Commit` has no view type: commit objects are
read a handful at a time and their fields are retained.

## RepoTree traversal (read-only GFile analogue)

```rust
pub struct RepoTree { /* repo handle + dirtree/dirmeta checksums, lazy */ }
impl RepoTree {
    pub async fn lookup(&self, path: &Path) -> Result<Option<TreeEntry>>;
    pub async fn read_dir(&self) -> Result<Vec<TreeEntry>>;  // files then dirs, name-sorted
    pub fn dirtree_checksum(&self) -> &Checksum;
    pub fn dirmeta_checksum(&self) -> &Checksum;
}
pub enum TreeEntry {
    File { name: String, checksum: Checksum },
    Dir  { name: String, tree: RepoTree },
}
```

## Transactions (the concurrency-critical handle)

```rust
/// Owns its own staging dir, object-size map, devino cache, ref queue, and
/// free-space counter. Multiple Transactions may exist concurrently in one
/// process. `&Transaction` is Send+Sync: concurrent writers are allowed.
/// Drop aborts if not committed.
pub struct Transaction { /* Repo clone + owned staging state */ }

impl Transaction {
    // object writers (return the computed checksum)
    /// Push-style ingestion: a writer that streams one payload into the
    /// transaction's staging area, hashing (and, in archive mode,
    /// compressing) on the way down.
    pub async fn content_writer(&self, expected: Option<&Checksum>,
        meta: &FileMeta) -> Result<ContentWriter>;
    /// Pull-style convenience over `content_writer`.
    pub async fn write_content(&self, expected: Option<&Checksum>,
        meta: &FileMeta, reader: impl AsyncRead + Send) -> Result<Checksum>;
    /// Small content the caller already holds; the general path is
    /// `write_content`, which streams.
    pub async fn write_regfile_inline(&self, expected: Option<&Checksum>,
        meta: &FileMeta, data: &[u8]) -> Result<Checksum>;
    pub async fn write_symlink(&self, target: &str, meta: &FileMeta) -> Result<Checksum>;
    pub async fn write_metadata(&self, ty: ObjectType, expected: Option<&Checksum>,
        variant: &Variant) -> Result<Checksum>;

    // tree building
    pub async fn write_dfd_to_mtree(&self, dfd: BorrowedFd<'_>, path: &Path,
        mtree: &mut MutableTree, modifier: Option<&mut CommitModifier>) -> Result<()>;
    /// Port extension: merge an overlayfs upperdir changeset into an mtree
    /// holding the overlay's lower layer (see "Staging tree, tree merge,
    /// and overlay import").
    pub async fn merge_overlay_dfd_to_mtree(&self, dfd: BorrowedFd<'_>,
        mtree: &mut MutableTree, modifier: Option<&mut CommitModifier>) -> Result<()>;
    pub async fn write_mtree(&self, mtree: &mut MutableTree) -> Result<RepoTree>;

    // path-addressed construction (port extension; see "Staging tree,
    // tree merge, and overlay import"). staging_tree is async: hydrating
    // from a commit reads its root dirtree.
    pub async fn staging_tree(&self, source: Option<&Commit>)
        -> Result<StagingTree<'_>>;
    pub fn staging_tree_from_mutable_tree(&self, source: MutableTree)
        -> StagingTree<'_>;

    // commit
    pub async fn write_commit(&self, opts: CommitOptions, root: &RepoTree) -> Result<Checksum>;

    // ref queue (applied atomically at commit)
    pub fn set_ref(&self, refspec: &str, checksum: Option<&Checksum>);
    pub fn set_collection_ref(&self, r: &CollectionRef, checksum: Option<&Checksum>);

    pub async fn commit(self) -> Result<TransactionStats>;
    pub async fn abort(self) -> Result<()>;
}

/// Streams one regular file's payload into a transaction. Implements
/// `futures_io::AsyncWrite` unconditionally and `tokio::io::AsyncWrite`
/// under the `tokio` feature. `finish` finalizes the digest, applies the
/// per-mode object metadata, and stages the object under its id (a dedup
/// hit returns the existing id). Dropping without `finish` abandons the
/// staged temporary, which the transaction reaps.
pub struct ContentWriter { /* HashingWriter over a staging rt::File */ }
impl ContentWriter {
    pub async fn finish(self) -> Result<Checksum>;
}

pub struct CommitOptions {
    pub parent: Option<Checksum>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub timestamp: Option<u64>,      // else SOURCE_DATE_EPOCH or now
    pub metadata: Option<Variant>,   // a{sv}; ostree.sizes auto-added
}

pub enum LockKind { Shared, Exclusive }
pub struct TransactionStats { pub metadata_written: u32, pub content_written: u32,
    pub content_bytes_written: u64, pub devino_cache_hits: u32 /* ... */ }
```

## Mutable tree and commit modifier

```rust
pub struct MutableTree { /* in-memory tree under construction */ }
impl MutableTree {
    pub fn new() -> Self;
    pub async fn from_commit(repo: &Repo, rev: &str) -> Result<Self>;
    // async: descending into a lazily-loaded committed subdirectory reads its
    // dirtree, so the hydrating descent is offloaded through the blocking pool.
    pub async fn ensure_dir(&mut self, name: &str) -> Result<&mut MutableTree>;
    pub fn replace_file(&mut self, name: &str, checksum: Checksum) -> Result<()>;
    pub fn set_metadata_checksum(&mut self, c: Checksum);
    pub fn remove(&mut self, name: &str, allow_noent: bool) -> Result<()>;
}

bitflags! { pub struct CommitModifierFlags: u32 {
    const SKIP_XATTRS; const GENERATE_SIZES; const CANONICAL_PERMISSIONS;
    const ERROR_ON_UNLABELED; const CONSUME; const DEVINO_CANONICAL;
    const SELINUX_LABEL_V1;
}}

pub enum FilterResult { Allow, Skip }

// The walk takes the modifier as `Option<&mut CommitModifier>`: the FnMut
// callbacks run through the exclusive borrow, and the Send bound on each
// box keeps the walk future Send.
pub struct CommitModifier {
    pub flags: CommitModifierFlags,
    pub filter: Option<Box<dyn FnMut(&Path, &FileMeta) -> FilterResult + Send>>,
    pub xattr_callback: Option<Box<dyn FnMut(&Path, &FileMeta) -> Xattrs + Send>>,
    pub label_callback: Option<Box<dyn FnMut(&Path, &FileMeta) -> Option<Vec<u8>> + Send>>,
    pub devino_cache: Option<DevInoCache>,
}
```

## Staging tree, tree merge, and overlay import (port extensions)

Tree-composition surfaces with no counterpart in the C API. They add no
on-disk state: everything they stage flows through the object writers and
ordinary trees, and the resulting commits are ordinary commits. Their
gates are self-consistency against the ingest path (`port-plan.md`,
Phases 7e and 7f).

`Transaction::merge_overlay_dfd_to_mtree` (see Transactions) merges an
overlayfs upperdir changeset into an mtree holding the overlay's lower
layer. `dfd` is the upperdir root; the overlay is expected to be
unmounted, which is not checked. Char 0:0 whiteout devices delete the
corresponding mtree path. Directories carrying `trusted.overlay.opaque`
or `user.overlay.opaque` clear the mtree subtree before fresh ingest;
both xattr namespaces are honored (rootless `userxattr` overlays write
`user.*`). Merged directories take dirmeta from the upper inode.
`overlay.*` xattrs are stripped from ingested entries. Entries carrying
`overlay.metacopy` or `overlay.redirect` are errors naming the feature,
since such entries are not self-contained. An upper directory over an
mtree symlink is a malformed-changeset error: the VFS resolves symlinks
at lookup, so a genuine upperdir never contains one relative to its
base. The modifier callbacks see real entries only, never whiteouts or
opaque markers; a filter `Skip` on an upper entry leaves the base
version in place.

```rust
/// Path-addressed construction over a transaction. Borrowing the
/// transaction makes close -> write_mtree -> commit the only ordering
/// that compiles. `&StagingTree` is Send + Sync (the tree sits behind a
/// sync mutex held only across map operations); file writes may run
/// concurrently.
pub struct StagingTree<'txn> { /* &'txn Transaction, Mutex<MutableTree>, writer count */ }

impl StagingTree<'_> {
    /// Hands the tree to write_mtree; fails while write_file writers
    /// are outstanding.
    pub fn close(self) -> Result<MutableTree>;

    pub async fn merge(&self, other: &MutableTree, opts: MergeOptions) -> Result<()>;

    pub async fn write_file(&self, path: &Path, meta: &FileMeta)
        -> Result<StagedFileWriter<'_>>;
    pub async fn write_file_content(&self, path: &Path, meta: &FileMeta,
        content: &[u8]) -> Result<()>;
    pub async fn make_dir(&self, path: &Path, meta: &DirMeta) -> Result<()>;
    pub async fn make_dir_all(&self, path: &Path, meta: &DirMeta) -> Result<()>;
    pub async fn symlink(&self, path: &Path, target: &Path, meta: &FileMeta)
        -> Result<()>;
    /// A second tree entry for the content object found at `target`;
    /// the object carries all metadata, so none is taken.
    pub async fn hardlink(&self, path: &Path, target: &Path) -> Result<()>;

    /// Path resolution against the staged tree; objects load from the
    /// transaction's staged set first, then from `objects/`.
    pub async fn read_file(&self, path: &Path, follow_symlinks: bool)
        -> Result<FileObject>;
    pub async fn read_dir(&self, path: &Path, follow_symlinks: bool)
        -> Result<Vec<StagingEntry>>;
}

/// finish() completes the content object and records it at the path.
pub struct StagedFileWriter<'a> { /* ContentWriter + path + tree handle */ }
impl StagedFileWriter<'_> { pub async fn finish(self) -> Result<()>; }

pub enum StagingEntry {
    File { name: String, checksum: Checksum },
    Dir  { name: String },                     // no checksum until written
}

#[derive(Default)]
pub struct MergeOptions { pub allow_overwrite: bool, pub follow_symlinks: bool }
```

Merge rules: entries with equal checksums merge silently; differing
files, file-versus-directory conflicts, and dirmeta on directories
present on both sides are errors without `allow_overwrite` and taken
from the right side with it (a right-side file replacing a whole
left-side subtree when it overwrites a directory). With
`follow_symlinks`, a right-side directory at a name where the left tree
has a symlink merges into the symlink's target directory; right-side
files and symlinks replace the left entry under the overwrite rule and
never write through, so a file arriving over
`etc/localtime -> /usr/share/zoneinfo/UTC` replaces the symlink and
leaves the zoneinfo object untouched. Resolution walks the left tree at
every level of the descent: relative targets resolve from the symlink's
parent, absolute targets from the tree root, `..` clamps at the root,
chains are capped at depth 40, and a dangling target is an error naming
the symlink and the missing target. Merge lives on `StagingTree` rather
than `MutableTree` because resolution loads symlink content objects, and
only transaction scope sees objects staged in the current transaction.

Path semantics for the write operations: intermediate components resolve
through symlinks with the same walker; the final component never
follows. `write_file` and `write_file_content` replace an existing file
or symlink entry and fail on a directory; `make_dir`, `symlink`, and
`hardlink` fail on any existing entry; `make_dir_all` applies its
`DirMeta` to the directories it creates and leaves existing ones
untouched.

## Checkout options

```rust
pub enum CheckoutMode { None, User }
pub enum OverwriteMode { None, UnionFiles, AddFiles, UnionIdentical }

pub struct CheckoutOptions {
    pub mode: CheckoutMode,
    pub overwrite: OverwriteMode,
    pub subpath: Option<PathBuf>,
    pub enable_fsync: bool,          // default false, matching the tool
    pub force_copy: bool,
    pub process_whiteouts: bool,
    pub devino_cache: Option<DevInoCache>,
    pub filter: Option<Box<dyn FnMut(&Path, &FileMeta) -> FilterResult>>,
}
```

## Signing

```rust
pub trait Signer {
    fn name(&self) -> &str;                       // "ed25519", "spki", "gpg", "dummy"
    fn metadata_key(&self) -> &str;               // e.g. "ostree.sign.ed25519"
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}
pub trait Verifier {
    fn metadata_key(&self) -> &str;
    async fn verify(&self, data: &[u8], signatures: &[Vec<u8>]) -> Result<VerifyOutcome>;
}

pub struct Ed25519Signer { /* 64-byte secret */ }
pub struct Ed25519Verifier { /* trusted + revoked 32-byte keys */ }
pub struct GpgSigner { /* key id/fingerprint + optional GNUPGHOME; signs via gpg */ }
pub struct GpgVerifier { /* binary keyring blobs; verifies via gpgv */ }
pub struct SpkiSigner;   pub struct SpkiVerifier;    // optional
pub struct DummySigner;  pub struct DummyVerifier;   // test-only

pub struct VerifyOutcome { pub valid: bool, pub signatures: Vec<SignatureInfo> }
pub struct SignatureInfo {
    pub valid: bool,
    pub fingerprint: Option<String>, pub primary_fingerprint: Option<String>,
    pub created: Option<u64>, pub expires: Option<u64>, pub key_expires: Option<u64>,
    pub expired: bool, pub revoked: bool, pub key_missing: bool,
    pub pubkey_algorithm: Option<String>, pub hash_algorithm: Option<String>,
    pub user_name: Option<String>, pub user_email: Option<String>,
    // mirrors the documented GPG verify result fields
}

impl Repo {
    pub async fn sign_commit(&self, c: &Checksum, signer: &dyn Signer) -> Result<()>;
    pub async fn verify_commit(&self, c: &Checksum, verifiers: &[&dyn Verifier])
        -> Result<VerifyOutcome>;
}
```

Key loading helpers (ed25519 base64-per-line files and the
`trusted.ed25519[.d]` / `revoked.ed25519[.d]` directory convention; GPG keyring
files binary and armored) are free functions or `impl` on the concrete signer
types.

## Fetcher

The HTTP client pull is built on. One `Fetcher` serves one remote: it holds the
mirrors, headers, credentials, and TLS configuration, pools connections per
origin, and admits a bounded number of requests at a time in priority order.
Protocol selection is the TLS handshake's -- ALPN offers `h2` and `http/1.1`.
Two deadlines bound one attempt's cost: `connect_timeout` over opening a
connection, and `progress_timeout` over a response delivering bytes, restarted
whenever bytes arrive. A body that stalls fails the read with
`io::ErrorKind::TimedOut`. `fetch_timeout` bounds the mirror rounds and the
retries together, from admission to the response head, which is what caps how
long one fetch holds an admission permit. A credential is sent to every mirror,
so `basic_auth` and an `Authorization`, `Proxy-Authorization`, or `Cookie` entry
in `headers` require every mirror to be `https`; a cleartext mirror alongside one
fails `Fetcher::new`.

```rust
pub struct FetcherOptions {
    pub mirrors: Vec<String>,             // base URLs, tried in order; a query
                                          // string or userinfo is rejected
    pub headers: Vec<(String, String)>,   // an Authorization, Proxy-Authorization,
                                          // or Cookie entry needs https mirrors
    pub basic_auth: Option<BasicAuth>,    // needs https mirrors
    pub tls: TlsOptions,                  // trust roots, client identity
    pub http2: bool,                      // default true
    pub max_retries: u32,                 // default 5
    pub max_outstanding: usize,           // default 8
    pub connect_timeout: Duration,        // default 30s: connect + TLS + handshake
    pub progress_timeout: Duration,       // default 60s: silence, not transfer time
    pub fetch_timeout: Option<Duration>,  // default 300s: mirrors and retries
                                          // together, up to the response head
}

pub enum TrustRoots { System, Pem(Vec<u8>) }
pub struct ClientIdentity { pub cert_chain_pem: Vec<u8>, pub key_pem: Vec<u8> }
pub struct TlsOptions { pub roots: TrustRoots, pub client_identity: Option<ClientIdentity> }

pub enum Priority { Low, Normal, High }
pub enum Protocol { Http11, Http2 }

/// The server's own validator strings, replayed to make a fetch conditional.
pub struct Validators { pub etag: Option<String>, pub last_modified: Option<String> }

pub struct FetchRequest<'a> {
    pub path: &'a str,                    // relative to each mirror, appended
                                          // as written; no query, no fragment
    pub priority: Priority,
    pub validators: Option<&'a Validators>,
    pub max_size: Option<u64>,
}

pub enum Fetched { Body(Body), NotModified }

/// A streaming response body; implements `futures-io` `AsyncRead` (and the
/// tokio trait under the `tokio` feature). Reaching the end of the body
/// releases the connection and the concurrency permit, and so does dropping
/// it. Outgrowing `max_size` fails the read with
/// `std::io::ErrorKind::FileTooLarge`, and every read after it replays that
/// error.
pub struct Body { /* ... */ }
impl Body {
    pub fn validators(&self) -> &Validators;
    pub fn content_length(&self) -> Option<u64>;
    pub fn protocol(&self) -> Protocol;
    pub fn received(&self) -> u64;        // bytes off the connection, which
                                          // leads the caller by up to a chunk
}

impl Fetcher {
    // Async: TrustRoots::System, the default, reads the host trust store on
    // the blocking pool, whatever the mirrors' scheme. A store holding no
    // certificate fails only when a mirror is https. Clone, Send + Sync.
    pub async fn new(options: FetcherOptions) -> Result<Fetcher>;
    pub async fn fetch(&self, request: FetchRequest<'_>) -> Result<Fetched>;
}
```

## Pull

`pull_local` copies refs, the commits they name, and every object those commits
reach out of another local repository, in one transaction. An object stored the
same way in both repositories, inode included, is hardlinked; a metadata object
whose link is refused falls back to a `FICLONE` reflink and then a byte copy. A
regular file whose payload bytes the two modes share and whose inode metadata
they do not -- any pair within the bare family -- has its payload cloned and the
destination's inode policy applied from the object's logical header, which is
also where a content object whose link was refused goes. What crosses the archive
boundary is read back into its logical form and written afresh through the
ordinary ingest path. What an import shares -- a hardlinked inode, a reflinked
payload -- allocates no blocks and is not charged against the `min-free-space`
budget, so such a pull needs no room for a second copy of those objects;
`content_bytes_written` counts their stored size all the same. The three
`PullStats` counters cover the objects the pull staged, so an object the
destination already held is absent from each and a `COMMIT_ONLY` pull reports its
commit objects alone. Objects are
sourced from `src` first and then each of
`localcache_repos` in order, and the walk that decides what to import resolves
each commit and dirtree through the same order, so a subtree `src` has lost is
enumerated from a cache that holds it. Refs are written after the objects are
published.

`pull` fetches the same thing from an HTTP remote named in the repository's
config, into one transaction, with up to `max_outstanding_fetches` objects in
flight. The plan is drained commits first, then the dirtree and dirmeta objects
the scan is blocked on, then the content, and each class carries the matching
fetch priority. A commit object is fetched before the objects it references and
staged where it arrives, checked there against the name it was requested by; a
commit whose tree is not yet complete is covered by its `.commitpartial` marker,
which is removed after the transaction publishes. Three write permits bound how
many fetched payloads stream into the
object store at once; a permit is taken before the response body is read, which
keeps a waiting step off the fetcher's progress clock. Every fetched object is
stored under the name it was requested by and the write path compares what it
hashed against that name, so an HTTP pull verifies whatever the flags say.
`localcache_repos` are consulted before the network, per object.

Each requested ref resolves against the remote's summary first and then
`refs/heads/<ref>`, the name percent-encoded where it becomes that path. An empty
ref list takes every summary ref under `MIRROR` and the remote's configured
`branches` otherwise. Whichever of the three a name comes from, it is held to the
ref store's rule -- no empty, `.`, or `..` component -- before any object is
requested. Refs are written under
`refs/remotes/<remote>/<ref>`, or as local refs under `MIRROR`, which also copies
the remote's `summary` and `summary.sig` bytes to this repository when the pull
took every ref.

Still remote-only and unimplemented: `subdirs`, the static-delta switches,
`override_commit_ids`, `gpg_verify`, `sign_verifiers`, and a progress callback.

```rust
pub struct PullFlags(u32);                // a bitset, as CommitModifierFlags is
impl PullFlags {
    pub const NONE: PullFlags;
    pub const UNTRUSTED: PullFlags;       // verify every imported object
    pub const COMMIT_ONLY: PullFlags;     // commit objects only; stays partial
    pub const BAREUSERONLY_FILES: PullFlags;      // reject modes outside 0775
    pub const DISABLE_VERIFY_BINDINGS: PullFlags; // skip the ref-binding check
    pub const FORCE_COPY: PullFlags;      // never hardlink
    pub const MIRROR: PullFlags;          // local refs; every summary ref
    pub const fn empty() -> PullFlags;
    pub const fn contains(self, other: PullFlags) -> bool;
    pub const fn bits(self) -> u32;
}

/// What a fetched tip's timestamp must be no older than. The comparison is
/// strict: an equal timestamp passes.
#[derive(Default)]
pub enum TimestampCheck {
    #[default] Off,
    CurrentRef,                           // the commit the ref names here
    Rev(Checksum),                        // a given commit
}

#[derive(Default)]
pub struct PullOptions {
    pub refs: Vec<String>,                // empty: every ref under refs/heads,
                                          // or the summary / `branches` remotely
    pub remote: Option<String>,           // refs/remotes/<remote>/<ref>
    pub flags: PullFlags,
    pub depth: i32,                       // 0 = the commit alone, -1 = all
    pub localcache_repos: Vec<Repo>,
    // The rest are the HTTP pull's; each defaults to what a local pull does.
    pub url: Option<String>,              // overrides the remote's configured url
    pub http_headers: Vec<(String, String)>,
    pub max_outstanding_fetches: Option<usize>,  // None is 8
    pub n_network_retries: Option<u32>,          // None is 5
    pub timestamp_check: TimestampCheck,
}

pub struct PullStats {
    pub metadata_imported: u32,
    pub content_imported: u32,
    pub content_bytes_written: u64,
}

/// The read side of a `summary` file: the ref list a pull resolves against, and
/// the global metadata dict verbatim.
pub struct Summary { pub refs: Vec<(String, Checksum)>, pub metadata: Value }
impl Summary {
    pub fn parse(bytes: &[u8]) -> Result<Summary>;
    pub fn lookup(&self, ref_name: &str) -> Option<Checksum>;
}

impl Repo {
    pub async fn pull_local(&self, src: &Repo, opts: PullOptions)
        -> Result<PullStats>;
    pub async fn pull(&self, remote: &str, opts: PullOptions)
        -> Result<PullStats>;
    /// The remote's `summary` and `summary.sig` bytes, an absent one as None.
    pub async fn remote_fetch_summary(&self, remote: &str)
        -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)>;
}
```

## Static deltas

```rust
pub struct DeltaGenerateOptions {
    pub max_chunk_size_mb: u32,           // default 32
    pub max_bsdiff_size_mb: u32,          // default 128
    pub min_fallback_size_mb: u32,        // default 4
    pub bsdiff_enabled: bool,
    pub inline_parts: bool,
    pub signers: Vec<Box<dyn Signer>>,
}
impl Repo {
    pub async fn static_delta_generate(&self, from: Option<&Checksum>, to: &Checksum,
        opts: DeltaGenerateOptions) -> Result<()>;
    pub async fn static_delta_execute_offline(&self, delta_dir: BorrowedFd<'_>,
        skip_validation: bool) -> Result<()>;
    pub async fn list_static_delta_names(&self) -> Result<Vec<String>>;
}
```

## Tar (always compiled) and composefs (feature-gated)

```rust
// Tar is always compiled (built on smol-tar), not feature-gated.
impl Repo {
    pub async fn export_tar(&self, commit: &Checksum, opts: TarExportOptions,
        out: impl AsyncWrite) -> Result<()>;
    pub async fn import_tar(&self, txn: &Transaction, opts: TarImportOptions,
        input: impl AsyncRead) -> Result<MutableTree>;
}

#[cfg(feature = "composefs")]
impl Repo {
    /// Produce the EROFS/composefs image for a commit and its fs-verity digest.
    /// Inode metadata always comes from the real file attributes (no canonical
    /// mode); in bare-user-shared mode metadata comes from `user.ostreemeta`
    /// and each regular file redirects to its `.file` loose path. Ownership is
    /// presented via composefs uid mapping at mount.
    pub async fn export_composefs(&self, commit: &Checksum, out: BorrowedFd<'_>)
        -> Result<[u8; 32]>;
    /// Compute and store `ostree.composefs.digest.v0` in the commit's metadata.
    pub async fn commit_add_composefs_metadata(&self, txn: &Transaction,
        commit: &Checksum) -> Result<Checksum>;
}
```

## Notes on divergence from the C API

- No `GCancellable`: cancel by dropping the future or racing a cancel signal.
- No out-parameters: results come back in `Result<T>`.
- No `glib::Variant` options dicts on the public surface: builders and structs.
  A `Variant` type still exists internally for on-disk metadata and is exposed
  where commit metadata genuinely is an arbitrary `a{sv}`.
- No raw `dfd: i32`: `BorrowedFd`/`OwnedFd`.
- The large `Repo` god-object is split: `Repo` for lifecycle/read/checkout/
  maintenance, `Transaction` for all writes, and `Signer`/`Verifier`/`Progress`
  traits for pluggable behavior.
- RAII guards from the bindings that are worth keeping: transaction auto-abort
  on drop, lock guards, and a typed `Checksum`.
