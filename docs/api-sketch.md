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
    pub fn from_hex(s: &str) -> Result<Self>;       // either case
    pub fn from_hex_lower(s: &str) -> Result<Self>; // the rule a revision takes
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

/// The path of a loose object relative to the repository's `objects/`
/// directory, `<first 2 hex>/<remaining 62 hex>.<ext>`. `ostrya` re-exports it,
/// so a consumer addressing an object on disk needs no dependency on
/// `ostrya-core`.
pub fn loose_path(checksum: &Checksum, ty: ObjectType, mode: RepoMode) -> String;

pub struct CollectionRef { pub collection_id: Option<String>, pub ref_name: String }

/// Sorted xattr set, canonicalized on construction.
pub struct Xattrs(Vec<(Vec<u8>, Vec<u8>)>);

pub type Result<T> = std::result::Result<T, Error>;

#[non_exhaustive]
pub enum Error {
    Io(std::io::Error),
    Core(ostrya_core::Error),          // the format-primitive layer
    ObjectNotFound { checksum: Checksum, ty: ObjectType },
    RefNotFound(String),
    InvalidRefspec(String),
    NoParentCommit(Checksum),
    InvalidFormat(String),
    Unsupported(String),
    LockTimeout { secs: i64 },
    ChecksumMismatch { expected: Checksum, actual: Checksum },
    InsufficientFreeSpace { shortfall: u64 },
    Signature(String),
    // The path-resolution conditions, each naming the path it refused. A
    // consumer branches on the variant; `Staging` carries the residue.
    PathNotFound { path: String },
    NotADirectory { path: String },
    DanglingSymlink { path: String, target: String },
    SymlinkLoop { path: String },
    EntryExists { path: String },
    Staging(String),
    MergeConflict(String),
    // ... one variant per class of refusal the library reports
}

/// Map an error onto the closest `std::io::ErrorKind`, keeping the error as
/// the payload so its `Display` and its source chain survive.
impl From<Error> for std::io::Error;
```

The `io::ErrorKind` an error converts to:

- `NotFound`: `PathNotFound`, `DanglingSymlink`, `ObjectNotFound`,
  `RefNotFound`.
- `NotADirectory`: `NotADirectory`, `ReplaceFileWithDir`.
- `AlreadyExists`: `EntryExists`, `MergeConflict`, `ReplaceDirWithFile`.
- `InvalidInput`: `MutableTree`.
- The inner error itself: `Io`.
- `Other`: everything else, `SymlinkLoop` included, since
  `ErrorKind::FilesystemLoop` is unstable.

## GVariant types and values (`ostrya-gvariant`)

`ostrya_gvariant::Variant<'a>` is the typed codec view over one serialized
metadata object, borrowing the buffer it decodes.
`ostrya-gvariant` also carries a dynamic pair, `Type` and `Value`, which
serves `a{sv}` metadata a caller supplies and the reading commands print.
`ostrya` re-exports `Type` and `Value` and takes them on its own surface;
`Variant` stays inside the codec.

`Type` names every character of the GVariant type alphabet. `Value` names
every representation those characters take, with four canonicalizations: a
byte array (`ay`) is `Bytes`, a dict entry is a two-element `Tuple`, an object
path (`o`) and a signature (`g`) are `Str`, and a handle (`h`) is `I32`. The
`Type` a value is paired with states which member of a folded pair the value
carries.

```rust
pub enum Type {
    Bool, Byte, I16, U16, I32, U32, I64, U64, Handle, Double,
    Str, ObjectPath, Signature, Variant,
    Maybe(Box<Type>), Array(Box<Type>), Tuple(Vec<Type>),
    DictEntry(Box<Type>, Box<Type>),
}
impl Type {
    pub fn parse(signature: &str) -> Result<Type>;
    pub fn signature(&self) -> String;
    /// Whether this is a basic type: a scalar or a string, the types a dict
    /// entry accepts as its key.
    pub fn is_basic(&self) -> bool;
}

pub enum Value {
    Bool(bool), Byte(u8), I16(i16), U16(u16), I32(i32), U32(u32),
    I64(i64), U64(u64),
    /// The IEEE-754 bit pattern of a `d` value, so a value compares by the
    /// bytes it serializes to. Build one with `Value::double`.
    Double(u64),
    Str(String), Bytes(Vec<u8>),
    /// `m<T>`: the value it holds, or `None` for `nothing`.
    Maybe(Option<Box<Value>>),
    Array(Vec<Value>), Tuple(Vec<Value>), Variant(Box<(Type, Value)>),
}
impl Value {
    pub fn variant(ty: Type, value: Value) -> Value;
    pub fn double(value: f64) -> Value;
}
```

Neither enum is `#[non_exhaustive]`. Both enumerate a closed external
specification, so an exhaustive `match` stays valid and stays a compile-time
gate; `port-plan.md`, decision 14, records the rule.

### Building an `a{sv}`

`DictBuilder` assembles the dict a caller hands to `CommitOptions::metadata`
and to `write_commit_detached_metadata`. It appends, so the entries stand in
insertion order, which is the order the dict holds on disk and part of the
commit checksum (`format-reference.md`, "Commit"). A key inserted twice yields
two entries of that name.

```rust
pub struct DictBuilder { /* the entries so far */ }

impl DictBuilder {
    pub fn new() -> DictBuilder;
    /// Append `key` holding `value` of type `ty`, wrapped as the `v` the
    /// dict's value member carries.
    pub fn insert(&mut self, key: &str, ty: Type, value: Value) -> &mut Self;
    pub fn insert_str(&mut self, key: &str, value: &str) -> &mut Self;
    pub fn insert_u64(&mut self, key: &str, value: u64) -> &mut Self;
    pub fn insert_bool(&mut self, key: &str, value: bool) -> &mut Self;
    pub fn insert_strv(&mut self, key: &str, values: &[String]) -> &mut Self;
    pub fn insert_bytes(&mut self, key: &str, value: &[u8]) -> &mut Self;
    /// The assembled `a{sv}`, its entries in insertion order.
    pub fn build(self) -> Value;
}
```

`ostrya` re-exports `DictBuilder` alongside `Type` and `Value`.

### The bootable pair

A bootable commit holds `ostree.linux` and `ostree.bootable`, in that order at
the head of the dict (`format-reference.md`, "CLI output formats", `commit`).
The value of `ostree.linux` is the name of the one directory under
`/usr/lib/modules` in the commit's tree that holds an entry named `vmlinuz`.
`BootableRefusal` names the four tree shapes that give no such name; a consumer
words them itself.

`DictBuilder` holds the value model and no ostree key names, so the pair goes
in through an extension trait `ostrya` defines.

```rust
pub enum BootableRefusal {
    MissingComponent { path: String },
    NotADirectory { path: String },
    NoKernel,
    MultipleKernels,
}

pub trait BootableMetadata {
    /// Append `ostree.linux` holding `kernel_version`, then `ostree.bootable`
    /// holding true. The pair goes in where the builder has reached, so a
    /// caller reproducing the tool's dict inserts it first.
    fn insert_bootable(&mut self, kernel_version: &str) -> &mut Self;
}

impl BootableMetadata for DictBuilder { /* ... */ }
```

The version itself comes from `Transaction::kernel_version` over a staged tree
or `RepoTree::kernel_version` over a published one.

### The GVariant text form

The pair also converts to and from the GVariant text form, which is the form
the reading commands print and the form `--add-metadata` reads. The rules are
recorded in `format-reference.md`, "The GVariant text form".

```rust
/// Render `value` of type `ty`, annotating each literal that states no type of
/// its own. `Error::TypeMismatch` where `value` does not match `ty`.
pub fn to_text(ty: &Type, value: &Value) -> Result<String>;

/// The same rendering with every annotation left out, for a report whose
/// reader already knows the type.
pub fn to_text_unannotated(ty: &Type, value: &Value) -> Result<String>;

/// Read one text form, returning the type it states and the value.
pub fn from_text(text: &str) -> std::result::Result<(Type, Value), TextError>;

/// A half-open byte range of the input text, as a refusal reports it.
pub struct Span { pub start: usize, pub end: usize }

/// Why a text form was refused. `Display` renders `<spans>:<reason>`, with the
/// spans separated by commas. Two spans appear where the reason names a pair
/// that disagrees, such as the two elements a container cannot unify.
pub struct TextError { pub spans: Vec<Span>, pub reason: String }
```

`ostrya` re-exports `to_text`, `to_text_unannotated`, `from_text`, `Span`, and
`TextError` alongside `Type` and `Value`.

## Repo

```rust
#[derive(Clone)]
pub struct Repo { /* Arc<RepoInner> */ }

pub struct CreateOptions { pub mode: RepoMode, pub collection_id: Option<String> }

impl Repo {
    pub async fn open_at(dir: BorrowedFd<'_>, path: &Path) -> Result<Repo>;
    pub async fn open(path: &Path) -> Result<Repo>;
    pub async fn create_at(dir: BorrowedFd<'_>, path: &Path, opts: CreateOptions) -> Result<Repo>;

    pub fn mode(&self) -> RepoMode;
    pub fn config(&self) -> &RepoConfig;                   // parsed, read-only view

    /// Replace `config` with the document a caller edited through `KeyFile`'s
    /// setters and removers: a temporary file at mode 0644, `fdatasync`ed when
    /// `[core] fsync` is set, renamed over the target, with the repository
    /// directory synced. This handle keeps the configuration it was opened with.
    pub async fn write_config(&self, keyfile: &KeyFile) -> Result<()>;
    /// Remove a remote's trusted keyring, `<remote>.trustedkeys.gpg`. An
    /// already-absent keyring is success.
    pub async fn remove_remote_keyring(&self, remote: &str) -> Result<()>;

    // --- reading ---
    /// A refspec, a 64-char lowercase checksum, an abbreviated checksum -- a
    /// shorter run of lowercase hex naming the one commit whose checksum
    /// starts with it -- or any of those with a trailing run of `^`, each
    /// stepping one generation back along `parent`. A 64-char name holding
    /// an uppercase character is a refspec.
    pub async fn resolve_rev(&self, rev: &str, allow_noent: bool)
        -> Result<Option<Checksum>>;
    /// The ref store alone, for a caller holding a ref name rather than a
    /// revision: no checksum syntax and no ancestry suffix.
    pub async fn resolve_ref_tip(&self, refspec: &str) -> Result<Option<Checksum>>;
    pub async fn list_refs(&self, prefix: Option<&str>)            // refs/heads
        -> Result<Vec<(String, Checksum)>>;
    /// refs/remotes, each named by its `remote:name` refspec.
    pub async fn list_remote_refs(&self) -> Result<Vec<(String, Checksum)>>;
    /// refs/mirrors, as (collection_id, ref_name, commit).
    pub async fn list_mirror_refs(&self) -> Result<Vec<(String, String, Checksum)>>;
    /// The refs stored as alias symlinks, under heads and remotes, with each
    /// link body verbatim.
    pub async fn list_ref_aliases(&self) -> Result<Vec<RefAlias>>;
    /// Probe one path below `refs/`, as a listing prefix names it: `ENOTDIR`
    /// where a component above the last is not a directory, `Ok` for a path
    /// naming nothing.
    pub async fn check_refs_path(&self, relpath: &str) -> Result<()>;

    pub async fn load_commit(&self, c: &Checksum) -> Result<(Commit, CommitState)>;
    pub async fn load_dirtree(&self, c: &Checksum) -> Result<DirTree>;
    pub async fn load_dirmeta(&self, c: &Checksum) -> Result<DirMeta>;
    pub async fn load_variant(&self, ty: ObjectType, c: &Checksum) -> Result<Value>;
    pub async fn has_object(&self, ty: ObjectType, c: &Checksum) -> Result<bool>;

    /// Open a committed file's metadata plus an async content reader.
    pub async fn load_file(&self, c: &Checksum) -> Result<FileObject>;

    /// A traversable, read-only view of a commit's root tree.
    pub async fn read_commit(&self, rev: &str) -> Result<(RepoTree, Checksum)>;

    // --- detached metadata / signing (see Signing) ---
    pub async fn read_commit_detached_metadata(&self, c: &Checksum) -> Result<Option<Value>>;
    pub async fn write_commit_detached_metadata(&self, c: &Checksum, meta: Option<&Value>) -> Result<()>;

    // --- transactions ---
    pub async fn transaction(&self) -> Result<Transaction>;
    pub async fn transaction_with_lock(&self, lock: LockKind) -> Result<Transaction>;

    // --- checkout ---
    // The options arrive by `&mut`: the filter callback runs through an
    // exclusive borrow and the devino cache is populated in place.
    pub async fn checkout_at(&self, opts: &mut CheckoutOptions,
        dest_dir: BorrowedFd<'_>, dest_path: &Path, commit: &Checksum) -> Result<()>;

    // --- immediate ref writes (outside a transaction) ---
    // Each honors `[core] fsync`: the ref file is `fdatasync`-ed and the
    // directory holding it is `fsync`-ed after the rename or the unlink.
    pub async fn set_ref_immediate(&self, refspec: &str, checksum: Option<&Checksum>) -> Result<()>;
    pub async fn set_collection_ref_immediate(&self, cref: &CollectionRef,
        checksum: Option<&Checksum>) -> Result<()>;
    /// Write `refspec` as a relative symlink to `target`'s ref file.
    pub async fn set_ref_alias_immediate(&self, refspec: &str, target: &str) -> Result<()>;

    // --- maintenance ---
    pub async fn prune(&self, opts: &PruneOptions) -> Result<PruneStats>;
    pub async fn fsck(&self, opts: &FsckOptions) -> Result<FsckReport>;
    pub async fn traverse_commit(&self, c: &Checksum, depth: i32)
        -> Result<HashSet<ObjectName>>;
    pub async fn regenerate_summary(&self, opts: &SummaryOptions) -> Result<()>;
}

/// Knobs for [`Repo::regenerate_summary`]. Both timestamps default to the
/// current time; setting them makes the output reproducible.
pub struct SummaryOptions {
    pub last_modified: Option<u64>,
    pub metadata_commit_timestamp: Option<u64>,
}
```

## Commit / tree value types

```rust
pub struct Commit {
    pub metadata: Value,                   // a{sv}, in on-disk order
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

/// `Partial` states that a `.commitpartial` marker sits beside the commit.
pub enum CommitState { Normal, Partial }

pub struct FileObject {
    pub uid: u32, pub gid: u32, pub mode: u32,
    pub xattrs: Xattrs,
    pub kind: FileKind,                    // Regular { size } | Symlink { target }
}
impl FileObject {
    /// Regular files: streams the payload in bounded chunks.
    pub async fn reader(&self) -> Result<ContentReader>;
    /// The same stream written into `writer`, for a caller that has a sink
    /// rather than a read loop. A symlink writes nothing. The writer is left
    /// unflushed: a sink takes as many payloads as its owner sends it, and a
    /// framing or compressing sink emits on a flush, so the caller settles its
    /// own sink once.
    pub async fn write_to<W: futures_io::AsyncWrite + Unpin>(&self, writer: &mut W)
        -> Result<()>;
}

/// One ref stored as an alias.
pub struct RefAlias { pub refspec: String, pub target: String }

/// Whether a refspec names a path under `refs/`: a ref name, optionally
/// preceded by a `<remote>:` prefix. A refspec that would leave the tree is
/// `Error::InvalidRefspec`, holding the refspec as given, which is the one
/// error a caller reporting a refused name needs the name from. Every ref
/// write and every resolution applies the same rule.
pub fn validate_refspec(refspec: &str) -> Result<()>;

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
// ostrya-rt -- the whole surface.
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

pub struct Timer;                       // Timer::after(Duration)
pub struct Deadline;                    // a restartable inactivity window
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>;
pub struct Command;                     // subprocess, for gpg signing and keys
pub struct TcpListener;  pub struct TcpStream;
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

    /// The value `ostree.linux` holds for this tree, over `objects/` alone.
    /// `Transaction::kernel_version` covers a tree that is still staged.
    pub async fn kernel_version(&self)
        -> Result<std::result::Result<String, BootableRefusal>>;
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
        meta: &FileMeta) -> Result<ContentWriter<'_>>;
    /// Pull-style convenience over `content_writer`.
    pub async fn write_content(&self, expected: Option<&Checksum>,
        meta: &FileMeta, reader: impl AsyncRead + Unpin) -> Result<Checksum>;
    /// Small content the caller already holds; the general path is
    /// `write_content`, which streams.
    pub async fn write_regfile_inline(&self, expected: Option<&Checksum>,
        meta: &FileMeta, data: &[u8]) -> Result<Checksum>;
    pub async fn write_symlink(&self, target: &str, meta: &FileMeta,
        expected: Option<&Checksum>) -> Result<Checksum>;
    /// `bytes` is one already-serialized metadata object.
    pub async fn write_metadata(&self, ty: ObjectType, expected: Option<&Checksum>,
        bytes: &[u8]) -> Result<Checksum>;
    /// Write the dirmeta object the repository mode records for `meta`.
    /// `bare-user-only` discards ownership and xattrs and reduces the
    /// permission bits, and the object's identity covers that form, so a
    /// caller assembling a tree takes this path rather than serializing a
    /// `DirMeta` itself and passing the bytes to `write_metadata`.
    pub async fn write_dirmeta(&self, meta: &DirMeta) -> Result<Checksum>;

    // tree building
    pub async fn write_dfd_to_mtree(&self, dfd: BorrowedFd<'_>, path: &Path,
        mtree: &mut MutableTree, modifier: Option<&mut CommitModifier>) -> Result<()>;
    /// Port extension: merge an overlayfs upperdir changeset into an mtree
    /// holding the overlay's lower layer (see "Staging tree, tree merge,
    /// and overlay import").
    pub async fn merge_overlay_dfd_to_mtree(&self, dfd: BorrowedFd<'_>,
        mtree: &mut MutableTree, modifier: Option<&mut CommitModifier>) -> Result<()>;
    /// Overlay a committed tree onto an mtree under the same modifier the
    /// filesystem walk takes, so the two source kinds compose.
    pub async fn overlay_tree_to_mtree(&self, dirtree: &Checksum, dirmeta: &Checksum,
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

    /// Replaces `[core] fsync` for this transaction alone, over the per-object
    /// writes, the publication step, and the ref writes `commit` applies.
    /// Changes durability and no stored byte.
    pub fn set_fsync(&mut self, enabled: bool);

    /// Settles whether every commit this transaction writes carries
    /// `ostree.sizes`, for an ingest that runs no commit modifier. The answer
    /// holds for the whole transaction and wins over the flag an ingest sets.
    /// Archive mode alone writes the key.
    pub fn set_generate_sizes(&mut self, enabled: bool);

    /// Opens a new tree source for `ostree.sizes` accounting, scoping the key
    /// to the objects the last source contributed plus the directory objects
    /// the tree serialization writes. A caller that composes a commit from
    /// several sources calls this before each of them; a caller that never
    /// calls it leaves the key covering every object the commit reaches.
    pub fn begin_tree_source(&self);

    /// Lists one directory of a tree this transaction staged, reading its
    /// staged objects before `objects/`, for metadata a commit derives from the
    /// tree it is about to publish. Each `TreeEntry::Dir` it returns is read
    /// back the same way; `RepoTree::read_dir` reads `objects/` alone.
    pub async fn read_dir(&self, tree: &RepoTree) -> Result<Vec<TreeEntry>>;

    /// The value `ostree.linux` holds for a tree this transaction staged,
    /// read through `read_dir` so it is available before the transaction
    /// publishes.
    pub async fn kernel_version(&self, root: &RepoTree)
        -> Result<std::result::Result<String, BootableRefusal>>;

    // detached metadata and signatures, written at `commit` after the staged
    // objects publish and before the queued refs, so a commit and its
    // `.commitmeta` are both durable before a ref names them.

    /// Queues the `a{sv}` dict a commit's `.commitmeta` holds, replacing what
    /// the repository stores. The last dict queued for a checksum wins.
    pub fn set_commit_detached_metadata(&self, c: &Checksum, meta: Value);

    /// Signs a commit this transaction staged and appends the signature to its
    /// queued dict, starting from the queued dict, else the stored one, else an
    /// empty one. Nothing reaches the filesystem here, so a signature that
    /// cannot be produced fails the transaction with no object published and no
    /// ref moved.
    pub async fn sign_commit(&self, c: &Checksum, signer: &dyn Signer) -> Result<()>;

    pub async fn commit(self) -> Result<TransactionStats>;
    pub async fn abort(self) -> Result<()>;
}

/// Removes the staging directory and the sibling lock file of every live
/// transaction in this process. `commit`, `abort`, and `Drop` each remove
/// their own, so an unwound return needs nothing more; a caller that ends the
/// process without running destructors calls this immediately ahead of the
/// exit. It is for that moment alone: a transaction that keeps running after it
/// finds its staged objects gone.
pub fn reap_process_staging();

/// Streams one regular file's payload into a transaction. Implements
/// `futures_io::AsyncWrite` unconditionally and `tokio::io::AsyncWrite`
/// under the `tokio` feature. `finish` finalizes the digest, applies the
/// per-mode object metadata, and stages the object under its id (a dedup
/// hit returns the existing id). Dropping without `finish` abandons the
/// staged temporary, which the transaction reaps.
pub struct ContentWriter<'txn> { /* HashingWriter over a staging rt::File */ }
impl ContentWriter<'_> {
    pub async fn finish(self) -> Result<Checksum>;
}

pub struct CommitOptions {
    pub parent: Option<Checksum>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub timestamp: Option<u64>,      // else SOURCE_DATE_EPOCH or now
    pub metadata: Option<Value>,     // a{sv}; ostree.sizes auto-added
}

pub enum LockKind { Shared, Exclusive }
pub struct TransactionStats { pub metadata_total: u32, pub metadata_written: u32,
    pub content_total: u32, pub content_written: u32,
    pub content_bytes_written: u64,   // stored size
    pub content_bytes_unpacked: u64,  // payload size, regular files only
    pub devino_cache_hits: u32,
    pub filtered: u32 }                // entries a modifier filter excluded
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
    /// This directory's dirmeta checksum, if set. A root with none cannot be
    /// written, which is how a source list that supplied no root directory is
    /// recognized.
    pub fn metadata_checksum(&self) -> Option<Checksum>;
    pub fn remove(&mut self, name: &str, allow_noent: bool) -> Result<()>;
}

bitflags! { pub struct CommitModifierFlags: u32 {
    const SKIP_XATTRS; const GENERATE_SIZES; const CANONICAL_PERMISSIONS;
    const ERROR_ON_UNLABELED; const CONSUME; const DEVINO_CANONICAL;
    const SELINUX_LABEL_V1;
}}

pub enum FilterResult { Allow, Skip }

// Each hook is a named boxed-closure alias. The walk takes the modifier as
// `Option<&mut CommitModifier>`: the FnMut callbacks run through the exclusive
// borrow, and the Send bound on each box keeps the walk future Send.
pub type FilterFn = Box<dyn FnMut(&Path, &FileMeta) -> FilterResult + Send>;
/// Returns the st_mode the entry records, file-type bits included.
pub type ModeFn   = Box<dyn FnMut(&Path, &FileMeta) -> u32 + Send>;
pub type XattrFn  = Box<dyn FnMut(&Path, &FileMeta) -> Xattrs + Send>;
pub type LabelFn  = Box<dyn FnMut(&Path, &FileMeta) -> Option<Vec<u8>> + Send>;

pub struct CommitModifier {
    pub flags: CommitModifierFlags,
    pub filter: Option<FilterFn>,
    /// The owner ids every ingested entry records. Applied after the
    /// CANONICAL_PERMISSIONS reduction and before the callbacks, so a declared
    /// id wins over that flag's `0`.
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    // mode_callback runs ahead of the xattr callback and the label hook.
    pub mode_callback: Option<ModeFn>,
    pub xattr_callback: Option<XattrFn>,
    pub label_callback: Option<LabelFn>,
    pub devino_cache: Option<DevInoCache>,
}

impl Repo {
    // The (device, inode) map of this repository's own uncompressed loose
    // content objects, which a hardlinking checkout puts on disk. Empty for
    // an archive repository, which stores every content object compressed.
    pub async fn devino_cache(&self) -> Result<DevInoCache>;
}
```

A cache attached to a modifier is consulted for every regular file and symlink
the walk reaches. Without `DEVINO_CANONICAL` a hit supplies the stored object's
metadata, the modifier is applied over it, and the object is rewritten from the
stored payload only where the result differs. With the flag the hit is taken
verbatim and the filter and every callback are skipped for that entry.

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
    /// The dirmeta applied to ancestors a write creates. Set once, at
    /// construction; left unset, a missing parent stays an error.
    pub fn with_implied_dirmeta(self, meta: DirMeta) -> Self;

    /// Hands the tree to write_mtree; fails while write_file writers
    /// are outstanding.
    pub fn close(self) -> Result<MutableTree>;

    /// Merge at the tree root, which is merge_at with a base of `.`.
    pub async fn merge(&self, other: &MutableTree, opts: MergeOptions) -> Result<()>;
    /// Merge into the directory at `base`. A missing base is created under
    /// an implied dirmeta and is an error without one; `base` resolves
    /// through symlinks, its final component included. A base with no
    /// components names the tree root.
    pub async fn merge_at(&self, base: &Path, other: &MutableTree,
        opts: MergeOptions) -> Result<()>;

    pub async fn write_file(&self, path: &Path, meta: &FileMeta)
        -> Result<StagedFileWriter<'txn>>;
    pub async fn write_file_content(&self, path: &Path, meta: &FileMeta,
        content: &[u8]) -> Result<()>;
    pub async fn make_dir(&self, path: &Path, meta: &DirMeta) -> Result<()>;
    pub async fn make_dir_all(&self, path: &Path, meta: &DirMeta) -> Result<()>;
    /// Create the directory, or reuse an existing one and stamp `meta`
    /// onto it. Stages the dirmeta only when it creates the directory or
    /// the recorded dirmeta differs, and restamps a lazy committed child
    /// in place without hydrating it.
    pub async fn ensure_dir(&self, path: &Path, meta: &DirMeta) -> Result<()>;
    pub async fn symlink(&self, path: &Path, target: &Path, meta: &FileMeta)
        -> Result<()>;
    /// A second tree entry for the content object found at `target`;
    /// the object carries all metadata, so none is taken.
    pub async fn hardlink(&self, path: &Path, target: &Path) -> Result<()>;
    /// Record `checksum` as the entry at `path`. An identical entry is
    /// silent; a differing entry or a directory is `MergeConflict`. The
    /// rule is decided and applied under one lock acquisition, so
    /// concurrent placements never silently overwrite. The object's
    /// presence in the store is not checked, the same as `write_mtree`.
    pub async fn place_object(&self, path: &Path, checksum: &Checksum)
        -> Result<()>;
    /// Remove the entry at `path`, subtree and all. The final component
    /// is never followed, so removing a symlink removes the symlink.
    /// With `allow_noent`, an absent entry, an absent ancestor, and a
    /// dangling intermediate symlink are all `Ok`.
    pub async fn remove(&self, path: &Path, allow_noent: bool) -> Result<()>;
    /// Remove every entry under `path`, keeping the directory and its
    /// dirmeta. With `allow_noent`, an absent directory is `Ok`. A lazy
    /// committed directory is emptied in place, keeping its recorded
    /// dirmeta checksum, without hydration.
    pub async fn clear_dir(&self, path: &Path, allow_noent: bool) -> Result<()>;
    /// Move the entry at `from` to `to`, subtree and dirmeta included.
    /// Neither final component is followed. An existing entry at `to` is
    /// `EntryExists`, and a destination at or under the moved entry is
    /// refused. A moved lazy committed directory stays lazy, so no
    /// dirtree is read for the moved subtree.
    pub async fn rename(&self, from: &Path, to: &Path) -> Result<()>;

    /// Path resolution against the staged tree; objects load from the
    /// transaction's staged set first, then from `objects/`.
    pub async fn lookup(&self, path: &Path, follow_symlinks: bool)
        -> Result<StagingLookup>;
    pub async fn read_file(&self, path: &Path, follow_symlinks: bool)
        -> Result<FileObject>;
    pub async fn read_dir(&self, path: &Path, follow_symlinks: bool)
        -> Result<Vec<StagingEntry>>;
}

/// finish() completes the content object and records it at the path.
pub struct StagedFileWriter<'txn> { /* ContentWriter + path + tree handle */ }
impl StagedFileWriter<'_> { pub async fn finish(self) -> Result<()>; }

pub enum StagingEntry {
    File { name: String, checksum: Checksum },
    Dir  { name: String },                     // no checksum until written
}

/// An absent component anywhere along the path is `Absent`, never an
/// error; a non-directory intermediate component and a dangling symlink
/// stay the typed errors. The file/symlink distinction is not recorded
/// in the tree, so `File` covers both; read_file loads the object where
/// the kind matters.
pub enum StagingLookup {
    Absent,
    File { checksum: Checksum },
    Dir,
}

/// How the merge treats the merge root's own dirmeta. Reconcile is the
/// default and treats the root like any other directory; KeepLeft ignores
/// the right root's dirmeta, so a left root that carries none keeps none
/// and the tree cannot be written. Every directory below the root
/// reconciles either way.
#[derive(Default)]
pub enum RootDirmeta { #[default] Reconcile, KeepLeft }

#[derive(Default)]
pub struct MergeOptions {
    pub allow_overwrite: bool,
    pub follow_symlinks: bool,
    pub root_dirmeta: RootDirmeta,
}
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
the symlink and the missing target. The flag governs the left-side entry
names the merge reaches; a `merge_at` base's own final component follows
either way. `root_dirmeta` governs the merge
root alone: the directory at `base` reconciles its own dirmeta under
`Reconcile` and keeps the dirmeta it has under `KeepLeft`, and every
directory below the root reconciles either way. A merge that drops a
directory is refused with `Staging` while any `write_file`
writer is outstanding, wherever in the tree it sits, and leaves that
directory and its subtree in place: a writer records its entry at
`finish` under the component path it captured, and a directory dropped
in between would leave that path stale. Two cases drop one: an
overwrite that replaces a directory with a file, and a right-side
directory arriving at a name a concurrent operation turned into a
directory after the merge read it. The merge re-reads that name inside
the lock acquisition that mutates it, so the guard cannot be stepped
past, and the second case is a `MergeConflict` without
`allow_overwrite`, the answer the same clash gets when the merge reads
the directory itself. A leaf a concurrent operation puts at a name the
merge already read is taken whatever `allow_overwrite` says, the
last-writer-wins rule the other staging writes follow on a raced name;
only a raced directory is re-read, because dropping one loses a
subtree. A merge that fails, on either refusal or on a
conflict, keeps the entries it applied before the failure. Merge lives
on `StagingTree` rather than `MutableTree` because resolution loads
symlink content objects, and only transaction scope sees objects staged
in the current transaction.

Path semantics for the write operations: intermediate components resolve
through symlinks with the same walker; the final component never
follows. With an implied dirmeta set, `write_file`,
`write_file_content`, `symlink`, `hardlink`, `place_object`,
`ensure_dir`, and the destination side of a `rename` create missing
ancestors as directories carrying it, staging that dirmeta at most
once per operation and only when a
directory is created; the leaf takes what the operation itself
supplies. A `merge_at` base is created under the same policy, its own
final component included, since the base names a directory rather than
a leaf. Ancestors created before a refused leaf stay in the tree, and
a component a later `..` steps back out of is created like any other
ancestor. A `rename` resolves its destination before it decides any
refusal, so a refused `rename` keeps those ancestors too; where the
destination is under the moved entry they sit inside that entry, and a
lazily-loaded source is hydrated to reach them. Resolution for a read,
a `lookup`, a `remove`, a `clear_dir`,
the source side of a `hardlink`, or the `from` side of a `rename`
never creates a directory, whatever the policy. `make_dir` and
`make_dir_all` keep their own rules.
`write_file`, `write_file_content`, `symlink`, and `hardlink`
replace an existing file or symlink entry and fail on a directory with
`ReplaceDirWithFile`; `make_dir` fails on any existing entry;
`ensure_dir` creates the directory or restamps an existing one and fails
on a file or symlink; `make_dir_all` applies its `DirMeta` to the
directories it creates and leaves existing ones untouched; `clear_dir`
fails with `NotADirectory` on a file, and on a symlink even where it
points at a directory, and names a directory below the root, so the
root itself cannot be cleared. A `remove` that takes an entry out and a
`clear_dir` that reaches a directory are refused with `Staging` while
any `write_file` writer is outstanding, wherever in the tree it sits,
the rule a merge that drops a directory follows; a call that removes
nothing is not. A `rename` that reaches its two checks is refused the
same way. A `write_file` writer is counted from its registration, not
from the call, so in the window between path resolution and that
registration the guard holds off no concurrent operation; a parent
dropped in that window is refused with `Staging` by the re-check the
registration makes under the lock.

Each refusal carries its own `Error` variant naming the path resolution
stopped at, so a consumer branches on the condition: `PathNotFound` for
an absent component, `NotADirectory` for a file or a resolved symlink
where a directory was required, `DanglingSymlink` and `SymlinkLoop`
from the walker, and `EntryExists` where an operation requires a fresh
entry. Every typed refusal the staging tree raises reports one path
form: the resolved literal component path, unrooted, with the tree root
spelled `.`. A path that crosses a symlink reports the target's
components, so a write under `opt -> usr/opt` reports `usr/opt`. An
absent component reached while a symlink's target components are still
queued reports `DanglingSymlink` for the innermost such symlink; once a
target is spent, an absent component reports `PathNotFound`.
`Staging` carries the conditions none of those names: the
outstanding-writer refusals from `close`, from a merge that drops a
directory, from `remove`, from `clear_dir`, and
from `rename`, a read of a directory where a file was wanted, a
`hardlink` whose source resolves to a directory, a `rename` whose
destination is at or under the moved entry, a directory a concurrent
operation removed under the lock, a path with no final component or
one ending
in `..`, a non-UTF-8 path component or symlink target, and a hydration
with no repository handle. A `Staging`
condition raised before resolution begins reports the path as the
caller gave it, because no resolved form exists. A symlink target that
is not UTF-8 names no path. A directory in the way of a write reports
`ReplaceDirWithFile`, whichever moment the directory appeared at; the
variant names the entry rather than the resolved path, because the
mutable-tree layer raises it, and it is the one carve-out from the path
form.

## Checkout options

```rust
pub enum CheckoutMode { None, User }
pub enum OverwriteMode { None, UnionFiles, AddFiles, UnionIdentical }

/// A `Skip` on a directory prunes its whole subtree.
pub type CheckoutFilterFn = Box<dyn FnMut(&Path, &FileMeta) -> FilterResult + Send>;

pub struct CheckoutOptions {
    pub mode: CheckoutMode,
    pub overwrite: OverwriteMode,
    pub subpath: Option<PathBuf>,
    pub enable_fsync: bool,          // default false, matching the tool
    pub force_copy: bool,
    pub process_whiteouts: bool,
    pub devino_cache: Option<DevInoCache>,
    pub filter: Option<CheckoutFilterFn>,
}
```

## Signing

Both traits are object-safe and taken as `&dyn`, so the asynchronous method
returns a boxed future rather than being an `async fn`.

```rust
pub type SignFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;
pub type VerifyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<VerifyOutcome>> + Send + 'a>>;

pub trait Signer: Send + Sync {
    fn name(&self) -> &str;                       // "ed25519", "spki", "gpg", "dummy"
    fn metadata_key(&self) -> &str;               // e.g. "ostree.sign.ed25519"
    fn sign<'a>(&'a self, data: &'a [u8]) -> SignFuture<'a>;
}
pub trait Verifier: Send + Sync {
    fn metadata_key(&self) -> &str;
    fn verify<'a>(&'a self, data: &'a [u8], signatures: &'a [Vec<u8>])
        -> VerifyFuture<'a>;
}

pub struct Ed25519Signer { /* 64-byte secret */ }
pub struct Ed25519Verifier { /* trusted + revoked 32-byte keys */ }
pub struct GpgSigner { /* key id/fingerprint + optional GNUPGHOME; signs via gpg */ }
pub struct GpgVerifier { /* parsed certificates; verifies in the process */ }
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
    /// Append a signature over the repository's `summary` bytes to
    /// `summary.sig`.
    pub async fn sign_summary(&self, signer: &dyn Signer) -> Result<()>;
    pub async fn verify_summary(&self, verifiers: &[&dyn Verifier])
        -> Result<VerifyOutcome>;
}

impl GpgSigner {
    /// The GnuPG home directory this signer resolves its key in, or `None` for
    /// gpg's own default.
    pub fn homedir(&self) -> Option<&Path>;

    /// The fingerprints `gpg --list-secret-keys` resolves this signer's
    /// selector to, in listing order. A home directory that does not exist, one
    /// that cannot be read, and one holding no matching key all answer an empty
    /// list. More than one fingerprint means the selector is ambiguous, and a
    /// caller that needs a single signing key refuses it.
    pub async fn secret_key_fingerprints(&self) -> Result<Vec<String>>;
}

/// One key of a remote's trusted keyring, as a `gpg` key listing states it.
pub struct GpgKey {
    pub fingerprint: String,
    pub created: Option<u64>,
    pub user_ids: Vec<String>,
}

impl Repo {                                   // feature = "verify-gpg"
    /// Add the certificates `keys` holds to `<remote>.trustedkeys.gpg`, and
    /// report how many the keyring did not already hold. With `key_ids`
    /// non-empty only the keys those selectors name are imported.
    pub async fn gpg_import_keys(&self, remote: &str, keys: &[u8], key_ids: &[String])
        -> Result<usize>;
    /// The keys that keyring holds. An absent keyring holds none.
    pub async fn gpg_list_keys(&self, remote: &str) -> Result<Vec<GpgKey>>;
}
```

Key loading helpers (ed25519 base64-per-line files and the
`trusted.ed25519[.d]` / `revoked.ed25519[.d]` directory convention; GPG keyring
files binary and armored) are free functions or `impl` on the concrete signer
types.

`GpgVerifier` is behind the `verify-gpg` feature, together with `GpgKey`,
`Repo::gpg_import_keys`, and `Repo::gpg_list_keys`, which manage the
verification trust set. `GpgSigner` is behind `sign-gpg`, which turns on
`verify-gpg` with it. A constructor of `GpgVerifier` parses each keyring into
certificates as it loads it, so a keyring the parser rejects fails the
construction. One keyring is held to four mebibytes and to 256 certificates,
and a GnuPG keybox is refused by the name of the file or the blob that carries
it; each refusal states the cap or the cause it names.

`Verifier::verify` for `GpgVerifier` answers in the process on the blocking
pool, over the `pgp` crate (rPGP). It spawns no process. One stored blob is
held to one mebibyte and to 64 signature packets. The port owns the trust and
validity policy: issuer resolution over primary keys and subkeys, the subkey
binding and its embedded primary-key binding, key expiry, revocation, the
signature class, and the digest policy.

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

A remote that publishes static deltas delivers a commit as one delta instead of
one request per object. A pull looks for one delta per tip: `<from>-<to>`, where
`from` is the commit the ref names in this repository and holds complete, and the
from-scratch `<to>` where the ref names none. The delta index for the target
commit is read first and the summary's own `ostree.static-deltas` map where the
remote serves no index; a remote serving no summary is asked for the superblock by
name. A superblock the remote advertised a digest for is checked against it, the
part files are checked against the superblock, and every object a part produces is
written under the checksum the superblock names. Two part fetches are in flight at
once whatever `max_outstanding_fetches` is. The objects the delta hands over loose
are fetched as ordinary content objects, and the commit's tree is walked once the
last part is applied, so an object no part delivered is fetched loose and a
published commit is whole. `disable_static_deltas` asks for no delta;
`require_static_deltas` refuses a remote that advertises none.

A pull checks the signatures on the commits it carries and on the remote's
summary. `verify` holds four switches, each overriding the remote configuration
key of the same name; a switch left `None` reads that configuration for `pull`
and is off for `pull_local`. The GPG axis takes the remote's trusted keyrings and
the sign-api axis takes the engines `sign-verify` names, with their keys from
`verification-<engine>-key`, `verification-<engine>-file`, and the system key
store. Each axis that applies has to find a valid signature, and within the
sign-api axis one engine is enough. The summary is checked before it is read and
a commit before its bytes are staged, so a refusal costs no object fetch. A
fetched static delta is held to the sign-api axis over its raw superblock bytes
before any part is requested.

Still remote-only and unimplemented: `subdirs`, `override_commit_ids`, and a
progress callback.

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
    pub disable_static_deltas: bool,      // fetch every object loose
    pub require_static_deltas: bool,      // refuse a remote advertising none
    pub verify: PullVerify,               // the signature checks to make
}

/// The signature checks a pull makes. `None` reads the remote's configuration
/// for `pull` and checks nothing for `pull_local`; `Some(true)` on a sign-api
/// field selects every engine the build has, as `sign-verify=true` does.
#[derive(Default)]
pub struct PullVerify {
    pub gpg: Option<bool>,                // gpg-verify, default true
    pub gpg_summary: Option<bool>,        // gpg-verify-summary, default false
    pub sign: Option<bool>,               // sign-verify, default off
    pub sign_summary: Option<bool>,       // sign-verify-summary, default off
}

pub struct PullStats {
    pub metadata_imported: u32,
    pub content_imported: u32,
    pub content_bytes_written: u64,
}

/// The read side of a `summary` file: the ref list a pull resolves against, and
/// the global metadata dict verbatim.
pub struct Summary { pub refs: Vec<SummaryRef>, pub metadata: Value }
/// One field-0 entry: a ref, the commit it names, and what the summary records
/// about that commit. `commit_size` is stored in host order; the numbers in
/// `metadata` are big-endian.
pub struct SummaryRef {
    pub name: String,
    pub commit: Checksum,
    pub commit_size: u64,
    pub metadata: Value,
}
impl Summary {
    pub fn parse(bytes: &[u8]) -> Result<Summary>;
    pub fn lookup(&self, ref_name: &str) -> Option<Checksum>;
    pub fn metadata_value(&self, key: &str) -> Option<&Value>;
    /// The refs of each collection `ostree.summary.collection-map` lists.
    pub fn collection_map(&self) -> Result<Vec<(String, Vec<SummaryRef>)>>;
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

The three size thresholds are in bytes, where the tool's options take decimal
megabytes. Generation, signing, and index publication are three calls, so a
caller signs a delta it has just written and publishes it once.

```rust
pub struct DeltaOptions {
    pub min_fallback_size: u64,           // default 4_000_000; 0 turns fallbacks off
    pub max_bsdiff_size: u64,             // default 64_000_000
    pub max_chunk_size: u64,              // default 32_000_000
    pub bsdiff: bool,
    /// The superblock timestamp. `None` uses the current time; setting it makes
    /// the output reproducible.
    pub timestamp: Option<u64>,
    /// Write the superblock and the part files here instead of the
    /// repository's `deltas/` tree.
    pub output_dir: Option<PathBuf>,
}
impl Repo {
    /// Returns the directory the delta was written to: relative to the
    /// repository root for the default location, and `output_dir` verbatim
    /// where that option is set.
    pub async fn generate_static_delta(&self, from: Option<&Checksum>,
        to: &Checksum, opts: &DeltaOptions) -> Result<PathBuf>;
    /// Apply the delta in `dir` and return the commit it delivered.
    pub async fn apply_static_delta_offline(&self, dir: &Path) -> Result<Checksum>;
    pub async fn sign_static_delta(&self, dir: &Path, signer: &dyn Signer) -> Result<()>;
    pub async fn verify_static_delta(&self, dir: &Path, verifiers: &[&dyn Verifier])
        -> Result<VerifyOutcome>;
    /// Rebuild the `delta-indexes/` cache that advertises the stored deltas to
    /// a fetcher.
    pub async fn reindex_static_deltas(&self) -> Result<()>;
    /// The stored deltas, each named as the tool names it: the target commit
    /// hex, or `<from-hex>-<to-hex>`.
    pub async fn list_static_deltas(&self) -> Result<Vec<String>>;
}
```

## Tar and composefs

Both are always compiled. Tar is built on smol-tar; composefs is built on the
workspace's own `ostrya-composefs` crate.

```rust
impl Repo {
    pub async fn export_tar(&self, commit: &Checksum, opts: TarExportOptions,
        out: impl AsyncWrite) -> Result<()>;
    pub async fn import_tar(&self, txn: &Transaction, opts: TarImportOptions,
        input: impl AsyncRead) -> Result<MutableTree>;
    /// Read an archive into a tree an earlier source already filled, shaping
    /// each member with the commit modifier. Every member is placed under a
    /// directory the tree already holds unless
    /// `TarImportOptions::autocreate_parents` permits synthesizing it, and
    /// `TarImportOptions::rename` rewrites each member's pathname first.
    pub async fn import_tar_into(&self, txn: &Transaction, opts: TarImportOptions,
        input: impl AsyncRead, mtree: &mut MutableTree,
        modifier: Option<&mut CommitModifier>) -> Result<()>;
}

#[non_exhaustive]
pub struct TarExportOptions {}

/// A rename hook over member pathnames. It takes the normalized member name
/// and returns the name the member is imported under.
pub type TarRename = Box<dyn FnMut(&str) -> Result<String> + Send>;

#[non_exhaustive]
pub struct TarImportOptions {
    pub etc_to_usr_etc: bool,
    pub owner_uid: Option<u32>,
    pub owner_gid: Option<u32>,
    pub skip_xattrs: bool,
    pub autocreate_parents: bool,
    pub rename: Option<TarRename>,
}

/// The EROFS image bytes and the fs-verity digest over them.
pub struct Image { pub bytes: Vec<u8>, pub fs_verity: [u8; 32] }

/// Whether an exported image carries the backing objects' fs-verity digests.
/// `Computed` is the default: each backed file takes the 36-byte metacopy
/// record holding the digest of its content. `Disabled` gives the metacopy
/// xattr an empty value and reads no payload; the image it produces has its own
/// fs-verity digest, distinct from the `ostree.composefs.digest.v0` value a
/// commit records.
pub enum VerityPolicy { Computed, Disabled }

/// Options for a composefs export.
pub struct ComposefsOptions { pub verity: VerityPolicy }

impl Repo {
    /// Produce the EROFS/composefs image for a commit and its fs-verity digest.
    /// Inode metadata always comes from the real file attributes (no canonical
    /// mode); in bare-user-shared mode metadata comes from `user.ostreemeta`
    /// and each regular file redirects to its `.file` loose path. Ownership is
    /// presented via composefs uid mapping at mount. A repository outside the
    /// composefs backing modes (`bare-user`, `bare-user-shared`) is
    /// `Error::Unsupported`. Every backing object is opened under either
    /// policy, because the inode's metadata comes from it.
    pub async fn export_composefs(&self, commit: &Checksum,
        opts: &ComposefsOptions) -> Result<Image>;
    /// Write that image through `out` and return its fs-verity digest. Emission
    /// is append-only, so the image reaches the descriptor as it is serialized
    /// and no image-sized buffer is held. `out` is written from its current
    /// offset onward and is never seeked, and a call that fails leaves the
    /// prefix it had already written. The mode rule and `opts` are those of
    /// `export_composefs`.
    ///
    /// Every path here refuses a tree whose inode spends more than 32755 bytes
    /// on extended attributes, counting each name, each value, and 7 bytes an
    /// attribute, with `Error::Unsupported`. This is the budget the tool holds
    /// (`format-reference.md`, "composefs"). A commit past it would carry a
    /// composefs digest no `ostree` reproduces. The one EROFS field the budget
    /// leaves unbound is refused there as well: a name above 255 bytes. A
    /// symlink target that fills its inode's block reaches the same refusal
    /// from the writer, which is where the block is measured.
    pub async fn export_composefs_to(&self, commit: &Checksum,
        opts: &ComposefsOptions, out: BorrowedFd<'_>) -> Result<[u8; 32]>;
    /// Compute and store `ostree.composefs.digest.v0` in the commit's metadata.
    /// The digest derives from the tree alone, so this builds no image and runs
    /// in every repository mode, as `Transaction::composefs_digest` does. The
    /// mode rule applies to the two forms that write an image.
    pub async fn commit_add_composefs_metadata(&self, txn: &Transaction,
        commit: &Checksum) -> Result<Checksum>;
}

impl Transaction {
    /// The fs-verity digest of the composefs image for a tree this transaction
    /// has staged, for a commit that carries the key in its own metadata. The
    /// image derives from the tree alone, so the value is the same in every
    /// repository mode holding that tree. The image goes through
    /// `std::io::sink`, so the digest costs no image-sized buffer.
    pub async fn composefs_digest(&self, root: &RepoTree) -> Result<[u8; 32]>;
}
```

The `ostrya-composefs` crate carries the emitting half of that pair. Both forms
run one emission pass:

```rust
/// Write the image for `root` through `out` and return its fs-verity digest.
/// The sink takes the image in many small writes, so a caller writing to a file
/// wraps it in a `std::io::BufWriter`. One write carries at most one field, and
/// the largest field is an xattr value, which the EROFS length field caps at
/// 65535 bytes. A call that succeeds flushes the sink before it returns; a call
/// that fails returns the sink's first error and does not flush, though a sink
/// that flushes on drop, such as a `std::io::BufWriter`, still does.
///
/// A symlink states its target inline in its inode, so a target the inode's
/// block does not hold is `Error::Unsupported`; `Symlink` states the bound. An
/// xattr value above 65535 bytes, an xattr name suffix above 255 bytes, or an
/// xattr area above 262148 bytes is a broken precondition of the `Directory`
/// the caller built, and panics; `Metadata` states all three. The split is that
/// a caller reads the xattr bounds off the values it holds, and the symlink
/// bound off the inode the writer lays out.
pub fn write_image_to(root: &Directory, out: &mut impl std::io::Write)
    -> Result<[u8; 32], Error>;

/// Run that same pass into a buffer sized by the sizing pass.
pub fn build_image(root: &Directory) -> Result<Image, Error>;

/// A tree the writer has no image for, or a sink that failed.
pub enum Error { Unsupported(String), Io(std::io::Error) }
```

`TarExportOptions` is `Send + Sync`. `TarImportOptions` is `Send` alone: it
holds the `rename` callback field, which the import calls through `&mut`, the
way `CommitModifier` holds its filter and its three hooks. A holder that needs
the options behind a shared reference across threads wraps them. Both
assertions are pinned in `crates/ostrya/src/tar.rs`.

## Notes on divergence from the C API

- No `GCancellable`: cancel by dropping the future or racing a cancel signal.
- No out-parameters: results come back in `Result<T>`.
- No `glib::Variant` options dicts on the public surface: builders and structs.
  The dynamic `Value` is exposed where commit metadata genuinely is an
  arbitrary `a{sv}`.
- No raw `dfd: i32`: `BorrowedFd`/`OwnedFd`.
- The large `Repo` god-object is split: `Repo` for lifecycle/read/checkout/
  maintenance, `Transaction` for all writes, and `Signer`/`Verifier`/`Progress`
  traits for pluggable behavior.
- RAII guards from the bindings that are worth keeping: transaction auto-abort
  on drop, lock guards, and a typed `Checksum`.
