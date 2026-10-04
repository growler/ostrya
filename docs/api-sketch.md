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

// ostrya-core -- the rules a new commit is built by.

/// Raw-DEFLATE encoder over a futures-io writer, the stored form of an
/// archive-mode content object. `reset` starts a new stream in the same
/// compressor and output buffer and returns the old writer.
pub struct DeflateSink<W>;
impl<W> DeflateSink<W> {
    pub fn new(inner: W, level: u8) -> Self;          // level 1-9
    pub fn reset(&mut self, inner: W, level: u8) -> W;
    pub fn into_inner(self) -> W;
}
/// The pull form of DeflateSink: reads uncompressed bytes from a futures-io
/// source and gives the bytes DeflateSink writes at the same level. It never
/// flushes the stream before its end. Implements AsyncRead and AsyncBufRead.
pub struct DeflateReader<R>;
impl<R> DeflateReader<R> {
    pub fn new(source: R, level: u8) -> Self;         // level 1-9
    pub fn reset(&mut self, source: R, level: u8) -> R;
    pub fn get_ref(&self) -> &R;
    pub fn get_mut(&mut self) -> &mut R;
    pub fn into_inner(self) -> R;
}
/// The commit metadata dict: entries in order, then ostree.ref-binding
/// (sorted refs), then ostree.collection-binding. `refs: None` writes no
/// binding key. `ostrya` re-exports it as `ostrya::commit::commit_metadata`.
pub fn commit_metadata(entries: impl IntoIterator<Item = (String, Value)>,
    refs: Option<&[&str]>, collection_id: Option<&str>) -> Value;
pub fn ref_binding(refs: &[&str]) -> Value;
/// explicit, else SOURCE_DATE_EPOCH, else now.
pub fn commit_timestamp(explicit: Option<u64>) -> Result<u64, TimestampError>;
impl DirTree { pub fn check_name(name: &str) -> Result<()>; }
/// The ref-name rule. A component is not empty, is not `.` or `..`, and holds
/// no `/` and no NUL. A ref name is one or more components joined with `/`.
/// A refspec is a ref name, or REMOTE:NAME split at the first `:`, with
/// REMOTE one component. `ostrya::validate_refspec` applies `is_refspec`.
pub fn is_ref_component(component: &str) -> bool;
pub fn is_ref_name(name: &str) -> bool;
pub fn is_refspec(refspec: &str) -> bool;
/// True for 64 lowercase hex characters, which a revision reads as a commit
/// checksum. The rule above accepts such a name. Each site where a push
/// writes a commit to a target ref refuses it: `Repo::push`,
/// `Repo::export_stream`, `push_tree`, `session::export_stream`, and the
/// `Commit` check of the receiver. A push delete of such a name passes the
/// client and the receiver. `Hello` does not tell a write from a delete, so
/// the receiver does not check the name at `Hello`. A name with a `REMOTE:`
/// part is not 64 hex characters, so it passes. Ref reads, local ref
/// deletes, pull, prune, `Transaction::set_ref`, and
/// `Repo::set_ref_immediate` do not apply the check, so a direct ref write
/// can make a ref that no revision reads back.
/// `ostrya` re-exports it as `ostrya::is_checksum_shaped`.
pub fn is_checksum_shaped(name: &str) -> bool;
pub const MAX_METADATA_SIZE: u64;       // also at ostrya::MAX_METADATA_SIZE

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
    InvalidInput(String),              // an argument outside the accepted values
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
    StaticDeltaNotFound { from: Option<Checksum>, to: Checksum },
    #[cfg(feature = "receive")]
    Push(ostrya_push::Error),          // a push session: wire code, abort, stream
    // ... one variant per class of refusal the library reports
}

/// Map an error onto the closest `std::io::ErrorKind`, keeping the error as
/// the payload so its `Display` and its source chain survive.
impl From<Error> for std::io::Error;
```

The `io::ErrorKind` an error converts to:

- `NotFound`: `PathNotFound`, `DanglingSymlink`, `ObjectNotFound`,
  `RefNotFound`, `StaticDeltaNotFound`, `HttpStatus` with status 404.
- `NotADirectory`: `NotADirectory`, `ReplaceFileWithDir`.
- `AlreadyExists`: `EntryExists`, `MergeConflict`, `ReplaceDirWithFile`.
- `InvalidInput`: `MutableTree`, `InvalidInput`.
- `PermissionDenied`: `HttpStatus` with status 401 or 403.
- `FileTooLarge`: `FetchTooLarge`, the same kind a body that outgrows the cap
  while streaming fails its read with.
- The inner error itself: `Io`.
- `Other`: everything else, `SymlinkLoop` and every other `HttpStatus` status
  included, since `ErrorKind::FilesystemLoop` is unstable.

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
    /// The path this handle was opened or created with, exactly as given.
    /// There is no canonicalization and no `/proc/self/fd` resolution, so a
    /// relative path stays relative. For `open_at` and `create_at` the value
    /// is relative to the `dir` fd of that call and needs that fd to resolve.
    pub fn path(&self) -> &Path;

    /// Replace `config` with the document a caller edited through `KeyFile`'s
    /// setters and removers: a temporary file at mode 0644, `fdatasync`ed when
    /// `[core] fsync` is set, renamed over the target, with the repository
    /// directory synced. This handle keeps the configuration it was opened with.
    /// The write runs under the repository lock shared and the update lock, as
    /// every writer below that states "update lock" does: each of the two
    /// waits fails with `LockTimeout` after `lock-timeout-secs`, and a holder
    /// of an `UpdateGuard` of this repository that calls the writer waits for
    /// its own guard. The locks cover the write alone, so a read-modify-write
    /// that must see the file as it stands goes through an `UpdateGuard`.
    pub async fn write_config(&self, keyfile: &KeyFile) -> Result<()>;
    /// Remove a remote's trusted keyring, `<remote>.trustedkeys.gpg`. An
    /// already-absent keyring is success. Update lock.
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
    /// The collection-qualified refs: the local refs qualified by the
    /// repository's own `[core] collection-id`, plus every mirror ref, sorted
    /// by collection id and then by ref name.
    pub async fn list_collection_refs(&self) -> Result<Vec<CollectionRefEntry>>;
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
    /// Update lock.
    pub async fn write_commit_detached_metadata(&self, c: &Checksum, meta: Option<&Value>) -> Result<()>;

    // --- transactions ---
    /// A held `UpdateGuard` holds the repository lock shared too when
    /// `[core] locking` is on, so a transaction opens and stages objects
    /// while a guard is held.
    pub async fn transaction(&self) -> Result<Transaction>;
    pub async fn transaction_with_lock(&self, lock: LockKind) -> Result<Transaction>;

    // --- update guard ---
    /// Take the repository lock shared, then the update lock on
    /// `<repo>/.update.lock` exclusive. The call never waits for a pull, and
    /// when `[core] locking` is on it waits for a prune. Each of the two
    /// waits gets the whole of `lock-timeout-secs` and then fails with
    /// `LockTimeout`; `-1` has no limit, `0` makes one attempt, and there is
    /// no variant that fails at once. The waiters of one process take the
    /// update lock in the order of the first poll of their wait for it.
    /// `[core] locking=false` leaves the repository lock out, and the update
    /// lock is taken all the same. The guard keeps the `[core] fsync` and
    /// lock values this handle was opened with. A long hold makes every
    /// writer that states "update lock" wait under `lock-timeout-secs` and
    /// fail with `LockTimeout`: the immediate ref writes, `write_config`,
    /// `remove_remote_keyring`, `gpg_import_keys`, `regenerate_summary`,
    /// `sign_summary`, `sign_summary_all`, the summary writes of a mirror
    /// pull, `write_commit_detached_metadata`, `sign_commit`,
    /// `delete_signatures`, and the step of `Transaction::commit` that writes
    /// detached metadata and refs, which a pull and the receive commit reach.
    /// When `[core] locking` is on, a prune waits for the whole hold. A
    /// transaction publishes its objects in parallel with the hold.
    pub async fn begin_update(&self) -> Result<UpdateGuard>;

    // --- checkout ---
    // The options arrive by `&mut`: the filter callback runs through an
    // exclusive borrow and the devino cache is populated in place.
    pub async fn checkout_at(&self, opts: &mut CheckoutOptions,
        dest_dir: BorrowedFd<'_>, dest_path: &Path, commit: &Checksum) -> Result<()>;

    // --- immediate ref writes (outside a transaction) ---
    // Each honors `[core] fsync`: the ref file is `fdatasync`-ed and the
    // directory holding it is `fsync`-ed after the rename or the unlink.
    // Each writes under the update lock.
    pub async fn set_ref_immediate(&self, refspec: &str, checksum: Option<&Checksum>) -> Result<()>;
    pub async fn set_collection_ref_immediate(&self, cref: &CollectionRef,
        checksum: Option<&Checksum>) -> Result<()>;
    /// Write `refspec` as a relative symlink to `target`'s ref file.
    pub async fn set_ref_alias_immediate(&self, refspec: &str, target: &str) -> Result<()>;

    // --- maintenance ---
    /// The run holds the repository lock exclusive from end to end, a
    /// `no_prune` dry run and a `static_deltas_only` run included. It reads
    /// `[core] locking` and `[core] lock-timeout-secs`, and it fails with
    /// `Error::LockTimeout` where another holder keeps the lock past the
    /// timeout. With `lock-timeout-secs=-1` the wait has no limit. The hold
    /// excludes every other writer, in this process and in another: a caller
    /// holding a transaction of its own open across the call waits out the
    /// timeout and then fails, and a transaction the process opens while the
    /// run stands waits for the run to finish. When `[core] locking` is on, a
    /// held `UpdateGuard` holds the repository lock shared, so the run waits
    /// for it, and `begin_update` waits for the run.
    pub async fn prune(&self, opts: &PruneOptions) -> Result<PruneStats>;
    pub async fn fsck(&self, opts: &FsckOptions) -> Result<FsckReport>;
    pub async fn traverse_commit(&self, c: &Checksum, depth: i32)
        -> Result<HashSet<ObjectName>>;
    /// Takes the repository lock shared and then the update lock, and holds
    /// both from the read of the previous anchor commit to the removal of
    /// `summary.sig`, so regenerations run one at a time. The anchor commit
    /// commits under that hold. A holder of an `UpdateGuard` that calls this
    /// waits for its own guard until `lock-timeout-secs`. The call takes the
    /// repository lock shared also with no collection id, so, when `[core]
    /// locking` is on, it waits for an exclusive holder of the repository
    /// lock, a caller that holds one itself included. A caller value the dict cannot hold is refused before
    /// any lock.
    pub async fn regenerate_summary(&self, opts: &SummaryOptions) -> Result<()>;
}

/// Held by one caller at a time, across processes and inside the process.
/// `Send + Sync`. While you hold it, write through it: the receive commit and
/// `Repo::regenerate_summary` wait for the guard, and a holder that calls one
/// of them waits for its own guard until `lock-timeout-secs`. Do not commit a
/// ref-writing `Transaction` while you hold it.
pub struct UpdateGuard { /* Arc<the Repo, the locks, the writes in flight, the changed directories> */ }

impl UpdateGuard {
    /// Follows a ref stored as an alias, as `Repo::resolve_ref_tip` does.
    pub async fn read_ref(&self, refspec: &str) -> Result<Option<Checksum>>;
    pub async fn read_collection_ref(&self, cref: &CollectionRef)
        -> Result<Option<Checksum>>;
    /// Each write is atomic and visible when it returns: a tmpfile,
    /// `fdatasync` under `[core] fsync`, and a rename. The guard records each
    /// directory that changed, and `finish` syncs it.
    pub async fn set_ref(&self, refspec: &str, checksum: Option<&Checksum>)
        -> Result<()>;
    pub async fn set_collection_ref(&self, cref: &CollectionRef,
        checksum: Option<&Checksum>) -> Result<()>;
    pub async fn set_ref_alias(&self, refspec: &str, target: &str) -> Result<()>;
    /// The `config` file as it is on disk now. The handle keeps the config it
    /// was opened with.
    pub async fn read_config(&self) -> Result<RepoConfig>;
    pub async fn write_config(&self, keyfile: &KeyFile) -> Result<()>;
    /// Wait until each write of the guard has ended, also a write whose
    /// future was dropped, then run `fsync` on each directory that changed,
    /// once, deepest first, then release both locks. Returns the first error
    /// of the syncs, and both locks are free when it returns. A dropped
    /// `finish` future releases the locks after the syncs.
    pub async fn finish(self) -> Result<()>;
}
// A guard that drops without `finish` runs the syncs synchronously on the
// thread that drops the last reference to its state, hides every error, and
// then releases both locks.

/// Knobs for [`Repo::regenerate_summary`]. Both timestamps default to the
/// current time; setting them makes the output reproducible.
pub struct SummaryOptions {
    pub last_modified: Option<u64>,
    pub metadata_commit_timestamp: Option<u64>,
    /// Keys added to the global metadata dict, each with the `v` it carries.
    /// They follow the standard entries in first-occurrence order; a repeated
    /// key takes its last value, and a key the writer writes in the same run
    /// keeps the writer's value. A repository with a collection id refuses
    /// any key with `Error::Unsupported`.
    pub additional_metadata: Vec<(String, Value)>,
}

/// What a prune keeps. The first nine fields are the tool's; the last three
/// are port extensions the tool has no counterpart for, and their defaults are
/// what the tool does.
pub struct PruneOptions {
    pub refs_only: bool,                  // roots are the refs alone
    pub depth: i32,                       // parents kept: -1 all, 0 the head,
                                          // every other negative the head
    pub no_prune: bool,                   // count, delete nothing, keep the
                                          // commit delete_commit names
    pub delete_commit: Option<Checksum>,  // remove this commit, walk it as gone
    /// Keep no commit older than this count of seconds since the Unix epoch.
    /// `Some` roots the walk on the refs alone and bounds the `parent` edge by
    /// time in place of by `depth`. A ref's own target is kept whatever its
    /// timestamp.
    pub keep_younger_than: Option<u64>,
    /// The branches the run prunes, each named as `Repo::list_refs` and
    /// `Repo::list_remote_refs` name one. Empty prunes every branch. A
    /// non-empty list roots the walk on the refs alone and retains in full
    /// every branch it does not name and `retain_branch_depth` does not name
    /// either. Every value is resolved as a revision, so one naming nothing
    /// fails the prune before any object is removed.
    pub only_branch: Vec<String>,
    /// A depth for one branch, in place of `depth` for it. A non-empty list
    /// roots the walk on the refs alone. The last entry naming a branch decides
    /// it, and an entry of depth 0 leaves the branch at the global `depth`
    /// while still counting as naming it.
    ///
    /// A branch's bound belongs to the commit its ref names: a walk that
    /// reaches that commit over the `parent` edge continues under the ref's own
    /// bound, so a branch cut short cuts every history running through its
    /// head. Where two refs name one commit, the commit is walked under each of
    /// the two bounds and keeps what either of them reaches.
    pub retain_branch_depth: Vec<(String, i32)>,
    /// Delete commit objects alone, leaving the trees they reached where they
    /// stand. The statistics then count commit objects alone.
    pub commit_only: bool,
    /// Delete the static deltas `delete_commit` targets and nothing else.
    /// Requires `delete_commit`; without it the prune fails with
    /// `Error::InvalidFormat`.
    pub static_deltas_only: bool,
    /// Metadata keys naming further commits to keep. Each is read from a
    /// reached commit's own metadata and from its detached metadata; the
    /// value is an `aay` of commit checksums, and each commit it names is
    /// walked as a root of its own. A key holding anything else fails the
    /// prune with `Error::InvalidGcRoot`. Empty by default. The `ostrya` CLI
    /// fills this from `[ex-ostrya] gc-root-metadata-keys`.
    pub gc_root_metadata_keys: Vec<String>,
    /// Whether a commit's `parent` is reachable from it. True by default,
    /// which is the edge `depth` bounds.
    pub traverse_parent: bool,
    /// The classifier that splits the ref space into strong refs and weak
    /// refs. Unset by default, which classifies every ref strong, so a prune
    /// that leaves it unset deletes no ref. A set filter requires `refs_only`;
    /// the two apart fail the prune with `Error::InvalidFormat` before the run
    /// reads anything.
    ///
    /// The filter sees each ref under `refs/heads` by its path below that
    /// directory, and each ref under `refs/remotes` by its `<remote>:<name>`
    /// refspec. A ref under `refs/mirrors` is strong and never reaches the
    /// filter.
    ///
    /// A ref is addressable where the name the listing gave it maps back to
    /// the file it was listed from. A non-addressable ref is strong and never
    /// reaches the filter either. The mapping splits a name at its first `:`,
    /// and the listing builds a remote name by replacing the first `/` of the
    /// path below `refs/remotes` with a `:`, so `refs/remotes/a:b/main` and
    /// `refs/remotes/a/b:main` share the listed name `a:b:main` and only the
    /// second addresses its own file.
    ///
    /// A strong ref roots the walk under the bound `retain_branch_depth`,
    /// `only_branch`, and `depth` give its name. A weak ref roots nothing, so
    /// the branch selection and the time bound have nothing to select for it.
    /// It survives where the walk reaches its commit over some other edge. An
    /// arrival over a `parent` edge gives the commit the bound that weak ref's
    /// own name carries in place of the bound the edge had left; an arrival
    /// over any other edge carries a bound of its own, and the commit expands
    /// under that bound and under the weak ref's bound alike. The run deletes
    /// each weak ref the walk did not reach and names it in
    /// `PruneStats::deleted_refs`.
    ///
    /// A classifier that tests a prefix of the name keeps the meaning it had
    /// where that prefix holds a `/` ahead of any `:`, which matches a local
    /// name alone. A bare segment prefix matches a remote refspec too: `pool`
    /// matches `poolcache:main`, the refspec of a ref of the remote
    /// `poolcache`.
    ///
    /// The callback runs while the run holds the repository lock exclusive, so
    /// it must call no `Repo` method: a transaction from inside it waits out
    /// `[core] lock-timeout-secs` and then fails, or waits with no end where
    /// the value is `-1`.
    pub weak_ref_filter: WeakRefFilter,
}
impl PruneOptions {
    /// Refs alone, no `parent` edge, and the named metadata keys as the extra
    /// roots: what an application recording its own reachability prunes with.
    pub fn gc_roots<I: IntoIterator<Item = S>, S: Into<String>>(keys: I)
        -> PruneOptions;
}

/// A verdict on one ref: its name and the commit it resolves to. True
/// classifies the ref strong, false weak.
pub type WeakRefFilterFn = Arc<dyn Fn(&str, &Checksum) -> bool + Send + Sync>;

/// The ref classifier a prune applies, unset by default, which classifies
/// every ref strong. `Debug` is hand-written over the callback and prints
/// `WeakRefFilter(set)` or `WeakRefFilter(unset)`, so `PruneOptions` keeps its
/// own `Debug` derive.
#[derive(Clone, Default)]
pub struct WeakRefFilter(Option<WeakRefFilterFn>);
impl WeakRefFilter {
    pub fn new<F: Fn(&str, &Checksum) -> bool + Send + Sync + 'static>(f: F)
        -> WeakRefFilter;
    // Over a callback the caller holds, shared with another PruneOptions.
    pub fn from_fn(f: WeakRefFilterFn) -> WeakRefFilter;
}

/// The outcome of a prune run. `Clone`, and not `Copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneStats {
    /// The loose objects considered: the store's total after any
    /// `delete_commit` removal, with detached commit metadata and tombstone
    /// markers left out and static deltas outside it. Under `commit_only` it
    /// counts commit objects alone.
    pub total_objects: usize,
    /// The objects deleted, or under `no_prune` that would be, on the terms
    /// `total_objects` states.
    pub pruned_objects: usize,
    /// The on-disk bytes the objects `pruned_objects` counts freed, or would
    /// free.
    pub freed_bytes: u64,
    /// The weak refs the run deleted, sorted by name in byte order.
    ///
    /// Under `no_prune` it names the refs the run would have deleted, and the
    /// run removes no ref. A ref the compare-and-delete guard skipped is in no
    /// list, because the run left it where it stood. A `static_deltas_only`
    /// run returns before it reads the ref space, so the list is empty
    /// whatever `weak_ref_filter` holds. Where the run fails part way through
    /// the deletions, the refs it already removed stay removed, and this list
    /// goes with the error the caller gets in place of the statistics.
    pub deleted_refs: Vec<String>,
}

/// What a check reads and what it does with a fault. Every field but
/// `mark_partial` is off by default, and `mark_partial` is a port extension
/// the tool has no counterpart for.
#[derive(Debug, Clone)]
pub struct FsckOptions {
    pub mark_partial: bool,               // default true; a port extension
    pub delete: bool,                     // unlink each mismatching object
    pub all: bool,                        // let `add_tombstones` act after a
                                          // walk that found a corrupt object
    pub add_tombstones: bool,             // tombstone a commit whose parent
                                          // commit object is absent
    pub verify_bindings: bool,            // each ref against its commit
    pub verify_back_refs: bool,           // each commit against its refs
}

/// What a check found. `failure` names the one condition that ends a run
/// before the walk finishes; every other fault is in `errors`.
pub struct FsckReport {
    pub reached: FsckPhase,
    pub commits_checked: usize,
    pub commits_partial: usize,           // skipped, already marked partial
    pub objects_checked: usize,           // the objects the walk examined
    pub errors: Vec<FsckError>,           // sorted by object checksum
    pub marked_partial: Vec<Checksum>,
    pub deleted: Vec<ObjectName>,
    pub tombstoned: Vec<Checksum>,
    pub failure: Option<FsckFailure>,
}
impl FsckReport {
    /// No faulty object, no condition that ended the run, and no commit
    /// skipped as already partial.
    pub fn is_ok(&self) -> bool;
}

pub enum FsckPhase { ValidateRefs, ValidateCollectionRefs,
                     EnumerateCommits, VerifyObjects }

pub struct FsckError {
    pub object: ObjectName,
    pub kind: FsckErrorKind,
    pub in_commits: Vec<Checksum>,        // sorted; empty for a ref-phase find
}
pub enum FsckErrorKind {
    Missing,
    ChecksumMismatch { actual: Checksum },
    Corrupt(String),
}

pub enum FsckFailure {
    RefTarget { ref_name: String, commit: Checksum, removed: bool },
    MissingDirTree(Checksum),
    Binding(FsckBindingError),
}
pub struct FsckBindingError { pub commit: Checksum, pub kind: FsckBindingErrorKind }
pub enum FsckBindingErrorKind {
    RefNotBound { ref_name: String, bindings: Vec<String> },
    CollectionMismatch { bound: String, found_under: String },
    BackRefMissing { ref_name: String },
    BackRefMismatch { ref_name: String },
    BackCollectionRefMissing { collection_id: String, ref_name: String },
    BackCollectionRefMismatch { collection_id: String, ref_name: String },
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
    /// The parent and the root checksums alone, with the checks of `parse`
    /// for those fields. The metadata, subject, and body are not parsed.
    pub fn parse_link(data: &[u8]) -> Result<CommitLink>;
}

pub struct CommitLink {
    pub parent: Option<Checksum>,
    pub root_dirtree: Checksum,
    pub root_dirmeta: Checksum,
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

/// One collection-qualified ref. `local` says the ref lives under
/// `refs/heads`, qualified by the repository's own collection id, rather than
/// under `refs/mirrors`.
pub struct CollectionRefEntry {
    pub collection: String,
    pub name: String,
    pub commit: Checksum,
    pub local: bool,
}

/// Whether a refspec names a path under `refs/`: a ref name, optionally
/// preceded by a `<remote>:` prefix. A refspec that would leave the tree is
/// `Error::InvalidRefspec`, holding the refspec as given, which is the one
/// error a caller reporting a refused name needs the name from. Every ref
/// write and every resolution applies the same rule, which is
/// `ostrya_core::is_refspec`.
pub fn validate_refspec(refspec: &str) -> Result<()>;

/// Streaming reader over a regular file's payload: raw for the bare family,
/// on-the-fly raw-DEFLATE inflate for archive (a streaming decoder over
/// bounded chunks), empty for symlinks. Streams from `rt::FileReader`, with
/// the length on disk as the length hint: the payload size for the bare
/// family, and for archive the length of the compressed stream, which the
/// open reads with one `fstat` in the same blocking-pool call. The inflate
/// input buffer is the stream length plus 1 byte, at most 16 KiB. Implements `futures_io::AsyncRead`
/// unconditionally and `tokio::io::AsyncRead` under the `tokio` feature, so
/// neither backend needs a caller-side adapter.
pub struct ContentReader { /* empty | rt::FileReader | inflate adapter */ }
```

## Runtime backend and streaming I/O

The runtime backend is feature-gated behind the internal `ostrya-rt` crate
(`smol` by default, `tokio` optional; policy in `port-plan.md`, "Async
model"). It is the only crate that knows which backend is compiled.

```rust
// ostrya-rt -- the whole surface.
pub async fn unblock<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static) -> T;   // the pool entry for awaited work
/// Runs `f` on the blocking pool as a detached task and returns at once.
/// Under tokio, a call outside the context of a runtime runs `f` inline.
pub fn unblock_detached(f: impl FnOnce() + Send + 'static);

pub fn block_on<F: Future>(future: F) -> F::Output; // test/doctest driver

/// Async file over an already-open fd (`smol::fs::File` or
/// `tokio::fs::File` underneath). Opens happen through rustix (fd-relative
/// `openat`); this type only streams. Presents the `futures-io` traits
/// under both backends; the tokio traits additionally under the `tokio`
/// feature.
pub struct File;    // From<std::fs::File> / From<OwnedFd> (Unix only);
                    // AsyncRead + AsyncWrite + AsyncSeek + Send + Sync
impl File {
    pub async fn sync_all(&mut self) -> std::io::Result<()>;
    pub async fn sync_data(&mut self) -> std::io::Result<()>;
    pub async fn into_std(self) -> std::fs::File;   // settles pipelined ops
}

/// Read-only async file over an already-open fd. It streams from the
/// current offset to the end of the file and does no seek. Under smol it is
/// `smol::Unblock::with_capacity`, with a read-ahead of 256 KiB. Under tokio
/// it is a `tokio::fs::File`, which reads at most the caller's buffer and
/// at most 2 MiB in one blocking-pool read. Presents `futures_io::AsyncRead`
/// alone. A read into an empty buffer gives 0 and keeps the stream. A
/// dropped reader closes its fd on the pool thread after the read in flight
/// returns.
pub struct FileReader;  // From<std::fs::File> / From<OwnedFd> (Unix only);
                        // AsyncRead + Send + Sync
impl FileReader {
    /// Read-ahead of len + 1 bytes, held between 4 KiB and 256 KiB. Under
    /// tokio the hint sets the maximum buffer size only when that number is
    /// below 256 KiB. A `len` below the real length still reads the whole
    /// file, in runs of at least 4 KiB.
    pub fn with_len_hint(file: std::fs::File, len: u64) -> FileReader;
}

pub struct Timer;                       // Timer::after(Duration)
pub struct Deadline;                    // a restartable inactivity window
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>;
pub struct Command;                     // helper process: output() for gpg signing,
impl Command {                          //   spawn() for a long-lived child
    pub async fn output(&self, input: &[u8]) -> std::io::Result<std::process::Output>;
    pub fn spawn(&self) -> std::io::Result<Child>;  // stdin/stdout piped, stderr inherited
}
pub struct Child;                       // take_stdin(), take_stdout(), async wait()
pub struct ChildStdin;                  // futures_io::AsyncWrite; close() gives EOF
pub struct ChildStdout;                 // futures_io::AsyncRead
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
    /// A streaming reader over a metadata object's raw bytes. The bound is
    /// `MAX_METADATA_SIZE`, the bound `load_object_bytes` holds, and the
    /// reader holds it without buffering the object whole. It carries no
    /// checksum verification, which matches `load_object_bytes`.
    pub async fn metadata_reader(&self, ty: ObjectType, c: &Checksum)
        -> Result<MetadataReader>;
}

/// The size bound both metadata readers hold, 128 MiB.
pub const MAX_METADATA_SIZE: u64;

/// An async reader over a metadata object's raw bytes. It implements
/// `futures_io::AsyncRead` unconditionally and `tokio::io::AsyncRead` under
/// the `tokio` feature.
pub struct MetadataReader { /* rt::FileReader + the running total */ }
```

`metadata_reader` holds the bound at two points, the two points
`load_object_bytes` holds it at: an `fstat` at the open refuses an object
already above the bound, and a running total refuses an object that grows
under the reader. The reader hands the caller at most `MAX_METADATA_SIZE`
bytes, and the refusal is terminal, so every later read repeats the error.

The owned `DirTree` and `DirMeta` values returned by `load_dirtree` and
`load_dirmeta` are built through `to_owned`. Callers that only traverse --
checkout, pull object scanning, `RepoTree::read_dir` -- hold the object
buffer and iterate the view. `Commit` has no view type: commit objects are
read a handful at a time and their fields are retained.

## RepoTree traversal (read-only GFile analogue)

```rust
pub struct RepoTree { /* repo handle + dirtree/dirmeta checksums, lazy */ }
impl RepoTree {
    /// A leading `/` and every `.` component are ignored. A `..` component
    /// names an entry that no directory holds, so the walk resolves the
    /// components ahead of it and then yields `Ok(None)`, which is the
    /// answer the tool gives such a path.
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

    /// Replaces `[core] per-object-fsync` for this transaction alone: each
    /// content object's file is synced as it is staged, and no metadata object.
    /// No effect while fsync is off. Changes durability and no stored byte.
    pub fn set_per_object_fsync(&mut self, enabled: bool);

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
    // `.commitmeta` are both durable before a ref names them. A pull stages
    // the `.commitmeta` bytes it copies as a file in the staging directory,
    // and `commit` renames the file into `objects/` at the same step.

    /// Queues the `a{sv}` dict a commit's `.commitmeta` holds, replacing what
    /// the repository stores. The last dict queued for a checksum wins.
    pub fn set_commit_detached_metadata(&self, c: &Checksum, meta: Value);

    /// Signs a commit this transaction staged and appends the signature to its
    /// queued dict, starting from the queued dict, else the stored one, else an
    /// empty one. Nothing reaches the filesystem here, so a signature that
    /// cannot be produced fails the transaction with no object published and no
    /// ref moved.
    pub async fn sign_commit(&self, c: &Checksum, signer: &dyn Signer) -> Result<()>;

    /// Publishes the staged objects with no update lock held. When the
    /// transaction writes a ref, a removal included, or detached metadata, it
    /// then takes the update lock and writes the detached metadata and the
    /// refs under it, in one blocking closure that owns the hold, the
    /// repository lock, and the staging directory. So a dropped future cannot
    /// release a lock or remove a staged file while those writes run, and the
    /// writes complete. A transaction
    /// that writes neither takes no update lock. A `LockTimeout` at that step
    /// leaves the published objects, no detached metadata, and no ref.
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
/// hit returns the existing id). Dropping without `finish`, or a `finish`
/// that fails before the object is staged, removes the staged temporary.
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
    /// The existing subdirectory named `name`, hydrating a lazy committed
    /// child in place. It creates nothing. An absent name is `PathNotFound`
    /// and a file of that name is `NotADirectory`, and both carry the bare
    /// entry name, since this layer holds no path. A symlink is a file entry
    /// in this model, so a symlink to a directory takes `NotADirectory` and
    /// the target is never read.
    pub async fn subtree(&mut self, name: &str) -> Result<&mut MutableTree>;
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
`user.*`). Merged directories take dirmeta from the upper inode. Every
xattr whose name starts with `trusted.overlay.` or `user.overlay.` is
stripped from every ingested file, symlink, and directory, dirmeta
included; every other xattr, including one that merely contains
`overlay`, is kept. Entries carrying `overlay.metacopy` or
`overlay.redirect` are errors naming the feature, since such entries
are not self-contained. An upper directory over an mtree symlink is a
malformed-changeset error: the VFS resolves symlinks at lookup, so a
genuine upperdir never contains one relative to its base. The modifier
callbacks see real entries only, never whiteouts or opaque markers; the
xattr strip runs before they see an entry, and an xattr callback can
still write a stripped name back. A filter `Skip` on an upper entry
leaves the base version in place.

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
    /// Create `path` and any missing ancestor. A symlink at the last
    /// component is `EntryExists`, whatever it points at, since the check
    /// precedes the walk of its target; a regular file there is
    /// `NotADirectory`. A symlink at an earlier component resolves to its
    /// target directory, and a `..` hop after a symlink makes that symlink
    /// an earlier component. `mkdir -p` accepts a symlink to a directory at
    /// the last component.
    pub async fn make_dir_all(&self, path: &Path, meta: &DirMeta) -> Result<()>;
    /// Create the directory, or reuse an existing one and stamp `meta`
    /// onto it. Stages the dirmeta only when it creates the directory or
    /// the recorded dirmeta differs, and restamps a lazy committed child
    /// in place without hydrating it. A path with no components names the
    /// tree root, which takes the same comparison and the same stamp.
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

/// The dirmeta policy for one directory in a merge: the merge root
/// (`root_dirmeta`) or a directory a followed left-side symlink lands in
/// (`symlink_target_dirmeta`). Reconcile is the default and treats the
/// directory like any other directory in the merge; KeepLeft ignores the
/// dirmeta the right side carries for it, so a left directory that carries
/// none keeps none, and a tree that holds a directory with no dirmeta
/// cannot be written. Every other directory the merge reaches reconciles
/// under either setting.
#[derive(Default)]
pub enum RootDirmeta { #[default] Reconcile, KeepLeft }

#[derive(Default)]
pub struct MergeOptions {
    pub allow_overwrite: bool,
    pub follow_symlinks: bool,
    pub root_dirmeta: RootDirmeta,
    /// How the merge treats the dirmeta of a directory reached by following
    /// a left-side symlink (`follow_symlinks`). It applies at every such
    /// landing the recursive merge reaches, independent of `root_dirmeta`,
    /// which governs the merge root alone, a `merge_at` base that is itself
    /// a symlink included. `allow_overwrite` does not override KeepLeft.
    pub symlink_target_dirmeta: RootDirmeta,
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
`Reconcile` and keeps the dirmeta it has under `KeepLeft`. `base` resolves
through symlinks before the merge starts, so a `base` that is itself a
symlink is the merge root and takes `root_dirmeta`. A directory a followed
left-side symlink lands in takes `symlink_target_dirmeta`, at every such
landing the recursion reaches, however deep the symlink sits; a chain of
symlinks resolves to a real directory first, so the landing is never itself
a symlink. Every other directory the merge reaches reconciles under either
setting. A landing that carries no dirmeta keeps none under `KeepLeft`, and
the tree that holds it cannot be written. A merge that drops a
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
on a file or symlink, and takes a path with no components -- `.`, `/`,
and the empty path -- as the tree root, which it stamps under the same
comparison; `make_dir_all` applies its `DirMeta` to the
directories it creates, leaves existing ones untouched, and refuses a
symlink at the last component with `EntryExists`, since that component is
the directory it creates, and the directories the walk created before the
refusal stay in the tree; `clear_dir`
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
    pub enable_fsync: bool,          // default false; `ostrya checkout`
                                     // resolves it from `[core] fsync` and
                                     // `--fsync`
    pub force_copy: bool,
    pub require_hardlinks: bool,     // refuse an entry a copy would materialize
    pub bareuseronly_dirs: bool,     // a created directory takes `mode & 0o775`
    pub process_whiteouts: bool,
    pub process_passthrough_whiteouts: bool,
    pub devino_cache: Option<DevInoCache>,
    pub filter: Option<CheckoutFilterFn>,
}
```

## Signing

The signing engines are items of the `ostrya-sign` crate: the two traits and
their futures, `VerifyOutcome`, `SignatureInfo`, the dummy, ed25519, and spki
engines, `GpgSigner`, `SignKeys`, the key reader, `append_signature`, and the
crate's `Error` and `Result`. `ostrya` re-exports each one except the spki
engines and `GpgSigner` at its path under `ostrya::sign`. The spki engines are
at `ostrya::spki` and `GpgSigner` at `ostrya::gpg`. The engines and traits are
also at the crate root. `GpgVerifier` and
the system key store readers are items of `ostrya`.

Both traits are object-safe and taken as `&dyn`, so the asynchronous method
returns a boxed future rather than being an `async fn`. The two futures give
`ostrya_sign::Result`, so a `Signer` or a `Verifier` of another crate fails
with `ostrya_sign::Error`.

```rust
// ostrya-sign
#[non_exhaustive]
pub enum Error {
    Signature(String),                  // a signer or a verifier failed
    InvalidFormat(String),              // append_signature over a bad dict
    Core(ostrya_core::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

// ostrya: each variant maps to the variant of the same name; a variant the
// conversion does not name maps to ostrya::Error::Signature with its message.
impl From<ostrya_sign::Error> for ostrya::Error;

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
impl Ed25519Verifier {
    pub fn new(trusted: impl IntoIterator<..>, revoked: impl IntoIterator<..>)
        -> Result<Ed25519Verifier>;
    pub fn from_sign_keys(keys: SignKeys) -> Result<Ed25519Verifier>;
    /// No key was given, or the revoked set removed every one.
    pub fn is_empty(&self) -> bool;
}
// SpkiVerifier also has these three methods.
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
    /// Signs with no lock held, then reads, merges, and writes the
    /// `.commitmeta` under the update lock, so two processes that sign one
    /// commit keep both signatures.
    pub async fn sign_commit(&self, c: &Checksum, signer: &dyn Signer) -> Result<()>;
    pub async fn verify_commit(&self, c: &Checksum, verifiers: &[&dyn Verifier])
        -> Result<VerifyOutcome>;
    /// Append a signature over the repository's `summary` bytes to
    /// `summary.sig`. The batch of one signer.
    pub async fn sign_summary(&self, signer: &dyn Signer) -> Result<()>;
    /// The batch takes the update lock before it reads `summary` and holds it
    /// until `summary.sig` is written.
    /// Append one signature per signer, in slice order, reading `summary` and
    /// `summary.sig` once and replacing `summary.sig` in one write. A signer
    /// that fails stops the batch before the write. An empty slice writes
    /// nothing and takes no lock.
    pub async fn sign_summary_all(&self, signers: &[&dyn Signer]) -> Result<()>;
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
    pub async fn secret_key_fingerprints(&self) -> ostrya_sign::Result<Vec<String>>;
}

/// Append `signature` to the engine's `aay` array in an `a{sv}` dict, and
/// create the entry when it is absent.
pub fn append_signature(dict: &mut Value, metadata_key: &str, signature: Vec<u8>)
    -> ostrya_sign::Result<()>;

/// One key of a remote's trusted keyring, as its certificate states it.
pub struct GpgKey {
    pub fingerprint: String,
    pub created: Option<u64>,
    pub user_ids: Vec<String>,
}

impl Repo {                                   // feature = "verify-gpg"
    /// Add the certificates `keys` holds to `<remote>.trustedkeys.gpg`, and
    /// report how many the keyring did not already hold. With `key_ids`
    /// non-empty only the keys those selectors name are imported. The keyring
    /// keeps the packet stream it already held and carries the packets of each
    /// added certificate as `keys` wrote them, with the Trust packets dropped.
    /// It is written in the binary form, so an armored keyring keeps its
    /// packets and loses its armor. A certificate for a key the keyring
    /// already holds is not merged in, so a new user id or a new binding for a
    /// held key reaches the keyring through `Repo::remove_remote_keyring` and
    /// a fresh import. Two statements are the exceptions, and each replaces the
    /// held certificate, which rewrites the keyring and drops the Trust packets
    /// it carried: a key revocation that verifies under the key it revokes, and
    /// a key expiry later than the held certificate states, an absent expiry
    /// counting as later than any instant. The key is still counted as one the
    /// keyring already held. `keys` and the keyring the remote already holds
    /// reach one keyring reader, so a keyring carrying bytes past its last
    /// framed packet takes no import, and such an import is refused by the
    /// name of the keyring. The read, the merge, and the write of the keyring
    /// run under the update lock.
    pub async fn gpg_import_keys(&self, remote: &str, keys: &[u8], key_ids: &[String])
        -> Result<usize>;
    /// The keys that keyring holds. An absent keyring holds none.
    pub async fn gpg_list_keys(&self, remote: &str) -> Result<Vec<GpgKey>>;
}
```

The key reader of `ostrya-sign` reads over `std::fs`. `read_key_file` opens
a path, and gives `None` where no file is there. `read_key_source` reads an
open file. Both read only a regular file and only up to the ceiling the caller
gives, `MAX_KEY_FILE` (one mebibyte) for a key file, and refuse a source over
the ceiling by its own name. On Unix the open carries `O_NONBLOCK`, so a fifo
does not hold the open and the type check refuses it. `key_text` reads the
bytes as UTF-8 text. `SignKeys` holds the trusted and the revoked keys as
bytes.

The system key store readers are items of `ostrya`. `load_sign_keys` and
`load_sign_keys_from` read the ed25519 base64-per-line files and the
`trusted.<type>[.d]` / `revoked.<type>[.d]` directory convention. GPG keyring
files, binary and armored, load through the constructors of `GpgVerifier`.
The extension trait `FromSystemKeys` builds a verifier from the system store:

```rust
pub trait FromSystemKeys: Sized {
    fn from_system_keys() -> ostrya::Result<Self>;
}
impl FromSystemKeys for Ed25519Verifier;     // trusted.ed25519, revoked.ed25519
impl FromSystemKeys for SpkiVerifier;        // feature = "sign-spki"
```

`GpgVerifier` is behind the `verify-gpg` feature, together with `GpgKey`,
`Repo::gpg_import_keys`, and `Repo::gpg_list_keys`, which manage the
verification trust set over the `pgp` crate and spawn no process. `GpgSigner` is
behind `sign-gpg`, which turns on `verify-gpg` with it and is the one path that
runs the `gpg` binary. A constructor of `GpgVerifier` parses each keyring into
certificates as it loads it, so a keyring the parser rejects fails the
construction. One keyring is held to four mebibytes and to 256 certificates,
and a GnuPG keybox is refused by the name of the file or the blob that carries
it; each refusal states the cap or the cause it names.

`Verifier::verify` for `GpgVerifier` answers in the process on the blocking
pool, over the `pgp` crate (rPGP). It spawns no process. One stored blob is
held to one mebibyte and to 64 signature packets. The port owns the trust and
validity policy: issuer resolution over primary keys and subkeys, the subkey
binding and its embedded primary-key binding, key expiry, revocation, the
signature class, and the digest policy. Issuer resolution answers with every
certificate that holds the key. A revocation any of them carries refuses the
signature. Two exports of one certificate are read as one certificate, so the
key expiry the newest self-signature of either export states answers; across
certificates holding different primary keys the key expires at the earliest
instant any of them states. The keyring load order decides none of the three.
The first certificate that answers supplies the reported fingerprints and user
id.

A `SignatureInfo` carries one of three field sets, and which one it carries
states how far the verification reached.

- A signature a resolved key verifies reports the signing key in
  `fingerprint`, the certificate that holds it in `primary_fingerprint`, that
  certificate's user id in `user_name` and `user_email`, the instants and the
  algorithm names the signature packet states, and the answer of the validity
  policy in `valid`. `expires` is the absolute instant the signature's own
  expiry names, which is the creation time plus the lifetime the packet
  states, and it is absent where the packet states no lifetime.
- A signature whose issuer no loaded certificate holds reports what its own
  packet states: the issuer fingerprint it names, or no fingerprint where the
  packet names none, its creation instant, and the two algorithm names, with
  `key_missing` set. A signature the policy
  refuses for its class, for its digest algorithm, or for a signing subkey the
  primary key did not cross-certify reports those same fields with
  `key_missing` clear. Neither set names a user id.
- A signature whose issuer resolved and whose cryptography failed reports the
  resolved signing key, the certificate that holds it, and that certificate's
  user id, and states no instant and no algorithm name, since nothing the
  packet claims was checked. `ostrya sign --delete` reaches such a signature
  under the key id or the whole fingerprint of either key.

`valid` on the outcome is the OR over the per-signature flags, so one good
signature among several makes the outcome valid. A blob the parser reads no
signature out of yields one record of its own, so the record count follows the
stored blob count. A signature past its own expiry is reported not valid and
carries no field of its own.

## Fetcher

The HTTP client pull is built on. The fetcher is the `ostrya-fetch` crate.
`ostrya` re-exports the crate as `ostrya::fetch`, and its public request and
response types at the crate root of `ostrya`. The fetcher has its own error
type, `ostrya::fetch::Error`, and every `Error::` item this section names is a
variant of that type. One `Fetcher` serves one remote: it holds the
mirrors, headers, credentials, and TLS configuration, pools connections per
endpoint, and admits a bounded number of requests at a time in priority order. A
request names a `Target`: a path under every mirror's base URL, or an absolute
`http` or `https` URL of its own, which is served from that URL's origin and
consults no mirror. A request carries headers and credentials of its own as
well, merged over the fetcher's, one of a name replacing the fetcher's.
Protocol selection is the TLS handshake's -- ALPN offers `h2` and `http/1.1`.
Two deadlines bound one attempt's cost: `connect_timeout` over opening a
connection, and `progress_timeout` over a response delivering bytes, restarted
whenever bytes arrive. A body that stalls fails the read with
`io::ErrorKind::TimedOut`. `low_speed`, off by default, adds a third: the rate
is sampled once a second as the bytes of the last five seconds divided by
five, and a transfer fails when the rate stays at or below `limit` for `time`
without a break. A response head has to arrive within `time` of the start of the
attempt, and the rate of a body is measured from its first read. A body below
the rate fails the read with `io::ErrorKind::TimedOut` as well. Inside the
crate, a pull reads every body through a refetch: a body that fails in transit
is fetched again from its first byte, starting again at the first mirror, and
each refetch spends one repeat of `max_retries`. A body refused for its content
is not fetched again. `fetch_timeout` bounds the mirror rounds and the retries
together, from admission to the response head, which is what caps how
long one fetch holds an admission permit. A credential is sent to every mirror,
so `basic_auth` and an `Authorization`, `Proxy-Authorization`, or `Cookie` entry
in `headers` require every mirror to be `https`; a cleartext mirror alongside one
fails `Fetcher::new`. A request whose merged headers carry a credential is
refused before admission when a destination it may reach is cleartext, which
`allow_cleartext_credentials` admits. A `Host` header, and a header the
connection layer sets -- `Content-Length`, `Transfer-Encoding`, `Connection`,
`Keep-Alive`, `Proxy-Connection`, `TE`, `Trailer`, `Upgrade`, `Expect` -- is
refused at both layers. A URL whose authority names a port the URL parser
cannot read is refused, and a host is one origin whichever case it is written
in. Every request carries `Accept-Encoding: identity` and asks for no content
coding, the bytes a fetch delivers being the ones the remote stores; an
`Accept-Encoding` entry at either layer replaces it and changes what the
request asks the server for. A 200 whose `Content-Encoding` names a coding
other than `identity`, or whose `Transfer-Encoding` names a coding other than
`chunked`, fails the attempt with `Error::ContentEncoded`, whichever layer
asked for the coding. A caller that wants a coded body decodes it outside the
fetcher.

A redirect is followed. A 301, 302, 303, 307, or 308 sends one attempt on to
the URL its `Location` names, up to `max_redirects` hops; a limit of zero
follows nothing, and each of those statuses is then a definitive answer of its
own. An attempt that has followed the limit and is sent on to another URL fails
with `Error::RedirectLimit`, and one that meets a redirect status naming no URL
reports that status whatever the hop count. A fetch is a GET, so none of the
five changes the method of the hop that follows it. An upload follows a 307 or
a 308 alone, for a body given whole, with the method kept and the bytes sent
again. `Location` is resolved against the URL of
the response that carried it, so it reads as an absolute URL, a relative one, or
a scheme-relative one. The resolution normalizes what it produces, where a
`Target::Url` reaches the wire as the caller wrote it: a dot segment is resolved
away, a backslash reads as a path separator, a tab and a newline are removed, a
character a path or a query may not carry is percent-encoded, an IPv4 or an IPv6
host is canonicalized, and a fragment is dropped. A scheme other than `http` or
`https`, and a hop from `https` to `http`, are refused with `Error::Fetch`
naming both URLs; a hop onto a TLS origin is refused the same way on a fetcher
that holds no trust anchors, and a hop from `http` to `https` is followed. A
credential -- `basic_auth`, or an `Authorization`, `Proxy-Authorization`, or
`Cookie` header at either layer -- and a configured client certificate reach
the origin the route named and a hop at that same origin, and no other; a
credential dropped for a hop stays dropped for the rest of the attempt. Every
other header reaches every hop. An intermediate body is discarded the way an
unsuccessful one is, `max_size` is compared against the response that answers
alone, the validators reach every hop, and every diagnostic names the URL of the
response that answered. The hop count belongs to one attempt, so a retryable
status on a hop makes the whole attempt retryable and the round that repeats it
starts again from the destination the route named.

`proxy` states which proxy an origin is reached through, and it defaults to the
one the process environment names. `Proxy::Environment` reads `http_proxy` for
an `http` origin, `https_proxy` for an `https` one, `all_proxy` for either
where the scheme-specific variable is unset, and `no_proxy` for the exemptions;
`Proxy::Variables` states those same variables in the options, and
`Proxy::Url` names one proxy for every origin and reads no exemption.
Every name is read in upper case as well, `HTTP_PROXY` excepted, a CGI gateway
handing a request header called `Proxy` on under that name. Lower case wins
over upper case and an empty value counts as unset. A proxy URL is
`http://host[:port]`, port 80 by default, with no path other than `/`, no
query, and no fragment; userinfo is percent-decoded and sent as
`Proxy-Authorization: Basic`, and anything else fails `Fetcher::new` with
`Error::Unsupported` naming the value without its userinfo. A `no_proxy` entry
matches the host text of the URL, ASCII case ignored, and never the address the
host resolves to: it matches a host it equals or a host that ends with a `.`
and the entry, one leading `.` on the entry stripped first, and it may carry
`:port` to match that port alone. An entry left naming no host exempts nothing.
`*` as a whole entry exempts every host and is the one wildcard the list reads,
so `*.example.com` is a host text no origin holds, and an entry in CIDR
notation names no network, which is where this parts from curl 7.86 and later.
Every form is resolved once, by `Fetcher::new`.

A cleartext origin behind a proxy is reached over a connection to the proxy,
carrying the absolute-form target and the origin's own `Host` header; such a
connection speaks HTTP/1.1 and pools under the proxy. A TLS origin behind a
proxy is reached over a `CONNECT` tunnel naming `host:port`, after which the
handshake, the ALPN selection, and the pool entry are a direct connection's; a
byte arriving before the client speaks fails the connect. A non-2xx answer to
`CONNECT` is retryable and a 407 is definitive, both `Error::Fetch` naming the
proxy, and `connect_timeout` bounds the proxy connect, the `CONNECT` exchange,
the TLS handshake, and the HTTP handshake together. The proxy credential
belongs to the connection layer: it reaches the proxy alone, it is no part of
the merged header list, and a tunnel carries nothing of it. A
`Proxy-Authorization` header a caller sets keeps its own meaning, and on a
proxied cleartext request it replaces the fetcher's proxy credential. The proxy
decision is made per hop from that hop's origin, and a cleartext origin is
cleartext however it is reached.

```rust
pub struct FetcherOptions {
    pub mirrors: Vec<String>,             // base URLs, tried in order; a query
                                          // string, userinfo, or an unreadable
                                          // port is rejected; empty serves
                                          // Target::Url requests alone
    pub headers: Vec<(String, String)>,   // an Authorization, Proxy-Authorization,
                                          // or Cookie entry needs https mirrors;
                                          // a Host or connection-layer name is
                                          // rejected; a User-Agent or
                                          // Accept-Encoding entry replaces the
                                          // one the fetcher sets
    pub basic_auth: Option<BasicAuth>,    // needs https mirrors
    pub tls: TlsOptions,                  // trust roots, client identity
    pub proxy: Proxy,                     // default Proxy::Environment
    pub http2: bool,                      // default true
    pub max_retries: u32,                 // default 5
    pub max_redirects: u32,               // default 10; 0 follows nothing
    pub max_outstanding: usize,           // default 8
    pub connect_timeout: Duration,        // default 30s: connect + TLS + handshake
    pub progress_timeout: Duration,       // default 60s: silence, not transfer time
    pub low_speed: Option<LowSpeed>,      // default None; a zero in either
                                          // field is rejected
    pub fetch_timeout: Option<Duration>,  // default 300s: mirrors and retries
                                          // together, up to the response head
}

/// The slowest transfer a fetch accepts: a rate, sampled once a second over
/// the last five seconds, that stays below `limit` bytes per second for
/// `time` fails the transfer.
pub struct LowSpeed { pub limit: u32, pub time: Duration }

#[non_exhaustive]
pub enum TrustRoots {
    System,                           // the certificates the host trusts
    Pem(Vec<u8>),                     // exactly this PEM blob
    DangerousAcceptAnyChain,          // the chain as presented: no trust
                                      // anchor, no expiry check, no key-usage
                                      // check, and no trust store read; the
                                      // host name check is kept
    DangerousAcceptAny,               // the name check dropped as well
}
/// A client certificate and its key. The key is PEM, and the first section
/// whose armor label names a private key is the one read. A `PRIVATE KEY`,
/// `RSA PRIVATE KEY`, or `EC PRIVATE KEY` section is read as it is, and an
/// `ENCRYPTED PRIVATE KEY` section is PKCS#8 under PBES2 that
/// `key_passphrase` decrypts on the blocking pool. A passphrase set for a key
/// section that carries no encryption is refused, as are the legacy OpenSSL
/// traditional encrypted PEM and a key under PKCS#5 PBES1. The `Debug`
/// rendering states the key by its length and the passphrase by whether it is
/// set.
pub struct ClientIdentity {
    pub cert_chain_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub key_passphrase: Option<String>,
}
pub struct TlsOptions { pub roots: TrustRoots, pub client_identity: Option<ClientIdentity> }

/// Which proxy an origin is reached through. The `Debug` rendering leaves the
/// userinfo of a proxy URL out.
pub enum Proxy {
    None,                             // connect directly, whatever the
                                      // environment says
    Environment,                      // the default: http_proxy, https_proxy,
                                      // all_proxy, no_proxy, read once at
                                      // construction
    Variables(Vec<(String, String)>), // the same variables, stated here
    Url(String),                      // one http:// proxy for every origin,
                                      // userinfo sent as
                                      // Proxy-Authorization: Basic
}

pub enum Priority { Low, Normal, High }
pub enum Protocol { Http11, Http2 }

/// The server's own validator strings, replayed to make a fetch conditional.
pub struct Validators { pub etag: Option<String>, pub last_modified: Option<String> }

/// What a request names. A path is served under every mirror; a URL is served
/// from its own origin, and the mirror list is not consulted.
pub enum Target<'a> { Path(&'a str), Url(&'a str) }

pub struct FetchRequest<'a> {
    pub target: Target<'a>,               // a path is appended to each mirror's
                                          // base path as written and holds no
                                          // query and no fragment; a URL sends
                                          // its query as written and holds
                                          // neither a fragment nor userinfo
    pub priority: Priority,
    pub validators: Option<&'a Validators>,
    pub max_size: Option<u64>,
    pub headers: &'a [(String, String)],  // merged over the fetcher's; one of
                                          // the same name replaces it, the
                                          // User-Agent and Accept-Encoding the
                                          // fetcher sets included
    pub basic_auth: Option<&'a BasicAuth>, // replaces the fetcher's for this
                                          // one request
    pub allow_cleartext_credentials: bool, // default false: a credential bound
                                          // for an http origin is refused
}

/// Credentials for HTTP basic authentication. The `Debug` rendering holds the
/// user name and a fixed word in place of the password.
pub struct BasicAuth { pub user: String, pub password: String }

impl<'a> FetchRequest<'a> {
    // A normal-priority, unconditional, uncapped request carrying the
    // fetcher's headers and credentials.
    pub fn path(path: &'a str) -> FetchRequest<'a>;
    pub fn url(url: &'a str) -> FetchRequest<'a>;
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
    // the blocking pool when a fetch can open a handshake: a mirror is https,
    // the mirror list is empty, or max_redirects is above 0. A fetcher whose
    // mirrors are all http and that follows no redirect reads no store and
    // holds no anchors. A store holding no certificate fails the constructor
    // when a mirror is https, and when the mirror list is empty, since a
    // request may then name an https URL; a fetcher whose mirrors are all
    // cleartext builds without anchors, and a fetch of a TLS destination over
    // it is refused before admission. Either
    // bypass variant reads no store, so the constructor reaches no file and no
    // blocking pool and an https mirror needs no anchors. Both keep the
    // handshake signature check.
    // Clone, Send + Sync.
    pub async fn new(options: FetcherOptions) -> Result<Fetcher>;
    pub async fn fetch(&self, request: FetchRequest<'_>) -> Result<Fetched>;
    pub async fn upload(&self, request: UploadRequest<'_>) -> Result<Uploaded>;
}

/// An upload body: given whole, which declares `Content-Length` and is sent
/// again on a followed 307 or 308, or streamed through a channel. Send + Sync.
pub struct UploadBody { /* ... */ }
impl UploadBody {
    pub fn bytes(bytes: Vec<u8>) -> UploadBody;   // no copy
    pub fn channel() -> (UploadBody, UploadWriter);
}
impl From<Vec<u8>> for UploadBody {}

/// The writing end of a channel body; implements `futures-io` `AsyncWrite`
/// (and the tokio trait under the `tokio` feature). Send + Sync.
pub struct UploadWriter { /* ... */ }

pub enum UploadMethod { Post /* default */, Delete /* no body */ }

/// `Authorization: Bearer TOKEN`, token68 syntax. The `Debug` rendering holds
/// no token.
pub struct BearerToken { pub token: String }

pub struct UploadRequest<'a> {
    pub target: Target<'a>,
    pub method: UploadMethod,
    pub body: UploadBody,
    pub priority: Priority,
    pub max_response: u64,                // default 2 MiB, for every status
    pub headers: &'a [(String, String)],
    pub basic_auth: Option<&'a BasicAuth>,
    pub bearer_token: Option<&'a BearerToken>, // refused beside basic_auth or
                                          // an Authorization header
    pub allow_cleartext_credentials: bool,
    pub response_timeout: Option<Duration>, // None: progress_timeout
}

impl<'a> UploadRequest<'a> {
    pub const DEFAULT_MAX_RESPONSE: u64 = 2 * 1024 * 1024;
    pub fn path(path: &'a str, body: UploadBody) -> UploadRequest<'a>;
    pub fn url(url: &'a str, body: UploadBody) -> UploadRequest<'a>;
}

/// The answer to an upload, for every final status. Send + Sync.
pub struct Uploaded { /* ... */ }
impl Uploaded {
    pub fn status(&self) -> u16;
    pub fn headers(&self) -> &hyper::HeaderMap;
    pub fn url(&self) -> &str;            // the URL that answered
    pub fn protocol(&self) -> Protocol;
    pub fn into_body(self) -> Body;       // capped at max_response
}

// ostrya-fetch, re-exported as ostrya::fetch
#[non_exhaustive]
pub enum Error {
    Fetch(String),                              // setup or transport failure
    HttpStatus { status: u16, url: String },    // every mirror refused
    RedirectLimit { url: String, hops: u32 },   // max_redirects reached
    FetchTooLarge { limit: u64 },               // declared length over the cap
    ContentEncoded { url: String, encoding: String },
    Unsupported(String),                        // unusable proxy or URL scheme
    UploadInterrupted { url: String, message: String }, // failed after sent
}
pub type Result<T> = std::result::Result<T, Error>;

// ostrya: each variant maps to the variant of the same name, with the same
// fields and the same message, so the io::ErrorKind mapping is the same. A
// variant the conversion does not name maps to ostrya::Error::Fetch with its
// message.
impl From<ostrya::fetch::Error> for ostrya::Error;
```

An upload is tried again only while its request is unsent: the connect, the
TLS handshake, a refused `CONNECT` tunnel, the HTTP handshake, or the wait for a
ready connection failed, or hyper gave the request back unwritten. An unsent
attempt spends a round as a retryable fetch failure does, and rounds that run
out report `Error::Fetch`. A channel body whose writer was dropped before close
fails before the hand-over, and the upload then reports `Error::Fetch` and
sends nothing. Every other outcome counts as sent, and the upload ends on the
destination that took it: every final status is `Ok(Uploaded)`, and a failure
after the hand-over is `Error::UploadInterrupted`. A response that declares a
coding, and a `Content-Length` over `max_response`, are `UploadInterrupted`
too, with a message that names the cause. So each failure of an upload after
the hand-over is `UploadInterrupted`, and `Error::is_unsent()` is true for each
other error of an upload. A `POST` whose body is at its end at the hand-over
declares `Content-Length: 0`.

An upload shares the HTTP/2 connection of its origin. It takes an idle
HTTP/1.1 connection from the pool only when the connection went idle less than
two seconds ago, and opens one of its own otherwise: a server closes an idle
connection at the end of its idle timeout, and a request that hyper began to
write over a connection closed that way counts as sent. A pooled connection
that fails before hyper writes the request is dropped, and the upload goes on
over a new connection with no round spent. The HTTP/1.1 connection of an upload
goes back to the pool when hyper took the end of the request body before the
response head arrived, the response does not close the connection, and the
response body was read to its end. Every other case closes it.
When the response body ends or is dropped before the request body has ended,
as after an early answer, the request body fails: the writer gets `BrokenPipe`,
and hyper stops sending the body.

The writer of a channel body hands frames of 64 KiB to the connection through a
slot of one frame, so the writer holds at most two frames. A flush of less than
4 KiB hands over a copy and keeps the buffer. hyper takes a body given whole in
frames of 64 KiB cut from its bytes. For each upload in flight the connection
holds more: over HTTP/1.1, hyper takes another frame while it holds fewer than
16 frames and less than 408 KiB, and over HTTP/2 it holds up to two frames.

The stall window starts at the hand-over. A frame that waits for
`progress_timeout` fails the body: the write fails with `TimedOut` for a
channel body, and the upload is `UploadInterrupted` for a body given whole. A
writer that waits at the gate, during the connect, or during the backoff of a
round has no bound, and a writer dropped before close fails the body. The wait
for the response head starts when hyper takes the end of the body and lasts
`response_timeout`. `fetch_timeout` bounds admission up to the hand-over alone,
and `low_speed` does not apply. `ostrya::Error` gains `UploadInterrupted` with
the same fields.

The pull uses four items of `ostrya-fetch` that are public for it and that
`ostrya` does not re-export at its crate root: `Fetcher::with_counters`, which
adds the bytes of each response body to a set of counters;
`Fetcher::refetching`, which gives a `Refetch` that fetches a body again from
its first byte when it fails in transit; the `fetch` and `retry` methods of
`Refetch`; and `fetch::gate::Gate`, the priority admission gate, with its
`Acquire` future and its `Permit`.

`Fetcher::new` and `Fetcher::fetch` return `ostrya::fetch::Result`. A read of a
`Body` fails with `std::io::Error`. `Repo::pull` and the other repository
operations return `ostrya::Error`, and a fetch failure reaches them through the
conversion.

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
config, or over ssh from a remote with an ssh address, into one transaction, with up to `max_outstanding_fetches` objects in
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

The driver of `pull` reads the remote through a source, one of two: the HTTP
source, over the fetcher, and the ssh source, over a `PullSession` of
`ostrya-push`. `pull_over_stream` runs the same pull through the ssh source
over a pair of streams (see "Pull over ssh: the client side"). The two
sources serve the same paths under the same size caps, and the plan, the
checks, the statistics, and the transaction are the same for both. An HTTP
request that fails retryably is sent again inside the HTTP source; the ssh
source sends no request again. A content object reads the end of its stream
before its store finishes, so a pull session moves to its next reply while
the object is stored.

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
`from` is the commit the ref names in this repository and holds complete, then
`<from>-<to>` for any other commit this repository holds complete, and the
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
`require_static_deltas` refuses a remote that serves no summary, and a commit
this repository does not hold complete for which no advertised delta can be
taken.
`pull_local` reads no delta unless `require_static_deltas` is set; with it set,
it reads the summary, the index, the superblock, and the parts from the source
directory, which must be an archive repository, and applies the delta.

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

`detached_metadata_filter` decides, property by property, which of a commit's
detached metadata reaches this repository. The pull calls it once per property of
each commit's `.commitmeta`, with the commit, the property's key, and the variant
the dict holds, and stores the properties it allows. It runs after every
signature check and over the metadata the source holds, so a filter that drops a
signature leaves the pull's own verification intact and stores a commit that
carries none. A filter that allows everything stores the source's bytes
verbatim. One that drops every property writes nothing, which leaves the
detached metadata the destination already holds where it stands, so a re-pull
into a destination holding an earlier copy does not remove it. The callback is
shared rather than exclusive, because an HTTP pull carries several commits at
once and calls it from each.

`DetachedMetadataFilter::excluding` builds the deny-list form: the names are
matched whole against the key of each detached-metadata property, and every
other property is kept. This is the constructor the `ostrya` CLI builds from
`[ex-ostrya] detached-metadata-exclude`. Those names live in the same key space
as `[ex-ostrya] gc-root-metadata-keys`, and neither list is derived from the
other.

Still remote-only and unimplemented: `subdirs` and `override_commit_ids`.

`progress` is a handle of live counters, not a callback. The pull adds to the
counters with relaxed atomic adds and never sets them to zero, and a caller
reads `snapshot()` from another task or thread on its own timer. The `ostrya`
CLI reads it for its terminal progress line. A handle that several pulls
share, or that one pull after another takes, shows the sum of their counters,
so a caller gives each pull a handle of its own to see that pull alone. Each
pull also counts into counters of its own, and its `PullStats` come from
those, whatever the handle holds. A count costs one relaxed atomic add, and
one more when the pull has a handle; the fetcher counts the bytes transferred
so once per data frame of each body. `PullStats` carries the counters at the
end of the pull, with the elapsed time and `content_bytes_unpacked`, which is
the figure the tool prints as the content written: a symlink, a hardlinked
object, and an object a static delta produced count nothing.

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
    pub depth: i32,                       // 0 = the commit alone, -1 = all;
                                          // below -1: InvalidInput, nothing written
    pub localcache_repos: Vec<Repo>,
    pub disable_fsync: bool,              // every sync off; never turns one on
    pub per_object_fsync: bool,           // sync each content object as staged
    // The rest are the remote pull's; each defaults to what a local pull
    // does. http_headers, n_network_retries above 0, and the two low-speed
    // fields apply to HTTP alone: an ssh address refuses them.
    pub subpaths: Vec<String>,            // absolute paths; empty is the whole
                                          // tree; a local pull refuses them;
                                          // leaves each commit partial
    pub url: Option<String>,              // an HTTP base URL or an ssh address;
                                          // overrides pull-url and url
    pub http_headers: Vec<(String, String)>,
    pub max_outstanding_fetches: Option<usize>,  // None is 8
    pub n_network_retries: Option<u32>,          // None is 5; a body refetch
                                                 // spends one as well
    pub low_speed_limit_bytes: Option<u32>,      // None is 1000; 0 is off
    pub low_speed_time: Option<Duration>,        // None is 30s below the
                                                 // limit; zero is off
    pub timestamp_check: TimestampCheck,
    pub disable_static_deltas: bool,      // fetch every object loose
    pub require_static_deltas: bool,      // refuse where no delta can be taken
    pub verify: PullVerify,               // the signature checks to make
    pub detached_metadata_filter: DetachedMetadataFilter,  // what to store
    pub progress: Option<PullProgress>,   // live counters for the caller
    pub connect: PullConnectOptions,      // ssh command, send command, and
                                          // remote ssh command; the remote
                                          // keys fill the fields left None;
                                          // HTTP refuses the first two
}

#[derive(Clone, Default)]
pub struct PullProgress { /* Arc of atomic counters */ }
impl PullProgress {
    pub fn new() -> PullProgress;
    pub fn snapshot(&self) -> PullProgressSnapshot;
}
pub struct PullProgressSnapshot {
    pub bytes_transferred: u64,
    pub metadata_fetched: u32,
    pub content_fetched: u32,
    pub objects_done: u32,                // units of work finished
    pub objects_total: u32,               // finished, in flight, and queued
    pub scanning: bool,                   // a pull with a commit or dirtree
                                          // still queued
    pub delta_parts_fetched: u32,
    pub delta_parts_total: u32,
    pub delta_bytes_fetched: u64,
    pub delta_bytes_total: u64,
}

/// A verdict on one property of a commit's detached metadata: the commit, the
/// property's key, and the `v` member the dict holds for it.
pub type DetachedMetadataFilterFn =
    Arc<dyn Fn(&Checksum, &str, &Value) -> FilterResult + Send + Sync>;

/// The detached-metadata filter a pull applies, unset by default, which stores
/// every property.
#[derive(Clone, Default)]
pub struct DetachedMetadataFilter(Option<DetachedMetadataFilterFn>);
impl DetachedMetadataFilter {
    pub fn new<F: Fn(&Checksum, &str, &Value) -> FilterResult + Send + Sync + 'static>(f: F)
        -> DetachedMetadataFilter;
    // Over a callback the caller holds, for one shared with another PullOptions.
    pub fn from_fn(f: DetachedMetadataFilterFn) -> DetachedMetadataFilter;
    // Drop the named keys, keep every other property. An empty list keeps all.
    pub fn excluding<I: IntoIterator<Item = S>, S: Into<String>>(names: I)
        -> DetachedMetadataFilter;
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
    pub content_bytes_written: u64,       // stored size, hardlinks included
    pub content_bytes_unpacked: u64,      // payload written, the tool's figure
    pub metadata_fetched: u32,            // HTTP only, delta index and
                                          // superblock requests included
    pub content_fetched: u32,             // HTTP only
    pub delta_parts: u32,                 // parts fetched as files
    pub bytes_transferred: u64,           // successful bodies after the
                                          // summary, config, and ref files
    pub elapsed: Duration,
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
    /// The global metadata dict alone, the ref list left undecoded.
    pub fn parse_metadata(bytes: &[u8]) -> Result<Value>;
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
    /// The pull through the ssh source, over a pair of streams to `ostrya
    /// send` (see "Pull over ssh: the client side").
    pub async fn pull_over_stream<R, W>(&self, remote: &str, input: R,
                                        output: W, opts: PullOptions)
        -> Result<PullStats>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;
    /// The remote's `summary` and `summary.sig` bytes, an absent one as None,
    /// over HTTP or over ssh by the address rule of `pull`, with no `url`.
    pub async fn remote_fetch_summary(&self, remote: &str)
        -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)>;
}
```

## Receive policy (feature `receive`)

The policy the server side of a push applies. `ReceivePolicy::from_config`
reads it from the receive groups of the repository config,
`[ex-ostrya receive]`, `[ex-ostrya receive "PATTERN"]`,
`[ex-ostrya trust "NAME"]`, and `[ex-ostrya key "NAME"]`, with `[core]
auto-update-summary` and its alias, and `[ex-ostrya]
detached-metadata-exclude` (`format-reference.md`, "Port extension: the
ex-ostrya config group"). `ReceivePolicy::from_file` reads the same groups
from a policy file alone. Both build each trust group and each key group once,
so a key source the policy cannot use fails the call, and the rules share
what they build. The structs are exhaustive, as the other option structs of
the crate are.

```rust
#[derive(Debug, Default)]
pub struct ReceivePolicy {
    pub default_rule: ReceiveRule,              // [ex-ostrya receive]
    pub rules: Vec<(RefPattern, ReceiveRule)>,  // [ex-ostrya receive "P"]
    pub allow_privileged: bool,
    pub summary_signers: Vec<Arc<ServerSigner>>,
    pub update_summary: bool,
    pub detached_metadata_filter: Option<DetachedMetadataFilter>,
}

/// `Default` accepts fast-forward updates with no signature check and no
/// server signature.
#[derive(Debug, Clone)]
pub struct ReceiveRule {
    pub accept: bool,                           // default true
    pub verify: ReceiveVerify,
    pub allow_non_fast_forward: bool,
    pub allow_delete: bool,
    pub signers: Vec<Arc<ServerSigner>>,
}

/// `NAME`, `PREFIX/*`, and either one after `REMOTE:` or `*:`, and
/// `REMOTE:*` and `*:*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefPattern { /* private */ }
impl RefPattern {
    pub fn parse(pattern: &str) -> Result<RefPattern>;
    pub fn as_str(&self) -> &str;
}

#[derive(Debug, Clone, Default)]
pub enum ReceiveVerify {
    #[default]
    Off,
    Keys(Arc<TrustedKeys>),
}

/// The axes are ANDed, the sign-api engines are ORed.
pub struct TrustedKeys { /* private: the built verifiers */ }
impl TrustedKeys {
    /// The keys a pull from the remote trusts for a commit.
    pub async fn for_remote(repo: &Repo, remote: &str) -> Result<TrustedKeys>;
    /// A sign-api axis; an empty list and a dummy verifier are refused.
    pub fn new(sign: Vec<Arc<dyn Verifier>>) -> Result<TrustedKeys>;
    /// A GPG axis, and a sign-api axis where `sign` is not empty; a dummy
    /// verifier is refused.
    #[cfg(feature = "verify-gpg")]
    pub fn with_gpg(gpg: GpgVerifier, sign: Vec<Arc<dyn Verifier>>) -> Result<TrustedKeys>;
}

impl ReceivePolicy {
    pub async fn from_config(repo: &Repo) -> Result<ReceivePolicy>;
    pub async fn from_file(repo: &Repo, path: &Path) -> Result<ReceivePolicy>;
    /// The rule of `NAME` or `REMOTE:NAME`; `None` refuses the update.
    pub fn rule_for(&self, refspec: &str) -> Option<&ReceiveRule>;
}

/// One server signing key, paired with a verifier that trusts that key
/// alone. The pair tells whether a signature on a commit, stored or
/// incoming, was made with the key already.
pub struct ServerSigner { /* private */ }
impl ServerSigner {
    /// The two halves must read one detached-metadata key.
    pub fn new(signer: Box<dyn Signer>, verifier: Box<dyn Verifier>)
        -> Result<ServerSigner>;
    pub fn ed25519(secret: &[u8]) -> Result<ServerSigner>;
    #[cfg(feature = "sign-spki")]
    pub fn spki(signer: SpkiSigner) -> Result<ServerSigner>;
    /// The selector names exactly one secret key. The certificate the
    /// verifier trusts comes from `gpg --export` in the same home.
    #[cfg(feature = "sign-gpg")]
    pub async fn gpg(signer: GpgSigner) -> Result<ServerSigner>;
    pub fn signer(&self) -> &dyn Signer;
}
```

`Repo::receive` runs one push session over a pair of streams, with the
policy the caller lends it. `ostrya::push` re-exports `ostrya-push`, the wire
protocol crate, in every build, so a caller names its error codes and
messages through `ostrya`. `Error::Push` carries them in every build too.

- `Hello` opens the session transaction, which holds the repository lock
  shared under `[core] lock-timeout-secs`. A repository with `[core]
  locking=false` refuses the session with `locking-disabled`. A
  `bare-split-xattrs` repository refuses it with `mode-refused`, and so does
  a `bare` repository when the process does not run as root. A ref name of
  `Hello` that `validate_refspec` refuses is `invalid-ref` with the text
  `invalid ref name 'NAME'`. A ref name with a trailing `^` passes, and so
  does a ref name of 64 lowercase hex characters: `Hello` does not tell a
  write from a delete, and `Commit` checks that shape. A `Hello` with
  `one-way` true is `protocol`, before the version check: it opens a
  one-way stream, which `Repo::receive_stream` reads.
- `Have` gets one bit for each object that neither the repository nor the
  session holds. More than `max-have` entries is `limit-exceeded`.
- The object stream checks the checksum of each object and the content rules
  of the repository mode and of `allow_privileged`, and stages the object. An
  object the repository or the session already holds is read, checked, and
  dropped. A detached metadata object is kept in the session, and a second one
  for one commit is `protocol`. The detached metadata of the session has one
  byte cap for the whole session, `MAX_METADATA_SIZE`. The bytes count as
  they arrive, and the read that takes the session past the cap is
  `limit-exceeded`. `ObjectsReply` counts the objects staged and the
  detached metadata objects kept, and the bytes they took on the wire.
- `Commit` runs the checks of the ref updates in order, and the first
  failure ends the session with nothing published. Each ref name is valid,
  and no update writes a commit to a ref name of 64 lowercase hex
  characters (`invalid-ref`). A delete of a ref name of 64 lowercase hex
  characters passes. The message holds one update at least, and each update
  names a ref of `Hello` once (`protocol`). The `CommitReply` of the
  updates fits in a frame of `MAX_FRAME` when each outcome carries an old
  commit, which an update that expects its ref absent or takes any state
  does not state (`limit-exceeded`). So a commit that wrote its refs always
  has a reply the server can send. Each detached metadata object
  belongs to a commit of the session: a staged commit, or the new commit of
  an update (`protocol`). The rule of
  each update accepts it, and no update names `ostree-metadata` in a
  repository with a collection id (`ref-denied`). Each new commit is staged
  or present, and the tree of each commit of the session is complete
  (`missing-objects`). The bindings of each new commit name its refs and the
  collection id (`binding-mismatch`). Each new commit passes the `verify` of
  each of its rules, over the stored and the incoming signatures
  (`signature-required`).
- The commits of the session are the commits the session staged and the new
  commits of the updates. A commit the client sends that the repository
  holds is not staged, so it is a commit of the session only where an update
  names it.
- The server then makes the staged objects durable with one `syncfs`. At
  the same time it signs each new commit with each key of the `signers` of
  the rules of its updates, each key once. A key with a verifying signature
  in the merge of the filtered incoming dict into the stored dict makes no
  signature.
- The server then takes the update lock. Under the lock it reads each
  ref again with `lstat`. An alias, and a path that a ref write cannot
  replace, are `ref-denied`: a directory, a path below a ref file, and two
  updates of which one writes below the other. It then checks the expected
  state (`ref-mismatch`), a delete (`delete-denied`), and a fast-forward
  (`non-fast-forward`). It reads each stored detached metadata dict again,
  and queues a merge of each incoming dict, filtered, into it. Where the
  stored dict changed since the read before the lock, it drops each prepared
  server signature whose key has a verifying signature in the new merged
  dict. It queues the kept signatures after the merge. The merged dict with
  those signatures is `limit-exceeded` over `MAX_METADATA_SIZE`. The server
  queues each ref that changes and commits the transaction under the lock it
  holds, through an internal commit step that does not take the lock again.
  That step renames the staged objects into `objects/` under the lock, where
  a `Transaction::commit` outside the receive path publishes them before it
  takes the lock. A delete of an absent ref and an update to the current
  commit write nothing.
- With `update_summary`, when a ref changes, a repository with a collection
  id also writes the refreshed anchor commit on `ostree-metadata` in the
  session transaction, with the anchor read under the lock as its parent.
  A failure there is `internal`, and nothing is published. Staged after the
  `syncfs`, the anchor objects are synced one by one, and the commit runs no
  second `syncfs`.
- After the commit the server removes the `.commitpartial` marker of each
  commit of the session. With `update_summary`, when a ref changed, it
  builds the summary, signs the built bytes with each of `summary_signers`,
  GPG keys first, and then removes `summary.sig`, writes `summary`, and
  writes the new `summary.sig`, still under the lock. With no summary signer
  it writes no `summary.sig`. The server then
  releases the lock and replies `CommitReply`. The call returns the report.
  A step after the commit that fails does not undo it: it adds a
  `ReceiveWarning` to the report, and the client is not told. A summary
  failure is such a step, and so is a `CommitReply` that cannot be sent, so
  the call returns `Ok` also when the client did not get the reply.
- A failure with a wire code goes to the peer and returns as `Error::Push`. A
  server-side failure goes to the peer as `internal` and returns as the error
  it is. An `Abort`, an abandoned object, and an error or end of file of the
  input send nothing: the first two return `push::Error::Aborted`, and an end
  of file at a frame boundary returns an `Error::Io` of kind
  `UnexpectedEof`.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveReport {
    pub refs: Vec<push::RefOutcome>,
    pub stats: TransactionStats,
    pub warnings: Vec<ReceiveWarning>,     // steps after the commit that failed
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiveWarning {
    pub step: ReceiveStep,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveStep {
    SummaryBuild,
    SummarySign,
    SummaryWrite,
    PartialMarker,                         // one for each commit
    ReplyNotDelivered,
}

impl Repo {
    pub async fn receive<R, W>(&self, input: R, output: W, policy: &ReceivePolicy)
        -> Result<ReceiveReport>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;

    /// Reads one one-way stream into one transaction, and sends nothing.
    pub async fn receive_stream<R>(&self, input: R, policy: &ReceivePolicy)
        -> Result<ReceiveReport>
    where
        R: AsyncRead + Unpin + Send;
}
```

`Repo::receive_stream` reads one one-way stream: one `Hello` with `one-way`
true, zero or more object streams, each closed by `ObjectsEnd`, one
`Commit`, and the end of the input. `ostrya_push::proto::Hello` carries the
key as the field `one_way`. The encoder writes the key when it is true
alone, and an absent key reads as false. The call sends no message and
returns the result.

- The frame limit and the chunk limit are 1 MiB, because no `HelloReply`
  announces another one. The objects are staged as in `Repo::receive`.
- The checks of `Hello` are those of `Repo::receive`, except that a
  repository with `[core] locking=false` is accepted. A `Hello` without
  `one-way` true is `protocol`, before the version check. The session
  transaction holds the repository lock shared from `Hello` to the end, with
  no lock under `[core] locking=false`. The commit takes the update lock,
  which ignores `[core] locking`.
- `Have`, a second `Hello`, and an `Abort` frame between two objects are
  `protocol`. An object that the sender abandons with the abandon marker and
  `Abort` returns `push::Error::Aborted`.
- An update of `Commit` whose expected state is `Commit`, and an update with
  no new commit, are `protocol`. The call then reads to the end of the
  input, and a byte after `Commit` is `protocol`, also a byte that does not
  make a whole frame. An end of the input before `Commit` is complete
  returns an `Error::Io` of kind `UnexpectedEof`, and an error of the input
  returns as `Error::Io`.
- `Commit` runs the checks and the steps of `Repo::receive` with a policy
  derived from `policy`: the `signers` of each rule and `summary_signers`
  are empty, and `update_summary` is false. So the commit adds no server
  signature, writes no anchor commit, and does not regenerate the summary.
  The check of the merged detached metadata against `MAX_METADATA_SIZE`
  stays, and so does the check that the `CommitReply` of the updates fits in
  a frame of `MAX_FRAME`.
- Each failure aborts the transaction, and the repository does not change.

`ReceiveService` runs the same session as steps, one for each request of a
transport such as HTTP. Each step does what the message of the same name
does in `Repo::receive`, with the same checks, the same session cap, and the
same wire codes, and the host sends the reply. The service is
`Send + Sync`, and every step takes `&self`, so the host keeps the service
in an `Arc` and runs steps of one session at the same time. The service
knows no HTTP, no session id, no owner, no timeout, and no status.

- `hello` opens the session transaction. `parallel_uploads` is the value
  that `HelloReply` announces. A `parallel_uploads` of 0 is
  `Error::InvalidInput`. The service sets no upper bound, and the host
  keeps the value in a range of its own. A `Hello` with `one-way` true is
  `protocol`.
- Up to `parallel_uploads` `objects` calls run at the same time and write
  through the one session transaction. One call more is `limit-exceeded`,
  and ends the session. One `have` runs next to the other steps and does
  not count against `parallel_uploads`. A second `have` while the first is
  in flight is `limit-exceeded`, and ends the session. `commit` runs only
  when no other step is in flight, `have` included. Otherwise it is
  `protocol`, and it ends the session. While `commit` runs, each other step
  is `protocol`.
- The dirtree, dirmeta, and commit objects that the streams of the session
  read at the same time share a budget of `MAX_METADATA_SIZE` bytes. The
  bytes of an object count from their arrival to its stage step, and give
  the budget back when the object is staged, dropped, or fails. The read
  that takes the session past the budget is `limit-exceeded`, and ends the
  session. The bytes of a detached metadata object count against the
  session cap of the detached metadata alone, and not against this budget.
  `Repo::receive` holds the same budget, and with one stream an object
  meets its own cap of `MAX_METADATA_SIZE` first.
- An `objects` call reads frames from `ObjectHeader` or `ObjectsEnd` on, to
  `ObjectsEnd`, and then the end of its input. A byte after `ObjectsEnd`,
  and an input that ends before it, are `protocol`. An `Abort` frame is
  `protocol`. An I/O error of the input other than an end of file returns
  as `Error::Io`. The counts of `ObjectsReply` are those of one stream: a
  content, dirtree, dirmeta, or commit object that two streams send at the
  same time can count in both. A second detached metadata object for one
  commit is `protocol`, also from another stream, and ends the session.
- An error in a step ends the session with no commit. The `objects` calls
  in flight fail at their next read, and a read that waits for input wakes.
  A step future that is dropped before it completes also ends the session.
  `abort` ends the session in the same way and returns at once. `abort`
  while `commit` runs does nothing, and the commit continues. When no step
  holds the session, the transaction is dropped in a detached task on the
  blocking pool through `ostrya_rt::unblock_detached`, which removes its
  staging directory and releases the repository lock in the background.
  Under the `tokio` backend with no runtime, the drop runs inline. A
  service dropped while its session is open ends the session in the same
  way. A `commit` owns the transaction while it runs: a `commit` future
  dropped before it completes drops the transaction inline, on the thread
  that drops the future. A host drops it only when it drops the commit
  task, for example at the shutdown of the runtime.
- A failure with a wire code returns as `Error::Push`, and a failure on the
  server side returns as the error it is. A `commit` that fails ends the
  session. After a commit every step is `protocol` with the message `the
  session committed`. A step on a session that an error or `abort` ended is
  `protocol` with the message `the session was aborted: CAUSE`. A step
  that completes after the session ended returns that error in place of
  its result. A dropped `commit` future gives the cause `the commit ended
  before its result`, and an `Abort` frame gives `the client aborted the
  session`.
- `commit` returns the report, and the host sends `CommitReply` from its
  refs. When that send fails, the host adds a `ReceiveWarning` with the step
  `ReplyNotDelivered`.

```rust
pub struct ReceiveService { /* private */ }

impl ReceiveService {
    pub async fn hello(repo: Repo, policy: Arc<ReceivePolicy>, parallel_uploads: u32,
                       hello: Hello) -> Result<(ReceiveService, HelloReply)>;
    pub async fn have(&self, names: Vec<ObjectName>) -> Result<HaveReply>;
    pub async fn objects<R>(&self, input: R) -> Result<ObjectsReply>
    where
        R: AsyncRead + Unpin + Send;
    pub async fn commit(&self, request: CommitRequest) -> Result<ReceiveReport>;
    pub fn abort(&self);
}
```

## Push client session

`ostrya-push` holds the client side of a push, re-exported as
`ostrya::push`. A `PushSession` runs one session over a pair of byte
streams. `over_stream` needs no runtime. `connect` opens a session over
ssh or HTTP, on the runtime backend that the `smol` or the `tokio` feature
selects.

- `over_stream` sends `Hello` with the refs the session updates and reads
  `HelloReply`. `server()` gives its facts.
- `missing` sends `Have` messages of at most `max-have` names, and of at
  most the names whose frame fits in `max-frame`, and gives the names the
  server needs. A name of a type other than file, dirtree, dirmeta, or
  commit is `Error::InvalidInput` in `missing` and in `send`, and the
  session stays usable.
- `send` sends objects from an `ObjectSource`, then one `CommitMeta` for
  each commit of `commits` with detached metadata that the session has not
  sent yet. The session builds the wire bytes of `ObjectData::Content`, raw
  or through its own `DeflateReader`, and copies `ObjectData::Encoded`. It
  does not hash or measure an object, because the server verifies each one.
  A source that fails ends the session with the abandon marker and `Abort`,
  and the call returns `Error::Source`.
- Each `send` call and each `export_stream` call asks
  `ObjectSource::content_size` at most once, before the first object, for
  the content bytes of the file objects of the call, and adds the answer to
  `bytes_total`. It then sets `Uploading`. A call asks only when the
  session has a `PushProgress` and `names` holds at least one file object.
  `None` and an error add nothing, and the session goes on to send. The
  provided method gives `None`.
- The content bytes of a file object are the bytes the session reads from
  the reader its source gave: the payload of `Content` before the session
  compressor, and the bytes of `Encoded`, as a stored `.filez` that goes
  as it is. A symlink, a metadata object, and detached metadata count no
  byte. The session counts them in `content_bytes`, so with a source that
  answers, `content_bytes` ends at `bytes_total`.
- `PushProgress` is a clone of shared atomic counters. `snapshot()` reads
  them. `with_hook` makes a handle that also calls a `PushProgressFn` with
  a snapshot: at each phase change, after each object of the object
  stream, and each time `content_bytes` reaches the next multiple of
  102,400 bytes. The hook runs on the task that changed the counters, and
  over HTTP each parallel object stream calls it, so calls can run at the
  same time on several threads. It must return soon, and it keeps its own
  state behind interior mutability.
- The phases are `Scanning` and `Hashing` for the scan of a tree push,
  `Connecting` while the transport starts and `Hello` goes out, `Negotiating`
  through the `Have` rounds, `Uploading` through the object streams, and
  `Committing` after `Commit`.
- The frame of each `ObjectHeader` is a fixed array of 40 bytes, with no
  allocation. The session writes the framed file header of each `Content`
  object into one buffer that it keeps, with `FileHeader::write_framed`
  (`raw`) or `FileHeader::write_framed_archive` (`deflate`) of
  `ostrya-core`. Each gives the bytes of `filehdr::frame` over
  `FileHeader::serialize` or `FileHeader::serialize_archive`. It clears the
  buffer first, so the buffer grows only for a header longer than each
  header before it.
- `commit` sends `Commit` and gives the `CommitReply` as a `PushOutcome`.
  An `Error` from the server is definite. When the write of `Commit` fails,
  the session reads one pending message: an `Error` is that error, and a
  `CommitReply` is the reply. Every other end of the session after
  `Commit`, and a `CommitReply` for other refs than the refs of the
  updates, is `Error::CommitOutcomeUnknown`, because the server may have
  written the refs. Empty updates, a ref that `Hello` did not name, and a
  ref named twice are `Error::InvalidInput`. On a broken session `commit`
  returns `Error::InvalidInput`. In these cases `commit` writes nothing.
- On a stream transport one call runs at a time. An overlapping call fails
  at once with `Error::InvalidInput`. A failed or dropped call leaves the
  session broken.
- `abort` writes `Abort` and closes the output when the stream is still
  usable. On a broken session it writes nothing and returns
  `Error::InvalidInput`.
- `session::export_stream` writes the messages of a session as one one-way
  stream, for a receiver that sends no reply: `Hello` with `one-way` true,
  one object stream with the names and the detached metadata of the
  commits, `ObjectsEnd`, and `Commit` with `force` false. It reads nothing
  and does no negotiation, and its frame limit and chunk limit are 1 MiB.
  Before it writes a byte, it refuses with `Error::InvalidInput`: empty
  updates, a ref named twice, a ref name that fails
  `ostrya_core::is_refspec`, a ref name of 64 lowercase hex characters that
  an update writes, an expected state `Commit`, an update with no new
  commit, a level outside 1
  to 9, a name of a type other than file,
  dirtree, dirmeta, or commit, and a `Hello` or a `Commit` frame over 1
  MiB. A source that fails ends the stream inside an object: the function
  writes the `ObjectHeader` of the object when it did not write it yet,
  then the abandon marker and `Abort`, and returns the error. A failed
  write returns its error, and the function writes nothing more. The
  function writes `output` in blocks of 64 KiB, so the caller need not give
  a buffered writer. It flushes `output` and does not close it. `W` has no `'static` bound, and a
  caller that keeps its writer gives `&mut W`. The `PushStats` count each
  name as offered and as needed. The crate root does not re-export the
  function.

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Default)]
pub enum Compression { #[default] None, Deflate { level: u8 } }

pub trait ObjectReader: AsyncRead + Send + Sync + Unpin {}

pub enum ObjectData {
    Content { header: FileHeader, size: u64, payload: Option<Box<dyn ObjectReader>> },
    Encoded { encoding: Encoding, reader: Box<dyn ObjectReader> },
}

pub trait ObjectSource: Send + Sync {
    fn objects<'a>(&'a self, commit: &'a Checksum)
        -> BoxFuture<'a, Result<Vec<ObjectName>>>;
    fn open<'a>(&'a self, name: &'a ObjectName, encoding: Encoding)
        -> BoxFuture<'a, Result<ObjectData>>;
    fn detached_metadata<'a>(&'a self, commit: &'a Checksum)
        -> BoxFuture<'a, Result<Option<Value>>>;
    // Provided: `None`.
    fn content_size<'a>(&'a self, names: &'a [ObjectName], encoding: Encoding)
        -> BoxFuture<'a, Result<Option<u64>>>;
}

pub type PushProgressFn = Arc<dyn Fn(&PushProgressSnapshot) + Send + Sync>;

#[derive(Debug, Clone, Default)]
pub struct PushProgress { /* Arc of atomic counters, and the hook */ }

impl PushProgress {
    pub fn new() -> PushProgress;
    pub fn with_hook(hook: PushProgressFn) -> PushProgress;
    pub fn snapshot(&self) -> PushProgressSnapshot;
}

#[non_exhaustive]
pub enum PushPhase {
    #[default] Scanning, Hashing, Connecting, Negotiating, Uploading, Committing,
}

#[non_exhaustive]                 // read by field; no struct literal outside
pub struct PushProgressSnapshot {
    pub phase: PushPhase,
    pub objects_total: u64,
    pub objects_needed: u64,
    pub objects_sent: u64,
    pub bytes_sent: u64,      // the bytes handed to the transport
    pub payload_bytes: u64,   // the object bytes in their wire encoding
    pub content_bytes: u64,   // the bytes read from the readers of file objects
    pub bytes_total: u64,     // the sum of `content_size`, 0 when unknown
}

#[derive(Debug, Clone, Default)]
pub struct SessionOptions {
    pub agent: Option<String>,             // default "ostrya/<version>"
    pub progress: Option<PushProgress>,
}

impl PushSession {
    pub async fn over_stream<R, W>(input: R, output: W, refs: &[String],
                                   opts: SessionOptions) -> Result<PushSession>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;
    pub fn server(&self) -> &ServerInfo;
    pub async fn missing(&self, names: &[ObjectName]) -> Result<Vec<ObjectName>>;
    pub async fn send(&self, source: &dyn ObjectSource, names: &[ObjectName],
                      commits: &[Checksum], compression: Compression) -> Result<()>;
    pub async fn commit(self, updates: &[RefUpdate], force: bool)
        -> Result<PushOutcome>;
    pub async fn abort(self) -> Result<()>;
}

pub mod session {
    pub async fn export_stream<W>(output: W, source: &dyn ObjectSource,
                                  names: &[ObjectName], commits: &[Checksum],
                                  updates: &[RefUpdate],
                                  compression: Compression,
                                  opts: SessionOptions) -> Result<PushStats>
    where
        W: AsyncWrite + Unpin + Send;
}

pub struct PushOutcome {
    pub commit: Option<Checksum>,
    pub refs: Vec<RefOutcome>,
    pub stats: PushStats,  // objects_total, objects_needed, objects_sent,
                           // bytes_sent, payload_bytes, elapsed
}
```

## Push tree model

`ostrya_push::tree` walks a local directory with `std::fs` into a
`TreeModel`: the metadata of each entry and the checksum of each object of
the tree. The model stores each entry once, as its name, its metadata, and
the index of its parent directory, and it holds no file content.
`TreeModel::scan` runs on the runtime backend that the `smol` or the
`tokio` feature selects.

- The walk does not follow symlinks, and the walk root must be a directory.
  It reads a directory listing to its end, with the metadata of each entry
  and the target of each symlink, and closes the directory before it enters
  a subdirectory. So it holds one directory open at a time.
- Names and symlink targets must be valid UTF-8, and names must pass the
  dirtree name rule. Regular files, directories, and symlinks are taken.
  Any other entry stops the walk before the entry filter sees it.
- The default metadata: on Unix the owner and the mode of the metadata
  read, which does not follow a symlink. On other platforms owner 0:0 and
  mode `0o100644` for a regular file and `0o40755` for a directory. A
  symlink has the mode `0o120777` on every platform. `xattrs` is empty.
- The `EntryFilter` runs once for each entry, the root first with the
  empty path, on the task that drives the scan. It can change the owner,
  the permission bits, the extended attributes, and the target of a
  symlink. A change of the kind or of the file-type bits, a bit above
  `0o177777`, and a symlink target on another kind or removed from a
  symlink are `Error::Walk` of kind `InvalidData`. `Skip` leaves out the
  entry and the subtree of a directory, and `Skip` on the root is
  `Error::Walk` of kind `InvalidInput`.
- The hash pass reads each kept regular file once, on the blocking pool,
  in chunks of at most 64 KiB, with at most `hash_jobs` files in flight.
  The default is the number of CPUs, or 1, and the pass takes at most
  `ostrya_rt::blocking_threads()`. `Some(0)` is `Error::InvalidInput`, and
  the walk does not start.
- On Unix the open takes `O_NOFOLLOW | O_NONBLOCK`, and one `fstat` of the
  open file must show a regular file with the device and inode numbers
  that the walk read. On Windows it takes `FILE_FLAG_OPEN_REPARSE_POINT |
  FILE_FLAG_BACKUP_SEMANTICS` and checks the type alone. A file that
  changed is `Error::Walk` of kind `InvalidData`.
- At the first error the pass sets a stop flag, starts no new job, and
  waits until each job in flight stops. So no file of the pass is open
  when `scan` returns. A dropped scan sets the flag too.
- Each directory is hashed bottom-up into its dirtree and dirmeta objects.
  A dirtree or a dirmeta object over `MAX_METADATA_SIZE` is `Error::Walk` of
  kind `InvalidData` that names the directory.
- `object_names` gives each object of the tree once, in the order the walk
  reached its first source.
- Each failure of the walk and of the hash pass is `Error::Walk`. `path`
  names the entry on the local filesystem, and `source` keeps the
  `io::ErrorKind`. The variant has no wire code.
- `set_commit` gives the model the checksum, the bytes, and the detached
  dict of the commit over the tree. The model does not check the bytes, and
  a later call replaces the commit.
- `TreeModel` is an `ObjectSource`. `objects` of the commit gives each
  object of the tree once and then the commit. `open` of a regular file
  opens it again, with the open and the checks of the hash pass, and gives
  `ObjectData::Content` with the byte count of the hash pass as `size`. The
  payload stops after `size` plus 1 byte, so a file that grew gives at most
  1 byte more than the hash pass read. The payload is an
  `ostrya_rt::FileReader` with the byte count of the hash pass as the length
  hint, so a small file reads ahead by its own size, at least 4 KiB, and a
  large file by 256 KiB under smol. It does not read the length again or hash the file again, and the
  server refuses a file that changed. A symlink opens nothing. A dirtree or a
  dirmeta object is serialized again from the model, and the commit is the
  bytes of `set_commit`, each as `ObjectData::Encoded` in `raw`.
  `detached_metadata` of the commit gives the stored dict. Another commit
  and an object the model does not hold are `Error::InvalidInput`. A failed
  open is `Error::Walk`, which the session returns inside `Error::Source`.
  `content_size` gives the sum of the byte counts of the hash pass, a
  symlink as 0, in each encoding, and reads no file.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind { File, Dir, Symlink }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    pub kind: EntryKind,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,                        // full st_mode, type bits included
    pub xattrs: Xattrs,
    pub symlink_target: Option<String>,   // present for a symlink alone
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryAction { Keep, Skip }

pub struct EntryPath { path: String }     // `/`-separated, the root is ""

impl EntryPath {
    pub fn as_str(&self) -> &str;
    pub fn as_path(&self) -> &Path;
    pub fn is_root(&self) -> bool;
}                                         // and Display

pub type EntryFilter =
    Box<dyn FnMut(&EntryPath, &mut EntryMeta) -> EntryAction + Send>;

#[derive(Default)]
pub struct ScanOptions {
    pub entry_filter: Option<EntryFilter>,
    pub hash_jobs: Option<usize>,
}

impl TreeModel {
    pub async fn scan(root: &Path, opts: ScanOptions) -> Result<TreeModel>;
    pub fn root_dirtree(&self) -> Checksum;
    pub fn root_dirmeta(&self) -> Checksum;
    pub fn object_names(&self) -> Vec<ObjectName>;
    pub fn set_commit(&mut self, checksum: Checksum, bytes: Vec<u8>,
                      detached: Option<Value>);
}

impl ObjectSource for TreeModel { /* the send pass */ }

pub enum Error {
    // ...
    Walk { path: PathBuf, source: io::Error },
}
```

## Tree push

`ostrya_push::push_tree` pushes a local directory as one commit and sets
the target refs of the server to it in one transaction.
`push_tree_prepared` runs the same push over a `PreparedSession`, the
transport that `PushSession::prepare` made ready, so a caller can run the
transport checks before its own work. `push_tree_over_stream` runs the same
push over a pair of byte streams. `ostrya` re-exports the three as
`ostrya::push`.

- Before the scan, the push refuses with `Error::InvalidInput`: empty
  `refs`, a ref named twice, a ref that holds `:`, a ref that holds `^`, a
  ref that fails `ostrya_core::is_ref_name`, a ref of 64 lowercase hex
  characters, a DEFLATE level outside 1 through 9, a malformed
  `SOURCE_DATE_EPOCH` when `timestamp` is not set, an
  empty key in `metadata` or in `detached_metadata`, entries that do not
  serialize as an `a{sv}` dict, entries whose serialized dict is over
  `MAX_METADATA_SIZE`, and a subject, a body, and `metadata` whose commit
  object is over `MAX_METADATA_SIZE` without the bindings and without a
  parent of `ParentPolicy::CurrentTip`. A revision reads `^` as the parent
  of a commit, and 64 lowercase hex characters as a commit checksum, so a
  ref of either form cannot be read back by its name. The
  timestamp is read here. `push_tree` then makes the transport ready with
  `PushSession::prepare`. For an ssh address it builds the command line.
  For an `http://` or an `https://` address it reads the token file and the
  TLS files and builds the HTTP client. It refuses each option that
  `PushSession::connect` refuses before it starts the transport.
  `push_tree_prepared` takes a transport that is ready, and makes these
  checks of `opts` after it.
- The scan is `TreeModel::scan` with `entry_filter` and `hash_jobs`. It runs
  before the ssh client starts, before the first HTTP request, and before
  the first byte is written. So a refusal of the options, a walk error, and
  a hash error start no ssh client, send no request, and open no session.
- The session opens with the target refs in one `Hello`. Without `force`,
  each target ref must have the state of the first one on the server: all
  absent, or all at one commit. Refs in mixed states are
  `Error::InvalidInput`, with a message that names each ref and its commit,
  and the push ends the session with `Abort` before it offers an object.
- The commit: the parent from `ParentPolicy`, the subject and the body, the
  timestamp, the root checksums of the scan, and the metadata dict of
  `ostrya_core::commit_metadata`: the entries of `metadata`, then
  `ostree.ref-binding` with the refs sorted, then
  `ostree.collection-binding` with the server collection id when the server
  has one. `no_bindings` leaves out both bindings. The commit checksum
  equals that of `Transaction::write_commit` over the same tree with the
  same inputs. A commit over `MAX_METADATA_SIZE` is `Error::InvalidInput`.
- The detached dict: the entries of `detached_metadata`, then the
  signature of each signer, in order, under its `metadata_key`, with
  `ostrya_sign::append_signature`. A value of the caller under the key of a
  signer that is not an `aay` is `Error::Sign` with `InvalidFormat`, and so
  is a failed signer. The push checks the key of each signer before the
  first signer signs. A dict over `MAX_METADATA_SIZE` is
  `Error::InvalidInput`. The push signs while the session is open.
- One `Have` round offers each object of the tree and the commit. The push
  sends the objects the server lacks and the detached dict of the commit,
  and then `Commit`. Each update expects the commit that `HelloReply`
  reported, or no ref, and `Expected::Any` with `force`.
- A failure after the session opened and before `Commit` ends the session
  with `Abort` when the stream is still usable.
- `PushProgress` shows `Scanning` until the walk has listed and filtered
  each directory, and `Hashing` through the hash jobs still in flight and
  the bottom-up pass. The session then sets `Connecting`, `Negotiating`,
  `Uploading`, and `Committing`. The push signs the commit in `Connecting`.
  `PushStats::elapsed` covers the session alone.
- `Error::Sign` has no wire code, and reports as `internal`.

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ParentPolicy { #[default] CurrentTip, None, Commit(Checksum) }

#[derive(Default)]
pub struct TreePushOptions {
    pub refs: Vec<String>,
    pub parent: ParentPolicy,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub metadata: Vec<(String, Value)>,
    pub detached_metadata: Vec<(String, Value)>,
    pub timestamp: Option<u64>,
    pub no_bindings: bool,
    pub signers: Vec<Box<dyn ostrya_sign::Signer>>,
    pub compression: Compression,
    pub entry_filter: Option<EntryFilter>,
    pub hash_jobs: Option<usize>,
    pub force: bool,
    pub progress: Option<PushProgress>,
}

pub async fn push_tree(remote: &PushRemote, root: &Path, connect: ConnectOptions,
                       opts: TreePushOptions) -> Result<PushOutcome>;
pub async fn push_tree_prepared(session: PreparedSession, root: &Path,
                                opts: TreePushOptions) -> Result<PushOutcome>;
pub async fn push_tree_over_stream<R, W>(input: R, output: W, root: &Path,
                                         opts: TreePushOptions) -> Result<PushOutcome>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static;

pub enum Error {
    // ...
    Sign(ostrya_sign::Error),
}
```

`ostrya push-tree`, under the `push` feature of `ostrya-cli`, is the command
form of `push_tree`:

```text
ostrya push-tree [--repo=PATH] REMOTE DIR -b REF [-b REF]...
                 [-s SUBJECT] [-m BODY] [--body-file=FILE]
                 [--add-metadata-string=KEY=VALUE]... [--add-metadata=KEY=VALUE]...
                 [--add-detached-metadata-string=KEY=VALUE]...
                 [--timestamp=TIME] [--parent=CHECKSUM|none] [--no-bindings]
                 [--owner-uid=UID] [--owner-gid=GID] [--canonical-permissions]
                 [--sign=KEY]... [--sign-from-file=FILE]... [--sign-type=ENGINE]
                 [--gpg-sign=KEYID]... [--gpg-homedir=DIR]
                 [--force] [--compress[=LEVEL]]
                 [--ssh-command=CMD] [--receive-command=CMD]
                 [--push-token-file=FILE] [--push-user=NAME]
                 [--tls-client-cert-path=FILE] [--tls-client-key-path=FILE]
                 [--tls-ca-path=FILE] [--allow-cleartext-credentials]
```

- A missing `REMOTE`, `DIR`, or `-b` gives the usage text and `error:
  REMOTE must be specified`, `error: DIR must be specified`, or `error: A
  branch must be specified with --branch`, checked in that order after
  `--owner-uid` and `--owner-gid` and before a repository opens. Each exits
  1 before an ssh client starts.
- `REMOTE` goes to `resolve_push_remote`. When `is_push_address` holds for
  it, the command opens no repository and gives a `config` of `None`.
  Otherwise the command opens the repository of `--repo`, the current
  directory, or `OSTREE_REPO`, and gives its config.
- The checks run in this order: `--owner-uid` and `--owner-gid`, the
  operands, `--canonical-permissions`, the `-b` names that the command
  refuses itself, `--parent`, the metadata options, and `--timestamp`. The
  command then resolves `REMOTE` and calls `PushSession::prepare`, which
  refuses an option of the other transport and a bad HTTP option, and
  reads the token file and the TLS files. It then builds the signers and
  reads `--body-file`, and calls `push_tree_prepared`, which checks the
  other options before the scan. So a refusal of the remote or of its
  options starts no gpg and reads no body file.
- `DIR` is `root`, and each `-b` is one of `refs`. The command refuses a
  `-b` of 64 lowercase hex characters with the wording of `commit`, before
  the library sees it. The check is `ostrya::is_checksum_shaped`.
- `--parent=CHECKSUM` sets `parent` to `ParentPolicy::Commit`, with 64
  lowercase hex characters, and `--parent=none` to `ParentPolicy::None`.
  Without it, `parent` is `ParentPolicy::CurrentTip`.
- `-s` sets `subject`. `-m` sets `body`, and `--body-file` wins over it.
  `--timestamp` sets `timestamp`, read as `commit` reads it. `--no-bindings`
  sets `no_bindings`.
- `metadata` holds every `--add-metadata-string` entry, then every
  `--add-metadata` entry, the order of `commit`. `detached_metadata` holds
  every `--add-detached-metadata-string` entry. The command refuses an
  empty key in either with `Empty metadata key`. It does not apply
  `[ex-ostrya] detached-metadata-exclude`.
- `--owner-uid`, `--owner-gid`, and `--canonical-permissions` set an
  `entry_filter` that keeps every entry. The filter applies the canonical
  rule first, then each declared id. Without the three options,
  `entry_filter` is `None`.
- `signers` holds one signer for each `--sign` key, then for each
  `--sign-from-file` key, then for each `--gpg-sign` selector. Under
  `--sign-type=gpg`, a `--sign` and a `--sign-from-file` key are gpg
  selectors too. The command builds the list before the scan, and it looks
  up the secret key of each gpg selector, so a key that does not decode and
  a selector that names no secret key are refused before an ssh client
  starts and before the first HTTP request. The command reads
  `--body-file` after it builds the list.
- `--force`, `--compress`, `--ssh-command`, `--receive-command`, and the
  HTTP options set `force`, `compression`, and `connect` as they do for
  `ostrya push`. `hash_jobs` is `None`. `progress` draws the progress bar
  of `ostrya push`, with its rules, or is `None` when the bar is hidden. The
  bar shows nothing during the scan, and nothing
  before `Negotiating`, so a signer that asks for a passphrase keeps the
  terminal.
- On success the command writes the checksum of `PushOutcome::commit` as
  one line to standard output and exits 0. Under `-v` the statistics line
  of `ostrya push` goes to standard error. On failure the command writes
  `error: MESSAGE` to standard error and nothing to standard output, and
  exits 1.

## Push transports

`PushRemote::parse` reads a push address, and `PushSession::connect` opens
a session to it over ssh or over HTTP. An ssh address takes the ssh fields
of `ConnectOptions`, and an `http://` or `https://` address takes the other
fields. A field of the other transport is `Error::InvalidInput`.
`remote_ssh_command` holds a key of a remote section, and an HTTP address
does not read it. With an ssh address, a field of `http` that differs from
`FetcherOptions::default()` is refused. A refusal names a field by its
remote key, which is also the CLI option without `--`, for example
`push-user needs push-token-file` and `ssh-command applies to an ssh
address`. A refusal of a field of `http` names `ConnectOptions::http`.

`PushSession::connect` is `PushSession::prepare` and then
`PreparedSession::open`. `prepare` checks the options and makes the
transport ready: for ssh it builds the command line, and for HTTP it reads
the token file and the TLS files and builds the HTTP client. It starts no
ssh client and sends no request. `open` starts the ssh client or sends the
first request, and opens the session. `PreparedSession` is `Send + Sync`,
and its `Debug` output shows the transport and the HTTP address alone.

The ssh transport runs the ssh client as a child process with the command
line
`SSH_COMMAND... [-p PORT] [USER@]HOST 'RECEIVE_COMMAND --repo=QUOTED_PATH'`,
and the remote side runs `ostrya receive`.

- The addresses are `ssh://[USER@]HOST[:PORT]/PATH`,
  `ssh://[USER@]HOST[:PORT]/~/PATH`, and the scp form `[USER@]HOST:PATH`. A
  `/~/` or a scp-form `~/` prefix is removed, and so is each `/` that
  follows it, so the path is relative to the remote home directory. The
  path is quoted with POSIX single quotes.
- In the scp form the first `:` ends the host, as git reads the form:
  `u:p@host:path` gives the host `u`, so the scp form cannot give a user
  with `:`. An IPv6 host needs brackets: `fe80::1:repo` gives the host
  `fe80`, and `[fe80::1]:repo` gives `fe80::1`.
- A user holds ASCII letters, digits, `.`, `-`, and `_`. A host holds the
  same, or it is a bracketed IPv6 address of hex digits, `:`, and `.`, with
  an optional `%ZONE` of ASCII letters and digits. The parser refuses every
  other character, which includes control characters, whitespace, and shell
  metacharacters.
- The parser also refuses a user or a host that starts with `-`, an empty
  part, a bad port, more than one `@`, a `~USER` path, and a scheme other
  than `ssh`, `http`, and `https`. In the `ssh://` form it refuses a
  `USER:PASSWORD@` user.
- On Windows it refuses a scp-form address that names a local path: a host
  of one ASCII letter, and a `\` before the first `:`.
- `SSH_COMMAND` is `ConnectOptions::ssh_command`, then the
  `OSTRYA_SSH_COMMAND` environment variable, then
  `ConnectOptions::remote_ssh_command`, then `ssh`. The two strings are
  split at ASCII whitespace. An empty command and a value that is not UTF-8
  are `Error::InvalidInput`.
- On a session that `connect` opened, the read of a pending message after a
  failed write waits at most 5 seconds. `commit` and `abort` close the
  standard input of the ssh client and wait at most 5 seconds for it to
  exit. `commit` and `abort` also wait on a broken session, and `commit`
  also waits when it refuses its updates. An open that fails waits in
  the same way. A session that failed
  with an I/O error while the ssh client exited with a failure status is
  `Error::Transport`. A session that committed gives its outcome whatever
  the exit status. `over_stream` puts no time limit on a read: its caller
  owns the liveness of the streams.
- Under the tokio backend, `connect` runs within a runtime that has the IO
  driver and the time driver enabled, and the session runs on the runtime
  that opened it.
- Memory: the object readers of a push and the standard input of
  `ostrya receive` are `ostrya_rt::FileReader`s. Under the smol backend they
  read ahead by at most 256 KiB. Under the tokio backend they read at most
  the caller's buffer in one read. The standard output of `ostrya receive` is an
  `ostrya_rt::File`. Under the smol backend it writes through a
  blocking-pool pipe of up to 8 MiB, and under the tokio backend it has one
  write of at most 2 MiB in flight. A stdin read in flight can block until
  the peer writes or closes the stream, also after the reader is dropped.

The HTTP transport sends each step of a session as one request to the
receive endpoint of the server ("Archive view and HTTP server").

- The addresses are `http://HOST[:PORT][/PATH]` and
  `https://HOST[:PORT][/PATH]`. `PushRemote::parse` checks them with
  `ostrya_fetch::check_base_url`, which refuses an `@` anywhere, a query, a
  fragment, an empty host, and a port that is not ASCII digits from 0 to
  65535. A refusal does not show the text before the last `@`.
- The client adds `_ostrya/receive/v1/session`, then `/ID` and the step, to
  the path of the address. `ostrya serve` serves the endpoint at the root of
  the server, so an address with a path works only behind a proxy that
  removes that path. The fetcher follows no redirect, and a 3xx answer is
  `Error::Transport`.
- `Hello`, `Have`, and `Commit` go as whole request bodies. Each object
  stream is the streamed body of one `objects` request. Each response body
  is one frame, read at the limit `MAX_FRAME`.
- `push_token_file` names a file whose first line is the token. The client
  reads at most 1 MiB of the file on the blocking pool and takes the bytes
  up to the first LF. A relative path is relative to the current directory
  of the process, and `~` is not expanded, for each file of this list. A
  file that cannot be read fails with `Error::Io`, whose message names the
  key and the path, for example `push-token-file 't': ...`. It refuses a CR, an empty token, a token that is not
  UTF-8, and a token that is not token68. No message holds the token. The
  client checks no permission of the file. With `push_user`, the token is
  the password of a Basic credential with that name. Without it, the token
  is a bearer token. `push_user` without `push_token_file`, an empty
  `push_user`, and a `push_user` that holds `:` are `Error::InvalidInput`.
- A credential to an `http://` address is `Error::InvalidInput` before any
  request, unless `allow_cleartext_credentials` is set. Set it for a server
  on a loopback address or behind a proxy that terminates TLS.
- `tls_ca_path` names the CA certificates that verify the server, in place
  of the trust store of the host. `tls_client_cert_path` and
  `tls_client_key_path` name a client certificate and its key, and the two
  come together. A key that needs a passphrase is refused. The client reads
  each file once, at most 1 MiB, before the session opens.
- `http` holds the other options of the HTTP client, for example a proxy and
  the timeouts. Mirrors, `basic_auth`, a trust setting that verifies no
  certificate chain, trust roots other than the system store beside
  `tls_ca_path`, and a client identity beside the client files are
  `Error::InvalidInput`. The client sets `max_outstanding` to 32 and
  `max_redirects` to 0.
- `send` runs `min(parallel-uploads, 31)` object streams at most, and no
  more streams than the objects it sends. A `parallel-uploads` of 0 counts
  as 1. All the `send` calls of one session share that limit. A call with
  nothing to send sends no request. After the first failure no stream of
  the call takes a name, and the call returns a failure of the client
  first, then an error that the server gave for its own cause, then any
  other error.
- `missing` sends one `Have` request at a time. A second `missing` call
  while one runs is `Error::InvalidInput`.
- The response to `Hello` may take 360 seconds after the request body was
  sent, and the response to `Commit` 1 hour. The response to each other
  request takes the progress timeout of `http`.
- The client sends a request again only when the attempt failed before it
  sent a byte. A `Commit` that was not sent is a definite error. After
  `Commit` was sent, an interrupted request, a failed read of the response,
  a body that is not one frame, and an unexpected status are
  `Error::CommitOutcomeUnknown`, with no retry: the server can have written
  the refs. An `Error` frame is definite.
- The body of a 200 holds one frame. The body of a 401, a 403, a 409, a
  422, a 500, and a 503 holds one `Error` frame, and gives the error of the
  frame, for example `Error::Unauthorized` with 401 or 403. Each other
  status, and a body that is not one frame, are `Error::Transport`, which
  names the URL and the status. A failure of the HTTP client is
  `Error::Fetch`.
- `abort` sends `DELETE`, and a 204 or a 404 is success. A `commit` that
  refuses its updates and a broken session send `DELETE` too, and `abort`
  on a broken session then gives `Error::InvalidInput`. A session that is
  dropped without `commit` or `abort` sends nothing, and the idle timeout of
  the server ends it.
- `PushStats::bytes_sent` counts the bytes of each request body that was
  handed to the connection, with no header and no TLS byte.

```rust
pub struct PushRemote { inner: RemoteAddr }

impl PushRemote {
    pub fn parse(address: &str) -> Result<PushRemote>;
}

#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    pub ssh_command: Option<Vec<String>>,     // wins over OSTRYA_SSH_COMMAND
    pub receive_command: Option<String>,      // default "ostrya receive"
    pub remote_ssh_command: Option<String>,   // the remote key, lowest
    pub push_token_file: Option<PathBuf>,     // first line: the token
    pub push_user: Option<String>,            // Basic name; else bearer
    pub tls_ca_path: Option<PathBuf>,         // replaces the host store
    pub tls_client_cert_path: Option<PathBuf>,
    pub tls_client_key_path: Option<PathBuf>,
    pub allow_cleartext_credentials: bool,    // a token to http://
    pub http: ostrya_fetch::FetcherOptions,   // the other client options
}

impl PushSession {
    pub async fn connect(remote: &PushRemote, connect: ConnectOptions,
                         refs: &[String], opts: SessionOptions)
        -> Result<PushSession>;
    pub async fn prepare(remote: &PushRemote, connect: ConnectOptions)
        -> Result<PreparedSession>;
}

pub struct PreparedSession { inner: Prepared }   // Send + Sync

impl PreparedSession {
    pub async fn open(self, refs: &[String], opts: SessionOptions)
        -> Result<PushSession>;
}
```

`ostrya receive [--repo=PATH] [--policy=FILE]`, under the `receive` feature
of `ostrya-cli`, runs one `Repo::receive` session over standard input and
standard output with `ReceivePolicy::from_config`, or with
`ReceivePolicy::from_file` under `--policy`. It writes one
`warning: STEP: MESSAGE` line to standard error for each warning of the
report, and the error line on failure. It exits 0 after a committed session.

An `authorized_keys` entry restricts an ssh key to one repository:

```text
restrict,command="ostrya receive --repo=/srv/repo --policy=/etc/ostrya/receive.conf" ssh-ed25519 AAAA...
```

- sshd runs the forced command and ignores the command of the client. The
  `ostrya receive --repo='PATH'` of the client reaches the server only in
  the `SSH_ORIGINAL_COMMAND` environment variable. So the key pushes into
  the forced repository, whatever path the address holds.
- Give absolute paths to `--repo` and `--policy`. A policy that must hold
  against the pusher is in a file that the pusher cannot write.
- sshd runs the `command=` string through the login shell of the user, with
  `-c`. The shell and its startup files must write nothing to standard
  output, because standard output carries the frames of the session.

## Push remotes

A remote section of the repository config can hold the push keys
`push-url`, `ssh-command`, `receive-command`, `push-token-file`, and
`push-user`. `Remote` reads each one as written, in every build. A push to
an HTTP address also reads the TLS keys of the pull: `tls-ca-path`,
`tls-client-cert-path`, `tls-client-key-path`, and `tls-permissive`.

`resolve_push_remote`, under the `push` feature, gives the push address and
the connect options of a push:

- A value that holds a `:` or a `/` is an address, which
  `PushRemote::parse` reads. No configuration is read for it.
  `is_push_address` gives this rule, so a caller can open no repository
  for an address.
- Any other value is the name of a remote section. The address is its
  `push-url`. When `push-url` is absent, a `url` that starts with `http://`
  or `https://` is the address. A `url` of another form, for example
  `file://`, `metalink=`, or `mirrorlist=`, is no push address.
- The keys of the section fill the fields of `ConnectOptions` that apply to
  the transport of the address, each only when the caller left that field
  `None`. A field that the caller set wins, and each key resolves on its
  own.
  - For an ssh address, `ssh-command` fills `remote_ssh_command`, and
    `receive-command` fills `receive_command`. The HTTP keys are not read.
  - For an `http://` or `https://` address, `push-token-file`, `push-user`,
    `tls-ca-path`, `tls-client-cert-path`, and `tls-client-key-path` fill
    the fields of the same names. The ssh keys are not read, so a
    `receive-command` key in such a section causes no refusal.
  - For an `https://` address, `tls-permissive=true` is `Error::Push` with
    `push::Error::InvalidInput`, before any request. A push verifies the
    certificate chain of the server. An `http://` address uses no TLS, and
    the key is not read.
- No key gives `allow_cleartext_credentials`. Only the caller sets it.
- A name with no section, and a section with no push address, are
  `Error::Push` with `push::Error::InvalidInput`. A `config` of `None` holds
  no section. So a caller that has no repository must give an address.

```rust
impl Remote<'_> {
    pub fn push_url(&self) -> Result<Option<String>>;
    pub fn ssh_command(&self) -> Result<Option<String>>;
    pub fn receive_command(&self) -> Result<Option<String>>;
    pub fn push_token_file(&self) -> Result<Option<String>>;
    pub fn push_user(&self) -> Result<Option<String>>;
}

pub fn is_push_address(remote: &str) -> bool;

pub fn resolve_push_remote(config: Option<&RepoConfig>, remote: &str,
                           connect: ConnectOptions)
    -> Result<(PushRemote, ConnectOptions)>;
```

## Push from a repository

`Repo::push`, under the `push` feature, pushes the commits that a set of
refspecs name to a remote. The server updates its refs in one transaction.
`remote` is a remote name or an address, and
`resolve_push_remote` reads it with the config of the repository and
`RepoPushOptions::connect`. The push then makes the transport ready with
`PushSession::prepare`, before the checks and the commit walk below, so a
refusal of the remote or of its options takes no lock and reads no
refspec. After the walk it opens the session with `PreparedSession::open`.
`Repo::push_over_stream` runs the same push over a
pair of byte streams, the mirror of `PushSession::over_stream`, and does not
read `connect`. Under the tokio backend, `Repo::push` needs a runtime with
the IO driver and the time driver, as `PushSession::connect` does.

```rust
#[derive(Debug, Clone, Default)]
pub struct RepoPushOptions {
    pub refspecs: Vec<String>,     // SRC[:DST], split at the last ':'
    pub depth: Option<i32>,        // None: the chain to the server tip
    pub compression: Compression,
    pub force: bool,
    pub connect: ConnectOptions,
    pub detached_metadata_filter: DetachedMetadataFilter,
    pub progress: Option<PushProgress>,
}

impl Repo {
    pub async fn push(&self, remote: &str, opts: RepoPushOptions)
        -> Result<PushOutcome>;

    pub async fn push_over_stream<R, W>(&self, input: R, output: W,
                                        opts: RepoPushOptions)
        -> Result<PushOutcome>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;
}
```

The struct carries no `#[non_exhaustive]`, and a caller builds it with
`..Default::default()`. `RepoPushOptions` is re-exported at the crate root.

The push holds the lock of the local repository shared from the start of the
call to its end. A prune of the local repository takes the lock exclusive, so
it waits for the push, and it fails with `Error::LockTimeout` after
`[core] lock-timeout-secs`.

Before it writes a byte, the push refuses:

- a `depth` below `-1`, as `Error::Push` with `InvalidInput`;
- an empty list of refspecs, an empty refspec, `:`, an empty `DST`, and a
  `DST` that two refspecs name, as `Error::Push` with `InvalidInput`;
- a checksum `SRC` and a `SRC` with a `^` suffix, each with no `DST`, as
  `Error::Push` with `InvalidInput`;
- a `DST` that `validate_refspec` refuses, a `DST` that holds a `^`, and a
  `DST` of 64 lowercase hex characters that takes a commit, as
  `Error::InvalidRefspec` with the `DST`. A revision reads a `DST` of 64
  lowercase hex characters as a commit checksum. A delete (`:DST`) of a
  `DST` of 64 lowercase hex characters passes;
- a `SRC` that does not resolve, with the error of `Repo::resolve_rev`;
- a source commit that the local repository marks partial, as `Error::Push`
  with `InvalidInput`;
- a source commit whose `ostree.ref-binding` is a list that does not hold its
  `DST`, as `Error::Push` with `BindingMismatch`. The message names the
  binding. A commit with no binding, or with an empty list, passes, as on the
  server.

The push reads commit objects alone before it opens the session:

- `depth` `None` (the default): the parent chain of each source commit to the
  root.
- `Some(0)`: each source commit alone. `Some(n)`: `n` parents more.
  `Some(-1)`: the whole chain.
- Each chain stops at the first commit that the local repository does not
  hold. It also stops at the first commit that the local repository marks
  partial. With `Some(n)`, the chain stops before that commit. With `None`,
  that commit is the last commit of the chain, so the cut can find the
  server tip there. The push does not walk the tree of a partial commit.
- The push reads each commit once, also when two chains share it.

The session opens with the `DST` of each refspec, in the order of the
refspecs. After `HelloReply`:

1. The push checks the `ostree.collection-binding` of each source commit.
   When the server has a collection id and a binding differs from it, the
   push sends no object. It ends the session with `Abort` and fails with
   `Error::Push` with `BindingMismatch`.
2. With `depth` `None`, the push cuts each chain at the server tip of its
   `DST`, the tip excluded. A chain that does not hold the tip keeps the
   source commit alone. This occurs when the server does not hold the
   `DST`. It also occurs when an absent or a partial commit stands between
   the source commit and the tip. When the tip is the partial commit that
   ends the chain, the cut is a normal cut. The server decides whether the
   update is a fast-forward. With `Some(n)`, the chains stay as the push
   read them.
3. The first `Have` round offers the commits: each source commit and each
   commit of the chains, each once.
4. The push walks the tree of each source commit, also when the server holds
   that commit. The server checks the tree of each commit of the session.
   The push also walks the tree of each history commit that the server
   lacks. It does not walk the tree of a history commit that the server
   holds. Each dirtree is walked once, and the walk loads up to 8 dirtrees
   at the same time. A dirtree or a dirmeta that the local repository lacks
   ends the session with `Abort`, and the push fails with
   `Error::ObjectNotFound`.
5. The second `Have` round offers the objects of those trees.
6. The push sends the commits and the tree objects that the server lacks.
   It sends the detached metadata of each commit that it sends, after
   `detached_metadata_filter`. It also sends the detached metadata of each
   source commit that the server holds. It sends no
   detached metadata for a history commit that the server holds.
7. Each ref update expects the state of `HelloReply`: `Commit(tip)`, or
   `Absent` when the server does not hold the ref. With `force`, each update
   expects `Any`, and `Commit` carries `force`. `:DST` is an update with no
   new commit.

A push whose refspecs are all deletes runs no `Have` round and sends no
object. A failure of the push after the session opened and before `Commit`
ends the session and returns that failure. The push writes `Abort` when the
stream is still usable. A refusal of the server is `Error::Push` with the error of the server. `opts.progress` goes to
the session, so its counters show the push while it runs.

The push reads objects through a source over the repository. Its
`content_size` reads the metadata of each file object in one pass on the
blocking pool, and no payload byte:

- one `statat` of the stored `.filez`, when an `archive` repository sends
  it as it is in `deflate`;
- an open and the read of the file header of an `archive` object
  otherwise, a symlink as 0;
- an open, the read of the `user.ostreemeta` xattr, and an `fstat` of a
  `bare-user` object, which is a regular file also for a symlink, a
  symlink as 0;
- one `statat` of an object of the other modes, a symlink as 0.

`ostrya push`, under the `push` feature of `ostrya-cli`, is the command
form of `Repo::push`:

```text
ostrya push [--repo=PATH] REMOTE SRC[:DST]...
            [--depth=N] [--force] [--compress[=LEVEL]]
            [--ssh-command=CMD] [--receive-command=CMD]
            [--push-token-file=FILE] [--push-user=NAME]
            [--tls-client-cert-path=FILE] [--tls-client-key-path=FILE]
            [--tls-ca-path=FILE] [--allow-cleartext-credentials]
```

- `REMOTE` is the `remote` argument, and each `SRC[:DST]` is one of
  `refspecs`. It is a remote name, an ssh address, or an `http://` or
  `https://` address.
- `--depth=N` sets `depth` to `Some(N)`. Without it, `depth` is `None`.
  When the server does not hold the ref, or the local chain does not hold
  the server tip, the push then sends the source commit alone.
  `--depth=-1` sends the whole local chain.
- `--force` sets `force`.
- `--compress` sets `compression` to `Compression::Deflate { level: 6 }`,
  and `--compress=LEVEL` to the level, 1 to 9. The value needs the `=`
  form. Without the option, `compression` is `Compression::None`.
- `--ssh-command=CMD` sets `connect.ssh_command` to `CMD` split at ASCII
  whitespace, and `--receive-command=CMD` sets `connect.receive_command`.
- `--push-token-file`, `--push-user`, `--tls-client-cert-path`,
  `--tls-client-key-path`, and `--tls-ca-path` set the fields of
  `connect` with the same names, and `--allow-cleartext-credentials` sets
  `connect.allow_cleartext_credentials`. So each option wins over the key
  of the remote with its name, and `PushSession::prepare` refuses an option
  of the other transport, before the push reads `--depth` and the
  refspecs.
- `detached_metadata_filter` comes from `[ex-ostrya]
  detached-metadata-exclude` of the local repository. `progress` is a
  `PushProgress` whose hook draws the progress bar of the command, or
  `None` when the bar is hidden.
- The progress bar goes to standard error through `indicatif`, at most 20
  frames a second. It is hidden when standard error is not a terminal, or
  when `TERM` is unset or `dumb`. A hidden bar gives `progress: None`, so
  the session asks for no byte total and calls no hook. The bar shows
  nothing before `Negotiating`, so a prompt of the ssh client or of a
  signer stays readable. It then shows a spinner with `Negotiating`, and a
  bar of `content_bytes` against `bytes_total` with `SENT/NEEDED objects`,
  the bytes, the rate, and the time left in `Uploading`. The template reads
  the object counts when it draws, so a hook call builds no string. When
  `bytes_total` is 0 the upload shows the bytes and the rate with no bar.
  The last frame can show less than 100%.
- The bar clears when the phase becomes `Committing`, and it draws nothing
  after that, so a line that the server writes on standard error at the
  commit starts on a clean line. The command also clears the bar before it
  writes a ref line, the statistics line, or an error line.
- Known gaps: a line that the server writes on standard error while the
  objects go can show in the middle of the bar, and Ctrl-C, another signal
  that stops the process, or a panic leaves the last frame on the terminal.
- After the repository opens, a missing `REMOTE` gives the usage text and
  `error: REMOTE must be specified`, and no refspec gives the usage text and
  `error: REFSPEC must be specified`. Both exit 1 before an ssh client
  starts.
- On success the command writes one line for each `RefOutcome` to standard
  output, in the order of the refspecs: the name, then the old commit or
  `(new)` or `(absent)`, then the new commit or `(deleted)` or
  `(unchanged)`. A commit is its full checksum. The forms are
  `main (new) C1`, `main C1 C2`, `main C2 (unchanged)`,
  `main C2 (deleted)`, and `main (absent) (unchanged)`, the last for a
  delete of a ref that the server does not hold. It exits 0.
- Under `-v` one line of `PushStats` goes to standard error: the objects
  offered, needed, and sent, the bytes sent, and the elapsed time.
- On failure the command writes `error: MESSAGE` to standard error and
  nothing to standard output, and exits 1. After
  `Error::CommitOutcomeUnknown` the refs of the server may have changed. A
  repeat push is safe, because each update is a compare-and-swap.
- When a ref line cannot go to standard output, the command writes
  `error: MESSAGE` to standard error and exits 1. The refs of the server
  have changed at that point.

`Repo::export_stream`, under the `push` feature, writes the commits that a
set of ref updates name as one one-way stream, for `Repo::receive_stream`
under the `receive` feature on the other side of a channel that carries data
in one direction. It has no CLI command.

```rust
#[derive(Debug, Clone, Default)]
pub struct ExportStreamOptions {
    pub updates: Vec<RefUpdate>,   // expected Absent or Any, new commit set
    pub compression: Compression,
    pub detached_metadata_filter: DetachedMetadataFilter,
}

impl Repo {
    pub async fn export_stream<W>(&self, output: W, opts: ExportStreamOptions)
        -> Result<PushStats>
    where
        W: AsyncWrite + Unpin + Send;
}
```

The struct carries no `#[non_exhaustive]`, and a caller builds it with
`..Default::default()`. It has no `force` field, because the stream sends
`force` false, and no progress field. `ExportStreamOptions` is re-exported
at the crate root.

- The stream holds each new commit of `updates` once, each object its tree
  reaches, and its detached metadata after `detached_metadata_filter`. It
  holds no parent commit. The sender does no negotiation.
- The export holds the lock of the local repository shared for the whole
  call, as `Repo::push` does.
- Before it writes a byte, the export refuses empty `updates`, a ref named
  twice, an update whose expected state is `Commit`, an update with no new
  commit, and a commit that the local repository marks partial, as
  `Error::Push` with `InvalidInput`. It refuses a ref name that
  `validate_refspec` refuses, and a ref name of 64 lowercase hex characters
  that an update writes, as `Error::InvalidRefspec`. A delete of such a
  name is refused as an update with no new commit. A remote ref
  `REMOTE:NAME` with a `NAME` of
  64 hex characters passes. It refuses a commit
  whose `ostree.ref-binding` is a list that does not hold the name of its
  ref as `Error::Push` with `BindingMismatch`. For a remote ref
  `REMOTE:NAME` the check compares `NAME` alone. A dirtree or a dirmeta that
  the local repository lacks is `Error::ObjectNotFound`. A level outside 1
  to 9, and a `Hello` or a `Commit` frame over 1 MiB, are `Error::Push` with
  `InvalidInput`.
- The export does not check before the stream that each file object
  exists. A missing file object, and another failure of the source, end the
  stream inside the object that the export was to send, with the abandon
  marker and `Abort`. The export returns `Error::Push` with `Source`, and
  the receiver returns `push::Error::Aborted`.
- An `archive` repository sends a file object in `deflate` as the bytes of
  its stored `.filez` file.
- The export writes `output` in blocks of 64 KiB, so the caller need not
  give a buffered writer. It flushes `output` after `Commit` and does not
  close it. The caller closes it, and the close gives the end of file that ends the
  stream. `W` has no `'static` bound, and a caller that keeps its writer
  gives `&mut W`.
- The `PushStats` of an export count each object of the stream as offered
  and as needed. The phases are `Uploading` and then `Committing`.

## Archive view and HTTP server

`ArchiveView` of `ostrya` builds in every feature set. It answers the
request paths of an HTTP pull over a repository of any mode as an `archive`
repository answers them (`format-reference.md`, "The archive view"). The
view builds `config` for each request, serves stored files through a walk
that follows no symlink, and builds each `.filez` of a mode other than
`archive` on request. At most `MAX_COMPRESSORS` (16) built `.filez` bodies
deflate at the same time, and each takes its compressor at its first read
past the header, so a body dropped before that read does no deflate work. A
built body fails when the stored file holds another size than its header
states, and each read after an error fails too. `head` gives the answer of
a `HEAD`: the same routing and walk, and for a built `.filez` a check of the
object with no read of its xattrs or of its payload. One request reads a
changed `config`, and the requests that see the same change wait for its
parse.

```rust
pub struct ArchiveView { /* private; Send + Sync */ }

impl ArchiveView {
    pub fn new(repo: Repo) -> ArchiveView;
    /// `path` is relative to the repository root, with no leading `/`.
    pub async fn get(&self, path: &str) -> Result<ArchiveAnswer>;
    pub async fn head(&self, path: &str) -> Result<ArchiveHead>;
}

pub enum ArchiveAnswer {
    Bytes(Vec<u8>),                       // the built `config`
    Stream { len: Option<u64>, body: Box<dyn AsyncRead + Unpin + Send> },
    NotFound,
    Refused,
}

pub enum ArchiveHead {
    Found { len: Option<u64> },           // None: a `.filez` built on request
    NotFound,
    Refused,
}
```

The crate `ostrya-server` serves the view over HTTP. It builds on Linux
alone, and its features `smol` and `tokio` select the runtime backend.

```rust
pub struct ServerTls {
    pub cert_chain_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub key_passphrase: Option<String>,
    pub client_ca_pem: Option<Vec<u8>>,   // client certificates, optional
}

#[non_exhaustive]
pub struct ServeOptions {
    pub listen: Vec<SocketAddr>,          // default 127.0.0.1:8080
    pub tls: Option<ServerTls>,           // None: plain HTTP
    pub body_timeout: Duration,           // default 60 s; zero is refused
    pub receive: Option<Arc<ReceivePolicy>>, // None: read-only server, the default
    pub allow_anonymous_push: bool,       // default false
    pub credentials: Option<Vec<u8>>,     // the push credential file; default None
    pub allow_cleartext_credentials: bool, // default false
    pub parallel_uploads: u32,            // default 4; 1..=31
    pub session_idle_timeout: Duration,   // default 300 s; zero is refused
    pub max_sessions: usize,              // default 16; zero is refused
    pub on_report: Option<Arc<dyn Fn(ReceiveReport) + Send + Sync>>, // default None
}

pub async fn bind(repo: Repo, opts: ServeOptions) -> Result<Server>;
pub async fn serve(repo: Repo, opts: ServeOptions) -> Result<()>; // bind, then run

impl Server {
    pub fn local_addrs(&self) -> &[SocketAddr];
    /// Serves until the future is dropped, which ends every connection.
    pub async fn run(self) -> Result<()>;
}
```

A connection ends when one of its response bodies waits longer than
`body_timeout` for the client to take its next bytes, so a client that stops
reading releases its file and its compressor. An HTTP/2 connection sends a
ping after half of `body_timeout` with no frame from the peer and ends when
the ping gets no answer within `body_timeout`. A stream body gives at most
256 KiB before it yields to the executor. Each listener accepts in a task of
its own.

With `receive` set, the HTTP/2 receive window of a stream is 2 MiB, and the
window of a connection is 2 MiB times `parallel_uploads`. The request bodies
of one connection thus hold at most that many bytes that the server did not
read. A read-only server keeps the windows of hyper.

With `receive` set, the server also runs the receive endpoint of a push
over the repository. Every session shares the one policy. The endpoint
reads the policy and the repository settings once, at start, and a change
applies at the next start. `bind` refuses `receive` with no authentication
method, a `parallel_uploads` outside `1..=31`, a zero
`session_idle_timeout`, and a zero `max_sessions`, with `Error::Options`.
With no `tls`, `bind` also refuses with `Error::Options` an endpoint whose
one method is the lines of `credentials`, unless
`allow_cleartext_credentials` or `allow_anonymous_push` is set: the endpoint
refuses each bearer and Basic credential over plain HTTP, so no request can
pass it. With `receive` set, `bind` parses `credentials`, and a malformed
line is `Error::Credentials { line, message }`, which names the line by its
number and holds no byte of it. A read-only server reads neither
`credentials` nor `allow_cleartext_credentials`. The `Debug` text of
`ServeOptions` states `credentials` by its length alone.

Authentication. The methods of the endpoint are:

- A bearer token, `Authorization: Bearer TOKEN`, which matches a line of
  `credentials` by the SHA-256 digest of the token.
- A Basic credential, `Authorization: Basic` with the base64 of
  `NAME:TOKEN`, which matches the line of `NAME` by the digest of `TOKEN`.
- A client certificate that the TLS handshake verified against
  `ServerTls::client_ca_pem`. The TLS layer also serves a client with no
  certificate, because a read needs no authentication.
- `allow_anonymous_push`, for a request with no credential.

A credential file with no credential line is no method. The grammar of the
file is in `docs/format-reference.md`, "Port extension: the push credential
file". The compare of two digests reads each digest as four 64-bit words,
and ORs the XOR of each word pair through `core::hint::black_box`. The
result goes through `black_box` too. A request compares its digest with the
digest of every line and does not stop at a match. A Basic credential then
compares its `NAME` with the name of the one line whose digest matched. No
two lines have one digest.
The server authorizes each request of the endpoint, in this order:

1. More than one `Authorization` header gets 401.
2. A `Bearer` or `Basic` scheme, in any case, on a connection without TLS
   gets 403, before any digest, also when `allow_anonymous_push` is set,
   unless `allow_cleartext_credentials` is set.
3. A header that matches no line gets 401, also beside a valid client
   certificate. A scheme other than `Bearer` and `Basic`, an empty token,
   and a Basic credential with no `:` match no line.
4. With no header: a verified client certificate gives its owner, then
   `allow_anonymous_push` gives the anonymous owner. Else the request gets
   401 when `credentials` has a line, and 403 when the client CA is the one
   method.

Each refusal carries an `unauthorized` frame. Each 401 carries the two
headers `WWW-Authenticate: Bearer realm="ostrya"` and `WWW-Authenticate:
Basic realm="ostrya"`. The owner of a session is the `NAME` of the line of
its `session` request, the SHA-256 digest of the DER bytes of the client
certificate, or anonymous. A bearer token and a Basic credential of one line
give one owner. Every request of a session is authorized again, and a
request of another owner gets the 404 of an unknown id. A `GET` and a
`HEAD` of the archive view ignore `Authorization`, so a read with a Basic
credential over plain HTTP succeeds.

The endpoint takes the requests under the raw path prefix
`/_ostrya/receive/v1/` with a method other than `GET` and `HEAD`. The path
is not percent-decoded. A `GET` or a `HEAD` there goes to the archive view
and gets 404. Each request is one step of the `ReceiveService` of its
session.

- `POST session` -- body: one `Hello` frame. 200 with the `HelloReply`
  frame, and the session id in the response header `Ostrya-Session`.
- `POST session/ID/have` -- body: one `Have` frame. 200 with `HaveReply`.
- `POST session/ID/objects` -- body: one object stream. 200 with
  `ObjectsReply`.
- `POST session/ID/commit` -- body: one `Commit` frame. 200 with
  `CommitReply`.
- `DELETE session/ID` -- no body. 204 with no body and no
  `Content-Length`. The session ends, and each request of the session in
  flight gets 422 with `protocol`.

A path under the prefix that names no route gets 404 with no body. A known
path with another method gets 405 with `Allow: POST`, or `Allow: DELETE` for
`session/ID`. The body of `session`, `have`, and `commit` holds one frame of
at most `MAX_FRAME`, 1 MiB. An empty body, a body that ends inside its
frame, and a byte after the frame are `protocol`. The buffer of the frame
grows with the bytes that arrive, and not with the length that the frame
states. One read of a request body takes the frames that hyper has ready
until the buffer of the read is full.

Sessions:

- The session id is 32 bytes from `getrandom::fill`, the random source of
  the operating system, shown as 64 lowercase hex digits. A failure of the
  random source is a 500 for that request. The parser of a request path
  takes 64 lowercase hex digits alone.
- The table holds one entry for each session: the service in an `Arc`, the
  owner, the time of the last activity, the count of the requests in
  progress, the request bodies in flight with the time each one started to
  wait for the client, and a cancel signal. The table lock is never held
  while a service is aborted or dropped.
- A `session` request takes a slot after its `Hello` body is read. With
  `max_sessions` sessions open or opening, it gets 503 with
  `limit-exceeded` and `the server serves no more sessions`. The `Hello`
  body must arrive in full within the idle timeout.
- An id that the table does not hold and a session of another owner get the
  same empty 404. The table holds no session that ended.
- Each step of `have`, `objects`, and the read of the `Commit` body races
  the cancel signal of its session. When the session ends first, the step
  is dropped and gets 422 with `protocol` and `the session was aborted:
  CAUSE`.
- A step that fails ends its session: the entry goes, its cancel signal
  fires, and the service is aborted. The cause is `a request of the session
  failed`. A request that ends before its response, as when the client
  closes the connection, ends its session in the same way, with the cause
  `a request of the session ended before its response`. A request body that
  hyper fails, as when the client closes the connection in the middle of
  the body, gives that cause too. A session that commits is left to its
  commit.
- The commit runs in a task of its own, so a disconnect, a `DELETE`, or the
  idle timeout does not drop it in the middle. A second `commit` and a
  `DELETE` while the session commits get 422 with `protocol` and `the
  session is committing`, and the first commit continues. The session keeps
  its entry and its slot of `max_sessions` until the commit ends. Then the
  task removes the entry, with the cause `the session committed` when the
  commit succeeded, and `a request of the session failed` when it failed. A
  guard in the task removes the entry with the second cause also when the
  commit panics or the task is dropped.
- One sweep task runs in `Server::run`. It aborts a session with no request
  in progress for `session_idle_timeout`, and a session with a request body
  that waited for the client for that time. A body waits from the poll that
  finds no byte to the next byte. A body that the server does not poll does
  not wait. The sweep sleeps to the earliest deadline, and at most one idle
  timeout, and never aborts a session that commits.
- When the future of `Server::run` drops, every session that does not
  commit is aborted, and the table takes no session after that. A
  `session` request then gets 503 with `limit-exceeded`, also when it took
  its slot before the stop: its service is aborted and dropped.

The status of an error: `ref-mismatch` and `non-fast-forward` get 409.
`internal`, and each error with no wire code, get 500 with an `internal`
frame of the error text. A request that no authentication method accepts
gets 401 or 403 with `unauthorized`, as the authorization states. Every
other code gets 422. A response with an
error carries one `Error` frame. 404, 405, and 204 have no body. No response
of the endpoint carries `Content-Type` or `Retry-After`. Before a refusal
that comes before the body is read (the authentication, 404, 405, 204, and
the 422 of a `DELETE` while the session commits), the server reads and drops
up to 1 MiB of the body within `session_idle_timeout` or 5 seconds,
whichever is shorter. On HTTP/1.1 a body that did not reach its end then
gets `Connection: close`. The body of an authorized `session`, `have`,
`objects`, or `commit` request keeps the bound of `session_idle_timeout`.

The report of each commit goes to `on_report` when the response body drops.
When hyper did not take the `CommitReply` frame from the body, the report
gets a `ReceiveWarning` with the step `ReplyNotDelivered`, also when the
client left before the commit ended. hyper can take the frame and still fail
to write it, so the warning is best effort. `on_report` runs on a task of
the server and must return soon.

`ostrya_fetch::server_config` builds the TLS configuration from the PEM
bytes, with the provider and the key loaders of the fetcher, and ALPN `h2`
then `http/1.1`. `FuturesIo`, `WriteVectored`, `RtExecutor`, and `RtTimer`
of `ostrya-fetch` drive the hyper connections of the server over
`ostrya-rt`.

## Pull over ssh: the serving side

`Repo::send` serves one pull session over a pair of streams, through one
`ArchiveView` of the repository. It takes no feature of `ostrya`. `ostrya
send` calls it with standard input and standard output, and an ssh pull
runs that command on the remote side. The wire protocol is in the module
docs of `ostrya::push::proto`.

```rust
impl Repo {
    /// Serves one pull session over a pair of streams. Takes no lock.
    pub async fn send<R, W>(&self, input: R, output: W) -> Result<()>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;
}
```

The session:

1. The client sends `PullHello` with the highest pull version it speaks.
   The server replies `PullHelloReply` with the lower of that version and
   `PULL_PROTOCOL_VERSION`. `PullHello` with version 0 gets `Error` with
   `version-unsupported`.
2. The client sends `Get` frames, each with the path of one file relative to
   the repository root. The server answers each `Get` with one `GetReply`,
   in the order of the `Get` frames. A body of chunks follows each reply
   with found true.
3. The client closes the input of the server at a frame boundary. `send`
   returns `Ok`.

Rules:

- The session builds one `ArchiveView`, so the requests share the parsed
  `config` and the idle compressors of the view. The view answers each
  path as it answers an HTTP `GET`. A path that the view refuses and a path
  that it does not find both get `GetReply` with found false, and the
  session goes on.
- `GetReply` holds the length of the body when the view knows it: the built
  `config` and a stored file. A `.filez` built on request has no length.
- The session reads one `Get`, answers it to the end of its body, and then
  reads the next. It drops each body before the next `Get`, so a built
  `.filez` gives its compressor back first.
- The session opens no transaction and takes no lock, neither the
  repository lock nor the update lock. Read access to the repository is
  sufficient for an `archive`, `bare-user`, `bare-user-only`, or
  `bare-user-shared` repository. A `bare` or `bare-split-xattrs` repository
  needs an account that can read every object and its extended attributes.
- The frame limit is `MIN_FRAME_LIMIT`, 1 MiB, in both directions. No
  message announces another limit.
- Each direction goes through a buffer of 64 KiB. The session writes each
  body in chunks of 64 KiB less 4 bytes, and fills each chunk to full or to
  the end of the body before it writes the chunk. So each write to the
  output is at most 64 KiB, and no write holds a chunk length alone.
- The session flushes its output when its input buffer holds no complete
  frame, before a read that can wait, and after an `Error`. It reads the
  input buffer through `FrameReader::get_ref` and polls no read future,
  because the futures of `FrameReader` are not cancel-safe. The end of the
  input adds no flush, and `send` does not close the output.
- A body streams through one chunk buffer. No content object is whole in
  memory. The memory of a session is the two stream buffers, the chunk
  buffer, one `Get` frame, and the reader of the current body: a
  `FileReader` ring of 4 KiB to 256 KiB, or a compressor and two buffers of
  64 KiB for a built `.filez`. A `Get` frame at the limit of 1 MiB adds
  about 2 MiB: the frame body and the decoded path are in memory at the
  same time.

Failures:

- A failure with a wire code goes to the client as `Error` and returns as
  `Error::Push` with that code: `version-unsupported` for `PullHello` with
  version 0; `protocol` for a `Get` before `PullHello`, a second
  `PullHello`, a kind of the push, `PullHelloReply`, `GetReply`, or `Error`
  from the client, a malformed frame, and an end of input inside a frame;
  `limit-exceeded` for a frame over 1 MiB.
- A failure of the view before the reply, for example a file that the
  account cannot read (`EACCES`), goes to the client as `Error` with
  `internal` in place of the reply, and returns as the error it is. An error
  of the input other than an end of file does the same.
- A body that fails after its reply ends with `ABANDON` and `Error` with
  `internal`, and `send` returns the error. A stored file is read to at most
  one byte past its stated length. A file that ends before that length
  returns `Error::Io` of kind `UnexpectedEof`, and a file that holds more
  returns `Error::Io` of kind `InvalidData`.
- A failed write of a reply or of a body to the output sends nothing more
  and returns `Error::Io`. A failure to deliver the `Error` message does not
  change the returned error.

## Pull over ssh: the client side

`PullSession` of `ostrya-push` is the client half of the pull over ssh, and
`Repo::pull_over_stream` wraps it as the ssh source of the pull driver. Both
take no feature.

```rust
// ostrya-push
#[derive(Debug, Clone, Default)]
pub struct PullConnectOptions {
    pub ssh_command: Option<Vec<String>>,       // default ["ssh"]
    pub send_command: Option<String>,           // default "ostrya send"
    pub remote_ssh_command: Option<String>,     // remote key, below the env
}

#[derive(Debug, Clone, Default)]
pub struct PullSessionOptions {
    pub agent: Option<String>,                  // default "ostrya/<version>"
    pub max_outstanding: Option<usize>,         // Get frames in flight; 8;
                                                // 0 is raised to 1
}

pub struct PullSession { /* private */ }        // Send + Sync

impl PullSession {
    pub async fn over_stream<R, W>(input: R, output: W,
                                   opts: PullSessionOptions)
        -> Result<PullSession>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static;
    pub async fn connect(remote: &PushRemote, connect: PullConnectOptions,
                         opts: PullSessionOptions)
        -> Result<PullSession>;
    pub async fn get(&self, path: &str, max_len: u64)
        -> Result<Option<PullBody>>;
    pub async fn finish(self) -> Result<()>;
}

pub struct PullBody { /* private */ }           // AsyncRead, Send + Sync
impl PullBody {
    pub fn len(&self) -> Option<u64>;           // the stated length
}
```

The session:

- `over_stream` and `connect` send `PullHello` with `PULL_PROTOCOL_VERSION`
  and read `PullHelloReply`. A reply with a version that the client does not
  speak is `Error::VersionUnsupported`, and the session closes its output
  and sends no `Get`. `connect` refuses an HTTP address with
  `Error::InvalidInput`, and runs `SSH_COMMAND... [-p PORT] [USER@]HOST
  'SEND_COMMAND --repo=QUOTED_PATH'`. The ssh command resolves from
  `ssh_command`, then `OSTRYA_SSH_COMMAND`, then `remote_ssh_command`, then
  `ssh`, as for the push.
- A `get` waits while `max_outstanding` calls hold a place in the pipeline.
  It then takes its place, and writes and flushes its `Get` frame under one
  lock, so the frames go on the wire in the order of the places. The places
  and the writes are each served in the order the calls arrive.
- The call returns at the head of its reply. `None` is a path that the
  server does not serve. The session moves to the next reply when it reads
  the chunk that ends a body, also while the caller still holds that body.
- A stated length above `max_len` ends the session with
  `Error::LimitExceeded` before the body is read. The body is held to
  `max_len` and to its stated length: a difference from the sum of the
  chunks is `Error::Protocol`. After `ABANDON` the body reads the `Error`
  frame and fails with its code.
- A failed read of a body gives an `io::Error` that carries the error of the
  session, with the kind of an I/O error.
- A failure ends the session: an `Error` of the server, a reply out of order,
  a length check, a failed read or write, a `get` future dropped after it
  took its place, and a body dropped before its end. Each later call, and
  each later read of a body, fails with an error of the variant and the
  message of the first failure, and an I/O error keeps its kind. A dropped
  call or body is `Error::InvalidInput`.
- When the write of a `Get` frame fails, the call reads the message that the
  server can have sent, at the turn of its reply, for at most 5 seconds on a
  session that `connect` opened. An `Error` is the error of the call.
- `finish` after a clean end, when every reply was read to its end and the
  caller holds no body, closes the output and returns `Ok` whatever the exit
  status of the ssh client. At any other end it closes the output and drops
  the input before it waits for the ssh client, and returns the error of the
  session, or `Error::InvalidInput` for a body still held, whose later reads
  then fail with that error. When that error
  is `Error::Io` and the ssh client exited with a failure status, it returns
  `Error::Transport` with the status. The wait for the ssh client takes at
  most 5 seconds. A session over a pair of streams sets no time limit.

The pull through the ssh source:

- `Repo::pull_over_stream` resolves the signature policy, then opens the
  session over the streams, then runs the pull of `Repo::pull` through the
  ssh source: the summary, the refs, the deltas, the commit walk, `depth`,
  the subpaths, the transaction, and the statistics. `remote` names the
  remote whose configuration the pull reads: the policy, the `branches`, and
  the prefix of the refs.
- The source asks for each file by the path of the HTTP pull. A ref goes as
  written, with no percent-encoding. A body is held to the cap of its path:
  `MAX_ROOT_FILE` for `summary`, `summary.sig`, and `config`, `MAX_REF_FILE`
  for a ref, `MAX_METADATA_SIZE` for a metadata object, a `.commitmeta`, an
  index, and a superblock, the size of the part in the superblock for a part,
  and no whole read for a `.filez`.
- The source sends the `Get` of `summary.sig`, `summary`, and `config` as
  three calls in flight together, and the `Get` of a `.commitmeta` and of its
  commit as two, in the order of the HTTP pull. The HTTP pull keeps its
  requests one after another.
- A content object of the ssh source takes no write permit. The session
  streams one body at a time, and the stores that finish after the end of
  their body are bounded by `max_outstanding_fetches`. The HTTP pull keeps
  its three write permits.
- `PullStats::bytes_transferred` counts the bytes of the bodies the source
  reads, from the same point as the HTTP count, so it equals the HTTP count
  for the same files. A wrapper of each body in `ostrya` adds them to the
  counters of the pull.
- After the plan ends, and before the transaction commits, the source ends
  the session with `finish`. The pull also ends the session on each error.
  The error of a failed pull is the error of the step that failed first. When
  that error came from the session, `Error::Push`, it takes the error that
  `finish` gives, so an I/O error under a failed ssh client becomes
  `Error::Transport`. An error of the session is `Error::Push`.
- `url`, `connect.ssh_command`, and `connect.send_command` are
  `Error::InvalidInput` for `pull_over_stream`.

The pull over ssh to an address:

- `Repo::pull` takes its address from `url`, then from the remote key
  `pull-url`, then from the remote key `url`. A value that starts with
  `ssh://`, or that holds no `://`, is an ssh address of `PushRemote::parse`,
  and a malformed one is `Error::InvalidInput` with the text of the parser.
  Any other value goes to the fetcher as written. An ssh address in the
  `url` key is `Error::Pull`, and so is a section with neither key.
- With an ssh address, `http_headers`, `n_network_retries` above 0,
  `low_speed_limit_bytes`, and `low_speed_time` are `Error::InvalidInput`
  before the ssh client starts. The message names the option of `ostrya
  pull` without `--`. `n_network_retries` of `Some(0)` is accepted.
- The remote keys `ssh-command` and `send-command` fill
  `connect.remote_ssh_command` and `connect.send_command` where they are
  `None`, also when the address comes from `url`. The pull reads no
  `contenturl`, `metalink`, or `tls-*` key.
- `Repo::pull` resolves the signature policy, then starts the ssh client with
  `PullSession::connect`, at the point where the HTTP pull sends its first
  request, and then runs the pull of `pull_over_stream`.
- `Repo::remote_fetch_summary` takes the address of the remote by the same
  rule, with no `url`. Over ssh it reads `summary.sig` and `summary` as two
  calls in flight together, and ends the session before it returns. The
  library caller sets the ssh command through `ssh-command` or
  `OSTRYA_SSH_COMMAND` alone.
- With an HTTP address, `Repo::pull` refuses `connect.ssh_command` and
  `connect.send_command` with `Error::InvalidInput`, and reads neither
  `connect.remote_ssh_command`, `ssh-command`, nor `send-command`.

## Static deltas

The three size thresholds are in bytes, where the tool's options take decimal
megabytes. Generation signs the superblock with the signers `DeltaOptions`
names before it writes the superblock, so a signer that fails leaves no
superblock. `sign_static_delta` adds a signature to a delta already written.
Index publication is a separate call, so a caller publishes once.

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
    /// Write the superblock to this file and the part files to the directory
    /// that holds it. The directory must exist. Refused beside `output_dir`.
    pub superblock_file: Option<PathBuf>,
    /// Sign the superblock with each signer, in order, before it is written.
    pub signers: Vec<Arc<dyn Signer>>,
    /// Carry each part in the superblock metadata dict under
    /// `deltas/<fanout>/<rest>/<i>` and write no part file. The parts count
    /// toward the 128 MiB superblock ceiling. A generation over the ceiling
    /// writes no file, and an earlier delta at the same location stays whole.
    pub inline: bool,
    /// The `ostree.endianness` byte and the order of the four size fields.
    /// Default `Little` on every host.
    pub endianness: DeltaEndianness,
}
impl Repo {
    /// Returns the directory the delta was written to: relative to the
    /// repository root for the default location, and `output_dir` or
    /// `superblock_file` verbatim where one is set.
    pub async fn generate_static_delta(&self, from: Option<&Checksum>,
        to: &Checksum, opts: &DeltaOptions) -> Result<PathBuf>;
    /// Apply the delta in `dir` and return the commit it delivered. A part the
    /// superblock carries inline is read from there, also where a part file of
    /// the same number is present.
    pub async fn apply_static_delta_offline(&self, dir: &Path) -> Result<Checksum>;
    /// Apply a superblock already read, with the part files in `parts_dir`.
    /// The superblock is not read again, so a caller that checks it with
    /// `DeltaSuperblock::verify` first applies the bytes it verified.
    pub async fn apply_static_delta(&self, superblock: DeltaSuperblock,
        parts_dir: &Path) -> Result<Checksum>;
    pub async fn sign_static_delta(&self, dir: &Path, signer: &dyn Signer) -> Result<()>;
    pub async fn verify_static_delta(&self, dir: &Path, verifiers: &[&dyn Verifier])
        -> Result<VerifyOutcome>;
    /// Rebuild the `delta-indexes/` cache that advertises the stored deltas to
    /// a fetcher. Entries are in delta-name order; the tool's are in
    /// hash-table order.
    pub async fn reindex_static_deltas(&self) -> Result<()>;
    /// Rewrite the index file of target `to` alone from the deltas into it,
    /// or remove the file where none is left. The index files of other
    /// targets stay, and `to` is not checked for a commit object.
    pub async fn reindex_static_deltas_to(&self, to: &Checksum) -> Result<()>;
    /// The stored deltas, sorted, each named as the tool names it: the target
    /// commit hex, or `<from-hex>-<to-hex>`. An entry counts only where its
    /// fanout and its delta path are directories, not symlinks, and its
    /// `superblock` resolves.
    pub async fn list_static_deltas(&self) -> Result<Vec<String>>;
    /// The target commits `delta-indexes/` holds an index file for, sorted.
    pub async fn list_static_delta_indexes(&self) -> Result<Vec<Checksum>>;
    /// Remove one delta's `deltas/<fanout>/<rest>` entry and all below it,
    /// following no symlink. The fanout directory, `delta-indexes/`, and
    /// `summary` stay. An absent delta is `Error::StaticDeltaNotFound`.
    pub async fn delete_static_delta(&self, from: Option<&Checksum>, to: &Checksum)
        -> Result<()>;
}
/// `deltas/<fanout>/<rest>` for a delta, relative to the repository root.
pub fn static_delta_relative_dir(from: Option<&Checksum>, to: &Checksum) -> String;
```

A superblock is read without a transaction, so a read-only repository can
report one. The part statistics check a part against its declared size and
checksum before they decompress it, and read the part in up to three passes,
so no payload is held and no temp file is written. The xz decoder takes at most
128 MiB, and a part whose xz stream needs more is refused.

```rust
pub struct DeltaSuperblock { /* fields private */ }
impl DeltaSuperblock {
    pub fn parse(bytes: Vec<u8>) -> Result<DeltaSuperblock>;
    /// Read a superblock file, signed or not, under the metadata ceiling.
    pub async fn read(path: &Path) -> Result<DeltaSuperblock>;
    pub fn from_commit(&self) -> Option<&Checksum>;
    pub fn to_commit(&self) -> &Checksum;
    pub fn is_signed(&self) -> bool;
    /// Verify the signed envelope against `verifiers`: valid when any verifier
    /// reports a valid signature; `Error::Signature` with no envelope.
    pub async fn verify(&self, verifiers: &[&dyn Verifier]) -> Result<VerifyOutcome>;
    pub fn endianness(&self) -> DeltaEndianness;
    pub fn timestamp(&self) -> u64;
    /// Field 5's byte length over 64.
    pub fn parent_count(&self) -> usize;
    pub fn parts(&self) -> &[DeltaPart];
    pub fn fallbacks(&self) -> &[DeltaFallback];
    pub fn relative_dir(&self) -> String;
    /// Part `index`, from the metadata dict where the superblock carries it
    /// inline and from `dir/<index>` otherwise.
    pub async fn part_stats(&self, index: usize, dir: &Path) -> Result<DeltaPartStats>;
}
/// What a superblock declares, and what the generator writes.
pub enum DeltaEndianness { Little, Big }
impl DeltaPart {
    pub fn checksum(&self) -> &Checksum;
    pub fn size(&self) -> u64;
    pub fn uncompressed_size(&self) -> u64;
    pub fn objects(&self) -> &[(ObjectType, Checksum)];
}
impl DeltaFallback {
    pub fn object_type(&self) -> ObjectType;
    pub fn checksum(&self) -> &Checksum;
    pub fn size(&self) -> u64;
    pub fn uncompressed_size(&self) -> u64;
}
pub struct DeltaPartStats {
    pub modes: u64,
    pub xattrs: u64,
    pub blob_size: u64,
    pub ops_size: u64,
    pub ops: DeltaOpCounts,
}
pub struct DeltaOpCounts {
    pub open_splice_close: u64,
    pub open: u64,
    pub write: u64,
    pub set_read_source: u64,
    pub unset_read_source: u64,
    pub close: u64,
    pub bspatch: u64,
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

pub struct TarExportOptions {
    /// The directory within the commit tree that becomes the archive root.
    pub subpath: Option<PathBuf>,
    /// A prefix over every member pathname.
    pub prefix: Option<String>,
    /// Emit no `SCHILY.xattr.*` records.
    pub skip_xattrs: bool,
}

/// A rename hook over member pathnames. It takes the normalized member name
/// and returns the name the member is imported under.
pub type TarRename = Box<dyn FnMut(&str) -> Result<String> + Send>;

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
/// record holding the digest of its content. A backing object that is the raw
/// payload and is sealed with SHA-256, 4096-byte blocks, and no salt gives the
/// digest the kernel holds, and no payload byte is read, so damage to a sealed
/// object is not found there; `fsck` is the check for object integrity. Every
/// other backing object, and every `archive` object, streams its payload to
/// compute it. `Disabled` gives the metacopy
/// xattr an empty value and reads no payload; the image it produces has its own
/// fs-verity digest, distinct from the `ostree.composefs.digest.v0` value a
/// commit records.
pub enum VerityPolicy { Computed, Disabled }

/// Options for a composefs export.
pub struct ComposefsOptions { pub verity: VerityPolicy }

impl Repo {
    /// Produce the EROFS/composefs image for a commit and its fs-verity digest.
    /// Inode metadata comes from each file object as `load_file` reads it in
    /// the repository's mode, and each regular file redirects to its `.file`
    /// loose path. Ownership is presented via composefs uid mapping at mount.
    /// The export runs in every repository mode; an image exported from an
    /// `archive` repository mounts over a store that holds the objects in
    /// `.file` form. Every backing object is opened under either policy,
    /// because the inode's metadata comes from it.
    pub async fn export_composefs(&self, commit: &Checksum,
        opts: &ComposefsOptions) -> Result<Image>;
    /// Write that image through `out` and return its fs-verity digest. Emission
    /// is append-only, so the image reaches the descriptor as it is serialized
    /// and no image-sized buffer is held. `out` is written from its current
    /// offset onward and is never seeked, and a call that fails leaves the
    /// prefix it had already written. The mode scope and `opts` are those of
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
    /// in every repository mode, as `Transaction::composefs_digest` does.
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
assertions are pinned in `crates/ostrya/src/tar.rs`. The futures of
`import_tar` and `import_tar_into` are `Send` when `input` is `Send`, with or
without a `rename` hook and a modifier. `crates/ostrya/tests/tar.rs` pins this.

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
