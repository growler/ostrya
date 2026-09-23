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
  `RefNotFound`, `HttpStatus` with status 404.
- `NotADirectory`: `NotADirectory`, `ReplaceFileWithDir`.
- `AlreadyExists`: `EntryExists`, `MergeConflict`, `ReplaceDirWithFile`.
- `InvalidInput`: `MutableTree`.
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
    /// The run holds the repository lock exclusive from end to end, a
    /// `no_prune` dry run and a `static_deltas_only` run included. It reads
    /// `[core] locking` and `[core] lock-timeout-secs`, and it fails with
    /// `Error::LockTimeout` where another holder keeps the lock past the
    /// timeout. The hold excludes every other writer, in this process and in
    /// another: a caller holding a transaction of its own open across the call
    /// waits out the timeout and then fails, and a transaction the process
    /// opens while the run stands waits for the run to finish.
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
    /// `[core] lock-timeout-secs` and then fails.
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
pub struct Command;                     // subprocess, for gpg signing
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
pub struct MetadataReader { /* rt::File + the running total */ }
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
    /// `summary.sig`. The batch of one signer.
    pub async fn sign_summary(&self, signer: &dyn Signer) -> Result<()>;
    /// Append one signature per signer, in slice order, reading `summary` and
    /// `summary.sig` once and replacing `summary.sig` in one write. A signer
    /// that fails stops the batch before the write. An empty slice writes
    /// nothing.
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
    pub async fn secret_key_fingerprints(&self) -> Result<Vec<String>>;
}

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
    /// name of the keyring.
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

The HTTP client pull is built on. One `Fetcher` serves one remote: it holds the
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
`io::ErrorKind::TimedOut`. `fetch_timeout` bounds the mirror rounds and the
retries together, from admission to the response head, which is what caps how
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
reports that status whatever the hop count. Every request is a GET, so none of
the five changes the
method of the hop that follows it. `Location` is resolved against the URL of
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
    pub fetch_timeout: Option<Duration>,  // default 300s: mirrors and retries
                                          // together, up to the response head
}

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
    // the blocking pool, whatever the mirrors' scheme. A store holding no
    // certificate fails the constructor when a mirror is https, and when the
    // mirror list is empty, since a request may then name an https URL; a
    // fetcher whose mirrors are all cleartext builds without anchors, and a
    // fetch of a TLS destination over it is refused before admission. Either
    // bypass variant reads no store, so the constructor reaches no file and no
    // blocking pool and an https mirror needs no anchors. Both keep the
    // handshake signature check.
    // Clone, Send + Sync.
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
    pub detached_metadata_filter: DetachedMetadataFilter,  // what to store
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
