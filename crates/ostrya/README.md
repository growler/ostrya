# ostrya

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly known as
_ironwood tree_\] is a pure-Rust, async implementation of the ostree repository
system, written from scratch.

An async, pure-Rust library that reads and writes ostree repositories.

A user opens a repository, writes commits in transactions, reads and checks out
trees, and pulls, pushes, signs, and prunes. The bytes on disk are the bytes
that the `ostree` command writes. Many `Transaction`s can write to one
repository at once in one process.

As an extension, the crate also has a push protocol over HTTP and over ssh. With
the `push` feature, `Repo::push` sends commits to a remote, and `Repo::push_onto`
asks a remote to commit the tree of a local commit. With the `receive` feature,
the `receive` module takes a push on the server side. With the `push` and `s3`
features, `Repo::push_to_bucket` writes commits to a bucket repository in an S3
bucket, `BucketRepo::push_tree` writes a local directory to one as a new commit,
and `BucketRepo::init` creates one.

API documentation: <https://docs.rs/ostrya>

## Entry points

- `Repo::open` and `Repo::create` give a `Repo`, the handle of a repository.
- `Repo::transaction` begins a `Transaction`, which publishes objects and refs at
  commit.
- `StagingTree` and `MutableTree` build the tree of a new commit.
- `Repo::checkout_at` writes the tree of a commit into a directory.
- `Repo::pull` copies commits from a remote, and `Repo::pull_local` from a local
  repository.
- `Repo::pull_with_session` copies commits from a remote through a session of the
  caller.
- `Repo::pull_collection` copies the refs of a collection from the remotes that
  serve it.
- `Error` is the error of each fallible operation of the crate.

## Modules

- Read: `read`, `file`, `tree`, `refs`, and `traverse`.
- Write: `transaction`, `mtree`, `staging_tree`, `commit`, `modifier`, `bootable`.
- Checkout and export: `checkout`, `composefs`, `tar`, and `archive`.
- Pull: `pull`, `summary`, `fetch`, the HTTP client of `ostrya-fetch`, and
  `remote`, which holds the session of a pull over HTTP, over ssh, or over a pair
  of byte streams.
- Push and receive: `remote`, the wire protocol of `ostrya-remote`, and `receive`.
- Client access: `access`, the client groups and the server settings of the
  config, the claims of a client certificate, and the read rights of a
  client.
- Remote resolution: `endpoint`, which reads the keys and files of a remote for a
  pull or a push.
- Bucket repositories: `bucket`, a repository in an S3 bucket, with the init,
  the writer lock, the listing of the objects, the fsck, the prune, and the
  summary update.
- Signing: `sign`, `gpg`, and `spki`.
- Signature trust: `verify`, the trusted keys and the trust of one pull.
- Maintenance: `prune`, `fsck`, `diff`, `update`, and `config`.
- Static deltas: `DeltaSuperblock`, `DeltaOptions`, `AdvertisedDelta`, and
  `Repo::generate_static_delta`.

## Features

- `smol` (default): the `smol` backend of `ostrya-rt`.
- `tokio`: the `tokio` backend of `ostrya-rt`.
- `sign-spki`: the `spki` module, the spki signing engine with each of its
  key types. It turns on `sign-spki-p256` and `sign-spki-rsa`.
- `sign-spki-p256`: the `spki` module with the ECDSA P-256 key type.
- `sign-spki-rsa`: the `spki` module with the RSA key type. A build with one
  of the two key features refuses a key of the other type.
- `verify-gpg`: the `gpg` module, GPG verification and keyring management.
- `sign-gpg`: `GpgSigner`, which signs with the `gpg` command. It turns on
  `verify-gpg`.
- `receive`: the `receive` module, the receive side of a push.
- `push`: `Repo::push`, `Repo::push_onto`, and `Repo::export_stream`, the push
  from a repository.
- `s3`: the pull from a bucket repository at an `s3://` address and the pull
  of collection refs from one, the `bucket` module with the fsck, the prune,
  and the summary update of a bucket repository, the `s3` module of
  `ostrya-remote`, and with `push`, the push of commits and of a local
  directory to a bucket repository.
- `lzma-static`: xz built from source and linked statically, with no runtime
  liblzma.

## Examples

```rust
let repo = ostrya::Repo::open("/srv/repo".as_ref()).await?;
let tip = repo.resolve_rev("exampleos/stable", false).await?;
```

## Design

The API is idiomatic Rust. The bytes on disk follow the format reference of the
project.

- `Repo` is cheap to clone. It holds its state in an `Arc`, so a handle moves
  between tasks. `Repo::open` does the descriptor and config work once, and each
  clone shares it.
- The runtime backend is a feature of the internal `ostrya-rt` crate: `smol` by
  default, or `tokio`. `ContentReader`, `ContentWriter`, and the hashing streams
  implement the `futures-io` traits with each backend, and the `tokio` traits with
  the `tokio` feature. A caller needs no adapter for these types.
- An `AsyncRead` or `AsyncWrite` bound in an argument, as in `write_content`,
  `import_tar`, and `export_tar`, is the `futures-io` trait. A caller on tokio
  adapts its stream with `tokio_util::compat`.
- Each I/O entry point is an `async fn`. A filter callback and an xattr callback
  are synchronous.
- `rustix` makes the namespace and metadata syscalls: the opens relative to a
  descriptor, stat, link, rename, the xattrs, reflink, `O_TMPFILE` with `linkat`,
  the record locks, and the syncs. These calls are synchronous. They run on the
  blocking pool of `ostrya-rt` in steps that each group several calls, and not
  one step for each call. The content of a file streams through the `File` and
  `FileReader` of `ostrya-rt`, over a descriptor that the `rustix` layer opened.
- To cancel an operation, drop its future. To cancel on a signal, race the future
  against that signal.
- Each fallible operation returns `ostrya::Error`, one enum for the crate.
- File content is never whole in memory. Hashing, compression, storing, checkout,
  and transfer read and write async streams in chunks of bounded size. Only a
  metadata object is held whole, because the format caps its size.
- `Repo`, `Transaction`, `FileObject`, and the file content readers and writers
  are `Send + Sync`. Compile-time assertions in the tests hold this.

### Relation to the C API

The public documentation of libostree describes a C API with GLib types. This
crate maps that API to Rust as follows:

- Cancellation is the drop of a future. The crate has no `GCancellable`.
- A result comes back in `Result<T>`. The crate has no out-parameters.
- Options are builders and structs. The dynamic `Value` of `ostrya-gvariant` holds
  commit metadata, which is an arbitrary `a{sv}`.
- A descriptor is a `BorrowedFd` or an `OwnedFd`. The crate has no raw `dfd: i32`.
- The functions of the C repository object are split: `Repo` for the lifecycle,
  the reads, the checkout, and the maintenance, and `Transaction` for all writes.
  The `Signer` and `Verifier` traits make signing pluggable, and the progress
  handles give live counters.
- RAII guards hold the scoped state: a transaction aborts when it drops without a
  commit, a lock releases when its guard drops, and `Checksum` is a typed value.
