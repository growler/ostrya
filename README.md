# Ostrya

Ostrya (n. a botanical genus within the family Betulaceae, commonly known as
ironwood tree) is a pure-Rust, async implementation of the ostree repository
system, written from scratch. It has two parts:

- `ostrya`, a library that reads and writes ostree repositories;
- `ostrya`, a command that does the work of the `ostree` command.

The library and the command are complete for the management of repositories
and commits. Each one writes the same bytes on disk that the `ostree` command
writes. The command carries each command of `ostree` except the few that
"Relation to ostree" lists. The largest of these is `ostree admin`, the
sysroot and deployment functions.

## Capabilities

Ostrya does these operations on an ostree repository:

- Repositories: create a repository in each mode, and read and write the
  `config` file. The modes are `archive`, `bare`, `bare-user`, and
  `bare-user-only`. Ostrya also reads the `bare-split-xattrs` mode.
- Remotes: add, delete, and list remotes, and manage the trusted GPG keys of
  each remote.
- Commits: commit a directory or a tar stream, with metadata, a parent, and a
  collection binding.
- Reading: resolve revisions, list refs, show commits and objects, print the
  log of a ref, list the files of a commit, and print file content.
- Checkout and export: check out a commit into a directory, and write the tree
  of a commit as a tar stream.
- composefs: store the composefs digest of a tree in the commit metadata, and
  write the composefs EROFS image of a commit.
- Pull: pull from a remote over HTTP or HTTPS, and from a local repository.
  A pull can use static deltas and a local cache, and it can make a mirror.
  A pull verifies signatures. A collection pull takes each ref of a
  collection from the configured remote that has the newest commit.
- Signing: sign and verify commits and summaries with the ed25519, spki, and
  GPG engines.
- Maintenance: prune unreachable objects, verify the objects of each commit,
  compare two revisions, generate and sign the summary, and generate, apply,
  and index static deltas.
- Integrity: seal objects with fs-verity.

## Port extensions

Ostrya adds these functions, which the `ostree` command does not have:

- Concurrent transactions. Many transactions can write to one repository at
  the same time, in one process.
- Push. `ostrya push` sends commits to a remote over ssh or HTTP and updates
  its refs, also the refs of a collection. `ostrya push --onto` and
  `ostrya push-tree` send a tree, and the server makes the commit and can
  sign it. `ostrya receive` is the server side of a push over ssh.
- Pull over ssh. `ostrya pull` reads from an ssh address, and `ostrya send` is
  the server side.
- HTTP server. `ostrya serve` serves a repository of any mode to the pull of
  `ostree` and of Ostrya, and receives pushes. It identifies a client by a
  bearer token, a Basic credential, a TLS client certificate, or a network
  address, also behind a trusted proxy.
- Client access. Client groups in the `config` file give each client the
  access modes of each ref. The same groups apply to `serve`, `receive`, and
  `send`.
- GC anchors. The key `[ex-ostrya] gc-root-metadata-keys` of the `config`
  file names metadata keys that hold commit checksums. A prune keeps each
  commit that such a key names in the metadata or the detached metadata of a
  kept commit. A library caller can add keys to a prune. A write of commit
  metadata refuses a value that a prune cannot read.
- The `bare-user-shared` mode, for development. It is `bare-user` storage
  with the fixed file mode 0644, for a repository that one group shares.
- composefs image objects. `ostrya commit --generate-composefs` and
  `ostrya composefs-image --add` store the composefs image of a commit in the
  repository, as `objects/<xx>/<commit>.cfs`. The fs-verity digest of the
  image is the digest that the commit records. `ostrya composefs-image`
  also checks a stored image and prints its path. Prune removes the image
  with its commit, and fsck checks it. A pull, a push, and a static delta
  carry the image with its commit, and `ostrya serve` and `ostrya send` serve
  it.
- composefs mounts. The library `ostrya-mount` mounts a commit as a composefs
  tree on Linux, from its stored image or from an image that it builds in
  memory. The mount reads the objects of the repository in place.
- Library functions: a staging tree with a tree merge, and the import of an
  overlay changeset.

`docs/format-reference.md`, part "Port extensions", specifies the formats and
the protocols of these functions.

## Relation to ostree

Ostrya and the `ostree` command use the same repository format. The `ostree`
command reads each repository that Ostrya writes, and Ostrya reads each
repository that the `ostree` command writes. The `bare-user-shared` mode, a
repository that holds a composefs image object, and a static delta that
carries one are the exceptions, because only Ostrya writes them.

The `ostrya` command is functionally compatible with the `ostree` command. A
command that `ostrya` carries takes the same option names and values, does the
same work, and writes the same bytes into the repository. The text that a
command writes to the terminal can be different. Where `ostrya` cannot accept
a value with the meaning that `ostree` gives it, `ostrya` refuses the value and
exits with a non-zero status.

These `ostree` commands have no counterpart in `ostrya`:

- `admin`, the sysroot and deployment functions;
- `reset`, `checksum`, and `create-usb`;
- `find-remotes`: `ostrya pull --collection=ID` does the work of
  `find-remotes --pull`, with the configured remotes as the only candidates.
  `ostrya` has no command that finds remotes and pulls nothing;
- `gpg-sign`: `ostrya sign --sign-type=gpg` does the same work, with
  different option names;
- `remote add-cookie`, `remote delete-cookie`, and `remote list-cookies`.

`ostrya init` does not create a `bare-split-xattrs` repository, because Ostrya
does not commit into that mode.

`docs/conformance/cli-surface.md` records each difference between the two
commands.

## The ostrya command

The `ostrya` command has these subcommands:

- `init`, `config`, and `remote`: create and configure a repository.
- `commit`: commit a directory or a tar stream.
- `refs`, `rev-parse`, `show`, `log`, `ls`, and `cat`: read the repository.
- `checkout` and `export`: write the tree of a commit into a directory, a
  composefs image, or a tar stream.
- `diff`: report the paths that changed between two revisions or directories.
- `pull` and `pull-local`: copy commits from a remote or from a local
  repository.
- `sign` and `summary`: sign and verify commits, and generate the summary.
- `static-delta`: list, generate, apply, and index static deltas.
- `prune` and `fsck`: delete unreachable objects and verify the repository.
- `composefs-image`, `push`, `push-tree`, `receive`, `send`, and `serve`: the
  port extensions.

Each subcommand has a man page, for example `ostrya-commit(1)`. The page
`ostrya-repo(5)` describes the layout of a repository, and the page
`ostrya-config(1)` lists each key of the `config` file.

Example:

```sh
ostrya init --repo=repo --mode=archive
mkdir -p rootfs/etc && echo example > rootfs/etc/hostname
ostrya commit --repo=repo --branch=exampleos/stable --subject='Build 1' rootfs
ostrya log --repo=repo exampleos/stable
ostrya checkout --repo=repo exampleos/stable checkout
```

This example serves the repository over HTTP and pulls the ref into a second
repository:

```sh
ostrya serve --repo=repo --listen=127.0.0.1:8080 &
ostrya init --repo=client --mode=bare-user
ostrya remote add --repo=client --no-gpg-verify origin http://127.0.0.1:8080/
ostrya pull --repo=client origin exampleos/stable
ostrya refs --repo=client
```

## The library

Add the library to `Cargo.toml`:

```toml
[dependencies]
ostrya = "0.3"
```

This example commits the directory `/var/tmp/build/rootfs` into the
repository `/srv/repo`, and points the ref `exampleos/stable` at the new
commit. The ingest takes a parent directory and a path relative to it:

```rust
use std::os::fd::AsFd;
use std::path::Path;

use ostrya::{CommitOptions, MutableTree, Repo};

let repo = Repo::open(Path::new("/srv/repo")).await?;
let txn = repo.transaction().await?;

let build_dir = std::fs::File::open("/var/tmp/build")?;
let mut mtree = MutableTree::new();
txn.write_dfd_to_mtree(build_dir.as_fd(), Path::new("rootfs"), &mut mtree, None)
    .await?;
let root = txn.write_mtree(&mut mtree).await?;

let opts = CommitOptions {
    subject: Some("Build 1".into()),
    ..CommitOptions::default()
};
let commit = txn.write_commit(opts, &root).await?;
txn.set_ref("exampleos/stable", Some(&commit));
let stats = txn.commit().await?;
println!("{} content objects written", stats.content_written);
```

The API documentation is on [docs.rs](https://docs.rs/ostrya).
`crates/ostrya/README.md`, section "Design", gives the design principles of
the API and its relation to the C API of libostree.

The features of the `ostrya` crate are:

- `smol` (default) and `tokio`: the async runtime.
- `sign-spki`: the spki signing engine.
- `verify-gpg`: GPG signature verification and key management.
- `sign-gpg`: GPG signing through the `gpg` command. It turns on `verify-gpg`.
- `push`: the client side of a push.
- `receive`: the server side of a push.
- `lzma-static`: xz built from source and linked statically.

## Design

- Pure Rust. Two C libraries are the exceptions. The library links `liblzma`
  for xz in static deltas. The `ostrya` command links PCRE2 for the
  `commit --tar-pathname-filter` expression. The `lzma-static` feature builds
  `liblzma` from source and links it statically. The `ostrya` command turns on
  this feature by default, so it needs no `liblzma` at run time.
- Async. The runtime is `smol` by default, or `tokio` with the `tokio`
  feature. Only the internal `ostrya-rt` crate knows the runtime.
- Concurrent transactions. A `Transaction` owns its staging directory and its
  counters. A `Repo` holds only shared state, and a clone of it is cheap.
  `Repo`, `Transaction`, `FileObject`, and the content readers and writers are
  `Send + Sync`.
- Byte-exact format. Field layouts, byte orders, sort orders, and checksum
  algorithms are the same as those of ostree. Golden fixtures that the
  `ostree` command writes verify this. The conformance harness verifies it in
  both directions: each implementation operates a repository that the other
  wrote.
- Streaming. File content moves in chunks of bounded size. Hashing,
  compression, storage, checkout, and transfer never hold a full file in
  memory. Only a metadata object is held whole, because the format limits its
  size.
- No unsafe code. Each crate has `#![forbid(unsafe_code)]`, except two audited
  sites: the `ostrya-sys` crate and the allocation-counting test harness.

## Crates

The project is a Cargo workspace of these crates:

- `ostrya-gvariant`: the byte-exact GVariant codec for the types that ostree
  uses.
- `ostrya-core`: the object model, checksums, and the serialization of the
  format.
- `ostrya-rt`: the internal async runtime layer, for `smol` or `tokio`.
- `ostrya-sys`: wrappers for the Linux fs-verity ioctls, a read-only memory
  map, the loop device, and a sealed memory file.
- `ostrya-sign`: the signing engines: dummy, ed25519, spki, and GPG.
- `ostrya-fetch`: the async HTTP/1.1 and HTTP/2 client, with TLS over
  `rustls`.
- `ostrya-remote`: the wire protocol and the client sessions of the push and
  of the pull.
- `ostrya-composefs`: the composefs EROFS image writer and the fs-verity
  digest.
- `ostrya-server`: the HTTP server of one repository, for pull and push.
- `ostrya`: the library.
- `ostrya-mount`: the composefs mount of a commit on Linux.
- `ostrya-cli`: the `ostrya` command. It is not published to crates.io.
- `ostrya-conformance`: the conformance harness that compares Ostrya with the
  `ostree` command. It is not published to crates.io.

## Building and installing

The workspace builds on stable Rust, edition 2024, minimum version 1.92.

To build and install the `ostrya` command with Cargo:

```sh
cargo install --path crates/ostrya-cli
```

To build the `ostrya` command with Nix:

```sh
nix build .#ostrya        # ./result/bin/ostrya
```

The flake gives the package as an overlay in `overlays.default`, so another
flake can use `pkgs.ostrya`.

The flake also gives the NixOS module `nixosModules.default`. Each item of
`services.ostrya-serve.instances` runs one `ostrya serve` process as the
systemd unit `ostrya-serve-<name>.service`. Each option of an instance that
is not set adds no flag, so the key of `[ex-ostrya server]` in the repository
config applies. The client groups, the trust groups, and the key groups are
in the repository config.

Two instances can serve one repository. The example below serves plain HTTP
on port 80 and HTTPS on port 443. The keys of `[ex-ostrya server]` apply to
the two instances, so the TLS files are options of the `https` instance.

```nix
services.ostrya-serve.instances =
  let
    common = {
      repo = "/srv/ostree/repo";
      user = "ostree";
      group = "ostree";
      openFirewall = true;
    };
  in
  {
    http = common // {
      listen = [ { address = "::"; port = 80; } ];
    };
    https = common // {
      listen = [ { address = "::"; port = 443; } ];
      tls.certFile = "/etc/ostrya/server.pem";
      tls.keyFile = "/etc/ostrya/server.key";
    };
  };
```

The Debian packaging is in `crates/ostrya-cli/debian`. The Nix package and the
Debian package install the man pages.

`CONTRIBUTING.md` gives the procedures for development: the tests, the golden
fixtures, and the man pages.

## Clean-room provenance and licensing

Ostrya is a clean-room reimplementation. Its design comes only from the public
ostree documentation (<https://ostreedev.github.io/ostree/>) and from the
observed behavior of the `ostree` command. The LGPL source of libostree is not
consulted on any stage of the development. 

The on-disk format is an interoperability interface. A run of the `ostree`
command can verify each fact of `docs/format-reference.md` outside the part
"Port extensions", except a fact labeled "Not observed" or "Design target". A
run of Ostrya can verify each fact of the part "Port extensions".

## Documentation

The design documents in `docs/` are the source of truth:

- `docs/format-reference.md`: the byte-exact on-disk format, and the formats
  and protocols of the port extensions.
- `docs/conformance/cli-behavior.md`: the observed behavior of the `ostree`
  command.
- `docs/conformance/cli-surface.md`: the command surface of Ostrya, and each
  difference from the `ostree` command.
- `docs/port-plan.md`: the architecture, the test strategy, and the roadmap.

## License

MIT. The `LICENSE` file gives the text of the license.
