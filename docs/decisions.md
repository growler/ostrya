# Ostrya -- Design Decisions

This document records the design decisions of the port and the alternatives
that were rejected, with the reason for each. The on-disk format is in
`format-reference.md`. The observed behavior of the `ostree` command is in
`conformance/cli-behavior.md`, and each difference from it is in
`conformance/cli-surface.md`. The rustdoc of each crate documents the API.

## Dependency policy

The port is pure Rust. The Rust crate ecosystem is in scope, and C libraries
are excluded. `CLAUDE.md`, "Goals", states the two exceptions: `liblzma` for
xz, and PCRE2 in the `ostrya-cli` binary alone. Each is built from source and
linked statically under its feature, and needs no C runtime beyond the libc
that `std` links.

These C libraries are excluded, with the Rust path that replaces each:

- `openssl-sys` -- TLS through `rustls` with the `rustls-graviola` provider,
  and ECDSA through `p256` and `p384`.
- `libgpg-error` and `gpgme` -- GPG signing through the system `gpg` binary,
  and GPG verification through the `pgp` crate.
- `libcurl` and `libsoup` -- HTTP through `hyper`.
- `libarchive` -- tar through `smol-tar`.
- `libcomposefs` -- composefs images through `ostrya-composefs`.
- `glib` -- GVariant through `ostrya-gvariant`, and the key file through
  `ostrya-core`.

Two CI steps in `.github/workflows/ci.yml` hold the rules over the whole
graph. One step holds the permissive-license rule. The other step fails on a
package that declares a `links` key and is not on its allowlist. The comments
of the two steps state their rules.

## Foundation crates

The workspace crates take these external crates directly. `CLAUDE.md` has an
"Authorized" section for each crate it marks so, with the terms of its
feature set and its graph.

- `rustix` -- the syscalls that a portable async file API cannot express:
  fd-relative open, stat, link, rename, readlink and mkdir, xattrs, statx,
  statvfs, FICLONE, O_TMPFILE with linkat, record locks, and fsync and
  syncfs.
- `smol` -- the default runtime backend, in `ostrya-rt` alone.
- `tokio` -- the optional runtime backend, in `ostrya-rt` alone.
- `futures-io` and `futures-lite` -- the async traits and the combinators
  that the library is written against.
- `pin-project-lite` -- pin projection for the stream wrapper types.
- `sha2` -- SHA-256, for object checksums, for fs-verity digests, and for
  the SigV4 signer of the `s3` feature of `ostrya-remote`.
- `hmac` -- HMAC-SHA256 for the SigV4 signer, in `ostrya-remote` under its
  `s3` feature. See "SigV4 and the AWS credentials".
- `miniz_oxide` -- the raw DEFLATE encoder of archive-mode content objects.
  `ostrya-core` takes it directly, so the stored `.filez` bytes for a given
  `[archive] zlib-level` are the same under each feature set. The golden
  SHA-256 vectors in `crates/ostrya-core/src/deflate.rs`, one for each level
  from 1 to 9, fail the test suite if a new version writes other bytes.
- `async-compression` -- streaming DEFLATE inflate of archive-mode content
  objects, and streaming xz of static-delta parts.
- `liblzma` -- the xz codec behind `async-compression`.
- `bsdiff` -- bspatch stream generation for static deltas. It has no
  dependencies and no `unsafe`. The port reads the streams with its own
  bspatch.
- `smol-tar` -- async tar import and export.
- `ed25519-dalek` -- the ed25519 sign engine and the Ed25519 key type of the
  spki sign engine, in `ostrya-sign`.
- `p256` -- the spki sign engine, in `ostrya-sign`.
- `pgp` -- OpenPGP keyring parsing and signature verification, in
  `ostrya-sign` under the feature `gpg`.
- `hyper` -- the HTTP/1.1 and HTTP/2 engine of `ostrya-fetch` and
  `ostrya-server`. Both crates take version 1.11.1 or later. Version 1.11.0
  can keep the last chunk of a response body in its write buffer when the
  first poll of the body is pending, and then the response does not end.
- `rustls`, `rustls-graviola`, `futures-rustls`, `rustls-native-certs` and
  `rustls-pemfile` -- TLS. See "TLS stack".
- `url` and `pkcs8` -- in `ostrya-fetch`.
- `getrandom` -- in `ostrya-server`.
- `x509-cert` -- in `ostrya-server`, and in `ostrya-sign` under the feature
  `x509`.
- `thiserror` -- the error types.
- `libc` -- in `ostrya-sys`, `ostrya-remote` and `ostrya-sign`.
- `clap` -- command-line parsing, in `ostrya-cli` and `ostrya-mountd`.
- `pcre2` -- the `commit --tar-pathname-filter` expression, in `ostrya-cli`
  alone. See "The expression engine of `--tar-pathname-filter`".
- `indicatif` -- the progress bar of `push` and `push-tree`, in `ostrya-cli`.

## The repository lock

The lock on `<repo>/.lock` is a classic `fcntl` record lock (`F_SETLK`,
through `rustix::fs::fcntl_lock`). An OFD lock was rejected: `rustix` does
not expose the OFD commands, and a raw OFD call needs the `libc` crate and
`unsafe` code.

A record lock and an OFD lock share one lock space. Thus the port and the
`ostree` command exclude each other on the same repository. This was
verified in both directions: each side held its lock while the other side
tried to get the lock.

A record lock belongs to the process, and the kernel releases it when the
process closes any descriptor of the file. Thus a process-global registry,
keyed by the `(device, inode)` of the lock file, keeps one descriptor and one
reference count for each repository. `crates/ostrya/src/lock.rs` documents
the registry.

## The options of an open and of a create

`OpenOptions` holds the options of an open, in the form of
`std::fs::OpenOptions`. `Repo::open` and `Repo::open_at` open with the default
options. A new option is a new method of `OpenOptions`, and adds no
constructor to `Repo`. These forms were rejected:

- `Repo::open_with_config` and `Repo::open_at_with_config`. They give the
  function of `OpenOptions` with two more methods on `Repo`. Also, a reader
  can read `open_with_config` as "a config in place of `config`".
- `Repo::open_with` and `Repo::open_at_with`. They also add two methods to
  `Repo`.
- A command that reads the config itself, or opens a repository two times,
  to apply a default remotes directory. With
  `OpenOptions::default_remotes_dir`, a library user with a default of its
  own gets the order of selection from one open.

`RemotesDir::Fd` holds an `Arc<OwnedFd>`. The handle keeps the value for its
life, so the value owns the descriptor. `Arc` keeps a clone cheap, so
`OpenOptions` and `CreateOptions` are `Clone`. A borrowed descriptor
(`BorrowedFd<'a>`) was rejected: it gives each options type a lifetime, and
the open must duplicate it.

`RemotesDir::InRepo` holds a path relative to the repository directory. After
`open_at`, no path from the working directory names that directory, so a
`Path` value cannot hold it. A form with the two variants `Path` and `Fd` was
rejected. In that form, `Repo::remotes_dir` gives a relative path as written,
and the value names a different directory from each working directory.

`CreateOptions` has private fields and the builder methods `collection_id`
and `remotes_dir`, as `OpenOptions` has. So the two options types have one
form, and a new option is a new method, which is additive. A struct
expression of `CreateOptions` and an assignment to its fields do not compile
outside the crate.

A create with a `RemotesDir::Path` value writes the value of
`std::path::absolute` of the path into `[ex-ostrya] remotes-config-dir`. A
relative `Path` value is relative to the working directory of the process,
which does not name a directory for another process. `std::path::absolute`
needs no existing directory and resolves no symlink, so the key names the
directory that the create took. A create with a `RemotesDir::InRepo` value
writes its path as given, and a `RemotesDir::Fd` value writes no key.

An open and a create refuse an empty path, a path that holds a NUL byte, and
an absolute `InRepo` path with `Error::InvalidInput`, before they open or
write a file. An empty path names no directory. A path with a NUL byte names
no file for a system call, and a create would write the NUL byte into
`config`, which the `ostree` tool then does not open. An `openat` call with an absolute path ignores the directory
descriptor, so an absolute `InRepo` value acts as a `Path` value. The port
refuses it and does not give it that meaning. A caller with an absolute
directory gives a `RemotesDir::Path` value. A create also refuses a path that
is not valid UTF-8, because `config` is UTF-8. An open takes such a path.

## The read of the remotes directory

The open selects the remotes directory of the handle in this order: the value
of `OpenOptions::remotes_dir`, the key `[ex-ostrya] remotes-config-dir` of
`config`, the value of `OpenOptions::default_remotes_dir`, and no directory.
No option turns off the key. The open reads and checks the key also when an
option comes before it, so a repository with an invalid key fails each open,
whatever the options.

The key is in `[ex-ostrya]`, the group of the port keys, so that a later
`[core]` key of libostree cannot clash with it. An absolute value gives a
`RemotesDir::Path`. A relative value gives a `RemotesDir::InRepo`, so it names
the same directory from each working directory. The open refuses an empty
value and a value with a NUL byte with `Error::InvalidFormat`.
`Repo::open_at_strict` reads no key and no directory, so `ostrya-mountd` reads
no `.conf` file.

The open reads `config` and each `.conf` file into the snapshot of
`Repo::config`, and `UpdateGuard::read_config` reads both again. A read on
first use was rejected: `Repo::config` is not async, so the read would block
the task, or each reader would change. A create reads the directory of its
value, or, with no value, the directory that the key of an existing `config`
names, so the handle of a create agrees with its `Repo::remotes_dir`. A later
open gives the same remotes when the key names the same directory. A `Fd`
value writes no key, and a create over an existing `config` writes no key, so
a later open can select another directory.

The own collection id of a handle, `[core] collection-id`, is in the same
snapshot. A handle and each `UpdateGuard` of it map a collection ref with the
id that the open read, so a change of the key applies to a handle of a new
open alone. Until it restarts, `ostrya serve` maps the collection refs,
applies its client groups and the `anonymous` item, and computes its access
digests with the old id, and the `config` file that it serves shows the new
value. Each open reads `config` one time, and the path of a ref name stays the
same over the life of a handle. A live update of the handle on `write_config` was rejected: it makes
`Repo::config` take a shared lock and changes its return type for each
caller, and the server must build its client groups again.

`RepoConfig` keeps the name and the parsed key file of each `.conf` file.
`RepoConfig::keyfile` gives `config` alone, so no write of `config` copies a
remote of the directory into `config`. `Remote::source` gives the file that
holds a remote.

The read follows the rules of the tool for the names, the symlinks, and the
entry types. It also refuses a file larger than 1 MiB and a file whose name or
content is not valid UTF-8, as it refuses such a `config`. The tool reads such
a file, and the cap bounds the memory of the read. The open skips a symlink to an
absent file, as the tool does, and fails on each other failure of a symlink,
such as a loop: the tool result for these is not observed, and a skip would
hide an error of the administrator.

The read takes the `[remote "NAME"]` groups of a file and ignores each other
group, as the tool does. The trust groups stay in `config` alone. The open
refuses a remote name that two sources define, as the tool does, because a
choice of one of the two sources reinterprets the configuration.

The keys `verification-<type>-key`, `verification-<type>-file`, and
`gpgkeypath` of a remote of a `.conf` file work as in `config`. A relative
path in `verification-<type>-file` or in `gpgkeypath` is relative to the
working directory of the process, as in `config` and as the tool does. So a
remote keeps its meaning when it moves between `config` and a `.conf` file,
and no reader of a path needs the source of the remote. A path relative to
the `.conf` file or to the remotes directory was rejected: the same text
would name another file when the remote moves between the two sources.

A create refuses a collection id with a line break. The create writes the id
into `config` as text, so a line break would add groups to `config`, such as
an `[ex-ostrya]` group with the key of the remotes directory.

## The write of the remotes directory

`UpdateGuard::add_remote` writes into the remotes directory when the handle
has one and `[core] add-remotes-config-dir` of `config` is not `false`. Else
it writes into `config`. The default of the key is `true` for a handle with a
remotes directory, so a user of the directory needs no key in `config`. This
is the documented default of the tool for a system repository. The key stays
in `[core]`, where the tool reads it.

The add writes `<dir>/<name>.conf` with the one group of the remote, through
a temporary file in the directory and a rename. The name of the temporary
file starts with `.` and does not end in `.conf`, so an open, which takes no
lock, never reads a partial file. The name is `.ostrya-tmp-<pid>-<n>`, and its
length does not depend on the name of the remote, so the write takes each
name whose `<name>.conf` fits in a file name. The tool creates the file in
place with `O_EXCL`, and the result on disk is the same. The file mode is
`0666` with the umask applied, and an absent directory and its absent parents
get `0777` with the umask applied, as the tool gives them.

The add refuses a name when the directory holds an entry `<name>.conf` of any
type and no source holds the remote. The check is a `stat` that does not
follow a symlink, then a plain rename. The tool replaces such a file, and the
remotes in it are lost. The rule "refuse rather than reinterpret" applies: the
entry can hold remotes of the administrator, or a symlink that a rename would
replace. The add uses a plain rename after the check: the update lock
excludes each other writer of the repository, and `RENAME_NOREPLACE` is
specific to Linux.

`set_remote_key`, `unset_remote_key`, `delete_remote`, and
`UpdateGuard::replace_remote` edit the file that holds the remote: `config` or
its `.conf` file. A remote never moves between two sources, so `--force` of
`remote add` replaces the remote where it is, as the tool does. The replace
removes the group and writes the new group at the end of the same file, as
`--force` writes it in `config`. The other groups of a `.conf` file stay. The
tool writes the file again with the new group alone, and a delete of the tool
removes the whole file. Each of the two loses remotes that the user did not
name, so the port edits the one group. A delete removes the file when no
remote group stays in it. A delete removes `<repo>/<name>.trustedkeys.gpg`
and keeps `<dir>/<name>.trustedkeys.gpg`, as the tool does. A later remote of
the same name trusts the keys of the directory while the repository holds no
keyring of that name.

A rewrite of a `.conf` file keeps the permission bits of the old file, so a
file that the administrator made private stays private. The owner is not
kept, because a change of the owner needs a privilege that the writer can
lack. The port refuses a rewrite of a `.conf` file that is a symlink: a
rename replaces the link with a regular file, and the target, which holds the
remote, keeps the old text. A delete of a file that is a symlink removes the
link, as the tool does.

With `[core] fsync` on, each write of the directory syncs the file and the
directory before the call returns. The directory is outside the repository,
so the syncs of `UpdateGuard::finish`, which name directories relative to the
repository, cannot hold it.

The update lock covers the writes of the directory. It is the lock of one
repository, so two repositories that share one directory do not exclude each
other. Each write changes one entry with one rename or one unlink, so a race
of the two loses at most the edit of one file. A lock in the directory was
rejected for this reason. Each guard call reads `config` and the directory
again under the lock, so a `.conf` file that fails the open and that comes in
after the open fails each edit. The edit then reports the file that the
administrator must correct.

`UpdateGuard::write_config` and `Repo::write_config` refuse a document with a
`[remote "NAME"]` group when a `.conf` file defines `NAME`, with
`Error::RemoteExists`. A write of such a document gives a name in two
sources, which fails each later open. Both writers share one check, which
reads the directory again under the lock. The check reads the remote groups
of the document alone, so a document with no `[core]` group still writes.
`ostrya config set` and `config unset` of a key in such a group refuse before
the lock, as the tool refuses `config set`.

## The remotes directory of the `ostrya` command

The `ostrya` command selects the remotes directory of a repository in this
order:

1. the global option `--remotes-config-dir`, through
   `OpenOptions::remotes_dir`;
2. the key `[ex-ostrya] remotes-config-dir` of `config`;
3. `/etc/ostree/remotes.d`, when the repository is the system repository,
   through `OpenOptions::default_remotes_dir`;
4. no remotes directory.

`ostrya init` gives the option to `CreateOptions::remotes_dir`, so the create
writes the key. The create does not apply step 3. With no `--repo`, `init`
opens the current directory, `OSTREE_REPO`, and `/ostree/repo` in the four
steps, as each other subcommand does. The option has no environment
variable. These forms were rejected:

- A command that reads the key alone. The tool reads the remotes of the
  system repository from `/etc/ostree/remotes.d` with no key, and it ignores
  the key. So that command does not see the remotes that the tool reads on an
  ostree host.
- A command that gives `/etc/ostree/remotes.d` to each repository. Then a
  `remote add` on a scratch repository writes into `/etc/ostree/remotes.d`,
  each `remote add` cell of the conformance harness changes the live
  directory of the test host, and each command fails on a repository whose
  `config` has a remote name of the directory. With the default for the
  system repository alone, the harness never reaches the directory, and the
  command needs no option to turn the default off.

With no `--repo`, the `ostrya` command resolves the repository from the
current directory, then `OSTREE_REPO`, then `/ostree/repo`. The chain ends at
`/ostree/repo`, as the chain of the tool does. The reason is functional
compatibility with the tool. The port runs on ostree hosts, and there the
users of the tool expect a command with no `--repo` to act on the system
repository. So a command that writes also acts on the system repository, and
`remote add` on it writes into `/etc/ostree/remotes.d`.

The system repository is the directory of `/ostree/repo`, as the tool selects
it. The command compares the device and the inode of the two paths, and it
follows symlinks. A compare of the path text was rejected: it misses a
symlink to the repository and a bind mount of it, which the tool takes as the
system repository. The command makes the check before the one open of the
repository, because `default_remotes_dir` is an option of the open, and
`Repo` gives no descriptor of its directory. A path that does not stat is not
the system repository. With `--remotes-config-dir`, the command makes no
check.

The library detects no system repository. It takes a remotes directory from
`OpenOptions` or from the key alone, so the remotes of a handle follow from
the inputs of the open. A program for an ostree host gives
`RemotesDir::path("/etc/ostree/remotes.d")` for the system repository.

The source repository of `ostrya pull-local` and each `--localcache-repo`
open with the key alone, with no option and no default. An open of such a
repository with the option was rejected: the option names the remotes of the
repository of the command, and a second repository that defines one of these
names in its `config` then fails its open with a name in two sources.

The command refuses an empty `--remotes-config-dir` when it parses the
command line, with the usage error of the parser at exit 1. A refusal at the
open, from the check of the library, was rejected: the parse refusal comes
before the command resolves a repository, as the refusal of an empty
`--repo` does.

## The GVariant codec

`ostrya-gvariant` is a GVariant codec written in the tree for the fixed type
set of ostree. No crate was taken, because the port needs byte-exact normal
form and decode with no heap allocation on the read paths.

Each object type has a hand-written codec impl. A proc-macro derive was
rejected. The set of object types is small and fixed, and a derive adds a
proc-macro crate together with `syn`, `quote` and `proc-macro2`. A derive
needs a dependency proposal under the confirmation rule of `CLAUDE.md`.

## The composefs writer

`ostrya-composefs` writes the composefs EROFS image. It is written in the
tree because no crate writes byte-exact composefs images under the no-C
rule. These crates were examined and rejected:

- `erofs/erofs-rs` and `Dreamacro/erofs-rs` read EROFS images and do not
  write them. Neither knows composefs.
- `composefs` (`containers/composefs-rs`, MIT OR Apache-2.0) writes images
  that are byte-identical to `mkcomposefs`. It has a non-optional `zstd`,
  which links C through `zstd-sys`, and a full `tokio`. No feature turns
  either off.
- `am-fs-erofs` writes generic EROFS images. It has no overlay xattrs and no
  fs-verity, and its byte layout is different from composefs.
- `lamfold-erofs`, `gobblytes-erofs`, `liberofs`, `erofs` and `nydus-rs`
  read images only, are stubs, or are container-image stacks.

`ostrya-composefs` writes only the metadata subset that composefs uses, and
no EROFS compression.

The fs-verity digest is a SHA-256 Merkle calculation over `sha2`. The
`fs-verity` crate was rejected because it takes `libc` with no condition.

The XATTR_FILTER field hashes each xattr name with xxHash32. The xxHash32 in
`crates/ostrya-composefs/src/xxhash.rs` is written in the tree to add no
crate. The golden filter bytes verify it.

## The composefs image store

The port stores the composefs image of a commit as a file of the repository
outside `objects/`, `extensions/ostrya/composefs/<xx>/<rest>.cfs`
(`format-reference.md`, "The composefs image store"). So `objects/` holds
only the object types that the `ostree` command knows. No transfer carries an
image: a repository that needs an image builds it.

The name of the file is the checksum of the commit. Two commits that share
one tree each have their own file, with the same bytes, because the image
depends on the tree alone.

Rejected alternatives:

- An image commit that the commit names by `root/composefs` in field 2. A
  commit that is a dependency then cannot carry an image, because a
  dependency names no dependency.
- An image commit that the commit names by `root/composefs` in
  `ostrya.related`. No transfer follows a build source,
  `keep-detached-related=false` drops the entry, and the prune of a bucket
  repository reads no `.commitmeta`. So the image stays local, with more
  indirection than a file.
- A file named by the fs-verity digest of the image. The prune must then
  check each kept commit before it deletes an image.

The prune deletes the image of a commit before the commit, so it leaves no
image whose commit it deleted. It deletes the images of all the commits that
it deletes in one pass before the first commit, and syncs each directory of
the images one time. One sync for each commit costs one open and one sync
of the directories for each deleted commit. A stop between the pass and the
commits leaves unreachable commits with no image, and the next prune deletes
them. The prune does not list the images. An image whose commit is absent
comes only from a change outside the port, and the fsck notes it.

The repository holds no symlink. A ref alias and a symlink object of a
`bare` repository are symlinks that the format allows. They are entries of
the format, so the rule does not apply to them. Each read and write of the
composefs images and of the summaries of the client groups refuses a symlink
at `extensions/`, `extensions/ostrya/`, `extensions/ostrya/composefs/`, and
`extensions/ostrya/summary/`. Each prune and fsck of the composefs images
refuses the same symlinks. A symlink there makes a write or a removal reach
a file outside the repository. The error names the path relative to the
repository root:
`invalid format: PATH is a symlink; ostrya refuses a symlink in the repository`.
The read of a stored image is one `openat2` with `RESOLVE_NO_SYMLINKS`, so
a symlink in its path fails the read with `ELOOP`. `ostrya serve` reads a
summary with a walk that opens each component with `O_NOFOLLOW`. A symlink
there gives no error, and the server answers 404, as for an absent summary.

## The generation of the composefs image

The key `[ex-ostrya] generate-composefs`, default `false`, makes the commit
of a transaction build the image of each complete commit that carries the
digest key. The rule is in `Transaction`, so each writer gets it from one
place.

The writer records its complete commits with the crate-internal
`Transaction::mark_complete`. The transaction cannot find them alone: it
does not see a held partial commit that a pull completes, and at its commit
each commit that a pull staged has a `.commitpartial` marker. The writers
are the commit writes of `Transaction` (`write_commit` and
`write_commit_checked`), the pull from a remote and the local pull, the
receive with ref updates, and `Repo::apply_static_delta`. A pull records the
commits of its markers under the condition that removes the markers after
the commit, and one helper holds that condition.
`Transaction::write_metadata` records no commit, because a pull writes
partial commits through it. `Repo::commit_add_composefs_metadata` and the
server commit of a receive build the image themselves, as
`commit --generate-composefs` does, so each of them reads the tree one time.
They stage the image only if the transaction stages the commit.

The build skips a commit that the transaction did not stage and that has no
marker. So a commit that the repository holds complete before the
transaction gets no image from it, also when a writer writes it again. The
commit writes and `Repo::apply_static_delta` record a commit only if the
transaction stages it. A commit that the repository holds partial is not
staged again, so it gets no image from them. There is no backfill under
the key: `composefs-image --add` and `commit --generate-composefs` build the
image of a held commit.

The build runs in the commit of the transaction, after the transaction
stages its objects and before the publication. `publish()` renames the
images after the objects, so an image is in place only after each object
that its commit reaches. A malformed key, or an image whose digest is not
the key, fails the transaction, so it publishes no object and writes no ref.
For a pull this covers each recorded commit: a target, a parent within the
depth, a dependency, or a held partial commit. One such commit fails the
whole pull, also for a target whose image is correct. A failed pull keeps
no staged object, so a retry fetches each object again.

A receive builds before it takes the update lock, so the other writers of
refs do not wait for the build. A server commit gets its parent from the tip
that the receive reads under the lock. The image depends on the tree alone,
so the receive builds the image of the tree before the lock and checks its
digest against the key of the client. Under the lock, it writes the commit
and stages the image as the image of the commit.

`Repo::transaction_with_lock` reads the key before it takes the lock and
discards the value, so a value that is not a boolean fails each writer
before its first write. A pull from a remote opens its transaction after its
first requests, so the pulls also read the key at their start. The fsck
reads the key at its start for its note of a commit with no image.

The key `true` in an `archive` repository is refused. The generation is for
production repositories, and the mount refuses `archive`. In the other modes
the key is accepted. Where the objects have no fs-verity seal, the build of
the recorded images of a transaction reads and hashes each object one time.
It uses that digest for each commit of the build and each path that names
the object. `Repo::seals_objects` tells if the
repository seals its objects, and the commands that write warn of the cost.
An object that the repository holds from before can have no seal, and the
build reads it. The port does not seal an object at the dedup of a write,
and the fsck does not check the seals.

`commit --generate-composefs` stores the image also with the key `false`.
With the key `true`, `commit --generate-composefs-metadata` takes the same
path, so the command reads the tree one time. The key alone stores no
image of a commit that the repository holds already.
`commit --generate-composefs` stores the image of such a commit, as
`composefs-image --add` does.

Rejected alternative: the transaction removes the markers of a pull, so that
one call decides the marker and the image. It changes the error handling of
three writers and the order of the removal and the refs. The writers keep
the removal of the markers.

## The mount daemon

`ostrya-mountd` mounts a commit as composefs for a caller in a user
namespace of its own. The kernel forced these choices:

- Each request runs in a worker process, the daemon binary run again. The
  kernel refuses `setns(CLONE_NEWUSER)` in a process with more than one
  thread. A process that enters a user namespace cannot go back to its
  parent namespace. Thus a thread of the runtime pool cannot do the steps
  on the side of the caller.
- The worker gives the daemon `open_tree(OPEN_TREE_CLONE)` copies of the
  repository directory and of `objects`. overlayfs takes a layer only from
  the mount namespace of the mounter or from a detached mount, and the
  daemon mounts in its own mount namespace.
- The worker makes an `open_tree(OPEN_TREE_CLONE)` copy of the composefs
  mount of the daemon. overlayfs takes a detached layer only from a process
  with `CAP_SYS_ADMIN` in the user namespace that owns the detached mount.
  The daemon makes the composefs mount in the initial user namespace, so the
  top overlay of the worker on the detached mount of the daemon fails with
  EPERM. The copy belongs to the user namespace of the caller.

The daemon checks that the sent user namespace owns the sent mount
namespace, and that it is not the initial user namespace. It does not check
that the peer is a member of the namespaces that it sends. A client such as
ostree-podman sends the namespaces of podman, which are not its own.

The daemon opens the repository in the strict open mode. Each read of an
object, of `config`, and of the stored image takes `openat2` with
`RESOLVE_BENEATH` and `RESOLVE_NO_SYMLINKS`, so a symlink at any component of
the path stops the read. The open has no fallback to `openat`: kernels older
than 5.6 are not a target of the port, and `ENOSYS` is an error of the open,
as each other errno is.

The daemon reads the stored image as root, and the check of the `objects`
directory does not cover its path. The access to the socket is the trust
boundary, and the documents state the files that a member of the group of
the socket can make the daemon read. Two alternatives were rejected:

- The worker opens the image with the credentials of the caller and gives
  the descriptor to the daemon. This needs a new message between the worker
  and the daemon, and a variant of `Repo::open_composefs_image_checked` that
  takes an open file. The image adds little that the read of `objects/` does
  not give: the daemon mounts an image only if its digest is the key of a
  commit that it reads from `objects/`, and that image holds the tree that a
  built mount makes from `objects/`.
- The worker reads `config` with the credentials of the caller. That change
  is outside the image store.

The reply of the daemon for a stored image that is not the key of its commit
names the commit and neither digest. The error of the library keeps both
digests for `composefs-image --check` and the fsck.

## The spki sign engine

The spki engine is pure Rust. It has four key types: ECDSA on NIST P-256
with SHA-256 over `p256`, ECDSA on NIST P-384 with SHA-256 over `p384`,
pure Ed25519 over `ed25519-dalek`, and RSA PKCS#1 v1.5 with SHA-256 over
`rsa` 0.9.10. The engine signs ECDSA with RFC 6979 nonces, so one key and
one data give the same signature bytes. The `ostree` command builds this engine only with OpenSSL,
and it signs ECDSA with a random nonce. The two forms verify the same way.
Ed25519 (RFC 8032) and RSASSA-PKCS1-v1_5 (RFC 8017) are deterministic on
both sides.

The `ostree` command signs ECDSA with SHA-256 on each curve, also on P-384.
The default `Signer` and `Verifier` of `p384` hash the data with SHA-384, so
the engine does not call them. It hashes the data with SHA-256 and calls
`sign_prehash` and `verify_prehash`. `sign_prehash` makes the RFC 6979 nonce
of a prehash with HMAC-SHA-384. So a P-384 signature of the port is the same
bytes for one key and one data, and it differs from the RFC 6979 test vectors
for P-384 with SHA-256, which use HMAC-SHA-256. The verify does not depend on
the nonce. A round trip of the port alone does not find a wrong digest, so
the P-384 fixtures that the `ostree` command signs are part of the tests.

An Ed25519 key signs the data itself, with no prehash and no context. The
signature is 64 bytes, `R || S`. The verify is `VerifyingKey::verify` of
`ed25519-dalek`, the verify of the ed25519 engine. It checks `[S]B = R +
[k]A` with no cofactor, refuses an `S` that is not below the group order,
and accepts a public key of small order. The `ostree` command gives the same
result for each of these cases. `verify_strict` was rejected: it refuses a
public key of small order, which the `ostree` command accepts. The ed25519
engine and the Ed25519 key type of the spki engine share no code. They write
the same bytes for one seed and one data, under two metadata keys, and the
verifier of each engine trusts only the keys of its own engine. The feature
`pkcs8` of `ed25519-dalek` reads the SubjectPublicKeyInfo of a key and
writes it again. The engine reads the fields of a PKCS#8 key itself, because
the `KeypairBytes` of `ed25519` wipes its copy of the seed only with a
feature that the build does not turn on.

The RSA signer blinds each private-key operation with a random value from the
operating system. The blinding does not change the signature. RUSTSEC-2023-0071
applies to `rsa` 0.9.10, and `CLAUDE.md`, "Advisory exceptions", states the
terms of the exception. `roadmap.md` records the move to a release of `rsa`
with the fix.

The engine takes an RSA modulus of 2048 to 16384 bits. OpenSSL verifies no
signature of a modulus above 16384 bits: `openssl dgst -verify` writes
`modulus too large`. The `ostree` command signs with such a key, and its
verify then fails. The `ostree` command signs and verifies with a 512-bit
key, and the port refuses it. `RsaPublicKey::new` of `rsa` 0.9.10 caps the
modulus at 4096 bits, and the SubjectPublicKeyInfo decoder of the crate calls
it. The private-key decoders of the crate apply no cap. They give general
errors, such as `KeyMalformed`, that do not state the reason of a refusal. So
the engine does not use the decoders of the crate. It reads the
`RSAPublicKey` and `RSAPrivateKey` structures with the `pkcs1` crate that
`rsa` exports, checks the size of the modulus and the number of primes, and
gives a message for each refusal. It then calls
`RsaPublicKey::new_with_max_size` with 16384 bits or
`RsaPrivateKey::from_components`. A direct dependency on `pkcs1` was
rejected, because the re-export gives the same crate.

The engine refuses a secret key of more than two primes. The `ostree` command
signs with keys of 3, 4, and 5 primes. `RsaPrivateKey::from_components` takes
more than two primes, so the engine reads the version of the `RSAPrivateKey`
before the call. The public key of a multi-prime key is a modulus and an
exponent, and the engine takes it. The engine refuses an `rsaEncryption` key
whose parameters are not `NULL`. The `ostree` command verifies with a key
with no parameters field, and with a key with an OID in the field.

The engine tells the three secret key forms apart by their ASN.1 structure.
After the version, a PKCS#8 `PrivateKeyInfo` holds an `AlgorithmIdentifier`,
a PKCS#1 `RSAPrivateKey` holds an `INTEGER`, and a SEC1 `ECPrivateKey` holds
an `OCTET STRING`. A PKCS#1 key is RSA. The version of a PKCS#1 key is 0 or
1, so a multi-prime PKCS#1 key gets the refusal of its primes.

The engine has one feature, `spki` of `ostrya-sign`, with each key type:
P-256, P-384, Ed25519, and RSA. `ostrya` forwards it as `sign-spki`. The
code of the engine names `der`, `spki`, `pkcs8`, and `pem-rfc7468`, so it
takes them as direct dependencies. A build of `ostrya-sign` with neither
`spki` nor `gpg` has no ECDSA crate tree. One feature for each key type was
rejected: each gate of the shared code named each key feature, and a build
without a key type needed code, tests, and CI builds of its own that refused
a key of that type. Each build with `spki` holds `rsa`, so RUSTSEC-2023-0071
is in the graph of a consumer that only verifies. The advisory covers RSA
private-key operations, and `CLAUDE.md`, "Advisory exceptions", states the
terms.

The algorithm OID of a key selects its key type, and the curve OID selects the
curve of an EC key. The engine refuses each key type and each curve outside
its set, and an EC key with explicit curve parameters. Explicit parameters let
a key name a curve of its own. The `ostree` command signs and verifies with
such a key. `conformance/cli-surface.md` records the differences.

The verify is strict. A trusted key tries a blob only when the blob parses in
the signature form of its key type, and a blob is valid only when a trusted
key verifies it. The `ostree` command with OpenSSL reports a valid signature
for blobs that no trusted key verifies. `conformance/cli-surface.md`, `sign`,
records the observed results.

The revocation compare and the fingerprint use one rule. The port encodes the
SubjectPublicKeyInfo DER of a key again from the decoded key, with an
uncompressed EC point, with `id-Ed25519` and no parameters for an Ed25519
key, or with `rsaEncryption` and `NULL` parameters for an RSA key. The DER of
an Ed25519 key holds the 32 bytes of the key as they were given: the port
does not encode the point again, so a non-canonical encoding of a point is a
key of its own. A trusted key whose DER is in the revoked set is not
trusted. The fingerprint of a verified signature is the SHA-256 of this DER
in lowercase hex. So two forms of one key give one key and one fingerprint. A
compare of the typed values of each key type was rejected: the DER is a
function of the decoded key and holds the algorithm OID, so one compare serves
each key type. The ed25519 engine gives the same fingerprint for an Ed25519
key. It puts the 32 bytes of the key, as they were given, after a DER prefix
constant of its own, the 12 bytes of RFC 8410. The encoder of the feature
`pkcs8` of `ed25519-dalek` was rejected: the feature is behind `spki`, and
the ed25519 engine has no feature gate. The GPG engine keeps its uppercase hex
fingerprint. The report of `sign --verify` and `summary --verify` prints the
fingerprint under the GPG engine alone.

The OpenSSL build of the `ostree` command on the development host has the
spki engine. The tests in `crates/ostrya/tests/sign_spki_fixtures.rs` compare
the engine with this build in both directions for each key type: the port
verifies the signatures of the fixtures that the tool wrote, and the tool
verifies a commit, a summary, and a static delta that the port signs. Without
this build, the second direction skips. The test `spki_openssl_interop`
compares the engine with the `openssl` command in both directions.

The spki signer signs in the call to `Signer::sign`, and its future is ready
at once, so a program with no async runtime can sign. `Verifier::verify` is
synchronous: each verifier does its work in the call, so a program with no
async runtime can verify. The call holds its thread for the time of the
verification, and the caller selects the thread. An RSA signature with a
16384-bit key takes about 0.5 seconds of CPU time. The receive endpoint of
`ostrya` signs with the spki key of an `[ex-ostrya key]` group on the
blocking pool, through `ostrya_rt::unblock`, so the signature does not hold
the async executor.

Each path of `ostrya` that verifies runs each verifier, on both axes, on the
blocking pool, with one copy of the payload for each check. A caller that
holds the payload in an `Arc` gives the `Arc`, and the pool gets no copy.
These paths are the commit check, the summary check, and the delta check of
a pull, the trust check of the receive endpoint, the search of the receive
endpoint for a signature of its own key, and the summary check of `remote
fsck` of a bucket. Each of these paths, other than the search for a
signature of the own key, runs the verifiers of one axis in one call on the
blocking pool. The call runs them in order and stops at the first valid
signature. A client sets the number of signature blobs that the
receive endpoint verifies, and a summary can be as large as 64 MiB.
`Repo::verify_commit`, `Repo::verify_summary`, and
`Repo::verify_static_delta` take `Arc<dyn Verifier>` and run the verifiers on
the blocking pool too. `DeltaSuperblock::verify` and `sign::verify_all`
verify in the calling thread, because they need no repository and no
runtime. The `ostrya` command calls `Verifier::verify`, `sign::verify_all`,
and `DeltaSuperblock::verify` in the calling task, because it runs one
command in each process.

These alternatives were rejected:

- A sign future in `ostrya-sign` that moves the work to the blocking pool,
  because the engine then needs a runtime.
- A verify future whose engine moves the work to the blocking pool, because
  the engine then needs a runtime.

The spki verifier computes the SHA-256 of the data one time for each call,
when the first ECDSA or RSA key tries a blob. Each of these keys verifies the
blob with this hash. A store of many keys then hashes a commit one time, and
a blob that no key tries computes no hash. An Ed25519 key verifies with the
data and computes no SHA-256.

With the feature `x509`, `ostrya-sign` has the trait `X509Signer`, with
the supertrait `Signer`. The trait gives the values of a CMS `SignerInfo` for
a signature with an X.509 certificate chain, for example an Authenticode
signature of a UEFI image. `certificates()` gives the DER of each
certificate: the certificate of the signer first, then the intermediate
certificates in chain order. `signature_algorithm()` and
`digest_algorithm()` give DER `AlgorithmIdentifier` values. `Signer::sign`
hashes the data with the digest algorithm and signs the hash. For
Authenticode, the data is the DER of the CMS signed attributes. The methods
other than `sign` need no private key. So a signer whose key is in a hardware
token, an HSM, or a key service can implement the trait with no change to
the traits.

`SpkiSigner::with_certificates` consumes a signer and gives an
`X509SpkiSigner`, which implements `Signer` and `X509Signer`. `SpkiSigner`
does not implement `X509Signer`, so `certificates()` always holds the
certificate of the signer. The constructor refuses an empty list, and a
first certificate whose key is not the key of the signer. It compares the
two keys by the rule of the revocation compare. It decodes each intermediate
certificate, and does not read its key.

The signature algorithm of an RSA key is `rsaEncryption` with `NULL`
parameters. `sha256WithRSAEncryption` is not used: `sbsign` and
`systemd-sbsign` of Debian trixie write `rsaEncryption` with `NULL`, and
firmware reads this form. The signature algorithm of a P-256 key and of a
P-384 key is `ecdsa-with-SHA256` with no parameters, because the engine
signs with SHA-256 on each curve. The digest algorithm is SHA-256 with
`NULL` parameters. The engine keeps these values as DER constants.

Ed25519 is outside the trait. An Ed25519 key signs the data and not a hash,
and Authenticode for UEFI does not use Ed25519. `with_certificates` refuses
an Ed25519 signer.

The port builds no CMS structure and no Authenticode structure, and it reads
no PE file. The caller builds these structures with the values of the trait.

`SpkiVerifier::from_certificates` trusts the SubjectPublicKeyInfo of each
certificate that it gets as DER or as PEM `CERTIFICATE` blocks. It validates
no chain, no signature of a certificate, and no validity period. A key from
a certificate, from a PEM `PUBLIC KEY` block, and from a SubjectPublicKeyInfo
DER is one trusted key, with one fingerprint. The function trusts the key of
an Ed25519 certificate.

The engine decodes a certificate with `x509-cert`, which reads strict DER. A
hand-written walk of the ASN.1 structure to the SubjectPublicKeyInfo was
rejected: a strict decode of the full structure refuses each malformed
certificate, and a walk to one field does not. `x509-cert` 0.2.5 was in the
graph through `ostrya-server`, so no package enters `Cargo.lock`.

The feature `spki` does not turn on `x509`. `X509SpkiSigner` and
`SpkiVerifier::from_certificates` need `x509` and `spki`. `x509` alone gives
the trait `X509Signer` alone.

## GPG

Signing runs the system `gpg` binary as a subprocess over its `--status-fd`
interface. Thus keys in an agent and keys on a hardware token work through
`gpg` with no code of their own, and the private key stays with `gpg`.

Verification is in the process, over the `pgp` crate. `sequoia-openpgp` was
rejected for its LGPL license. The port owns the trust policy: issuer
resolution, subkey bindings, expiry, revocation, the signature class and the
digest policy. No fallback to the `gpgv` binary exists, so one engine and one
policy give each verdict.

The GPG verifier verifies in the call to `Verifier::verify`, as the other
verifiers do, and the caller selects the thread.

`GpgVerifier::with_ignore_time` turns off the time checks of the GPG
verifier. With the option, no expiry makes a signature invalid: the expiry of
the data signature, the key expiry, and the expiry of a self-signature. A
revocation still makes a signature invalid. The record still reports the
expiry fields. Their values come from the certificate as the option reads it,
with expired self-signatures in effect, and from the clock. The reason is a
trust store that is written one time and not updated, for example the trust
files of a sealed boot image. A key renewal cannot get into such a store, and
the clock at an early boot stage can be wrong. A fixed instant in place of the
clock was rejected. A key that expired before that instant is still refused,
and the store has no instant to give. The tests compare the verdict without
the option with `gpgv`. The tests with the option set use fixed expected
values, because `gpgv` has no such option to compare with. The option is on the
verifier alone. The keyring import applies the time checks at the clock.

The GPG verifier, the parse of a keyring, the key listing, and the keyring
merge of an import are in `ostrya-sign`, next to the GPG signer, under the
feature `gpg`. So one crate parses OpenPGP, and a build with `gpg` holds no
runtime. `ostrya` reads and writes the keyring files, takes the locks, and
holds the constructors that read the ostree keyrings, as the trait
`FromOstreeKeyrings`. A second parse in `ostrya` for the import and the
listing was rejected, because two crates would then parse OpenPGP.

`FromOstreeKeyrings` reads the keyring of a remote through a repository handle
alone. `for_remote_in` reads `<repo>/<remote>.trustedkeys.gpg` and, only when
that file is absent, the keyring of the remote in the remotes directory of the
handle. `for_remote_keyrings` takes the bytes of the keyring from the caller.
So `for_remote_in` reads the same keyring of a remote as a pull. Constructors
that take the path of a repository were rejected. A path does not give the
remotes directory of the handle. When the keyring of a remote is only in that
directory, such a constructor trusts the global trusted set, and a pull trusts
the keyring of the directory. The two trusted sets of one remote are then
different, with no message.

`GpgSigner::export_public` gives the minimal public certificate of a signing
key, for a trust store such as the trust files of a sealed boot image. It runs
`gpg --export` with `--export-options export-minimal`, keeps the primary user
id, and drops each subkey that cannot sign. `--no-armor` keeps the output
binary when a `gpg.conf` sets `armor`. Before `gpg` runs, the method refuses a
value that is not 40 or 64 hex digits. The parse of
`GpgVerifier::add_binary_keyring` checks the output in the process, so the
method gives only bytes that the verifier loads. The method gives the bytes of
`gpg` unchanged, so the returned bytes are the bytes that the parse accepted.
A serialization of the parsed certificate was rejected for this reason. A
second `gpg --show-keys` run to check the output was rejected, because the
parse in the process already checks it. The read of the output stops at the
keyring limit plus one byte, through the capped output read of `ostrya-rt`, so
`gpg` cannot make the process hold a larger output. The method needs the
feature `gpg` with `gpg-sign`. A `gpg-sign` that turns on `gpg` was rejected,
so a build with the signer and no OpenPGP parser stays possible.

## The signature policy of a local pull

`Repo::pull_local` takes each field of `PullVerify` that is `None` from the
`[remote "NAME"]` section that `PullOptions::remote` names. The four keys
apply: `gpg-verify` (default true), `gpg-verify-summary`, `sign-verify`, and
`sign-verify-summary`. For a remote with a section, the defaults are those of
`Repo::pull`. So a local pull and a pull over HTTP of one remote apply one
policy. The rule is in the library, so each caller of `Repo::pull_local` gets
it.

A remote name with no section gives no check. So `--remote` can name a ref
namespace alone. A field that is `Some(true)` turns on its check for a name
with no section too, and with no key the check fails. `Repo::pull` applies the
defaults of a described remote to a name with no section, so its GPG check of
the commits is on.

`ostrya pull-local` has the off switches `--no-gpg-verify`,
`--no-gpg-verify-summary`, `--no-sign-verify`, and `--no-sign-verify-summary`.
Each switch sets its field of `PullVerify` to `Some(false)`. The two summary
off switches need `--remote`. `--no-gpg-verify` and `--no-sign-verify` need
`--remote` or `--trust`, because each one also turns off an axis of the trust
group that `--trust` names. Each off switch conflicts with its positive
switch.
`--sign-verify` and `--sign-verify-summary` set `sign` and `sign_summary` to
`Some(true)` and need `--remote`. Each one selects each engine of the build,
as `ostrya pull --sign-verify` does. The two GPG switches and the two sign
switches take no value. The `ostree` command reads `--gpg-verify=false` as
`--gpg-verify`, so a valued form of a GPG switch in the port would give that
spelling a different meaning. The `ostree` command has no `pull-local
--sign-verify` or `--sign-verify-summary`, so the two sign switches take no
value to match the GPG switches.

Two alternatives were rejected:

- The rule of the `ostree` command, where only a switch turns on a check. The
  command reads none of the four keys for `pull-local`
  (`conformance/cli-behavior.md`, "Signature verification during a pull").
  So a local pull accepts an unsigned commit from a remote whose config
  requires a signature, and a pull over HTTP of the same remote refuses it.
- The config read with no off switch. A configured check would then apply
  to each local pull of the remote, and a command line could not turn it off.

The signature check of a commit keeps the SHA-256 of the `.commitmeta` that
it read from a source. The import reads the `.commitmeta` again. If the
sources do not hold the same bytes, the import fails the pull with
`Error::Pull` and stages no `.commitmeta`. So the pull stores the
`.commitmeta` that the check verified. The rule applies to each pull whose
policy checks the signatures of the commits, with or without
`PullFlags::UNTRUSTED`.

Two alternatives were rejected:

- A carry of the verified bytes to the import. The pull would keep one
  buffer for each commit of the chain, and a `depth=-1` pull puts no bound
  on the number of commits.
- A second signature check at the import. The pull would verify each commit
  two times.

## The trust group of a remote

The remote key `trust=NAME` names a trust group `[ex-ostrya trust "NAME"]`.
The group supplies the commit keys of each pull from the remote. The key name
has no prefix, as the other remote keys of the port (`ssh-command`,
`push-user`, `s3-region`). The value is the quoted part of the group name.

Each pull reads the key: `pull` over HTTP, over ssh, and from an `s3://`
address, `pull --collection`, and `pull-local`. `PullTrust::resolve` reads
it, and each pull calls that function.

The group sets the commit policy alone. The remote keys `gpg-verify-summary`
and `sign-verify-summary`, and the key sources that they read, set the
summary policy. So `ostrya remote fsck NAME` keeps its summary check. A trust
group refuses `gpg-verify-summary` and `sign-verify-summary` on the receive
side and on the pull side, because a trust group sets a commit policy alone.
The commit policy and the summary policy share no verifier. So the GPG check
of the summary cannot take the verifier of the group, which reads no
repository keyring.

With a trust group, the pull refuses `Some(true)` in `PullVerify::gpg` or
`PullVerify::sign` with `Error::InvalidInput`. `Some(false)` in one of the two
fields turns that commit axis of the group off. The summary fields override
the summary keys of the remote, as without a trust group. `ostrya remote
fsck NAME` sets both commit fields to `Some(false)`, so it reads no key of
the group.

Beside `trust`, the pull refuses a remote key that turns on a commit check:
`gpg-verify=true`, and a `sign-verify` value other than false. It accepts
`gpg-verify=false`, which `remote add --no-gpg-verify` writes. An absent
`gpg-verify` gives no GPG check of the commits, because the group sets the
commit policy. The pull also refuses a key source of the remote that no
summary check reads: `gpgkeypath` without a GPG summary check, and a
`verification-ENGINE-key` or a `verification-ENGINE-file` of an engine that
the summary check does not select. This rule reads the summary keys of the
config, and not the overrides of `PullVerify`. So an override that turns the
summary check off for one pull does not make the remote refused. A summary
key of the remote that the pull reads and cannot parse is refused too. Each
refusal comes before the pull reads a key source and before it fetches
anything.

A pull checks and builds the one trust group that it names, and no other
group. `ostrya receive` and `ostrya serve` keep their check of each group.

The commit policy of a group reads no repository keyring
`<repo>/NAME.trustedkeys.gpg` and no system key store. So the keys that
`ostrya remote gpg-import NAME` writes do not check the commits of a remote
with `trust=NAME`. The GPG check of the summary still reads them. The pull
does not refuse the keyring file, and `ostrya-config(1)` states the rule.

Three alternatives were rejected:

- A key that `pull-local` alone reads. A pull over HTTP of the same remote
  would then use the keys of the remote, with no message.
- A trust group with no summary check. The summary keys of the remote would
  then apply to no check, and `ostrya remote fsck NAME` would verify no
  summary of such a remote.
- A refusal of each `Some` field of `PullVerify`. `Some(false)` makes the
  policy of the group smaller and never larger, and `ostrya remote fsck
  NAME` sets it. The summary fields do not touch the group.

## The trust group of one pull

`PullOptions::trust_group` names a trust group `[ex-ostrya trust "NAME"]` for
one pull. The field applies to each pull that reads its policy from the
config: `Repo::pull` over HTTP, over ssh, and from an `s3://` address,
`Repo::pull_collection`, and `Repo::pull_local`. `Repo::pull_with_session`
takes its keys from the trust of the caller, so it refuses the field with
`Error::InvalidInput`.

The field wins over the remote key `trust`, and the pull then does not read
the key. The rules of "The trust group of a remote" apply to the group that
the field names: the refusal of `Some(true)` in `PullVerify::gpg` and
`PullVerify::sign`, the refusal of the commit keys of the remote, and the
summary policy from the summary keys of the remote. A name that is malformed
or names no group is `Error::InvalidInput`, because the name comes from the
caller and not from the config.

A local pull with the field needs no remote. With no remote, no section
supplies the summary keys, so the pull checks no summary. A summary field that
is `Some(true)` then fails with `Error::Pull`, as it does with no field.
`PullOptions::remote` still names the ref namespace.

The option `--trust=NAME` of the command is on `ostrya pull-local` alone.
`ostrya pull --trust` is in `roadmap.md`.

Two alternatives were rejected:

- `--trust` on each pull command now. The library field gives each pull the
  rule, and the option of the other commands can come later with no change
  to the library.
- A field that `Repo::pull_local` alone reads. A pull over HTTP with the same
  options would then use the keys of the remote, with no message.

## The engine of each signing key

Each command that takes `--sign-type` gives each key the engine of the
nearest `--sign-type` before it on the command line. A key before the first
`--sign-type` takes `ed25519`. A key is a value of `--sign`,
`--sign-from-file`, `--keys-file`, or a positional key. `--gpg-sign` keeps
the gpg engine, and it is not a key of a `--sign-type`. The `ostree` command
applies the last `--sign-type` to each key, so the two can write different
signatures for one command line. `conformance/cli-surface.md`, "P2", records
the difference in each command.

Each `--sign-type` needs a key of its own: a key after it and before the
next `--sign-type`. A command refuses a `--sign-type` with no key of its own
before the first signature and before the verification. The refusal of a
name that no engine carries comes first. In a verify mode other than
`apply-offline`, a run with no key on the command line takes each
`--sign-type` as a selection of its engine.

A verify mode makes one verifier for each engine of the run, and each engine
must have a valid signature. A user who names a key of an engine expects a
valid signature of that engine. A run with no key, no `--remote`, and no
`--sign-type` is an exception: it skips each engine that finds no signature,
if another engine finds one. The verify modes are `sign --verify`,
`summary --verify`, `static-delta verify`, and `static-delta apply-offline`
with a key source. A run with no engine is refused. A verify mode of `sign`
and `summary` refuses `--gpg-homedir`, which names the home directory of a
gpg signing key. The key sources are:

- A key on the command line: the engines of the keys alone, and no key
  directory. The command refuses a `--keys-dir` in this run. `sign` also
  refuses `--keys-dir` in a signing run, and `summary` refuses it in each
  mode other than `--verify`. Each gpg `--keys-file` must name a regular
  file, as the last ed25519 or spki `--keys-file` must.
  `GpgVerifier::from_keyring_files` skips a keyring path that names no file,
  so the command checks each path before the load.
- No key and no `--remote`: each engine with a trusted key in the system key
  directories and each `--keys-dir`, and the gpg engine if the GPG system
  trust holds a certificate. Each `--keys-dir` adds one directory. The two
  `static-delta` verify modes have no gpg engine. With no `--sign-type`, the
  user names no engine, so the host decides which engines the run finds. An
  engine that finds no signature prints nothing, and does not fail the run, if
  another engine finds a signature. Each engine that finds a signature must
  have a valid one, and a run where no engine finds a signature fails. An
  engine that does not load still refuses the run. A keyring of the GPG system
  trust that cannot be read refuses a run that looks for the gpg engine. A
  broken trust store is an error of the host, and the command does not hide
  it. A `--sign-type` that selects the other engines does not read the GPG
  system trust. A `--sign-type` that selects the gpg engine alone reads no
  `--keys-dir`.
- `--remote`: the engines that the config of the remote turns on, as a pull
  reads them, with the keys of the remote alone. `RemoteKeys` of the `ostrya`
  crate reads them. The command reads no global GPG trusted directory and no
  system key directory for `--remote`. A `--sign-type` with no key selects
  its engine, and `RemoteKeys` then reads the keys of the selected engines
  alone. An engine that the run does not check cannot refuse the run.

`ostrya sign` has no `-d/--delete`. The `-d` of the `ostree` command signs,
and the port has no `gpg-sign` command, so no command of the port removes a
signature. The library keeps `Repo::delete_signatures`.

These alternatives were rejected:

- The last `--sign-type` for each key, as the `ostree` command does. A
  command line with keys of two engines could not sign or verify with both.
- The first or the last `--sign-type` for the keys before the first one. The
  rule of the nearest `--sign-type` before a key has no exception.
- A `--sign-type` after the last key that applies to that key. The tool signs
  `--sign=K --sign-type=spki` with spki, so the port refuses the form rather
  than sign K with ed25519.
- One valid signature of any engine in a verify mode, as the sign-api axis of
  a pull accepts. `--remote` keeps the rule of each engine too.
- A valid signature of each engine that a run with no key finds. A key in
  `/etc/ostree` or a keyring of the GPG system trust then fails each verify
  of an object that has no signature of that engine. `static-delta
  apply-offline` takes no `--sign-type` with no key, so the user cannot
  select one engine there.
- A `--keys-dir` that replaces the default key directories, as the `ostree`
  command does. The key directories of the port are one set, and a revoked
  key of one directory applies to each directory.
- A `--keys-dir` that a verify with a key on the command line or a signing
  run of `sign` ignores, as the `ostree` command does. A user who gives a key
  directory then gets no message when the run reads no key from it.
- A verify that reads the `*.gpg` files of `--gpg-homedir` as keyrings, as
  `show --gpg-homedir` does. The GnuPG home directory of a signer is then a
  trust source of the verify, and the verify trusts each key in it with no
  statement of trust from the user.
- A gpg `--keys-file` that names no file and that the command skips, as the
  library skips an optional keyring. A typo then verifies with an empty
  trusted set, and no message names the path.
- The refusal in `GpgVerifier::from_keyring_files`. The keyring paths of a
  remote and of the system trust name files that can be absent.
- The global GPG trusted set and the system key store for `--remote`. These
  sets do not belong to the remote.
- A `sign -d` that removes a signature. The tool has no such mode on `sign`.

## TLS stack

The fetcher uses `rustls` 0.23 with `rustls-graviola` 0.4 as the crypto
provider. The provider is Rust together with formally verified assembly from
s2n-bignum, so the build needs no C compiler and no `cc` build dependency.
The provider supports x86_64 and aarch64 alone. A build for another target
needs a different provider in `crates/ostrya-fetch/src/tls.rs`.

`rustls-native-certs` reads the trust store of the host. `webpki-roots` was
rejected: its license, CDLA-Permissive-2.0, is not on the permissive list.

`h2` puts `tokio` and `tokio-util` into the graph under the `smol` backend
too. The fetcher uses only their I/O traits and codec framing, and drives no
tokio runtime.

## The HTTP adapters

The adapters between `hyper` and `futures-io` keep `forbid(unsafe_code)`.
They fill the read cursor of `hyper` through its safe `put_slice`. This
costs one copy for each read, because a read into the uninitialized buffer
needs `unsafe` code.

The request body is a `Body` type of the fetcher, so `http-body-util` is not
a dependency. The `basic` authorization header is encoded by
`ostrya-core::base64`, so no base64 crate is a dependency.

## SOCKS5 proxies

The fetcher reaches an origin through a `socks5://` or a `socks5h://`
proxy. With `socks5://`, the fetcher resolves the host name of the origin
and sends an address. With `socks5h://`, it sends the host name of the
origin, and the proxy resolves it. An origin host that is an IP literal goes
as an address under both schemes. The default port is 1080, and a message
names the proxy by its URL without the userinfo and without the port 1080.
The connection to the origin carries origin-form requests, as a direct
connection does. So its pool key is the origin, and no proxy flag is set.

The client offers "no authentication" alone if the URL has no userinfo. With
userinfo, it also offers the user name and password method of RFC 1929.
GSSAPI is not offered. The userinfo takes the percent-decode of an `http://`
proxy, and each field must be UTF-8 and 1 to 255 bytes after the decode.
`Fetcher::new` refuses other userinfo with `Error::Unsupported`. A host name
longer than 255 bytes, or with a `%`, fails the hop as definitive before the
client connects to the proxy. These checks apply under both schemes, before
the resolve. The client ignores the value of the `RSV` byte.

Under `socks5://`, the fetcher asks the proxy to connect to each resolved
address in turn, in the order that `ostrya_rt::TcpStream::connect` tries
them. `ostrya_rt::resolve` gives this order. Each address gets a new
connection to the proxy, because a refused `CONNECT` ends the connection.
The first address that the proxy connects wins. A definitive failure ends
the loop, because each later address gets the same answer. A failed connect
to the proxy also ends the loop, with the retryable message of a proxy
connect failure and no count of addresses. If the proxy refuses each
address, the message is "connect to HOST:PORT through the proxy P failed at
ADDR, the last of N addresses: REASON". A failed resolve, or a resolve that
gives no address, is retryable and names the origin host.

One `connect_timeout` covers the resolve, the whole address loop, the TLS
handshake, and the HTTP handshake, as it covers a `CONNECT` tunnel. An
attempt that stalls can use the full timeout, and then no later address is
tried. The `Proxy` rustdoc states this limit.

The failure classes follow the rule of an HTTP proxy, where 407 is
definitive and each other refusal is retryable. A proxy that accepts no
offered method, or that refuses the user name and the password, is
definitive. Each reply code other than `00` is retryable. This includes
`02` (not allowed by ruleset), `07` (command not supported), and `08`
(address type not supported), which a retry can get again. The length
check of a host name is different: the client makes it itself, before it
sends the request, so no proxy answer is involved.

`socks4://` and `socks4a://` stay refused, which is a divergence from the
tool that `cli-surface.md` records with its source.

Four alternatives were rejected:

- A SOCKS crate. The client side of RFC 1928 and RFC 1929 is
  `crates/ostrya-fetch/src/socks.rs`: 418 lines without its tests, of which
  303 are code lines that are not blank and not comments. `tunnel()`, the
  `CONNECT` exchange of an HTTP proxy, is 106 lines with its doc comment,
  of which 89 are code lines. A crate adds packages to `Cargo.lock`.
- `socks4` and `socks4a`. They have no IPv6 and no password, and each is a
  second protocol to test.
- "No authentication" alone. A proxy URL with userinfo then needs a
  refusal, and a proxy that needs a password cannot serve the port.
- The first resolved address alone. A name with IPv6 and IPv4 addresses then
  fails through a proxy that cannot reach the first family, while a direct
  connection reaches the origin.

## Request signing in the fetcher

`ostrya_fetch::RequestSigner` is a hook that adds headers to each attempt.
The fetcher calls it after it takes the connection, for each retry, each
round, and each redirect hop at the origin that the route names. A hop at
another origin gets no signature. A signer is a credential: the fetcher
refuses it beside basic-auth credentials, a bearer token, or an
`Authorization` header, and toward a cleartext mirror without the permission
of the caller. The same refusal applies to these credentials on a fetch or
an upload: the request fails before admission, and the signer is not called.
Each header value of the signer is marked sensitive, so an HTTP/2
connection never adds it to its header compression table.

A presigned query for each target was rejected, for three reasons:

- A signature with a date must be fresh when the request leaves. A retry
  after a backoff, or a request that waits for a connection, needs a new
  date. The hook signs each attempt.
- The signature stays in a credential header, which the fetcher marks
  sensitive and keeps from other origins. A presigned signature is part of
  the URL, and each error message of the fetcher prints the URL.
- A signed `PUT` with the signature in its headers signs the hash of the
  body.

The signer gets a body given whole as a slice of the request body, with no
copy. A body of `UploadBody::bytes` reaches the signer as
`SignPayload::Bytes`, and the signer hashes it on the task of the request,
on each call. A body of `UploadBody::bytes_with_sha256` carries the SHA-256
that the caller computed. It reaches the signer as `SignPayload::Sha256`,
with the slice and the digest, so the signer hashes no byte of it. The
upload gives the same digest to the signer of each attempt, each retry, and
each redirect hop, and a copy of the body keeps the digest. The fetcher does
not check the digest, and it does not hash a body itself: `ostrya-fetch`
has no SHA-256 code. A streamed body reaches the signer as
`SignPayload::Streamed`, with no bytes.

## SigV4 and the AWS credentials

`ostrya_remote::s3::SigV4` is the AWS Signature Version 4 code, written in
the tree over `sha2` and the `hmac` crate 0.12.1. The algorithm is a fixed
sequence of hashes and string joins, and the AWS documentation gives worked
examples with full inputs and outputs. The unit tests check the signer
against these examples. `hmac` was in `Cargo.lock` before the feature, so no
package entered the graph. Two alternatives were rejected:

- HMAC-SHA256 written in the tree too, over `sha2`. It adds no manifest
  entry, but it is cryptographic code that the RustCrypto crate `hmac`
  already supplies, and that crate is in the graph.
- A SigV4 crate, for example `aws-sigv4` or `rusty-s3`. Each one brings
  packages that are not in `Cargo.lock`, and `rusty-s3` makes presigned URLs
  alone, which "Request signing in the fetcher" rejects.

`ostrya_remote::s3::resolve` reads static key pairs alone: the environment
variables, then the shared credentials file, then the shared config file,
with an optional session token. A profile section that names another source
(`role_arn`, `source_profile`, `credential_process`, `web_identity_token_file`,
or a key that starts with `sso_`) is refused with an error that names the
file, the section, and the key. The chain does not skip to the next source,
so the port never signs with an identity other than the one that the profile
names. If the environment gives the key pair, these keys are not read. The
full chain of the AWS SDKs, with STS, IMDSv2, and the container endpoint, was
rejected: it is a large part of the work, and each source needs a test
server of its own.

A profile that the caller names skips the key pair, the region, and the
endpoint of the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `AWS_REGION`, `AWS_DEFAULT_REGION`,
`AWS_ENDPOINT_URL_S3`, and `AWS_ENDPOINT_URL`). The chain reads the shared
files for that profile alone. Without this rule, a named profile `prod` with
`AWS_ENDPOINT_URL` set for a test server sends requests that the key of
`prod` signs to the test server, and `AWS_ACCESS_KEY_ID` wins over the named
profile. A profile from `AWS_PROFILE`, or the profile `default`, keeps the
order of the AWS documentation, where the keys of the environment win. The
order of the AWS documentation in all cases was rejected for these two
reasons.

When no source gives a region, the region is `us-east-1`. SigV4 puts the
region into the scope of each signature, so each request carries a region.
A server that does not check the region then needs an endpoint alone. A
server that checks its own region, and an AWS bucket outside `us-east-1`,
needs a region from the caller, the environment, or the config file. The
region changes no byte of the repository, only the signature. A default
that applies only with an endpoint of the caller was rejected.

## Error responses of a fetch

`ostrya_fetch::FetchRequest::max_error_body` asks a fetch to keep the
unsuccessful response that it reports. `Error::HttpStatus` then carries an
`ErrorResponse` with the headers of that response, and its body if the whole
body is within the cap. A fetch that does not set the field reads no error
body, as before. The bucket client of S3 needs the field: the code and the
message of an S3 error, and the region of a bucket, are in the body and in
the headers of the error response.

- A fetch reads the body of a failure only if the failure order can make it
  the reported failure. So it reads at most two bodies, one retryable and
  one definitive, and keeps the body of the failure that it reports.
- The read has one progress window from the arrival of the response head.
  A body over the cap, a coded body, a stalled body, and a body that fails
  in transit give the headers alone. The fetch keeps no part of a body.
- The declared length of a body is a claim of the server, so the read
  reserves at most 64 KiB before the body arrives. The capacity of a kept
  body never passes the cap. A cap of `u64::MAX` and a response that
  declares 1 PiB then cost no allocation of 1 PiB.
- The read never changes the retry class of a status, and the kept bytes do
  not count in the received counters.
- `ostrya::Error::HttpStatus` does not carry the response. Its conversion
  from the fetch error drops it, so the error type of the library keeps its
  shape.
- `Error::HttpStatus` of `ostrya-fetch` has no `#[non_exhaustive]`. A caller
  outside the crate can build each variant, and a pattern names the new
  field or ends in `..`.

These alternatives were rejected:

- `UploadMethod::Get`, a `GET` through `Fetcher::upload`, which gives each
  final status with its headers and a capped body. The bucket client then
  owns the retries of its `GET` requests, and a streamed object loses the
  refetch of a failed body and the low-speed rule of a fetch. The
  maintainer chose the change of the fetch.
- A `Fetched::Status` variant, which makes each caller of `fetch` match an
  unsuccessful status as a success.
- A new `Error` variant for a status with a response. Each caller that
  matches `Error::HttpStatus` then also matches the new variant.
- A per-request switch of redirect following. `max_redirects` of the
  fetcher already gives each redirect as a status at the limit of zero.
- A truncated prefix of a body over the cap. The caller cannot tell a
  truncated XML document from a malformed one.

An upload gives each final status as an `Uploaded`. An answer other than
2xx whose body declares a coding, or a `Content-Length` over
`max_response`, keeps its status and its headers, and the upload withholds
the body: `Uploaded::body_withheld` returns `true`, and the body reads as
empty. A 2xx answer with such a body fails the upload with
`Error::UploadInterrupted`. So a definitive refusal, for example
a 403 behind a proxy that compresses it, keeps its status, and the bucket
client of S3 does not send it again as an interrupted upload. An
interrupted upload in place of the status was rejected: the caller loses
the status, and repeats a request that the server refused.

## The S3 bucket client

`ostrya_remote::s3::Bucket` is the client of a bucket repository, in the
module `s3` of `ostrya-remote`, under the feature `s3`. `ostrya-remote`
holds the transports of push and pull and the type `Endpoint`, so the
client side of S3 goes there with the signer and the credential chain. A
new published crate `ostrya-s3` was rejected: it needs a `README.md`, a place
in the release sequence, and the same dependencies.

The XML bodies of the S3 responses are read with the crate `quick-xml`
0.42.0, with no feature. The reader of the port refuses a `DOCTYPE`, accepts
the five predefined entities and the character references of XML 1.0, and
refuses each other reference. It refuses a body with an open element at its
end, a second root, or an element deeper than 32 levels, and it reads at
most 4 MiB of UTF-8. Two alternatives were rejected:

- The crate `xml` 1.4.0. It reads the definitions of internal entities and
  expands them, up to 1,000,000 bytes for each expansion. Its time is
  quadratic in the depth of the elements: 40,000 levels took 831 ms, and a
  body of 4 MiB of nested elements took more than 5 minutes. In a test
  program, it cost 151,312 bytes of a stripped release binary, and
  `quick-xml` cost 45,528 bytes. On a listing of 4 MiB, `quick-xml` took
  22 ms and `xml` took 122 ms.
- A reader written in the tree. `quick-xml` gives each event and each
  reference to the caller, so the rules of the port are a short walker over
  the events. A tokenizer of its own adds the code of the lexical rules of
  XML, which the crate already has.

The fetch, the stream, and the lists of the client are fetches with
`max_error_body` of 4 MiB, and the fetcher of the client follows no redirect.
So the client sees the `x-amz-bucket-region` header and the S3 `Error`
document of each unsuccessful response. A region other than the region of
the signature, from the header or from the `Region` element, gives
`Error::S3Region`, which names both regions. A redirect of S3 to another
region is never followed, because a hop to another origin carries no
signature. The retries of a `GET` are the retries of the fetcher. The
client sends a `PUT` and a `DELETE` again itself, after an interrupted
upload and after a 408, 429, or 5xx, because an upload is never repeated by
the fetcher. `UploadBody::try_clone` gives the second request the bytes of
the first one with no copy.

A 404 is an absent key only if its body arrived whole and holds the code
`NoSuchKey` or no S3 code. A 404 with `NoSuchBucket` is an error, so a
missing bucket never reads as an empty repository. A 404 whose body did not
arrive, for example a body that stalls or fails in transit, can come from
a missing bucket too, so it is an error with no code. The absent-key rule
runs before the region check: a server that does not check the region of
the signature, and names another region in the header of a 404, still
gives an absent key. A region check on 301, 307, 400, and 403 alone was
rejected, because S3 can name the region of a bucket with another status.

`Bucket::get_strict` reads a key by a strict rule: a 404 is an absent key
only if its body arrived whole and holds the code `NoSuchKey`. The
reachability walk over a bucket repository reads each commit and each
dirtree with it. A false absent key hides a subtree from the walk, and each
object of that subtree then reads as unreachable. So in the walk, a 404
with an empty body, or with a body that is not an S3 `Error` document, for
example a page of a proxy, is an error. The fsck of a bucket repository
reads each object with the strict rule too: `Bucket::get_strict` for a
metadata object and `Bucket::get_stream_strict` for a `.filez`. A false absent
key there gives a false finding, and with the repair a marker on a commit
whose tree is whole. `get_stream_strict` shares the code of `get_stream`, as
`get_strict` shares the code of `get`. The other readers of a bucket keep the
rule above.

`Bucket::exists` and `Bucket::exists_strict` check that a key holds an
object, by the rule of `get` and by the rule of `get_strict`. A check is a
`GET` with `Range: bytes=0-0` and a size cap of one byte. A 206 and a 200
are an object. A 416 is an object too, because a server gives it for an
object of zero bytes. No object of a bucket repository has zero bytes, so
the rule costs nothing. The client reads a body that declares a length of
at most one byte to its end, so the connection goes back to the pool. A
failure of the body after the status does not change the answer, because
the status decides, and the drop of the body closes the connection. The
client does not read a body with no declared length, and the drop of the
body closes its connection. A read of such a body was rejected: a server
that sends no byte and stalls holds the check, and one of the
`max_outstanding` places of the caller, until the progress timeout. A
server that ignores the range answers 200 with the whole object. The fetcher then refuses a declared
length over one byte with `FetchTooLarge`, and the check takes that refusal
as an object. The fetcher reads a declared body of at most 64 KiB to its
end, so the connection goes back to the pool. It closes the connection of
a larger body, or of a body with no declared length. The fetcher takes a
206 as a body only for a request with a `Range` header. A 206 to another
request is `Error::HttpStatus`, because it holds a part of the object that
the caller did not ask for. The SigV4 signature does not cover the `Range`
header, so the signer signs a check as it signs each other `GET`.

A `HEAD` was rejected. The response to a `HEAD` has no body, so a 404 to a
`HEAD` holds no S3 code, and the strict rule cannot tell `NoSuchKey` from
`NoSuchBucket` or from a page of a proxy. A `GET` with no range was
rejected. For a large object, the server starts to send the body, and the
drop of the stream closes the connection. So many checks open many
connections, and each one uses bandwidth. `rclone serve s3` 1.75.1 answers
a check with 200, `Content-Range: bytes 0-0/<size>`, and one byte.
SeaweedFS 4.36 answers it with 206 and one byte.

A conditional `PUT` (`If-None-Match: *`) gives `PutIfAbsent::Created` only
when a request of the call got a 2xx. A request whose outcome is not known,
then a 412 or a failed request, makes the client read the key and compare
its SHA-256 with the SHA-256 of the body. The same bytes give
`PutIfAbsent::Refused` after a 412 and `PutIfAbsent::Matches` after a
failed request, other bytes give `PutIfAbsent::Present`, and an absent key
after a failed request sends the request again. `Matches` and `Refused`
state that the key holds the bytes of the body, and no answer names the
writer. So a writer lock that sends its own body again tells a 2xx of its
own request from bytes that the key held before the call. `Refused` also
states that the server answered 412, so the server honors the header,
and a writer lock that probes the header does not read a 412 after a 503
`SlowDown` as an unknown outcome. `rclone serve s3` 1.75.1 does not honor `If-None-Match: *`: a second
conditional `PUT` writes over the object.

The compare reads the object as a stream in chunks of 64 KiB, and holds no
copy of the object. A response that declares a length other than the
length of the body holds other bytes, and the client reads none of it. For
a body of more than 1 MiB, the client computes the SHA-256 of the body on
the blocking pool of the runtime, once before the first request. The signer
of each request and the compare use that digest. For a body of 1 MiB or
less, the signer hashes the body on the task of each request, and the
compare computes the digest on the blocking pool at the first compare.

A conditional `DELETE` (`If-Match` with an `ETag`) gives
`DeleteIfMatch::Deleted` for a 2xx, and `DeleteIfMatch::NotMatched` for a
412 or an absent key to the first request. SeaweedFS 4.36 answers 412 also
for an absent key, so a 412 after a request with an unknown outcome can
answer a delete of this call. The client then checks the key with
`Bucket::exists`, which asks for the first byte of the object alone: an
absent key gives `Deleted`, and an object gives `NotMatched`. `rclone serve s3` 1.75.1 does
not honor `If-Match`, and deletes the object whatever its `ETag` is.

Each page of a list must move forward, or the list fails. Each key and
common prefix of a page of `ListObjectsV2` comes after each one of the
earlier pages, in the byte order of UTF-8. S3 can give a truncated page
with no key and no common prefix, for example over many delete markers of a
versioned bucket. The client follows such a page if its continuation token
is new since the last page with a key or a common prefix. The client keeps
the tokens of that run in a set, and a page with a key or a common prefix
clears the set. A run of more than 1000 truncated pages with no key and no
common prefix fails the list. So a server that gives the same page again,
or empty pages with new tokens and no end, fails the list. A cap on the
number of all pages was rejected: a repository has no fixed upper limit of
keys. The cap on a run of empty pages bounds the set and the time of a
list, and it does not limit the number of keys.

For `ListMultipartUploads`, the `NextKeyMarker` of each truncated page does
not come before the key marker of the page before it, in the byte order of
UTF-8. While the key marker stays the same, the `NextUploadIdMarker` is one
that no earlier page gave for that key marker. The set of these upload id
markers clears when the key marker moves forward. S3 sorts the uploads of
one key by the time of their start, and not by the upload id, so the
upload id markers of one key have no order. A rule that the pair of the
markers increases was rejected: it refuses a key with more than one page of
incomplete multipart uploads.

The request path of a key encodes each byte outside `A-Z a-z 0-9 - . _ ~ /`
as `%XX`, which is the canonical URI of SigV4. So a `+` of a delta key goes
as `%2B`, and the signature does not depend on how a server reads a raw `+`
of a path. A listing asks for the encoding type `url`, and the client
decodes `%XX` and reads a `+` as a space, as S3 and `rclone serve s3` write
a space in that encoding.

The deletion of a key is one `DELETE` for each key. `DeleteObjects`
(`POST ?delete`) was rejected: AWS requires a `Content-MD5` or a checksum
header on it, and the first one needs the crate `md-5` in a manifest.

`Bucket::put_stream` writes an object from a reader. A body of at most
one part goes in one `PUT`, and a longer body goes in a multipart upload.
The call holds one part buffer, and the parts of one object go one after
the other. The first buffer starts at 8 KiB and doubles up to the part
size, so a small object takes a small buffer. After a full part, the call
reads one byte more, so a body of exactly one part goes in one `PUT`.

After each part, the call takes the buffer back with `UploadBody::into_vec`
of `ostrya-fetch`, and reads the next part into it with no fill of zeros.
The retries of a part share its buffer, so the buffer comes back after the
last request of the part. If the fetcher still holds the bytes, the next
part takes a new buffer with the capacity of one part. Its length doubles
from 8 KiB while the bytes arrive, so a short last part does not fill a
whole part with zeros.

`s3::part_size` gives the part size of an object of `N` bytes: the larger
of 8 MiB and `(2N + 1 MiB) / 10,000`, rounded up to a whole MiB. A `.filez`
of a file with `N` bytes of content is smaller than `2N + 1 MiB`, so
10,000 parts hold it. The part size is 8 MiB up to 41,942,515,712 bytes.
A part size over 5 GiB, the S3 limit of a part, gives
`Error::LimitExceeded`. No value is clamped. A body that is longer than
10,000 parts aborts the upload and gives `Error::LimitExceeded`.

`put_stream` refuses a part size below 5 MiB or above 5 GiB. No test hook
gives smaller parts. `rclone serve s3` 1.75.1 does not enforce the 5 MiB
minimum, but SeaweedFS 4.36 refuses a small part at the completion with
400 `EntityTooSmall`. The multipart tests use parts of 5 MiB.

The retries of a multipart upload differ for each request:

- The `POST` that starts the upload and each part are sent again after an
  interrupted request and after a 408, 429, or 5xx, as a `PUT` is. A part
  goes again with the same bytes.
- The `POST` that starts the upload is also sent again after a 2xx whose
  body did not arrive. Such an answer is an interrupted request, because
  the client does not get the upload id. An interrupted start can leave an
  upload that the client does not know. Such an upload holds storage until
  an abort or a lifecycle rule of the bucket removes it, and this is
  accepted.
- The `POST` that completes the upload is also sent again after a 2xx
  whose body cannot be read, and after a 200 whose body is an S3 `Error`
  document. The AWS API reference states that a completion can fail after
  the head of a 200.
- An answer to a part with no `ETag` fails the upload, because the
  completion cannot name the part.

The client takes an upload id and an `ETag` of a part of at most 1 KiB
each. A longer upload id fails the start, and the client sends no part. A
longer `ETag` fails the upload as a missing `ETag` does, and the client
aborts the upload. So the list of the `ETag` values holds at most 10,000
values of 1 KiB, and the completion document has a limit.

The outcome of a completion is unknown after an interrupted request,
after a 408, 429, or 5xx, and after a 2xx that cannot be used. A gateway
or a load balancer can give a 408, 429, or 5xx after the server completed
the upload. A later request can then get a 404 with the code
`NoSuchUpload`, because the earlier request completed the upload:
`rclone serve s3` 1.75.1 gives this answer to a second completion, and
SeaweedFS 4.36 gives 200 with the same `ETag`. After such a 404, the
client reads the key, and accepts the object if the declared
`Content-Length` equals the number of bytes of the parts. It reads no byte
of the object. A compare of the bytes was rejected, because it reads the
whole object again and the client holds one part alone. The completion has
the default timeout of the fetcher.

The check compares the length alone. It is sound for a key whose name sets
its content, such as a content-addressed object or a static delta. For a
key whose content changes, an older object of the same length passes the
check. The check runs for each key, and this limit is accepted. An absent
object and an object of another length give `Error::Transport`, whose
message states that the completion got 404 `NoSuchUpload` and what the key
holds. A failed read of the key gives the error of `Bucket::get_stream`.

After each failure that comes after the start of an upload, the client
sends one `DELETE KEY?uploadId=ID` and ignores its outcome, so the error of
the failure is the error of the call. If the last answer to a request of
the upload is a 404 `NoSuchUpload`, the server holds no such upload, and
the client sends no abort. This is the case after the check of the key
that follows such an answer to a completion. A dropped future sends no
abort.
`Bucket::abort_upload` takes a 404 `NoSuchUpload` as success: after a
refused completion, `rclone serve s3` 1.75.1 removes the upload and gives
404 `NoSuchUpload` to each later request of it, but `ListMultipartUploads`
still gives the upload. SeaweedFS 4.36 keeps the upload after a refused
completion.

`Bucket::abort_upload` refuses an empty upload id with
`Error::InvalidInput`, and sends no request. `rclone serve s3` 1.75.1 reads
`DELETE KEY?uploadId=` with an empty value as a `DeleteObject`: it gave 204
and removed the object.

The answer that starts an upload has the root
`InitiateMultipartUploadResult` in the AWS API reference and on SeaweedFS
4.36, and `InitiateMultipartUpload` with no namespace on `rclone serve s3`
1.75.1. The reader takes both roots, and refuses an absent or empty
`UploadId`. An `ETag` of the completion result that is empty or white space
alone reads as absent, so the `ETag` header of the answer applies.

The completion document gives the `ETag` of each part as the answer to the
part gave it, with its quotes, and with `&`, `<`, and `>` escaped. Both
servers take an `ETag` with quotes, with no quotes, and with `&quot;`.

The `ETag` that `put_stream` returns is not compared with the `ETag` of a
later read. For an object of several parts, the completion gives
`"<MD5 of the MD5 values of the parts>-N"` on both servers. A later read
on `rclone serve s3` 1.75.1 gives the MD5 of the whole object, and
SeaweedFS 4.36 keeps the value with `-N`.

The bucket client hashes a body of more than 1 MiB once, on the blocking
pool of the runtime, before the first request of the body. The rule applies
to each part of a multipart upload, to the body of `put`, `put_if_absent`,
and a `put_stream` of one part, and to the document that completes an
upload. The body moves to the pool and back with no copy, so the buffer of
a part comes back for the next part. The client gives the digest with
`UploadBody::bytes_with_sha256`, so the signer gets `SignPayload::Sha256`,
and each retry of the body signs the same digest. The compare of
`put_if_absent` uses that digest too. The signer hashes a body of 1 MiB or
less on the task of each request, as `SignPayload::Bytes`. The SHA-256 of
8 MiB takes about 4.8 ms on the dev host, so 1 MiB takes about 0.6 ms.

`Endpoint` of `ostrya-remote` has `#[non_exhaustive]`, and the variant
`Endpoint::S3` is behind the feature `s3`. Cargo features are additive, so
without the attribute a crate that matches each variant compiles alone and
fails when another crate of the same build turns `s3` on. A variant with no
feature gate was rejected: `S3Endpoint` and the types that it holds then
compile in each build. The push session constructors refuse `Endpoint::S3`.
`PullSession::connect` opens an HTTP pull session to it, with the fetcher
options of `S3Endpoint::pull_options`. `Endpoint::parse` refuses an `s3://`
address, because the endpoint needs credentials that the parse does not
read.

## The S3 pull

`resolve_pull` gives `Endpoint::S3` for an `s3://` address, and the variant
is the mark of a pull from a bucket repository. `Endpoint::Http` with a
signer was rejected: such an endpoint has no mark of S3, and the pull needs
the mark for two rules. The pull reads the root files through the bucket
client, and `Repo::pull_collection` reads no ref listing from the remote.

The fetcher of the pull has the one mirror of the repository URL, the SigV4
signer, and `max_redirects` set to 0. A redirect to another origin carries
no signature, so a redirect of S3 to the region of the bucket fails at the
other origin. With no redirect, the pull fails at the first answer, and the
bucket client names the region.

The pull sends the path of each request in the canonical form of SigV4.
The modified base64 of a delta name holds `+`, and SigV4 signs a `+` of a
path as `%2B`. With a raw `+` on the wire, the signature depends on how the
server reads a raw `+` of a path. `RequestSigner` of `ostrya-fetch` has the
provided method `request_path`. The fetcher gives it the path of each
`Target::Path` and `Target::PathQuery`, and sends the path that it returns.
A fetcher with no signer does not call it, and the default method returns
the path unchanged. So such a fetcher sends the path as the caller writes
it. `SigV4` returns the canonical path. It refuses a path that holds an
escaped `/`, or an escaped `.` that makes a `.` or a `..` segment, because
the decoded path names another key.
A `Target::Url` goes as written, and `SigV4` refuses a request whose path
is not in the canonical form. So no signature covers a path other than the
path on the wire.

This refusal has a known cost. AWS accepts a path with a raw `$`, an escape
with lowercase hex digits, or `%7E`, but `SigV4` refuses such a path in a
`Target::Url`, in the `Location` of a redirect to the same origin, and in
the base path of a mirror. No path of the port gets there: the S3 options
set `max_redirects` to 0, and each URL target of the bucket client comes
from `encode_path`.

Three alternatives were rejected:

- A new field of `FetcherOptions` that sets the form of the path. A caller
  that builds `FetcherOptions` with a struct literal and no `..` then fails
  to compile.
- The encoding of the delta paths in the delta source of the pull that the
  bucket client gives. The pull without a bucket client,
  `PullSession::connect` with `Endpoint::S3`, then sends a raw `+`.
- The encoding of the delta paths in each HTTP pull. That changes the bytes
  that a plain HTTP pull sends, and such a pull has no signature to match.

`summary.sig`, `summary`, and `config` go through `s3::Bucket::get`, and the
objects, the deltas, and the ref files go through the signed fetcher of the
pull. A fetch keeps no body of an error response, so through the fetcher a
wrong secret key is a bare 403, and a 404 of an absent bucket reads as a
repository with no summary. The bucket client reads the S3 error document.
Thus a wrong secret key gives `Error::S3` with the code
`SignatureDoesNotMatch`, a bucket of another region gives `Error::S3Region`,
and 404 `NoSuchBucket` is an error. `ostrya::Error::Remote` carries each of
them. `s3::Bucket::from_fetcher` opens the bucket client over a clone of
the fetcher of the pull, so the pull builds one fetcher: one read of the
trust store and one connection pool. A second fetcher from
`s3::Bucket::new` was rejected: it reads the trust store again and opens its
own connections. The bucket client names each request by its URL under the
bucket URL, so it reads the keys of the repository through the fetcher
whose mirror is the repository URL. The source of the pull gives the bucket
client the byte counters of the pull through `s3::Bucket::counted`. So these
reads count in the live progress of the pull until the count starts again,
as the reads of the root files over HTTP do, and
`PullStats::bytes_transferred` does not include them. These alternatives
were rejected:

- `s3::Bucket::with_fetcher`, which takes the counted fetcher of the pull.
  A client from `s3::Bucket::new` sends its request paths under the one
  mirror of its fetcher, the bucket URL. Over the fetcher of the pull, whose
  mirror is the repository URL, such a client adds the key prefix two times,
  unless the call forces a base URL.
- An `S3Endpoint` in the connection of the pull, so that the source opens
  the bucket client over its counted fetcher. That needs more code in three
  files.

The bucket client asks for `summary.sig` first and for `summary` next. If
the fetcher admits two requests at once, the bucket client keeps the two
requests in flight together, as the stream source does. So a pull of an
`s3://` remote, and a collection probe of it under a summary policy, wait
for one round trip for the two files in place of two. A pull over HTTP with
no bucket client keeps the order of the `ostree` command: `summary.sig`,
and then `summary`.

A pull from a bucket repository needs the permissions `s3:GetObject` and
`s3:ListBucket` on the bucket. Without `s3:ListBucket`, AWS answers the read
of an absent key with 403 `AccessDenied` in place of 404. The pull then fails
at an absent optional file, for example `summary.sig` or the `.commitmeta`
of a commit. A 403 stays an error: the same answer comes for a present key
that the credentials cannot read, and a pull that reads it as absent
continues without a signature or a file that the bucket holds.

`EndpointOverrides` gets four fields with no feature gate: `s3_region`,
`s3_endpoint`, `s3_addressing`, and `s3_profile`, each an `Option<String>`.
A build without the feature `s3` has the same struct, so a caller that
builds it compiles with and without the feature. `s3_addressing` is text,
because the type `s3::Addressing` is behind the feature. The pull reads it
with `Addressing::from_name` and refuses another value by the name
`s3-addressing`. The keys of the same names follow the same rule. A field
of the caller wins over its key, and `s3::resolve` gives each other source.

An S3 field or an S3 key with an address that is not S3 is refused. An
`s3://` address in the key `url` is refused, in each build, as an ssh
address there is refused: the `ostree` command also reads `url`. An
`s3://` address in `url` for a remote that the port alone reads, with a
note in the documentation, was rejected: the config has no mark of such a
remote, and the `ostree` command refuses the remote at each pull and each
`remote refs` with `error: Invalid URI scheme in s3://BUCKET/PREFIX`.

`resolve_pull` refuses an `http://` S3 endpoint without
`allow_cleartext_credentials`, because the signature is a credential. The
check comes after the resolution, because the endpoint can come from the
environment or from a profile. The rule applies to an S3 endpoint alone,
and the resolution of a pull from an HTTP address does not change.

`Repo::pull_collection` reads the refs of a remote at an `s3://` address
from the summary of its bucket repository alone. No server answers
`_ostrya/refs/v1` for a bucket repository, so the pull does not send that
request, and `Repo::pull` does not send it either. The probe reads
`summary` through the bucket client. Under a summary policy it also reads
`summary.sig`: it asks for `summary.sig` first, and if the fetcher admits
two requests at once, the two requests are in flight together. So an absent
bucket and a wrong secret key skip the remote with the S3 code. The pull
from a selected bucket repository reads its `config` through the same
client. A bucket repository with no `summary` fails the probe, and the pull
skips it with an event. A bucket repository with no summary that lists no
ref was rejected: the remote then gives no sign of the reason that it serves
no ref.

A list of the ref keys of the bucket, as a source of the collection refs,
was rejected. The summary is the one signed source of the refs of a bucket
repository, so a remote under a summary policy reads it in each case.
`ostrya remote refs` reads the summary too. A probe from a list costs a
`ListObjectsV2` of `refs/`, a read of each ref file, and a read of each
commit for its timestamp. A check of the summary against the ref files of
the bucket was rejected for the same cost. So a ref file that names a newer
commit than the summary has no effect: the pull takes the commit of the
summary, as `Repo::pull` takes it for a ref that the summary lists. The
pull does not compare the `collection-id` of the bucket `config` with
`ostree.summary.collection-id`: the summary alone states the collection of
each ref, as for an HTTP remote.

A listing request to S3, with a 404 read as no listing, was rejected. S3
answers the read of an absent key with 403 when the credentials have no
`s3:ListBucket`, and the request costs one round trip at each probe for no
answer.

The check of the length of each requested name against the limits of a ref
listing request applies also when each remote is a bucket repository. The
check reads the arguments alone, before the resolution of the remotes, so
one rule applies to each pull of collection refs.

## The writer lock of a bucket repository

S3 has no transaction over more than one object, so two writers on one
bucket repository race in two ways. Two pushes, or a push and an update of
the summary, each read the refs and each write a summary that does not hold
the ref of the other. A prune removes an object that no ref reaches, and at
the same time a push finds the object in its listing, does not upload it,
and writes a ref that reaches it. Each writer therefore holds a writer lock,
one object at `extensions/ostrya/lock`, which it writes with
`If-None-Match: *` and removes at the end. A read takes no lock.
`docs/format-reference.md`, "The writer lock", gives the body and the
requests. `ostrya::bucket` holds the lock, and `BucketRepo` is in `ostrya`,
because the push, the fsck, and the prune of a bucket repository need the
parsers and the summary builder of the crate.

Two alternatives were rejected:

- Conditional writes on the ref files and the summary, and a documented
  rule that a prune runs when no push runs. Conditional writes do not stop
  the race of a prune and a push.
- A lock with a lease: an expiry time in the lock, which the holder writes
  again during a long run, and a take of an expired lock with `If-Match`.
  It adds a dependency on the clocks of the hosts, and a run that stops
  writing the lock in time loses it during a change.

The lock has no lease. A lock that a crashed writer leaves stays until a
break of the lock removes it.

The `id` of a run is the SHA-256 of the host name, the process id, the time
in nanoseconds, and a counter of the process, in lowercase hex. The id
needs no random source: `getrandom` is authorized for `ostrya-server` alone.
The host name comes from `/proc/sys/kernel/hostname`, because `ostrya`
builds on Linux alone. The feature `system` of `rustix`, for `uname`, was
rejected: it changes a feature of a dependency and gives the same value on
Linux.

Before a request to the lock key, the writer probes that the server honors
`If-None-Match`, on the key `extensions/ostrya/lock-probe`. It sends the
fixed body `ostrya lock probe\n` with `If-None-Match: *`, and sends it again
if the first request wrote the key. A 412 to either request shows that the
server honors the header. A server that writes the second request gives no
exclusion, and the writer fails with `Error::BucketNoExclusion` before a
request to the lock key, so a lock that the key holds does not change. The
library has no option that lets a writer run on such a server.
`rclone serve s3` 1.75.1 ignores the header, so no writer runs on it. The
tests of a writer run on SeaweedFS 4.36, which honors the header, and on a
stand-in server in the test process, and the tests on `rclone serve s3`
check the refusal. An option that lets a writer run with no exclusion was
rejected, and so was a test proxy in front of `rclone serve s3` that gives
the headers their meaning.

A second probe request with an unknown outcome, whose read finds the probe
body, fails the take before a request to the lock key, and the operator
runs the operation again. `PutIfAbsent::Present` counts as a 412. It also
comes from a read after an interrupted request that finds other bytes, and
only a program other than the port writes other bytes to the probe key. The
probe runs on each take. A cache of an earlier result was rejected: the
server in front of a bucket can change between runs, and the probe costs
one `PUT` on a bucket that holds the key.

Three alternatives of the probe were rejected:

- A probe after the take: a second `PUT` of the lock body to the lock key.
  On a server that ignores the header, the take writes over the live lock
  of another writer, and the removal after the failed probe deletes the
  key. The other writer then stops in the middle of its run, at its next
  check, with `Error::BucketLockLost`.
- A delete of the probe key after the probe. A delete between the two
  requests of the probe of another writer lets the second request of that
  writer write the key, and that writer fails with
  `Error::BucketNoExclusion` on a server that honors the header. So no
  writer deletes the key.
- A body for each run, for example with the id of the run. After a
  request with an unknown outcome, put-if-absent reads the key and
  compares its bytes with the body, and other bytes give
  `PutIfAbsent::Present`, which the probe counts as a 412. With the same
  bytes from each writer, the probe of another writer on a server that
  ignores the header cannot give other bytes and a false 412. Such a body
  also leaves the data of a host in a key that no writer deletes.

The release and the break read the lock and its `ETag`, and send `DELETE`
with `If-Match` and that `ETag`. The writer does not probe for `If-Match`:
on a server that ignores the header, the conditional delete is a delete
with no condition. A break removes only the lock that it read. A 412 to the
delete of a break fails the take with `Error::BucketLocked`, which names
the new holder. If the read after the 412 finds no lock, its holder
removed it, and the break goes on to the take. A delete with no condition
on a break was rejected: it can remove the lock of another writer that
broke the lock after the read. So a break whose `GET` gives no `ETag`
fails, and deletes no lock.

A release whose `DELETE` removed the lock, but whose answer did not
arrive, sends the `DELETE` again. If another writer took the lock between
the two requests, the release fails with `Error::BucketLockLost`, although
it was complete. The documentation of the release states this case. A
third outcome of `Bucket::delete_if_match` for it was rejected: another
writer holds the lock at the end of the release, as the error states.

A lock body that the port cannot read is the lock of an unknown writer: a
take fails with `Error::BucketLocked`, a check fails with
`Error::BucketLockLost`, and a break removes the lock. An error that stops
each writer and the break was rejected, because the operator then deletes
the object by hand.

A take that gets 412 and then reads no lock fails with
`Error::BucketLocked` with no holder, and makes no second attempt. A
release that finds another `id` or no lock fails with
`Error::BucketLockLost`. The writes of the run were done under its last
check, and the error tells the operator that another writer ran. A success
with a flag was rejected.

`ostrya::Error` has the variants `BucketLocked`, `BucketLockLost`, and
`BucketNoExclusion` behind the feature `s3`, so a caller tells a refusal of
the lock from other errors. `BucketRepo::lock`, `BucketRepo::lock_holder`,
`WriterLock`, `LockHolder`, `LockOperation`, and `BucketRepo::list_objects`
are public, so another tool on the bucket client keeps the exclusion.
`BucketRepo::open` sends no request. An init and a push take the lock
before they read `config`.

`BucketRepo::list_objects` sends one list of each of the 256 fan-out
prefixes. The lists are futures of one set that the call polls, with no
spawned task. At most `max_outstanding` lists are in the set at a time, the
admission limit of the fetcher. A list of a prefix with more than one page
holds the keys of its earlier pages while it waits for the next page. With
256 lists in the set, the fetcher admits page 1 of each prefix before page
2 of any, so almost each key of the repository is in memory before the
first list ends. A set that holds the 256 lists at one time was rejected
for this reason.

## The S3 push

`Repo::push_to_bucket` writes commits to a bucket repository with no
session, and `Repo::push` with `Endpoint::S3` calls it. It gives
`BucketPushOutcome`: the `PushOutcome` and the holder of a lock that
`break_lock` deleted. `Repo::push` drops the holder. A field in
`PushOutcome` was rejected: the type is in `ostrya-remote`, it has no
`#[non_exhaustive]`, and a session push has no writer lock.

`RepoPushOptions` gets `break_lock` and the hidden `part_size`, with no
feature gate, as `EndpointOverrides` gets its S3 fields. A gate behind the
feature `s3` was rejected: a caller that builds the struct then compiles in
one feature set alone. A push over ssh or HTTP refuses each of the two
fields. `part_size` lets a test send an object in parts of 5 MiB.
`Bucket::put_stream` still refuses a part below 5 MiB, because SeaweedFS
4.36 refuses it at the completion.

The push runs all local checks of a session push before it takes the writer
lock, so a local refusal takes no lock and sends no request. The
fast-forward check needs the refs of the bucket, so it comes after the
lock.

Each `DST` of a push names its own namespace by the rule of the receive
push ("The namespace of each pushed ref"), with the `config` of the bucket
in the role of the server. One push can write refs of more than one
namespace. The binding of a commit checks, and selects no namespace. A
bucket has no server and no client group, so the flag
`RepoPushOptions::disable_verify_bindings` alone skips the ref-binding
check of a push to a bucket. No flag skips the check of the collection
binding. A bucket
repository can have a `[core] collection-id`, and it is then the primary
server of that collection. It can also mirror other collections under
`refs/mirrors/ID/`. A bucket repository with no collection id and with the
refs of `refs/heads/` alone was rejected: a bucket repository must serve as
the primary server of a collection and as a mirror of several collections.
The summary holds `ostree.summary.collection-id` and
`ostree.summary.collection-map` from the builder of the local summary, and
no `ostree-metadata` anchor commit.

`BucketRepo::init` writes the `config`, with an optional collection id,
under the writer lock with the operation `init`. It refuses a bucket that
holds a `config`, so the collection id of a bucket repository never
changes. A push to a bucket with no `config` is refused. A push that writes
the `config` of a new bucket was rejected: the collection id is then set by
the first push, with no step of its own.

A bucket repository follows the rule of "The own collection id": the push
writes the refs of the own collection under `refs/heads/`, and no writer
writes `refs/mirrors/ID/` of the own collection id. The push and the
summary update skip the keys of that directory, the prune reads them as
roots, and the fsck gives each of them a note.

A push reads the ref files of the ref directories of its namespaces alone:
`refs/heads/` for the local refs and the refs of the own collection, and
`refs/mirrors/ID/` for each other collection of a `DST`. It reads each such
directory one time. The check that
each ref names a commit that the bucket holds or that the push uploads,
and the check of the directory prefixes, cover these ref directories
alone. A key or a ref file of another namespace that breaks a
rule does not refuse the push, and the fsck of a bucket repository checks
it. A read of all refs of the bucket at each push was rejected: the cost of
the push then grows with the refs of each namespace, also of the namespaces
that the push does not write, and only a summary write needs all refs.

A push refuses an update whose new ref set holds, in one ref directory, a
name that is a directory of another name. A bucket has no
directories, so the two keys can both exist, but a local repository cannot
hold the two refs, and a pull into one fails.

After a failure before the ref writes, the push releases its lock and
returns the first error. An error of that release is dropped: the lock
stays, and the next writer names it. After `Error::BucketLockLost` and
`Error::BucketLocked`, the push releases no lock, because the lock is the
lock of another writer.

When one upload fails, the push starts no new upload, waits for the uploads
in flight, and returns the first error. Each failed `put_stream` aborts its
own multipart upload. A drop of the uploads in flight was rejected: a
dropped `put_stream` sends no abort, so it leaves open multipart uploads
that hold storage.

The push uploads a `.commitmeta` when the listing does not hold it, when
its size in the listing differs, or when a read of it gives other bytes.
So a second push with no change uploads no object. A `.commitmeta` that
holds `ostrya.related` alone uploads nothing under
`[ex-ostrya] keep-detached-related=false` of the bucket, and the bucket keeps
its copy, as a pull under the same switch keeps the copy of the destination.
An upload of an empty file and a delete of the bucket copy were rejected:
each one removes metadata other than `ostrya.related`. An
upload of each `.commitmeta` of each source commit at each run was
rejected: a second push with no change then uploads the `.commitmeta` of
each source commit.

The push writes no summary. The update of the summary of a bucket
repository is always explicit, as in a local `archive` repository with no
`auto-update-summary`. A push leaves a `summary` and a `summary.sig` of the
bucket as they are, so they can list old refs, and a pull of a named ref
reads the ref file when the summary does not list the ref. The writer
still reads `tombstone-commits` and `indexed-deltas` with the `config`, so
a value that is not a boolean refuses the push before its first upload.

The push uploads no static delta. A delta comes into a bucket repository
from another writer, for example as a copy of a delta directory of a local
`archive` repository, and a summary update lists each delta with a
superblock. An upload of the deltas of the local repository that end at a
pushed commit, in the `archive` mode alone, was rejected: the deltas of the
bucket then follow the content and the mode of the local repository, so
two pushes of one commit from two repositories leave different deltas in
the bucket.

A summary write on each push, signed by the signers of a field
`summary_signers` of `RepoPushOptions`, with a refusal of a push with no
signer to a bucket repository with a `summary.sig`, is rejected. With it,
each push needs the signing keys of the summary, and reads the commit of
each ref and each superblock of the bucket. One rule, the explicit update,
writes the summary. `RepoPushOptions` has no field for the signers of a
summary. `BucketRepo::update_summary` is the explicit update ("The summary
update of a bucket repository").

The push walks no tree of a commit that the listing of the bucket holds,
unless the commit has a partial-commit marker under `state/`. Each writer
uploads a commit object after each object of its tree, so a commit object
in the bucket has its whole tree in the bucket, or a marker that the repair
of the fsck wrote, and the fsck checks this rule. A walk of each source
commit, as a push over a session does, was rejected: a push with no change
then reads each dirtree of its commits and uploads nothing. The push lists
`state/` only if the listing holds an offered commit, walks the tree of
each offered commit with a marker, uploads the objects that the listing
lacks, and deletes the marker after a check of the lock and before the ref
writes. The commit object of such a commit does not go up again. A tree
push lists no `state/`: the tree of its parent does not change.

The holder of a lock that `break_lock` deleted is in `BucketPushOutcome`
and in the result of `BucketRepo::init` on success alone. A push or an
init that breaks the lock and then fails returns its error with no holder.
A holder in the error was rejected: it changes the error type of each
writer for one case, and a caller can read the holder with
`BucketRepo::lock_holder` before it breaks the lock.

`PushProgress` gets the public methods `set_phase`, `start_phase`,
`add_upload`, `object_uploaded`, and `add_content`, so a client that
uploads with no session counts into the handle of the caller. The progress
bar of the `ostrya` command reads the same handle with no change. A
progress type of its own for the bucket push was rejected for this reason.

`PushProgress::start_phase` sets a phase and calls the hook, also when the
handle holds that phase before the call. A tree scan calls it with
`Scanning` before its walk, and `Repo::push_to_bucket` calls it with
`Scanning` after its local checks. A tree push to a bucket repository gets
its call from its tree scan. A `set_phase` call at the start of the scan
and of the bucket push was rejected: a new handle holds `Scanning`, so the
call gives the hook no call. The first hook call then comes after the
walk, with `Hashing` or `Uploading`, and a client that writes one line at
each hook call writes nothing during a long scan. `set_phase` and the
phase changes of a session share one rule: a repeated phase gives the hook
no call. A rule that calls the hook at each call that sets a phase was
rejected: `PushSession::send` sets `Uploading` before it sends its
objects, and a session can make more than one `send` call, so the hook
gets calls with no change. A handle that starts in no phase was rejected.
It needs a new `PushPhase` variant, and it changes `PushPhase::default()`
and `PushProgressSnapshot::default()`. Each `match` of a client over
`PushPhase` then gets a phase that is new to it.

A push builds each `.filez` at the `[archive] zlib-level` of the `config`
of the bucket. The level of the local repository was rejected: two pushes
of one commit from two repositories then upload other bytes for one
object, and the bucket has no level of its own. A `.filez` of a local
`archive` repository still goes up as it is stored, at the level of that
repository, because a build again costs a deflate of each file. The push of
commits still refuses a compression. `BucketRepo::init` takes the level as
an argument, and writes the group `[archive]` with it. With no level, the
`config` has no `[archive]` group, and a writer takes the level 6, as a
local repository does.

`BucketRepo::push_tree` writes a local directory to a bucket repository as
one new commit. It takes `TreePushOptions` of `ostrya-remote` and a new
`BucketWriteOptions` with `break_lock` and the hidden `part_size`, and it
gives `BucketPushOutcome` with the new commit in `PushOutcome::commit`. The
struct is `#[non_exhaustive]`, so a later writer option is additive. Two
fields in `TreePushOptions` were rejected: the struct is in `ostrya-remote`
and has no `#[non_exhaustive]`, and a session push has no writer lock.

The bucket has no server, so the client makes the commit, with the commit
builder of the receive side of a session tree push. The two writers share
one crate-private function, so the same inputs give the same bytes.
`ostrya_remote::scan_tree` runs the checks of the options of a session tree
push and the scan, and gives the model of the tree and the checked fields
of the commit. It also checks the depth of each metadata value, which a
session push checks after the session opens. A copy of the checks in
`ostrya` was rejected: the two writers then refuse different options. The
size limits of the two writers are different: a session push refuses a
`Commit` frame over the `max-frame` of the server, 1 MiB for an ostrya
server, and a bucket push has no frame and refuses a commit object over
`MAX_METADATA_SIZE`.

The tree push takes the writer lock with the operation `push`. A new
operation for the tree push was rejected: the operation tells the operator
which writer holds the lock, and the two pushes make the same kind of
change. The parent is the tip of the branch that the push reads under the
lock, so each tree push is a fast-forward. With `orphan` on a branch that
exists, the new commit replaces the tip with no check. A right of the
client, as the `d` of a server, was rejected: a bucket has no client
groups, and the writer of a bucket can write each ref.

A tree push to a bucket refuses tags. A tag of a server commit needs a
check that the tag is absent and a write of two refs, and the push of
commits creates no tag either. The anchor ref `ostree-metadata` in
`refs/heads/` of a bucket with a collection id is refused, as a server
refuses it.

A tree push signs no commit. A signer in the options was rejected for this
release: the signing engines are in `ostrya`, and a session tree push signs
on the server. To sign the commit, a user pulls it into a local
repository, signs it there, and pushes it with `Repo::push_to_bucket`,
which then uploads the `.commitmeta` alone. `docs/roadmap.md` records the
gap.

The tree push reads each file again as a stream, hashes its header and its
payload, and fails at the end of the payload if the checksum is not the
checksum of the scan. The bucket client reads one byte past each full part
before it sends the part, so the last part never goes up, and a failed
multipart upload is aborted. So a file that changed after the scan leaves
no object of it in the bucket. A check by a server, as in a session push,
does not exist for a bucket.

## The `ostrya` command and bucket repositories

`ostrya-cli` turns on the feature `s3` of `ostrya` in its default set, so
the shipped binary reads and writes bucket repositories. The feature is
off by default in `ostrya-remote` and in `ostrya`, so a build of the
library that reads no bucket compiles no SigV4 signer and no XML reader.
The feature off in all crates was rejected: the shipped binary then
refuses each `s3://` address. The feature gates
the S3 options, `--break-lock`, `remote init`, `remote fsck`,
`remote prune`, and `remote summary -u`, as the features `push`, `serve`,
and `send` gate their commands. A build without
the feature refuses an `s3://` address with the message of the library,
which names the feature.

The init of a bucket repository is `ostrya remote init NAME|ADDRESS`, with
`--collection-id`, `--break-lock`, the S3 options, and
`--allow-cleartext-credentials`. A group `repo` with a command
`repo init-s3` was rejected: `remote` already holds the commands that act on
a remote, and the init needs no local repository. With an address, the
command opens no repository. With a remote name, it reads the remote from
the config of the repository.

`endpoint::resolve_bucket` gives the endpoint of each writer of a bucket
repository other than a push. For a remote name, the address is `push-url`
when it is `s3://`, else `pull-url` when it is `s3://`, and else the remote
is refused. The key `url` is never read. The function makes the refusals of
a push to an `s3://` address: `tls-permissive=true`, `push-token-file`,
`push-user`, and the ssh fields. A resolver for each writer was rejected,
because each writer takes the same address and the same refusals.

`endpoint::pull_address_is_s3` tells if the pull address of a remote,
`--url`, else `pull-url`, else `url`, is `s3://`, an HTTP or an ssh
address, or an address that `resolve_pull` refuses, with no file and no
environment. The command refuses `--allow-cleartext-credentials` and the
four `--s3-*` options of `pull`, `remote refs`, and `remote summary` when
the address is an HTTP or an ssh address, with the name of the option. For
an address that `resolve_pull` refuses, the command passes the options on,
and `resolve_pull` states its refusal. A refusal of the options for such an
address was rejected: its message hides the real refusal, for example an
`s3://` address in `url` or a remote that the config does not describe.
`Repo::remote_fetch_summary_with` takes the overrides of the caller, so
`remote refs` and `remote summary` take the S3 options.
`Repo::remote_fetch_summary` stays, with the default overrides. For
`push`, the command reads the push address of the remote, `push-url`, else
`url`, and refuses `--break-lock` and the `--s3-*` options for an HTTP or
an ssh destination with the name of the option. A refusal by the library,
which names the remote key, was rejected for these options, because the
key names do not tell the user which option to remove.

`ostrya push` calls `Repo::push_to_bucket` for an S3 endpoint, because
`Repo::push` drops the holder of a broken lock. The holder goes to standard
error in one line, `warning: removed the writer lock of HOLDER`, after a
push or an init that succeeds. `--break-lock` conflicts with `--onto`.

`ostrya remote add NAME s3://...` writes `pull-url` and `push-url` after the
branches, and writes no `url`, also in a build without the feature `s3`.
The command does not parse the address. A pull or a push refuses a bad
address when it uses the remote. `remote show-url` and `remote list -u`
then fail for the remote, because it has no `url`.

`resolve_push` reads the environment and the shared AWS files before the
library refuses `--tag` and `--compress` for an S3 destination. When
`push-branches` gives the refs of a push with no refspec, the command
refuses `--tag` before the resolution and reads no AWS file. A check of
these options in the command before the resolution was rejected: it copies
a rule of the library, and the read of the files sends no request.

A push to a bucket repository shows no progress bar while it lists the
bucket and walks the commits, because the bar of `push` shows nothing in
the phase `Scanning`. A bar of its own for the listing was rejected for
this release.

`ostrya push-tree` takes an `s3://` destination, and calls
`BucketRepo::push_tree`. It takes the S3 options and `--break-lock`, and
refuses them for an HTTP or an ssh destination, with the rule and the
message of `push`. The command prints the new commit, as for a session
tree push, and the holder of a broken lock on standard error. The timestamp
of the commit is `--timestamp`, else `SOURCE_DATE_EPOCH`, else the clock of
the host, which the library reads. `--compress=LEVEL` sets the level of the
`.filez` objects of the push in place of the level of the bucket.
`ostrya remote init` takes `--zlib-level LEVEL`, which `clap` checks for 1
to 9 before any request.

The tests of the S3 options run against the stand-in of
`crates/ostrya/tests/common/s3.rs`, which keeps the `Authorization` header
of each request, so a test of `--s3-region` and of `--s3-profile` needs no
rclone. CI installs `rclone` and sets `OSTRYA_REQUIRE_S3`, and a CI step
builds `ostrya-cli` without the feature `s3` and runs
`crates/ostrya-cli/tests/s3_absent.rs`.

## The fsck of a bucket repository

The fsck of a bucket repository is `BucketRepo::fsck` and the command
`ostrya remote fsck NAME|ADDRESS`. The group `remote` holds the commands
that act on a remote, and the init of a bucket repository is there. Two
other commands were rejected: `ostrya fsck` with an `s3://` value of
`--repo`, which gives `--repo` a second meaning, and most of whose options
have no meaning for a bucket, and a new group `ostrya bucket`.

A key under `refs/mirrors/ID/` of the own collection id gets a `ref` note,
and the fsck reads no such ref file, as "The own collection id" states.

The fsck reads and checks each object that a commit reaches, as the local
fsck does. Its cost is the download of these objects. An option that checks
the metadata objects alone, and the presence and the size of each content
object from the listing, was rejected: it does not find a `.filez` whose
bytes changed.

The repair, `delete`, writes a partial-commit marker
`state/<checksum>.commitpartial` for each commit that reaches a missing or a
bad object of a tree, and then deletes each bad object. It deletes no commit
because of a bad object of its tree. The push walks the tree of an offered
commit with a marker, uploads the objects that the bucket lacks, and deletes
the marker, so a push of the ref repairs the commit with no option. The key
`state/<checksum>.commitpartial` is the path of the marker of a local
repository, and a copy of the bucket directory opened as a local repository
sees the commit as partial. These alternatives were rejected:

- No repair of a commit that a ref names. The commit stays broken until a
  deletion of its ref, which no command of the port makes.
- A delete of each commit that reaches a bad object, also a commit that a
  ref names. Each push to the namespace of the ref is then refused, because
  a ref names a commit that the bucket does not hold, and so is the update
  of the summary, until a push of the ref.
- A delete of each such commit that no ref names, and a marker on each ref
  target. It deletes commits of the history, and the local fsck deletes no
  commit: it marks each commit that reaches a missing or a deleted
  object.
- An option of the push that walks the tree of each offered commit that the
  bucket holds. It needs a manual step, and each such push reads each
  dirtree of its commits.

A commit object whose own bytes are bad goes, also when a ref names it. No
reader can use it: a pull and the build of a summary both check its
checksum. A push of the ref uploads it again, because the listing does not
hold it. A commit whose object goes gets no marker. The report names each
ref of such a commit, because until the push of the ref, each push to its
namespace is refused.

The repair also deletes the marker of each commit whose tree the run finds
whole, and a run without the repair gives a note for such a marker. The
push deletes the marker of an offered commit alone, and the offer stops at
the tip of the ref in the bucket. So with no such delete, the marker of a
commit of the history stays after a push repaired its tree.

A repair that fails after its first change gives
`Error::BucketRepairIncomplete`. The error holds the report, with each
marker and each delete that completed, and states that the repair must run
again before a push. The marker goes up before the delete of the bad
objects, so a failure between the two leaves a marker on a commit whose bad
objects are still in the bucket, and a push of that commit uploads no
object that the listing holds and deletes the marker. The push does not
change for this state. Two changes of the push were rejected: an upload of
each tree object of a marked commit that the local repository holds, and a
read and a check of each listed tree object of a marked commit before the
delete of the marker. Each costs each push of a marked commit the upload or
the download of its whole tree, for a state that only a failed repair
leaves.

The repair needs a valid `config`. A run with `delete` reads `config` before
it takes the lock, and an absent or a bad `config` refuses the repair: the
run then checks the bucket, writes no key, and takes no lock. A wrong
address thus never loses an object. A push refuses a bucket with no
`config` in the same way.

The summary of a bucket repository changes only with an explicit update,
and a push writes none. So a summary that differs from the ref files or the
deltas is a note, and an absent summary is a note when the run verifies no
signature. A summary that a pull trusts and that leads the pull to an
absent object is an error: a summary ref whose commit is absent, a summary
delta whose superblock is absent or has another digest, a summary that does
not parse, and a signature that does not verify. A summary that differs is
an error in no case, because each fsck after a push then fails until an
update of the summary.

`BucketFsckOptions::summary_keys` takes the summary keys as
`TrustedKeys`, and `PullTrust::summary_keys` gives the summary keys of a
remote. `ostrya remote fsck NAME` reads the remote with the commit checks
off, so it reads no commit keyring. A field of the type `PullTrust` was
rejected: the fsck verifies no commit, and the type holds the commit keys
too. The options have no progress field. With `#[non_exhaustive]`, a later
field is additive.

A finding names the commits that reach its object. The walk keeps no list
of the files of a dirtree, so when a finding names an object of a tree, a
second pass reads each dirtree one more time. It gives each dirtree a
32-bit number, keeps each edge from a dirtree to its parent as two numbers
in one sorted list, and keeps the dirtrees that hold each bad object. The
cost is one more `GET` for each dirtree, and only with such a finding. A
list of parents for each dirtree in a map was rejected: it costs one heap
allocation for each dirtree.

The summary of a bucket gives the delta map that a pull reads. With a
summary in the bucket, a delta map of the bucket that the run cannot build
is a `summary` error: a superblock key whose directory names do not decode
as a delta, or a superblock larger than its cap. The summary builder fails
on the same keys. The run reads the superblocks of the deltas that the
summary advertises alone, and takes the names of the other deltas from the
list of `deltas/`.

A run without the repair takes no lock, and the listing of the 256 fan-out
prefixes is no snapshot, so a push or a prune during the run can give a
false `missing` finding. Before the run records a `missing` finding for an
object that the listing does not hold, it reads the object again. An object
that the bucket holds now gives a note. Else the run reads each commit of
the finding again, and a finding whose commits are all gone is dropped. The
read is a check of `Bucket::exists_strict`, which asks for the first byte
of the object alone, so its connection serves the next read. A `HEAD`
cannot apply the strict rule, and the key rule refuses a list with the key
as its prefix.

The hash and the parse of a metadata object larger than 1 MiB, and the
parse of a summary, run on the blocking pool, as the parse of a commit and
of a summary of a pull does. The reads of the other slots go on in the
meantime.

A body of a `.filez` that fails in transit is read again once from its start,
and a second failure fails the run. A failure of the run on the first failure
was rejected: the fsck reads the whole bucket, and one failed connection then
stops the run.

`ostrya remote fsck` prints the counts and the result line on standard
output, and one line for each finding on standard error, as `ostrya fsck`
does. A note starts with `note: `. A report with an error exits 1, and a
report with notes alone exits 0.

## The prune of a bucket repository

The prune of a bucket repository is `BucketRepo::prune` and the command
`ostrya remote prune NAME|ADDRESS`, for the reasons of the fsck: the group
`remote` holds the commands that act on a remote. `ostrya prune` with an
`s3://` value of `--repo`, and a new group `ostrya bucket`, were rejected.

The walk is the walk of the local prune, `traverse::walk_reachable_gc`,
over a source of metadata objects that the local repository and the bucket
both give. So the bucket prune has the roots and the bounds of
`Repo::prune` with no copy, and the tests of the local prune gate the walk.
The bucket prune follows the field 2 edge of the walk and does not follow
the `ostrya.related` edge ("Related commits"). With `refs_only` or
`keep_younger_than`, it deletes a build source that the local prune keeps.
In each case, it deletes the `.commitmeta` of a build source that the
listing does not hold, which the local prune keeps. A walk for the
bucket alone, with a copy of the rules of the bounds, was rejected: a
later change to one copy can miss the other.

The roots include the refs under `refs/mirrors/ID/` of the own collection
id, as in the local prune ("The own collection id").

The walk reads the commits one at a time, and walks the tree of a commit
before it reads the next commit. It reads the dirtrees of one tree with the
`Slots` driver of the pull, at most `max_reads` of the source at a time. The
local repository gives one, so the local walk reads one object at a time. A
bucket repository gives `max_outstanding`. With a limit of one, the walk
reads the dirtrees in depth-first order, and starts each read after the
read before it ends. If more than one read fails, the first read that fails
in time gives the error, and the walk drops the other reads in flight, as
the bucket fsck does. These alternatives were rejected:

- A prefetch in the source of the bucket prune of each commit and each
  dirtree of the listing. It reads objects that no root reaches, and holds
  them in memory.
- A batch of the subdirectories of one dirtree. A dirtree with few
  subdirectories does not use the limit.
- A batch across the frontier, with each read of a batch done before the
  next batch starts. Each batch waits for its slowest read.

`BucketRepo::prune` takes the `PruneOptions` of the local prune and a
`BucketPruneOptions` with `break_lock`. It takes `refs_only`, `depth`,
`keep_younger_than`, and `no_prune`, and refuses each other option that is
not at its default, before a request, with `Error::InvalidInput` that
names the first such field in the order of the fields. A type of options
for the bucket alone was rejected: the four options have the meaning of the
local prune, and a later option of the local prune that the bucket takes
then needs no new field. `delete_commit` and `static_deltas_only` need a
tombstone, `only_branch`, `retain_branch_depth`, and `weak_ref_filter` read
names of the local ref space, `commit_only` leaves objects with no commit,
and `traverse_parent` reads the metadata of each commit. These stay for a
later version.

The result is `BucketPruneReport`: the `PruneStats` of the local prune,
whose `deleted_refs` is always empty and whose `warnings` hold the
defective field 2 entries, and the deleted deltas, the deleted markers, the
aborted uploads, and the holder of a broken lock. With `no_prune`, the
lists name what a run deletes. A `PruneStats` alone was rejected, because
the command prints the deltas, the markers, and the uploads, and the holder
of a broken lock needs a place on success.

When the roots are not on the refs alone, each commit of the listing is a
root, so each root, the ref targets and the commits of the summary
included, keeps no parent. A dependency is then a root that keeps no parent
too. Each commit of the listing is already a root, so a parent bound adds
no commit of the listing to the kept set. The kept objects of the listing
are the same as in the local prune, with one exception, apart from the
build sources. The walk does not reach a parent commit that the listing
does not hold, so the prune deletes the `.commitmeta` of that commit. The
local prune keeps it when its bound reaches that parent. Such a
`.commitmeta` has no commit object in the bucket, and a push of that commit
uploads it again. So the prune treats it as an object that no root
reaches. The bound of the local prune for these roots was rejected: it
keeps these objects, and it adds no object of the listing to the kept set.
With `refs_only` or `keep_younger_than`, the walk takes the bounds of the
local prune. A dependency, also a dependency of a commit of the summary, is
a root under the bound of the run, as in the local prune. A commit of the
summary that a ref also names is a root under the bound of the ref alone.
The walk keeps the parent and the timestamp of each commit that it reads,
so it reads each commit one time in each mode, with one exception. With
`keep_younger_than`, the walk reads a commit a second time when the time
bound rejected the commit as a parent and the walk then reaches the commit
as a root, for example as a dependency.

The walk reads an object that the listing does not hold as absent, with no
request. The run holds the writer lock, so no writer adds an object during
the run. Each read takes at most the size of the object in the listing, and
the run checks the SHA-256 of each commit and dirtree that it reads. A bad
object fails the run before its first delete, with a message that names
`ostrya remote fsck --delete`. A walk with no check was rejected: a dirtree
with other bytes names other children, and the prune then deletes objects
that a commit of the bucket reaches. `BucketRepo::traverse_reachable`, which
is not a stable API, keeps its reads with no listing and no check.

The commits that the summary names, in field 0 and in the collection map,
are roots with no parent. The prune writes no summary, so the summary that
a pull reads after a prune can still name the commits of refs that moved
before the prune. With these roots, such a pull finds its commits. A
summary that does not parse fails the run before its first delete. A
prune that ignores the summary was rejected, because it can break a pull
that trusts the summary until an update of the summary. The deltas that
the summary names get no such rule: a delta whose target commit goes, goes
too, as in the local prune. The summary then names an absent delta until an
update of the summary, and the fsck reports it as a `summary` error.

A run with `no_prune` takes the writer lock too, so its counts describe a
state that no writer changes during the run. Thus a dry run needs the
permissions of a writer. The prune refuses `break_lock` together with
`no_prune`, with `Error::InvalidInput`, before a request. Thus a dry run
never removes the lock of another writer. A removed lock makes that writer
fail at its next check of the lock. `ostrya remote prune` refuses
`--break-lock` with `--no-prune` in the option parser. A refusal in the
option parser alone was rejected: a library caller can set both options. A
dry run that takes no lock, as the fsck with no repair, was rejected: its
counts then describe a state that a concurrent push can change.

The prune refuses a `config` that sets `[core] tombstone-commits=true`,
because it writes no tombstone. A run that ignores the key was rejected: it
deletes commits with no tombstone, which the repository policy asks for.
The refusal comes before the lock.

The prune deletes a delta directory whose target commit is absent also when
it has no superblock, and deletes the superblock first when it has one. A
run that stops between the two deletes then leaves a directory with no
superblock, and the next run deletes it. A key under `deltas/` that fails
`ostrya_remote::s3::is_repository_key` stays, as a stray key. The key rule
is exported for this check, so the prune and the bucket client take one
rule. `delta-indexes/` does not change, as in the local prune.

The run checks the lock before each step that has a change to make, and after
each 1000 deletes or aborts of a step. The steps are the commits with the
`.commitmeta` of absent commits, the other objects, the static deltas with the
markers, and the aborts. One check for each delete was rejected: it doubles
the requests of a run. The check gives no exclusion of its own, as "The writer
lock of a bucket repository" states.

Each delete is one `DELETE` of one key, in parallel under the admission
limit of the fetcher. `DeleteObjects` was rejected: AWS needs a
`Content-MD5` or a checksum header on it, and the first needs a crate.

A failed run gives the error of the failure, and releases the lock unless
the lock was lost or held by another writer. An error that holds the
deletes that completed, as the error of the fsck repair holds its report,
was rejected: the deletes of a prune leave a bucket repository that a
reader can use, and a run again completes the prune. A lost lock at the
release is an error, as for a push.

## The summary update of a bucket repository

The summary update of a bucket repository is `BucketRepo::update_summary`
and the mode `-u` of `ostrya remote summary NAME|ADDRESS`. `-u`/`--update`
is the option name of `ostrya summary`, and `ostree remote summary` has no
`-u`. The maintainer rejected a new subcommand `remote update-summary`,
which leaves the surface of `remote summary` of the `ostree` command as it
is, and selected the option name of `ostrya summary`. With an address,
the command opens no repository. Without `-u`, `remote summary` keeps its
behavior and takes a remote name alone.

`BucketRepo::update_summary` takes a `BucketSummaryOptions` with the
summary signers, `last_modified`, and `break_lock`, and gives a
`BucketSummaryReport`: the number of refs of field 0 and of the collection
map, the number of deltas, the name of the engine of each signer in the
order of the signatures, the `last-modified` value that it wrote, and the
holder of a broken lock. The options struct has a hand-written `Debug` that
names the engines of the signers, as `DeltaOptions` does.

The update reads the `config` before it takes the lock, as the prune does,
so a bucket repository with no `config` refuses the update with no lock
`PUT`. It reads the refs under the lock. An update with no signer probes
`summary.sig` under the lock, at the same time as the read of the refs. An
update with a signer sends no probe: the refusal below is the one reader of
the probe, and it applies to an update with no signer alone. A probe in
each update was rejected: it costs one request for no use.

The update reads the commit objects of the refs and the superblocks at the
same time. Each of the two reads at most `max_outstanding` keys at a time,
and the fetcher holds the requests in flight to `max_outstanding`. A
failure of a commit read takes precedence over a failure of a superblock
read in the error that the update gives.

Each read of a superblock takes the strict rule of an absent key, as the
fsck does. A superblock gone with an answer 404 `NoSuchKey` is left out of
`ostree.static-deltas`, as the local scan leaves out a superblock that went
away. The lenient rule was rejected: with it, a 404 that is not an absent
key leaves a superblock that the bucket holds out of the map, and the
update writes a summary that does not name the delta.

A bucket repository that holds a `summary.sig` refuses an update with no
signer, and no option turns the refusal off. The refusal changes nothing in
the bucket but the probe key of the writer lock.
A signed bucket repository is a signed bucket repository by the presence
of the key `summary.sig` alone. The probe is a check of
`Bucket::exists_strict`. It takes the strict rule of an absent key, so only
an answer 404 `NoSuchKey` is an absent key, and it asks for the first byte
of the key alone. A
probe with the lenient rule was rejected: with it, a 404 that is not an
absent key lets an update with no signer go on, and its summary then has
no signature that covers it. A read of the body was rejected: the body can
be as large as the cap of a summary, 64 MiB. The update never deletes
`summary.sig`. The local writer removes the old signature file before it
writes the summary. A delete in the bucket was rejected: a reader of a
bucket sees each write at once, so a delete first gives a window in which
the bucket repository has no `summary.sig`. An opt-out of the refusal was
rejected: the update does not delete `summary.sig`, so an update with no
signer leaves an old signature that does not cover the new summary, and
each reader that verifies the summary then refuses it.

The update writes `summary` and then `summary.sig`. S3 has no write of two
keys in one operation, so a reader that verifies the summary refuses it
between the two writes. An update with a signer gives
`Error::BucketSummaryIncomplete` when it can leave a pair that does not
match: the write of `summary.sig` fails after the server accepted the
write of `summary`, or the write of `summary` fails with an unknown
outcome. An unknown outcome is a failure of the HTTP client or a last
answer 408, 429, or 5xx, by the retry rule of the bucket client. A failure
of the HTTP client before the request was sent counts too, because it can
end the retries after an interrupted request. The error holds the report
of the update, with the holder of a broken lock, and the failure of the
write. Its message states the state of the pair and names
`ostrya remote summary -u` with the same signers. The update tries to
release the lock, and drops an error of that release. A refusal of the
write of `summary`, for example an answer 403, keeps the error of the
bucket client, and so does an update with no signer. A refusal of the
first request of that write changes nothing. A refusal of a request that
the bucket client sent again can leave the new summary with the old
`summary.sig`, because an earlier request can have written `summary`. A
process that stops between the two writes gives no error. The fsck with
the summary keys reports such a pair as an error on `summary.sig`, and its
detail states that a summary update with the signers writes a matching
pair. For an absent `summary.sig`, the detail states that a summary update
with the signers writes a `summary.sig`. The repair of the fsck does not
change for these findings, because only a signer can write a matching
pair. These alternatives were rejected:

- A write of `summary.sig` first: the window is the same, with the order
  of the two keys reversed.
- A read of the old summary before the write, and a write of it again
  after a failure: the read takes up to 64 MiB, and the second write can
  fail too.
- More attempts of the write of `summary.sig` in the update, after the
  retries of the bucket client: a 403 does not change with a new attempt.
- A probe of `summary.sig` in an update with a signer, to state in the
  error if the bucket holds an old `summary.sig`: the probe costs one more
  request for a detail of the text.
- `Error::BucketSummaryIncomplete` for a refusal of the write of `summary`
  after a request that the bucket client sent again: the bucket client
  returns the last answer alone. A result that tells the update of an
  earlier interrupted request, or of an earlier answer 408, 429, or 5xx,
  changes the public error API of `ostrya-remote`. The trigger is rare,
  and the fsck with the summary keys finds the pair that it leaves.

The update reads each commit of a ref with one `GET`, at most the cap of a
metadata object, and checks its SHA-256 against its name. It sends no
list of `objects/`. A listing of the 256 fan-out prefixes was rejected: it
costs 256 requests or more for each update, and the read of the commit
finds an absent commit too. The hash and the parse of a commit object
larger than 1 MiB run on the blocking pool, as in the prune. The summary
builder lost its input of a local repository and of a listing: the push
writes no summary, so no caller gave them.

The update writes `ostree.summary.tombstone-commits` from the `config`, as
the local summary does, and refuses no value of it. A ref whose commit has
a partial-commit marker is in the summary, and the update reads no key
under `state/`: the marker tells a push to upload the missing objects, and
the commit object is in the bucket. A bucket repository with no ref gets a
summary with an empty field 0, as a local repository with no ref does.

A ref name that is a directory of another ref name of the same directory,
as `a` is of `a/b`, refuses the update with the check of the push. The
refusal changes nothing in the bucket but the probe key of the writer lock.
A local repository cannot hold both refs: `refs/heads/a` is a file, and
`refs/heads/a/b` needs a directory at the same path.

`ostrya remote summary -u` prints nothing on standard output on success,
as `ostrya summary -u` prints nothing. A lock that `--break-lock` removed
gives one `warning: removed the writer lock of HOLDER` line on standard
error, as for the other writers. The command takes `--gpg-sign`,
`--gpg-homedir`, `--sign`, `--sign-type`, `--keys-file`, `--break-lock`,
and `--last-modified`, and each one needs `-u`. `-u` conflicts with
`--raw`, `--list-metadata-keys`, and `--print-metadata-key`. The command
builds the signers with the code of `ostrya summary -u`, in the same order
and with the same checks. Two refusals name the options of
`remote summary -u`, which has no KEY-ID operand: `--keys-file` under the
gpg engine, and a key file with no key. The command does not carry these
options of `ostrya summary`:

- `-m`/`--add-metadata`: the summary of a bucket repository holds the keys
  of the builder alone, so the update and a local update of a copy write
  the same bytes.
- `-c`/`--client-groups`: a bucket repository has no auth items.
- `--metadata-commit-timestamp`: the update writes no anchor commit.
- the positional KEY-ID: the operand of `remote summary` is the remote or
  the address.
- `--keys-dir`: it serves a verify alone.

## The `ostree` command and a bucket repository

A bucket repository has the layout of a static `archive` repository, so
the `ostree` command pulls it over HTTP, and the port writes nothing for
it. The URL is `https://BUCKET.s3.REGION.amazonaws.com/PREFIX`, or the URL
of the endpoint in path style, `ENDPOINT/BUCKET/PREFIX`. The `ostree`
command sends no signature, so the bucket policy gives anonymous
`s3:GetObject` on the keys that the `ostree` command reads: `PREFIX/config`,
`PREFIX/summary`, `PREFIX/summary.sig`, `PREFIX/objects/*`,
`PREFIX/refs/*`, `PREFIX/deltas/*`, and `PREFIX/delta-indexes/*`. The
writer lock under `PREFIX/extensions/` holds the host name and the pid of
the writer, and the `ostree` command reads no key under
`PREFIX/extensions/`, so the policy gives no key there. An anonymous
`s3:GetObject` on `PREFIX/*` with a Deny statement on
`PREFIX/extensions/*` for each principal was rejected: the Deny also
refuses the signed `GET` of the lock by a writer of the port.

S3 answers a read of an absent key with 403 when the caller has no
`s3:ListBucket`. The `ostree` command reads a 403 for `summary.sig`,
`summary`, a delta index, a superblock, and a `.commitmeta` as an absent
file, and a 403 for `config` after a summary fails the pull
(`conformance/cli-behavior.md`, "A 403 for an optional file"). The init
writes `config`, so an anonymous policy with `s3:GetObject` alone serves a
pull of the `ostree` command. A rule that also gives anonymous
`s3:ListBucket` was not taken, because no read of the `ostree` command
needs it.

The port pulls a bucket repository from its `s3://` address alone, with
signed requests. An anonymous S3 pull of the port is not in this release.
The S3 pull reads a 403 as an error ("The S3 pull"), and the HTTP pull of
the port reads a 403 for an optional file as an error too. So the HTTP
pull of the port stops at the first absent optional file of a bucket
repository under the anonymous policy (`roadmap.md`, "Gaps in pull").

The tests that check a bucket repository with the `ostree` command run
`ostree fsck` on a dump of the bucket, which the S3 client of the port
writes to a directory. SeaweedFS keeps no tree of files of a bucket on disk,
and no writer of the port runs on `rclone serve s3`, which honors no
conditional write. The `ostree` command pulls from the S3 port of SeaweedFS
with the identity `anonymous` and the action `Read`. The read-only port of
the filer was not taken, because the S3 port serves the same reads. Under
this identity, the S3 port answers an unsigned `GET` of an absent key with
404 `NoSuchKey`, and an unsigned list with 403 `AccessDenied`. AWS answers
the same `GET` with 403 under the anonymous policy, so the tests cover the
reads of the `ostree` command after a 403 on the stand-in alone, which
answers 403 for the keys of a test. The compare of the findings of the
bucket fsck with the findings of `ostree fsck -a` runs on a dump of the
stand-in, which makes each corruption with no write through S3.

## The client access of `ostrya serve`

- The reader of the PROXY protocol, v1 and v2, is written in the tree, with
  no crate. The CIDR match of `trusted-proxy` and of a `net:` item is
  `std::net::IpAddr` and a prefix length, with no crate.
- A forwarded certificate in base64 DER is decoded by `ostrya::base64`, so
  no base64 crate is a dependency.
- The server keeps each verified forwarded certificate in a cache. One
  verification costs 23 to 52 µs of CPU, and each request from a proxy
  carries the certificate, each object `GET` included.

## The protocol versions

Protocol version 1 changed in place for the client groups, the server
commit, and the collection selectors of the ref listing. No deployment ran
version 1 when these changes came, so the version number did not change.

Version 1 also changed in place for the namespace of each ref of a push
("The namespace of each pushed ref"). `Hello` and `HelloReply` have no
`collection` key, and the name of each ref carries its namespace. Few
nodes run the receive endpoint, and the operator updates them at one time,
so the port keeps no second form of `Hello`.

## The one-way stream in the command

`ostrya send --one-way` writes a one-way stream to standard output, and
`ostrya receive --one-way` reads it into a repository. A host script
deploys commits into the repository of a new VM with these two commands,
and the host and the guest do not talk in two directions. The stream
travels in a file, in a pipe, or on a channel that gives no end of input,
for example virtio-serial or vsock.

The rules of the two commands:

- The receive needs a repository that exists. The guest script runs
  `ostrya init --mode=MODE` first. No rule applies to an empty repository.
- The receive reads standard input, or the file of `--input`. The CLI opens
  FILE with `std::fs::File::open` and reads it through
  `ostrya_rt::FileReader`, as it reads a tar file. FILE can be a regular
  file, a character device, or a FIFO, and the open of a FIFO waits for a
  writer. `-` is a file with that name. The option opens no socket: a
  vsock socket reaches standard input through a relay, for example a
  systemd socket unit with `Accept=yes`. A FILE that does not open gives
  `error: FILE: REASON` and exit 1. A directory gets no check of its own:
  the first read fails before the transaction opens.
- The receive opens the repository, then builds the keys of the trust
  group, then opens its input. A bad trust group thus ends the command
  before the open of a FIFO waits for a writer.
- The ref rules are the default rules of `StreamPolicy` and the options. A
  plain ref takes a fast-forward update. `--allow-remote=REMOTE`, which
  repeats, adds the rule `REMOTE:**`, and `--allow-remote='*'` adds `*:**`.
  `--allow-collection=ID`, which repeats, adds the rule `@ID:**`. `ID` is a
  literal collection id, as in an item of a client group ("The access items
  of each namespace"), so no value names each collection. A ref of a
  collection other than the collection id of the repository takes no
  default rule, as a remote ref takes none. The command line has no pattern
  syntax. The stream cannot carry a delete, so the receive has no
  `--allow-delete`.
- `send --one-way --disable-verify-bindings` skips the ref-binding check of
  the send, through `ExportStreamOptions`. `receive --one-way
  --disable-verify-bindings` skips the ref-binding check of the receive,
  through `StreamPolicy`. A stream from a send with the option is refused by
  a receive without it. Neither option skips the check of the collection
  binding.
- The commands make no update that is not a fast-forward. The send has no
  `--force`, and the receive has no `--allow-non-fast-forward`.
- Each update of the send expects any state of the ref. With an update that
  expects the ref absent, a second send of a ref fails with
  `ref-mismatch`, also for a fast-forward. With any state, the receiver
  applies the fast-forward check, and a send of the commit that the ref
  holds passes and changes nothing. The send has no option that expects the
  ref absent.
- The stream carries no parent commit. The history check of the receive
  stops at the first commit that neither side holds, so a send of a commit
  whose parent the guest does not hold gets `non-fast-forward`. Such a send
  is not a supported use, and the receive has no path of its own for it.
- `--trust=NAME` names a trust group of the receiving repository, through
  `TrustedKeys::from_trust_group`. Each new commit must pass its keys. A
  dependency gets no verification of its own, because field 2 of the signed
  commit holds the checksum of each dependency.
- Privileged content is refused by default, as in the library.
  `--allow-privileged` sets `StreamPolicy::allow_privileged`.
- The send takes `SRC[:DST]` refspecs with the parse and the rules of
  `ostrya push`, through `Repo::export_updates` ("The ref syntax"). A `DST`
  can be `@ID:NAME`. `--remote=REMOTE` writes each DST as `REMOTE:DST`, and
  refuses an `@ID:` `DST`, because a remote ref has no collection. The
  delete form `:DST` is refused, `:@ID:NAME` included.
- The send cannot know the collection id of the receiver. Before the first
  byte, it refuses a commit with no collection binding and a commit bound to
  `Y` on a `DST` `@X:NAME`, with `Y` other than `X`. It refuses a commit with
  no binding on each `@X:` `DST`, also when `X` is the collection id of the
  receiver. The receiver checks the collection binding of a plain `DST`, and
  of a remote ref against its own collection id. A receiver with no
  collection id does not check the collection binding of these refs.
- `send --remote=REMOTE` and `receive --allow-remote=REMOTE` check REMOTE
  with `ostrya::valid_remote_name`, the rule of `remote add`.
  `--allow-remote` also takes `*`. The option parser checks each value
  before the repository opens.
- `--one-way` conflicts with `--client` on both commands. The one-way
  commands read no client group, no server group, no key group, and no
  `LOGNAME`. The receive reads the trust group of `--trust` alone.
- `send --one-way` and each option of `send` that needs `--one-way` exist
  only in a build with the features `send` and `push` of `ostrya-cli`. The
  feature `send` does not turn on `ostrya/push`. Each of these options
  carries the same `cfg`, because a `requires` or a `conflicts_with` cannot
  name an argument that the build leaves out.
- The output follows `ostrya receive` and `ostrya send`. The send writes the
  stream alone to standard output. The receive writes nothing to standard
  output and one `warning: STEP: MESSAGE` line for each warning of the
  report. A failure writes one `error:` line and exits 1. Neither command
  writes more under `--verbose`.
- The receive has no time limit. On a channel with no end of input, it
  waits for the host and holds the shared repository lock, unless the config
  sets `[core] locking=false`. The man page tells the user to run the
  command under `timeout(1)`.
- On virtio-serial, a receive that starts before the host side of the port
  connects can see an end of input at once and fail. The man page states
  this. It is not probed.

The stop at `Commit`:

- A channel with no end of input needs `--stop-at-commit`. With it, the
  receive commits at the `Commit` frame and checks no byte after it. The
  wire format is the same with and without the option. Bytes that the buffer
  holds after the frame are discarded with no check, so the result does not
  depend on the timing of the channel.
- The reader of the CLI can read ahead of the library call. Under the smol
  backend, a pool thread of `FileReader` reads the channel after the
  `Commit` frame, and the bytes that it reads are lost to a later reader.
  The process exits when the receive ends, under each backend. So the docs
  state that the receive checks no byte after `Commit`, and do not state
  that the process reads no byte after it. The CLI puts no other buffer
  around the input: under the tokio backend, the drop of the runtime waits
  for a read in flight.
- The library gives the stop as the method
  `Repo::receive_stream_to_commit(input, policy)`, which shares the body of
  `Repo::receive_stream`. The signature of `Repo::receive_stream` and the
  fields of `StreamPolicy` do not hold the stop.

Two alternatives for the stop were rejected:

- A field of `StreamPolicy`. A public field breaks each struct literal
  of a caller with no `..Default::default()`. The fields of the policy state
  what the receiver accepts, and the stop states how the input of the
  channel ends, which the caller knows at the call. With a field, a caller
  that reads a file and a port with the same rules needs two policy values,
  and `StreamPolicy` is not `Clone`.
- A parameter of `receive_stream`. It breaks each call, and gives
  nothing that the method does not give.

## Related commits

A commit names its related commits in two fixed fields, both of type
`a(say)`. `format-reference.md`, "Related commits", states the format and
the rules.

- Field 2 of the commit object holds the dependencies: the runtime needs of
  the commit, for example the UKI, the kernel, the initrd, or a container.
  The detached metadata key `ostrya.related` holds the build sources: for
  example an intermediate layer, an artifact, or a package set. The two
  fields are fixed: no config key and no option of a call selects them.
  Thus a reader finds the related commits with no repository config, and
  the check of a write is the same in each repository.
- A dependency names no dependency. The commit write and the composefs
  rewrite refuse a nested dependency with `Error::InvalidRelated`. A
  dependency can have a parent and build sources. A UKI, a kernel, an
  initrd, or a container needs no dependency of its own. With one level,
  field 2 cannot make a cycle, and a check reads one commit and the commits
  that it names.
- The commit write of `ostrya commit` checks each dependency one time.
  `Transaction::check_related` checks the dependencies before the command
  reads the tree, and gives a `CheckedRelated` that borrows the transaction.
  `Transaction::write_commit_checked` takes it and writes the sorted entries
  with no second check. It refuses a `CheckedRelated` of another
  transaction. A process outside the transaction can make a dependency
  partial or absent after the check: an fsck, which takes no repository
  lock, or a prune in a repository with `[core] locking=false`. The write
  does not refuse such a dependency, and an fsck reports it. The same
  window is open after the write until the transaction publishes. Two
  alternatives were rejected. A public write with no check was rejected:
  each user of the library can then write a field 2 that is not sorted or
  not checked. A record of the checked lists in the transaction was
  rejected: it is state that the caller does not see.
- A local prune roots on the commits that field 2 and `ostrya.related` of
  each reached commit name. The walk treats each such commit as a root of
  its own, at the global bound of the run.
- The prune reads field 2 of each commit that it reaches, a dependency
  included. So it keeps the commits that a nested dependency names, with no
  warning. To keep too much is the safe direction.
- Build sources are recursive in the local prune: the prune reads
  `ostrya.related` of each commit that it reaches, a build source included.
  `Repo::add_detached_related` can make a cycle. The walk reads the fields of
  each commit one time, so a cycle ends the walk.
- A related entry that names a commit that the repository does not hold
  gives no error, and the walk reads nothing below it. The prune keeps the
  name of that commit, as it keeps the name of an absent parent within the
  bound. So it keeps the
  `.commitmeta` of that commit if the store holds it.
- A prune that reads a defective related value gives a warning and
  continues. The warning names the commit, the field, and the reason. The
  defective value or entry roots nothing, and the other entries of the field
  root as usual. `PruneStats::warnings` carries the warnings, and
  `ostrya prune` writes each one to standard error and exits 0. For the
  prune, a nested dependency is not defective.
- The local prune parses a `.commitmeta` only if its bytes hold the key
  `ostrya.related` and its terminating NUL. In a serialized `a{sv}` dict, the
  key of each entry is a NUL-terminated string at contiguous bytes. So a file
  without these bytes has no build sources. The prune parses no such file, so
  such a file that does not parse gives no error. A file that holds these
  bytes gets the full parse. If it does not parse, it fails the prune before
  the prune deletes an object. These bytes in a value of another entry only
  cause the full parse. Three alternatives were rejected. A full parse of
  each `.commitmeta` was rejected. With it, the prune decodes the signature
  dict of each signed commit, and one defective file with no build sources
  stops each prune. A lookup of the one key with no parse of the other
  values was rejected. It accepts a file whose other values do not parse.
  Its errors also differ from the errors of the other readers of detached
  metadata. A warning for a file that holds the key and does not parse was
  rejected. With the warning, the prune continues and deletes build sources
  that nobody can read.
- The bucket prune roots on field 2 alone. It reads field 2 from the bytes
  of each commit object that it reads, so the field gives no extra request.
  It reads no `.commitmeta`, so a build source in a bucket repository stays
  only if a ref or another root keeps it. The bucket prune gives the warning
  of a defective field 2 entry in `BucketPruneReport`, and
  `ostrya remote prune` writes each one to standard error. A bucket prune
  that also reads the `.commitmeta` of each commit that it reaches was
  rejected: it sends one more `GET` for each such commit.
- A pull from a remote and a local pull follow the dependencies of each commit
  that they read, the parents that their depth takes included. Field 2 is in
  the signed commit, so the pull is complete with no option. Field 2 also
  binds each dependency to its checksum in a commit that the signature policy
  covers, so the pull checks no signature of a dependency. A dependency that
  is also a target, a parent that the depth takes, or a commit of a chain of
  static deltas gets the check of that role. The pull requests and copies no
  `.commitmeta` of a dependency that the repository holds complete. The pull
  takes each dependency at depth 0, with no parent: a dependency is a runtime
  need of the commit, and its history is not. A prune of the destination
  accepts the missing parents, as after a pull with a small depth. A
  dependency gets no ref. A commit-only pull and a pull with subpaths take no
  dependency. A dependency that neither the repository, a localcache
  repository, nor the remote (the source of a local pull) holds fails the
  pull, and the pull moves no ref. A local pull finds each such failure before
  its transaction opens. Two alternatives were rejected. A pull that follows
  each dependency at the depth of the pull was rejected: it takes the history
  of each dependency, which no commit needs. A pull that checks the signatures
  of each dependency was rejected: field 2 is in the signed commit, so the
  dependency is bound by its checksum, and a signature on the dependency adds
  no trust.
- A pull looks for a static delta of each dependency of its own. After the
  pull reads the commits that name the dependencies, it looks for a delta of
  each dependency that it does not hold complete. The `from` is the entry of
  the same name in field 2 of the commit that the local ref of a target names
  before the pull, the paired entry, so an update of a dependency goes from
  the dependency that the client runs. The pull takes the first paired entry
  that it holds complete, in the order of the targets, and takes the
  from-scratch delta only if it holds no paired entry complete. The
  requirement of static deltas applies to each dependency. With a list of
  static deltas, the pull takes one entry of the list to the dependency. The
  search checks no signature of the superblock: the parse compares the
  checksum of the commit that the superblock carries with the checksum in
  field 2. Two alternatives were rejected. A change to the delta format, so
  that the delta of a target also carries its dependencies, was rejected: the
  tool writes and reads the format, and a delta of each dependency keeps it.
  A search that verifies the superblock of the delta of a dependency under
  the policy of the pull was rejected: the superblock gives the dependency
  commit, and field 2 of the signed commit names that commit by its
  checksum, so a signature on the superblock adds no trust.
- A pull from a remote requests the superblock of the delta of each
  dependency one time. The search writes each superblock to one temp file
  after the digest check, and the commit that it carries after the parse. A
  failed check fails the pull, so the file holds checked bytes. The pull
  keeps on the heap the fallbacks, the number of parts, and the ranges in the
  file of each delta. The step of the commit reads the commit from the file
  and takes the fallbacks. Just before the parts of a delta, a load step
  parses the superblock again from the file, and the run drops the parse
  after the last part. The application of the parts loads the jobs of at most
  two dependencies at a time, the cap of the part fetches. The file has the
  limit of the record file of a chain, 1 GiB, and a pull whose superblocks
  and commits of dependencies pass it fails. After a search fails, the pull
  starts no further search. Three alternatives were rejected. To request the
  superblock again at the start of its parts was rejected: it doubles the
  transfer of each superblock, and with no summary no digest checks that the
  second copy is the checked copy. A failure then also comes late in the
  transaction. To keep each parsed delta until the run ends was rejected:
  field 2 of the commits that the remote serves sets the number of
  dependencies, which has no cap, so the heap cost of the parsed deltas then
  has no limit. To keep the commit of each delta on the heap until the step
  of the commit was rejected for the same reason: the steps of the commits
  come after the search, so the heap then holds the commits of all the
  dependencies.
- A push (`Repo::push`, `Repo::push_over_stream`, and `Repo::push_to_bucket`)
  sends the dependencies of each commit that it offers, at depth 0 and with
  no ref. It refuses an absent or a partial dependency, a defective field 2
  entry, and a nested dependency before the first upload. With a depth, the
  push resolves each dependency before it writes a byte. With no depth, the
  history of the offer ends at the server tip, which the push knows only
  after `HelloReply`, or under the writer lock of a bucket. So the push
  resolves the dependencies of the source commits first, and the
  dependencies of the offered history commits after the cut. It checks the
  format of field 2 of each commit of its walk, from the bytes that it
  already read. Two alternatives were rejected. To leave each check to the
  receiver was rejected: a push to a bucket repository has no receiver, and
  the client can refuse before it sends an object. To resolve the
  dependencies of the whole local history with no depth was rejected: the
  push reads the commit objects of dependencies that it does not send, and
  a dependency of old history that the server holds, which the local
  repository no longer holds, refuses the push. The one-way export
  (`Repo::export_stream`) sends the dependencies of each new commit by the
  same rules. It does no negotiation, so it sends a dependency that the
  receiver holds, and it finds each refusal before it writes the first byte.
  A receiver that holds a dependency with a partial-commit marker refuses
  the stream, also though the stream carries the whole tree of the
  dependency. The sender completes such a dependency with an update that
  takes it as a new commit.
- The receiver of a push session and of a one-way stream checks the
  dependencies of each commit that it stages, the staged parents of a new
  commit included. It also checks a new commit that it holds with a
  partial-commit marker, because the session completes the tree of that
  commit and removes its marker. For the same reason, a dependency that is a
  new commit counts as complete. Each other dependency must be staged or
  held complete, and no dependency can have dependencies of its own. The
  receiver checks no signature of a dependency and adds no server signature
  to it. A dependency that is also a new commit gets the check and the
  signatures of its own updates alone. The checksum of a dependency is in
  field 2 of a commit of the session. A new commit is that commit, or binds
  it through the parent checksums of its history, and the signature rules
  cover the new commit. The receiver checks that the bytes of each object
  hash to the checksum that names it. A dependency that only a staged commit
  outside each history names is bound to no new commit, and no ref update of
  the session reaches it. A staged parent gets no check and no signature,
  also when a field 2 names it. The receiver merges the incoming dict of a staged dependency into the
  stored dict, as for each other staged commit. A later pull can take the
  dependency as a target, and that pull needs the signatures. So under
  `verify`, a client can store a dict with signatures that no key trusts on
  a staged dependency. The server drops a detached metadata dict for a
  commit that it holds, that the session did not stage, and that no update
  names, if field 2 of a commit of the session names that commit. The
  server writes and merges nothing from the dict. The one-way export sends
  such a dict, because it does no negotiation. A refusal of the dict was
  rejected: it refuses each second export of a dependency with a
  `.commitmeta` to one receiver. A merge of the dict was rejected: the
  server held the dependency and its dict before the session, and no rule
  of the session covers a change to them. A dict for each other commit that
  the session did not stage and that no update names stays `protocol`. A
  `Commit` message that lists the dependencies of the push was rejected.
  The dependencies are in the signed commits, so a list in the message adds
  a second source that can disagree with them. A receiver that checks the
  signatures of a staged dependency and signs it, under the rules of the
  updates that name it, was rejected: a new commit binds each dependency of
  its history by its checksum, so a signature on the dependency adds no
  trust.
- The fsck (`Repo::fsck` and `ostrya fsck`) reports each dependency of a
  commit that it checks that is absent, partial, or defective, in
  `FsckReport::dependency_errors`. A nested dependency is defective. The run
  reads field 2 from the read of its object walk, and classifies each entry
  against the state after its own findings: a dependency that the run
  deletes is absent, and a dependency whose tree the run finds incomplete is
  partial. Under `mark_partial` and `mark_dependencies`, the run marks the
  commit of an absent or a partial dependency as partial, so a later pull
  fetches the commit again with its dependencies. A pull cannot repair a
  defective entry, so it gets no marker. `mark_dependencies` is a separate
  switch, because a caller can accept a commit whose dependencies are
  absent and still need the marks of absent objects. A pull walks the tree
  of a commit only when the commit is marked partial. One enum in place of
  `mark_partial` was rejected: it removes the field `mark_partial`, so it
  breaks each caller that sets the field, also a caller that starts from
  `..FsckOptions::new()`. The field `mark_dependencies` breaks only a caller
  that builds the struct with a full literal. Public marker functions were
  rejected: the marks are on disk before `Repo::fsck` returns, so a caller
  cannot filter the findings first. The marks of this check do not change
  the other findings of the run. The bucket fsck gives the same findings as
  `dependency` findings, reads a dependency as partial if the bucket holds
  its partial-commit marker, and writes no key for them in a repair. A run
  with the repair classifies each entry against the markers and the commit
  objects after the repair, as the local run does, so its findings describe
  the bucket that the run leaves. A run with no lock reads
  each absent dependency again, as it reads a missing object again. The
  tool reports no finding for field 2 and exits 0, so the exit status of
  `ostrya fsck` over such a repository is a divergence. To pass a commit
  whose dependency is absent was rejected: the commit is not complete, and
  each other operation of the port refuses it. To mark the commit of a
  defective entry was rejected: a pull of the commit gives the same entry.
- No transfer follows a build source. A pull, a push, and the one-way stream
  move `ostrya.related` as any other detached metadata key, under the switch
  of the destination, and fetch no commit that it names. A build cache needs the refs of its sources, and not
  only the commits. A distributed build cache mirrors the refs of its build
  sources with the existing pull and push.
- `[ex-ostrya] keep-detached-related=false` makes each transfer into the
  repository drop `ostrya.related`: a pull, a pull-local, a receive, and a
  push to a bucket. The repository that stores the dict reads its own
  switch, and a push to a bucket reads the `config` of the bucket. A
  distribution repository sets `false`, so the build sources of a builder
  do not go to the clients. A local write ignores the switch: a commit
  write and the add API always store the key, because the owner of the
  repository writes the value. A pull, also a pull-local and a pull through
  a static delta, and a push to a bucket replace the whole stored
  `.commitmeta` with the dict that the switch leaves, so a stored value
  stays only if that dict is empty. A receive merges the incoming dict into
  the stored dict, so a stored value stays. An option of the sender was
  rejected: the rule belongs to the repository that stores the dict, and a
  sender that does not set the option stores the key against the rule of the
  destination.
- The switch is the one rule that drops a detached metadata key in a
  transfer. `[ex-ostrya] detached-metadata-exclude`, a list of keys to
  drop, was removed with no alias and no refusal. The config reader ignores
  an unknown key, so a config that sets it gets no filter and no message.
  `DetachedMetadataFilter` and each option field that took it were removed
  too: `PullOptions`, `RepoPushOptions`, `ExportStreamOptions`,
  `ReceivePolicy`, and `StreamPolicy` carry no filter. The one key that a
  distribution repository must not keep is `ostrya.related`, and the
  destination reads its own switch, so the sender needs no option. A list
  of keys to drop lets a fault span two configs: if an upstream drops a key
  and a downstream roots on that key, the downstream prune deletes the
  commits that the key kept, and no call reports it.
- A config key that names more metadata keys with commit checksums was
  rejected. A reader then needs the repository config to find the related
  commits, and one dict is valid in one repository and not valid in
  another. If an upstream drops a key from the detached metadata and a
  downstream roots on that key, the downstream prune deletes the commits
  that the key kept, and no call reports it.

## The weak refs of a prune

`PruneOptions::weak_ref_filter` holds one callback for the refs of each
space. The callback gets a `Ref` and the commit of the ref, and returns
`true` for a strong ref:

- `Ref::Local` for a ref under `refs/heads`, with its name.
- `Ref::Remote` for a ref under `refs/remotes`, with the remote and the
  name.
- `Ref::Collection` for a ref under `refs/mirrors`, with the collection id
  and the name. The id is never the `[core] collection-id` of the
  repository, so each `Ref` that the callback gets is canonical ("The ref
  syntax").

The rules of the classification:

- A local ref or a remote ref gets a `Ref` when its listed name maps back
  to the file that the listing read. A mirror ref gets a `Ref` when the
  part of its path before the first `/` passes `is_collection_id` and is at
  most 255 bytes, and the rest passes the ref-name rule. Each other ref is
  strong and never reaches the callback. The classification reads no file:
  the ref listing of the run already reads `refs/mirrors`.
- A ref under `refs/mirrors/ID/` of the `[core] collection-id` of the
  repository is a strong ref with no name. The classification reads the
  own id from the config that the handle read at the open. The ref roots
  the walk, never reaches the callback, and takes the bound of a ref that
  no list names: the global bound, or no bound under a non-empty
  `only_branch`. No value of `only_branch` or `retain_branch_depth`
  selects it, and the run never deletes it. "The own collection id" states
  the rule.
- `only_branch` and `retain_branch_depth` hold `Ref` values. The run maps
  a value `@OWN:NAME` of the own id to the local ref `NAME`, and selects a
  ref by a value equal to its `Ref`. A ref that gets no `Ref` takes the
  bound of a ref that no list names. Each run, the `static_deltas_only`
  run too, reads each `only_branch` value from the ref store with
  `Repo::resolve_ref_tip` before it takes the lock. The run does not read a
  value as a full checksum, as an abbreviated checksum, or with a `^`
  suffix. A value that no ref has as its name, for example a checksum,
  fails the prune with `Error::RefNotFound`. A value that fails the
  ref-name rule, for example `main^`, fails the prune with
  `Error::InvalidRefspec`. After a refusal the run removes nothing. A ref
  that the ref listing does not give, for example through a symlink that
  the port does not write, selects nothing.
- A weak collection ref follows the rule of each weak ref. It survives when
  the walk reaches its commit over a `parent` edge, a dependency in field 2,
  or a build source in `ostrya.related`. A strong ref on the same commit
  keeps it too.
- `PruneStats::deleted_refs` names each deleted weak ref as a `Ref`. It is
  sorted with `sort`, by the derived order of `Ref`: the local refs first,
  the remote refs next, and the collection refs last, each by its parts in
  byte order. Under `no_prune`, the list names what a run deletes, and the
  run deletes nothing.
- One helper deletes the weak refs of each space.
  `delete_matching_refs_blocking` takes a key and a closure that gives the
  path of each key. One blocking hop and one set of `fsync` calls cover the
  refs under `refs/heads`, `refs/remotes`, and `refs/mirrors`, with one
  compare-and-delete guard.
- An emptied `refs/mirrors/ID/` directory stays, as an emptied directory
  under `refs/heads` does.
- The `ostrya` command builds the filter from the key
  `[ex-ostrya] gc-weak-references`, which `RepoConfig::gc_weak_references`
  reads as a `ReceiveSelector`. The filter marks each ref that the selector
  selects weak, with the `[core] collection-id` of the repository as the own
  id. `Repo::prune` reads no config key for the filter, so a library caller
  keeps full control of it. `ostrya prune` applies the key when the roots are
  the refs alone: `--refs-only`, `--only-branch`, `--retain-branch-depth`, or
  `--keep-younger-than`. In these runs it also sets `refs_only`, which
  changes no root. Each run reads and checks the key, so a bad value refuses
  each prune before it deletes anything. `RepoConfig::gc_weak_references`
  refuses a value with no pattern without `!`, so an empty value and a list
  of exclusions alone are bad values. `ostrya remote prune` does not read
  the key, because the prune of a bucket refuses a weak ref filter.
- `PruneOptions` and `PruneStats` have no `#[non_exhaustive]`. With the
  attribute, no other crate can use `..PruneOptions::default()`, and the
  `ostrya` command uses it. A new field in either struct takes a minor
  version before 1.0.

These alternatives were rejected:

- A flat string with a prefix for each space, for example `mirrors:ID/NAME`.
  Each callback must parse the string again to find the space, the id, and
  the name. A substring test still matches refs of more than one space. A
  remote ref `REMOTE:NAME` in such a string carries two `:` separators.
- A second filter field for the collection refs. A caller that applies one
  rule to each space then writes the rule two times. The `Ref` gives the
  same split in one callback.
- A location type of the prune alone. The API then has two types for one
  ref, and a caller converts between them. Each public API that names one
  ref takes a `Ref` ("The ref syntax").
- A mirror ref of the own collection id as a `Local` ref. `Ref::Local`
  names `refs/heads/NAME`, and the mirror ref is a different file. Both
  files can exist and name two commits, so the callback gets one `Ref` for
  two refs.
- A mirror ref of the own collection id as a weak `Collection` ref. The
  readers of the port ignore such a ref, so a caller has no use for it, and
  a filter that marks each ref weak then deletes a ref that the port did
  not write. A strong ref keeps the commit, and the operator removes the
  ref by hand.
- A list of refspecs for the local and the remote refs, and a second list
  for the collection refs. No refspec maps below `refs/mirrors`, and the
  form `ID:NAME` reads as the refspec of a remote named `ID`. One list of
  `Ref` values names the refs of each space.
- A selection by the listed name of a ref, with the path `ID/NAME` for a
  mirror ref. The name `ID/NAME` is also a valid local ref name, so one
  value selects two refs.
- A read of `[ex-ostrya] gc-weak-references` in `Repo::prune`. A library
  caller then cannot give a filter of its own that the key does not
  change.
- An empty value or a list of exclusions alone that selects each ref that
  no exclusion matches, as `pull-branches` and `push-branches` read it. An
  empty value then marks weak each ref that gets a `Ref`. Only the mirror
  refs of the own collection and the refs that get no `Ref` stay strong.
  `prune --refs-only` then deletes each weak ref whose commit the walk does
  not reach, and each object that no root reaches.
- The key in a plain `ostrya prune`, with `refs_only` set. Each commit in
  the store then stops being a root, so the key changes which objects a
  plain prune keeps.
- A resolve of each `only_branch` value as a revision, as
  `Repo::resolve_rev` does. A hex branch name, for example `cafe`, then
  goes to the abbreviated-checksum lookup first. If two commits start with
  `cafe`, the prune fails with `Error::AmbiguousRefspec`, and the ref
  `cafe` is never read. A value that resolves only as a revision, for
  example `main^` or a checksum, selects no branch, so the run accepts a
  value that has no effect.

## The unbound collection pull

`CollectionPullOptions::allow_unbound` is one `bool` switch of
`Repo::pull_collection`. The default is `false`. The rules:

- With `true`, a tip passes the collection-binding check when the commit
  metadata has no `ostree.collection-binding` key. The switch applies to this
  case alone.
- A tip whose binding names another collection fails with either value. A
  tip whose binding value is not a string fails with either value.
- The switch does not change the ref binding check, the check of the listed
  timestamp, or the timestamp check. A tip with no binding of either kind
  passes. A tip whose ref binding does not hold the ref fails.
- `Repo::pull_collection` refuses `PullFlags::DISABLE_VERIFY_BINDINGS` with
  either value.
- The `ostrya` command does not set the switch.

The switch is for content-addressed refs that carry no binding. A binding in
the commit object gives one content a different commit for each collection
id. Without a binding, one commit serves each collection that names the
content.

These alternatives were rejected:

- A collection pull that takes `PullFlags::DISABLE_VERIFY_BINDINGS`. The flag
  also turns off the ref binding check, and the collection pull keeps that
  check.
- A check of the content of the commit against the name of its ref, in
  addition to the ref binding check. The pull has no rule that maps a name to
  content. The caller checks the content after the pull.
- A binding value that is not a string, read as an absent key. A malformed
  binding is a binding. The presence test of the ref binding check refuses a
  value of the same shape.

## The local candidate of a collection pull

`Repo::pull_collection` takes a remote whose `pull-url`, or else `url`, is a
`file://` address as a local candidate. The rules:

- The address is `file://` followed by an absolute path, taken as written.
  A host part (`localhost` too), an empty path, and `%`, `?`, or `#` in the
  path are config errors, which stop the pull before its first request.
- The probe opens the repository at the path, and reads the refs of the
  collection with the rule of `Repo::list_collection_refs_in`. The timestamp
  of each ref is the timestamp of the commit that the probe pins. Under a
  summary policy, the probe reads the refs and their timestamps from the
  verified summary of the source, as over HTTP.
- `Repo::list_collection_refs_in` reads under one `ReadAccess`: an
  anonymous client under the implicit client groups of the collection id of
  the repository. Each repository handle builds this access one time, at its
  first use, and the clones of the handle share it. The summary write and
  the S3 push read under the same value of the handle. The access gives the
  rule of the target of an alias: a target under `refs/remotes/`, or under a
  directory of `refs/mirrors/` whose name fails the collection-id rule, gives
  no ref. It also gives the rule of the collection id of the repository and
  the shape of the walk.
- The pull from the candidate is the local pull of `Repo::pull_local`, at the
  commits of the probe, with the trust of the remote, the binding rules of
  the collection pull, and the timestamp check of the options. It reads each
  tip commit from the source, and checks it against the listed timestamp of
  the probe, as over HTTP. Under a summary policy, it reads the `summary` and
  the `summary.sig` of the source again, and checks them under the trust of
  the remote. It does not compare the refs of that summary with the commits
  of the probe: the pull hashes each commit that it reads against its name.
- The probe keeps no commit bytes and no summary for the pull. Without a
  summary policy, it reads each tip commit for its timestamp, and drops the
  bytes before it reads the next commit. A commit is named by its hash. In a
  source that does not change, a second read of a tip gives the same bytes.
  The check of the listed timestamp finds a tip commit whose timestamp
  changed between the probe and the pull. Under `PullFlags::UNTRUSTED`, the
  pull hashes the read of each tip commit before the checks, and a tip
  commit that does not hash to its name fails the pull with
  `Error::ChecksumMismatch` before the check of the listed timestamp. The
  second read of each tip commit without a summary policy, and of the
  summary under a summary policy, is the cost of this design.
- The client groups of the source do not apply. The file permissions are
  the access.
- Each error of the open and of the probe skips the candidate.
- The probe of each candidate, local or remote, skips a listed ref whose
  name fails the ref-name rule, for example `refs/heads/origin:main` under
  the collection id of the source. The other refs of the candidate stay in
  the selection. The probe reads no timestamp and no commit of a skipped
  ref. `CollectionPullEvent::RefSkipped` reports each skipped ref, to
  `CollectionPullOptions::on_event` of the pull and to the event callback of
  `Repo::remote_list_collection_refs_with`. `ostrya pull --collection`
  prints it as a warning.
- `Repo::remote_list_collection_refs_with` lists the refs of one remote
  through the same probe as the pull, and drops the timestamps. So without
  a summary policy, the listing of a local candidate reads each tip commit
  for its timestamp. A tip commit that the source does not hold then fails
  the listing. `Repo::build_ref_listing`, the listing of `ostrya serve` and
  `ostrya send`, fails the same way.
- A caller field of another transport, and a subpath, are refused before the
  first request.
- Each other pull from a remote, and the fetch of a summary, keep the
  refusal of a `file://` address by the HTTP client.
- If the trust of the remote checks the signatures of the commits or of the
  summary, the pull from the candidate runs as under
  `PullFlags::UNTRUSTED`. It hashes each commit that it reads for the checks
  and each dirtree that it reads for the walk of the tree before it uses the
  bytes, and it hashes each object that it imports. A signature covers the
  commit, or the summary the checksum of the commit. The commit names its
  root dirtree, and each dirtree names the objects below it, so the hashes
  bind each imported object to the verified commit. Otherwise the flags of
  the caller apply.
- `CollectionPullStats::local` holds the counts of the pulls from local
  candidates, and `CollectionPullStats::stats` the counts of all pulls. When
  the pull fetched objects, and the local candidates imported objects and
  fetched nothing, `ostrya pull --collection` prints two lines: the
  statistics line of a fetch, and then the statistics line of `pull-local`
  with the counts of the local candidates. The content written of the first
  line excludes the part of the local candidates, so the two figures add up
  to the total. Each line has a form that the tool prints, and the import
  counts of the local candidates stay in the output. A local candidate that
  reads static deltas counts as a fetch, so its counts stay in the one line
  of a fetch.

The local pull already reads a source repository through the file system,
with hardlinks where the file systems permit them. So the collection pull
sends a local candidate there, and the HTTP client stays a client of `http`
and `https` alone.

These alternatives were rejected:

- A `file://` scheme in the HTTP client, for each pull. It is a second reader
  of a local repository, apart from the local pull, with the request and
  retry rules of a fetch that do not apply to a file.
- A decode of `%` escapes and a host of `localhost`, as RFC 8089 permits.
  The port does not link a URL parser in `ostrya`, and a parser written for
  this one form carries its own edge cases. A path as written, with a
  refusal of each other form, has no such edge case.
- The client groups of the source as the access of a local candidate. The
  groups govern `ostrya serve` and `ostrya send`. A process that reads the
  files of the source reads them with or without the groups.
- A second read of the ref files of the source at the pull. The probe pins
  a commit for each ref, so the selection and the pull agree. Without a
  summary policy, the probe reads each timestamp from the commit that it
  pins. Under a summary policy, the timestamps come from the verified
  summary, and the pull checks each commit against them.
- The flags of the caller alone for a candidate whose remote checks
  signatures. A signature proves the commit, and nothing proves the objects
  of its tree. A source on removable media can keep a signed commit and
  replace the bytes of an object under its name, and the pull then imports
  that object.
- A hash of each object of each local candidate. A builder on the same host
  that checks no signature then reads each object one more time. The link
  still saves the write and the disk space. The read removes most of the
  time that the link saves.
- A second read of each tip commit at the pull, without the check of the
  listed timestamp. The pull then can take a commit whose timestamp is not
  the timestamp of the selection.
- Kept bytes of each tip commit, from the probe to the pull, with a cap for
  each candidate. The kept bytes of all candidates stay in memory until the
  selection ends, so the peak grows with the number of candidates. The pull
  then needs rules of its own for a kept tip: no check of the listed
  timestamp, and a hash of the kept bytes before the hash of the import.
- The summary of the probe for the pull of a local candidate. It is a rule
  of the local pull alone, and a read of a local file is cheap. A remote
  candidate keeps the summary of its probe, because a second request costs a
  round trip.
- One statistics line of a fetch with the sums, when the pull fetched
  objects and also imported objects from a local candidate. The line of a
  fetch has no import counts, so the output then drops the counts of the
  local candidates.
- One statistics line for each selected candidate. The tool never prints
  this form.
- The import counts inside the statistics line of a fetch. The tool never
  prints this form.
- A listing with no access: the crate-internal `select_refs` with an
  `Option<&ReadAccess>`, and `None` from `Repo::list_collection_refs_in`.
  The rule of the target of an alias, the rule of the collection id of the
  repository, and the shape of the walk are in the read access. A path with
  no access needs a copy of these rules.
- A listing of one remote that reads no tip commit and gives each ref with
  its listed commit. A missing tip commit does not fail such a listing.
  The pull and the listing then need two probes with different rules. The
  listing of `ostrya serve` reads each commit, and a missing commit fails
  the whole listing too.
- A skip of a ref whose name fails the ref-name rule with no event, as the
  `-c` listing of the `ostree` command does. The user then gets no sign that
  a ref of the source is not in the pull.
- The refusal of the whole candidate for one listed name that fails the
  ref-name rule. One ref file that the user cannot pull then hides each
  other ref of the candidate.

## The ref syntax

A ref has three text forms. A revision adds zero or more `^` to each form.

- `NAME` is the local ref `refs/heads/NAME`.
- `REMOTE:NAME` is the remote ref `refs/remotes/REMOTE/NAME`.
- `@ID:NAME` is the collection ref `refs/mirrors/ID/NAME`, or
  `refs/heads/NAME` when `ID` is the own collection id ("The own
  collection id").

`@OWN:NAME` and `NAME` name the same ref. The ref-name rule refuses `@`, so
the third form gives a new meaning to no refspec. Error text names a
collection ref as `@ID:NAME`. `refs -c --create=ID:REF` and the listing
form `(ID, REF)` of `refs -c` keep the meaning of the `ostree` command.

The library has one typed ref, `ostrya_core::Ref`, with the cases `Local`,
`Remote`, and `Collection`. The rules:

- The constructors do not check the value. `Ref::validate` checks it, and
  the ref store checks it before it reads or writes a file. `FromStr` reads
  the three forms and checks the result. `Display` gives the same text
  back. A failure is `ParseRefError`, which holds the text. The `ostrya`
  crate maps it to `Error::InvalidRefspec` with the same text.
- The ref store has one method for each operation, and it takes `&Ref`:
  `Transaction::set_ref`, `Transaction::set_ref_expecting`,
  `Repo::set_ref_immediate`, `UpdateGuard::read_ref`,
  `UpdateGuard::set_ref`, and `Repo::resolve_ref_tip`. `resolve_ref_tip`
  gives `None` for an absent ref. A ref path that names a directory, or
  that passes through a file, holds no ref, so it also gives `None`. A
  caller that needs an error gives `Error::RefNotFound` with the text of
  the ref. `Repo::resolve_rev` reads a revision, and it fails with
  `Error::Io` for such a path.
- A value from a caller can be `@OWN:NAME`, and the ref store maps it to
  the local ref. A value that the library gives is canonical: a ref of the
  own id is `Local`.
- An operand that can hold a revision stays text: `Repo::resolve_rev`,
  `PullOptions::refs`, and the refspecs of a push. `resolve_rev` reads
  `@ID:NAME[^...]`.
- `Repo::pull_local` reads each name of `PullOptions::refs` as a revision
  of the source, `@ID:NAME[^...]` included. It refuses a name that starts
  with `@` and, less each `^` at its end, is not an `@ID:NAME` ref, before
  it reads the source. It writes the ref of an `@ID:NAME` name as the
  collection ref of `ID` by the rule of the own id, and the ref of each
  other name at the place that `PullOptions::remote` names. Without
  `no_ref_writes`, the tip commit of each `@ID:NAME` name must hold the
  `ostree.collection-binding` `ID`, also when `ID` is the own id of the
  destination, and `DISABLE_VERIFY_BINDINGS` does not skip the check. The
  ref-binding check reads the part after `@ID:`. Delta discovery reads the
  `from` commit at the ref that the name gives in the destination, with
  and without `no_ref_writes`. `PullOptions` has no collection id field.
- `Repo::pull` and `Repo::pull_with_session` read each name of
  `PullOptions::refs` as `NAME` or `@ID:NAME`, and refuse each other form
  before the first request ("The collection refs of a named remote").
- Each name field of the push protocol holds the text of a ref: `NAME` or
  `@ID:NAME`, and in a one-way stream also `REMOTE:NAME`. The receive path
  reads each name with the parser of `Ref` ("The namespace of each pushed
  ref").
- A push refspec is `SRC[:DST]`. `SRC` is a revision, and `DST` is the last
  ref of the refspec. The parser splits the refspec at each `:` into fields.
  If the field before the last field starts with `@`, the last ref is
  `@ID:NAME`, which is two fields. Else the last ref is the last field. If
  the last ref is the whole refspec, the refspec has a `SRC` alone, and the
  `DST` is the text of `SRC`. Else `SRC` is the text before the `:` that
  comes before the last ref, and an empty `SRC` is a delete. No part of a
  ref other than a collection id starts with `@`, so the rule never guesses.
  A refspec with no `@` gives the parts of a split at the last `:`.
  Examples:
  - `main`: `SRC` `main`, `DST` `main`;
  - `origin:main`: `SRC` `origin`, `DST` `main`;
  - `R:main:dst`: `SRC` `R:main`, `DST` `dst`;
  - `@X:a`: `SRC` `@X:a`, `DST` `@X:a`;
  - `main:@X:a`: `SRC` `main`, `DST` `@X:a`;
  - `R:main:@X:a`: `SRC` `R:main`, `DST` `@X:a`;
  - `@X:a:b`: `SRC` `@X:a`, `DST` `b`;
  - `@X:a:@Y:b`: `SRC` `@X:a`, `DST` `@Y:b`;
  - `@X:main^:b`: `SRC` `@X:main^`, `DST` `b`;
  - `:@X:a`: a delete of `@X:a`;
  - `a:@X`: `SRC` `a`, `DST` `@X`, which the ref-name rule refuses.
- One parser splits each refspec: `Repo::push`, `Repo::export_updates`, and
  the push to a bucket. The delete check of `export_updates` and of the push
  to a bucket calls it, so each finds the delete `:@X:a`.
  `export_updates` with a `remote` refuses an `@ID:` `DST`, because a remote
  ref has no collection.
- `RepoPushOptions::tags`, `TreePushOptions::onto` and `tags`, and
  `PushOntoOptions::onto` and `tags` take `Ref` values. A push refuses a
  `Remote` value. `bind_refs` of `TreePushOptions` and of `PushOntoOptions`
  stays text, because `ostree.ref-binding` holds names alone.
- `PruneOptions::only_branch` and `retain_branch_depth` take `Ref` values,
  and `PruneStats::deleted_refs` gives them ("The weak refs of a prune").
- The CLI reads `@ID:NAME` in each ref operand of `commit`, `refs`,
  `prune`, `pull-local`, `push`, `push-tree`, and `send --one-way`.
  `commit -b` and `--tag` take `@ID:NAME`. The
  refs of one commit are in one namespace after the own-id mapping: the
  local refs, with a `REMOTE:NAME` branch, or the refs of one collection.
  The command refuses refs of two namespaces before the repository lock.
  `ostree.collection-binding` holds the id of the namespace, or the own id
  for the local namespace, and `ostree.ref-binding` holds the name part of
  each `@ID:NAME` value. A `--tag` that is a remote ref is refused.
- `refs --create` and `refs --delete` take `@ID:NAME` without `-c`. A
  `PREFIX` `@X:` matches each ref of X, as `REMOTE:` matches each ref of a
  remote, and `@X:PREFIX` matches by the rule of a plain `PREFIX`. A
  listing prints each such ref as `@X:NAME`. `@OWN:PREFIX` is `PREFIX` if
  `PREFIX` is a local ref name, and `@OWN:` matches each local ref. The
  command refuses each other `@OWN:REST`, for example `@OWN:origin:main`,
  as the refspec rule refuses `@X:origin:main`. `-A` refuses a collection
  ref of another id as `NEWREF`, as the target of an alias, and as a
  `PREFIX`. `refs --delete` refuses `@X:` and `@OWN:` with an empty rest
  if the prefix matches a ref, as it refuses a whole-remote `PREFIX`.
- `prune --only-branch` and `--retain-branch-depth` take `@ID:NAME`. The
  command passes each value as a `Ref`, and `Repo::prune` reads each
  `only_branch` value from the ref store before it takes the lock. A value
  that no ref has as its name, for example a checksum, fails the command,
  the `--static-deltas-only` run too. A value that is not a ref, for
  example `main^`, becomes the local ref of the text. `--only-branch`
  refuses such a value with `Error::InvalidRefspec`. For
  `--retain-branch-depth`, such a value selects nothing.

These alternatives were rejected:

- A typed value for each operand. `PullOptions::refs` as `Vec<Ref>` loses
  the checksum and the `^` pins of a local pull, so it needs a second
  field. A typed push refspec moves the parser of the refspec into each
  caller.
- A typed value only for a collection ref, beside a refspec `&str` for a
  local or a remote ref. The API then has two names for one ref, for
  example a refspec setter for `main` and a collection ref setter for the
  local ref `main`.
- Text for the tags of a push and the branch of a server commit, for one
  form with `RepoPushOptions::refspecs`. A tag and a branch hold no
  revision, and the typed value gives the same text on the wire.

## The own collection id

The `[core] collection-id` of a repository is its local namespace. The
refs of that id are the local refs, under `refs/heads/`. The rules:

- Each writer of the collection ref `@ID:NAME` of the own id writes
  `refs/heads/NAME`: `Transaction::set_ref`,
  `Transaction::set_ref_expecting`, `Repo::set_ref_immediate`,
  `UpdateGuard::set_ref`, `refs -c --create`, `refs --create`, `commit`,
  `Repo::pull_collection`, `Repo::pull_local` and `Repo::pull` with an
  `@ID:NAME` name, the receive path, and the S3 push. The same
  writers remove `refs/heads/NAME` for a removal, and so does
  `Repo::remove_refs_immediate`. No writer creates
  `refs/mirrors/ID/` of the own id. `ostree refs --collections
  --create=ID:NAME` writes `refs/heads/NAME` for the own id too (observed).
- The readers ignore `refs/mirrors/ID/` of the own id:
  `Repo::resolve_ref_tip`, `Repo::resolve_rev`, `UpdateGuard::read_ref`,
  `Repo::list_collection_refs`, `Repo::list_collection_refs_in`, the ref
  listing, the summary, and the archive view: `ReadAccess::can_read_path`
  refuses each path under that directory. Delta discovery, the search for
  the delta of a dependency, and `TimestampCheck::CurrentRef` read
  `refs/heads/NAME`.
  `Repo::list_mirror_refs` lists the directory, and the fsck and the
  prune read it.
- The collection ref listing, `Repo::list_collection_refs` and `refs -c`,
  lists no ref of a remote whose `collection-id` is the own id. The rows of
  the own id come from `refs/heads/` alone. So `refs -c --delete OWN` does
  not map a ref of a remote to a local ref of the same name. The `-c`
  listing of the `ostree` command lists the refs of such a remote under the
  own id (observed). This is a divergence, recorded in
  `docs/conformance/cli-surface.md`.
- `Repo::pull_local` reads each `@ID:NAME` name of the source with the
  rule of `Repo::resolve_ref_tip`: `refs/heads/NAME` when the source has
  the collection id `ID`, and `refs/mirrors/ID/NAME` otherwise. The probe
  of a local candidate reads the source with
  `Repo::list_collection_refs_in`, which has the same rule.
- Such a directory comes from outside the port: a hand edit, the `ostree`
  command, or a repository that took the own id after a pull of that
  collection. The summary of the `ostree` command reads the directory, and
  its field 0 gives the mirror ref in place of the ref of `refs/heads/` of
  the same name (observed). The `-c` listing of the `ostree` command lists
  the refs of the directory (observed). Both are divergences, recorded in
  `docs/conformance/cli-surface.md`.
- `Repo::fsck` lists each such ref in `FsckReport::own_mirror_refs`, which
  `FsckReport::is_ok` does not read. `ostrya fsck` prints one line on
  standard output for each such ref and exits 0. The `ostree` command
  prints no line and exits 0 (observed). Phase 2 still checks the commit of
  each such ref, because the prune keeps it: a missing commit is an error,
  and a binding mismatch under `--verify-bindings` stops the run. The
  back-ref check of phase 3 reads no such ref.
- `Repo::prune` holds each such ref as a strong ref with no name, as "The
  weak refs of a prune" states. The run keeps its commit and never deletes
  it.
- A bucket repository follows the same rule. The S3 push lists and reads
  no key under `refs/mirrors/ID/` of the own id. The summary update skips
  each such key with no check and no read. The bucket prune reads these
  keys as roots by the rules of each other ref key, so a malformed key
  fails the prune before a delete. The bucket fsck gives each such key a
  `ref` note and reads no such ref file.
- The port has no migration step and no repair code. The collection
  namespaces are not in production, so no repository of the port holds
  such a directory. The operator removes such a ref by hand.

These alternatives were rejected:

- The mirror ref wins: a pull writes `refs/mirrors/ID/NAME` when that file
  holds a ref, and each reader reads it before `refs/heads/NAME`. Each
  reader and each writer then needs one shared rule for a `stat` of the
  mirror path and its errors. A push writes `refs/heads/NAME`, so after a
  push the readers still give the commit of the mirror ref.
- A repair step that moves `refs/mirrors/ID/NAME` to `refs/heads/NAME`. The
  step overwrites a local ref that the user wrote, and no repository of the
  port holds the directory.
- An fsck error for such a ref. The ref breaks no object, the prune keeps
  its commit, and the `ostree` command exits 0 for the same state.

## The collection refs of a named remote

A pull from a named remote takes collection refs beside plain refs. The
rules:

- `Repo::pull`, `Repo::pull_with_session`, and `ostrya pull REMOTE` read
  each name as `NAME` or `@ID:NAME`. One pull takes both forms, and the
  refs of more than one collection. Before the first request, the pull
  refuses `REMOTE:NAME`, a `^` suffix, and a name that fails the rule of
  `Ref`, with `Error::InvalidRefspec`. The `branches` key of a remote
  holds plain names alone.
- The pull resolves `@ID:NAME` from the summary first: field 0 when the
  summary states the collection id `ID`, and else the entry of `ID` in the
  collection map. Then it reads one ref file: `refs/heads/NAME` when the
  collection id of the remote is `ID`, and else `refs/mirrors/ID/NAME`. The
  collection id of the remote is the `[core] collection-id` of the `config`
  of the remote. When the remote serves no config, or the config has no
  `collection-id`, it is the `ostree.summary.collection-id` of the summary.
  The server keeps the refs of its own id under `refs/heads/` ("The own
  collection id"), and its summary lists them in field 0. The config id
  wins because `ostrya serve` and `ostrya send` take it as the own id of
  the repository: they serve no file under `refs/mirrors/OWN/`, and the
  summary that they make states it. The config thus states which refs are
  under `refs/heads/`.
- The pull writes `@ID:NAME` by the own-id rule of the client: to
  `refs/mirrors/ID/NAME`, or to `refs/heads/NAME` when `ID` is the own id.
  The remote name gives the place of a plain name alone.
- Unless the pull writes no ref, the tip of `@ID:NAME` must hold the
  `ostree.collection-binding` `ID`, as in `Repo::pull_local`.
  `DISABLE_VERIFY_BINDINGS` skips the ref-binding check alone, which reads
  `NAME`.
- `Repo::pull` keeps its refusal of a `file://` address. A pull of
  collection refs from a local repository is `Repo::pull_local`, or
  `pull --collection` with a local candidate.

These alternatives were rejected:

- A ref listing request for the collection refs. The summary and the ref
  file give each ref, as for a plain name, so a pull from a named remote
  needs no other request kind.
- A read of `refs/mirrors/ID/NAME` for each id. A server keeps the refs of
  its own id under `refs/heads/`, so the pull would not find them when the
  remote serves no summary.
- A read of `refs/heads/NAME` when the config id or the summary id is `ID`.
  When the config states another id `X`, `refs/heads/NAME` holds a ref of
  `X`, and the binding check refuses its tip.

## The collection of a mirror pull

A mirror pull writes the refs of a remote in their collections, as the
`ostree` command does (`conformance/cli-behavior.md`, "The pulled ref under
the own collection id"). The rules:

- The `ostree.summary.collection-id` of the summary of the remote gives the
  collection of a plain name and of each ref of field 0. A plain `NAME` is
  then `@ID:NAME`, and the pull writes it by the own-id rule of the client.
  With no summary, or with a summary that states no collection id, the pull
  writes `refs/heads/NAME`.
- An `@ID:NAME` name keeps its collection.
- A mirror pull of every ref also takes the refs of the collection map.
- The tip of each ref that the pull writes as `@ID:NAME` must hold the
  collection binding `ID`. This is the check of an `@ID:NAME` operand. The
  `ostree` command checks against another value, the `[core] collection-id`
  of the source or the remote key `collection-id`, and with neither it
  checks nothing. The check against the collection of the written ref
  makes sure that each collection ref that the pull writes holds a commit
  bound to that collection.
- Two different names that write one ref file stop the pull. Two such
  names can read different refs of the remote, so the pull does not select
  one. The check needs the collection of the summary, so it runs after the
  read of the summary and of the `config`, and before the first read of a
  ref file or an object. A name that occurs two times counts one time.

These alternatives were rejected:

- The remote key `collection-id` as the collection of a plain name. The
  `ostree` command reads the collection from the summary, and does not read
  the key for this purpose. A key with another value would write the refs
  in another collection than the tool writes. A pull from a remote with no
  such key would write no collection ref.
- The check of two names that write one ref file before the first request.
  Without the summary, the pull does not know the collection of a plain
  name.

## The mirrored collections of a remote

The remote key `mirrored-collection-ids` lists the collections that a
remote serves from `refs/mirrors/ID/`, which its summary lists in
`ostree.summary.collection-map`. The rules:

- `pull --collection=ID` takes as a candidate each remote whose
  `collection-id` is `ID` or whose `mirrored-collection-ids` holds `ID`, in
  the order of the config. The command fails when no remote has `ID` in
  either key. The probe of a candidate does not change: it reads the
  collection map when the summary or the listing states another own id.
- The key does not need `collection-id`. Each id passes the collection-id
  rule. The key refuses the `collection-id` of the same remote and an empty
  list. An id that occurs again counts one time.
  `Remote::mirrored_collection_ids` reads the key with these rules, and
  `config::check_mirrored_collection_ids` applies them to a value.
- `remote add --mirrored-collection-id=ID` can occur more than once. The
  command writes the ids in the order of the command line, and applies the
  same rules to the final value of the key, from the option or from
  `--set`.
- `pull --collection` reads both keys of each remote, so a bad value in any
  remote fails the command. A pull that names the remote reads neither key.

## The access items of each namespace

One client group holds the allow items and the deny items of each
namespace (`ostrya-config(1)`, "Access modes and patterns"). The rules:

- An allow item is `[MODES:]PATTERN` or `[MODES:]@ID:PATTERN`, and a deny
  item is `PATTERN` or `@ID:PATTERN`. `ID` is a literal collection id. No
  form names more than one id. `@OWN:PATTERN` is the same as `PATTERN`.
- The config has at most one group for each auth item. The server selects
  the group of the item, and the group gives the session policies:
  `verify`, `allow-unsigned`, `sign`, `allow-privileged`, and
  `disable-verify-bindings`. A session reads the items of the namespace of
  each ref. The items of two namespaces never combine.
- A group opens a push session when an allow item of any namespace has
  `w`, `c`, `t`, or `d`. The check of each ref of `Hello` refuses a ref
  with no `r` in its namespace.
- The claims of a namespace replace the items of the group for that
  namespace alone. A certificate with claims for `org.x` alone keeps the
  local rights of the group.
- A claim has the one kind `ref`. The text after `ostrya:ref:` is an allow
  item, or `!` and a deny item. `MODES` comes before `@ID:`, and `!` comes
  before `@ID:`. One parser reads the items of a group and the body of a
  claim, so the two grammars stay the same. A URI with the scheme `ostrya`
  and another kind is no claim, so the server refuses each request of the
  certificate with 403.
- A group cannot set both `tls-accept-claim=true` and `summary=true`, and
  each auth item has one group. Thus a TLS client whose group takes claims
  gets no summary, also for the local refs. A remote with
  `gpg-verify-summary` or `sign-verify-summary` reads the refs from the
  summary alone, so that client pulls no ref through such a remote.
- The implicit group `anonymous` of a config with no client group reads
  each local ref and each ref of each collection. No item names each
  collection, so the rights of each other collection are a part of the
  implicit group alone. The access digest gives them the namespace line
  `namespace=*`, so the digest of the implicit group keeps its text.

These alternatives were rejected:

- A claim form for each namespace kind: `ostrya:ref:` for the local refs
  and `ostrya:collection:ID:` for a collection, with no `@` in a claim. The
  claims then have a grammar that the items of a group do not have.
- Both claim spellings, `ostrya:ref:[MODES:]@ID:PATTERN` and
  `ostrya:collection:ID:[MODES:]PATTERN`. Two spellings of one claim need
  two parsers and two sets of tests, and give a CA two ways to state one
  right.

## The namespace of each pushed ref

The push protocol carries the namespace of each ref in its name
(`format-reference.md`, "Hello and HelloReply"). A user pushes local refs
and the refs of more than one collection in one push. The rules:

- Each name field holds the text of a ref ("The ref syntax"): `NAME` or
  `@ID:NAME`, and in a one-way stream also `REMOTE:NAME`. The name fields
  are `Hello.refs`, the names of `HelloReply`, `Commit`, and `CommitReply`,
  and the branch and the tags of a server commit. The GVariant types are
  the same for each form. `Hello` and `HelloReply` have no `collection`
  key. `HelloReply` keeps `collection-id`, so the client checks the
  bindings of each ref before it sends an object.
- The server parses each name and maps `@OWN:NAME`, where `OWN` is its
  collection id, to the local ref `NAME`. The names of `HelloReply` and of
  `CommitReply` repeat the text that the client sent.
- The server refuses two names of one ref in one `Hello` with `protocol`,
  before it sends `HelloReply`: one name two times, or `NAME` with
  `@OWN:NAME`. The server knows its own collection id at `Hello`, so the
  client sends no object for a push that fails.
- The binding of a commit checks the namespace, and never selects it. A
  plain `DST` is a local ref of the server. A commit bound to `X` on a
  plain `DST` is refused unless `X` is the collection id of the server. The
  user writes `main:@X:main`, or `@X:main` when the source is the
  collection ref `@X:main` of the local repository.
- A commit with no `ostree.collection-binding` goes to the local refs
  alone. An update of `@X:NAME`, where `X` is not the collection id of the
  server, with such a commit is refused. No key and no flag turns this rule
  off. A collection pull refuses a commit with no binding unless the caller
  allows it, so such a ref fails the pull of its collection. A user binds a
  commit with `ostrya commit -b @X:NAME`, or pushes it with
  `push --onto @X:NAME`, where the server binds the commit.
- The ref-binding check compares the name part of each `DST` and of each
  tag with the `ostree.ref-binding` list of its commit: `stable` for
  `@X:stable`. A commit with no key passes the check of a `DST`. An empty
  list holds no name, so it is refused, as a pull refuses it. The client and
  the server apply the check, also to a one-way stream and to a push to a
  bucket. The client also refuses a tag whose commit has no key.
- The client group key `disable-verify-bindings` (`ostrya-config(1)`,
  "Client keys") makes the server skip the ref-binding check for the ref
  updates and the tags of a session of the group. `ReceivePolicy` and
  `StreamPolicy` carry the same flag. `ostrya push --disable-verify-bindings`
  and `RepoPushOptions` skip the check of the client, and the server then
  applies the key of the group. A bucket has no server check, so the flag
  alone skips the check of a push to a bucket. `send --one-way` and
  `receive --one-way` take the option for their side of the stream. The
  check of the collection binding stays on under each key and each flag.
  When a push under the key or a flag writes a ref whose commit does not
  hold its name, a pull of the ref fails without
  `--disable-verify-bindings`, also a pull by the `ostree` command.
- The server checks the access of each ref in its namespace. The refusal of
  `ostree-metadata` applies to each local ref, `@OWN:ostree-metadata`
  included.
- `push --collection=ID`, `push --onto`, and `push-tree` take one rule:
  `--collection=ID` adds `@ID:` to each plain `DST` and to each plain tag
  or branch. An `@ID:` operand stays, and an `@Y:` operand, with `Y` other
  than `ID`, is refused before the session. A `DST` that defaults from an
  `@Y:` `SRC` is an `@Y:` `DST`. `--bind-ref` takes a plain name, and
  `--collection` does not change it.
- The branch and the tags of a server commit are in one namespace, after
  the mapping of the own collection id of the server. A commit made in a
  namespace stays bound to it, and each tag of the commit is in that
  namespace. The client checks this after `HelloReply`, before it sends an
  object, and the server checks it again. The server needs `c` on the
  branch, and `t` or `w` on each tag, each in its namespace. It writes
  `ostree.collection-binding` with the id of the namespace, and no key for
  the local refs of a server with no collection id. It writes
  `ostree.ref-binding` with the name parts of the branch and the tags and
  each bound name, and drops the binding keys of the client. `push --onto`
  does not check the bindings of the local commit, and `push-tree` and
  `push --onto` read no `disable-verify-bindings`.
- A one-way stream takes `@ID:NAME` names and `@ID:` patterns. A ref of a
  collection takes no default rule, so it needs a pattern rule that
  matches it. A remote ref keeps the check of its collection binding
  against the collection id of the receiver.
- The push to a bucket takes the namespace of each `DST` with the `config`
  of the bucket in the role of the server ("The S3 push").
- The hooks and the receive report take types of `ostrya` with typed
  names: `ReceiveRefUpdate` and `ReceiveRefOutcome` hold `name: Ref`, and
  `ReceiveServerCommit` holds `branch: Ref` and `tags: Vec<Ref>`, with
  `bind_refs` as text. Each name is canonical: a ref of the own collection
  id of the server is `Local`, so `main` and `@OWN:main` give a hook the
  same value. The server builds these values once, after the checks of the
  `Commit`. `ReceiveReport` holds no namespace of the session. The protocol
  types of `ostrya-remote` are the same for each form, and the client keeps
  `PushOutcome` with the protocol `RefOutcome`, which holds the text that
  the client sent.
- `ReceiveService::commit` gives the host the `ReceiveReport` and the
  protocol `RefOutcome` list. The host builds `CommitReply` from that list,
  so the reply repeats the text of the client. The selector of
  `receive_selected` takes no namespace, because a session has none.

These alternatives were rejected:

- A namespace for each session, named by a key of `Hello`. A push of the
  refs of two collections then needs two sessions, and the binding of a
  commit has to select the namespace when the user gives none.
- A refusal of each `@ID:` operand under `--collection`, also of an operand
  of the same id. The three push commands then take two rules for one
  option.
- The protocol `ServerCommit` for the hook, with the typed names as a second
  argument. The host gets each name two times, and the two must agree.
- The protocol types alone for the hooks and the report. Each host then
  parses the names and reads the own collection id of the server to
  compare `main` with `@OWN:main`.

## The refs of a push with no refspec

The key `push-branches` of a `[remote "NAME"]` section is a list of ref
patterns, which `Remote::push_branches` reads as a `ReceiveSelector`. The
rules:

- The `ostrya push` command reads the key when the command line gives no
  refspec. A refspec on the command line has precedence, so a bad value
  does not block it. `--onto` and an address do not read the key, and a
  refspec is then still required.
- `Repo::push` reads no config key for its refs. The command fills
  `RepoPushOptions::refspecs` from the key.
- The command lists the local refs and the refs under `refs/mirrors/ID/`,
  and keeps each ref that the selector selects, with the
  `[core] collection-id` of the repository as the own id. The list skips
  the own id and each id that is not valid. Each match goes to the push as
  the refspec `CHECKSUM:NAME` or `CHECKSUM:@ID:NAME`, with the commit that
  the listing read: the local refs by name, and then the collection refs by
  id and name. An alias is a match like each other ref. A refusal of one
  match by the server fails the whole push.
- With no match, the command writes a line to standard error, writes
  nothing to standard output, exits 0, and opens no connection. The ref
  listing and this check come after the checks of `--collection` and of the
  S3 options, and before the push address resolves.
- The command refuses `--tag` when it reads the key, with `--tag needs a
  refspec, and [remote "NAME"] push-branches gives none` at exit 1. The
  refusal comes after the checks of `--collection` and of the S3 options,
  and before the ref listing and the connection. It does not depend on the
  local refs. A tag needs one source commit, and the selection gives no
  commit, one commit, or more than one.

These alternatives were rejected:

- A read of `push-branches` in `Repo::push`. A library caller then cannot
  give a list of refs that the key does not change.
- A refspec of the name alone. The push resolves the name again, and a
  revision of lowercase hex characters reads as an abbreviated checksum
  first. A ref such as `cafe` then resolves to a commit whose checksum
  starts with `cafe`, and the push fails because a checksum source needs a
  destination.
- A listing of the remote refs that are collection refs. The key selects
  the refs of the local repository. A ref under `refs/remotes/` is the copy
  of a ref that a pull from another remote wrote.
- A tag at the one commit of the selection. The result then depends on the
  local refs: the same command creates the tag or fails when a local ref
  moves.
- A push with no match that drops `--tag` and exits 0. The push then does
  not create a ref that the user requested, and the exit status reports
  success.
- A clap `requires` rule between `--tag` and the refspecs. The refusal then
  writes the usage text of clap, and its text does not name the key. The
  rule also refuses `--tag` with no refspec when the remote has no key, and
  that push then does not get `REFSPEC must be specified`.
- A tag at each matched commit. This reads `--tag` with a meaning of its
  own, and writes refs that the user did not request.

## The refs of a pull with no ref

The key `pull-branches` of a `[remote "NAME"]` section is a list of ref
patterns, which `Remote::pull_branches` reads as a `ReceiveSelector`. The
rules:

- `Repo::pull` reads the key when `PullOptions::refs` is empty and `MIRROR`
  is not set. The selector matches the refs of the summary, and the summary
  is available inside the pull alone. `Repo::pull` also reads `branches`
  there. The pull reads the key after it reads the summary and the `config`
  of the remote, and before it reads a ref file or an object.
- `Repo::pull_with_session` has no remote section, so it reads neither key
  and refuses an empty ref list. A `--collection` pull does not read the
  key.
- A ref on the command line has precedence over `pull-branches`, and
  `pull-branches` has precedence over `branches`. The two keys do not
  merge, so a section with both keys takes the refs of `pull-branches`
  alone.
- A ref of field 0 of the summary is the ref `NAME`, and a ref of the entry
  of `ID` in `ostree.summary.collection-map` is the ref `@ID:NAME`. The own
  id of the match is the `ostree.summary.collection-id` of the summary, or
  none if the summary states none. So `@ID:NAME` of that id matches a ref
  of field 0. A pattern `REMOTE:NAME` matches no ref of the summary.
- A match of field 0 is written to `refs/remotes/NAME/REF`, as a ref of
  `branches` is, also when an `@ID:NAME` pattern selected it. A match of the
  collection map is the target `@ID:NAME`, and the pull writes it and checks
  its tip as a requested `@ID:NAME` ref.
- Only the matches go through the ref-name rule. A bad name of a ref that
  the key does not select does not fail the pull.
- A remote with no summary fails the pull with `[remote "NAME"]
  pull-branches selects refs of the summary, but the remote repository does
  not have a summary`. A list that selects no ref of the summary fails the
  pull with `no ref of the summary matches [remote "NAME"] pull-branches`.
  Both are `Error::Pull`, and the pull writes no object and no ref.

These alternatives were rejected:

- A read of `pull-branches` in the `ostrya pull` command. The command then
  fetches the summary one time to select the refs, and the pull fetches it
  again.
- A match of the written names, `REMOTE:NAME`. The key selects refs of the
  remote, and the summary lists them with no remote part.
- A list of the matches as names for the path that reads `branches`. That
  path reads each name as a plain ref, so it refuses a match `@ID:NAME` of
  the collection map. It also looks up each match in the summary a second
  time.

## The ref check of a transaction commit

`Transaction::commit` writes the queued refs one by one, each with a temp
file and a rename. A write that fails stops the commit. So the commit checks
the whole queue against the ref store before the first write. The rules:

- The check runs under the update lock, in the trip to the blocking pool
  that writes the detached metadata and the refs. It runs before the
  detached metadata and before the first ref write. `commit_under` runs the
  same check. The receive path reads each ref path under the update lock
  before it queues its writes. Its compare of the expectations, its policy
  checks, the fast-forward walk, the parent of a server commit, and its
  reply need the current commit. It sends each refusal as a wire error
  before it publishes an object. The commit check then reads each queued
  path again with one `lstat`.
- The check reads each queued path of `Transaction::set_ref` with `lstat`
  alone. A queued write or removal fails with `Error::RefNotWritable` if
  its path names an alias, names a directory, passes through a file, or
  names a special file: a FIFO, a socket, or a device file.
- A queued removal whose path passes through a file passes when an earlier
  removal of the same queue removes a path above it at any level, for
  example `a` for `a/b/c`. The unlink of `a` leaves `a/b/c` absent, if no
  write below an alias writes `a` again. The earlier removal can be an
  entry of `set_ref` or of `set_ref_expecting`. The other order, a removal
  of `a/b` and then of `a`, fails. A conditional removal does not take this
  exception. A path that names a directory or a special file stays refused.
- Two queued entries where the path of one names a directory of the path of
  the other fail with `Error::RefNotWritable`, if one of the two is a write.
  Examples are a write of `a` and a write of `a/b`, or a removal of `a` and
  a write of `a/b`. The error names the outer ref. Two removals pass this
  rule.
- The check reads the ref store as it is before the first write. It does
  not look through an alias in a parent directory of a queued path. So a
  write below such an alias can fail after the commit writes earlier refs,
  and these refs stay. Examples are a write of `old/x`, where `old` is an
  alias that points to no ref, and a write of `x`, then a write of `al/y`,
  where `al` is an alias of `x`. A write below such an alias can also write
  a ref at a path that the check read for another entry. A later entry can
  then fail after the commit writes earlier refs. A removal of `x`, then a
  removal of `al/b`, where `al` is an alias of the ref file `x`, fails the
  commit. The check refuses `al/b` before the first write, because its path
  passes through a file.
- A queued write or removal whose path names an alias fails with
  `Error::RefNotWritable`, reason `names an alias`. This applies to an
  entry of `set_ref` and to an entry of `set_ref_expecting`.
  `Repo::set_ref_immediate` and `UpdateGuard::set_ref` refuse a write or a
  removal over an alias with the same error, under the update lock, before
  the rename or the unlink. The receive path refuses an alias in the same
  way. The reason: a write through the alias replaces the link with a ref
  file, and the target of the alias keeps its old commit, with no error.
- `Repo::remove_ref_alias_immediate(refspec)` and
  `UpdateGuard::remove_ref_alias(refspec)` remove an alias. They unlink the
  link, and the target ref stays. An absent path is success, as for the
  removal of an absent ref. A path that names a ref file fails with
  `Error::RefNotWritable`, reason `names a ref file`. A path that names a
  directory or a special file, or that passes through a file, fails with
  `Error::RefNotWritable` and the reason of the `lstat` read. In the CLI,
  only `refs -A --delete` removes an alias.
- `Repo::remove_refs_immediate(refs)` removes a set of refs outside a
  transaction. It takes the update lock one time for the set. Under the
  lock, it applies the check of `Transaction::set_ref` to the whole set
  before the first unlink, so a path that names an alias, names a
  directory, passes through a file, or names a special file stops the
  removal before the first ref goes. It uses no staging directory and does
  not use `tmp/`. An absent ref is success, and the parent directories
  stay. `refs --delete @<id>:PREFIX` removes the refs of each prefix, and
  `refs -c --delete` the refs of all ids, with one call. So an alias under
  `refs/mirrors/<id>/` stops the prefix, or the `-c` deletion, before it
  removes a ref.
- A refused commit leaves the published objects, and writes no detached
  metadata and no ref. `gc` removes the objects.
- An I/O error between two ref writes, for example on a full disk, leaves
  the refs written before it. There is no rollback.

`Transaction::set_ref_expecting(r, expected, new)` queues a conditional
write. `expected = None` expects that no file stands at the path of the
ref. `Some(c)` expects a ref file that names `c`. `new = None` removes the
ref. The rules of a conditional write:

- The check above compares each conditional entry with the ref store, in
  queue order with the other entries. The first failure stops the commit.
- The compare reads the ref store as it is before the first write. This is
  also true when an earlier entry of the same queue writes the same ref.
- A ref that does not have the state `expected` fails with
  `Error::RefMismatch`. The error holds the name of the ref, the expected
  state, and the state in the store.
- A conditional entry whose path names a directory or passes through a file
  fails with `Error::RefNotWritable`, also for `expected = None`.
  `Repo::resolve_ref_tip` gives `None` for such a path, so a caller that
  gives back that `None` as `expected` gets this error.
- A conditional entry whose ref file does not parse fails with the error
  of the parse, because the compare needs the content.
- An entry of `set_ref` costs one `lstat`. A conditional entry costs one
  `lstat` and one `O_NOFOLLOW` open, with a read of at most 4096 bytes and
  a parse.
- `commit_under` runs the same compare. The receive path queues entries
  of `set_ref` alone. It compares each update with the current commit that
  it reads under the update lock, so it sends a mismatch as a wire error
  before it publishes an object.
- The server commit of a receive queues each tag with `set_ref`, and the
  branch too if the branch moves. `publish` can also queue the anchor ref
  `ostree-metadata` with `set_ref`. The server commit reads these refs and
  the tip of the anchor ref after it takes the update lock. `publish` runs
  `commit_under` under the same hold of the lock. A receive with no server
  commit also runs `commit_under` under the update lock that its caller
  holds. These ref writers of the port take the update lock, also under
  `[core] locking=false`: `Transaction::commit`, `Repo::set_ref_immediate`,
  `Repo::remove_refs_immediate`, `Repo::set_ref_alias_immediate`,
  `Repo::remove_ref_alias_immediate`, and each write of an `UpdateGuard`. So
  none of them can change a ref between the read and the commit. For these
  writers, a compare of `set_ref_expecting` finds the state that the read
  found, so it adds no check.
- `Repo::prune` takes no update lock, and it holds the repository lock
  exclusive. The server commit holds the repository lock shared. A two-way
  receive refuses a repository with `[core] locking=false`, and a one-way
  stream carries no server commit. So a prune does not run between the
  read and the commit. Other writers take no update lock, so they can
  change a ref after the read. These are the `ostree` command, a hand edit
  of a ref file, and a prune whose handle reads `[core] locking=false`
  after a change of the config. Each handle reads the config once at the
  open, so the server can still hold a handle that read `true`. Such a
  change can also come after the compare of a conditional write, so
  `set_ref_expecting` does not close that window.

These alternatives were rejected:

- A rollback of the written refs after a failed write. The rollback is a
  second set of writes that can fail too, and a reader can see the refs
  between the two sets.
- A skip of the refused ref, with the other refs written. The caller then
  gets a part of a set that it queued as one, which is the failure that the
  check prevents.
- A check in `set_ref`, or before the commit takes the update lock. Another
  writer can change the ref store between the check and the writes.
- A check that replays the queue on a model of the ref store, so that each
  entry sees the result of the entries before it. The model must apply each
  write and each removal in queue order, as a second copy of the rules of
  the ref store. The `lstat` of each path reads the store itself.
- A parse of the content of each ref file in the check. A write over a ref
  file whose content does not parse then fails, and the write replaces that
  file in each other case.
- A write over an alias that replaces the link with a ref file, as the
  `ostree` command does. The target of the alias then keeps its old commit,
  and the caller gets no error.
- One `Transaction` for each set of `Repo::remove_refs_immediate`. A
  transaction creates a staging directory, scans `tmp/`, and parses
  `tmp-expiry-secs`, the `min-free-space-*` keys, and `generate-composefs`.
  It can fail with `ENOSPC` on a full disk, where a removal frees space.
- A wider check in the CLI before it removes the refs of a prefix one by
  one with `Repo::set_ref_immediate`. The CLI holds no lock between the
  check and the unlinks, so another writer can put an alias in place after
  the check.

## The pull scheduler

`crates/ostrya/src/pull/drive.rs` is a poll core of the port.
`FuturesUnordered` was rejected: `futures-lite` has no unordered join, and
`futures-util` is not in the graph.

## The expression engine of `--tar-pathname-filter`

`commit --tar-pathname-filter` compiles its expression with PCRE2, the
library that the `ostree` command compiles it with. This follows rule 2 of
`CLAUDE.md`, "CLI compatibility is functional, not literal". Two other
engines were rejected on measurements:

- A backtracking matcher written in the tree. A review found three
  constructs that it read differently from PCRE, and three paths with no
  bound on the work.
- The `regex` crate. It read the POSIX class names as ASCII, and `$` as the
  end of the text. Thus one command line wrote two different commits.

## `#[non_exhaustive]` on the public types

The attribute marks a type that a caller matches over and does not build,
when the port owns its set of members and expects the set to grow.

- `ostrya::Error` has the attribute. Its variants are the error vocabulary of
  the port, and a new failure mode adds a variant.
- `TrustRoots` has the attribute. The port owns the set of trust settings.
- `ostrya_fetch::UploadMethod` and `ostrya_fetch::SignPayload` have the
  attribute. The fetcher owns the set of upload methods and the set of body
  forms that a signer gets.
- `ostrya_remote::s3::Origin` and `ostrya_remote::s3::Resolved` have the
  attribute. The port owns the set of sources of an S3 setting, and the set
  of resolved settings grows with the S3 support.
- `ostrya_remote::transport::Endpoint` has the attribute, and
  `Endpoint::S3` is behind the feature `s3`. A match outside
  `ostrya-remote` needs a wildcard arm, so the build compiles with and
  without the feature. "The S3 bucket client" states the reason.
- `ostrya_remote::s3::S3Endpoint`, `Object`, `PutIfAbsent`,
  `DeleteIfMatch`, `Listing`, `Listed`, and `Upload` have the attribute, and
  so do the variants `ostrya_remote::Error::S3` and
  `ostrya_remote::Error::S3Region`. The bucket client builds them, and the
  set of fields grows with the S3 support. A caller builds an `S3Endpoint`
  with `S3Endpoint::new` and sets its fields.
- `ostrya::bucket::LockOperation`, `LockHolder`, `ObjectListing`,
  `BucketPushOutcome`, `BucketFsckReport`, `BucketFinding`,
  `BucketFindingKind`, `BucketPruneReport`, and `BucketSummaryReport` have
  the attribute. The port builds them, and a later
  version can add an operation, a field, or a kind of finding.
- The option structs of the `ostrya` crate do not have the attribute:
  `PruneOptions`, `PullOptions`, `TarExportOptions`, `TarImportOptions` and
  the others. The attribute stops a struct expression outside the defining
  crate, `..Default::default()` included. Thus a new field in one of these
  option structs is a breaking change, and it takes a minor version before
  1.0. The option structs of the bucket writers, `BucketWriteOptions`,
  `BucketFsckOptions`, `BucketPruneOptions`, and `BucketSummaryOptions`,
  have the attribute. A caller starts from
  `Default::default()` and sets the fields, so a later field is additive.
- `ostrya_server::ServeOptions` and `ostrya_mount::MountOptions` have the
  attribute. A caller starts from `Default::default()` and sets the fields.
- `ostrya_gvariant::Type` and `ostrya_gvariant::Value` do not have the
  attribute. The GVariant serialization specification closes the type
  alphabet, and the two enums name all of it. An exhaustive `match` over
  either enum is the gate that makes each site answer for a new type
  character. A new variant in either enum takes a major version.
