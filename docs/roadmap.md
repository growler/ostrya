# Ostrya -- Roadmap

This document lists the work that is not done: planned features, gaps in
the commands and the library, open decisions, and gaps in the tests. Each
done feature is documented in `format-reference.md`, in the conformance
documents, and in the rustdoc of its crate. The design decisions are in
`decisions.md`.

## Planned features

### P3 commands

The `ostrya` command does not carry these commands of the `ostree` command.
`conformance/cli-surface.md`, "P3", states the surface of each.

- `reset`.
- `checksum`, with `--ignore-xattrs`.
- `find-remotes`. `ostrya pull --collection` over `Repo::pull_collection`
  does the work of `find-remotes --pull`, with the config finder alone. The
  library has no entry point that finds the remotes of a collection and
  pulls nothing.
- `create-usb`. It puts a `pull-local` or a mirror pull onto a destination
  repository, and needs no new library primitive.
- The media of `create-usb` and the pull of `find-remotes` carry one static
  delta, or the loose objects, of each dependency of a commit that they
  carry. A delta carries its target alone, and an offline apply refuses a
  target whose dependencies are not complete.
- `gpg-sign`, the alias of `sign --sign-type=gpg` with its own option names.
  `ostree gpg-sign --delete` removes a GPG signature, and no command of the
  port removes a signature, so the alias needs a delete mode of its own.

The cookie commands of `remote` (`add-cookie`, `delete-cookie` and
`list-cookies`) are out of scope. `conformance/cli-surface.md`, "P3", states
the reason.

Verification: the basic form of each command agrees with the `ostree`
command for a case that the matrix does not cover.

### Sysroot and deployments (optional)

The sysroot layout, deployments, boot config parsing, bootloader
integration, and the `admin` commands. This work needs root, mount
namespaces and bootloaders. It is out of scope unless the maintainer asks
for it.

## Gaps in pull

- `pull --dry-run` is not carried.
- `--cache-dir` is not carried on `pull`, `remote refs` and `remote
  summary`. The decision is to carry the summary cache or to refuse the
  option at each site.
- The pull does not write the summary cache `tmp/cache/summaries/`.
- `/etc/ostree/remotes.d/<remote>.trustedkeys.gpg` acts as the repository
  keyring of the remote: it takes binary keyrings alone, and it stops the
  read of the global trusted directory. The answer of the `ostree` command
  to this file is not observed, because the probe needs root.
- The pull does not read the remote keys `contenturl` and `metalink`, and
  refuses a `metalink=` or `mirrorlist=` URL.
- `Repo::pull` over HTTP refuses `collection_id`. `Repo::pull_collection`
  pulls collection refs.
- `Repo::pull_local` refuses a subpath. It refuses `collection_id` unless
  `no_ref_writes` is set.
- The HTTP pull of the port reads a 403 for an optional file as an error,
  for example for `summary.sig`, a `.commitmeta` object, or the superblock
  of a static delta. So the HTTP pull of the port stops at the first absent
  optional file of a bucket repository whose anonymous policy gives no
  `s3:ListBucket` (`ostrya-repo(5)`, section BUCKET REPOSITORIES).

## Gaps in the commands

- The DESTINATION of `checkout` is required. When DESTINATION is absent,
  the `ostree` command checks the commit out into a directory of the current
  directory, which it names after the COMMIT argument. This needs a
  black-box observation first: the name can be the given revision string or
  the resolved checksum, and a ref name with `/` needs a rule.
  `conformance/cli-surface.md`, "Global conventions", records the
  difference.
- `cat`, `log`, `ls`, `checkout` and `export` print `object not found:
  Commit <checksum>` for an absent commit. `show` and `fsck` print the text
  of the `ostree` command.
- `ostrya serve` reads the key groups before `check_server` runs, so a start
  that a check refuses reads the key files first. A fix needs a second read
  of the client groups or a new constructor of `ReceivePolicies`.
- `ostrya commit --tag` checks in the CLI that the ref is absent, before the
  lock and again before the commit. The library has no API for this check. A
  ref that another writer makes during the publish step is replaced.
  `conformance/cli-surface.md` states this.
- The armored repository keyring in `remote gpg-import` and `remote
  gpg-list-keys`. These commands read an armored `<remote>.trustedkeys.gpg`,
  and a verification refuses it. The answer of the `ostree` command to such a
  keyring in these two commands is not observed.
- The keyrings of `show` with no `--gpg-verify-remote`. The `ostree` command
  reads the global trusted directory there, and the port reads `gpgkeys.gpg`
  and `--gpg-homedir` alone. The port reads each file of `--gpg-homedir`
  whose extension is `gpg`, binary or armored, and the read of the `ostree`
  command is not compared. `conformance/cli-surface.md`, "P1", `show`,
  records both.
- `ostrya pull --trust=NAME`, also with `--collection`. The library field
  `PullOptions::trust_group` applies to each pull, and the command takes
  `--trust` on `pull-local` alone (`decisions.md`, "The trust group of one
  pull").

## Gaps in the library

- A tree handle that reads the staged objects of a transaction. A
  `TreeEntry::Dir` from `Transaction::read_dir` reads back through the
  transaction alone, so `RepoTree::read_dir` on it before the commit gives
  `Error::ObjectNotFound`. The rustdoc of `Transaction::read_dir` states the
  constraint. The handle is a public API addition, and it comes with a
  second caller.
- `FileObject::into_reader`. `fsck` opens each content object two times:
  `load_file` reads the header and drops its descriptor, and `reader()` opens
  the object again.
- A parallel verify pass in `fsck`. The pass verifies one object at a time,
  so the handoff to the blocking pool is a large part of a run over many
  small objects. The `Slots` driver of the pull has the necessary shape.
- A config key that marks weak refs by a name pattern. `Repo::prune` takes
  the classification as a function.
- The detached metadata in an offline apply.
  `Repo::apply_static_delta_offline` and `Repo::apply_static_delta` write no
  `.commitmeta`. The `ostree` command writes the `.commitmeta` of the target
  from the copy in the superblock (`conformance/cli-behavior.md`, "CLI output
  formats", `static-delta`, "`apply-offline`"). `conformance/cli-surface.md`,
  "P2", `static-delta`, records the difference.
- The partial marker of a dependency in an offline apply.
  `Repo::apply_static_delta_offline` and `Repo::apply_static_delta` refuse a
  target whose dependency has a `.commitpartial` marker, and do not remove the
  marker when they apply the delta of the dependency. So offline media cannot
  repair a dependency that the repository holds partial.
- The tombstone step of `fsck --add-tombstones` and dependencies. The step
  deletes each commit whose parent commit is absent, also a commit that
  another commit names as a dependency. A pull takes a dependency at depth
  0, with no parent, so a dependency with a parent is such a commit. The
  next run then gives an `Absent` finding for the commit that names it. The
  dependency check of the run runs before the tombstone step, so the run
  that deletes the dependency does not report it.
- The rules of the one-way stream come from code alone (`StreamPolicy`), and
  they can name remote refs. No client group applies to the stream. A later
  command, for example `ostrya repo import`, can replace the stream.
- The archive view serves `deltas/` in the `archive` mode alone. Outside
  that mode, the summary of an auth item and the ref listing name no static
  delta.
- `rsa` 0.10 with the fix for RUSTSEC-2023-0071. The RSA key type of the
  spki engine takes `rsa` 0.9.10, which has no fix. The move to a release
  with the fix comes with a review of the advisory exception in `CLAUDE.md`.
- More key types in the spki engine. The engine takes ECDSA P-256, ECDSA
  P-384, Ed25519, and RSA. The `ostree` command also signs and verifies with
  ECDSA P-521 and ML-DSA. Each type can come later in the feature `spki`,
  with its tool fixtures, and the cross-check with the `ostree` command. A type that
  needs a new crate needs the authorization of the maintainer first.
- A light commit parse in the prune walk. For each commit that the walk
  expands, `Commit::parse` builds the `a{sv}` metadata tree and copies the
  subject and the body. The walk reads the parent, the root dirtree and
  dirmeta, the timestamp, and field 2 alone. A parse that checks the normal
  form and decodes these fields alone refuses the same commits.
- One pool job for a commit load. `Repo::load_commit` and
  `Repo::load_commit_with_bytes` run two jobs on the blocking pool: one for
  the read of the object and one for the check of the `.commitpartial`
  marker. One job can do the read, the parse, and the check.

## Gaps of bucket repositories

A bucket repository is a repository at an `s3://` address
(`format-reference.md`, "The S3 bucket repository"). These parts of the
work on a local repository are not carried for it:

- The deletion of a ref, and weak refs.
- These options of `prune`: `--delete-commit`, `--only-branch`,
  `--retain-branch-depth`, `--commit-only`, and `--static-deltas-only`.
- Tombstone commits. `ostrya remote prune` refuses a bucket `config` that
  sets `[core] tombstone-commits=true`.
- These options of `fsck`: `--add-tombstones`, `--all`, `--verify-bindings`,
  `--verify-back-refs`, and `--no-mark-partial`.
- `push --onto`, and tags.
- A signed tree push to a bucket repository. `BucketRepo::push_tree` and
  `ostrya push-tree` to an `s3://` address sign no commit. A user pulls the
  commit into a local repository, signs it there, and pushes it with
  `Repo::push_to_bucket` or `ostrya push`, which then uploads the
  `.commitmeta` alone. A signer in the options of the tree push, as the
  signing options of `commit`, closes the gap.
- A shared frontier in the reachability walk of the bucket prune.
  `BucketRepo::prune` reads the commits one at a time, and walks the tree
  of each commit before it reads the next commit. The walk knows the
  children of a dirtree only after its read ends. So the n dirtrees that a
  commit adds, from the root dirtree to the change, are n reads in
  sequence at each `max_outstanding`, and the commit costs 1 + n round
  trips. For example, 1,000 linear commits that each change the file
  `/usr/lib/x/y/file` cost 6 round trips each: about 120 s at 20 ms for
  each round trip, at a limit of 1 and of 8. Parallel commit reads do not
  make a linear history shorter, because the walk knows the parent of a
  commit only after it reads the commit. They help only across separate
  roots. A frontier that the tree walks of all commits share removes the
  chain of each commit: C linear commits then cost about C + n round trips
  in place of C x (1 + n).
- A static delta that the push generates or uploads. The push uploads no
  delta, and a delta comes into the bucket from another writer.
- The summaries of auth items under `extensions/ostrya/summary/`, and the
  client groups of `ostrya summary -u -c`.
- `-m`/`--add-metadata` on a summary update. Each later summary update
  drops the key, as `ostrya summary -u` drops it in a local repository.
- Refs under `refs/remotes/`. The summary update refuses them.
- The anchor commit `ostree-metadata` in a bucket repository with a
  collection id.
- Credential sources other than the key pairs of the environment and of the
  shared AWS files: EC2 instance metadata, ECS container credentials, web
  identity, SSO, `credential_process`, and an assumed role.
- A `Cache-Control` header on the mutable keys: `summary`, `summary.sig`,
  and the ref files.
- Server-side encryption headers, ACL headers, and storage classes.
- An anonymous S3 pull of the port, with no signature. The port pulls a
  bucket repository from its `s3://` address alone, with signed requests.
- `Bucket::list_uploads` has no cap on a run of truncated pages with no
  upload. A server that gives such pages with a new upload id marker for
  one key holds the list with no end. `Bucket::list` fails after more than
  1000 truncated pages in a row with no key and no common prefix.
- The tree push to a bucket has a small compressor pool of its own, next to
  `Compressors` in `crates/ostrya/src/archive.rs`. A merge needs
  `Compressors` to be generic over its source.
- Two reads of a bucket open a `GET` stream for its headers alone, and drop
  it. The read of a key after a completion of a multipart upload with no
  known outcome reads the declared length and the `ETag` of the object.
  The read of a writer lock larger than 64 KiB reads its `ETag`. For a
  large object, the server starts to send the body, and the drop closes
  the connection. A read with `Range: bytes=0-0` closes the gap. The read
  after a completion needs the total length of the `Content-Range` header
  of a 206. `ostrya_fetch::Body` gives the `ETag` of a 206, and does not
  give its `Content-Range` header.

## Open decisions

These decisions belong to the maintainer. The port keeps the stated behavior
until each one is made.

- The fsync schedule of `checkout`. The port syncs each file and each
  directory that it writes into the destination, one after the other. The
  `ostree` command syncs the uncompressed object cache, which persists, so a
  second checkout pays nothing. Measured on one host, with 5000 files in one
  directory from an `archive` repository: the port makes 5002 calls in
  14.3 s, against 0.39 s with the policy off. The alternatives are one
  barrier for the whole destination, or no barrier for a reused directory.
  The schedule is in `crates/ostrya/src/checkout.rs`.
- An xattr with a zero-length value at ingest. The port records it and the
  `ostree` command drops it, so the object checksums differ for a tree that
  has one. `conformance/m0-content.matrix`, row C4, states this, and no cell
  states the corpus in the affected modes.
- `.` and `..` in a subpath. `checkout` and `export` write the whole tree for
  `--subpath=..` and `--subpath=.`, and the port drops `.` at any position.
  The `ostree` command exits 1. The decision is whether `/` alone names the
  root. `conformance/cli-surface.md` records both differences.
- `summary -m` in a repository with a collection id. The port refuses caller
  keys there. The alternative carries the keys into the
  `ostree-metadata` anchor commit in the order of the port, and records the
  anchor checksum as a difference.
- Four differences in the bytes of the repository, which
  `conformance/cli-surface.md`, "P2", records as open:
  - `sign` with a repeated `--keys-file`;
  - `static-delta generate` with a repeated `--keys-file`;
  - the `usize` of the meta-entry of a delta part;
  - the part boundaries of `static-delta generate`.
- The width of the progress line of `pull`. The port pads each line to 80
  bytes. A read of the terminal width needs `terminal_size` as a direct
  dependency of `ostrya-cli`, which needs the confirmation of the
  maintainer.

## Gaps in the tests and in CI

- No advisory scan runs over the dependency graph. The scan needs a scanner
  that reads the RustSec database over `Cargo.lock`, at a pinned version,
  with RUSTSEC-2023-0071 on a reviewed ignore list. Then an unexplained
  advisory fails the build. `CLAUDE.md`, "Advisory exceptions", states the
  two known advisories.
- No environment variable turns a skip for an absent fixture into a failure,
  as `OSTRYA_REQUIRE_GNUPG` does for GnuPG.
- No test compares `ostrya-composefs` with the `composefs-rs` writer. The
  golden tests compare with the images of the `ostree` command alone.
- GPG verification:
  - Three rules are not measured: a designation through signature subpacket
    12 on an expired self-signature, a revocation signature after its own
    expiration time, and the boundary second of a self-signature.
  - No fixture has a Text-class signature, which hashes the payload with
    CRLF line endings.
  - No measurement covers a designated revoker of a subkey. The subkey rule
    uses the signature of the primary key.
  - The differential matrix has no cell for public-key algorithm 27
    (`Ed25519`), because `gpg` 2.4.9 writes algorithm 22.
- No test runs against AWS. These answers of AWS are not observed: a
  bucket of another region in path style and in virtual-host style, a
  `DeleteObject` with an `If-Match` of another `ETag`, a raw `+` of a
  delta key in the path of an unsigned `GET` of the `ostree` command, and
  the unsigned reads under the anonymous bucket policy of `ostrya-repo(5)`.
  The answers of the stand-in of the tests follow the AWS API reference.
- CI installs neither `weed` nor the `ostree` command. So in CI, the tests
  on SeaweedFS and the cross-checks with the `ostree` command skip, the
  writer tests of a bucket repository run on the stand-in of the tests
  alone, and `ostree fsck` and `ostree pull` of a bucket repository do not
  run.
- The answers of SeaweedFS to a `ListObjectsV2` with a trailing `/` in the
  path of the bucket, and its form of a key with `+` in a listing with
  `encoding-type=url`, are not recorded.
- No test makes a `GET` of a bucket repository fail after the last retry of
  the fetcher. The stand-in of the tests has no setting for it.
- No test of `Repo::pull_collection` reads a summary that
  `BucketRepo::update_summary` wrote, and no library test runs a summary
  update against `rclone serve s3`. The test of `ostrya remote summary -u`
  on rclone covers the refusal.
- `cargo clippy -p ostrya-cli --all-targets` with a feature set other than
  the default set fails in `crates/ostrya-cli/src/man.rs` on items with no
  use. CI does not run it.
