# Ostrya -- Roadmap

This document lists the work that is not done: planned features, gaps in
the commands and the library, open decisions, and gaps in the tests. Each
done feature is documented in `format-reference.md`, in the conformance
documents, and in the rustdoc of its crate. The design decisions are in
`decisions.md`.

## Planned features

### S3 push and pull

A feature `s3` adds push to and pull from an S3 bucket.

- Push writes the objects, the refs and the summary of a repository into a
  bucket. Push is a port extension.
- Pull reads from a bucket directly.
- A pushed bucket is a static repository. Thus the `ostree` command can pull
  from it over the HTTP endpoint of the bucket.
- The S3 work is SigV4 request signing, the bucket and prefix addressing, and
  multipart upload for large objects. It runs over the fetcher of
  `ostrya-fetch`. `Target::PathQuery` carries a presigned query for each
  target.
- The credentials come from the standard AWS environment and profile chain.
- The choice between a SigV4 crate and signing written in the tree is made
  when the work starts. A crate needs the confirmation of the maintainer.

Verification: push a fixture repository to an S3-compatible test server and
pull it back with no change. The `ostree` command pulls the pushed bucket
over plain HTTP.

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
- `gpg-sign`, the alias of `sign --sign-type=gpg` with its own option names.

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
- The pull does not read the remote keys `contenturl` and `metalink`, and
  refuses a `metalink=` or `mirrorlist=` URL.
- `Repo::pull` over HTTP refuses `collection_id`. `Repo::pull_collection`
  pulls collection refs.
- `Repo::pull_local` refuses a subpath. It refuses `collection_id` unless
  `no_ref_writes` is set.

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
  the classification as a function, and `[ex-ostrya] gc-root-metadata-keys`
  marks roots by a metadata key.
- An option that turns off the keys of `[ex-ostrya] gc-root-metadata-keys`
  for one run of `Repo::prune`. It comes when a caller needs a run that
  keeps less than the policy of the repository.
- The rules of the one-way stream come from code alone (`StreamPolicy`), and
  they can name remote refs. No client group applies to the stream. A later
  command, for example `ostrya repo import`, can replace the stream.
- The archive view serves `deltas/` in the `archive` mode alone. Outside
  that mode, the summary of an auth item and the ref listing name no static
  delta.
- A signed tree push to a bucket repository. `BucketRepo::push_tree` and
  `ostrya push-tree` to an `s3://` address sign no commit. A user pulls the
  commit into a local repository, signs it there, and pushes it with
  `Repo::push_to_bucket` or `ostrya push`, which then uploads the
  `.commitmeta` alone. A signer in the options of the tree push, as the
  signing options of `commit`, closes the gap.

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
- Five differences in the bytes of the repository, which
  `conformance/cli-surface.md`, "P2", records as open:
  - `sign` with a repeated `--keys-file`;
  - the key kind of `sign -d`;
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
- The spki engine is not checked against the `ostree` command. The test
  `spki_tool_cross_verify_pending` skips until a build of the command with
  spki is available.
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
