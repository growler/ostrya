# Changelog

This file lists the changes in each release of the Ostrya workspace, newest
first.

- Library: the published crates (`ostrya`, `ostrya-core`, `ostrya-gvariant`,
  `ostrya-composefs`, `ostrya-rt`, `ostrya-sign`, `ostrya-fetch`, `ostrya-remote`,
  `ostrya-sys`, `ostrya-mount`, `ostrya-server`).
- CLI: the `ostrya` command, the `ostrya-mountd` daemon, their man pages, and
  their packages.

An item that starts with `Breaking:` needs a change in code or config that uses
the release before it. An item that starts with `Fix:` corrects a defect.

## [0.13.0] - 2026-11-18

### Library

- Breaking: The API calls an entry of field 2 of a commit an attachment, and an
  entry of the detached metadata key `ostrya.related` a supplement.
  `CommitRelated` is `CommitRelations` (fields `attachments`, `supplements`),
  `RelatedField` is `RelationField`, `RelatedWarning` is `RelationWarning`,
  `CheckedRelated` is `CheckedAttachments`, and `Error::InvalidRelated` is
  `Error::InvalidRelations`.
- Breaking: `read_commit_related`, `add_detached_related`, `check_related`, and
  `CommitOptions::related` are `read_commit_relations`, `add_supplement`,
  `check_attachments`, and `CommitOptions::attachments`. The module
  `pull::dependency` is `pull::attachment`. The fsck and bucket fsck names say
  "attachment" in place of "dependency".
- Breaking: The error texts of related commits change, and the bucket fsck finding
  kind is `attachment`.
- An attachment can have attachments of its own. The commit write,
  `check_attachments`, the composefs rewrite, and the static delta apply accept
  it. The check is shallow: each attachment must be complete.
- The pull over HTTP, over a stream, from a bucket, and from a local repository,
  and the media export and import, take the full set of nested attachments level
  by level. A pull skips an attachment that the repository holds complete.
- The push, the bucket push, and the one-way export send nested attachments. An
  absent or partial attachment at any level refuses the transfer before any byte
  is sent.
- The receiver accepts nested attachments.
- fsck and bucket fsck give a `Partial` finding to an attachment when one of its
  own attachments is absent or partial, at each depth, up to each commit above it.

### CLI

- Breaking: `ostrya fsck --no-mark-dependencies` is `--no-mark-attachments`, with
  no alias. The help text, the man pages, the fsck lines, and the `ostrya remote
  fsck` error kind say "attachment" and "supplement".
- `ostrya commit --related` accepts an attachment that has attachments of its own.
- `ostrya pull`, `pull-local`, `push`, `send`, `receive`, and `media
  export`/`import` carry the full set of nested attachments of each commit.
- `ostrya fsck` and `ostrya remote fsck` report an attachment as partial when one
  of its own attachments is absent or partial, and mark the commit that names it.
- `ostrya static-delta apply` needs each attachment of the target commit complete,
  at each depth. Apply the deltas of the deepest attachments first.

## [0.12.1] - 2026-11-17

### Library

- Fix: the xattr read unit test of `ostrya` (`repo_fs::read`) fits in one ext4
  xattr block. The test set a value of 3000 bytes and 30 long names on one file,
  and `fsetxattr` gave `ENOSPC` on the ext4 CI runner. The test sets a value of
  1024 bytes. The value still makes both read buffers grow past 256 bytes. The
  library code does not change.

### CLI

- No changes.

## [0.12.0] - 2026-11-17

### Library

- Breaking: `ServerSigner` is removed. Use `ostrya::sign::SigningKey`, which no
  feature gates. New `SigningKey::from_key_group` builds the one `[ex-ostrya key
  "NAME"]` group that it names. `SigningKey::has_signed` is public. The signer
  fields of `ReceivePolicy` and `StreamPolicy` hold `Arc<SigningKey>`. New
  `Repo::has_signed_commit`.
- Breaking: `set_ref_alias_immediate`, `remove_ref_alias_immediate`,
  `UpdateGuard::set_ref_alias`, and `UpdateGuard::remove_ref_alias` take `&Ref`,
  so an alias can be under `refs/mirrors/ID/`. `RefAlias` has the fields `name`,
  `target`, and `body`. The alias listing also reads `refs/mirrors/`.
- Breaking: Each read and write of a repository file applies one set of rules. A
  symlink, a FIFO, a socket, or a device at a repository file or directory gives
  `Error::InvalidFormat` where it gave `Error::Io`. No open blocks on a FIFO. This
  applies to `config`, objects, `tmp/`, `state/`, lock files, refs, summaries,
  static deltas, delta indexes, and composefs images. New `Error::NotARef`.
- Breaking: A ref read refuses a symlink above the ref and a ref file over 4096
  bytes. An alias resolves only to a regular ref file inside `refs/`. A listing
  skips a broken alias. A symlink at `refs/remotes/R` or `refs/mirrors/ID` fails
  each listing, prune, and fsck.
- Breaking: A relative path in `config` resolves against the repository root, and
  in a `.conf` file against its remotes directory. A relative path with a `..`
  component is refused. `resolve_pull`, `resolve_push`, and `resolve_bucket` take
  `Option<&Repo>`. `read_token_file` and `read_pem_file` are private.
  `FromOstreeKeyrings::for_remote_in` takes no keypath, and `for_repo_in` is a new
  required method. In `ostrya-sign`, `GpgVerifier::add_keyring_skipping` replaces
  `add_keyring_files_skipping`.
- Breaking: The `tls_cert`, `tls_key`, and `tls_client_ca` fields of
  `ServerSettings` are `Option<ServerFile>`. New `read_tls_files` reads them with
  a 1 MiB cap. `ClientAccess::from_config` takes no directory argument.
- Breaking: `RemotesDir::Path` refuses a relative path. A remotes directory read
  skips special entries. A `.conf` write replaces a symlink with a regular file.
  An add never replaces an entry. A new remotes directory in a `bare-user-shared`
  repository gets mode 02770.
- Breaking: A symlink or a non-directory at `state/` fails a pull before it stages
  an object and a prune before it removes anything. fsck writes its markers before
  it deletes objects.
- Each ref, summary, config, keyring, and static delta write stages a temp file in
  `tmp/` and syncs it. An object write publishes with `RENAME_NOREPLACE`. Under
  `[core] fsync`, marker, prune, fsck, and `.conf` writes sync their directories.
- New `Repo::read_static_delta`, `Repo::static_delta_part_stats`,
  `Repo::has_static_delta`, and `Repo::ref_path_has_entry`.
- Fix: The receive session reads a ref below a symlink as absent at Hello and
  refuses the commit with `ref-denied`. It ended with an internal error before.

### CLI

- A symlink, a FIFO, a socket, or a device at a repository file or directory stops
  each command with an error. No open waits on a FIFO. `ostrya init` refuses a
  symlink or a non-directory at each layout directory.
- A ref read refuses a symlink above the ref and a ref file over 4096 bytes. A
  listing skips a broken alias.
- `ostrya commit --tag` refuses a symlink at `refs`, `refs/heads`, `refs/mirrors`,
  or `refs/mirrors/ID` before it takes the lock, and writes no object.
- `ostrya refs -A` and `ostrya refs --delete` with no `-c` also read the aliases
  under `refs/mirrors/`.
- A relative path in `config` or in a remotes `.conf` file resolves against the
  repository root or the remotes directory. A `..` component is refused. `ostrya
  serve` reads its TLS files by the same rules, with a 1 MiB cap, and makes each
  `--tls-*` path absolute. `--remotes-config-dir` is made absolute.
- `ostrya remote add` never replaces an entry, and a `.conf` write replaces a
  symlink with a regular file.
- `ostrya static-delta generate` checks that `tmp/` and the delta directory are on
  one file system before it removes an old superblock.
- Fix: A push to `ostrya receive` or `ostrya serve` that names a ref below a
  symlink gets `ref-denied`. It ended with an internal error before.
- `ostrya diff` accepts an xattr name that is not UTF-8. A verification key file
  that is absent gives "does not exist".

## [0.11.2] - 2026-11-13

### Library

- New `ReceiveSelector`, a ref pattern list with `!` exclusions. A build without
  the feature `receive` has `ReceivePattern` and `ReceiveSelector`.
- New `RepoConfig::gc_weak_references` reads `[ex-ostrya] gc-weak-references`. New
  public `PruneOptions::roots_on_refs_alone`. A value with no positive pattern is
  refused.
- New `Remote::push_branches` and `Remote::pull_branches`. `Repo::pull` with no
  ref and no MIRROR flag takes the refs of `branches` and the summary refs that
  `pull-branches` selects.
- `Repo::pull` checks `branches`, `pull-branches`, `[core] fsync`, and `[core]
  per-object-fsync` before it connects.
- New `check_push`, `PushKind`, `RepoPushOptions::check`, `PushSession::check`,
  and `ostrya_fetch::check_options` make the push option checks with no file read
  and no connection.
- New `Repo::list_refs_where` applies a predicate to each ref name before it reads
  the ref file.
- New `Repo::remove_refs_immediate` checks a batch of refs under one update lock
  before the first unlink. New `Repo::remove_ref_alias_immediate` and
  `UpdateGuard::remove_ref_alias`.
- Fix: `Transaction::set_ref`, `Repo::set_ref_immediate`, and
  `UpdateGuard::set_ref` refuse an alias with `Error::RefNotWritable`. A ref write
  or removal refuses a path that passes through an alias. A read still follows an
  alias.
- Fix: `Repo::create` and `create_at` refuse a path that holds an entry `config`
  with `Error::RepoExists`.
- Fix: each ref reader opens a ref file with no wait on a FIFO. A FIFO, a socket,
  or a device file is no ref.

### CLI

- New key `[ex-ostrya] gc-weak-references`. `ostrya prune` makes each selected ref
  weak when the roots are the refs alone. A value with no positive pattern stops
  each prune before it deletes anything.
- New key `[remote "NAME"] push-branches`. `ostrya push REMOTE` with no refspec
  sends the selected refs. `--collection=ID` keeps the local refs and the refs of
  `ID`. The push refuses `--tag` with no refspec.
- New key `[remote "NAME"] pull-branches`. `ostrya pull NAME` with no ref and no
  `--mirror` takes the refs of `branches` and of `pull-branches`. The pull checks
  both keys and the fsync keys before it connects.
- With no `--repo`, a command opens `/ostree/repo` when the current directory and
  `OSTREE_REPO` give no repository.
- Fix: `ostrya init` refuses a path that holds `config` and never writes into
  `/ostree/repo`.
- Fix: `ostrya commit --tag` refuses a ref that another writer makes at the tag
  path during the commit. The branch does not move.
- Fix: a ref write or removal refuses a path that names or passes through an
  alias. `refs --delete` and `refs -c --delete` check each selected ref under the
  update lock first. `refs -A --delete` removes an alias.
- Fix: a ref read does not wait on a FIFO.

## [0.11.1] - 2026-11-11

### Library

- Fix: `Transaction::commit` checks each queued ref path under the update lock
  before it writes the detached metadata and the first ref. A bad path refuses the
  commit with `Error::RefNotWritable`, and no ref changes.
- New `Transaction::set_ref_expecting` queues a ref write that applies only when
  the ref has the expected state. Another state refuses the commit with
  `Error::RefMismatch`.

### CLI

- Fix: a command that writes refs in one transaction checks each ref path first.
  `commit --branch B --tag T` with a directory at the path of `T` no longer moves
  `B`.

## [0.11.0] - 2026-11-10

### Library

- New `Repo::export_media` with `MediaExportOptions` and `MediaExportReport`
  copies collection refs into `MOUNT/.ostree/repo` in the layout of `ostree
  create-usb`. New `SummaryOptions::root_summary_only`.
- New `Repo::import_media` with `MediaImportOptions` and `MediaImportReport` finds
  the media repository on the mounted volumes and pulls the selected collection
  refs. The trust of the matched remote checks each commit. New
  `Error::MediaNotFound` and `Error::AmbiguousMedia`.
- `Repo::list_collection_refs` lists the refs of each remote under its
  `collection-id`. New field `CollectionRefEntry::remote`. A remote with a
  malformed `collection-id` gives no row.
- New claim API in `ostrya::access`: `Claims::rules`, public `Namespace::of`, and
  the read helpers of the rights types.
- A ref path that names a directory or passes through a ref file reads as no ref.
  A ref entry that is a FIFO or a socket is no ref.
- A local pull from an archive repository into an archive repository that cannot
  link a content object copies the `.filez` as it is.
- Fix: an untrusted local pull hashes each commit, dependency commit, and dirtree
  before it uses the bytes, and stages only the hashed bytes.
- Fix: a strict handle opens the payload of a file object, the `.filez` copy, and
  the linked or cloned objects with the strict open. A symlink or FIFO swapped in
  stops the read.

### CLI

- New command `ostrya media export MOUNT [-c ID] REF...` writes collection refs
  onto removable media. `--commit` exports one commit.
- New command `ostrya media import` finds the media repository on the mounted
  volumes, or under `--mount PATH`, and pulls collection refs from it.
- `ostrya refs -c` lists each ref of a remote under the `collection-id` of the
  remote. `refs -c --delete` deletes no ref of a remote.
- `ostrya refs -A --create` reports a ref path that names a directory or passes
  through a ref file as a ref that does not exist.
- Fix: the ref listing of `refs`, `summary -u`, and `serve` does not wait on a
  FIFO.
- Fix: `pull-local --untrusted` and a `file://` candidate of `pull --collection`
  hash each commit and dirtree before they use the bytes.
- Fix: `ostrya-mountd` opens the payload of a file object with `RESOLVE_BENEATH`
  and `RESOLVE_NO_SYMLINKS`.

## [0.10.0] - 2026-11-07

### Library

- Breaking: New `ostrya_core::Ref` (`Local`, `Remote`, `Collection`) reads and
  writes `NAME`, `REMOTE:NAME`, and `@ID:NAME`. New `Ref::validate`,
  `ParseRefError`, `Ref::canonical`, `Ref::namespace`, `Ref::in_collection`,
  `RefNamespace`, `split_collection`, and `is_valid_collection_id`.
  `MAX_COLLECTION_ID_LEN` moves into `ostrya-core`.
- Breaking: The ref store methods (`Transaction::set_ref`,
  `Repo::set_ref_immediate`, `UpdateGuard::read_ref`/`set_ref`,
  `Repo::resolve_ref_tip`) take `&Ref`. `CollectionRef`, the `*_collection_ref*`
  methods, `RefLocation`, and `PullOptions::collection_id` are removed.
  `resolve_rev` reads `@ID:NAME[^...]`.
- Breaking: The own collection id is the local namespace. `@OWN:NAME` writes
  `refs/heads/NAME`. Resolve, listing, summary, bucket summary, and S3 push ignore
  `refs/mirrors/OWN/`. Fsck gives a note for each ref there, and prune keeps its
  commit.
- Breaking: `PruneOptions::only_branch` and `retain_branch_depth` take `Ref`
  values. `Repo::prune` reads each value as a ref before the lock.
  `WeakRefFilterFn` takes `&Ref`. `PruneStats` has one `deleted_refs: Vec<Ref>`.
- Breaking: The push protocol carries `@ID:NAME` for each ref. `Hello`,
  `HelloReply`, and `ReceiveReport` have no collection field. The receive hooks
  take `ReceiveRefUpdate` and `ReceiveServerCommit`, and `ReceiveService::commit`
  returns `ReceiveCommit`. The push options take typed `Ref` values. New option to
  skip the ref-binding check (`disable-verify-bindings`).
- Breaking: Access rules are per namespace. Group items take
  `[MODES:]@ID:PATTERN`, and claims take `ostrya:ref:[MODES:][@ID:]PATTERN`.
  `CollectionScope` and `ClientGroup::scope`/`ReceivePolicy::scope` are removed.
  `rules` is `NamespaceRules`. The implicit group is `anonymous` alone.
- Pull from a named remote takes `@ID:NAME` refs of more than one collection. A
  mirror pull writes refs under the collection id of the summary. Pull and local
  pull refuse two names that write one ref.
- Breaking: New `OpenOptions` and `RemotesDir`. The open reads remotes from the
  `.conf` files of a remotes directory, and the update guard writes new remotes
  there. New `UpdateGuard::replace_remote`, `Remote::source`, and
  `Repo::remotes_dir`. `CreateOptions` fields are private. Use
  `CreateOptions::new` and `CreateOptions::collection_id`.
- Breaking: Remote GPG keyrings come from the repository, then from the remotes
  directory of the handle. The port does not read `/etc/ostree/remotes.d` for each
  repository. New `FromOstreeKeyrings::for_remote_in`. `for_remote` and
  `for_remote_keypath` are removed. `gpg_offered_keys` and `Repo::gpg_import_keys`
  take `&[&[u8]]` and decode each stream as binary or armored.
- Breaking: The composefs image is the file `extensions/ostrya/composefs/<aa>/<62
  hex>.cfs` and stays local. No transfer carries it. `ObjectType::ComposefsImage`
  and `BucketFsckReport::orphan_images` are removed. New
  `Error::ComposefsImageNotFound`. Prune and fsck delete the image of a deleted
  commit.
- Breaking: With `[ex-ostrya] generate-composefs` true, each writer builds and
  checks the image of each complete commit with `ostree.composefs.digest.v0`. New
  `Repo::seals_objects` and `FsckReport::missing_images`.
- Fix: A receive gives `protocol` for a malformed composefs digest key and
  `checksum-mismatch` for a wrong digest. The server commit builds the image after
  the `before_server_commit` hook.
- Fix: The push refuses a ref that maps to a 64-hex local name. A one-way receive
  with no own collection id skips the local ref collection check. The archive view
  serves no file under `refs/mirrors/OWN/`.

### CLI

- New global option `--remotes-config-dir`. The command reads and writes remotes
  in `NAME.conf` files of the remotes directory. The system repository uses
  `/etc/ostree/remotes.d`. `init --remotes-config-dir` writes the key.
- `remote add` writes `NAME.conf` unless `[core] add-remotes-config-dir` is false.
  `remote add --force` and `remote delete` edit the file that holds the remote.
  `remote add` takes `--mirrored-collection-id`.
- Breaking: Remote GPG keys come from `NAME.trustedkeys.gpg` of the repository,
  then of the remotes directory. `remote gpg-import` reads a mix of binary and
  armored `-k` files and refuses key input over 4 MiB.
- Revisions, `commit -b`/`--tag`, `refs --create`/`--delete`/listing, `prune
  --only-branch`/`--retain-branch-depth`, `pull`, `pull-local`, `push`, `push
  --onto`, `push-tree`, and `send` take `@ID:NAME`. The own collection id names
  `refs/heads`.
- Breaking: `refs -c`, `summary -u`, and `serve` ignore `refs/mirrors/OWN/`.
  `fsck` prints a line for each ref there.
- `pull --mirror` writes refs under the collection id of the summary. `pull
  --collection=ID` selects remotes by `collection-id` or
  `mirrored-collection-ids`.
- Fix: `pull` and `pull-local` refuse two operands that write one ref. `refs
  --delete` refuses an `@ID:` prefix with an empty rest and checks each name
  before the first delete. `prune --only-branch` refuses a checksum and `main^`.
- New `--disable-verify-bindings` for `push`, `send`, and `receive`, and the
  client group key `disable-verify-bindings`. `receive --one-way` takes
  `--allow-collection=ID`.
- Breaking: Client group items take `@ID:PATTERN`, and the key `collection` is
  refused. Claims take `ostrya:ref:[MODES:]@ID:PATTERN`. `serve` refuses an
  `ostrya:collection:` certificate with 403.
- Breaking: The composefs image is in `extensions/ostrya/composefs/` and no
  transfer carries it. With `generate-composefs` true, `commit`, `pull`,
  `pull-local`, `receive`, `serve`, and `static-delta apply-offline` build and
  check the image. `fsck` checks each image, and `--delete` removes a faulty one.
- Fix: `pull` and `pull-local` write the unsealed-objects warning after a complete
  pull.
- `ostrya-mountd` reads images from `extensions/ostrya/composefs/` with `openat2`
  and needs a kernel with `openat2`.

## [0.9.0] - 2026-11-04

### Library

- Breaking: `Transaction::set_collection_ref`,
  `Repo::set_collection_ref_immediate`, and the `UpdateGuard` collection ref calls
  refuse a collection id that fails `is_collection_id` or is longer than 255
  bytes. `pull_local` with a collection id applies the same check.
- New `Repo::resolve_collection_ref` and `Repo::list_collection_refs_in`. Under
  the own collection id, the mirror ref wins over `refs/heads/NAME`.
- New `Repo::remote_list_collection_refs` and `remote_list_collection_refs_with`:
  list the refs of a collection on one remote, through the listing, the summary,
  an S3 bucket, or a `file://` remote.
- Breaking: `Repo::remote_list_collection_refs_with` takes an `on_event` callback.
  The probe skips a listed ref name that fails the ref-name rule and sends
  `CollectionPullEvent::RefSkipped`.
- `Repo::pull_collection` takes `file://` candidates and reads them as local
  repositories. When the trust of the remote checks signatures, the pull hashes
  each imported object.
- New `CollectionPullOptions::allow_unbound` passes a tip with no
  `ostree.collection-binding` key. New `CollectionPullStats::local` holds the
  counts of the `file://` runs.
- `Repo::pull_local` with `PullOptions::collection_id` writes collection refs and
  refuses a tip with an absent or a wrong collection binding.
- Breaking: `WeakRefFilterFn` and `WeakRefFilter::new` take `Fn(RefLocation<'_>,
  &Checksum) -> bool`. Prune sends collection refs to the weak ref filter. New
  `PruneStats::deleted_collection_refs`.
- New `CollectionRef::validate`.
- New `Ed25519Signer::public_key`. A valid ed25519 signature gives the
  `fingerprint` of its key in `SignatureInfo`.
- New `GpgVerifier::with_ignore_time` skips the time checks. New
  `GpgSigner::export_public` exports the public certificate of the key.
- New `Command::output_capped` in `ostrya-rt`.
- Fix: a collection pull under the own collection id writes
  `refs/mirrors/OWN/NAME` when the resolve reads that file, and `refs/heads/NAME`
  otherwise.
- Fix: `Command::output` and `Command::output_capped` kill the child process when
  the caller drops the run.
- Fix: a GPG keyring import reads the clock one time, so an expiry between two
  reads gives no mixed state.

### CLI

- `ostrya pull --collection` takes a remote with a `file://` `pull-url` or `url`
  as a local repository candidate. It hashes each imported object when the keys of
  the candidate check signatures.
- `ostrya pull --collection` skips a listed ref name that fails the ref-name rule,
  with a warning.
- Fix: `ostrya pull --collection` prints the HTTP statistics line and then the
  `pull-local` line when it fetches and imports objects, and the `pull-local` line
  when it only imports.
- Fix: `ostrya refs -c --delete` checks each ref before it deletes a ref, and
  refuses a local name with `:`.

## [0.8.0] - 2026-11-02

### Library

- Breaking: `Error::TarPathname` is removed. A tar member with a text field that
  is not valid UTF-8 fails with `Error::Io` (`smol-tar` 0.2.0).

### CLI

- The tar import fails with an I/O error on a member text field that is not valid
  UTF-8.

## [0.7.0] - 2026-11-02

### Library

- Breaking: new public field `FsckOptions::mark_dependencies` (default `true`)
  controls the partial marks of the dependency check. `mark_partial` controls the
  marks for missing and deleted objects.

### CLI

- `ostrya fsck` accepts `--no-mark-dependencies`.

## [0.6.0] - 2026-11-01

### Library

- New feature `s3` of `ostrya` and `ostrya-remote`: pull from and push to a bucket
  repository at an `s3://` address. `ostrya-remote` adds `s3::SigV4`,
  `s3::resolve` (AWS environment and shared files), `s3::Bucket` with multipart
  `put_stream`, and `scan_tree`. `ostrya` adds the `bucket` module: `BucketRepo`
  with `init`, `push_tree`, `fsck`, `prune`, and `update_summary`, a writer lock
  (`WriterLock`), and `Repo::push_to_bucket`. `Repo::pull_collection` accepts S3
  remotes.
- Breaking: `ostrya-fetch` adds `UploadMethod::Put`, the `RequestSigner` hook
  (`FetcherOptions::signer`), and `FetchRequest::max_error_body`.
  `Error::HttpStatus` has the new field `response`. `transport::Endpoint` is
  `#[non_exhaustive]` and has the variant `S3`. `EndpointOverrides` and
  `RepoPushOptions` have new public fields.
- Breaking: the spki engine signs and verifies RSA PKCS#1 v1.5, ECDSA P-384, and
  Ed25519 keys, and selects the key type from the OID. It reads key files as PEM
  `PUBLIC KEY` and `PRIVATE KEY` blocks and refuses base64-line key files, raw
  P-256 scalars, raw SEC1 points, and `r || s` signatures.
- New X.509 support behind `sign-x509`: the trait `X509Signer`,
  `SpkiSigner::with_certificates`, and `SpkiVerifier::from_certificates`.
- Breaking: `Verifier::verify` is synchronous, and `VerifyFuture` is removed. The
  GPG verifier moves to `ostrya-sign` behind the feature `gpg`, with the trait
  `FromOstreeKeyrings`. The `ostrya-sign` features are `spki`, `gpg`, `gpg-sign`,
  and `x509` (`sign-spki` and `sign-gpg` are renamed).
- Commit dependencies: `CommitOptions::related` writes field 2 of a commit. New
  `Repo::read_commit_related`, `Transaction::check_related`,
  `Transaction::write_commit_checked`, and `add_detached_related` for build
  sources (`ostrya.related`). Breaking: `CommitOptions` has the new field
  `related`.
- Pull, pull-local, push, the one-way stream, receive, and static delta apply
  carry or check the dependencies of each commit. A defective or nested dependency
  gives `Error::InvalidRelated`.
- Breaking: prune roots on field 2 and `ostrya.related`, and `PruneStats` has the
  new field `warnings`. The GC anchor keys are removed:
  `PruneOptions::gc_root_metadata_keys`, `PruneOptions::gc_roots`,
  `RepoConfig::gc_root_metadata_keys`, and their errors.
- Breaking: fsck reports dependency errors in the new field
  `FsckReport::dependency_errors`.
- Breaking: the config key `[ex-ostrya] detached-metadata-exclude` and
  `DetachedMetadataFilter` are removed. The new key `keep-detached-related`
  (`RepoConfig::keep_detached_related`) controls if a transfer stores
  `ostrya.related`.
- Breaking: `Repo::pull_local` reads the verification keys of the `[remote
  "NAME"]` section that `PullOptions::remote` names.
- A remote with `trust=NAME` takes its commit keys from `[ex-ostrya trust
  "NAME"]`. New `PullOptions::trust_group` and `TrustedKeys::from_trust_group`.
- `ReceiveHooks::before_server_commit` lets a host accept a server commit. New
  `Repo::receive_stream_to_commit` and `Repo::export_updates`. New
  `PushProgress::start_phase`.
- The fetcher reaches an origin through a `socks5://` or `socks5h://` proxy.
- Fix: the GPG keyring functions refuse an invalid remote name before they read or
  write a keyring path. A `gpgkeypath` directory gives each regular file,
  `gpgkeypath` is read raw, and the global trusted directory is a fallback. New
  `GpgVerifier::add_keyring_files_skipping`, `add_binary_keyring`, and
  `add_binary_keyring_files`.
- Fix: a failed pull waits for its blocking jobs before the cleanup.

### CLI

- New S3 support (feature `s3`, in the default set): `push`, `push-tree`, `pull`,
  `remote refs`, and `remote summary` take `--s3-region`, `--s3-endpoint`,
  `--s3-addressing`, and `--s3-profile`. `push` takes `--break-lock`. `remote add
  NAME s3://...` writes `pull-url` and `push-url`.
- New commands `ostrya remote init`, `ostrya remote fsck`, `ostrya remote prune`,
  and `ostrya remote summary -u` for a bucket repository.
- Breaking: the spki engine accepts RSA, P-384, and Ed25519 keys, and reads key
  files as PEM blocks. Raw spki key forms and `r || s` signatures are refused.
- Breaking: `--sign-type` applies to the keys after it, and a `--sign-type` with
  no key is refused. `sign -d/--delete` is removed.
- `commit` takes `--related=NAME=CHECKSUM`. Pull, push, receive, and static deltas
  carry the dependencies. `prune` keeps related commits, and `fsck` reports
  dependency errors.
- Breaking: the config keys `gc-root-metadata-keys` and
  `detached-metadata-exclude` are removed. The new config key
  `keep-detached-related` is added.
- `pull-local` reads the verification keys of the remote and takes
  `--sign-verify`, `--sign-verify-summary`, `--no-gpg-verify`,
  `--no-gpg-verify-summary`, `--no-sign-verify`, `--no-sign-verify-summary`, and
  `--trust`.
- `send --one-way` and `receive --one-way` are added.
- A pull reaches an origin through a `socks5` or `socks5h` proxy.
- Fix: a verify with no key skips an engine that finds no signature. `sign` and
  `summary` refuse a gpg `--keys-file` that names no file, `--keys-dir` where no
  key directory is read, and `--gpg-homedir` in a verify. `commit` checks
  `--sign-type` before it reads the tree.
- Fix: `show --gpg-verify-remote` checks the remote and reads its `gpgkeypath`.

## [0.5.0] - 2026-10-19

### Library

- Breaking: New object type `ObjectType::ComposefsImage` (type 100,
  `objects/<xx>/<commit>.cfs`) holds the composefs image of a commit that records
  `ostree.composefs.digest.v0`. The store seals it under `[ex-integrity]` fsverity
  and installs it only when its digest equals the key. `ObjectType` is
  `#[non_exhaustive]`.
- Breaking: Prune removes the image with its commit and removes orphan images.
  Fsck checks each image. `FsckReport` gains `images_checked`, `image_errors`, and
  `orphan_images`.
- Breaking: Pull (local, HTTP, stream), push, the one-way stream, and the archive
  view carry the `.cfs` image. Each receiver checks the digest. `Have` and
  `ObjectHeader` accept type 100, so an older receiver refuses a push that carries
  an image.
- Breaking: A static delta carries the image of its target commit as a type 100
  item. An older reader refuses such a delta. A fallback image is optional for a
  pull and for offline apply.
- New crate `ostrya-mount`: `Direct` mounts a commit as composefs (loop device,
  EROFS, overlayfs), read-only or read-write. `Helper`, the `Mounter` enum, and
  the feature `server` support the `ostrya-mountd` daemon.
- New `Repo::objects_dir`, `Repo::open_composefs_image_checked`, and a strict open
  mode for a repository opened for another user. `ostrya-sys` gains loop device,
  sealed memfd, namespace, idmapped `mount_setattr`, `SO_PEERGROUPS`, and systemd
  socket handover helpers.
- Breaking: The root summary holds each local ref and each collection ref with the
  real mode, and the archive view never serves it. The anonymous item gets its own
  summary under `extensions/ostrya/summary/`.
- Breaking: New field `SummaryOptions::auth_items_only` writes the summaries of
  the auth items alone.
- The summary of each auth item and the ref listing state `archive-z2`. Outside
  archive mode they name no static delta and no `indexed-deltas` key.
- Fix: A mirror pull keeps the summary of the anonymous item served.
- Fix: A plain HTTP serve starts next to an HTTPS serve of one repository. A
  `tls:` or `tls-sha256:` item on a server with no client CA matches no request.

### CLI

- `ostrya commit --generate-composefs` stores the composefs image with the commit.
  New `ostrya composefs-image` adds, locates, and checks the image of a commit.
- `ostrya prune` and `ostrya fsck` handle images. `pull`, `push`, `send`, `serve`,
  and `static-delta` carry the image.
- `ostrya summary -u` writes each ref into the root summary and writes the summary
  of the anonymous item. New `ostrya summary -c/--client-groups` (needs `-u`)
  writes the summaries of the auth items alone.
- Fix: `ostrya serve` keeps the anonymous summary served after a mirror pull.
- Fix: A plain HTTP `ostrya serve` starts next to an HTTPS serve. It ignores the
  `tls-client-ca` key when it has no `tls-cert` and no
  `trusted-proxy-client-cert`.
- New daemon `ostrya-mountd` mounts the composefs image of a commit for an
  unprivileged caller in its own user namespace. It supports systemd socket
  activation and `--listen`, and has the man page `ostrya-mountd(8)`.
- New Debian package `ostrya-mountd` from its own source package. The `ostrya`
  package adds the template unit `ostrya-serve@.service` and the sysusers.d file
  of the user `ostrya`.
- New NixOS module `services.ostrya-mountd`. `nixosModules.default` imports the
  serve and mountd modules.

## [0.4.0] - 2026-10-18

### Library

- New client access model: `[ex-ostrya server]` and `[ex-ostrya client "NAME"]`
  groups give auth items, collection scopes, and allow and deny rules
  (`ClientAccess` in `ostrya-core`). `is_collection_id` moves into `ostrya-core`.
- Breaking: A push checks the rights of its client group (`r`, `w`, `t`, `d`,
  force, verify, `allow-unsigned`, sign, `allow-privileged`). The `[ex-ostrya
  receive]` groups, `verify=remote:NAME`, and the policy file are removed.
  `Repo::receive_stream` takes a `StreamPolicy`.
- Breaking: `ostrya-server` identifies a client by an auth item: bearer token,
  Basic credentials, client certificate, peer network, or anonymous. The push
  credential file, `ServeOptions::allow_anonymous_push`, and `Error::Credentials`
  are removed. Receive takes `ReceivePolicies`.
- Breaking: Each read checks the `r` right of the client. `ArchiveView::get`,
  `ArchiveView::head`, `Repo::send`, `Repo::send_capped`, and
  `Repo::build_ref_listing` take a `ReadAccess`.
- With `tls-accept-claim=true`, the server reads access claims from the URI SANs
  of a client certificate. New `Claims`, `ClientAccess::claim_rules`, and
  `ServeOptions::on_event`.
- Breaking: The server works behind a proxy: PROXY protocol v1 and v2,
  `trusted-proxy-header`, and `trusted-proxy-client-cert`. `ServerSettings` gains
  `trusted_proxy_header`. `ServerTls::client_ca_pem` moves to `ServeOptions`.
- Breaking: A push goes into a collection namespace. `Hello`, `HelloReply`,
  `SessionOptions`, `ServerInfo`, `ReceivePolicy`, `ReceiveReport`, and
  `RepoPushOptions` gain fields.
- Breaking: The ref listing takes a collections selector and lists collection
  refs. `Repo::build_ref_listing` returns `RefListing`, and `Message::ListRefs`
  holds `ListRefsRequest`. New `ServerEvent::InvalidCollectionDir`.
- New `Repo::pull_collection` pulls the newest commit of each ref from the remotes
  of a collection.
- Breaking: The server builds and signs a commit from a pushed tree
  (`CommitRequest::server_commit`). New `Repo::push_onto`. `ParentPolicy`,
  `TreeModel::set_commit`, `Error::Sign`, and several `TreePushOptions` fields are
  removed. `ostrya-remote` does not depend on `ostrya-sign`. The container
  variants of `ostrya_gvariant::Type` take `ElementType` and `MemberTypes`.
- Breaking: Summary writes a summary for each auth item under
  `extensions/ostrya/summary/`. `ReadAccess::serves_summary` is removed.
  `ArchiveAnswer`, `ArchiveHead`, `ServerEvent`, and `SendEvent` gain
  `StaleSummary`. A summary over 64 MiB is refused.
- Breaking: `Repo::prune` reads `[ex-ostrya] gc-root-metadata-keys` itself. An
  anchor value can be `aay`, `a(say)`, or `a{s(say)}`. The prune walk pushes each
  anchor one time.
- `Transaction::write_commit`, `Transaction::commit`,
  `Repo::write_commit_detached_metadata`, and
  `Repo::commit_add_composefs_metadata` refuse a bad GC anchor value with
  `Error::InvalidGcAnchor`.
- Fix: A config integer with a leading plus sign, such as `+101`, is refused.
- Summaries, ref listings, and protocol frames use less memory and I/O.

### CLI

- Breaking: `ostrya serve` reads `[ex-ostrya server]`, and each option overrides
  its key. `--read-only`, `--push-credentials`, `--allow-anonymous-push`, and
  `--policy` are removed. `--client-ca` becomes `--tls-client-ca`.
  `--allow-cleartext-credentials` takes an optional BOOL.
- `ostrya serve` identifies clients by token, Basic credentials, client
  certificate, or network, reads certificate claims, and works behind a proxy with
  the PROXY protocol and forwarded headers.
- `ostrya receive` and `ostrya send` take `--client NAME` (default `LOGNAME`) and
  apply the client groups.
- `ostrya push` pushes into the collection namespace of the commit bindings. New
  `ostrya push --tag`.
- Breaking: `ostrya push --onto` and `ostrya push-tree` ask the server to build
  the commit. `push-tree` loses `-b`, `--parent`, `--sign*`, `--gpg-sign`,
  `--gpg-homedir`, `--add-detached-metadata-string`, `--force`, and
  `--no-bindings`.
- New `ostrya pull --collection ID [REF]...`.
- New `ostrya commit --tag NAME` binds a name and creates its ref.
- `ostrya summary -u` writes a summary for each auth item. New `ostrya summary
  --auth-group=NAME`.
- `ostrya prune` accepts named GC anchors. `ostrya commit` refuses a bad value of
  a GC anchor key.
- New man pages `ostrya-repo(5)` and `ostrya-config(1)`.
- New NixOS module `services.ostrya-serve.instances.<name>` runs one or more
  `ostrya serve` instances.

## [0.3.1] - 2026-10-14

### Library

- No changes.

### CLI

- New man pages of the `ostrya` command. The Debian package and the Nix package
  install them.
- New Debian package `ostrya`.
- Each help item gives a short line for `-h` and a long text for `--help`.
- `--help` wraps to the width of the terminal.

## [0.3.0] - 2026-10-13

### Library

- New published crates: `ostrya-sign` (signing engines), `ostrya-fetch` (HTTP
  fetcher with its own `Error`), `ostrya-remote` (wire protocol, push, receive,
  pull over ssh), and `ostrya-server` (HTTP server). `ostrya` re-exports them as
  `ostrya::fetch` and `ostrya::remote` and at the old item paths.
- New push: `Repo::push`, `Repo::push_over_stream`, `push_tree`, and `PushSession`
  over ssh and HTTP, with `Endpoint`, `SshAddress`, `SshOptions`, and
  `PushProgress`. A push refuses a target ref of 64 hex characters.
- New receive side: `Repo::receive`, `ReceiveService`, `ReceivePolicy` from
  `[ex-ostrya receive "PATTERN"]`, `[ex-ostrya trust "N"]`, and `[ex-ostrya key
  "N"]` groups, `ServerSigner`, and `ReceiveHooks` with `before_update` and
  `after_update`.
- New one-way transfer: `Repo::export_stream` and `Repo::receive_stream`.
- New `ostrya-server`: `ArchiveView` over HTTP/1.1 and TLS with h2, the receive
  endpoint `/_ostrya/receive/v1/` (`ReceiveEndpoint`, `ReceiveAuth`, `FileAuth`),
  and the ref listing `/_ostrya/refs/v1`.
- New pull over ssh and caller sessions: `Repo::send`, `PullSession` (HTTP or
  `StreamSession`), `Repo::pull_with_session`, `PullTrust`, and the module
  `ostrya::verify`. `Repo::pull` reads an ssh `pull-url` and the `ssh-command` and
  `send-command` keys.
- New module `ostrya::endpoint` with `resolve_pull` and `resolve_push`. Breaking:
  `PullOptions::overrides` replaces `url`, `http_headers`, `n_network_retries`,
  `low_speed_limit_bytes`, and `low_speed_time`.
- New `PullOptions::static_deltas` applies a chain of static deltas in a remote
  and a local pull. New `Summary::static_deltas`, `AdvertisedDelta`,
  `Repo::build_ref_listing`, and `PullSession::fetch_refs`.
- New `PullOptions::no_ref_writes`. `Repo::pull_local` resolves collection refs
  with `PullOptions::collection_id` and takes the GPG and static-delta switches.
  The HTTP pull reads the remote `proxy` key.
- New `RefPattern`, `RefSelector`, and `Error::InvalidRefPattern`. Breaking: the
  ostree ref-name rule applies to every ref name in each write, resolution, pull,
  push, and listing.
- Breaking: each writer of refs, config, keyrings, summary, and detached metadata
  takes `.update.lock` and can return `Error::LockTimeout`. New
  `Repo::begin_update` and `UpdateGuard` with `add_remote`, `set_remote_key`,
  `unset_remote_key`, and `delete_remote`.
- Breaking: `lock-timeout-secs=-1` waits with no limit, and a value below -1 is
  refused.
- New `Error::InvalidInput`, `Error::RemoteExists`, `Error::RemoteNotFound`,
  `valid_remote_name`, `KeyFile::set_string_list`, `ComposefsOptions::RECORDED`,
  `ostrya_rt::FileReader`, and `ostrya_gvariant::validate`.
- New `Fetcher::upload`, `Fetcher::counted`, and the `FetcherOptions` fields
  `bearer_token` and `allow_cleartext_credentials`. The `Debug` output of fetcher
  types redacts header values and URL secrets.
- `pull_local` reads the dirtrees that the destination holds from the destination,
  and fails on a child that no source holds.
- Fix: prune removes doomed commits before their content, so an interrupted prune
  leaves no complete-looking commit with a partial tree.
- Fix: ref files, aliases, `.commitmeta`, and `.tombstone-commit` are written as
  temp files in `tmp/`.
- Fix: the pull refuses a depth below -1, an invalid `PullOptions::remote`, and a
  deflate payload shorter than its header states.
- Fix: the fetcher refuses a proxy variable with white space around its value.
- Fix: the composefs writer refuses a child name that is empty, `.`, `..`, longer
  than 255 bytes, or holds `/`.
- Fix: the futures of `import_tar` and `import_tar_into` are `Send`.

### CLI

- New `ostrya push REMOTE REFSPEC...` over ssh and HTTP, with `--depth`,
  `--force`, `--compress`, `--ssh-command`, `--receive-command`, and the
  `push-token-file`, `push-user`, and `tls-*` keys. It draws a progress bar on a
  terminal.
- New `ostrya push-tree REMOTE DIR -b REF...` pushes a directory tree as a new
  commit.
- New `ostrya receive` with `--policy`, and new `ostrya send`, which serves a pull
  session over standard input and output.
- New `ostrya serve` with `--read-only`, and with `--policy`,
  `--push-credentials`, `--allow-anonymous-push`, `--allow-cleartext-credentials`,
  `--session-timeout`, `--max-sessions`, and `--parallel-uploads` for the receive
  endpoint.
- `ostrya pull`, `remote refs`, and `remote summary` read a remote with an ssh
  `pull-url`. The HTTP pull reads the remote `proxy` key.
- `ostrya pull-local` takes `--gpg-verify`, `--gpg-verify-summary`,
  `--require-static-deltas`, and `--disable-static-deltas`.
  `--require-static-deltas` refuses a commit that no usable delta produces.
- Breaking: each command refuses a ref name outside the ostree ref-name rule.
- `ostrya commit` looks up a GPG key from `--sign` or `--sign-from-file` and signs
  by its fingerprint.
- Fix: `config set`, `config unset`, `remote add`, and `remote delete` edit the
  config under the update guard, so no edit of another writer is lost.
- Fix: `ostrya pull` and `ostrya pull-local` refuse `--depth` below -1.
- Fix: `ostrya prune` removes doomed commits before their content.

## [0.2.8] - 2026-09-26

### Library

- Fix: With `fsverity=yes`, an unprivileged write of a content object with no
  owner-write bit fails no more with `EACCES`. The write seals the object first
  and then applies the logical mode and owner. With `fsverity=maybe`, such objects
  get the seal.
- Fix: The bare write path and the faithful checkout copy apply the owner, then
  the xattrs, then the mode, so a file capability (`security.capability`)
  survives.

### CLI

- Fix: Commands that write objects into a repository with `fsverity=yes` seal
  objects with a read-only logical mode. File capabilities survive a bare write
  and a checkout copy.

## [0.2.7] - 2026-09-26

### Library

- Breaking: `DeltaOptions` gains `superblock_file`, `signers`, `inline`, and
  `endianness`. Static deltas can hold inline parts and use big-endian byte order.
  Apply, pull, and show read inline parts.
- Breaking: `PullOptions` gains `disable_fsync`, `per_object_fsync`, `subpaths`,
  `low_speed_limit_bytes`, `low_speed_time`, and `progress`. `FetcherOptions`
  gains `low_speed`. `PullStats` gains the transfer counters and `elapsed`.
- A pull fetches a failed body again from the start, and takes no static delta for
  a commit that is present.
- New `Repo::delete_static_delta` and `Error::StaticDeltaNotFound`. New
  `DeltaSuperblock::verify`, which `Repo::verify_static_delta` calls.
- Delta and delta-index files get mode 0644 whatever the umask.
- A transaction start removes the aged top-level `tmp/` entries after
  `tmp-expiry-secs`.
- The static-delta scan does not follow a symlink below `deltas/`.
- Fix: The prune delta sweep does not delete files outside the repository through
  a symlink, and removes a delta directory that holds a subdirectory.
- The composefs digest reads the kernel fs-verity digest of a sealed object and
  does not stream its payload.

### CLI

- `pull` accepts `--subpath`, `--untrusted`, `--http-trusted`, `--disable-fsync`,
  `--per-object-fsync`, `--low-speed-limit-bytes`, `--low-speed-time-seconds`,
  `--disable-retry-on-network-errors`, and `--update-frequency`. `pull-local`
  accepts `--disable-fsync` and `--per-object-fsync`.
- `pull` prints the statistics line and draws a progress line on a terminal.
- `static-delta generate` accepts a positional `TO`, `--empty`, `-n`,
  `--filename`, `--inline`, `--set-endianness`, and `--swap-endianness`. It reads
  size options in decimal megabytes and uses the parent of `TO` as the default
  source.
- New `static-delta verify` and `static-delta delete`.
- `static-delta apply-offline` accepts a superblock path, a positional `KEY-ID`,
  `--sign-type`, `--keys-file`, and `--keys-dir`. `static-delta reindex` accepts
  `--to=REV`.
- `static-delta list` prints `(No static deltas)` for an empty repository.
- `sign --verify` and `summary --verify` read keys with the key rules of
  `static-delta verify`.

## [0.2.6] - 2026-09-24

### Library

- `Repo::export_composefs` and `Repo::export_composefs_to` export from every
  repository mode.
- New public `DeltaSuperblock`, `DeltaPart`, `DeltaFallback`,
  `DeltaSuperblock::part_stats`, `Repo::list_static_delta_indexes`, and
  `static_delta_relative_dir`. `offset_size_for` is public in `ostrya-gvariant`
  and `ostrya-core`.
- Breaking: `SummaryOptions` gains `additional_metadata`. New
  `Repo::sign_summary_all`, which writes `summary.sig` once for all signers.
- New `Summary::parse_metadata`, which decodes the metadata dict without the ref
  list. New `tuple_field_from_bytes` in the codec.
- New `Repo::diff`, `DiffSide`, `DiffOptions`, `Repo::diff_stats`, and
  `DiffStats`. A diff side can be a directory on the filesystem.
- Breaking: `Repo::diff_commits` gives its entries in walk order, not in three
  sorted lists.

### CLI

- New `static-delta show` and `static-delta indexes`.
- `summary` accepts `--sign`, `-m/--add-metadata`, and `--gpg-sign`.
- `summary` accepts `-v/--view`, `--raw`, `--list-metadata-keys`, and
  `--print-metadata-key`.
- Breaking: `summary -v` means `--view`. Use `--verbose` for verbose output.
- Breaking: `summary --sign-type` refuses an unknown name at exit 1, not exit 2.
- `diff` accepts `--stats`, `--fs-diff`, `--no-xattrs`, `--owner-uid`,
  `--owner-gid`, one argument, and a directory as a side.
- Fix: `summary` and `remote summary` print a string value with no label in
  quotes, as the tool does.

## [0.2.5] - 2026-09-22

### Library

- Breaking: `Repo::prune` holds the repository lock exclusive for the whole run
  and fails with `Error::LockTimeout`. A shared and an exclusive acquire exclude
  each other in the process.
- Breaking: `PruneOptions` gains `keep_younger_than`, `only_branch`,
  `retain_branch_depth`, `commit_only`, `static_deltas_only`, and
  `weak_ref_filter`. `PruneStats` gains `deleted_refs` and is no longer `Copy`.
- A prune with `weak_ref_filter` can delete local and remote refs that the
  classifier calls weak.
- A prune writes a `.tombstone-commit` object under `[core] tombstone-commits`,
  and removes a static delta whose target commit it deletes.
- Breaking: A negative prune depth other than -1 keeps the head alone.
- Breaking: `FsckOptions` and `FsckReport` gain fields. `Repo::fsck` runs four
  phases. New `FsckBindingError`, `FsckBindingErrorKind`, `FsckFailure`,
  `FsckPhase`, and `Repo::list_collection_refs`.

### CLI

- `prune` accepts `--keep-younger-than`, `--static-deltas-only`,
  `--retain-branch-depth`, `--only-branch`, and `--commit-only`, and prints the
  totals.
- `prune` writes a warning to standard error when `[core] locking` is false.
- `fsck` accepts `--add-tombstones`, `-q/--quiet`, `-a/--all`, `--delete`,
  `--verify-bindings`, and `--verify-back-refs`, and writes the output of the
  tool.
- `checkout` takes the fsync policy from `[core] fsync`, narrowed by `--fsync`.

## [0.2.4] - 2026-09-17

### Library

- In `bare-user-shared`, the port forces mode 02770 on the directories it creates,
  0660 on lock files, and 0644 on `.commitpartial`, whatever the umask.
- Breaking: `CheckoutOptions` gains `require_hardlinks` and `bareuseronly_dirs`.
  `OverwriteMode::UnionIdentical` needs `require_hardlinks` and excludes
  `force_copy`.
- A checkout does not hardlink a zero-length regular file.
- Breaking: `CheckoutOptions.filter` gets a call for the checkout root and before
  the whiteout verdict, and no call for the object of a file subpath.

### CLI

- `checkout` accepts `-H/--require-hardlinks`, `-M/--bareuseronly-dirs`, and
  `--disable-cache`.
- `checkout` accepts `--skip-list`, `--from-stdin`, and `--from-file`.
- A group member can write to a `bare-user-shared` repository that another member
  created.

## [0.2.3] - 2026-09-15

### Library

- New `Repo::path`, `MergeOptions::symlink_target_dirmeta`,
  `MutableTree::subtree`, and `Repo::metadata_reader`.
- Breaking: `RepoTree::lookup` refuses a `..` component.
- Breaking: `StagingTree::make_dir_all` refuses a symlink at the final component.
- docs.rs builds the `ostrya` documentation with the signing and verification
  features.

### CLI

- `ls`, `cat`, `checkout --subpath`, and the tar export subpath refuse a `..`
  component.
- A Nix flake builds the `ostrya` binary.

## [0.2.2] - 2026-09-11

### Library

- Breaking: `FetcherOptions` gains `max_redirects`. The fetcher follows redirects
  and sends credentials and the client certificate to the first origin only.
- Breaking: `FetcherOptions` gains `proxy`. The fetcher reaches an origin through
  an HTTP proxy and reads the proxy environment variables by default.
- Breaking: `FetchRequest::new` is now `FetchRequest::path`. A request can name an
  absolute URL and carry its own headers and credentials.
- Breaking: `ClientIdentity` gains `key_passphrase`, which decrypts an encrypted
  PKCS#8 client key.
- Breaking: `TrustRoots` is `#[non_exhaustive]` and gains
  `DangerousAcceptAnyChain` and `DangerousAcceptAny`. `tls-permissive=true` maps
  to `DangerousAcceptAnyChain`.
- The fetcher sends `Accept-Encoding: identity` and refuses a coded response with
  `Error::ContentEncoded`.
- A fetch 404 maps to io `NotFound`, 401 and 403 to `PermissionDenied`, and
  `FetchTooLarge` to `FileTooLarge`.
- Breaking: `TcpStream::connect` in `ostrya-rt` races the addresses of a host.
- Breaking: `PruneOptions::gc_root_properties` is now `gc_root_metadata_keys`. New
  `RepoConfig::gc_root_metadata_keys` and `RepoConfig::detached_metadata_exclude`
  read the new `[ex-ostrya]` keys.
- New checkout union and whiteout behavior: `OverwriteMode::UnionIdentical`
  compares checksums, and `CheckoutOptions` gains `process_passthrough_whiteouts`.
  `Error::Checkout` for a subpath splits into `Error::SubpathNotFound` and
  `Error::SubpathNotADirectory`.
- Fix: The composefs image of a checkout gets mode 0644 whatever the umask.

### CLI

- `checkout` accepts `--union`, `--union-add`, `--union-identical`,
  `--allow-noent`, `--whiteouts`, and `--process-passthrough-whiteouts`.
- `prune`, `pull`, and `pull-local` read `[ex-ostrya] gc-root-metadata-keys` and
  `detached-metadata-exclude`.
- `pull` follows redirects, uses the proxy environment variables, and accepts
  `tls-permissive=true`.
- Fix: `checkout --composefs` writes the image with mode 0644 whatever the umask.

## [0.2.1] - 2026-09-08

### Library

- Breaking: `PruneOptions` gains `gc_root_properties` and `traverse_parent`. New
  `PruneOptions::gc_roots` and `Error::InvalidGcRoot`.
- Breaking: `PullOptions` gains `detached_metadata_filter`.
- New `Value::as_strv` in `ostrya-gvariant`.
- `TarExportOptions` carries a subpath, a prefix, and an xattr switch.
- `StagingTree::ensure_dir` stamps the tree root for `.`, `/`, and the empty path.
- Breaking: New feature `lzma-static` builds liblzma statically. It is off by
  default, and a build without it links the system liblzma.
- `miniz_oxide` and `smol-tar` take version ranges.

### CLI

- `export` accepts `--no-xattrs`, `--subpath`, `--prefix`, and `-o/--output`.
- `prune` refuses `--no-prune` with `--delete-commit`.
- The `ostrya` binary links liblzma statically.

## [0.2.0] - 2026-09-03

### Library

- New `Repo::export_tar` and `Repo::import_tar`. Tar import can remap `/etc` to
  `/usr/etc` and refuses device and FIFO members.
- New maintenance operations: `Repo::prune`, `Repo::fsck`, `Repo::diff_commits`,
  `Repo::list_objects`, `Repo::traverse_commit`, and `Repo::traverse_reachable`.
- The write path seals loose objects with fs-verity under the `[ex-integrity]`
  config section. New crate `ostrya-sys` holds the fs-verity ioctl and mmap
  wrappers.
- New commit signing API: `Signer`, `Verifier`, `Repo::sign_commit`,
  `Repo::verify_commit`, and the dummy, ed25519, spki (P-256, feature
  `sign-spki`), and GPG engines. The sign-api key store reads trusted and revoked
  keys.
- GPG verification and key management run in the process over the `pgp` crate
  (feature `verify-gpg`). `Repo::gpg_import_keys` and `Repo::gpg_list_keys` need
  no GnuPG binary. Signing (feature `sign-gpg`) runs the system `gpg`.
- New repository summaries: `Repo::regenerate_summary`, `Repo::sign_summary`, and
  `Repo::verify_summary`, with collection-map support.
- New static deltas: `Repo::generate_static_delta`, `Repo::sign_static_delta`,
  `Repo::reindex_static_deltas`, `Repo::apply_static_delta_offline`,
  `Repo::verify_static_delta`, and `Repo::list_static_deltas`. xz links liblzma,
  built statically from bundled source.
- New `Repo::pull` from an HTTP(S) remote over HTTP/1.1 and HTTP/2, with mirrors,
  retries, static deltas, localcache repositories, and GPG and sign-api
  verification of commits and summaries. New `Repo::pull_local` from a local
  repository. A pull into an archive repository stores the fetched `.filez` bytes
  unchanged.
- A revision of 1 to 63 lowercase hex characters resolves to the one commit whose
  checksum starts with it. New `Repo::resolve_rev`, `Repo::resolve_ref_tip`, ref
  alias and collection ref calls, and `Error::AmbiguousRefspec`.
- `StagingTree` gains `lookup`, `ensure_dir`, `place_object`, `remove`,
  `clear_dir`, `rename`, implied parent directories, and typed refusals
  (`PathNotFound`, `NotADirectory`, `DanglingSymlink`, `SymlinkLoop`,
  `EntryExists`).
- Breaking: `StagingTree::merge` is `merge_at`, and `MergeOptions` gains
  `root_dirmeta`.
- Breaking: `Repo::export_composefs` takes `ComposefsOptions` with a verity
  policy, `Content::Backed::verity` is an `Option`, `build_image` returns a
  `Result`, and `write_image_to` and `Repo::export_composefs_to` replace
  `write_image`. The composefs writer streams the image to a sink.
- New `DictBuilder`, public `Transaction::write_dirmeta` and `loose_path`,
  `Transaction::kernel_version`, `RepoTree::kernel_version`, and
  `BootableMetadata`. `ostrya-gvariant` gains a text-form printer and reader for
  every GVariant type.
- Fix: a bare or bare-user object, and a checked-out file, with a mode without
  owner write and `user.*` xattrs is stored without `EACCES`.
- Fix: a bare-user-only object and a commit under `CANONICAL_PERMISSIONS` get the
  same checksums as the `ostree` tool.
- Fix: a concurrent transaction in the same process cannot remove the staging
  directory of a live transaction.

### CLI

- The binary is `ostrya`. New `commit`, `checkout`, and `export`. `checkout` takes
  `-C`, `-H`, `-U`, `--subpath`, `--composefs`, and `--composefs-noverity`.
- New `init` and the global options `--repo`, `-v`, and `--version`. With no
  `--repo`, the command uses the current directory or `OSTREE_REPO`.
- New `refs`, `rev-parse`, `cat`, `show`, `log`, `ls`, `diff`, `prune`, and
  `fsck`.
- New `config get`, `config set`, `config unset`, and `remote
  add|delete|list|show-url|refs|summary|gpg-import|gpg-list-keys`.
- `commit` takes the parent options (`--parent`, `--orphan`, implicit branch tip),
  `-m`, `-F`, `-e`, the metadata and binding options, `--owner-uid`,
  `--owner-gid`, `--timestamp`, `--no-xattrs`, `--statoverride`, `--skip-list`,
  `--tree=dir|tar|ref`, `--bootable`, `--generate-sizes`,
  `--generate-composefs-metadata`, and the signing options.
- `commit --tar-pathname-filter` compiles the expression with a statically linked
  PCRE2.
- New `sign` with `--verify`, `--delete`, `-s ed25519|spki|gpg`, `--keys-file`,
  and `--remote`. GPG verification reads `OSTREE_GPG_HOME` and the default trusted
  keyrings, and needs no GnuPG binary.
- New `summary` and `static-delta list|apply-offline|generate|reindex`.
- New `pull` and `pull-local`.
- A revision can be an abbreviated commit checksum.
- The `smol` and `tokio` features select the runtime. The spki and GPG engines are
  on by default.

## [0.0.1] - 2026-07-14

### Library

- First release of `ostrya`, `ostrya-core`, `ostrya-gvariant`, `ostrya-rt`, and
  `ostrya-composefs`.
- `ostrya-gvariant` serializes and deserializes GVariant byte-exactly.
  `ostrya-core` holds the object model: `ObjectType`, `Checksum`, commit, dirtree,
  dirmeta, file header, xattrs, and keyfile.
- `ostrya-rt` hides the async runtime: `smol` by default, `tokio` behind a
  feature.
- `Repo::create` and `Repo::open` for the bare, bare-user, bare-user-only,
  bare-user-shared, and archive modes. bare-split-xattrs is read-only.
  `RepoConfig` reads the config.
- Read path: `load_commit`, `load_dirtree`, `load_dirmeta`, `load_file`,
  `has_object`, ref resolution and listing, and `RepoTree` traversal. Content
  streams through `ContentReader`.
- `Transaction` holds the repository lock and its own staging directory. One
  process can run more than one transaction at a time.
- Write path: `ContentWriter`, `MutableTree`, `Transaction::write_mtree`,
  `Transaction::write_dfd_to_mtree` with `CommitModifier`, commits from
  `CommitOptions`, `ostree.sizes`, detached metadata, min-free-space, and refs
  (`set_ref`, `set_collection_ref`, `set_ref_immediate`).
- `Transaction::merge_overlay_dfd_to_mtree` imports an overlayfs upper directory.
- `StagingTree` builds a commit tree by path, with file writers, links, and
  `merge`.
- `Repo::checkout_at` writes a commit tree in faithful or unprivileged mode, with
  the overwrite policies, subpaths, whiteouts, and reflink copies.
- `ostrya-composefs` writes composefs EROFS images byte-identical to the tool.
  `Repo::export_composefs` and `Repo::commit_add_composefs_metadata` use it.

### CLI

- The `ostrya-cli` binary has no subcommands.
