//! The import of collection refs from removable media.
//!
//! Each test exports refs of a source repository onto a mount directory of a
//! scratch directory, and imports them into a client repository with
//! `mount` set to that directory. The remotes of the client turn the GPG
//! check off and trust an ed25519 key, so the tests also run in a build
//! with no GPG engine. One test mounts a read-only `tmpfs` in a user
//! namespace.

mod common;

use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{TmpDir, file_inventory};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Ed25519Signer,
    Error, FsckOptions, MediaExportOptions, MediaImportOptions, MediaImportReport, MutableTree,
    Ref, Repo, RepoMode, SummaryOptions, Type, Value,
};
use ostrya_rt::block_on;

/// The collection that the remote `origin` of the client matches.
const X: &str = "org.example.X";
/// A collection that no remote of most clients matches.
const Y: &str = "org.example.Y";
/// The variable that names the scratch directory of the child of
/// [`the_import_reads_media_on_a_read_only_mount`].
const READ_ONLY_CHILD: &str = "OSTRYA_MEDIA_IMPORT_CHILD";

/// The ed25519 key that signs the commits of the media.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
/// A second ed25519 key.
const OTHER_SECRET_B64: &str =
    "5ILWxT+l9G/u3h0BptRpmSi35C9uog7YDdD+Fp1Xk+Hz52p0NlYh6xBA73kJEJKhKbbnjcE0rsWA5XA/K5Sq5Q==";

/// Returns the public key of the ed25519 secret key `secret` in base64.
fn public(secret: &str) -> String {
    ostrya::base64::encode(&Ed25519Signer::from_base64(secret).unwrap().public_key())
}

/// Returns a metadata entry `key` with the value `value` of type `ty`.
fn entry(key: &str, ty: &str, value: Value) -> Value {
    Value::Tuple(vec![
        Value::Str(key.to_owned()),
        Value::Variant(Box::new((Type::parse(ty).unwrap(), value))),
    ])
}

/// Creates an archive repository at `path` with the collection id `own`.
async fn create(path: &Path, own: Option<&str>) -> Repo {
    let mut opts = CreateOptions::new(RepoMode::Archive);
    if let Some(id) = own {
        opts = opts.collection_id(id);
    }
    Repo::create(path, opts).await.unwrap()
}

/// Creates the archive source repository `dir/src` with no collection id.
async fn source(dir: &Path) -> Repo {
    create(&dir.join("src"), None).await
}

/// Creates the empty mount directory `dir/name`, and returns its path.
fn mount_dir(dir: &Path, name: &str) -> PathBuf {
    let mount = dir.join(name);
    std::fs::create_dir(&mount).unwrap();
    mount
}

/// Returns the section of the remote `name` with the key line `key`, which
/// trusts the ed25519 key of `secret` and turns the GPG check off.
fn remote(name: &str, key: &str, secret: &str) -> String {
    format!(
        "\n[remote \"{name}\"]\nurl=file:///dev/null\n{key}\ngpg-verify=false\n\
         sign-verify=ed25519\nverification-ed25519-key={}\n",
        public(secret)
    )
}

/// Returns the section of the remote `origin` with `collection-id=X`, which
/// trusts the key of [`SECRET_B64`].
fn origin() -> String {
    remote("origin", &format!("collection-id={X}"), SECRET_B64)
}

/// Creates the client repository `dir/name` with the collection id `own`
/// and the remote sections `remotes`.
async fn client(dir: &Path, name: &str, own: Option<&str>, remotes: &str) -> Repo {
    let path = dir.join(name);
    drop(create(&path, own).await);
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str(remotes);
    std::fs::write(&config, text).unwrap();
    Repo::open(&path).await.unwrap()
}

/// Commits a small tree with the marker `marker` and the timestamp
/// `timestamp` into `repo`, and writes it to the ref `target`. The commit
/// binds the name of `target`, and the collection `collection` if it is
/// set. The commit is signed with `secret` if it is set.
async fn commit(
    repo: &Repo,
    dir: &Path,
    marker: &str,
    target: &Ref,
    collection: Option<&str>,
    timestamp: u64,
    secret: Option<&str>,
) -> Checksum {
    let sub = format!("tree-{marker}");
    std::fs::create_dir_all(dir.join(&sub).join("sub")).unwrap();
    std::fs::write(dir.join(&sub).join("hello.txt"), marker).unwrap();
    std::fs::write(dir.join(&sub).join("sub/nested.txt"), b"nested\n").unwrap();
    let txn = repo.transaction().await.unwrap();
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::SKIP_XATTRS | CommitModifierFlags::CANONICAL_PERMISSIONS,
    );
    let dfd = std::fs::File::open(dir).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new(&sub),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let mut metadata = vec![entry(
        "ostree.ref-binding",
        "as",
        Value::Array(vec![Value::Str(target.name().to_owned())]),
    )];
    if let Some(id) = collection {
        metadata.push(entry(
            "ostree.collection-binding",
            "s",
            Value::Str(id.to_owned()),
        ));
    }
    let checksum = txn
        .write_commit(
            CommitOptions {
                subject: Some(marker.to_owned()),
                timestamp: Some(timestamp),
                metadata: Some(Value::Array(metadata)),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref(target, Some(&checksum));
    txn.commit().await.unwrap();
    if let Some(secret) = secret {
        let signer = Ed25519Signer::from_base64(secret).unwrap();
        repo.sign_commit(&checksum, &signer).await.unwrap();
    }
    checksum
}

/// Commits the ref `@id:name` into `src`, bound to `id` and signed with
/// [`SECRET_B64`], with the timestamp `timestamp`.
async fn signed(src: &Repo, dir: &Path, id: &str, name: &str, timestamp: u64) -> Checksum {
    let target = Ref::collection(id, name);
    let marker = format!("{id}-{name}-{timestamp}");
    commit(
        src,
        dir,
        &marker,
        &target,
        Some(id),
        timestamp,
        Some(SECRET_B64),
    )
    .await
}

/// Exports `refs` of `src` onto `mount` with the default options.
async fn export(src: &Repo, mount: &Path, refs: &[Ref]) {
    src.export_media(mount, refs, MediaExportOptions::default())
        .await
        .unwrap();
}

/// Imports `refs` and the collections `collections` from the media under
/// `mount` into `client`.
async fn import(
    client: &Repo,
    mount: &Path,
    refs: &[Ref],
    collections: &[&str],
) -> ostrya::Result<MediaImportReport> {
    client
        .import_media(MediaImportOptions {
            mount: Some(mount.to_owned()),
            refs: refs.to_vec(),
            collections: collections.iter().map(|id| (*id).to_owned()).collect(),
        })
        .await
}

/// Returns the refs of `list` as text.
fn names<T>(list: &[(Ref, T)]) -> Vec<String> {
    list.iter().map(|(r, _)| r.to_string()).collect()
}

/// Returns the path of each ref file of the repository `repo`.
fn ref_files(repo: &Repo) -> Vec<String> {
    file_inventory(repo.path(), "refs")
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

/// Reads the ref file `rel` under `refs/` of the repository `repo`.
fn ref_file(repo: &Repo, rel: &str) -> Option<Checksum> {
    let text = std::fs::read_to_string(repo.path().join("refs").join(rel)).ok()?;
    Some(text.trim_end().parse().unwrap())
}

/// Asserts that fsck finds no error in the repository `repo`.
async fn assert_fsck_clean(repo: &Repo) {
    let repo = Repo::open(repo.path()).await.unwrap();
    let report = repo.fsck(&FsckOptions::new()).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

/// The selection of each operand form, on media with the refs `a` and `b`
/// of X and the ref `a` of Y. Only X has a remote. A ref file that the
/// summary does not list, and a summary entry with no ref file, are not on
/// the media.
#[test]
fn the_import_selects_the_refs_of_each_operand_form() {
    let tmp = TmpDir::new("media-import-select");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let a = signed(&src, dir, X, "a", 1000).await;
        let b = signed(&src, dir, X, "b", 1000).await;
        signed(&src, dir, X, "gone", 1000).await;
        signed(&src, dir, Y, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        let refs = [
            Ref::collection(X, "a"),
            Ref::collection(X, "b"),
            Ref::collection(X, "gone"),
            Ref::collection(Y, "a"),
        ];
        export(&src, &mount, &refs).await;
        let media = mount.join(".ostree/repo");
        std::fs::remove_file(media.join(format!("refs/mirrors/{X}/gone"))).unwrap();
        std::fs::write(
            media.join(format!("refs/mirrors/{X}/extra")),
            format!("{a}\n"),
        )
        .unwrap();

        let mut n = 0;
        let mut fresh = async |own: Option<&str>| {
            n += 1;
            client(dir, &format!("client-{n}"), own, &origin()).await
        };
        let both = [format!("@{X}:a"), format!("@{X}:b")];

        let c = fresh(None).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(names(&report.written), both);
        assert_eq!(report.written[0].1, a);
        assert_eq!(report.written[1].1, b);
        assert!(report.unchanged.is_empty() && report.refused.is_empty());
        assert_eq!(report.repo, media);
        assert_eq!(
            ref_files(&c),
            [format!("refs/mirrors/{X}/a"), format!("refs/mirrors/{X}/b")]
        );

        let c = fresh(None).await;
        let report = import(&c, &mount, &[], &[X]).await.unwrap();
        assert_eq!(names(&report.written), both);

        let c = fresh(None).await;
        let report = import(&c, &mount, &[Ref::collection(X, "a")], &[])
            .await
            .unwrap();
        assert_eq!(names(&report.written), [format!("@{X}:a")]);
        assert_eq!(ref_files(&c), [format!("refs/mirrors/{X}/a")]);

        // `NAME` is the ref of the own collection id of the client.
        let c = fresh(Some(X)).await;
        let report = import(&c, &mount, &[Ref::local("b")], &[]).await.unwrap();
        assert_eq!(names(&report.written), [format!("@{X}:b")]);
        assert_eq!(ref_file(&c, "heads/b"), Some(b));

        // A duplicate, and a prefix that covers a named ref, import one time.
        let c = fresh(None).await;
        let twice = [Ref::collection(X, "b"), Ref::collection(X, "b")];
        let report = import(&c, &mount, &twice, &[X, X]).await.unwrap();
        assert_eq!(
            names(&report.written),
            [format!("@{X}:b"), format!("@{X}:a")]
        );

        // Each refusal comes before the first write.
        let c = fresh(None).await;
        let err = import(&c, &mount, &[Ref::local("a")], &[])
            .await
            .unwrap_err();
        assert!(matches!(&err, Error::InvalidInput(_)), "{err:?}");
        let both_forms = [Ref::local("a"), Ref::collection(X, "a")];
        let own = fresh(Some(X)).await;
        let err = import(&own, &mount, &both_forms, &[]).await.unwrap_err();
        assert!(matches!(&err, Error::InvalidInput(_)), "{err:?}");
        for (refs, collections) in [(vec![Ref::collection(Y, "a")], vec![]), (vec![], vec![Y])] {
            let err = import(&c, &mount, &refs, &collections).await.unwrap_err();
            assert!(
                matches!(&err, Error::InvalidInput(m) if m.contains(Y)
                    && m.contains("collection-id")
                    && m.contains("mirrored-collection-ids")),
                "{err:?}"
            );
        }
        for name in ["missing", "gone", "extra"] {
            let err = import(&c, &mount, &[Ref::collection(X, name)], &[])
                .await
                .unwrap_err();
            assert!(
                matches!(&err, Error::RefNotFound(m) if *m == format!("@{X}:{name}")),
                "{err:?}"
            );
        }
        let err = import(&c, &mount, &[Ref::remote("origin", "a")], &[])
            .await
            .unwrap_err();
        assert!(matches!(&err, Error::InvalidRefspec(_)), "{err:?}");
        let err = import(&c, &mount, &[], &["not an id"]).await.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRefspec(m) if m == "@not an id:"),
            "{err:?}"
        );
        assert!(ref_files(&c).is_empty());
        assert!(ref_files(&own).is_empty());
    });
}

/// A commit that is older than the commit of the ref in the client is
/// refused, and the other refs are imported, also the other refs of the
/// same collection. A ref that holds the commit of the media is unchanged.
#[test]
fn a_downgrade_is_refused_and_the_other_refs_are_imported() {
    let tmp = TmpDir::new("media-import-downgrade");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let old = signed(&src, dir, X, "a", 1000).await;
        let new = signed(&src, dir, X, "a", 2000).await;
        let same = signed(&src, dir, X, "u", 1000).await;
        let b = signed(&src, dir, X, "b", 1000).await;
        let other = signed(&src, dir, Y, "c", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(
            &src,
            &mount,
            &[Ref::collection(X, "a"), Ref::collection(X, "u")],
        )
        .await;
        let remotes = origin() + &remote("other", &format!("collection-id={Y}"), SECRET_B64);
        let c = client(dir, "client", None, &remotes).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(
            names(&report.written),
            [format!("@{X}:a"), format!("@{X}:u")]
        );

        src.export_media(
            &mount,
            &[Ref::collection(X, "a")],
            MediaExportOptions { commit: Some(old) },
        )
        .await
        .unwrap();
        export(
            &src,
            &mount,
            &[Ref::collection(X, "b"), Ref::collection(Y, "c")],
        )
        .await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(
            names(&report.written),
            [format!("@{X}:b"), format!("@{Y}:c")]
        );
        assert_eq!(report.written[0].1, b);
        assert_eq!(report.written[1].1, other);
        assert_eq!(report.unchanged, [(Ref::collection(X, "u"), same)]);
        assert_eq!(names(&report.refused), [format!("@{X}:a")]);
        assert!(
            matches!(&report.refused[0].1, Error::Pull(m) if m.contains("chronologically older")),
            "{:?}",
            report.refused[0].1
        );
        assert_eq!(ref_file(&c, &format!("mirrors/{X}/a")), Some(new));
        assert_eq!(ref_file(&c, &format!("mirrors/{Y}/c")), Some(other));
        assert_fsck_clean(&c).await;
    });
}

/// With no mirror ref, the import refuses a commit that is older than the
/// remote ref of the matched remote.
#[test]
fn a_commit_older_than_the_remote_ref_is_refused() {
    let tmp = TmpDir::new("media-import-remote-ref");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let c = client(dir, "client", None, &origin()).await;
        let tracked = Ref::remote("origin", "a");
        let new = commit(&c, dir, "new", &tracked, Some(X), 2000, Some(SECRET_B64)).await;

        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert!(report.written.is_empty(), "{:?}", report.written);
        assert!(report.unchanged.is_empty(), "{:?}", report.unchanged);
        assert_eq!(names(&report.refused), [format!("@{X}:a")]);
        assert!(
            matches!(&report.refused[0].1, Error::Pull(m) if m.contains("chronologically older")),
            "{:?}",
            report.refused[0].1
        );
        assert_eq!(ref_files(&c), ["refs/remotes/origin/a"]);
        assert_eq!(ref_file(&c, "remotes/origin/a"), Some(new));
        assert_fsck_clean(&c).await;
    });
}

/// With no mirror ref, a remote ref of the matched remote that holds the
/// commit of the media is unchanged, and the import writes no mirror ref.
#[test]
fn a_remote_ref_at_the_commit_of_the_media_is_unchanged() {
    let tmp = TmpDir::new("media-import-remote-ref-same");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let old = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let c = client(dir, "client", None, &origin()).await;
        let tracked = Ref::remote("origin", "a");
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), old)]);
        c.set_ref_immediate(&tracked, Some(&old)).await.unwrap();
        c.set_ref_immediate(&Ref::collection(X, "a"), None)
            .await
            .unwrap();
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert!(report.written.is_empty(), "{:?}", report.written);
        assert_eq!(report.unchanged, [(Ref::collection(X, "a"), old)]);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(ref_files(&c), ["refs/remotes/origin/a"]);
    });
}

/// The remote ref of a remote that matches the collection through
/// `mirrored-collection-ids` alone is not the current ref.
#[test]
fn the_remote_ref_of_a_mirroring_remote_is_ignored() {
    let tmp = TmpDir::new("media-import-mirroring-remote-ref");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let old = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let mirror = remote(
            "mirror",
            &format!("mirrored-collection-ids={X}"),
            SECRET_B64,
        );
        let c = client(dir, "client", None, &mirror).await;
        let tracked = Ref::remote("mirror", "a");
        let new = commit(&c, dir, "new", &tracked, Some(X), 2000, Some(SECRET_B64)).await;

        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), old)]);
        assert_eq!(ref_file(&c, &format!("mirrors/{X}/a")), Some(old));
        assert_eq!(ref_file(&c, "remotes/mirror/a"), Some(new));
    });
}

/// Under the own collection id of the client, the remote ref of the matched
/// remote is not the current ref.
#[test]
fn the_remote_ref_under_the_own_collection_is_ignored() {
    let tmp = TmpDir::new("media-import-own-remote-ref");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let old = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let c = client(dir, "client", Some(X), &origin()).await;
        let tracked = Ref::remote("origin", "a");
        let new = commit(&c, dir, "new", &tracked, Some(X), 2000, Some(SECRET_B64)).await;

        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), old)]);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(ref_file(&c, "heads/a"), Some(old));
        assert_eq!(ref_file(&c, "remotes/origin/a"), Some(new));
    });
}

/// A mirror ref is the current ref when a remote ref of the matched remote
/// is also present.
#[test]
fn the_mirror_ref_comes_before_the_remote_ref() {
    let tmp = TmpDir::new("media-import-mirror-before-remote");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let old = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let c = client(dir, "client", None, &origin()).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), old)]);
        let tracked = Ref::remote("origin", "a");
        let new = commit(&c, dir, "new", &tracked, Some(X), 2000, Some(SECRET_B64)).await;

        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert!(report.written.is_empty(), "{:?}", report.written);
        assert_eq!(report.unchanged, [(Ref::collection(X, "a"), old)]);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(ref_file(&c, &format!("mirrors/{X}/a")), Some(old));
        assert_eq!(ref_file(&c, "remotes/origin/a"), Some(new));
    });
}

/// A remote ref that the import cannot read refuses the ref.
#[test]
fn a_remote_ref_that_cannot_be_read_refuses_the_ref() {
    let tmp = TmpDir::new("media-import-bad-remote-ref");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let c = client(dir, "client", None, &origin()).await;
        let bad = c.path().join("refs/remotes/origin");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("a"), "not a checksum\n").unwrap();

        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert!(report.written.is_empty(), "{:?}", report.written);
        assert!(report.unchanged.is_empty(), "{:?}", report.unchanged);
        assert_eq!(names(&report.refused), [format!("@{X}:a")]);
        assert_eq!(ref_files(&c), ["refs/remotes/origin/a"]);
    });
}

/// The trust of the matched remote checks each commit. A remote that checks
/// no commit signature makes the import check the GPG signature, and a
/// build with no GPG engine refuses the ref with its own text. A commit
/// signed with a key that the remote does not trust is refused. A remote
/// with `gpg-verify-summary=true` still imports: the import checks no
/// summary.
#[test]
fn the_trust_of_the_matched_remote_checks_each_commit() {
    let tmp = TmpDir::new("media-import-trust");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let unsigned_ref = Ref::collection(X, "unsigned");
        commit(&src, dir, "unsigned", &unsigned_ref, Some(X), 1000, None).await;
        let other_ref = Ref::collection(X, "other");
        commit(
            &src,
            dir,
            "other",
            &other_ref,
            Some(X),
            1000,
            Some(OTHER_SECRET_B64),
        )
        .await;
        let signed_tip = signed(&src, dir, X, "signed", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[unsigned_ref.clone(), other_ref.clone()]).await;
        export(&src, &mount, &[Ref::collection(X, "signed")]).await;

        let plain = format!(
            "\n[remote \"origin\"]\nurl=file:///dev/null\ncollection-id={X}\ngpg-verify=false\n"
        );
        let c = client(dir, "client-plain", None, &plain).await;
        let report = import(&c, &mount, std::slice::from_ref(&unsigned_ref), &[])
            .await
            .unwrap();
        assert!(report.written.is_empty(), "{report:?}");
        assert_eq!(names(&report.refused), [unsigned_ref.to_string()]);
        let err = &report.refused[0].1;
        #[cfg(feature = "verify-gpg")]
        assert!(matches!(err, Error::Signature(_)), "{err:?}");
        #[cfg(not(feature = "verify-gpg"))]
        assert!(
            matches!(err, Error::Unsupported(m)
                if m.contains("verify-gpg") && !m.contains("gpg-verify=false")),
            "{err:?}"
        );
        assert_eq!(ref_file(&c, &format!("mirrors/{X}/unsigned")), None);

        let k2 = remote("origin", &format!("collection-id={X}"), OTHER_SECRET_B64);
        let c = client(dir, "client-k2", None, &k2).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(names(&report.written), [other_ref.to_string()]);
        assert_eq!(
            names(&report.refused),
            [format!("@{X}:signed"), unsigned_ref.to_string()]
        );
        for (_, err) in &report.refused {
            assert!(matches!(err, Error::Signature(_)), "{err:?}");
        }

        let summary = origin() + "gpg-verify-summary=true\n";
        let c = client(dir, "client-summary", None, &summary).await;
        let report = import(&c, &mount, &[Ref::collection(X, "signed")], &[])
            .await
            .unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "signed"), signed_tip)]);
    });
}

/// A trust of the matched remote that cannot be read does not stop an
/// import whose refs all hold the commit of the media. An import with a
/// ref to pull fails and writes no ref.
#[test]
fn a_trust_error_does_not_stop_an_import_with_nothing_to_pull() {
    let tmp = TmpDir::new("media-import-trust-error-unchanged");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let a = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let c = client(dir, "client", None, &origin()).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), a)]);
        signed(&src, dir, X, "b", 1000).await;
        export(&src, &mount, &[Ref::collection(X, "b")]).await;

        let config = c.path().join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        let absent = dir.join("absent.key");
        text.push_str(&format!("verification-ed25519-file={}\n", absent.display()));
        std::fs::write(&config, text).unwrap();
        let c = Repo::open(c.path()).await.unwrap();

        let report = import(&c, &mount, &[Ref::collection(X, "a")], &[])
            .await
            .unwrap();
        assert!(report.written.is_empty(), "{:?}", report.written);
        assert_eq!(report.unchanged, [(Ref::collection(X, "a"), a)]);
        assert!(report.refused.is_empty(), "{:?}", report.refused);

        let err = import(&c, &mount, &[], &[]).await.unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "{err:?}");
        assert_eq!(ref_files(&c), [format!("refs/mirrors/{X}/a")]);
    });
}

/// A trust that cannot be read fails the import before the first pull, also
/// when the ref of that trust comes after a ref with a good trust.
#[test]
fn a_trust_error_comes_before_the_first_pull() {
    let tmp = TmpDir::new("media-import-trust-error-order");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        signed(&src, dir, X, "a", 1000).await;
        signed(&src, dir, Y, "b", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(
            &src,
            &mount,
            &[Ref::collection(X, "a"), Ref::collection(Y, "b")],
        )
        .await;

        // The section of `other` is the last one, so the key line lands in
        // it.
        let absent = dir.join("absent.key");
        let remotes = origin()
            + &remote("other", &format!("collection-id={Y}"), SECRET_B64)
            + &format!("verification-ed25519-file={}\n", absent.display());
        let c = client(dir, "client", None, &remotes).await;

        let err = import(&c, &mount, &[], &[]).await.unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "{err:?}");
        assert!(ref_files(&c).is_empty());
    });
}

/// A `gpgkeypath` that cannot be read does not stop an import whose refs
/// all hold the commit of the media.
#[cfg(feature = "verify-gpg")]
#[test]
fn an_unreadable_gpgkeypath_does_not_stop_an_import_with_nothing_to_pull() {
    let tmp = TmpDir::new("media-import-gpgkeypath-unchanged");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let a = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let c = client(dir, "client", None, &origin()).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), a)]);

        let config = c.path().join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        assert!(text.contains(&origin()), "{text}");
        let absent = dir.join("absent.gpg");
        let section = format!(
            "\n[remote \"origin\"]\nurl=file:///dev/null\ncollection-id={X}\n\
             gpg-verify=false\ngpgkeypath={}\n",
            absent.display()
        );
        std::fs::write(&config, text.replace(&origin(), &section)).unwrap();
        let c = Repo::open(c.path()).await.unwrap();

        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert!(report.written.is_empty(), "{:?}", report.written);
        assert_eq!(report.unchanged, [(Ref::collection(X, "a"), a)]);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
    });
}

/// A stale media summary pins its commit: the media repository does not
/// hold that commit, so that ref is refused, and another ref is imported.
#[test]
fn a_stale_media_summary_fails_the_import_of_its_ref() {
    let tmp = TmpDir::new("media-import-stale");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        signed(&src, dir, X, "a", 1000).await;
        let b = signed(&src, dir, X, "b", 1000).await;
        let first = mount_dir(dir, "first");
        export(
            &src,
            &first,
            &[Ref::collection(X, "a"), Ref::collection(X, "b")],
        )
        .await;
        signed(&src, dir, X, "a", 2000).await;
        let second = mount_dir(dir, "second");
        export(
            &src,
            &second,
            &[Ref::collection(X, "a"), Ref::collection(X, "b")],
        )
        .await;
        std::fs::copy(
            first.join(".ostree/repo/summary"),
            second.join(".ostree/repo/summary"),
        )
        .unwrap();

        let c = client(dir, "client", None, &origin()).await;
        let report = import(&c, &second, &[], &[]).await.unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "b"), b)]);
        assert_eq!(names(&report.refused), [format!("@{X}:a")]);
        assert!(
            matches!(&report.refused[0].1, Error::ObjectNotFound { .. }),
            "{:?}",
            report.refused[0].1
        );
        assert_eq!(ref_file(&c, &format!("mirrors/{X}/a")), None);
    });
}

/// A ref of the own collection id of the client lands in `refs/heads/`.
#[test]
fn a_ref_of_the_own_collection_lands_in_refs_heads() {
    let tmp = TmpDir::new("media-import-own");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let a = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let c = client(dir, "client", Some(X), &origin()).await;
        let report = import(&c, &mount, &[Ref::collection(X, "a")], &[])
            .await
            .unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), a)]);
        assert_eq!(ref_files(&c), ["refs/heads/a"]);
        assert_eq!(ref_file(&c, "heads/a"), Some(a));
    });
}

/// A remote whose `collection-id` is the own id of the client and whose
/// `mirrored-collection-ids` holds a second collection is the matched remote
/// of both. A second remote with `collection-id` of the second collection
/// wins over it, and its trust applies.
#[test]
fn a_remote_with_the_collection_id_wins_over_a_mirroring_remote() {
    let tmp = TmpDir::new("media-import-mirrored");
    let dir = tmp.path();
    block_on(async {
        let own = "org.example.P";
        let mirrored = "org.example.A";
        let src = source(dir).await;
        let main = signed(&src, dir, own, "main", 1000).await;
        let app = signed(&src, dir, mirrored, "app", 1000).await;
        let mount = mount_dir(dir, "mnt");
        let refs = [
            Ref::collection(own, "main"),
            Ref::collection(mirrored, "app"),
        ];
        export(&src, &mount, &refs).await;

        let key = format!("collection-id={own}\nmirrored-collection-ids={mirrored}");
        let origin = remote("origin", &key, SECRET_B64);
        let c = client(dir, "client", Some(own), &origin).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(
            names(&report.written),
            [format!("@{mirrored}:app"), format!("@{own}:main")]
        );
        assert_eq!(ref_file(&c, "heads/main"), Some(main));
        assert_eq!(ref_file(&c, &format!("mirrors/{mirrored}/app")), Some(app));

        let zzz = remote(
            "zzz",
            &format!("collection-id={mirrored}"),
            OTHER_SECRET_B64,
        );
        let c = client(dir, "client-zzz", Some(own), &(origin + &zzz)).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(names(&report.written), [format!("@{own}:main")]);
        assert_eq!(names(&report.refused), [format!("@{mirrored}:app")]);
        assert!(
            matches!(&report.refused[0].1, Error::Signature(_)),
            "{:?}",
            report.refused[0].1
        );
    });
}

/// Media whose collection id is the id of the ref, in the layout of
/// `ostree create-usb`, list the ref in `refs/heads/` and in field 0. A
/// client with no collection id writes it to `refs/mirrors/`.
#[test]
fn media_with_the_collection_id_of_the_ref_are_read() {
    let tmp = TmpDir::new("media-import-create-usb");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let a = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        std::fs::create_dir(mount.join(".ostree")).unwrap();
        drop(create(&mount.join(".ostree/repo"), Some(X)).await);
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        assert!(mount.join(".ostree/repo/refs/heads/a").exists());

        let c = client(dir, "client", None, &origin()).await;
        let report = import(&c, &mount, &[Ref::collection(X, "a")], &[])
            .await
            .unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), a)]);
        assert_eq!(ref_files(&c), [format!("refs/mirrors/{X}/a")]);
    });
}

/// A commit on the media that is bound to another collection, or that has
/// no collection binding, is refused, and the other refs are imported.
#[test]
fn a_commit_with_a_wrong_collection_binding_is_refused() {
    let tmp = TmpDir::new("media-import-binding");
    let dir = tmp.path();
    block_on(async {
        let src = source(dir).await;
        let a = signed(&src, dir, X, "a", 1000).await;
        let mount = mount_dir(dir, "mnt");
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
        let media = Repo::open(&mount.join(".ostree/repo")).await.unwrap();
        let bound_y = Ref::collection(X, "bound-y");
        let unbound = Ref::collection(X, "unbound");
        commit(&media, dir, "y", &bound_y, Some(Y), 1000, Some(SECRET_B64)).await;
        commit(&media, dir, "none", &unbound, None, 1000, Some(SECRET_B64)).await;
        media
            .regenerate_summary(&SummaryOptions {
                root_summary_only: true,
                ..SummaryOptions::default()
            })
            .await
            .unwrap();
        drop(media);

        let c = client(dir, "client", None, &origin()).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(report.written, [(Ref::collection(X, "a"), a)]);
        assert_eq!(
            names(&report.refused),
            [bound_y.to_string(), unbound.to_string()]
        );
        for (_, err) in &report.refused {
            assert!(matches!(err, Error::Pull(_)), "{err:?}");
        }
        assert_eq!(ref_files(&c), [format!("refs/mirrors/{X}/a")]);
    });
}

/// The import reads media on a read-only `tmpfs`. The test runs the child
/// half in a new mount namespace, in a user namespace when it does not run
/// as root.
#[test]
fn the_import_reads_media_on_a_read_only_mount() {
    let tmp = TmpDir::new("media-import-read-only");
    let unshare = |args: &[&str]| {
        Command::new("unshare")
            .args(args)
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    };
    if unshare(&[]).is_err() {
        eprintln!("skipping: unshare is not available");
        return;
    }
    let root = std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
        .unwrap_or(false);
    if !root && !unshare(&["--map-root-user"]).is_ok_and(|s| s.success()) {
        eprintln!("skipping: the host grants no user namespace");
        return;
    }
    let namespace: &[&str] = if root {
        &["-m", "--propagation", "private"]
    } else {
        &["--map-root-user", "-m", "--propagation", "private"]
    };
    if !unshare(namespace).is_ok_and(|s| s.success()) {
        eprintln!("skipping: the host grants no mount namespace");
        return;
    }
    let out = Command::new("unshare")
        .args(namespace)
        .arg(std::env::current_exe().unwrap())
        .args([
            "read_only_media_subprocess",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env(READ_ONLY_CHILD, tmp.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    if let Some(line) = stdout.lines().find(|l| l.starts_with("mount refused")) {
        eprintln!("skipping: {line}");
        return;
    }
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "the child reported {}:\n{stdout}{}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Runs `mount` with `args`, and prints the line that the parent of
/// [`read_only_media_subprocess`] reads as a skip if the mount fails.
/// Returns `true` if the mount succeeds.
fn run_mount(args: &[&str], point: &Path) -> bool {
    match Command::new("mount").args(args).arg(point).output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!("mount refused: {}", stderr.trim());
            false
        }
        Err(e) => {
            println!("mount refused: mount: {e}");
            false
        }
    }
}

/// The half of [`the_import_reads_media_on_a_read_only_mount`] that mounts
/// a `tmpfs`, exports onto it, makes it read-only, and imports from it. It
/// runs only if this test binary runs again with the environment set.
#[test]
#[ignore = "helper process for the_import_reads_media_on_a_read_only_mount"]
fn read_only_media_subprocess() {
    let Some(dir) = std::env::var_os(READ_ONLY_CHILD).map(PathBuf::from) else {
        return;
    };
    let dir = std::fs::canonicalize(dir).unwrap();
    let mount = mount_dir(&dir, "mnt");
    if !run_mount(&["-t", "tmpfs", "tmpfs"], &mount) {
        return;
    }
    block_on(async {
        let src = source(&dir).await;
        signed(&src, &dir, X, "a", 1000).await;
        export(&src, &mount, &[Ref::collection(X, "a")]).await;
    });
    if !run_mount(&["-o", "remount,bind,ro"], &mount) {
        return;
    }
    let err = std::fs::write(mount.join("probe"), b"").unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ReadOnlyFilesystem,
        "{err:?}"
    );
    block_on(async {
        let c = client(&dir, "client", None, &origin()).await;
        let report = import(&c, &mount, &[], &[]).await.unwrap();
        assert_eq!(names(&report.written), [format!("@{X}:a")]);
        assert!(report.refused.is_empty(), "{report:?}");
        assert_fsck_clean(&c).await;
    });
}
