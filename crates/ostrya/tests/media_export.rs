//! The export of collection refs onto removable media.
//!
//! Each test exports from a source repository into a mount directory of a
//! scratch directory, and reads the media repository `MOUNT/.ostree/repo`.
//! Each refusal leaves no `MOUNT/.ostree`, or changes no file of a source
//! repository that is the media repository. One test mounts a vfat and an
//! exFAT volume, and needs root.

mod common;

use std::os::fd::AsFd;
use std::path::Path;
use std::process::{Command, Stdio};

use common::{TmpDir, file_inventory};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DictBuilder,
    Error, FsckOptions, MediaExportOptions, MutableTree, ObjectType, Ref, Repo, RepoMode, Summary,
    SummaryOptions, Type, Value,
};
use ostrya_rt::block_on;

/// The collection of the source repository.
const ID: &str = "org.example.Os";
/// Another collection.
const OTHER: &str = "org.example.Other";
/// The ref that the tests export.
const REF: &str = "os/stable";
/// The variable that turns the skip of the vfat and exFAT test into a
/// failure.
const REQUIRE_MEDIA_FS: &str = "OSTRYA_REQUIRE_MEDIA_FS";

/// The bindings of a test commit.
#[derive(Clone, Copy)]
struct Bind<'a> {
    /// The `ostree.collection-binding`, or `None` for no key.
    collection: Option<&'a str>,
    /// The `ostree.ref-binding`, or `None` for no key.
    refs: Option<&'a [&'a str]>,
}

/// The bindings of a commit of `REF` in `ID`.
const BOUND: Bind<'static> = Bind {
    collection: Some(ID),
    refs: Some(&[REF]),
};

/// Returns a metadata entry `key` with the value `value` of type `ty`.
fn entry(key: &str, ty: &str, value: Value) -> Value {
    Value::Tuple(vec![
        Value::Str(key.to_owned()),
        Value::Variant(Box::new((Type::parse(ty).unwrap(), value))),
    ])
}

/// Creates a repository of `mode` at `path` with the collection id `own`.
async fn create(path: &Path, mode: RepoMode, own: Option<&str>) -> Repo {
    let mut opts = CreateOptions::new(mode);
    if let Some(id) = own {
        opts = opts.collection_id(id);
    }
    Repo::create(path, opts).await.unwrap()
}

/// Creates the archive source repository `dir/src` with the collection id
/// `own`.
async fn source(dir: &Path, own: Option<&str>) -> Repo {
    create(&dir.join("src"), RepoMode::Archive, own).await
}

/// Creates the empty mount directory `dir/mnt`, and returns its path.
fn mount_dir(dir: &Path) -> std::path::PathBuf {
    let mount = dir.join("mnt");
    std::fs::create_dir(&mount).unwrap();
    mount
}

/// Commits a small tree with the marker `marker` into `repo`, with the
/// bindings `bind` and the dependencies `related` in field 2. Writes the
/// commit to the ref `target`, or to no ref if `target` is `None`.
async fn commit(
    repo: &Repo,
    dir: &Path,
    marker: &str,
    target: Option<&Ref>,
    bind: Bind<'_>,
    related: &[(&str, Checksum)],
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
    let mut metadata = Vec::new();
    if let Some(id) = bind.collection {
        metadata.push(entry(
            "ostree.collection-binding",
            "s",
            Value::Str(id.to_owned()),
        ));
    }
    if let Some(refs) = bind.refs {
        let refs = refs.iter().map(|r| Value::Str((*r).to_owned())).collect();
        metadata.push(entry("ostree.ref-binding", "as", Value::Array(refs)));
    }
    let checksum = txn
        .write_commit(
            CommitOptions {
                subject: Some(marker.to_owned()),
                timestamp: Some(1_700_000_000),
                metadata: Some(Value::Array(metadata)),
                related: related
                    .iter()
                    .map(|(name, checksum)| ((*name).to_owned(), *checksum))
                    .collect(),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    if let Some(target) = target {
        txn.set_ref(target, Some(&checksum));
    }
    txn.commit().await.unwrap();
    checksum
}

/// Exports `refs` of `src` onto `mount` with the default options.
async fn export(src: &Repo, mount: &Path, refs: &[Ref]) -> ostrya::Result<Vec<(Ref, Checksum)>> {
    src.export_media(mount, refs, MediaExportOptions::default())
        .await
        .map(|report| report.refs)
}

/// Returns the media repository under `mount`.
fn media(mount: &Path) -> std::path::PathBuf {
    mount.join(".ostree/repo")
}

/// Reads the ref file `rel` of the media repository under `mount`.
fn media_ref(mount: &Path, rel: &str) -> Option<Checksum> {
    let text = std::fs::read_to_string(media(mount).join("refs").join(rel)).ok()?;
    Some(text.trim_end().parse().unwrap())
}

/// Parses the summary of the media repository under `mount`.
fn media_summary(mount: &Path) -> Summary {
    Summary::parse(&std::fs::read(media(mount).join("summary")).unwrap()).unwrap()
}

/// Asserts that a refused export left no `.ostree` under `mount`.
fn assert_untouched(mount: &Path) {
    assert!(!mount.join(".ostree").exists(), "{mount:?}");
}

/// Asserts that fsck finds no error in the repository at `path`.
async fn assert_fsck_clean(path: &Path) {
    let repo = Repo::open(path).await.unwrap();
    let report = repo.fsck(&FsckOptions::new()).await.unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
}

/// A ref goes onto the media at its tip, also when the summary of the source
/// lists an older commit.
#[test]
fn a_stale_source_summary_is_not_read() {
    let tmp = TmpDir::new("media-stale-summary");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let old = commit(&src, tmp.path(), "old", Some(&Ref::local(REF)), BOUND, &[]).await;
        src.regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        let new = commit(&src, tmp.path(), "new", Some(&Ref::local(REF)), BOUND, &[]).await;
        assert_ne!(old, new);
        let mount = mount_dir(tmp.path());
        let refs = export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
        assert_eq!(refs, [(Ref::collection(ID, REF), new)]);
        assert_eq!(media_ref(&mount, &format!("mirrors/{ID}/{REF}")), Some(new));
    });
}

/// The export does not read `refs/remotes/`, also for a remote whose
/// collection id is the id of the ref.
#[test]
fn a_ref_that_only_a_remote_holds_is_not_found() {
    let tmp = TmpDir::new("media-remote-only");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let config = src.path().join("config");
        let text = std::fs::read_to_string(&config).unwrap();
        std::fs::write(
            &config,
            format!("{text}[remote \"origin\"]\nurl=file:///nowhere\ncollection-id={OTHER}\n"),
        )
        .unwrap();
        let src = Repo::open(src.path()).await.unwrap();
        let bind = Bind {
            collection: Some(OTHER),
            refs: Some(&[REF]),
        };
        commit(
            &src,
            tmp.path(),
            "remote",
            Some(&Ref::remote("origin", REF)),
            bind,
            &[],
        )
        .await;
        let mount = mount_dir(tmp.path());
        let err = export(&src, &mount, &[Ref::collection(OTHER, REF)])
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::RefNotFound(text) if *text == format!("@{OTHER}:{REF}")),
            "{err:?}"
        );
        assert_untouched(&mount);
    });
}

/// An operand that names a directory of the ref tree of the source, or a path
/// under a ref file, is a ref that the source does not hold.
#[test]
fn an_operand_that_names_a_ref_directory_is_not_found() {
    let tmp = TmpDir::new("media-ref-directory");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        let under = format!("{REF}/x");
        for (operand, name) in [
            (Ref::local("os"), "os"),
            (Ref::collection(ID, "os"), "os"),
            (Ref::local(&under), under.as_str()),
            (Ref::collection(ID, &under), under.as_str()),
        ] {
            let err = export(&src, &mount, &[operand]).await.unwrap_err();
            assert!(
                matches!(&err, Error::RefNotFound(text) if *text == format!("@{ID}:{name}")),
                "{err:?}"
            );
            assert_untouched(&mount);
        }
    });
}

/// A remote ref is refused before the export creates a file.
#[test]
fn a_remote_ref_is_refused() {
    let tmp = TmpDir::new("media-remote-ref");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let mount = mount_dir(tmp.path());
        let err = export(&src, &mount, &[Ref::remote("origin", REF)])
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidRefspec(text) if *text == format!("origin:{REF}")),
            "{err:?}"
        );
        assert_untouched(&mount);
    });
}

/// A plain name is the local ref of the source, and goes onto the media
/// under the collection id of the source.
#[test]
fn a_local_name_goes_under_the_own_collection_id() {
    let tmp = TmpDir::new("media-local-name");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let tip = commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        let refs = export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
        assert_eq!(refs, [(Ref::collection(ID, REF), tip)]);
        assert_eq!(media_ref(&mount, &format!("mirrors/{ID}/{REF}")), Some(tip));
        assert_eq!(media_ref(&mount, &format!("heads/{REF}")), None);
    });
}

/// A plain name from a source with no collection id is refused.
#[test]
fn a_local_name_from_a_source_with_no_collection_id_is_refused() {
    let tmp = TmpDir::new("media-no-own-id");
    block_on(async {
        let src = source(tmp.path(), None).await;
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        let err = export(&src, &mount, &[Ref::local(REF)]).await.unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert_untouched(&mount);
    });
}

/// A tip whose collection binding names another collection is refused.
#[test]
fn a_commit_bound_to_another_collection_is_refused() {
    let tmp = TmpDir::new("media-other-binding");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let target = Ref::collection(OTHER, REF);
        commit(&src, tmp.path(), "a", Some(&target), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        let err = export(&src, &mount, &[target]).await.unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        assert_untouched(&mount);
    });
}

/// A tip with no collection binding is refused.
#[test]
fn a_commit_with_no_collection_binding_is_refused() {
    let tmp = TmpDir::new("media-no-binding");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let bind = Bind {
            collection: None,
            refs: Some(&[REF]),
        };
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), bind, &[]).await;
        let mount = mount_dir(tmp.path());
        let err = export(&src, &mount, &[Ref::local(REF)]).await.unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        assert_untouched(&mount);
    });
}

/// `NAME` and `@OWN:NAME` name one ref, and the export refuses them.
#[test]
fn a_name_and_its_own_collection_form_are_refused() {
    let tmp = TmpDir::new("media-two-forms");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        let err = export(&src, &mount, &[Ref::local(REF), Ref::collection(ID, REF)])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert_untouched(&mount);
    });
}

/// An operand that occurs two times is exported one time.
#[test]
fn a_duplicate_operand_is_exported_once() {
    let tmp = TmpDir::new("media-duplicate");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let tip = commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        let operand = Ref::collection(ID, REF);
        let refs = export(&src, &mount, &[operand.clone(), operand])
            .await
            .unwrap();
        assert_eq!(refs, [(Ref::collection(ID, REF), tip)]);
    });
}

/// One run exports the refs of two collections onto one media, in the order
/// of the operands.
#[test]
fn the_refs_of_two_collections_go_onto_one_media() {
    let tmp = TmpDir::new("media-two-collections");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let main = commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let app_ref = Ref::collection(OTHER, "app");
        let app_bind = Bind {
            collection: Some(OTHER),
            refs: Some(&["app"]),
        };
        let app = commit(&src, tmp.path(), "b", Some(&app_ref), app_bind, &[]).await;
        let mount = mount_dir(tmp.path());
        let refs = export(&src, &mount, &[app_ref.clone(), Ref::local(REF)])
            .await
            .unwrap();
        assert_eq!(refs, [(app_ref, app), (Ref::collection(ID, REF), main)]);
        assert_eq!(
            media_ref(&mount, &format!("mirrors/{OTHER}/app")),
            Some(app)
        );
        assert_eq!(
            media_ref(&mount, &format!("mirrors/{ID}/{REF}")),
            Some(main)
        );
        assert_fsck_clean(&media(&mount)).await;
    });
}

/// A new media repository is an archive repository with
/// `indexed-deltas=true`, the ref under `refs/mirrors/`, the `.commitmeta`,
/// no static delta, and a summary with the ref in the collection map, no
/// anchor commit, and no summary of an auth item.
#[test]
fn a_new_destination_is_an_archive_repository() {
    let tmp = TmpDir::new("media-new");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let tip = commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mut dict = DictBuilder::new();
        dict.insert_str("example.key", "value");
        src.write_commit_detached_metadata(&tip, Some(&dict.build()))
            .await
            .unwrap();
        let mount = mount_dir(tmp.path());
        let report = src
            .export_media(&mount, &[Ref::local(REF)], MediaExportOptions::default())
            .await
            .unwrap();
        let repo = media(&mount);
        assert_eq!(report.repo, repo);
        assert_eq!(
            std::fs::read_to_string(repo.join("config")).unwrap(),
            "[core]\nrepo_version=1\nmode=archive-z2\nindexed-deltas=true\n"
        );
        assert_eq!(media_ref(&mount, &format!("mirrors/{ID}/{REF}")), Some(tip));
        assert!(file_inventory(&repo, "refs/heads").is_empty());
        let meta = format!(
            "objects/{}/{}.commitmeta",
            &tip.to_string()[..2],
            &tip.to_string()[2..]
        );
        assert_eq!(
            std::fs::read(repo.join(&meta)).unwrap(),
            std::fs::read(src.path().join(&meta)).unwrap()
        );
        assert!(file_inventory(&repo, "deltas").is_empty());
        assert!(!repo.join("summary.sig").exists());
        assert!(!repo.join("extensions/ostrya/summary").exists());

        let summary = media_summary(&mount);
        assert!(summary.refs.is_empty());
        let map = summary.collection_map().unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0, ID);
        assert_eq!(map[0].1.len(), 1);
        assert_eq!(map[0].1[0].name, REF);
        assert_eq!(map[0].1[0].commit, tip);
        assert!(
            summary
                .metadata_value("ostree.summary.collection-id")
                .is_none()
        );
        assert_fsck_clean(&repo).await;
    });
}

/// An existing media repository keeps its mode and its collection id.
#[test]
fn an_existing_destination_keeps_its_mode_and_collection_id() {
    let tmp = TmpDir::new("media-existing");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let tip = commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        std::fs::create_dir(mount.join(".ostree")).unwrap();
        create(&media(&mount), RepoMode::BareUserOnly, Some(OTHER)).await;
        export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
        let repo = Repo::open(&media(&mount)).await.unwrap();
        assert_eq!(repo.mode(), RepoMode::BareUserOnly);
        assert_eq!(repo.config().collection_id(), Some(OTHER));
        assert_eq!(media_ref(&mount, &format!("mirrors/{ID}/{REF}")), Some(tip));
        assert_fsck_clean(&media(&mount)).await;
    });
}

/// An existing media repository with `indexed-deltas=false` gets
/// `indexed-deltas=true`, and its summary states the new value.
#[test]
fn an_existing_destination_gets_indexed_deltas() {
    let tmp = TmpDir::new("media-indexed-deltas");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        std::fs::create_dir(mount.join(".ostree")).unwrap();
        create(&media(&mount), RepoMode::Archive, None).await;
        let config = media(&mount).join("config");
        std::fs::write(
            &config,
            "[core]\nrepo_version=1\nmode=archive-z2\nindexed-deltas=false\n",
        )
        .unwrap();
        export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "[core]\nrepo_version=1\nmode=archive-z2\nindexed-deltas=true\n"
        );
        assert_eq!(
            media_summary(&mount).metadata_value("ostree.summary.indexed-deltas"),
            Some(&Value::Bool(true))
        );
    });
}

/// An export removes an existing `summary.sig` of the media repository.
#[test]
fn an_existing_summary_sig_is_deleted() {
    let tmp = TmpDir::new("media-summary-sig");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
        std::fs::write(media(&mount).join("summary.sig"), b"stale").unwrap();
        export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
        assert!(!media(&mount).join("summary.sig").exists());
    });
}

/// A mount path that does not exist or that is not a directory is refused,
/// and the export writes nothing.
#[test]
fn a_missing_or_non_directory_mount_is_refused() {
    let tmp = TmpDir::new("media-bad-mount");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let missing = tmp.path().join("missing");
        let err = export(&src, &missing, &[Ref::local(REF)])
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound),
            "{err:?}"
        );
        assert!(!missing.exists());
        let file = tmp.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let err = export(&src, &file, &[Ref::local(REF)]).await.unwrap_err();
        assert!(
            matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::NotADirectory),
            "{err:?}"
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"");
    });
}

/// A media repository that is the source repository is refused, also
/// through a symlink, and the export changes no file of the source.
/// `MOUNT/.ostree` exists here, so the test compares the files of the
/// source.
#[test]
fn the_source_repository_is_refused_as_the_media() {
    let tmp = TmpDir::new("media-source-is-media");
    block_on(async {
        let mount = mount_dir(tmp.path());
        std::fs::create_dir(mount.join(".ostree")).unwrap();
        let src = create(&media(&mount), RepoMode::Archive, Some(ID)).await;
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        src.regenerate_summary(&SummaryOptions::default())
            .await
            .unwrap();
        std::fs::write(media(&mount).join("summary.sig"), b"sig").unwrap();
        let before = file_inventory(&media(&mount), "");
        let err = export(&src, &mount, &[Ref::local(REF)]).await.unwrap_err();
        assert!(matches!(&err, Error::InvalidInput(_)), "{err:?}");
        assert_eq!(file_inventory(&media(&mount), ""), before);

        let link = tmp.path().join("link");
        std::fs::create_dir_all(link.join(".ostree")).unwrap();
        std::os::unix::fs::symlink(media(&mount), link.join(".ostree/repo")).unwrap();
        let err = export(&src, &link, &[Ref::local(REF)]).await.unwrap_err();
        assert!(matches!(&err, Error::InvalidInput(_)), "{err:?}");
        assert_eq!(file_inventory(&media(&mount), ""), before);
    });
}

/// In a media repository whose collection id is the id of the ref, the ref
/// goes to `refs/heads/`, and field 0 of the summary lists it.
#[test]
fn a_destination_of_the_refs_collection_writes_local_refs_and_field_0() {
    let tmp = TmpDir::new("media-own-id");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let tip = commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        std::fs::create_dir(mount.join(".ostree")).unwrap();
        create(&media(&mount), RepoMode::Archive, Some(ID)).await;
        export(&src, &mount, &[Ref::collection(ID, REF)])
            .await
            .unwrap();
        assert_eq!(media_ref(&mount, &format!("heads/{REF}")), Some(tip));
        assert!(file_inventory(&media(&mount), "refs/mirrors").is_empty());
        assert_eq!(media_ref(&mount, "heads/ostree-metadata"), None);
        let summary = media_summary(&mount);
        let names: Vec<&str> = summary.refs.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, [REF]);
        assert!(summary.collection_map().unwrap().is_empty());
        assert_eq!(
            summary.metadata_value("ostree.summary.collection-id"),
            Some(&Value::Str(ID.to_owned()))
        );
    });
}

/// A dependency of field 2 goes onto the media as loose objects, with no
/// ref and no static delta.
#[test]
fn a_field_2_dependency_lands_as_loose_objects() {
    let tmp = TmpDir::new("media-field-2");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let dep = commit(&src, tmp.path(), "dep", None, BOUND, &[]).await;
        let tip = commit(
            &src,
            tmp.path(),
            "main",
            Some(&Ref::local(REF)),
            BOUND,
            &[("dep", dep)],
        )
        .await;
        let mount = mount_dir(tmp.path());
        export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
        let repo = Repo::open(&media(&mount)).await.unwrap();
        assert!(repo.has_object(ObjectType::Commit, &dep).await.unwrap());
        assert!(repo.has_object(ObjectType::Commit, &tip).await.unwrap());
        assert_eq!(
            file_inventory(&media(&mount), "refs"),
            [(
                format!("refs/mirrors/{ID}/{REF}"),
                format!("{tip}\n").into_bytes()
            )]
        );
        assert!(file_inventory(&media(&mount), "deltas").is_empty());
        assert_fsck_clean(&media(&mount)).await;
    });
}

/// The commit option sets the ref to an older commit, also on media that
/// hold a newer commit of the ref.
#[test]
fn the_commit_option_pins_an_older_commit() {
    let tmp = TmpDir::new("media-commit-option");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let old = commit(&src, tmp.path(), "old", Some(&Ref::local(REF)), BOUND, &[]).await;
        let new = commit(&src, tmp.path(), "new", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
        assert_eq!(media_ref(&mount, &format!("mirrors/{ID}/{REF}")), Some(new));
        let report = src
            .export_media(
                &mount,
                &[Ref::local(REF)],
                MediaExportOptions { commit: Some(old) },
            )
            .await
            .unwrap();
        assert_eq!(report.refs, [(Ref::collection(ID, REF), old)]);
        assert_eq!(media_ref(&mount, &format!("mirrors/{ID}/{REF}")), Some(old));
    });
}

/// The commit option takes one ref, and an export needs a ref.
#[test]
fn the_commit_option_takes_one_ref() {
    let tmp = TmpDir::new("media-commit-one-ref");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let tip = commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
        let mount = mount_dir(tmp.path());
        let err = src
            .export_media(
                &mount,
                &[Ref::local(REF), Ref::local("other")],
                MediaExportOptions { commit: Some(tip) },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        let err = export(&src, &mount, &[]).await.unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err:?}");
        assert_untouched(&mount);
    });
}

/// A commit that the source does not hold fails before the export creates a
/// file.
#[test]
fn an_unknown_commit_fails_before_the_destination() {
    let tmp = TmpDir::new("media-unknown-commit");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let mount = mount_dir(tmp.path());
        let err = src
            .export_media(
                &mount,
                &[Ref::local(REF)],
                MediaExportOptions {
                    commit: Some(Checksum::from_bytes([7; 32])),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }), "{err:?}");
        assert_untouched(&mount);
    });
}

/// A tip whose ref binding does not name the ref is refused, also when its
/// collection binding names the collection of the ref.
#[test]
fn a_tip_bound_to_another_ref_is_refused() {
    let tmp = TmpDir::new("media-tip-ref-binding");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let bind = Bind {
            collection: Some(ID),
            refs: Some(&["other"]),
        };
        commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), bind, &[]).await;
        let mount = mount_dir(tmp.path());
        let err = export(&src, &mount, &[Ref::local(REF)]).await.unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        assert_untouched(&mount);
    });
}

/// A commit of the commit option whose ref binding does not name the ref
/// fails before the export creates a file.
#[test]
fn a_commit_bound_to_another_ref_is_refused() {
    let tmp = TmpDir::new("media-ref-binding");
    block_on(async {
        let src = source(tmp.path(), Some(ID)).await;
        let bind = Bind {
            collection: Some(ID),
            refs: Some(&["other"]),
        };
        let tip = commit(&src, tmp.path(), "a", None, bind, &[]).await;
        let mount = mount_dir(tmp.path());
        let err = src
            .export_media(
                &mount,
                &[Ref::local(REF)],
                MediaExportOptions { commit: Some(tip) },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Pull(_)), "{err:?}");
        assert_untouched(&mount);
    });
}

/// Returns `true` if `program` with `args` runs and exits 0. The output is
/// dropped.
fn runs(program: &str, args: &[&std::ffi::OsStr]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Skips the test for `reason`. If [`REQUIRE_MEDIA_FS`] is set, the skip
/// fails the test.
fn skip(reason: &str) {
    assert!(
        std::env::var_os(REQUIRE_MEDIA_FS).is_none(),
        "{REQUIRE_MEDIA_FS} is set and {reason}"
    );
    eprintln!("skipped: {reason}");
}

/// Unmounts the directory when the value drops.
struct Unmount(std::path::PathBuf);

impl Drop for Unmount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
    }
}

/// An export onto a vfat and an exFAT volume writes a media repository that
/// fsck finds whole.
///
/// The test needs root, loop devices, `mkfs.vfat`, and `mkfs.exfat`. Without
/// them it skips with a reason.
#[test]
fn exports_onto_vfat_and_exfat() {
    if !rustix::process::geteuid().is_root() {
        return skip("the test needs root");
    }
    let volumes: [(&str, &str, &[&str]); 2] = [
        ("vfat", "mkfs.vfat", &["-F", "32"]),
        ("exfat", "mkfs.exfat", &[]),
    ];
    for (fs, mkfs, options) in volumes {
        let tmp = TmpDir::new(&format!("media-{fs}"));
        let image = tmp.path().join("image");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 << 20)
            .unwrap();
        let mut args: Vec<&std::ffi::OsStr> = options.iter().map(|o| o.as_ref()).collect();
        args.push(image.as_os_str());
        if !runs(mkfs, &args) {
            return skip(&format!("{mkfs} cannot make a volume"));
        }
        let mount = mount_dir(tmp.path());
        let mounted = runs(
            "mount",
            &[
                "-t".as_ref(),
                fs.as_ref(),
                "-o".as_ref(),
                "loop".as_ref(),
                image.as_os_str(),
                mount.as_os_str(),
            ],
        );
        if !mounted {
            return skip(&format!("the {fs} volume does not mount"));
        }
        let _unmount = Unmount(mount.clone());
        block_on(async {
            let src = source(tmp.path(), Some(ID)).await;
            let tip = commit(&src, tmp.path(), "a", Some(&Ref::local(REF)), BOUND, &[]).await;
            let refs = export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
            assert_eq!(refs, [(Ref::collection(ID, REF), tip)], "{fs}");
            export(&src, &mount, &[Ref::local(REF)]).await.unwrap();
            assert_eq!(media_ref(&mount, &format!("mirrors/{ID}/{REF}")), Some(tip));
            assert_fsck_clean(&media(&mount)).await;
        });
    }
}
