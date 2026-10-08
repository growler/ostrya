//! The commit timestamp that `SOURCE_DATE_EPOCH` sets.
//!
//! If [`CommitOptions::timestamp`](ostrya::CommitOptions) is unset,
//! `SOURCE_DATE_EPOCH` supplies the commit timestamp. If the variable holds
//! the fixture epoch, the commit is equal to the fixture commit, byte for
//! byte.
//!
//! This test has a test binary of its own with one test, so the write to the
//! environment is sound. The write occurs on the only thread of the process,
//! before the blocking pool starts a thread. As a result, no concurrent
//! `getenv` can race the `setenv`.

mod common;

use std::path::Path;

use common::{COMMIT, TmpDir};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, MutableTree, Repo,
    RepoMode, Type, Value,
};
use ostrya_rt::block_on;
use std::os::fd::AsFd;

fn build_fixture_source(base: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let set_mode = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    let src = base.join("src");
    std::fs::create_dir_all(src.join("subdir")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello ostree\n").unwrap();
    std::fs::write(src.join("empty.txt"), b"").unwrap();
    std::fs::write(src.join("subdir/nested.txt"), b"nested\n").unwrap();
    std::os::unix::fs::symlink("hello.txt", src.join("link")).unwrap();
    set_mode(&src.join("hello.txt"), 0o644);
    set_mode(&src.join("empty.txt"), 0o644);
    set_mode(&src.join("subdir/nested.txt"), 0o644);
    set_mode(&src.join("subdir"), 0o755);
    set_mode(&src, 0o755);
}

fn ref_binding() -> Value {
    Value::Array(vec![Value::Tuple(vec![
        Value::Str("ostree.ref-binding".to_owned()),
        Value::variant(
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str("test/main".to_owned())]),
        ),
    ])])
}

#[test]
fn source_date_epoch_pins_the_commit_timestamp() {
    // The write occurs before a blocking-pool thread exists. This binary has
    // one test, so this thread is the only thread, and the write cannot race
    // a concurrent read.
    unsafe {
        std::env::set_var("SOURCE_DATE_EPOCH", "1700000000");
    }

    let tmp = TmpDir::new("commit-sde");
    let base = tmp.path();
    build_fixture_source(base);
    let root_dir = base.join("repo");
    block_on(async {
        let repo = Repo::create(&root_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
        );
        let mut mtree = MutableTree::new();
        let dfd = std::fs::File::open(base).unwrap();
        txn.write_dfd_to_mtree(
            dfd.as_fd(),
            Path::new("src"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await
        .unwrap();
        let root = txn.write_mtree(&mut mtree).await.unwrap();

        // The options give no timestamp. `SOURCE_DATE_EPOCH` supplies the
        // fixture epoch, so the commit is equal to the fixture commit, byte for
        // byte, and the two checksums are equal.
        let commit = txn
            .write_commit(
                CommitOptions {
                    subject: Some("fixture commit".to_owned()),
                    timestamp: None,
                    metadata: Some(ref_binding()),
                    ..CommitOptions::default()
                },
                &root,
            )
            .await
            .unwrap();
        assert_eq!(
            commit,
            Checksum::from_hex(COMMIT).unwrap(),
            "SOURCE_DATE_EPOCH pinned the timestamp to the fixture epoch"
        );
    });
}
