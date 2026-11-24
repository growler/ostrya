//! The list of the refs that a pull changed.
//!
//! Each test of a pull from a remote serves a repository directory from an
//! in-process static file server. Each test of a local pull reads the remote
//! repository directly.

mod common;
#[path = "common/pull.rs"]
mod pull;

use common::TmpDir;
use ostrya::{
    Checksum, CreateOptions, PullFlags, PullOptions, PullReport, Ref, RefChange, Repo, RepoMode,
    SummaryOptions, commit_operand,
};
use ostrya_rt::block_on;
use pull::*;

/// Returns the entries of `report` as triples, for the comparison with the
/// expected list.
fn changes(report: &PullReport) -> Vec<(Ref, Option<Checksum>, Checksum)> {
    report
        .changed_refs
        .iter()
        .map(|RefChange { name, old, new, .. }| (name.clone(), *old, *new))
        .collect()
}

/// Returns the options of a pull of `refs`.
fn refs(refs: &[&str]) -> PullOptions {
    PullOptions {
        refs: refs.iter().map(|r| (*r).to_owned()).collect(),
        ..PullOptions::default()
    }
}

/// Commits a second tree to `test/main` of `remote`, with `parent` as its
/// parent, and writes the summary again. Returns the new commit.
async fn advance(remote: &Repo, dir: &std::path::Path, parent: Checksum) -> Checksum {
    build_tree(&dir.join("src2"), b"hello again\n");
    let commit = commit_tree(remote, dir, "src2", "test/main", Some(parent), FIXED_TS + 1).await;
    remote
        .regenerate_summary(&SummaryOptions {
            last_modified: Some(FIXED_TS + 1),
            ..SummaryOptions::default()
        })
        .await
        .unwrap();
    commit
}

/// A pull over HTTP lists the remote ref that it writes: first as a new ref,
/// then as a ref that moved. A pull at the same commit lists nothing. Into
/// two new destinations, the statistics of the report equal those of `pull`.
#[test]
fn an_http_pull_lists_a_new_ref_and_a_moved_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-report-http");
        let (remote, first) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        let main = Ref::remote("origin", "test/main");

        let report = dest
            .pull_with_report("origin", refs(&["test/main"]))
            .await
            .unwrap();
        assert_eq!(changes(&report), [(main.clone(), None, first)]);
        assert_eq!(report.stats.content_imported, 4);

        let second = advance(&remote, dir.path(), first).await;
        let report = dest
            .pull_with_report("origin", refs(&["test/main"]))
            .await
            .unwrap();
        assert_eq!(changes(&report), [(main.clone(), Some(first), second)]);

        let report = dest
            .pull_with_report("origin", refs(&["test/main"]))
            .await
            .unwrap();
        assert!(report.changed_refs.is_empty(), "{report:?}");

        // `pull` gives the statistics of the report.
        let plain = dir.path().join("plain");
        let reported = dir.path().join("reported");
        std::fs::create_dir(&plain).unwrap();
        std::fs::create_dir(&reported).unwrap();
        let plain = build_dest(&plain, RepoMode::Archive, &server.url(), "").await;
        let reported = build_dest(&reported, RepoMode::Archive, &server.url(), "").await;
        let stats = plain.pull("origin", refs(&["test/main"])).await.unwrap();
        let report = reported
            .pull_with_report("origin", refs(&["test/main"]))
            .await
            .unwrap();
        assert_eq!(changes(&report), [(main, None, second)]);
        assert!(stats.content_fetched > 0, "{stats:?}");
        assert_eq!(
            ostrya::PullStats {
                elapsed: report.stats.elapsed,
                ..stats
            },
            report.stats
        );
    });
}

/// A `CHECKSUM` operand and a pull with no ref writes list nothing. A
/// `REF@CHECKSUM` operand lists its ref.
#[test]
fn an_http_pull_lists_only_the_refs_that_it_writes() {
    block_on(async {
        let dir = TmpDir::new("pull-report-http-operands");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let report = dest
            .pull_with_report("origin", refs(&[&commit.to_hex()]))
            .await
            .unwrap();
        assert!(report.changed_refs.is_empty(), "{report:?}");

        let report = dest
            .pull_with_report(
                "origin",
                PullOptions {
                    no_ref_writes: true,
                    ..refs(&["test/main"])
                },
            )
            .await
            .unwrap();
        assert!(report.changed_refs.is_empty(), "{report:?}");
        assert!(dest.list_remote_refs().await.unwrap().is_empty());

        let operand = commit_operand(&Ref::local("test/main"), &commit);
        let report = dest
            .pull_with_report("origin", refs(&[&operand]))
            .await
            .unwrap();
        assert_eq!(
            changes(&report),
            [(Ref::remote("origin", "test/main"), None, commit)]
        );
    });
}

/// A mirror pull lists the local ref that it writes.
#[test]
fn a_mirror_pull_lists_a_local_ref() {
    block_on(async {
        let dir = TmpDir::new("pull-report-mirror");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;

        let report = dest
            .pull_with_report(
                "origin",
                PullOptions {
                    flags: PullFlags::MIRROR,
                    ..PullOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(changes(&report), [(Ref::local("test/main"), None, commit)]);
    });
}

/// A mirror pull that fails after the ref write returns the error and no
/// list. A directory at the path of the summary fails the copy of the
/// summary of the remote.
#[test]
fn a_mirror_pull_that_fails_after_the_ref_write_returns_the_error() {
    block_on(async {
        let dir = TmpDir::new("pull-report-mirror-fails");
        let (_remote, commit) = build_remote(dir.path()).await;
        let server = RepoServer::start(&dir.path().join("remote"), false).await;
        let dest = build_dest(dir.path(), RepoMode::Archive, &server.url(), "").await;
        std::fs::create_dir_all(dir.path().join("dest/summary/blocked")).unwrap();

        let result = dest
            .pull_with_report(
                "origin",
                PullOptions {
                    flags: PullFlags::MIRROR,
                    ..PullOptions::default()
                },
            )
            .await;
        assert!(matches!(result, Err(ostrya::Error::Io(_))), "{result:?}");
        assert_eq!(
            dest.resolve_ref_tip(&Ref::local("test/main"))
                .await
                .unwrap(),
            Some(commit)
        );
    });
}

/// A local pull lists a new ref, then nothing at the same commit, then the
/// ref that moved. With a remote name, the entry is a remote ref. An
/// `@ID:NAME` operand gives a collection ref.
#[test]
fn a_local_pull_lists_the_refs_that_it_changes() {
    block_on(async {
        let dir = TmpDir::new("pull-report-local");
        let (remote, commit) = build_remote(dir.path()).await;
        let collected = commit_bound(
            &remote,
            dir.path(),
            "src",
            &Ref::collection(ID_X, "a"),
            Some(ID_X),
        )
        .await;
        let dest = Repo::create(
            &dir.path().join("local"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();

        let report = dest
            .pull_local_with_report(&remote, refs(&["test/main"]))
            .await
            .unwrap();
        assert_eq!(changes(&report), [(Ref::local("test/main"), None, commit)]);
        assert!(report.stats.content_imported > 0, "{report:?}");

        let report = dest
            .pull_local_with_report(&remote, refs(&["test/main"]))
            .await
            .unwrap();
        assert!(report.changed_refs.is_empty(), "{report:?}");

        let second = advance(&remote, dir.path(), commit).await;
        let report = dest
            .pull_local_with_report(&remote, refs(&["test/main"]))
            .await
            .unwrap();
        assert_eq!(
            changes(&report),
            [(Ref::local("test/main"), Some(commit), second)]
        );

        let report = dest
            .pull_local_with_report(
                &remote,
                PullOptions {
                    remote: Some("origin".to_owned()),
                    ..refs(&["test/main"])
                },
            )
            .await
            .unwrap();
        assert_eq!(
            changes(&report),
            [(Ref::remote("origin", "test/main"), None, second)]
        );

        let operand = format!("@{ID_X}:a");
        let report = dest
            .pull_local_with_report(&remote, refs(&[&operand]))
            .await
            .unwrap();
        assert_eq!(
            changes(&report),
            [(Ref::collection(ID_X, "a"), None, collected)]
        );

        let report = dest
            .pull_local_with_report(
                &remote,
                PullOptions {
                    no_ref_writes: true,
                    ..refs(&["test/main"])
                },
            )
            .await
            .unwrap();
        assert!(report.changed_refs.is_empty(), "{report:?}");
    });
}
