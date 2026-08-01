//! Static-delta generation (Phase 15b), cross-checked against the `ostree` tool.
//!
//! The port commits trees, generates deltas, and then both directions are
//! exercised: the port applies its own delta and reproduces the target commit's
//! objects, and the tool applies the same delta and validates the result with
//! `fsck`. Each delivery route has its own test -- splice, rollsum copy-from-
//! source, bspatch, and loose fallback -- with `ostree static-delta show`
//! confirming which operations the delta actually carries, so a test cannot pass
//! by silently falling back to a plain splice. Signing and the `delta-indexes/`
//! cache are checked the same way, through the tool.
//!
//! Tests needing the tool are skipped when it is absent, matching the other
//! interop tests.

mod common;

use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TmpDir, ostree_available};
use futures_lite::AsyncReadExt;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DeltaOptions,
    Ed25519Signer, Ed25519Verifier, MutableTree, Repo, RepoMode, SummaryOptions, TreeEntry, base64,
};
use ostrya_rt::block_on;

/// The fixed ed25519 keypair shared with the other signing tests.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// Run the `ostree` tool and assert it succeeded.
fn ostree(args: &[&str]) -> Vec<u8> {
    let out = Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree");
    assert!(
        out.status.success(),
        "ostree {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Run the `ostree` tool and return whether it succeeded.
fn ostree_status(args: &[&str]) -> bool {
    Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree")
        .status
        .success()
}

/// Deterministic pseudo-random bytes (xorshift64), so a test's objects are
/// stable across runs.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xff) as u8
        })
        .collect()
}

/// Commit `tree` into `repo` on branch `test`, with canonical permissions so the
/// objects do not depend on the test environment's owner or umask.
async fn commit_tree(repo: &Repo, tree: &Path, parent: Option<Checksum>) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(tree).unwrap();
    let mut modifier = Some(CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    ));
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, modifier.as_mut())
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some("test".to_owned()),
                body: None,
                timestamp: Some(1_700_000_000),
                metadata: None,
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("test", Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// Commit `tree` into `repo` on branch `test` keeping the tree's xattrs. The
/// walk runs under no flags: canonical permissions would record no xattrs, and
/// `SKIP_XATTRS` would not read them.
async fn commit_tree_with_xattrs(repo: &Repo, tree: &Path, parent: Option<Checksum>) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(tree).unwrap();
    let mut modifier: Option<CommitModifier> = None;
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, modifier.as_mut())
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some("test".to_owned()),
                body: None,
                timestamp: Some(1_700_000_000),
                metadata: None,
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("test", Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// Set a user xattr, reporting whether the filesystem under test took it. Not
/// every filesystem supports `user.*` xattrs, so a test that needs one skips
/// rather than failing when it cannot be set.
fn set_user_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
    rustix::fs::setxattr(path, name, value, rustix::fs::XattrFlags::empty()).is_ok()
}

/// A file's xattrs in a commit, as name/value pairs.
async fn file_xattrs(repo: &Repo, rev: &str, path: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let (tree, _) = repo.read_commit(rev).await.unwrap();
    let entry = tree
        .lookup(Path::new(path))
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{path} not found in {rev}"));
    let checksum = match entry {
        TreeEntry::File { checksum, .. } => checksum,
        _ => panic!("{path} is not a file"),
    };
    repo.load_file(&checksum)
        .await
        .unwrap()
        .xattrs
        .iter()
        .map(|(name, value)| (name.to_vec(), value.to_vec()))
        .collect()
}

/// Read a file's content from a commit's tree.
async fn read_file(repo: &Repo, rev: &str, path: &str) -> Vec<u8> {
    let (tree, _) = repo.read_commit(rev).await.unwrap();
    let entry = tree
        .lookup(Path::new(path))
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{path} not found in {rev}"));
    let checksum = match entry {
        TreeEntry::File { checksum, .. } => checksum,
        _ => panic!("{path} is not a file"),
    };
    let mut buf = Vec::new();
    repo.load_file(&checksum)
        .await
        .unwrap()
        .reader()
        .await
        .unwrap()
        .read_to_end(&mut buf)
        .await
        .unwrap();
    buf
}

/// The delta's name as the tool spells it: the target hex, or `<from>-<to>`.
fn delta_name(from: Option<&Checksum>, to: &Checksum) -> String {
    match from {
        Some(from) => format!("{}-{}", from.to_hex(), to.to_hex()),
        None => to.to_hex(),
    }
}

/// The count `ostree static-delta show` reports for an operation, such as
/// `"write="`, summed over the parts it lists.
fn op_count(show: &str, key: &str) -> u64 {
    show.split_whitespace()
        .filter_map(|token| token.strip_prefix(key).and_then(|n| n.parse::<u64>().ok()))
        .sum()
}

/// Whether `haystack` holds `needle` as a run of bytes.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|run| run == needle)
}

/// `ostree static-delta show` for a delta in `repo`.
fn show(repo: &Path, name: &str) -> String {
    String::from_utf8(ostree(&[
        &format!("--repo={}", repo.display()),
        "static-delta",
        "show",
        name,
    ]))
    .unwrap()
}

#[test]
fn from_scratch_delta_round_trips_and_the_tool_applies_it() {
    let tmp = TmpDir::new("gen-scratch");
    let base = tmp.path();

    // A tree mixing a small file, an empty file, a symlink, and an object past
    // the reader's 128 KiB heap threshold, so the part payload spills to a temp
    // file and a zero-length splice is exercised.
    let tree = base.join("tree");
    std::fs::create_dir_all(tree.join("usr/bin")).unwrap();
    std::fs::write(tree.join("usr/bin/app"), b"hello world\n").unwrap();
    std::fs::write(tree.join("usr/bin/empty"), b"").unwrap();
    std::fs::write(tree.join("usr/bin/data.bin"), noise(512 * 1024, 3)).unwrap();
    std::os::unix::fs::symlink("app", tree.join("usr/bin/applink")).unwrap();

    let src = base.join("src");
    let dst = base.join("dst");
    let delta = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        let relative = repo
            .generate_static_delta(None, &commit, &DeltaOptions::default())
            .await
            .unwrap();
        let delta = src.join(relative);

        // The port applies its own delta into a fresh repository.
        let target = Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let applied = target.apply_static_delta_offline(&delta).await.unwrap();
        assert_eq!(applied, commit, "the delta reproduces its target commit");
        assert_eq!(
            read_file(&target, &commit.to_hex(), "usr/bin/data.bin").await,
            noise(512 * 1024, 3)
        );
        assert_eq!(
            read_file(&target, &commit.to_hex(), "usr/bin/app").await,
            b"hello world\n"
        );
        assert!(
            read_file(&target, &commit.to_hex(), "usr/bin/empty")
                .await
                .is_empty()
        );
        target
            .set_ref_immediate("test", Some(&applied))
            .await
            .unwrap();
        delta
    });

    if !ostree_available() {
        eprintln!("skipping tool cross-check: ostree not available");
        return;
    }
    // The tool validates what the port wrote, and applies the same delta itself.
    ostree(&[&format!("--repo={}", dst.display()), "fsck"]);
    let tool = base.join("tool");
    let tool_arg = format!("--repo={}", tool.display());
    ostree(&[&tool_arg, "init", "--mode=archive"]);
    ostree(&[
        &tool_arg,
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&tool_arg, "fsck"]);
    assert_eq!(
        ostree(&[&tool_arg, "cat", &read_ref(&dst), "/usr/bin/app"]),
        b"hello world\n",
        "the tool reads the content the delta delivered"
    );
}

/// The commit `refs/heads/test` points at in a repository, as hex.
fn read_ref(repo: &Path) -> String {
    std::fs::read_to_string(repo.join("refs/heads/test"))
        .expect("read the test ref")
        .trim()
        .to_owned()
}

#[test]
fn from_to_delta_copies_unchanged_runs_out_of_the_source() {
    let tmp = TmpDir::new("gen-rollsum");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // A 2 MiB object edited in place: content-defined chunking finds most of it
    // unchanged, so the delta copies those runs from the source object.
    let v1 = noise(2 * 1024 * 1024, 5);
    let mut v2 = v1.clone();
    for byte in &mut v2[1_048_576..1_049_088] {
        *byte = !*byte;
    }

    let src = base.join("src");
    let (delta, c1, c2) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        std::fs::write(tree.join("big.dat"), &v1).unwrap();
        std::fs::write(tree.join("notes.txt"), b"notes v1\n").unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        std::fs::write(tree.join("big.dat"), &v2).unwrap();
        std::fs::write(tree.join("notes.txt"), b"notes v2\n").unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;

        let relative = repo
            .generate_static_delta(Some(&c1), &c2, &DeltaOptions::default())
            .await
            .unwrap();
        (src.join(relative), c1, c2)
    });

    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }

    // The delta must actually carry copy-from-source writes, or it would not
    // exercise the path under test.
    let listing = show(&src, &delta_name(Some(&c1), &c2));
    assert!(
        op_count(&listing, "write=") > 0 && op_count(&listing, "setread=") > 0,
        "the delta carries no rollsum copies:\n{listing}"
    );

    // A destination holding only the source commit: the tool applies the delta
    // and reproduces the edited object exactly.
    // The tool dispatches the `open` opcode only for bare-family repositories,
    // so a delta that carries copy-from-source writes is applied into bare-user.
    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=bare-user"]);
    ostree(&[&dst_arg, "pull-local", &src.to_string_lossy(), &c1.to_hex()]);
    ostree(&[
        &dst_arg,
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&dst_arg, "fsck"]);
    assert_eq!(
        ostree(&[&dst_arg, "cat", &c2.to_hex(), "/big.dat"]),
        v2,
        "the tool reconstructs the edited object"
    );
    assert_eq!(
        ostree(&[&dst_arg, "cat", &c2.to_hex(), "/notes.txt"]),
        b"notes v2\n"
    );
}

#[test]
fn from_to_delta_patches_a_small_edit_with_bspatch() {
    let tmp = TmpDir::new("gen-bsdiff");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // Below the chunker's minimum chunk size the whole object is one chunk, so
    // an edit leaves nothing to copy and the delta falls to a patch instead.
    let v1 = noise(1024, 7);
    let mut v2 = v1.clone();
    v2[500] ^= 0xff;
    v2[501] ^= 0xff;

    let src = base.join("src");
    let (delta, c1, c2) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        std::fs::write(tree.join("small.dat"), &v1).unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        std::fs::write(tree.join("small.dat"), &v2).unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;
        let relative = repo
            .generate_static_delta(Some(&c1), &c2, &DeltaOptions::default())
            .await
            .unwrap();
        (src.join(relative), c1, c2)
    });

    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }

    let listing = show(&src, &delta_name(Some(&c1), &c2));
    assert!(
        op_count(&listing, "bspatch=") > 0,
        "the delta carries no bspatch stream:\n{listing}"
    );

    // As with rollsum, a patched object needs `open`, so the destination is
    // bare-user.
    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=bare-user"]);
    ostree(&[&dst_arg, "pull-local", &src.to_string_lossy(), &c1.to_hex()]);
    ostree(&[
        &dst_arg,
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&dst_arg, "fsck"]);
    assert_eq!(
        ostree(&[&dst_arg, "cat", &c2.to_hex(), "/small.dat"]),
        v2,
        "the tool applies the patch and reproduces the object"
    );

    // With bsdiff disabled the same edit travels as a plain splice.
    block_on(async {
        let repo = Repo::open(&src).await.unwrap();
        repo.generate_static_delta(
            Some(&c1),
            &c2,
            &DeltaOptions {
                bsdiff: false,
                ..DeltaOptions::default()
            },
        )
        .await
        .unwrap();
    });
    let plain = show(&src, &delta_name(Some(&c1), &c2));
    assert_eq!(
        op_count(&plain, "bspatch="),
        0,
        "bsdiff was disabled but a patch was emitted:\n{plain}"
    );
    assert!(op_count(&plain, "openspliceclose=") > 0);
}

#[test]
fn a_delta_carries_a_files_xattrs_through_the_xattr_table() {
    let tmp = TmpDir::new("gen-xattrs");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("labelled.txt"), b"labelled\n").unwrap();
    std::fs::write(tree.join("plain.txt"), b"plain\n").unwrap();

    // Two files with distinct xattr sets and one with none, so the table holds
    // more than a single entry and the indices have to select between them.
    if !set_user_xattr(&tree.join("labelled.txt"), "user.first", b"one")
        || !set_user_xattr(&tree.join("plain.txt"), "user.second", b"two")
    {
        eprintln!("skipping: the filesystem under test does not take user xattrs");
        return;
    }
    std::fs::write(tree.join("bare.txt"), b"bare\n").unwrap();

    let src = base.join("src");
    let dst = base.join("dst");
    let (delta, commit) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree_with_xattrs(&repo, &tree, None).await;
        let delta = src.join(
            repo.generate_static_delta(None, &commit, &DeltaOptions::default())
                .await
                .unwrap(),
        );

        // The port applies its own delta and reproduces every xattr set.
        let target = Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let applied = target.apply_static_delta_offline(&delta).await.unwrap();
        assert_eq!(applied, commit);
        let rev = commit.to_hex();
        // Stored xattr names carry their terminating NUL, as the tool writes them.
        assert_eq!(
            file_xattrs(&target, &rev, "labelled.txt").await,
            vec![(b"user.first\0".to_vec(), b"one".to_vec())]
        );
        assert_eq!(
            file_xattrs(&target, &rev, "plain.txt").await,
            vec![(b"user.second\0".to_vec(), b"two".to_vec())]
        );
        assert!(file_xattrs(&target, &rev, "bare.txt").await.is_empty());
        (delta, commit)
    });

    if !ostree_available() {
        eprintln!("skipping tool cross-check: ostree not available");
        return;
    }

    // The xattr table is a format structure the tool has to parse, so the counts
    // it reports are asserted before it applies the delta.
    let listing = show(&src, &delta_name(None, &commit));
    assert!(
        listing.contains("nxattrs=3"),
        "the tool did not report three xattr sets:\n{listing}"
    );

    let tool = base.join("tool");
    let tool_arg = format!("--repo={}", tool.display());
    ostree(&[&tool_arg, "init", "--mode=archive"]);
    ostree(&[
        &tool_arg,
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&tool_arg, "fsck"]);
    let listed =
        String::from_utf8(ostree(&[&tool_arg, "ls", "-X", "-R", &commit.to_hex()])).unwrap();
    for expected in ["'user.first', [byte 0x6f", "'user.second', [byte 0x74"] {
        assert!(
            listed.contains(expected),
            "the tool did not reproduce {expected}:\n{listed}"
        );
    }
}

#[test]
fn a_patch_that_loses_to_splicing_is_rejected() {
    let tmp = TmpDir::new("gen-patch-reject");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // Unrelated content at the same path, small enough that a patch is attempted:
    // chunking finds nothing to copy, and the patch that comes back carries about
    // as much novel data as the content itself, so it loses to a splice.
    let v1 = noise(4_096, 41);
    let v2 = noise(4_096, 43);

    let src = base.join("src");
    let (delta, c1, c2) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        std::fs::write(tree.join("rewritten.dat"), &v1).unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        std::fs::write(tree.join("rewritten.dat"), &v2).unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;
        let relative = repo
            .generate_static_delta(Some(&c1), &c2, &DeltaOptions::default())
            .await
            .unwrap();
        (src.join(relative), c1, c2)
    });

    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }

    let listing = show(&src, &delta_name(Some(&c1), &c2));
    assert_eq!(
        op_count(&listing, "bspatch="),
        0,
        "a patch against unrelated content was kept:\n{listing}"
    );
    assert!(
        op_count(&listing, "openspliceclose=") > 0,
        "the rewritten object was not spliced:\n{listing}"
    );

    // A splice-only delta applies into any mode, and the object it delivers is
    // the new content rather than a patched version of the old.
    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=archive"]);
    ostree(&[&dst_arg, "pull-local", &src.to_string_lossy(), &c1.to_hex()]);
    ostree(&[
        &dst_arg,
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&dst_arg, "fsck"]);
    assert_eq!(
        ostree(&[&dst_arg, "cat", &c2.to_hex(), "/rewritten.dat"]),
        v2
    );
}

#[test]
fn part_files_carry_the_pinned_xz_settings() {
    let tmp = TmpDir::new("gen-xz-level");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("data.bin"), noise(300_000, 17)).unwrap();

    let src = base.join("src");
    let delta = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        src.join(
            repo.generate_static_delta(None, &commit, &DeltaOptions::default())
                .await
                .unwrap(),
        )
    });

    // A part file is the compression byte followed by the xz stream, so the
    // stream's own header fields start at offset 1: the 6-byte magic, the two
    // stream flags (a null byte and the check id), and their CRC32. The block
    // header follows at stream offset 12 -- its size byte, its flags, then the
    // filter chain, here one LZMA2 filter (id 0x21) whose single property byte
    // encodes the dictionary size.
    let part = std::fs::read(delta.join("0")).unwrap();
    assert_eq!(part[0], b'x', "part 0 is not xz-compressed");
    let xz = &part[1..];
    assert_eq!(&xz[..6], b"\xfd7zXZ\x00", "no xz stream header");
    assert_eq!(xz[6], 0x00, "unexpected stream flags");
    assert_eq!(xz[7], 0x04, "the check is not CRC64");
    assert_eq!(xz[13] & 0x03, 0x00, "more than one filter in the chain");
    assert_eq!(xz[14], 0x21, "the filter is not LZMA2");
    assert_eq!(xz[15], 0x01, "unexpected LZMA2 property size");
    let prop = u32::from(xz[16]);
    let dict = (2 | (prop & 1)) << (prop / 2 + 11);
    assert_eq!(dict, 32 * 1024 * 1024, "the LZMA2 dictionary is not 32 MiB");
}

/// The index file a target's deltas are listed in, as `reindex` names it.
fn index_path(repo: &Path, to: &Checksum) -> PathBuf {
    let b64 = to.to_base64_modified();
    let (fanout, rest) = b64.split_at(2);
    repo.join("delta-indexes")
        .join(fanout)
        .join(format!("{rest}.index"))
}

/// Every `.index` file under `delta-indexes/`, sorted.
fn index_files(repo: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(fanouts) = std::fs::read_dir(repo.join("delta-indexes")) else {
        return files;
    };
    for fanout in fanouts {
        for entry in std::fs::read_dir(fanout.unwrap().path()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "index") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn reindexing_removes_the_index_of_a_deleted_delta() {
    let tmp = TmpDir::new("gen-reindex-prune");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"first\n").unwrap();

    let src = base.join("src");
    let (c1, c2) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        std::fs::write(tree.join("a.txt"), b"second\n").unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;

        // Two from-scratch deltas, so each target has its own index file.
        let first = src.join(
            repo.generate_static_delta(None, &c1, &DeltaOptions::default())
                .await
                .unwrap(),
        );
        repo.generate_static_delta(None, &c2, &DeltaOptions::default())
            .await
            .unwrap();
        repo.reindex_static_deltas().await.unwrap();
        assert_eq!(index_files(&src).len(), 2, "both targets are indexed");

        std::fs::remove_dir_all(&first).unwrap();
        repo.reindex_static_deltas().await.unwrap();
        (c1, c2)
    });

    assert_eq!(
        index_files(&src),
        vec![index_path(&src, &c2)],
        "the deleted delta's index survived"
    );
    // The tool leaves the fanout directory its removal empties, so the port
    // leaves it too.
    assert!(
        index_path(&src, &c1).parent().unwrap().exists(),
        "the emptied fanout directory was removed"
    );

    if !ostree_available() {
        eprintln!("skipping tool cross-check: ostree not available");
        return;
    }
    let indexes = String::from_utf8(ostree(&[
        &format!("--repo={}", src.display()),
        "static-delta",
        "indexes",
    ]))
    .unwrap();
    let listed: Vec<&str> = indexes.lines().map(str::trim).collect();
    assert!(
        listed.contains(&c2.to_hex().as_str()),
        "the remaining delta is not indexed:\n{indexes}"
    );
    assert!(
        !listed.contains(&c1.to_hex().as_str()),
        "the tool still lists the deleted delta:\n{indexes}"
    );
}

#[test]
fn reindexing_refuses_an_oversized_superblock() {
    let tmp = TmpDir::new("gen-reindex-oversized");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"indexed\n").unwrap();

    let src = base.join("src");
    block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        let delta = src.join(
            repo.generate_static_delta(None, &commit, &DeltaOptions::default())
                .await
                .unwrap(),
        );
        repo.reindex_static_deltas().await.unwrap();

        // One byte past the format's 128 MiB metadata ceiling, which the
        // superblock is bounded by. The file is sparse, so it costs no disk.
        let superblock = std::fs::OpenOptions::new()
            .write(true)
            .open(delta.join("superblock"))
            .unwrap();
        superblock.set_len(128 * 1024 * 1024 + 1).unwrap();
        drop(superblock);

        // Indexing a prefix would publish a digest that covers part of the
        // superblock, so the pass fails instead.
        let err = repo
            .reindex_static_deltas()
            .await
            .expect_err("an oversized superblock must fail the index pass");
        assert!(
            err.to_string().contains("exceeds the size ceiling"),
            "unexpected error for an oversized superblock: {err}"
        );
    });
}

#[test]
fn a_zero_fallback_threshold_packs_every_object() {
    let tmp = TmpDir::new("gen-fallback-zero");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    let big = noise(1_500_000, 13);
    let src = base.join("src");
    let dst = base.join("dst");
    let (delta, commit) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        std::fs::write(tree.join("big.dat"), &big).unwrap();
        let commit = commit_tree(&repo, &tree, None).await;

        // A zero threshold turns fallbacks off, matching the tool, so the
        // object travels inside a part however large it is.
        let delta = src.join(
            repo.generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    min_fallback_size: 0,
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap(),
        );

        // The destination holds none of the objects, so application succeeds
        // only if the delta carries the content itself.
        let target = Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let applied = target.apply_static_delta_offline(&delta).await.unwrap();
        assert_eq!(applied, commit);
        assert_eq!(read_file(&target, &commit.to_hex(), "big.dat").await, big);
        (delta, commit)
    });

    if !ostree_available() {
        eprintln!("skipping tool cross-check: ostree not available");
        return;
    }

    let listing = show(&src, &delta_name(None, &commit));
    assert!(
        listing.contains("Number of fallback entries: 0"),
        "a zero threshold named a fallback:\n{listing}"
    );
    // With no fallback entries the tool's offline applier takes the delta.
    let tool = base.join("tool");
    block_on(async {
        Repo::create(&tool, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
    });
    ostree(&[
        &format!("--repo={}", tool.display()),
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&format!("--repo={}", tool.display()), "fsck"]);
    assert_eq!(
        ostree(&[
            &format!("--repo={}", tool.display()),
            "cat",
            &commit.to_hex(),
            "/big.dat"
        ]),
        big
    );
}

#[test]
fn a_large_object_travels_as_a_fallback() {
    let tmp = TmpDir::new("gen-fallback");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    // The threshold is lowered rather than writing a 4 MB object: the rule is
    // the same, and the test stays fast.
    let big = noise(1_500_000, 11);
    let src = base.join("src");
    let dst = base.join("dst");
    let (fallback_delta, c2) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        std::fs::write(tree.join("big.dat"), &big).unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        // A second commit sharing the large object, with one more small file.
        std::fs::write(tree.join("extra.txt"), b"extra\n").unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;

        // The first commit's delta packs everything (the default threshold is
        // well above the object), so applying it seeds the destination with the
        // large object.
        let seed = src.join(
            repo.generate_static_delta(None, &c1, &DeltaOptions::default())
                .await
                .unwrap(),
        );
        // The threshold is lowered rather than writing a 4 MB object: the rule is
        // the same, and the test stays fast.
        let fallback_delta = src.join(
            repo.generate_static_delta(
                None,
                &c2,
                &DeltaOptions {
                    min_fallback_size: 1_000_000,
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap(),
        );

        // Without the fallback object present, application refuses up front
        // rather than writing a partial commit.
        let empty = Repo::create(&base.join("empty"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let err = empty
            .apply_static_delta_offline(&fallback_delta)
            .await
            .expect_err("a missing fallback object must fail the application");
        assert!(
            matches!(err, ostrya::Error::ObjectNotFound { .. }),
            "unexpected error for a missing fallback object: {err}"
        );

        let target = Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        target.apply_static_delta_offline(&seed).await.unwrap();
        let applied = target
            .apply_static_delta_offline(&fallback_delta)
            .await
            .unwrap();
        assert_eq!(applied, c2);
        assert_eq!(read_file(&target, &c2.to_hex(), "big.dat").await, big);
        assert_eq!(
            read_file(&target, &c2.to_hex(), "extra.txt").await,
            b"extra\n"
        );
        target
            .set_ref_immediate("test", Some(&applied))
            .await
            .unwrap();
        (fallback_delta, c2)
    });

    if !ostree_available() {
        eprintln!("skipping tool cross-check: ostree not available");
        return;
    }

    let listing = show(&src, &delta_name(None, &c2));
    assert!(
        listing.contains("Number of fallback entries: 1"),
        "the large object was packed instead of named as a fallback:\n{listing}"
    );
    // The tool's offline applier refuses any delta carrying fallback entries
    // ("contains nonempty http fallback entries"), so its cross-check here is
    // `fsck` over the objects the port's own application wrote.
    assert!(
        !ostree_status(&[
            &format!("--repo={}", base.join("tool").display()),
            "static-delta",
            "apply-offline",
            &fallback_delta.to_string_lossy(),
        ]),
        "the tool applied a delta with fallback entries offline"
    );
    ostree(&[&format!("--repo={}", dst.display()), "fsck"]);
    assert_eq!(
        ostree(&[
            &format!("--repo={}", dst.display()),
            "cat",
            &c2.to_hex(),
            "/big.dat"
        ]),
        big
    );
}

#[test]
fn the_fallback_threshold_classifies_an_object_as_the_tool_does() {
    // The size compared against the threshold is the file header variant plus
    // seven bytes plus the content (`FALLBACK_FRAMING` in deltagen.rs). A
    // canonical `uid=gid=0` no-xattr file's header is 18 bytes, so at a
    // 1,000,000-byte threshold the largest content still packed is 999,974 and
    // 999,975 becomes a fallback. The tool takes the same threshold as its
    // decimal-megabyte 1, so both sides of the boundary are cross-checked against
    // it.
    let tmp = TmpDir::new("gen-fallback-boundary");
    let base = tmp.path();

    for (size, packed) in [(999_974usize, true), (999_975usize, false)] {
        let tree = base.join(format!("tree-{size}"));
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("f.dat"), noise(size, 53)).unwrap();

        let src = base.join(format!("src-{size}"));
        let dst = base.join(format!("dst-{size}"));
        let commit = block_on(async {
            let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let commit = commit_tree(&repo, &tree, None).await;
            let delta = src.join(
                repo.generate_static_delta(
                    None,
                    &commit,
                    &DeltaOptions {
                        min_fallback_size: 1_000_000,
                        ..DeltaOptions::default()
                    },
                )
                .await
                .unwrap(),
            );

            // A destination holding none of the objects: the delta applies only
            // when the object travelled inside a part, and refuses up front when
            // it is named as a fallback that is absent.
            let target = Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let outcome = target.apply_static_delta_offline(&delta).await;
            if packed {
                assert_eq!(
                    outcome.unwrap(),
                    commit,
                    "content of {size} bytes was not packed"
                );
            } else {
                assert!(
                    matches!(outcome, Err(ostrya::Error::ObjectNotFound { .. })),
                    "content of {size} bytes was packed instead of named as a fallback"
                );
            }
            commit
        });

        if !ostree_available() {
            continue;
        }
        // The tool's own delta over the same commit at the same threshold, which
        // overwrites the port's at that location, so `show` reports the tool's
        // classification of the same object.
        let src_arg = format!("--repo={}", src.display());
        ostree(&[
            &src_arg,
            "static-delta",
            "generate",
            "--empty",
            &format!("--to={}", commit.to_hex()),
            "--min-fallback-size=1",
        ]);
        let expected = if packed {
            "Number of fallback entries: 0"
        } else {
            "Number of fallback entries: 1"
        };
        let listing = show(&src, &delta_name(None, &commit));
        assert!(
            listing.contains(expected),
            "the tool classified content of {size} bytes differently: expected \
             {expected}\n{listing}"
        );
    }

    if !ostree_available() {
        eprintln!("skipping tool cross-check: ostree not available");
    }
}

#[test]
fn the_chunk_ceiling_splits_the_delta_into_parts() {
    let tmp = TmpDir::new("gen-parts");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for i in 0..4u64 {
        std::fs::write(tree.join(format!("f{i}.dat")), noise(400_000, 13 + i)).unwrap();
    }

    let src = base.join("src");
    let (delta, commit) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        let relative = repo
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    max_chunk_size: 500_000,
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        (src.join(relative), commit)
    });

    // Four 400 KB objects under a 500 KB ceiling cannot share a part.
    let parts = std::fs::read_dir(&delta)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().parse::<u32>().is_ok())
        .count();
    assert!(parts >= 4, "expected at least four parts, got {parts}");

    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=archive"]);
    ostree(&[
        &dst_arg,
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&dst_arg, "fsck"]);
    assert_eq!(
        ostree(&[&dst_arg, "cat", &commit.to_hex(), "/f3.dat"]),
        noise(400_000, 16)
    );
}

#[test]
fn a_signed_delta_verifies_and_indexes() {
    let tmp = TmpDir::new("gen-signed");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"signed content\n").unwrap();

    let src = base.join("src");
    let (delta, commit) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        let relative = repo
            .generate_static_delta(None, &commit, &DeltaOptions::default())
            .await
            .unwrap();
        let delta = src.join(relative);

        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        repo.sign_static_delta(&delta, &signer).await.unwrap();

        // The port's own verifier accepts the trusted key and rejects another.
        let trusted =
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap();
        let outcome = repo.verify_static_delta(&delta, &[&trusted]).await.unwrap();
        assert!(outcome.valid, "the signed delta verifies");
        let other = Ed25519Verifier::new([vec![0u8; 32]], Vec::<Vec<u8>>::new()).unwrap();
        assert!(
            !repo
                .verify_static_delta(&delta, &[&other])
                .await
                .unwrap()
                .valid
        );

        // Signing rewrote the superblock, so the index is built afterwards.
        repo.reindex_static_deltas().await.unwrap();
        (delta, commit)
    });

    // A signed delta still applies, and its index names the target commit.
    assert!(
        std::fs::read(delta.join("superblock"))
            .unwrap()
            .starts_with(b"OSTSGNDT"),
        "the superblock is not wrapped in the signed envelope"
    );

    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    let src_arg = format!("--repo={}", src.display());
    let name = delta_name(None, &commit);
    assert!(
        ostree_status(&[&src_arg, "static-delta", "verify", &name, PUBLIC_B64]),
        "the tool rejected the port's signature"
    );
    assert!(
        !ostree_status(&[
            &src_arg,
            "static-delta",
            "verify",
            &name,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ]),
        "the tool accepted the signature under a foreign key"
    );

    let indexes = String::from_utf8(ostree(&[&src_arg, "static-delta", "indexes"])).unwrap();
    assert!(
        indexes.lines().any(|line| line.trim() == commit.to_hex()),
        "the index does not list the target commit:\n{indexes}"
    );

    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=archive"]);
    ostree(&[
        &dst_arg,
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&dst_arg, "fsck"]);
}

/// A delta carries a copy of the target commit's detached metadata in its
/// superblock, keyed by the delta's own directory with `/commitmeta` appended,
/// and that copy is what a tool pull checks the delivered commit against. The
/// tool pulls the port's delta under `sign-verify=ed25519`, over a `file://`
/// remote with `--require-static-deltas`, so the delta path is the one under
/// test. A delta over a commit with no detached metadata carries no such entry
/// and still delivers its commit.
#[test]
fn a_delta_carries_the_target_commits_detached_metadata() {
    let tmp = TmpDir::new("gen-commitmeta");
    let base = tmp.path();
    let signed_tree = base.join("signed-tree");
    let plain_tree = base.join("plain-tree");
    std::fs::create_dir_all(&signed_tree).unwrap();
    std::fs::create_dir_all(&plain_tree).unwrap();
    std::fs::write(signed_tree.join("a.txt"), b"signed content\n").unwrap();
    std::fs::write(plain_tree.join("a.txt"), b"unsigned content\n").unwrap();

    let signed_src = base.join("signed");
    let plain_src = base.join("plain");
    let (signed_delta, signed_commit, plain_delta, plain_commit) = block_on(async {
        let mut built = Vec::new();
        for (path, tree, sign) in [
            (&signed_src, &signed_tree, true),
            (&plain_src, &plain_tree, false),
        ] {
            let repo = Repo::create(path, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let commit = commit_tree(&repo, tree, None).await;
            if sign {
                let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
                repo.sign_commit(&commit, &signer).await.unwrap();
            }
            let relative = repo
                .generate_static_delta(None, &commit, &DeltaOptions::default())
                .await
                .unwrap();
            // The tool discovers a delta through the summary and the index, so
            // both are written before it pulls.
            repo.reindex_static_deltas().await.unwrap();
            repo.regenerate_summary(&SummaryOptions::default())
                .await
                .unwrap();
            built.push((relative, commit));
        }
        let plain = built.pop().unwrap();
        let signed = built.pop().unwrap();
        (signed.0, signed.1, plain.0, plain.1)
    });

    // The signed commit's copy is the `.commitmeta` file's own bytes, under the
    // delta's directory.
    let superblock = std::fs::read(signed_src.join(&signed_delta).join("superblock")).unwrap();
    let key = format!("{}/commitmeta", signed_delta.display());
    assert!(
        holds(&superblock, key.as_bytes()),
        "the superblock carries no {key} entry"
    );
    let hex = signed_commit.to_hex();
    let detached = signed_src
        .join("objects")
        .join(&hex[..2])
        .join(format!("{}.commitmeta", &hex[2..]));
    assert!(
        holds(&superblock, &std::fs::read(&detached).unwrap()),
        "the superblock does not carry the .commitmeta bytes verbatim"
    );

    // The unsigned commit has no detached metadata, so its delta gets no entry.
    let plain_superblock = std::fs::read(plain_src.join(&plain_delta).join("superblock")).unwrap();
    assert!(
        !holds(&plain_superblock, b"/commitmeta"),
        "a commit with no detached metadata got a commitmeta entry"
    );

    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    // A delta destination has to be bare-user: the tool refuses static deltas in
    // an archive repository.
    for (src, commit, verify) in [
        (&signed_src, &signed_commit, true),
        (&plain_src, &plain_commit, false),
    ] {
        let dest = base.join(format!("dest-{}", src.file_name().unwrap().display()));
        let dest_arg = format!("--repo={}", dest.display());
        ostree(&[&dest_arg, "init", "--mode=bare-user"]);
        let url = format!("file://{}", src.display());
        let mut add = vec![
            &dest_arg,
            "remote",
            "add",
            "origin",
            &url,
            "--no-gpg-verify",
        ];
        let key_arg = format!("--set=verification-ed25519-key={PUBLIC_B64}");
        if verify {
            add.push("--set=sign-verify=ed25519");
            add.push(&key_arg);
        }
        ostree(&add);
        ostree(&[
            &dest_arg,
            "pull",
            "--require-static-deltas",
            "origin",
            "test",
        ]);
        let resolved = String::from_utf8(ostree(&[&dest_arg, "rev-parse", "origin:test"])).unwrap();
        assert_eq!(resolved.trim(), commit.to_hex());
        ostree(&[&dest_arg, "fsck"]);
    }
}

#[test]
fn a_metadata_only_change_delivers_an_empty_mode_table() {
    let tmp = TmpDir::new("gen-metaonly");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"unchanged\n").unwrap();

    // Adding an empty directory changes the tree metadata and nothing else, so
    // the delta carries dirtree and dirmeta objects and no content object at
    // all: the part's mode and xattr tables come out empty.
    let src = base.join("src");
    let (delta, c1, c2) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        std::fs::create_dir(tree.join("newdir")).unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;
        let relative = repo
            .generate_static_delta(Some(&c1), &c2, &DeltaOptions::default())
            .await
            .unwrap();
        (src.join(relative), c1, c2)
    });

    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    let listing = show(&src, &delta_name(Some(&c1), &c2));
    assert!(
        listing.contains("nmodes=0 nxattrs=0"),
        "expected empty mode and xattr tables:\n{listing}"
    );

    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=archive"]);
    ostree(&[&dst_arg, "pull-local", &src.to_string_lossy(), &c1.to_hex()]);
    ostree(&[
        &dst_arg,
        "static-delta",
        "apply-offline",
        &delta.to_string_lossy(),
    ]);
    ostree(&[&dst_arg, "fsck"]);
    let listed = String::from_utf8(ostree(&[&dst_arg, "ls", "-R", &c2.to_hex()])).unwrap();
    assert!(
        listed.contains("/newdir"),
        "missing new directory:\n{listed}"
    );
}

#[test]
fn generation_is_reproducible_for_a_pinned_timestamp() {
    let tmp = TmpDir::new("gen-repro");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"one\n").unwrap();
    std::fs::write(tree.join("b.bin"), noise(200_000, 17)).unwrap();

    let src = base.join("src");
    let first = base.join("out-1");
    let second = base.join("out-2");
    block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        for out in [&first, &second] {
            repo.generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    timestamp: Some(1_700_000_500),
                    output_dir: Some(out.clone()),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        }
    });

    for name in ["superblock", "0"] {
        assert_eq!(
            std::fs::read(first.join(name)).unwrap(),
            std::fs::read(second.join(name)).unwrap(),
            "{name} differs between two runs over the same input"
        );
    }
}

#[test]
fn a_failed_regeneration_leaves_no_superblock_behind() {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipping: root ignores the directory permissions this test relies on");
        return;
    }

    let tmp = TmpDir::new("gen-regen-fail");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    // Past the 128 KiB spill threshold, so the payload needs a temp file.
    std::fs::write(tree.join("big.dat"), noise(512 * 1024, 47)).unwrap();

    let src = base.join("src");
    let delta: PathBuf = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        let delta = src.join(
            repo.generate_static_delta(None, &commit, &DeltaOptions::default())
                .await
                .unwrap(),
        );
        assert!(delta.join("superblock").exists());

        // Regeneration overwrites the parts in place, so the superblock has to go
        // first: a run that fails partway must not leave one describing files it
        // has already replaced. The spill directory is made unwritable so this
        // run fails after the delta directory is opened and before any part is
        // written.
        let spill = src.join("tmp");
        std::fs::set_permissions(&spill, std::fs::Permissions::from_mode(0o555)).unwrap();
        let outcome = repo
            .generate_static_delta(None, &commit, &DeltaOptions::default())
            .await;
        std::fs::set_permissions(&spill, std::fs::Permissions::from_mode(0o755)).unwrap();
        outcome.expect_err("an unwritable spill directory must fail the generation");
        delta
    });

    assert!(
        !delta.join("superblock").exists(),
        "the failed regeneration left a superblock describing parts it was replacing"
    );
    assert!(
        delta.join("0").exists(),
        "the test did not reach the point where parts are written"
    );
}

#[test]
fn regenerating_over_a_longer_delta_removes_its_extra_parts() {
    let tmp = TmpDir::new("gen-stale");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for i in 0..3u64 {
        std::fs::write(tree.join(format!("f{i}.dat")), noise(300_000, 19 + i)).unwrap();
    }

    let src = base.join("src");
    let delta: PathBuf = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        // A tight ceiling first, so the delta has several parts.
        let relative = repo
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    max_chunk_size: 400_000,
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        let delta = src.join(&relative);
        assert!(delta.join("2").exists(), "expected a multi-part delta");

        // Then the default ceiling, which fits everything in one part.
        repo.generate_static_delta(None, &commit, &DeltaOptions::default())
            .await
            .unwrap();
        delta
    });

    assert!(delta.join("0").exists());
    assert!(
        !delta.join("1").exists() && !delta.join("2").exists(),
        "part files from the previous delta were left behind"
    );
}

/// Set a file's mtime `seconds` into the past, so a test can age a temp file the
/// sweep decides on by age.
fn backdate(path: &Path, seconds: i64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let when = rustix::fs::Timespec {
        tv_sec: now - seconds,
        tv_nsec: 0,
    };
    rustix::fs::utimensat(
        rustix::fs::CWD,
        path,
        &rustix::fs::Timestamps {
            last_access: when,
            last_modification: when,
        },
        rustix::fs::AtFlags::empty(),
    )
    .unwrap();
}

#[test]
fn regenerating_removes_a_stale_temp_file_and_leaves_a_fresh_one() {
    let tmp = TmpDir::new("gen-temp-leftover");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"content\n").unwrap();

    let src = base.join("src");
    let delta: PathBuf = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        let delta = src.join(
            repo.generate_static_delta(None, &commit, &DeltaOptions::default())
                .await
                .unwrap(),
        );

        // Two temp names of the shape a generation killed between creating a part
        // and renaming it into place leaves behind. The old one is a leftover and
        // goes; the fresh one may be the file a generation running right now is
        // still writing, and unlinking it would fail that run's rename.
        std::fs::write(delta.join(".0.tmp-1-1"), b"partial").unwrap();
        backdate(&delta.join(".0.tmp-1-1"), 2 * 60 * 60);
        std::fs::write(delta.join(".0.tmp-1-2"), b"in flight").unwrap();
        repo.generate_static_delta(None, &commit, &DeltaOptions::default())
            .await
            .unwrap();
        delta
    });

    let mut names: Vec<String> = std::fs::read_dir(&delta)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    // A delta directory holds its superblock, its numbered parts, and whatever
    // temp file is too young for the sweep to judge abandoned.
    assert_eq!(
        names,
        vec![".0.tmp-1-2", "0", "superblock"],
        "unexpected delta directory contents: {names:?}"
    );
}

#[test]
fn generating_into_an_output_dir_leaves_the_callers_files_alone() {
    let tmp = TmpDir::new("gen-output-dir-foreign");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"content\n").unwrap();

    let src = base.join("src");
    let out = base.join("out");
    std::fs::create_dir_all(&out).unwrap();
    // Names a delta's own files take, in a directory that is the caller's: a
    // numeric name past the part count this delta writes, and a temp name old
    // enough for the repository sweep to remove.
    std::fs::write(out.join("7"), b"the caller's chapter seven\n").unwrap();
    std::fs::write(out.join(".notes.tmp-1-1"), b"the caller's draft\n").unwrap();
    backdate(&out.join(".notes.tmp-1-1"), 2 * 60 * 60);

    block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        repo.generate_static_delta(
            None,
            &commit,
            &DeltaOptions {
                output_dir: Some(out.clone()),
                ..DeltaOptions::default()
            },
        )
        .await
        .unwrap();
    });

    assert_eq!(
        std::fs::read(out.join("7")).unwrap(),
        b"the caller's chapter seven\n",
        "generation removed a file it does not own"
    );
    assert_eq!(
        std::fs::read(out.join(".notes.tmp-1-1")).unwrap(),
        b"the caller's draft\n",
        "generation removed a file it does not own"
    );
    assert!(out.join("superblock").exists() && out.join("0").exists());
}
