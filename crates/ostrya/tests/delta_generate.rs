//! Integration tests for static-delta generation, checked against the `ostree`
//! command.
//!
//! ostrya commits trees and generates deltas. The tests then check both
//! directions:
//!
//! - ostrya applies its own delta and gives the objects of the target commit.
//! - The `ostree` command applies the same delta and verifies the result with
//!   `fsck`.
//!
//! Each delivery route has its own test: splice, rollsum copy-from-source,
//! bspatch, and loose fallback. `ostree static-delta show` tells which
//! operations the delta carries, so a test cannot pass if the delta falls back
//! to a plain splice without notice. The tests check signing and the
//! `delta-indexes/` cache through the `ostree` command too.
//!
//! If the `ostree` command is not available, the tests that need it skip, as
//! the other interop tests do. The tests that sign also need the ed25519
//! engine of the `ostree` command. If the build has no such engine, they skip.

mod common;

use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use common::{TmpDir, ostree_available, ostree_supports_ed25519};
use futures_lite::AsyncReadExt;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DeltaEndianness,
    DeltaOptions, DeltaSuperblock, DummyVerifier, Ed25519Signer, Ed25519Verifier, Error,
    MutableTree, Repo, RepoMode, SignFuture, Signer, SummaryOptions, TreeEntry, Type, Value,
    base64, from_bytes, static_delta_relative_dir,
};
use ostrya_rt::block_on;

/// The fixed ed25519 keypair that the other signing tests also use.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// Runs the `ostree` command, asserts that it succeeds, and returns its
/// standard output.
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

/// Runs the `ostree` command and returns `true` if it succeeds.
fn ostree_status(args: &[&str]) -> bool {
    Command::new("ostree")
        .args(args)
        .output()
        .expect("run ostree")
        .status
        .success()
}

/// Returns deterministic pseudo-random bytes (xorshift64), so the objects of a
/// test are the same in each run.
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

/// Commits `tree` into `repo` on branch `test` with canonical permissions. The
/// objects then do not depend on the owner or the umask of the test
/// environment.
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

/// Commits `tree` into `repo` on branch `test` with the xattrs of the tree.
/// The walk uses no flags. Canonical permissions record no xattrs, and
/// `SKIP_XATTRS` does not read them.
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

/// Sets a user xattr and returns `true` if the file system accepts it. Some
/// file systems do not support `user.*` xattrs. If a test cannot set one, the
/// test skips and does not fail.
fn set_user_xattr(path: &Path, name: &str, value: &[u8]) -> bool {
    rustix::fs::setxattr(path, name, value, rustix::fs::XattrFlags::empty()).is_ok()
}

/// Returns the xattrs of a file in a commit, as name/value pairs.
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

/// Reads the content of a file from the tree of a commit.
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

/// Returns the name of a delta as the `ostree` command writes it: the target
/// hex, or `<from>-<to>`.
fn delta_name(from: Option<&Checksum>, to: &Checksum) -> String {
    match from {
        Some(from) => format!("{}-{}", from.to_hex(), to.to_hex()),
        None => to.to_hex(),
    }
}

/// Returns the count that `ostree static-delta show` gives for an operation,
/// such as `"write="`, as the sum over the parts that it lists.
fn op_count(show: &str, key: &str) -> u64 {
    show.split_whitespace()
        .filter_map(|token| token.strip_prefix(key).and_then(|n| n.parse::<u64>().ok()))
        .sum()
}

/// Returns `true` if `haystack` holds `needle` as a run of bytes.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|run| run == needle)
}

/// Returns the output of `ostree static-delta show` for a delta in `repo`.
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

    // A tree with a small file, an empty file, a symlink, and an object larger
    // than the 128 KiB heap threshold of the reader. The part payload spills
    // to a temp file, and the test runs a zero-length splice.
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

        // ostrya applies its own delta into a new repository.
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
    // `ostree fsck` verifies the objects that ostrya wrote. Then the `ostree`
    // command applies the same delta itself.
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

/// Returns the commit that `refs/heads/test` points at in a repository, as hex.
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

    // A 2 MiB object with an edit in place. Content-defined chunking finds
    // most of it unchanged, so the delta copies those runs from the source
    // object.
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

    // The delta must carry copy-from-source writes. If it has none, the test
    // does not run the path under test.
    let listing = show(&src, &delta_name(Some(&c1), &c2));
    assert!(
        op_count(&listing, "write=") > 0 && op_count(&listing, "setread=") > 0,
        "the delta carries no rollsum copies:\n{listing}"
    );

    // The destination holds only the source commit. The `ostree` command
    // applies the delta and gives the edited object byte for byte.
    // The `ostree` command runs the `open` opcode only for bare-family
    // repositories. A delta with copy-from-source writes therefore goes into
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

    // If the object is smaller than the minimum chunk size of the chunker, the
    // whole object is one chunk. An edit then leaves nothing to copy, and the
    // delta uses a patch.
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

    // A patched object needs `open`, as a rollsum copy does, so the
    // destination is bare-user.
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

    // If bsdiff is off, the same edit travels as a plain splice.
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

    // Two files with different xattr sets and one file with none. The table
    // then holds more than one entry, and the indices must select between them.
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

        // ostrya applies its own delta and gives each xattr set again.
        let target = Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let applied = target.apply_static_delta_offline(&delta).await.unwrap();
        assert_eq!(applied, commit);
        let rev = commit.to_hex();
        // A stored xattr name ends with a NUL, as the `ostree` command writes it.
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

    // The xattr table is a format structure that the `ostree` command must
    // parse. The test asserts the counts that it reports before it applies the
    // delta.
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

    // Unrelated content at the same path. The content is small, so the
    // generator tries a patch. Chunking finds nothing to copy. The patch carries
    // about as much new data as the content, so a splice wins over it.
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

    // A splice-only delta applies into each mode. The object that it delivers
    // is the new content, with no patch against the old content.
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

    // A part file is the compression byte and then the xz stream. The header
    // fields of the stream start at offset 1:
    //
    // - the 6-byte magic
    // - the two stream flags (a null byte and the check id)
    // - the CRC32 of the flags
    //
    // The block header starts at stream offset 12. It holds its size byte, its
    // flags, and then the filter chain. Here the chain is one LZMA2 filter (id
    // 0x21). The single property byte of this filter encodes the dictionary
    // size.
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

/// Returns the index file that lists the deltas of a target, with the name
/// that `reindex` gives it.
fn index_path(repo: &Path, to: &Checksum) -> PathBuf {
    let b64 = to.to_base64_modified();
    let (fanout, rest) = b64.split_at(2);
    repo.join("delta-indexes")
        .join(fanout)
        .join(format!("{rest}.index"))
}

/// Returns each `.index` file under `delta-indexes/`, sorted.
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
    // If the removal of an index file empties its fanout directory, the
    // `ostree` command keeps the directory. ostrya keeps it too.
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
fn reindexing_one_target_leaves_the_others() {
    let tmp = TmpDir::new("gen-reindex-to");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"first\n").unwrap();

    let src = base.join("src");
    block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        std::fs::write(tree.join("a.txt"), b"second\n").unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;

        let opts = DeltaOptions::default();
        let c1_scratch = src.join(repo.generate_static_delta(None, &c1, &opts).await.unwrap());
        repo.generate_static_delta(None, &c2, &opts).await.unwrap();
        let c1_c2 = src.join(
            repo.generate_static_delta(Some(&c1), &c2, &opts)
                .await
                .unwrap(),
        );
        repo.reindex_static_deltas().await.unwrap();
        let c1_index = std::fs::read(index_path(&src, &c1)).unwrap();
        let c2_index = std::fs::read(index_path(&src, &c2)).unwrap();

        std::fs::remove_dir_all(&c1_scratch).unwrap();
        std::fs::remove_dir_all(&c1_c2).unwrap();

        // A pass over c2 writes its file again with the one delta that is
        // left. The stale file of c1 does not change.
        repo.reindex_static_deltas_to(&c2).await.unwrap();
        let rewritten = std::fs::read(index_path(&src, &c2)).unwrap();
        assert_ne!(rewritten, c2_index, "the index of c2 was not rewritten");
        assert_eq!(
            std::fs::read(index_path(&src, &c1)).unwrap(),
            c1_index,
            "the index of another target changed"
        );

        // c1 has no delta left. A pass over c1 removes its file and keeps the
        // fanout directory.
        repo.reindex_static_deltas_to(&c1).await.unwrap();
        assert_eq!(index_files(&src), vec![index_path(&src, &c2)]);
        assert!(
            index_path(&src, &c1).parent().unwrap().exists(),
            "the emptied fanout directory was removed"
        );

        // The pass over one target writes the same bytes as the full pass.
        repo.reindex_static_deltas().await.unwrap();
        assert_eq!(std::fs::read(index_path(&src, &c2)).unwrap(), rewritten);
    });

    // A target with no delta and no `delta-indexes/` creates nothing.
    let empty = base.join("empty");
    block_on(async {
        let repo = Repo::create(&empty, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let zero = Checksum::from_bytes([0; 32]);
        repo.reindex_static_deltas_to(&zero).await.unwrap();
    });
    assert!(
        !empty.join("delta-indexes").exists(),
        "a pass with nothing to index created delta-indexes/"
    );
}

#[test]
fn reindexing_one_target_refuses_a_directory_at_the_index_path() {
    let tmp = TmpDir::new("gen-reindex-to-dir");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"one\n").unwrap();

    let src = base.join("src");
    let commit = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        std::fs::create_dir_all(index_path(&src, &commit)).unwrap();
        let err = repo.reindex_static_deltas_to(&commit).await.unwrap_err();
        assert!(matches!(err, Error::Io(_)), "unexpected error: {err:?}");
        commit
    });
    assert!(
        index_path(&src, &commit).is_dir(),
        "the directory at the index path was removed"
    );
}

#[test]
fn reindexing_one_target_refuses_a_file_at_the_fanout() {
    let tmp = TmpDir::new("gen-reindex-to-fanout-file");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"one\n").unwrap();

    let src = base.join("src");
    let fanout = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        let fanout = index_path(&src, &commit).parent().unwrap().to_owned();
        std::fs::create_dir_all(fanout.parent().unwrap()).unwrap();
        std::fs::write(&fanout, b"x").unwrap();
        let err = repo.reindex_static_deltas_to(&commit).await.unwrap_err();
        assert!(matches!(err, Error::Io(_)), "unexpected error: {err:?}");
        fanout
    });
    assert_eq!(
        std::fs::read(&fanout).unwrap(),
        b"x",
        "the file at the fanout changed"
    );
}

#[test]
fn reindexing_skips_a_malformed_directory_without_a_superblock() {
    let tmp = TmpDir::new("gen-reindex-malformed");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"indexed\n").unwrap();

    let src = base.join("src");
    let commit = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        repo.generate_static_delta(None, &commit, &DeltaOptions::default())
            .await
            .unwrap();
        std::fs::create_dir_all(src.join("deltas/zz/garbage")).unwrap();
        repo.reindex_static_deltas().await.unwrap();
        commit
    });
    assert_eq!(index_files(&src), vec![index_path(&src, &commit)]);
}

#[test]
fn reindexing_follows_no_symlink_and_skips_a_file_in_the_tree() {
    let tmp = TmpDir::new("gen-reindex-symlinks");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"one\n").unwrap();

    let src = base.join("src");
    let outside = base.join("outside");
    block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        std::fs::write(tree.join("a.txt"), b"two\n").unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;
        for (from, to) in [(None, &c1), (Some(&c1), &c2)] {
            repo.generate_static_delta(from, to, &DeltaOptions::default())
                .await
                .unwrap();
        }
        std::fs::create_dir(&outside).unwrap();

        // The from-scratch delta moves behind a symlink at its delta path.
        let scratch = src.join(static_delta_relative_dir(None, &c1));
        std::fs::rename(&scratch, outside.join("leaf")).unwrap();
        std::os::unix::fs::symlink(outside.join("leaf"), &scratch).unwrap();
        std::fs::write(src.join("deltas/file"), b"file").unwrap();
        repo.reindex_static_deltas().await.unwrap();
        assert_eq!(
            index_files(&src),
            vec![index_path(&src, &c2)],
            "only the delta at a real directory is indexed"
        );

        // The fanout that the two deltas share moves behind a symlink.
        std::fs::remove_file(&scratch).unwrap();
        std::fs::rename(outside.join("leaf"), &scratch).unwrap();
        let fanout = scratch.parent().unwrap();
        std::fs::rename(fanout, outside.join("fanout")).unwrap();
        std::os::unix::fs::symlink(outside.join("fanout"), fanout).unwrap();
        repo.reindex_static_deltas().await.unwrap();
        assert_eq!(
            index_files(&src),
            Vec::<PathBuf>::new(),
            "no delta behind a symlinked fanout is indexed"
        );
    });
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

        // One byte more than the 128 MiB metadata ceiling of the format, which
        // is the size limit of a superblock. The file is sparse, so it uses no
        // disk space.
        let superblock = std::fs::OpenOptions::new()
            .write(true)
            .open(delta.join("superblock"))
            .unwrap();
        superblock.set_len(128 * 1024 * 1024 + 1).unwrap();
        drop(superblock);

        // An index of a prefix publishes a digest that covers only part of the
        // superblock. The pass therefore fails.
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

        // A zero threshold turns fallbacks off, as in the `ostree` command. The
        // object therefore travels inside a part at any size.
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

        // The destination holds none of the objects. The application succeeds
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
    // If the delta has no fallback entries, the offline applier of the
    // `ostree` command accepts it.
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

    // The test uses a lower threshold and no 4 MB object. The rule is the
    // same, and the test stays fast.
    let big = noise(1_500_000, 11);
    let src = base.join("src");
    let dst = base.join("dst");
    let (fallback_delta, c2) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        std::fs::write(tree.join("big.dat"), &big).unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        // A second commit with the same large object and one more small file.
        std::fs::write(tree.join("extra.txt"), b"extra\n").unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;

        // The delta of the first commit packs all objects, because the default
        // threshold is much larger than the object. Its application puts the
        // large object into the destination.
        let seed = src.join(
            repo.generate_static_delta(None, &c1, &DeltaOptions::default())
                .await
                .unwrap(),
        );
        // The test uses a lower threshold and no 4 MB object. The rule is the
        // same, and the test stays fast.
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

        // If the fallback object is not present, the application refuses the
        // delta before it writes anything. It writes no partial commit.
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
    // The offline applier of the `ostree` command refuses each delta with
    // fallback entries ("contains nonempty http fallback entries"). The check
    // with the `ostree` command is therefore `fsck` over the objects that the
    // application of ostrya wrote.
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
    // The size that the generator compares with the threshold is the sum of:
    //
    // - the file header variant
    // - seven bytes (`FALLBACK_FRAMING` in deltagen.rs)
    // - the content
    //
    // The header of a canonical `uid=gid=0` file with no xattrs is 18 bytes.
    // At a 1,000,000-byte threshold, the largest packed content is 999,974
    // bytes, and 999,975 bytes becomes a fallback. The `ostree` command reads
    // the same threshold as its decimal-megabyte value 1. The test checks the
    // two sides of the boundary against it.
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

            // The destination holds none of the objects. If the object travels
            // inside a part, the delta applies. If the delta names it as a
            // fallback that is absent, the application refuses before it writes.
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
        // The `ostree` command generates its own delta of the same commit at
        // the same threshold. This delta overwrites the delta of ostrya at the
        // same location. `show` then reports how the `ostree` command
        // classifies the same object.
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

        // The verifier of ostrya accepts the trusted key and rejects another
        // key.
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

        // The signature step wrote the superblock again, so the index pass runs
        // after it.
        repo.reindex_static_deltas().await.unwrap();
        (delta, commit)
    });

    // A signed delta applies, and its index names the target commit.
    assert!(
        std::fs::read(delta.join("superblock"))
            .unwrap()
            .starts_with(b"OSTSGNDT"),
        "the superblock is not wrapped in the signed envelope"
    );

    if !ostree_supports_ed25519() {
        eprintln!("skipping: ostree has no ed25519 engine");
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

/// Generates a from-scratch delta of a one-file tree in a new archive
/// repository at `base/src` and returns the delta directory. If `sign` is
/// `true`, the delta gets a signature with the shared key.
fn verify_fixture_delta(base: &Path, sign: bool) -> PathBuf {
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"verify content\n").unwrap();
    let src = base.join("src");
    block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let commit = commit_tree(&repo, &tree, None).await;
        let relative = repo
            .generate_static_delta(None, &commit, &DeltaOptions::default())
            .await
            .unwrap();
        let delta = src.join(relative);
        if sign {
            let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
            repo.sign_static_delta(&delta, &signer).await.unwrap();
        }
        delta
    })
}

/// `DeltaSuperblock::verify` reads a superblock file under any name, in a
/// directory without its parts. A copy named `sbcopy` verifies under the
/// signing key and fails under another key.
#[test]
fn superblock_verify_reads_a_superblock_under_any_name() {
    let tmp = TmpDir::new("sb-verify-any-name");
    let delta = verify_fixture_delta(tmp.path(), true);
    let away = tmp.path().join("away");
    std::fs::create_dir_all(&away).unwrap();
    let copy = away.join("sbcopy");
    std::fs::copy(delta.join("superblock"), &copy).unwrap();
    block_on(async {
        let sb = DeltaSuperblock::read(&copy).await.unwrap();
        let trusted =
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap();
        let outcome = sb.verify(&[&trusted]).await.unwrap();
        assert!(
            outcome.valid,
            "the trusted key verifies the copied superblock"
        );
        let other = Ed25519Verifier::new([vec![0u8; 32]], Vec::<Vec<u8>>::new()).unwrap();
        let rejected = sb.verify(&[&other]).await.unwrap();
        assert!(!rejected.valid, "an untrusted key verifies the superblock");
        assert_eq!(rejected.signatures.len(), 1);
    });
}

/// Creates a new archive repository at `base/<name>`.
async fn fresh_archive(base: &Path, name: &str) -> Repo {
    Repo::create(&base.join(name), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// `Repo::apply_static_delta` applies a superblock that it reads under another
/// name in another directory. It reads the parts from the directory that the
/// caller names.
#[test]
fn apply_static_delta_takes_a_superblock_read_under_any_name() {
    let tmp = TmpDir::new("apply-any-name");
    let delta = verify_fixture_delta(tmp.path(), true);
    let away = tmp.path().join("away");
    std::fs::create_dir_all(&away).unwrap();
    let copy = away.join("sbcopy");
    std::fs::copy(delta.join("superblock"), &copy).unwrap();
    block_on(async {
        let dst = fresh_archive(tmp.path(), "dst").await;
        let sb = DeltaSuperblock::read(&copy).await.unwrap();
        let to = *sb.to_commit();
        assert_eq!(dst.apply_static_delta(sb, &delta).await.unwrap(), to);
        dst.load_commit(&to).await.unwrap();
    });
}

/// If a superblock is verified and then applied from the same read, the
/// verified bytes apply. The test removes the file on disk between the two
/// steps, and the parts apply.
#[test]
fn a_verified_superblock_applies_from_the_same_read() {
    let tmp = TmpDir::new("apply-verified-read");
    let delta = verify_fixture_delta(tmp.path(), true);
    block_on(async {
        let dst = fresh_archive(tmp.path(), "dst").await;
        let sb = DeltaSuperblock::read(&delta.join("superblock"))
            .await
            .unwrap();
        std::fs::remove_file(delta.join("superblock")).unwrap();
        let trusted =
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap();
        assert!(sb.verify(&[&trusted]).await.unwrap().valid);
        let to = *sb.to_commit();
        assert_eq!(dst.apply_static_delta(sb, &delta).await.unwrap(), to);
        dst.load_commit(&to).await.unwrap();
    });
}

/// Neither apply call writes a ref.
#[test]
fn apply_static_delta_writes_no_ref() {
    let tmp = TmpDir::new("apply-no-ref");
    let delta = verify_fixture_delta(tmp.path(), false);
    block_on(async {
        let dst = fresh_archive(tmp.path(), "dst").await;
        let sb = DeltaSuperblock::read(&delta.join("superblock"))
            .await
            .unwrap();
        dst.apply_static_delta(sb, &delta).await.unwrap();
        assert_eq!(dst.list_refs(None).await.unwrap(), []);
        let offline = fresh_archive(tmp.path(), "offline").await;
        offline.apply_static_delta_offline(&delta).await.unwrap();
        assert_eq!(offline.list_refs(None).await.unwrap(), []);
    });
}

/// `DeltaSuperblock::verify` refuses a superblock with no signed envelope.
#[test]
fn superblock_verify_refuses_an_unsigned_superblock() {
    let tmp = TmpDir::new("sb-verify-unsigned");
    let delta = verify_fixture_delta(tmp.path(), false);
    block_on(async {
        let sb = DeltaSuperblock::read(&delta.join("superblock"))
            .await
            .unwrap();
        let trusted =
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap();
        let err = sb.verify(&[&trusted]).await.unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "{err}");
    });
}

/// If the envelope holds no blob for the engine key of a verifier, the
/// verifier reports an invalid outcome and examines no signature.
#[test]
fn superblock_verify_reports_no_blob_for_an_absent_engine() {
    let tmp = TmpDir::new("sb-verify-absent-engine");
    let delta = verify_fixture_delta(tmp.path(), true);
    block_on(async {
        let sb = DeltaSuperblock::read(&delta.join("superblock"))
            .await
            .unwrap();
        let dummy = DummyVerifier::new([b"key".to_vec()]);
        let outcome = sb.verify(&[&dummy]).await.unwrap();
        assert!(!outcome.valid);
        assert!(outcome.signatures.is_empty());
    });
}

/// A delta carries a copy of the detached metadata of the target commit in its
/// superblock. The key is the directory of the delta with `/commitmeta` added.
/// A pull of the `ostree` command checks the delivered commit against this
/// copy.
///
/// The `ostree` command pulls the delta of ostrya under `sign-verify=ed25519`,
/// over a `file://` remote with `--require-static-deltas`. The pull therefore
/// uses the delta path under test. A delta of a commit with no detached
/// metadata carries no such entry and delivers its commit.
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
            // The `ostree` command finds a delta through the summary and the
            // index, so the test writes both before the pull.
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

    // The copy for the signed commit holds the bytes of the `.commitmeta`
    // file, under the directory of the delta.
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

    // The unsigned commit has no detached metadata, so its delta has no entry.
    let plain_superblock = std::fs::read(plain_src.join(&plain_delta).join("superblock")).unwrap();
    assert!(
        !holds(&plain_superblock, b"/commitmeta"),
        "a commit with no detached metadata got a commitmeta entry"
    );

    if !ostree_supports_ed25519() {
        eprintln!("skipping: ostree has no ed25519 engine");
        return;
    }
    // The destination of the pull must be bare-user. A pull of the `ostree`
    // command into an archive repository uses no static delta. With
    // `--require-static-deltas`, the pull fails with this message:
    // `error: Can't use static deltas in an archive repo`. An offline apply
    // into an archive repository works.
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

    // A new empty directory changes only the tree metadata. The delta carries
    // dirtree and dirmeta objects and no content object, so the mode table and
    // the xattr table of the part are empty.
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
    // Larger than the 128 KiB spill threshold, so the payload needs a temp file.
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

        // A new generation overwrites the parts in place, so it must remove the
        // superblock first. If a run fails partway, it must not leave a
        // superblock that describes files that it already replaced. The test
        // makes the spill directory read-only. The run then fails after it
        // opens the delta directory and before it writes a part.
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
        // First a small ceiling, so the delta has several parts.
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

        // The second generation uses the default ceiling, which puts all
        // objects in one part.
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

/// Sets the mtime of a file `seconds` into the past. A test uses it to make a
/// temp file old, because the sweep selects temp files by age.
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

        // Two temp names of the shape that a killed generation leaves. The kill
        // occurs after the generation creates a part and before it renames the
        // part.
        //
        // The old file is a leftover, and the sweep removes it. The new file can
        // be the file of a generation that runs now. An unlink of it makes the
        // rename of that run fail.
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
    // A delta directory holds its superblock, its numbered parts, and each temp
    // file that is too new for the sweep to treat as abandoned.
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
    // Names of the kind that the files of a delta use, in a directory of the
    // caller:
    //
    // - a numeric name larger than the part count of this delta
    // - a temp name that is old enough for the repository sweep to remove
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

/// Commits a one-file tree into a new archive repository at `base/src` and
/// returns the repository path, the handle, and the commit.
async fn one_file_repo(base: &Path) -> (PathBuf, Repo, Checksum) {
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), b"superblock target content\n").unwrap();
    let src = base.join("src");
    let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let commit = commit_tree(&repo, &tree, None).await;
    (src, repo, commit)
}

/// Returns the sorted names in a directory.
fn dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A signer that always fails.
struct FailingSigner;

impl Signer for FailingSigner {
    fn name(&self) -> &str {
        "failing"
    }

    fn metadata_key(&self) -> &str {
        "ostree.sign.failing"
    }

    fn sign<'a>(&'a self, _data: &'a [u8]) -> SignFuture<'a> {
        Box::pin(async {
            Err(ostrya::sign::Error::Signature(
                "the test signer fails".to_owned(),
            ))
        })
    }
}

/// A signature through `DeltaOptions::signers` gives the same superblock bytes
/// as an unsigned generation and then `sign_static_delta`. ed25519 signatures
/// are deterministic, so the two envelopes are equal.
#[test]
fn signing_through_the_options_equals_signing_after() {
    let tmp = TmpDir::new("gen-sign-options");
    let base = tmp.path();
    let (signed_now, signed_after) = block_on(async {
        let (_src, repo, commit) = one_file_repo(base).await;
        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        let now = base.join("now");
        repo.generate_static_delta(
            None,
            &commit,
            &DeltaOptions {
                timestamp: Some(1_700_000_500),
                output_dir: Some(now.clone()),
                signers: vec![Arc::new(signer.clone())],
                ..DeltaOptions::default()
            },
        )
        .await
        .unwrap();
        let after = base.join("after");
        repo.generate_static_delta(
            None,
            &commit,
            &DeltaOptions {
                timestamp: Some(1_700_000_500),
                output_dir: Some(after.clone()),
                ..DeltaOptions::default()
            },
        )
        .await
        .unwrap();
        repo.sign_static_delta(&after, &signer).await.unwrap();
        (
            std::fs::read(now.join("superblock")).unwrap(),
            std::fs::read(after.join("superblock")).unwrap(),
        )
    });
    assert!(signed_now.starts_with(b"OSTSGNDT"));
    assert_eq!(signed_now, signed_after);
}

/// If a signer fails, the generation fails and writes no superblock. The
/// superblock of an earlier generation at the same location is also gone, so
/// the list of deltas does not show the delta.
#[test]
fn a_failing_signer_leaves_no_superblock() {
    let tmp = TmpDir::new("gen-sign-fails");
    let base = tmp.path();
    block_on(async {
        let (src, repo, commit) = one_file_repo(base).await;
        let delta = src.join(
            repo.generate_static_delta(None, &commit, &DeltaOptions::default())
                .await
                .unwrap(),
        );
        assert!(delta.join("superblock").exists());

        let err = repo
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    signers: vec![Arc::new(FailingSigner)],
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "{err}");
        assert_eq!(dir_names(&delta), vec!["0"]);
        assert!(repo.list_static_deltas().await.unwrap().is_empty());
    });
}

/// An inline generation writes no part file. The superblock of an earlier
/// delta at the same location therefore stays until the new superblock
/// replaces it. If a signer fails, the earlier delta stays complete:
///
/// - its superblock and its part file do not change
/// - the list of deltas shows it
/// - it applies
#[test]
fn a_failing_signer_under_inline_keeps_the_earlier_delta() {
    let tmp = TmpDir::new("gen-sign-fails-inline");
    let base = tmp.path();
    block_on(async {
        let (src, repo, commit) = one_file_repo(base).await;
        let delta = src.join(
            repo.generate_static_delta(None, &commit, &DeltaOptions::default())
                .await
                .unwrap(),
        );
        let superblock = std::fs::read(delta.join("superblock")).unwrap();
        let part = std::fs::read(delta.join("0")).unwrap();
        let listed = repo.list_static_deltas().await.unwrap();

        let err = repo
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    inline: true,
                    signers: vec![Arc::new(FailingSigner)],
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "{err}");
        assert_eq!(dir_names(&delta), vec!["0", "superblock"]);
        assert_eq!(std::fs::read(delta.join("superblock")).unwrap(), superblock);
        assert_eq!(std::fs::read(delta.join("0")).unwrap(), part);
        assert_eq!(repo.list_static_deltas().await.unwrap(), listed);

        let dst = Repo::create(&base.join("dst"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        assert_eq!(
            dst.apply_static_delta_offline(&delta).await.unwrap(),
            commit
        );
    });
}

/// Only the final rename replaces a file at the `superblock_file` path. If a
/// signer fails after the parts are written, the file does not change.
#[test]
fn a_failing_signer_leaves_the_file_at_the_superblock_path() {
    let tmp = TmpDir::new("gen-sign-fails-file");
    let base = tmp.path();
    let out = base.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let sb = out.join("sb");
    std::fs::write(&sb, b"keep\n").unwrap();
    block_on(async {
        let (_src, repo, commit) = one_file_repo(base).await;
        let err = repo
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    superblock_file: Some(sb.clone()),
                    signers: vec![Arc::new(FailingSigner)],
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "{err}");
    });
    assert_eq!(std::fs::read(&sb).unwrap(), b"keep\n");
    assert_eq!(dir_names(&out), vec!["0", "sb"]);
}

/// If `superblock_file` is set, the superblock goes to that path and the parts
/// go to the directory that holds it. The bytes are the same as at the
/// repository location, and nothing goes under `deltas/`. A signed superblock
/// at that path verifies.
#[test]
fn a_superblock_file_takes_the_superblock_and_its_directory_the_parts() {
    let tmp = TmpDir::new("gen-superblock-file");
    let base = tmp.path();
    let out = base.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let sb = out.join("sb");
    block_on(async {
        let (src, repo, commit) = one_file_repo(base).await;
        let returned = repo
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    timestamp: Some(1_700_000_500),
                    superblock_file: Some(sb.clone()),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(returned, sb);
        assert!(!src.join("deltas").exists() || dir_names(&src.join("deltas")).is_empty());
        assert_eq!(dir_names(&out), vec!["0", "sb"]);

        let delta = src.join(
            repo.generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    timestamp: Some(1_700_000_500),
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            std::fs::read(&sb).unwrap(),
            std::fs::read(delta.join("superblock")).unwrap()
        );
        assert_eq!(
            std::fs::read(out.join("0")).unwrap(),
            std::fs::read(delta.join("0")).unwrap()
        );

        let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
        repo.generate_static_delta(
            None,
            &commit,
            &DeltaOptions {
                superblock_file: Some(sb.clone()),
                signers: vec![Arc::new(signer)],
                ..DeltaOptions::default()
            },
        )
        .await
        .unwrap();
        let read = DeltaSuperblock::read(&sb).await.unwrap();
        let trusted =
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap();
        assert!(read.verify(&[&trusted]).await.unwrap().valid);
    });
}

/// The generator refuses each superblock-file target that it cannot write,
/// before it writes anything. These targets are:
///
/// - a directory at the path
/// - a trailing `/`
/// - a last component `.` or `..` (also after a file or an absent name)
/// - a missing parent
/// - a part file name
/// - `superblock_file` together with `output_dir`
#[test]
fn a_superblock_file_target_is_refused_before_anything_is_written() {
    let tmp = TmpDir::new("gen-superblock-file-refused");
    let base = tmp.path();
    let out = base.join("out");
    std::fs::create_dir_all(out.join("d")).unwrap();
    std::fs::write(out.join("keep"), b"the caller's file\n").unwrap();
    block_on(async {
        let (_src, repo, commit) = one_file_repo(base).await;
        let before = dir_names(&out);
        let cases: Vec<(DeltaOptions, &str)> = vec![
            (
                DeltaOptions {
                    superblock_file: Some(out.join("d")),
                    ..DeltaOptions::default()
                },
                "directory",
            ),
            (
                DeltaOptions {
                    superblock_file: Some(PathBuf::from(format!("{}/", out.display()))),
                    ..DeltaOptions::default()
                },
                "trailing slash",
            ),
            (
                DeltaOptions {
                    superblock_file: Some(out.join("keep/.")),
                    ..DeltaOptions::default()
                },
                "dot after a file",
            ),
            (
                DeltaOptions {
                    superblock_file: Some(out.join("new/.")),
                    ..DeltaOptions::default()
                },
                "dot after an absent name",
            ),
            (
                DeltaOptions {
                    superblock_file: Some(out.join("..")),
                    ..DeltaOptions::default()
                },
                "dot dot",
            ),
            (
                DeltaOptions {
                    superblock_file: Some(out.join("nodir/x/sb")),
                    ..DeltaOptions::default()
                },
                "missing parent",
            ),
            (
                DeltaOptions {
                    superblock_file: Some(out.join("0")),
                    ..DeltaOptions::default()
                },
                "part name",
            ),
            (
                DeltaOptions {
                    superblock_file: Some(out.join("sb")),
                    output_dir: Some(out.clone()),
                    ..DeltaOptions::default()
                },
                "both targets",
            ),
        ];
        for (opts, what) in cases {
            let err = repo
                .generate_static_delta(None, &commit, &opts)
                .await
                .expect_err(what);
            match what {
                "directory"
                | "trailing slash"
                | "dot after a file"
                | "dot after an absent name"
                | "dot dot" => assert!(
                    matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::IsADirectory),
                    "{what}: {err}"
                ),
                "missing parent" => assert!(
                    matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound),
                    "{what}: {err}"
                ),
                _ => assert!(matches!(err, Error::InvalidFormat(_)), "{what}: {err}"),
            }
            assert_eq!(dir_names(&out), before, "{what}");
            assert!(dir_names(&out.join("d")).is_empty(), "{what}");
            assert_eq!(
                std::fs::read(out.join("keep")).unwrap(),
                b"the caller's file\n",
                "{what}"
            );
        }
    });
}

/// The superblock replaces a symlink at the superblock-file path. The
/// directory that the symlink points at does not change.
#[test]
fn a_symlink_at_the_superblock_file_is_replaced_not_followed() {
    let tmp = TmpDir::new("gen-superblock-file-symlink");
    let base = tmp.path();
    let out = base.join("out");
    let elsewhere = base.join("elsewhere");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    let sb = out.join("sb");
    std::os::unix::fs::symlink(&elsewhere, &sb).unwrap();
    block_on(async {
        let (_src, repo, commit) = one_file_repo(base).await;
        repo.generate_static_delta(
            None,
            &commit,
            &DeltaOptions {
                superblock_file: Some(sb.clone()),
                ..DeltaOptions::default()
            },
        )
        .await
        .unwrap();
    });
    assert!(std::fs::symlink_metadata(&sb).unwrap().is_file());
    assert!(dir_names(&elsewhere).is_empty());
}

// --- inline parts and the endianness byte -------------------------------------

/// The GVariant type string of a superblock, used to read a superblock that a
/// test holds.
const SUPERBLOCK_SIG: &str = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";

/// Returns the fields of an unsigned superblock file.
fn superblock_fields(path: &Path) -> Vec<Value> {
    let bytes = std::fs::read(path).unwrap();
    let value = from_bytes(&Type::parse(SUPERBLOCK_SIG).unwrap(), &bytes).unwrap();
    let Value::Tuple(fields) = value else {
        panic!("a superblock is a tuple");
    };
    fields
}

/// Returns the metadata dict of an unsigned superblock file, as keys and
/// values in dict order.
fn superblock_dict(path: &Path) -> Vec<(String, Value)> {
    let fields = superblock_fields(path);
    fields[0]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let pair = entry.as_tuple().unwrap();
            (pair[0].as_str().unwrap().to_owned(), pair[1].clone())
        })
        .collect()
}

/// Returns the bytes of an inline part value: the compression byte and the
/// body. A part file holds the same bytes.
fn inline_bytes(value: &Value) -> Vec<u8> {
    let (ty, inner) = value.as_variant().unwrap();
    assert_eq!(ty.signature(), "(yay)");
    let pair = inner.as_tuple().unwrap();
    let mut bytes = vec![pair[0].as_byte().unwrap()];
    bytes.extend_from_slice(pair[1].as_bytes().unwrap());
    bytes
}

/// Creates a repository at `base/src` with one signed commit of three
/// 300,000-byte files. A 250,000-byte chunk size puts each file in its own
/// part.
async fn multi_part_repo(base: &Path) -> (PathBuf, Repo, Checksum) {
    let tree = base.join("multi-tree");
    std::fs::create_dir_all(&tree).unwrap();
    for i in 0..3u64 {
        std::fs::write(tree.join(format!("f{i}")), noise(300_000, 20 + i)).unwrap();
    }
    std::os::unix::fs::symlink("f0", tree.join("link")).unwrap();
    let src = base.join("src");
    let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let commit = commit_tree(&repo, &tree, None).await;
    let signer = Ed25519Signer::from_base64(SECRET_B64).unwrap();
    repo.sign_commit(&commit, &signer).await.unwrap();
    (src, repo, commit)
}

/// Returns the options of the inline tests: a pinned timestamp, no fallback,
/// and a chunk size that gives each file of `multi_part_repo` a part.
fn inline_test_options() -> DeltaOptions {
    DeltaOptions {
        timestamp: Some(1_700_000_000),
        min_fallback_size: 0,
        max_chunk_size: 250_000,
        ..DeltaOptions::default()
    }
}

/// An inline delta carries each part in the superblock and writes no part
/// file. ostrya applies the delta.
///
/// The dict holds `ostree.endianness`, the parts in part order, and then
/// `commitmeta`. The `ostree` command writes the same order. Each value holds
/// the bytes of the part file that a generation with the same options writes.
#[test]
fn an_inline_delta_carries_its_parts_in_the_superblock() {
    let tmp = TmpDir::new("gen-inline");
    let base = tmp.path();
    let files = base.join("files");
    block_on(async {
        let (src, repo, commit) = multi_part_repo(base).await;
        repo.generate_static_delta(
            None,
            &commit,
            &DeltaOptions {
                output_dir: Some(files.clone()),
                ..inline_test_options()
            },
        )
        .await
        .unwrap();
        let relative = repo
            .generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    inline: true,
                    ..inline_test_options()
                },
            )
            .await
            .unwrap();
        let delta = src.join(&relative);
        assert_eq!(dir_names(&delta), ["superblock"]);

        let dict = superblock_dict(&delta.join("superblock"));
        let dir = relative.display().to_string();
        let parts = dir_names(&files).len() - 1;
        assert!(parts >= 4, "{parts} parts");
        let mut expected = vec!["ostree.endianness".to_owned()];
        expected.extend((0..parts).map(|i| format!("{dir}/{i}")));
        expected.push(format!("{dir}/commitmeta"));
        let keys: Vec<String> = dict.iter().map(|(key, _)| key.clone()).collect();
        assert_eq!(keys, expected);
        for (i, (_, value)) in dict[1..=parts].iter().enumerate() {
            assert_eq!(
                inline_bytes(value),
                std::fs::read(files.join(i.to_string())).unwrap(),
                "part {i}"
            );
        }
        let sb = DeltaSuperblock::read(&delta.join("superblock"))
            .await
            .unwrap();
        let stats = sb.part_stats(1, &delta).await.unwrap();
        assert_eq!(stats.ops.open_splice_close, 1);

        let dst = Repo::create(&base.join("dst"), CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let applied = dst.apply_static_delta_offline(&delta).await.unwrap();
        assert_eq!(applied, commit);
        assert_eq!(
            read_file(&dst, &commit.to_hex(), "f2").await,
            noise(300_000, 22)
        );
    });
}

/// The inline key is the repository-relative name under `output_dir` and
/// under `superblock_file`. Neither target gets a part file.
#[test]
fn the_inline_key_is_repository_relative_under_every_target() {
    let tmp = TmpDir::new("gen-inline-targets");
    let base = tmp.path();
    let out = base.join("out");
    let sb_dir = base.join("sb-dir");
    std::fs::create_dir_all(&sb_dir).unwrap();
    block_on(async {
        let (_src, repo, commit) = multi_part_repo(base).await;
        let dir = static_delta_relative_dir(None, &commit);
        for opts in [
            DeltaOptions {
                output_dir: Some(out.clone()),
                ..DeltaOptions::default()
            },
            DeltaOptions {
                superblock_file: Some(sb_dir.join("sb")),
                ..DeltaOptions::default()
            },
        ] {
            repo.generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    inline: true,
                    ..opts.clone()
                },
            )
            .await
            .unwrap();
        }
        assert_eq!(dir_names(&out), ["superblock"]);
        assert_eq!(dir_names(&sb_dir), ["sb"]);
        for path in [out.join("superblock"), sb_dir.join("sb")] {
            let keys: Vec<String> = superblock_dict(&path)
                .into_iter()
                .map(|(key, _)| key)
                .collect();
            assert!(keys.contains(&format!("{dir}/0")), "{keys:?}");
        }
    });
}

/// A new inline generation of a delta at the repository location removes the
/// part files that the earlier delta wrote there. Under `output_dir`, the
/// files of the caller stay.
#[test]
fn regenerating_inline_removes_the_stale_part_files() {
    let tmp = TmpDir::new("gen-inline-stale");
    let base = tmp.path();
    let out = base.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("0"), b"the caller's part\n").unwrap();
    block_on(async {
        let (src, repo, commit) = multi_part_repo(base).await;
        let relative = repo
            .generate_static_delta(None, &commit, &inline_test_options())
            .await
            .unwrap();
        assert!(dir_names(&src.join(&relative)).len() > 2);
        let inline = DeltaOptions {
            inline: true,
            ..inline_test_options()
        };
        repo.generate_static_delta(None, &commit, &inline)
            .await
            .unwrap();
        assert_eq!(dir_names(&src.join(&relative)), ["superblock"]);

        repo.generate_static_delta(
            None,
            &commit,
            &DeltaOptions {
                output_dir: Some(out.clone()),
                ..inline
            },
        )
        .await
        .unwrap();
        assert_eq!(dir_names(&out), ["0", "superblock"]);
        assert_eq!(
            std::fs::read(out.join("0")).unwrap(),
            b"the caller's part\n"
        );
    });
}

/// A big-endian generation writes the byte `B` and swaps four size fields.
/// These are the `size` and `usize` of a meta-entry and the two sizes of a
/// fallback. The generation changes nothing else:
///
/// - the superblocks have the same length
/// - all other fields are equal
/// - the part files are identical
///
/// The two superblocks read back to the same sizes.
#[test]
fn a_big_endian_superblock_swaps_the_four_size_fields_only() {
    let tmp = TmpDir::new("gen-big-endian");
    let base = tmp.path();
    let (little, big) = (base.join("little"), base.join("big"));
    block_on(async {
        let (_src, repo, commit) = multi_part_repo(base).await;
        for (dir, endianness) in [
            (&little, DeltaEndianness::Little),
            (&big, DeltaEndianness::Big),
        ] {
            repo.generate_static_delta(
                None,
                &commit,
                &DeltaOptions {
                    timestamp: Some(1_700_000_000),
                    // One file travels as a fallback.
                    min_fallback_size: 250_000,
                    output_dir: Some(dir.clone()),
                    endianness,
                    ..DeltaOptions::default()
                },
            )
            .await
            .unwrap();
        }
    });
    let (l_path, b_path) = (little.join("superblock"), big.join("superblock"));
    assert_eq!(
        std::fs::metadata(&l_path).unwrap().len(),
        std::fs::metadata(&b_path).unwrap().len()
    );
    assert_eq!(
        std::fs::read(little.join("0")).unwrap(),
        std::fs::read(big.join("0")).unwrap()
    );

    let (l, b) = (superblock_fields(&l_path), superblock_fields(&b_path));
    let byte = |dict: &Value| {
        dict.dict_get("ostree.endianness")
            .and_then(Value::as_variant)
            .and_then(|(_, value)| value.as_byte())
    };
    assert_eq!(byte(&l[0]), Some(b'l'));
    assert_eq!(byte(&b[0]), Some(b'B'));
    assert_eq!(
        &l[1..6],
        &b[1..6],
        "the timestamp, the commits, the recursion"
    );
    let swapped = |value: &Value, sizes: &[usize]| -> Value {
        let Value::Array(entries) = value else {
            panic!("an array");
        };
        Value::Array(
            entries
                .iter()
                .map(|entry| {
                    let mut fields = entry.as_tuple().unwrap().to_vec();
                    for &i in sizes {
                        fields[i] = Value::U64(fields[i].as_u64().unwrap().swap_bytes());
                    }
                    Value::Tuple(fields)
                })
                .collect(),
        )
    };
    assert_eq!(swapped(&l[6], &[2, 3]), b[6], "the meta-entry sizes");
    assert_eq!(swapped(&l[7], &[2, 3]), b[7], "the fallback sizes");
    assert_eq!(l[7].as_array().unwrap().len(), 3);

    let (l_sb, b_sb) = block_on(async {
        (
            DeltaSuperblock::read(&l_path).await.unwrap(),
            DeltaSuperblock::read(&b_path).await.unwrap(),
        )
    });
    assert_eq!(b_sb.endianness(), DeltaEndianness::Big);
    for (lp, bp) in l_sb.parts().iter().zip(b_sb.parts()) {
        assert_eq!(
            (lp.size(), lp.uncompressed_size()),
            (bp.size(), bp.uncompressed_size())
        );
    }
    for (lf, bf) in l_sb.fallbacks().iter().zip(b_sb.fallbacks()) {
        assert_eq!(
            (lf.size(), lf.uncompressed_size()),
            (bf.size(), bf.uncompressed_size())
        );
    }
}

/// The `ostree` command applies inline big-endian deltas of ostrya offline
/// into a `bare-user` repository that ostrya created. One delta is
/// from-scratch, and one is from-to and copies runs out of the source object.
/// The from-scratch delta carries only splices, so the `ostree` command also
/// applies it into an `archive` repository that ostrya created. The `fsck` of
/// the `ostree` command passes each time.
#[test]
fn the_tool_applies_a_port_inline_big_endian_delta() {
    tool_applies_port_deltas("gen-inline-tool-apply", true, DeltaEndianness::Big);
}

/// The `ostree` command applies little-endian deltas of ostrya, with the parts
/// in files, offline into a `bare-user` repository that ostrya created. One
/// delta is from-scratch, and one is from a source commit. The `ostree`
/// command also applies the from-scratch delta into an `archive` repository
/// that ostrya created. The `fsck` of the `ostree` command passes each time.
#[test]
fn the_tool_applies_a_port_file_part_little_endian_delta() {
    tool_applies_port_deltas("gen-file-tool-apply", false, DeltaEndianness::Little);
}

/// Generates a from-scratch delta and a from-to delta in a repository of
/// ostrya, with the parts inline or in files and under `endianness`. Then the
/// `ostree` command applies them into `bare-user` and `archive` repositories
/// that ostrya created.
fn tool_applies_port_deltas(tag: &str, inline: bool, endianness: DeltaEndianness) {
    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    let tmp = TmpDir::new(tag);
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let mut bulk = noise(2 * 1024 * 1024, 31);
    std::fs::write(tree.join("bulk.bin"), &bulk).unwrap();
    std::fs::write(tree.join("app"), b"version one\n").unwrap();
    let src = base.join("src");
    let options = DeltaOptions {
        timestamp: Some(1_700_000_000),
        min_fallback_size: 0,
        inline,
        endianness,
        ..DeltaOptions::default()
    };
    let (scratch, fromto, c1, c2) = block_on(async {
        let repo = Repo::create(&src, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let c1 = commit_tree(&repo, &tree, None).await;
        bulk[1024 * 1024..1024 * 1024 + 4].copy_from_slice(b"edit");
        std::fs::write(tree.join("bulk.bin"), &bulk).unwrap();
        std::fs::write(tree.join("app"), b"version two\n").unwrap();
        let c2 = commit_tree(&repo, &tree, Some(c1)).await;
        let scratch = repo
            .generate_static_delta(None, &c1, &options)
            .await
            .unwrap();
        let fromto = repo
            .generate_static_delta(Some(&c1), &c2, &options)
            .await
            .unwrap();
        (src.join(scratch), src.join(fromto), c1, c2)
    });
    if inline {
        assert_eq!(dir_names(&fromto), ["superblock"]);
    } else {
        assert_eq!(dir_names(&fromto), ["0", "superblock"]);
    }
    // `ostree static-delta show` reads no inline part, so ostrya reads the
    // byte.
    let sb = block_on(DeltaSuperblock::read(&fromto.join("superblock"))).unwrap();
    assert_eq!(sb.endianness(), endianness);
    let payload = block_on(sb.part_stats(0, &fromto)).unwrap();
    assert!(
        payload.ops.write > 0,
        "no copy out of the source: {payload:?}"
    );

    for mode in [RepoMode::BareUser, RepoMode::Archive] {
        // ostrya creates the destination.
        let dst = base.join(format!("tool-{}", mode.as_mode_str()));
        block_on(Repo::create(&dst, CreateOptions::new(mode))).unwrap();
        let dst_arg = format!("--repo={}", dst.display());
        ostree(&[
            &dst_arg,
            "static-delta",
            "apply-offline",
            &scratch.to_string_lossy(),
        ]);
        ostree(&[&dst_arg, "fsck"]);
        assert_eq!(
            ostree(&[&dst_arg, "cat", &c1.to_hex(), "/app"]),
            b"version one\n"
        );
        if mode == RepoMode::BareUser {
            ostree(&[
                &dst_arg,
                "static-delta",
                "apply-offline",
                &fromto.to_string_lossy(),
            ]);
            ostree(&[&dst_arg, "fsck"]);
            assert_eq!(ostree(&[&dst_arg, "cat", &c2.to_hex(), "/bulk.bin"]), bulk);
        }
    }
}

/// The `ostree` command, as a client, pulls inline deltas of ostrya into
/// `bare-user`. The pull uses a `file://` remote and `--require-static-deltas`,
/// with little-endian and big-endian deltas. The `fsck` of the `ostree` command
/// passes.
///
/// The delta directory holds only the superblock, so the `ostree` command
/// applies the inline parts. The remote is `file://`, so the test does not see
/// the requests of the `ostree` command.
#[test]
fn the_tool_pulls_a_port_inline_delta() {
    if !ostree_available() {
        eprintln!("skipping: ostree not available");
        return;
    }
    let tmp = TmpDir::new("gen-inline-tool-pull");
    let base = tmp.path();
    for endianness in [DeltaEndianness::Little, DeltaEndianness::Big] {
        let case = base.join(format!("{endianness:?}"));
        std::fs::create_dir_all(&case).unwrap();
        let (src, commit) = block_on(async {
            let (src, repo, commit) = multi_part_repo(&case).await;
            let relative = repo
                .generate_static_delta(
                    None,
                    &commit,
                    &DeltaOptions {
                        inline: true,
                        endianness,
                        ..inline_test_options()
                    },
                )
                .await
                .unwrap();
            assert_eq!(dir_names(&src.join(relative)), ["superblock"]);
            repo.reindex_static_deltas().await.unwrap();
            repo.regenerate_summary(&SummaryOptions::default())
                .await
                .unwrap();
            (src, commit)
        });
        let dest = case.join("dest");
        let dest_arg = format!("--repo={}", dest.display());
        ostree(&[&dest_arg, "init", "--mode=bare-user"]);
        let url = format!("file://{}", src.display());
        ostree(&[
            &dest_arg,
            "remote",
            "add",
            "origin",
            &url,
            "--no-gpg-verify",
        ]);
        ostree(&[
            &dest_arg,
            "pull",
            "--require-static-deltas",
            "origin",
            "test",
        ]);
        let resolved = String::from_utf8(ostree(&[&dest_arg, "rev-parse", "origin:test"])).unwrap();
        assert_eq!(resolved.trim(), commit.to_hex(), "{endianness:?}");
        ostree(&[&dest_arg, "fsck"]);
    }
}

/// A signed inline delta verifies in both implementations:
///
/// - the `ostree` command verifies the delta of ostrya
/// - ostrya verifies the delta of the `ostree` command
/// - ostrya reads the part statistics of the signed inline superblock of the
///   `ostree` command
#[test]
fn a_signed_inline_delta_verifies_in_both() {
    if !ostree_supports_ed25519() {
        eprintln!("skipping: ostree has no ed25519 engine");
        return;
    }
    let tmp = TmpDir::new("gen-inline-signed");
    let base = tmp.path();
    let (src, commit) = block_on(async {
        let (src, repo, commit) = multi_part_repo(base).await;
        let signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_base64(SECRET_B64).unwrap());
        repo.generate_static_delta(
            None,
            &commit,
            &DeltaOptions {
                inline: true,
                signers: vec![signer],
                ..inline_test_options()
            },
        )
        .await
        .unwrap();
        (src, commit)
    });
    let src_arg = format!("--repo={}", src.display());
    let name = delta_name(None, &commit);
    assert!(
        ostree_status(&[&src_arg, "static-delta", "verify", &name, PUBLIC_B64]),
        "the tool rejected the port's signed inline delta"
    );

    // The `ostree` command signs its own inline delta of the same commit.
    let _ = std::fs::remove_dir_all(src.join("deltas"));
    ostree(&[
        &src_arg,
        "static-delta",
        "generate",
        "--inline",
        "--empty",
        &format!("--to={}", commit.to_hex()),
        "--min-fallback-size=0",
        &format!("--sign={SECRET_B64}"),
    ]);
    let delta = src.join(static_delta_relative_dir(None, &commit));
    assert_eq!(dir_names(&delta), ["superblock"]);
    block_on(async {
        let sb = DeltaSuperblock::read(&delta.join("superblock"))
            .await
            .unwrap();
        assert!(sb.is_signed());
        let trusted =
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap();
        assert!(sb.verify(&[&trusted]).await.unwrap().valid);
        let stats = sb.part_stats(0, &delta).await.unwrap();
        assert!(stats.ops.open_splice_close > 0);
    });
}
