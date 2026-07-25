//! Static-delta offline application and signature verification (Phase 15a).
//!
//! These drive the `ostree` tool as a black box: it builds an archive
//! repository, commits two trees, and generates static deltas; the port then
//! applies them offline and the produced objects are checked. Both directions
//! are exercised -- the port applies the tool's delta, and the tool's `fsck`
//! validates the objects the port wrote. The from-scratch delta carries a
//! 512 KiB object, so it exercises the temp-file + mmap part-payload path; one
//! from->to delta exercises the bspatch path over a 20 KiB file with a small
//! edit; another exercises the rollsum copy-from-source `write` op over a 2 MiB
//! file edited in place; and a signed delta is verified with the ed25519 engine.
//!
//! Every test is skipped when the tool is absent, matching the other
//! interop tests.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TmpDir, ostree_available};
use futures_lite::AsyncReadExt;
use ostrya::{
    CommitState, CreateOptions, Ed25519Verifier, FileKind, Repo, RepoMode, TreeEntry, base64,
};
use ostrya_rt::block_on;

/// The fixed ed25519 keypair shared with the other signing tests.
const SECRET_B64: &str =
    "o74ME/dmhvDeYf64dDJQY8kX2piK0M/nyIRWVi30i6DCOzRsHVcvgYToz6zOb5OvK/v8nH6KfLR3dfdsn6ZSyQ==";
const PUBLIC_B64: &str = "wjs0bB1XL4GE6M+szm+Tryv7/Jx+iny0d3X3bJ+mUsk=";

/// The v1 and v2 contents of the small file rewritten between commits.
const APP_V1: &[u8] = b"hello world version one\n";
const APP_V2: &[u8] = b"hello world version two changed\n";

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

/// A 512 KiB data file, identical in both commits. It exceeds the reader's
/// 128 KiB heap/mmap threshold, so its object in the from-scratch delta is
/// spliced from an mmapped part payload rather than a heap buffer. It is
/// unchanged between commits, so the from->to delta does not redeliver it.
fn data_bin() -> Vec<u8> {
    (0..512u32 * 1024)
        .map(|i| ((i * 7 + 3) % 256) as u8)
        .collect()
}

/// A 20 000-byte file that changes between commits, sized so the tool expresses
/// the from->to delta as a compact bspatch. `edit` flips three bytes near the
/// middle.
fn patch_bin(edit: bool) -> Vec<u8> {
    let mut v: Vec<u8> = (0..20_000u32).map(|i| ((i * 7 + 3) % 256) as u8).collect();
    if edit {
        v[10_000] = 0x00;
        v[10_001] = 0x01;
        v[10_002] = 0x02;
    }
    v
}

/// Build the v1 and v2 source trees under `base`, returning their paths.
fn build_trees(base: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let make = |dir: &Path, app: &[u8], conf: &[u8], patch: &[u8]| {
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::create_dir_all(dir.join("usr/share")).unwrap();
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(dir.join("usr/bin/app"), app).unwrap();
        std::fs::set_permissions(
            dir.join("usr/bin/app"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        symlink("app", dir.join("usr/bin/applink")).unwrap();
        std::fs::write(dir.join("usr/share/data.bin"), data_bin()).unwrap();
        std::fs::write(dir.join("usr/share/patch.bin"), patch).unwrap();
        std::fs::write(dir.join("etc/conf"), conf).unwrap();
    };

    let v1 = base.join("t1");
    let v2 = base.join("t2");
    make(&v1, APP_V1, b"line a\nline b\nline c\n", &patch_bin(false));
    make(
        &v2,
        APP_V2,
        b"line a\nline B\nline c\nline d\n",
        &patch_bin(true),
    );
    (v1, v2)
}

/// Initialize an archive repo, commit both trees, and generate both deltas.
/// Returns the repo path and the two commit checksums (hex).
fn build_source_repo(base: &Path) -> (PathBuf, String, String) {
    let (v1, v2) = build_trees(base);
    let repo = base.join("srcrepo");
    let repo_arg = format!("--repo={}", repo.display());
    ostree(&[&repo_arg, "init", "--mode=archive"]);
    let c1 = String::from_utf8(ostree(&[
        &repo_arg,
        "commit",
        "-b",
        "test",
        "--owner-uid=0",
        "--owner-gid=0",
        "--no-xattrs",
        "--timestamp=@1700000000",
        &format!("--tree=dir={}", v1.display()),
    ]))
    .unwrap()
    .trim()
    .to_owned();
    let c2 = String::from_utf8(ostree(&[
        &repo_arg,
        "commit",
        "-b",
        "test",
        "--owner-uid=0",
        "--owner-gid=0",
        "--no-xattrs",
        "--timestamp=@1700000100",
        &format!("--tree=dir={}", v2.display()),
    ]))
    .unwrap()
    .trim()
    .to_owned();
    ostree(&[
        &repo_arg,
        "static-delta",
        "generate",
        "--empty",
        "--to",
        &c1,
    ]);
    ostree(&[
        &repo_arg,
        "static-delta",
        "generate",
        "--from",
        &c1,
        "--to",
        &c2,
    ]);
    (repo, c1, c2)
}

/// Find the delta directories under `repo/deltas`, classifying by whether the
/// leaf name carries a `-` (a from->to delta) or not (a from-scratch delta).
fn find_delta_dirs(repo: &Path) -> (Option<PathBuf>, Option<PathBuf>) {
    let mut scratch = None;
    let mut fromto = None;
    let deltas = repo.join("deltas");
    for fanout in std::fs::read_dir(&deltas).into_iter().flatten().flatten() {
        for leaf in std::fs::read_dir(fanout.path())
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = leaf.file_name();
            let name = name.to_string_lossy();
            if name.contains('-') {
                fromto = Some(leaf.path());
            } else {
                scratch = Some(leaf.path());
            }
        }
    }
    (scratch, fromto)
}

/// Read a file's payload from a commit's tree.
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
    let file = repo.load_file(&checksum).await.unwrap();
    let mut reader = file.reader().await.unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.unwrap();
    buf
}

/// Read a symlink's target from a commit's tree.
async fn read_symlink(repo: &Repo, rev: &str, path: &str) -> String {
    let (tree, _) = repo.read_commit(rev).await.unwrap();
    let entry = tree.lookup(Path::new(path)).await.unwrap().unwrap();
    let checksum = match entry {
        TreeEntry::File { checksum, .. } => checksum,
        _ => panic!("{path} is not a file"),
    };
    match repo.load_file(&checksum).await.unwrap().kind {
        FileKind::Symlink { target } => target,
        _ => panic!("{path} is not a symlink"),
    }
}

#[test]
fn applies_from_scratch_delta() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("delta-scratch");
    let base = tmp.path();
    let (src_repo, c1, _c2) = build_source_repo(base);
    let (scratch, _) = find_delta_dirs(&src_repo);
    let scratch = scratch.expect("from-scratch delta dir");

    let dst = base.join("dst");
    block_on(async {
        let repo = Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let to = repo.apply_static_delta_offline(&scratch).await.unwrap();
        assert_eq!(
            to.to_hex(),
            c1,
            "applied delta reproduces the target commit"
        );

        let (_commit, state) = repo.load_commit(&to).await.unwrap();
        assert_eq!(state, CommitState::Normal);
        assert_eq!(read_file(&repo, &c1, "usr/bin/app").await, APP_V1);
        // The 512 KiB object is spliced from an mmapped part payload.
        assert_eq!(
            read_file(&repo, &c1, "usr/share/data.bin").await,
            data_bin()
        );

        // The tool validates the objects the port wrote.
        repo.set_ref_immediate("test", Some(&to)).await.unwrap();
    });
    ostree(&[&format!("--repo={}", dst.display()), "fsck"]);
}

#[test]
fn applies_from_to_delta_with_bspatch() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("delta-fromto");
    let base = tmp.path();
    let (src_repo, c1, c2) = build_source_repo(base);
    let (_, fromto) = find_delta_dirs(&src_repo);
    let fromto = fromto.expect("from->to delta dir");

    // A destination repo holding only the source commit's objects.
    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=archive"]);
    ostree(&[&dst_arg, "pull-local", &src_repo.to_string_lossy(), &c1]);

    block_on(async {
        let repo = Repo::open(&dst).await.unwrap();
        let to = repo.apply_static_delta_offline(&fromto).await.unwrap();
        assert_eq!(
            to.to_hex(),
            c2,
            "applied delta reproduces the target commit"
        );

        let (_commit, state) = repo.load_commit(&to).await.unwrap();
        assert_eq!(state, CommitState::Normal);
        // The bspatch'd object reproduces its exact v2 content.
        assert_eq!(
            read_file(&repo, &c2, "usr/share/patch.bin").await,
            patch_bin(true)
        );
        assert_eq!(read_file(&repo, &c2, "usr/bin/app").await, APP_V2);
        // The unchanged 512 KiB object is shared from the source, still readable.
        assert_eq!(
            read_file(&repo, &c2, "usr/share/data.bin").await,
            data_bin()
        );
        // An unchanged symlink is still resolvable (shared with the source).
        assert_eq!(read_symlink(&repo, &c2, "usr/bin/applink").await, "app");

        repo.set_ref_immediate("test", Some(&to)).await.unwrap();
    });
    ostree(&[&dst_arg, "fsck"]);
}

#[test]
fn verifies_signed_delta() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("delta-signed");
    let base = tmp.path();
    let (src_repo, c1, c2) = build_source_repo(base);

    // A separate repo holding both commits, with a signed from->to delta.
    let srepo = base.join("srepo");
    let srepo_arg = format!("--repo={}", srepo.display());
    ostree(&[&srepo_arg, "init", "--mode=archive"]);
    ostree(&[&srepo_arg, "pull-local", &src_repo.to_string_lossy(), &c1]);
    ostree(&[&srepo_arg, "pull-local", &src_repo.to_string_lossy(), &c2]);
    ostree(&[
        &srepo_arg,
        "static-delta",
        "generate",
        "--from",
        &c1,
        "--to",
        &c2,
        "--sign-type=ed25519",
        &format!("--sign={SECRET_B64}"),
    ]);
    let (_, signed) = find_delta_dirs(&srepo);
    let signed = signed.expect("signed from->to delta dir");

    block_on(async {
        let repo = Repo::open(&srepo).await.unwrap();
        let trusted =
            Ed25519Verifier::new([base64::decode(PUBLIC_B64).unwrap()], Vec::<Vec<u8>>::new())
                .unwrap();
        let outcome = repo
            .verify_static_delta(&signed, &[&trusted])
            .await
            .unwrap();
        assert!(outcome.valid, "trusted key verifies the signed delta");
        assert!(outcome.signatures.iter().any(|s| s.valid));

        // A verifier trusting a different key rejects it.
        let other = Ed25519Verifier::new([vec![0u8; 32]], Vec::<Vec<u8>>::new()).unwrap();
        let rejected = repo.verify_static_delta(&signed, &[&other]).await.unwrap();
        assert!(!rejected.valid, "untrusted key does not verify the delta");
    });
}

/// A 2 MiB pseudo-random file (xorshift64), sized so the tool expresses an
/// in-place edit as a rollsum copy-from-source delta rather than a bsdiff.
/// `edit` inverts a 512-byte window near the middle, leaving well over half the
/// content-defined chunks unchanged so the compiler prefers rollsum `write` ops.
fn rollsum_bin(edit: bool) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut v: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xff) as u8
        })
        .collect();
    if edit {
        for b in &mut v[1_048_576..1_049_088] {
            *b = !*b;
        }
    }
    v
}

/// Read the count reported for `key` (for example `"write="`) on a
/// `static-delta show` line, or zero if absent.
fn op_count(show: &str, key: &str) -> u64 {
    show.split_whitespace()
        .find_map(|tok| tok.strip_prefix(key).and_then(|n| n.parse().ok()))
        .unwrap_or(0)
}

#[test]
fn applies_from_to_delta_with_rollsum() {
    use std::os::unix::fs::PermissionsExt;

    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("delta-rollsum");
    let base = tmp.path();

    // Build a tree with a large regular file and commit it, then overwrite the
    // file in place and commit again.
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    let write_tree = |edit: bool, notes: &[u8]| {
        std::fs::write(tree.join("bigfile.dat"), rollsum_bin(edit)).unwrap();
        std::fs::set_permissions(
            tree.join("bigfile.dat"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std::fs::write(tree.join("notes.txt"), notes).unwrap();
    };

    let src = base.join("srcrepo");
    let src_arg = format!("--repo={}", src.display());
    ostree(&[&src_arg, "init", "--mode=archive"]);
    let commit = |tree: &Path, ts: &str| {
        String::from_utf8(ostree(&[
            &src_arg,
            "commit",
            "-b",
            "test",
            "--owner-uid=0",
            "--owner-gid=0",
            "--no-xattrs",
            &format!("--timestamp={ts}"),
            &format!("--tree=dir={}", tree.display()),
        ]))
        .unwrap()
        .trim()
        .to_owned()
    };

    write_tree(false, b"notes v1\n");
    let c1 = commit(&tree, "@1700000000");
    write_tree(true, b"notes v2\n");
    let c2 = commit(&tree, "@1700000100");
    ostree(&[
        &src_arg,
        "static-delta",
        "generate",
        "--from",
        &c1,
        "--to",
        &c2,
    ]);

    // The delta must actually use rollsum `write` ops, or it would not exercise
    // the path under test.
    let show = String::from_utf8(ostree(&[
        &src_arg,
        "static-delta",
        "show",
        &format!("{c1}-{c2}"),
    ]))
    .unwrap();
    assert!(
        op_count(&show, "write=") > 0,
        "the tool did not emit rollsum write ops:\n{show}"
    );

    let (_, fromto) = find_delta_dirs(&src);
    let fromto = fromto.expect("from->to delta dir");

    // A destination repo holding only the source commit's objects.
    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=archive"]);
    ostree(&[&dst_arg, "pull-local", &src.to_string_lossy(), &c1]);

    block_on(async {
        let repo = Repo::open(&dst).await.unwrap();
        let to = repo.apply_static_delta_offline(&fromto).await.unwrap();
        assert_eq!(
            to.to_hex(),
            c2,
            "applied delta reproduces the target commit"
        );

        let (_commit, state) = repo.load_commit(&to).await.unwrap();
        assert_eq!(state, CommitState::Normal);
        // The rollsum-reconstructed 2 MiB object reproduces its exact v2 content:
        // unchanged runs copied from the source object, the edited window from
        // the delta payload.
        assert_eq!(
            read_file(&repo, &c2, "bigfile.dat").await,
            rollsum_bin(true)
        );
        repo.set_ref_immediate("test", Some(&to)).await.unwrap();
    });
    ostree(&[&dst_arg, "fsck"]);
}

/// A 4 MiB pseudo-random file (xorshift64) with `edits` scattered 512-byte
/// windows inverted. Each edited window splits the rollsum match into another
/// contiguous run, and the tool emits one `r`/`R` pair per run, so the op stream
/// names the same source object once per edit plus one.
fn scattered_bin(edits: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut v: Vec<u8> = (0..4 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x & 0xff) as u8
        })
        .collect();
    for k in 0..edits {
        let off = 100_000 + k * 100_000;
        for b in &mut v[off..off + 512] {
            *b = !*b;
        }
    }
    v
}

/// A delta that names its read source many times over reconstructs the target
/// object correctly. The reader holds the loaded source across the `R`/`r`
/// boundary and reuses it on a checksum match, so this covers the reuse being
/// valid: a stale or misindexed held source would corrupt the copied runs and
/// fail the `close` checksum assertion. Forty scattered edits make the tool emit
/// forty-one `r` ops against one 4 MiB source object, where loading per op would
/// cost a full read and spill of the object forty-one times.
#[test]
fn applies_delta_naming_one_read_source_many_times() {
    use std::os::unix::fs::PermissionsExt;

    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("delta-resource");
    let base = tmp.path();
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();

    let write_tree = |edits: usize| {
        std::fs::write(tree.join("big.dat"), scattered_bin(edits)).unwrap();
        std::fs::set_permissions(tree.join("big.dat"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
    };

    let src = base.join("srcrepo");
    let src_arg = format!("--repo={}", src.display());
    ostree(&[&src_arg, "init", "--mode=archive"]);
    let commit = |ts: &str| {
        String::from_utf8(ostree(&[
            &src_arg,
            "commit",
            "-b",
            "test",
            "--owner-uid=0",
            "--owner-gid=0",
            "--no-xattrs",
            &format!("--timestamp={ts}"),
            &format!("--tree=dir={}", tree.display()),
        ]))
        .unwrap()
        .trim()
        .to_owned()
    };

    write_tree(0);
    let c1 = commit("@1700000000");
    write_tree(40);
    let c2 = commit("@1700000100");
    // Keep the object packed rather than delivered as a 4 MiB fallback.
    ostree(&[
        &src_arg,
        "static-delta",
        "generate",
        "--from",
        &c1,
        "--to",
        &c2,
        "--min-fallback-size=999",
    ]);

    let show = String::from_utf8(ostree(&[
        &src_arg,
        "static-delta",
        "show",
        &format!("{c1}-{c2}"),
    ]))
    .unwrap();
    let setread = op_count(&show, "setread=");
    assert!(
        setread > 10,
        "the tool must name the read source many times to exercise reuse:\n{show}"
    );
    assert_eq!(
        setread,
        op_count(&show, "unsetread="),
        "each read source is unset again, so reuse spans the R boundary:\n{show}"
    );

    let (_, fromto) = find_delta_dirs(&src);
    let fromto = fromto.expect("from->to delta dir");

    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    ostree(&[&dst_arg, "init", "--mode=archive"]);
    ostree(&[&dst_arg, "pull-local", &src.to_string_lossy(), &c1]);

    block_on(async {
        let repo = Repo::open(&dst).await.unwrap();
        let to = repo.apply_static_delta_offline(&fromto).await.unwrap();
        assert_eq!(to.to_hex(), c2);
        assert_eq!(
            read_file(&repo, &c2, "big.dat").await,
            scattered_bin(40),
            "every copied run lands, so the reused source stayed correct"
        );
        repo.set_ref_immediate("test", Some(&to)).await.unwrap();
    });
    ostree(&[&dst_arg, "fsck"]);
}

/// Write `size` bytes of a repeating block to `path` in bounded chunks, so a
/// large fixture costs little memory to produce and compresses small on disk
/// while still decompressing to its full size inside a delta part.
fn write_pattern(path: &Path, size: usize) {
    use std::io::Write;

    let mut block = vec![0u8; 1024 * 1024];
    for (i, b) in block.iter_mut().enumerate() {
        *b = (i * 31 + 7) as u8;
    }
    let file = std::fs::File::create(path).unwrap();
    let mut writer = std::io::BufWriter::new(file);
    let mut left = size;
    while left > 0 {
        let n = left.min(block.len());
        writer.write_all(&block[..n]).unwrap();
        left -= n;
    }
    writer.flush().unwrap();
}

/// A regular-file object larger than 512 MiB, carried inside a delta part
/// (fallback disabled), applies and validates. The reader spills the whole
/// decompressed part payload to a temp file and mmaps it, so a large packed
/// object costs staging-filesystem space rather than resident heap and no fixed
/// size ceiling rejects a delta the tool wrote. Ignored by default: it commits
/// and applies over half a gigabyte, too slow and disk-heavy for the normal
/// suite; run with `cargo test -p ostrya --test delta -- --ignored`.
#[test]
#[ignore = "creates a >512 MiB object; run with --ignored"]
fn applies_delta_with_object_over_half_gib_packed() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("delta-huge");
    let base = tmp.path();

    // One object of 520 MiB, past the reader's former 512 MiB ceiling.
    let size = 520 * 1024 * 1024;
    let tree = base.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    write_pattern(&tree.join("huge.bin"), size);

    let src = base.join("src");
    let src_arg = format!("--repo={}", src.display());
    ostree(&[&src_arg, "init", "--mode=archive"]);
    let c = String::from_utf8(ostree(&[
        &src_arg,
        "commit",
        "-b",
        "test",
        "--owner-uid=0",
        "--owner-gid=0",
        "--no-xattrs",
        "--timestamp=@1700000000",
        &format!("--tree=dir={}", tree.display()),
    ]))
    .unwrap()
    .trim()
    .to_owned();
    // Disable fallback so the object is packed into a part rather than delivered
    // as a loose fallback object, which is the path the size ceiling blocked.
    ostree(&[
        &src_arg,
        "static-delta",
        "generate",
        "--empty",
        "--to",
        &c,
        "--min-fallback-size=99999",
    ]);
    let show = String::from_utf8(ostree(&[&src_arg, "static-delta", "show", &c])).unwrap();
    assert!(
        show.contains("Number of fallback entries: 0"),
        "the object must be packed, not a fallback:\n{show}"
    );

    let (scratch, _) = find_delta_dirs(&src);
    let scratch = scratch.expect("from-scratch delta dir");

    let dst = base.join("dst");
    let dst_arg = format!("--repo={}", dst.display());
    block_on(async {
        let repo = Repo::create(&dst, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let to = repo.apply_static_delta_offline(&scratch).await.unwrap();
        assert_eq!(to.to_hex(), c, "applied delta reproduces the target commit");
        repo.set_ref_immediate("test", Some(&to)).await.unwrap();
    });
    // The tool validates the checksums of the objects the port wrote.
    ostree(&[&dst_arg, "fsck"]);
}
