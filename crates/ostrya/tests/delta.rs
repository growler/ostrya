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
//! Every test that drives the tool is skipped when the tool is absent,
//! matching the other interop tests. The signed-delta test also needs the
//! tool's ed25519 engine and is skipped where the build carries none. The
//! removal tests build their delta entries by hand and need no tool.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{TmpDir, ostree_available, ostree_supports_ed25519};
use futures_lite::AsyncReadExt;
use ostrya::{
    Checksum, CommitState, CreateOptions, DeltaEndianness, DeltaSuperblock, Ed25519Verifier, Error,
    FileKind, Repo, RepoMode, TreeEntry, base64, static_delta_relative_dir,
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
    if !ostree_supports_ed25519() {
        eprintln!("skipping: ostree tool has no ed25519 engine");
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

/// The part lines of the tool's `static-delta show` for the delta in `dir`,
/// against the superblock accessors and `DeltaSuperblock::part_stats` over the
/// same files.
fn assert_part_stats_match_the_tool(repo_arg: &str, name: &str, dir: &Path) {
    let show = String::from_utf8(ostree(&[repo_arg, "static-delta", "show", name])).unwrap();
    let lines: Vec<&str> = show.lines().collect();
    block_on(async {
        let sb = DeltaSuperblock::read(&dir.join("superblock"))
            .await
            .unwrap();
        assert!(lines.contains(&format!("To: {}", sb.to_commit()).as_str()));
        assert!(lines.contains(&format!("Timestamp: {}", sb.timestamp()).as_str()));
        assert!(lines.contains(&format!("Number of parts: {}", sb.parts().len()).as_str()));
        assert_eq!(sb.endianness(), DeltaEndianness::Little);
        for (i, part) in sb.parts().iter().enumerate() {
            let stats = sb.part_stats(i, dir).await.unwrap();
            let ops = stats.ops;
            let expected = [
                format!(
                    "PartMeta{i}: nobjects={} size={} usize={}",
                    part.objects().len(),
                    part.size(),
                    part.uncompressed_size()
                ),
                format!(
                    "PartPayload{i}: nmodes={} nxattrs={} blobsize={} opsize={}",
                    stats.modes, stats.xattrs, stats.blob_size, stats.ops_size
                ),
                format!(
                    "PartPayloadOps{i}: openspliceclose={} open={} write={} setread={} \
                     unsetread={} close={} bspatch={}",
                    ops.open_splice_close,
                    ops.open,
                    ops.write,
                    ops.set_read_source,
                    ops.unset_read_source,
                    ops.close,
                    ops.bspatch
                ),
            ];
            for line in &expected {
                assert!(lines.contains(&line.as_str()), "{line} not in:\n{show}");
            }
        }
    });
}

/// The part statistics the library reads agree with the tool's report over a
/// from-scratch delta and a from->to delta carrying a bspatch object.
#[test]
fn part_stats_match_the_tool_show() {
    if !ostree_available() {
        eprintln!("skipping: ostree tool not available");
        return;
    }
    let tmp = TmpDir::new("delta-stats");
    let base = tmp.path();
    let (src_repo, c1, c2) = build_source_repo(base);
    let repo_arg = format!("--repo={}", src_repo.display());
    let (scratch, fromto) = find_delta_dirs(&src_repo);
    assert_part_stats_match_the_tool(&repo_arg, &c1, &scratch.unwrap());
    let show = String::from_utf8(ostree(&[
        &repo_arg,
        "static-delta",
        "show",
        &format!("{c1}-{c2}"),
    ]))
    .unwrap();
    assert!(op_count(&show, "bspatch=") > 0, "no bspatch op:\n{show}");
    assert_part_stats_match_the_tool(&repo_arg, &format!("{c1}-{c2}"), &fromto.unwrap());
}

/// The `delta-indexes/` listing takes a regular file `<2 chars>/<41
/// chars>.index` that decodes as a checksum, sorted, and skips every other
/// entry.
#[test]
fn static_delta_indexes_skip_what_is_not_an_index() {
    let tmp = TmpDir::new("delta-indexes");
    let base = tmp.path();
    let path = base.join("repo");
    block_on(async {
        let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        assert!(repo.list_static_delta_indexes().await.unwrap().is_empty());

        let indexes = path.join("delta-indexes");
        std::fs::create_dir_all(&indexes).unwrap();
        assert!(repo.list_static_delta_indexes().await.unwrap().is_empty());

        let targets = [
            Checksum::from_bytes([0xee; 32]),
            Checksum::from_bytes([0x01; 32]),
        ];
        for to in &targets {
            let b64 = to.to_base64_modified();
            std::fs::create_dir_all(indexes.join(&b64[..2])).unwrap();
            std::fs::write(
                indexes.join(&b64[..2]).join(format!("{}.index", &b64[2..])),
                b"",
            )
            .unwrap();
        }

        let a41 = "A".repeat(41);
        let skipped = [
            format!("abc/{}.index", "A".repeat(40)),
            format!("abc/{a41}.index"),
            format!("AA/{}.index", "A".repeat(40)),
            format!("AA/{}.index", "A".repeat(42)),
            format!("AA/{a41}.INDEX"),
            format!("AA/{a41}.index.index"),
            format!("AA/{a41}.index~"),
            format!("AA/{a41}.idx"),
            // A last character with nonzero low bits, and one outside the
            // alphabet.
            format!("AA/{}B.index", "A".repeat(40)),
            format!("AA/{}!.index", "A".repeat(40)),
        ];
        for entry in &skipped {
            let file = indexes.join(entry);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, b"").unwrap();
        }
        std::fs::create_dir_all(indexes.join("AB").join(format!("{a41}.index"))).unwrap();
        std::fs::create_dir_all(indexes.join("AC")).unwrap();
        std::os::unix::fs::symlink("/dev/null", indexes.join("AC").join(format!("{a41}.index")))
            .unwrap();
        std::os::unix::fs::symlink("AA", indexes.join("AD")).unwrap();
        std::fs::write(indexes.join("stray"), b"").unwrap();

        let mut expected = targets.to_vec();
        expected.sort();
        assert_eq!(repo.list_static_delta_indexes().await.unwrap(), expected);
    });
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
    assert_part_stats_match_the_tool(&src_arg, &format!("{c1}-{c2}"), &fromto);

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
    // The statistics walk streams the part three times with no temp file, and
    // its payload framing takes 4-byte offsets.
    assert_part_stats_match_the_tool(&src_arg, &c, &scratch);

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

/// Two distinct commit checksums for the removal tests. No commit object backs
/// them: the removal reads only the `deltas/` tree.
fn removal_checksums() -> (Checksum, Checksum) {
    (
        Checksum::from_hex(&"1a".repeat(32)).unwrap(),
        Checksum::from_hex(&"2b".repeat(32)).unwrap(),
    )
}

/// A fresh `archive` repository under `base/repo`.
async fn removal_repo(base: &Path) -> Repo {
    Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// The absolute path of one delta's `deltas/<fanout>/<rest>` entry.
fn delta_entry(base: &Path, from: Option<&Checksum>, to: &Checksum) -> PathBuf {
    base.join("repo").join(static_delta_relative_dir(from, to))
}

/// A delta directory holding a superblock and one part, as a generator leaves
/// it.
fn write_flat_delta(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("superblock"), b"superblock").unwrap();
    std::fs::write(dir.join("0"), b"part").unwrap();
}

#[test]
fn delete_static_delta_removes_the_entry_and_keeps_the_fanout() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let tmp = TmpDir::new("delta-delete-tree");
    let base = tmp.path();
    let (c1, c2) = removal_checksums();
    block_on(async {
        let repo = removal_repo(base).await;
        let outside = base.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("file"), b"keep\n").unwrap();

        let scratch = delta_entry(base, None, &c2);
        let from_to = delta_entry(base, Some(&c1), &c2);
        write_flat_delta(&scratch);
        write_flat_delta(&from_to);
        std::fs::create_dir_all(scratch.join("n1/n2/n3")).unwrap();
        std::fs::write(scratch.join("n1/n2/n3/f"), b"nested").unwrap();
        std::os::unix::fs::symlink(&outside, scratch.join("n1/outside")).unwrap();
        std::os::unix::fs::symlink("nowhere", scratch.join("dangling")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            scratch.join("fifo"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        std::fs::write(scratch.join(OsStr::from_bytes(b"n\xff\xfe")), b"bytes").unwrap();

        let b64 = c2.to_base64_modified();
        let index_dir = base.join("repo/delta-indexes").join(&b64[..2]);
        std::fs::create_dir_all(&index_dir).unwrap();
        let index = index_dir.join(format!("{}.index", &b64[2..]));
        std::fs::write(&index, b"index").unwrap();
        std::fs::write(base.join("repo/summary"), b"summary").unwrap();

        repo.delete_static_delta(None, &c2).await.unwrap();
        assert!(
            std::fs::symlink_metadata(&scratch).is_err(),
            "the entry goes"
        );
        assert!(scratch.parent().unwrap().is_dir(), "the fanout stays");
        assert_eq!(
            std::fs::read(outside.join("file")).unwrap(),
            b"keep\n",
            "no symlink below the entry is followed"
        );
        assert!(
            from_to.join("superblock").is_file(),
            "the other delta stays"
        );
        assert_eq!(std::fs::read(&index).unwrap(), b"index");
        assert_eq!(
            std::fs::read(base.join("repo/summary")).unwrap(),
            b"summary"
        );
        assert_eq!(
            repo.list_static_delta_indexes().await.unwrap(),
            vec![c2],
            "the index still names the target"
        );

        repo.delete_static_delta(Some(&c1), &c2).await.unwrap();
        assert!(std::fs::symlink_metadata(&from_to).is_err());
        assert!(repo.list_static_deltas().await.unwrap().is_empty());
    });
}

#[test]
fn delete_static_delta_removes_a_file_or_a_link_at_the_path() {
    let tmp = TmpDir::new("delta-delete-leaf");
    let base = tmp.path();
    let (_, c2) = removal_checksums();
    block_on(async {
        let repo = removal_repo(base).await;
        let outside = base.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("file"), b"keep\n").unwrap();
        let entry = delta_entry(base, None, &c2);
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();

        let cases: [(&str, &dyn Fn()); 4] = [
            ("a regular file", &|| {
                std::fs::write(&entry, b"file").unwrap()
            }),
            ("an empty directory", &|| {
                std::fs::create_dir(&entry).unwrap()
            }),
            ("a symlink to a directory", &|| {
                std::os::unix::fs::symlink(&outside, &entry).unwrap()
            }),
            ("a symlink to a file", &|| {
                std::os::unix::fs::symlink(outside.join("file"), &entry).unwrap()
            }),
        ];
        for (case, make) in cases {
            make();
            repo.delete_static_delta(None, &c2)
                .await
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            assert!(
                std::fs::symlink_metadata(&entry).is_err(),
                "{case} at the path is removed"
            );
            assert_eq!(
                std::fs::read(outside.join("file")).unwrap(),
                b"keep\n",
                "{case}: the link target stays"
            );
        }
    });
}

#[test]
fn delete_static_delta_reports_an_absent_delta() {
    let tmp = TmpDir::new("delta-delete-absent");
    let base = tmp.path();
    let (c1, c2) = removal_checksums();
    block_on(async {
        let repo = removal_repo(base).await;
        let absent = |err: Error, from: Option<Checksum>| {
            let name = match from {
                Some(from) => format!("{}-{}", from.to_hex(), c2.to_hex()),
                None => c2.to_hex(),
            };
            assert_eq!(err.to_string(), format!("Can't find delta {name}"));
            assert!(
                matches!(&err, Error::StaticDeltaNotFound { from: f, to } if *f == from && *to == c2),
                "{err:?}"
            );
            assert_eq!(
                std::io::Error::from(err).kind(),
                std::io::ErrorKind::NotFound
            );
        };

        // No `deltas/` directory at all.
        let deltas = base.join("repo/deltas");
        if deltas.exists() {
            std::fs::remove_dir_all(&deltas).unwrap();
        }
        absent(repo.delete_static_delta(None, &c2).await.unwrap_err(), None);

        // `deltas/` with no fanout.
        std::fs::create_dir(&deltas).unwrap();
        absent(
            repo.delete_static_delta(Some(&c1), &c2).await.unwrap_err(),
            Some(c1),
        );

        // A dangling symlink at the path is an absent delta, and it stays.
        let entry = delta_entry(base, None, &c2);
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("nowhere", &entry).unwrap();
        absent(repo.delete_static_delta(None, &c2).await.unwrap_err(), None);
        assert!(std::fs::symlink_metadata(&entry).is_ok(), "the link stays");
        std::fs::remove_file(&entry).unwrap();

        // A symlink loop fails the existence check with its own errno.
        std::os::unix::fs::symlink(entry.file_name().unwrap(), &entry).unwrap();
        let err = repo.delete_static_delta(None, &c2).await.unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err:?}");
    });
}

/// Marks the re-executed child of
/// [`delete_static_delta_removes_a_tree_deeper_than_the_descriptor_limit`], and
/// names the file the child writes to record that the removal ran.
const DEEP_DELETE_CHILD: &str = "OSTRYA_DEEP_DELTA_DELETE_CHILD";
/// The soft descriptor limit the child runs under. It stands well above what
/// the repository, the runtime, and the blocking pool open for themselves.
const DEEP_DELETE_NOFILE: usize = 256;
/// The depth of the tree the child removes. It stands well above
/// [`DEEP_DELETE_NOFILE`], so a removal holding one descriptor per level runs
/// out.
const DEEP_DELETE_DEPTH: usize = 1024;

#[test]
fn delete_static_delta_removes_a_tree_deeper_than_the_descriptor_limit() {
    // The limit is a property of the process and the tests of this binary run
    // in parallel threads, so the lowered limit goes to a child: this test
    // binary re-executed for this test alone, through `sh` with `ulimit -n`.
    if let Some(marker) = std::env::var_os(DEEP_DELETE_CHILD) {
        delete_a_deep_delta();
        std::fs::write(marker, b"removed").expect("record that the deep removal ran");
        return;
    }
    let tmp = TmpDir::new("delta-delete-deep-marker");
    let marker = tmp.path().join("removed");
    let exe = std::env::current_exe().expect("the path of the running test binary");
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"ulimit -n "$1" || exit 111; shift; exec "$@""#)
        .arg("sh")
        .arg(DEEP_DELETE_NOFILE.to_string())
        .arg(&exe)
        .arg("--exact")
        .arg("delete_static_delta_removes_a_tree_deeper_than_the_descriptor_limit")
        .arg("--nocapture")
        .env(DEEP_DELETE_CHILD, &marker)
        .status()
        .expect("re-run the test binary under a lowered descriptor limit");
    assert!(
        status.success(),
        "the deep removal failed under a soft limit of {DEEP_DELETE_NOFILE} descriptors: {status}"
    );
    // A name the child's filter does not match runs nothing and still exits 0,
    // so the marker is what proves the removal ran.
    assert!(
        marker.exists(),
        "the child ran no deep removal: the test name the filter names is stale"
    );
}

/// Remove a delta directory [`DEEP_DELETE_DEPTH`] levels deep. Runs in the
/// child process, under the lowered descriptor limit.
fn delete_a_deep_delta() {
    use std::os::fd::AsFd;

    let tmp = TmpDir::new("delta-delete-deep");
    let base = tmp.path();
    let (_, c2) = removal_checksums();
    block_on(async {
        let repo = removal_repo(base).await;
        let entry = delta_entry(base, None, &c2);
        write_flat_delta(&entry);
        // The tree is built through a descending descriptor, so no path of its
        // own grows past the kernel's limit.
        let mut dir: std::os::fd::OwnedFd = std::fs::File::open(&entry).unwrap().into();
        for _ in 0..DEEP_DELETE_DEPTH {
            rustix::fs::mkdirat(dir.as_fd(), "d", rustix::fs::Mode::from_raw_mode(0o755)).unwrap();
            dir = rustix::fs::openat(
                dir.as_fd(),
                "d",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
        }
        rustix::fs::openat(
            dir.as_fd(),
            "marker",
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o644),
        )
        .unwrap();
        drop(dir);

        repo.delete_static_delta(None, &c2).await.unwrap();
        assert!(
            std::fs::symlink_metadata(&entry).is_err(),
            "the deep entry goes"
        );
    });
}

#[test]
fn delete_static_delta_removes_an_empty_directory_with_no_search_permission() {
    use std::os::unix::fs::PermissionsExt;

    if rustix::process::geteuid().is_root() {
        eprintln!("skipping: root ignores the directory permissions this test relies on");
        return;
    }
    let tmp = TmpDir::new("delta-delete-no-search");
    let base = tmp.path();
    let (c1, c2) = removal_checksums();
    let read_only = || std::fs::Permissions::from_mode(0o400);
    block_on(async {
        let repo = removal_repo(base).await;

        // An empty subdirectory that can be read but not searched.
        let entry = delta_entry(base, None, &c2);
        write_flat_delta(&entry);
        std::fs::create_dir(entry.join("sub")).unwrap();
        std::fs::set_permissions(entry.join("sub"), read_only()).unwrap();
        repo.delete_static_delta(None, &c2).await.unwrap();
        assert!(
            std::fs::symlink_metadata(&entry).is_err(),
            "the entry with an empty mode-0400 subdirectory goes"
        );

        // The delta directory itself, empty, with no search permission.
        let entry = delta_entry(base, Some(&c1), &c2);
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::set_permissions(&entry, read_only()).unwrap();
        repo.delete_static_delta(Some(&c1), &c2).await.unwrap();
        assert!(
            std::fs::symlink_metadata(&entry).is_err(),
            "the empty mode-0400 delta directory goes"
        );

        // A subdirectory with no search permission and an entry in it cannot
        // be emptied, and the removal fails.
        let entry = delta_entry(base, None, &c2);
        std::fs::create_dir_all(entry.join("sub")).unwrap();
        std::fs::write(entry.join("sub/f"), b"f").unwrap();
        std::fs::set_permissions(entry.join("sub"), read_only()).unwrap();
        let err = repo.delete_static_delta(None, &c2).await.unwrap_err();
        std::fs::set_permissions(entry.join("sub"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert_eq!(
            std::io::Error::from(err).kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(entry.join("sub/f").is_file(), "the unreachable entry stays");
    });
}
