//! The corpora `docs/conformance/README.md` defines.
//!
//! A corpus is a source tree the harness materializes, together with the
//! lowest privilege tier at which the tree can be built. Both implementations
//! get their own copy, built by this code rather than by either binary, so a
//! difference the run reports is a difference in what the implementations did
//! with the tree.
//!
//! Two builders are absent. `C5` needs a `security.capability` value in the
//! form real root writes, which the harness does not synthesize, and `C7`
//! needs an SELinux-enforcing kernel. Both sit at tier T3 or above, so a
//! host below that tier reports their cells as `skip: tier` and never reaches
//! the builder; a host at that tier gets an explicit failure naming what is
//! missing.

use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, FileType, Mode, XattrFlags};

use crate::record::Tier;

/// Every corpus name, with the tier its tree needs.
pub const CORPORA: [(&str, Tier); 14] = [
    ("C0", Tier::T0),
    ("C1", Tier::T0),
    ("C2", Tier::T0),
    ("C3", Tier::T0),
    ("C4", Tier::T0),
    ("C5", Tier::T3),
    ("C6", Tier::T3),
    ("C7", Tier::T4),
    ("C8", Tier::T0),
    ("C9", Tier::T0),
    ("C10", Tier::T0),
    ("C11", Tier::T0),
    ("C12", Tier::T3),
    ("C13", Tier::T2),
];

/// Whether `name` is a registered corpus.
pub fn is_registered(name: &str) -> bool {
    CORPORA.iter().any(|(known, _)| *known == name)
}

/// The tier the corpus needs, or `None` when it is not registered.
pub fn tier(name: &str) -> Option<Tier> {
    CORPORA
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, tier)| *tier)
}

/// Build the corpus tree at `root`, which must not exist yet.
pub fn materialize(name: &str, root: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root).map_err(|err| fail(root, err))?;
    match name {
        "C0" | "C3" => basic(root),
        "C1" => modes(root),
        "C2" => special_bits(root),
        "C4" => user_xattrs(root),
        "C5" => Err(
            "corpus C5 needs a security.capability value in the form real \
                     root writes; the harness does not synthesize one"
                .to_owned(),
        ),
        "C6" => trusted_xattrs(root),
        "C7" => Err("corpus C7 needs an SELinux-enforcing kernel".to_owned()),
        "C8" => hardlinks(root),
        "C9" => payload_sizes(root),
        "C10" => names(root),
        "C11" => unsupported_unprivileged(root),
        "C12" => unsupported_privileged(root),
        "C13" => real_ownership(root),
        other => Err(format!("corpus `{other}` is not registered")),
    }
}

/// `C0` and `C3`: a regular file, an empty file, a nested regular file, and a
/// symlink. `C3` differs only in the commit options a record states.
fn basic(root: &Path) -> Result<(), String> {
    write(&root.join("file.txt"), b"corpus C0 regular file\n", 0o644)?;
    write(&root.join("empty"), b"", 0o644)?;
    directory(&root.join("dir"), 0o755)?;
    write(
        &root.join("dir/nested.txt"),
        b"corpus C0 nested file\n",
        0o644,
    )?;
    symlink("file.txt", &root.join("link"))
}

/// `C1`: five regular-file modes and three directory modes.
fn modes(root: &Path) -> Result<(), String> {
    for mode in [0o644u32, 0o755, 0o400, 0o000, 0o664] {
        write(
            &root.join(format!("f{mode:04o}")),
            b"corpus C1 mode sample\n",
            mode,
        )?;
    }
    for mode in [0o755u32, 0o700, 0o711] {
        directory(&root.join(format!("d{mode:04o}")), mode)?;
    }
    Ok(())
}

/// `C2`: setuid, setgid, and sticky, on files and on directories.
fn special_bits(root: &Path) -> Result<(), String> {
    write(&root.join("setuid"), b"corpus C2 setuid\n", 0o4755)?;
    write(&root.join("setgid"), b"corpus C2 setgid\n", 0o2755)?;
    write(&root.join("sticky"), b"corpus C2 sticky\n", 0o1755)?;
    directory(&root.join("setgid-dir"), 0o2775)?;
    directory(&root.join("sticky-dir"), 0o1777)
}

/// `C4`: user xattrs, including a set whose stored order differs from its
/// creation order, an empty value, and a 1024-byte value.
fn user_xattrs(root: &Path) -> Result<(), String> {
    let one = root.join("one");
    write(&one, b"corpus C4 one xattr\n", 0o644)?;
    set_xattr(&one, "user.demo", b"value")?;

    let three = root.join("three");
    write(&three, b"corpus C4 three xattrs\n", 0o644)?;
    for name in ["user.c", "user.a", "user.b"] {
        set_xattr(&three, name, name.as_bytes())?;
    }

    let empty = root.join("empty-value");
    write(&empty, b"corpus C4 empty value\n", 0o644)?;
    set_xattr(&empty, "user.empty", b"")?;

    let big = root.join("big-value");
    write(&big, b"corpus C4 big value\n", 0o644)?;
    set_xattr(&big, "user.big", &vec![b'x'; 1024])
}

/// `C6`: a file carrying `trusted.demo`, which needs real root.
fn trusted_xattrs(root: &Path) -> Result<(), String> {
    let path = root.join("trusted.txt");
    write(&path, b"corpus C6 trusted xattr\n", 0o644)?;
    set_xattr(&path, "trusted.demo", b"value")
}

/// `C8`: two paths on one inode, and a third path holding the same content on
/// its own inode.
fn hardlinks(root: &Path) -> Result<(), String> {
    let first = root.join("a.txt");
    write(&first, b"corpus C8 shared content\n", 0o644)?;
    std::fs::hard_link(&first, root.join("b.txt")).map_err(|err| fail(&first, err))?;
    write(&root.join("c.txt"), b"corpus C8 shared content\n", 0o644)
}

/// `C9`: a file large enough to cross a payload-link threshold, and a sparse
/// file.
fn payload_sizes(root: &Path) -> Result<(), String> {
    let large = root.join("large.bin");
    let pattern: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();
    let mut file = std::fs::File::create(&large).map_err(|err| fail(&large, err))?;
    for _ in 0..16 {
        file.write_all(&pattern).map_err(|err| fail(&large, err))?;
    }
    drop(file);
    permissions(&large, 0o644)?;

    let sparse = root.join("sparse.bin");
    let mut file = std::fs::File::create(&sparse).map_err(|err| fail(&sparse, err))?;
    file.write_all(b"head").map_err(|err| fail(&sparse, err))?;
    file.seek(SeekFrom::Start(1 << 20))
        .map_err(|err| fail(&sparse, err))?;
    file.write_all(b"tail").map_err(|err| fail(&sparse, err))?;
    drop(file);
    permissions(&sparse, 0o644)
}

/// `C10`: names the command line cannot carry.
fn names(root: &Path) -> Result<(), String> {
    let non_utf8 = std::ffi::OsStr::from_bytes(b"non-utf8-\xff\xfe");
    write(&root.join(non_utf8), b"corpus C10 non-utf8 name\n", 0o644)?;
    write(
        &root.join("n".repeat(255)),
        b"corpus C10 long name\n",
        0o644,
    )?;
    write(&root.join("line\nbreak"), b"corpus C10 newline\n", 0o644)?;
    write(
        &root.join("quote\"back\\slash"),
        b"corpus C10 quoting\n",
        0o644,
    )?;

    let mut deep = root.to_path_buf();
    for _ in 0..40 {
        deep.push("d");
    }
    std::fs::create_dir_all(&deep).map_err(|err| fail(&deep, err))?;
    write(&deep.join("leaf.txt"), b"corpus C10 deep path\n", 0o644)
}

/// `C11`: a fifo and a unix socket, both of which the format excludes.
fn unsupported_unprivileged(root: &Path) -> Result<(), String> {
    let fifo = root.join("fifo");
    rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(0o644), 0)
        .map_err(|err| fail(&fifo, err))?;
    let socket = root.join("socket");
    std::os::unix::net::UnixListener::bind(&socket).map_err(|err| fail(&socket, err))?;
    Ok(())
}

/// `C12`: a character device and a block device, which need real root.
fn unsupported_privileged(root: &Path) -> Result<(), String> {
    let character = root.join("chardev");
    rustix::fs::mknodat(
        CWD,
        &character,
        FileType::CharacterDevice,
        Mode::from_raw_mode(0o644),
        rustix::fs::makedev(1, 3),
    )
    .map_err(|err| fail(&character, err))?;
    let block = root.join("blockdev");
    rustix::fs::mknodat(
        CWD,
        &block,
        FileType::BlockDevice,
        Mode::from_raw_mode(0o644),
        rustix::fs::makedev(7, 0),
    )
    .map_err(|err| fail(&block, err))
}

/// `C13`: files the filesystem records as owned by 0:0, 1:1, and
/// 65534:65534.
fn real_ownership(root: &Path) -> Result<(), String> {
    for id in [0u32, 1, 65534] {
        let path = root.join(format!("owned-{id}"));
        write(&path, b"corpus C13 real ownership\n", 0o644)?;
        rustix::fs::chownat(
            CWD,
            &path,
            Some(rustix::fs::Uid::from_raw(id)),
            Some(rustix::fs::Gid::from_raw(id)),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|err| fail(&path, err))?;
    }
    Ok(())
}

fn write(path: &Path, content: &[u8], mode: u32) -> Result<(), String> {
    std::fs::write(path, content).map_err(|err| fail(path, err))?;
    permissions(path, mode)
}

fn directory(path: &Path, mode: u32) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|err| fail(path, err))?;
    permissions(path, mode)
}

fn permissions(path: &Path, mode: u32) -> Result<(), String> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|err| fail(path, err))
}

fn symlink(target: &str, path: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, path).map_err(|err| fail(path, err))
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) -> Result<(), String> {
    rustix::fs::lsetxattr(path, name, value, XattrFlags::empty())
        .map_err(|err| format!("setting {name} on {}: {err}", path.display()))
}

fn fail(path: &Path, err: impl std::fmt::Display) -> String {
    format!("{}: {err}", path.display())
}

/// The path a corpus tree is built at, under a cell's scratch root.
pub fn tree_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!("corpus-{name}"))
}
