//! Shared helpers for the reading-path integration tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// Root of the tool-generated fixture repositories, one subdirectory per mode.
pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/generated")
}

/// The commit and object checksums recorded by the fixture generator. These are
/// mode-independent (the cross-mode commit-identity invariant), so they hold for
/// every fixture repository.
pub const COMMIT: &str = "b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89";
pub const CONTENT: &str = "d79e5560a90877b47660b639e3d7c88c20ca5a7604f867960e155c552025e104";
pub const ROOT_DIRTREE: &str = "1075002e681eb1fe7ff54ae6b76b1f65285e514b54d96deaa0952330b10c7983";
pub const ROOT_DIRMETA: &str = "446a0ef11b7cc167f3b603e585c7eeeeb675faa412d5ec73f62988eb0b6c5488";
pub const EMPTY_TXT: &str = "cc700d46f407c6c5ab2d5dde474366a928b7398277e61162e7f8ec06f469f07e";
pub const HELLO_TXT: &str = "cfffd52f38d14c87cf46e18d5260074421ba5961f0895954e9921f165f9c91db";
pub const LINK: &str = "f66efa496a72379413c44593de510dc344beb045294f1a543da87b2b6118db35";
pub const SUBDIR_DIRTREE: &str = "78154b9650d2a28716fd4a83584a2d9cba1833be4851714d8a0e89e8933c875a";
pub const NESTED_TXT: &str = "a4d80a620354908d76238bea8185775d2f6d60f55a1506d16ee06af212b4a125";

/// A throwaway directory removed when dropped.
pub struct TmpDir(PathBuf);

impl TmpDir {
    pub fn new(tag: &str) -> TmpDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ostrya-read-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        TmpDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Whether the `ostree` tool is available for cross-check tests.
pub fn ostree_available() -> bool {
    Command::new("ostree")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
