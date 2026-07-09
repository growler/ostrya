#![deny(unsafe_code)]

//! Phase 1a verification gate (see docs/port-plan.md): borrowed dirtree and
//! xattr traversal must perform zero heap allocations.
//!
//! This is the one test binary that installs a global allocator, so nothing
//! else runs concurrently to perturb the count. The allocator wraps the system
//! allocator and tallies allocations only while `ACTIVE` is set. `GlobalAlloc`
//! cannot be implemented in safe Rust, so the single `impl` below carries a
//! scoped `allow(unsafe_code)`; this is the allocation-test exception recorded
//! in CLAUDE.md.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ostrya_gvariant::{GvDecode, Type, Value, to_bytes};

#[path = "../../../tests/support.rs"]
mod support;

use support::{DirMetaView, DirTreeView};

struct Counting;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicBool = AtomicBool::new(false);

fn tally() {
    if ACTIVE.load(Ordering::SeqCst) {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
    }
}

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        tally();
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        tally();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        tally();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn checksum(seed: u8) -> Value {
    Value::Bytes(support::checksum(seed))
}

/// A `(a(say)a(sayay))` dirtree with several file and directory entries.
fn build_dirtree() -> Vec<u8> {
    let files = Value::Array(vec![
        Value::Tuple(vec!["alpha.txt".into(), checksum(1)]),
        Value::Tuple(vec!["beta.txt".into(), checksum(2)]),
        Value::Tuple(vec!["gamma.txt".into(), checksum(3)]),
    ]);
    let dirs = Value::Array(vec![
        Value::Tuple(vec!["sub".into(), checksum(4), checksum(5)]),
        Value::Tuple(vec!["sub2".into(), checksum(6), checksum(7)]),
    ]);
    to_bytes(
        &Type::parse("(a(say)a(sayay))").unwrap(),
        &Value::Tuple(vec![files, dirs]),
    )
    .unwrap()
}

/// A `(uuua(ayay))` dirmeta with several xattrs.
fn build_dirmeta() -> Vec<u8> {
    let xattr =
        |k: &str, v: &str| Value::Tuple(vec![Value::from(k.as_bytes()), Value::from(v.as_bytes())]);
    let xattrs = Value::Array(vec![
        xattr("user.one", "first"),
        xattr("user.two", "second"),
        xattr("security.selinux", "system_u:object_r:etc_t:s0"),
    ]);
    to_bytes(
        &Type::parse("(uuua(ayay))").unwrap(),
        &Value::Tuple(vec![
            Value::U32(0),
            Value::U32(0),
            Value::U32(0o40755),
            xattrs,
        ]),
    )
    .unwrap()
}

#[test]
fn dirtree_and_xattr_traversal_is_allocation_free() {
    let dirtree = build_dirtree();
    let dirmeta = build_dirmeta();
    let mut acc = 0usize;

    ACTIVE.store(true, Ordering::SeqCst);

    let (files, dirs): DirTreeView = GvDecode::decode(&dirtree).unwrap();
    let (_uid, _gid, _mode, xattrs): DirMetaView = GvDecode::decode(&dirmeta).unwrap();

    for entry in files {
        let (name, checksum) = entry.unwrap();
        acc += name.len() + checksum.len();
    }
    for entry in dirs {
        let (name, tree, meta) = entry.unwrap();
        acc += name.len() + tree.len() + meta.len();
    }
    for entry in xattrs {
        let (key, value) = entry.unwrap();
        acc += key.len() + value.len();
    }

    ACTIVE.store(false, Ordering::SeqCst);

    assert!(acc > 0, "traversal visited nothing");
    assert_eq!(
        ALLOCS.load(Ordering::SeqCst),
        0,
        "borrowed dirtree/xattr traversal must not allocate"
    );
}
