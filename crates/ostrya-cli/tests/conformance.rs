//! The conformance matrix, run against the binary this crate builds.
//!
//! `docs/conformance/harness.md`, "Cargo and CI wiring": this keeps the
//! workspace test run as the gate with no workflow change. Every cell that
//! needs the `ostree` tool reports as `skip: reference-absent` where the tool
//! is not installed, and never as a pass. A machine that holds the tool runs
//! `ostrya-conformance run --require tool=ostree` to demand the coverage.
//!
//! One setup list also runs directly here, over the port alone, because the
//! matrix run reaches it only where the `ostree` tool resolves.

use std::path::Path;

use ostrya_conformance::record::Actor;
use ostrya_conformance::{corpus, exec, setup};

#[test]
fn the_t0_matrix_selection_holds() {
    let port = Path::new(env!("CARGO_BIN_EXE_ostrya"));
    let artifacts = Path::new(env!("CARGO_TARGET_TMPDIR")).join("conformance");
    let gate = ostrya_conformance::t0_gate(port, &artifacts).expect("the matrix runs");
    assert!(!gate.failed, "{}", gate.text);
    eprintln!("{}", gate.text);
}

/// The corpus tree two setups of one record share.
///
/// `crates/ostrya-conformance/src/setup.rs`: every setup that needs the
/// corpus names one path for it, so `repo-with-commit` and `tree` in one
/// record resolve to the tree the first of them wrote. The runner skips a
/// cell before setup where no `ostree` binary resolves, so the context here
/// holds no reference handle and names the port for every step.
#[test]
fn two_setups_share_one_corpus_tree() {
    let port = exec::resolve(
        "port",
        Some(Path::new(env!("CARGO_BIN_EXE_ostrya"))),
        "OSTRYA_BIN",
        "ostrya",
    )
    .expect("the binary this crate builds resolves");
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("conformance-setup");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("the scratch root is created");

    let context = setup::Context {
        root: &root,
        own: &port,
        port: Some(&port),
        reference: None,
        mode: setup::DEFAULT_MODE,
        src_mode: setup::DEFAULT_MODE,
        dst_mode: setup::DEFAULT_MODE,
        corpus: setup::DEFAULT_CORPUS,
        created_by: Actor::Own,
        populated_by: Actor::Own,
    };
    let bindings = setup::apply(&["repo-with-commit", "tree"], &context)
        .expect("both setups apply, so the second binds `$TREE` for the first time");

    let bound = bindings.get("TREE").expect("`tree` binds `$TREE`");
    let expected = corpus::tree_path(&root, setup::DEFAULT_CORPUS);
    assert_eq!(
        Path::new(bound),
        expected,
        "`$TREE` names the corpus path the run materialized"
    );

    let mut trees: Vec<String> = std::fs::read_dir(&root)
        .expect("the scratch root reads")
        .map(|entry| {
            entry
                .expect("the entry reads")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("corpus-"))
        .collect();
    trees.sort();
    assert_eq!(
        trees,
        vec![format!("corpus-{}", setup::DEFAULT_CORPUS)],
        "one corpus tree stands under {}",
        root.display()
    );
}
