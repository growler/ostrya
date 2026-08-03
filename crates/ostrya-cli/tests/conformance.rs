//! The conformance matrix, run against the binary this crate builds.
//!
//! `docs/conformance/harness.md`, "Cargo and CI wiring": this keeps the
//! workspace test run as the gate with no workflow change. Every cell that
//! needs the `ostree` tool reports as `skip: reference-absent` where the tool
//! is not installed, and never as a pass. A machine that holds the tool runs
//! `ostrya-conformance run --require tool=ostree` to demand the coverage.

use std::path::Path;

#[test]
fn the_t0_matrix_selection_holds() {
    let port = Path::new(env!("CARGO_BIN_EXE_ostrya"));
    let artifacts = Path::new(env!("CARGO_TARGET_TMPDIR")).join("conformance");
    let gate = ostrya_conformance::t0_gate(port, &artifacts).expect("the matrix runs");
    assert!(!gate.failed, "{}", gate.text);
    eprintln!("{}", gate.text);
}
