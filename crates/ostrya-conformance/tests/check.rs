//! The static check of every record file, on each run of `cargo test`.
//!
//! The test loads the default matrix and runs `check::check` on it. The doc of
//! `check::check` lists the rules. The test needs no built binary and no
//! `ostree` command, so a record file that breaks a rule fails `cargo test`.

use ostrya_conformance::{check, default_matrix_dir, record};

#[test]
fn every_record_passes_static_validation() {
    let matrix = record::load(&default_matrix_dir()).expect("the record files load");
    let report = check::check(&matrix);
    assert!(
        report.ok(),
        "{} error(s) in {} records:\n{}",
        report.errors.len(),
        report.records,
        report.errors.join("\n")
    );
    assert!(report.cells > 0, "the matrix expanded to no cell");
}
