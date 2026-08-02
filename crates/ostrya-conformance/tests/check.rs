//! Static validation of every record, on every run of `cargo test`.
//!
//! This test needs no built binary and no reference tool, so it gates the
//! record files themselves: deb822 syntax, the field vocabulary, the
//! completeness rule, placeholder binding, and the corpus, setup, oracle, and
//! probe registries.

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
