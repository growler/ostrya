//! The record vocabulary and the expansion of a record into cells.
//!
//! [`load`] reads the record files of a directory into a [`Matrix`]. The
//! constants hold the field vocabularies: [`DESCRIPTIVE_FIELDS`],
//! [`EXECUTABLE_FIELDS`], [`MODES`], and [`OUTCOMES`].

use std::fmt;
use std::path::{Path, PathBuf};

use crate::deb822::{self, Paragraph};

/// The six repository modes that a record can name.
///
/// [`check`](crate::check::check) refuses a value of `modes`, `src-mode`, or
/// `dst-mode` that is not in this list. The mode grids of
/// [`grids`](crate::report::grids) have one column for each mode, in this order.
pub const MODES: [&str; 6] = [
    "archive",
    "bare",
    "bare-user",
    "bare-user-only",
    "bare-user-shared",
    "bare-split-xattrs",
];

/// The record fields that describe a cell and that
/// [`runner::run`](crate::runner::run) does not execute.
///
/// [`check`](crate::check::check) refuses a field name that is not in this
/// list or in [`EXECUTABLE_FIELDS`].
pub const DESCRIPTIVE_FIELDS: [&str; 21] = [
    "family",
    "corpus",
    "op",
    "modes",
    "src-mode",
    "dst-mode",
    "created-by",
    "populated-by",
    "operated-by",
    "tier",
    "outcome",
    "severity",
    "identity",
    "oracle",
    "evidence",
    "spec",
    "loss",
    "question",
    "cli-gap",
    "subcommand",
    "note",
];

/// The record fields that state what [`runner::run`](crate::runner::run) executes.
pub const EXECUTABLE_FIELDS: [&str; 12] = [
    "cell",
    "setup",
    "run",
    "ref-run",
    "probe",
    "expect-exit",
    "expect-stdout",
    "expect-stderr",
    "ref-expect-exit",
    "ref-expect-stdout",
    "ref-expect-stderr",
    "ref-may-abort",
];

/// The values of the `outcome` field.
///
/// [`check`](crate::check::check) refuses a value that is not in this list. If
/// a record has no invocation and cites no evidence, its cells report a skip
/// with the reason `declaration`. The detail of that skip names the outcome (see
/// [`CellResult::reason`](crate::runner::CellResult::reason)).
pub const OUTCOMES: [&str; 8] = [
    "full",
    "lossy",
    "needs-priv",
    "refused-both",
    "refused-clean",
    "impossible",
    "unobserved",
    "unimplemented-cli",
];

/// The privilege tier that a cell needs, or that the host gives.
///
/// The variants are in tier order, from `T0` to `T4`.
/// [`detect`](crate::tier::detect) finds the tier of the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Unprivileged.
    T0,
    /// Unprivileged, in two or more groups.
    T1,
    /// Root in a user namespace, with a mapped root user.
    T2,
    /// Real root in the initial namespace.
    T3,
    /// Real root on an SELinux-enforcing kernel.
    T4,
}

impl Tier {
    /// Returns the tier that `text` names (`T0` to `T4`), or `None` for other
    /// text.
    pub fn parse(text: &str) -> Option<Tier> {
        match text {
            "T0" => Some(Tier::T0),
            "T1" => Some(Tier::T1),
            "T2" => Some(Tier::T2),
            "T3" => Some(Tier::T3),
            "T4" => Some(Tier::T4),
            _ => None,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Tier::T0 => "T0",
            Tier::T1 => "T1",
            Tier::T2 => "T2",
            Tier::T3 => "T3",
            Tier::T4 => "T4",
        };
        f.write_str(text)
    }
}

/// The implementation that does one step of a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    /// The `ostree` command.
    Reference,
    /// The `ostrya` binary.
    Port,
    /// The implementation of the [side](crate::oracle::Side) that runs the step.
    Own,
}

impl Actor {
    /// Returns the actor that the value of a custody field names.
    ///
    /// The custody fields are `created-by`, `populated-by`, and `operated-by`.
    /// The value `t` names [`Reference`](Actor::Reference), and `p` names
    /// [`Port`](Actor::Port). Other text gives `None`, so this function never
    /// returns [`Own`](Actor::Own).
    pub fn parse(text: &str) -> Option<Actor> {
        match text {
            "t" => Some(Actor::Reference),
            "p" => Some(Actor::Port),
            _ => None,
        }
    }
}

/// One record of a `*.matrix` file.
#[derive(Clone, Debug)]
pub struct Record {
    /// The [`Paragraph`] that holds the fields of the record.
    pub paragraph: Paragraph,
}

impl Record {
    /// Returns the value of the first field named `name`, or `None` if there
    /// is none.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.paragraph.get(name)
    }

    /// Returns the values of the first field named `name`, split at white
    /// space.
    ///
    /// The values are in their order in the field. If the record has no such
    /// field, the vector is empty.
    pub fn list(&self, name: &str) -> Vec<&str> {
        self.paragraph.list(name)
    }

    /// Returns the `<file>:<line>` position where the record starts.
    pub fn origin(&self) -> String {
        self.paragraph.origin()
    }

    /// Returns the `family` field, or the empty string if the record has none.
    pub fn family(&self) -> &str {
        self.get("family").unwrap_or("")
    }

    /// Returns the tier that the `tier` field names.
    ///
    /// If the field is absent or names no tier, the result is `T0`.
    pub fn tier(&self) -> Tier {
        self.get("tier").and_then(Tier::parse).unwrap_or(Tier::T0)
    }

    /// Returns the `severity` field, or `interop` if the record has none.
    pub fn severity(&self) -> &str {
        self.get("severity").unwrap_or("interop")
    }

    /// Returns the `outcome` field, or `unobserved` if the record has none.
    pub fn outcome(&self) -> &str {
        self.get("outcome").unwrap_or("unobserved")
    }

    /// Returns the actor that the custody field `field` names.
    ///
    /// If the field is absent or names no actor, the result is
    /// [`Own`](Actor::Own). [`Actor::parse`] reads the value.
    pub fn actor(&self, field: &str) -> Actor {
        self.get(field).and_then(Actor::parse).unwrap_or(Actor::Own)
    }

    /// Returns `true` if the record has a `run` or a `probe` field.
    pub fn is_executable(&self) -> bool {
        self.get("run").is_some() || self.get("probe").is_some()
    }

    /// Returns `true` if the record cites a test that proves its claim.
    ///
    /// The `evidence` field names the test. The value `-` cites no test.
    pub fn cites_evidence(&self) -> bool {
        matches!(self.get("evidence"), Some(value) if value != "-")
    }

    /// Returns the invocation of the `ostree` command for this record.
    ///
    /// The result is the `ref-run` field if the record has one, else the `run`
    /// field. If `ref-run` is `n-a`, the `ostree` command has no equivalent
    /// invocation and the result is `None`. If the record has neither field,
    /// the result is `None`.
    pub fn reference_run(&self) -> Option<&str> {
        match self.get("ref-run") {
            Some("n-a") => None,
            Some(line) => Some(line),
            None => self.get("run"),
        }
    }
}

/// One cell: a record with one combination of the values of its list fields.
///
/// [`load`] makes the cells. The forms of each field are in
/// [Cells](load#cells).
#[derive(Clone, Debug)]
pub struct Cell {
    /// The cell id, for example `m0/C1/bare`.
    ///
    /// [`check`](crate::check::check) refuses two cells with the same id.
    pub id: String,
    /// The family that the cell belongs to.
    pub family: String,
    /// The row key that [`check`](crate::check::check) and the mode grids use.
    pub row: String,
    /// The repository mode that the cell runs in, if it names one.
    pub mode: Option<String>,
    /// The corpus of the cell, if it names one.
    pub corpus: Option<String>,
    /// The operation of the cell, if it names one.
    pub op: Option<String>,
    /// The index in [`Matrix::records`] of the record that gives this cell.
    pub record: usize,
}

/// The records of one matrix directory and their cells.
pub struct Matrix {
    /// The directory that [`load`] read the record files from.
    pub dir: PathBuf,
    /// The records, in the order of the files and of the records in each file.
    pub records: Vec<Record>,
    /// The cells of the records, in record order.
    pub cells: Vec<Cell>,
}

impl Matrix {
    /// Returns the record that a cell comes from.
    ///
    /// # Panics
    ///
    /// Panics if `cell.record` is not a valid index into
    /// [`records`](Matrix::records). This can occur if `cell` comes from
    /// another matrix.
    pub fn record(&self, cell: &Cell) -> &Record {
        &self.records[cell.record]
    }
}

/// Reads every `*.matrix` file in `dir` and expands the records into cells.
///
/// `load` reads the files in name order. It skips a directory entry that it
/// cannot read.
///
/// # Cells
///
/// A record expands into one cell for each combination of the values of its
/// list fields. The `family` field selects the fields that the record must
/// have and the form of each [`Cell`]:
///
/// - `M0` needs `corpus` and `modes`. Each corpus and mode give the id
///   `m0/<corpus>/<mode>`. The row key is the corpus.
/// - `M1` needs `op`, `modes`, and the custody fields `t t p` or `p p t`. Each
///   operation and mode give the id `m1/<direction>/<op>/<mode>`, with the
///   token of [`direction`]. The row key is `<direction>/<op>`.
/// - `M10` needs `cell` and names at most one mode. The record gives one cell
///   with the id `m10/<cell>`. The row key is the `subcommand` field, else the
///   `cell` field.
/// - `M2` to `M9` need `src-mode` and `dst-mode`. Each source mode and
///   destination mode give the id `<family>/<src-mode>/<dst-mode>`, with the
///   family in lower case. The row key is the source mode, and
///   [`Cell::mode`] is the destination mode.
///
/// In all families except `M0`, [`Cell::corpus`] is the first `corpus` value.
/// In `M2` to `M9`, [`Cell::op`] is the first `op` value. `M0` and `M10` cells
/// have no operation.
///
/// # Errors
///
/// - An error if `dir` cannot be read.
/// - An error if `dir` holds no `*.matrix` file.
/// - An error if a matrix file cannot be read as UTF-8 text.
/// - An error if a matrix file has a syntax error, from
///   [`parse`](deb822::parse).
/// - An error if a record has no `family` field or names an unknown family.
/// - An error if a record does not have a field that its family needs.
/// - An error if an `M10` record names more than one mode.
/// - An error if a record expands into no cell.
pub fn load(dir: &Path) -> Result<Matrix, String> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|err| format!("reading {}: {err}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "matrix"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("no *.matrix file in {}", dir.display()));
    }

    let mut records = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .map_err(|err| format!("reading {}: {err}", file.display()))?;
        let paragraphs = deb822::parse(file, &text).map_err(|err| err.to_string())?;
        records.extend(paragraphs.into_iter().map(|paragraph| Record { paragraph }));
    }

    let mut cells = Vec::new();
    for (index, record) in records.iter().enumerate() {
        cells.extend(expand(record, index)?);
    }
    Ok(Matrix {
        dir: dir.to_path_buf(),
        records,
        cells,
    })
}

/// Returns the direction token of an `M1` record.
///
/// The custody fields are `created-by`, `populated-by`, and `operated-by`:
///
/// - `t t p` gives `d1`. The `ostree` command creates and populates the
///   repository, and the `ostrya` binary operates on it.
/// - `p p t` gives `d2`. The `ostrya` binary creates and populates the
///   repository, and the `ostree` command operates on it.
/// - Other values, or an absent field, give `None`.
pub fn direction(record: &Record) -> Option<&'static str> {
    match (
        record.get("created-by"),
        record.get("populated-by"),
        record.get("operated-by"),
    ) {
        (Some("t"), Some("t"), Some("p")) => Some("d1"),
        (Some("p"), Some("p"), Some("t")) => Some("d2"),
        _ => None,
    }
}

/// Expands one record into its cells.
fn expand(record: &Record, index: usize) -> Result<Vec<Cell>, String> {
    let family = record.family().to_owned();
    if family.is_empty() {
        return Err(format!("{}: record has no `family` field", record.origin()));
    }
    let modes = record.list("modes");
    let corpora = record.list("corpus");
    let ops = record.list("op");

    let mut cells = Vec::new();
    match family.as_str() {
        "M0" => {
            require(record, "corpus")?;
            require(record, "modes")?;
            for corpus in &corpora {
                for mode in &modes {
                    cells.push(Cell {
                        id: format!("m0/{corpus}/{mode}"),
                        family: family.clone(),
                        row: (*corpus).to_owned(),
                        mode: Some((*mode).to_owned()),
                        corpus: Some((*corpus).to_owned()),
                        op: None,
                        record: index,
                    });
                }
            }
        }
        "M1" => {
            require(record, "op")?;
            require(record, "modes")?;
            let direction = direction(record).ok_or_else(|| {
                format!(
                    "{}: M1 needs `created-by`, `populated-by`, and `operated-by` \
                     naming either `t t p` or `p p t`",
                    record.origin()
                )
            })?;
            for op in &ops {
                for mode in &modes {
                    cells.push(Cell {
                        id: format!("m1/{direction}/{op}/{mode}"),
                        family: family.clone(),
                        row: format!("{direction}/{op}"),
                        mode: Some((*mode).to_owned()),
                        corpus: corpora.first().map(|corpus| (*corpus).to_owned()),
                        op: Some((*op).to_owned()),
                        record: index,
                    });
                }
            }
        }
        "M10" => {
            let tail = record
                .get("cell")
                .ok_or_else(|| format!("{}: M10 needs a `cell` field", record.origin()))?;
            // A cell is one invocation, so it holds one repository mode: the
            // mode that the record names, else the default mode. Two modes
            // give two cells with one id.
            if modes.len() > 1 {
                return Err(format!(
                    "{}: an M10 record names at most one mode, and this one names {}",
                    record.origin(),
                    modes.len()
                ));
            }
            cells.push(Cell {
                id: format!("m10/{tail}"),
                family: family.clone(),
                row: record.get("subcommand").unwrap_or(tail).to_owned(),
                mode: modes.first().map(|mode| (*mode).to_owned()),
                corpus: corpora.first().map(|corpus| (*corpus).to_owned()),
                op: None,
                record: index,
            });
        }
        "M2" | "M3" | "M4" | "M5" | "M6" | "M7" | "M8" | "M9" => {
            require(record, "src-mode")?;
            require(record, "dst-mode")?;
            let lower = family.to_lowercase();
            for src in record.list("src-mode") {
                for dst in record.list("dst-mode") {
                    cells.push(Cell {
                        id: format!("{lower}/{src}/{dst}"),
                        family: family.clone(),
                        row: src.to_owned(),
                        mode: Some(dst.to_owned()),
                        corpus: corpora.first().map(|corpus| (*corpus).to_owned()),
                        op: ops.first().map(|op| (*op).to_owned()),
                        record: index,
                    });
                }
            }
        }
        other => {
            return Err(format!("{}: unknown family `{other}`", record.origin()));
        }
    }

    if cells.is_empty() {
        return Err(format!("{}: record expands to no cell", record.origin()));
    }
    Ok(cells)
}

fn require(record: &Record, field: &str) -> Result<(), String> {
    if record.list(field).is_empty() {
        return Err(format!(
            "{}: `{}` needs a `{field}` field",
            record.origin(),
            record.family()
        ));
    }
    Ok(())
}
