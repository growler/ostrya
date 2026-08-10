//! The record vocabulary and the expansion of a record into cells.
//!
//! `docs/conformance/README.md` defines the axes and the descriptive fields.
//! `docs/conformance/harness.md` defines the executable fields. This module
//! holds both vocabularies, the record type, and the rule that turns one
//! record covering a product of `corpus`, `modes`, and `op` values into one
//! cell per combination.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::deb822::{self, Paragraph};

/// The six repository modes a family file may name.
pub const MODES: [&str; 6] = [
    "archive",
    "bare",
    "bare-user",
    "bare-user-only",
    "bare-user-shared",
    "bare-split-xattrs",
];

/// Fields that describe a cell and that the runner does not execute.
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

/// Fields the runner executes.
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

/// The outcome vocabulary, which is also the reason a declaration reports.
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

/// The privilege tier a cell needs, and the tier the host provides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Unprivileged.
    T0,
    /// Unprivileged, in two or more groups.
    T1,
    /// User namespace with mapped root.
    T2,
    /// Real root in the initial namespace.
    T3,
    /// Real root on an SELinux-enforcing kernel.
    T4,
}

impl Tier {
    /// The tier `text` names, or `None` for an unrecognized token.
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

/// Which implementation performs a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    /// The `ostree` tool.
    Reference,
    /// The `ostrya` binary.
    Port,
    /// The implementation whose subtree the step runs in.
    Own,
}

impl Actor {
    /// The actor the `created-by`, `populated-by`, or `operated-by` token
    /// names, or `None` for an unrecognized token.
    pub fn parse(text: &str) -> Option<Actor> {
        match text {
            "t" => Some(Actor::Reference),
            "p" => Some(Actor::Port),
            _ => None,
        }
    }
}

/// One record from a family file.
#[derive(Clone, Debug)]
pub struct Record {
    /// The paragraph the record was parsed from.
    pub paragraph: Paragraph,
}

impl Record {
    /// The single value of `name`, or `None` where the record states none.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.paragraph.get(name)
    }

    /// Every value of `name`, in file order.
    pub fn list(&self, name: &str) -> Vec<&str> {
        self.paragraph.list(name)
    }

    /// The `<file>:<line>` position the record starts at.
    pub fn origin(&self) -> String {
        self.paragraph.origin()
    }

    /// The `family` field, or the empty string.
    pub fn family(&self) -> &str {
        self.get("family").unwrap_or("")
    }

    /// The tier the record declares, defaulting to T0.
    pub fn tier(&self) -> Tier {
        self.get("tier").and_then(Tier::parse).unwrap_or(Tier::T0)
    }

    /// The `severity` field, `interop` by default.
    pub fn severity(&self) -> &str {
        self.get("severity").unwrap_or("interop")
    }

    /// The `outcome` field, `unobserved` by default.
    pub fn outcome(&self) -> &str {
        self.get("outcome").unwrap_or("unobserved")
    }

    /// The actor a custody field names, `Own` when the field is absent.
    pub fn actor(&self, field: &str) -> Actor {
        self.get(field).and_then(Actor::parse).unwrap_or(Actor::Own)
    }

    /// Whether the record states an invocation or a probe the runner executes.
    pub fn is_executable(&self) -> bool {
        self.get("run").is_some() || self.get("probe").is_some()
    }

    /// Whether the record cites a test that proves its claim elsewhere.
    pub fn cites_evidence(&self) -> bool {
        matches!(self.get("evidence"), Some(value) if value != "-")
    }

    /// The reference invocation: `ref-run` when given, else `run`.
    /// `None` states that the reference has no equivalent invocation.
    pub fn reference_run(&self) -> Option<&str> {
        match self.get("ref-run") {
            Some("n-a") => None,
            Some(line) => Some(line),
            None => self.get("run"),
        }
    }
}

/// One cell: a record combined with one point of the product its multi-valued
/// fields describe.
#[derive(Clone, Debug)]
pub struct Cell {
    /// The cell id, unique across the matrix.
    pub id: String,
    /// The family the cell belongs to.
    pub family: String,
    /// The row key the completeness rule and the report grid use.
    pub row: String,
    /// The repository mode the cell runs in, where it names one.
    pub mode: Option<String>,
    /// The corpus the cell runs over, where it names one.
    pub corpus: Option<String>,
    /// The operation the cell exercises, where it names one.
    pub op: Option<String>,
    /// The index of the record this cell expanded from.
    pub record: usize,
}

/// Every record file in one directory, and the cells they expand into.
pub struct Matrix {
    /// The directory the record files were read from.
    pub dir: PathBuf,
    /// Every record, in file order.
    pub records: Vec<Record>,
    /// Every cell those records expand into.
    pub cells: Vec<Cell>,
}

impl Matrix {
    /// The record a cell came from.
    pub fn record(&self, cell: &Cell) -> &Record {
        &self.records[cell.record]
    }
}

/// Read every `*.matrix` file in `dir`, in name order, and expand the records.
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

/// The direction token for an M1 record: `d1` when the tool produced the
/// repository, `d2` when the port did.
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

/// Expand one record into its cells.
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
            // A cell is one invocation, so it holds one repository mode: the one
            // the record names, else the default. Naming two would state two
            // cells under one identifier.
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
