#![forbid(unsafe_code)]

//! The `ostrya-conformance` binary.
//!
//! Four subcommands, defined in `docs/conformance/harness.md`: `check`
//! validates the records and runs no binary, `run` executes the selected
//! cells, `observe` runs the reference alone and prints a record skeleton,
//! and `report` renders a JSON document as the per-family mode grids.
//!
//! Exit status: 0 when no `interop` failure occurred, 1 when one did or a
//! `--require` flag promoted a skip, and 2 on a static or usage error.

use std::path::PathBuf;
use std::process::ExitCode;

use ostrya_conformance::{
    check, exec, json, observe, record,
    record::Tier,
    report::{self, Format},
    runner, tier,
};

const USAGE: &str = "\
usage: ostrya-conformance <check|run|observe|report> [options]

common:
  --matrix DIR         the record directory (default: the one built beside
                       this crate, or $OSTRYA_MATRIX_DIR)
  --format FORMAT      human (default), tap, or json
  --ostrya PATH        the port binary (default: $OSTRYA_BIN, then PATH)
  --ostree PATH        the reference binary (default: $OSTREE_BIN, then PATH)

check:
  --verify-evidence    confirm every `evidence:` test name exists, at the
                       cost of a compile

run:
  --family F           select one family, for example M10
  --cell ID            select one cell by its identifier
  --corpus C           select one corpus
  --mode M             select one repository mode
  --tier T             select the cells that need exactly this tier
  --jobs N             threads (default: the available parallelism)
  --artifact-dir DIR   default: target/conformance/<run-id>
  --keep               keep a passing cell's artifacts
  --require WHAT       tool=ostree, or tier=T3, promoting those skips
  --strict-identity    let an `identity` failure gate the run

observe:
  --cell ID            the cell to observe (required)
  --run LINE           the invocation to try, when the record states none
  --setup NAMES        the setups to build, when the record states none

report:
  FILE                 a `check --format json` or `run --format json`
                       document, or `-` for standard input
  --output PATH        write here instead of standard output
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&arguments) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

/// Everything a subcommand may read from the command line.
#[derive(Default)]
struct Args {
    matrix: Option<PathBuf>,
    format: Option<String>,
    ostrya: Option<PathBuf>,
    ostree: Option<PathBuf>,
    family: Option<String>,
    cell: Option<String>,
    corpus: Option<String>,
    mode: Option<String>,
    tier: Option<String>,
    jobs: Option<String>,
    artifact_dir: Option<PathBuf>,
    keep: bool,
    require: Vec<String>,
    strict_identity: bool,
    verify_evidence: bool,
    run: Option<String>,
    setup: Vec<String>,
    output: Option<PathBuf>,
    positional: Vec<String>,
}

fn dispatch(arguments: &[String]) -> Result<ExitCode, String> {
    let Some(subcommand) = arguments.first() else {
        print!("{USAGE}");
        return Ok(ExitCode::from(2));
    };
    if subcommand == "-h" || subcommand == "--help" {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }

    let args = parse(&arguments[1..])?;
    let format = match args.format.as_deref() {
        None => Format::Human,
        Some(text) => Format::parse(text).ok_or_else(|| format!("`{text}` is no format"))?,
    };

    match subcommand.as_str() {
        "check" => command_check(&args, format),
        "run" => command_run(&args, format),
        "observe" => command_observe(&args),
        "report" => command_report(&args),
        other => Err(format!("`{other}` is no subcommand\n\n{USAGE}")),
    }
}

fn parse(arguments: &[String]) -> Result<Args, String> {
    let mut args = Args::default();
    let mut rest = arguments.iter().peekable();

    while let Some(argument) = rest.next() {
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_owned())),
            _ => (argument.as_str(), None),
        };
        let mut value = || -> Result<String, String> {
            match inline.clone() {
                Some(value) => Ok(value),
                None => rest
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("`{name}` needs a value")),
            }
        };

        match name {
            "--matrix" => args.matrix = Some(PathBuf::from(value()?)),
            "--format" => args.format = Some(value()?),
            "--ostrya" => args.ostrya = Some(PathBuf::from(value()?)),
            "--ostree" => args.ostree = Some(PathBuf::from(value()?)),
            "--family" => args.family = Some(value()?),
            "--cell" => args.cell = Some(value()?),
            "--corpus" => args.corpus = Some(value()?),
            "--mode" => args.mode = Some(value()?),
            "--tier" => args.tier = Some(value()?),
            "--jobs" => args.jobs = Some(value()?),
            "--artifact-dir" => args.artifact_dir = Some(PathBuf::from(value()?)),
            "--keep" => args.keep = true,
            "--require" => args.require.push(value()?),
            "--strict-identity" => args.strict_identity = true,
            "--verify-evidence" => args.verify_evidence = true,
            "--run" => args.run = Some(value()?),
            "--setup" => args
                .setup
                .extend(value()?.split_whitespace().map(str::to_owned)),
            "--output" => args.output = Some(PathBuf::from(value()?)),
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("`{other}` is no option"));
            }
            _ => args.positional.push(argument.clone()),
        }
    }
    Ok(args)
}

fn load(args: &Args) -> Result<record::Matrix, String> {
    let dir = args
        .matrix
        .clone()
        .unwrap_or_else(ostrya_conformance::default_matrix_dir);
    record::load(&dir)
}

fn command_check(args: &Args, format: Format) -> Result<ExitCode, String> {
    let matrix = load(args)?;
    let mut report_data = check::check(&matrix);
    if args.verify_evidence {
        let workspace = ostrya_conformance::workspace_dir();
        report_data
            .errors
            .extend(check::verify_evidence(&matrix, &workspace)?);
    }
    print!("{}", report::check_report(&matrix, &report_data, format));
    Ok(if report_data.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

fn command_run(args: &Args, format: Format) -> Result<ExitCode, String> {
    let matrix = load(args)?;
    let port = exec::resolve("port", args.ostrya.as_deref(), "OSTRYA_BIN", "ostrya")
        .ok_or_else(|| "no ostrya binary resolved; name one with --ostrya".to_owned())?;
    let reference = exec::resolve("reference", args.ostree.as_deref(), "OSTREE_BIN", "ostree");

    let mut require_tool = false;
    let mut require_tier = None;
    for requirement in &args.require {
        match requirement.split_once('=') {
            Some(("tool", "ostree")) => require_tool = true,
            Some(("tier", value)) => {
                require_tier =
                    Some(Tier::parse(value).ok_or_else(|| format!("`{value}` names no tier"))?);
            }
            _ => return Err(format!("`--require {requirement}` is not understood")),
        }
    }

    let filters = runner::Filters {
        family: args.family.clone(),
        cell: args.cell.clone(),
        corpus: args.corpus.clone(),
        mode: args.mode.clone(),
        tier: match &args.tier {
            None => None,
            Some(text) => Some(Tier::parse(text).ok_or_else(|| format!("`{text}` names no tier"))?),
        },
    };
    let jobs = match &args.jobs {
        None => std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1),
        Some(text) => text
            .parse()
            .map_err(|err| format!("`--jobs {text}`: {err}"))?,
    };
    let artifact_dir =
        ostrya_conformance::absolute(&args.artifact_dir.clone().unwrap_or_else(|| {
            PathBuf::from("target/conformance").join(ostrya_conformance::run_id())
        }));

    // Only the reference converts its messages through the locale, so a run
    // without one is unaffected.
    if reference.is_some()
        && let Some(defect) = exec::locale_codeset_defect()
    {
        return Err(defect);
    }

    let options = runner::Options {
        port: port.clone(),
        reference: reference.clone(),
        artifact_dir: artifact_dir.clone(),
        keep: args.keep,
        jobs,
        filters,
        require_tool,
        require_tier,
        strict_identity: args.strict_identity,
        host: tier::detect(),
    };

    let results = runner::run(&matrix, &options);
    let info = report::RunInfo {
        artifact_dir: artifact_dir.display().to_string(),
        port: port.path.display().to_string(),
        reference: reference.map(|tool| tool.path.display().to_string()),
        host: options.host.clone(),
    };
    print!("{}", report::run_report(&results, &info, format));

    Ok(if runner::gating_failure(&results, args.strict_identity) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn command_observe(args: &Args) -> Result<ExitCode, String> {
    let matrix = load(args)?;
    let id = args
        .cell
        .clone()
        .or_else(|| args.positional.first().cloned())
        .ok_or_else(|| "observe needs --cell ID".to_owned())?;
    let reference = exec::resolve("reference", args.ostree.as_deref(), "OSTREE_BIN", "ostree")
        .ok_or_else(|| "no ostree binary resolved; name one with --ostree".to_owned())?;
    let options = observe::Options {
        reference,
        port: exec::resolve("port", args.ostrya.as_deref(), "OSTRYA_BIN", "ostrya"),
        artifact_dir: ostrya_conformance::absolute(&args.artifact_dir.clone().unwrap_or_else(
            || PathBuf::from("target/conformance").join(ostrya_conformance::run_id()),
        )),
        run: args.run.clone(),
        setup: args.setup.clone(),
    };
    print!("{}", observe::observe(&matrix, &id, &options)?);
    Ok(ExitCode::SUCCESS)
}

fn command_report(args: &Args) -> Result<ExitCode, String> {
    let source = args.positional.first().map(String::as_str).unwrap_or("-");
    let text = if source == "-" {
        std::io::read_to_string(std::io::stdin()).map_err(|err| format!("reading stdin: {err}"))?
    } else {
        std::fs::read_to_string(source).map_err(|err| format!("reading {source}: {err}"))?
    };
    let document = json::parse(&text)?;
    let grids = report::grids(&document)?;
    match &args.output {
        None => print!("{grids}"),
        Some(path) => {
            std::fs::write(path, &grids).map_err(|err| format!("{}: {err}", path.display()))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}
