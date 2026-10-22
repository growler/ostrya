//! The man pages of the `ostrya` command.
//!
//! The pages are generated from the `clap` definition of [`Cli`] and are
//! kept in `crates/ostrya-cli/man`. The test in this module renders each page
//! and compares it with its file. When a page differs, the test fails. Run the
//! test with `OSTRYA_BLESS_MAN=1` to write the files again:
//!
//! ```text
//! OSTRYA_BLESS_MAN=1 cargo test -p ostrya-cli --bin ostrya man_pages
//! ```
//!
//! The module is compiled for tests alone, so the `ostrya` binary carries no
//! generator.
//!
//! # Pages
//!
//! - `ostrya.1` has the global options and the list of subcommands.
//! - `ostrya-<name>.1` has one subcommand. A nested subcommand, such as
//!   `remote add`, is a section of the page of its parent.
//! - Each page of [`FILE_PAGES`], such as `ostrya-repo.5`, describes a file
//!   format and has no subcommand.
//!
//! A file `man/extra/<page>.roff`, for example `man/extra/ostrya.1.roff`, is
//! added to the end of the page of the same name, before SEE ALSO. It holds
//! the sections that `clap` does not describe, such as ENVIRONMENT and
//! EXAMPLES. The body of a page of [`FILE_PAGES`] is its file in
//! `man/extra` alone.
//!
//! # Text
//!
//! The help text is written in the roff `man` macros. A `-` becomes `\-`, so
//! an option name in the text stays an ASCII hyphen-minus. A pair of
//! backticks becomes bold text. A word with a character that is not a letter,
//! such as an option name, gets `\%`, so groff does not hyphenate it. A
//! paragraph with an indented line is kept without fill.
//!
//! The submodule `roff` holds the generic renderer. The man page test of
//! `ostrya-mountd` includes the same file.

use std::collections::HashSet;
use std::path::Path;

use clap::{Arg, Command, CommandFactory};

use super::Cli;

mod roff;

use roff::{
    about, arg_description, escape, escape_quoted, local_options, long_about, option_label,
    positional_args, positional_label, push_extra, push_item, push_name, push_synopsis, push_text,
    push_title, usage, visible_subcommands, with_full_stop,
};

/// The name of the top-level command and of the manual in each title line.
const NAME: &str = "ostrya";

/// The environment variable that lets the test write the pages again.
const BLESS: &str = "OSTRYA_BLESS_MAN";

/// A page that describes a file format and has no subcommand.
struct FilePage {
    /// The page name, such as `ostrya-repo`.
    name: &'static str,
    /// The manual section, such as `5`.
    section: &'static str,
    /// The title of the manual in the title line.
    manual: &'static str,
    /// The one-line summary of the NAME section.
    summary: &'static str,
    /// The pages of the SEE ALSO section, as a name and a section.
    see_also: &'static [(&'static str, &'static str)],
}

/// The pages that describe a file format.
const FILE_PAGES: &[FilePage] = &[FilePage {
    name: "ostrya-repo",
    section: "5",
    manual: "File Formats",
    summary: "The layout of an ostrya repository",
    see_also: &[
        ("ostrya", "1"),
        ("ostrya-config", "1"),
        ("ostrya-init", "1"),
    ],
}];

/// Returns the file name and the roff text of each page.
///
/// `extra` is the directory of the hand-written sections.
fn render_pages(extra: &Path) -> Vec<(String, String)> {
    let mut top = Cli::command();
    // `build` sets the full name of each subcommand, such as `ostrya remote
    // add`, which the usage text shows. It also adds the `help` subcommand
    // and copies each global option into each subcommand.
    top.build();
    let globals: HashSet<String> = top
        .get_arguments()
        .filter(|arg| arg.is_global_set())
        .map(|arg| arg.get_id().to_string())
        .collect();

    let mut pages = Vec::new();
    let file = format!("{NAME}.1");
    let text = render_top_page(&top, &read_extra(extra, &file));
    pages.push((file, text));
    for sub in visible_subcommands(&top) {
        let file = format!("{NAME}-{}.1", sub.get_name());
        let text = render_subcommand_page(sub, &globals, &read_extra(extra, &file));
        pages.push((file, text));
    }
    for page in FILE_PAGES {
        let file = format!("{}.{}", page.name, page.section);
        let body = read_extra(extra, &file);
        assert!(!body.is_empty(), "man/extra has no body for {file}");
        pages.push((file, render_file_page(page, &body)));
    }
    pages
}

/// Returns the hand-written sections for the page `file`, or an empty string.
fn read_extra(extra: &Path, file: &str) -> String {
    std::fs::read_to_string(extra.join(format!("{file}.roff"))).unwrap_or_default()
}

/// Renders a page of [`FILE_PAGES`] with the hand-written `body`.
fn render_file_page(page: &FilePage, body: &str) -> String {
    let mut out = String::new();
    push_title(&mut out, page.name, page.section, page.manual);
    push_name(&mut out, page.name, page.summary);
    push_extra(&mut out, body);
    out.push_str(".SH SEE ALSO\n");
    let see_also: Vec<String> = page
        .see_also
        .iter()
        .map(|(name, section)| format!("\\fB{}\\fR({section})", escape(name)))
        .collect();
    out.push_str(&see_also.join(",\n"));
    out.push('\n');
    out
}

/// Renders `ostrya.1`.
fn render_top_page(top: &Command, extra: &str) -> String {
    let mut out = String::new();
    push_title(&mut out, NAME, "1", "User Commands");
    push_name(&mut out, NAME, &about(top));
    push_synopsis(&mut out, top);
    out.push_str(".SH DESCRIPTION\n");
    push_text(&mut out, &with_full_stop(long_about(top)), ".PP");

    let options: Vec<&Arg> = top
        .get_arguments()
        .filter(|arg| arg.is_global_set() && !arg.is_hide_set())
        .collect();
    if !options.is_empty() {
        out.push_str(".SH OPTIONS\n");
        out.push_str("The options below are global. Each one is accepted before and after\n");
        out.push_str("the subcommand name.\n");
        for arg in options {
            push_item(&mut out, &option_label(arg), &arg_description(arg));
        }
    }

    out.push_str(".SH COMMANDS\n");
    for sub in visible_subcommands(top) {
        let page = format!("\\fB{NAME}\\-{}\\fR(1)", escape(sub.get_name()));
        push_item(&mut out, &page, &about(sub));
    }

    push_extra(&mut out, extra);
    out
}

/// Renders `ostrya-<name>.1` for the subcommand `cmd`.
fn render_subcommand_page(cmd: &Command, globals: &HashSet<String>, extra: &str) -> String {
    let name = format!("{NAME}-{}", cmd.get_name());
    let mut out = String::new();
    push_title(&mut out, &name, "1", "User Commands");
    push_name(&mut out, &name, &about(cmd));
    push_synopsis(&mut out, cmd);
    out.push_str(".SH DESCRIPTION\n");
    push_text(&mut out, &with_full_stop(long_about(cmd)), ".PP");

    let positionals = positional_args(cmd);
    if !positionals.is_empty() {
        out.push_str(".SH ARGUMENTS\n");
        for arg in positionals {
            push_item(&mut out, &positional_label(arg), &arg_description(arg));
        }
    }

    out.push_str(".SH OPTIONS\n");
    for arg in local_options(cmd, globals) {
        push_item(&mut out, &option_label(arg), &arg_description(arg));
    }
    out.push_str(".PP\n");
    out.push_str(&format!(
        "The global options are listed in \\fB{NAME}\\fR(1).\n"
    ));

    let nested = visible_subcommands(cmd);
    if !nested.is_empty() {
        out.push_str(".SH COMMANDS\n");
        for sub in nested {
            push_nested(&mut out, sub.get_name(), sub, globals);
        }
    }

    push_extra(&mut out, extra);
    out.push_str(".SH SEE ALSO\n");
    out.push_str(&format!("\\fB{NAME}\\fR(1)\n"));
    out
}

/// Renders the nested subcommand `cmd` as a section with the title `title`.
///
/// A deeper level of nesting is a further section with a longer title.
fn push_nested(out: &mut String, title: &str, cmd: &Command, globals: &HashSet<String>) {
    out.push_str(&format!(".SS \"{}\"\n", escape_quoted(title)));
    push_text(out, &with_full_stop(long_about(cmd)), ".PP");
    out.push_str(".PP\n.nf\n");
    out.push_str(&escape(&usage(cmd)));
    out.push_str("\n.fi\n");

    let positionals = positional_args(cmd);
    if !positionals.is_empty() {
        out.push_str(".PP\nArguments:\n");
        for arg in positionals {
            push_item(out, &positional_label(arg), &arg_description(arg));
        }
    }
    let options = local_options(cmd, globals);
    if !options.is_empty() {
        out.push_str(".PP\nOptions:\n");
        for arg in options {
            push_item(out, &option_label(arg), &arg_description(arg));
        }
    }
    for sub in visible_subcommands(cmd) {
        push_nested(out, &format!("{title} {}", sub.get_name()), sub, globals);
    }
}

/// The committed pages are the pages that the `clap` definition renders.
///
/// The pages describe the default feature set, which the shipped binary
/// has, so the test runs only when each subcommand feature is on. If a page
/// differs, is missing, or has no subcommand and is not in [`FILE_PAGES`],
/// the test fails. Only then does
/// it read `OSTRYA_BLESS_MAN`. If the variable is set, the test writes the
/// pages again and removes each page that has no subcommand.
#[cfg(all(
    feature = "receive",
    feature = "push",
    feature = "serve",
    feature = "send",
    feature = "s3"
))]
#[test]
fn man_pages_match_the_committed_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("man");
    let extra = dir.join("extra");
    let pages = render_pages(&extra);
    let names: HashSet<&str> = pages.iter().map(|(name, _)| name.as_str()).collect();

    let stale: Vec<&(String, String)> = pages
        .iter()
        .filter(|(name, text)| {
            std::fs::read_to_string(dir.join(name)).ok().as_deref() != Some(text.as_str())
        })
        .collect();
    let orphans: Vec<String> = std::fs::read_dir(&dir)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| is_page_file(name) && !names.contains(name.as_str()))
                .collect()
        })
        .unwrap_or_default();
    let unused_extra: Vec<String> = std::fs::read_dir(&extra)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| {
                    name.strip_suffix(".roff")
                        .is_none_or(|page| !names.contains(page))
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(
        unused_extra.is_empty(),
        "man/extra has files for no page: {unused_extra:?}"
    );
    if stale.is_empty() && orphans.is_empty() {
        return;
    }

    if std::env::var_os(BLESS).is_none() {
        let stale: Vec<&str> = stale.iter().map(|(name, _)| name.as_str()).collect();
        panic!(
            "the man pages differ from the clap definition: changed or missing \
             {stale:?}, no subcommand {orphans:?}. Run \
             `{BLESS}=1 cargo test -p ostrya-cli --bin ostrya man_pages` to write \
             them again."
        );
    }
    std::fs::create_dir_all(&dir).expect("create the man directory");
    for (name, text) in stale {
        std::fs::write(dir.join(name), text).expect("write a man page");
    }
    for name in orphans {
        std::fs::remove_file(dir.join(name)).expect("remove a man page");
    }
}

/// Returns true if `name` is the file name of a man page, such as
/// `ostrya.1` or `ostrya-repo.5`.
#[cfg(all(
    feature = "receive",
    feature = "push",
    feature = "serve",
    feature = "send",
    feature = "s3"
))]
fn is_page_file(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(stem, section)| {
        !stem.is_empty() && section.len() == 1 && section.as_bytes()[0].is_ascii_digit()
    })
}
