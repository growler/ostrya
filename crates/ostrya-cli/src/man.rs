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
//!
//! A file `man/extra/<page>.roff`, for example `man/extra/ostrya.1.roff`, is
//! added to the end of the page of the same name, before SEE ALSO. It holds
//! the sections that `clap` does not describe, such as ENVIRONMENT and
//! EXAMPLES.
//!
//! # Text
//!
//! The help text is written in the roff `man` macros. A `-` becomes `\-`, so
//! an option name in the text stays an ASCII hyphen-minus. A pair of
//! backticks becomes bold text. A word with a character that is not a letter,
//! such as an option name, gets `\%`, so groff does not hyphenate it. A
//! paragraph with an indented line is kept without fill.

use std::collections::HashSet;
use std::path::Path;

use clap::{Arg, ArgAction, Command, CommandFactory};

use super::Cli;

/// The name of the top-level command and of the manual in each title line.
const NAME: &str = "ostrya";

/// The environment variable that lets the test write the pages again.
const BLESS: &str = "OSTRYA_BLESS_MAN";

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
    pages
}

/// Returns the hand-written sections for the page `file`, or an empty string.
fn read_extra(extra: &Path, file: &str) -> String {
    std::fs::read_to_string(extra.join(format!("{file}.roff"))).unwrap_or_default()
}

/// Renders `ostrya.1`.
fn render_top_page(top: &Command, extra: &str) -> String {
    let mut out = String::new();
    push_title(&mut out, NAME);
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
    push_title(&mut out, &name);
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

/// Writes the title line of the page `name`.
///
/// The line has no date and no version, so a page changes only when its
/// text changes.
fn push_title(out: &mut String, name: &str) {
    out.push_str(&format!(
        ".TH \"{}\" \"1\" \"\" \"{NAME}\" \"User Commands\"\n",
        escape_quoted(&name.to_uppercase())
    ));
}

/// Writes the NAME section: the page name and the one-line summary.
fn push_name(out: &mut String, name: &str, summary: &str) {
    out.push_str(".SH NAME\n");
    out.push_str(&format!("{} \\- {}\n", escape(name), inline(summary)));
}

/// Writes the SYNOPSIS section from the usage text of `clap`.
fn push_synopsis(out: &mut String, cmd: &Command) {
    out.push_str(".SH SYNOPSIS\n.nf\n");
    out.push_str(&escape(&usage(cmd)));
    out.push_str("\n.fi\n");
}

/// Writes the hand-written sections.
fn push_extra(out: &mut String, extra: &str) {
    if !extra.is_empty() {
        out.push_str(extra);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
}

/// Writes one tagged paragraph: `tag` is roff text, and `text` is help text.
fn push_item(out: &mut String, tag: &str, text: &str) {
    out.push_str(".TP\n");
    out.push_str(tag);
    out.push('\n');
    push_text(out, text, ".IP");
}

/// Writes help text. Paragraphs after the first start with `break_macro`.
///
/// A paragraph with a line that starts with whitespace is kept without fill.
fn push_text(out: &mut String, text: &str, break_macro: &str) {
    for (index, paragraph) in text.trim().split("\n\n").enumerate() {
        if index > 0 {
            out.push_str(break_macro);
            out.push('\n');
        }
        let verbatim = paragraph.lines().any(|line| line.starts_with([' ', '\t']));
        if verbatim {
            out.push_str(".nf\n");
        }
        for line in paragraph.trim_end().lines() {
            let line = if verbatim { line } else { line.trim() };
            out.push_str(&inline(line));
            out.push('\n');
        }
        if verbatim {
            out.push_str(".fi\n");
        }
    }
}

/// Returns the usage text of `cmd` without the `Usage: ` prefix.
///
/// A usage text with more than one form has one line for each form.
fn usage(cmd: &Command) -> String {
    let rendered = cmd.clone().render_usage().to_string();
    rendered
        .lines()
        .map(|line| line.trim_start_matches("Usage:").trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns the subcommands of `cmd` that a page lists.
///
/// The `help` subcommand that `clap` adds is not listed.
fn visible_subcommands(cmd: &Command) -> Vec<&Command> {
    cmd.get_subcommands()
        .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
        .collect()
}

/// Returns the positional arguments of `cmd` that a page lists.
fn positional_args(cmd: &Command) -> Vec<&Arg> {
    cmd.get_arguments()
        .filter(|arg| arg.is_positional() && !arg.is_hide_set())
        .collect()
}

/// Returns the options of `cmd` that a page lists.
///
/// A global option is listed in `ostrya.1` alone. `--help` is not listed.
fn local_options<'a>(cmd: &'a Command, globals: &HashSet<String>) -> Vec<&'a Arg> {
    cmd.get_arguments()
        .filter(|arg| {
            !arg.is_positional()
                && !arg.is_hide_set()
                && !globals.contains(arg.get_id().as_str())
                && arg.get_id() != "help"
        })
        .collect()
}

/// Returns the one-line summary of `cmd`.
fn about(cmd: &Command) -> String {
    cmd.get_about().map(ToString::to_string).unwrap_or_default()
}

/// Returns the full description of `cmd`, or the summary if it has none.
fn long_about(cmd: &Command) -> String {
    cmd.get_long_about()
        .map(ToString::to_string)
        .unwrap_or_else(|| about(cmd))
}

/// Returns the roff tag of an option: its names and its value.
///
/// A value that `--name=VALUE` alone can give, because the option also
/// works without a value, is shown as `[=VALUE]`.
fn option_label(arg: &Arg) -> String {
    let mut names = Vec::new();
    if let Some(short) = arg.get_short() {
        names.push(format!("\\fB\\-{}\\fR", escape(&short.to_string())));
    }
    if let Some(long) = arg.get_long() {
        names.push(format!("\\fB\\-\\-{}\\fR", escape(long)));
    }
    let mut label = names.join(", ");
    if takes_value(arg) {
        let value = format!("\\fI{}\\fR", escape(&value_name(arg)));
        let optional = arg
            .get_num_args()
            .is_some_and(|range| range.min_values() == 0);
        if optional {
            label.push_str(&format!("[={value}]"));
        } else {
            label.push(' ');
            label.push_str(&value);
        }
    }
    label
}

/// Returns the roff tag of a positional argument.
fn positional_label(arg: &Arg) -> String {
    let mut name = value_name(arg);
    if arg
        .get_num_args()
        .is_some_and(|range| range.max_values() > 1)
    {
        name.push_str("...");
    }
    format!("\\fI{}\\fR", escape(&name))
}

/// Returns the value name of `arg`, or its id in upper case.
fn value_name(arg: &Arg) -> String {
    match arg.get_value_names() {
        Some(names) => names
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        None => arg.get_id().as_str().to_uppercase(),
    }
}

/// Returns true if `arg` takes a value.
fn takes_value(arg: &Arg) -> bool {
    match arg.get_action() {
        ArgAction::Set | ArgAction::Append => true,
        ArgAction::SetTrue
        | ArgAction::SetFalse
        | ArgAction::Count
        | ArgAction::Help
        | ArgAction::HelpShort
        | ArgAction::HelpLong
        | ArgAction::Version => false,
        _ => arg.get_num_args().is_some_and(|range| range.takes_values()),
    }
}

/// Returns the help text of `arg`, with its default and its possible values.
fn arg_description(arg: &Arg) -> String {
    let mut text = arg
        .get_long_help()
        .or_else(|| arg.get_help())
        .map(ToString::to_string)
        .unwrap_or_default();
    text = with_full_stop(text);
    if takes_value(arg) {
        let defaults: Vec<String> = arg
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        if !defaults.is_empty() && !arg.is_hide_default_value_set() {
            add_sentence(&mut text, &format!("Default: {}.", defaults.join(", ")));
        }
        let possible: Vec<String> = arg
            .get_possible_values()
            .iter()
            .filter(|value| !value.is_hide_set())
            .map(|value| value.get_name().to_owned())
            .collect();
        if !possible.is_empty() && !arg.is_hide_possible_values_set() {
            add_sentence(
                &mut text,
                &format!("Possible values: {}.", possible.join(", ")),
            );
        }
    }
    text
}

/// Adds `sentence` to the last paragraph of `text`.
fn add_sentence(text: &mut String, sentence: &str) {
    if !text.is_empty() {
        text.push(' ');
    }
    text.push_str(sentence);
}

/// Returns `text` with a full stop at its end.
///
/// `clap` removes the full stop at the end of a one-paragraph help text, so
/// a page adds it back.
fn with_full_stop(text: String) -> String {
    let mut text = text.trim_end().to_owned();
    if !text.is_empty() && !text.ends_with(['.', '!', '?', ':']) {
        text.push('.');
    }
    text
}

/// Escapes one line of help text and turns each pair of backticks into bold.
///
/// A backtick with no pair stays a grave accent. A code span, and a word with
/// a character that is not a letter, such as an option name or `KEY=VALUE`,
/// get `\%`, so groff does not hyphenate them.
fn inline(line: &str) -> String {
    let parts: Vec<&str> = line.split('`').collect();
    if parts.len().is_multiple_of(2) {
        let parts: Vec<String> = parts.iter().map(|part| unbreakable_words(part)).collect();
        return parts.join("\\(ga");
    }
    let mut out = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index % 2 == 1 {
            out.push_str(&format!("\\fB\\%{}\\fR", escape(part)));
        } else {
            out.push_str(&unbreakable_words(part));
        }
    }
    out
}

/// Escapes `text` and puts `\%` before each word that has a character that
/// is not a letter.
///
/// A `(` before the word and punctuation after it do not count.
fn unbreakable_words(text: &str) -> String {
    // NUL is not in help text. It marks the place of each `\%` until the
    // text is escaped, so that `escape` sees the words as they are.
    const MARK: char = '\0';
    let mut marked = String::with_capacity(text.len());
    for (index, word) in text.split(' ').enumerate() {
        if index > 0 {
            marked.push(' ');
        }
        let core = word
            .trim_start_matches('(')
            .trim_end_matches(['.', ',', ';', ':', ')']);
        if core.chars().any(|ch| !ch.is_alphabetic()) {
            let start = word.len() - word.trim_start_matches('(').len();
            marked.push_str(&word[..start]);
            marked.push(MARK);
            marked.push_str(&word[start..]);
        } else {
            marked.push_str(word);
        }
    }
    escape(&marked).replace(MARK, "\\%")
}

/// Escapes text for roff: a backslash and a hyphen-minus.
///
/// A line that starts with a control character gets `\&` before it.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
        }
        if line.starts_with(['.', '\'']) {
            out.push_str("\\&");
        }
        for ch in line.chars() {
            match ch {
                '\\' => out.push_str("\\e"),
                '-' => out.push_str("\\-"),
                _ => out.push(ch),
            }
        }
    }
    out
}

/// Escapes text for a quoted argument of a macro.
fn escape_quoted(text: &str) -> String {
    escape(text).replace('"', "\\(dq")
}

/// The committed pages are the pages that the `clap` definition renders.
///
/// The pages describe the default feature set, which the shipped binary
/// has, so the test runs only when each subcommand feature is on. If a page
/// differs, is missing, or has no subcommand, the test fails. Only then does
/// it read `OSTRYA_BLESS_MAN`. If the variable is set, the test writes the
/// pages again and removes each page that has no subcommand.
#[cfg(all(
    feature = "receive",
    feature = "push",
    feature = "serve",
    feature = "send"
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
                .filter(|name| name.ends_with(".1") && !names.contains(name.as_str()))
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
