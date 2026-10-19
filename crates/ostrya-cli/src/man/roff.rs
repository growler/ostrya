//! The generic part of the man page renderer: roff text from a `clap`
//! command.
//!
//! The man pages of `ostrya` and of `ostrya-mountd` share this file. The
//! renderer of each binary chooses the pages and their sections.

use std::collections::HashSet;

use clap::{Arg, ArgAction, Command};

/// The source of each page, which the title line shows.
const SOURCE: &str = "ostrya";

/// Writes the title line of the page `name` in the manual section `section`.
///
/// `manual` is the title of the manual. The line has no date and no version,
/// so a page changes only when its text changes.
pub(crate) fn push_title(out: &mut String, name: &str, section: &str, manual: &str) {
    out.push_str(&format!(
        ".TH \"{}\" \"{section}\" \"\" \"{SOURCE}\" \"{manual}\"\n",
        escape_quoted(&name.to_uppercase())
    ));
}

/// Writes the NAME section: the page name and the one-line summary.
pub(crate) fn push_name(out: &mut String, name: &str, summary: &str) {
    out.push_str(".SH NAME\n");
    out.push_str(&format!("{} \\- {}\n", escape(name), inline(summary)));
}

/// Writes the SYNOPSIS section from the usage text of `clap`.
pub(crate) fn push_synopsis(out: &mut String, cmd: &Command) {
    out.push_str(".SH SYNOPSIS\n.nf\n");
    out.push_str(&escape(&usage(cmd)));
    out.push_str("\n.fi\n");
}

/// Writes the hand-written sections.
pub(crate) fn push_extra(out: &mut String, extra: &str) {
    if !extra.is_empty() {
        out.push_str(extra);
        if !out.ends_with('\n') {
            out.push('\n');
        }
    }
}

/// Writes one tagged paragraph: `tag` is roff text, and `text` is help text.
pub(crate) fn push_item(out: &mut String, tag: &str, text: &str) {
    out.push_str(".TP\n");
    out.push_str(tag);
    out.push('\n');
    push_text(out, text, ".IP");
}

/// Writes help text. Paragraphs after the first start with `break_macro`.
///
/// A paragraph with a line that starts with whitespace is kept without fill.
pub(crate) fn push_text(out: &mut String, text: &str, break_macro: &str) {
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
pub(crate) fn usage(cmd: &Command) -> String {
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
pub(crate) fn visible_subcommands(cmd: &Command) -> Vec<&Command> {
    cmd.get_subcommands()
        .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
        .collect()
}

/// Returns the positional arguments of `cmd` that a page lists.
pub(crate) fn positional_args(cmd: &Command) -> Vec<&Arg> {
    cmd.get_arguments()
        .filter(|arg| arg.is_positional() && !arg.is_hide_set())
        .collect()
}

/// Returns the options of `cmd` that a page lists.
///
/// A global option is listed in `ostrya.1` alone. `--help` is not listed.
pub(crate) fn local_options<'a>(cmd: &'a Command, globals: &HashSet<String>) -> Vec<&'a Arg> {
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
pub(crate) fn about(cmd: &Command) -> String {
    cmd.get_about().map(ToString::to_string).unwrap_or_default()
}

/// Returns the full description of `cmd`, or the summary if it has none.
pub(crate) fn long_about(cmd: &Command) -> String {
    cmd.get_long_about()
        .map(ToString::to_string)
        .unwrap_or_else(|| about(cmd))
}

/// Returns the roff tag of an option: its names and its value.
///
/// A value that `--name=VALUE` alone can give, because the option also
/// works without a value, is shown as `[=VALUE]`.
pub(crate) fn option_label(arg: &Arg) -> String {
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
pub(crate) fn positional_label(arg: &Arg) -> String {
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
pub(crate) fn value_name(arg: &Arg) -> String {
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
pub(crate) fn takes_value(arg: &Arg) -> bool {
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
pub(crate) fn arg_description(arg: &Arg) -> String {
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
pub(crate) fn add_sentence(text: &mut String, sentence: &str) {
    if !text.is_empty() {
        text.push(' ');
    }
    text.push_str(sentence);
}

/// Returns `text` with a full stop at its end.
///
/// `clap` removes the full stop at the end of a one-paragraph help text, so
/// a page adds it back.
pub(crate) fn with_full_stop(text: String) -> String {
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
pub(crate) fn inline(line: &str) -> String {
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
pub(crate) fn unbreakable_words(text: &str) -> String {
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
pub(crate) fn escape(text: &str) -> String {
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
pub(crate) fn escape_quoted(text: &str) -> String {
    escape(text).replace('"', "\\(dq")
}
