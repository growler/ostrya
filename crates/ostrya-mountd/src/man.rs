//! The man pages of the commands of the crate: `ostrya-mountd.8` and
//! `mount.ostrya.8`.
//!
//! Each page is generated from the `clap` definition of its command with the
//! renderer of the `ostrya` man pages, and kept in `crates/ostrya-mountd/man`.
//! The file `man/extra/<name>.<section>.roff` is added to the end of the
//! page. It holds the sections that `clap` does not describe. Each command
//! has a test that renders its page and compares it with its file. Run the
//! tests with `OSTRYA_BLESS_MAN=1` to write the files again:
//!
//! ```text
//! OSTRYA_BLESS_MAN=1 cargo test -p ostrya-mountd man_page
//! ```

use std::collections::HashSet;
use std::path::Path;

use clap::Command;

#[path = "../../ostrya-cli/src/man/roff.rs"]
#[allow(dead_code)]
mod roff;

use roff::{
    arg_description, local_options, long_about, option_label, positional_args, positional_label,
    push_extra, push_item, push_name, push_synopsis, push_text, push_title, with_full_stop,
};

/// The environment variable that lets the test write the page again.
const BLESS: &str = "OSTRYA_BLESS_MAN";

/// Renders the page `name` in the section `section` of the command `cmd`,
/// with the hand-written sections `extra`.
fn render_page(mut cmd: Command, name: &str, section: &str, extra: &str) -> String {
    cmd.build();
    let mut out = String::new();
    push_title(&mut out, name, section, "System Administration Commands");
    push_name(
        &mut out,
        name,
        &cmd.get_about().map(ToString::to_string).unwrap_or_default(),
    );
    push_synopsis(&mut out, &cmd);
    out.push_str(".SH DESCRIPTION\n");
    push_text(&mut out, &with_full_stop(long_about(&cmd)), ".PP");
    let positionals = positional_args(&cmd);
    if !positionals.is_empty() {
        out.push_str(".SH ARGUMENTS\n");
        for arg in positionals {
            push_item(&mut out, &positional_label(arg), &arg_description(arg));
        }
    }
    out.push_str(".SH OPTIONS\n");
    for arg in local_options(&cmd, &HashSet::new()) {
        push_item(&mut out, &option_label(arg), &arg_description(arg));
    }
    push_extra(&mut out, extra);
    out
}

/// Asserts that the committed page `name` in the section `section` is the
/// page that the `clap` definition `cmd` renders. If it differs, the call
/// fails. Only then does it read `OSTRYA_BLESS_MAN`. If the variable is set,
/// the call writes the page again.
pub(crate) fn assert_page_matches(cmd: Command, name: &str, section: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("man");
    let file = format!("{name}.{section}");
    let extra = std::fs::read_to_string(dir.join("extra").join(format!("{file}.roff")))
        .expect("read the hand-written sections");
    let text = render_page(cmd, name, section, &extra);
    if std::fs::read_to_string(dir.join(&file)).ok().as_deref() == Some(text.as_str()) {
        return;
    }
    assert!(
        std::env::var_os(BLESS).is_some(),
        "{file} differs from the clap definition. Run \
         `{BLESS}=1 cargo test -p ostrya-mountd man_page` to write it again."
    );
    std::fs::write(dir.join(&file), text).expect("write the man page");
}
