//! The man page of the `ostrya-mountd` command, `ostrya-mountd.8`.
//!
//! The page is generated from the `clap` definition of [`Cli`] with the
//! renderer of the `ostrya` man pages, and kept in
//! `crates/ostrya-mountd/man`. The file `man/extra/ostrya-mountd.8.roff`
//! is added to the end of the page. It holds the sections that `clap` does
//! not describe. The test in this module renders the page and compares it
//! with its file. Run the test with `OSTRYA_BLESS_MAN=1` to write the file
//! again:
//!
//! ```text
//! OSTRYA_BLESS_MAN=1 cargo test -p ostrya-mountd man_page
//! ```

use std::collections::HashSet;
use std::path::Path;

use clap::CommandFactory;

use super::Cli;

#[path = "../../ostrya-cli/src/man/roff.rs"]
#[allow(dead_code)]
mod roff;

use roff::{
    arg_description, local_options, long_about, option_label, push_extra, push_item, push_name,
    push_synopsis, push_text, push_title, with_full_stop,
};

/// The name of the page.
const NAME: &str = "ostrya-mountd";

/// The section of the page.
const SECTION: &str = "8";

/// The environment variable that lets the test write the page again.
const BLESS: &str = "OSTRYA_BLESS_MAN";

/// Renders the page with the hand-written sections `extra`.
fn render_page(extra: &str) -> String {
    let mut cmd = Cli::command();
    cmd.build();
    let mut out = String::new();
    push_title(&mut out, NAME, SECTION, "System Administration Commands");
    push_name(
        &mut out,
        NAME,
        &cmd.get_about().map(ToString::to_string).unwrap_or_default(),
    );
    push_synopsis(&mut out, &cmd);
    out.push_str(".SH DESCRIPTION\n");
    push_text(&mut out, &with_full_stop(long_about(&cmd)), ".PP");
    out.push_str(".SH OPTIONS\n");
    for arg in local_options(&cmd, &HashSet::new()) {
        push_item(&mut out, &option_label(arg), &arg_description(arg));
    }
    push_extra(&mut out, extra);
    out
}

/// The committed page is the page that the `clap` definition renders. If
/// it differs, the test fails. Only then does it read `OSTRYA_BLESS_MAN`.
/// If the variable is set, the test writes the page again.
#[test]
fn man_page_matches_the_committed_file() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("man");
    let file = format!("{NAME}.{SECTION}");
    let extra = std::fs::read_to_string(dir.join("extra").join(format!("{file}.roff")))
        .expect("read the hand-written sections");
    let text = render_page(&extra);
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
