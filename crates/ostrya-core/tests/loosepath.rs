#![forbid(unsafe_code)]

//! Phase 2 verification gate (see docs/port-plan.md): golden loose paths.
//!
//! For every loose object the `ostree` tool wrote into
//! tests/fixtures/generated/, reconstruct the loose path from the checksum
//! parsed out of the filename plus the object type and repository mode, and
//! require it to equal the path the tool actually used. This exercises the
//! fanout split and the mode-aware extension selection (the `z` suffix on
//! archive content objects) against real tool output.

use ostrya_core::{Checksum, ObjectType, RepoMode, loose_path};

#[path = "../../../tests/support.rs"]
mod support;

#[test]
fn reconstructs_every_fixture_loose_path() {
    let mut checked = 0usize;

    for object in support::loose_objects() {
        let Some(mode) = RepoMode::from_mode_str(&object.mode) else {
            continue;
        };
        let ty = ObjectType::from_extension(&object.ext)
            .unwrap_or_else(|| panic!("unknown extension .{}", object.ext));

        let checksum = Checksum::from_hex(&object.hex()).unwrap();
        let expected = format!("{}/{}.{}", object.prefix, object.stem, object.ext);
        assert_eq!(loose_path(&checksum, ty, mode), expected);
        checked += 1;
    }

    // The fixtures contain several objects across two modes; guard against a
    // silently empty walk masking a regression.
    assert!(
        checked >= 8,
        "expected multiple fixture objects, saw {checked}"
    );
}

/// The `z` suffix appears only on a `File` object in archive mode. The
/// auxiliary non-meta types (payload-link, file-xattrs, file-xattrs-link) are
/// stored uncompressed, so their loose-path extension is fixed and
/// mode-independent and never gains a trailing `z`.
///
/// This pins review finding 2 (decision D1), resolved against black-box
/// observation: an archive repo populated by commit or `pull-local` holds only
/// `.filez` content objects, and the tool refuses every write to
/// `bare-split-xattrs`, so it never materializes those auxiliary types in
/// archive mode.
#[test]
fn z_suffix_is_file_and_archive_only() {
    let c = Checksum::from_hex("b3c8e8525e8a5c3409bf6e6db5f5d656da77ae76d08cbc4f8b75b71879757a89")
        .unwrap();

    let modes = [
        RepoMode::Bare,
        RepoMode::BareUser,
        RepoMode::BareUserOnly,
        RepoMode::BareSplitXattrs,
        RepoMode::Archive,
        RepoMode::BareUserShared,
    ];

    // Auxiliary non-meta types keep a fixed extension in every mode.
    let aux = [
        (ObjectType::PayloadLink, "payload-link"),
        (ObjectType::FileXattrs, "file-xattrs"),
        (ObjectType::FileXattrsLink, "file-xattrs-link"),
    ];
    for (ty, ext) in aux {
        for mode in modes {
            assert_eq!(ty.extension(mode), ext, "{ty:?} in {mode:?}");
            assert!(
                loose_path(&c, ty, mode).ends_with(&format!(".{ext}")),
                "{ty:?} loose path in {mode:?} must end .{ext}"
            );
        }
    }

    // `File` is the only type that gains the `z` suffix, and only in archive.
    for mode in modes {
        let ends_z = ObjectType::File.extension(mode).ends_with('z');
        assert_eq!(
            ends_z,
            mode == RepoMode::Archive,
            "File z suffix must be archive-only, checked {mode:?}"
        );
    }
    assert_eq!(ObjectType::File.extension(RepoMode::Archive), "filez");
}
