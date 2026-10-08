#![forbid(unsafe_code)]

//! Golden loose paths.
//!
//! One test reads each loose object that the `ostree` command wrote into
//! `tests/fixtures/generated/`. It builds the loose path from the checksum
//! in the file name, the object type, and the repository mode. The path must
//! equal the path that the `ostree` command used. The tests cover the fan-out
//! split and the extension for each mode, with the `z` suffix on archive
//! content objects.

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

    // The fixtures hold several objects in two modes. If the walk finds fewer
    // than 8 objects, the test fails, so an empty walk cannot hide a
    // regression.
    assert!(
        checked >= 8,
        "expected multiple fixture objects, saw {checked}"
    );
}

/// The `z` suffix appears only on a `File` object in archive mode.
///
/// ostrya stores the auxiliary non-meta types (payload-link, file-xattrs,
/// file-xattrs-link) uncompressed. Their loose-path extension is the same in
/// every mode and never ends in `z`.
///
/// Black-box observation supports this rule. A commit or a `pull-local` into
/// an archive repository writes only `.filez` content objects. The `ostree`
/// command refuses every write to `bare-split-xattrs`, so it never writes the
/// auxiliary types in archive mode.
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

    // The auxiliary non-meta types have the same extension in every mode.
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

    // Only the `File` type gets the `z` suffix, and only in archive mode.
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
