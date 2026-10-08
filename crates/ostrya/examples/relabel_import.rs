//! Imports `./rootfs` into the new repository `./repo`, and gives each path
//! an SELinux label from a compiled-in policy table.

use std::os::fd::AsFd;
use std::path::Path;

use ostrya::{
    CommitModifier, CommitModifierFlags, CreateOptions, MutableTree, Repo, RepoMode, Result,
};

/// The SELinux label of each path prefix.
///
/// The first match applies. A prefix matches whole path components only.
static LABELS: &[(&str, &str)] = &[
    ("/etc/shadow", "system_u:object_r:shadow_t:s0"),
    ("/etc", "system_u:object_r:etc_t:s0"),
    ("/usr/bin", "system_u:object_r:bin_t:s0"),
    ("/usr/lib", "system_u:object_r:lib_t:s0"),
    ("/var", "system_u:object_r:var_t:s0"),
    ("/", "system_u:object_r:usr_t:s0"), // catch-all: keeps ERROR_ON_UNLABELED quiet
];

/// Returns the label of a walk path, such as `/`, `/etc`, or `/etc/passwd`.
///
/// The label has a NUL terminator, because the stored xattr value has one.
fn label_for(path: &Path) -> Option<Vec<u8>> {
    let path = path.to_str()?;
    LABELS.iter().find_map(|(prefix, label)| {
        let hit = path == *prefix
            || *prefix == "/"
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'));
        hit.then(|| {
            let mut value = label.as_bytes().to_vec();
            value.push(0);
            value
        })
    })
}

fn main() -> Result<()> {
    ostrya_rt::block_on(async {
        let repo = Repo::create(Path::new("repo"), CreateOptions::new(RepoMode::BareUser)).await?;
        let txn = repo.transaction().await?;

        // If `LABELS` has no label for a path, the import fails with an error.
        let mut modifier = CommitModifier::new(
            CommitModifierFlags::SELINUX_LABEL_V1 | CommitModifierFlags::ERROR_ON_UNLABELED,
        );
        modifier.label_callback = Some(Box::new(|path, _meta| label_for(path)));

        let cwd = std::fs::File::open(".")?;
        let mut mtree = MutableTree::new();
        txn.write_dfd_to_mtree(
            cwd.as_fd(),
            Path::new("rootfs"),
            &mut mtree,
            Some(&mut modifier),
        )
        .await?;

        let root = txn.write_mtree(&mut mtree).await?;
        let stats = txn.commit().await?;

        println!(
            "imported {} content + {} metadata objects, root dirtree {}",
            stats.content_written,
            stats.metadata_written,
            root.dirtree_checksum(),
        );
        Ok(())
    })
}
