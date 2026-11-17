//! The reader of the trust groups and the key groups, and the build of the
//! receive policy of each client group.
//!
//! The reader makes two passes. The first pass checks each trust group and
//! each key group, and refuses each key and each value outside the syntax.
//! This pass reads no file and runs no program.
//!
//! The second pass builds each key group and each trust group once, in file
//! order. It also builds a group that no client group names. The policies get
//! shared handles to these objects.

use std::collections::HashMap;
use std::sync::Arc;

use crate::access::{ClientAccess, Group, classify};
use crate::error::Result;
use crate::repo::Repo;
use crate::sign::SigningKey;
use crate::sign::key_group::{KeySpec, build_signers, parse_key};
use crate::verify::trust::check_trust;

use super::{ReceivePolicy, ReceiveVerify, TrustedKeys};

/// Reads the client groups of the config of `repo`, and returns them with the
/// receive policy of each group, in the order of the groups.
pub(crate) async fn read(repo: &Repo) -> Result<(ClientAccess, Vec<Arc<ReceivePolicy>>)> {
    let config = repo.config();
    let access = ClientAccess::from_config(config)?;
    let keyfile = config.keyfile();

    // The first pass checks each key group, then each trust group. The
    // access reader refused each other group name with the extension prefix.
    let mut builds: Vec<(Group<'_>, &str)> = Vec::new();
    for group in keyfile.groups() {
        if let Some(found @ (Group::Trust(_) | Group::Key(_))) = classify(group)? {
            builds.push((found, group));
        }
    }
    let mut keys: HashMap<&str, KeySpec> = HashMap::new();
    for (build, group) in &builds {
        if let Group::Key(name) = build {
            keys.insert(name, parse_key(keyfile, group)?);
        }
    }
    for (build, group) in &builds {
        if let Group::Trust(_) = build {
            check_trust(keyfile, group)?;
        }
    }

    // The second pass builds each key group and each trust group once, in
    // file order.
    let mut signers: HashMap<&str, Vec<Arc<SigningKey>>> = HashMap::new();
    let mut trusts: HashMap<&str, Arc<TrustedKeys>> = HashMap::new();
    for (build, _) in builds {
        match build {
            Group::Key(name) => {
                let built = build_signers(repo, name, &keys[name]).await?;
                signers.insert(name, built.into_iter().map(Arc::new).collect());
            }
            Group::Trust(name) => {
                let built = TrustedKeys::from_trust_group(repo, name).await?;
                trusts.insert(name, Arc::new(built));
            }
            _ => {}
        }
    }

    let named = |names: &[String]| -> Vec<Arc<SigningKey>> {
        names
            .iter()
            .flat_map(|name| signers[name.as_str()].iter().map(Arc::clone))
            .collect()
    };
    let summary_signers = named(access.server().sign_summary.as_deref().unwrap_or_default());
    let update_summary = config.auto_update_summary()?;
    let policies = access
        .groups()
        .iter()
        .map(|group| {
            Arc::new(ReceivePolicy {
                rules: group.rules().clone(),
                verify: match group.verify_trust() {
                    Some(name) => ReceiveVerify::Keys(Arc::clone(&trusts[name])),
                    None => ReceiveVerify::Off,
                },
                allow_unsigned: group.allow_unsigned(),
                signers: named(group.sign()),
                allow_privileged: group.allow_privileged(),
                disable_verify_bindings: group.disable_verify_bindings(),
                summary_signers: summary_signers.clone(),
                update_summary,
                group: Some(group.name().to_owned()),
            })
        })
        .collect();
    Ok((access, policies))
}
