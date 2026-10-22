//! The client side of a push from a repository.
//!
//! The `push` feature gates this module. [`is_push_address`] tells an address
//! from the name of a remote section.
//! [`resolve_push`](crate::endpoint::resolve_push) returns the endpoint of a
//! configured remote or of an address.
//! [`Repo::push`](crate::Repo::push) and
//! [`Repo::push_over_stream`](crate::Repo::push_over_stream) push the commits
//! of a set of refspecs with the options of [`RepoPushOptions`].
//! [`Repo::push_onto`](crate::Repo::push_onto) and
//! [`Repo::push_onto_over_stream`](crate::Repo::push_onto_over_stream) push
//! the tree of a local commit, and the server commits it onto a branch with
//! the options of [`PushOntoOptions`].
//! [`Repo::export_stream`](crate::Repo::export_stream) writes the commits of a
//! set of ref updates as one one-way stream, with the options of
//! [`ExportStreamOptions`]. The private submodules read the refspecs of a push
//! against the local repository. They also give the objects of its commits to
//! a push session.

mod export;
mod negotiate;
mod onto;
mod refspec;
#[cfg(feature = "s3")]
mod s3;
mod source;
#[cfg(test)]
mod test_repo;

pub use self::export::ExportStreamOptions;
pub use self::negotiate::RepoPushOptions;
pub use self::onto::PushOntoOptions;

use crate::error::Error;

/// Returns `true` if `remote` is a push address: a value with a `:` or a `/`.
///
/// A value with no `:` and no `/` is the name of a remote section.
/// [`resolve_push`](crate::endpoint::resolve_push) reads no configuration for
/// an address, so a caller does not need to open the local repository.
pub fn is_push_address(remote: &str) -> bool {
    remote.contains([':', '/'])
}

/// Returns the error of a push request that the client refuses.
pub(crate) fn invalid(msg: impl Into<String>) -> Error {
    Error::Remote(crate::remote::Error::InvalidInput(msg.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_holds_a_colon_or_a_slash() {
        for address in [
            "host:srv/repo",
            "host:",
            ":repo",
            "srv/repo",
            "/srv/repo",
            "ssh://host/srv/repo",
            "https://ex.com/r",
        ] {
            assert!(is_push_address(address), "{address}");
        }
        for name in ["origin", "my-remote", "a.b", "", "with space"] {
            assert!(!is_push_address(name), "{name:?}");
        }
    }
}
