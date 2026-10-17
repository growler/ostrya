//! The events that a server reports to its host.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use ostrya::Checksum;
use ostrya::access::AuthItem;

/// The callback that receives each [`ServerEvent`].
pub(crate) type EventSink = Arc<dyn Fn(&ServerEvent) + Send + Sync>;

/// An event of a server, which
/// [`ServeOptions::on_event`](crate::ServeOptions::on_event) receives.
///
/// [`Display`](fmt::Display) writes one line for the log of the host. It
/// writes each control character of a text from the client as an escape
/// sequence, for example `\n`, so the line holds no line break.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerEvent {
    /// The server refused a request because the claims of its client
    /// certificate do not parse.
    ///
    /// For a `session` request, the selected client group has
    /// `tls-accept-claim=true`. For a read, a group with
    /// `tls-accept-claim=true` carries the item of the certificate. The
    /// request got 403.
    #[non_exhaustive]
    BadClaims {
        /// The SHA-256 digest of the DER bytes of the certificate, as a
        /// `tls-sha256:HEX` item names it.
        digest: Checksum,
        /// The URI SAN that is no claim, or `None` when no one URI is at
        /// fault, for example when the certificate holds too many claims.
        san: Option<String>,
        /// Why the claims do not parse.
        reason: String,
    },
    /// A ref listing left out a directory under `refs/mirrors/` whose name
    /// fails the collection-id rule
    /// ([`ostrya::is_collection_id`]).
    ///
    /// The server reports each name one time for each [`Server`](crate::Server)
    /// value, at the first listing that finds it. Only a listing whose query
    /// holds a `collection` pair reads the directories under
    /// `refs/mirrors/`. The listing itself goes on. The server reports the
    /// event also with no receive policies.
    #[non_exhaustive]
    InvalidCollectionDir {
        /// The name of the directory.
        name: String,
    },
    /// The server answered `summary` or `summary.sig` with 404, because the
    /// `.access` file of the auth item of the client does not hold the
    /// access digest of the item
    /// ([`ArchiveAnswer::StaleSummary`](ostrya::ArchiveAnswer::StaleSummary)).
    ///
    /// The summary of the item does not match the client groups that the
    /// server read at start. `ostrya summary -u` writes the summaries again.
    /// The server reports each item one time for each
    /// [`Server`](crate::Server) value, at the first request that finds it.
    #[non_exhaustive]
    StaleSummary {
        /// The text of the auth item.
        item: String,
    },
}

impl ServerEvent {
    /// Returns `true` if the event is a warning: the server served the
    /// request. Each other event is an error of a request that the server
    /// refused.
    ///
    /// [`InvalidCollectionDir`](ServerEvent::InvalidCollectionDir) is a
    /// warning. [`BadClaims`](ServerEvent::BadClaims) and
    /// [`StaleSummary`](ServerEvent::StaleSummary) are errors.
    pub fn is_warning(&self) -> bool {
        match self {
            ServerEvent::BadClaims { .. } | ServerEvent::StaleSummary { .. } => false,
            ServerEvent::InvalidCollectionDir { .. } => true,
        }
    }
}

impl fmt::Display for ServerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerEvent::BadClaims {
                digest,
                san,
                reason,
            } => {
                write!(f, "refused the client certificate tls-sha256:{digest}: ")?;
                if let Some(san) = san {
                    write!(f, "malformed claim '{}': ", Escaped(san))?;
                }
                write!(f, "{}", Escaped(reason))
            }
            ServerEvent::InvalidCollectionDir { name } => write!(
                f,
                "refs/mirrors/{}: the directory name is not a collection id, and the ref \
                 listing leaves out the directory",
                Escaped(name)
            ),
            ServerEvent::StaleSummary { item } => write!(
                f,
                "the summary of the auth item {} does not match the client groups, and the \
                 server answers 404 for it; run `ostrya summary -u`",
                Escaped(item)
            ),
        }
    }
}

/// The stale summaries that one server reported.
pub(crate) struct StaleSummaries {
    /// The text of each item that the server reported.
    reported: Mutex<HashSet<String>>,
    /// The callback of the events of the server.
    on_event: Option<EventSink>,
}

impl StaleSummaries {
    /// Returns the record of a server that reported no stale summary, which
    /// reports its events to `on_event`.
    pub(crate) fn new(on_event: Option<EventSink>) -> StaleSummaries {
        StaleSummaries {
            reported: Mutex::new(HashSet::new()),
            on_event,
        }
    }

    /// Reports `item` as a [`ServerEvent::StaleSummary`] if the server did
    /// not report it before.
    pub(crate) fn report(&self, item: &AuthItem) {
        let Some(on_event) = &self.on_event else {
            return;
        };
        let item = item.to_string();
        let new = self
            .reported
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(item.clone());
        if new {
            on_event(&ServerEvent::StaleSummary { item });
        }
    }
}

/// A text with each ASCII control character as its escape sequence.
pub(crate) struct Escaped<'a>(pub(crate) &'a str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.chars() {
            if c.is_ascii_control() {
                write!(f, "{}", c.escape_default())?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line names the digest, the URI SAN, and the reason, and escapes
    /// each control character.
    #[test]
    fn the_line_names_the_digest_and_the_san() {
        let digest = Checksum::sha256(b"cert");
        let event = ServerEvent::BadClaims {
            digest,
            san: Some("ostrya:ref:x:a\nforged line\t\u{7f}".to_owned()),
            reason: "the modes are one or more of r, w, c, t, and d".to_owned(),
        };
        assert_eq!(
            event.to_string(),
            format!(
                "refused the client certificate tls-sha256:{}: malformed claim \
                 'ostrya:ref:x:a\\nforged line\\t\\u{{7f}}': the modes are one or more of r, w, \
                 c, t, and d",
                digest.to_hex()
            )
        );
        let event = ServerEvent::BadClaims {
            digest,
            san: None,
            reason: "the certificate holds more than 256 claims\r".to_owned(),
        };
        assert_eq!(
            event.to_string(),
            format!(
                "refused the client certificate tls-sha256:{}: the certificate holds more \
                 than 256 claims\\r",
                digest.to_hex()
            )
        );
        assert!(!event.is_warning());
    }

    /// The line of an invalid collection directory names its path and
    /// escapes each control character. The event is a warning.
    #[test]
    fn the_line_of_an_invalid_collection_dir_escapes_its_name() {
        let event = ServerEvent::InvalidCollectionDir {
            name: "bad\nforged line\t\u{7f}".to_owned(),
        };
        assert_eq!(
            event.to_string(),
            "refs/mirrors/bad\\nforged line\\t\\u{7f}: the directory name is not a \
             collection id, and the ref listing leaves out the directory"
        );
        assert!(event.is_warning());
    }

    /// The line of a stale summary names the item, escapes each control
    /// character, and names the command that writes the summaries. The event
    /// is an error.
    #[test]
    fn the_line_of_a_stale_summary_names_the_item() {
        let event = ServerEvent::StaleSummary {
            item: "tls:a\nb".to_owned(),
        };
        assert_eq!(
            event.to_string(),
            "the summary of the auth item tls:a\\nb does not match the client groups, and \
             the server answers 404 for it; run `ostrya summary -u`"
        );
        assert!(!event.is_warning());
    }

    /// The record reports each item one time.
    #[test]
    fn a_stale_summary_is_reported_one_time_for_each_item() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let stale = StaleSummaries::new(Some(Arc::new(move |event: &ServerEvent| {
            sink.lock().unwrap().push(event.to_string());
        })));
        let ssh = AuthItem::parse("ssh:u").unwrap();
        for item in [&AuthItem::Anonymous, &ssh, &AuthItem::Anonymous, &ssh] {
            stale.report(item);
        }
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[0].contains(" anonymous "), "{}", seen[0]);
        assert!(seen[1].contains(" ssh:u "), "{}", seen[1]);
    }
}
