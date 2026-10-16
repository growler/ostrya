//! The events that a server reports to its host.

use std::fmt;
use std::sync::Arc;

use ostrya::Checksum;

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
    /// The selected client group of the request has `tls-accept-claim=true`.
    /// The request got 403.
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
    }
}
