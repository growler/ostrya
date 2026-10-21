//! The key pair that signs an S3 request.

use crate::{Error, Result};

/// An AWS access key pair, with an optional session token.
///
/// [`SigV4`](super::SigV4) signs each request with it.
/// [`resolve`](super::resolve) gives one from the environment or from the
/// shared AWS files, and a caller can make one with
/// [`Credentials::new`].
///
/// The [`Debug`] output shows the access key id alone. It shows the secret
/// access key and the session token as `<redacted>`. No method gives the
/// secret access key or the session token back.
#[derive(Clone)]
pub struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl Credentials {
    /// Returns the key pair of `access_key_id` and `secret_access_key`, with
    /// the session token `session_token`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] if a value cannot go into a signature. The
    /// message holds no part of the secret access key or of the session
    /// token. These values are refused:
    ///
    /// - an empty access key id, or an access key id with a character that is
    ///   not printable ASCII, a space, `/`, or `,`
    /// - an empty secret access key, or a secret access key with a control
    ///   character
    /// - an empty session token, or a session token with a character that is
    ///   not printable ASCII, or a space
    ///
    /// # Examples
    ///
    /// ```
    /// use ostrya_remote::s3::Credentials;
    /// # fn run() -> ostrya_remote::Result<()> {
    /// let credentials = Credentials::new(
    ///     "AKIAIOSFODNN7EXAMPLE".into(),
    ///     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
    ///     None,
    /// )?;
    /// assert_eq!(credentials.access_key_id(), "AKIAIOSFODNN7EXAMPLE");
    /// assert!(!format!("{credentials:?}").contains("EXAMPLEKEY"));
    /// # Ok(()) }
    /// # run().unwrap();
    /// ```
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    ) -> Result<Credentials> {
        Credentials::checked(access_key_id, secret_access_key, session_token)
            .map_err(|why| Error::InvalidInput(why.into()))
    }

    /// Returns the key pair as [`Credentials::new`] does, or the reason of its
    /// refusal. The reason holds no value.
    pub(super) fn checked(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    ) -> std::result::Result<Credentials, &'static str> {
        if access_key_id.is_empty() {
            return Err("the access key id is empty");
        }
        if !access_key_id
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'/' && b != b',')
        {
            return Err(
                "the access key id holds a character that is not printable ASCII, a space, '/', or ','",
            );
        }
        if secret_access_key.is_empty() {
            return Err("the secret access key is empty");
        }
        if secret_access_key.chars().any(char::is_control) {
            return Err("the secret access key holds a control character");
        }
        if let Some(token) = &session_token {
            if token.is_empty() {
                return Err("the session token is empty");
            }
            if !token.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(
                    "the session token holds a character that is not printable ASCII, or a space",
                );
            }
        }
        Ok(Credentials {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }

    /// Returns the access key id.
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// Returns `true` if the key pair has a session token.
    pub fn has_session_token(&self) -> bool {
        self.session_token.is_some()
    }

    /// Returns the secret access key, for the signing key.
    pub(super) fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    /// Returns the session token, for the `x-amz-security-token` header.
    pub(super) fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(id: &str, secret: &str, token: Option<&str>) -> String {
        match Credentials::new(id.into(), secret.into(), token.map(Into::into)) {
            Err(Error::InvalidInput(msg)) => msg,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_valid_pair_is_accepted() {
        let credentials = Credentials::new(
            "AKIAIOSFODNN7EXAMPLE".into(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            Some("FwoGZXIvYXdz+/=".into()),
        )
        .unwrap();
        assert_eq!(credentials.access_key_id(), "AKIAIOSFODNN7EXAMPLE");
        assert!(credentials.has_session_token());
        assert_eq!(credentials.session_token(), Some("FwoGZXIvYXdz+/="));
    }

    #[test]
    fn each_invalid_value_is_refused_without_the_secret() {
        // Each secret holds `QQ` and each token holds `ZZ`, which no message
        // may hold.
        let cases: &[(&str, &str, Option<&str>, &str)] = &[
            ("", "QQ", None, "access key id is empty"),
            ("AKIA EXAMPLE", "QQ", None, "access key id holds"),
            ("AKIA/EXAMPLE", "QQ", None, "access key id holds"),
            ("AKIA,EXAMPLE", "QQ", None, "access key id holds"),
            ("AKIAÉXAMPLE", "QQ", None, "access key id holds"),
            ("AKIA", "", None, "secret access key is empty"),
            ("AKIA", "Q\nQ", None, "secret access key holds"),
            ("AKIA", "QQ", Some(""), "session token is empty"),
            ("AKIA", "QQ", Some("ZZ ZZ"), "session token holds"),
            ("AKIA", "QQ", Some("ZZ\u{7f}"), "session token holds"),
        ];
        for (id, secret, token, want) in cases {
            let msg = refused(id, secret, *token);
            assert!(msg.contains(want), "{id:?}: {msg}");
            assert!(!msg.contains('Q'), "{msg}");
            assert!(!msg.contains('Z'), "{msg}");
        }
    }

    #[test]
    fn a_secret_with_unicode_and_spaces_is_accepted() {
        Credentials::new("AKIA".into(), "s é cret".into(), None).unwrap();
    }

    #[test]
    fn debug_hides_the_secret_and_the_token() {
        let credentials = Credentials::new(
            "AKIAIOSFODNN7EXAMPLE".into(),
            "wJalrXUtnFEMI".into(),
            Some("FwoGZXIvYXdz".into()),
        )
        .unwrap();
        let debug = format!("{credentials:?}");
        assert!(debug.contains("AKIAIOSFODNN7EXAMPLE"), "{debug}");
        assert!(!debug.contains("wJalrXUtnFEMI"), "{debug}");
        assert!(!debug.contains("FwoGZXIvYXdz"), "{debug}");
        assert!(debug.contains("Some(\"<redacted>\")"), "{debug}");
        let none = Credentials::new("AKIA".into(), "x".into(), None).unwrap();
        assert!(format!("{none:?}").contains("session_token: None"));
    }
}
