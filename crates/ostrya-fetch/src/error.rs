//! The error type of the fetcher.

/// Result alias used throughout the fetcher.
pub type Result<T> = std::result::Result<T, Error>;

/// The error a fetch fails with.
///
/// The enum is `#[non_exhaustive]`, so a match outside the crate needs a
/// wildcard arm. Each variant stays constructible outside the crate. Each
/// variant converts to the `ostrya::Error` variant of the same name, with the
/// same message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A fetch could not be set up or carried out: an unusable mirror URL,
    /// header, or TLS configuration, or a transport failure that outlived its
    /// retries.
    #[error("fetch: {0}")]
    Fetch(String),
    /// Every mirror answered the request with an unsuccessful HTTP status. A
    /// 404 here means the object is absent from the remote, which pull treats
    /// as a normal answer for optional objects.
    ///
    /// One mirror's answer is reported: the first status received that is not
    /// retried, from whichever round it came, unless the rounds ran out with a
    /// retryable status outstanding, in which case the last mirror to give one.
    #[error("http status {status} for {url}")]
    HttpStatus {
        /// The status that mirror returned.
        status: u16,
        /// The URL requested of it.
        url: String,
    },
    /// A redirect chain reached the limit
    /// [`max_redirects`](crate::FetcherOptions::max_redirects) sets, and the
    /// response at the end of it named another URL to follow. One attempt
    /// against one destination counts its own hops, so a repeated round counts
    /// again from the destination the route named.
    #[error("redirect from {url} exceeds the {hops}-redirect limit")]
    RedirectLimit {
        /// The last hop the attempt reached, which is the URL whose `Location`
        /// the limit stopped it from following.
        url: String,
        /// How many redirects the attempt followed, which is the limit it was
        /// given.
        hops: u32,
    },
    /// A response declared more bytes than the caller's cap allows. A body that
    /// outgrows the cap while streaming fails the read with the
    /// [`FileTooLarge`](std::io::ErrorKind::FileTooLarge) kind, under a
    /// message payload that downcasts to no library error.
    #[error("fetched object exceeds the {limit}-byte cap")]
    FetchTooLarge {
        /// The cap the caller set on the request.
        limit: u64,
    },
    /// A response declared a coding, in `Content-Encoding` or in
    /// `Transfer-Encoding`, so its body holds bytes other than the ones the
    /// remote stores.
    #[error("response for {url} carries the coding {encoding}")]
    ContentEncoded {
        /// The URL that answered.
        url: String,
        /// The coding the response declared.
        encoding: String,
    },
    /// A URL the fetcher cannot use: a proxy URL or a proxy variable it cannot
    /// carry, or a fetch URL whose scheme is neither `http` nor `https`.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// An upload failed after hyper took its request: the connection failed
    /// while the request or the response head was in transit, the body
    /// failed because its writer was dropped or a frame of it waited past the
    /// stall window, no response head arrived within the response window, or
    /// the response head was one the upload does not deliver: a declared
    /// coding, a declared length over the cap, or a redirect the upload
    /// cannot follow. The server can have received the whole request and
    /// acted on it, so the outcome is unknown, and the fetcher does not send
    /// the request again.
    #[error("upload to {url} interrupted: {message}")]
    UploadInterrupted {
        /// The URL the request was sent to.
        url: String,
        /// What ended the upload.
        message: String,
    },
}

impl Error {
    /// Whether this error of [`Fetcher::upload`](crate::Fetcher::upload)
    /// states that the upload failed before the fetcher handed its request to
    /// a connection. No byte of such a request reached a server, so the
    /// server did nothing for it.
    ///
    /// Each failure of an upload after the hand-over is
    /// [`Error::UploadInterrupted`], whatever ended it. So the method gives
    /// `false` for that variant, and `true` for each other error of an upload:
    /// a refusal before admission, a connect or a handshake that failed, and
    /// rounds that ran out before the request was sent. The answer applies to
    /// the errors of an upload alone. A fetch never fails with
    /// `UploadInterrupted`, and it can fail with any other variant after its
    /// request was sent.
    pub fn is_unsent(&self) -> bool {
        !matches!(self, Error::UploadInterrupted { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An interrupted upload was sent. Each other error of an upload is a
    /// failure before the hand-over.
    #[test]
    fn an_interrupted_upload_alone_was_sent() {
        let interrupted = Error::UploadInterrupted {
            url: "https://h/x".into(),
            message: "response for https://h/x carries the coding gzip".into(),
        };
        assert!(!interrupted.is_unsent());
        for unsent in [
            Error::Fetch("connect to h:443 failed".into()),
            Error::Unsupported("fetch url scheme ftp".into()),
            Error::HttpStatus {
                status: 407,
                url: "https://h/x".into(),
            },
        ] {
            assert!(unsent.is_unsent(), "{unsent}");
        }
    }
}
