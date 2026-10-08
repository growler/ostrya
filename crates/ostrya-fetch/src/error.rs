//! The error type of the fetcher.

/// The result type of this crate, with [`Error`] as the error.
pub type Result<T> = std::result::Result<T, Error>;

/// The error of each fallible operation of this crate.
///
/// A caller outside this crate can build each variant. Each variant converts
/// to the `ostrya::Error` variant of the same name, with the same message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A failure to set up or to carry out a request.
    ///
    /// The causes include an option value, a mirror URL, a header, or a TLS
    /// configuration that the fetcher cannot use. They also include a refused
    /// credential, a refused redirect hop, and a transport failure or an
    /// expired deadline that outlived the retries.
    /// [`Fetcher::fetch`](crate::Fetcher::fetch) and
    /// [`Fetcher::upload`](crate::Fetcher::upload) list the cases.
    #[error("fetch: {0}")]
    Fetch(String),
    /// An HTTP status other than 200 and 304 that ended a fetch.
    ///
    /// A 404 means that the remote does not hold the requested file. The
    /// statuses 408, 429, and 5xx are retryable, and each other status is
    /// definitive. If a fetch fails, it reports the first definitive failure
    /// that it received, from any round. If it received no definitive failure,
    /// it reports the first retryable failure.
    ///
    /// If the reported failure is a status, it is this variant.
    /// [`Fetcher::fetch`](crate::Fetcher::fetch) states the failure order. An
    /// upload returns each status in an [`Uploaded`](crate::Uploaded) and does
    /// not fail with this variant.
    #[error("http status {status} for {url}")]
    HttpStatus {
        /// The status of the response.
        status: u16,
        /// The URL of the hop that answered with the status.
        url: String,
    },
    /// A redirect chain that reached the limit of
    /// [`max_redirects`](crate::FetcherOptions::max_redirects).
    ///
    /// The response at the end of the chain named another URL to follow. Each
    /// attempt against one destination counts its own hops, so a repeated
    /// round counts again from the destination that the route named.
    #[error("redirect from {url} exceeds the {hops}-redirect limit")]
    RedirectLimit {
        /// The URL of the last hop, whose `Location` the limit did not follow.
        url: String,
        /// The number of redirects that the attempt followed, which is the
        /// limit.
        hops: u32,
    },
    /// A response that declared more bytes than the cap of the caller.
    ///
    /// If a body grows past the cap while it streams, the read fails with the
    /// [`FileTooLarge`](std::io::ErrorKind::FileTooLarge) kind. The payload of
    /// that I/O error is a message string. It does not downcast to [`Error`].
    #[error("fetched object exceeds the {limit}-byte cap")]
    FetchTooLarge {
        /// The cap that the caller set on the request.
        limit: u64,
    },
    /// A response that declared a coding in `Content-Encoding` or
    /// `Transfer-Encoding`.
    ///
    /// The body of such a response holds bytes other than the bytes that the
    /// remote stores. The value `identity` in each header and the value
    /// `chunked` in `Transfer-Encoding` declare no coding.
    #[error("response for {url} carries the coding {encoding}")]
    ContentEncoded {
        /// The URL that answered.
        url: String,
        /// The coding that the response declared.
        encoding: String,
    },
    /// A URL or a proxy variable that the fetcher cannot use.
    ///
    /// The causes are a proxy URL or a proxy variable that the fetcher cannot
    /// carry. A request URL whose scheme is not `http` or `https` is also a
    /// cause.
    /// [`Proxy`](crate::Proxy) states the rules of the proxy URL and of the
    /// proxy variables.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// An upload that failed after hyper took its request.
    ///
    /// The causes are:
    ///
    /// - The connection failed while the request or the response head was in
    ///   transit.
    /// - The writer of the body was dropped, or a frame of the body waited
    ///   past the stall window.
    /// - No response head arrived within the response window.
    /// - The response head is one that the upload does not deliver. Such a
    ///   head declares a coding, declares a length over the cap, or names a
    ///   redirect that the upload cannot follow.
    ///
    /// The server can have received the whole request and acted on it, so the
    /// outcome is unknown. The fetcher does not send the request again.
    #[error("upload to {url} interrupted: {message}")]
    UploadInterrupted {
        /// The URL that the request was sent to.
        url: String,
        /// The text that names what ended the upload.
        message: String,
    },
}

impl Error {
    /// Returns `true` if an upload failed before it handed its request over.
    ///
    /// The hand-over gives the request to hyper. No byte of a request
    /// reaches a server before the hand-over, so the server does nothing for
    /// it.
    ///
    /// Each failure of an upload after the hand-over is
    /// [`Error::UploadInterrupted`], whatever ended it. The method returns
    /// `false` for that variant. It returns `true` for each other error of an
    /// upload. Examples are a refusal before admission, a failed connect or
    /// handshake, and rounds that ran out before the request was sent.
    ///
    /// The answer applies only to the errors of
    /// [`Fetcher::upload`](crate::Fetcher::upload). A fetch never fails with
    /// `UploadInterrupted`, and it can fail with any other variant after it
    /// sent its request.
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
