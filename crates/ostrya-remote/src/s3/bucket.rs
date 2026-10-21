//! The client of a bucket repository.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_io::AsyncRead;
use futures_lite::io::AsyncReadExt;
use ostrya_fetch::{
    Body, ErrorResponse, FetchRequest, Fetched, Fetcher, UploadBody, UploadMethod, UploadRequest,
    Uploaded,
};
use sha2::{Digest, Sha256};

use super::key::{
    check_key, check_list_prefix, decode_listed, encode_path, encode_query, is_repository_key,
};
use super::sigv4::valid_region;
use super::xml::{self, Doc, ErrorDoc, MAX_BODY, shown};
use super::{Location, S3Endpoint};
use crate::{Error, Result};

/// The largest listing body and error body that the client reads: the limit
/// of the XML reader, 4 MiB.
const XML_CAP: u64 = MAX_BODY as u64;

/// The largest number of truncated pages in a row, with no key and no common
/// prefix, that a list follows.
///
/// S3 can give a truncated page of `ListObjectsV2` with no key and no common
/// prefix, for example over many delete markers of a versioned bucket. The
/// list follows such a page if its continuation token is new since the last
/// page with a key or a common prefix. A run of more than this number of such
/// pages fails the list, so a server that gives empty pages with new tokens
/// and no end cannot keep the list open.
const MAX_EMPTY_PAGES: usize = 1000;

/// The largest body of one `PUT`: 5 GiB, the S3 limit.
const MAX_PUT: u64 = 5 * 1024 * 1024 * 1024;

/// The largest capacity that a whole read of a listing body or of an error
/// body reserves before the body arrives. A larger body grows the buffer as
/// it arrives.
const MAX_RESERVE: u64 = XML_CAP;

/// The capacity that a whole read of a body with no declared length reserves
/// before the body arrives: 8 KiB.
const FIRST_READ: u64 = 8 * 1024;

/// The size of the chunks in which the compare of a conditional `PUT` reads
/// the object of the key: 64 KiB.
const COMPARE_CHUNK: usize = 64 * 1024;

/// The client of a bucket repository.
///
/// [`Bucket::new`] opens it from an [`S3Endpoint`], and
/// [`Bucket::from_fetcher`] opens it over a fetcher that the caller built.
/// Each method takes a key or a list prefix relative to the prefix of the
/// repository, and the client adds `PREFIX/`. A key in a result is relative
/// to the prefix of the repository too.
///
/// # Keys
///
/// The client refuses a key that is not a key of a bucket repository, before
/// it sends a request:
///
/// - `config`, `summary`, `summary.sig`, and `extensions/ostrya/lock`
/// - `objects/XX/<62 hex digits>.<ext>`, in lowercase hex, with the
///   extension `commit`, `commitmeta`, `dirtree`, `dirmeta`, `filez`,
///   `tombstone-commit`, or `cfs`
/// - `refs/heads/<name>`, with a ref name that
///   [`is_ref_name`](ostrya_core::is_ref_name) accepts
/// - `deltas/<2>/<41>/<target>` and `deltas/<2>/<41>-<43>/<target>`, with
///   checksums in modified base64, and the target `superblock` or a part
///   number with no leading zero
/// - `delta-indexes/<2>/<41>.index`.
///
/// A list prefix ends in `/`, so a list for `s3://b/repo` never gives the
/// keys of `s3://b/repo2`. Its segments are not empty and are not `.` or
/// `..`.
///
/// The request path of a key encodes each byte other than `A-Z`, `a-z`,
/// `0-9`, `-`, `.`, `_`, `~`, and `/` as `%XX`. So a `+` of a delta key goes
/// as `%2B`.
///
/// # Requests
///
/// The `GET` requests (get, get stream, and the lists) are fetches. The
/// fetcher repeats a fetch after a transport failure or a 408, 429, or 5xx,
/// as [`Fetcher::fetch`] states, and fetches a failed body of a whole read
/// again.
///
/// The client sends a `PUT` or a `DELETE` again after
/// [`Error::UploadInterrupted`](ostrya_fetch::Error::UploadInterrupted) and
/// after a 408, 429, or 5xx, at most
/// [`max_retries`](ostrya_fetch::FetcherOptions::max_retries) times. The
/// delay starts at 250 ms, doubles each time, and stops at 2 s.
/// [`put_if_absent`](Bucket::put_if_absent) states its own rule.
///
/// The client follows no redirect. The body of each listing and of each
/// error response is at most 4 MiB.
///
/// # Errors of the server
///
/// An unsuccessful status gives [`Error::S3`], with the code and the message
/// of the S3 `Error` document in the body. A response whose
/// `x-amz-bucket-region` header or whose `Region` element names a region
/// other than the region of the location gives [`Error::S3Region`]. An
/// absent key is not an error, whatever region its response names.
///
/// The body of an error response to a `PUT` or a `DELETE` that declares a
/// coding, or a length over 4 MiB, is not read. The status then gives
/// [`Error::S3`] with no code, and the client does not send a definitive
/// status again.
///
/// The [`Debug`] output shows the location and the mirror of the fetcher.
pub struct Bucket {
    fetcher: Fetcher,
    location: Location,
    max_retries: u32,
    /// The bucket URL, if each request names its URL. It is `None` if the
    /// request paths go under the one mirror of the fetcher, the bucket URL.
    base: Option<String>,
}

impl std::fmt::Debug for Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bucket")
            .field("location", &self.location)
            .field("fetcher", &self.fetcher)
            .finish_non_exhaustive()
    }
}

/// An object that [`Bucket::get`] read whole.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Object {
    /// The bytes of the object.
    pub bytes: Vec<u8>,
    /// The `ETag` of the response, as the server wrote it.
    pub etag: Option<String>,
}

/// The body of an object that [`Bucket::get_stream`] gives.
///
/// A read gives the bytes in bounded chunks, as a [`Body`] does. The stream
/// holds an admission permit of the fetcher until it ends or is dropped. A
/// failure in transit fails the read, and the caller reads the object
/// again.
#[derive(Debug)]
pub struct ObjectStream {
    body: Body,
    etag: Option<String>,
}

impl ObjectStream {
    /// Returns the `ETag` of the response, as the server wrote it.
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// Returns the `Content-Length` of the response, if it declared one.
    pub fn content_length(&self) -> Option<u64> {
        self.body.content_length()
    }
}

impl AsyncRead for ObjectStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.body).poll_read(cx, buf)
    }
}

/// The read trait of tokio.
#[cfg(feature = "tokio")]
impl ostrya_rt::tokio_io::AsyncRead for ObjectStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ostrya_rt::tokio_io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        ostrya_rt::tokio_io::AsyncRead::poll_read(Pin::new(&mut self.body), cx, buf)
    }
}

/// The outcome of [`Bucket::put_if_absent`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PutIfAbsent {
    /// A request of this call wrote the object: the server answered it with
    /// a 2xx.
    Created {
        /// The `ETag` of the response, as the server wrote it.
        etag: Option<String>,
    },
    /// The key held an object, and the call wrote nothing. The server
    /// answered 412 to the first request, or a read of the key after a
    /// request with an unknown outcome found other bytes.
    Present,
    /// The key holds the bytes of the body, and no answer of the server
    /// states which writer put them there.
    ///
    /// A request of this call had an unknown outcome. Then a 412 or a failed
    /// request followed, and a read of the key found the same bytes. A
    /// request of this call can have written them, or an earlier writer of
    /// the same bytes.
    Matches {
        /// The `ETag` of the read of the key, as the server wrote it.
        etag: Option<String>,
    },
}

/// The keys and the common prefixes of a list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Listing {
    /// The objects, in the order of the server.
    pub objects: Vec<Listed>,
    /// The common prefixes of a list with a delimiter, relative to the prefix
    /// of the repository, each with its trailing `/`.
    pub common_prefixes: Vec<String>,
}

/// One object of a [`Listing`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Listed {
    /// The key, relative to the prefix of the repository.
    ///
    /// The key is not checked. A key that is not a key of a bucket
    /// repository is a stray key.
    pub key: String,
    /// The size of the object in bytes.
    pub size: u64,
}

/// One incomplete multipart upload of a key of the repository.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Upload {
    /// The key, relative to the prefix of the repository.
    pub key: String,
    /// The upload id.
    pub upload_id: String,
    /// The `Initiated` time, as the server wrote it.
    pub initiated: String,
}

/// The answer to one upload request, read whole.
struct Reply {
    status: u16,
    etag: Option<String>,
    region: Option<String>,
    /// The body, or `None` if it is larger than 4 MiB or failed in transit.
    body: Option<Vec<u8>>,
}

/// The outcome of one upload request.
enum Sent {
    /// The server answered.
    Reply(Reply),
    /// The request failed after the fetcher sent it, so the outcome is not
    /// known.
    Interrupted(ostrya_fetch::Error),
}

/// What a key holds, compared with the body of a request.
enum Compared {
    /// The same bytes, with the `ETag` of the read.
    Same(Option<String>),
    /// Other bytes.
    Other,
    /// No object.
    Absent,
}

impl Bucket {
    /// Opens the client of the bucket repository of `endpoint`.
    ///
    /// The call builds the fetcher. It sends no request.
    /// [`S3Endpoint`] states the HTTP options that the client takes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if [`SigV4::new`](super::SigV4::new) refuses
    ///   the region.
    /// - [`Error::Fetch`] if [`Fetcher::new`] refuses the options. An example
    ///   is an `http://` endpoint with
    ///   [`allow_cleartext_credentials`](ostrya_fetch::FetcherOptions::allow_cleartext_credentials)
    ///   set to `false`, because the signer is a credential. Another is
    ///   [`basic_auth`](ostrya_fetch::FetcherOptions::basic_auth), a bearer
    ///   token, or an `Authorization` header in the options.
    pub async fn new(endpoint: &S3Endpoint) -> Result<Bucket> {
        let location = endpoint.location.clone();
        let options = endpoint.signed_options(location.bucket_url())?;
        let fetcher = Fetcher::new(options).await.map_err(Error::Fetch)?;
        Ok(Bucket {
            fetcher,
            location,
            max_retries: endpoint.http.max_retries,
            base: None,
        })
    }

    /// Opens the client of the bucket repository of `endpoint` over
    /// `fetcher`.
    ///
    /// The call builds no fetcher and sends no request. The client shares
    /// the connection pool, the admission limit, and the counters of
    /// `fetcher`. The client names each request by its URL under the
    /// [`bucket_url`](Location::bucket_url) of the location, so it does not
    /// use the mirrors of `fetcher`. An example of `fetcher` is the fetcher
    /// of a pull, from the options that
    /// [`pull_options`](S3Endpoint::pull_options) gives, whose mirror is the
    /// [`repository_url`](Location::repository_url).
    ///
    /// The client takes the location and the retry count of `endpoint`.
    /// `fetcher` must sign each request with the credentials and the region
    /// of `endpoint`, and follow no redirect, as the fetcher of
    /// [`Bucket::new`] does. The call cannot check this.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ostrya_fetch::Fetcher;
    /// use ostrya_remote::s3::{Bucket, Environment, S3Endpoint, Settings};
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let endpoint =
    ///     S3Endpoint::resolve("s3://builds/exampleos", &Settings::default(), &Environment::Process)
    ///         .await?;
    /// let fetcher = Fetcher::new(endpoint.pull_options()?).await?;
    /// let bucket = Bucket::from_fetcher(&endpoint, fetcher.clone());
    /// // The fetcher reads the objects under the repository URL. The client
    /// // reads `summary` with the S3 rules of an absent key and of an error.
    /// let summary = bucket.get("summary", 1 << 20).await?;
    /// # Ok(()) }
    /// ```
    pub fn from_fetcher(endpoint: &S3Endpoint, fetcher: Fetcher) -> Bucket {
        Bucket {
            fetcher,
            location: endpoint.location.clone(),
            max_retries: endpoint.http.max_retries,
            base: Some(endpoint.location.bucket_url()),
        }
    }

    /// Returns the location of the bucket repository.
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Reads the object of `key` whole, or returns `None` if the key holds no
    /// object.
    ///
    /// A 404 is an absent key if its body arrived whole and holds the code
    /// `NoSuchKey`, or holds no S3 code: an empty body, or a body that is
    /// not an S3 `Error` document. A 404 with another code, for example
    /// `NoSuchBucket`, is an error, so a missing bucket never reads as an
    /// empty repository. A 404 whose body did not arrive is an error too,
    /// with no code. An absent key is not an error, whatever region its
    /// response names.
    ///
    /// The bytes have the capacity of the object and one byte, if the
    /// response declares the length of the object.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `key` is not a key of a bucket repository.
    /// - [`Error::LimitExceeded`] if the object is larger than `max_size`
    ///   bytes. The message names the key.
    /// - [`Error::S3`] and [`Error::S3Region`] for an unsuccessful response.
    /// - [`Error::Transport`] if the server answers with 304. The request
    ///   sends no validators, so the answer cannot be used.
    /// - [`Error::Fetch`] for a failure of the fetcher, and [`Error::Io`] for
    ///   a body that failed in transit after the last refetch.
    pub async fn get(&self, key: &str, max_size: u64) -> Result<Option<Object>> {
        check_key(key)?;
        let full = self.full_key(key);
        let path = encode_path(&full);
        let target = self.target(&path, "");
        let mut refetch = self.fetcher.refetching(FetchRequest {
            max_size: Some(max_size),
            max_error_body: Some(XML_CAP),
            ..target.fetch()
        });
        loop {
            let mut body = match refetch.fetch().await {
                Ok(Fetched::Body(body)) => body,
                Ok(Fetched::NotModified) => return Err(not_modified(&full)),
                Err(e) => {
                    self.absent_or_error(e, &full, max_size)?;
                    return Ok(None);
                }
            };
            let etag = body.validators().etag.clone();
            let declared = body.content_length();
            // The fetcher refuses a declared length over `max_size`, so the
            // read reserves a declared length whole.
            match read_whole(&mut body, declared, max_size, max_size).await {
                Ok(bytes) => return Ok(Some(Object { bytes, etag })),
                Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                    return Err(too_large(&full, max_size));
                }
                Err(e) => {
                    drop(body);
                    refetch.retry(e).await?;
                }
            }
        }
    }

    /// Opens the body of the object of `key` as a stream, or returns `None`
    /// if the key holds no object.
    ///
    /// The stream holds no more than one chunk of the object in memory.
    /// [`get`](Bucket::get) states the rule of an absent key.
    ///
    /// # Errors
    ///
    /// The errors of [`get`](Bucket::get), other than the size limit: also
    /// [`Error::Transport`] for a 304. A read of the stream fails with an I/O
    /// error if the body fails in transit.
    pub async fn get_stream(&self, key: &str) -> Result<Option<ObjectStream>> {
        check_key(key)?;
        let full = self.full_key(key);
        let path = encode_path(&full);
        let target = self.target(&path, "");
        let fetched = self
            .fetcher
            .fetch(FetchRequest {
                max_error_body: Some(XML_CAP),
                ..target.fetch()
            })
            .await;
        match fetched {
            Ok(Fetched::Body(body)) => {
                let etag = body.validators().etag.clone();
                Ok(Some(ObjectStream { body, etag }))
            }
            Ok(Fetched::NotModified) => Err(not_modified(&full)),
            Err(e) => {
                self.absent_or_error(e, &full, u64::MAX)?;
                Ok(None)
            }
        }
    }

    /// Writes `body` to `key`, and returns the `ETag` of the response.
    ///
    /// The request is idempotent, so the client sends it again by the rule
    /// of [`Bucket`]. A second request shares the bytes of the first one, so
    /// the client holds one copy of the body.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `key` is not a key of a bucket repository,
    ///   or if `body` is larger than 5 GiB, the limit of one S3 `PUT`.
    /// - [`Error::S3`] and [`Error::S3Region`] for an unsuccessful response.
    /// - [`Error::Fetch`] for a failure of the fetcher, also after the last
    ///   request that the client sent again.
    pub async fn put(&self, key: &str, body: Vec<u8>) -> Result<Option<String>> {
        check_key(key)?;
        check_put_size(key, &body)?;
        let full = self.full_key(key);
        let path = encode_path(&full);
        let body = UploadBody::bytes(body);
        let mut round = 0;
        loop {
            match self
                .send(UploadMethod::Put, &path, copy(&body), &[])
                .await?
            {
                Sent::Reply(reply) if is_success(reply.status) => return Ok(reply.etag),
                Sent::Reply(reply) if is_retryable(reply.status) && round < self.max_retries => {}
                Sent::Reply(reply) => return Err(self.reply_error(reply, Some(&full))),
                Sent::Interrupted(_) if round < self.max_retries => {}
                Sent::Interrupted(e) => return Err(Error::Fetch(e)),
            }
            round += 1;
            ostrya_rt::Timer::after(backoff(round)).await;
        }
    }

    /// Writes `body` to `key` if the key holds no object.
    ///
    /// The request carries `If-None-Match: *`. A 2xx gives
    /// [`PutIfAbsent::Created`]. A 412 to the first request gives
    /// [`PutIfAbsent::Present`]. A 409 with the code
    /// `ConditionalRequestConflict` is sent again, at most
    /// [`max_retries`](ostrya_fetch::FetcherOptions::max_retries) times.
    ///
    /// After an interrupted request, the outcome is not known. The client
    /// then reads the key and compares the SHA-256 of what it holds with the
    /// SHA-256 of `body`:
    ///
    /// - The same bytes give [`PutIfAbsent::Matches`].
    /// - Other bytes give [`PutIfAbsent::Present`].
    /// - An absent key sends the request again, within the retry count.
    ///
    /// After a 408, 429, or 5xx, the client sends the request again within
    /// the retry count. A 412 after such a status, or after an interrupted
    /// request, can answer a request of this call. So the client then reads
    /// the key and compares it in the same way: the same bytes give
    /// [`PutIfAbsent::Matches`], and other bytes or an absent key give
    /// [`PutIfAbsent::Present`].
    ///
    /// The compare reads the object as a stream, in chunks of 64 KiB. A
    /// response that declares a length other than the length of `body`
    /// holds other bytes, and the client reads none of it. The SHA-256 of
    /// `body` is computed only for a compare, on the blocking pool of the
    /// runtime.
    ///
    /// A server that does not honor `If-None-Match` writes the object over
    /// the one that the key holds, and gives [`PutIfAbsent::Created`].
    ///
    /// # Errors
    ///
    /// The errors of [`put`](Bucket::put), and the errors of
    /// [`get`](Bucket::get) for the read of the key.
    pub async fn put_if_absent(&self, key: &str, body: Vec<u8>) -> Result<PutIfAbsent> {
        check_key(key)?;
        check_put_size(key, &body)?;
        let full = self.full_key(key);
        let path = encode_path(&full);
        let body = UploadBody::bytes(body);
        let headers = [("If-None-Match".to_owned(), "*".to_owned())];
        let mut round = 0;
        // `true` after a request whose outcome is not known.
        let mut unsure = false;
        // The SHA-256 of `body`, computed at the first compare that needs it.
        let mut digest: Option<[u8; 32]> = None;
        loop {
            match self
                .send(UploadMethod::Put, &path, copy(&body), &headers)
                .await?
            {
                Sent::Reply(reply) if is_success(reply.status) => {
                    return Ok(PutIfAbsent::Created { etag: reply.etag });
                }
                Sent::Reply(reply) if reply.status == 412 => {
                    if !unsure {
                        return Ok(PutIfAbsent::Present);
                    }
                    return Ok(match self.compare(&full, &body, &mut digest).await? {
                        Compared::Same(etag) => PutIfAbsent::Matches { etag },
                        Compared::Other | Compared::Absent => PutIfAbsent::Present,
                    });
                }
                Sent::Reply(reply)
                    if reply.status == 409
                        && reply_code(&reply).as_deref() == Some("ConditionalRequestConflict")
                        && round < self.max_retries => {}
                Sent::Reply(reply) if is_retryable(reply.status) && round < self.max_retries => {
                    unsure = true;
                }
                Sent::Reply(reply) => return Err(self.reply_error(reply, Some(&full))),
                Sent::Interrupted(e) => match self.compare(&full, &body, &mut digest).await? {
                    Compared::Same(etag) => return Ok(PutIfAbsent::Matches { etag }),
                    Compared::Other => return Ok(PutIfAbsent::Present),
                    Compared::Absent if round < self.max_retries => unsure = true,
                    Compared::Absent => return Err(Error::Fetch(e)),
                },
            }
            round += 1;
            ostrya_rt::Timer::after(backoff(round)).await;
        }
    }

    /// Deletes the object of `key`.
    ///
    /// A 2xx and an absent key are success. [`get`](Bucket::get) states the
    /// rule of an absent key. The client sends the request again by the rule
    /// of [`Bucket`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `key` is not a key of a bucket repository.
    /// - [`Error::S3`] and [`Error::S3Region`] for an unsuccessful response.
    /// - [`Error::Fetch`] for a failure of the fetcher, also after the last
    ///   request that the client sent again.
    pub async fn delete(&self, key: &str) -> Result<()> {
        check_key(key)?;
        let full = self.full_key(key);
        let path = encode_path(&full);
        let mut round = 0;
        loop {
            let empty = UploadBody::bytes(Vec::new());
            match self.send(UploadMethod::Delete, &path, empty, &[]).await? {
                Sent::Reply(reply) if is_success(reply.status) => return Ok(()),
                Sent::Reply(reply) if is_absent(reply.status, reply.body.as_deref()) => {
                    return Ok(());
                }
                Sent::Reply(reply) if is_retryable(reply.status) && round < self.max_retries => {}
                Sent::Reply(reply) => return Err(self.reply_error(reply, Some(&full))),
                Sent::Interrupted(_) if round < self.max_retries => {}
                Sent::Interrupted(e) => return Err(Error::Fetch(e)),
            }
            round += 1;
            ostrya_rt::Timer::after(backoff(round)).await;
        }
    }

    /// Lists each object under `prefix`, over all pages.
    ///
    /// `prefix` is relative to the prefix of the repository and ends in `/`,
    /// for example `objects/ab/` or `refs/heads/`. The request is
    /// `ListObjectsV2` with the encoding type `url`, and the client decodes
    /// each key.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `prefix` does not end in `/`, or holds an
    ///   empty segment, `.`, `..`, or a character outside the alphabet of a
    ///   key.
    /// - [`Error::Transport`] if a page cannot be used: a body that the XML
    ///   reader refuses, a truncated page with no continuation token, a key
    ///   outside the prefix, or a page that does not move forward. Each key
    ///   and common prefix of a page comes after each one of the earlier
    ///   pages, in the byte order of UTF-8. A truncated page that holds no
    ///   key and no common prefix gives a continuation token that no page
    ///   gave after the last page with a key or a common prefix. More than
    ///   1000 truncated pages in a row with no key and no common prefix fail
    ///   the list. So a server that gives the same page again, or empty
    ///   pages with no end, fails the list.
    /// - [`Error::Transport`] if the server answers with 304.
    /// - [`Error::LimitExceeded`] if a page is larger than 4 MiB.
    /// - [`Error::S3`] and [`Error::S3Region`] for an unsuccessful response,
    ///   or for an S3 `Error` document with a 200.
    /// - [`Error::Fetch`] and [`Error::Io`] as for [`get`](Bucket::get).
    pub async fn list(&self, prefix: &str) -> Result<Listing> {
        self.list_pages(prefix, false).await
    }

    /// Lists the objects and the common prefixes under `prefix`, with the
    /// delimiter `/`, over all pages.
    ///
    /// Each key and each common prefix is relative to the prefix of the
    /// repository.
    ///
    /// # Errors
    ///
    /// The errors of [`list`](Bucket::list).
    pub async fn list_delimited(&self, prefix: &str) -> Result<Listing> {
        self.list_pages(prefix, true).await
    }

    /// Lists the incomplete multipart uploads of the keys of the repository,
    /// over all pages.
    ///
    /// The request is `ListMultipartUploads` with the prefix `PREFIX/`. With
    /// no prefix, the list covers the whole bucket, and the client keeps an
    /// upload only if its key is a key of a bucket repository. A 404 with
    /// the code `NoSuchUpload` is an empty list, because a server can answer
    /// a bucket with no upload in this way.
    ///
    /// # Errors
    ///
    /// The errors of [`list`](Bucket::list), with the markers of the next
    /// page in place of the continuation token. The rule of progress is
    /// different:
    ///
    /// - The `NextKeyMarker` of each truncated page does not come before the
    ///   key marker of the page before it, in the byte order of UTF-8.
    /// - While the key marker stays the same, the `NextUploadIdMarker` of
    ///   each truncated page is one that no earlier page gave for that key
    ///   marker. S3 sorts the uploads of one key by the time of their start,
    ///   and not by the upload id, so the upload id markers of one key have
    ///   no order.
    ///
    /// So a truncated page that holds no upload must move the markers.
    pub async fn list_uploads(&self) -> Result<Vec<Upload>> {
        let repository = self.repository_prefix();
        let mut uploads = Vec::new();
        let mut markers: Option<(String, String)> = None;
        // The upload id markers of the key marker of `markers`.
        let mut ids: HashSet<String> = HashSet::new();
        loop {
            let mut query = "uploads".to_owned();
            if !repository.is_empty() {
                query.push_str("&prefix=");
                query.push_str(&encode_query(&repository));
            }
            query.push_str("&encoding-type=url");
            if let Some((key_marker, id_marker)) = &markers {
                query.push_str("&key-marker=");
                query.push_str(&encode_query(key_marker));
                query.push_str("&upload-id-marker=");
                query.push_str(&encode_query(id_marker));
            }
            let body = match self.fetch_listing(&query).await {
                Ok(body) => body,
                Err(Error::S3 {
                    status: 404,
                    code: Some(code),
                    ..
                }) if code == "NoSuchUpload" => return Ok(uploads),
                Err(e) => return Err(e),
            };
            let page = match xml::list_uploads(&body).map_err(|why| self.unusable(&why))? {
                Doc::Result(page) => page,
                Doc::Error(doc) => return Err(self.answer_error(200, None, Some(doc), None)),
            };
            for (key, upload_id, initiated) in page.uploads {
                let key = self.listed(&key, page.encoded, &repository, repository.len())?;
                if is_repository_key(&key) {
                    uploads.push(Upload {
                        key,
                        upload_id,
                        initiated,
                    });
                }
            }
            if !page.truncated {
                return Ok(uploads);
            }
            let key_marker = page
                .next_key_marker
                .filter(|marker| !marker.is_empty())
                .map(|marker| decode_listed(&marker, page.encoded));
            let id_marker = page.next_upload_id_marker.filter(|id| !id.is_empty());
            let (Some(key_marker), Some(id_marker)) = (key_marker, id_marker) else {
                return Err(
                    self.unusable("a truncated page has no NextKeyMarker or no NextUploadIdMarker")
                );
            };
            match &markers {
                Some((earlier, _)) if key_marker < *earlier => {
                    return Err(self.unusable(
                        "the markers of a page do not move past the markers of the page \
                         before it: its NextKeyMarker comes before the key marker",
                    ));
                }
                Some((earlier, _)) if key_marker == *earlier => {
                    if !ids.insert(id_marker.clone()) {
                        return Err(self.unusable(
                            "the markers of a page do not move past the markers of the earlier \
                             pages: an earlier page gave the same NextUploadIdMarker for the \
                             same NextKeyMarker",
                        ));
                    }
                }
                _ => {
                    ids.clear();
                    ids.insert(id_marker.clone());
                }
            }
            markers = Some((key_marker, id_marker));
        }
    }

    /// Lists the objects under `prefix`, with the delimiter `/` if
    /// `delimited` is `true`.
    async fn list_pages(&self, prefix: &str, delimited: bool) -> Result<Listing> {
        check_list_prefix(prefix)?;
        let strip = self.repository_prefix().len();
        let full = self.full_key(prefix);
        let mut listing = Listing::default();
        let mut token: Option<String> = None;
        // The last key or common prefix of the earlier pages.
        let mut last: Option<String> = None;
        // The continuation tokens of the pages after the last page with a
        // key or a common prefix, and of that page.
        let mut tokens: HashSet<String> = HashSet::new();
        // The number of truncated pages in a row with no key and no common
        // prefix.
        let mut empty_run = 0usize;
        loop {
            let mut query = format!(
                "list-type=2&prefix={}&encoding-type=url",
                encode_query(&full)
            );
            if delimited {
                query.push_str("&delimiter=%2F");
            }
            if let Some(token) = &token {
                query.push_str("&continuation-token=");
                query.push_str(&encode_query(token));
            }
            let body = self.fetch_listing(&query).await?;
            let page = match xml::list_objects(&body).map_err(|why| self.unusable(&why))? {
                Doc::Result(page) => page,
                Doc::Error(doc) => return Err(self.answer_error(200, None, Some(doc), None)),
            };
            let (objects, prefixes) = (listing.objects.len(), listing.common_prefixes.len());
            for (key, size) in page.contents {
                let key = self.listed(&key, page.encoded, &full, strip)?;
                listing.objects.push(Listed { key, size });
            }
            for common in page.prefixes {
                let common = self.listed(&common, page.encoded, &full, strip)?;
                listing.common_prefixes.push(common);
            }
            let entries = listing.objects[objects..]
                .iter()
                .map(|listed| listed.key.as_str())
                .chain(
                    listing.common_prefixes[prefixes..]
                        .iter()
                        .map(String::as_str),
                );
            let (first, page_last) = entries.fold((None, None), |(low, high), entry| {
                (
                    low.filter(|low| low <= &entry).or(Some(entry)),
                    high.filter(|high| high >= &entry).or(Some(entry)),
                )
            });
            if let (Some(first), Some(last)) = (first, &last)
                && first <= last.as_str()
            {
                return Err(self.unusable(&format!(
                    "a page does not move past the keys of the earlier pages: it holds {:?} \
                     after {:?}",
                    shown(first),
                    shown(last)
                )));
            }
            if let Some(page_last) = page_last {
                last = Some(page_last.to_owned());
            }
            if !page.truncated {
                return Ok(listing);
            }
            let Some(next) = page.token.filter(|token| !token.is_empty()) else {
                return Err(self.unusable("a truncated page has no NextContinuationToken"));
            };
            if page_last.is_some() {
                tokens.clear();
                empty_run = 0;
            } else {
                empty_run += 1;
                if empty_run > MAX_EMPTY_PAGES {
                    return Err(self.unusable(&format!(
                        "more than {MAX_EMPTY_PAGES} truncated pages in a row hold no key and \
                         no common prefix"
                    )));
                }
            }
            if !tokens.insert(next.clone()) {
                return Err(self.unusable(
                    "a truncated page holds no key and no common prefix, and gives the \
                     continuation token of an earlier page",
                ));
            }
            token = Some(next);
        }
    }

    /// Fetches the listing of `query` on the bucket, and returns its body.
    async fn fetch_listing(&self, query: &str) -> Result<Vec<u8>> {
        let target = self.target("", query);
        let mut refetch = self.fetcher.refetching(FetchRequest {
            max_size: Some(XML_CAP),
            max_error_body: Some(XML_CAP),
            ..target.fetch()
        });
        loop {
            let mut body = match refetch.fetch().await {
                Ok(Fetched::Body(body)) => body,
                Ok(Fetched::NotModified) => {
                    return Err(self.unusable("the server answered a list with 304"));
                }
                Err(ostrya_fetch::Error::FetchTooLarge { .. }) => {
                    return Err(self.listing_too_large());
                }
                Err(ostrya_fetch::Error::HttpStatus {
                    status, response, ..
                }) => return Err(self.status_error(status, response.as_deref(), None)),
                Err(e) => return Err(Error::Fetch(e)),
            };
            let declared = body.content_length();
            match read_whole(&mut body, declared, XML_CAP, MAX_RESERVE).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                    return Err(self.listing_too_large());
                }
                Err(e) => {
                    drop(body);
                    refetch.retry(e).await?;
                }
            }
        }
    }

    /// Sends one upload request of `method` to `path` with `body` and
    /// `headers`, and reads the answer whole.
    async fn send(
        &self,
        method: UploadMethod,
        path: &str,
        body: UploadBody,
        headers: &[(String, String)],
    ) -> Result<Sent> {
        let target = self.target(path, "");
        let request = UploadRequest {
            method,
            max_response: XML_CAP,
            headers,
            ..target.upload(body)
        };
        match self.fetcher.upload(request).await {
            Ok(uploaded) => Ok(Sent::Reply(read_reply(uploaded).await)),
            Err(e) if !e.is_unsent() => Ok(Sent::Interrupted(e)),
            Err(e) => Err(Error::Fetch(e)),
        }
    }

    /// Reads the object of the full key `full` as a stream, and compares it
    /// with `body`.
    ///
    /// A declared length other than the length of `body` gives
    /// [`Compared::Other`] with no read of the object. Else the function
    /// hashes the object in chunks of [`COMPARE_CHUNK`] bytes, and stops at
    /// the first byte past the length of `body`. `digest` keeps the SHA-256
    /// of `body` for a later compare.
    async fn compare(
        &self,
        full: &str,
        body: &UploadBody,
        digest: &mut Option<[u8; 32]>,
    ) -> Result<Compared> {
        let size = body.as_bytes().map_or(0, <[u8]>::len) as u64;
        let path = encode_path(full);
        let target = self.target(&path, "");
        let mut refetch = self.fetcher.refetching(FetchRequest {
            max_error_body: Some(XML_CAP),
            ..target.fetch()
        });
        let (stored, etag) = loop {
            let mut stream = match refetch.fetch().await {
                Ok(Fetched::Body(stream)) => stream,
                Ok(Fetched::NotModified) => return Err(not_modified(full)),
                Err(e) => {
                    self.absent_or_error(e, full, u64::MAX)?;
                    return Ok(Compared::Absent);
                }
            };
            if stream.content_length().is_some_and(|length| length != size) {
                return Ok(Compared::Other);
            }
            let etag = stream.validators().etag.clone();
            match hash_exact(&mut stream, size).await {
                Ok(Some(stored)) => break (stored, etag),
                Ok(None) => return Ok(Compared::Other),
                Err(e) => {
                    drop(stream);
                    refetch.retry(e).await?;
                }
            }
        };
        let ours = match *digest {
            Some(ours) => ours,
            None => {
                let copy = copy(body);
                let ours: [u8; 32] = ostrya_rt::unblock(move || {
                    Sha256::digest(copy.as_bytes().unwrap_or_default()).into()
                })
                .await;
                *digest = Some(ours);
                ours
            }
        };
        Ok(if stored == ours {
            Compared::Same(etag)
        } else {
            Compared::Other
        })
    }

    /// Returns `Ok` if the failed fetch `e` of the object `full` states that
    /// the key holds no object, and the error of the fetch otherwise.
    ///
    /// The absent-key rule runs before the region check, so an absent key is
    /// never a region error.
    fn absent_or_error(&self, e: ostrya_fetch::Error, full: &str, max_size: u64) -> Result<()> {
        match e {
            ostrya_fetch::Error::FetchTooLarge { .. } => Err(too_large(full, max_size)),
            ostrya_fetch::Error::HttpStatus {
                status, response, ..
            } => {
                let response = response.as_deref();
                if is_absent(status, response.and_then(ErrorResponse::body)) {
                    Ok(())
                } else {
                    Err(self.status_error(status, response, Some(full)))
                }
            }
            other => Err(Error::Fetch(other)),
        }
    }

    /// Returns the error of an unsuccessful fetch with `status` and the kept
    /// `response`.
    fn status_error(
        &self,
        status: u16,
        response: Option<&ErrorResponse>,
        key: Option<&str>,
    ) -> Error {
        let region = response
            .and_then(|response| response.headers().get("x-amz-bucket-region"))
            .and_then(|value| value.to_str().ok());
        let doc = response.and_then(ErrorResponse::body).and_then(xml::error);
        self.answer_error(status, region, doc, key)
    }

    /// Returns the error of an unsuccessful upload `reply`.
    fn reply_error(&self, reply: Reply, key: Option<&str>) -> Error {
        let doc = reply.body.as_deref().and_then(xml::error);
        self.answer_error(reply.status, reply.region.as_deref(), doc, key)
    }

    /// Returns the error of an answer with `status`, the region header
    /// `region`, and the S3 `Error` document `doc`.
    ///
    /// A region of the header, else of the `Region` element, that differs
    /// from the region of the location gives [`Error::S3Region`]. A value
    /// that is not a region counts as absent.
    fn answer_error(
        &self,
        status: u16,
        region: Option<&str>,
        doc: Option<ErrorDoc>,
        key: Option<&str>,
    ) -> Error {
        let doc = doc.unwrap_or_default();
        let bucket_region = region
            .map(str::trim)
            .filter(|region| valid_region(region))
            .or_else(|| {
                doc.region
                    .as_deref()
                    .map(str::trim)
                    .filter(|region| valid_region(region))
            });
        if let Some(bucket_region) = bucket_region
            && bucket_region != self.location.region()
        {
            return Error::S3Region {
                bucket: self.location.address().bucket().to_owned(),
                region: self.location.region().to_owned(),
                bucket_region: bucket_region.to_owned(),
            };
        }
        Error::S3 {
            status,
            code: doc.code.as_deref().map(str::trim).map(shown),
            message: doc.message.as_deref().map(shown),
            key: key.map(str::to_owned),
        }
    }

    /// Returns the key or the common prefix `text` of a listing, relative to
    /// the prefix of the repository, which is the first `strip` bytes.
    ///
    /// `encoded` states that the listing has the encoding type `url`. A text
    /// outside `requested`, the prefix of the request, fails the listing.
    /// `requested` starts with the prefix of the repository.
    fn listed(&self, text: &str, encoded: bool, requested: &str, strip: usize) -> Result<String> {
        let mut decoded = decode_listed(text, encoded);
        if !decoded.starts_with(requested) {
            return Err(self.unusable(&format!(
                "the listing holds the key {:?}, which is outside the prefix {requested:?}",
                shown(&decoded)
            )));
        }
        decoded.drain(..strip);
        Ok(decoded)
    }

    /// Returns the target of a request to the encoded path `path`, relative
    /// to the bucket URL, with the query `query`. An empty query is no query.
    fn target<'a>(&self, path: &'a str, query: &'a str) -> RequestTarget<'a> {
        match &self.base {
            None => RequestTarget::Mirror { path, query },
            Some(base) if query.is_empty() => RequestTarget::Url(format!("{base}/{path}")),
            Some(base) => RequestTarget::Url(format!("{base}/{path}?{query}")),
        }
    }

    /// Returns the prefix of each key of the repository: `PREFIX/`, or empty
    /// for an address with no prefix.
    fn repository_prefix(&self) -> String {
        match self.location.address().prefix() {
            "" => String::new(),
            prefix => format!("{prefix}/"),
        }
    }

    /// Returns the full key of `key`, which is relative to the prefix of the
    /// repository.
    fn full_key(&self, key: &str) -> String {
        format!("{}{key}", self.repository_prefix())
    }

    /// Returns the error of a listing that the client cannot use.
    fn unusable(&self, why: &str) -> Error {
        Error::Transport(format!(
            "S3: the answer of {} cannot be used: {why}",
            self.location.address()
        ))
    }

    /// Returns the error of a listing page over the limit of the reader.
    fn listing_too_large(&self) -> Error {
        Error::LimitExceeded(format!(
            "S3: a listing page of {} is larger than {XML_CAP} bytes",
            self.location.address()
        ))
    }
}

/// The target of one request of the client.
enum RequestTarget<'a> {
    /// A path and a query under the one mirror of the fetcher, the bucket
    /// URL. An empty query is no query.
    Mirror {
        /// The encoded path.
        path: &'a str,
        /// The query.
        query: &'a str,
    },
    /// The URL of the request, under the bucket URL.
    Url(String),
}

impl RequestTarget<'_> {
    /// Returns a fetch of the target with the default of each other field.
    fn fetch(&self) -> FetchRequest<'_> {
        match self {
            RequestTarget::Mirror { path, query: "" } => FetchRequest::path(path),
            RequestTarget::Mirror { path, query } => FetchRequest::path_query(path, query),
            RequestTarget::Url(url) => FetchRequest::url(url),
        }
    }

    /// Returns an upload of `body` to the target with the default of each
    /// other field. An upload of the client carries no query.
    fn upload(&self, body: UploadBody) -> UploadRequest<'_> {
        match self {
            RequestTarget::Mirror { path, .. } => UploadRequest::path(path, body),
            RequestTarget::Url(url) => UploadRequest::url(url, body),
        }
    }
}

/// Returns a second body with the bytes of `body`.
fn copy(body: &UploadBody) -> UploadBody {
    body.try_clone()
        .expect("a body of bytes has a copy that shares its bytes")
}

/// Refuses a body larger than one S3 `PUT` takes.
fn check_put_size(key: &str, body: &[u8]) -> Result<()> {
    if body.len() as u64 > MAX_PUT {
        return Err(Error::InvalidInput(format!(
            "S3: the body of {key} has {} bytes, more than the {MAX_PUT}-byte limit of one PUT",
            body.len()
        )));
    }
    Ok(())
}

/// Reads the status, the `ETag`, the region header, and the body of
/// `uploaded`.
async fn read_reply(uploaded: Uploaded) -> Reply {
    let header = |name: &str| {
        uploaded
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let status = uploaded.status();
    let etag = header("etag");
    let region = header("x-amz-bucket-region");
    let withheld = uploaded.body_withheld();
    let mut body = uploaded.into_body();
    let declared = body.content_length();
    let body = if withheld {
        None
    } else {
        read_whole(&mut body, declared, XML_CAP, MAX_RESERVE)
            .await
            .ok()
    };
    Reply {
        status,
        etag,
        region,
        body,
    }
}

/// Returns the `Code` of the S3 `Error` document of `reply`.
fn reply_code(reply: &Reply) -> Option<String> {
    reply.body.as_deref().and_then(xml::error)?.code
}

/// Returns `true` for a 2xx status.
fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Returns `true` for a status that a later request can avoid: 408, 429,
/// and 5xx.
fn is_retryable(status: u16) -> bool {
    status == 408 || status == 429 || (500..600).contains(&status)
}

/// Returns `true` if an answer with `status` and the whole body `body`
/// states an absent key: a 404 whose body holds the code `NoSuchKey`, or no
/// S3 code.
///
/// `body` is `None` if the body did not arrive whole. Such a 404 can come
/// from a missing bucket, so it is not an absent key.
fn is_absent(status: u16, body: Option<&[u8]>) -> bool {
    status == 404
        && body.is_some_and(|body| {
            xml::error(body)
                .and_then(|doc| doc.code)
                .is_none_or(|code| code.trim() == "NoSuchKey")
        })
}

/// Reads `body` to its end, and refuses a body larger than `limit` bytes
/// with [`ErrorKind::FileTooLarge`].
///
/// The vector reserves the `declared` length and one byte for the end of
/// the body, up to `reserve` bytes before the body arrives. With no
/// declared length, it reserves [`FIRST_READ`] bytes, up to `reserve`. It
/// then doubles as the bytes arrive, and its capacity never passes the
/// declared length or `limit` by more than one byte.
async fn read_whole(
    body: &mut (impl AsyncRead + Unpin),
    declared: Option<u64>,
    limit: u64,
    reserve: u64,
) -> std::io::Result<Vec<u8>> {
    let most = declared.map_or(limit, |declared| declared.min(limit));
    let ceiling = usize::try_from(most.saturating_add(1)).unwrap_or(usize::MAX);
    let first = usize::try_from(declared.unwrap_or(FIRST_READ).min(most).min(reserve))
        .unwrap_or(0)
        .saturating_add(1);
    let mut bytes = vec![0u8; first];
    let mut filled = 0;
    loop {
        if filled == bytes.len() {
            if bytes.len() >= ceiling {
                return Err(std::io::Error::new(
                    ErrorKind::FileTooLarge,
                    format!("the body is larger than {limit} bytes"),
                ));
            }
            let grown = bytes.len().saturating_mul(2).min(ceiling);
            bytes.reserve_exact(grown - bytes.len());
            bytes.resize(grown, 0);
        }
        let n = body.read(&mut bytes[filled..]).await?;
        if n == 0 {
            bytes.truncate(filled);
            return Ok(bytes);
        }
        filled += n;
    }
}

/// Hashes the stream `body` with SHA-256, in chunks of [`COMPARE_CHUNK`]
/// bytes, if it holds exactly `size` bytes.
///
/// Returns `None` at the first byte past `size`, or at an end before `size`.
async fn hash_exact(
    body: &mut (impl AsyncRead + Unpin),
    size: u64,
) -> std::io::Result<Option<[u8; 32]>> {
    let chunk =
        usize::try_from(size.saturating_add(1)).map_or(COMPARE_CHUNK, |len| len.min(COMPARE_CHUNK));
    let mut buf = vec![0u8; chunk];
    let mut hasher = Sha256::new();
    let mut read = 0u64;
    loop {
        let n = body.read(&mut buf).await?;
        if n == 0 {
            return Ok((read == size).then(|| hasher.finalize().into()));
        }
        read += n as u64;
        if read > size {
            return Ok(None);
        }
        hasher.update(&buf[..n]);
    }
}

/// Returns the delay before the request of retry `round`: 250 ms, doubled for
/// each round, up to 2 s.
fn backoff(round: u32) -> Duration {
    Duration::from_millis(250u64 << round.saturating_sub(1).min(3))
}

/// Returns the error of an object over the limit of the caller.
fn too_large(key: &str, max_size: u64) -> Error {
    Error::LimitExceeded(format!(
        "S3: the object {key} is larger than the limit of {max_size} bytes"
    ))
}

/// Returns the error of a 304 to a request with no validators.
fn not_modified(key: &str) -> Error {
    Error::Transport(format!(
        "S3: the server answered the read of {key}, which sent no validators, with 304"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_and_stops_at_two_seconds() {
        let delays: Vec<u64> = (1..=6)
            .map(|round| backoff(round).as_millis() as u64)
            .collect();
        assert_eq!(delays, [250, 500, 1000, 2000, 2000, 2000]);
    }

    #[test]
    fn the_retryable_statuses_are_408_429_and_5xx() {
        for status in [408, 429, 500, 503, 599] {
            assert!(is_retryable(status), "{status}");
        }
        for status in [200, 301, 400, 403, 404, 409, 412] {
            assert!(!is_retryable(status), "{status}");
        }
    }

    #[test]
    fn an_absent_key_is_a_404_whose_body_has_no_code_or_no_such_key() {
        let coded = |code: &str| format!("<Error><Code>{code}</Code></Error>").into_bytes();
        assert!(is_absent(404, Some(b"")));
        assert!(is_absent(404, Some(b"not found")));
        assert!(is_absent(404, Some(b"<Error><Message>m</Message></Error>")));
        assert!(is_absent(404, Some(&coded("NoSuchKey"))));
        assert!(!is_absent(404, Some(&coded("NoSuchBucket"))));
        assert!(!is_absent(404, None));
        assert!(!is_absent(403, Some(b"")));
    }

    #[test]
    fn a_whole_read_holds_no_capacity_past_its_limit() {
        ostrya_rt::block_on(async {
            let data = vec![b'x'; XML_CAP as usize];
            // No declared length: the vector doubles up to the limit and one
            // byte.
            let mut reader = futures_lite::io::Cursor::new(data.clone());
            let bytes = read_whole(&mut reader, None, XML_CAP, MAX_RESERVE)
                .await
                .unwrap();
            assert_eq!(bytes.len(), data.len());
            assert!(bytes.capacity() <= data.len() + 1, "{}", bytes.capacity());
            // A declared length: the vector reserves it and one byte.
            let mut reader = futures_lite::io::Cursor::new(data[..3000].to_vec());
            let bytes = read_whole(&mut reader, Some(3000), XML_CAP, MAX_RESERVE)
                .await
                .unwrap();
            assert_eq!(bytes.len(), 3000);
            assert!(bytes.capacity() <= 3001, "{}", bytes.capacity());
            // A body past the limit fails.
            let mut reader = futures_lite::io::Cursor::new(vec![b'x'; 11]);
            let err = read_whole(&mut reader, None, 10, MAX_RESERVE)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), ErrorKind::FileTooLarge);
        });
    }

    /// A read with a reserve over 4 MiB reserves a declared length whole, at
    /// once. With no declared length, it reserves 8 KiB first.
    #[test]
    fn a_whole_read_reserves_a_declared_length_at_once() {
        ostrya_rt::block_on(async {
            let size = 2 * XML_CAP as usize + 5;
            let limit = 4 * XML_CAP;
            /// A reader that records the length of the buffer of its first
            /// read.
            struct First {
                data: futures_lite::io::Cursor<Vec<u8>>,
                first: Option<usize>,
            }
            impl AsyncRead for First {
                fn poll_read(
                    mut self: Pin<&mut Self>,
                    cx: &mut Context<'_>,
                    buf: &mut [u8],
                ) -> Poll<std::io::Result<usize>> {
                    self.first.get_or_insert(buf.len());
                    Pin::new(&mut self.data).poll_read(cx, buf)
                }
            }
            let mut reader = First {
                data: futures_lite::io::Cursor::new(vec![b'x'; size]),
                first: None,
            };
            let bytes = read_whole(&mut reader, Some(size as u64), limit, limit)
                .await
                .unwrap();
            assert_eq!(bytes.len(), size);
            assert_eq!(reader.first, Some(size + 1));
            assert!(bytes.capacity() <= size + 1, "{}", bytes.capacity());
            // The listing reserve caps the first read at 4 MiB.
            let mut reader = First {
                data: futures_lite::io::Cursor::new(vec![b'x'; size]),
                first: None,
            };
            read_whole(&mut reader, Some(size as u64), limit, MAX_RESERVE)
                .await
                .unwrap();
            assert_eq!(reader.first, Some(XML_CAP as usize + 1));
            // No declared length: 8 KiB first, whatever the reserve.
            let mut reader = First {
                data: futures_lite::io::Cursor::new(vec![b'x'; size]),
                first: None,
            };
            read_whole(&mut reader, None, limit, limit).await.unwrap();
            assert_eq!(reader.first, Some(FIRST_READ as usize + 1));
        });
    }

    #[test]
    fn a_stream_hashes_only_at_its_exact_length() {
        ostrya_rt::block_on(async {
            let data = vec![b'h'; 3 * COMPARE_CHUNK + 7];
            let size = data.len() as u64;
            let digest: [u8; 32] = Sha256::digest(&data).into();
            let mut reader = futures_lite::io::Cursor::new(data.clone());
            assert_eq!(hash_exact(&mut reader, size).await.unwrap(), Some(digest));
            let mut reader = futures_lite::io::Cursor::new(data.clone());
            assert_eq!(hash_exact(&mut reader, size - 1).await.unwrap(), None);
            let mut reader = futures_lite::io::Cursor::new(data);
            assert_eq!(hash_exact(&mut reader, size + 1).await.unwrap(), None);
        });
    }
}
