//! The client of a bucket repository.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_io::AsyncRead;
use futures_lite::io::AsyncReadExt;
use ostrya_fetch::{
    Body, ErrorResponse, FetchRequest, Fetched, Fetcher, Target, UploadBody, UploadMethod,
    UploadRequest, Uploaded,
};
use quick_xml::escape::partial_escape;
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

/// The largest body of one `PUT`: 5 GiB, the S3 limit. It is also the
/// largest part of a multipart upload.
const MAX_PUT: u64 = 5 * 1024 * 1024 * 1024;

/// One MiB.
const MIB: u64 = 1024 * 1024;

/// The smallest part size of [`Bucket::put_stream`]: 5 MiB, the S3 limit of
/// each part other than the last part.
const MIN_PART: u64 = 5 * MIB;

/// The smallest part size that [`part_size`] gives: 8 MiB.
const DEFAULT_PART: u64 = 8 * MIB;

/// The largest number of parts of one multipart upload: 10,000, the S3
/// limit.
const MAX_PARTS: u32 = 10_000;

/// The largest upload id and the largest `ETag` of a part that the client
/// takes: 1 KiB. So the `ETag` values of an upload and the document that
/// completes it have a limit.
const MAX_UPLOAD_TOKEN: usize = 1024;

/// The namespace of the S3 documents.
const S3_NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

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
/// - `refs/mirrors/<id>/<name>`, with an id of at most 255 bytes that
///   [`is_collection_id`](ostrya_core::is_collection_id) accepts, and a ref
///   name that [`is_ref_name`](ostrya_core::is_ref_name) accepts
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
/// The client sends a `PUT`, a `DELETE`, and the `POST` that starts a
/// multipart upload again after
/// [`Error::UploadInterrupted`](ostrya_fetch::Error::UploadInterrupted) and
/// after a 408, 429, or 5xx, at most
/// [`max_retries`](ostrya_fetch::FetcherOptions::max_retries) times. The
/// delay starts at 250 ms, doubles each time, and stops at 2 s.
/// [`put_if_absent`](Bucket::put_if_absent) and
/// [`delete_if_match`](Bucket::delete_if_match) state their own rules, and
/// [`put_stream`](Bucket::put_stream) states more rules for the `POST`
/// requests of a multipart upload.
///
/// The client follows no redirect. The body of each listing, of each answer
/// to a request of a multipart upload, and of each error response is at most
/// 4 MiB.
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

/// The body of an object that [`Bucket::get_stream`] and
/// [`Bucket::get_stream_strict`] give.
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
    /// request with an unknown outcome found other bytes. Or a read after a
    /// 412 that followed a request with an unknown outcome found no object.
    Present,
    /// The key holds the bytes of the body, and no answer of the server
    /// states which writer put them there.
    ///
    /// A request of this call had an unknown outcome. Then a failed request
    /// followed, and a read of the key found the same bytes. A request of
    /// this call can have written them, or an earlier writer of the same
    /// bytes.
    Matches {
        /// The `ETag` of the read of the key, as the server wrote it.
        etag: Option<String>,
    },
    /// The key holds the bytes of the body, and the server answered 412 to
    /// a request of this call.
    ///
    /// A request of this call had an unknown outcome. Then a request got
    /// 412, and a read of the key found the same bytes. A request of this
    /// call can have written them, or an earlier writer of the same bytes.
    /// The 412 shows that the server honors `If-None-Match`.
    Refused {
        /// The `ETag` of the read of the key, as the server wrote it.
        etag: Option<String>,
    },
}

/// The outcome of [`Bucket::delete_if_match`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteIfMatch {
    /// The key holds no object after the call. A request of the call
    /// deleted it, or the key was absent at a read after a request with an
    /// unknown outcome.
    Deleted,
    /// The key did not hold an object with the `ETag` at the first request:
    /// the server answered 412, or the key was absent. Or the read after a
    /// request with an unknown outcome found an object.
    NotMatched,
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
    /// response names. [`get_strict`](Bucket::get_strict) reads a key by a
    /// strict rule.
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
        self.get_whole(key, max_size, is_absent).await
    }

    /// Reads the object of `key` whole, or returns `None` if the key holds no
    /// object, by a strict rule of an absent key.
    ///
    /// A 404 is an absent key only if its body arrived whole and holds the
    /// code `NoSuchKey`. Each other 404 is an error, also a 404 with an empty
    /// body or with a body that is not an S3 `Error` document, for example a
    /// page of a proxy. Use this call where a false absent key causes a loss
    /// of data. Else the call is [`get`](Bucket::get).
    ///
    /// # Errors
    ///
    /// The errors of [`get`](Bucket::get). A 404 that is not an absent key
    /// gives [`Error::S3`] with the status 404, and with no code if the body
    /// holds no S3 code.
    pub async fn get_strict(&self, key: &str, max_size: u64) -> Result<Option<Object>> {
        self.get_whole(key, max_size, is_no_such_key).await
    }

    /// Reads the object of `key` whole, as [`get`](Bucket::get) does, with
    /// `absent` as the rule of an absent key.
    async fn get_whole(
        &self,
        key: &str,
        max_size: u64,
        absent: fn(u16, Option<&[u8]>) -> bool,
    ) -> Result<Option<Object>> {
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
                    self.absent_or_error(e, &full, max_size, absent)?;
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
        self.open_stream(key, is_absent).await
    }

    /// Opens the body of the object of `key` as a stream, or returns `None`
    /// if the key holds no object, by the strict rule of an absent key of
    /// [`get_strict`](Bucket::get_strict).
    ///
    /// The stream holds no more than one chunk of the object in memory.
    ///
    /// # Errors
    ///
    /// The errors of [`get_stream`](Bucket::get_stream). A 404 that is not an
    /// absent key gives [`Error::S3`] with the status 404, and with no code
    /// if the body holds no S3 code.
    pub async fn get_stream_strict(&self, key: &str) -> Result<Option<ObjectStream>> {
        self.open_stream(key, is_no_such_key).await
    }

    /// Opens the body of the object of `key` as a stream, as
    /// [`get_stream`](Bucket::get_stream) does, with `absent` as the rule of
    /// an absent key.
    async fn open_stream(
        &self,
        key: &str,
        absent: fn(u16, Option<&[u8]>) -> bool,
    ) -> Result<Option<ObjectStream>> {
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
                self.absent_or_error(e, &full, u64::MAX, absent)?;
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
        self.put_body(&full, &path, UploadBody::bytes(body)).await
    }

    /// Writes the bytes that `body` gives to `key`, and returns the `ETag`
    /// of the answer that wrote the object, as the server wrote it.
    ///
    /// Servers give different `ETag` values for one object of several
    /// parts. Do not compare the result with the `ETag` of a later read of
    /// the key.
    ///
    /// The call reads `body` in parts of `part_size` bytes. [`part_size`]
    /// gives the part size of an object of a known size. A body of at most
    /// one part goes in one `PUT`. A longer body goes in a multipart upload:
    ///
    /// 1. `POST KEY?uploads` starts the upload and gives the upload id.
    /// 2. `PUT KEY?partNumber=N&uploadId=ID` sends each part, one part after
    ///    the other. The part numbers start at 1 and have no gap. Each part
    ///    other than the last one holds `part_size` bytes.
    /// 3. `POST KEY?uploadId=ID` with a `CompleteMultipartUpload` document
    ///    completes the upload. The document gives each part number with the
    ///    `ETag` of its answer, as the server wrote it.
    ///
    /// The call holds one part in memory, with the `ETag` of each part that
    /// it sent and the document that completes the upload. The first part
    /// starts at 8 KiB and doubles up to `part_size` while the bytes arrive,
    /// so a small body takes a small buffer. After each part, the call takes
    /// the buffer back and reads the next part into it. If the fetcher still
    /// holds the bytes of a part, the next part takes a new buffer. After a
    /// full part, the call reads one byte more to find if the body goes on.
    /// The signer hashes each part on the task of the call, before each
    /// request.
    ///
    /// The client takes an upload id and an `ETag` of a part of at most
    /// 1 KiB each. So the `ETag` values of an upload and the document that
    /// completes it have a limit.
    ///
    /// The client sends each part again by the rule of [`Bucket`]. A part
    /// has the same bytes in each request. The `POST` that starts the upload
    /// is sent again by the same rule, and also after a 2xx whose body did
    /// not arrive. The `POST` that completes the upload is sent again after
    /// an interrupted request, after a 408, 429, or 5xx, after a 2xx whose
    /// body cannot be read, and after a 2xx whose body is an S3 `Error`
    /// document. S3 can send such a document after the head of a 200.
    ///
    /// After an interrupted request, a 408, 429, or 5xx, or an unusable 2xx
    /// to the `POST` that completes the upload, the server can have
    /// completed the upload. If a later request then gets a 404 with the code
    /// `NoSuchUpload`, the client reads the key as
    /// [`get_stream`](Bucket::get_stream) does. A `Content-Length` equal to
    /// the number of bytes of the body gives success with the `ETag` of the
    /// read, and the client reads no byte of the object. An absent object and
    /// an object of another length give an error.
    ///
    /// This check compares the length alone. It is sound for a key whose
    /// name sets its content, such as a content-addressed object or a static
    /// delta. For a key whose content changes, an older object of the same
    /// length passes the check.
    ///
    /// After each failure that comes after the start of the upload, the
    /// client sends one `DELETE KEY?uploadId=ID` to abort the upload, and
    /// ignores its outcome. Then it returns the error of the failure. If the
    /// last answer to a request of the upload is a 404 with the code
    /// `NoSuchUpload`, the server holds no such upload, and the client sends
    /// no abort.
    ///
    /// A dropped future sends no abort, so the upload stays open, and it
    /// holds storage in the bucket. [`list_uploads`](Bucket::list_uploads)
    /// gives each such upload, and [`abort_upload`](Bucket::abort_upload)
    /// aborts it. To remove such uploads with no call of the client, set a
    /// lifecycle rule on the bucket that aborts incomplete multipart uploads.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `key` is not a key of a bucket repository,
    ///   or if `part_size` is less than 5 MiB or more than 5 GiB, the S3
    ///   limits of a part. The call then reads no byte of `body`.
    /// - [`Error::Io`] if a read of `body` fails.
    /// - [`Error::LimitExceeded`] if the body is longer than 10,000 parts of
    ///   `part_size` bytes, the S3 limit of the parts of an upload. The
    ///   message names the key and the part size.
    /// - [`Error::S3`] and [`Error::S3Region`] for an unsuccessful response,
    ///   and [`Error::S3`] for an S3 `Error` document with a 2xx after the
    ///   last request that the client sent again.
    /// - [`Error::Transport`] if the answer that starts the upload has no
    ///   usable upload id or an upload id of more than 1 KiB, if its body did
    ///   not arrive after the last request that the client sent again, if the
    ///   answer to a part has no `ETag` or an `ETag` of more than 1 KiB, or if
    ///   no answer that completes the upload can be read. Also if the key
    ///   holds no object or an object of another length after a 404
    ///   `NoSuchUpload` to a completion whose outcome is not known. The
    ///   message then states what the key holds.
    /// - The errors of [`get_stream`](Bucket::get_stream) for the read of
    ///   the key after such a 404 `NoSuchUpload`.
    /// - [`Error::Fetch`] for a failure of the fetcher, also after the last
    ///   request that the client sent again.
    pub async fn put_stream<R>(&self, key: &str, body: R, part_size: u64) -> Result<Option<String>>
    where
        R: AsyncRead + Unpin + Send,
    {
        check_key(key)?;
        let size = usize::try_from(part_size)
            .ok()
            .filter(|_| (MIN_PART..=MAX_PUT).contains(&part_size))
            .ok_or_else(|| {
                Error::InvalidInput(format!(
                    "S3: the part size {part_size} of {key} is outside the range of \
                     {MIN_PART} to {MAX_PUT} bytes of a part"
                ))
            })?;
        self.put_parts(key, Parts::new(body, size, MAX_PARTS)).await
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
    /// [`PutIfAbsent::Refused`], and other bytes or an absent key give
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
                .send(UploadMethod::Put, &path, "", copy(&body), &headers)
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
                        Compared::Same(etag) => PutIfAbsent::Refused { etag },
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
            match self
                .send(UploadMethod::Delete, &path, "", empty, &[])
                .await?
            {
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

    /// Deletes the object of `key` if its `ETag` is `etag`.
    ///
    /// The request is `DELETE KEY` with `If-Match: ETAG`. `etag` goes as the
    /// server wrote it, for example the [`etag`](Object::etag) of a read. A
    /// 2xx gives [`DeleteIfMatch::Deleted`]. A 412 or an absent key to the
    /// first request gives [`DeleteIfMatch::NotMatched`].
    /// [`get`](Bucket::get) states the rule of an absent key. SeaweedFS 4.36
    /// answers 412 for an absent key.
    ///
    /// The client sends the request again by the rule of [`Bucket`]. A 412
    /// or an absent key after a request with an unknown outcome can answer a
    /// request of this call. So the client then reads the key as
    /// [`get_stream`](Bucket::get_stream) does, and reads no byte of the
    /// object. An absent key gives [`DeleteIfMatch::Deleted`], and an object
    /// gives [`DeleteIfMatch::NotMatched`].
    ///
    /// A server that does not honor `If-Match` deletes the object whatever
    /// its `ETag` is, and gives [`DeleteIfMatch::Deleted`].
    /// `rclone serve s3` 1.75.1 is such a server.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `key` is not a key of a bucket repository,
    ///   or if `etag` is empty or longer than 1 KiB. The client then sends no
    ///   request.
    /// - [`Error::S3`] and [`Error::S3Region`] for an unsuccessful response.
    /// - [`Error::Fetch`] for a failure of the fetcher, also after the last
    ///   request that the client sent again.
    /// - The errors of [`get_stream`](Bucket::get_stream) for the read of
    ///   the key.
    pub async fn delete_if_match(&self, key: &str, etag: &str) -> Result<DeleteIfMatch> {
        check_key(key)?;
        if etag.is_empty() || etag.len() > MAX_UPLOAD_TOKEN {
            return Err(Error::InvalidInput(format!(
                "S3: the ETag of a conditional delete of {key} is empty or longer than \
                 {MAX_UPLOAD_TOKEN} bytes"
            )));
        }
        let full = self.full_key(key);
        let path = encode_path(&full);
        let headers = [("If-Match".to_owned(), etag.to_owned())];
        let mut round = 0;
        // `true` after a request whose outcome is not known.
        let mut unsure = false;
        loop {
            let empty = UploadBody::bytes(Vec::new());
            match self
                .send(UploadMethod::Delete, &path, "", empty, &headers)
                .await?
            {
                Sent::Reply(reply) if is_success(reply.status) => {
                    return Ok(DeleteIfMatch::Deleted);
                }
                Sent::Reply(reply)
                    if reply.status == 412 || is_absent(reply.status, reply.body.as_deref()) =>
                {
                    if !unsure {
                        return Ok(DeleteIfMatch::NotMatched);
                    }
                    return Ok(match self.get_stream(key).await? {
                        Some(_) => DeleteIfMatch::NotMatched,
                        None => DeleteIfMatch::Deleted,
                    });
                }
                Sent::Reply(reply) if is_retryable(reply.status) && round < self.max_retries => {
                    unsure = true;
                }
                Sent::Reply(reply) => return Err(self.reply_error(reply, Some(&full))),
                Sent::Interrupted(_) if round < self.max_retries => unsure = true,
                Sent::Interrupted(e) => return Err(Error::Fetch(e)),
            }
            round += 1;
            ostrya_rt::Timer::after(backoff(round)).await;
        }
    }

    /// Aborts the multipart upload `upload_id` of `key`.
    ///
    /// The request is `DELETE KEY?uploadId=ID`. A 2xx and a 404 with the
    /// code `NoSuchUpload` are success, so an upload that a server already
    /// removed is not an error. The client sends the request again by the
    /// rule of [`Bucket`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidInput`] if `key` is not a key of a bucket repository,
    ///   or if `upload_id` is empty.
    /// - [`Error::S3`] and [`Error::S3Region`] for an unsuccessful response.
    /// - [`Error::Fetch`] for a failure of the fetcher, also after the last
    ///   request that the client sent again.
    pub async fn abort_upload(&self, key: &str, upload_id: &str) -> Result<()> {
        check_key(key)?;
        if upload_id.is_empty() {
            return Err(Error::InvalidInput(format!(
                "S3: the upload id of an abort of {key} is empty"
            )));
        }
        let full = self.full_key(key);
        let path = encode_path(&full);
        let query = upload_query(upload_id);
        let empty = UploadBody::bytes(Vec::new());
        let reply = self
            .send_retrying(UploadMethod::Delete, &path, &query, &empty)
            .await?;
        if is_success(reply.status) || is_no_such_upload(&reply) {
            return Ok(());
        }
        Err(self.reply_error(reply, Some(&full)))
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

    /// Sends one upload request of `method` to `path` with the query
    /// `query`, `body`, and `headers`, and reads the answer whole. An empty
    /// query is no query.
    async fn send(
        &self,
        method: UploadMethod,
        path: &str,
        query: &str,
        body: UploadBody,
        headers: &[(String, String)],
    ) -> Result<Sent> {
        let target = self.target(path, query);
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

    /// Sends one request of `method` to `path` with the query `query` and
    /// `body` by the rule of [`Bucket`], and returns the last answer.
    ///
    /// The client sends the request again after an interrupted request and
    /// after a 408, 429, or 5xx, at most `max_retries` times. Each request
    /// shares the bytes of `body`.
    async fn send_retrying(
        &self,
        method: UploadMethod,
        path: &str,
        query: &str,
        body: &UploadBody,
    ) -> Result<Reply> {
        let mut round = 0;
        loop {
            match self.send(method, path, query, copy(body), &[]).await? {
                Sent::Reply(reply) if is_retryable(reply.status) && round < self.max_retries => {}
                Sent::Reply(reply) => return Ok(reply),
                Sent::Interrupted(_) if round < self.max_retries => {}
                Sent::Interrupted(e) => return Err(Error::Fetch(e)),
            }
            round += 1;
            ostrya_rt::Timer::after(backoff(round)).await;
        }
    }

    /// Writes `body` to the full key `full`, whose encoded path is `path`,
    /// with one `PUT`, and returns the `ETag` of the answer.
    async fn put_body(&self, full: &str, path: &str, body: UploadBody) -> Result<Option<String>> {
        let reply = self
            .send_retrying(UploadMethod::Put, path, "", &body)
            .await?;
        if is_success(reply.status) {
            return Ok(reply.etag);
        }
        Err(self.reply_error(reply, Some(full)))
    }

    /// Writes the parts that `parts` reads to `key`, with one `PUT` for a
    /// body of one part and a multipart upload for a longer body.
    async fn put_parts<R: AsyncRead + Unpin>(
        &self,
        key: &str,
        mut parts: Parts<R>,
    ) -> Result<Option<String>> {
        let full = self.full_key(key);
        let path = encode_path(&full);
        let first = parts.next().await.map_err(|stop| stop.error(&full))?;
        if first.last {
            return self
                .put_body(&full, &path, UploadBody::bytes(first.bytes))
                .await;
        }
        let upload_id = self.create_upload(&full, &path).await?;
        let query = upload_query(&upload_id);
        match self
            .send_parts(key, &full, &path, &query, first, parts)
            .await
        {
            Ok(etag) => Ok(etag),
            // The server holds no such upload, so the client sends no abort.
            Err(Failed { error, gone: true }) => Err(error),
            Err(Failed { error, gone: false }) => {
                // One abort, sent once. Its outcome does not change the
                // error of the call.
                let empty = UploadBody::bytes(Vec::new());
                let _ = self
                    .send(UploadMethod::Delete, &path, &query, empty, &[])
                    .await;
                Err(error)
            }
        }
    }

    /// Sends `first` and each later part that `parts` reads to the upload
    /// of the query `query`, and completes the upload.
    ///
    /// After each part other than the last one, `parts` takes the buffer of
    /// the part back for the next part.
    async fn send_parts<R: AsyncRead + Unpin>(
        &self,
        key: &str,
        full: &str,
        path: &str,
        query: &str,
        first: Part,
        mut parts: Parts<R>,
    ) -> std::result::Result<Option<String>, Failed> {
        let mut etags = Vec::new();
        let mut sent = 0u64;
        let mut part = first;
        loop {
            sent += part.bytes.len() as u64;
            let last = part.last;
            let (etag, body) = self.upload_part(full, path, query, part).await?;
            etags.push(etag);
            if last {
                break;
            }
            parts.recycle(body);
            part = parts.next().await.map_err(|stop| stop.error(full))?;
        }
        let body = UploadBody::bytes(complete_body(&etags));
        drop(etags);
        self.complete_upload(key, full, path, query, body, sent)
            .await
    }

    /// Starts a multipart upload of the full key `full`, and returns its
    /// upload id.
    ///
    /// The client sends the request again by the rule of [`Bucket`], and
    /// also after a 2xx whose body did not arrive.
    async fn create_upload(&self, full: &str, path: &str) -> Result<String> {
        let unusable = |why: &str| {
            self.unusable(&format!(
                "the answer that starts the multipart upload of {full}: {why}"
            ))
        };
        let mut round = 0;
        loop {
            let empty = UploadBody::bytes(Vec::new());
            let failure = match self
                .send(UploadMethod::Post, path, "uploads", empty, &[])
                .await?
            {
                Sent::Reply(reply) if is_success(reply.status) => match reply.body.as_deref() {
                    // A body that failed in transit counts as an interrupted
                    // request.
                    None => unusable("the body did not arrive"),
                    Some(body) => {
                        return match xml::initiate(body).map_err(|why| unusable(&why))? {
                            Doc::Result(upload_id) if upload_id.len() > MAX_UPLOAD_TOKEN => {
                                Err(unusable(&format!(
                                    "the UploadId has more than {MAX_UPLOAD_TOKEN} bytes"
                                )))
                            }
                            Doc::Result(upload_id) => Ok(upload_id),
                            Doc::Error(doc) => Err(self.answer_error(
                                reply.status,
                                reply.region.as_deref(),
                                Some(doc),
                                Some(full),
                            )),
                        };
                    }
                },
                Sent::Reply(reply) if is_retryable(reply.status) => {
                    self.reply_error(reply, Some(full))
                }
                Sent::Reply(reply) => return Err(self.reply_error(reply, Some(full))),
                Sent::Interrupted(e) => Error::Fetch(e),
            };
            if round >= self.max_retries {
                return Err(failure);
            }
            round += 1;
            ostrya_rt::Timer::after(backoff(round)).await;
        }
    }

    /// Sends `part` to the upload of the query `query`, and returns the
    /// `ETag` of the answer with the body of the part.
    async fn upload_part(
        &self,
        full: &str,
        path: &str,
        query: &str,
        part: Part,
    ) -> std::result::Result<(String, UploadBody), Failed> {
        let number = part.number;
        let query = format!("partNumber={number}&{query}");
        let body = UploadBody::bytes(part.bytes);
        let reply = self
            .send_retrying(UploadMethod::Put, path, &query, &body)
            .await?;
        if !is_success(reply.status) {
            return Err(self.upload_failed(reply, full));
        }
        let why = match reply.etag {
            Some(etag) if etag.len() <= MAX_UPLOAD_TOKEN => return Ok((etag, body)),
            Some(_) => format!("an ETag of more than {MAX_UPLOAD_TOKEN} bytes"),
            None => "no ETag".to_owned(),
        };
        Err(self
            .unusable(&format!("the answer to part {number} of {full} has {why}"))
            .into())
    }

    /// Completes the upload of the query `query` with the
    /// `CompleteMultipartUpload` document `body`, and returns the `ETag` of
    /// the object. `sent` is the number of bytes of the parts.
    ///
    /// After an unsure request, a 404 with the code `NoSuchUpload` makes the
    /// client read the key `key`, by the rule of [`Bucket::put_stream`].
    async fn complete_upload(
        &self,
        key: &str,
        full: &str,
        path: &str,
        query: &str,
        body: UploadBody,
        sent: u64,
    ) -> std::result::Result<Option<String>, Failed> {
        let mut round = 0;
        // `true` after a request whose outcome is not known.
        let mut unsure = false;
        loop {
            let failure = match self
                .send(UploadMethod::Post, path, query, copy(&body), &[])
                .await?
            {
                Sent::Reply(reply) if is_success(reply.status) => {
                    unsure = true;
                    match reply.body.as_deref().map(xml::complete) {
                        Some(Ok(Doc::Result(etag))) => return Ok(etag.or(reply.etag)),
                        Some(Ok(Doc::Error(doc))) => self.answer_error(
                            reply.status,
                            reply.region.as_deref(),
                            Some(doc),
                            Some(full),
                        ),
                        Some(Err(why)) => self.unusable(&format!(
                            "the answer that completes the multipart upload of {full}: {why}"
                        )),
                        None => self.unusable(&format!(
                            "the answer that completes the multipart upload of {full}: the \
                             body did not arrive"
                        )),
                    }
                }
                Sent::Reply(reply) if unsure && is_no_such_upload(&reply) => {
                    return self
                        .completed_object(key, full, sent)
                        .await
                        .map_err(|error| Failed { error, gone: true });
                }
                Sent::Reply(reply) if is_retryable(reply.status) => {
                    unsure = true;
                    self.reply_error(reply, Some(full))
                }
                Sent::Reply(reply) => return Err(self.upload_failed(reply, full)),
                Sent::Interrupted(e) => {
                    unsure = true;
                    Error::Fetch(e)
                }
            };
            if round >= self.max_retries {
                return Err(failure.into());
            }
            round += 1;
            ostrya_rt::Timer::after(backoff(round)).await;
        }
    }

    /// Reads the key `key`, whose full key is `full`, after a 404 with the
    /// code `NoSuchUpload` to the completion of its upload, and returns the
    /// `ETag` of the object if its declared length is `sent`.
    ///
    /// The client reads no byte of the object.
    async fn completed_object(&self, key: &str, full: &str, sent: u64) -> Result<Option<String>> {
        let held = match self.get_stream(key).await? {
            Some(stream) => match stream.content_length() {
                Some(length) if length == sent => return Ok(stream.etag),
                Some(length) => format!("an object of {length} bytes"),
                None => "an object of no declared length".to_owned(),
            },
            None => "no object".to_owned(),
        };
        Err(self.unusable(&format!(
            "the answer that completes the multipart upload of {full} is 404 NoSuchUpload \
             after a request with no known outcome, and the key holds {held}, not the \
             {sent} bytes of the parts"
        )))
    }

    /// Returns the failure of an unsuccessful `reply` to a request of the
    /// multipart upload of the full key `full`.
    fn upload_failed(&self, reply: Reply, full: &str) -> Failed {
        let gone = is_no_such_upload(&reply);
        Failed {
            error: self.reply_error(reply, Some(full)),
            gone,
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
                    self.absent_or_error(e, full, u64::MAX, is_absent)?;
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
    /// the key holds no object by the rule `absent`, and the error of the
    /// fetch otherwise.
    ///
    /// The absent-key rule runs before the region check, so an absent key is
    /// never a region error.
    fn absent_or_error(
        &self,
        e: ostrya_fetch::Error,
        full: &str,
        max_size: u64,
        absent: fn(u16, Option<&[u8]>) -> bool,
    ) -> Result<()> {
        match e {
            ostrya_fetch::Error::FetchTooLarge { .. } => Err(too_large(full, max_size)),
            ostrya_fetch::Error::HttpStatus {
                status, response, ..
            } => {
                let response = response.as_deref();
                if absent(status, response.and_then(ErrorResponse::body)) {
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
    /// other field.
    fn upload(&self, body: UploadBody) -> UploadRequest<'_> {
        match self {
            RequestTarget::Mirror { path, query: "" } => UploadRequest::path(path, body),
            RequestTarget::Mirror { path, query } => UploadRequest {
                target: Target::PathQuery { path, query },
                ..UploadRequest::path(path, body)
            },
            RequestTarget::Url(url) => UploadRequest::url(url, body),
        }
    }
}

/// Returns the part size of a multipart upload of an object of `size`
/// bytes.
///
/// The part size is the larger of 8 MiB and `(2 * size + 1 MiB) / 10,000`,
/// rounded up to a whole MiB. So 10,000 parts hold `2 * size + 1 MiB` bytes,
/// more than the bytes of a `.filez` object whose file has `size` bytes of
/// content. The part size is 8 MiB up to a size of 41,942,515,712 bytes, and
/// 9 MiB from one byte more.
///
/// # Errors
///
/// [`Error::LimitExceeded`] if the part size is more than 5 GiB, the S3 limit
/// of a part. This is the case for a size of more than 26,843,545,075,712
/// bytes.
pub fn part_size(size: u64) -> Result<u64> {
    let too_large = || {
        Error::LimitExceeded(format!(
            "S3: an object of {size} bytes needs parts of more than {MAX_PUT} bytes, the limit \
             of a part"
        ))
    };
    let span = size
        .checked_mul(2)
        .and_then(|span| span.checked_add(MIB))
        .ok_or_else(too_large)?;
    let part = span
        .div_ceil(u64::from(MAX_PARTS) * MIB)
        .checked_mul(MIB)
        .ok_or_else(too_large)?
        .max(DEFAULT_PART);
    if part > MAX_PUT {
        return Err(too_large());
    }
    Ok(part)
}

/// One part of a body that [`Parts`] read.
struct Part {
    /// The part number, from 1.
    number: u32,
    /// The bytes of the part.
    bytes: Vec<u8>,
    /// `true` if the body ends with this part.
    last: bool,
}

/// A failure of a multipart upload after its start.
struct Failed {
    /// The error of the call.
    error: Error,
    /// `true` if the last answer to a request of the upload is a 404 with
    /// the code `NoSuchUpload`. The server then holds no such upload, so the
    /// client sends no abort.
    gone: bool,
}

impl From<Error> for Failed {
    fn from(error: Error) -> Failed {
        Failed { error, gone: false }
    }
}

/// Why [`Parts::next`] gave no part.
enum Stop {
    /// A read of the body failed.
    Io(std::io::Error),
    /// The part with the largest number is full, and the body goes on.
    TooMany {
        /// The largest number of parts.
        max_parts: u32,
        /// The part size.
        part_size: usize,
    },
}

impl Stop {
    /// Returns the error of a stop of the parts of the full key `full`.
    fn error(self, full: &str) -> Error {
        match self {
            Stop::Io(e) => Error::Io(e),
            Stop::TooMany {
                max_parts,
                part_size,
            } => Error::LimitExceeded(format!(
                "S3: the body of {full} is longer than {max_parts} parts of {part_size} bytes"
            )),
        }
    }
}

/// The reader of the parts of a body, one part after the other.
struct Parts<R> {
    body: R,
    part_size: usize,
    max_parts: u32,
    /// The number of the last part that [`Parts::next`] gave.
    number: u32,
    /// The first byte of the next part, which the read after a full part
    /// gave.
    carry: Option<u8>,
    /// The buffer of an earlier part, which [`Parts::recycle`] took back.
    spare: Option<Vec<u8>>,
}

impl<R: AsyncRead + Unpin> Parts<R> {
    /// Returns the reader of the parts of `body`, each of `part_size` bytes
    /// other than the last one, at most `max_parts` parts.
    fn new(body: R, part_size: usize, max_parts: u32) -> Parts<R> {
        Parts {
            body,
            part_size,
            max_parts,
            number: 0,
            carry: None,
            spare: None,
        }
    }

    /// Reads the next part.
    ///
    /// The first part starts with no capacity and grows as [`fill`] states.
    /// A later part reads into the buffer that [`Parts::recycle`] took back,
    /// with no fill of zeros. Else it starts with the capacity of a whole
    /// part. After a full part, the reader reads one byte more to find if the
    /// body goes on, and keeps it for the next part. A full part with the
    /// number `max_parts` and a byte after it gives [`Stop::TooMany`].
    async fn next(&mut self) -> std::result::Result<Part, Stop> {
        let mut bytes = self.spare.take().unwrap_or_default();
        let mut filled = 0;
        if let Some(byte) = self.carry.take() {
            match bytes.first_mut() {
                Some(first) => *first = byte,
                None => {
                    bytes.reserve_exact(self.part_size);
                    bytes.push(byte);
                }
            }
            filled = 1;
        }
        let filled = fill(&mut self.body, &mut bytes, filled, self.part_size)
            .await
            .map_err(Stop::Io)?;
        bytes.truncate(filled);
        self.number += 1;
        let mut last = true;
        if bytes.len() == self.part_size {
            let mut probe = [0u8; 1];
            if self.body.read(&mut probe).await.map_err(Stop::Io)? == 1 {
                if self.number >= self.max_parts {
                    return Err(Stop::TooMany {
                        max_parts: self.max_parts,
                        part_size: self.part_size,
                    });
                }
                self.carry = Some(probe[0]);
                last = false;
            }
        }
        Ok(Part {
            number: self.number,
            bytes,
            last,
        })
    }

    /// Takes back the buffer of `body`, the body of a part that the upload
    /// sent, for the next part. A buffer that another body still shares
    /// stays with that body.
    fn recycle(&mut self, body: UploadBody) {
        self.spare = body.into_vec().ok();
    }
}

/// Reads from `body` into `buffer`, from the byte `filled`, until the
/// buffer holds `limit` bytes or the body ends, and returns the number of
/// bytes that the buffer holds. `buffer` has a length and a capacity of at
/// most `limit` bytes, and `filled` is at most its length.
///
/// The read overwrites the bytes of `buffer` past `filled`, with no fill of
/// zeros. When the read reaches the length of `buffer`, the length doubles,
/// from [`FIRST_READ`] bytes, up to `limit`, and only the new bytes are
/// zeros. The capacity grows with the length when it must, and never passes
/// `limit`.
async fn fill(
    body: &mut (impl AsyncRead + Unpin),
    buffer: &mut Vec<u8>,
    mut filled: usize,
    limit: usize,
) -> std::io::Result<usize> {
    loop {
        if filled == limit {
            return Ok(filled);
        }
        if filled == buffer.len() {
            let grown = filled.saturating_mul(2).max(FIRST_READ as usize).min(limit);
            buffer.reserve_exact(grown - filled);
            buffer.resize(grown, 0);
        }
        match body.read(&mut buffer[filled..]).await? {
            0 => return Ok(filled),
            n => filled += n,
        }
    }
}

/// Returns the query `uploadId=ID` of the upload `upload_id`.
fn upload_query(upload_id: &str) -> String {
    format!("uploadId={}", encode_query(upload_id))
}

/// Returns the `CompleteMultipartUpload` document of the parts whose `ETag`
/// values are `etags`, the first one for part 1.
///
/// Each `ETag` goes as the server wrote it, with `&`, `<`, and `>` escaped.
fn complete_body(etags: &[String]) -> Vec<u8> {
    let mut body = format!("<CompleteMultipartUpload xmlns=\"{S3_NAMESPACE}\">");
    for (number, etag) in (1u32..).zip(etags) {
        body.push_str(&format!(
            "<Part><PartNumber>{number}</PartNumber><ETag>{}</ETag></Part>",
            partial_escape(etag.as_str())
        ));
    }
    body.push_str("</CompleteMultipartUpload>");
    body.into_bytes()
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

/// Returns `true` if `reply` is a 404 with the code `NoSuchUpload`.
fn is_no_such_upload(reply: &Reply) -> bool {
    reply.status == 404 && reply_code(reply).is_some_and(|code| code.trim() == "NoSuchUpload")
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

/// Returns `true` if an answer with `status` and the whole body `body`
/// states an absent key by the strict rule: a 404 whose body holds the code
/// `NoSuchKey`.
///
/// `body` is `None` if the body did not arrive whole. A 404 with no S3 code
/// can come from a proxy or from a missing bucket, so it is not an absent
/// key.
fn is_no_such_key(status: u16, body: Option<&[u8]>) -> bool {
    status == 404
        && body
            .and_then(xml::error)
            .and_then(|doc| doc.code)
            .is_some_and(|code| code.trim() == "NoSuchKey")
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
    fn a_strict_absent_key_is_a_404_whose_body_has_no_such_key() {
        let coded = |code: &str| format!("<Error><Code>{code}</Code></Error>").into_bytes();
        assert!(is_no_such_key(404, Some(&coded("NoSuchKey"))));
        assert!(is_no_such_key(404, Some(&coded(" NoSuchKey\n"))));
        assert!(!is_no_such_key(404, Some(b"")));
        assert!(!is_no_such_key(404, Some(b"<html>Not Found</html>")));
        assert!(!is_no_such_key(
            404,
            Some(b"<Error><Message>m</Message></Error>")
        ));
        assert!(!is_no_such_key(404, Some(&coded("NoSuchBucket"))));
        assert!(!is_no_such_key(404, None));
        assert!(!is_no_such_key(403, Some(&coded("NoSuchKey"))));
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
    fn the_part_size_grows_by_whole_mib_past_8_mib() {
        assert_eq!(part_size(0).unwrap(), 8 * MIB);
        assert_eq!(part_size(41_942_515_712).unwrap(), 8 * MIB);
        assert_eq!(part_size(41_942_515_713).unwrap(), 9 * MIB);
        assert_eq!(part_size(26_843_545_075_712).unwrap(), MAX_PUT);
        for size in [26_843_545_075_713, u64::MAX / 2, u64::MAX] {
            let err = part_size(size).unwrap_err();
            assert!(matches!(err, Error::LimitExceeded(_)), "{size}: {err}");
        }
    }

    #[test]
    fn the_complete_document_lists_each_part_with_its_escaped_etag() {
        let etags = [
            "\"5d41402abc4b2a76b9719d911017c592\"".to_owned(),
            "\"a&b<c>\"".to_owned(),
        ];
        assert_eq!(
            String::from_utf8(complete_body(&etags)).unwrap(),
            "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Part><PartNumber>1</PartNumber>\
             <ETag>\"5d41402abc4b2a76b9719d911017c592\"</ETag></Part>\
             <Part><PartNumber>2</PartNumber><ETag>\"a&amp;b&lt;c&gt;\"</ETag></Part>\
             </CompleteMultipartUpload>"
        );
    }

    /// Reads each part of `data` with parts of `part_size` bytes, at most
    /// `max_parts` parts, and returns the parts or the stop.
    fn read_parts(
        data: &[u8],
        part_size: usize,
        max_parts: u32,
    ) -> std::result::Result<Vec<Part>, Stop> {
        ostrya_rt::block_on(async {
            let mut parts = Parts::new(futures_lite::io::Cursor::new(data), part_size, max_parts);
            let mut read = Vec::new();
            loop {
                let part = parts.next().await?;
                let last = part.last;
                read.push(part);
                if last {
                    return Ok(read);
                }
            }
        })
    }

    #[test]
    fn a_body_reads_as_numbered_parts_with_a_probe_byte_between_them() {
        let data: Vec<u8> = (0..10u8).collect();
        let Ok(parts) = read_parts(&data, 4, 3) else {
            panic!("three parts of four bytes hold ten bytes");
        };
        let found: Vec<(u32, &[u8], bool)> = parts
            .iter()
            .map(|part| (part.number, part.bytes.as_slice(), part.last))
            .collect();
        assert_eq!(
            found,
            [
                (1, &data[..4], false),
                (2, &data[4..8], false),
                (3, &data[8..], true)
            ]
        );
        // A body of whole parts ends with a full part, and an empty body is
        // one empty part.
        let parts = read_parts(&data[..8], 4, 3).ok().unwrap();
        assert_eq!(parts.len(), 2);
        assert!(parts[1].last && parts[1].bytes == data[4..8]);
        let parts = read_parts(&[], 4, 3).ok().unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].last && parts[0].bytes.is_empty());
    }

    #[test]
    fn a_body_past_the_last_part_stops_at_the_probe_byte() {
        assert!(read_parts(&[7u8; 12], 4, 3).is_ok());
        match read_parts(&[7u8; 13], 4, 3) {
            Err(Stop::TooMany {
                max_parts: 3,
                part_size: 4,
            }) => {}
            Err(Stop::TooMany { .. }) => panic!("another limit"),
            Err(Stop::Io(e)) => panic!("{e}"),
            Ok(parts) => panic!("{} parts", parts.len()),
        }
        let err = Stop::TooMany {
            max_parts: 3,
            part_size: 4,
        }
        .error("repo/config");
        assert!(matches!(err, Error::LimitExceeded(_)), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("repo/config") && text.contains("3 parts of 4 bytes"),
            "{text}"
        );
    }

    #[test]
    fn a_part_holds_no_capacity_past_the_part_size() {
        // The first part grows from 8 KiB: a small body takes a small
        // buffer.
        let small = read_parts(&[1u8; 100], 1 << 20, 3).ok().unwrap();
        assert_eq!(small[0].bytes.len(), 100);
        assert_eq!(small[0].bytes.capacity(), FIRST_READ as usize);
        // A part size that is not a power of two: the doubling stops at the
        // part size, and a later part with no buffer to take back takes the
        // capacity of a whole part at once.
        let size = 3 * FIRST_READ as usize + 5;
        let data = vec![2u8; 2 * size + 1];
        let parts = read_parts(&data, size, 3).ok().unwrap();
        assert_eq!(parts.len(), 3);
        for part in &parts[..2] {
            assert_eq!(part.bytes.len(), size);
            assert_eq!(part.bytes.capacity(), size);
        }
        assert_eq!(parts[2].bytes, [2u8]);
        assert_eq!(parts[2].bytes.capacity(), size);
    }

    #[test]
    fn a_later_part_reads_into_the_buffer_that_came_back() {
        /// A reader of `data` that counts the zero bytes of each buffer of
        /// more than one byte that it gets. The probe after a full part
        /// reads into a buffer of one byte.
        struct Counting {
            data: futures_lite::io::Cursor<Vec<u8>>,
            zeros: usize,
        }
        impl AsyncRead for Counting {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                if buf.len() > 1 {
                    self.zeros += buf.iter().filter(|byte| **byte == 0).count();
                }
                Pin::new(&mut self.data).poll_read(cx, buf)
            }
        }
        let size = 3 * FIRST_READ as usize + 5;
        let data: Vec<u8> = (0..3 * size + 1).map(|at| (at % 255) as u8 + 1).collect();
        ostrya_rt::block_on(async {
            let mut parts = Parts::new(
                Counting {
                    data: futures_lite::io::Cursor::new(data.clone()),
                    zeros: 0,
                },
                size,
                4,
            );
            // The first part grows, and the fill of zeros comes with the
            // growth.
            let first = parts.next().await.ok().unwrap();
            let zeros = parts.body.zeros;
            assert!(zeros > 0);
            let address = first.bytes.as_ptr();
            // No copy shares the body, so the second part reads into the
            // same buffer with no fill of zeros.
            parts.recycle(UploadBody::bytes(first.bytes));
            let second = parts.next().await.ok().unwrap();
            assert_eq!(second.bytes, data[size..2 * size]);
            assert_eq!(second.bytes.as_ptr(), address);
            assert_eq!(second.bytes.capacity(), size);
            assert_eq!(parts.body.zeros, zeros);
            // A copy shares the body, so the third part takes a new buffer.
            let body = UploadBody::bytes(second.bytes);
            let shared = body.try_clone().unwrap();
            parts.recycle(body);
            let third = parts.next().await.ok().unwrap();
            assert_eq!(third.bytes, data[2 * size..3 * size]);
            assert_ne!(third.bytes.as_ptr(), address);
            assert_eq!(third.bytes.capacity(), size);
            assert_eq!(shared.as_bytes(), Some(&data[size..2 * size]));
            let zeros = parts.body.zeros;
            // A short last part reads into the buffer that came back, with
            // no fill of zeros.
            let address = third.bytes.as_ptr();
            parts.recycle(UploadBody::bytes(third.bytes));
            let last = parts.next().await.ok().unwrap();
            assert!(last.last);
            assert_eq!(last.bytes, data[3 * size..]);
            assert_eq!(last.bytes.as_ptr(), address);
            assert_eq!(last.bytes.capacity(), size);
            assert_eq!(parts.body.zeros, zeros);
        });
    }

    #[test]
    fn a_failed_read_of_the_body_stops_the_parts() {
        /// A reader that gives four bytes and then fails.
        struct Failing {
            given: bool,
        }
        impl AsyncRead for Failing {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                if self.given {
                    return Poll::Ready(Err(std::io::Error::other("the source failed")));
                }
                self.given = true;
                let n = buf.len().min(4);
                buf[..n].fill(9);
                Poll::Ready(Ok(n))
            }
        }
        ostrya_rt::block_on(async {
            let mut parts = Parts::new(Failing { given: false }, 4, 3);
            // The probe after the full first part fails.
            let Err(Stop::Io(e)) = parts.next().await else {
                panic!("a failed read stops the parts");
            };
            assert_eq!(e.to_string(), "the source failed");
            assert!(matches!(Stop::Io(e).error("k"), Error::Io(_)));
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
