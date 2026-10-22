//! Tests of the bucket client against a stand-in S3 server.
//!
//! The stand-in is a small HTTP/1.1 responder on a loopback port. A test
//! gives it a handler that answers each request, or closes the connection
//! after it read the request. The stand-in records each request.

#![cfg(feature = "s3")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use ostrya_fetch::{FetchRequest, Fetched, Fetcher, Proxy};
use ostrya_remote::Error;
use ostrya_remote::s3::{
    Address, Bucket, Credentials, DeleteIfMatch, Listed, Location, PutIfAbsent, S3Endpoint,
};
use ostrya_rt::{TcpListener, block_on, spawn};
use sha2::{Digest, Sha256};

/// A request as the stand-in read it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    /// The request target: the path and the query.
    target: String,
    /// The headers, with lowercase names.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The answer of the stand-in to one request.
enum Answer {
    /// A response with a status, headers, and a body of a declared length.
    Respond {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// No response: the stand-in closes the connection.
    Close,
    /// A response whose head declares `declared` bytes of body. The stand-in
    /// sends `body`, which is shorter, and then closes the connection.
    Cut {
        status: u16,
        declared: usize,
        body: Vec<u8>,
    },
}

/// A handler gets the request and the 1-based count of the requests that the
/// stand-in read, with this one.
type Handler = Arc<dyn Fn(&Seen, usize) -> Answer + Send + Sync>;

struct StandIn {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl StandIn {
    async fn start(handler: Handler) -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let task_seen = seen.clone();
        drop(spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let handler = handler.clone();
                let seen = task_seen.clone();
                drop(spawn(async move {
                    let mut buffer = Vec::new();
                    while let Some(request) = read_request(&mut stream, &mut buffer).await {
                        let count = {
                            let mut seen = seen.lock().unwrap();
                            seen.push(request.clone());
                            seen.len()
                        };
                        match handler(&request, count) {
                            Answer::Close => return,
                            Answer::Cut {
                                status,
                                declared,
                                body,
                            } => {
                                let head = format!(
                                    "HTTP/1.1 {status} Answer\r\nContent-Length: {declared}\r\n\r\n"
                                );
                                let _ = stream.write_all(head.as_bytes()).await;
                                let _ = stream.write_all(&body).await;
                                let _ = stream.flush().await;
                                return;
                            }
                            Answer::Respond {
                                status,
                                headers,
                                body,
                            } => {
                                let mut head = format!(
                                    "HTTP/1.1 {status} Answer\r\nContent-Length: {}\r\n",
                                    body.len()
                                );
                                for (name, value) in headers {
                                    head.push_str(&format!("{name}: {value}\r\n"));
                                }
                                head.push_str("\r\n");
                                if stream.write_all(head.as_bytes()).await.is_err()
                                    || stream.write_all(&body).await.is_err()
                                    || stream.flush().await.is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                }));
            }
        }));
        StandIn { addr, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Returns the endpoint of `address` on the stand-in, signed for
    /// `us-east-1`, with two retries.
    fn endpoint(&self, address: &str) -> S3Endpoint {
        let location = Location::new(
            Address::parse(address).unwrap(),
            "us-east-1",
            Some(&format!("http://{}", self.addr)),
            None,
        )
        .unwrap();
        let credentials =
            Credentials::new("AKIDEXAMPLE".into(), "SECRETEXAMPLEKEY".into(), None).unwrap();
        let mut endpoint = S3Endpoint::new(location, credentials);
        endpoint.http.allow_cleartext_credentials = true;
        endpoint.http.proxy = Proxy::None;
        endpoint.http.max_retries = 2;
        endpoint.http.progress_timeout = Duration::from_secs(5);
        endpoint
    }

    async fn bucket(&self, address: &str) -> Bucket {
        Bucket::new(&self.endpoint(address)).await.unwrap()
    }
}

/// Reads one request from `stream`, or returns `None` at the end of the
/// connection. `buffer` keeps the bytes after the request.
async fn read_request(stream: &mut ostrya_rt::TcpStream, buffer: &mut Vec<u8>) -> Option<Seen> {
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buffer[..end].to_vec()).ok()?;
    buffer.drain(..end + 4);
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while buffer.len() < length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    let body = buffer.drain(..length).collect();
    Some(Seen {
        method,
        target,
        headers,
        body,
    })
}

fn respond(status: u16, body: &[u8]) -> Answer {
    Answer::Respond {
        status,
        headers: Vec::new(),
        body: body.to_vec(),
    }
}

fn respond_with(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Answer {
    Answer::Respond {
        status,
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        body: body.to_vec(),
    }
}

/// The body of an S3 `Error` document with `code`.
fn s3_error(code: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
         <Message>the {code} message</Message></Error>"
    )
    .into_bytes()
}

/// A `ListBucketResult` page of `keys` under `prefix`, with `next` as its
/// continuation token.
fn list_page(keys: &[&str], next: Option<&str>) -> Vec<u8> {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    for key in keys {
        body.push_str(&format!(
            "<Contents><Key>{key}</Key><Size>{}</Size></Contents>",
            key.len()
        ));
    }
    match next {
        Some(token) => body.push_str(&format!(
            "<IsTruncated>true</IsTruncated><NextContinuationToken>{token}</NextContinuationToken>"
        )),
        None => body.push_str("<IsTruncated>false</IsTruncated>"),
    }
    body.push_str("<EncodingType>url</EncodingType></ListBucketResult>");
    body.into_bytes()
}

/// A commit key whose name is `byte` repeated.
fn commit_key(byte: char) -> String {
    let hex: String = std::iter::repeat_n(byte, 64).collect();
    format!("objects/{}/{}.commit", &hex[..2], &hex[2..])
}

#[test]
fn each_request_is_signed_and_carries_the_encoded_target() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| match seen.method.as_str() {
            "GET" if seen.target.contains("uploads") => respond(
                200,
                b"<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>\
                  </ListMultipartUploadsResult>",
            ),
            "GET" if seen.target.contains("list-type=2") => respond(200, &list_page(&[], None)),
            "GET" => respond_with(200, &[("ETag", "\"e1\"")], b"config bytes"),
            "PUT" => respond_with(200, &[("ETag", "\"e2\"")], b""),
            _ => respond(204, b""),
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let object = bucket.get("config", 1024).await.unwrap().unwrap();
        assert_eq!(object.bytes, b"config bytes");
        assert_eq!(object.etag.as_deref(), Some("\"e1\""));
        let etag = bucket
            .put("refs/heads/grün", b"0123".to_vec())
            .await
            .unwrap();
        assert_eq!(etag.as_deref(), Some("\"e2\""));
        bucket.delete("summary").await.unwrap();
        bucket.list("objects/ab/").await.unwrap();
        bucket.list_delimited("objects/").await.unwrap();
        assert!(bucket.list_uploads().await.unwrap().is_empty());

        let seen = stand_in.seen();
        let targets: Vec<(&str, &str)> = seen
            .iter()
            .map(|s| (s.method.as_str(), s.target.as_str()))
            .collect();
        assert_eq!(
            targets,
            [
                ("GET", "/bucket/repo/config"),
                ("PUT", "/bucket/repo/refs/heads/gr%C3%BCn"),
                ("DELETE", "/bucket/repo/summary"),
                (
                    "GET",
                    "/bucket/?list-type=2&prefix=repo%2Fobjects%2Fab%2F&encoding-type=url"
                ),
                (
                    "GET",
                    "/bucket/?list-type=2&prefix=repo%2Fobjects%2F&encoding-type=url&delimiter=%2F"
                ),
                ("GET", "/bucket/?uploads&prefix=repo%2F&encoding-type=url"),
            ]
        );
        for request in &seen {
            let authorization = request.header("authorization").unwrap();
            assert!(
                authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
                    && authorization.contains("/us-east-1/s3/aws4_request"),
                "{authorization}"
            );
            assert!(request.header("x-amz-date").is_some());
            assert!(request.header("x-amz-content-sha256").is_some());
            assert!(!format!("{request:?}").contains("SECRETEXAMPLEKEY"));
        }
        assert_eq!(seen[1].body, b"0123");
        assert_eq!(
            seen[1].header("x-amz-content-sha256"),
            Some("1be2e452b46d7a0d9656bbb1f768e8248eba1b75baed65f5d99eafa948899a6a")
        );
    });
}

/// A client over the fetcher of a pull, whose mirror is the repository URL,
/// sends each request to the key under the bucket URL. It keeps the rules of
/// an absent key and of an absent bucket, and the fetcher keeps its mirror.
#[test]
fn a_client_over_the_fetcher_of_a_pull_names_the_keys_under_the_bucket() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if seen.target.contains("list-type=2") {
                respond(200, &list_page(&[], None))
            } else if seen.target.ends_with("/config") {
                respond(404, &s3_error("NoSuchKey"))
            } else if seen.target.ends_with("/summary.sig") {
                respond(404, &s3_error("NoSuchBucket"))
            } else {
                respond(200, b"bytes")
            }
        }))
        .await;
        let endpoint = stand_in.endpoint("s3://bucket/repo");
        let fetcher = Fetcher::new(endpoint.pull_options().unwrap())
            .await
            .unwrap();
        let bucket = Bucket::from_fetcher(&endpoint, fetcher.clone());
        assert_eq!(bucket.location(), &endpoint.location);
        let summary = bucket.get("summary", 1024).await.unwrap().unwrap();
        assert_eq!(summary.bytes, b"bytes");
        assert_eq!(bucket.get("config", 1024).await.unwrap(), None);
        let err = bucket.get("summary.sig", 1024).await.unwrap_err();
        let Error::S3 { status, code, .. } = &err else {
            panic!("{err}");
        };
        assert_eq!(*status, 404);
        assert_eq!(code.as_deref(), Some("NoSuchBucket"));
        bucket.list("refs/heads/").await.unwrap();
        bucket.put("refs/heads/main", b"0".to_vec()).await.unwrap();
        let key = commit_key('a');
        let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path(&key)).await.unwrap() else {
            panic!("a fetch with no validators gives a body");
        };
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"bytes");

        let seen = stand_in.seen();
        let targets: Vec<(&str, &str)> = seen
            .iter()
            .map(|s| (s.method.as_str(), s.target.as_str()))
            .collect();
        let object = format!("/bucket/repo/{key}");
        assert_eq!(
            targets,
            [
                ("GET", "/bucket/repo/summary"),
                ("GET", "/bucket/repo/config"),
                ("GET", "/bucket/repo/summary.sig"),
                (
                    "GET",
                    "/bucket/?list-type=2&prefix=repo%2Frefs%2Fheads%2F&encoding-type=url"
                ),
                ("PUT", "/bucket/repo/refs/heads/main"),
                ("GET", object.as_str()),
            ]
        );
        for request in &seen {
            let authorization = request.header("authorization").unwrap();
            assert!(
                authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
                "{authorization}"
            );
        }
    });
}

#[test]
fn a_key_out_of_the_rules_sends_no_request() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| respond(200, b""))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        for key in ["../config", "/config", "objects/ab", "refs/heads/-x"] {
            assert!(matches!(
                bucket.get(key, 1).await,
                Err(Error::InvalidInput(_))
            ));
            assert!(matches!(
                bucket.put(key, Vec::new()).await,
                Err(Error::InvalidInput(_))
            ));
            assert!(matches!(
                bucket.delete(key).await,
                Err(Error::InvalidInput(_))
            ));
        }
        for prefix in ["objects", "", "../"] {
            assert!(matches!(
                bucket.list(prefix).await,
                Err(Error::InvalidInput(_))
            ));
        }
        assert!(stand_in.seen().is_empty());
    });
}

#[test]
fn an_absent_key_and_an_absent_bucket_differ() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if seen.target.ends_with("/config") {
                respond(404, &s3_error("NoSuchKey"))
            } else if seen.target.ends_with("/summary") {
                respond(404, b"")
            } else {
                respond(404, &s3_error("NoSuchBucket"))
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        assert_eq!(bucket.get("config", 1024).await.unwrap(), None);
        assert_eq!(bucket.get("summary", 1024).await.unwrap(), None);
        assert!(bucket.get_stream("config").await.unwrap().is_none());
        bucket.delete("config").await.unwrap();
        let err = bucket.get("summary.sig", 1024).await.unwrap_err();
        let Error::S3 {
            status, code, key, ..
        } = &err
        else {
            panic!("{err}");
        };
        assert_eq!(*status, 404);
        assert_eq!(code.as_deref(), Some("NoSuchBucket"));
        assert_eq!(key.as_deref(), Some("repo/summary.sig"));
        assert!(bucket.delete("summary.sig").await.is_err());
        assert!(bucket.list("refs/heads/").await.is_err());
    });
}

/// A strict read takes a 404 with the code `NoSuchKey` alone as an absent
/// key. A 404 with an empty body or with a page that is not an S3 `Error`
/// document is an error with no code.
#[test]
fn a_strict_read_takes_no_such_key_alone_as_absent() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if seen.target.ends_with("/config") {
                respond(404, &s3_error("NoSuchKey"))
            } else if seen.target.ends_with("/summary") {
                respond(404, b"")
            } else {
                respond(404, b"<html><body>Not Found</body></html>")
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        assert_eq!(bucket.get_strict("config", 1024).await.unwrap(), None);
        for key in ["summary", "summary.sig"] {
            assert_eq!(bucket.get(key, 1024).await.unwrap(), None);
            let err = bucket.get_strict(key, 1024).await.unwrap_err();
            let Error::S3 {
                status,
                code,
                key: named,
                ..
            } = &err
            else {
                panic!("{err}");
            };
            assert_eq!(*status, 404);
            assert_eq!(*code, None);
            assert_eq!(named.as_deref(), Some(format!("repo/{key}").as_str()));
        }
    });
}

#[test]
fn a_slow_down_is_retried() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, count| {
            if count % 2 == 1 {
                respond(503, &s3_error("SlowDown"))
            } else {
                respond(200, b"ok")
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket").await;
        assert_eq!(
            bucket.get("config", 16).await.unwrap().unwrap().bytes,
            b"ok"
        );
        bucket.put("config", b"x".to_vec()).await.unwrap();
        assert_eq!(stand_in.seen().len(), 4);
        // With no prefix, a key has no leading `/` under the bucket.
        assert_eq!(stand_in.seen()[0].target, "/bucket/config");
    });
}

#[test]
fn a_slow_down_past_the_retries_names_its_code() {
    block_on(async {
        let stand_in =
            StandIn::start(Arc::new(|_: &Seen, _| respond(503, &s3_error("SlowDown")))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        for err in [
            bucket.get("config", 16).await.unwrap_err(),
            bucket.put("config", b"x".to_vec()).await.unwrap_err(),
            bucket.delete("config").await.unwrap_err(),
            bucket.list("objects/").await.unwrap_err(),
        ] {
            let Error::S3 {
                status: 503,
                code: Some(code),
                message: Some(message),
                ..
            } = &err
            else {
                panic!("{err}");
            };
            assert_eq!(code, "SlowDown");
            assert_eq!(message, "the SlowDown message");
        }
        // Each of the four calls sends one request and two retries.
        assert_eq!(stand_in.seen().len(), 12);
    });
}

#[test]
fn a_bucket_in_another_region_is_named_and_not_followed() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if seen.target.ends_with("/config") {
                respond_with(
                    301,
                    &[
                        ("x-amz-bucket-region", "eu-central-1"),
                        ("Location", "http://127.0.0.1:1/elsewhere"),
                    ],
                    &s3_error("PermanentRedirect"),
                )
            } else if seen.target.ends_with("/summary") {
                respond(
                    400,
                    b"<Error><Code>AuthorizationHeaderMalformed</Code>\
                      <Region>eu-west-2</Region></Error>",
                )
            } else {
                respond_with(
                    307,
                    &[("x-amz-bucket-region", "us-east-1")],
                    &s3_error("TemporaryRedirect"),
                )
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        for (key, bucket_region) in [("config", "eu-central-1"), ("summary", "eu-west-2")] {
            let err = bucket.get(key, 16).await.unwrap_err();
            let Error::S3Region {
                bucket,
                region,
                bucket_region: named,
                ..
            } = &err
            else {
                panic!("{err}");
            };
            assert_eq!(bucket, "bucket");
            assert_eq!(region, "us-east-1");
            assert_eq!(named, bucket_region);
        }
        let err = bucket.put("config", b"x".to_vec()).await.unwrap_err();
        assert!(matches!(err, Error::S3Region { .. }), "{err}");
        let err = bucket.get("summary.sig", 16).await.unwrap_err();
        assert!(
            matches!(&err, Error::S3 { status: 307, code: Some(code), .. } if code == "TemporaryRedirect"),
            "{err}"
        );
        assert_eq!(stand_in.seen().len(), 4);
    });
}

#[test]
fn a_skewed_clock_and_a_wrong_secret_name_their_cause() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if seen.target.ends_with("/config") {
                respond(403, &s3_error("RequestTimeTooSkewed"))
            } else {
                respond(403, &s3_error("SignatureDoesNotMatch"))
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let skewed = bucket.get("config", 16).await.unwrap_err().to_string();
        assert!(skewed.contains("RequestTimeTooSkewed"), "{skewed}");
        assert!(skewed.contains("the clock of this host"), "{skewed}");
        let wrong = bucket.get("summary", 16).await.unwrap_err().to_string();
        assert!(wrong.contains("SignatureDoesNotMatch"), "{wrong}");
    });
}

#[test]
fn a_conditional_put_reports_a_present_key_and_repeats_a_conflict() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, count| {
            assert_eq!(seen.header("if-none-match"), Some("*"));
            if seen.target.ends_with("/summary") {
                return respond(412, &s3_error("PreconditionFailed"));
            }
            if count == 2 {
                respond(409, &s3_error("ConditionalRequestConflict"))
            } else {
                respond_with(200, &[("ETag", "\"new\"")], b"")
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        assert_eq!(
            bucket
                .put_if_absent("summary", b"x".to_vec())
                .await
                .unwrap(),
            PutIfAbsent::Present
        );
        assert_eq!(
            bucket
                .put_if_absent("extensions/ostrya/lock", b"lock".to_vec())
                .await
                .unwrap(),
            PutIfAbsent::Created {
                etag: Some("\"new\"".into())
            }
        );
        assert_eq!(stand_in.seen().len(), 3);
    });
}

#[test]
fn an_interrupted_put_is_sent_again() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, count| {
            if count == 1 {
                Answer::Close
            } else {
                respond(200, b"")
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        bucket.put("config", b"twice".to_vec()).await.unwrap();
        let seen = stand_in.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].body, b"twice");
        assert_eq!(seen[1].body, b"twice");
    });
}

#[test]
fn an_interrupted_conditional_put_reads_the_key() {
    block_on(async {
        // The first request is interrupted. The read then finds the bytes of
        // the request. No answer states which writer put them there, so the
        // client reports matching bytes.
        let same = StandIn::start(Arc::new(|seen: &Seen, _| match seen.method.as_str() {
            "PUT" => Answer::Close,
            _ => respond_with(200, &[("ETag", "\"held\"")], b"lock body"),
        }))
        .await;
        let bucket = same.bucket("s3://bucket/repo").await;
        assert_eq!(
            bucket
                .put_if_absent("extensions/ostrya/lock", b"lock body".to_vec())
                .await
                .unwrap(),
            PutIfAbsent::Matches {
                etag: Some("\"held\"".into())
            }
        );
        let methods: Vec<String> = same.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["PUT", "GET"]);

        // The read finds other bytes, so another writer holds the key.
        let other = StandIn::start(Arc::new(|seen: &Seen, _| match seen.method.as_str() {
            "PUT" => Answer::Close,
            _ => respond(200, b"other body"),
        }))
        .await;
        let bucket = other.bucket("s3://bucket/repo").await;
        assert_eq!(
            bucket
                .put_if_absent("extensions/ostrya/lock", b"lock body".to_vec())
                .await
                .unwrap(),
            PutIfAbsent::Present
        );

        // The read finds no object, so the client sends the request again.
        let absent = StandIn::start(Arc::new(|seen: &Seen, count| match seen.method.as_str() {
            "PUT" if count == 1 => Answer::Close,
            "PUT" => respond(200, b""),
            _ => respond(404, &s3_error("NoSuchKey")),
        }))
        .await;
        let bucket = absent.bucket("s3://bucket/repo").await;
        assert!(matches!(
            bucket
                .put_if_absent("extensions/ostrya/lock", b"lock body".to_vec())
                .await
                .unwrap(),
            PutIfAbsent::Created { .. }
        ));
        let methods: Vec<String> = absent.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["PUT", "GET", "PUT"]);
    });
}

#[test]
fn a_listing_follows_its_pages_and_decodes_its_keys() {
    block_on(async {
        let a = commit_key('a');
        let b = commit_key('b');
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, _| {
            let first = format!("repo/{a}");
            let second = format!("repo/{b}");
            if seen.target.contains("continuation-token=") {
                assert!(
                    seen.target.ends_with("&continuation-token=t%2B1%2Fx%3D"),
                    "{}",
                    seen.target
                );
                respond(
                    200,
                    &list_page(&[&second, "repo/objects/x%2By/sp+ace"], None),
                )
            } else {
                respond(200, &list_page(&[&first], Some("t+1/x=")))
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let listing = bucket.list("objects/").await.unwrap();
        let keys: Vec<&str> = listing.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                commit_key('a').as_str(),
                commit_key('b').as_str(),
                "objects/x+y/sp ace"
            ]
        );
        let first: &Listed = &listing.objects[0];
        assert_eq!(first.size, format!("repo/{}", commit_key('a')).len() as u64);
    });
}

#[test]
fn a_listing_that_cannot_be_used_fails() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            let target = seen.target.as_str();
            if target.contains("prefix=repo%2Frefs%2F") {
                // A truncated page with no token.
                respond(
                    200,
                    b"<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
                )
            } else if target.contains("prefix=repo%2Fdeltas%2F") {
                // Each page gives the same token and no key.
                respond(200, &list_page(&[], Some("same")))
            } else if target.contains("prefix=repo%2Fobjects%2F") {
                // A key of a sibling repository.
                respond(200, &list_page(&["repo2/objects/x"], None))
            } else {
                respond(200, b"<Error><Code>InternalError</Code></Error>")
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        for (prefix, part) in [
            ("refs/", "NextContinuationToken"),
            ("deltas/", "continuation token of an earlier page"),
            ("objects/", "outside the prefix"),
        ] {
            let err = bucket.list(prefix).await.unwrap_err();
            assert!(
                matches!(&err, Error::Transport(message) if message.contains(part)),
                "{prefix}: {err}"
            );
        }
        let err = bucket.list("delta-indexes/").await.unwrap_err();
        assert!(
            matches!(&err, Error::S3 { status: 200, code: Some(code), .. } if code == "InternalError"),
            "{err}"
        );
    });
}

#[test]
fn an_error_body_over_the_limit_gives_the_status_alone() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| {
            let mut body = s3_error("AccessDenied");
            body.resize(4 * 1024 * 1024 + 1, b' ');
            respond(403, &body)
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket.get("config", 16).await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::S3 {
                    status: 403,
                    code: None,
                    message: None,
                    ..
                }
            ),
            "{err}"
        );
    });
}

#[test]
fn an_object_over_the_cap_of_the_caller_is_refused() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| respond(200, b"0123456789"))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket.get("config", 9).await.unwrap_err();
        assert!(
            matches!(&err, Error::LimitExceeded(message) if message.contains("repo/config")),
            "{err}"
        );
        assert_eq!(
            bucket.get("config", 10).await.unwrap().unwrap().bytes.len(),
            10
        );
    });
}

#[test]
fn the_uploads_of_a_bucket_with_no_prefix_keep_the_repository_keys() {
    block_on(async {
        let commit = commit_key('c');
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, _| {
            assert_eq!(seen.target, "/bucket/?uploads&encoding-type=url");
            respond(
                200,
                format!(
                    "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated>\
                     <Upload><Key>other/key</Key><UploadId>u1</UploadId></Upload>\
                     <Upload><Key>{commit}</Key><UploadId>u2</UploadId>\
                     <Initiated>2026-10-21T12:00:00.000Z</Initiated></Upload>\
                     </ListMultipartUploadsResult>"
                )
                .as_bytes(),
            )
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket").await;
        let uploads = bucket.list_uploads().await.unwrap();
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].key, commit_key('c'));
        assert_eq!(uploads[0].upload_id, "u2");
        assert_eq!(uploads[0].initiated, "2026-10-21T12:00:00.000Z");
    });
}

#[test]
fn no_such_upload_is_an_empty_list_of_uploads() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| {
            respond(404, &s3_error("NoSuchUpload"))
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        assert!(bucket.list_uploads().await.unwrap().is_empty());
    });
}

#[test]
fn a_cleartext_endpoint_needs_the_permission() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| respond(200, b""))).await;
        let mut endpoint = stand_in.endpoint("s3://bucket/repo");
        endpoint.http.allow_cleartext_credentials = false;
        let err = Bucket::new(&endpoint).await.unwrap_err();
        assert!(matches!(err, Error::Fetch(_)), "{err}");
        assert!(!format!("{endpoint:?}").contains("SECRETEXAMPLEKEY"));
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        assert!(!format!("{bucket:?}").contains("SECRETEXAMPLEKEY"));
    });
}

/// Each page must move past the keys of the earlier pages. A server that
/// gives a key of an earlier page again fails the list at that page.
#[test]
fn a_listing_that_does_not_move_forward_fails() {
    block_on(async {
        let a = format!("repo/{}", commit_key('a'));
        let b = format!("repo/{}", commit_key('b'));
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, count| {
            let token = format!("t{count}");
            if seen.target.contains("continuation-token=") {
                // The second page gives the key of the first page again.
                respond(200, &list_page(&[&b, &a], Some(&token)))
            } else {
                respond(200, &list_page(&[&a, &b], Some(&token)))
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket.list_delimited("objects/").await.unwrap_err();
        assert!(
            matches!(&err, Error::Transport(message) if message.contains("does not move past")),
            "{err}"
        );
        assert_eq!(stand_in.seen().len(), 2);
    });
}

/// A truncated page with no key and no common prefix is followed when its
/// token is new since the last page with a key. A page with a key clears the
/// tokens, so a later empty page can give a token of an earlier run again.
#[test]
fn an_empty_truncated_page_is_followed() {
    block_on(async {
        let a = format!("repo/{}", commit_key('a'));
        let b = format!("repo/{}", commit_key('b'));
        let c = format!("repo/{}", commit_key('c'));
        let stand_in = StandIn::start(Arc::new(move |_: &Seen, count| match count {
            1 => respond(200, &list_page(&[&a], Some("t1"))),
            2 => respond(200, &list_page(&[], Some("t2"))),
            3 => respond(200, &list_page(&[&b], Some("t1"))),
            4 => respond(200, &list_page(&[], Some("t2"))),
            _ => respond(200, &list_page(&[&c], None)),
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let listing = bucket.list("objects/").await.unwrap();
        let keys: Vec<&str> = listing.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                commit_key('a').as_str(),
                commit_key('b').as_str(),
                commit_key('c').as_str()
            ]
        );
        let tokens: Vec<String> = stand_in
            .seen()
            .iter()
            .map(|seen| {
                seen.target
                    .split("continuation-token=")
                    .nth(1)
                    .unwrap_or("")
                    .to_owned()
            })
            .collect();
        assert_eq!(tokens, ["", "t1", "t2", "t1", "t2"]);
    });
}

/// An empty truncated page that gives a token seen since the last page with
/// a key fails the list, also when another empty page came between them.
#[test]
fn an_empty_page_with_a_token_seen_before_fails() {
    block_on(async {
        let a = format!("repo/{}", commit_key('a'));
        let stand_in = StandIn::start(Arc::new(move |_: &Seen, count| match count {
            1 => respond(200, &list_page(&[&a], Some("t1"))),
            2 => respond(200, &list_page(&[], Some("t2"))),
            _ => respond(200, &list_page(&[], Some("t1"))),
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket.list("objects/").await.unwrap_err();
        assert!(
            matches!(&err, Error::Transport(message) if message.contains("continuation token of an earlier page")),
            "{err}"
        );
        assert_eq!(stand_in.seen().len(), 3);
    });
}

/// A list follows 1000 truncated pages in a row with no key and no common
/// prefix, and fails at the next one.
#[test]
fn a_run_of_empty_pages_over_the_cap_fails() {
    block_on(async {
        let a = format!("repo/{}", commit_key('a'));
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, count| {
            let token = format!("t{count}");
            if seen.target.contains("prefix=repo%2Frefs%2F") {
                // An endless run of empty pages, each with a new token.
                respond(200, &list_page(&[], Some(&token)))
            } else if count <= 1000 {
                respond(200, &list_page(&[], Some(&token)))
            } else {
                respond(200, &list_page(&[&a], None))
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let listing = bucket.list("objects/").await.unwrap();
        assert_eq!(listing.objects.len(), 1);
        assert_eq!(stand_in.seen().len(), 1001);
        let err = bucket.list("refs/").await.unwrap_err();
        assert!(
            matches!(&err, Error::Transport(message) if message.contains("more than 1000 truncated pages")),
            "{err}"
        );
        assert_eq!(stand_in.seen().len(), 2002);
    });
}

/// The key marker of each truncated page of uploads must not go back, and
/// while it stays the same, the upload id marker must be new.
#[test]
fn a_listing_of_uploads_that_does_not_move_forward_fails() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, count| {
            let (key, id) = match count {
                // The second page goes back to an earlier key.
                1 => ("m", "u2"),
                2 => ("a", "u9"),
                // The fifth page gives the pair of the third page again.
                3 => ("m", "u2"),
                4 => ("m", "u1"),
                _ => ("m", "u2"),
            };
            respond(
                200,
                format!(
                    "<ListMultipartUploadsResult><IsTruncated>true</IsTruncated>\
                     <NextKeyMarker>repo/{key}</NextKeyMarker>\
                     <NextUploadIdMarker>{id}</NextUploadIdMarker>\
                     </ListMultipartUploadsResult>"
                )
                .as_bytes(),
            )
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket.list_uploads().await.unwrap_err();
        assert!(
            matches!(&err, Error::Transport(message) if message.contains("move past")),
            "{err}"
        );
        assert_eq!(stand_in.seen().len(), 2);
        let err = bucket.list_uploads().await.unwrap_err();
        assert!(
            matches!(&err, Error::Transport(message) if message.contains("move past")),
            "{err}"
        );
        assert_eq!(stand_in.seen().len(), 5);
    });
}

/// S3 sorts the uploads of one key by the time of their start. A key whose
/// uploads span two pages gives upload id markers in no order, and the list
/// follows them.
#[test]
fn the_uploads_of_one_key_over_two_pages_are_listed() {
    block_on(async {
        let c = commit_key('c');
        let d = commit_key('d');
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, count| {
            let upload = |key: &str, id: &str| {
                format!("<Upload><Key>repo/{key}</Key><UploadId>{id}</UploadId></Upload>")
            };
            let (uploads, next) = match count {
                1 => (upload(&c, "u9"), Some(("repo/".to_owned() + &c, "u9"))),
                2 => {
                    assert!(
                        seen.target.ends_with("&upload-id-marker=u9"),
                        "{}",
                        seen.target
                    );
                    (upload(&c, "u3"), Some(("repo/".to_owned() + &c, "u3")))
                }
                _ => {
                    assert!(
                        seen.target.ends_with("&upload-id-marker=u3"),
                        "{}",
                        seen.target
                    );
                    (upload(&d, "u1"), None)
                }
            };
            let tail = match next {
                Some((key, id)) => format!(
                    "<IsTruncated>true</IsTruncated><NextKeyMarker>{key}</NextKeyMarker>\
                     <NextUploadIdMarker>{id}</NextUploadIdMarker>"
                ),
                None => "<IsTruncated>false</IsTruncated>".to_owned(),
            };
            respond(
                200,
                format!("<ListMultipartUploadsResult>{uploads}{tail}</ListMultipartUploadsResult>")
                    .as_bytes(),
            )
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let uploads = bucket.list_uploads().await.unwrap();
        let found: Vec<(&str, &str)> = uploads
            .iter()
            .map(|u| (u.key.as_str(), u.upload_id.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                (commit_key('c').as_str(), "u9"),
                (commit_key('c').as_str(), "u3"),
                (commit_key('d').as_str(), "u1")
            ]
        );
        assert_eq!(stand_in.seen().len(), 3);
    });
}

/// A message about a listing that the reader refuses holds no text of the
/// body: no terminal escape, no bell, and no name from the body.
#[test]
fn an_unusable_listing_names_no_text_of_the_body() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| {
            respond(
                200,
                b"<ListBucketResult><Contents><Key>x</K\x1b[2J\x07SECRET></Contents></ListBucketResult>",
            )
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket.list("objects/").await.unwrap_err();
        let text = err.to_string();
        assert!(matches!(err, Error::Transport(_)), "{text:?}");
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(!text.contains('\x07'), "{text:?}");
        assert!(!text.contains("SECRET"), "{text:?}");
        assert!(text.contains("at byte"), "{text:?}");
    });
}

/// The key held the bytes of the body before the call. The first request
/// gets a 503, and the second gets a 412. The read finds the same bytes, but
/// no answer states that a request of this call wrote them. The 412 shows
/// that the server honors the header.
#[test]
fn a_conditional_put_refused_after_an_unsure_request_reports_matching_bytes() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, count| match seen.method.as_str() {
            "PUT" if count == 1 => respond(503, &s3_error("SlowDown")),
            "PUT" => respond(412, &s3_error("PreconditionFailed")),
            "GET" => respond(200, b"lock"),
            _ => respond(500, b""),
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let outcome = bucket
            .put_if_absent("extensions/ostrya/lock", b"lock".to_vec())
            .await
            .unwrap();
        assert_eq!(outcome, PutIfAbsent::Refused { etag: None });
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["PUT", "PUT", "GET"]);
    });
}

/// A stored object whose answer declares a length other than the length of
/// the body holds other bytes. The client decides from the head and reads no
/// byte of the object, so a body that never arrives does not hold it up.
#[test]
fn a_conditional_put_does_not_read_a_stored_object_of_another_length() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| match seen.method.as_str() {
            "PUT" => Answer::Close,
            _ => Answer::Cut {
                status: 200,
                declared: 3,
                body: Vec::new(),
            },
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let outcome = bucket
            .put_if_absent("extensions/ostrya/lock", b"lock body".to_vec())
            .await
            .unwrap();
        assert_eq!(outcome, PutIfAbsent::Present);
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["PUT", "GET"]);
    });
}

/// An absent key is not an error, also when the answer names another
/// region.
#[test]
fn an_absent_key_that_names_another_region_is_absent() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| {
            respond_with(
                404,
                &[("x-amz-bucket-region", "eu-west-1")],
                &s3_error("NoSuchKey"),
            )
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        assert_eq!(bucket.get("summary.sig", 1024).await.unwrap(), None);
        assert!(bucket.get_stream("summary.sig").await.unwrap().is_none());
        bucket.delete("summary.sig").await.unwrap();
    });
}

/// A 404 whose body did not arrive can be a missing bucket. So it is an
/// error with the status 404 and no code, and never an absent key.
#[test]
fn a_404_whose_body_did_not_arrive_is_an_error() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| Answer::Cut {
            status: 404,
            declared: 200,
            body: b"<Error><Code>NoSuchBu".to_vec(),
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket.get("config", 1024).await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::S3 {
                    status: 404,
                    code: None,
                    ..
                }
            ),
            "{err}"
        );
        let err = bucket.get_stream("config").await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::S3 {
                    status: 404,
                    code: None,
                    ..
                }
            ),
            "{err}"
        );
    });
}

/// An error answer to a `PUT` whose body declares a coding keeps its status.
/// The status is definitive, so the client does not send the request again.
#[test]
fn a_coded_error_answer_to_a_put_is_not_sent_again() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| {
            respond_with(403, &[("Content-Encoding", "gzip")], b"\x1f\x8b coded")
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket.put("config", b"x".to_vec()).await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::S3 {
                    status: 403,
                    code: None,
                    ..
                }
            ),
            "{err}"
        );
        let err = bucket.delete("config").await.unwrap_err();
        assert!(
            matches!(
                &err,
                Error::S3 {
                    status: 403,
                    code: None,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(stand_in.seen().len(), 2);
    });
}

/// A 304 to a request that sent no validators cannot be used. The read and
/// the list fail with a transport error.
#[test]
fn a_304_to_a_read_or_a_list_is_a_transport_error() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| respond(304, b""))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        for err in [
            bucket.get("config", 16).await.unwrap_err(),
            bucket.get_stream("config").await.unwrap_err(),
            bucket.list("objects/").await.unwrap_err(),
            bucket.list_uploads().await.unwrap_err(),
        ] {
            assert!(
                matches!(&err, Error::Transport(message) if message.contains("304")),
                "{err}"
            );
        }
    });
}

/// A whole read reserves the declared length and one byte for the end of the
/// body. So the bytes of an object hold no doubled buffer.
#[test]
fn a_whole_read_holds_no_spare_capacity() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| respond(200, &[b'o'; 3000]))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let object = bucket.get("config", 1 << 20).await.unwrap().unwrap();
        assert_eq!(object.bytes.len(), 3000);
        assert!(
            object.bytes.capacity() <= 3001,
            "{}",
            object.bytes.capacity()
        );
    });
}

/// The part size of the multipart tests: 5 MiB, the smallest part size.
const PART: usize = 5 << 20;

/// The upload id of the multipart tests, which holds characters that a query
/// encodes.
const UPLOAD_ID: &str = "up+id/1=";

/// The upload id of the multipart tests, as the query of a request gives it.
const UPLOAD_QUERY: &str = "uploadId=up%2Bid%2F1%3D";

/// Returns `len` bytes of a pattern.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|at| (at * 31 % 251) as u8).collect()
}

/// Returns `bytes` in lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Returns the part number of the query of `seen`, if it has one.
fn part_number(seen: &Seen) -> Option<u32> {
    seen.target
        .split(['?', '&'])
        .find_map(|pair| pair.strip_prefix("partNumber="))
        .and_then(|number| number.parse().ok())
}

/// The answer of a stand-in that takes each request of a multipart upload.
///
/// The start gives [`UPLOAD_ID`], part `N` gives the `ETag` `"etag-N"`, the
/// completion gives the `ETag` `"whole-3"`, an abort gives 204, and a `PUT`
/// with no query gives the `ETag` `"single"`.
fn multipart(seen: &Seen) -> Answer {
    let query = seen.target.split_once('?').map(|(_, query)| query);
    match (seen.method.as_str(), query) {
        ("POST", Some("uploads")) => respond(
            200,
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <Bucket>bucket</Bucket><Key>k</Key><UploadId>{UPLOAD_ID}</UploadId>\
                 </InitiateMultipartUploadResult>"
            )
            .as_bytes(),
        ),
        ("PUT", Some(_)) => {
            let etag = format!("\"etag-{}\"", part_number(seen).unwrap());
            respond_with(200, &[("ETag", &etag)], b"")
        }
        ("POST", Some(_)) => respond(
            200,
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
              <CompleteMultipartUploadResult><ETag>&quot;whole-3&quot;</ETag>\
              </CompleteMultipartUploadResult>",
        ),
        ("DELETE", Some(_)) => respond(204, b""),
        ("PUT", None) => respond_with(200, &[("ETag", "\"single\"")], b""),
        _ => respond(400, &s3_error("InvalidRequest")),
    }
}

/// Returns the method and the target of each request that `stand_in` read.
fn requests(stand_in: &StandIn) -> Vec<(String, String)> {
    stand_in
        .seen()
        .into_iter()
        .map(|seen| (seen.method, seen.target))
        .collect()
}

/// Returns the request of `method` to `target`, as [`requests`] gives it.
fn request(method: &str, target: &str) -> (String, String) {
    (method.to_owned(), target.to_owned())
}

#[test]
fn a_body_of_at_most_one_part_goes_in_one_put() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| multipart(seen))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        for len in [0, 100, PART] {
            let body = pattern(len);
            let etag = bucket
                .put_stream(&key, &body[..], PART as u64)
                .await
                .unwrap();
            assert_eq!(etag.as_deref(), Some("\"single\""));
            let seen = stand_in.seen();
            let last = seen.last().unwrap();
            assert_eq!(last.body, body, "{len}");
        }
        let target = format!("/bucket/repo/{key}");
        assert_eq!(requests(&stand_in), vec![request("PUT", &target); 3]);
    });
}

#[test]
fn a_part_size_out_of_the_s3_limits_sends_no_request() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| multipart(seen))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        for part_size in [0, PART as u64 - 1, (5 << 30) + 1] {
            let err = bucket
                .put_stream("config", &b"x"[..], part_size)
                .await
                .unwrap_err();
            assert!(matches!(&err, Error::InvalidInput(_)), "{err}");
        }
        let err = bucket
            .put_stream("objects/zz", &b"x"[..], PART as u64)
            .await
            .unwrap_err();
        assert!(matches!(&err, Error::InvalidInput(_)), "{err}");
        assert!(stand_in.seen().is_empty());
    });
}

#[test]
fn a_body_of_several_parts_goes_in_a_signed_multipart_upload() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| multipart(seen))).await;
        let endpoint = stand_in.endpoint("s3://bucket/repo");
        let fetcher = Fetcher::new(endpoint.pull_options().unwrap())
            .await
            .unwrap();
        let key = commit_key('d');
        let body = pattern(2 * PART + PART / 2);
        // A client whose requests go under the mirror of its fetcher, and a
        // client that names the URL of each request.
        let buckets = [
            stand_in.bucket("s3://bucket/repo").await,
            Bucket::from_fetcher(&endpoint, fetcher),
        ];
        for bucket in buckets {
            let start = stand_in.seen().len();
            let etag = bucket
                .put_stream(&key, &body[..], PART as u64)
                .await
                .unwrap();
            assert_eq!(etag.as_deref(), Some("\"whole-3\""));
            let seen = stand_in.seen().split_off(start);
            let object = format!("/bucket/repo/{key}");
            let targets: Vec<(&str, &str)> = seen
                .iter()
                .map(|s| (s.method.as_str(), s.target.as_str()))
                .collect();
            assert_eq!(
                targets,
                [
                    ("POST", format!("{object}?uploads").as_str()),
                    (
                        "PUT",
                        format!("{object}?partNumber=1&{UPLOAD_QUERY}").as_str()
                    ),
                    (
                        "PUT",
                        format!("{object}?partNumber=2&{UPLOAD_QUERY}").as_str()
                    ),
                    (
                        "PUT",
                        format!("{object}?partNumber=3&{UPLOAD_QUERY}").as_str()
                    ),
                    ("POST", format!("{object}?{UPLOAD_QUERY}").as_str()),
                ]
            );
            for (part, request) in body.chunks(PART).zip(&seen[1..4]) {
                assert_eq!(request.body, part);
            }
            assert!(seen[0].body.is_empty());
            assert_eq!(
                String::from_utf8(seen[4].body.clone()).unwrap(),
                "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <Part><PartNumber>1</PartNumber><ETag>\"etag-1\"</ETag></Part>\
                 <Part><PartNumber>2</PartNumber><ETag>\"etag-2\"</ETag></Part>\
                 <Part><PartNumber>3</PartNumber><ETag>\"etag-3\"</ETag></Part>\
                 </CompleteMultipartUpload>"
            );
            for request in &seen {
                let authorization = request.header("authorization").unwrap();
                assert!(
                    authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"),
                    "{authorization}"
                );
                assert_eq!(
                    request.header("x-amz-content-sha256"),
                    Some(hex(&Sha256::digest(&request.body)).as_str())
                );
            }
        }
    });
}

#[test]
fn a_refused_part_aborts_the_upload() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if part_number(seen) == Some(2) {
                respond(400, &s3_error("InvalidArgument"))
            } else {
                multipart(seen)
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        let body = pattern(2 * PART + PART / 2);
        let err = bucket
            .put_stream(&key, &body[..], PART as u64)
            .await
            .unwrap_err();
        let full = format!("repo/{key}");
        assert!(
            matches!(
                &err,
                Error::S3 { status: 400, code: Some(code), key: Some(named), .. }
                    if code == "InvalidArgument" && *named == full
            ),
            "{err}"
        );
        let object = format!("/bucket/{full}");
        assert_eq!(
            requests(&stand_in),
            [
                request("POST", &format!("{object}?uploads")),
                request("PUT", &format!("{object}?partNumber=1&{UPLOAD_QUERY}")),
                request("PUT", &format!("{object}?partNumber=2&{UPLOAD_QUERY}")),
                request("DELETE", &format!("{object}?{UPLOAD_QUERY}")),
            ]
        );
    });
}

#[test]
fn a_part_that_meets_a_slow_down_is_sent_again() {
    block_on(async {
        let refused = Arc::new(AtomicBool::new(false));
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, _| {
            if part_number(seen) == Some(2) && !refused.swap(true, Ordering::SeqCst) {
                respond(503, &s3_error("SlowDown"))
            } else {
                multipart(seen)
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        let body = pattern(2 * PART + PART / 2);
        let etag = bucket
            .put_stream(&key, &body[..], PART as u64)
            .await
            .unwrap();
        assert_eq!(etag.as_deref(), Some("\"whole-3\""));
        let seen = stand_in.seen();
        let second: Vec<&Seen> = seen
            .iter()
            .filter(|seen| part_number(seen) == Some(2))
            .collect();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].body, &body[PART..2 * PART]);
        assert_eq!(second[1].body, second[0].body);
        assert_eq!(
            second[0].header("x-amz-content-sha256"),
            second[1].header("x-amz-content-sha256")
        );
        assert!(!seen.iter().any(|seen| seen.method == "DELETE"));
    });
}

#[test]
fn a_part_with_no_etag_aborts_the_upload() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if part_number(seen).is_some() {
                respond(200, b"")
            } else {
                multipart(seen)
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        let err = bucket
            .put_stream(&key, &pattern(PART + 1)[..], PART as u64)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Transport(message) if message.contains("no ETag")),
            "{err}"
        );
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["POST", "PUT", "DELETE"]);
    });
}

/// A reader that gives the bytes of `data`, and then fails.
struct FailingAfter {
    data: futures_lite::io::Cursor<Vec<u8>>,
}

impl futures_io::AsyncRead for FailingAfter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match std::pin::Pin::new(&mut self.data).poll_read(cx, buf) {
            std::task::Poll::Ready(Ok(0)) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the source failed",
            ))),
            other => other,
        }
    }
}

#[test]
fn a_failed_read_of_the_body_aborts_the_upload() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| multipart(seen))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        // A failure in the first part comes before any request.
        let body = FailingAfter {
            data: futures_lite::io::Cursor::new(pattern(100)),
        };
        let err = bucket
            .put_stream(&key, body, PART as u64)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "{err}"
        );
        assert!(stand_in.seen().is_empty());
        // A failure in the second part comes after the upload started.
        let body = FailingAfter {
            data: futures_lite::io::Cursor::new(pattern(PART + 100)),
        };
        let err = bucket
            .put_stream(&key, body, PART as u64)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut),
            "{err}"
        );
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["POST", "PUT", "DELETE"]);
    });
}

#[test]
fn an_error_document_after_a_200_to_the_completion_is_sent_again() {
    block_on(async {
        let failed = Arc::new(AtomicBool::new(false));
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, _| {
            let completes = seen.method == "POST" && seen.target.ends_with(UPLOAD_QUERY);
            if completes && !failed.swap(true, Ordering::SeqCst) {
                respond(200, &s3_error("InternalError"))
            } else {
                multipart(seen)
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        let body = pattern(PART + 1);
        let etag = bucket
            .put_stream(&key, &body[..], PART as u64)
            .await
            .unwrap();
        assert_eq!(etag.as_deref(), Some("\"whole-3\""));
        let seen = stand_in.seen();
        let methods: Vec<&str> = seen.iter().map(|s| s.method.as_str()).collect();
        assert_eq!(methods, ["POST", "PUT", "PUT", "POST", "POST"]);
        assert_eq!(seen[3].body, seen[4].body);
    });
}

/// The answer of a stand-in whose completion gets `unsure` first and 404
/// `NoSuchUpload` after it. A `GET` of the key gets `object`, and each other
/// request gets the answer of [`multipart`].
fn completed_before(
    unsure: fn() -> Answer,
    object: Arc<dyn Fn() -> Answer + Send + Sync>,
) -> Handler {
    let first = Arc::new(AtomicBool::new(false));
    Arc::new(move |seen: &Seen, _| {
        let completes = seen.method == "POST" && seen.target.ends_with(UPLOAD_QUERY);
        if completes && !first.swap(true, Ordering::SeqCst) {
            unsure()
        } else if completes {
            respond(404, &s3_error("NoSuchUpload"))
        } else if seen.method == "GET" {
            object()
        } else {
            multipart(seen)
        }
    })
}

/// Returns the answer to a `GET` whose head declares `declared` bytes, with
/// no byte of the body after it.
fn declared_object(declared: usize) -> Arc<dyn Fn() -> Answer + Send + Sync> {
    Arc::new(move || Answer::Cut {
        status: 200,
        declared,
        body: Vec::new(),
    })
}

#[test]
fn an_unsure_completion_reads_the_key_after_no_such_upload() {
    block_on(async {
        let body = pattern(PART + 1);
        let absent: Arc<dyn Fn() -> Answer + Send + Sync> =
            Arc::new(|| respond(404, &s3_error("NoSuchKey")));
        let cases = [
            (declared_object(body.len()), None),
            (
                declared_object(body.len() - 1),
                Some(format!("an object of {} bytes", body.len() - 1)),
            ),
            (absent, Some("no object".to_owned())),
        ];
        for (object, held) in cases {
            let stand_in = StandIn::start(completed_before(|| Answer::Close, object)).await;
            let bucket = stand_in.bucket("s3://bucket/repo").await;
            let key = commit_key('d');
            let outcome = bucket.put_stream(&key, &body[..], PART as u64).await;
            let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
            // The last answer of the upload is 404 `NoSuchUpload`, so no
            // abort goes.
            assert_eq!(methods, ["POST", "PUT", "PUT", "POST", "POST", "GET"]);
            let Some(held) = held else {
                assert_eq!(outcome.unwrap(), None);
                continue;
            };
            let err = outcome.unwrap_err();
            let expected = format!(
                "is 404 NoSuchUpload after a request with no known outcome, and the key holds \
                 {held}, not the {} bytes of the parts",
                body.len()
            );
            assert!(
                matches!(&err, Error::Transport(message) if message.contains(&expected)),
                "{err}"
            );
        }
    });
}

#[test]
fn a_completion_that_meets_a_gateway_timeout_reads_the_key_after_no_such_upload() {
    block_on(async {
        let body = pattern(PART + 1);
        let unsure = || respond(504, &s3_error("GatewayTimeout"));
        let stand_in = StandIn::start(completed_before(unsure, declared_object(body.len()))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        let etag = bucket
            .put_stream(&key, &body[..], PART as u64)
            .await
            .unwrap();
        assert_eq!(etag, None);
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["POST", "PUT", "PUT", "POST", "POST", "GET"]);
    });
}

#[test]
fn a_part_of_an_absent_upload_sends_no_abort() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if part_number(seen).is_some() {
                respond(404, &s3_error("NoSuchUpload"))
            } else {
                multipart(seen)
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        let err = bucket
            .put_stream(&key, &pattern(PART + 1)[..], PART as u64)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::S3 { status: 404, code: Some(code), .. } if code == "NoSuchUpload"
            ),
            "{err}"
        );
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["POST", "PUT"]);
    });
}

#[test]
fn a_start_whose_body_did_not_arrive_is_sent_again() {
    block_on(async {
        // The head of a 200 declares a body that does not arrive.
        let cut = || Answer::Cut {
            status: 200,
            declared: 100,
            body: b"<InitiateMultipart".to_vec(),
        };
        // The first start fails in transit, and the second one gives the
        // upload id.
        let failed = Arc::new(AtomicBool::new(false));
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, _| {
            let starts = seen.target.ends_with("?uploads");
            if starts && !failed.swap(true, Ordering::SeqCst) {
                cut()
            } else {
                multipart(seen)
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = commit_key('d');
        let body = pattern(PART + 1);
        let etag = bucket
            .put_stream(&key, &body[..], PART as u64)
            .await
            .unwrap();
        assert_eq!(etag.as_deref(), Some("\"whole-3\""));
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["POST", "POST", "PUT", "PUT", "POST"]);
        // Each start fails in transit: the client sends it two times again,
        // and then fails with no upload id to abort.
        let stand_in = StandIn::start(Arc::new(move |seen: &Seen, _| {
            if seen.target.ends_with("?uploads") {
                cut()
            } else {
                multipart(seen)
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket
            .put_stream(&key, &body[..], PART as u64)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Transport(message) if message.contains("did not arrive")),
            "{err}"
        );
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["POST", "POST", "POST"]);
    });
}

#[test]
fn an_etag_or_an_upload_id_over_1_kib_is_refused() {
    block_on(async {
        let key = commit_key('d');
        let body = pattern(PART + 1);
        // An `ETag` of 1 KiB is taken, and one byte more is refused.
        for (len, taken) in [(1024, true), (1025, false)] {
            let etag = format!("\"{}\"", "e".repeat(len - 2));
            let stand_in = StandIn::start(Arc::new(move |seen: &Seen, _| {
                if part_number(seen).is_some() {
                    respond_with(200, &[("ETag", &etag)], b"")
                } else {
                    multipart(seen)
                }
            }))
            .await;
            let bucket = stand_in.bucket("s3://bucket/repo").await;
            let outcome = bucket.put_stream(&key, &body[..], PART as u64).await;
            let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
            if taken {
                assert_eq!(outcome.unwrap().as_deref(), Some("\"whole-3\""));
                assert_eq!(methods, ["POST", "PUT", "PUT", "POST"]);
            } else {
                let err = outcome.unwrap_err();
                assert!(
                    matches!(
                        &err,
                        Error::Transport(message)
                            if message.contains("an ETag of more than 1024 bytes")
                    ),
                    "{err}"
                );
                assert_eq!(methods, ["POST", "PUT", "DELETE"]);
            }
        }
        // An upload id of more than 1 KiB is refused, and the client sends
        // no part.
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if seen.target.ends_with("?uploads") {
                let id = "u".repeat(1025);
                respond(
                    200,
                    format!(
                        "<InitiateMultipartUploadResult><UploadId>{id}</UploadId>\
                         </InitiateMultipartUploadResult>"
                    )
                    .as_bytes(),
                )
            } else {
                multipart(seen)
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let err = bucket
            .put_stream(&key, &body[..], PART as u64)
            .await
            .unwrap_err();
        assert!(
            matches!(
                &err,
                Error::Transport(message) if message.contains("UploadId has more than 1024 bytes")
            ),
            "{err}"
        );
        let methods: Vec<String> = stand_in.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["POST"]);
    });
}

#[test]
fn an_abort_of_an_absent_upload_succeeds() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| {
            if seen.target.ends_with("uploadId=live") {
                respond(204, b"")
            } else if seen.target.ends_with("uploadId=gone") {
                respond(404, &s3_error("NoSuchUpload"))
            } else {
                respond(403, &s3_error("AccessDenied"))
            }
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        bucket.abort_upload("config", "live").await.unwrap();
        bucket.abort_upload("config", "gone").await.unwrap();
        let err = bucket.abort_upload("config", "denied").await.unwrap_err();
        assert!(
            matches!(&err, Error::S3 { status: 403, code: Some(code), .. } if code == "AccessDenied"),
            "{err}"
        );
        let err = bucket.abort_upload("config", "").await.unwrap_err();
        assert!(matches!(&err, Error::InvalidInput(_)), "{err}");
        assert_eq!(
            requests(&stand_in),
            [
                request("DELETE", "/bucket/repo/config?uploadId=live"),
                request("DELETE", "/bucket/repo/config?uploadId=gone"),
                request("DELETE", "/bucket/repo/config?uploadId=denied"),
            ]
        );
    });
}

#[test]
fn a_conditional_delete_sends_the_etag_and_reads_412_and_404_as_not_matched() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|seen: &Seen, _| match seen.header("if-match") {
            Some("\"held\"") => respond(204, b""),
            Some("\"other\"") => respond(412, &s3_error("PreconditionFailed")),
            _ => respond(404, &s3_error("NoSuchKey")),
        }))
        .await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = "extensions/ostrya/lock";
        assert_eq!(
            bucket.delete_if_match(key, "\"held\"").await.unwrap(),
            DeleteIfMatch::Deleted
        );
        assert_eq!(
            bucket.delete_if_match(key, "\"other\"").await.unwrap(),
            DeleteIfMatch::NotMatched
        );
        assert_eq!(
            bucket.delete_if_match(key, "\"absent\"").await.unwrap(),
            DeleteIfMatch::NotMatched
        );
        let seen = stand_in.seen();
        assert_eq!(seen.len(), 3);
        for request in &seen {
            assert_eq!(request.method, "DELETE");
            assert_eq!(request.target, "/bucket/repo/extensions/ostrya/lock");
        }
        assert_eq!(seen[0].header("if-match"), Some("\"held\""));
    });
}

#[test]
fn a_conditional_delete_after_an_unsure_request_reads_the_key() {
    block_on(async {
        // The first request is interrupted, and the second one gets a 412.
        // The read finds no object, so a request of the call deleted it.
        let deleted = StandIn::start(Arc::new(|seen: &Seen, count| {
            match (seen.method.as_str(), count) {
                ("DELETE", 1) => Answer::Close,
                ("DELETE", _) => respond(412, &s3_error("PreconditionFailed")),
                _ => respond(404, &s3_error("NoSuchKey")),
            }
        }))
        .await;
        let bucket = deleted.bucket("s3://bucket/repo").await;
        assert_eq!(
            bucket
                .delete_if_match("extensions/ostrya/lock", "\"held\"")
                .await
                .unwrap(),
            DeleteIfMatch::Deleted
        );
        let methods: Vec<String> = deleted.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["DELETE", "DELETE", "GET"]);

        // The read finds an object, so the key holds another object.
        let held = StandIn::start(Arc::new(|seen: &Seen, count| {
            match (seen.method.as_str(), count) {
                ("DELETE", 1) => respond(503, &s3_error("SlowDown")),
                ("DELETE", _) => respond(412, &s3_error("PreconditionFailed")),
                _ => respond_with(200, &[("ETag", "\"new\"")], b"new lock"),
            }
        }))
        .await;
        let bucket = held.bucket("s3://bucket/repo").await;
        assert_eq!(
            bucket
                .delete_if_match("extensions/ostrya/lock", "\"held\"")
                .await
                .unwrap(),
            DeleteIfMatch::NotMatched
        );
        let methods: Vec<String> = held.seen().into_iter().map(|s| s.method).collect();
        assert_eq!(methods, ["DELETE", "DELETE", "GET"]);
    });
}

#[test]
fn a_conditional_delete_with_no_usable_etag_sends_no_request() {
    block_on(async {
        let stand_in = StandIn::start(Arc::new(|_: &Seen, _| respond(204, b""))).await;
        let bucket = stand_in.bucket("s3://bucket/repo").await;
        let key = "extensions/ostrya/lock";
        let err = bucket.delete_if_match(key, "").await.unwrap_err();
        assert!(matches!(&err, Error::InvalidInput(_)), "{err}");
        let long = "e".repeat(1025);
        let err = bucket.delete_if_match(key, &long).await.unwrap_err();
        assert!(matches!(&err, Error::InvalidInput(_)), "{err}");
        assert!(stand_in.seen().is_empty());
    });
}
