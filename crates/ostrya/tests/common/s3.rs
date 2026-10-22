//! S3 servers for the tests of a pull from an `s3://` address and of a
//! bucket repository.
//!
//! - [`Rclone`] runs `rclone serve s3` on a directory, with a key pair and a
//!   port that it picks. The top-level directories of the served directory
//!   are the buckets. The server keeps the listing of each directory for one
//!   hour. So a test writes each file of the served directory before the
//!   server starts.
//! - [`Seaweed`] runs `weed mini` of SeaweedFS on a data directory in the
//!   scratch directory, with one bucket and the same key pair.
//! - [`StandIn`] is an S3 server in the process that holds its objects in
//!   memory. A test sets the conditional headers that it honors, the
//!   requests that it interrupts, refuses, or delays, and the requests that
//!   get 503.
//!
//! A test skips when `rclone` or `weed` is not on `PATH`, and writes the
//! reason to standard error. With `OSTRYA_REQUIRE_S3` set, a missing
//! `rclone` fails the test. With `OSTRYA_REQUIRE_SEAWEEDFS` set, a missing
//! `weed` fails the test.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ops::Bound;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use ostrya::Proxy;
use ostrya::remote::s3::{Address, Bucket, Credentials, Location, S3Endpoint};

/// The access key id of the server. `rclone serve s3` refuses a very short
/// key.
pub const ACCESS_KEY: &str = "ostryatest";
/// The secret access key of the server.
pub const SECRET_KEY: &str = "ostryasecret";

/// The environment variable that turns the skip for a missing `rclone` into
/// a failure.
pub const REQUIRE_S3: &str = "OSTRYA_REQUIRE_S3";

/// The environment variable that turns the skip for a missing `weed` into a
/// failure.
pub const REQUIRE_SEAWEEDFS: &str = "OSTRYA_REQUIRE_SEAWEEDFS";

/// Returns the endpoint of `address` on the server at `url`, with the key
/// pair of the servers, signed for `us-east-1`, with two retries.
pub fn endpoint(url: &str, address: &str) -> S3Endpoint {
    let location = Location::new(
        Address::parse(address).unwrap(),
        "us-east-1",
        Some(url),
        None,
    )
    .unwrap();
    let credentials = Credentials::new(ACCESS_KEY.into(), SECRET_KEY.into(), None).unwrap();
    let mut endpoint = S3Endpoint::new(location, credentials);
    endpoint.http.allow_cleartext_credentials = true;
    endpoint.http.proxy = Proxy::None;
    endpoint.http.max_retries = 2;
    endpoint.http.progress_timeout = Duration::from_secs(10);
    endpoint
}

/// Returns `true` if `rclone` runs. With [`REQUIRE_S3`] set, a missing
/// `rclone` fails the test. Else the function writes the reason of the skip
/// of `test` to standard error.
pub fn rclone_available(test: &str) -> bool {
    let found = Command::new("rclone")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    assert!(
        found || std::env::var_os(REQUIRE_S3).is_none(),
        "{REQUIRE_S3} is set and rclone is not installed, so the S3 tests cannot run"
    );
    if !found {
        eprintln!("skipping {test}: rclone is not installed");
    }
    found
}

/// A running `rclone serve s3`. A drop stops it.
pub struct Rclone {
    child: Child,
    port: u16,
}

impl Rclone {
    /// Starts the server on the directory `root`, with an empty config file
    /// of rclone in `scratch`.
    pub fn start(scratch: &Path, root: &Path) -> Rclone {
        // An empty config file, so the server reads no config of the user.
        let config = scratch.join("rclone.conf");
        std::fs::write(&config, "").unwrap();
        // The directory cache time is not zero. With `--dir-cache-time 0s`,
        // rclone 1.75.1 starts the cleanup timer of a directory with a
        // virtual entry again with no delay, each time that it expires, and a
        // request can get no response for more than 60 s.
        let mut child = Command::new("rclone")
            .args(["serve", "s3", "--config"])
            .arg(&config)
            .args(["--auth-key", &format!("{ACCESS_KEY},{SECRET_KEY}")])
            .args(["--addr", "127.0.0.1:0", "--dir-cache-time", "1h"])
            .arg(root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The server writes the address that it took to standard error, in
        // the form `Starting s3 server on [http://127.0.0.1:PORT/]`.
        let stderr = child.stderr.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { return };
                if let Some(port) = line
                    .split("http://127.0.0.1:")
                    .nth(1)
                    .and_then(|rest| rest.split('/').next())
                    .and_then(|port| port.parse::<u16>().ok())
                {
                    let _ = sender.send(port);
                }
            }
        });
        let port = match receiver.recv_timeout(Duration::from_secs(20)) {
            Ok(port) => port,
            Err(_) => {
                let _ = child.kill();
                panic!("rclone serve s3 wrote no address within 20 s");
            }
        };
        Rclone { child, port }
    }

    /// Returns the endpoint URL of the server.
    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Rclone {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Returns `true` if `weed` runs. With [`REQUIRE_SEAWEEDFS`] set, a missing
/// `weed` fails the test. Else the function writes the reason of the skip of
/// `test` to standard error.
pub fn seaweed_available(test: &str) -> bool {
    let found = Command::new("weed")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    assert!(
        found || std::env::var_os(REQUIRE_SEAWEEDFS).is_none(),
        "{REQUIRE_SEAWEEDFS} is set and weed is not installed, so the SeaweedFS tests cannot run"
    );
    if !found {
        eprintln!("skipping {test}: weed is not installed");
    }
    found
}

/// The port flags of `weed mini` that the harness sets. Each component
/// listens on its HTTP port and on its gRPC port.
const WEED_PORTS: [&str; 10] = [
    "master.port",
    "master.port.grpc",
    "volume.port",
    "volume.port.grpc",
    "filer.port",
    "filer.port.grpc",
    "s3.port",
    "s3.port.grpc",
    "admin.port",
    "admin.port.grpc",
];

/// The components whose sockets `weed mini` makes in `/tmp`, by port.
const WEED_COMPONENTS: [&str; 5] = ["master", "volume", "filer", "s3", "admin"];

/// A running `weed mini` with one bucket. A drop stops it.
///
/// The harness gives each component an explicit port that it picks, and
/// never a default port, so it never meets another SeaweedFS on the host.
/// `weed mini` refuses the port 0. The iceberg server is off.
pub struct Seaweed {
    child: Child,
    /// The ports of [`WEED_PORTS`], in order.
    ports: Vec<u16>,
}

impl Seaweed {
    /// Starts the server with a data directory in `scratch` and the bucket
    /// `bucket`.
    ///
    /// The harness picks free ports, and picks new ones if the server ends
    /// before it is ready, at most three times.
    pub fn start(scratch: &Path, bucket: &str) -> Seaweed {
        let config = scratch.join("weed-s3.json");
        std::fs::write(
            &config,
            format!(
                "{{\"identities\":[{{\"name\":\"tester\",\"credentials\":[{{\"accessKey\":\
                 \"{ACCESS_KEY}\",\"secretKey\":\"{SECRET_KEY}\"}}],\"actions\":[\"Admin\",\
                 \"Read\",\"Write\",\"List\",\"Tagging\"]}}]}}"
            ),
        )
        .unwrap();
        for attempt in 0..3 {
            let data = scratch.join(format!("weed-{attempt}"));
            std::fs::create_dir_all(&data).unwrap();
            // Each listener holds its port until all ports are picked, so
            // the ports differ.
            let listeners: Vec<TcpListener> = WEED_PORTS
                .iter()
                .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
                .collect();
            let ports: Vec<u16> = listeners
                .iter()
                .map(|listener| listener.local_addr().unwrap().port())
                .collect();
            drop(listeners);
            let mut command = Command::new("weed");
            command
                .arg("mini")
                .arg(format!("-dir={}", data.display()))
                .args(["-ip=127.0.0.1", "-ip.bind=127.0.0.1"])
                .args(["-webdav=false", "-admin.ui=false", "-s3.port.iceberg=0"])
                .arg(format!("-s3.config={}", config.display()))
                .arg(format!("-bucket={bucket}"));
            for (flag, port) in WEED_PORTS.iter().zip(&ports) {
                command.arg(format!("-{flag}={port}"));
            }
            let child = command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut weed = Seaweed { child, ports };
            if weed.wait_ready(bucket) {
                return weed;
            }
        }
        panic!("weed mini did not start in three attempts");
    }

    /// Waits until the S3 port answers a request and the bucket `bucket`
    /// exists, at most 30 s. Returns `false` if the server ends first.
    ///
    /// The S3 port of `weed mini` answers before the server makes the
    /// bucket, and a read of a key then gets 404 `NoSuchBucket`.
    fn wait_ready(&mut self, bucket: &str) -> bool {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !answers(self.s3_port()) {
            if self.child.try_wait().unwrap().is_some() {
                return false;
            }
            assert!(
                Instant::now() < deadline,
                "weed mini did not answer on its S3 port within 30 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let client = ostrya_rt::block_on(Bucket::new(&endpoint(
            &self.endpoint(),
            &format!("s3://{bucket}"),
        )))
        .unwrap();
        loop {
            match ostrya_rt::block_on(client.get("config", 1)) {
                Err(ostrya::remote::Error::S3 {
                    code: Some(code), ..
                }) if code == "NoSuchBucket" => {}
                Ok(_) => return true,
                Err(e) => panic!("weed mini did not answer a read of the bucket {bucket}: {e}"),
            }
            if self.child.try_wait().unwrap().is_some() {
                return false;
            }
            assert!(
                Instant::now() < deadline,
                "weed mini did not make the bucket {bucket} within 30 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn s3_port(&self) -> u16 {
        self.ports[WEED_PORTS
            .iter()
            .position(|flag| *flag == "s3.port")
            .unwrap()]
    }

    /// Returns the endpoint URL of the S3 server.
    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.s3_port())
    }
}

impl Drop for Seaweed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // A killed server leaves its sockets in `/tmp`, named by the ports
        // of this server.
        for port in &self.ports {
            for component in WEED_COMPONENTS {
                for kind in ["", "grpc-"] {
                    let socket = format!("/tmp/seaweedfs-{component}-{kind}{port}.sock");
                    let _ = std::fs::remove_file(socket);
                }
            }
        }
    }
}

/// Returns `true` if a server on `port` answers an unsigned `GET /` with an
/// HTTP status line.
fn answers(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 12];
    stream.read_exact(&mut head).is_ok() && head.starts_with(b"HTTP/1.")
}

/// One object of the [`StandIn`]: its bytes and its `ETag`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub bytes: Vec<u8>,
    pub etag: String,
}

/// A change of the objects that a [`StandIn`] runs before a request.
pub type Change = Box<dyn FnOnce(&mut BTreeMap<String, Stored>) + Send>;

/// The state of a [`StandIn`], which a test reads and sets.
pub struct State {
    /// Each object, by its key in the bucket, with the prefix of the
    /// repository.
    pub objects: BTreeMap<String, Stored>,
    /// `true` if a `PUT` with `If-None-Match: *` to a key that holds an
    /// object gets 412.
    pub honor_if_none_match: bool,
    /// `true` if a `DELETE` with `If-Match` gets 412 unless the key holds an
    /// object with that `ETag`.
    pub honor_if_match: bool,
    /// The method and the target of each request, in order.
    pub requests: Vec<(String, String)>,
    /// A method and a count `n`: the server acts on the `n`-th request of
    /// the method, then closes its connection with no response.
    pub close_after: Option<(&'static str, usize)>,
    /// A method and a change that the server runs before the first request
    /// of the method.
    pub before: Option<(&'static str, Change)>,
    /// A method, a key, and a change that the server runs before the first
    /// request of the method to the key, with the prefix of the repository.
    pub before_key: Option<(&'static str, String, Change)>,
    /// A method and a key prefix: each request of the method to a key that
    /// starts with the prefix gets 403 `AccessDenied` and changes nothing.
    pub refuse: Option<(&'static str, String)>,
    /// A method, a key, and a time: the server waits that time before it
    /// acts on each request of the method to the key, with the prefix of the
    /// repository. The wait holds no lock, so the server serves the other
    /// connections in the meantime.
    pub delay: Option<(&'static str, String, Duration)>,
    /// A method and a count `n`: the server answers the `n`-th request of
    /// the method with 503 `SlowDown`, and does not act on it.
    pub slow_down: Option<(&'static str, usize)>,
    /// `true` if the answer to a `GET` of a key has the `ETag` of the
    /// object.
    pub etag_on_get: bool,
    /// The number of requests of each method.
    counts: BTreeMap<String, usize>,
    /// The number of each `ETag`.
    etags: u64,
}

impl State {
    /// Returns a new `ETag`, quoted.
    pub fn next_etag(&mut self) -> String {
        self.etags += 1;
        format!("\"{:032x}\"", self.etags)
    }

    /// Stores `bytes` at `key` with a new `ETag`.
    pub fn store(&mut self, key: &str, bytes: &[u8]) {
        let etag = self.next_etag();
        self.objects.insert(
            key.to_owned(),
            Stored {
                bytes: bytes.to_vec(),
                etag,
            },
        );
    }
}

/// An S3 server in the process, over HTTP/1.1 on a loopback port, with one
/// bucket `bkt`.
///
/// The server accepts each signature. It answers `GET`, `PUT`, and `DELETE`
/// of a key, and `ListObjectsV2` with pages of at most 1000 keys. One
/// thread serves each connection.
pub struct StandIn {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
}

impl StandIn {
    /// Starts a server that honors `If-None-Match` and `If-Match`.
    pub fn start() -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            objects: BTreeMap::new(),
            honor_if_none_match: true,
            honor_if_match: true,
            requests: Vec::new(),
            close_after: None,
            before: None,
            before_key: None,
            refuse: None,
            delay: None,
            slow_down: None,
            etag_on_get: true,
            counts: BTreeMap::new(),
            etags: 0,
        }));
        let shared = state.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let state = shared.clone();
                std::thread::spawn(move || serve(stream, &state));
            }
        });
        StandIn { addr, state }
    }

    /// Returns the endpoint URL of the server.
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Returns the state of the server.
    pub fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
}

/// A request that the stand-in read.
struct Request {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Serves the requests of one connection.
fn serve(mut stream: TcpStream, state: &Mutex<State>) {
    // The head and the body of an answer go in two writes. With Nagle's
    // algorithm, the body then waits for the delayed ACK of the client.
    let _ = stream.set_nodelay(true);
    let mut buffer = Vec::new();
    while let Some(request) = read_request(&mut stream, &mut buffer) {
        let key = request_key(&request.target);
        let delay = state
            .lock()
            .unwrap()
            .delay
            .as_ref()
            .filter(|(method, wanted, _)| {
                *method == request.method && key.as_deref() == Some(wanted.as_str())
            })
            .map(|(_, _, time)| *time);
        if let Some(time) = delay {
            std::thread::sleep(time);
        }
        let (status, headers, body, close) = {
            let mut state = state.lock().unwrap();
            state
                .requests
                .push((request.method.clone(), request.target.clone()));
            let count = {
                let count = state.counts.entry(request.method.clone()).or_default();
                *count += 1;
                *count
            };
            if count == 1
                && let Some((method, _)) = &state.before
                && *method == request.method
            {
                let (_, change) = state.before.take().unwrap();
                change(&mut state.objects);
            }
            if let Some((method, wanted, _)) = &state.before_key
                && *method == request.method
                && key.as_deref() == Some(wanted.as_str())
            {
                let (_, _, change) = state.before_key.take().unwrap();
                change(&mut state.objects);
            }
            let refused = state.refuse.as_ref().is_some_and(|(method, prefix)| {
                *method == request.method && key.as_deref().is_some_and(|k| k.starts_with(prefix))
            });
            let close = state
                .close_after
                .is_some_and(|(method, n)| method == request.method && n == count);
            let slow_down = state
                .slow_down
                .is_some_and(|(method, n)| method == request.method && n == count);
            let (status, headers, body) = if slow_down {
                (503, Vec::new(), s3_error("SlowDown"))
            } else if refused {
                (403, Vec::new(), s3_error("AccessDenied"))
            } else {
                answer(&mut state, &request)
            };
            (status, headers, body, close)
        };
        if close {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        let mut head = format!(
            "HTTP/1.1 {status} Answer\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        if stream.write_all(head.as_bytes()).is_err()
            || stream.write_all(&body).is_err()
            || stream.flush().is_err()
        {
            return;
        }
    }
}

/// Returns the status, the headers, and the body of the answer to
/// `request`, and changes `state` as the request does.
fn answer(state: &mut State, request: &Request) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let (path, query) = request
        .target
        .split_once('?')
        .unwrap_or((request.target.as_str(), ""));
    let Some(key) = path.strip_prefix("/bkt/") else {
        return (404, Vec::new(), s3_error("NoSuchBucket"));
    };
    let key = decode(key);
    if key.is_empty() && request.method == "GET" {
        return list(state, query);
    }
    match request.method.as_str() {
        "GET" => match state.objects.get(&key) {
            Some(stored) => (
                200,
                if state.etag_on_get {
                    vec![("ETag".to_owned(), stored.etag.clone())]
                } else {
                    Vec::new()
                },
                stored.bytes.clone(),
            ),
            None => (404, Vec::new(), s3_error("NoSuchKey")),
        },
        "PUT" => {
            if state.honor_if_none_match
                && request.header("if-none-match") == Some("*")
                && state.objects.contains_key(&key)
            {
                return (412, Vec::new(), s3_error("PreconditionFailed"));
            }
            state.store(&key, &request.body);
            let etag = state.objects[&key].etag.clone();
            (200, vec![("ETag".to_owned(), etag)], Vec::new())
        }
        "DELETE" => {
            if let Some(wanted) = request.header("if-match")
                && state.honor_if_match
            {
                let matches = state.objects.get(&key).is_some_and(|stored| {
                    stored.etag.trim_matches('"') == wanted.trim_matches('"')
                });
                if !matches {
                    return (412, Vec::new(), s3_error("PreconditionFailed"));
                }
            }
            state.objects.remove(&key);
            (204, Vec::new(), Vec::new())
        }
        _ => (405, Vec::new(), s3_error("MethodNotAllowed")),
    }
}

/// Returns the key of the bucket `bkt` that the request target `target`
/// names, with the prefix of the repository, or `None` for another target.
fn request_key(target: &str) -> Option<String> {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    path.strip_prefix("/bkt/").map(decode)
}

/// Returns the answer to the `ListObjectsV2` request with the query `query`.
fn list(state: &State, query: &str) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let parameter = |name: &str| {
        query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(n, _)| *n == name)
            .map(|(_, value)| decode(value))
    };
    let prefix = parameter("prefix").unwrap_or_default();
    let after = parameter("continuation-token");
    let start = match &after {
        Some(after) => Bound::Excluded(after.as_str()),
        None => Bound::Included(prefix.as_str()),
    };
    let mut keys = state
        .objects
        .range::<str, _>((start, Bound::Unbounded))
        .take_while(|(key, _)| key.starts_with(&prefix));
    let page: Vec<(&String, &Stored)> = keys.by_ref().take(1000).collect();
    let truncated = keys.next().is_some();
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    // The listing states the encoding type `url`, so each key goes in that
    // encoding, and a `+` of a delta key goes as `%2B`.
    for (key, stored) in &page {
        body.push_str(&format!(
            "<Contents><Key>{}</Key><Size>{}</Size></Contents>",
            encode(key),
            stored.bytes.len()
        ));
    }
    match page.last() {
        Some((last, _)) if truncated => body.push_str(&format!(
            "<IsTruncated>true</IsTruncated><NextContinuationToken>{last}</NextContinuationToken>"
        )),
        _ => body.push_str("<IsTruncated>false</IsTruncated>"),
    }
    body.push_str("<EncodingType>url</EncodingType></ListBucketResult>");
    (200, Vec::new(), body.into_bytes())
}

/// Returns `text` with each byte other than `A-Z`, `a-z`, `0-9`, `-`, `.`,
/// `_`, `~`, and `/` as `%XX`.
fn encode(text: &str) -> String {
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

/// Returns `text` with each `%XX` decoded.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && let Some(byte) = text
                .get(at + 1..at + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        {
            decoded.push(byte);
            at += 3;
        } else {
            decoded.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(decoded).unwrap()
}

/// The body of an S3 `Error` document with `code`.
fn s3_error(code: &str) -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{code}</Code>\
         <Message>the {code} message</Message></Error>"
    )
    .into_bytes()
}

/// Reads one request from `stream`, or returns `None` at the end of the
/// connection. `buffer` keeps the bytes after the request.
fn read_request(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Option<Request> {
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        let n = stream.read(&mut chunk).ok()?;
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
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    let body = buffer.drain(..length).collect();
    Some(Request {
        method,
        target,
        headers,
        body,
    })
}
