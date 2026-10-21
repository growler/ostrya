//! Tests of the bucket client against `rclone serve s3`.
//!
//! Each test starts `rclone serve s3` on a scratch directory, with a key pair
//! and a port that the server picks. The top-level directories of the scratch
//! directory are the buckets.
//!
//! A test skips when `rclone` is not on `PATH`, and writes the reason to
//! standard error. With `OSTRYA_REQUIRE_S3` set, a missing `rclone` fails
//! the test.
//!
//! The server keeps the listing of each directory for one hour. So a test
//! writes each file that it puts in the scratch directory itself before its
//! first request. A file that it writes after a request can be absent from
//! a listing.

#![cfg(feature = "s3")]

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use futures_lite::io::AsyncReadExt;
use ostrya_core::Checksum;
use ostrya_fetch::{
    FetchRequest, Fetched, Fetcher, FetcherOptions, Proxy, Target, UploadBody, UploadMethod,
    UploadRequest,
};
use ostrya_remote::Error;
use ostrya_remote::s3::{Address, Bucket, Credentials, Location, PutIfAbsent, S3Endpoint, SigV4};
use ostrya_rt::block_on;
use sha2::{Digest, Sha256};

const ACCESS_KEY: &str = "ostryatest";
const SECRET_KEY: &str = "ostryasecret";

/// Returns `true` if `rclone` runs. With `OSTRYA_REQUIRE_S3` set, a missing
/// `rclone` fails the test.
fn rclone_available() -> bool {
    let found = Command::new("rclone")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    assert!(
        found || std::env::var_os("OSTRYA_REQUIRE_S3").is_none(),
        "OSTRYA_REQUIRE_S3 is set and rclone is not installed, so the S3 tests cannot run"
    );
    found
}

/// Returns `true` if the test runs. Writes the reason of a skip to standard
/// error.
fn runs(test: &str) -> bool {
    let found = rclone_available();
    if !found {
        eprintln!("skipping {test}: rclone is not installed");
    }
    found
}

/// A scratch directory under the temporary directory. A drop removes it.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ostrya-remote-s3-bucket-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Scratch { path }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A running `rclone serve s3` on the directory `root` of a scratch
/// directory. A drop stops it.
struct Rclone {
    child: Child,
    port: u16,
    scratch: Scratch,
}

impl Rclone {
    /// Starts the server with the buckets `buckets`, each an empty directory.
    fn start(tag: &str, buckets: &[&str]) -> Rclone {
        let scratch = Scratch::new(tag);
        let root = scratch.path.join("root");
        for bucket in buckets {
            fs::create_dir_all(root.join(bucket)).unwrap();
        }
        // An empty config file, so the server reads no config of the user.
        let config = scratch.path.join("rclone.conf");
        fs::write(&config, "").unwrap();
        // The directory cache time is not zero. With `--dir-cache-time 0s`,
        // rclone 1.75.1 starts the cleanup timer of a directory with a
        // virtual entry again with no delay, each time that it expires. A
        // `PUT` and a multipart upload make such entries. The server then
        // runs the cleanup with no end, and a request can get no response
        // for more than 60 s.
        let mut child = Command::new("rclone")
            .args(["serve", "s3", "--config"])
            .arg(&config)
            .args(["--auth-key", &format!("{ACCESS_KEY},{SECRET_KEY}")])
            .args(["--addr", "127.0.0.1:0", "--dir-cache-time", "1h"])
            .arg(&root)
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
        Rclone {
            child,
            port,
            scratch,
        }
    }

    /// Returns the directory that the server serves.
    fn root(&self) -> PathBuf {
        self.scratch.path.join("root")
    }

    /// Returns the endpoint of `address` on the server, with `secret` as the
    /// secret access key.
    fn endpoint_with(&self, address: &str, secret: &str) -> S3Endpoint {
        let location = Location::new(
            Address::parse(address).unwrap(),
            "us-east-1",
            Some(&format!("http://127.0.0.1:{}", self.port)),
            None,
        )
        .unwrap();
        let credentials = Credentials::new(ACCESS_KEY.into(), secret.into(), None).unwrap();
        let mut endpoint = S3Endpoint::new(location, credentials);
        endpoint.http.allow_cleartext_credentials = true;
        endpoint.http.proxy = Proxy::None;
        endpoint.http.max_retries = 1;
        endpoint
    }

    async fn bucket(&self, address: &str) -> Bucket {
        Bucket::new(&self.endpoint_with(address, SECRET_KEY))
            .await
            .unwrap()
    }

    /// Returns a fetcher of the bucket `bucket` that signs its requests, for
    /// the requests that the bucket client does not send.
    async fn signed_fetcher(&self, bucket: &str) -> Fetcher {
        let credentials = Credentials::new(ACCESS_KEY.into(), SECRET_KEY.into(), None).unwrap();
        let options = FetcherOptions {
            signer: Some(Arc::new(SigV4::new(credentials, "us-east-1").unwrap())),
            allow_cleartext_credentials: true,
            proxy: Proxy::None,
            max_redirects: 0,
            max_retries: 1,
            ..FetcherOptions::new(format!("http://127.0.0.1:{}/{bucket}", self.port))
        };
        Fetcher::new(options).await.unwrap()
    }
}

impl Drop for Rclone {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Writes `bytes` to `path`, with the parent directories.
fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// Returns the object key of the checksum `checksum` with `ext`.
fn object_key(checksum: &Checksum, ext: &str) -> String {
    let hex = checksum.to_hex();
    format!("objects/{}/{}.{ext}", &hex[..2], &hex[2..])
}

/// Returns a checksum whose modified base64 holds `+` and `_`.
fn delta_checksum() -> Checksum {
    let mut bytes = [0x11u8; 32];
    bytes[..3].copy_from_slice(&[0xfb, 0xff, 0xbf]);
    Checksum::from_bytes(bytes)
}

#[test]
fn put_get_delete_round_trip() {
    if !runs("put_get_delete_round_trip") {
        return;
    }
    let rclone = Rclone::start("round-trip", &["bkt"]);
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        let etag = bucket
            .put("config", b"[core]\nmode=archive\n".to_vec())
            .await
            .unwrap();
        assert!(etag.is_some());
        assert_eq!(
            fs::read(rclone.root().join("bkt/repo/config")).unwrap(),
            b"[core]\nmode=archive\n"
        );
        let object = bucket.get("config", 1024).await.unwrap().unwrap();
        assert_eq!(object.bytes, b"[core]\nmode=archive\n");
        assert!(object.etag.is_some());
        bucket.delete("config").await.unwrap();
        assert!(!rclone.root().join("bkt/repo/config").exists());
        assert_eq!(bucket.get("config", 1024).await.unwrap(), None);
    });
}

#[test]
fn get_of_an_absent_key_is_none() {
    if !runs("get_of_an_absent_key_is_none") {
        return;
    }
    let rclone = Rclone::start("absent", &["bkt"]);
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        assert_eq!(bucket.get("summary", 1024).await.unwrap(), None);
        assert!(bucket.get_stream("summary").await.unwrap().is_none());
    });
}

#[test]
fn delete_of_an_absent_key_succeeds() {
    if !runs("delete_of_an_absent_key_succeeds") {
        return;
    }
    let rclone = Rclone::start("delete-absent", &["bkt"]);
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        bucket.delete("summary.sig").await.unwrap();
    });
}

#[test]
fn get_stream_reads_a_large_object() {
    if !runs("get_stream_reads_a_large_object") {
        return;
    }
    let rclone = Rclone::start("stream", &["bkt"]);
    let key = object_key(&Checksum::from_bytes([0xab; 32]), "filez");
    // 64 MiB of a pattern, written in chunks and hashed on the way.
    let path = rclone.root().join("bkt/repo").join(&key);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = fs::File::create(&path).unwrap();
    let mut digest = Sha256::new();
    let mut chunk = vec![0u8; 1 << 20];
    for round in 0..64u32 {
        for (at, byte) in chunk.iter_mut().enumerate() {
            *byte = (at as u32).wrapping_mul(31).wrapping_add(round) as u8;
        }
        digest.update(&chunk);
        std::io::Write::write_all(&mut file, &chunk).unwrap();
    }
    drop(file);
    let expected: [u8; 32] = digest.finalize().into();
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        let mut stream = bucket.get_stream(&key).await.unwrap().unwrap();
        assert_eq!(stream.content_length(), Some(64 << 20));
        assert!(stream.etag().is_some());
        let mut digest = Sha256::new();
        let mut buffer = vec![0u8; 256 * 1024];
        let mut total = 0u64;
        loop {
            let n = stream.read(&mut buffer).await.unwrap();
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
            total += n as u64;
        }
        assert_eq!(total, 64 << 20);
        let found: [u8; 32] = digest.finalize().into();
        assert_eq!(found, expected);
    });
}

#[test]
fn put_if_absent_creates_an_absent_key() {
    if !runs("put_if_absent_creates_an_absent_key") {
        return;
    }
    let rclone = Rclone::start("put-if-absent", &["bkt"]);
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        let created = bucket
            .put_if_absent("extensions/ostrya/lock", b"holder".to_vec())
            .await
            .unwrap();
        assert!(
            matches!(created, PutIfAbsent::Created { etag: Some(_) }),
            "{created:?}"
        );
        assert_eq!(
            fs::read(rclone.root().join("bkt/repo/extensions/ostrya/lock")).unwrap(),
            b"holder"
        );
    });
}

#[test]
fn list_follows_pages() {
    if !runs("list_follows_pages") {
        return;
    }
    let rclone = Rclone::start("pages", &["bkt"]);
    let mut expected = Vec::new();
    for n in 0..2500u32 {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[28..].copy_from_slice(&n.to_be_bytes());
        let key = object_key(&Checksum::from_bytes(bytes), "dirtree");
        let size = (n % 7) as usize;
        write(
            &rclone.root().join("bkt/repo").join(&key),
            &vec![b'x'; size],
        );
        expected.push((key, size as u64));
    }
    expected.sort();
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        let listing = bucket.list("objects/ab/").await.unwrap();
        let mut found: Vec<(String, u64)> = listing
            .objects
            .into_iter()
            .map(|object| (object.key, object.size))
            .collect();
        found.sort();
        assert_eq!(found.len(), 2500);
        assert_eq!(found, expected);
    });
}

#[test]
fn list_does_not_reach_a_sibling_prefix() {
    if !runs("list_does_not_reach_a_sibling_prefix") {
        return;
    }
    let rclone = Rclone::start("sibling", &["bkt"]);
    let key = object_key(&Checksum::from_bytes([0xcd; 32]), "commit");
    write(&rclone.root().join("bkt/repo").join(&key), b"mine");
    write(&rclone.root().join("bkt/repo2").join(&key), b"sibling");
    write(&rclone.root().join("bkt/repo2/config"), b"sibling");
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        let listing = bucket.list("objects/").await.unwrap();
        let keys: Vec<&str> = listing.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, [key.as_str()]);
        assert_eq!(listing.objects[0].size, 4);
    });
}

#[test]
fn list_with_a_delimiter_gives_common_prefixes() {
    if !runs("list_with_a_delimiter_gives_common_prefixes") {
        return;
    }
    let rclone = Rclone::start("delimiter", &["bkt"]);
    let key = object_key(&Checksum::from_bytes([0xab; 32]), "commit");
    let repo = rclone.root().join("bkt/repo");
    write(&repo.join(&key), b"commit");
    write(&repo.join("objects/abc"), b"stray");
    write(&repo.join("objects/zz/x"), b"stray");
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        let listing = bucket.list_delimited("objects/").await.unwrap();
        let keys: Vec<&str> = listing.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, ["objects/abc"]);
        let mut prefixes = listing.common_prefixes.clone();
        prefixes.sort();
        assert_eq!(prefixes, ["objects/ab/", "objects/zz/"]);
    });
}

#[test]
fn list_uploads_keeps_repository_keys() {
    if !runs("list_uploads_keeps_repository_keys") {
        return;
    }
    let rclone = Rclone::start("uploads", &["bkt"]);
    let key = object_key(&Checksum::from_bytes([0x5a; 32]), "filez");
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        // A bucket in which no upload began has no uploads.
        assert!(bucket.list_uploads().await.unwrap().is_empty());

        let fetcher = rclone.signed_fetcher("bkt").await;
        let mut ids = Vec::new();
        for full in [
            format!("repo/{key}"),
            "repo2/config".to_owned(),
            "other/key".to_owned(),
            key.clone(),
        ] {
            let uploaded = fetcher
                .upload(UploadRequest {
                    method: UploadMethod::Post,
                    target: Target::PathQuery {
                        path: &full,
                        query: "uploads",
                    },
                    ..UploadRequest::path(&full, UploadBody::bytes(Vec::new()))
                })
                .await
                .unwrap_or_else(|e| panic!("{full}: {e}"));
            assert_eq!(uploaded.status(), 200, "{full}");
            let mut body = Vec::new();
            uploaded.into_body().read_to_end(&mut body).await.unwrap();
            let body = String::from_utf8(body).unwrap();
            let id = body
                .split("<UploadId>")
                .nth(1)
                .and_then(|rest| rest.split("</UploadId>").next())
                .unwrap()
                .to_owned();
            ids.push(id);
        }

        let uploads = bucket.list_uploads().await.unwrap();
        assert_eq!(uploads.len(), 1, "{uploads:?}");
        assert_eq!(uploads[0].key, key);
        assert_eq!(uploads[0].upload_id, ids[0]);
        assert!(!uploads[0].initiated.is_empty());

        // With no prefix, the list covers the bucket and keeps the keys of a
        // bucket repository alone.
        let root = rclone.bucket("s3://bkt").await;
        let uploads = root.list_uploads().await.unwrap();
        let mut keys: Vec<&str> = uploads.iter().map(|u| u.key.as_str()).collect();
        keys.sort();
        assert_eq!(keys, [key.as_str()]);
        assert_eq!(uploads[0].upload_id, ids[3]);
    });
}

#[test]
fn a_key_with_plus_round_trips() {
    if !runs("a_key_with_plus_round_trips") {
        return;
    }
    let rclone = Rclone::start("plus", &["bkt"]);
    // A space and a `+` in a listing with the encoding type `url`.
    write(&rclone.root().join("bkt/enc/objects/sp ace"), b"s");
    write(&rclone.root().join("bkt/enc/objects/pl+us"), b"p");
    let to = delta_checksum().to_base64_modified();
    assert!(to.contains('+') && to.contains('_'), "{to}");
    let key = format!("deltas/{}/{}/superblock", &to[..2], &to[2..]);
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        bucket.put(&key, b"superblock".to_vec()).await.unwrap();
        // The server stores the key with a literal `+`.
        assert_eq!(
            fs::read(rclone.root().join("bkt/repo").join(&key)).unwrap(),
            b"superblock"
        );
        // The listing gives the key back with its `+`.
        let listing = bucket.list("deltas/").await.unwrap();
        let keys: Vec<&str> = listing.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, [key.as_str()]);
        // The client sends `+` as `%2B`, and a request with a raw `+` reads
        // the same object.
        assert_eq!(
            bucket.get(&key, 64).await.unwrap().unwrap().bytes,
            b"superblock"
        );
        let fetcher = rclone.signed_fetcher("bkt").await;
        let raw = format!("repo/{key}");
        assert!(raw.contains('+'));
        let fetched = fetcher.fetch(FetchRequest::path(&raw)).await.unwrap();
        let Fetched::Body(mut body) = fetched else {
            panic!("a 304 for {raw}");
        };
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"superblock");

        // The files that the test wrote before the first request.
        let bucket = rclone.bucket("s3://bkt/enc").await;
        let listing = bucket.list("objects/").await.unwrap();
        let mut keys: Vec<&str> = listing.objects.iter().map(|o| o.key.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["objects/pl+us", "objects/sp ace"]);
    });
}

#[test]
fn a_non_ascii_ref_round_trips() {
    if !runs("a_non_ascii_ref_round_trips") {
        return;
    }
    let rclone = Rclone::start("non-ascii", &["bkt"]);
    let commit = Checksum::from_bytes([0x42; 32]).to_hex();
    block_on(async {
        let bucket = rclone.bucket("s3://bkt/repo").await;
        bucket
            .put("refs/heads/grün/stable", format!("{commit}\n").into_bytes())
            .await
            .unwrap();
        assert!(
            rclone
                .root()
                .join("bkt/repo/refs/heads/grün/stable")
                .exists()
        );
        let listing = bucket.list("refs/heads/").await.unwrap();
        let keys: Vec<&str> = listing.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, ["refs/heads/grün/stable"]);
        let object = bucket
            .get("refs/heads/grün/stable", 128)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(object.bytes, format!("{commit}\n").as_bytes());
    });
}

#[test]
fn a_wrong_secret_gives_signature_does_not_match() {
    if !runs("a_wrong_secret_gives_signature_does_not_match") {
        return;
    }
    let rclone = Rclone::start("wrong-secret", &["bkt"]);
    block_on(async {
        let endpoint = rclone.endpoint_with("s3://bkt/repo", "notthesecret");
        let bucket = Bucket::new(&endpoint).await.unwrap();
        let err = bucket.get("config", 64).await.unwrap_err();
        assert!(
            matches!(&err, Error::S3 { status: 403, code: Some(code), .. } if code == "SignatureDoesNotMatch"),
            "{err}"
        );
        assert!(err.to_string().contains("SignatureDoesNotMatch"));
        assert!(!err.to_string().contains("notthesecret"));
    });
}

#[test]
fn an_absent_bucket_gives_no_such_bucket() {
    if !runs("an_absent_bucket_gives_no_such_bucket") {
        return;
    }
    let rclone = Rclone::start("no-bucket", &["bkt"]);
    block_on(async {
        let bucket = rclone.bucket("s3://absent/repo").await;
        for err in [
            bucket.get("config", 64).await.unwrap_err(),
            bucket.list("objects/").await.unwrap_err(),
        ] {
            assert!(
                matches!(&err, Error::S3 { status: 404, code: Some(code), .. } if code == "NoSuchBucket"),
                "{err}"
            );
        }
    });
}

#[test]
fn a_bucket_without_a_prefix_works() {
    if !runs("a_bucket_without_a_prefix_works") {
        return;
    }
    let rclone = Rclone::start("no-prefix", &["bkt"]);
    let key = object_key(&Checksum::from_bytes([0x77; 32]), "dirmeta");
    block_on(async {
        let bucket = rclone.bucket("s3://bkt").await;
        bucket.put(&key, b"dirmeta".to_vec()).await.unwrap();
        bucket.put("config", b"config".to_vec()).await.unwrap();
        assert!(rclone.root().join("bkt").join(&key).exists());
        assert!(rclone.root().join("bkt/config").exists());
        let listing = bucket.list("objects/").await.unwrap();
        let keys: Vec<&str> = listing.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, [key.as_str()]);
        assert_eq!(
            bucket.get("config", 64).await.unwrap().unwrap().bytes,
            b"config"
        );
    });
}
