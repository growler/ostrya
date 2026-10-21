//! A `rclone serve s3` server for the tests of a pull from an `s3://`
//! address.
//!
//! The server serves a directory with a key pair and a port that it picks.
//! The top-level directories of the served directory are the buckets.
//!
//! A test skips when `rclone` is not on `PATH`, and writes the reason to
//! standard error. With `OSTRYA_REQUIRE_S3` set, a missing `rclone` fails
//! the test.
//!
//! The server keeps the listing of each directory for one hour. So a test
//! writes each file of the served directory before the server starts.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The access key id of the server. `rclone serve s3` refuses a very short
/// key.
pub const ACCESS_KEY: &str = "ostryatest";
/// The secret access key of the server.
pub const SECRET_KEY: &str = "ostryasecret";

/// The environment variable that turns the skip for a missing `rclone` into
/// a failure.
pub const REQUIRE_S3: &str = "OSTRYA_REQUIRE_S3";

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
