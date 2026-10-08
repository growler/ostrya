#![forbid(unsafe_code)]

//! Tests of a fetcher on a host with no CA bundle.
//!
//! The fetcher reads the system trust store from `SSL_CERT_FILE` and
//! `SSL_CERT_DIR`. If both point at paths that do not exist, the fetcher sees
//! the store of a container with no ca-certificates package. The test sets the
//! two variables only in a child process. Because of this, the test needs no
//! in-process `set_var`, and the empty store does not reach other tests.
//!
//! The same child process also checks the verification bypass. A bypass
//! variant of `TrustRoots` reads no store, so it builds an `https` fetcher
//! where `TrustRoots::System` fails.

use std::process::Command;

use ostrya::{Fetcher, FetcherOptions, Proxy, TlsOptions, TrustRoots};
use ostrya_rt::block_on;

const NO_CERT_FILE: &str = "/nonexistent/ca-bundle.pem";
const NO_CERT_DIR: &str = "/nonexistent/certs";

/// Returns the options of a fetcher with the mirror `url` and no proxy.
///
/// The fetcher connects to each origin directly, so the proxy variables of the
/// host that runs the tests have no effect.
fn direct_options(url: impl Into<String>) -> FetcherOptions {
    FetcherOptions {
        proxy: Proxy::None,
        ..FetcherOptions::new(url)
    }
}

#[test]
fn a_cleartext_fetcher_needs_no_trust_store() {
    // Run this test binary again, with the trust store variables set to
    // paths that do not exist.
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "an_absent_trust_store_subprocess",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("SSL_CERT_FILE", NO_CERT_FILE)
        .env("SSL_CERT_DIR", NO_CERT_DIR)
        .output()
        .expect("re-execute this test binary");
    assert!(
        child.status.success(),
        "the child reported {}:\n{}{}",
        child.status,
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
}

/// Builds the fetchers for `a_cleartext_fetcher_needs_no_trust_store`.
///
/// This test does its work only when the parent test runs this binary again
/// with the variables set.
#[test]
#[ignore = "helper process for a_cleartext_fetcher_needs_no_trust_store"]
fn an_absent_trust_store_subprocess() {
    // If the parent test did not set the variables, this process reads the
    // real store of the host, and the result proves nothing.
    if std::env::var("SSL_CERT_FILE").ok().as_deref() != Some(NO_CERT_FILE) {
        return;
    }

    block_on(async {
        Fetcher::new(direct_options("http://example.invalid/repo"))
            .await
            .expect("a cleartext mirror opens no handshake, so it needs no anchors");

        let err = Fetcher::new(direct_options("https://example.invalid/repo"))
            .await
            .expect_err("an https mirror needs anchors the handshake can use");
        assert!(err.to_string().contains("no trusted certificates"), "{err}");

        // If one mirror of many uses https, the fetcher needs trust anchors.
        let mixed = FetcherOptions {
            mirrors: vec![
                "http://example.invalid/repo".to_owned(),
                "https://example.invalid/mirror".to_owned(),
            ],
            proxy: Proxy::None,
            ..FetcherOptions::default()
        };
        let err = Fetcher::new(mixed)
            .await
            .expect_err("an https mirror needs anchors the handshake can use");
        assert!(err.to_string().contains("no trusted certificates"), "{err}");

        // A verification bypass reads no store, so the https mirror that
        // fails with `TrustRoots::System` builds here. The failure of
        // `TrustRoots::System` in this process shows that the store of this
        // child is empty. The bypass alone lets the constructor succeed.
        for roots in [
            TrustRoots::DangerousAcceptAnyChain,
            TrustRoots::DangerousAcceptAny,
        ] {
            let options = FetcherOptions {
                tls: TlsOptions {
                    roots: roots.clone(),
                    client_identity: None,
                },
                ..direct_options("https://example.invalid/repo")
            };
            Fetcher::new(options)
                .await
                .unwrap_or_else(|e| panic!("{roots:?} reads no trust store: {e}"));
        }
    });
}
