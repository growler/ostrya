#![forbid(unsafe_code)]

//! A fetcher on a host with no CA bundle (Phase 16a).
//!
//! `SSL_CERT_FILE` and `SSL_CERT_DIR` are what the system trust store is read
//! from, so pointing both at paths that do not exist presents the fetcher with
//! the store of a container without ca-certificates. The environment is set for
//! a child process, which keeps the process that reads it free of an in-process
//! `set_var`, and keeps the store the child runs with -- one that trusts nothing
//! -- away from every other test.
//!
//! The same child covers the verification bypass (Phase 23): a bypass variant
//! of `TrustRoots` reads no store, so it builds an `https` fetcher where
//! `TrustRoots::System` fails.

use std::process::Command;

use ostrya::{Fetcher, FetcherOptions, Proxy, TlsOptions, TrustRoots};
use ostrya_rt::block_on;

const NO_CERT_FILE: &str = "/nonexistent/ca-bundle.pem";
const NO_CERT_DIR: &str = "/nonexistent/certs";

/// Options for a fetcher whose mirror is `url` and which reaches every origin
/// directly, so the proxy variables the host running the suite holds decide
/// nothing here.
fn direct_options(url: impl Into<String>) -> FetcherOptions {
    FetcherOptions {
        proxy: Proxy::None,
        ..FetcherOptions::new(url)
    }
}

#[test]
fn a_cleartext_fetcher_needs_no_trust_store() {
    // Re-execute this test binary with the trust store pointed at nothing.
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

/// The half of [`a_cleartext_fetcher_needs_no_trust_store`] that builds the
/// fetchers, run only when this test binary is re-executed with the environment
/// set.
#[test]
#[ignore = "helper process for a_cleartext_fetcher_needs_no_trust_store"]
fn an_absent_trust_store_subprocess() {
    // Without the parent's environment this reads the host's real store, which
    // decides nothing either way.
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

        // One https mirror among cleartext ones is enough to need them.
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

        // A verification bypass reads no store, so the same https mirror that
        // fails above builds here. `TrustRoots::System` failing in the same
        // process is what shows the store this child runs with is empty, so
        // the bypass is what carried the constructor and not a store that
        // happened to hold something.
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
