//! The receive-side check of the trusted keys, which runs the verifiers of
//! the sign-api axis on the blocking pool.

use ostrya_core::Value;

use crate::error::Result;
use crate::verify::TrustedKeys;

impl TrustedKeys {
    /// Verifies `payload` against every axis of this set.
    ///
    /// `detached` is the detached-metadata dict that holds the signatures. It
    /// is `None` if the payload has no detached metadata. `subject` names the
    /// payload in a message.
    ///
    /// The verifiers of the sign-api axis run on the blocking pool, with a
    /// copy of `payload`, because the ed25519 and spki verifiers do their work
    /// in the call. A client controls the number of signature blobs, and an
    /// RSA verify with a 16384-bit key takes milliseconds of CPU time.
    pub(crate) async fn check(
        &self,
        subject: &str,
        payload: &[u8],
        detached: Option<&Value>,
    ) -> Result<()> {
        self.policy()
            .check_unblocked(subject, payload, detached)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::trust::tests::{PAYLOAD, dict_with};

    /// A verifier that accepts each blob and records the thread of each call.
    #[derive(Default)]
    struct ThreadRecorder {
        /// The thread of each call to `verify`, in order.
        threads: std::sync::Mutex<Vec<std::thread::ThreadId>>,
    }

    impl crate::sign::Verifier for ThreadRecorder {
        fn metadata_key(&self) -> &str {
            "ostree.sign.ed25519"
        }

        fn verify<'a>(
            &'a self,
            _data: &'a [u8],
            signatures: &'a [Vec<u8>],
        ) -> crate::sign::VerifyFuture<'a> {
            self.threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());
            let outcome = crate::sign::VerifyOutcome {
                valid: !signatures.is_empty(),
                ..Default::default()
            };
            Box::pin(async move { Ok(outcome) })
        }
    }

    /// The trust check runs the verifiers of the sign-api axis on the blocking
    /// pool, so a verifier that works in the call does not hold the async
    /// executor.
    #[test]
    fn the_sign_api_axis_verifies_on_the_blocking_pool() {
        let recorder = std::sync::Arc::new(ThreadRecorder::default());
        let verifier: std::sync::Arc<dyn crate::sign::Verifier> = recorder.clone();
        let keys = TrustedKeys::new(vec![verifier]).unwrap();
        let dict = dict_with("ostree.sign.ed25519", vec![7; 64]);
        ostrya_rt::block_on(keys.check("commit", PAYLOAD, Some(&dict))).unwrap();
        let threads = recorder.threads.lock().unwrap();
        assert_eq!(threads.len(), 1);
        assert_ne!(threads[0], std::thread::current().id());
    }
}
