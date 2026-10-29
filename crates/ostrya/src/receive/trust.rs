//! The receive-side check of the trusted keys, which runs each verifier of
//! each axis on the blocking pool.

use ostrya_core::Value;

use crate::error::Result;
use crate::verify::{Payload, TrustedKeys};

impl TrustedKeys {
    /// Verifies `payload` against every axis of this set.
    ///
    /// `detached` is the detached-metadata dict that holds the signatures. It
    /// is `None` if the payload has no detached metadata. `subject` names the
    /// payload in a message.
    ///
    /// Each verifier of each axis runs on the blocking pool, because a
    /// verifier does its work in the call. A client controls the number of
    /// signature blobs, and an RSA verify with a 16384-bit key takes
    /// milliseconds of CPU time.
    pub(crate) async fn check<'p>(
        &self,
        subject: &str,
        payload: impl Into<Payload<'p>>,
        detached: Option<&Value>,
    ) -> Result<()> {
        self.policy().check(subject, payload, detached).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::trust::tests::{PAYLOAD, ThreadRecorder, dict_with};

    /// The trust check runs the verifiers on the blocking pool, so a verifier
    /// that works in the call does not hold the async executor.
    #[test]
    fn the_trust_check_verifies_on_the_blocking_pool() {
        let recorder = ThreadRecorder::new("ostree.sign.ed25519");
        let keys = TrustedKeys::new(vec![std::sync::Arc::new(recorder.clone())]).unwrap();
        let dict = dict_with("ostree.sign.ed25519", vec![7; 64]);
        ostrya_rt::block_on(keys.check("commit", PAYLOAD, Some(&dict))).unwrap();
        recorder.assert_one_foreign_call();
    }
}
