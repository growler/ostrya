//! A fused, validating adapter over a borrowed [`ArrayIter`].
//!
//! Several object views iterate a serialized array while applying value-level
//! checks per entry: dirtree names must be traversal-safe and strictly sorted,
//! xattr names must be in stored form and strictly increasing. The checks
//! differ, but the control flow is identical: decode the next raw element, run
//! a validation step that threads state (the previous name) across entries, and
//! fuse on the first error so a later caller cannot resume past a malformed
//! entry.

use ostrya_gvariant::{ArrayIter, GvDecode};

use crate::error::{Error, Result};

/// Wraps an [`ArrayIter`] and runs `step` on each decoded element, yielding
/// `Result<T>`. `state` carries context between entries (typically the previous
/// name); after the first `Err` -- a framing error from the inner iterator or a
/// rejected element -- the adapter is exhausted.
pub(crate) struct ValidatedIter<'a, E, T, S> {
    inner: ArrayIter<'a, E>,
    state: S,
    step: fn(&mut S, E) -> Result<T>,
    failed: bool,
}

impl<'a, E, T, S> ValidatedIter<'a, E, T, S> {
    pub(crate) fn new(inner: ArrayIter<'a, E>, state: S, step: fn(&mut S, E) -> Result<T>) -> Self {
        ValidatedIter {
            inner,
            state,
            step,
            failed: false,
        }
    }
}

impl<'a, E, T, S> Iterator for ValidatedIter<'a, E, T, S>
where
    E: GvDecode<'a>,
{
    type Item = Result<T>;

    fn next(&mut self) -> Option<Result<T>> {
        if self.failed {
            return None;
        }
        let raw = match self.inner.next()? {
            Ok(entry) => entry,
            Err(e) => {
                self.failed = true;
                return Some(Err(Error::from(e)));
            }
        };
        let out = (self.step)(&mut self.state, raw);
        if out.is_err() {
            self.failed = true;
        }
        Some(out)
    }
}
