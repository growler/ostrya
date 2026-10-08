//! An adapter that checks each entry of a borrowed [`ArrayIter`].
//!
//! Some object views read a serialized array and check each entry. A dirtree
//! name must be safe for traversal, and the names must be in strict ascending
//! order. An xattr name must be in stored form, and the names must be in strict
//! ascending order. The checks are different, but the control flow is the same:
//!
//! 1. The adapter decodes the next raw element.
//! 2. It runs a check step. The step carries state (the previous name) from one
//!    entry to the next.
//! 3. After the first error, the adapter is exhausted, so that a later caller
//!    cannot resume after a malformed entry.

use ostrya_gvariant::{ArrayIter, GvDecode};

use crate::error::{Error, Result};

/// An iterator that runs `step` on each decoded element of an [`ArrayIter`].
///
/// Each item is a `Result<T>`. `state` carries context from one entry to the
/// next, usually the previous name. After the first `Err`, the adapter is
/// exhausted. The `Err` is a framing error from the inner iterator or an
/// element that `step` refuses.
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
