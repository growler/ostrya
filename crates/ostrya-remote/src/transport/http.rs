//! The HTTP transport. It checks the options of the HTTP client and builds the
//! fetcher of a session.

use ostrya_fetch::{Fetcher, FetcherOptions};

use crate::error::{Error, Result};
use crate::session::http::{Endpoint, MAX_PARALLEL};

/// The maximum number of requests of one session in flight: one object
/// stream for each permit, and one `Have` or `Commit` request.
const MAX_OUTSTANDING: usize = MAX_PARALLEL as usize + 1;

/// Checks `http` and builds the fetcher of the session. The call sends no
/// request.
///
/// `http` must name exactly one mirror, the push address, and the address must
/// pass [`ostrya_fetch::check_base_url`]. The call sets `max_outstanding` to
/// [`MAX_OUTSTANDING`] and `max_redirects` to 0.
pub(super) async fn prepare(mut http: FetcherOptions) -> Result<Endpoint> {
    let url = match http.mirrors.as_slice() {
        [url] => url.clone(),
        mirrors => {
            return Err(Error::InvalidInput(format!(
                "an HTTP push needs exactly one mirror, the push address, and the options \
                 name {}",
                mirrors.len()
            )));
        }
    };
    // The message of the fetcher holds no userinfo.
    ostrya_fetch::check_base_url(&url).map_err(|e| Error::InvalidInput(format!("address: {e}")))?;
    http.max_outstanding = MAX_OUTSTANDING;
    http.max_redirects = 0;
    // The future of the construction is large. The box keeps it out of the
    // connect futures of the session.
    let fetcher = Box::pin(Fetcher::new(http)).await.map_err(Error::Fetch)?;
    Ok(Endpoint { fetcher, url })
}
