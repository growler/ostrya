# ostrya-fetch

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

An async HTTP/1.1 and HTTP/2 client over rustls, for the mirrors of a remote.

A caller builds a `Fetcher` from the mirrors, headers, credentials, proxy,
TLS configuration, retry limits, and deadlines of one remote. The fetcher
downloads files with `GET` and sends uploads with `POST` or `DELETE`. A
response body streams in bounded chunks, so no object is held whole in memory.

The `Target` of a request is a path under each mirror, a path with a
query string under each mirror, or an absolute URL. The fetcher sends a
path and a query as written, so the caller escapes them.

API documentation: <https://docs.rs/ostrya-fetch>

## Entry points

- `Fetcher::new` builds a fetcher from `FetcherOptions`.
- `Fetcher::fetch` sends a `FetchRequest` and returns a `Fetched`.
- `Body` streams a response body in bounded chunks.
- `Fetcher::refetching` returns a `Refetch`, which fetches a failed body again.
- `Fetcher::upload` sends an `UploadRequest` and returns an `Uploaded`.
- `UploadBody` gives an upload body whole or streams it from an `UploadWriter`.
- `Error` is the error of each fallible operation of the crate.

## Modules

- `gate`: the priority admission gate that bounds concurrent work.

## Features

- `smol` (default): the `smol` backend of `ostrya-rt`.
- `tokio`: the `tokio` backend of `ostrya-rt`, with tokio I/O impls on `Body` and `UploadWriter`.

## Examples

```rust
use futures_lite::AsyncReadExt;
use ostrya_fetch::{FetchRequest, Fetched, Fetcher, FetcherOptions};
let fetcher = Fetcher::new(FetcherOptions::new("https://example.com/repo")).await?;
if let Fetched::Body(mut body) = fetcher.fetch(FetchRequest::path("config")).await? {
    let mut config = Vec::new();
    body.read_to_end(&mut config).await?;
}
```
