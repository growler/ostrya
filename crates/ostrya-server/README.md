# ostrya-server

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

The HTTP server of ostrya, for the pull and the push of one repository.

A `Server` serves one repository to the pull of the `ostree` command and
of ostrya. The pull reads it as an `archive` repository, whatever its mode
(see `ostrya::ArchiveView`). With the client groups of the repository
(`ostrya::ReceivePolicies`), the server also runs the receive endpoint
of a push. It identifies the client of each request by the auth items of
the groups, and gives each session the policy of one group. Behind a
proxy, it reads the PROXY protocol header of a connection, and the client
address, the scheme, and the client certificate that a trusted proxy
forwards in the request headers. A host with
its own HTTP router mounts that endpoint as a `ReceiveEndpoint` and
authenticates the requests itself. The server also answers `GET /_ostrya/refs/v1` with the bytes of
`ostrya::Repo::build_ref_listing` for the ref patterns of its query. The
crate builds on Linux alone.

API documentation: <https://docs.rs/ostrya-server>

## Entry points

- `serve` binds the listeners of a `ServeOptions` and runs the server.
- `bind` binds the listeners and returns a `Server` to run with `Server::run`.
- `ServeOptions` holds the addresses, the TLS files, the client CA, the proxy settings, and the options of a push.
- `ReceiveEndpoint::new` creates the receive endpoint for the router of a host.
- `ReceiveEndpoint::handle` answers one request of the endpoint.
- `ReceiveAuth` is the authentication of the endpoint by its host.
- `Error` is the error of each fallible operation of the crate.

## Features

- `smol` (default): the `smol` backend of `ostrya-rt`.
- `tokio`: the `tokio` backend of `ostrya-rt`, for a host on tokio.

## Examples

```rust
use ostrya::Repo;
use ostrya_server::{ServeOptions, bind};
let repo = Repo::open("/srv/repo".as_ref()).await?;
let mut opts = ServeOptions::default();
opts.listen = vec!["0.0.0.0:8080".parse()?];
let server = bind(repo, opts).await?;
println!("listening on {:?}", server.local_addrs());
server.run().await?;
```
