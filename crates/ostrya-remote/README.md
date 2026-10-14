# ostrya-remote

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

The wire codec and the client sessions of the ostrya push and pull.

A caller pushes a local directory with `push_tree`, or its own objects with a
`PushSession`. A `PullSession` reads the summary and the ref listings of a remote. The
crate has no repository knowledge, and it compiles on Linux, macOS, and Windows.

API documentation: <https://docs.rs/ostrya-remote>

## Entry points

- `Endpoint::parse` reads an address into an `Endpoint`.
- `push_tree` pushes a local directory to an endpoint as one commit.
- `PushSession::connect` opens a push session to an endpoint.
- `PushSession::prepare` checks an endpoint before the session opens.
- `PushSession::over_stream` opens a push session over a pair of byte streams.
- `PullSession::connect` opens the session of a pull to an endpoint.
- `StreamSession::connect` opens a stream session over ssh.
- `Error` is the error of each fallible operation.

## Modules

- `proto`: the wire format and its codec.
- `session`: the push and pull sessions, their progress, and the one-way stream.
- `transport`: the endpoints, the addresses, and the ssh and HTTP transports.
- `tree`: the walk and the hash of a local directory.

## Features

- `smol` (default): the `smol` backend of `ostrya-rt` for the ssh and HTTP transports.
- `tokio`: the `tokio` backend of `ostrya-rt` for the ssh and HTTP transports.

## Examples

```rust
use ostrya_remote::{TreePushOptions, push_tree, transport::Endpoint};
let endpoint = Endpoint::parse("ssh://builder@repo.example.com/srv/repo")?;
let opts = TreePushOptions { refs: vec!["exampleos/stable".into()], ..Default::default() };
let outcome = push_tree(endpoint, "rootfs".as_ref(), opts).await?;
println!("{:?}", outcome.commit);
```
