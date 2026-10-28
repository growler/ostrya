# ostrya-rt

Ostrya \[_n._ a botanical genus within the family Betulaceae, commonly
known as _ironwood tree_\] is a pure-Rust, async implementation of the
ostree repository system, written from scratch.

The async runtime layer of ostrya, over a `smol` or a `tokio` backend.

The other ostrya crates run tasks, blocking work, file I/O, TCP, timers,
and helper processes through this crate. It is the only ostrya crate that
names the backend. Its stream types implement the `futures-io` traits with
each backend, so the code of a caller does not change with the backend.
The crate compiles on Unix and Windows.

API documentation: <https://docs.rs/ostrya-rt>

## Entry points

- `spawn` starts a task and returns a `JoinHandle`.
- `unblock` and `unblock_detached` run a closure on the blocking pool.
  `unblock_task` runs one there and returns a `JoinHandle`.
- `File` and `FileReader` stream over an open file descriptor.
- `TcpStream` and `TcpListener` carry async TCP.
- `Command` runs a helper process.
- `Timer` and `Deadline` measure a time window.
- `block_on` runs a future to completion on the current thread.

## Features

- `smol` (default): the `smol` backend.
- `tokio`: the `tokio` backend. It adds the `tokio_io` module, and
  `File` and `TcpStream` also implement the tokio I/O traits.

If both features are on, `tokio` selects the backend, so a build in which
Cargo unifies the two features still compiles. If neither feature is on,
the build stops with a compile error. With the `tokio` feature, the I/O,
the timers, and the tasks of this crate need a tokio runtime context.
`block_on` gives one.

## Examples

```rust
let total = ostrya_rt::block_on(async {
    let task = ostrya_rt::spawn(async { 6 * 7 });
    let sum = ostrya_rt::unblock(|| (1..=4).sum::<u32>()).await;
    task.await + sum
});
assert_eq!(total, 52);
```
