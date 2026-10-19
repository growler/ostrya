# Contributing to Ostrya

This file gives the procedures for work on the Ostrya source tree. The design
documents in `docs/` are the source of truth. A change that alters behavior
changes the related document in the same commit.

## Development environment

The workspace builds on stable Rust, edition 2024, minimum version 1.92.

The Nix flake supplies the development shell:

```sh
nix develop
```

The shell holds Rust 1.92, the `ostree` tool, GnuPG, and the other binaries
that the test suite runs.

## Tests

The test suite runs under both runtime backends:

```sh
cargo test                                        # smol (default)
cargo test -p ostrya --no-default-features --features tokio
```

The mount tests of `ostrya-sys`, `ostrya-mount`, and `ostrya-mountd` need
`CAP_SYS_ADMIN` in the initial user namespace, so they skip for another user.
Run them as root on a file system with fs-verity. If `OSTRYA_REQUIRE_MOUNT` is
set, a missing privilege or a file system without fs-verity fails them:

```sh
OSTRYA_REQUIRE_MOUNT=1 cargo test -p ostrya-sys -p ostrya-mount -p ostrya-mountd
```

The tests of `ostrya-mountd` also need `setpriv`, `unshare`, `nsenter`, and
user namespaces for an unprivileged user. They run each client as the user
65534 in its own user namespace, and keep their repositories and targets in
`/var/tmp`, where that user can reach them.

The unit tests of the protocol and of the daemon handler in `ostrya-mount`
need the `server` feature:

```sh
cargo test -p ostrya-mount --features server
```

## Golden fixtures

The golden fixtures are in `tests/fixtures/`. This directory is outside every
crate root, so a crate on crates.io holds no fixture.

- The tests that read the fixtures from a git checkout do not need the
  `ostree` tool.
- To generate the fixtures again, run `tests/fixtures/generate.sh`. The
  script needs the `ostree` tool.

`docs/port-plan.md`, "Golden fixtures: layout, packaging, and how to run them",
gives the fixture layout, the requirements of the generator, and the exact
test commands. It also tells how to identify a skipped fixture test.

## Man pages

The man pages of the `ostrya` command are in `crates/ostrya-cli/man/`. A unit
test of `ostrya-cli` generates the pages from the `clap` definition. The test
fails if a checked-in page is different.

After a change to the help text, write the pages again:

```sh
OSTRYA_BLESS_MAN=1 cargo test -p ostrya-cli --bin ostrya man_pages
```

The hand-written sections, for example ENVIRONMENT and EXAMPLES, are in
`crates/ostrya-cli/man/extra/<page>.roff`.

The man page `ostrya-mountd(8)` is in `crates/ostrya-mountd/man/`, and its
hand-written sections are in
`crates/ostrya-mountd/man/extra/ostrya-mountd.8.roff`. Write it again with:

```sh
OSTRYA_BLESS_MAN=1 cargo test -p ostrya-mountd man_page
```
