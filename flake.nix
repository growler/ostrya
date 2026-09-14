{
  description = "ostrya — a pure-Rust async reimplementation of the ostree repository format";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      ...
    }:
    let
      overlays.default = import ./nix/overlay.nix;
    in
    # Linux alone: the library reaches statx, FICLONE, O_TMPFILE and OFD locks
    # through rustix, and the conformance suite drives the `ostree` binary.
    flake-utils.lib.eachSystem
      [
        "x86_64-linux"
        "aarch64-linux"
      ]
      (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              (import rust-overlay)
              overlays.default
            ];
          };
          inherit (pkgs) lib;

          rustExtensions.extensions = [
            "rust-analyzer"
            "rustfmt"
            "clippy"
            "rust-src"
          ];

          # The binaries the test suite and the CI guards run. Each test that
          # needs one of these skips where it is absent, so the shell carries
          # them to run the whole suite rather than a subset.
          devPackages = with pkgs; [
            # The reference the conformance and interop tests drive as a black
            # box. `getBin` selects the binary output, so libostree's headers
            # and its `.pc` file stay out of the shell.
            (lib.getBin ostree)

            # `gpg` signs a commit, `gpgv` checks a signature against a
            # keyring, and `gpgconf` shuts an agent down between tests.
            gnupg

            # The cross-check in `crates/ostrya/tests/sign_spki.rs` signs with
            # `openssl` and verifies with the port, and the other way round.
            openssl

            # `setfattr` and `getfattr` for the xattr tests.
            attr

            # The fsync-ordering assertions in `crates/ostrya-cli/tests/cli.rs`
            # read an `strace` log.
            strace

            # `unshare` for the tests that want uid 0 in a user namespace.
            util-linux

            # The license and PCRE2 guards in `.github/workflows/ci.yml` read
            # the `cargo metadata` JSON with jq.
            jq
          ];

          mkDevShell =
            toolchain:
            pkgs.mkShell {
              packages = [ toolchain ] ++ devPackages;
              shellHook = ''
                export RUST_BACKTRACE=1
              '';
            };
        in
        {
          packages = {
            inherit (pkgs) ostrya;
            default = pkgs.ostrya;
          };

          # default pins the version CI enforces, which is the workspace's
          # `rust-version`. stable and nightly are there when you need them.
          devShells = {
            default = mkDevShell (pkgs.rust-bin.stable."1.92.0".default.override rustExtensions);
            stable = mkDevShell (pkgs.rust-bin.stable.latest.default.override rustExtensions);
            nightly = mkDevShell (
              pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default.override rustExtensions)
            );
          };

          formatter = pkgs.nixfmt-rfc-style;
        }
      )
    // {
      inherit overlays;
    };
}
