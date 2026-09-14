{
  lib,
  rustPlatform,
}:
let
  cliToml = lib.importTOML ../crates/ostrya-cli/Cargo.toml;
  # `ostrya-cli` takes `version.workspace = true`, so the version string lives
  # in the root manifest's `[workspace.package]`.
  workspaceToml = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "ostrya";
  version = workspaceToml.workspace.package.version;

  src = lib.cleanSourceWith {
    src = ../.;
    filter =
      name: _type:
      let
        base = baseNameOf (toString name);
      in
      !(base == "target" || base == "result" || base == ".git");
  };

  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "--package"
    "ostrya-cli"
    "--bin"
    "ostrya"
  ];

  # The build links no system library, so it needs neither `pkg-config` nor a
  # `buildInputs` entry. The default feature set of `ostrya-cli` carries
  # `lzma-static`, so `liblzma-sys` compiles the vendored xz sources, and
  # `.cargo/config.toml` sets `PCRE2_SYS_STATIC`, so `pcre2-sys` compiles the
  # vendored PCRE2 sources. Both are linked statically. The rest of the graph
  # is pure Rust.

  # The suite drives the `ostree` binary as its oracle, reaches the network,
  # and wants uid 0 in a user namespace. Run it from the dev shell.
  doCheck = false;

  meta = {
    description = cliToml.package.description;
    mainProgram = "ostrya";
    license = lib.licenses.mit;
    # The library reaches statx, FICLONE, O_TMPFILE and OFD locks through
    # rustix, so it builds on Linux alone.
    platforms = lib.platforms.linux;
  };
}
