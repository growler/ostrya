{
  lib,
  rustPlatform,
  installShellFiles,
}:
let
  mountdToml = lib.importTOML ../crates/ostrya-mountd/Cargo.toml;
  # `ostrya-mountd` takes `version.workspace = true`, so the version string
  # lives in the root manifest's `[workspace.package]`.
  workspaceToml = lib.importTOML ../Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = "ostrya-mountd";
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
    "ostrya-mountd"
    "--bin"
    "ostrya-mountd"
  ];

  # The default feature set of `ostrya-mountd` carries `lzma-static`, so
  # `liblzma-sys` compiles the vendored xz sources and links them statically.
  # The build links no system library.

  nativeBuildInputs = [ installShellFiles ];

  # The units name `/usr/sbin/ostrya-mountd`, the path of the Debian package,
  # so the service units get the store path of the binary. The sysusers.d file
  # is installed for completeness; the NixOS module creates the group itself.
  postInstall = ''
    for unit in ostrya-mountd.socket ostrya-mountd.service ostrya-mountd@.service; do
      install -Dm644 "crates/ostrya-mountd/systemd/$unit" "$out/lib/systemd/system/$unit"
    done
    for unit in ostrya-mountd.service ostrya-mountd@.service; do
      substituteInPlace "$out/lib/systemd/system/$unit" \
        --replace-fail /usr/sbin/ostrya-mountd "$out/bin/ostrya-mountd"
    done
    install -Dm644 crates/ostrya-mountd/systemd/ostrya-mountd.sysusers \
      "$out/lib/sysusers.d/ostrya-mountd.conf"

    installManPage crates/ostrya-mountd/man/ostrya-mountd.8
  '';

  # The daemon tests mount EROFS and overlayfs, which needs root on the host.
  doCheck = false;

  meta = {
    description = mountdToml.package.description;
    mainProgram = "ostrya-mountd";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
