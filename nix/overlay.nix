final: _prev: {
  # The `ostrya` CLI binary, built from `crates/ostrya-cli`.
  ostrya = final.callPackage ./ostrya.nix { };
  # The `ostrya-mountd` daemon, its systemd units, and its man page, built
  # from `crates/ostrya-mountd`.
  ostrya-mountd = final.callPackage ./ostrya-mountd.nix { };
}
