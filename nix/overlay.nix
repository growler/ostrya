final: _prev: {
  # The `ostrya` CLI binary, built from `crates/ostrya-cli`.
  ostrya = final.callPackage ./ostrya.nix { };
}
