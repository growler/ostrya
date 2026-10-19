# The NixOS module that runs `ostrya-mountd`, the composefs mount daemon. It
# installs the packaged units and enables the socket unit, which listens at
# `/run/ostrya/mountd.sock` with the mode 0660 and the group `ostrya-mount`.
#
# The socket unit has `Accept=yes`, so systemd starts one instance of
# `ostrya-mountd@.service` for each connection. With
# `socketConfig.Accept = false`, systemd starts `ostrya-mountd.service`, which
# serves all connections with one process.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.ostrya-mountd;
in
{
  options.services.ostrya-mountd = {
    enable = mkEnableOption ''
      the socket-activated `ostrya-mountd` daemon. A member of the group
      `ostrya-mount` can read each object of each repository whose `objects`
      directory it can open. `ostrya-mountd(8)` gives the details
    '';

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.ostrya-mountd;
      defaultText = lib.literalExpression "ostrya.packages.\${system}.ostrya-mountd";
      description = "The package that supplies `ostrya-mountd` and its systemd units.";
    };

    socketConfig = mkOption {
      type = types.attrs;
      default = { };
      example = {
        Accept = false;
      };
      description = "Other `[Socket]` settings for `ostrya-mountd.socket`.";
    };

    serviceConfig = mkOption {
      type = types.attrs;
      default = { };
      description = ''
        Other `[Service]` settings for `ostrya-mountd@.service` and
        `ostrya-mountd.service`.
      '';
    };
  };

  config = mkIf cfg.enable {
    systemd.packages = [ cfg.package ];
    environment.systemPackages = [ cfg.package ];

    # NixOS reads no sysusers.d file from `systemd.packages`, so the module
    # creates the group of the socket. Add a user to it with
    # `users.users.<name>.extraGroups`.
    users.groups.ostrya-mount = { };

    # `systemd.packages` does not read the `[Install]` section of a unit, so
    # the module enables the socket. The settings become drop-ins of the
    # packaged units.
    systemd.sockets.ostrya-mountd = {
      wantedBy = [ "sockets.target" ];
      inherit (cfg) socketConfig;
    };
    systemd.services."ostrya-mountd@".serviceConfig = cfg.serviceConfig;
    systemd.services.ostrya-mountd.serviceConfig = cfg.serviceConfig;
  };
}
