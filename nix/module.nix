# The NixOS module that runs `ostrya serve`. Each item of
# `services.ostrya-serve.instances` is one server process with its own
# systemd unit, `ostrya-serve-<name>.service`.
#
# Each nullable option adds its flag only when it is set. With `null`, the
# key of `[ex-ostrya server]` in the repository config applies, or the default
# of the command. The client groups, the trust groups, and the key groups are
# in the repository config alone.
{ self }:
{
  config,
  lib,
  pkgs,
  utils,
  ...
}:
let
  instances = config.services.ostrya-serve.instances;
  inherit (lib) types mkOption;

  nullOr =
    type: description:
    mkOption {
      type = types.nullOr type;
      default = null;
      inherit description;
    };

  # `--listen` takes a socket address, so an IPv6 address needs brackets.
  formatListen =
    l:
    if lib.hasInfix ":" l.address then
      "[${l.address}]:${toString l.port}"
    else
      "${l.address}:${toString l.port}";

  flag =
    name: value:
    lib.optionals (value != null) [
      name
      (toString value)
    ];
  boolFlag = name: value: lib.optional (value != null) "${name}=${lib.boolToString value}";

  args =
    cfg:
    [
      (lib.getExe cfg.package)
      "--repo"
      (toString cfg.repo)
      "serve"
    ]
    ++ lib.concatMap (l: [
      "--listen"
      (formatListen l)
    ]) cfg.listen
    ++ lib.concatMap (cidr: [
      "--trusted-proxy"
      cidr
    ]) cfg.trustedProxies
    ++ flag "--trusted-proxy-header" cfg.trustedProxyHeader
    ++ flag "--trusted-proxy-client-cert" cfg.trustedProxyClientCert
    ++ boolFlag "--proxy-protocol" cfg.proxyProtocol
    ++ boolFlag "--allow-cleartext-credentials" cfg.allowCleartextCredentials
    ++ flag "--session-timeout" cfg.sessionTimeout
    ++ flag "--max-sessions" cfg.maxSessions
    ++ flag "--parallel-uploads" cfg.parallelUploads
    ++ flag "--body-timeout" cfg.bodyTimeout
    ++ cfg.extraArgs;

  # The TLS files go through LoadCredential, so a key that only root reads
  # gets to the service user. `%d` is the credentials directory of the unit.
  # These arguments stay out of `escapeSystemdExecArgs`, which escapes `%`.
  credentials =
    cfg:
    lib.filter (c: c.file != null) [
      {
        name = "tls-cert";
        option = "--tls-cert";
        file = cfg.tls.certFile;
      }
      {
        name = "tls-key";
        option = "--tls-key";
        file = cfg.tls.keyFile;
      }
      {
        name = "tls-client-ca";
        option = "--tls-client-ca";
        file = cfg.tls.clientCaFile;
      }
    ];

  defaultUser = lib.any (cfg: cfg.user == "ostrya") (lib.attrValues instances);
  defaultGroup = lib.any (cfg: cfg.group == "ostrya") (lib.attrValues instances);

  bindsPrivilegedPort = cfg: lib.any (l: l.port != 0 && l.port < 1024) cfg.listen;

  instanceModule = {
    options = {
      package = mkOption {
        type = types.package;
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.ostrya;
        defaultText = lib.literalExpression "ostrya.packages.\${system}.ostrya";
        description = "The package that supplies the `ostrya` command.";
      };

      repo = mkOption {
        type = types.path;
        example = "/srv/ostree/repo";
        description = ''
          The absolute path of the repository to serve. The repository must
          exist; create it with `ostrya init`. The service gets write access to
          this path, because a push and `auto-update-summary` write to it.
        '';
      };

      user = mkOption {
        type = types.str;
        default = "ostrya";
        description = ''
          The user that runs the server. With the default value, the module
          creates a system user, which all instances with the default value
          share. The user must be able to read and write the repository.
        '';
      };

      group = mkOption {
        type = types.str;
        default = "ostrya";
        description = ''
          The group that runs the server. With the default value, the module
          creates a system group, which all instances with the default value
          share.
        '';
      };

      listen = mkOption {
        type = types.listOf (
          types.submodule {
            options = {
              address = mkOption {
                type = types.str;
                example = "::";
                description = "An IPv4 or IPv6 address. A host name is refused.";
              };
              port = mkOption {
                type = types.port;
                example = 8080;
                description = "The TCP port. Port 0 lets the kernel choose a port.";
              };
            };
          }
        );
        default = [
          {
            address = "127.0.0.1";
            port = 8080;
          }
        ];
        description = ''
          The addresses to listen on. Each item gives one `--listen` flag. With
          an empty list, the `listen` key of the repository config applies.
        '';
      };

      openFirewall = mkOption {
        type = types.bool;
        default = false;
        description = "Open the TCP ports of {option}`services.ostrya-serve.instances.<name>.listen` in the firewall.";
      };

      tls = {
        certFile = nullOr types.path "The PEM certificate chain of the server, for `--tls-cert`.";
        keyFile = nullOr types.path ''
          The PEM private key of the server, for `--tls-key`. The key must not
          be encrypted. The file can be readable by root alone.
        '';
        clientCaFile = nullOr types.path "The PEM CA certificates that verify client certificates, for `--tls-client-ca`.";
      };

      trustedProxies = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "10.0.0.0/8" ];
        description = ''
          The networks, as ADDR/LEN or ADDR, of the proxies whose forwarding
          headers the server reads. Each item gives one `--trusted-proxy` flag.
        '';
      };

      trustedProxyHeader =
        nullOr
          (types.enum [
            "forwarded"
            "x-forwarded-for"
            "x-real-ip"
          ])
          "The header that gives the client address of a request from a trusted proxy, for `--trusted-proxy-header`.";

      trustedProxyClientCert = nullOr types.str "The request header that gives the client certificate from a trusted proxy, for `--trusted-proxy-client-cert`.";

      proxyProtocol = nullOr types.bool "Read a PROXY protocol header at the start of each connection, for `--proxy-protocol`.";

      allowCleartextCredentials = nullOr types.bool "Take a bearer or Basic credential over plain HTTP, for `--allow-cleartext-credentials`.";

      sessionTimeout = nullOr types.ints.positive "The idle time in seconds that aborts a push session, for `--session-timeout`.";

      maxSessions = nullOr types.ints.positive "The maximum number of push sessions at the same time, for `--max-sessions`.";

      parallelUploads = nullOr (types.ints.between 1 31) "The number of object streams of one push session at the same time, for `--parallel-uploads`.";

      bodyTimeout = nullOr types.ints.positive "The time in seconds that a response waits for the client, for `--body-timeout`.";

      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Other arguments for `ostrya serve`.";
      };
    };
  };

  mkService = name: cfg: {
    name = "ostrya-serve-${name}";
    value = {
      description = "ostrya HTTP server ${name} of the repository ${toString cfg.repo}";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      # A key group with `gpg-key` signs the summary with the `gpg` binary.
      path = [ pkgs.gnupg ];

      serviceConfig = {
        Type = "simple";
        ExecStart = lib.concatStringsSep " " (
          [ (utils.escapeSystemdExecArgs (args cfg)) ]
          ++ map (c: "${c.option} %d/${c.name}") (credentials cfg)
        );
        LoadCredential = map (c: "${c.name}:${toString c.file}") (credentials cfg);
        User = cfg.user;
        Group = cfg.group;
        Restart = "on-failure";
        RestartSec = "5s";

        ReadWritePaths = [ (toString cfg.repo) ];
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        LockPersonality = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        AmbientCapabilities = lib.optional (bindsPrivilegedPort cfg) "CAP_NET_BIND_SERVICE";
        # The empty value gives the empty bounding set.
        CapabilityBoundingSet = if bindsPrivilegedPort cfg then "CAP_NET_BIND_SERVICE" else "";
      };
    };
  };
in
{
  options.services.ostrya-serve.instances = mkOption {
    type = types.attrsOf (types.submodule instanceModule);
    default = { };
    example = lib.literalExpression ''
      {
        http = {
          repo = "/srv/ostree/repo";
          listen = [ { address = "::"; port = 80; } ];
        };
        https = {
          repo = "/srv/ostree/repo";
          listen = [ { address = "::"; port = 443; } ];
          tls.certFile = "/etc/ostrya/server.pem";
          tls.keyFile = "/etc/ostrya/server.key";
        };
      }
    '';
    description = ''
      The `ostrya serve` HTTP servers. Each item runs one server process as
      the systemd unit `ostrya-serve-<name>.service`. Two instances can serve
      the same repository, for example one with plain HTTP and one with
      HTTPS. The `[ex-ostrya server]` keys of the repository config apply to
      each instance that serves that repository. Thus, for such a pair, give
      the TLS files in the `tls` options of the HTTPS instance, and not in the
      `tls-cert` and `tls-key` keys.
    '';
  };

  config = lib.mkIf (instances != { }) {
    users.users = lib.mkIf defaultUser {
      ostrya = {
        isSystemUser = true;
        group = "ostrya";
      };
    };
    # The group is also the primary group of the default user.
    users.groups = lib.mkIf (defaultUser || defaultGroup) { ostrya = { }; };

    networking.firewall.allowedTCPPorts = lib.concatMap (
      cfg: lib.optionals cfg.openFirewall (map (l: l.port) (lib.filter (l: l.port != 0) cfg.listen))
    ) (lib.attrValues instances);

    systemd.services = lib.mapAttrs' mkService instances;
  };
}
