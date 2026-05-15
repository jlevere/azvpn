{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        openvpn-azvpn = pkgs.openvpn.overrideAttrs (old: {
          patches = (old.patches or []) ++ [
            ./patches/openvpn-increase-user-pass-len.patch
          ];
        });

        # Statically linked (musl) build of the patched openvpn. Used by
        # the .deb / .rpm release pipeline so a single binary works on
        # every glibc version we ship to (Debian 11+, Ubuntu 22.04+,
        # Fedora 39+, Amazon Linux 2023, RHEL 9). Linux-only — pkgsStatic
        # on Darwin falls back to dynamic and isn't what we want here.
        #
        # PAM + systemd are disabled because:
        #   (a) linux-pam doesn't have a static nixpkgs target — it's
        #       fundamentally a dlopen-based subsystem.
        #   (b) the openvpn child doesn't need sd_notify; the daemon
        #       owns that signal.
        # `--disable-plugin-auth-pam` is required at the configure level
        # because openvpn's configure script REQUIRES libpam by default
        # (the nixpkgs default `configureFlags` adds the disable flag on
        # Darwin but not Linux). Plugins use dlopen — meaningless in a
        # static build, so disable them outright.
        openvpn-azvpn-static =
          (pkgs.pkgsStatic.openvpn.override {
            useSystemd = false;
            pam = null;
          }).overrideAttrs (old: {
            patches = (old.patches or []) ++ [
              ./patches/openvpn-increase-user-pass-len.patch
            ];
            configureFlags = (old.configureFlags or []) ++ [
              "--disable-plugin-auth-pam"
              "--disable-plugins"
            ];
          });

        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          pname = "azvpn";
          version = "0.1.0";
          strictDeps = true;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = [
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
          ];
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        azvpn = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });
      in
      {
        checks = {
          inherit azvpn;

          azvpn-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          azvpn-fmt = craneLib.cargoFmt {
            inherit src;
          };
        };

        packages = {
          default = azvpn;
          inherit azvpn openvpn-azvpn;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          inherit openvpn-azvpn-static;
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};

          packages = with pkgs; [
            cargo-deny
            cargo-edit
            cargo-watch
            openvpn-azvpn
          ];
        };
      });
}
