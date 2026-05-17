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

        # Cross-compiled openvpn.exe for Windows x86_64, our patches
        # applied. Bundled into the W7 MSI alongside wintun.dll. Same
        # `overrideAttrs` shape as the Linux flavors — just driven
        # through `pkgsCross.mingwW64` which swaps in the
        # `x86_64-w64-mingw32-gcc` toolchain. OpenSSL is statically
        # linked in (no `libcrypto-3.dll` on the install side).
        #
        # systemd/pam are off for the same reasons as Linux-static, plus
        # neither exists on mingw. `--disable-lz4` because openvpn's
        # autoconf doesn't reliably find the cross-built lz4 and we
        # don't depend on the compression for our profiles. Plugins
        # depend on dlopen (mingw has loadlibrary but openvpn's plugin
        # ABI is Unix-shaped) — disable.
        # Single header from openvpn/tap-windows6. openvpn's configure
        # refuses to build without one of {tap-windows.h, linux/if_tun.h,
        # net/if_tun.h} — even when we'll only use Wintun at runtime via
        # `--windows-driver wintun`. nixpkgs doesn't package
        # tap-windows separately, so we fetch the single header directly
        # (BSD-licensed, ~80 lines) and wrap it in a tiny derivation so
        # we can point CPPFLAGS at a fixed nix store path. Note: openvpn
        # uses the standard `AC_CHECK_HEADERS([tap-windows.h])` macro,
        # so the path is consumed via `CPPFLAGS=-I…`, not a dedicated
        # `--with-tap-windows-includes` flag (that flag doesn't exist).
        tap-windows-include = pkgs.runCommand "tap-windows-include" {
          src = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/OpenVPN/tap-windows6/refs/tags/9.26.0/src/tap-windows.h";
            hash = "sha256-C56l5LTcLCdk/eM4NECvmhGh6tPypLvsZ0vkDaOE0Q4=";
          };
        } ''
          mkdir -p $out
          cp $src $out/tap-windows.h
        '';

        mingwPkgs = pkgs.pkgsCross.mingwW64;

        openvpn-azvpn-win64 =
          (mingwPkgs.openvpn.override {
            useSystemd = false;
            pam = null;
          }).overrideAttrs (old: {
            patches = (old.patches or []) ++ [
              ./patches/openvpn-increase-user-pass-len.patch
            ];
            configureFlags = (old.configureFlags or []) ++ [
              "--disable-plugin-auth-pam"
              "--disable-plugins"
              "--disable-lz4"
            ];
            # openvpn 2.6.19's source tarball ships `src/Makefile.in`
            # referencing `src/openvpnserv/eventmsg.mc`, but that .mc
            # file isn't actually included in the release — upstream
            # forgot to ship it. openvpnserv (the Windows interactive
            # service) is build-unconditional on Win32 in
            # `src/Makefile.in` (no `if WIN32` guard around the
            # `openvpnserv` entry in SUBDIRS), so the build fails as
            # soon as make recurses into that subdir.
            #
            # We don't ship openvpnserv anyway — it's the helper
            # service that mediates between unprivileged GUI clients
            # and the tunnel, and our daemon runs as LocalSystem and
            # drives openvpn directly via the management interface.
            # Just strip `openvpnserv` out of SUBDIRS in Makefile.in
            # before configure runs.
            #
            # Consequence to know: openvpn 2.6 on Windows delegates
            # *route installation* (and a couple of small DNS
            # helpers) to openvpnserv via its `msg_channel` IPC. With
            # openvpnserv absent, openvpn emits `msg_channel=0` and
            # silently skips those operations. We hit this for routes
            # — fixed by owning route install in our daemon via
            # `net-route` (`commit ce8c990`, `azvpn-core::route`).
            # For DNS we also own it via NRPT (the macOS-bug-fix on
            # Windows; see `azvpn-tunnel-windows::DnsManager`). So
            # the missing iservice doesn't impair anything we ship
            # today.
            #
            # **If we ever add a feature openvpn delegates to
            # iservice** (additional netsh helpers, MTU adjust,
            # route prio bumps), it will silently no-op until
            # `openvpnserv` is restored to this build. Re-evaluate
            # then; the fix is upstream-style — provide the missing
            # `eventmsg.mc` and let openvpnserv build normally.
            postPatch = (old.postPatch or "") + ''
              substituteInPlace src/Makefile.in \
                --replace-fail \
                  "SUBDIRS = compat openvpn openvpnmsica openvpnserv plugins tapctl" \
                  "SUBDIRS = compat openvpn openvpnmsica plugins tapctl"
            '';
            CPPFLAGS = "-I${tap-windows-include}";
            # Upstream openvpn ships `meta.platforms = lib.platforms.unix`,
            # which makes nix refuse to evaluate a mingw32 build even
            # though the toolchain handles it fine. Widen so the
            # `pkgsCross.mingwW64` instantiation is valid.
            meta = old.meta // {
              platforms = old.meta.platforms ++ pkgs.lib.platforms.windows;
            };
          });

        # WireGuard LLC's officially-signed wintun.dll redistributable.
        # Source-of-truth distribution at wintun.net. Single zip
        # contains x86 / amd64 / arm / arm64 binaries; we only ship
        # the amd64 one. The pinned 0.14.1 ZIP hash is verified at
        # fetch time. Authenticode signature (WireGuard LLC) is what
        # Windows checks when openvpn loads the DLL via LoadLibrary —
        # do NOT re-sign or re-pack the DLL, that breaks the
        # signature chain.
        wintun-dll = pkgs.fetchzip {
          url = "https://www.wintun.net/builds/wintun-0.14.1.zip";
          hash = "sha256-O+of1t8HQEY/JZ4sUeX81ekpZIFYL3uxxqbiId5K+hY=";
        };

        # `openvpn.exe` dynamically imports libcrypto-3-x64.dll,
        # libssl-3-x64.dll, and liblzo2-2.dll. On Windows the loader
        # only searches the directory the .exe lives in (plus
        # System32 and %PATH%), so we ship the DLLs alongside.
        # nixpkgs's `win-dll-link.sh` fixupPhase creates symlinks
        # for native execution under Wine but doesn't materialize
        # the DLLs in the bin/, so we build a flat directory
        # ourselves. The MSI installer copies this entire directory
        # into `C:\Program Files\azvpn\openvpn\`.
        #
        # `wintun.dll` is co-located with the openvpn binary: openvpn
        # passes `--windows-driver wintun` and the driver is loaded
        # via LoadLibrary from the same directory as openvpn.exe.
        openvpn-azvpn-win64-bundle = pkgs.runCommandLocal "openvpn-azvpn-win64-bundle" { } ''
          mkdir -p $out
          cp ${openvpn-azvpn-win64}/bin/openvpn.exe $out/
          cp ${mingwPkgs.openssl.bin}/bin/libcrypto-3-x64.dll $out/
          cp ${mingwPkgs.openssl.bin}/bin/libssl-3-x64.dll $out/
          cp ${mingwPkgs.lzo}/bin/liblzo2-2.dll $out/
          cp ${wintun-dll}/bin/amd64/wintun.dll $out/
          chmod 0644 $out/*.dll $out/*.exe
        '';

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

        # Cross-build the workspace for x86_64-pc-windows-gnu (mingw
        # ABI). Used by the MSI derivation so a `nix build .#azvpn-msi`
        # on any host (darwin / linux / win) produces the same MSI.
        #
        # We target windows-gnu rather than windows-msvc because:
        #   * msvc requires the Microsoft Visual C++ runtime, which
        #     can't legally be redistributed via nix (proprietary).
        #   * gnu uses the mingw-w64 runtime which is GPL-with-runtime-
        #     exception and freely redistributable.
        #   * windows-rs / windows-service / windows-sys all support
        #     both ABIs identically — gnu has no functional downside
        #     for our use case.
        #
        # `depsBuildBuild` is the right list for the cross-toolchain
        # itself (compiles on host, runs on host, produces win64
        # artifacts) — not `nativeBuildInputs`, which is for host->host
        # tools, and not `buildInputs`, which is for target-platform
        # libs. Getting this wrong makes crane's `strictDeps = true`
        # fail with mysterious linker errors.
        windowsCrossArgs = commonArgs // {
          # `strictDeps = true` plus the cross-stdenv interaction means
          # we have to switch off the host-side pkg-config — there's no
          # pkg-config we need for the windows targets and leaving it
          # in `nativeBuildInputs` pollutes `PKG_CONFIG_PATH` with the
          # build-host's openssl. We're not linking openssl into the
          # rust binaries (openvpn does that statically separately).
          nativeBuildInputs = [ ];

          # Tell cargo + linker where to find the windows toolchain.
          CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
          CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER =
            "${mingwPkgs.stdenv.cc}/bin/${mingwPkgs.stdenv.cc.targetPrefix}cc";

          # `cc-rs` (the C build-script driver used by `ring`,
          # `aws-lc-sys`, `winapi-build`, etc.) reads target-suffixed
          # env vars to pick the C compiler / archiver for the target.
          # Without these it falls back to the host's default `cc`,
          # which is darwin clang and has no `assert.h` for windows.
          "CC_x86_64-pc-windows-gnu" =
            "${mingwPkgs.stdenv.cc}/bin/${mingwPkgs.stdenv.cc.targetPrefix}cc";
          "CXX_x86_64-pc-windows-gnu" =
            "${mingwPkgs.stdenv.cc}/bin/${mingwPkgs.stdenv.cc.targetPrefix}c++";
          "AR_x86_64-pc-windows-gnu" =
            "${mingwPkgs.buildPackages.binutils}/bin/${mingwPkgs.stdenv.cc.targetPrefix}ar";

          # The mingw toolchain (gcc + binutils + win32 headers) goes
          # in depsBuildBuild because it runs on the build host and
          # produces artifacts for the host's `--target` flag.
          depsBuildBuild = with mingwPkgs.buildPackages; [
            stdenv.cc
            # `windres` is needed by anything that compiles a .rc
            # resource (we don't currently embed one, but several
            # of our deps do — e.g. for icon embedding).
            binutils
          ];

          # Rust's prebuilt `windows-gnu` stdlib hard-links
          # `-l:libpthread.a` (winpthreads), but nixpkgs's
          # `pkgsCross.mingwW64` now defaults to `mcfgthread` as the
          # threading library, which doesn't ship libpthread.a.
          # Provide winpthreads explicitly so the linker can satisfy
          # rust-std's reference. (We're not actually using
          # pthread_create in the binary — this is purely a stdlib
          # link-time satisfaction issue.)
          #
          # `buildInputs` alone isn't enough: with crane's
          # `strictDeps = true` the cross cc-wrapper doesn't propagate
          # the lib dir into rust's linker search path. We have to
          # tell rustc explicitly via the target-specific RUSTFLAGS.
          buildInputs = [ mingwPkgs.windows.pthreads ];
          CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS =
            "-L native=${mingwPkgs.windows.pthreads}/lib";

          # Can't execute *.exe on darwin / linux without wine, and we
          # are explicitly not using wine. The MSI smoke test on
          # win-test-vm exercises the binaries.
          doCheck = false;

          # crane defaults the artifact name from `pname`; making it
          # explicit so the output dir is obvious.
          pname = "azvpn-windows-cross";
        };

        azvpn-windows-cross-deps = craneLib.buildDepsOnly windowsCrossArgs;

        azvpn-windows-cross = craneLib.buildPackage (windowsCrossArgs // {
          cargoArtifacts = azvpn-windows-cross-deps;
        });

        # Cross-compile the workspace for aarch64-apple-darwin from a
        # Linux host via cargo-zigbuild. zig ships SDK shims (libSystem
        # tbd files + headers) so we don't need Apple's redistribution-
        # restricted SDK in the nix store. Works because our macOS
        # tunnel crate is pure Rust filesystem I/O — no
        # `system-configuration`, no `core-foundation`, no framework
        # links. The keyring backend is file-only on macOS this
        # session, so no `Security.framework` either.
        #
        # Motivation: macos-latest runners bill 10× ubuntu rate. The
        # whole point of brew/.deb/.msi delivery is end users never
        # build, so CI just has to produce the artifacts — no need to
        # run them. The dev machine catches macOS-specific runtime
        # regressions.
        darwinCrossArgs = commonArgs // {
          # zig provides the darwin shim; we don't need nixpkgs's
          # darwin SDK in the picture.
          nativeBuildInputs = [ pkgs.zig pkgs.cargo-zigbuild ];
          buildInputs = [ ];

          CARGO_BUILD_TARGET = "aarch64-apple-darwin";
          # crane wraps `cargo build`; replace the command so deps
          # also use zigbuild's linker. The `HOME` redirect is
          # because `cargo-zigbuild` writes a symlink-shim cache to
          # `dirs::cache_dir()` (`~/Library/Caches/` on darwin,
          # `~/.cache/` on linux) on first invocation — nix's sandbox
          # has `$HOME=/homeless-shelter` read-only, so we point it at
          # the build's own writable workdir.
          preBuild = ''
            export HOME=$TMPDIR
            export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-cache
          '';
          cargoBuildCommand =
            "cargo zigbuild --release --target aarch64-apple-darwin";
          cargoCheckCommand =
            "cargo zigbuild --release --target aarch64-apple-darwin --tests";

          # Can't execute aarch64-apple-darwin Mach-O on a Linux host
          # without rosetta/wine equivalents (there are none worth
          # using). Maintainer's dev mac runs the test suite.
          doCheck = false;

          # No explicit `CC_*` / `CXX_*` overrides — `cargo-zigbuild`
          # installs PATH shims (`cc`, `c++`, `ar`, `ranlib`) that
          # re-exec into `zig cc --target=…`. Setting the env-var form
          # would re-enter cargo-zigbuild's frontend and confuse cc-rs.
          # Vendored-C deps (ring, libz-sys) pick up the shims via PATH.
          pname = "azvpn-darwin-cross";
        };

        azvpn-darwin-cross-deps = craneLib.buildDepsOnly darwinCrossArgs;

        azvpn-darwin-cross = craneLib.buildPackage (darwinCrossArgs // {
          cargoArtifacts = azvpn-darwin-cross-deps;
        });

        # Linux-native MSI build driven by `wixl` from `msitools`.
        # No Wine, no .NET, no Windows host — `wixl` is a pure C
        # implementation of the WiX 3 compiler/linker that emits
        # real Windows Installer MSI databases. Mullvad uses the
        # same toolchain for parts of their Windows packaging
        # pipeline.
        #
        # Inputs are all nix-store paths produced by other
        # derivations in this flake:
        #   - azvpn.exe / azvpnd.exe from .#azvpn-windows-cross
        #   - openvpn.exe + 4 DLLs from .#openvpn-azvpn-win64-bundle
        # — meaning a single `nix build .#azvpn-windows-msi` from
        # any host (darwin or linux) materializes the complete,
        # reproducible installer.
        #
        # Authenticode signing is intentionally NOT done here. It
        # belongs in CI as a separate `osslsigncode sign` step
        # keyed off a private cert that doesn't live in the nix
        # store. The unsigned MSI from this derivation is still
        # functional — Windows will just show "Unknown publisher"
        # in the UAC prompt.
        azvpn-windows-msi = pkgs.runCommandLocal "azvpn-0.1.0-x64.msi" {
          nativeBuildInputs = [ pkgs.msitools ];
        } ''
          mkdir -p staging/openvpn
          cp -r ${openvpn-azvpn-win64-bundle}/. staging/openvpn/
          cp ${azvpn-windows-cross}/bin/azvpn.exe staging/azvpn.exe
          cp ${azvpn-windows-cross}/bin/azvpnd.exe staging/azvpnd.exe
          cp ${./packaging/windows/msi/README-FIRSTRUN.txt} \
             staging/README-FIRSTRUN.txt

          # wixl -D substitutions for the placeholders in azvpn.wxs.
          # Paths are absolute (staging is the cwd for wixl) so the
          # File Source attributes resolve against the real files.
          wixl \
            -v \
            -a x64 \
            -D Version=0.1.0 \
            -D AzvpnExe=$PWD/staging/azvpn.exe \
            -D AzvpndExe=$PWD/staging/azvpnd.exe \
            -D ReadmeFirstRun=$PWD/staging/README-FIRSTRUN.txt \
            -D OpenvpnBundleDir=$PWD/staging/openvpn \
            -o $out \
            ${./packaging/windows/msi/azvpn.wxs}
        '';
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
          inherit azvpn openvpn-azvpn openvpn-azvpn-win64 openvpn-azvpn-win64-bundle
                  azvpn-windows-cross azvpn-windows-msi
                  azvpn-darwin-cross;
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
            # Windows MSI signing toolchain. `osslsigncode` is a
            # Linux-native Authenticode signer — no Wine, no
            # signtool. `msitools` provides `msiinfo` for sanity-
            # inspecting the MSIs we produce.
            osslsigncode
            msitools
          ];
        };
      });
}
