# Homebrew formula for azvpn.
#
# Lives in this repo as the canonical source; the deployed copy is
# vendored into github.com/jlevere/homebrew-tap on each release.
# Keeping the template here means tap and binary stay in lock-step:
# CI copies this file into the tap with the new version/url/sha256
# baked in, and we never edit two places by hand.
#
# Install layout:
#   - `azvpn` CLI            → #{bin}/azvpn
#   - `azvpnd` daemon        → #{libexec}/azvpnd
#   - bundled patched openvpn → #{libexec}/azvpn-openvpn  (renamed so it
#                              doesn't clash with the upstream openvpn
#                              formula on PATH; the daemon picks it up
#                              from a relative `../libexec/` lookup)
#
# Why we build openvpn from source here instead of vendoring a prebuilt
# binary: cross-compiling openvpn from Linux to aarch64-apple-darwin is
# structurally broken in nixpkgs today (apple-sdk propagate-inputs
# infinite recursion; nixpkgs Hydra doesn't test that path; see
# https://github.com/NixOS/nixpkgs/issues/273442). The fallback —
# building openvpn natively on a macos-latest runner — bills 10× the
# ubuntu rate. Compiling openvpn on the user's mac via brew at install
# time takes ~30s on M1, comes pre-loaded with the C toolchain via
# Xcode CLI tools, and costs us nothing in CI minutes. Mullvad's
# posture is the same shape (build natively where you ship from).
#
# The USER_PASS_LEN patch is load-bearing for AAD: vanilla openvpn
# truncates passwords at 128 bytes, AAD bearer tokens are ~2–3 KB JWTs,
# and the gateway's TLS handshake fails opaquely with truncated input.
# Patch is shipped in the release tarball under patches/ so this
# formula is self-contained.
#
# Tailscale's pattern for the daemon: the bootstrap is a CLI
# subcommand (`sudo azvpn install-daemon`) that writes the launchd
# plist with absolute paths to the freshly-installed binaries, then
# calls `launchctl bootstrap system`. The formula never touches
# /Library/LaunchDaemons/ — `brew install`/`brew uninstall` only
# manages cellar contents, and the user owns the launchd lifecycle.
class Azvpn < Formula
  desc "Cross-platform Azure VPN client for macOS, Linux, and Windows"
  homepage "https://github.com/jlevere/azvpn"
  license any_of: ["MIT", "Apache-2.0"]

  # ===== TEMPLATE FILL: replaced on every release by CI =====
  # `cargo xtask release-macos` / `nix build .#azvpn-darwin-tarball`
  # both produce a tarball with the matching version/sha256 baked into
  # `dist/manifest.txt` for the publish-formula step to copy in.
  version "0.1.0"
  url "https://github.com/jlevere/azvpn/releases/download/v#{version}/azvpn-#{version}-aarch64-apple-darwin.tar.gz"
  sha256 "REPLACE_ME_WITH_AARCH64_SHA256"
  depends_on arch: :arm64
  # =========================================================

  depends_on "pkg-config" => :build
  # Patched openvpn links against these at runtime. mbedtls@3 because
  # openvpn 2.6 supports mbedtls 2.x/3.x but not 4.x (major API
  # rewrite); brew's default `mbedtls` formula is 4.x. lzo gives the
  # legacy LZO compression openvpn defaults to, distinct from LZ4
  # (which we --disable since Azure profiles don't push LZ4-compressed
  # data).
  depends_on "mbedtls@3"
  depends_on "lzo"

  # Upstream openvpn source — pinned to the same 2.6.x release the .deb
  # pipeline builds against, so the macOS and Linux installs end up
  # with the same wire-compatible openvpn binary.
  resource "openvpn" do
    url "https://swupdate.openvpn.net/community/releases/openvpn-2.6.19.tar.gz"
    sha256 "13702526f687c18b2540c1a3f2e189187baaa65211edcf7ff6772fa69f0536cf"
  end

  def install
    # Rust binaries from our release tarball — cross-built on Linux
    # via cargo-zigbuild + nix (see flake.nix). No compilation here.
    bin.install     "bin/azvpn"
    libexec.install "libexec/azvpnd"

    pkgshare.install "LICENSE-MIT", "LICENSE-APACHE"
    doc.install      "README.md"

    # Patched openvpn — compile from upstream source with our
    # USER_PASS_LEN patch applied. ~30s on M1. The patch file ships
    # in the release tarball at `patches/`. Homebrew's superenv
    # auto-injects `-I/-L` flags and `PKG_CONFIG_PATH` for the
    # `depends_on` deps above, so no manual env munging here.
    patch_file = buildpath/"patches/openvpn-increase-user-pass-len.patch"
    resource("openvpn").stage do
      system "patch", "-p1", "-i", patch_file
      system "./configure",
             "--prefix=#{prefix}",
             "--with-crypto-library=mbedtls",
             "--disable-lz4",
             "--disable-plugins",
             "--disable-dependency-tracking",
             "--disable-silent-rules"
      system "make"

      # Bypass `make install` — it would lay down man pages and
      # sample configs we don't want a brew install to scatter. Pluck
      # just the binary into our `libexec/` with the namespaced name
      # the daemon's resolver looks for.
      libexec.install "src/openvpn/openvpn" => "azvpn-openvpn"
    end
  end

  def caveats
    <<~EOS
      First install compiles the patched openvpn from source
      (~30s on Apple Silicon). Subsequent upgrades reuse the cellar
      unless the openvpn version pin changes.

      Next:
        1. sudo azvpn install-daemon
           (one-time: writes the launchd plist and starts the daemon;
            idempotent so re-run after every `brew upgrade azvpn` to
            point the unit at the new binary)
        2. Download your Azure profile XML from the Azure portal
           (Virtual Network Gateway → Point-to-site → "Download VPN
            client"; unzip and grab AzureVpnProfile.xml)
        3. azvpn profile import <path-to-AzureVpnProfile.xml>
        4. azvpn login
        5. azvpn up

      The CLI talks to the daemon over a UNIX socket — no sudo needed
      for day-to-day commands. To tear it all down:

        sudo azvpn uninstall-daemon            # stops + removes the daemon
        sudo azvpn uninstall-daemon --purge    # also wipes profiles + cached tokens
        brew uninstall azvpn                   # removes the binaries
    EOS
  end

  # No `zap` stanza — that's a cask-only directive. The deep-clean
  # path is `sudo azvpn uninstall-daemon --purge` (already mentioned
  # in caveats), which wipes the launchd plist, system-state dir,
  # log dir, and runtime socket dir end-to-end.

  test do
    assert_match version.to_s, shell_output("#{bin}/azvpn --version")
    # `azvpn-openvpn --version` exits 1 even on success — openvpn returns
    # non-zero from --version for historical reasons. The output is what
    # we actually want to inspect.
    output = shell_output("#{libexec}/azvpn-openvpn --version 2>&1", 1)
    assert_match "OpenVPN", output
    assert_match "mbed TLS", output
  end
end
