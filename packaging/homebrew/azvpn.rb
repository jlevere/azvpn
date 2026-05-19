# Homebrew formula for azvpn.
#
# Lives in this repo as the canonical source; the deployed copy is
# vendored into github.com/jlevere/homebrew-tap on each release.
# Keeping the template here means tap and binary stay in lock-step:
# CI copies this file into the tap with the new version/url/sha256
# baked in, and we never edit two places by hand.
#
# Install layout (extracted from the release tarball as-is):
#   - `azvpn`           CLI    → #{bin}/azvpn
#   - `azvpnd`          daemon → #{libexec}/azvpnd
#   - `azvpn-openvpn`   bundled patched openvpn → #{libexec}/azvpn-openvpn
#     (renamed so it doesn't clash with the upstream openvpn formula
#      on PATH; the daemon picks it up from a relative `../libexec/`
#      lookup at runtime)
#
# Everything in the tarball is pre-built by CI on a `macos-latest`
# arm64 runner — Rust binaries via `cargo build --release` plus
# patched openvpn linked against `mbedtls@3` from this same Homebrew
# prefix. arm64 brew is always `/opt/homebrew`, so the openvpn
# binary's `install_name` references the same `mbedtls@3` dylib path
# the user will have after `brew install`.
#
# The USER_PASS_LEN patch is load-bearing for AAD: vanilla openvpn
# truncates passwords at 128 bytes, AAD bearer tokens are ~2–3 KB
# JWTs, and the gateway's TLS handshake fails opaquely with truncated
# input. The patch is applied at build time in CI; the resulting
# binary is what ships.
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
  # `cargo xtask publish-formula` substitutes version + sha256 from
  # the build-macos job's outputs in release.yml.
  version "0.2.0"
  url "https://github.com/jlevere/azvpn/releases/download/v#{version}/azvpn-#{version}-aarch64-apple-darwin.tar.gz"
  sha256 "REPLACE_ME_WITH_AARCH64_SHA256"
  depends_on arch: :arm64
  # =========================================================

  # Runtime dylib deps for the bundled `azvpn-openvpn`. CI builds
  # openvpn against `mbedtls@3` (openvpn 2.6 supports mbedtls 2.x and
  # 3.x; brew's default `mbedtls` is 4.x, which broke the API) and
  # `lzo` (legacy compression openvpn defaults to). `install_name`s
  # in the shipped binary point at `/opt/homebrew/opt/mbedtls@3/...`
  # — same path the user gets from these two depends_on lines.
  depends_on "mbedtls@3"
  depends_on "lzo"

  def install
    bin.install     "bin/azvpn"
    libexec.install "libexec/azvpnd"
    libexec.install "libexec/azvpn-openvpn"
    pkgshare.install "LICENSE-MIT", "LICENSE-APACHE"
    doc.install     "README.md"
  end

  def caveats
    <<~EOS
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
