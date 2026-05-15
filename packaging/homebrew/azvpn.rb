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
# Tailscale's pattern: the daemon bootstrap is a CLI subcommand
# (`sudo azvpn install-daemon`) that writes the launchd plist with
# absolute paths to the freshly-installed binaries, then calls
# `launchctl bootstrap system`. The formula never touches
# /Library/LaunchDaemons/ — `brew install`/`brew uninstall` only
# manages cellar contents, and the user owns the launchd lifecycle.
class Azvpn < Formula
  desc "Cross-platform Azure VPN client for macOS, Linux, and Windows"
  homepage "https://github.com/jlevere/azvpn"
  license any_of: ["MIT", "Apache-2.0"]

  # ===== TEMPLATE FILL: replaced on every release by CI =====
  # `scripts/release-macos.sh` prints these three values when it
  # builds a fresh tarball.
  version "0.1.0"
  url "https://github.com/jlevere/azvpn/releases/download/v#{version}/azvpn-#{version}-aarch64-apple-darwin.tar.gz"
  sha256 "REPLACE_ME_WITH_AARCH64_SHA256"
  depends_on arch: :arm64
  # =========================================================

  def install
    bin.install     "bin/azvpn"
    libexec.install "libexec/azvpnd"
    libexec.install "libexec/azvpn-openvpn"

    pkgshare.install "LICENSE-MIT", "LICENSE-APACHE"
    doc.install      "README.md"
  end

  def caveats
    <<~EOS
      One-time daemon bootstrap (writes the launchd plist and starts it):

        sudo azvpn install-daemon

      Verify with `azvpn status` (no sudo needed; the CLI talks to the
      daemon over a UNIX socket). To remove the daemon later:

        sudo azvpn uninstall-daemon
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/azvpn --version")
    # `azvpn-openvpn --version` exits 1 even on success — openvpn returns
    # non-zero from --version for historical reasons. The output is what
    # we actually want to inspect.
    assert_match "OpenVPN", shell_output("#{libexec}/azvpn-openvpn --version 2>&1", 1)
  end
end
