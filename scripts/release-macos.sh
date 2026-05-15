#!/usr/bin/env bash
#
# Build a macOS release tarball: azvpn CLI + azvpnd daemon + the
# patched openvpn binary, ready for upload to a GitHub Release and
# pickup by the homebrew tap (https://github.com/jlevere/homebrew-tap).
#
# Why this exists at all: macOS users can't easily build the patched
# openvpn (the patch lifts USER_PASS_LEN to 4096 so AAD bearer tokens
# don't truncate) without our nix flake. Shipping a pre-built tarball
# means `brew install jlevere/tap/azvpn` gets a working tunnel without
# requiring nix, openssl-dev, or anything else on the user's side.
#
# Build inputs:
#  * `cargo build --release` for both binaries
#  * `nix build .#openvpn-azvpn` for the patched openvpn (renamed to
#    `azvpn-openvpn` in the tarball to dodge the brew openvpn formula
#    PATH collision)
#  * launchd plist + LICENSEs from the tree
#
# Output: dist/azvpn-${VERSION}-aarch64-apple-darwin.tar.gz and its
# SHA256, plus a copy-pasteable Homebrew formula stanza printed to
# stdout. No upload happens here — that's a manual `gh release create`
# step; we'll automate via Actions on tag-push once the manual path
# is wired and tested.
#
# Usage:
#     scripts/release-macos.sh           # builds for the host arch
#     scripts/release-macos.sh --clean   # also wipes dist/ first
#
# Hard requirements: bash, cargo, nix (for the openvpn package), and
# the standard BSD `tar`, `shasum`, `lipo`, `strip` on PATH. The
# release runs from the repo root.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CLEAN=0
if [[ "${1:-}" == "--clean" ]]; then
    CLEAN=1
fi

# Version lives on each crate (the workspace doesn't share a single
# `version` field) — the CLI crate is canonical since users invoke its
# binary first. CLI and daemon are bumped together by convention.
VERSION="$(grep -E '^version' crates/cli/Cargo.toml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -z "$VERSION" ]]; then
    echo "error: couldn't extract version from crates/cli/Cargo.toml" >&2
    exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
    arm64|aarch64) TARGET_TRIPLE="aarch64-apple-darwin" ;;
    x86_64)        TARGET_TRIPLE="x86_64-apple-darwin" ;;
    *)             echo "error: unsupported arch $ARCH" >&2; exit 1 ;;
esac

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script targets macOS only" >&2
    exit 1
fi

DIST="$REPO_ROOT/dist"
STAGE="$DIST/azvpn-$VERSION-$TARGET_TRIPLE"
TARBALL="$DIST/azvpn-$VERSION-$TARGET_TRIPLE.tar.gz"

if [[ "$CLEAN" -eq 1 ]]; then
    rm -rf "$DIST"
fi
mkdir -p "$STAGE"/{bin,libexec,share/azvpn}

echo "==> building azvpn + azvpnd (release)"
cargo build --release --workspace --bins

echo "==> building patched openvpn via nix"
# `nix build` is content-addressed; running it repeatedly with no input
# changes is a near-instant cache hit. Output lands at ./result-openvpn
# rather than the default ./result so it doesn't collide with a
# previous `nix build .#azvpn`.
nix build .#openvpn-azvpn --out-link "$DIST/nix-openvpn"

# Strip debug info — the daemon ships with `info`-level tracing, no
# need to ship debug symbols too. Saves ~10MB across the three binaries.
echo "==> staging binaries"
install -m 0755 "$REPO_ROOT/target/release/azvpn"  "$STAGE/bin/azvpn"
install -m 0755 "$REPO_ROOT/target/release/azvpnd" "$STAGE/libexec/azvpnd"
install -m 0755 "$DIST/nix-openvpn/bin/openvpn"    "$STAGE/libexec/azvpn-openvpn"
strip "$STAGE/bin/azvpn" "$STAGE/libexec/azvpnd" "$STAGE/libexec/azvpn-openvpn" 2>/dev/null || true

echo "==> staging support files"
install -m 0644 \
    "$REPO_ROOT/packaging/launchd/com.jlevere.azvpn.daemon.plist" \
    "$STAGE/share/azvpn/com.jlevere.azvpn.daemon.plist"
install -m 0644 "$REPO_ROOT/LICENSE-MIT"    "$STAGE/LICENSE-MIT"
install -m 0644 "$REPO_ROOT/LICENSE-APACHE" "$STAGE/LICENSE-APACHE"
install -m 0644 "$REPO_ROOT/README.md"      "$STAGE/README.md"

echo "==> creating tarball"
# -C STAGE/.. then the bare directory name keeps a top-level
# `azvpn-<ver>-<triple>/` in the archive instead of leaking the
# absolute build path.
tar -czf "$TARBALL" -C "$DIST" "$(basename "$STAGE")"

SHA256="$(shasum -a 256 "$TARBALL" | awk '{print $1}')"

cat <<EOF

==> done
   tarball: $TARBALL
   size:    $(du -h "$TARBALL" | awk '{print $1}')
   sha256:  $SHA256

Homebrew formula stanza (paste into jlevere/homebrew-tap/Formula/azvpn.rb):

  version "$VERSION"
  if Hardware::CPU.arm?
    url "https://github.com/jlevere/azvpn/releases/download/v$VERSION/azvpn-$VERSION-aarch64-apple-darwin.tar.gz"
    sha256 "$SHA256"
  else
    # TODO: build + upload x86_64 tarball, paste its sha256 here.
  end

Next steps:
  1. \`gh release create v$VERSION $TARBALL\` (or upload via the web UI)
  2. Update the formula in jlevere/homebrew-tap to point at this release
  3. Verify with \`brew install jlevere/tap/azvpn\` and \`brew test azvpn\`
EOF
