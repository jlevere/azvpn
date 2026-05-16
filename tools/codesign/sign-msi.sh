#!/usr/bin/env bash
#
# Sign an azvpn MSI (or any PE/MSI) using osslsigncode with a
# PEM-format cert + key pair. Linux-native, no Wine.
#
# Usage:
#   sign-msi.sh INPUT_MSI OUTPUT_MSI
#
# Inputs from environment (or defaults):
#   AZVPN_SIGNING_CERT — path to PEM cert (default: ~/.config/azvpn-signing/dev-cert.pem)
#   AZVPN_SIGNING_KEY  — path to PEM key  (default: ~/.config/azvpn-signing/dev-key.pem)
#   AZVPN_TIMESTAMP_URL — RFC3161 timestamp authority
#                        (default: http://timestamp.digicert.com)
#
# Timestamping is critical for code-signing. Without a
# countersignature from an RFC3161 TSA, the signature becomes
# invalid the day the signing cert expires. With one, the
# signature stays valid forever — Windows trusts that the file
# was signed while the cert was valid, even if the cert expires
# later. Use a free public TSA; this is the same pattern
# Microsoft / nu / signtool use.
#
# Reproducibility note: timestamping makes signing non-deterministic
# (the TSA returns a different counter-signature each call). That
# is why signing is OUTSIDE the nix derivation — building the MSI
# stays reproducible, and the signed copy is a separate artifact.

set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 INPUT_MSI OUTPUT_MSI" >&2
  echo "  reads cert from \$AZVPN_SIGNING_CERT" >&2
  echo "  reads key from  \$AZVPN_SIGNING_KEY" >&2
  exit 64
fi

INPUT="$1"
OUTPUT="$2"

SIGNING_DIR="${AZVPN_SIGNING_DIR:-$HOME/.config/azvpn-signing}"
CERT="${AZVPN_SIGNING_CERT:-$SIGNING_DIR/dev-cert.pem}"
KEY="${AZVPN_SIGNING_KEY:-$SIGNING_DIR/dev-key.pem}"
TSA="${AZVPN_TIMESTAMP_URL:-http://timestamp.digicert.com}"

# Resolve a symlinked result/ to the actual MSI inside.
if [ -L "$INPUT" ]; then
  INPUT=$(readlink -f "$INPUT")
fi
if [ -d "$INPUT" ]; then
  # nix's `result` is a symlink, but if pointed at, say, the
  # `azvpn-windows-msi` derivation output directly, it's a
  # directory containing a single .msi. Find that.
  MSI=$(find "$INPUT" -maxdepth 1 -name "*.msi" | head -1)
  [ -n "$MSI" ] || { echo "no .msi found under $INPUT" >&2; exit 1; }
  INPUT="$MSI"
fi

if [ ! -f "$INPUT" ]; then
  echo "ERROR: input MSI not found: $INPUT" >&2
  exit 1
fi
if [ ! -f "$CERT" ]; then
  echo "ERROR: signing cert not found: $CERT" >&2
  echo "Run tools/codesign/gen-dev-cert.sh first for a dev cert." >&2
  exit 1
fi
if [ ! -f "$KEY" ]; then
  echo "ERROR: signing key not found: $KEY" >&2
  exit 1
fi

echo ">>> signing $INPUT"
echo "    cert: $CERT"
echo "    tsa:  $TSA"
echo "    out:  $OUTPUT"

# `-h sha256` selects the hashing algorithm for the signature
# digest (also fed into the TSA request). SHA-1 is deprecated and
# Windows 10+ rejects SHA-1 Authenticode signatures on new files.
osslsigncode sign \
  -certs "$CERT" \
  -key "$KEY" \
  -h sha256 \
  -n "azvpn" \
  -i "https://github.com/jlevere/azvpn" \
  -ts "$TSA" \
  -in "$INPUT" \
  -out "$OUTPUT"

echo
echo ">>> verifying signature"
osslsigncode verify -in "$OUTPUT" || {
  # osslsigncode verify exits non-zero on "Unknown publisher" since
  # our self-signed cert isn't in the default CA bundle. That's
  # expected. Re-verify ignoring CA chain to confirm at least the
  # digest + countersignature integrity is good.
  echo
  echo "(verify exited non-zero — expected for self-signed cert."
  echo " Retrying without CA-chain check:)"
  osslsigncode verify -in "$OUTPUT" -CAfile "$CERT" || true
}

echo
echo "Done."
