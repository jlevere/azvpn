#!/usr/bin/env bash
#
# Generate a self-signed Authenticode code-signing cert for azvpn
# dev builds. NOT for production — Windows still treats the
# signature as "Unknown publisher" because the cert isn't chained
# to a Microsoft-trusted root.
#
# What this DOES buy us:
#   * File integrity: the MSI's signature is invalidated if anyone
#     tampers with the package between build and install.
#   * Trust pinning: a Windows admin who installs this cert into
#     "Trusted Publishers" (HKLM\SOFTWARE\Microsoft\SystemCertificates
#     \TrustedPublisher) will see no UAC warning for our signed
#     builds. Same pattern used by Tailscale's pre-1.0 builds.
#   * AV/EDR signal: many endpoint products allow-list by signing
#     cert, so any signature is better than none.
#
# What this DOES NOT buy us:
#   * SmartScreen reputation. That requires a CA-trusted cert.
#   * No-prompt install on unmanaged machines. That requires
#     either SmartScreen approval or a Microsoft-trusted CA cert.
#
# Defaults:
#   ~/.config/azvpn-signing/dev-cert.pem
#   ~/.config/azvpn-signing/dev-key.pem
#
# Override the output directory by setting AZVPN_SIGNING_DIR.
# Override Common Name / Organization via CN= / O= env vars.
#
# Re-running this script does NOT regenerate — it refuses to
# overwrite an existing cert. Delete the dir manually if you
# really want a fresh cert; doing so invalidates trust pinning
# for everyone who installed the old one.

set -euo pipefail

SIGNING_DIR="${AZVPN_SIGNING_DIR:-$HOME/.config/azvpn-signing}"
CN="${CN:-azvpn dev}"
ORG="${O:-azvpn}"
# 10-year validity. Authenticode signatures don't expire when the
# cert does (countersignatures pin the signing time), but a long
# default avoids surprise renewals during development.
DAYS="${DAYS:-3650}"

CERT="$SIGNING_DIR/dev-cert.pem"
KEY="$SIGNING_DIR/dev-key.pem"

if [ -e "$CERT" ] || [ -e "$KEY" ]; then
  echo "ERROR: cert or key already exists at $SIGNING_DIR" >&2
  echo "Delete the directory manually to regenerate." >&2
  exit 1
fi

mkdir -p "$SIGNING_DIR"
# Lock the dir down. Private key is about to land here.
chmod 0700 "$SIGNING_DIR"

# OpenSSL ext config: codeSigning EKU is mandatory for Authenticode.
# Microsoft's `osslsigncode` rejects certs without it. The keyUsage
# digitalSignature is also required by some Windows trust chains.
EXT_CFG=$(mktemp)
trap 'rm -f "$EXT_CFG"' EXIT
cat >"$EXT_CFG" <<'EOF'
[ v3_ca ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
EOF

echo ">>> generating ${DAYS}-day self-signed code-signing cert"
echo "    CN: $CN"
echo "    O:  $ORG"
echo "    output: $SIGNING_DIR"

# 4096-bit RSA. ECDSA would be smaller / faster but Windows's
# Authenticode verifier has had historical bugs with non-RSA
# signing keys (especially under legacy CAPI paths). Stick to RSA.
openssl req \
  -x509 \
  -newkey rsa:4096 \
  -sha256 \
  -nodes \
  -keyout "$KEY" \
  -out "$CERT" \
  -days "$DAYS" \
  -subj "/CN=$CN/O=$ORG" \
  -extensions v3_ca \
  -config "$EXT_CFG"

chmod 0600 "$KEY"
chmod 0644 "$CERT"

echo
echo "Done. To sign an MSI:"
echo "  tools/codesign/sign-msi.sh result/ out/azvpn-0.1.0-x64.msi"
echo
echo "To install the cert on a Windows machine so signed builds"
echo "stop showing 'Unknown publisher':"
echo "  scp $CERT user@windows-box:C:/temp/azvpn-cert.pem"
echo "  # on Windows, in elevated PowerShell:"
echo "  Import-Certificate -FilePath C:\\temp\\azvpn-cert.pem \\"
echo "    -CertStoreLocation Cert:\\LocalMachine\\TrustedPublisher"
echo "  Import-Certificate -FilePath C:\\temp\\azvpn-cert.pem \\"
echo "    -CertStoreLocation Cert:\\LocalMachine\\Root"
