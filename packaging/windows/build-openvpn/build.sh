#!/usr/bin/env bash
#
# Cross-compile patched openvpn for x86_64-pc-windows-msvc-compatible
# distribution using mingw-w64 from a Debian host.
#
# Mirrors Mullvad's pre-2023 mullvadvpn-app-binaries build with our
# pins:
#
#   openvpn-2.6.19  + our azvpn-patches/
#   openssl-3.6.1
#   lzo-2.10
#
# Produces /out/openvpn.exe with no external DLL dependencies and
# the OpenVPN-2.6.19 SHA-256 we applied our `TLS_CHANNEL_BUF_SIZE`
# patch over.
#
# Strictness levels:
#   STRICT_HASHES=0 (default)   download tarballs without verifying,
#                                print observed hashes for backfill
#                                into SHASUMS256.txt
#   STRICT_HASHES=1             fail if downloaded hash != manifest
#
# Set in build.sh once the manifest is real, not 000…

set -euo pipefail

# ---- versions ---------------------------------------------------------
OPENVPN_VERSION=2.6.19
OPENSSL_VERSION=3.6.1
LZO_VERSION=2.10

# ---- urls -------------------------------------------------------------
OPENVPN_URL="https://swupdate.openvpn.org/community/releases/openvpn-${OPENVPN_VERSION}.tar.gz"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
LZO_URL="https://www.oberhumer.com/opensource/lzo/download/lzo-${LZO_VERSION}.tar.gz"

STRICT_HASHES=${STRICT_HASHES:-0}

JOBS=${JOBS:-$(nproc)}
SRC=/work/sources
BUILD=/work/build
PREFIX=${PREFIX:-/work/install}
TRIPLE=${TRIPLE:-x86_64-w64-mingw32}
OUT=/out

mkdir -p "$SRC" "$BUILD" "$PREFIX" "$OUT"

# ---- helpers ----------------------------------------------------------

# Download a tarball + (optionally) verify against SHASUMS256.txt.
# When STRICT_HASHES=0 (default during iteration), prints the
# observed hash so the maintainer can lock it into the manifest.
fetch() {
    local url="$1" file="$2"
    local path="$SRC/$file"
    if [ ! -f "$path" ]; then
        echo ">>> downloading $file"
        wget -q -O "$path.tmp" "$url"
        mv "$path.tmp" "$path"
    fi
    local observed
    observed=$(sha256sum "$path" | awk '{print $1}')
    echo "    observed sha256: $observed  $file"
    if [ "$STRICT_HASHES" = "1" ]; then
        local expected
        expected=$(grep "  $file\$" /work/SHASUMS256.txt | awk '{print $1}' || true)
        if [ -z "$expected" ] || [ "$expected" = "0000000000000000000000000000000000000000000000000000000000000000" ]; then
            echo "ERROR: SHASUMS256.txt has no real hash for $file; rerun with STRICT_HASHES=0 and copy the observed hash in"
            exit 1
        fi
        if [ "$expected" != "$observed" ]; then
            echo "ERROR: hash mismatch for $file"
            echo "  expected: $expected"
            echo "  observed: $observed"
            exit 1
        fi
    fi
}

# ---- 1. OpenSSL -------------------------------------------------------

build_openssl() {
    echo ">>> building openssl-${OPENSSL_VERSION} for ${TRIPLE}"
    cd "$BUILD"
    rm -rf "openssl-${OPENSSL_VERSION}"
    tar xf "$SRC/openssl-${OPENSSL_VERSION}.tar.gz"
    cd "openssl-${OPENSSL_VERSION}"

    # mingw64 = x86_64 Windows target, no-shared/no-dso = static only,
    # no-async/no-tests = skip features we don't ship. --libdir=lib so
    # openvpn's pkg-config sees a sane layout.
    ./Configure mingw64 \
        --prefix="$PREFIX" \
        --libdir=lib \
        --cross-compile-prefix="${TRIPLE}-" \
        no-shared \
        no-dso \
        no-async \
        no-tests \
        no-docs

    make -j"$JOBS"
    make install_sw
}

# ---- 2. LZO -----------------------------------------------------------

build_lzo() {
    echo ">>> building lzo-${LZO_VERSION} for ${TRIPLE}"
    cd "$BUILD"
    rm -rf "lzo-${LZO_VERSION}"
    tar xf "$SRC/lzo-${LZO_VERSION}.tar.gz"
    cd "lzo-${LZO_VERSION}"

    ./configure \
        --host="$TRIPLE" \
        --prefix="$PREFIX" \
        --disable-shared \
        --enable-static

    make -j"$JOBS"
    make install
}

# ---- 3. OpenVPN -------------------------------------------------------

build_openvpn() {
    echo ">>> building openvpn-${OPENVPN_VERSION} for ${TRIPLE} (azvpn-patched)"
    cd "$BUILD"
    rm -rf "openvpn-${OPENVPN_VERSION}"
    tar xf "$SRC/openvpn-${OPENVPN_VERSION}.tar.gz"
    cd "openvpn-${OPENVPN_VERSION}"

    # Apply our patch series. Each patch is `-p1`-style (relative to
    # the openvpn source root) and is applied in lexicographic order.
    # Failure to apply is fatal — we want to know early if upstream
    # rename / refactor broke our delta.
    for p in /work/patches/*.patch; do
        echo ">>> applying $p"
        patch -p1 < "$p"
    done

    # `--disable-lz4` keeps deps tight. `--disable-plugin-auth-pam`
    # because mingw doesn't have PAM. `--disable-systemd` because
    # mingw doesn't have systemd-notify either. `--disable-debug`
    # for release-style binaries (smaller, no extra symbols).
    #
    # OPENSSL_LIBS chains in the Win32 system libs OpenSSL needs
    # statically (ws2_32 = winsock, crypt32 = CertOpenStore etc.,
    # bcrypt = CNG entropy). Without these the static link silently
    # produces an exe that fails at first crypto call.
    PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" \
    PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig" \
    LZO_LIBS="-L$PREFIX/lib -llzo2" \
    LZO_CFLAGS="-I$PREFIX/include" \
    OPENSSL_LIBS="-L$PREFIX/lib -lssl -lcrypto -lws2_32 -lcrypt32 -lbcrypt" \
    OPENSSL_CFLAGS="-I$PREFIX/include" \
    LDFLAGS="-static -static-libgcc" \
    ./configure \
        --host="$TRIPLE" \
        --prefix="$PREFIX" \
        --disable-debug \
        --disable-plugin-auth-pam \
        --disable-systemd \
        --disable-lz4 \
        --enable-static \
        --disable-shared

    make -j"$JOBS"

    # The openvpn build emits the unstripped binary at
    # src/openvpn/openvpn.exe. Strip debug symbols for size + ship.
    "${TRIPLE}-strip" src/openvpn/openvpn.exe
    cp src/openvpn/openvpn.exe "$OUT/openvpn.exe"
}

# ---- 4. manifest ------------------------------------------------------

write_manifest() {
    echo ">>> writing /out/SHASUMS256.txt + /out/build-info.txt"
    (
        cd "$SRC"
        sha256sum "openvpn-${OPENVPN_VERSION}.tar.gz" \
                  "openssl-${OPENSSL_VERSION}.tar.gz" \
                  "lzo-${LZO_VERSION}.tar.gz"
    ) > "$OUT/SHASUMS256.txt"
    {
        echo "openvpn:       ${OPENVPN_VERSION}"
        echo "openssl:       ${OPENSSL_VERSION}"
        echo "lzo:           ${LZO_VERSION}"
        echo "host triple:   ${TRIPLE}"
        echo "patches:"
        ls /work/patches | sed 's/^/  /'
        echo
        echo "azvpn-built openvpn.exe sha256:"
        sha256sum "$OUT/openvpn.exe"
        echo
        echo "imports:"
        "${TRIPLE}-objdump" -p "$OUT/openvpn.exe" | grep -E 'DLL Name' | sort -u
    } > "$OUT/build-info.txt"
    cat "$OUT/build-info.txt"
}

# ---- main -------------------------------------------------------------

fetch "$OPENVPN_URL" "openvpn-${OPENVPN_VERSION}.tar.gz"
fetch "$OPENSSL_URL" "openssl-${OPENSSL_VERSION}.tar.gz"
fetch "$LZO_URL"     "lzo-${LZO_VERSION}.tar.gz"

build_openssl
build_lzo
build_openvpn
write_manifest

echo ">>> success — /out/openvpn.exe ready"
