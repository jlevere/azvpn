# syntax=docker/dockerfile:1.6
#
# Cross-compile environment for building openvpn.exe (x86_64-w64-mingw32)
# with statically linked OpenSSL + LZO. Produces a single portable
# Windows binary suitable for bundling alongside our daemon.
#
# Layout:
#   /work/sources/          upstream tarballs (downloaded + verified)
#   /work/patches/          our patch series applied to openvpn
#   /work/build/openssl/    OpenSSL build dir
#   /work/build/lzo/        LZO build dir
#   /work/build/openvpn/    openvpn build dir
#   /work/install/          --prefix for OpenSSL + LZO (host headers/libs)
#   /out/                   final artifacts (openvpn.exe + SHASUMS256.txt)
#
# Usage:
#   docker buildx build --platform linux/amd64 \
#     --output type=local,dest=./out \
#     -f packaging/windows/build-openvpn/Dockerfile .
#
# The output stage copies the final binary out via BuildKit's `--output`
# so the host filesystem ends up with `out/openvpn.exe` directly.

FROM --platform=linux/amd64 debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc-mingw-w64-x86-64 \
        g++-mingw-w64-x86-64 \
        mingw-w64-tools \
        autoconf \
        automake \
        libtool \
        pkg-config \
        wget \
        ca-certificates \
        xz-utils \
        gzip \
        bzip2 \
        perl \
        patch \
        ed \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Build inputs — staged in /work so layer caching is per-file.
COPY packaging/windows/build-openvpn/SHASUMS256.txt /work/SHASUMS256.txt
COPY packaging/windows/build-openvpn/azvpn-patches /work/patches
COPY packaging/windows/build-openvpn/build.sh /work/build.sh
RUN chmod +x /work/build.sh

# `host` for mingw cross; consumed by configure/Configure invocations
# below. Pulled from a single place so the build script can stay
# version-agnostic.
ENV TRIPLE=x86_64-w64-mingw32
ENV PREFIX=/work/install
ENV PATH=/work/install/bin:$PATH

RUN /work/build.sh

# Final stage: ship only the built binary + manifest. BuildKit's
# `--output type=local` consumes this stage and copies the contents
# to the host's `./out`.
FROM scratch AS export
COPY --from=builder /out/openvpn.exe /openvpn.exe
COPY --from=builder /out/SHASUMS256.txt /SHASUMS256.txt
COPY --from=builder /out/build-info.txt /build-info.txt
