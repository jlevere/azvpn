# build-openvpn — patched openvpn for Windows

Cross-compile pipeline that produces a statically-linked
`openvpn.exe` for x86_64 Windows, with our
`TLS_CHANNEL_BUF_SIZE` / `USER_PASS_LEN` patches applied. Bundled
into the W7 MSI alongside `wintun.dll`.

Mullvad's pre-2023 mullvadvpn-app-binaries pipeline is the model
— see [[reference-mullvad-openvpn-build]] in memory. We pin newer
versions (openvpn 2.6.19, openssl 3.6.1) and a different patch
series, but keep the mingw-w64-cross-from-Debian + statically-
linked-OpenSSL recipe.

## Pinned sources

| Component | Version | Source |
|---|---|---|
| openvpn | 2.6.19 | swupdate.openvpn.org |
| openssl | 3.6.1 | openssl.org |
| lzo | 2.10 | oberhumer.com |

SHA-256 hashes live in `SHASUMS256.txt`. The first build with
`STRICT_HASHES=0` (default) prints the observed hash so we can
back-fill the manifest; subsequent builds with `STRICT_HASHES=1`
refuse to proceed on drift.

## Patches

`azvpn-patches/` is applied lexicographically over the
upstream openvpn source after the tarball is unpacked. Patches
are `-p1`-relative (i.e. start with `a/src/openvpn/...`).

- `0001-azvpn-increase-buffers.patch` — bumps
  `TLS_CHANNEL_BUF_SIZE` 2048→6144 and `USER_PASS_LEN` to 4096.
  Required for Azure P2S gateways whose cert chain + AAD token
  push the TLS handshake over the stock 2048 buffer (see
  `docs/windows-plan.md` §status table — W4a discovery).

## Build

```sh
# from the worktree root
make -C packaging/windows/build-openvpn build
```

Output is dropped at `packaging/windows/build-openvpn/out/`:

- `openvpn.exe` — the patched static binary
- `SHASUMS256.txt` — observed hashes of the upstream tarballs
- `build-info.txt` — versions, hash of the produced exe, DLL
  imports the binary declares (sanity check that it really is
  statically linked — should only show kernel32 / advapi32 etc.,
  no openssl / lzo libs)

Requires Docker Desktop (or any Docker with BuildKit). On macOS
the `linux/amd64` platform uses Rosetta — slow on M-series, but
the build is bounded enough (~5 min total) that it's not painful.

## Deploying

After a green build:

```sh
scp -J p620 packaging/windows/build-openvpn/out/openvpn.exe \
    localuser@10.1.10.10:'C:/Program Files/azvpn/openvpn/openvpn.exe'
```

Then on jackson-dev:

```pwsh
& "C:\src\azvpn\target\x86_64-pc-windows-msvc\release\azvpn.exe" \
    up --profile C:\src\profiles\vwan-pla-cus.xml --ephemeral
```

## Why not Nix / pkgsCross.mingwW64

Nixpkgs has `pkgsCross.mingwW64.openvpn` and we could in
principle express this as a flake derivation. On an Apple Silicon
dev box the cross-compile would run under QEMU emulation, which
is significantly slower than Docker Desktop's native amd64
Rosetta path. Once we have a Linux CI runner (GitHub Actions
ubuntu-22.04) we can revisit — but for now Docker is the
faster ergonomic choice.

## Why not native MSVC on jackson-dev

OpenSSL 3.x + openvpn 2.6 builds with MSVC but the OpenSSL build
requires Strawberry Perl + nmake + a separate static-build dance.
End-to-end takes longer to set up and isn't the canonical
"production" recipe — Mullvad, openvpn upstream's own installer
build, and most distribution maintainers all use mingw-cross.
