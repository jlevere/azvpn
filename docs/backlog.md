# Backlog — known gaps and deferred work

Things we explicitly chose **not** to build (yet), with the context for
why so future-us doesn't have to re-derive the decisions.

Each item is one of:
- **Deferred** — useful, just not the highest-leverage thing to do right
  now. Concrete trigger listed.
- **Blocked** — needs external input we don't have (test data, real
  profile, external capture, etc.).
- **Declined** — looked at and decided against. Reason recorded.

Sorted by likely order of pickup.

---

## HA failover (`<secondaryProfileName>` / `<highavailability>`)

**Status:** Blocked on test data.

The profile parser already covers both fields:
- `VpnProfile.secondary_profile_name: Option<String>` —
  `crates/profile/src/lib.rs:33`
- `VpnProfile.highavailability: Option<bool>` —
  `crates/profile/src/lib.rs:36`

What we don't have, in order:

1. **A real HA-paired profile.** User's only working profile (vWAN
   `wan.2zobhmuc3ev8dfvaqhcxez0n8.vpn.azure.com`) has
   `<secondaryProfileName>None</secondaryProfileName>` — the literal
   string `"None"` sentinel — and no `<highavailability>` element. We
   can't write to Azure to provision a paired one.
2. **An RE'd failover mechanism.** Ghidra decomp of Microsoft's macOS
   tunnel extension references `secondaryProfileName` exactly once —
   in the XML parser. **Zero references in connection logic.** The
   macOS official client doesn't appear to implement failover at the
   tunnel layer; if it does failover, it's UI-layer (manual profile
   swap by the user).
3. **A discovery mechanism.** Is the secondary profile expected to live
   in the same directory? Different filename derived from the
   `secondary_profile_name` string? We don't know.

**Pickup trigger:** Acquire a real HA-paired profile, OR find failover
code in the Windows `AzVpnAppBg.dll` decomp (Microsoft's HA logic
probably lives there if anywhere — that's their daemon).

**Workaround today:** With `secondary_profile_name == Some("None")` or
absent, the field is ignored. Users with paired profiles can manually
swap by passing a different `--profile` path. No data loss.

---

## Client-certificate auth (`AuthType::Certificate`)

**Status:** Blocked on test data + per-platform keystore code.

Connect path errors clearly at `crates/core/src/commands/connect.rs:272`:

```
client certificate auth is not yet implemented — only AAD and
username/password profiles can connect today
```

The profile parser is complete: `ClientCert { hash, issuer,
certificatedata }` covers the full schema. Implementation gap is in two
tiers:

### Tier A — Embedded PEM (`<certificatedata>`)

Smallest path. Write the inline PEM blob to a tempfile, pass to openvpn
via `--cert`/`--key` config directives. **~50–100 LOC, no platform
code.** Drawback: real Azure profiles use the keystore-by-hash path,
not embedded data — the schema-harvest's `linux-v3.0.0-export-template
.xml` has `<hash i:nil="true"/>` and no `certificatedata`, suggesting
embedded PEM is rarer than thumbprint refs.

### Tier B — Keystore by thumbprint (`<hash>`)

The realistic case. Look up a cert+private-key pair in the OS keystore
by SHA-1 thumbprint, export to openvpn-readable form.

- **macOS**: `security-framework` crate, query `SecItemCopyMatching` by
  `kSecAttrCertificateThumbprint`. Keys may be non-exportable
  (`kSecAttrIsExtractable=false`); fallback is to ask openvpn to use a
  PKCS#11 module pointing at the Keychain (`tokend`-style — gnarly).
- **Linux**: NSS (via `nss` crate) or pkcs11 (via `cryptoki` crate)
  against the user's softoken / smartcard.
- **Windows**: `windows-rs` Crypt32 (`CertFindCertificateInStore` with
  `CERT_FIND_HASH`), then export via `CryptUIWizExport` or NCrypt for
  hardware-bound keys.

**~500–1000 LOC per platform**, plus the trait + per-platform impl
plumbing. Realistic only when the Windows tunnel milestone is in
flight, since Crypt32 work overlaps.

### What Microsoft's client does

Their macOS tunnel extension has exactly **one** cert-related symbol
(`azurexplatvpn::ClientCertInfo::~ClientCertInfo` — a destructor) and
no constructor. They presumably handle cert auth via the
`NetworkExtension` framework's built-in mechanisms, not by spawning
openvpn directly. That's a different architecture from ours and not
something we can crib from.

**Pickup trigger:** A real cert-auth profile to test against, OR the
Windows tunnel milestone starting (Crypt32 has to come in then anyway).

---

## Real commercial-cloud public-client GUID

**Status:** Open empirical question, low impact.

We currently default to **audience-as-client_id**: when the profile's
`<applicationid>` is unset, `AadConfig::client_id()` returns the
audience GUID (`41b23e61-…`). This works in commercial AAD because
that GUID is registered as a public client with `http://localhost:2023`
in its reply-URL list.

**Confirmed wrong path:** `51bb15d4-3a4f-4ebf-9dca-40096fe32426` —
appears in the official Linux client's FOCI list — triggers
`AADSTS900383: Please login to your National Cloud dedicated portal`
in commercial AAD. It's the USGov / sovereign-cloud variant. Reverted
in commit `40aa460`.

**Unknown:** Whether there's a separate, dedicated commercial-cloud
public-client GUID that Microsoft's clients actually use (instead of
the audience-as-client pattern). Static analysis hasn't found one:

- Windows v4.0.5.0 `AzVpnAppBg.dll` / `AzVpnAppx.exe` strings dumps:
  five total GUIDs, none auth-related.
- Linux v3.0.0 binary strings: only the FOCI block (see below).
- macOS reflection-string pool: none.

The real client_id is likely constructed at runtime from a resource or
compact representation rather than appearing as a plaintext UUID.

**Pickup trigger:** Live OAuth capture (mitmproxy / Charles) against
the official Microsoft client during sign-in, to read the
`client_id=` query parameter on the wire. Possible but hasn't been
worth doing — audience-as-client works for every commercial profile
we've tested.

**Impact if we DID switch:** Marginal. Spec-cleaner, might (slightly)
reduce conditional-access friction in some tenants. Not blocking
anything.

---

## FOCI family participation

**Status:** Declined.

Microsoft's FOCI (Family of Client IDs) feature lets sibling apps
share refresh tokens — Outlook's RT works for OneDrive without
re-prompting. The Azure VPN Linux binary references seven FOCI member
GUIDs:

```
49f817b6-84ae-4cc0-928c-73f27289b3aa
51bb15d4-3a4f-4ebf-9dca-40096fe32426    ← USGov Azure VPN
538ee9e6-310a-468d-afef-ea97365856a9
79f718a8-9644-4162-be91-dd7115b393ee
ba64e473-e6ba-468c-880d-f9d005bf91c2
c632b3df-fb67-4d84-bdcf-b95ad541b5c8
e9294e7b-d9b2-4ad7-8526-82e0a30c6f7f
```

**Why declined:**

1. **Threat model.** FOCI sibling-sharing means a compromise of our
   token cache also leaks credentials usable against Outlook / Teams /
   OneDrive under the same tenant. Audience-as-client (our current
   pattern) bounds the blast radius to "tokens that only work against
   the Azure VPN gateway."

2. **The only real motivation is cache interop**, and that's a
   bad bet:
   - macOS / Linux / Windows official clients use *different* cache
     shapes (MSAL Keychain, libsecret, WAM). Three per-platform cache
     readers just to *reach* the RTs.
   - The official Microsoft client isn't usable on Linux meaningfully
     (no nix / no AUR), so there's no shared RT to interop with there.
   - macOS users hitting our CLI almost certainly hit it precisely
     because the official client is broken (DNS-suffix bug). "Share
     auth with the broken client" is the wrong direction.

**Pickup trigger:** Probably never. File under "if a Windows broker
integration becomes a priority, revisit." See
`research/aad-flow-notes.md` for the long form.

---

## WAM broker on Windows + CompanyPortal broker on macOS

**Status:** Deferred — belongs in the Windows / macOS milestone.

Best UX for managed environments. WAM (Web Account Manager) is the
Windows native broker that backs the system Settings → Accounts page;
macOS has CompanyPortal as the rough equivalent for MDM-enrolled Macs.
A broker-mediated sign-in is the lowest-friction path in those
environments — no separate browser launch, can use Windows Hello /
TouchID, picks up device-bound primary refresh tokens.

**Cost:** `windows-rs` + WinRT bindings for WAM
(`Windows.Security.Authentication.Web.Core.WebTokenRequest`), or
`MSAL.framework` Obj-C FFI for CompanyPortal. Each is a few hundred
lines plus per-platform conditional compilation.

**Workaround today:** System browser via `open::that()` opens the
user's default browser. SSO via existing browser session is honored
(the user lands on AAD already signed in). Strictly worse than a
broker, but a long way from broken.

**Pickup trigger:** Windows or macOS tunnel-milestone work picks up
the platform-specific dep.

---

## Linux tunnel (M2)

**Status:** Deferred.

`crates/tunnel-linux/` exists but is mostly empty. To ship:

- `tun-tap` crate (or direct `/dev/net/tun` ioctl) for the device.
- systemd-resolved D-Bus integration for DNS apply (the `<dnssuffix>`
  fix is the entire point of the project — must be right here).
- `netlink` (via `rtnetlink` crate) for route apply.
- Packaging: `.deb`, `.rpm`, AUR. `flake.nix` is already covered.

The cross-cutting crates (`auth`, `profile`, `openvpn`, `ipc`,
`daemon`, `core`) are platform-agnostic and don't need touching.

---

## Windows tunnel (M3)

**Status:** Deferred.

`crates/tunnel-windows/` exists but is mostly empty. To ship:

- `wintun` crate for the TUN driver.
- `windows-rs` for NRPT (DNS Name Resolution Policy Table) writes —
  Microsoft's split-horizon DNS mechanism, equivalent to macOS's
  `SCDynamicStore` supplemental match domains. Required for the
  `<dnssuffix>` fix to work on Windows.
- `windows-rs` Crypt32 for cert-auth (see above).
- WiX or NSIS installer; SCM service registration for the daemon.
- Signed binary (purchasable code-signing cert).

---

## Refresh-token rotation drift in `cloud::exchange_for`

**Status:** Deferred (small).

`crates/auth/src/cloud.rs::exchange_for` runs a refresh-token grant
for Graph / ARM audiences but doesn't save the rotated RT back to the
cache. AAD considers the old RT valid for a grace window (~5 min), so
in practice the next `connect` invocation rotates the cache before
this matters — but a long-lived session of `azvpn me` / `azvpn groups`
calls without intervening connects could theoretically drift the
cache out of sync with AAD's record.

**Fix shape:** Use the existing `TokenCache::save_refresh_result`
helper, but **only the RT field** — `cloud` requests Graph- and
ARM-scoped ATs, which must not overwrite the gateway-scoped AT used
by openvpn auth. Would need a `save_rotated_refresh_token(new_rt:
&str)` method that touches only the RT slot of the cache record.

**Impact:** Theoretical; not observed in practice. Defer until we see
it bite a real user.

---

## CI workflow verification

**Status:** Unverified.

`.github/workflows/` files exist but haven't been run end-to-end on a
fresh runner. Probably want at least:

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- macOS + Linux matrix
- Nix flake build sanity (`nix flake check`)

**Pickup trigger:** First contributor PR, or first release tagging.
