# Graph & ARM canonical APIs — path forward

Status snapshot from the M0–M4 + canonical-recon session (commit `e8e6162`
and prior). Capturing what we built, what we learned, and what to pick up
when this thread resumes.

## What's live

The Graph identity-side commands all work end-to-end against the user's
real Azure tenant (verified 2026-05-14):

| Command  | Endpoint                   | Status |
|----------|----------------------------|--------|
| `me`     | `GET /v1.0/me`             | ✅ full data |
| `manager`| `GET /v1.0/me/manager`     | ✅ (gracefully reports "no manager") |
| `org`    | `GET /v1.0/organization`   | ✅ full data (name, country, domains, contacts) |
| `groups` | `GET /v1.0/me/memberOf`    | ⚠️ IDs only — see scope-limit below |

The mechanism: cached `refresh_token` from the device-code flow gets
exchanged via `RefreshGrant` (in `crates/auth/src/refresh.rs`) for a
Graph-audience access token, then we call Graph endpoints with direct
`reqwest` through `crate::aad::graph_get<T>`. Same flow the official
Microsoft Azure VPN Client uses, verified against the Ghidra decomp of
`MacTunnelExtension::AadController::getContentWithToken`.

`crate::aad` also exposes `arm_token` / `arm_get<T>` for ARM-audience calls
— they're currently `#[allow(dead_code)]` waiting to be wired into commands.

## The token-scope ceiling

The well-known Azure VPN client ID `41b23e61-6c1e-4545-b367-cd054e0ed4b4`
only has consent for `User.Read` + `User.ReadBasic.All` + `offline_access`
on Microsoft Graph. Concrete consequences:

- `/me/memberOf` works (we can confirm *which* groups you belong to by
  their IDs) but every property comes back `null` because we lack
  `Group.Read.All` to read group metadata.
- `/users/{id}` for other users probably works for basic fields under
  `User.ReadBasic.All`. Worth experimenting.
- `/me/transitiveMemberOf` likely same shape as `/me/memberOf`: IDs
  visible, properties null.
- `/me/joinedTeams`, `/me/calendar`, `/me/messages`, etc.: blocked — no
  consent for those scopes via this client ID.

If we want richer Graph data, we have to acquire tokens through a
different client app registration. Two paths:

1. **Use Microsoft's "public client" common ID**
   `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI) — has broad consent
   in most tenants. Works with the same OAuth flow because the user has
   already authenticated via that public client at some point.
2. **Register our own multi-tenant app** with the scopes we want and have
   the user / tenant admin grant consent. Cleaner long-term; needs an
   app-registration story in Entra.

Both are deferrable until the use case justifies it.

## ARM (untested)

`arm_token` + `arm_get` are scaffolded; no commands wire them in yet. The
two interesting endpoints to try first:

- `GET /subscriptions?api-version=2022-12-01` — lists subscriptions the
  user has any RBAC role on. Likely empty for most users on a tenant
  where they only consume VPN access. Graceful 403 expected when empty.
- `POST /subscriptions/{subId}/resourceGroups/{rg}/providers/Microsoft.Network/p2svpnGateways/{name}/getP2sVpnConnectionHealth?api-version=2022-07-01`
  — lists currently-connected P2S clients with bytes / connection time /
  allocated IP. Requires `Microsoft.Network/p2svpnGateways/read` RBAC.

Same scope-acquisition question applies: the Azure VPN client ID may not
have ARM consent — first refresh-token-grant against
`https://management.azure.com/.default` will tell us with either a token
or an `interaction_required` / `invalid_grant` error. Worth a single
test before architecting full ARM commands.

## OpenVPN management interface — untouched

We use `state on`, `log on`, `hold release`, `signal SIGTERM`, and the
auth-user-pass forwarding. Commands we *could* surface from the
documented management interface (https://openvpn.net/community-resources/management-interface/):

- `status` — peer info, byte counts, route table, virtual addresses.
- `bytecount N` — already parsed in `Event::ByteCount`, just not surfaced.
- `version` — OpenVPN protocol/management versions.
- `pid`, `auth-retry`, `mute`, `verb`.

Building these as separate CLI commands requires an IPC channel from the
new invocation to the running `connect` process (only one mgmt client at
a time — same constraint that drove the `kill(2)` rewrite of
`disconnect`/`status`). Probably blocks on the daemon-pattern refactor.

## Re-entry plan when we come back

1. Land the architectural refactor first (the thing the next session is
   tackling) — gives us a clean home for new commands.
2. Try one ARM call from a throwaway test to confirm token scope works.
3. If ARM works: build `azvpn arm subscriptions` and `azvpn arm gateways`
   (with subscription auto-discovery + correlation to
   `session.server_fqdn`).
4. If ARM doesn't work: document the scope-acquisition options in this
   file and stop.
5. Surface OpenVPN management `status` / `bytecount` / `version` once the
   IPC story exists.
