//! Drive DNS and route apply from the current `PushOptions`. Both
//! subsystems are set-replace internally, so this is safe to call on
//! every push-reply — the first call installs, every later call diffs
//! and only changes what actually moved.

use azvpn_openvpn::{PushOptions, PushedRoute};
use azvpn_profile::VpnProfile;
use ipnet::IpNet;
use tracing::info;

use crate::Result;
use crate::cleanup;
use crate::dns::{DnsApplyCtx, DnsManager};
use crate::route::{self, RouteManager};
use crate::session::RunningSession;

/// One-shot entry point: bring DNS + routes into sync with `push_opts`.
/// Errors during route install are logged but don't fail the whole
/// apply — DNS may have already succeeded, and a partial state is
/// recoverable on the next push-reply.
pub(super) async fn tunnel_state(
    dns_manager: &mut dyn DnsManager,
    route_manager: &mut RouteManager,
    session: &mut RunningSession,
    profile: &VpnProfile,
    push_opts: &PushOptions,
) {
    apply_dns(dns_manager, session, profile, push_opts).await;
    if let Err(e) = apply_routes(route_manager, push_opts).await {
        tracing::error!(error = %e, "route apply failed");
    }
    record_cleanup_manifest(route_manager);
}

/// Persist the current install set so a crashed-then-restarted daemon
/// can find and tear it down. Failure is non-fatal — the worst case is
/// orphan routes on the next startup, which the new tunnel's apply
/// path already handles defensively. Logging warns on the way out.
fn record_cleanup_manifest(route_manager: &RouteManager) {
    let manifest = cleanup::Manifest {
        routes: route_manager
            .installed_routes()
            .into_iter()
            .map(|(destination, gateway)| cleanup::RouteEntry {
                destination,
                gateway,
            })
            .collect(),
    };
    let path = cleanup::default_path();
    if let Err(e) = manifest.save(&path) {
        tracing::warn!(path = %path.display(), error = %e, "cleanup manifest write failed");
    }
}

async fn apply_routes(manager: &mut RouteManager, push_opts: &PushOptions) -> Result<()> {
    let Some(gateway) = push_opts.route_gateway else {
        tracing::warn!("no route-gateway in push reply — skipping route install");
        return Ok(());
    };
    let has_v6_ifconfig = push_opts.ifconfig_ipv6.is_some();
    let mut desired: Vec<IpNet> = push_opts
        .routes
        .iter()
        .filter_map(|r| route_for_apply(r, has_v6_ifconfig))
        .collect();

    if let Some(rg) = push_opts.redirect_gateway {
        let extra = route::redirect_gateway_routes(rg);
        if !extra.is_empty() {
            info!(
                full_tunnel_v4 = rg.covers_ipv4(),
                full_tunnel_v6 = rg.covers_ipv6(),
                added = extra.len(),
                "redirect-gateway: appending def1 split-route override"
            );
            desired.extend(extra);
        }
    }

    manager.apply(&desired, gateway).await?;
    Ok(())
}

/// Decide whether a single pushed route should make it into the apply
/// set. Drops:
///
/// - IPv6 routes when no `ifconfig-ipv6` was pushed (would point a v6
///   destination at a v4-only tunnel).
/// - Routes the management-line parser admitted with an invalid
///   (family, prefix-length) pairing.
///
/// Both rejections log a `warn!` so an operator can see what dropped.
fn route_for_apply(r: &PushedRoute, has_v6_ifconfig: bool) -> Option<IpNet> {
    if r.is_ipv6() && !has_v6_ifconfig {
        tracing::warn!(
            destination = %r.destination,
            prefix = r.prefix,
            "skipping IPv6 pushed route — no ifconfig-ipv6 in push reply"
        );
        return None;
    }
    match route::pushed_to_ipnet(r) {
        Ok(net) => Some(net),
        Err(e) => {
            tracing::warn!(
                destination = %r.destination,
                prefix = r.prefix,
                error = %e,
                "skipping route with invalid prefix length"
            );
            None
        }
    }
}

/// Apply DNS suffixes + servers. `DnsManager::apply` is documented as
/// set-replace (first call installs, subsequent calls overwrite), so
/// this is safe to call on every push-reply.
async fn apply_dns(
    manager: &mut dyn DnsManager,
    session: &mut RunningSession,
    profile: &VpnProfile,
    push_opts: &PushOptions,
) {
    let (suffixes, dns_servers) = collect_dns_inputs(profile, push_opts);
    if suffixes.is_empty() {
        info!("no DNS suffixes in profile or push-reply, skipping resolver setup");
        return;
    }
    if dns_servers.is_empty() {
        tracing::warn!("DNS suffixes configured but no DNS servers available");
        return;
    }

    let ctx = DnsApplyCtx {
        tunnel_local: push_opts.ifconfig.as_ref().map(|c| c.local),
    };

    info!(?suffixes, ?dns_servers, "applying DNS resolvers");
    match manager.apply(&suffixes, &dns_servers, &ctx).await {
        Ok(()) => session.record_dns(&suffixes, &dns_servers),
        Err(e) => tracing::error!(error = %e, "failed to apply DNS resolvers"),
    }
}

/// Merge profile-time + push-time DNS inputs. Profile suffixes always
/// apply; push `domain` is appended unless it's already present. DNS
/// servers from push take precedence over profile (matches what the
/// official client does — pushed servers are the gateway's
/// authoritative view).
fn collect_dns_inputs<'p>(
    profile: &'p VpnProfile,
    push_opts: &'p PushOptions,
) -> (Vec<&'p str>, Vec<std::net::IpAddr>) {
    let mut suffixes = profile.dns_suffixes();
    if let Some(pushed) = push_opts.domain.as_deref()
        && !suffixes.iter().any(|s| s.trim_start_matches('.') == pushed)
    {
        suffixes.push(pushed);
    }

    let dns_servers: Vec<std::net::IpAddr> = if push_opts.dns_servers.is_empty() {
        profile
            .dns_servers()
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    } else {
        push_opts.dns_servers.clone()
    };

    (suffixes, dns_servers)
}
