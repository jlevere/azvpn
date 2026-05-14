//! M4 acceptance test for the macOS SCDynamicStore DNS path.
//!
//! Run with: `cargo build --example dns-roundtrip -p azvpn-tunnel-darwin
//! && sudo target/debug/examples/dns-roundtrip`
//!
//! Requires root (writing `State:/Network/...` keys is restricted). No
//! tunnel, no AAD, no openvpn — pure DNS-guard install/remove roundtrip.

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use azvpn_tunnel_darwin::DnsGuard;

const SERVICE_UUID: &str = "a1f2cd87-3e9b-4a8d-9c2e-b53f7d4a1c20";
const SERVICE_KEY: &str = "State:/Network/Service/a1f2cd87-3e9b-4a8d-9c2e-b53f7d4a1c20/DNS";
const TEST_SUFFIX_A: &str = "azvpn-roundtrip-a.test";
const TEST_SUFFIX_B: &str = "azvpn-roundtrip-b.test";
const TEST_NS_A: &str = "10.99.0.4";
const TEST_NS_B: &str = "10.99.0.5";

// SCDynamicStore writes propagate to mDNSResponder asynchronously.
const SETTLE: Duration = Duration::from_millis(500);

fn scutil_dns() -> String {
    let out = Command::new("scutil")
        .arg("--dns")
        .output()
        .expect("scutil failed to spawn");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Query the dynamic store directly via `scutil show <key>` — proves whether
/// the key is present in SCDynamicStore independently of mDNSResponder.
fn scutil_show(key: &str) -> String {
    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("scutil failed to spawn");
    let cmd = format!("show {key}\nquit\n");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(cmd.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("scutil wait");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn install_or_die(suffixes: &[&str], dns_servers: &[IpAddr]) -> DnsGuard {
    match DnsGuard::install(suffixes, dns_servers) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("install failed: {e}");
            eprintln!("hint: must run as root — `sudo target/debug/examples/dns-roundtrip`");
            std::process::exit(1);
        }
    }
}

fn diagnostic_dump(label: &str) {
    eprintln!("\n=== diagnostic dump ({label}) ===");
    eprintln!("--- scutil show {SERVICE_KEY} ---");
    eprintln!("{}", scutil_show(SERVICE_KEY));
    eprintln!("--- scutil --dns (first ~80 lines) ---");
    let dns = scutil_dns();
    for line in dns.lines().take(80) {
        eprintln!("{line}");
    }
    eprintln!("--- scutil --dns grep for service UUID + suffixes ---");
    for line in dns.lines() {
        if line.contains(SERVICE_UUID)
            || line.contains(TEST_SUFFIX_A)
            || line.contains(TEST_SUFFIX_B)
        {
            eprintln!("HIT: {line}");
        }
    }
}

fn main() {
    let suffixes = [TEST_SUFFIX_A, TEST_SUFFIX_B];
    let dns_servers: Vec<IpAddr> = vec![
        TEST_NS_A.parse().unwrap(),
        TEST_NS_B.parse().unwrap(),
    ];

    println!("phase 1: install");
    let mut guard = install_or_die(&suffixes, &dns_servers);
    thread::sleep(SETTLE);

    // First: is the key actually in the dynamic store?
    let stored = scutil_show(SERVICE_KEY);
    let key_in_store = !stored.contains("No such key");
    if !key_in_store {
        eprintln!("  \u{2717} key NOT present in SCDynamicStore after install");
        eprintln!("  scutil show returned: {stored}");
        eprintln!("\nFAIL: SCDynamicStore.set call did not persist");
        std::process::exit(1);
    }
    println!("  \u{2713} key present in SCDynamicStore");
    println!("    scutil show output:");
    for line in stored.lines().take(20) {
        println!("    | {line}");
    }

    // Second: does mDNSResponder pick it up?
    let after_install = scutil_dns();
    let mdns_visible = after_install.contains(SERVICE_UUID)
        || after_install.contains(TEST_SUFFIX_A);
    if !mdns_visible {
        eprintln!(
            "\n  \u{2717} key is in the store but mDNSResponder is NOT picking it up"
        );
        eprintln!(
            "  most likely: synthetic services without an Interface/IPv4 binding"
        );
        eprintln!("  get filtered out");
        diagnostic_dump("mDNSResponder did not pick up our key");
        // tear down so we don't leave a key in the store
        guard.remove();
        std::process::exit(1);
    }
    println!("  \u{2713} mDNSResponder shows our entry in scutil --dns");

    println!("\nphase 2: remove");
    guard.remove();
    thread::sleep(SETTLE);
    let stored_after = scutil_show(SERVICE_KEY);
    if !stored_after.contains("No such key") {
        eprintln!("  \u{2717} key still in store after remove");
        eprintln!("  scutil show: {stored_after}");
        std::process::exit(1);
    }
    println!("  \u{2713} key removed from SCDynamicStore");

    println!("\nPASS");
}
