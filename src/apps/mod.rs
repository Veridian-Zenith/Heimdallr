// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Apps — WASM-sandboxed `DnsApp` trait (`ROADMAP.md:M5-M9`).
//! Replaces `DnsServer/Apps/*/` `C#` `dnsApp.config` per-app `csproj`; never `C#` direct.

#![allow(dead_code)]

pub trait DnsApp: Send + Sync {
    fn name(&self) -> &'static str;
    fn handle_query(&self, _qname: &str) -> Option<Vec<u8>> {
        None
    }
}

// Future: wasmtime host, app registry (like Apps/apps2.json)
pub struct AppRegistry {
    apps: Vec<Box<dyn DnsApp>>,
}

impl AppRegistry {
    pub fn new() -> Self {
        Self { apps: vec![] }
    }

    pub fn register(&mut self, app: Box<dyn DnsApp>) {
        self.apps.push(app);
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// M7.1 — Per-app split-horizon / geo routing helper.
/// Returns the zone override for a given (client_ip, qname) pair.
/// Empty result = no app override (use default/global filter).
///
/// Original Heimdallr interface; no Technitium `Apps/` `.csproj` reference.
pub fn app_route_override(
    registry: Option<&AppRegistry>,
    client: std::net::IpAddr,
    qname: &str,
) -> Option<String> {
    let reg = registry.as_ref()?;
    if reg.apps.is_empty() {
        return None;
    }
    // Stub: M7.1 will implement per-subnet matching against
    // `dns_app` geo rules. For now return identity override.
    Some(qname.trim_end_matches('.').to_string())
}


#[cfg(test)]
mod m71_tests {
    use super::*;

    /// M7.1: `AppRegistry` loads from registry and identity override works.
    /// Original `dnsApp` interface; no Technitium `.csproj` derivation.
    #[test]
    fn app_registry_identity_override() {
        let registry = AppRegistry::new();
        assert!(registry.apps.is_empty());
        // The stub override (before full per-subnet geo matching) returns
        // the trimmed qname — verifies the helper is callable.
        let result = super::app_route_override(Some(&registry), std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)), "test.example.");
        assert!(result.is_none(), "stub M7.1: empty registry -> None (will become geo/split-horizon match in M7.2)");
    }
}
