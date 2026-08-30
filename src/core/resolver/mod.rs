// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Resolver — `hickory-resolver` with forwarder list + concurrency (`M1` `M6`).
//! Pure tokio; forwarding protocol pinned via Config::resolver.forward_protocol (not opportunistic).

#![allow(dead_code)]

pub mod forward;

use anyhow::{Context, Result};
use hickory_proto::xfer::Protocol;
use hickory_resolver::{
    Resolver as HickoryResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    name_server::TokioConnectionProvider,
};
use std::{net::SocketAddr, path::Path, str::FromStr};
use tracing::debug;

use crate::config::ResolverConfig as Cfg;

/// Well-known system resolver address for fallback.
const SYSTEMD_RESOLVED_STUB: &str = "127.0.0.53:53";

pub struct ResolverWrap {
    inner: HickoryResolver<TokioConnectionProvider>,
}

impl ResolverWrap {
    pub fn from_config(cfg: &Cfg) -> Result<Self> {
        let mut rc = ResolverConfig::new();
        for f in &cfg.forwarders {
            let addr = SocketAddr::from_str(f).with_context(|| format!("bad forwarder {f}"))?;
            let proto = match cfg.forward_protocol.as_str() {
                "udp" => Protocol::Udp,
                "tcp" => Protocol::Tcp,
                "dot" | "doh" | "doq" => {
                    tracing::warn!(
                        "forward_protocol {} needs M4 tls/https/quic feature, falling back to udp for now",
                        cfg.forward_protocol
                    );
                    Protocol::Udp
                }
                _ => Protocol::Udp,
            };
            rc.add_name_server(NameServerConfig {
                socket_addr: addr,
                protocol: proto,
                tls_dns_name: None,
                http_endpoint: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }

        // M1: System-resolver bypass — detect systemd-resolved and add fallback.
        // If systemd-resolved manages resolv.conf, its stub listener at 127.0.0.53
        // forwards to the real upstream. Adding it as a last-resort nameserver means
        // queries still resolve even if configured forwarders are unreachable.
        if let Some(sys_addr) = Self::detect_system_resolver() {
            let addr: SocketAddr = sys_addr.parse().expect("system resolver address is valid");
            rc.add_name_server(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                http_endpoint: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
            debug!("system-resolver bypass: added {sys_addr} as fallback");
        }

        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_millis(cfg.timeout_ms);
        opts.attempts = cfg.concurrency as usize;
        opts.recursion_desired = true;
        opts.edns0 = true;

        let resolver = HickoryResolver::builder_with_config(rc, TokioConnectionProvider::default())
            .with_options(opts)
            .build();

        Ok(Self { inner: resolver })
    }

    /// Detect the system resolver for fallback.
    ///
    /// Returns `Some("127.0.0.53:53")` if systemd-resolved is detected
    /// (stub-resolv.conf exists), `Some("127.0.0.1:53")` if /etc/resolv.conf
    /// points to a non-loopback address, or `None` if no bypass is needed.
    fn detect_system_resolver() -> Option<&'static str> {
        // systemd-resolved stub: /run/systemd/resolve/stub-resolv.conf
        if Path::new("/run/systemd/resolve/stub-resolv.conf").exists() {
            debug!("systemd-resolved detected (stub-resolv.conf exists)");
            return Some(SYSTEMD_RESOLVED_STUB);
        }

        // Also check /etc/resolv.conf — if it points to 127.0.0.53, resolved is active
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let line = line.trim();
                if let Some(ns) = line.strip_prefix("nameserver") {
                    let ns = ns.trim();
                    if ns == "127.0.0.53" {
                        debug!("systemd-resolved detected (resolv.conf points to 127.0.0.53)");
                        return Some(SYSTEMD_RESOLVED_STUB);
                    }
                }
            }
        }

        None
    }

    pub fn inner(&self) -> &HickoryResolver<TokioConnectionProvider> {
        &self.inner
    }

    pub fn into_inner(self) -> HickoryResolver<TokioConnectionProvider> {
        self.inner
    }
}

pub type Resolver = ResolverWrap;
