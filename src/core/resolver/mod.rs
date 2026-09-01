// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Resolver — `hickory-resolver` with forwarder list + concurrency (`M1` `M6`).
//! Pure tokio; forwarding protocol pinned via Config::resolver.forward_protocol (not opportunistic).

#![allow(dead_code)]

pub mod forward;
pub mod qname_min;

use anyhow::{Context, Result};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_resolver::{
    Resolver as HickoryResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
};
use std::{net::SocketAddr, path::Path, str::FromStr, sync::Arc};
use tracing::debug;

use crate::config::ResolverConfig as Cfg;

/// Well-known system resolver address for fallback.
const SYSTEMD_RESOLVED_STUB: &str = "127.0.0.53:53";

pub struct ResolverWrap {
    inner: HickoryResolver<TokioRuntimeProvider>,
    dnssec_enabled: bool,
}

impl ResolverWrap {
    pub fn from_config(cfg: &Cfg, dnssec_enabled: bool) -> Result<Self> {
        let mut rc = ResolverConfig::default();
        let tls_host = Self::extract_tls_host(cfg);
        for f in &cfg.forwarders {
            let addr = SocketAddr::from_str(f).with_context(|| format!("bad forwarder {f}"))?;
            let ns_config = match cfg.forward_protocol.as_str() {
                "udp" => NameServerConfig::udp(addr.ip()),
                "tcp" => NameServerConfig::tcp(addr.ip()),
                "dot" => {
                    let server_name: Arc<str> = tls_host.as_str().into();
                    NameServerConfig::tls(addr.ip(), server_name)
                }
                "doh" => {
                    let server_name: Arc<str> = tls_host.as_str().into();
                    NameServerConfig::https(addr.ip(), server_name, None)
                }
                "doq" => {
                    let server_name: Arc<str> = tls_host.as_str().into();
                    NameServerConfig::quic(addr.ip(), server_name)
                }
                _ => NameServerConfig::udp(addr.ip()),
            };
            rc.add_name_server(ns_config);
        }

        // M1: System-resolver bypass — detect systemd-resolved and add fallback.
        if let Some(sys_addr) = Self::detect_system_resolver() {
            let addr: SocketAddr = sys_addr.parse().expect("system resolver address is valid");
            let mut ns_config = NameServerConfig::udp(addr.ip());
            ns_config.trust_negative_responses = true;
            rc.add_name_server(ns_config);
            debug!("system-resolver bypass: added {sys_addr} as fallback");
        }

        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_millis(cfg.timeout_ms);
        opts.attempts = cfg.concurrency as usize;
        opts.recursion_desired = true;

        // M3: DNSSEC validation — enable on the resolver when configured
        if dnssec_enabled {
            opts.validate = true;
            debug!("dnssec: resolver validation enabled");
        }

        let builder = HickoryResolver::builder_with_config(rc, TokioRuntimeProvider::default())
            .with_options(opts);

        // M3: Attach built-in root trust anchors when DNSSEC validation is enabled
        let builder = if dnssec_enabled {
            let trust_anchors = Arc::new(hickory_proto::dnssec::TrustAnchors::default());
            debug!("dnssec: attached built-in root trust anchors (20326, 38696)");
            builder.with_trust_anchor(trust_anchors)
        } else {
            builder
        };

        let resolver = builder.build().context("build resolver")?;

        Ok(Self {
            inner: resolver,
            dnssec_enabled,
        })
    }

    /// Detect the system resolver for fallback.
    fn detect_system_resolver() -> Option<&'static str> {
        if Path::new("/run/systemd/resolve/stub-resolv.conf").exists() {
            debug!("systemd-resolved detected (stub-resolv.conf exists)");
            return Some(SYSTEMD_RESOLVED_STUB);
        }

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

    pub fn inner(&self) -> &HickoryResolver<TokioRuntimeProvider> {
        &self.inner
    }

    pub fn into_inner(self) -> HickoryResolver<TokioRuntimeProvider> {
        self.inner
    }

    pub fn is_dnssec_enabled(&self) -> bool {
        self.dnssec_enabled
    }

    /// Extract the TLS hostname from forwarder addresses for DoT/DoH/DoQ SNI.
    ///
    /// Uses the first forwarder address's host as the TLS server name. This works
    /// because DoT/DoH/DoQ all use the same TLS SNI to identify the server.
    fn extract_tls_host(cfg: &Cfg) -> String {
        cfg.forwarders
            .first()
            .and_then(|f| f.split(':').next())
            .unwrap_or("1.1.1.1")
            .to_string()
    }
}

pub type Resolver = ResolverWrap;
