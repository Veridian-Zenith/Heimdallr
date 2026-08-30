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
use std::{net::SocketAddr, str::FromStr};

use crate::config::ResolverConfig as Cfg;

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

    pub fn inner(&self) -> &HickoryResolver<TokioConnectionProvider> {
        &self.inner
    }

    pub fn into_inner(self) -> HickoryResolver<TokioConnectionProvider> {
        self.inner
    }
}

pub type Resolver = ResolverWrap;
