// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

pub mod doh;
pub mod handler;
pub mod proxy;
pub mod quic;
pub mod tcp;
pub mod tls;
pub mod udp;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::config::Config;
use crate::core::cache::{CacheConfig, SharedCache, new_shared_cache};
use crate::core::resolver::ResolverWrap;
use crate::core::resolver::forward::CacheForwardAuthority;
use crate::core::zone::ZoneManager;
use crate::net::handler::HeimdallrHandler;
use hickory_server::proto::rr::{LowerName, Name};
use hickory_server::server::Server;
use hickory_server::zone_handler::ZoneHandler;

/// `Net` binds listeners for `ROADMAP.md:M1,M2,M4` — UDP + TCP (`7766`) + DoT (`7858`) + DoQ (`9250`) + DoH (`8484`).
pub struct Net {
    cfg: Config,
}

impl Net {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub async fn run(self) -> Result<()> {
        info!(
            "net: listen={:?} tls={:?} quic={:?} https={:?} proxy={}",
            self.cfg.listen,
            self.cfg.listen_tls,
            self.cfg.listen_quic,
            self.cfg.listen_https,
            self.cfg.proxy.enable
        );

        // Build the catalog: authoritative zones + cache-aware forwarder
        let cache_cfg = CacheConfig {
            size: self.cfg.cache.size,
            serve_stale: Duration::from_secs(30),
            prefetch: self.cfg.cache.prefetch as u32,
        };
        let cache = new_shared_cache(cache_cfg);

        let (catalog, secondaries) = self.build_catalog(cache)?;
        let handler = HeimdallrHandler::new(catalog, secondaries);
        let mut server = Server::new(handler);

        // Register UDP listeners
        for addr in &self.cfg.listen {
            let sock_addr: SocketAddr = addr
                .parse()
                .map_err(|e| anyhow::anyhow!("bad listen addr '{addr}': {e}"))?;
            let udp_socket = tokio::net::UdpSocket::bind(sock_addr)
                .await
                .map_err(|e| anyhow::anyhow!("bind udp {sock_addr}: {e}"))?;
            debug!("udp listening on {sock_addr}");
            server.register_socket(udp_socket);
        }

        // Register TCP listeners (M1 — RFC 7766)
        for addr in &self.cfg.listen {
            let sock_addr: SocketAddr = addr
                .parse()
                .map_err(|e| anyhow::anyhow!("bad listen addr '{addr}': {e}"))?;
            let tcp_listener = tokio::net::TcpListener::bind(sock_addr)
                .await
                .map_err(|e| anyhow::anyhow!("bind tcp {sock_addr}: {e}"))?;
            debug!("tcp listening on {sock_addr}");
            server.register_listener(tcp_listener, Duration::from_secs(5), 4096);
        }

        // M4: TLS / QUIC / HTTPS listeners would be registered here

        info!("net: all listeners registered, serving");
        server.block_until_done().await?;
        Ok(())
    }

    /// Build a `Catalog` with authoritative zones from config + a catch-all cache-aware forwarder.
    fn build_catalog(
        &self,
        cache: SharedCache,
    ) -> Result<(
        hickory_server::zone_handler::Catalog,
        Vec<handler::SecondaryZoneInfo>,
    )> {
        // Load authoritative zones
        let zone_manager = ZoneManager::new(self.cfg.clone());
        let (mut catalog, secondaries) = zone_manager.load_all()?;

        // Add catch-all cache-aware forwarder for recursive resolution
        let forwarder = self.build_cache_forwarder(cache)?;
        catalog.upsert(
            LowerName::from(Name::root()),
            vec![Arc::new(forwarder) as Arc<dyn ZoneHandler>],
        );

        Ok((catalog, secondaries))
    }

    /// Build a `CacheForwardAuthority` — hickory-resolver + Heimdallr cache.
    fn build_cache_forwarder(&self, cache: SharedCache) -> Result<CacheForwardAuthority> {
        let dnssec_enabled = self.cfg.dnssec.validation;
        let resolver_wrap = ResolverWrap::from_config(&self.cfg.resolver, dnssec_enabled)?;
        let resolver = resolver_wrap.into_inner();
        let origin = LowerName::from(Name::root());

        info!(
            "net: cache-aware forwarder configured (recursive resolution via hickory-resolver, dnssec={dnssec_enabled})"
        );
        Ok(CacheForwardAuthority::new(
            origin,
            resolver,
            cache,
            dnssec_enabled,
        ))
    }
}
