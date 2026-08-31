// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

pub mod cert;
pub mod doh;
pub mod handler;
pub mod proxy;
pub mod quic;
pub mod tcp;
pub mod tls;
pub mod udp;

use anyhow::Result;
use rustls::server::ResolvesServerCert;
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

        // M4: Load TLS cert once for all encrypted listeners (DoT/DoH/DoQ).
        let has_tls_listeners = !self.cfg.listen_tls.is_empty()
            || !self.cfg.listen_https.is_empty()
            || !self.cfg.listen_quic.is_empty();

        let cert_resolver: Option<Arc<dyn ResolvesServerCert>> = if has_tls_listeners {
            let cert_result = crate::net::cert::resolve_cert_paths(
                self.cfg.tls.cert.as_deref(),
                self.cfg.tls.key.as_deref(),
                &self.cfg.host,
                &self.cfg.tls.letsencrypt_dir,
            );

            let (cert_path, key_path) = match cert_result {
                Ok(paths) => paths,
                Err(e) if self.cfg.tls.self_signed_enabled() => {
                    info!("tls: {e} — generating self-signed cert (self_signed=true)");
                    crate::net::cert::generate_self_signed(
                        &self.cfg.host,
                        &self.cfg.dnssec_keys.keys_dir,
                    )?
                }
                Err(e) => return Err(e),
            };

            Some(crate::net::cert::load_tls_cert(&cert_path, &key_path)?)
        } else {
            None
        };

        // M4: DoT listeners — RFC 7858
        if let Some(ref resolver) = cert_resolver {
            for addr in &self.cfg.listen_tls {
                let sock_addr: SocketAddr = addr
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad listen_tls addr '{addr}': {e}"))?;
                let tcp_listener = tokio::net::TcpListener::bind(sock_addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("bind tls {sock_addr}: {e}"))?;
                info!("dot listening on {sock_addr}");
                server
                    .register_tls_listener(tcp_listener, Duration::from_secs(30), resolver.clone())
                    .map_err(|e| anyhow::anyhow!("register_tls_listener {sock_addr}: {e}"))?;
            }
        }

        // M4: DoH listeners — RFC 8484
        if let Some(ref resolver) = cert_resolver {
            for addr in &self.cfg.listen_https {
                let sock_addr: SocketAddr = addr
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad listen_https addr '{addr}': {e}"))?;
                let tcp_listener = tokio::net::TcpListener::bind(sock_addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("bind https {sock_addr}: {e}"))?;
                info!("doh listening on {sock_addr}");
                server
                    .register_https_listener(
                        tcp_listener,
                        Duration::from_secs(30),
                        resolver.clone(),
                        Some(self.cfg.host.clone()),
                        "/dns-query".to_string(),
                    )
                    .map_err(|e| anyhow::anyhow!("register_https_listener {sock_addr}: {e}"))?;
            }
        }

        // M4: DoQ listeners — RFC 9250
        if let Some(ref resolver) = cert_resolver {
            for addr in &self.cfg.listen_quic {
                let sock_addr: SocketAddr = addr
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad listen_quic addr '{addr}': {e}"))?;
                let udp_socket = tokio::net::UdpSocket::bind(sock_addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("bind quic {sock_addr}: {e}"))?;
                info!("doq listening on {sock_addr}");
                server
                    .register_quic_listener(udp_socket, Duration::from_secs(30), resolver.clone())
                    .map_err(|e| anyhow::anyhow!("register_quic_listener {sock_addr}: {e}"))?;
            }
        }

        info!("net: all listeners registered, serving");

        // Graceful shutdown on ctrl+C — cancel hickory-server's internal tasks.
        let shutdown_token = server.shutdown_token().clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install ctrl+C handler");
            info!("net: ctrl+C received, shutting down");
            shutdown_token.cancel();
        });

        server.block_until_done().await?;
        info!("net: all listeners stopped");
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
