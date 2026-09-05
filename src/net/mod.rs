// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

pub mod cert;
pub mod handler;
pub mod proxy;
pub mod tcp;
pub mod udp;

use anyhow::Result;
use rustls::server::ResolvesServerCert;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

use crate::config::Config;
use crate::core::cache::{CacheConfig as RuntimeCacheConfig, SharedCache, new_shared_cache};
use crate::core::resolver::ResolverWrap;
use crate::core::resolver::forward::CacheForwardAuthority;
use crate::core::zone::ZoneManager;
use crate::net::handler::{HeimdallrHandler, SharedHandler};
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
        let cache_cfg = RuntimeCacheConfig {
            size: self.cfg.cache.size,
            serve_stale: Duration::from_secs(30),
            prefetch: self.cfg.cache.prefetch as u32,
        };
        let cache = new_shared_cache(cache_cfg);

        // M6.3: Load persistent cache from disk if configured. Missing
        // file = fresh start (no-op). Corrupt file = log warning, proceed
        // with in-memory only.
        if let Some(path) = self.cfg.cache.persistent.clone() {
            match Self::load_persistent_cache(&self.cfg) {
                Ok(Some(loaded)) => {
                    let count = loaded.len();
                    *cache.write().await = loaded;
                    info!(path = %path, count, "net: loaded persistent cache");
                }
                Ok(None) => {
                    debug!(path = %path, "net: no persistent cache to load");
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path,
                        error = %e,
                        "net: persistent cache could not be loaded — starting with empty cache"
                    );
                }
            }
        }

        let (catalog, secondaries) = self.build_catalog(cache.clone())?;
        let handler = SharedHandler::new(HeimdallrHandler::new(catalog, secondaries));
        let mut server = Server::new(handler.clone());

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
        //
        // When proxy protocol is enabled, TCP is handled by our own listener
        // that strips the PROXY header before processing DNS. When disabled,
        // hickory-server handles TCP natively.
        if self.cfg.proxy.enable {
            for addr in &self.cfg.listen {
                let sock_addr: SocketAddr = addr
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad listen addr '{addr}': {e}"))?;
                let tcp_listener = tokio::net::TcpListener::bind(sock_addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("bind tcp {sock_addr}: {e}"))?;
                let handler = handler.clone();
                let proxy_allow = self.cfg.proxy.allow.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        tcp::run_tcp_listener(tcp_listener, handler, true, &proxy_allow).await
                    {
                        tracing::error!("tcp proxy listener failed: {e}");
                    }
                });
            }
        } else {
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

        // M6.3: Save cache to disk before exit. Best-effort — if it
        // fails (full disk, permission denied), we log a warning and
        // continue so the operator doesn't lose their last query stats.
        if let Err(e) = Self::save_persistent_cache(&self.cfg, cache.clone()).await {
            tracing::warn!(error = %e, "net: failed to save persistent cache");
        }

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
        let zone_manager = ZoneManager::new(self.cfg.clone());
        let (mut catalog, secondaries) = zone_manager.load_all()?;

        let forwarder = self.build_cache_forwarder(cache)?;
        catalog.upsert(
            LowerName::from(Name::root()),
            vec![Arc::new(forwarder) as Arc<dyn ZoneHandler>],
        );

        Ok((catalog, secondaries))
    }

    fn build_cache_forwarder(&self, cache: SharedCache) -> Result<CacheForwardAuthority> {
        let dnssec_enabled = self.cfg.dnssec.validation;
        let resolver_wrap = ResolverWrap::from_config(&self.cfg.resolver, dnssec_enabled)?;
        let resolver = resolver_wrap.into_inner();
        let origin = LowerName::from(Name::root());

        info!(
            "net: cache-aware forwarder configured (recursive resolution via hickory-resolver, dnssec={dnssec_enabled})"
        );
        // M5.4: pass QNAME-minimization config to the forwarder.
        // Default is opt-out (enable=false) — behavior unchanged.
        // M5.6: DNS64 prefix for AAAA synthesis.
        // Source priority: top-level [dns64].prefix (preferred, M6) over
        // legacy [resolver].dns64_prefix (kept for backwards compatibility
        // with M5.6 toml). Top-level wins when both are set.
        let dns64_prefix = self
            .cfg
            .dns64
            .prefix
            .as_deref()
            .or(self.cfg.resolver.dns64_prefix.as_deref())
            .and_then(crate::core::resolver::dns64::Dns64Prefix::parse);
        let dns64_always_synthesize = self.cfg.dns64.always_synthesize;
        Ok(CacheForwardAuthority::with_dns64_always_synthesize(
            origin,
            resolver,
            cache,
            dnssec_enabled,
            self.cfg.resolver.qname_minimization.clone(),
            crate::core::filter::Filter::new(&self.cfg.filter),
            dns64_prefix,
            dns64_always_synthesize,
            self.cfg.resolver.ecs,
        ))
    }

    /// M6.3: Load the persistent cache from `cfg.cache.persistent`.
    ///
    /// Returns:
    /// * `Ok(None)` — no path configured (operator opted out) OR file does
    ///   not exist (fresh start) OR file is older than `persistent_max_age_days`.
    /// * `Ok(Some(cache))` — file loaded successfully.
    /// * `Err(InvalidData)` — file exists but is not a valid cache JSON
    ///   snapshot. Caller should log and start with an empty cache.
    /// * `Err(NotFound)` — file path's parent directory doesn't exist;
    ///   usually a misconfiguration.
    ///
    /// `persistent_max_age_days` is checked against the file's mtime;
    /// stale files are ignored so a long-down server doesn't load an
    /// outdated snapshot.
    pub fn load_persistent_cache(
        cfg: &Config,
    ) -> std::io::Result<Option<crate::core::cache::Cache>> {
        let Some(path) = cfg.cache.persistent.as_deref() else {
            return Ok(None);
        };
        let path_buf = std::path::Path::new(path);
        if !path_buf.exists() {
            return Ok(None);
        }
        // Age check: if the file's mtime is older than the configured
        // max age, skip the load. Prevents serving stale entries from
        // a snapshot older than the operator's intent.
        let max_age = std::time::Duration::from_secs(cfg.cache.persistent_max_age_days * 86_400);
        let age_check = std::fs::metadata(path_buf)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok());
        if let Some(age) = age_check
            && age > max_age
        {
            let path_owned = path.to_owned();
            let age_days = age.as_secs() / 86_400;
            let max_days = cfg.cache.persistent_max_age_days;
            tracing::warn!(
                "persistent cache at {} is {} days old (max {} days) — skipping load",
                path_owned,
                age_days,
                max_days
            );
            return Ok(None);
        }
        let cache = crate::core::cache::Cache::load_from_file(path)?;
        Ok(Some(cache))
    }

    /// M6.3: Save the cache to `cfg.cache.persistent`. Creates parent
    /// directories if missing. No-op if no path is configured.
    pub async fn save_persistent_cache(cfg: &Config, cache: SharedCache) -> std::io::Result<()> {
        let Some(path) = cfg.cache.persistent.as_deref() else {
            return Ok(());
        };
        let path_buf = std::path::Path::new(path);
        if let Some(parent) = path_buf.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let guard = cache.read().await;
        guard.save_to_file(path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::cache::{Cache as RuntimeCache, CacheConfig as RuntimeCacheConfig, CacheKey};

    /// M6.3: `load_persistent_cache` returns `Ok(None)` when no path is
    /// configured — caller starts with a fresh in-memory cache.
    #[test]
    fn load_persistent_returns_none_when_no_path_configured() {
        let cfg = Config {
            cache: crate::config::CacheConfig {
                persistent: None,
                ..Default::default()
            },
            ..Config::default()
        };
        let result = Net::load_persistent_cache(&cfg).expect("load");
        assert!(result.is_none());
    }

    /// M6.3: `load_persistent_cache` returns `Ok(None)` when the file
    /// does not exist (fresh start, expected on first run).
    #[test]
    fn load_persistent_returns_none_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            cache: crate::config::CacheConfig {
                persistent: Some(dir.path().join("nonexistent.json").to_string_lossy().into()),
                ..Default::default()
            },
            ..Config::default()
        };
        let result = Net::load_persistent_cache(&cfg).expect("load");
        assert!(result.is_none());
    }

    /// M6.3: `load_persistent_cache` returns `Ok(Some(cache))` when the
    /// file is present and parseable.
    #[test]
    fn load_persistent_returns_some_when_file_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let mut cache = RuntimeCache::new(RuntimeCacheConfig::default());
        cache.insert(
            CacheKey {
                qname: "p.com".into(),
                qtype: 1,
                client_subnet: None,
            },
            vec![1, 2, 3],
            std::time::Duration::from_secs(60),
        );
        cache
            .save_to_file(path.to_str().unwrap())
            .expect("seed save");

        let cfg = Config {
            cache: crate::config::CacheConfig {
                persistent: Some(path.to_string_lossy().into()),
                ..Default::default()
            },
            ..Config::default()
        };
        let loaded = Net::load_persistent_cache(&cfg).expect("load");
        let cache = loaded.expect("some(cache)");
        assert_eq!(cache.len(), 1);
    }

    /// M6.3: `save_persistent_cache` writes the cache to the configured
    /// path and creates parent directories if needed.
    #[test]
    fn save_persistent_writes_to_configured_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("cache.json");
        let cfg = Config {
            cache: crate::config::CacheConfig {
                persistent: Some(path.to_string_lossy().into()),
                ..Default::default()
            },
            ..Config::default()
        };
        let cache = RuntimeCache::new(RuntimeCacheConfig::default());
        let cache: SharedCache = Arc::new(tokio::sync::RwLock::new(cache));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(Net::save_persistent_cache(&cfg, cache))
            .expect("save");
        assert!(path.exists(), "save must create the file");
    }

    /// M6.3: `save_persistent_cache` is a no-op (and returns Ok) when
    /// no path is configured.
    #[test]
    fn save_persistent_is_noop_when_no_path_configured() {
        let cfg = Config {
            cache: crate::config::CacheConfig {
                persistent: None,
                ..Default::default()
            },
            ..Config::default()
        };
        let cache = RuntimeCache::new(RuntimeCacheConfig::default());
        let cache: SharedCache = Arc::new(tokio::sync::RwLock::new(cache));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(Net::save_persistent_cache(&cfg, cache))
            .expect("save without path");
    }

    /// M6.3: corrupt persistent files should not crash the process.
    /// The helper surfaces `InvalidData` so the caller can decide.
    #[test]
    fn load_persistent_corrupt_file_is_handled_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, b"not-json").unwrap();
        let cfg = Config {
            cache: crate::config::CacheConfig {
                persistent: Some(path.to_string_lossy().into()),
                ..Default::default()
            },
            ..Config::default()
        };
        let err = Net::load_persistent_cache(&cfg).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
