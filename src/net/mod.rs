pub mod doh;
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
use crate::core::zone::ZoneManager;
use hickory_server::ServerFuture;
use hickory_server::authority::{AuthorityObject, Catalog};
use hickory_server::store::forwarder::{ForwardAuthority, ForwardConfig};

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

        // Build the catalog: authoritative zones + forwarder
        let catalog = self.build_catalog()?;
        let mut server = ServerFuture::new(catalog);

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
            server.register_listener(tcp_listener, Duration::from_secs(5));
        }

        // M4: TLS / QUIC / HTTPS listeners would be registered here

        info!("net: all listeners registered, serving");
        server.block_until_done().await?;
        Ok(())
    }

    /// Build a `Catalog` with authoritative zones from config + a catch-all forwarder.
    fn build_catalog(&self) -> Result<Catalog> {
        // Load authoritative zones
        let zone_manager = ZoneManager::new(self.cfg.clone());
        let mut catalog = zone_manager.load_all()?;

        // Add catch-all forwarder for recursive resolution (everything not handled by zones)
        let forwarder = self.build_forwarder()?;
        catalog.upsert(
            hickory_server::proto::rr::LowerName::from(hickory_server::proto::rr::Name::root()),
            vec![Arc::new(forwarder) as Arc<dyn AuthorityObject>],
        );

        Ok(catalog)
    }

    /// Build a `ForwardAuthority` for recursive resolution.
    fn build_forwarder(&self) -> Result<ForwardAuthority> {
        use hickory_server::proto::xfer::Protocol;
        use hickory_server::resolver::config::{NameServerConfig, NameServerConfigGroup};

        let mut ns_configs = vec![];
        for f in &self.cfg.resolver.forwarders {
            let addr: SocketAddr = f
                .parse()
                .map_err(|e| anyhow::anyhow!("bad forwarder '{f}': {e}"))?;
            let proto = match self.cfg.resolver.forward_protocol.as_str() {
                "tcp" => Protocol::Tcp,
                _ => Protocol::Udp,
            };
            ns_configs.push(NameServerConfig::new(addr, proto));
        }
        let name_servers = NameServerConfigGroup::from(ns_configs);

        let forwarder = ForwardAuthority::builder_tokio(ForwardConfig {
            name_servers,
            options: None,
        })
        .build()
        .map_err(|e| anyhow::anyhow!("build forwarder: {e}"))?;

        Ok(forwarder)
    }
}
