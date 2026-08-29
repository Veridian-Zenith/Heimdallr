pub mod doh;
pub mod proxy;
pub mod quic;
pub mod tcp;
pub mod tls;
pub mod udp;

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use crate::{
    config::Config,
    core::{cache::Cache, filter::Filter, resolver::Resolver},
};

/// `Net` binds listeners for `ROADMAP.md:M1,M4` — `UDP`+`TCP` (`7766`) + `DoT` (`7858`) + `DoQ` (`9250`) + `DoH` (`8484`).
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

        let resolver = Arc::new(Resolver::from_config(&self.cfg.resolver)?);
        let cache = Arc::new(Cache::new());
        let filter = Arc::new(Filter::new());

        // M1: spawn udp + tcp per listen addr (udp currently functional, tcp stub)
        let mut handles = vec![];
        for addr in self.cfg.listen.clone() {
            let r = resolver.clone();
            let c = cache.clone();
            let f = filter.clone();
            let cfg = self.cfg.clone();
            handles.push(tokio::spawn(async move {
                let listener = udp::UdpListener::bind(cfg, r, c, f, addr.clone())
                    .await
                    .unwrap();
                if let Err(e) = listener.run().await {
                    tracing::error!("udp {} error: {e:#}", addr);
                }
            }));
        }

        // Keep running until first handle exits (or ctrl_c)
        if handles.is_empty() {
            // No listen configured — idle
            std::future::pending::<()>().await;
        } else {
            let _ = futures::future::select_all(handles).await;
        }
        Ok(())
    }
}
