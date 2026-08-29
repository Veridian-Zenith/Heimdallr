pub mod proxy;
pub mod quic;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod doh;

use anyhow::Result;
use tracing::info;

use crate::config::Config;

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
            self.cfg.listen, self.cfg.listen_tls, self.cfg.listen_quic, self.cfg.listen_https, self.cfg.proxy.enable
        );
        // M1: spawn udp + tcp tasks per listen addr.
        // M4: spawn tls/quic/doh if configured.
        // Stub — gates in ROADMAP.md ensure each listener is tested before merge.
        Ok(())
    }
}
