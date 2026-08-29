//! DHCPv4/v6 multi-scope (`ROADMAP.md:M8`) — `DnsServerCore/Dhcp/` parity.

use anyhow::Result;
use tracing::info;

pub struct Dhcp {
    pub enable: bool,
}

impl Dhcp {
    pub fn new(enable: bool) -> Self {
        Self { enable }
    }

    pub async fn run(self) -> Result<()> {
        if !self.enable {
            return Ok(());
        }
        info!("dhcp: enabled (stub)");
        // TODO M8: lease pool, BOOTP, option handling
        Ok(())
    }
}
