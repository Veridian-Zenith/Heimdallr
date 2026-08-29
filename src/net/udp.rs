//! UDP listener — `tokio::net::UdpSocket` + `recvmmsg` batching (M1).
//! Mirrors `TechnitiumLibrary.Net` async IO but with `ring`-only crypto upper layers.

use anyhow::Result;
use tracing::debug;

pub struct UdpListener {
    pub addr: String,
}

impl UdpListener {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    pub async fn run(self) -> Result<()> {
        debug!("udp listen on {}", self.addr);
        // TODO M1: bind, loop recv_from, handoff to core::resolver with TXID+port randomization
        Ok(())
    }
}
