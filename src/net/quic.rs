//! DoQ `RFC 9250` — `quinn:ring` pure Rust, no `libmsquic` (`README.md:7`).

use anyhow::Result;
use tracing::debug;

pub struct QuicListener {
    pub addr: String,
}

impl QuicListener {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    pub async fn run(self) -> Result<()> {
        debug!("doq listen on {}", self.addr);
        // TODO M4: quinn Endpoint, rustls:ring cert, DNS over QUIC stream handling
        Ok(())
    }
}
