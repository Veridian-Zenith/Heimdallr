//! DoT `RFC 7858` — `rustls:ring` (no OpenSSL/BoringSSL/libmsquic).

#![allow(dead_code)]

use anyhow::Result;
use tracing::debug;

pub struct TlsListener {
    pub addr: String,
}

impl TlsListener {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    pub async fn run(self) -> Result<()> {
        debug!("dot listen on {}", self.addr);
        // TODO M4: rustls ServerConfig with ring, tokio-rustls accept, then tcp framing
        Ok(())
    }
}
