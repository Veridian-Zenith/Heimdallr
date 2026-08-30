//! DoH `RFC 8484` — `axum` + `h2`, later `h3` via `quinn` (`M4`).

#![allow(dead_code)]

use anyhow::Result;
use tracing::debug;

pub struct DohListener {
    pub addr: String,
}

impl DohListener {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    pub async fn run(self) -> Result<()> {
        debug!("doh listen on {}", self.addr);
        // TODO M4: axum Router at /dns-query, GET+POST, wireformat application/dns-message
        Ok(())
    }
}
