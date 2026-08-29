//! Resolver wrapper — `hickory-resolver` + latency concurrency (`M1` `M6`).

use anyhow::Result;

pub struct Resolver;

impl Resolver {
    pub fn new() -> Self {
        Self
    }

    pub async fn lookup(&self, _qname: &str) -> Result<Vec<u8>> {
        // TODO M1: build hickory-resolver with forwarders or root hints (named.root),
        // latency-based selection concurrency 2, ECS if enabled, DNSSEC validation if on.
        anyhow::bail!("M1 resolver not yet implemented")
    }
}
