//! Filtering — `AdvancedBlockingApp` regex per-client, `DnsBlockListApp`, `CNAME` cloaking, rebinding.

#![allow(dead_code)]

#[derive(Default)]
pub struct Filter {
    // TODO M6: blocklist URLs, regex set, per-client map, cname cloaking flag
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_blocked(&self, _qname: &str, _client: std::net::IpAddr) -> bool {
        false
    }
}
