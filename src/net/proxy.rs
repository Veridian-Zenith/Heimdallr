//! PROXY protocol v1/v2 for UDP+TCP (`HAProxy` spec, Technitium parity `M4`).

#![allow(dead_code)]

use anyhow::Result;

#[derive(Debug, Clone, Copy)]
pub enum ProxyVersion {
    V1,
    V2,
}

/// Parse PROXY line from stream prefix; allowlist check in `Config::proxy.allow`.
pub fn parse_proxy_header(_buf: &[u8]) -> Result<Option<(ProxyVersion, std::net::SocketAddr)>> {
    // TODO M4: v1 text "PROXY TCP4 ..." + v2 binary TLV, strict CRLF, deny on mismatch
    Ok(None)
}
