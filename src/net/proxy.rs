#![allow(dead_code)]
// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! PROXY protocol v1/v2 parser (`HAProxy` spec, Technitium parity `M4`).
//!
//! v1: `PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n` (text, TCP only)
//! v2: binary header with signature, version+command, family, length, then address data.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyVersion {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyCommand {
    Proxy,
    Local,
}

/// Parsed PROXY protocol source address.
#[derive(Debug, Clone)]
pub struct ProxyInfo {
    pub version: ProxyVersion,
    pub command: ProxyCommand,
    pub source: SocketAddr,
}

/// v1 signature: "PROXY " prefix
const V1_PREFIX: &[u8] = b"PROXY ";
/// v2 binary signature: \r\n\r\n\0\r\nQUIT\n (12 bytes)
const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

/// Parse a PROXY protocol header from the beginning of a byte buffer.
///
/// Returns `Ok(None)` if the buffer doesn't look like a PROXY header.
/// Returns `Ok(Some(ProxyInfo))` on success.
/// Returns `Err` if the header is recognized but malformed.
pub fn parse_proxy_header(buf: &[u8]) -> Result<Option<ProxyInfo>> {
    // Check for v2 binary signature (12 bytes) — needs at least 16 bytes total
    if buf.starts_with(V2_SIGNATURE) {
        return parse_v2(buf);
    }

    // Check for v1 text prefix — needs at least 8 bytes ("PROXY \r\n")
    if buf.starts_with(V1_PREFIX) {
        return parse_v1(buf);
    }

    // Not a PROXY header at all
    Ok(None)
}

/// Parse v1 PROXY protocol header (text format).
///
/// Format: `PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n`
fn parse_v1(buf: &[u8]) -> Result<Option<ProxyInfo>> {
    // Find CRLF terminator
    let crlf_pos = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .context("proxy v1: missing CRLF terminator")?;

    let header =
        std::str::from_utf8(&buf[..crlf_pos]).context("proxy v1: header is not valid UTF-8")?;

    let parts: Vec<&str> = header.split(' ').collect();
    if parts.len() < 2 {
        anyhow::bail!("proxy v1: header too short");
    }

    let proto = parts.get(1).unwrap_or(&"UNKNOWN");
    match *proto {
        "UNKNOWN" => Ok(None),
        "TCP4" => {
            if parts.len() < 5 {
                anyhow::bail!("proxy v1 TCP4: expected 5 fields, got {}", parts.len());
            }
            let src_ip: Ipv4Addr = parts[2].parse().context("proxy v1 TCP4: bad source IP")?;
            let src_port: u16 = parts[4].parse().context("proxy v1 TCP4: bad source port")?;
            let source = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
            Ok(Some(ProxyInfo {
                version: ProxyVersion::V1,
                command: ProxyCommand::Proxy,
                source,
            }))
        }
        "TCP6" => {
            if parts.len() < 5 {
                anyhow::bail!("proxy v1 TCP6: expected 5 fields, got {}", parts.len());
            }
            let src_ip: Ipv6Addr = parts[2].parse().context("proxy v1 TCP6: bad source IP")?;
            let src_port: u16 = parts[4].parse().context("proxy v1 TCP6: bad source port")?;
            let source = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
            Ok(Some(ProxyInfo {
                version: ProxyVersion::V1,
                command: ProxyCommand::Proxy,
                source,
            }))
        }
        other => {
            anyhow::bail!("proxy v1: unsupported protocol {other}");
        }
    }
}

/// Parse v2 PROXY protocol header (binary format).
///
/// Layout:
/// ```text
/// 0x00: Signature  (12 bytes: \r\nPROXY\r\n)
/// 0x0C: Ver|Cmd    (1 byte:  high nibble=version, low nibble=command)
/// 0x0D: Family     (1 byte:  0x00=UNSPEC, 0x10=TCP4, 0x20=TCP6, 0x30=UNIX)
/// 0x0E: Length     (2 bytes, network order)
/// 0x10: Address    (variable, length bytes)
/// ```
fn parse_v2(buf: &[u8]) -> Result<Option<ProxyInfo>> {
    // Minimum v2 header: 16 bytes (12 sig + 1 ver/cmd + 1 family + 2 len)
    if buf.len() < 16 {
        anyhow::bail!("proxy v2: header too short ({} < 16)", buf.len());
    }

    let ver_cmd = buf[12];
    let version = (ver_cmd >> 4) & 0x0F;
    let command = ver_cmd & 0x0F;

    if version != 2 {
        anyhow::bail!("proxy v2: unsupported version {version}");
    }

    let proxy_cmd = match command {
        0x00 => ProxyCommand::Proxy,
        0x01 => ProxyCommand::Local,
        other => anyhow::bail!("proxy v2: unsupported command {other}"),
    };

    let family = buf[13];
    let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;

    // Total needed: 16-byte header + addr_len
    if buf.len() < 16 + addr_len {
        anyhow::bail!(
            "proxy v2: header too short for address data ({} < {})",
            buf.len(),
            16 + addr_len
        );
    }

    let addr_data = &buf[16..16 + addr_len];

    match family {
        // TCP4: src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) = 12 bytes
        0x10 => {
            if addr_len < 12 {
                anyhow::bail!("proxy v2 TCP4: addr_len too short ({addr_len} < 12)");
            }
            let src_ip = Ipv4Addr::new(addr_data[0], addr_data[1], addr_data[2], addr_data[3]);
            let src_port = u16::from_be_bytes([addr_data[8], addr_data[9]]);
            let source = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
            Ok(Some(ProxyInfo {
                version: ProxyVersion::V2,
                command: proxy_cmd,
                source,
            }))
        }
        // TCP6: src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) = 36 bytes
        0x20 => {
            if addr_len < 36 {
                anyhow::bail!("proxy v2 TCP6: addr_len too short ({addr_len} < 36)");
            }
            let src_ip = Ipv6Addr::from([
                addr_data[0],
                addr_data[1],
                addr_data[2],
                addr_data[3],
                addr_data[4],
                addr_data[5],
                addr_data[6],
                addr_data[7],
                addr_data[8],
                addr_data[9],
                addr_data[10],
                addr_data[11],
                addr_data[12],
                addr_data[13],
                addr_data[14],
                addr_data[15],
            ]);
            let src_port = u16::from_be_bytes([addr_data[32], addr_data[33]]);
            let source = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
            Ok(Some(ProxyInfo {
                version: ProxyVersion::V2,
                command: proxy_cmd,
                source,
            }))
        }
        // UNSPEC: no address data
        0x00 => Ok(Some(ProxyInfo {
            version: ProxyVersion::V2,
            command: proxy_cmd,
            source: SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        })),
        // UNIX socket — skip (not relevant for DNS)
        0x30 | 0x31 => Ok(None),
        other => anyhow::bail!("proxy v2: unsupported family 0x{other:02x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_tcp4_basic() {
        let header = b"PROXY TCP4 192.168.1.100 10.0.0.1 12345 53\r\n";
        let info = parse_proxy_header(header).unwrap().unwrap();
        assert_eq!(info.version, ProxyVersion::V1);
        assert_eq!(info.command, ProxyCommand::Proxy);
        assert_eq!(
            info.source,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345))
        );
    }

    #[test]
    fn v1_tcp6_basic() {
        let header = b"PROXY TCP6 2001:db8::1 ::1 12345 53\r\n";
        let info = parse_proxy_header(header).unwrap().unwrap();
        assert_eq!(info.version, ProxyVersion::V1);
        assert_eq!(
            info.source,
            SocketAddr::V6(SocketAddrV6::new(
                "2001:db8::1".parse().unwrap(),
                12345,
                0,
                0
            ))
        );
    }

    #[test]
    fn v1_unknown() {
        let header = b"PROXY UNKNOWN\r\n";
        let info = parse_proxy_header(header).unwrap();
        assert!(info.is_none());
    }

    #[test]
    fn v2_tcp4_proxy() {
        let mut buf = Vec::new();
        buf.extend_from_slice(V2_SIGNATURE); // 12 bytes
        buf.push(0x20); // version=2, command=PROXY(0)
        buf.push(0x10); // family=TCP4
        buf.extend_from_slice(&12u16.to_be_bytes()); // addr_len=12
        buf.extend_from_slice(&[10, 0, 0, 1]); // src_ip
        buf.extend_from_slice(&[192, 168, 1, 1]); // dst_ip
        buf.extend_from_slice(&443u16.to_be_bytes()); // src_port
        buf.extend_from_slice(&80u16.to_be_bytes()); // dst_port

        let info = parse_proxy_header(&buf).unwrap().unwrap();
        assert_eq!(info.version, ProxyVersion::V2);
        assert_eq!(info.command, ProxyCommand::Proxy);
        assert_eq!(
            info.source,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443))
        );
    }

    #[test]
    fn v2_tcp6_proxy() {
        let mut buf = Vec::new();
        buf.extend_from_slice(V2_SIGNATURE);
        buf.push(0x20); // version=2, command=PROXY(0)
        buf.push(0x20); // family=TCP6
        buf.extend_from_slice(&36u16.to_be_bytes()); // addr_len=36
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src_ip
        buf.extend_from_slice(&[0; 16]); // dst_ip
        buf.extend_from_slice(&53u16.to_be_bytes()); // src_port
        buf.extend_from_slice(&853u16.to_be_bytes()); // dst_port

        let info = parse_proxy_header(&buf).unwrap().unwrap();
        assert_eq!(info.version, ProxyVersion::V2);
        assert_eq!(info.command, ProxyCommand::Proxy);
        assert_eq!(
            info.source,
            SocketAddr::V6(SocketAddrV6::new("::1".parse().unwrap(), 53, 0, 0))
        );
    }

    #[test]
    fn v2_local_command() {
        let mut buf = Vec::new();
        buf.extend_from_slice(V2_SIGNATURE);
        buf.push(0x21); // version=2, command=LOCAL(1)
        buf.push(0x00); // family=UNSPEC
        buf.extend_from_slice(&0u16.to_be_bytes()); // addr_len=0

        let info = parse_proxy_header(&buf).unwrap().unwrap();
        assert_eq!(info.version, ProxyVersion::V2);
        assert_eq!(info.command, ProxyCommand::Local);
    }

    #[test]
    fn not_proxy_protocol() {
        let data = b"\x00\x00\x00\x00\x00\x00\x00\x00hello";
        assert!(parse_proxy_header(data).unwrap().is_none());
    }

    #[test]
    fn v2_too_short() {
        let mut buf = Vec::new();
        buf.extend_from_slice(V2_SIGNATURE);
        buf.push(0x20);
        // Only 13 bytes, need at least 16
        assert!(parse_proxy_header(&buf).is_err());
    }

    #[test]
    fn v1_no_crlf() {
        let data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678";
        assert!(parse_proxy_header(data).is_err());
    }
}
