// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! DNS64 (RFC 6147) — synthesize AAAA records from A responses.
//!
//! Given an upstream A answer and a DNS64 prefix (RFC 6052), produces
//! AAAA records by embedding each IPv4 address into the prefix.
//! e.g. prefix `64:ff9b::/96` + A `192.0.2.1` → AAAA `64:ff9b::192.0.2.1`.

use std::net::{Ipv4Addr, Ipv6Addr};

/// A DNS64 prefix (RFC 6052). The prefix length determines which IPv4
/// bytes are embedded:
/// - /96: embed the full IPv4 address (4 bytes) after the 12-byte prefix.
/// - /64: embed the last 4 bytes of the IPv4 address after the 8-byte prefix.
#[derive(Debug, Clone, Copy)]
pub struct Dns64Prefix {
    pub addr: Ipv6Addr,
    pub len: u8,
}

impl Dns64Prefix {
    /// Parse a prefix string like "64:ff9b::/96".
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_str, len_str) = s.split_once('/')?;
        let addr: Ipv6Addr = addr_str.parse().ok()?;
        let len: u8 = len_str.parse().ok()?;
        if len > 128 {
            return None;
        }
        Some(Self { addr, len })
    }
}

/// M5.6: Synthesize AAAA records from A records using the DNS64 prefix.
/// Returns an empty Vec if the prefix is invalid for the given address.
pub fn synthesize_aaaa(a_records: &[A], prefix: Dns64Prefix) -> Vec<AAAA> {
    let mut out = Vec::with_capacity(a_records.len());
    for a in a_records {
        if let Some(v6) = synthesize_one(a.0, prefix) {
            out.push(AAAA(v6));
        }
    }
    out
}

/// Embed a single IPv4 address into the DNS64 prefix.
fn synthesize_one(v4: Ipv4Addr, prefix: Dns64Prefix) -> Option<Ipv6Addr> {
    let v4_bytes = v4.octets();
    let mut v6_bytes = prefix.addr.octets();

    match prefix.len {
        96 => {
            if v6_bytes[..12] != prefix.addr.octets()[..12] {
                return None;
            }
            v6_bytes[12] = v4_bytes[0];
            v6_bytes[13] = v4_bytes[1];
            v6_bytes[14] = v4_bytes[2];
            v6_bytes[15] = v4_bytes[3];
            Some(Ipv6Addr::from(v6_bytes))
        }
        64 => {
            if v6_bytes[..8] != prefix.addr.octets()[..8] {
                return None;
            }
            v6_bytes[8] = v4_bytes[0];
            v6_bytes[9] = v4_bytes[1];
            v6_bytes[10] = v4_bytes[2];
            v6_bytes[11] = v4_bytes[3];
            v6_bytes[12] = 0;
            v6_bytes[13] = 0;
            v6_bytes[14] = 0;
            v6_bytes[15] = 0;
            Some(Ipv6Addr::from(v6_bytes))
        }
        _ => None,
    }
}

/// Lightweight A record type to keep this module decoupled from hickory.
#[derive(Debug, Clone, Copy)]
pub struct A(pub Ipv4Addr);

/// Lightweight AAAA record type.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy)]
pub struct AAAA(pub Ipv6Addr);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefix_basic() {
        let p = Dns64Prefix::parse("64:ff9b::/96").unwrap();
        assert_eq!(
            p.addr,
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(p.len, 96);
    }

    #[test]
    fn synthesize_prefix_96() {
        let prefix = Dns64Prefix::parse("64:ff9b::/96").unwrap();
        let result = synthesize_aaaa(&[A(Ipv4Addr::new(192, 0, 2, 1))], prefix);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].0,
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1)
        );
    }

    #[test]
    fn synthesize_prefix_64() {
        let prefix = Dns64Prefix::parse("64:ff9b::/64").unwrap();
        let result = synthesize_aaaa(&[A(Ipv4Addr::new(192, 0, 2, 1))], prefix);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].0,
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1, 0, 0, 0, 0)
        );
    }

    #[test]
    fn synthesize_multiple_a() {
        let prefix = Dns64Prefix::parse("64:ff9b::/96").unwrap();
        let a_list = [
            A(Ipv4Addr::new(192, 0, 2, 1)),
            A(Ipv4Addr::new(192, 0, 2, 2)),
        ];
        let result = synthesize_aaaa(&a_list, prefix);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0.octets()[12..], [192, 0, 2, 1]);
        assert_eq!(result[1].0.octets()[12..], [192, 0, 2, 2]);
    }

    #[test]
    fn synthesize_unsupported_prefix_len() {
        let prefix = Dns64Prefix::parse("64:ff9b::/56").unwrap();
        let result = synthesize_aaaa(&[A(Ipv4Addr::new(192, 0, 2, 1))], prefix);
        assert!(result.is_empty(), "/56 not supported, should return empty");
    }

    #[test]
    fn parse_invalid_prefix() {
        assert!(Dns64Prefix::parse("not-a-prefix").is_none());
        assert!(Dns64Prefix::parse("64:ff9b::/200").is_none());
    }
}
