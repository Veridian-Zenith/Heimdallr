// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Filtering — blocklists, allowlists, per-client ACL, CNAME cloaking, rebinding.

#![allow(dead_code)]

pub mod blocklist;

use hickory_server::proto::rr::{RData, Record, RecordType};
use std::net::IpAddr;
use std::str::FromStr;

pub use blocklist::{Allowlist, Blocklist, blocked as blocklist_match};

use regex::Regex;

/// M6.1+: in-memory filter state. CNAME cloaking + rebinding come
/// from M5.5; blocklist/allowlist/per-client are M6.1.
pub struct Filter {
    pub cname_chain_limit: u8,
    pub cname_cloaking: bool,
    pub rebinding: bool,
    /// M6.1: loaded blocklist (FQDNs, suffix match).
    pub blocklist: Blocklist,
    /// M6.1: loaded allowlist (FQDNs, overrides blocklist).
    pub allowlist: Allowlist,
    /// M6.1: per-client ACLs (`{ block = false }` disables
    /// blocking for matching client subnets). IPv4 CIDR only.
    pub per_client: Vec<(Ipv4Cidr, bool)>,
    /// M6.1: sinkhole IPv4 address (returned for blocked A queries).
    pub sinkhole_v4: std::net::Ipv4Addr,
    /// M6.1: sinkhole IPv6 address (returned for blocked AAAA queries).
    pub sinkhole_v6: std::net::Ipv6Addr,
    /// M6.2: compiled regex blocklist patterns.
    pub regex_blocklist: Vec<Regex>,
}

/// M6.1: minimal IPv4 CIDR (`a.b.c.d/n`). Avoids pulling `ipnet`
/// just for per-client ACLs.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Cidr {
    addr: std::net::Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    pub fn contains(&self, ip: &std::net::Ipv4Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        if self.prefix >= 32 {
            return self.addr == *ip;
        }
        let mask = !0u32 << (32 - self.prefix);
        let addr_bits = u32::from(self.addr) & mask;
        let ip_bits = u32::from(*ip) & mask;
        addr_bits == ip_bits
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| format!("missing '/' in CIDR: {s}"))?;
        let addr: std::net::Ipv4Addr = addr_str
            .parse()
            .map_err(|e| format!("bad CIDR address '{addr_str}': {e}"))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|e| format!("bad CIDR prefix '{prefix_str}': {e}"))?;
        if prefix > 32 {
            return Err(format!("CIDR prefix out of range: {prefix}"));
        }
        Ok(Self { addr, prefix })
    }
}

impl Filter {
    /// Construct from config. Loads blocklists/allowlists from disk
    /// (missing sources are logged and skipped). Per-client ACLs
    /// that fail to parse as IPv4 CIDR are logged and skipped.
    pub fn new(cfg: &crate::config::FilterConfig) -> Self {
        let blocklist = Blocklist::load_sources(&cfg.blocklists);
        let allowlist = Allowlist::load_sources(&cfg.allowlists);
        let per_client = cfg
            .per_client
            .iter()
            .filter_map(|(cidr, pf)| match Ipv4Cidr::from_str(cidr) {
                Ok(net) => Some((net, pf.block)),
                Err(e) => {
                    tracing::warn!("filter: bad per_client CIDR '{cidr}': {e}");
                    None
                }
            })
            .collect();
        let sinkhole_v4 = std::net::Ipv4Addr::from_str(&cfg.sinkhole_v4).unwrap_or_else(|_| {
            tracing::warn!(
                "filter: bad sinkhole_v4 '{}', defaulting to 0.0.0.0",
                cfg.sinkhole_v4
            );
            std::net::Ipv4Addr::UNSPECIFIED
        });
        let sinkhole_v6 = std::net::Ipv6Addr::from_str(&cfg.sinkhole_v6).unwrap_or_else(|_| {
            tracing::warn!(
                "filter: bad sinkhole_v6 '{}', defaulting to ::",
                cfg.sinkhole_v6
            );
            std::net::Ipv6Addr::UNSPECIFIED
        });
        // M6.2: compile regex patterns; skip invalid ones.
        let regex_blocklist = cfg
            .regex_blocklist
            .iter()
            .filter_map(|pat| match Regex::new(pat) {
                Ok(re) => Some(re),
                Err(e) => {
                    tracing::warn!("filter: invalid regex '{pat}': {e}");
                    None
                }
            })
            .collect();
        Self {
            cname_chain_limit: cfg.cname_chain_limit.unwrap_or(8),
            cname_cloaking: cfg.cname_cloaking,
            rebinding: cfg.rebinding,
            blocklist,
            allowlist,
            per_client,
            sinkhole_v4,
            sinkhole_v6,
            regex_blocklist,
        }
    }

    /// M6.1: True if `qname` should be blocked for `client`.
    /// Per-client `block = false` overrides a blocklist match.
    pub fn is_blocked(&self, qname: &str, client: IpAddr) -> bool {
        // Per-client override: scan in order; first match wins.
        if let IpAddr::V4(v4) = client {
            for (net, block) in &self.per_client {
                if net.contains(&v4) {
                    return *block;
                }
            }
        }
        // Regex blocklist match (M6.2).
        if self.regex_blocklist.iter().any(|re| re.is_match(qname)) {
            MetricsRegistry::new().increment(MetricName::BlockedTotal, 1);
            return true;
        }
        let blocked = blocklist_match(&self.blocklist, &self.allowlist, qname);
        if blocked {
            MetricsRegistry::increment_global(MetricName::BlockedTotal, 1);
        }
        blocked
    }
}

use crate::core::metrics::{MetricName, MetricsRegistry};

/// M5.3: DNAME/ANAME co-existence check (RFC 6676 §2.2).
/// Returns true if a name has both DNAME/ANAME and CNAME records.
pub fn dname_cname_coexistence_violation(records: &[Record]) -> bool {
    let has_dname = records.iter().any(|r| r.record_type() == RecordType::ANAME);
    let has_cname = records.iter().any(|r| r.record_type() == RecordType::CNAME);
    has_dname && has_cname
}

impl Filter {
    fn is_private_or_loopback(addr: std::net::Ipv4Addr) -> bool {
        addr.is_loopback() || addr.is_private() || addr.is_link_local()
    }

    fn is_private_or_loopback_aaaa(addr: std::net::Ipv6Addr) -> bool {
        addr.is_loopback() || addr.is_unique_local() || addr.is_unspecified()
    }

    /// M5.5: Count CNAME chain length in a set of records.
    pub fn cname_chain_count(&self, records: &[Record]) -> usize {
        records
            .iter()
            .filter(|r| r.record_type() == RecordType::CNAME)
            .count()
    }

    /// M5.5: Check if CNAME chain exceeds limit.
    pub fn cname_chain_truncated(&self, records: &[Record]) -> bool {
        let truncated = self.cname_cloaking
            && self.cname_chain_count(records) > self.cname_chain_limit as usize;
        if truncated {
            MetricsRegistry::increment_global(MetricName::CnameChainTruncatedTotal, 1);
        }
        truncated
    }

    /// M5.5: DNS rebinding protection — check if an A/AAAA answer
    /// points to a private/internal address.
    pub fn rebinding_detected(&self, records: &[Record]) -> bool {
        let detected = if !self.rebinding {
            false
        } else {
            records.iter().any(|r| match &r.data {
                RData::A(a) => Self::is_private_or_loopback(a.0),
                RData::AAAA(aaaa) => Self::is_private_or_loopback_aaaa(aaaa.0),
                _ => false,
            })
        };
        if detected {
            MetricsRegistry::increment_global(MetricName::RebindingDetectedTotal, 1);
        }
        detected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};

    fn tmp_hosts(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    fn cfg_with(paths: Vec<String>) -> crate::config::FilterConfig {
        crate::config::FilterConfig {
            blocklists: paths,
            ..Default::default()
        }
    }

    #[test]
    fn empty_filter_blocks_nothing() {
        let f = Filter::new(&cfg_with(vec![]));
        assert!(!f.is_blocked("ads.example.com", IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn loaded_blocklist_blocks_and_allows_subdomains() {
        let tmp = tmp_hosts("0.0.0.0 ads.example.com\n");
        let f = Filter::new(&cfg_with(vec![tmp.path().to_string_lossy().into()]));
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert!(f.is_blocked("ads.example.com", client));
        assert!(f.is_blocked("x.ads.example.com", client));
        assert!(!f.is_blocked("example.com", client));
    }

    #[test]
    fn per_client_block_false_overrides_blocklist() {
        let tmp = tmp_hosts("0.0.0.0 ads.example.com\n");
        let mut cfg = cfg_with(vec![tmp.path().to_string_lossy().into()]);
        cfg.per_client.insert(
            "10.0.0.0/24".into(),
            crate::config::PerClientFilter { block: false },
        );
        let f = Filter::new(&cfg);
        let lan = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        assert!(!f.is_blocked("ads.example.com", lan));
        assert!(f.is_blocked("ads.example.com", other));
    }

    #[test]
    fn cidr_parse_and_match() {
        let cidr = Ipv4Cidr::from_str("10.0.0.0/24").unwrap();
        assert!(cidr.contains(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(cidr.contains(&Ipv4Addr::new(10, 0, 0, 255)));
        assert!(!cidr.contains(&Ipv4Addr::new(10, 0, 1, 1)));
        assert!(!cidr.contains(&Ipv4Addr::new(11, 0, 0, 1)));

        let cidr32 = Ipv4Cidr::from_str("192.0.2.1/32").unwrap();
        assert!(cidr32.contains(&Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!cidr32.contains(&Ipv4Addr::new(192, 0, 2, 2)));

        let cidr0 = Ipv4Cidr::from_str("0.0.0.0/0").unwrap();
        assert!(cidr0.contains(&Ipv4Addr::new(1, 2, 3, 4)));

        assert!(Ipv4Cidr::from_str("not-a-cidr").is_err());
        assert!(Ipv4Cidr::from_str("10.0.0.0/33").is_err());
        assert!(Ipv4Cidr::from_str("10.0.0.0/abc").is_err());
    }
}
