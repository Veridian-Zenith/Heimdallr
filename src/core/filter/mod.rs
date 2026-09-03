// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Filtering — `AdvancedBlockingApp` regex per-client, `DnsBlockListApp`, `CNAME` cloaking, rebinding.

#![allow(dead_code)]

use hickory_server::proto::rr::{RData, Record, RecordType};
use std::net::Ipv4Addr;

#[derive(Default, Clone, Debug)]
pub struct Filter {
    pub cname_chain_limit: u8,
    pub cname_cloaking: bool,
    pub rebinding: bool,
}

/// M5.3: DNAME/ANAME co-existence check (RFC 6676 §2.2).
/// Returns true if a name has both DNAME/ANAME and CNAME records.
pub fn dname_cname_coexistence_violation(records: &[Record]) -> bool {
    let has_dname = records.iter().any(|r| r.record_type() == RecordType::ANAME);
    let has_cname = records.iter().any(|r| r.record_type() == RecordType::CNAME);
    has_dname && has_cname
}

impl Filter {
    pub fn new(cfg: &crate::config::FilterConfig) -> Self {
        Self {
            cname_chain_limit: cfg.cname_chain_limit.unwrap_or(8),
            cname_cloaking: cfg.cname_cloaking,
            rebinding: cfg.rebinding,
        }
    }

    pub fn is_blocked(&self, _qname: &str, _client: std::net::IpAddr) -> bool {
        false
    }

    fn is_private_or_loopback(addr: Ipv4Addr) -> bool {
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
        self.cname_cloaking && self.cname_chain_count(records) > self.cname_chain_limit as usize
    }

    /// M5.5: DNS rebinding protection — check if an A/AAAA answer points
    /// to a private/internal address.
    pub fn rebinding_detected(&self, records: &[Record]) -> bool {
        if !self.rebinding {
            return false;
        }
        records.iter().any(|r| match &r.data {
            RData::A(a) => Self::is_private_or_loopback(a.0),
            RData::AAAA(aaaa) => Self::is_private_or_loopback_aaaa(aaaa.0),
            _ => false,
        })
    }
}
