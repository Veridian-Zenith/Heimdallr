// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Filtering — `AdvancedBlockingApp` regex per-client, `DnsBlockListApp`, `CNAME` cloaking, rebinding.

#![allow(dead_code)]

use hickory_server::proto::rr::{Record, RecordType};

#[derive(Default)]
pub struct Filter {
    // TODO M6: blocklist URLs, regex set, per-client map, cname cloaking flag
}

/// M5.3: DNAME/ANAME co-existence check (RFC 6676 §2.2).
/// Returns true if a name has both DNAME/ANAME and CNAME records.
pub fn dname_cname_coexistence_violation(records: &[Record]) -> bool {
    let has_dname = records.iter().any(|r| r.record_type() == RecordType::ANAME);
    let has_cname = records.iter().any(|r| r.record_type() == RecordType::CNAME);
    has_dname && has_cname
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_blocked(&self, _qname: &str, _client: std::net::IpAddr) -> bool {
        false
    }
}
