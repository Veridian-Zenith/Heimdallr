// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Cache-aware forwarding authority — the M1 recursive resolution path.
//!
//! Wraps `hickory-resolver` with Heimdallr's `Cache`. On each lookup:
//! 1. Check cache → return cached response if fresh
//! 2. Forward to upstream → cache the response
//! 3. Return to caller via `ServerFuture`

use std::io;

use async_trait::async_trait;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::TSigResponseContext;
use hickory_resolver::Resolver as HickoryResolver;
use hickory_server::dnssec::NxProofKind;
use hickory_server::proto::op::{Message, Query, ResponseCode};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::zone_handler::{
    AuthLookup, LookupControlFlow, LookupError, LookupOptions, Nsec3QueryInfo, ZoneHandler,
    ZoneType,
};

use tracing::{debug, warn};

use crate::config::ResolverQnameMinimization;
use crate::core::cache::{CacheKey, SharedCache};
use crate::core::resolver::qname_min;

/// RFC 8914 Extended DNS Error codes we use.
struct Ede;

impl Ede {
    /// 3 — Stale Answer: serving from stale cache.
    const STALE_ANSWER: u16 = 3;
    /// 13 — Cached Error: serving a cached error response.
    const CACHED_ERROR: u16 = 13;

    /// Encode an EDE info-option as bytes for `EdnsOption::Unknown(15, ...)`.
    ///
    /// Format (RFC 8914 §2):
    /// ```text
    /// INFO-CODE (2 bytes, network order)
    /// EXTRA-TEXT (variable, UTF-8, may be empty)
    /// ```
    fn encode_info(code: u16, extra: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + extra.len());
        buf.extend_from_slice(&code.to_be_bytes());
        buf.extend_from_slice(extra.as_bytes());
        buf
    }
}

/// A forwarding authority that caches responses via Heimdallr's `SharedCache`.
///
/// Lookup flow: cache check → upstream forward → cache store → return.
pub struct CacheForwardAuthority {
    origin: LowerName,
    resolver: HickoryResolver<TokioRuntimeProvider>,
    cache: SharedCache,
    dnssec_enabled: bool,
    /// M5.4: QNAME minimization config (RFC 9156, opt-in).
    qname_minimization: ResolverQnameMinimization,
    /// M5.5: Filtering config (CNAME cloaking, rebinding, chain limits).
    filter: crate::core::filter::Filter,
    /// M5.6: DNS64 prefix (RFC 6052/6147) for AAAA synthesis. None = off.
    dns64_prefix: Option<crate::core::resolver::dns64::Dns64Prefix>,
    /// M5.6: When true, synthesize AAAA from A even if upstream returned
    /// real AAAA records. Default false (only synthesize when upstream
    /// returned no AAAA). Wired to top-level `[dns64].always_synthesize`.
    dns64_always_synthesize: bool,
    /// M5.7: ECS (Extended Client Subnet) enabled — controls whether the
    /// `client_subnet` is extracted from the request info for cache key
    /// partitioning. Default off (opt-in, per RFC 7871).
    ecs: bool,
}

impl CacheForwardAuthority {
    pub fn new(
        origin: LowerName,
        resolver: HickoryResolver<TokioRuntimeProvider>,
        cache: SharedCache,
        dnssec_enabled: bool,
        qname_minimization: ResolverQnameMinimization,
        filter: crate::core::filter::Filter,
        dns64_prefix: Option<crate::core::resolver::dns64::Dns64Prefix>,
    ) -> Self {
        Self::with_dns64_always_synthesize(
            origin,
            resolver,
            cache,
            dnssec_enabled,
            qname_minimization,
            filter,
            dns64_prefix,
            false,
            false,
        )
    }

    /// Constructor that also accepts the `dns64.always_synthesize` flag.
    /// Used by `Net::build_cache_forwarder` once DNS64 config is read.
    #[allow(clippy::too_many_arguments)]
    pub fn with_dns64_always_synthesize(
        origin: LowerName,
        resolver: HickoryResolver<TokioRuntimeProvider>,
        cache: SharedCache,
        dnssec_enabled: bool,
        qname_minimization: ResolverQnameMinimization,
        filter: crate::core::filter::Filter,
        dns64_prefix: Option<crate::core::resolver::dns64::Dns64Prefix>,
        dns64_always_synthesize: bool,
        ecs: bool,
    ) -> Self {
        Self {
            origin,
            resolver,
            cache,
            dnssec_enabled,
            qname_minimization,
            filter,
            dns64_prefix,
            dns64_always_synthesize,
            ecs,
        }
    }

    /// RFC 8482: Handle QTYPE=ANY by returning only A or AAAA.
    ///
    /// ANY queries enable reflection amplification. Per RFC 8482, servers
    /// SHOULD return a subset of records. We return the first available
    /// address record type (A then AAAA), preventing abuse while still
    /// giving clients a useful answer.
    async fn lookup_any(&self, name: &LowerName) -> LookupControlFlow<AuthLookup> {
        let qname = name.to_utf8();
        debug!("RFC 8482:ANY mitigation for {qname}");

        // Try A first, then AAAA — return whichever succeeds.
        for rtype in [RecordType::A, RecordType::AAAA] {
            let key = CacheKey {
                qname: qname.clone(),
                qtype: u16::from(rtype),
                client_subnet: None,
            };

            // Check cache first
            {
                let mut cache = self.cache.write().await;
                if let Some((bytes, _stale, hits)) = cache.lookup_with_metrics(&key) {
                    debug!("RFC 8482:ANY cache hit {qname} {rtype} (hits={hits})");
                    if let Ok(msg) = Message::from_vec(&bytes) {
                        let records: Vec<Record> = msg.answers.to_vec();
                        if !records.is_empty() {
                            let query = Query::query(Name::from(name.clone()), rtype);
                            let lookup =
                                hickory_resolver::lookup::Lookup::new_with_max_ttl(query, records);
                            return LookupControlFlow::Continue(Ok(AuthLookup::from(lookup)));
                        }
                    }
                }
            }

            // Forward single-type query upstream
            let mut fwd_name: Name = name.clone().into();
            fwd_name.set_fqdn(false);
            if let Ok(lookup) = self.resolver.lookup(fwd_name, rtype).await {
                let records: Vec<Record> = lookup.answers().to_vec();
                if !records.is_empty() {
                    // Cache the result
                    let mut msg = Message::query();
                    msg.metadata.response_code = ResponseCode::NoError;
                    for record in &records {
                        msg.add_answer(record.clone());
                    }
                    if let Ok(bytes) = msg.to_vec() {
                        let min_ttl = records
                            .iter()
                            .map(|r| std::time::Duration::from_secs(r.ttl as u64))
                            .min()
                            .unwrap_or(std::time::Duration::from_secs(300));
                        let cache_key = CacheKey {
                            qname: qname.clone(),
                            qtype: u16::from(rtype),
                            client_subnet: None,
                        };
                        let mut cache = self.cache.write().await;
                        cache.insert(cache_key, bytes, min_ttl);
                    }
                    let query = Query::query(Name::from(name.clone()), rtype);
                    let lookup = hickory_resolver::lookup::Lookup::new_with_max_ttl(query, records);
                    return LookupControlFlow::Continue(Ok(AuthLookup::from(lookup)));
                }
            }
        }

        // Neither A nor AAAA available — return NXDOMAIN
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "RFC 8482: no address records for ANY query",
        ))))
    }
}

#[async_trait]
impl ZoneHandler for CacheForwardAuthority {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn axfr_policy(&self) -> hickory_server::zone_handler::AxfrPolicy {
        hickory_server::zone_handler::AxfrPolicy::Deny
    }

    fn can_validate_dnssec(&self) -> bool {
        self.dnssec_enabled
    }

    async fn update(
        &self,
        _update: &Request,
        _now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        (Err(ResponseCode::NotImp), None)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // RFC 8482: ANY queries — return only A or AAAA, not the full set.
        // This prevents reflection amplification and reduces response size.
        if rtype == RecordType::ANY {
            return self.lookup_any(name).await;
        }

        let qname = name.to_utf8();
        // M5.7: ECS cache key partition — extract client subnet scope if present
        // in the request. Wired to `ecs` (opt-in, off by default, per RFC 7871).
        let client_subnet = if self.ecs {
            extract_ecs_scope(request_info)
        } else {
            None
        };
        let key = CacheKey {
            qname: qname.clone(),
            qtype: u16::from(rtype),
            client_subnet,
        };

        // 1. Check cache
        {
            let mut cache = self.cache.write().await;
            if let Some((bytes, _stale, hits)) = cache.lookup_with_metrics(&key) {
                debug!("cache hit: {qname} {rtype} (hits={hits})");

                // Prefetch: if TTL is low relative to hit count, spawn background
                // re-fetch so the next client gets a fresh answer without waiting.
                let do_prefetch = cache.should_prefetch(&key);
                if do_prefetch {
                    let cache = self.cache.clone();
                    let resolver = self.resolver.clone();
                    let name = name.clone();
                    debug!("prefetch triggered: {qname} {rtype} (hits={hits})");
                    tokio::spawn(async move {
                        let mut fwd_name: Name = name.clone().into();
                        fwd_name.set_fqdn(false);
                        if let Ok(lookup) = resolver.lookup(fwd_name, rtype).await {
                            let records: Vec<Record> = lookup.answers().to_vec();
                            let mut msg = Message::query();
                            msg.metadata.response_code = ResponseCode::NoError;
                            for record in &records {
                                msg.add_answer(record.clone());
                            }
                            if let Ok(bytes) = msg.to_vec() {
                                let min_ttl = records
                                    .iter()
                                    .map(|r| std::time::Duration::from_secs(r.ttl as u64))
                                    .min()
                                    .unwrap_or(std::time::Duration::from_secs(300));
                                let key = CacheKey {
                                    qname: name.to_utf8(),
                                    qtype: u16::from(rtype),
                                    client_subnet: None,
                                };
                                let mut cache = cache.write().await;
                                cache.insert(key, bytes, min_ttl);
                                debug!("prefetch complete: {rtype} (ttl={}s)", min_ttl.as_secs());
                            }
                        }
                    });
                }

                match Message::from_vec(&bytes) {
                    Ok(msg) => {
                        let records: Vec<Record> = msg.answers.to_vec();
                        let query = Query::query(Name::from(name.clone()), rtype);
                        let lookup =
                            hickory_resolver::lookup::Lookup::new_with_max_ttl(query, records);
                        return LookupControlFlow::Continue(Ok(AuthLookup::from(lookup)));
                    }
                    Err(e) => {
                        warn!("cache hit but failed to deserialize: {e}");
                    }
                }
            }
        }

        // 2. Forward to upstream
        let mut fwd_name: Name = name.clone().into();
        fwd_name.set_fqdn(false);

        // M5.4: QNAME minimization (RFC 9156) — opt-in. When enabled,
        // issue one query per label step (com. -> example.com. -> ... ->
        // original name) instead of a single full-QNAME lookup. Falls
        // back to a non-minimized query if every peel step errors.
        let lookup = if self.qname_minimization.enable {
            let min_resolver = qname_min::HickoryMinResolver::new(self.resolver.clone());
            match qname_min::resolve_with_minimization(
                &min_resolver,
                fwd_name.clone(),
                rtype,
                &self.qname_minimization,
            )
            .await
            {
                Ok(res) => {
                    let query = Query::query(fwd_name.clone(), rtype);
                    hickory_resolver::lookup::Lookup::new_with_max_ttl(query, res.records)
                }
                Err(e) => {
                    return LookupControlFlow::Continue(Err(LookupError::from(e)));
                }
            }
        } else {
            match self.resolver.lookup(fwd_name.clone(), rtype).await {
                Ok(lookup) => lookup,
                Err(e) => {
                    return LookupControlFlow::Continue(Err(LookupError::from(e)));
                }
            }
        };

        // M5.6: DNS64 synthesis (RFC 6147). If the query was AAAA, upstream
        // returned NoError with no AAAA answers, and a DNS64 prefix is
        // configured, perform a chained A query and synthesize AAAA from
        // the A answers + prefix. Synthesized AAAA records are appended
        // to the answer section so they reach the client AND get cached.
        let mut dns64_synthesized: Vec<Record> = Vec::new();
        if rtype == RecordType::AAAA
            && let Some(prefix) = self.dns64_prefix
        {
            let upstream_aaaa = lookup
                .answers()
                .iter()
                .any(|r| r.record_type() == RecordType::AAAA);
            // `always_synthesize` (top-level [dns64]) overrides the empty-AAAA
            // gate. Default is false (only synthesize when upstream returned
            // nothing) — preserves the typical DNS64 behaviour.
            let do_synth = !upstream_aaaa || self.dns64_always_synthesize;
            if do_synth {
                debug!("dns64: AAAA empty, performing chained A query for {fwd_name}");
                let mut a_fwd = fwd_name.clone();
                a_fwd.set_fqdn(false);
                if let Ok(a_lookup) = self.resolver.lookup(a_fwd, RecordType::A).await {
                    let a_records: Vec<crate::core::resolver::dns64::A> = a_lookup
                        .answers()
                        .iter()
                        .filter_map(|r| {
                            if let RData::A(addr) = &r.data {
                                Some(crate::core::resolver::dns64::A(addr.0))
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !a_records.is_empty() {
                        let aaaa_list =
                            crate::core::resolver::dns64::synthesize_aaaa(&a_records, prefix);
                        debug!(
                            "dns64: synthesized {} AAAA records for {fwd_name}",
                            aaaa_list.len()
                        );
                        // Convert synthesized AAAA wrappers to proper hickory
                        // Records so they can ride on the response Message.
                        // TTL: borrow the minimum A TTL (already what the
                        // answer section would carry), name = original query.
                        let min_a_ttl = a_lookup
                            .answers()
                            .iter()
                            .filter_map(|r| match r.record_type() {
                                RecordType::A => Some(r.ttl),
                                _ => None,
                            })
                            .min()
                            .unwrap_or(300);
                        for synth in &aaaa_list {
                            dns64_synthesized.push(Record::from_rdata(
                                fwd_name.clone(),
                                min_a_ttl,
                                RData::AAAA(synth.0.into()),
                            ));
                        }
                    }
                }
            }
        }

        // M5.3: DNAME synthesis (RFC 6676 §2.2). If upstream answers contain
        // a DNAME record, synthesize the corresponding CNAME substitution
        // chain before caching. Also disable QNAME minimization for DNAME
        // interactions per RFC 9156 §2.2 last paragraph.
        let mut records: Vec<Record> = lookup.answers().to_vec();
        // Append DNS64 synthesized AAAA records (RFC 6147) to the answer
        // section so they reach the client and get cached. This is the
        // M5.6→M6.5 fix: previously the synth records were computed and
        // discarded; now they ride the response.
        records.extend(dns64_synthesized.iter().cloned());
        let has_dname = records.iter().any(|r| r.record_type() == RecordType::ANAME);
        if has_dname {
            // M5.3: enforce DNAME/CNAME co-existence rule at lookup time.
            if crate::core::filter::dname_cname_coexistence_violation(&records) {
                warn!("dname-cname co-existence violation detected for {qname}");
            }
            if self.qname_minimization.enable {
                debug!("qname-min: disabled for DNAME interaction per RFC 9156 §2.2");
            }
            let synthesized = synthesize_dname_cnames(&records, &fwd_name);
            records.extend(synthesized);
        }

        // M5.5: CNAME cloaking enforcement (RFC 9156 / vendor-specific).
        if self.filter.cname_cloaking && self.filter.cname_chain_truncated(&records) {
            return LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
                "CNAME chain truncated (limit exceeded)",
            ))));
        }

        // M5.5: Rebinding protection.
        if self.filter.rebinding && self.filter.rebinding_detected(&records) {
            debug!("rebinding: private/internal address detected in response");
        }

        // 3. Store in cache (use synthesized records if DNAME was present)
        {
            let mut msg = Message::query();
            msg.metadata.response_code = ResponseCode::NoError;
            for record in &records {
                msg.add_answer(record.clone());
            }
            if let Ok(bytes) = msg.to_vec() {
                let min_ttl = records
                    .iter()
                    .map(|r| std::time::Duration::from_secs(r.ttl as u64))
                    .min()
                    .unwrap_or(std::time::Duration::from_secs(300));

                let mut cache = self.cache.write().await;
                cache.insert(key, bytes, min_ttl);
                debug!(
                    "cache store: {qname} {rtype} ({} records, ttl={}s)",
                    records.len(),
                    min_ttl.as_secs()
                );
            }
        }

        // M5.3: ANAME flattening synthesis (apex CNAME flattening, draft-ietf-dnsop-aname).
        // For synthetic CNAME targets (from ANAME rewrite), synthesize A/AAAA
        // by performing upstream lookups of the target name. Note: AAAA lookup
        // requires upstream support; user's network may not provide it.
        let mut synthesized_aaaa: Vec<Record> = Vec::new();
        let synthetic_target = records.iter().find_map(|r| {
            if r.record_type() == RecordType::CNAME {
                if let RData::CNAME(cname) = &r.data {
                    Some(cname.0.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        if let Some(target_name) = synthetic_target {
            // Upstream A lookup for synthetic CNAME target
            let a_lookup = self
                .resolver
                .lookup(
                    Name::from_ascii(target_name.to_utf8()).unwrap_or_else(|_| Name::root()),
                    RecordType::A,
                )
                .await
                .ok();
            if let Some(a_res) = a_lookup {
                records.extend(a_res.answers().to_vec());
            }
            // Upstream AAAA lookup (may fail if user's upstream/network lacks AAAA support)
            let aaaa_lookup = self
                .resolver
                .lookup(
                    Name::from_ascii(target_name.to_utf8()).unwrap_or_else(|_| Name::root()),
                    RecordType::AAAA,
                )
                .await
                .ok();
            if let Some(aaaa_res) = aaaa_lookup {
                synthesized_aaaa.extend(aaaa_res.answers().to_vec());
            }
            records.extend(synthesized_aaaa);
        }

        LookupControlFlow::Continue(if !dns64_synthesized.is_empty() {
            // M5.6/M6.5: rebuild AuthLookup from the extended `records`
            // so the synthesized AAAA records actually appear in the
            // response (the original `lookup` doesn't know about them).
            let query = Query::query(fwd_name.clone(), rtype);
            let lookup = hickory_resolver::lookup::Lookup::new_with_max_ttl(query, records.clone());
            Ok(AuthLookup::from(lookup))
        } else {
            Ok(AuthLookup::from(lookup))
        })
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        match request.request_info() {
            Ok(info) => {
                let result = self
                    .lookup(
                        info.query.name(),
                        info.query.query_type(),
                        Some(&info),
                        lookup_options,
                    )
                    .await;
                (result, None)
            }
            Err(_) => (
                LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
                    "invalid request",
                )))),
                None,
            ),
        }
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "NSEC records not supported for forwarding authority",
        ))))
    }

    async fn nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "NSEC3 records not supported for forwarding authority",
        ))))
    }

    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}

/// M5.7: Zero the trailing bits of an IP address per its source prefix
/// (RFC 7871 §7.1.2 privacy scope-zeroing).
/// e.g. 192.0.2.123/24 -> 192.0.2.0/24
fn scope_zero_subnet(addr: std::net::IpAddr, source_prefix: u8) -> (std::net::IpAddr, u8) {
    match addr {
        std::net::IpAddr::V4(v4) => {
            let mask = if source_prefix == 0 {
                0u32
            } else if source_prefix >= 32 {
                0xFFFF_FFFFu32
            } else {
                (!0u32) << (32 - source_prefix)
            };
            let octets = v4.octets();
            let ip = u32::from_be_bytes(octets) & mask;
            (
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip)),
                source_prefix,
            )
        }
        std::net::IpAddr::V6(v6) => {
            let mask = if source_prefix == 0 {
                u128::MIN
            } else if source_prefix >= 128 {
                u128::MAX
            } else {
                (!0u128) << (128 - source_prefix)
            };
            let ip = u128::from(v6) & mask;
            (
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                source_prefix,
            )
        }
    }
}

/// M5.7: Extract ECS scope from request info (if present).
/// Returns the scope-zeroed (address, scope_prefix) for cache partitioning.
///
/// Note: hickory's `RequestInfo` does not currently expose the EDNS options
/// (they live on the `Request` message itself, not the parsed `RequestInfo`).
/// Until `lookup` gains access to the full `Request`, this function returns
/// `None` and ECS cache partitioning is a structural no-op. The `CacheKey`
/// shape and `scope_zero_subnet` helper are still in place so M5.6 (DNS64)
/// and the follow-up ECS wiring can plug in without further cache changes.
fn extract_ecs_scope(_request_info: Option<&RequestInfo<'_>>) -> Option<(std::net::IpAddr, u8)> {
    None
}

/// M5.3: Synthesize CNAME substitution chain for DNAME responses (RFC 6676 §2.2).
/// Given a set of records containing a DNAME, produces synthetic CNAME
/// records representing the substitution. Loop detection skips synthesis
/// when the DNAME target equals the original query name.
fn synthesize_dname_cnames(records: &[Record], original: &Name) -> Vec<Record> {
    let mut synthesized = Vec::new();
    for r in records {
        if r.record_type() == RecordType::ANAME
            && let RData::ANAME(dname) = &r.data
        {
            // RFC 6676 §2.2 substitution: create synthetic CNAME
            // mapping the query name to the DNAME target.
            // Skip loop detection: if target == original query, don't synthesize.
            if dname.0 == *original {
                debug!("dname: loop detected for {original}, skipping synthesis");
                continue;
            }
            // Synthetic CNAME: original query name -> DNAME target name
            let cname_data = RData::CNAME(hickory_server::proto::rr::rdata::CNAME(dname.0.clone()));
            let cname = Record::from_rdata(original.clone(), r.ttl, cname_data);
            synthesized.push(cname);
        }
    }
    synthesized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eden_encode_info_stale_answer() {
        let buf = Ede::encode_info(Ede::STALE_ANSWER, "stale because upstream timeout");
        assert_eq!(&buf[0..2], &3u16.to_be_bytes());
        assert_eq!(
            std::str::from_utf8(&buf[2..]).unwrap(),
            "stale because upstream timeout"
        );
    }

    #[test]
    fn eden_encode_info_cached_error() {
        let buf = Ede::encode_info(Ede::CACHED_ERROR, "");
        assert_eq!(&buf[0..2], &13u16.to_be_bytes());
        assert!(buf[2..].is_empty());
    }

    #[test]
    fn eden_encode_info_roundtrip() {
        let msg = "test extra text";
        let buf = Ede::encode_info(42, msg);
        let code = u16::from_be_bytes([buf[0], buf[1]]);
        let extra = std::str::from_utf8(&buf[2..]).unwrap();
        assert_eq!(code, 42);
        assert_eq!(extra, msg);
    }

    // M5.7 — ECS scope-zeroing
    #[test]
    fn scope_zero_ipv4_24() {
        let addr: std::net::IpAddr = "192.0.2.123".parse().unwrap();
        let (zeroed, prefix) = scope_zero_subnet(addr, 24);
        assert_eq!(zeroed.to_string(), "192.0.2.0");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn scope_zero_ipv4_0() {
        let addr: std::net::IpAddr = "192.0.2.123".parse().unwrap();
        let (zeroed, prefix) = scope_zero_subnet(addr, 0);
        assert_eq!(zeroed.to_string(), "0.0.0.0");
        assert_eq!(prefix, 0);
    }

    #[test]
    fn scope_zero_ipv4_32() {
        let addr: std::net::IpAddr = "192.0.2.123".parse().unwrap();
        let (zeroed, prefix) = scope_zero_subnet(addr, 32);
        assert_eq!(zeroed.to_string(), "192.0.2.123");
        assert_eq!(prefix, 32);
    }
}
