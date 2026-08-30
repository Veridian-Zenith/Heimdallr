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
use hickory_server::proto::rr::{LowerName, Name, Record, RecordType};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::zone_handler::{
    AuthLookup, LookupControlFlow, LookupError, LookupOptions, Nsec3QueryInfo, ZoneHandler,
    ZoneType,
};

use tracing::{debug, warn};

use crate::core::cache::{CacheKey, SharedCache};

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
}

impl CacheForwardAuthority {
    pub fn new(
        origin: LowerName,
        resolver: HickoryResolver<TokioRuntimeProvider>,
        cache: SharedCache,
    ) -> Self {
        Self {
            origin,
            resolver,
            cache,
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
            };

            // Check cache first
            {
                let mut cache = self.cache.write().await;
                if let Some((bytes, _stale, hits)) = cache.lookup(&key) {
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
        false
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
        _request_info: Option<&RequestInfo<'_>>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        // RFC 8482: ANY queries — return only A or AAAA, not the full set.
        // This prevents reflection amplification and reduces response size.
        if rtype == RecordType::ANY {
            return self.lookup_any(name).await;
        }

        let qname = name.to_utf8();
        let key = CacheKey {
            qname: qname.clone(),
            qtype: u16::from(rtype),
        };

        // 1. Check cache
        {
            let mut cache = self.cache.write().await;
            if let Some((bytes, _stale, hits)) = cache.lookup(&key) {
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

        let lookup = match self.resolver.lookup(fwd_name, rtype).await {
            Ok(lookup) => lookup,
            Err(e) => {
                return LookupControlFlow::Continue(Err(LookupError::from(e)));
            }
        };

        // 3. Store in cache
        {
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

                let mut cache = self.cache.write().await;
                cache.insert(key, bytes, min_ttl);
                debug!(
                    "cache store: {qname} {rtype} ({} records, ttl={}s)",
                    records.len(),
                    min_ttl.as_secs()
                );
            }
        }

        LookupControlFlow::Continue(Ok(AuthLookup::from(lookup)))
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
}
