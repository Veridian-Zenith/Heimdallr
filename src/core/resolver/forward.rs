//! Cache-aware forwarding authority — the M1 recursive resolution path.
//!
//! Wraps `hickory-resolver` with Heimdallr's `Cache`. On each lookup:
//! 1. Check cache → return cached response if fresh
//! 2. Forward to upstream → cache the response
//! 3. Return to caller via `ServerFuture`

use std::io;

use async_trait::async_trait;
use hickory_resolver::Resolver as HickoryResolver;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_server::authority::{
    Authority, LookupControlFlow, LookupError, LookupOptions, MessageRequest, Nsec3QueryInfo,
    UpdateResult, ZoneType,
};
use hickory_server::dnssec::NxProofKind;
use hickory_server::proto::op::{Message, Query, ResponseCode};
use hickory_server::proto::rr::{LowerName, Name, Record, RecordType};
use hickory_server::server::RequestInfo;
use hickory_server::store::forwarder::ForwardLookup;
use tracing::{debug, warn};

use crate::core::cache::{CacheKey, SharedCache};

/// A forwarding authority that caches responses via Heimdallr's `SharedCache`.
///
/// Lookup flow: cache check → upstream forward → cache store → return.
pub struct CacheForwardAuthority {
    origin: LowerName,
    resolver: HickoryResolver<TokioConnectionProvider>,
    cache: SharedCache,
}

impl CacheForwardAuthority {
    pub fn new(
        origin: LowerName,
        resolver: HickoryResolver<TokioConnectionProvider>,
        cache: SharedCache,
    ) -> Self {
        Self {
            origin,
            resolver,
            cache,
        }
    }
}

#[async_trait]
impl Authority for CacheForwardAuthority {
    type Lookup = ForwardLookup;

    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    fn can_validate_dnssec(&self) -> bool {
        false
    }

    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
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
                match Message::from_vec(&bytes) {
                    Ok(msg) => {
                        let records: Vec<Record> = msg.answers().to_vec();
                        let query = Query::query(Name::from(name.clone()), rtype);
                        let lookup = hickory_resolver::lookup::Lookup::new_with_max_ttl(
                            query,
                            records.into(),
                        );
                        return LookupControlFlow::Continue(Ok(ForwardLookup(lookup)));
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
            let records: Vec<Record> = lookup.record_iter().cloned().collect();
            let mut msg = Message::new();
            msg.set_response_code(ResponseCode::NoError);
            for record in &records {
                msg.add_answer(record.clone());
            }
            if let Ok(bytes) = msg.to_vec() {
                let min_ttl = records
                    .iter()
                    .map(|r| std::time::Duration::from_secs(r.ttl() as u64))
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

        LookupControlFlow::Continue(Ok(ForwardLookup(lookup)))
    }

    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.lookup(
            request_info.query.name(),
            request_info.query.query_type(),
            lookup_options,
        )
        .await
    }

    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "NSEC records not supported for forwarding authority",
        ))))
    }

    async fn get_nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
            "NSEC3 records not supported for forwarding authority",
        ))))
    }

    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}
