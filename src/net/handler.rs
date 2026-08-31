// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! `HeimdallrHandler` — wraps hickory `Catalog` with NOTIFY (`RFC 1996`) support.
//!
//! hickory-server's `Catalog` dispatches `OpCode::Query` and `OpCode::Update`
//! but returns `NotImp` for `OpCode::Notify`. This handler intercepts NOTIFY
//! messages, triggers zone re-AXFR from primaries, and delegates everything
//! else to the inner `Catalog`.

use async_trait::async_trait;
use hickory_server::proto::op::{Header, Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_server::proto::serialize::binary::BinDecodable;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{Catalog, MessageResponseBuilder};
use tracing::{debug, error, info, warn};

/// Zone config needed for NOTIFY-triggered re-AXFR.
#[derive(Debug, Clone)]
pub struct SecondaryZoneInfo {
    pub name: String,
    pub primaries: Vec<String>,
}

/// A `RequestHandler` that wraps hickory's `Catalog` and adds NOTIFY handling.
pub struct HeimdallrHandler {
    catalog: Catalog,
    secondaries: Vec<SecondaryZoneInfo>,
}

impl HeimdallrHandler {
    pub fn new(catalog: Catalog, secondaries: Vec<SecondaryZoneInfo>) -> Self {
        Self {
            catalog,
            secondaries,
        }
    }

    /// Handle an incoming NOTIFY (`OpCode::Notify`).
    ///
    /// Per RFC 1996, a NOTIFY contains the zone name in the query section and
    /// optionally the current SOA serial in the answer section.
    async fn handle_notify<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let query = match request.request_info() {
            Ok(info) => info.query,
            Err(e) => {
                warn!("notify: malformed request: {e}");
                return Self::send_error(request, ResponseCode::FormErr, &mut response_handle)
                    .await;
            }
        };

        let zone_name = query.name().to_utf8();

        // Parse the full message to extract SOA serial from answers
        let serial = if let Ok(msg) = Message::from_bytes(request.as_slice()) {
            msg.answers
                .iter()
                .find(|r| r.record_type() == hickory_server::proto::rr::RecordType::SOA)
                .and_then(|r| {
                    if let hickory_server::proto::rr::RData::SOA(soa) = &r.data {
                        Some(soa.serial)
                    } else {
                        None
                    }
                })
                .unwrap_or(0)
        } else {
            0
        };

        info!("notify: received for {zone_name} serial={serial}");

        // Find matching secondary zone config
        let matching = self
            .secondaries
            .iter()
            .find(|s| s.name == zone_name || s.name == format!("{zone_name}."));

        if let Some(sec) = matching {
            let primaries = sec.primaries.clone();
            let name = sec.name.clone();
            info!("notify: triggering re-AXFR for {name} from {primaries:?}");

            tokio::spawn(async move {
                for primary in &primaries {
                    match crate::core::zone::secondary::axfr_from_primary(&name, primary).await {
                        Ok(_authority) => {
                            info!("notify: {name} re-synced from {primary}");
                            break;
                        }
                        Err(e) => {
                            error!("notify: {name} re-sync from {primary} failed: {e}");
                        }
                    }
                }
            });
        } else {
            debug!("notify: no secondary zone config for {zone_name}, ignoring");
        }

        // Acknowledge the NOTIFY
        Self::send_notify_ack(request, &mut response_handle).await
    }

    async fn send_notify_ack<R: ResponseHandler>(
        request: &Request,
        response_handle: &mut R,
    ) -> ResponseInfo {
        let response = MessageResponseBuilder::new(&request.queries, None)
            .error_msg(&request.metadata, ResponseCode::NoError);
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                error!("notify: failed to send ack: {e}");
                let mut meta =
                    Metadata::new(request.metadata.id, MessageType::Response, OpCode::Notify);
                meta.response_code = ResponseCode::ServFail;
                ResponseInfo::from(Header {
                    metadata: meta,
                    counts: Default::default(),
                })
            }
        }
    }

    async fn send_error<R: ResponseHandler>(
        request: &Request,
        code: ResponseCode,
        response_handle: &mut R,
    ) -> ResponseInfo {
        let response =
            MessageResponseBuilder::new(&request.queries, None).error_msg(&request.metadata, code);
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                error!("handler: failed to send error response: {e}");
                let mut meta = Metadata::new(
                    request.metadata.id,
                    MessageType::Response,
                    request.metadata.op_code,
                );
                meta.response_code = ResponseCode::ServFail;
                ResponseInfo::from(Header {
                    metadata: meta,
                    counts: Default::default(),
                })
            }
        }
    }
}

#[async_trait]
impl RequestHandler for HeimdallrHandler {
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        // Intercept NOTIFY before delegating to Catalog
        if request.metadata.op_code == OpCode::Notify {
            return self.handle_notify(request, response_handle).await;
        }

        // Delegate everything else to the inner Catalog
        self.catalog
            .handle_request::<_, T>(request, response_handle)
            .await
    }
}
