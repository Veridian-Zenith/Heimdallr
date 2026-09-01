// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! `HeimdallrHandler` — wraps hickory `Catalog` with NOTIFY (`RFC 1996`) support.
//!
//! hickory-server's `Catalog` dispatches `OpCode::Query` and `OpCode::Update`
//! but returns `NotImp` for `OpCode::Notify`. This handler intercepts NOTIFY
//! messages, triggers zone re-AXFR from primaries, and delegates everything
//! else to the inner `Catalog`.
//!
//! The handler is wrapped in `Arc` for sharing between hickory-server's
//! internal listeners (UDP/TLS/DoH/DoQ) and our custom PROXY-aware TCP listener.

use async_trait::async_trait;
use hickory_server::proto::op::{Header, Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_server::proto::serialize::binary::BinDecodable;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{Catalog, MessageResponseBuilder};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Zone config needed for NOTIFY-triggered re-AXFR.
#[derive(Debug, Clone)]
pub struct SecondaryZoneInfo {
    pub name: String,
    pub primaries: Vec<String>,
}

/// A `RequestHandler` that wraps hickory's `Catalog` and adds NOTIFY handling.
///
/// Not `Clone` — use `Arc<HeimdallrHandler>` for sharing.
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

/// Shared handler — wraps `Arc<HeimdallrHandler>` and implements `RequestHandler`.
///
/// This allows sharing one handler instance between hickory-server's listeners
/// (UDP/TLS/DoH/DoQ) and our custom PROXY-aware TCP listener.
#[derive(Clone)]
pub struct SharedHandler(pub Arc<HeimdallrHandler>);

impl SharedHandler {
    pub fn new(handler: HeimdallrHandler) -> Self {
        Self(Arc::new(handler))
    }
}

#[async_trait]
impl RequestHandler for SharedHandler {
    async fn handle_request<R: ResponseHandler, T: hickory_server::net::runtime::Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        if request.metadata.op_code == OpCode::Notify {
            return self.0.handle_notify(request, response_handle).await;
        }

        self.0
            .catalog
            .handle_request::<_, T>(request, response_handle)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::zone_handler::Catalog;

    #[test]
    fn shared_handler_new_and_clone() {
        let catalog = Catalog::default();
        let handler = SharedHandler::new(HeimdallrHandler::new(catalog, vec![]));
        let handler2 = handler.clone();
        assert!(std::ptr::eq(
            Arc::as_ptr(&handler.0),
            Arc::as_ptr(&handler2.0)
        ));
    }

    #[test]
    fn shared_handler_empty_secondaries() {
        let catalog = Catalog::default();
        let handler = SharedHandler::new(HeimdallrHandler::new(catalog, vec![]));
        assert_eq!(handler.0.secondaries.len(), 0);
    }
}
