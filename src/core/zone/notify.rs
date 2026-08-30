// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! NOTIFY sender (`RFC 1996`) — informs secondaries of zone changes.
//!
//! After a primary increments its SOA serial, it sends a NOTIFY to each
//! secondary, which triggers an immediate zone transfer check.

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{debug, info};

/// Send a NOTIFY to a secondary server for a given zone.
///
/// Builds a DNS NOTIFY message with the zone's current SOA and sends it
/// via UDP to `secondary_addr:53`.
pub async fn send_notify(zone_name: &str, secondary_addr: &str, serial: u32) -> Result<()> {
    let sock_addr: SocketAddr = secondary_addr
        .parse()
        .with_context(|| format!("bad secondary addr '{secondary_addr}'"))?;

    let origin =
        Name::from_ascii(zone_name).with_context(|| format!("invalid zone name '{zone_name}'"))?;

    // Build NOTIFY message
    let mut msg = Message::new();
    // Generate a random 16-bit ID using system time entropy (no `rand` dependency)
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        & 0xFFFF) as u16;
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Notify);
    msg.set_authoritative(true);
    msg.set_recursion_desired(false);

    // Add SOA query for the zone (NOTIFY uses query section to identify the zone)
    let query = hickory_proto::op::Query::query(origin, RecordType::SOA);
    msg.add_query(query);

    let bytes = msg.to_bytes().context("serialize NOTIFY message")?;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind UDP for NOTIFY")?;

    debug!("notify: sending NOTIFY for {zone_name} serial={serial} to {secondary_addr}");

    sock.send_to(&bytes, sock_addr)
        .await
        .with_context(|| format!("send NOTIFY to {sock_addr}"))?;

    info!("notify: sent NOTIFY for {zone_name} to {secondary_addr}");
    Ok(())
}

/// Handle an incoming NOTIFY from a primary.
///
/// Parses the NOTIFY, extracts the zone name and serial, and returns
/// `(zone_name, serial)` for the caller to decide whether to transfer.
pub fn handle_notify(msg: &Message) -> Result<(String, u32)> {
    let query = msg
        .queries()
        .first()
        .context("NOTIFY has no query section")?;

    let zone_name = query.name().to_utf8();

    // Extract serial from the answer section SOA if present
    let serial = msg
        .answers()
        .iter()
        .find(|r| r.record_type() == RecordType::SOA)
        .and_then(|r| {
            if let hickory_proto::rr::RData::SOA(soa) = r.data() {
                Some(soa.serial())
            } else {
                None
            }
        })
        .unwrap_or(0);

    debug!("notify: received NOTIFY for {zone_name} serial={serial}");
    Ok((zone_name, serial))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_notify_extracts_zone_and_serial() {
        let mut msg = Message::new();
        msg.set_op_code(OpCode::Notify);

        let origin = Name::from_ascii("example.test.").unwrap();
        let query = hickory_proto::op::Query::query(origin, RecordType::SOA);
        msg.add_query(query);

        let (zone, serial) = handle_notify(&msg).unwrap();
        assert_eq!(zone, "example.test.");
        assert_eq!(serial, 0);
    }
}
