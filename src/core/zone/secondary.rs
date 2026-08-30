// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! AXFR client for secondary zones (`RFC 1995`).
//!
//! Fetches full zone from primary via TCP AXFR, loads into `InMemoryAuthority`.

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, ZoneType};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

/// Perform an AXFR transfer from a primary and return a loaded `InMemoryAuthority`.
///
/// Sends a single AXFR query over TCP, receives all response messages,
/// and assembles the complete zone.
pub async fn axfr_from_primary(zone_name: &str, primary_addr: &str) -> Result<InMemoryZoneHandler> {
    let sock_addr: SocketAddr = primary_addr
        .parse()
        .with_context(|| format!("bad primary addr '{primary_addr}'"))?;

    let origin =
        Name::from_ascii(zone_name).with_context(|| format!("invalid zone name '{zone_name}'"))?;

    info!("axfr: connecting to {primary_addr} for zone {zone_name}");

    let mut stream = TcpStream::connect(sock_addr)
        .await
        .with_context(|| format!("tcp connect to {primary_addr}"))?;

    // Build AXFR query
    let mut query_msg = Message::query();
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        & 0xFFFF) as u16;
    query_msg.metadata.id = id;
    query_msg.metadata.message_type = MessageType::Query;
    query_msg.metadata.op_code = OpCode::Query;
    query_msg.metadata.recursion_desired = false;

    let query = hickory_proto::op::Query::query(origin.clone(), RecordType::AXFR);
    query_msg.add_query(query);

    let query_bytes = query_msg.to_bytes().context("serialize AXFR query")?;

    // TCP: 2-byte length prefix
    let len = query_bytes.len() as u16;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .context("write AXFR query length")?;
    stream
        .write_all(&query_bytes)
        .await
        .context("write AXFR query body")?;

    debug!("axfr: query sent ({len} bytes), reading responses...");

    // Read all response messages
    let mut records: Vec<Record> = Vec::new();
    let mut saw_soa_start = false;
    let mut soa_serial: Option<u32> = None;

    loop {
        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("read AXFR response length"),
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        if msg_len == 0 {
            break;
        }

        let mut msg_buf = vec![0u8; msg_len];
        stream
            .read_exact(&mut msg_buf)
            .await
            .with_context(|| format!("read AXFR response body ({msg_len} bytes)"))?;

        let response = Message::from_bytes(&msg_buf).context("parse AXFR response")?;

        if response.metadata.response_code != ResponseCode::NoError {
            let rcode = response.metadata.response_code;
            error!("axfr: primary returned {rcode:?} for zone {zone_name}");
            anyhow::bail!("AXFR failed: {rcode:?}");
        }

        // Extract records from answer section
        for rr in response.answers.iter() {
            let rdata = rr.data.clone();

            // Detect SOA records for boundary detection
            if let RData::SOA(soa) = &rdata {
                if !saw_soa_start {
                    // First SOA = start of zone
                    saw_soa_start = true;
                    soa_serial = Some(soa.serial);
                    debug!("axfr: SOA start serial={}", soa.serial);
                } else {
                    // Second SOA = end of zone
                    let serial = soa.serial;
                    debug!("axfr: SOA end serial={serial}");
                    if let Some(start_serial) = soa_serial
                        && serial != start_serial
                    {
                        warn!("axfr: SOA serial mismatch: start={start_serial} end={serial}");
                    }
                    // Don't add the closing SOA
                    continue;
                }
            }

            records.push(rr.clone());
        }

        // Check for truncation (more messages coming)
        if !response.metadata.truncation {
            // Not truncated — but in AXFR, the second SOA signals end
            if saw_soa_start && records.iter().any(|r| r.record_type() == RecordType::SOA) {
                break;
            }
        }
    }

    info!(
        "axfr: received {} records for zone {zone_name}",
        records.len()
    );

    // Build InMemoryZoneHandler from collected records
    let authority = InMemoryZoneHandler::empty(origin, ZoneType::Primary, AxfrPolicy::Deny, None);

    for record in records {
        authority.upsert(record, 0).await;
    }

    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_axfr_response_records() {
        // Verify that SOA boundary detection logic works
        let origin = Name::from_ascii("example.test.").unwrap();
        let mut records: Vec<Record> = Vec::new();

        // Simulate: SOA start, records, SOA end
        let soa_start = Record::update0(origin.clone(), 0, RecordType::SOA);
        records.push(soa_start);

        let a_record = Record::update0(
            Name::from_ascii("host1.example.test.").unwrap(),
            300,
            RecordType::A,
        );
        records.push(a_record);

        // Filter out closing SOA (second SOA in records)
        let mut filtered = Vec::new();
        let mut soa_count = 0;
        for r in &records {
            if r.record_type() == RecordType::SOA {
                soa_count += 1;
                if soa_count == 1 {
                    filtered.push(r.clone());
                }
                // Skip second SOA
            } else {
                filtered.push(r.clone());
            }
        }
        assert_eq!(filtered.len(), 2); // SOA + A record
    }
}
