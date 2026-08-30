//! NOTIFY sender (`RFC 1996`) — informs secondaries of zone changes.

#![allow(dead_code)]

use anyhow::Result;
use tracing::info;

/// Send NOTIFY to a secondary after zone serial increment.
/// Placeholder for M2 — will build DNS NOTIFY message and send via UDP.
pub async fn send_notify(_zone_name: &str, _secondary_addr: &str, _serial: u32) -> Result<()> {
    info!("notify: placeholder — will send NOTIFY to secondary in M2.2");
    Ok(())
}
