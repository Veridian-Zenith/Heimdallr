//! AXFR client for secondary zones (`RFC 1995`).
//!
//! Fetches full zone from primary via TCP AXFR, loads into `InMemoryAuthority`.

use anyhow::Result;
use tracing::info;

/// Perform an AXFR transfer from a primary and return loaded records.
/// Placeholder for M2 — will be wired to TCP transport.
pub async fn axfr_from_primary(_zone_name: &str, _primary_addr: &str) -> Result<()> {
    info!("axfr: placeholder — will connect to primary via TCP in M2.1");
    Ok(())
}
