// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Zone file loading via `hickory_server::store::file::FileAuthority`.
//!
//! Supports standard zone file format: `$ORIGIN`, `$TTL`, and all common record types
//! (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SOA`, `NS`, `PTR`, `SRV`).
//!
//! After loading, the SOA RNAME (admin email) is patched to match the configured
//! `hostadmin` setting, ensuring consistency across all zones.

use anyhow::{Result, bail};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType, RrKey};
use hickory_server::store::file::{FileConfig, FileZoneHandler};
use hickory_server::zone_handler::{AxfrPolicy, ZoneType};
use std::path::{Path, PathBuf};

/// Load a zone file and return a `FileAuthority`.
///
/// If `soa_rname_override` is provided, the SOA RNAME (admin email) in the loaded
/// zone is patched to match it. This ensures all zones use the configured `hostadmin`.
pub fn load_zone_file(
    file_path: &str,
    zone_name: &str,
    zones_dir: &str,
    zone_type: ZoneType,
    soa_rname_override: Option<&str>,
) -> Result<FileZoneHandler> {
    load_zone_file_with_proof(
        file_path,
        zone_name,
        zones_dir,
        zone_type,
        soa_rname_override,
        Some(hickory_server::dnssec::NxProofKind::Nsec),
    )
}

/// Load a zone file with explicit NSEC/NSEC3 proof kind.
pub fn load_zone_file_with_proof(
    file_path: &str,
    zone_name: &str,
    zones_dir: &str,
    zone_type: ZoneType,
    soa_rname_override: Option<&str>,
    nx_proof_kind: Option<hickory_server::dnssec::NxProofKind>,
) -> Result<FileZoneHandler> {
    let path = resolve_zone_path(file_path, zones_dir);

    if !path.exists() {
        bail!("zone file not found: {}", path.display());
    }

    let origin =
        Name::from_ascii(zone_name).map_err(|e| anyhow::anyhow!("invalid zone origin: {e}"))?;

    let config = FileConfig {
        zone_path: path.clone(),
    };

    let mut authority = FileZoneHandler::try_from_config(
        origin.clone(),
        zone_type,
        AxfrPolicy::AllowAll, // allow_axfr
        None,                 // root_dir
        &config,
        nx_proof_kind,
    )
    .map_err(|e| anyhow::anyhow!("failed to parse zone file {}: {e}", path.display()))?;

    // Patch SOA RNAME if configured
    if let Some(rname_str) = soa_rname_override {
        patch_soa_rname(&mut authority, &origin, rname_str)?;
    }

    Ok(authority)
}

/// Replace the SOA record's RNAME (admin email) in the authority.
fn patch_soa_rname(authority: &mut FileZoneHandler, origin: &Name, rname_str: &str) -> Result<()> {
    let new_rname = Name::from_ascii(rname_str)
        .map_err(|e| anyhow::anyhow!("invalid SOA RNAME '{rname_str}': {e}"))?;

    let soa_key = RrKey::new(LowerName::from(origin.clone()), RecordType::SOA);

    // Extract existing SOA data, then remove the old record set and re-insert with new RNAME
    let old_soa = {
        let records = authority.records_get_mut();
        records.get(&soa_key).and_then(|set| {
            set.records(false).next().and_then(|r| {
                if let RData::SOA(soa) = &r.data {
                    Some(soa.clone())
                } else {
                    None
                }
            })
        })
    };

    if let Some(soa) = old_soa {
        let new_soa = hickory_server::proto::rr::rdata::SOA::new(
            soa.mname.clone(),
            new_rname,
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum,
        );

        // Remove old SOA, then upsert new one
        authority.records_get_mut().remove(&soa_key);
        let new_record = Record::from_rdata(origin.clone(), 86400, RData::SOA(new_soa));
        authority.upsert_mut(new_record, 0);
    }

    Ok(())
}

/// Resolve a zone file path: absolute as-is, relative joined to `zones_dir`.
fn resolve_zone_path(file_path: &str, zones_dir: &str) -> PathBuf {
    let p = Path::new(file_path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        PathBuf::from(zones_dir).join(file_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_example_test_zone() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/zones/live");
        let zone = load_zone_file(
            "example.test.zone",
            "example.test.",
            dir.to_str().unwrap(),
            ZoneType::Primary,
            None,
        );
        assert!(zone.is_ok(), "failed to load example.test zone");
    }

    #[test]
    fn load_reverse_zone() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/zones/live");
        let zone = load_zone_file(
            "10.in-addr.arpa.zone",
            "10.in-addr.arpa.",
            dir.to_str().unwrap(),
            ZoneType::Primary,
            None,
        );
        assert!(zone.is_ok(), "failed to load reverse zone");
    }

    #[test]
    fn missing_file_errors() {
        let zone = load_zone_file("nope.zone", "nope.test.", "/tmp", ZoneType::Primary, None);
        assert!(zone.is_err());
    }

    #[test]
    fn load_zone_records_count() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/zones/live");
        let zone = load_zone_file(
            "example.test.zone",
            "example.test.",
            dir.to_str().unwrap(),
            ZoneType::Primary,
            None,
        )
        .unwrap();

        let records = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(zone.records());
        // SOA, NS, A (ns1, ns2, @, www, mail), AAAA, MX, CNAME, TXT (x2), SRV
        assert!(
            records.len() >= 8,
            "expected >=8 record sets, got {}",
            records.len()
        );
    }

    #[test]
    fn soa_rname_patched() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/zones/live");
        let zone = load_zone_file(
            "example.test.zone",
            "example.test.",
            dir.to_str().unwrap(),
            ZoneType::Primary,
            Some("admin.mynetwork.test."),
        )
        .unwrap();

        let records = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(zone.records());

        let origin = Name::from_ascii("example.test.").unwrap();
        let soa_key = RrKey::new(LowerName::from(origin), RecordType::SOA);
        if let Some(soa_set) = records.get(&soa_key)
            && let Some(soa_record) = soa_set.records(false).next()
            && let RData::SOA(soa) = &soa_record.data
        {
            let expected = Name::from_ascii("admin.mynetwork.test.").unwrap();
            let rname_str = soa.rname.to_utf8();
            let expected_str = expected.to_utf8();
            assert_eq!(
                rname_str.to_lowercase(),
                expected_str.to_lowercase(),
                "SOA RNAME mismatch: got {rname_str}"
            );
            return;
        }
        panic!("SOA record not found or wrong type");
    }
}
