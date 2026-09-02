// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Record management for primary zones — CRUD + zone file persistence.
//!
//! Supports all hickory record types including TLSA (DANE, RFC 6698).

use anyhow::{Context, Result, bail};
use hickory_server::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector, TLSA};
use hickory_server::proto::rr::{LowerName, Name, RData, Record, RecordType, RrKey};
use hickory_server::store::file::FileZoneHandler;
use hickory_server::zone_handler::ZoneType;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use tracing::info;

use crate::config::ZoneConfig;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecordSummary {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Deserialize)]
pub struct RecordCreate {
    pub name: String,
    pub record_type: String,
    pub ttl: Option<u32>,
    pub data: String,
}

#[derive(Deserialize)]
pub struct RecordDelete {
    pub name: String,
    pub record_type: String,
}

// ── Record listing ───────────────────────────────────────────────────────────

/// List all records in a zone.
pub async fn list_records(zone_cfg: &ZoneConfig, zones_dir: &str) -> Result<Vec<RecordSummary>> {
    let handler = load_handler(zone_cfg, zones_dir)?;
    let records = handler.records().await;

    let mut summaries = Vec::new();
    for set in records.values() {
        for record in set.records(false) {
            summaries.push(RecordSummary {
                name: record.name.to_utf8(),
                record_type: record.record_type().to_string(),
                ttl: record.ttl,
                data: record.data.to_string(),
            });
        }
    }
    Ok(summaries)
}

/// Get records of a specific type at a specific name.
pub async fn get_records(
    zone_cfg: &ZoneConfig,
    zones_dir: &str,
    name: &str,
    record_type: &str,
) -> Result<Vec<RecordSummary>> {
    let handler = load_handler(zone_cfg, zones_dir)?;
    let rtype = parse_record_type(record_type)?;
    let records = handler.records().await;

    let search_name = LowerName::from(
        Name::from_ascii(name).map_err(|e| anyhow::anyhow!("invalid name '{name}': {e}"))?,
    );

    let mut summaries = Vec::new();
    for (key, set) in records.iter() {
        if key.name == search_name && key.record_type == rtype {
            for record in set.records(false) {
                summaries.push(RecordSummary {
                    name: record.name.to_utf8(),
                    record_type: record.record_type().to_string(),
                    ttl: record.ttl,
                    data: record.data.to_string(),
                });
            }
        }
    }
    Ok(summaries)
}

// ── Record insertion ─────────────────────────────────────────────────────────

/// Insert a record into a zone (in-memory + persist to zone file).
pub async fn insert_record(
    zone_cfg: &ZoneConfig,
    zones_dir: &str,
    create: RecordCreate,
) -> Result<()> {
    let mut handler = load_handler(zone_cfg, zones_dir)?;
    let rtype = parse_record_type(&create.record_type)?;
    let origin = Name::from_ascii(&zone_cfg.name)
        .map_err(|e| anyhow::anyhow!("invalid zone name '{}': {}", zone_cfg.name, e))?;

    let name = if create.name == "@" || create.name == zone_cfg.name || create.name.is_empty() {
        origin.clone()
    } else {
        Name::from_ascii(&create.name)
            .map_err(|e| anyhow::anyhow!("invalid record name '{}': {}", create.name, e))?
    };

    let ttl = create.ttl.unwrap_or(3600);
    let rdata = parse_rdata(rtype, &create.data)?;

    let record = Record::from_rdata(name, ttl, rdata);
    handler.upsert_mut(record, 0);

    // Persist to zone file
    let zone_path = resolve_zone_path(zone_cfg.file.as_deref().unwrap_or(""), zones_dir);
    persist_zone(&handler, &zone_path, &origin).await?;

    info!(
        "zone {}: inserted {} {} (ttl={})",
        zone_cfg.name, create.record_type, create.name, ttl
    );
    Ok(())
}

/// Delete records by name and type.
pub async fn delete_records(
    zone_cfg: &ZoneConfig,
    zones_dir: &str,
    delete: RecordDelete,
) -> Result<usize> {
    let mut handler = load_handler(zone_cfg, zones_dir)?;
    let rtype = parse_record_type(&delete.record_type)?;
    let origin = Name::from_ascii(&zone_cfg.name)
        .map_err(|e| anyhow::anyhow!("invalid zone name '{}': {}", zone_cfg.name, e))?;

    let name = if delete.name == "@" || delete.name == zone_cfg.name {
        origin.clone()
    } else {
        Name::from_ascii(&delete.name)
            .map_err(|e| anyhow::anyhow!("invalid record name '{}': {}", delete.name, e))?
    };

    let key = RrKey::new(LowerName::from(name.clone()), rtype);
    let removed = handler
        .records_get_mut()
        .remove(&key)
        .map(|set| set.records_count())
        .unwrap_or(0);

    if removed > 0 {
        let zone_path = resolve_zone_path(zone_cfg.file.as_deref().unwrap_or(""), zones_dir);
        persist_zone(&handler, &zone_path, &origin).await?;

        info!(
            "zone {}: deleted {} {} ({} records)",
            zone_cfg.name, delete.record_type, delete.name, removed
        );
    }

    Ok(removed)
}

// ── TLSA-specific helpers ────────────────────────────────────────────────────

/// Parse TLSA data from presentation format: "usage selector matching hex_data"
pub fn parse_tlsa_data(data: &str) -> Result<TLSA> {
    let parts: Vec<&str> = data.split_whitespace().collect();
    if parts.len() != 4 {
        bail!("TLSA data must be '<usage> <selector> <matching> <hex_data>', got: {data}");
    }

    let usage: u8 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid TLSA cert_usage: {}", parts[0]))?;
    let selector: u8 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid TLSA selector: {}", parts[1]))?;
    let matching: u8 = parts[2]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid TLSA matching type: {}", parts[2]))?;
    let cert_data =
        hex::decode(parts[3].trim()).map_err(|e| anyhow::anyhow!("invalid TLSA hex data: {e}"))?;

    let cert_usage = CertUsage::from(usage);
    let sel = Selector::from(selector);
    let mat = Matching::from(matching);

    // Validate hash length
    match mat {
        Matching::Sha256 if cert_data.len() != 32 => {
            bail!(
                "TLSA SHA-256 hash must be 32 bytes, got {}",
                cert_data.len()
            );
        }
        Matching::Sha512 if cert_data.len() != 64 => {
            bail!(
                "TLSA SHA-512 hash must be 64 bytes, got {}",
                cert_data.len()
            );
        }
        _ => {}
    }

    Ok(TLSA::new(cert_usage, sel, mat, cert_data))
}

// ── Internal helpers ─────────────────────────────────────────────────────────

fn load_handler(zone_cfg: &ZoneConfig, zones_dir: &str) -> Result<FileZoneHandler> {
    let file_path = zone_cfg
        .file
        .as_deref()
        .with_context(|| format!("zone {}: no file configured", zone_cfg.name))?;

    let soa_rname = crate::config::Config::default().soa_rname();

    let nx_proof_kind = zone_cfg.nx_proof_kind();
    super::file::load_zone_file_with_proof(
        file_path,
        &zone_cfg.name,
        zones_dir,
        ZoneType::Primary,
        Some(&soa_rname),
        nx_proof_kind,
    )
}

fn parse_record_type(s: &str) -> Result<RecordType> {
    match s.to_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "CNAME" => Ok(RecordType::CNAME),
        "MX" => Ok(RecordType::MX),
        "NS" => Ok(RecordType::NS),
        "SOA" => Ok(RecordType::SOA),
        "TXT" => Ok(RecordType::TXT),
        "SRV" => Ok(RecordType::SRV),
        "PTR" => Ok(RecordType::PTR),
        "TLSA" => Ok(RecordType::TLSA),
        "HTTPS" => Ok(RecordType::HTTPS),
        "SVCB" => Ok(RecordType::SVCB),
        "CAA" => Ok(RecordType::CAA),
        "DNSKEY" => Ok(RecordType::DNSKEY),
        "DS" => Ok(RecordType::DS),
        "RRSIG" => Ok(RecordType::RRSIG),
        "NSEC" => Ok(RecordType::NSEC),
        "NSEC3" => Ok(RecordType::NSEC3),
        "NSEC3PARAM" => Ok(RecordType::NSEC3PARAM),
        "ANY" => Ok(RecordType::ANY),
        other => {
            if let Ok(num) = other.parse::<u16>() {
                Ok(RecordType::from(num))
            } else {
                bail!("unknown record type: {other}");
            }
        }
    }
}

fn parse_rdata(rtype: RecordType, data: &str) -> Result<RData> {
    match rtype {
        RecordType::A => {
            let ip: Ipv4Addr = data
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid A record data '{data}': {e}"))?;
            Ok(RData::A(hickory_server::proto::rr::rdata::A(ip)))
        }
        RecordType::AAAA => {
            let ip: Ipv6Addr = data
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid AAAA record data '{data}': {e}"))?;
            Ok(RData::AAAA(hickory_server::proto::rr::rdata::AAAA(ip)))
        }
        RecordType::CNAME => {
            let name = Name::from_ascii(data)
                .map_err(|e| anyhow::anyhow!("invalid CNAME '{data}': {e}"))?;
            Ok(RData::CNAME(hickory_server::proto::rr::rdata::CNAME(name)))
        }
        RecordType::NS => {
            let name =
                Name::from_ascii(data).map_err(|e| anyhow::anyhow!("invalid NS '{data}': {e}"))?;
            Ok(RData::NS(hickory_server::proto::rr::rdata::NS(name)))
        }
        RecordType::MX => {
            let parts: Vec<&str> = data.split_whitespace().collect();
            if parts.len() != 2 {
                bail!("MX data must be '<priority> <exchange>', got: {data}");
            }
            let preference: u16 = parts[0]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid MX priority: {e}"))?;
            let exchange = Name::from_ascii(parts[1])
                .map_err(|e| anyhow::anyhow!("invalid MX exchange '{}': {e}", parts[1]))?;
            Ok(RData::MX(hickory_server::proto::rr::rdata::MX::new(
                preference, exchange,
            )))
        }
        RecordType::TXT => {
            let txt = data.trim_matches('"').trim_matches('\'');
            Ok(RData::TXT(hickory_server::proto::rr::rdata::TXT::new(
                vec![txt.to_string()],
            )))
        }
        RecordType::SRV => {
            let parts: Vec<&str> = data.split_whitespace().collect();
            if parts.len() != 4 {
                bail!("SRV data must be '<priority> <weight> <port> <target>', got: {data}");
            }
            let priority: u16 = parts[0]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid SRV priority: {e}"))?;
            let weight: u16 = parts[1]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid SRV weight: {e}"))?;
            let port: u16 = parts[2]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid SRV port: {e}"))?;
            let target = Name::from_ascii(parts[3])
                .map_err(|e| anyhow::anyhow!("invalid SRV target '{}': {e}", parts[3]))?;
            Ok(RData::SRV(hickory_server::proto::rr::rdata::SRV::new(
                priority, weight, port, target,
            )))
        }
        RecordType::PTR => {
            let name =
                Name::from_ascii(data).map_err(|e| anyhow::anyhow!("invalid PTR '{data}': {e}"))?;
            Ok(RData::PTR(hickory_server::proto::rr::rdata::PTR(name)))
        }
        RecordType::TLSA => {
            let tlsa = parse_tlsa_data(data)?;
            Ok(RData::TLSA(tlsa))
        }
        RecordType::SVCB => {
            // M5.1: RFC 9460 SVCB presentation-format rdata
            // (e.g. "1 . alpn=\"h2,h3\" ipv4hint=192.0.2.1").
            let svcb = super::file::parse_svcb_data(data)?;
            Ok(RData::SVCB(svcb))
        }
        RecordType::HTTPS => {
            // M5.1: RFC 9460/9461 HTTPS — SVCB with the HTTPS rdata tag.
            let https = super::file::parse_https_data(data)?;
            Ok(RData::HTTPS(https))
        }
        RecordType::CAA => {
            bail!("CAA record insertion via API not yet supported (use zone file)");
        }
        RecordType::SOA => {
            let parts: Vec<&str> = data.split_whitespace().collect();
            if parts.len() != 7 {
                bail!(
                    "SOA data must be '<mname> <rname> <serial> <refresh> <retry> <expire> <minimum>', got: {data}"
                );
            }
            let mname = Name::from_ascii(parts[0])
                .map_err(|e| anyhow::anyhow!("invalid SOA MNAME '{}': {e}", parts[0]))?;
            let rname = Name::from_ascii(parts[1])
                .map_err(|e| anyhow::anyhow!("invalid SOA RNAME '{}': {e}", parts[1]))?;
            let serial: u32 = parts[2]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid SOA serial: {e}"))?;
            let refresh: i32 = parts[3]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid SOA refresh: {e}"))?;
            let retry: i32 = parts[4]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid SOA retry: {e}"))?;
            let expire: i32 = parts[5]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid SOA expire: {e}"))?;
            let minimum: u32 = parts[6]
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid SOA minimum: {e}"))?;
            Ok(RData::SOA(hickory_server::proto::rr::rdata::SOA::new(
                mname, rname, serial, refresh, retry, expire, minimum,
            )))
        }
        other => {
            bail!(
                "record type {other} insertion not yet supported via API (use zone file instead)"
            );
        }
    }
}

fn resolve_zone_path(file_path: &str, zones_dir: &str) -> PathBuf {
    let p = Path::new(file_path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        PathBuf::from(zones_dir).join(file_path)
    }
}

/// Persist a zone handler's records to a zone file.
async fn persist_zone(handler: &FileZoneHandler, zone_path: &Path, origin: &Name) -> Result<()> {
    let records = handler.records().await;

    let mut lines = Vec::new();
    lines.push(format!("$ORIGIN {}", origin.to_utf8()));
    lines.push("$TTL 3600".to_string());
    lines.push(String::new());

    for set in records.values() {
        for record in set.records(false) {
            // Skip NSEC/NSEC3/RRSIG/DNSKEY records (auto-generated by DNSSEC)
            match record.record_type() {
                RecordType::RRSIG
                | RecordType::NSEC
                | RecordType::NSEC3
                | RecordType::NSEC3PARAM
                | RecordType::DNSKEY => continue,
                _ => {}
            }

            let name = record.name.to_utf8();
            let rtype = record.record_type();
            let ttl = record.ttl;
            let rdata = &record.data;

            // Format: name TTL IN rtype rdata
            // Strip origin suffix from name for readability
            let base = origin.to_utf8();
            let short_name = if name == base {
                "@".to_string()
            } else if let Some(stripped) = name.strip_suffix(&format!(".{base}")) {
                stripped.to_string()
            } else {
                name.clone()
            };

            lines.push(format!("{short_name} {ttl} IN {rtype} {rdata}"));
        }
    }

    lines.push(String::new());
    let content = lines.join("\n");

    // Ensure parent directory exists
    if let Some(parent) = zone_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create zone dir {}", parent.display()))?;
    }

    std::fs::write(zone_path, &content)
        .with_context(|| format!("write zone file {}", zone_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tlsa_valid() {
        let tlsa = parse_tlsa_data(
            "3 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971",
        );
        assert!(tlsa.is_ok());
        let t = tlsa.unwrap();
        assert_eq!(t.cert_usage, CertUsage::DaneEe);
        assert_eq!(t.selector, Selector::Spki);
        assert_eq!(t.matching, Matching::Sha256);
    }

    #[test]
    fn parse_tlsa_bad_length() {
        let tlsa = parse_tlsa_data("3 1 1 aabb");
        assert!(tlsa.is_err());
    }

    #[test]
    fn parse_tlsa_bad_format() {
        let tlsa = parse_tlsa_data("3 1");
        assert!(tlsa.is_err());
    }

    #[test]
    fn parse_record_types() {
        assert_eq!(parse_record_type("A").unwrap(), RecordType::A);
        assert_eq!(parse_record_type("tlsa").unwrap(), RecordType::TLSA);
        assert_eq!(parse_record_type("AAAA").unwrap(), RecordType::AAAA);
        assert!(parse_record_type("INVALID").is_err());
    }

    // M5.1 — SVCB / HTTPS API insertion (presentation-format rdata)

    #[test]
    fn parse_rdata_svcb_basic() {
        // RFC 9460 §2.4.2: priority=10, target=svc1.example.com., ipv4hint=192.0.2.1
        let r = parse_rdata(RecordType::SVCB, "10 svc1.example.com. ipv4hint=192.0.2.1").unwrap();
        match r {
            RData::SVCB(svcb) => {
                assert_eq!(svcb.svc_priority, 10);
                assert_eq!(
                    svcb.target_name,
                    Name::from_ascii("svc1.example.com.").unwrap()
                );
                assert!(!svcb.svc_params.is_empty());
            }
            other => panic!("expected RData::SVCB, got {other:?}"),
        }
    }

    #[test]
    fn parse_rdata_https_alpn() {
        // RFC 9461 §3: HTTPS apex with alpn="h2,h3", target=.
        let r = parse_rdata(RecordType::HTTPS, "1 . alpn=\"h2,h3\"").unwrap();
        match r {
            RData::HTTPS(https) => {
                // HTTPS is a newtype around SVCB (hickory struct field, not method).
                let inner = &https.0;
                assert_eq!(inner.svc_priority, 1);
                assert_eq!(inner.target_name, Name::root());
                assert!(!inner.svc_params.is_empty());
            }
            other => panic!("expected RData::HTTPS, got {other:?}"),
        }
    }

    #[test]
    fn parse_rdata_svcb_rejects_garbage() {
        // hickory's lexer must reject malformed priority tokens.
        let r = parse_rdata(RecordType::SVCB, "not-a-priority .");
        assert!(r.is_err(), "expected error for malformed SVCB, got {r:?}");
    }
}
