// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Catalog Zone Handler (`RFC 9432`) - Manages dynamic member zones.

use anyhow::Result;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::zone_handler::ZoneType;
use std::net::IpAddr;

/// `CatalogZoneHandler` tracks a catalog zone and manages member zone lifecycle.
pub struct CatalogZoneHandler {
    origin: Name,
    zone_type: ZoneType,
}

impl CatalogZoneHandler {
    pub fn new(origin: Name, zone_type: ZoneType) -> Self {
        Self { origin, zone_type }
    }

    /// Perform an AXFR transfer for the catalog zone itself and return the records.
    pub async fn sync_catalog(&self, primary_addr: &str) -> Result<Vec<Record>> {
        crate::core::zone::secondary::axfr_records_from_primary(
            &self.origin.to_string(),
            primary_addr,
        )
        .await
    }

    /// Helper to verify catalog version TXT record.
    /// RFC 9432 specifies that a catalog zone MUST have a version TXT record at `version.<catalog-zone>`.
    pub fn verify_version(&self, records: &[Record]) -> bool {
        let version_name = match Name::from_ascii(format!("version.{}", self.origin)) {
            Ok(name) => name,
            Err(_) => return false,
        };

        for record in records {
            if record.name == version_name
                && record.record_type() == RecordType::TXT
                && let RData::TXT(ref txt) = record.data
            {
                for txt_bytes in &txt.txt_data {
                    if txt_bytes.as_ref() == b"2" {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Parses PTR records to discover member zones in the catalog.
    /// RFC 9432: `<unique-id>.zones.<catalog-zone> PTR <member-zone-name>`
    pub fn parse_member_zones(&self, records: &[Record]) -> Vec<(String, Name)> {
        let mut member_zones = Vec::new();
        let suffix = format!("zones.{}", self.origin);

        for record in records {
            if record.record_type() == RecordType::PTR {
                let name_str = record.name.to_string();
                if let Some(prefix) = name_str.strip_suffix(&suffix) {
                    // Suffix match means we found <unique-id>.zones.<catalog-zone>
                    // Get the unique label (the first part of the record name)
                    let unique_id = prefix.trim_end_matches('.').to_string();
                    if let RData::PTR(ref ptr) = record.data {
                        // The PTR target is the member zone name
                        member_zones.push((unique_id, ptr.0.clone()));
                    }
                }
            }
        }
        member_zones
    }

    /// Extract primaries for a specific unique-id:
    /// `primaries.<unique-id>.zones.<catalog-zone>`
    pub fn parse_primaries(&self, records: &[Record], unique_id: &str) -> Vec<IpAddr> {
        let mut ips = Vec::new();

        let primaries_subdomain =
            match Name::from_ascii(format!("primaries.{unique_id}.zones.{}", self.origin)) {
                Ok(name) => name,
                Err(_) => return ips,
            };

        for record in records {
            if record.name == primaries_subdomain {
                match &record.data {
                    RData::A(ip) => {
                        ips.push(IpAddr::V4(ip.0));
                    }
                    RData::AAAA(ip) => {
                        ips.push(IpAddr::V6(ip.0));
                    }
                    _ => {}
                }
            }
        }
        ips
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, PTR, TXT};
    use std::net::Ipv4Addr;

    #[test]
    fn test_verify_catalog_version() {
        let origin = Name::from_ascii("catalog.example.test.").unwrap();
        let handler = CatalogZoneHandler::new(origin.clone(), ZoneType::Secondary);

        let version_name = Name::from_ascii("version.catalog.example.test.").unwrap();
        let record = Record::from_rdata(
            version_name,
            300,
            RData::TXT(TXT::new(vec!["2".to_string()])),
        );

        assert!(handler.verify_version(&[record]));
    }

    #[test]
    fn test_parse_member_zones_and_primaries() {
        let origin = Name::from_ascii("catalog.example.test.").unwrap();
        let handler = CatalogZoneHandler::new(origin.clone(), ZoneType::Secondary);

        let ptr_name = Name::from_ascii("member1.zones.catalog.example.test.").unwrap();
        let member_name = Name::from_ascii("example.com.").unwrap();
        let ptr_record = Record::from_rdata(ptr_name, 300, RData::PTR(PTR(member_name.clone())));

        let prim_name = Name::from_ascii("primaries.member1.zones.catalog.example.test.").unwrap();
        let a_record = Record::from_rdata(prim_name, 300, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))));

        let records = vec![ptr_record, a_record];
        let members = handler.parse_member_zones(&records);
        assert_eq!(members.len(), 1);
        let (ref uid, ref name) = members[0];
        assert_eq!(uid, "member1");
        assert_eq!(name, &member_name);

        let primaries = handler.parse_primaries(&records, uid);
        assert_eq!(primaries.len(), 1);
        assert_eq!(primaries[0], IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    }
}
