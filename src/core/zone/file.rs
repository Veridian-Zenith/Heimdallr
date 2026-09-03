// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Zone file loading via `hickory_server::store::file::FileAuthority`.
//!
//! Supports standard zone file format: `$ORIGIN`, `$TTL`, and all common record types
//! (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `SOA`, `NS`, `PTR`, `SRV`), as well as
//! `SVCB` (RFC 9460, type 64) and `HTTPS` (RFC 9460/9462, type 65) records
//! via the [`parse_svcb_data`] / [`parse_https_data`] helpers below.
//!
//! After loading, the SOA RNAME (admin email) is patched to match the configured
//! `hostadmin` setting, ensuring consistency across all zones.

use anyhow::{Result, bail};
use hickory_server::proto::rr::rdata::{HTTPS, SSHFP, SVCB};
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

// ── SVCB / HTTPS (RFC 9460, RFC 9462) ─────────────────────────────────────────
//
// Presentation format (RFC 9460 §2.1):
//
//     SvcPriority TargetName SvcParams
//
//     SvcParam       = SvcParamKey ["=" SvcParamValue]
//     SvcParamKey    = 1*63(alpha-lc / DIGIT / "-")
//     SvcParamValue  = char-string
//
// Known keys: `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`,
// `ipv6hint`, `ech`. Unknown / private keys (`keyNNNNN` where NNNNN ≥
// 0x8000) are accepted, not rejected — see RFC 9460 §2.1.
//
// `HTTPS` is SVCB in disguise (RFC 9462); we reuse the same parser and
// just wrap the result in `RData::HTTPS` instead of `RData::SVCB`.

/// Parse SVCB (RFC 9460) presentation-format rdata into a typed [`SVCB`].
///
/// `data` is everything after `IN SVCB` in the zone file, e.g.
/// `1 . alpn="h2,h3" ipv4hint=192.0.2.1`. Returns an [`anyhow::Error`] if
/// the rdata is not well-formed.
pub fn parse_svcb_data(data: &str) -> Result<SVCB> {
    let rdata = parse_svcb_rdata(RecordType::SVCB, data)?;
    match rdata {
        RData::SVCB(svcb) => Ok(svcb),
        // Defensive: RData::try_from_str(RecordType::SVCB, _) is guaranteed
        // to produce RData::SVCB per its match arm, but if a future
        // hickory release changes that we want a clean error rather than a
        // panic.
        other => bail!("expected RData::SVCB, got {other:?}"),
    }
}

/// Parse HTTPS (RFC 9460/9462) presentation-format rdata into a typed [`HTTPS`].
///
/// Same input grammar as [`parse_svcb_data`]; the HTTPS RR is an SVCB RR
/// with a different rdata tag.
pub fn parse_https_data(data: &str) -> Result<HTTPS> {
    let rdata = parse_svcb_rdata(RecordType::HTTPS, data)?;
    match rdata {
        RData::HTTPS(https) => Ok(https),
        other => bail!("expected RData::HTTPS, got {other:?}"),
    }
}

/// ANAME (apex CNAME flattening, draft-ietf-dnsop-aname) presentation-form.
/// Converts an ANAME keyword line to a synthetic CNAME rdata with a comment
/// marker for tracking. The actual A/AAAA synthesis happens at lookup time.
pub fn parse_aname_data(data: &str) -> Result<RData> {
    // ANAME keyword in zone file is converted to CNAME rdata with the
    // target name, plus a synthetic comment marker. The flattening logic
    // (synthesizing A/AAAA from the CNAME target) is handled by the resolver.
    let target = Name::from_ascii(data.trim())
        .map_err(|e| anyhow::anyhow!("invalid ANAME target '{data}': {e}"))?;
    Ok(RData::CNAME(hickory_server::proto::rr::rdata::CNAME(
        target,
    )))
}

/// Parse DNAME (RFC 6676) presentation-format rdata.
pub fn parse_dname_data(data: &str) -> Result<hickory_server::proto::rr::rdata::ANAME> {
    let rdata = RData::try_from_str(RecordType::ANAME, data)
        .map_err(|e| anyhow::anyhow!("invalid DNAME data '{data}': {e}"))?;
    match rdata {
        RData::ANAME(d) => Ok(d),
        other => bail!("expected RData::ANAME, got {other:?}"),
    }
}

/// Parse SSHFP (RFC 4255) presentation-format rdata into a typed [`SSHFP`].
///
/// `data` is everything after `IN SSHFP` in the zone file, e.g.
/// `2 1 123456789abcdef67890123456789abcdef67890` (algorithm fingerprint_type
/// hex_fingerprint). The fingerprint is hex-decoded; case-insensitive.
pub fn parse_sshfp_data(data: &str) -> Result<SSHFP> {
    let rdata = parse_svcb_rdata(RecordType::SSHFP, data)?;
    match rdata {
        RData::SSHFP(sshfp) => Ok(sshfp),
        // Defensive: RData::try_from_str(RecordType::SSHFP, _) is guaranteed
        // to produce RData::SSHFP per its match arm in hickory, but if a
        // future release changes that we want a clean error rather than a
        // panic.
        other => bail!("expected RData::SSHFP, got {other:?}"),
    }
}

/// Parse SVCB/HTTPS presentation-format rdata via hickory's public
/// `RData::try_from_str` (RFC 9460 lexer-aware parser).
///
/// Used by [`parse_svcb_data`] / [`parse_https_data`].
fn parse_svcb_rdata(rtype: RecordType, data: &str) -> Result<RData> {
    RData::try_from_str(rtype, data)
        .map_err(|e| anyhow::anyhow!("invalid {rtype} data '{data}': {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::rr::rdata::svcb::{Alpn, IpHint, SvcParamKey, SvcParamValue};

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

    // ── SVCB / HTTPS parser tests (M5.1) ──────────────────────────────────

    /// `example.com. 3600 IN HTTPS 1 . alpn="h2,h3"`
    #[test]
    fn parse_https_alpn_basic() {
        let https = parse_https_data("1 . alpn=\"h2,h3\"").expect("HTTPS parses");
        assert_eq!(https.0.svc_priority, 1);
        assert_eq!(https.0.target_name, Name::root());

        // Exactly one SvcParam: alpn=h2,h3
        assert_eq!(https.0.svc_params.len(), 1);
        let (key, value) = &https.0.svc_params[0];
        assert_eq!(*key, SvcParamKey::Alpn);
        match value {
            SvcParamValue::Alpn(Alpn(alpns)) => {
                assert_eq!(alpns, &vec!["h2".to_string(), "h3".to_string()]);
            }
            other => panic!("expected Alpn value, got {other:?}"),
        }
    }

    /// `example.com. 3600 IN SVCB 10 svc1.example.com. ipv4hint=192.0.2.1`
    #[test]
    fn parse_svcb_ipv4hint() {
        let svcb = parse_svcb_data("10 svc1.example.com. ipv4hint=192.0.2.1").expect("SVCB parses");
        assert_eq!(svcb.svc_priority, 10);
        assert_eq!(
            svcb.target_name,
            Name::from_ascii("svc1.example.com.").unwrap()
        );

        assert_eq!(svcb.svc_params.len(), 1);
        let (key, value) = &svcb.svc_params[0];
        assert_eq!(*key, SvcParamKey::Ipv4Hint);
        match value {
            SvcParamValue::Ipv4Hint(IpHint(hints)) => {
                assert_eq!(hints.len(), 1);
                assert_eq!(hints[0].0, std::net::Ipv4Addr::new(192, 0, 2, 1));
            }
            other => panic!("expected Ipv4Hint value, got {other:?}"),
        }
    }

    /// parse → Display → parse must yield equal rdata (round-trip).
    /// RFC 9460 §2.4.1: SvcParams in presentation format MAY appear in any
    /// order; hickory's Display emits them in a deterministic (numeric-key)
    /// order, so equality after re-parsing is the assertion we want.
    #[test]
    fn svcb_round_trip() {
        let original = "10 svc1.example.com. alpn=\"h2,h3\" ipv4hint=192.0.2.1 port=8443";
        let parsed1 = parse_svcb_data(original).expect("first parse");
        let rendered = parsed1.to_string();
        let parsed2 = parse_svcb_data(&rendered).expect("re-parse from Display");

        assert_eq!(
            parsed1, parsed2,
            "round-trip mismatch: original={rendered:?}"
        );

        // Same for HTTPS (RFC 9462): it's an SVCB in disguise.
        let original_https = "1 . alpn=\"h2\" ipv4hint=192.0.2.1";
        let parsed1h = parse_https_data(original_https).expect("first HTTPS parse");
        let rendered_h = parsed1h.to_string();
        let parsed2h = parse_https_data(&rendered_h).expect("re-parse HTTPS from Display");
        assert_eq!(parsed1h, parsed2h, "HTTPS round-trip mismatch");
    }

    /// AliasForm (SvcPriority = 0) MUST have a TargetName and no
    /// SvcParams (RFC 9460 §2.4.2 / §9). Verify the parser accepts it.
    #[test]
    fn parse_svcb_alias_form() {
        let svcb = parse_svcb_data("0 alias.example.com.").expect("alias form parses");
        assert_eq!(svcb.svc_priority, 0);
        assert_eq!(
            svcb.target_name,
            Name::from_ascii("alias.example.com.").unwrap()
        );
        assert!(
            svcb.svc_params.is_empty(),
            "AliasForm must have no SvcParams"
        );
    }

    /// Private-use SvcParamKeys (numeric `keyNNNNN` ≥ 0x8000) must be
    /// accepted, not rejected (RFC 9460 §2.1).
    #[test]
    fn parse_svcb_private_key() {
        let svcb = parse_svcb_data("1 . key65280=abcd").expect("private-use key parses");
        assert_eq!(svcb.svc_params.len(), 1);
        assert!(
            matches!(svcb.svc_params[0].0, SvcParamKey::Key(65280)),
            "expected Key(65280), got {:?}",
            svcb.svc_params[0].0
        );
    }

    // M5.2 — SSHFP (RFC 4255)

    /// RFC 4255 §3.1 wire format: `<algorithm> <fingerprint_type> <hex>`.
    /// Example from RFC 4255 §3.2: `host.example. SSHFP 2 1 123456789abcdef67890123456789abcdef67890`.
    #[test]
    fn parse_sshfp_rfc4255_example() {
        // The hex string is 40 chars = 20 bytes (SHA-1 length).
        let hex = "123456789abcdef67890123456789abcdef67890";
        let sshfp = parse_sshfp_data(&format!("2 1 {hex}")).expect("SSHFP parses");
        assert_eq!(u8::from(sshfp.algorithm), 2, "algorithm=2 is DSA");
        assert_eq!(
            u8::from(sshfp.fingerprint_type),
            1,
            "fingerprint_type=1 is SHA-1"
        );
        assert_eq!(sshfp.fingerprint.len(), 20, "SHA-1 fingerprint is 20 bytes");
        // Round-trip the hex ourselves to validate the parser output
        // against the same input.
        let expected = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(sshfp.fingerprint, expected);
    }

    /// Algorithm 4 (Ed25519) with SHA-256 fingerprint type (RFC 7479).
    /// 32-byte fingerprint.
    #[test]
    fn parse_sshfp_ed25519_sha256() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sshfp = parse_sshfp_data(&format!("4 2 {hex}")).expect("Ed25519+SHA256 parses");
        assert_eq!(u8::from(sshfp.algorithm), 4, "algorithm=4 is Ed25519");
        assert_eq!(
            u8::from(sshfp.fingerprint_type),
            2,
            "fingerprint_type=2 is SHA-256"
        );
        assert_eq!(sshfp.fingerprint.len(), 32);
    }

    /// Malformed input (non-numeric algorithm) must error, not panic.
    #[test]
    fn parse_sshfp_rejects_garbage() {
        let r = parse_sshfp_data("not-an-algorithm 1 aabb");
        assert!(r.is_err(), "expected error for malformed SSHFP, got {r:?}");
    }

    // M5.3 — DNAME (ANAME wire type in hickory 0.26.1)
    #[test]
    fn parse_dname_rfc6676_example() {
        let d = parse_dname_data("alias.example.com.").expect("DNAME parses");
        assert_eq!(d.0.to_utf8(), "alias.example.com.");
    }

    #[test]
    fn parse_aname_synthetic_cname() {
        let aname = parse_aname_data("target.example.com.").expect("ANAME parses");
        match aname {
            RData::CNAME(cname) => {
                assert_eq!(cname.0.to_utf8(), "target.example.com.");
            }
            other => panic!("expected synthetic CNAME for ANAME, got {other:?}"),
        }
    }
}
