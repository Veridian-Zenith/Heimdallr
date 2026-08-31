// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! DNSSEC key generation and management.
//!
//! Generates and persists signing keys for zones with `dnssec_signing = true`.
//! Supports ECDSA P-256 (default), ECDSA P-384, Ed25519, and RSA-SHA256.

use anyhow::{Context, Result};
use hickory_server::proto::dnssec::rdata::DNSKEY;
use hickory_server::proto::dnssec::{Algorithm, DnssecSigner, SigningKey};
use hickory_server::proto::rr::Name;
use rustls_pki_types::PrivatePkcs8KeyDer;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, info};

/// Default signature validity: 30 days.
const DEFAULT_SIG_DURATION: Duration = Duration::from_secs(30 * 24 * 3600);

/// Resolve the algorithm string from config to an hickory `Algorithm`.
pub fn algorithm_from_str(s: &str) -> Result<Algorithm> {
    match s {
        "ecdsa-p256" => Ok(Algorithm::ECDSAP256SHA256),
        "ecdsa-p384" => Ok(Algorithm::ECDSAP384SHA384),
        "ed25519" => Ok(Algorithm::ED25519),
        "rsa-sha256" => Ok(Algorithm::RSASHA256),
        other => anyhow::bail!("unsupported DNSSEC algorithm: {other}"),
    }
}

/// Generate a new signing key for the given algorithm and persist it to `keys_dir`.
///
/// Returns the path to the generated key file.
pub fn generate_and_save_key(zone_name: &str, algorithm: &str, keys_dir: &str) -> Result<PathBuf> {
    let alg = algorithm_from_str(algorithm)?;
    let key_path = key_path_for_zone(zone_name, keys_dir, algorithm);

    if key_path.exists() {
        debug!(
            "dnssec: key already exists for {zone_name} at {}",
            key_path.display()
        );
        return Ok(key_path);
    }

    // Ensure keys directory exists
    std::fs::create_dir_all(keys_dir).with_context(|| format!("create keys dir {keys_dir}"))?;

    // Generate PKCS#8 key
    let pkcs8 = match alg {
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => {
            hickory_server::proto::dnssec::crypto::EcdsaSigningKey::generate_pkcs8(alg)
                .map_err(|e| anyhow::anyhow!("generate ECDSA key: {e}"))?
        }
        Algorithm::ED25519 => {
            hickory_server::proto::dnssec::crypto::Ed25519SigningKey::generate_pkcs8()
                .map_err(|e| anyhow::anyhow!("generate Ed25519 key: {e}"))?
        }
        Algorithm::RSASHA256 => {
            anyhow::bail!(
                "RSA key generation not supported by ring — import a PKCS#8 key via dnssec_key config"
            );
        }
        other => anyhow::bail!("unsupported algorithm for key generation: {other:?}"),
    };

    // Write PKCS#8 DER to file
    let der_bytes = pkcs8.secret_pkcs8_der();
    std::fs::write(&key_path, der_bytes)
        .with_context(|| format!("write key to {}", key_path.display()))?;

    info!(
        "dnssec: generated {algorithm} key for {zone_name} at {}",
        key_path.display()
    );
    Ok(key_path)
}

/// Load a signing key from a PKCS#8 file and create a `DnssecSigner`.
pub fn load_signer(key_path: &Path, zone_name: &str, algorithm: &str) -> Result<DnssecSigner> {
    let alg = algorithm_from_str(algorithm)?;
    let key_bytes =
        std::fs::read(key_path).with_context(|| format!("read key file {}", key_path.display()))?;

    let pkcs8 = PrivatePkcs8KeyDer::from(key_bytes);

    let signing_key: Box<dyn SigningKey> = match alg {
        Algorithm::ECDSAP256SHA256 | Algorithm::ECDSAP384SHA384 => Box::new(
            hickory_server::proto::dnssec::crypto::EcdsaSigningKey::from_pkcs8(&pkcs8, alg)
                .map_err(|e| anyhow::anyhow!("load ECDSA key: {e}"))?,
        ),
        Algorithm::ED25519 => Box::new(
            hickory_server::proto::dnssec::crypto::Ed25519SigningKey::from_pkcs8(&pkcs8)
                .map_err(|e| anyhow::anyhow!("load Ed25519 key: {e}"))?,
        ),
        Algorithm::RSASHA256 => Box::new(
            hickory_server::proto::dnssec::crypto::RsaSigningKey::from_pkcs8(&pkcs8, alg)
                .map_err(|e| anyhow::anyhow!("load RSA key: {e}"))?,
        ),
        other => anyhow::bail!("unsupported algorithm: {other:?}"),
    };

    // Build DNSKEY from the public key
    let public_key = signing_key
        .to_public_key()
        .map_err(|e| anyhow::anyhow!("extract public key: {e}"))?;
    let dnskey = DNSKEY::from_key(&public_key);

    let origin = Name::from_ascii(zone_name)
        .map_err(|e| anyhow::anyhow!("invalid zone name '{zone_name}': {e}"))?;

    Ok(DnssecSigner::new(
        dnskey,
        signing_key,
        origin,
        DEFAULT_SIG_DURATION,
    ))
}

/// Get the file path for a zone's signing key.
fn key_path_for_zone(zone_name: &str, keys_dir: &str, algorithm: &str) -> PathBuf {
    let safe_name = zone_name
        .replace('.', "_")
        .trim_end_matches('_')
        .to_string();
    PathBuf::from(keys_dir).join(format!("{safe_name}.{algorithm}.key"))
}

/// Resolve the key path for a zone — either explicit config or auto-generated.
pub fn resolve_key_path(
    zone_name: &str,
    explicit_key: Option<&str>,
    algorithm: &str,
    keys_dir: &str,
) -> Result<PathBuf> {
    if let Some(path) = explicit_key {
        let p = PathBuf::from(path);
        if !p.exists() {
            anyhow::bail!("dnssec_key not found: {}", p.display());
        }
        return Ok(p);
    }
    // Auto-generate if not found
    generate_and_save_key(zone_name, algorithm, keys_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_parse() {
        assert!(algorithm_from_str("ecdsa-p256").is_ok());
        assert!(algorithm_from_str("ecdsa-p384").is_ok());
        assert!(algorithm_from_str("ed25519").is_ok());
        assert!(algorithm_from_str("rsa-sha256").is_ok());
        assert!(algorithm_from_str("invalid").is_err());
    }

    #[test]
    fn key_path_deterministic() {
        let p1 = key_path_for_zone("example.test.", "/tmp/keys", "ecdsa-p256");
        let p2 = key_path_for_zone("example.test.", "/tmp/keys", "ecdsa-p256");
        assert_eq!(p1, p2);
        assert!(p1.to_string_lossy().contains("example_test"));
    }

    #[test]
    fn generate_and_load_ecdsa_p256() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().to_str().unwrap();

        let key_path = generate_and_save_key("test.example.", "ecdsa-p256", keys_dir).unwrap();
        assert!(key_path.exists());

        let signer = load_signer(&key_path, "test.example.", "ecdsa-p256").unwrap();
        assert!(signer.is_zone_signing_key());
    }

    #[test]
    fn generate_and_load_ed25519() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().to_str().unwrap();

        let key_path = generate_and_save_key("test2.example.", "ed25519", keys_dir).unwrap();
        assert!(key_path.exists());

        let signer = load_signer(&key_path, "test2.example.", "ed25519").unwrap();
        assert!(signer.is_zone_signing_key());
    }
}
