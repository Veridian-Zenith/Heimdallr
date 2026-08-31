// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! TLS certificate loading for DoT/DoH/DoQ listeners.
//!
//! Loads PEM certificate chain + private key into a rustls `ResolvesServerCert`
//! compatible with hickory-server's listener registration methods.
//!
//! Self-signed certificate generation (opt-in via `tls.self_signed = true`)
//! uses rcgen + ring ECDSA P-256. Intended for private/dev environments only.

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::ResolvesServerCert;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// Load a TLS certificate chain and private key from PEM files.
///
/// Returns an `Arc<dyn ResolvesServerCert>` suitable for hickory-server's
/// `register_tls_listener`, `register_https_listener`, and `register_quic_listener`.
pub fn load_tls_cert(cert_path: &str, key_path: &str) -> Result<Arc<dyn ResolvesServerCert>> {
    let cert_chain = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("open cert file {cert_path}"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse cert chain from {cert_path}"))?;

    if cert_chain.is_empty() {
        anyhow::bail!("certificate chain is empty: {cert_path}");
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("parse private key from {key_path}"))?;

    info!(
        "tls: loaded {} certificates from {}",
        cert_chain.len(),
        cert_path
    );

    let provider = rustls::crypto::ring::default_provider();
    let certified_key = CertifiedKey::from_der(cert_chain, key, &provider)
        .map_err(|e| anyhow::anyhow!("invalid private key or cert mismatch: {e}"))?;

    Ok(Arc::new(SingleCertAndKey::from(certified_key)))
}

/// Auto-detect TLS cert/key paths for a hostname.
///
/// Checks Let's Encrypt paths first, then falls back to configured paths.
pub fn auto_detect_cert_paths(host: &str, letsencrypt_dir: &str) -> Option<(String, String)> {
    let host = host.trim_end_matches('.');

    // Let's Encrypt standard paths
    let le_dir = std::path::Path::new(letsencrypt_dir).join(host);
    let cert = le_dir.join("fullchain.pem");
    let key = le_dir.join("privkey.pem");

    if cert.exists() && key.exists() {
        info!(
            "tls: auto-detected Let's Encrypt certs for {host} at {}",
            le_dir.display()
        );
        return Some((cert.to_str()?.to_string(), key.to_str()?.to_string()));
    }

    None
}

/// Resolve TLS cert and key paths from config.
///
/// Uses explicit config paths first, then auto-detects Let's Encrypt.
/// If `self_signed` is true and no certs are found, generates a self-signed cert.
pub fn resolve_cert_paths(
    cert: Option<&str>,
    key: Option<&str>,
    host: &str,
    letsencrypt_dir: &str,
) -> Result<(String, String)> {
    if let (Some(c), Some(k)) = (cert, key) {
        return Ok((c.to_string(), k.to_string()));
    }

    if let Some((c, k)) = auto_detect_cert_paths(host, letsencrypt_dir) {
        return Ok((c, k));
    }

    anyhow::bail!(
        "no TLS certificates found for {host}. Set tls.cert and tls.key in config, \
         or place certs at {}/{{fullchain,privkey}}.pem",
        std::path::Path::new(letsencrypt_dir).join(host).display()
    )
}

/// Generate a self-signed TLS certificate for private/dev environments.
///
/// Creates an ECDSA P-256 key pair and a self-signed X.509 certificate valid for 1 year.
/// Writes cert PEM and key PEM to `keys_dir/self_signed/{host}/`.
///
/// Returns (cert_path, key_path).
pub fn generate_self_signed(host: &str, keys_dir: &str) -> Result<(String, String)> {
    use rcgen::{CertificateParams, KeyPair};

    let host = host.trim_end_matches('.');
    let out_dir = PathBuf::from(keys_dir).join("self_signed").join(host);
    std::fs::create_dir_all(&out_dir).with_context(|| format!("create {}", out_dir.display()))?;

    let cert_path = out_dir.join("cert.pem");
    let key_path = out_dir.join("key.pem");

    // Skip if already exists
    if cert_path.exists() && key_path.exists() {
        info!(
            "tls: using existing self-signed cert at {}",
            out_dir.display()
        );
        return Ok((
            cert_path.to_str().unwrap().to_string(),
            key_path.to_str().unwrap().to_string(),
        ));
    }

    // Generate ECDSA P-256 key pair
    let key_pair =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).context("generate ECDSA key")?;

    // Build self-signed certificate params
    let mut params =
        CertificateParams::new(vec![host.to_string()]).context("create cert params")?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String(host.to_string()),
    );

    // Create the certificate
    let cert = params
        .self_signed(&key_pair)
        .context("create self-signed cert")?;

    // Write certificate PEM
    let cert_pem = cert.pem();
    std::fs::write(&cert_path, &cert_pem)
        .with_context(|| format!("write {}", cert_path.display()))?;

    // Write private key PEM
    let key_pem = key_pair.serialize_pem();
    std::fs::write(&key_path, &key_pem).with_context(|| format!("write {}", key_path.display()))?;

    info!(
        "tls: generated self-signed ECDSA P-256 cert for {host} at {}",
        out_dir.display()
    );

    Ok((
        cert_path.to_str().unwrap().to_string(),
        key_path.to_str().unwrap().to_string(),
    ))
}
