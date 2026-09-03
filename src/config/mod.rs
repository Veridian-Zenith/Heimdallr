// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server hostname (used for SOA NS, default NS records). Defaults to first zone's ns1.
    #[serde(default = "default_host")]
    pub host: String,
    /// Zone admin email (SOA RNAME). Default: hostadmin@<host>. Stored as `user@domain` —
    /// converted to DNS wire format (`user.domain`) automatically when writing SOA.
    #[serde(default)]
    pub hostadmin: Option<String>,
    pub listen: Vec<String>,
    #[serde(default)]
    pub listen_tls: Vec<String>,
    #[serde(default)]
    pub listen_quic: Vec<String>,
    #[serde(default)]
    pub listen_https: Vec<String>,
    /// TLS certificate config. If omitted, auto-detected from Let's Encrypt
    /// at `/etc/letsencrypt/live/<host>/` (fullchain.pem + privkey.pem).
    #[serde(default)]
    pub tls: TlsConfig,
    /// DNSSEC key management config.
    #[serde(default)]
    pub dnssec_keys: DnssecKeyConfig,
    #[serde(default)]
    pub resolver: ResolverConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub dnssec: DnssecConfig,
    #[serde(default)]
    pub filter: FilterConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub dhcp: DhcpConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub zones: Vec<ZoneConfig>,
    #[serde(default = "default_zones_dir")]
    pub zones_dir: String,
}

fn default_host() -> String {
    "localhost".into()
}

fn default_zones_dir() -> String {
    "/etc/heimdallr/zones".into()
}

// ── Resolver ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    #[serde(default = "default_forwarders")]
    pub forwarders: Vec<String>,
    #[serde(default = "default_forward_protocol")]
    pub forward_protocol: String,
    #[serde(default)]
    pub qname_minimization: ResolverQnameMinimization,
    #[serde(default)]
    pub qname_randomization: bool,
    #[serde(default)]
    pub ecs: bool,
    #[serde(default = "default_concurrency")]
    pub concurrency: u8,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// RFC 9156 — QNAME minimization configuration.
///
/// Minimization splits a recursive lookup into a series of queries with
/// progressively more labels (e.g. `com.` → `example.com.` → … → original
/// name) so the upstream server only learns the label it's authoritative
/// for. This reduces the privacy leakage inherent in sending the full
/// QNAME to every server in the chain.
///
/// `enable` is **opt-in** (defaults to `false`) to preserve existing
/// recursive behavior until the operator has validated the behavior in
/// their environment. Modes:
///
/// * [`QnameMinMode::Incremental`] — peel one label per step (most
///   compatible; used by BIND's `qname-minimization` `relaxed` mode).
/// * [`QnameMinMode::Aggressive`] — skip labels when the cached NS set
///   already covers a deeper cut (fewest queries; requires glue cache).
/// * [`QnameMinMode::Strict`] — RFC 9156 §3.3 algorithm (recommended
///   default if minimization is enabled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverQnameMinimization {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub mode: QnameMinMode,
    #[serde(default = "default_qmin_max_iterations")]
    pub max_iterations: u8,
}

/// QNAME minimization mode selector.
///
/// See [`ResolverQnameMinimization`] for semantics. Defaults to
/// [`QnameMinMode::Strict`].
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QnameMinMode {
    /// 1-label-per-step probe; most compatible.
    Incremental,
    /// Skip if NS set already known from cache.
    Aggressive,
    /// RFC 9156 §3.3 algorithm.
    #[default]
    Strict,
}

impl Default for ResolverQnameMinimization {
    fn default() -> Self {
        Self {
            enable: false,
            mode: QnameMinMode::Strict,
            max_iterations: default_qmin_max_iterations(),
        }
    }
}

fn default_qmin_max_iterations() -> u8 {
    // RFC 9156 §3.3 sets an upper bound on the number of minimization
    // steps equal to the number of labels in the QNAME + 1. We cap at 7
    // to bound work for pathological inputs.
    7
}

fn default_forwarders() -> Vec<String> {
    vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()]
}
fn default_forward_protocol() -> String {
    "udp".into()
}
fn default_true() -> bool {
    true
}
fn default_concurrency() -> u8 {
    2
}
fn default_timeout_ms() -> u64 {
    2000
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            forwarders: default_forwarders(),
            forward_protocol: default_forward_protocol(),
            // QNAME minimization is opt-in for M5.4 — defaults to off.
            // Operators enable explicitly via [resolver] config block.
            qname_minimization: ResolverQnameMinimization::default(),
            qname_randomization: false,
            ecs: false,
            concurrency: default_concurrency(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

// ── Cache ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_size")]
    pub size: usize,
    #[serde(default = "default_true")]
    pub serve_stale: bool,
    #[serde(default = "default_prefetch")]
    pub prefetch: u8,
    #[serde(default)]
    pub persistent: Option<String>,
}
fn default_cache_size() -> usize {
    50_000
}
fn default_prefetch() -> u8 {
    2
}
impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            size: default_cache_size(),
            serve_stale: true,
            prefetch: default_prefetch(),
            persistent: None,
        }
    }
}

// ── DNSSEC ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecConfig {
    #[serde(default = "default_true")]
    pub validation: bool,
    #[serde(default)]
    pub anchors: Option<String>,
    #[serde(default)]
    pub signing: bool,
    #[serde(default = "default_provider")]
    pub provider: String,
}
fn default_provider() -> String {
    "ring".into()
}
impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            validation: true,
            anchors: None,
            signing: false,
            provider: default_provider(),
        }
    }
}

// ── Filter ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    #[serde(default)]
    pub blocklists: Vec<String>,
    #[serde(default)]
    pub allowlists: Vec<String>,
    #[serde(default)]
    pub regex_blocklist: Vec<String>,
    #[serde(default)]
    pub per_client: std::collections::HashMap<String, PerClientFilter>,
    #[serde(default = "default_true")]
    pub cname_cloaking: bool,
    #[serde(default = "default_true")]
    pub rebinding: bool,
    #[serde(default = "default_cname_chain_limit")]
    pub cname_chain_limit: Option<u8>,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            blocklists: vec![],
            allowlists: vec![],
            regex_blocklist: vec![],
            per_client: std::collections::HashMap::new(),
            cname_cloaking: default_true(),
            rebinding: default_true(),
            cname_chain_limit: default_cname_chain_limit(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerClientFilter {
    #[serde(default)]
    pub block: bool,
}

// ── Proxy ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default = "default_proxy_proto")]
    pub protocol: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enable: false,
            allow: vec![],
            protocol: default_proxy_proto(),
        }
    }
}
fn default_cname_chain_limit() -> Option<u8> {
    Some(8)
}
fn default_proxy_proto() -> String {
    "v2".into()
}

// ── API ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    #[serde(default = "default_api_listen")]
    pub listen: String,
    #[serde(default)]
    pub tls_cert: Option<String>,
    #[serde(default)]
    pub tls_key: Option<String>,
}
fn default_api_listen() -> String {
    "127.0.0.1:5380".into()
}
impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen: default_api_listen(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub users: Vec<AuthUser>,
    #[serde(default)]
    pub tokens: Vec<AuthToken>,
    #[serde(default)]
    pub totp: bool,
    #[serde(default)]
    pub oidc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthUser {
    pub name: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthToken {
    pub name: String,
    pub value: String,
}

// ── Log ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub query_log: Option<String>,
    #[serde(default = "default_log_format")]
    pub format: String,
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "text".into()
}
impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            query_log: None,
            format: default_log_format(),
        }
    }
}

// ── DHCP ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhcpConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub ranges: Vec<DhcpRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhcpRange {
    pub subnet: String,
    pub start: String,
    pub end: String,
    pub router: String,
}

// ── Cluster ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub peers: Vec<String>,
}

// ── Zones ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZoneConfig {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub primaries: Vec<String>,
    /// DNSSEC signing for primary zones. If true, signs the zone with RRSIG/DNSKEY/NSEC.
    #[serde(default)]
    pub dnssec_signing: bool,
    /// DNSSEC signing algorithm: "ecdsa-p256" (default), "ecdsa-p384", "ed25519", "rsa-sha256".
    #[serde(default = "default_dnssec_algorithm")]
    pub dnssec_algorithm: String,
    /// Path to DNSSEC signing key (PEM/DER). If omitted, auto-generate and store in keys_dir.
    #[serde(default)]
    pub dnssec_key: Option<String>,
    /// NSEC/NSEC3 proof kind for DNSSEC signing. "nsec" (default) or "nsec3" with params.
    #[serde(default)]
    pub nx_proof: Option<NxProofConfig>,
}

/// NSEC3 configuration for DNSSEC non-existence proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NxProofConfig {
    /// Proof kind: "nsec" or "nsec3".
    #[serde(default = "default_nx_proof_kind")]
    pub kind: String,
    /// NSEC3 hash algorithm (default: SHA1).
    #[serde(default)]
    pub algorithm: Option<String>,
    /// NSEC3 salt (hex-encoded).
    #[serde(default)]
    pub salt: Option<String>,
    /// NSEC3 iterations (default: 0).
    #[serde(default)]
    pub iterations: Option<u16>,
    /// NSEC3 opt-out flag (default: false).
    #[serde(default)]
    pub opt_out: Option<bool>,
}

fn default_nx_proof_kind() -> String {
    "nsec".into()
}

impl ZoneConfig {
    /// Convert nx_proof config to hickory's NxProofKind.
    pub fn nx_proof_kind(&self) -> Option<hickory_server::dnssec::NxProofKind> {
        match self.nx_proof.as_ref().map(|c| c.kind.as_str()) {
            Some("nsec") | None => Some(hickory_server::dnssec::NxProofKind::Nsec),
            Some("nsec3") => {
                let cfg = self.nx_proof.as_ref().unwrap();
                // Nsec3HashAlgorithm currently only supports SHA1
                let algorithm = hickory_server::proto::dnssec::Nsec3HashAlgorithm::SHA1;
                let salt = cfg
                    .salt
                    .as_deref()
                    .and_then(|s| hex::decode(s).ok())
                    .map(|b| std::sync::Arc::from(b.as_slice()))
                    .unwrap_or_default();
                let iterations = cfg.iterations.unwrap_or(0);
                let opt_out = cfg.opt_out.unwrap_or(false);
                Some(hickory_server::dnssec::NxProofKind::Nsec3 {
                    algorithm,
                    salt,
                    iterations,
                    opt_out,
                })
            }
            Some(other) => {
                tracing::warn!("unknown nx_proof kind '{other}', defaulting to NSEC");
                Some(hickory_server::dnssec::NxProofKind::Nsec)
            }
        }
    }
}

fn default_dnssec_algorithm() -> String {
    "ecdsa-p256".into()
}

// ── DNSSEC Key Config ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecKeyConfig {
    /// Directory to store auto-generated signing keys.
    #[serde(default = "default_keys_dir")]
    pub keys_dir: String,
    /// Trust anchor file path. If omitted, uses built-in root anchors.
    #[serde(default)]
    pub trust_anchor: Option<String>,
}

fn default_keys_dir() -> String {
    "/var/lib/heimdallr/keys".into()
}

impl Default for DnssecKeyConfig {
    fn default() -> Self {
        Self {
            keys_dir: default_keys_dir(),
            trust_anchor: None,
        }
    }
}

// ── TLS ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default = "default_letsencrypt_dir")]
    pub letsencrypt_dir: String,
    /// Generate a self-signed cert if no real cert is found.
    /// Off by default — only for private/dev environments.
    #[serde(default)]
    pub self_signed: bool,
}

fn default_letsencrypt_dir() -> String {
    "/etc/letsencrypt/live".into()
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert: None,
            key: None,
            letsencrypt_dir: default_letsencrypt_dir(),
            self_signed: false,
        }
    }
}

impl TlsConfig {
    /// Resolve the TLS cert and key paths. Falls back to Let's Encrypt auto-detection.
    #[allow(dead_code)]
    pub fn resolve_paths(
        &self,
        host: &str,
    ) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
        let cert = if let Some(ref c) = self.cert {
            std::path::PathBuf::from(c)
        } else {
            let host = host.trim_end_matches('.');
            std::path::PathBuf::from(&self.letsencrypt_dir)
                .join(host)
                .join("fullchain.pem")
        };

        let key = if let Some(ref k) = self.key {
            std::path::PathBuf::from(k)
        } else {
            let host = host.trim_end_matches('.');
            std::path::PathBuf::from(&self.letsencrypt_dir)
                .join(host)
                .join("privkey.pem")
        };

        if cert.exists() && key.exists() {
            return Ok((cert, key));
        }

        anyhow::bail!("TLS cert not found: {}", cert.display());
    }

    /// Whether to generate a self-signed cert if no real cert is found.
    pub fn self_signed_enabled(&self) -> bool {
        self.self_signed
    }
}

// ── Config ────────────────────────────────────────────────────────────────────

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            hostadmin: None,
            listen: vec!["0.0.0.0:53".into(), "[::]:53".into()],
            listen_tls: vec![],
            listen_quic: vec![],
            listen_https: vec![],
            resolver: ResolverConfig::default(),
            cache: CacheConfig::default(),
            dnssec: DnssecConfig::default(),
            filter: FilterConfig::default(),
            proxy: ProxyConfig::default(),
            api: ApiConfig::default(),
            auth: AuthConfig::default(),
            log: LogConfig::default(),
            dhcp: DhcpConfig::default(),
            cluster: ClusterConfig::default(),
            zones: vec![],
            zones_dir: default_zones_dir(),
            tls: TlsConfig::default(),
            dnssec_keys: DnssecKeyConfig::default(),
        }
    }
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let s = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("read {}", path.as_ref().display()))?;
        let cfg: Self = toml::from_str(&s).context("parse toml")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolved admin email for SOA RNAME. Returns `hostadmin` if set, otherwise
    /// `hostadmin@<host>`. The `@` is replaced with `.` for DNS wire format.
    pub fn soa_rname(&self) -> String {
        let email = self.hostadmin.as_deref().unwrap_or("hostadmin");
        if email.contains('@') {
            email.replace('@', ".")
        } else {
            let host = self.host.trim_end_matches('.');
            format!("{email}.{host}")
        }
    }

    /// Resolved NS hostname for the zone (e.g. "ns1.example.test.").
    #[allow(dead_code)]
    pub fn ns_name(&self, zone_name: &str) -> String {
        format!("ns1.{}", zone_name.trim_end_matches('.'))
    }

    pub fn validate(&self) -> Result<()> {
        // DNSSEC provider
        if self.dnssec.provider != "ring" && self.dnssec.provider != "botan" {
            anyhow::bail!(
                "dnssec.provider must be ring|botan, got {}",
                self.dnssec.provider
            );
        }

        // Forward protocol
        match self.resolver.forward_protocol.as_str() {
            "udp" | "tcp" | "dot" | "doh" | "doq" => {}
            other => {
                anyhow::bail!("resolver.forward_protocol must be udp|tcp|dot|doh|doq, got {other}");
            }
        }

        // Concurrency range
        if self.resolver.concurrency == 0 {
            anyhow::bail!("resolver.concurrency must be >= 1");
        }

        // Timeout
        if self.resolver.timeout_ms == 0 {
            anyhow::bail!("resolver.timeout_ms must be > 0");
        }

        // Cache size
        if self.cache.size == 0 {
            anyhow::bail!("cache.size must be > 0");
        }

        // Validate listen addresses
        for addr in self
            .listen
            .iter()
            .chain(self.listen_tls.iter())
            .chain(self.listen_quic.iter())
            .chain(self.listen_https.iter())
        {
            addr.parse::<std::net::SocketAddr>()
                .with_context(|| format!("bad listen address '{addr}'"))?;
        }

        // API listen address
        self.api
            .listen
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("bad api.listen address '{}'", self.api.listen))?;

        // Proxy protocol
        match self.proxy.protocol.as_str() {
            "v1" | "v2" => {}
            other => {
                anyhow::bail!("proxy.protocol must be v1|v2, got {other}");
            }
        }

        // Log level
        match self.log.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            other => {
                anyhow::bail!("log.level must be trace|debug|info|warn|error, got {other}");
            }
        }

        // Log format
        match self.log.format.as_str() {
            "json" | "text" => {}
            other => {
                anyhow::bail!("log.format must be json|text, got {other}");
            }
        }

        // Zone kinds
        for zone in &self.zones {
            match zone.kind.as_str() {
                "primary" | "secondary" | "stub" | "conditional" | "forwarder" => {}
                other => {
                    anyhow::bail!(
                        "zone {}: kind must be primary|secondary|stub|conditional|forwarder, got {other}",
                        zone.name
                    );
                }
            }
            if zone.kind == "primary" && zone.file.is_none() {
                anyhow::bail!("zone {}: primary requires 'file'", zone.name);
            }
            if zone.kind == "secondary" && zone.primaries.is_empty() {
                anyhow::bail!("zone {}: secondary requires 'primaries'", zone.name);
            }
            if zone.dnssec_signing {
                match zone.dnssec_algorithm.as_str() {
                    "ecdsa-p256" | "ecdsa-p384" | "ed25519" | "rsa-sha256" => {}
                    other => {
                        anyhow::bail!(
                            "zone {}: dnssec_algorithm must be ecdsa-p256|ecdsa-p384|ed25519|rsa-sha256, got {other}",
                            zone.name
                        );
                    }
                }
            }
        }

        // Zones dir
        if !self.zones_dir.starts_with('/') {
            anyhow::bail!(
                "zones_dir must be an absolute path, got '{}'",
                self.zones_dir
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_parses() {
        let cfg = Config::default();
        cfg.validate().unwrap();
    }
    #[test]
    fn toml_roundtrip() {
        let s = toml::to_string(&Config::default()).unwrap();
        let _: Config = toml::from_str(&s).unwrap();
    }
    #[test]
    fn safe_defaults() {
        let cfg = Config::default();
        // API bound to localhost only
        assert_eq!(cfg.api.listen, "127.0.0.1:5380");
        // TOTP off by default (opt-in)
        assert!(!cfg.auth.totp);
        // TLS listeners empty by default (only when TLS configured)
        assert!(cfg.listen_tls.is_empty());
        // DNSSEC validation on by default
        assert!(cfg.dnssec.validation);
        // CNAME cloaking on by default
        assert!(cfg.filter.cname_cloaking);
        // Rebinding protection on by default
        assert!(cfg.filter.rebinding);
        // M5.4: QNAME minimization is opt-in — disabled by default.
        assert!(!cfg.resolver.qname_minimization.enable);
        // Default mode is Strict (RFC 9156 §3.3).
        assert_eq!(
            cfg.resolver.qname_minimization.mode,
            crate::config::QnameMinMode::Strict
        );
        assert!(cfg.resolver.qname_minimization.max_iterations > 0);
        // ECS off by default (privacy)
        assert!(!cfg.resolver.ecs);
        // Serve stale on by default
        assert!(cfg.cache.serve_stale);
    }
    #[test]
    fn validates_bad_listen_addr() {
        let cfg = Config {
            listen: vec!["not-an-addr".into()],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_bad_api_listen() {
        let mut cfg = Config::default();
        cfg.api.listen = "999.999.999.999:5380".into();
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_bad_forward_protocol() {
        let mut cfg = Config::default();
        cfg.resolver.forward_protocol = "invalid".into();
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_zero_concurrency() {
        let mut cfg = Config::default();
        cfg.resolver.concurrency = 0;
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_zero_timeout() {
        let mut cfg = Config::default();
        cfg.resolver.timeout_ms = 0;
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_zero_cache_size() {
        let mut cfg = Config::default();
        cfg.cache.size = 0;
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_relative_zones_dir() {
        let cfg = Config {
            zones_dir: "relative/path".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_zone_primary_requires_file() {
        let cfg = Config {
            zones: vec![ZoneConfig {
                name: "test.".into(),
                kind: "primary".into(),
                file: None,
                primaries: vec![],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_zone_secondary_requires_primaries() {
        let cfg = Config {
            zones: vec![ZoneConfig {
                name: "test.".into(),
                kind: "secondary".into(),
                file: None,
                primaries: vec![],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_bad_zone_kind() {
        let cfg = Config {
            zones: vec![ZoneConfig {
                name: "test.".into(),
                kind: "invalid".into(),
                file: None,
                primaries: vec![],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_bad_log_level() {
        let mut cfg = Config::default();
        cfg.log.level = "invalid".into();
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_bad_log_format() {
        let mut cfg = Config::default();
        cfg.log.format = "xml".into();
        assert!(cfg.validate().is_err());
    }
    #[test]
    fn validates_bad_proxy_protocol() {
        let mut cfg = Config::default();
        cfg.proxy.protocol = "v3".into();
        assert!(cfg.validate().is_err());
    }
}
