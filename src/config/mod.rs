use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen: Vec<String>,
    #[serde(default = "default_listen_tls")]
    pub listen_tls: Vec<String>,
    #[serde(default)]
    pub listen_quic: Vec<String>,
    #[serde(default)]
    pub listen_https: Vec<String>,
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
}

fn default_listen_tls() -> Vec<String> {
    vec!["0.0.0.0:853".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    #[serde(default = "default_forwarders")]
    pub forwarders: Vec<String>,
    #[serde(default = "default_forward_protocol")]
    pub forward_protocol: String,
    #[serde(default = "default_true")]
    pub qname_minimization: bool,
    #[serde(default)]
    pub qname_randomization: bool,
    #[serde(default)]
    pub ecs: bool,
    #[serde(default = "default_concurrency")]
    pub concurrency: u8,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
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
            qname_minimization: true,
            qname_randomization: false,
            ecs: false,
            concurrency: default_concurrency(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

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
    50000
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecConfig {
    #[serde(default = "default_true")]
    pub validation: bool,
    #[serde(default)]
    pub anchors: Option<String>,
    #[serde(default)]
    pub signing: bool,
    #[serde(default = "default_provider")]
    pub provider: String, // ring | botan
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerClientFilter {
    #[serde(default)]
    pub block: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default = "default_proxy_proto")]
    pub protocol: String,
}
fn default_proxy_proto() -> String {
    "v2".into()
}

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
    "0.0.0.0:5380".into()
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default)]
    pub users: Vec<AuthUser>,
    #[serde(default)]
    pub tokens: Vec<AuthToken>,
    #[serde(default = "default_true")]
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
    "json".into()
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub peers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZoneConfig {
    pub name: String,
    pub kind: String, // primary | secondary | stub | conditional | forwarder
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub primaries: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: vec!["0.0.0.0:53".into(), "[::]:53".into()],
            listen_tls: default_listen_tls(),
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

    pub fn validate(&self) -> Result<()> {
        if self.dnssec.provider != "ring" && self.dnssec.provider != "botan" {
            anyhow::bail!("dnssec.provider must be ring|botan, got {}", self.dnssec.provider);
        }
        #[cfg(not(feature = "botan-crypto"))]
        if self.dnssec.provider == "botan" {
            anyhow::bail!("botan provider requires --features botan-crypto");
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
}
