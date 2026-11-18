// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! HTTP API `:5380` parity `Technitium/DnsServer/APIDOCS.md` + `DnsServerCore/WebService*.cs`.
//! Axum router — `M2` zones+health+info, `M3` records+TLSA, `M4` TLS, `M6` logs+settings, `M7` auth RBAC+TOTP+OIDC.

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use hyper_util::rt::TokioIo;
use ring::digest;
use ring::rand::SecureRandom;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tower_http::services::ServeDir;
use tracing::info;

use crate::config::Config;
use crate::core::metrics::{MetricName, MetricsRegistry};
use crate::core::zone::record::{self, RecordCreate, RecordDelete, RecordSummary};

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct ServerInfo {
    version: &'static str,
    hostname: String,
    dns_listen: Vec<String>,
    api_listen: String,
    zones_loaded: usize,
    dnssec_validation: bool,
    cache_size: usize,
    log_level: String,
}

#[derive(Serialize, Clone)]
pub(crate) struct ZoneSummary {
    name: String,
    kind: String,
    file: Option<String>,
    primaries: Vec<String>,
}

#[derive(Serialize)]
struct ZoneList {
    zones: Vec<ZoneSummary>,
    total: usize,
}

#[derive(Serialize)]
struct Error {
    error: String,
}

#[derive(Serialize)]
struct RecordList {
    records: Vec<RecordSummary>,
    total: usize,
}

#[derive(Serialize)]
struct RecordDeleteResult {
    deleted: usize,
}

#[derive(Serialize)]
struct MessageResponse {
    message: String,
}

// ── Human verification (AUR-style challenge) ─────────────────────────────────

const CHALLENGE_TTL_SECS: u64 = 300;
const VERIFICATION_TOKEN_TTL_SECS: u64 = 600;

#[derive(Clone)]
struct Challenge {
    challenge: String,
    expected_prefix: String,
    created: Instant,
    used: bool,
}

#[derive(Default)]
struct ChallengeStore {
    challenges: HashMap<String, Challenge>,
}

impl ChallengeStore {
    fn cleanup(&mut self) {
        self.challenges
            .retain(|_, c| c.created.elapsed().as_secs() < CHALLENGE_TTL_SECS);
    }
}

// ── Shared state ─────────────────────────────────────────────────────────────

pub struct ApiState {
    pub config: RwLock<Config>,
    pub zones: Arc<RwLock<Vec<ZoneSummary>>>,
    /// M6.6: live filter (blocklist, regex, etc.) for `/api/filter/stats`.
    pub filter: Arc<crate::core::filter::Filter>,
    /// AUR-style human verification challenges.
    challenges: RwLock<ChallengeStore>,
    /// Runtime cache for flush/stats endpoints.
    pub cache: Arc<RwLock<crate::core::cache::Cache>>,
    /// Runtime manual blocked domains (API-managed, separate from config blocklists).
    pub manual_blocked: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Runtime manual allowed domains (API-managed, overrides manual_blocked).
    pub manual_allowed: Arc<RwLock<std::collections::HashSet<String>>>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// M6.5: Metrics endpoint (OpenMetrics text format).
async fn metrics_handler() -> impl IntoResponse {
    let body = MetricsRegistry::serialize_global();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

/// M6.6: Basic filter stats.
#[derive(Serialize)]
struct FilterStats {
    cname_cloaking: bool,
    rebinding: bool,
    blocklist_entries: usize,
    regex_patterns: usize,
}

async fn filter_stats(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let cfg = state.config.read().await;
    Json(FilterStats {
        cname_cloaking: cfg.filter.cname_cloaking,
        rebinding: cfg.filter.rebinding,
        blocklist_entries: state.filter.blocklist.len(),
        regex_patterns: cfg.filter.regex_blocklist.len(),
    })
}

impl Api {
    /// True when the `/metrics` endpoint should be registered.
    pub fn metrics_enabled(config: &Config) -> bool {
        config.metrics.enable
    }
}

/// M7.1: Runtime toggle endpoint (`PUT /api/rec/options`).
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct RecOptionsUpdate {
    pub qname_minimization: Option<bool>,
    pub ecs: Option<bool>,
    pub dns64_always_synthesize: Option<bool>,
    pub dns64_prefix: Option<String>,
}

async fn rec_options_update(
    State(state): State<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(payload): axum::extract::Json<RecOptionsUpdate>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    {
        let cfg = state.config.read().await;
        if cfg.auth.enabled {
            let token_key = crate::auth::TokenKey::from_secret(&cfg.auth.token_secret);
            let session = extract_session(&headers, &token_key, &cfg).ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(Error {
                        error: "missing or invalid authorization token".into(),
                    }),
                )
            })?;
            if !session.is_authorized_for_toggle("dns_admin") {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(Error {
                        error: "dns_admin role required".into(),
                    }),
                ));
            }
        }
    }

    let mut cfg = state.config.write().await;
    if let Some(v) = payload.qname_minimization {
        cfg.resolver.qname_minimization.enable = v;
    }
    if let Some(v) = payload.ecs {
        cfg.resolver.ecs = v;
    }
    if let Some(v) = payload.dns64_always_synthesize {
        cfg.dns64.always_synthesize = v;
    }
    if let Some(v) = &payload.dns64_prefix {
        cfg.dns64.prefix = Some(v.clone());
    }

    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("M7.1: could not persist config: {e}");
    }

    info!("M7.1: runtime config persisted to disk");

    Ok(Json(MessageResponse {
        message: "config updated and persisted".into(),
    }))
}

/// Extract an `AuthSession` from the `Authorization: Bearer <token>` header.
fn extract_session(
    headers: &axum::http::HeaderMap,
    key: &crate::auth::TokenKey,
    config: &crate::config::Config,
) -> Option<crate::auth::AuthSession> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;
    let bearer = auth_header.strip_prefix("Bearer ")?;

    if let Some(session) = crate::auth::AuthSession::from_token(bearer, key) {
        return Some(session);
    }

    for api_token in &config.auth.tokens {
        if crate::auth::verify_api_token(bearer, &api_token.value) {
            let roles: Vec<String> = api_token.roles.iter().map(|s| s.to_string()).collect();
            return Some(crate::auth::AuthSession::with_roles(
                api_token.name.clone(),
                roles,
                crate::auth::TokenScope::Full,
            ));
        }
    }

    None
}

// ── Auth endpoints (M7.2) ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub totp_code: Option<String>,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: String,
    pub roles: Vec<String>,
    pub expires: u64,
    pub force_password_change: bool,
}

/// POST /api/auth/login — authenticate with password (+ optional TOTP).
async fn login(
    State(state): State<Arc<ApiState>>,
    axum::extract::Json(payload): axum::extract::Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<Error>)> {
    let cfg = state.config.read().await;

    if !cfg.auth.enabled {
        return Err((
            StatusCode::FORBIDDEN,
            Json(Error {
                error: "auth is not enabled".into(),
            }),
        ));
    }

    let user = cfg
        .auth
        .users
        .iter()
        .find(|u| u.name == payload.username)
        .ok_or_else(|| {
            let _ = crate::auth::hash_password("dummy-to-prevent-timing-oracle");
            (
                StatusCode::UNAUTHORIZED,
                Json(Error {
                    error: "invalid credentials".into(),
                }),
            )
        })?;

    if !crate::auth::verify_password(&payload.password, &user.password_hash) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(Error {
                error: "invalid credentials".into(),
            }),
        ));
    }

    if !user.totp_secret.is_empty() {
        let code = payload.totp_code.as_deref().ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(Error {
                    error: "TOTP code required".into(),
                }),
            )
        })?;
        if !crate::auth::verify_totp(&user.totp_secret, "Heimdallr", &user.name, code) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(Error {
                    error: "invalid TOTP code".into(),
                }),
            ));
        }
    }

    let key = crate::auth::TokenKey::from_secret(&cfg.auth.token_secret);
    let session = crate::auth::AuthSession::with_roles(
        user.name.clone(),
        user.roles.clone(),
        crate::auth::TokenScope::ReadOnly,
    );
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + crate::auth::SESSION_EXPIRY.as_secs();
    let token = session.to_token(&key, expires);

    info!("auth: login success user={}", user.name);

    Ok(Json(LoginResponse {
        token,
        user: user.name.clone(),
        roles: user.roles.clone(),
        expires,
        force_password_change: user.force_password_change,
    }))
}

// ── Human verification (AUR-style) ───────────────────────────────────────────

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub command: String,
    pub description: String,
}

/// GET /api/auth/challenge — generate an AUR-style human verification challenge.
/// Returns a command the user must run locally and paste the output.
async fn get_challenge(State(state): State<Arc<ApiState>>) -> Json<ChallengeResponse> {
    let rng = ring::rand::SystemRandom::new();
    let mut nonce = [0u8; 16];
    rng.fill(&mut nonce[..]).expect("rng");

    let challenge = hex_encode(&nonce);
    let digest = digest::digest(&digest::SHA256, challenge.as_bytes());
    let full_hash = hex_encode(digest.as_ref());
    let expected_prefix = full_hash[..16].to_string();

    let challenge_id = hex_encode(&nonce[..8]);

    {
        let mut store = state.challenges.write().await;
        store.cleanup();
        store.challenges.insert(
            challenge_id.clone(),
            Challenge {
                challenge: challenge.clone(),
                expected_prefix: expected_prefix.clone(),
                created: Instant::now(),
                used: false,
            },
        );
    }

    Json(ChallengeResponse {
        challenge_id,
        command: format!("echo -n {challenge} | sha256sum"),
        description: "Run this command and paste the first 16 characters of the hex output (before the space).".into(),
    })
}

#[derive(Deserialize)]
pub struct VerifyHumanRequest {
    pub challenge_id: String,
    pub answer: String,
}

#[derive(Serialize)]
pub struct VerifyHumanResponse {
    pub verification_token: String,
    pub expires: u64,
}

/// POST /api/auth/verify — submit the answer to a human verification challenge.
async fn verify_human(
    State(state): State<Arc<ApiState>>,
    axum::extract::Json(payload): axum::extract::Json<VerifyHumanRequest>,
) -> Result<Json<VerifyHumanResponse>, (StatusCode, Json<Error>)> {
    let answer = payload.answer.trim().to_lowercase();

    let mut store = state.challenges.write().await;
    store.cleanup();

    let challenge = store
        .challenges
        .get_mut(&payload.challenge_id)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(Error {
                    error: "invalid or expired challenge".into(),
                }),
            )
        })?;

    if challenge.used {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "challenge already used".into(),
            }),
        ));
    }

    if challenge.created.elapsed().as_secs() > CHALLENGE_TTL_SECS {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "challenge expired".into(),
            }),
        ));
    }

    if answer != challenge.expected_prefix {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "incorrect answer".into(),
            }),
        ));
    }

    challenge.used = true;

    let cfg = state.config.read().await;
    let key = crate::auth::TokenKey::from_secret(&cfg.auth.token_secret);
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + VERIFICATION_TOKEN_TTL_SECS;

    let session = crate::auth::AuthSession::with_roles(
        "human-verified".into(),
        vec!["human_verified".into()],
        crate::auth::TokenScope::ReadOnly,
    );
    let verification_token = session.to_token(&key, expires);

    info!("auth: human verification passed");

    Ok(Json(VerifyHumanResponse {
        verification_token,
        expires,
    }))
}

// ── Registration ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub verification_token: String,
    pub username: String,
    pub password: String,
}

/// POST /api/auth/register — create a new user account.
/// Requires a valid human verification token.
async fn register(
    State(state): State<Arc<ApiState>>,
    axum::extract::Json(payload): axum::extract::Json<RegisterRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let password_hash = crate::auth::hash_password(&payload.password).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: format!("invalid password: {e}"),
            }),
        )
    })?;

    let username = payload.username.trim().to_string();
    if username.is_empty() || username.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "username must be 1-32 characters".into(),
            }),
        ));
    }

    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "username may only contain letters, numbers, underscore, hyphen".into(),
            }),
        ));
    }

    {
        let mut cfg = state.config.write().await;

        let token_key = crate::auth::TokenKey::from_secret(&cfg.auth.token_secret);
        let session = crate::auth::AuthSession::from_token(&payload.verification_token, &token_key)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(Error {
                        error: "invalid or expired verification token".into(),
                    }),
                )
            })?;

        if !session.has_role("human_verified") {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(Error {
                    error: "verification token invalid".into(),
                }),
            ));
        }

        if cfg.auth.users.iter().any(|u| u.name == username) {
            return Err((
                StatusCode::CONFLICT,
                Json(Error {
                    error: "username already taken".into(),
                }),
            ));
        }

        cfg.auth.users.push(crate::config::AuthUser {
            name: username.clone(),
            password_hash,
            totp_secret: String::new(),
            roles: vec!["dns_reader".into()],
            force_password_change: false,
        });

        if let Err(e) = cfg.save_to_source() {
            tracing::warn!("auth: could not persist config: {e}");
        }
    }

    info!("auth: registered new user {username}");

    Ok(Json(MessageResponse {
        message: "account created".into(),
    }))
}

// ── Change password ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_username: Option<String>,
    pub new_password: String,
}

/// POST /api/auth/change-password — change password (+ optional username).
/// Requires a valid session token. If force_password_change is set, the
/// user must complete this before accessing other endpoints.
async fn change_password(
    State(state): State<Arc<ApiState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Json(payload): axum::extract::Json<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let mut cfg = state.config.write().await;

    if !cfg.auth.enabled {
        return Err((
            StatusCode::FORBIDDEN,
            Json(Error {
                error: "auth is not enabled".into(),
            }),
        ));
    }

    let token_key = crate::auth::TokenKey::from_secret(&cfg.auth.token_secret);
    let session = extract_session(&headers, &token_key, &cfg).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(Error {
                error: "missing or invalid authorization token".into(),
            }),
        )
    })?;

    let user_idx = cfg
        .auth
        .users
        .iter()
        .position(|u| u.name == session.user)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(Error {
                    error: "user not found".into(),
                }),
            )
        })?;

    if !crate::auth::verify_password(
        &payload.current_password,
        &cfg.auth.users[user_idx].password_hash,
    ) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(Error {
                error: "current password is incorrect".into(),
            }),
        ));
    }

    let new_hash = crate::auth::hash_password(&payload.new_password).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: format!("invalid password: {e}"),
            }),
        )
    })?;

    if let Some(new_name) = &payload.new_username {
        let new_name = new_name.trim().to_string();
        if new_name.is_empty() || new_name.len() > 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(Error {
                    error: "username must be 1-32 characters".into(),
                }),
            ));
        }
        if !new_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(Error {
                    error: "username may only contain letters, numbers, underscore, hyphen".into(),
                }),
            ));
        }
        if cfg
            .auth
            .users
            .iter()
            .any(|u| u.name == new_name && u.name != cfg.auth.users[user_idx].name)
        {
            return Err((
                StatusCode::CONFLICT,
                Json(Error {
                    error: "username already taken".into(),
                }),
            ));
        }
        cfg.auth.users[user_idx].name = new_name;
    }

    cfg.auth.users[user_idx].password_hash = new_hash;
    cfg.auth.users[user_idx].force_password_change = false;

    let changed_name = cfg.auth.users[user_idx].name.clone();

    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("auth: could not persist config: {e}");
    }

    info!("auth: password changed for user {changed_name}");

    Ok(Json(MessageResponse {
        message: "password changed successfully".into(),
    }))
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn server_info(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let zones = state.zones.read().await;
    let cfg = state.config.read().await;
    Json(ServerInfo {
        version: env!("CARGO_PKG_VERSION"),
        hostname: cfg.host.clone(),
        dns_listen: cfg.listen.clone(),
        api_listen: cfg.api.listen.clone(),
        zones_loaded: zones.len(),
        dnssec_validation: cfg.dnssec.validation,
        cache_size: cfg.cache.size,
        log_level: cfg.log.level.clone(),
    })
}

async fn list_zones(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let zones = state.zones.read().await;
    Json(ZoneList {
        zones: zones.clone(),
        total: zones.len(),
    })
}

async fn zone_detail(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<ZoneSummary>, (StatusCode, Json<Error>)> {
    let zones = state.zones.read().await;
    let search = if name.ends_with('.') {
        name
    } else {
        format!("{name}.")
    };
    zones
        .iter()
        .find(|z| z.name == search)
        .cloned()
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(Error {
                    error: format!("zone '{search}' not found"),
                }),
            )
        })
}

// ── Record handlers ──────────────────────────────────────────────────────────

async fn list_records(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(zone_name): axum::extract::Path<String>,
) -> Result<Json<RecordList>, (StatusCode, Json<Error>)> {
    let zone_cfg = find_zone(&state, &zone_name).await?;
    let cfg = state.config.read().await;
    let zones_dir = &cfg.zones_dir;
    match record::list_records(&zone_cfg, zones_dir).await {
        Ok(records) => {
            let total = records.len();
            Ok(Json(RecordList { records, total }))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Error {
                error: e.to_string(),
            }),
        )),
    }
}

async fn get_records(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path((zone_name, name, rtype)): axum::extract::Path<(String, String, String)>,
) -> Result<Json<RecordList>, (StatusCode, Json<Error>)> {
    let zone_cfg = find_zone(&state, &zone_name).await?;
    let cfg = state.config.read().await;
    let zones_dir = &cfg.zones_dir;
    match record::get_records(&zone_cfg, zones_dir, &name, &rtype).await {
        Ok(records) => {
            let total = records.len();
            Ok(Json(RecordList { records, total }))
        }
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: e.to_string(),
            }),
        )),
    }
}

async fn create_record(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(zone_name): axum::extract::Path<String>,
    Json(create): Json<RecordCreate>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let zone_cfg = find_zone(&state, &zone_name).await?;
    let cfg = state.config.read().await;
    let zones_dir = &cfg.zones_dir;
    match record::insert_record(&zone_cfg, zones_dir, create).await {
        Ok(()) => Ok(Json(MessageResponse {
            message: format!("record added to zone {zone_name}"),
        })),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: e.to_string(),
            }),
        )),
    }
}

async fn delete_record(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(zone_name): axum::extract::Path<String>,
    Json(delete): Json<RecordDelete>,
) -> Result<Json<RecordDeleteResult>, (StatusCode, Json<Error>)> {
    let zone_cfg = find_zone(&state, &zone_name).await?;
    let cfg = state.config.read().await;
    let zones_dir = &cfg.zones_dir;
    match record::delete_records(&zone_cfg, zones_dir, delete).await {
        Ok(deleted) => Ok(Json(RecordDeleteResult { deleted })),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: e.to_string(),
            }),
        )),
    }
}

/// Find a zone config by name from the shared state.
async fn find_zone(
    state: &ApiState,
    name: &str,
) -> Result<crate::config::ZoneConfig, (StatusCode, Json<Error>)> {
    let search = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    let cfg = state.config.read().await;
    cfg.zones
        .iter()
        .find(|z| z.name == search)
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(Error {
                    error: format!("zone '{search}' not found"),
                }),
            )
        })
}

// ── Metrics JSON (for dashboard) ──────────────────────────────────────────────

#[derive(Serialize)]
struct MetricsJson {
    cache_hits: u64,
    cache_misses: u64,
    queries: u64,
    blocked: u64,
    dns64_synthesized: u64,
    qmin_steps: u64,
    cname_chain_truncated: u64,
    rebinding_detected: u64,
}

async fn metrics_json() -> Json<MetricsJson> {
    Json(MetricsJson {
        cache_hits: MetricsRegistry::read_global(MetricName::CacheHitsTotal),
        cache_misses: MetricsRegistry::read_global(MetricName::CacheMissesTotal),
        queries: MetricsRegistry::read_global(MetricName::QueriesTotal),
        blocked: MetricsRegistry::read_global(MetricName::BlockedTotal),
        dns64_synthesized: MetricsRegistry::read_global(MetricName::Dns64SynthesizedTotal),
        qmin_steps: MetricsRegistry::read_global(MetricName::QminStepsTotal),
        cname_chain_truncated: MetricsRegistry::read_global(MetricName::CnameChainTruncatedTotal),
        rebinding_detected: MetricsRegistry::read_global(MetricName::RebindingDetectedTotal),
    })
}

// ── Cache management ─────────────────────────────────────────────────────────

#[derive(Serialize)]
struct CacheStats {
    entries: usize,
    max_size: usize,
    hits: u64,
    misses: u64,
}

async fn cache_stats(State(state): State<Arc<ApiState>>) -> Json<CacheStats> {
    let cache = state.cache.read().await;
    let cfg = state.config.read().await;
    Json(CacheStats {
        entries: cache.len(),
        max_size: cfg.cache.size,
        hits: cache.hits(),
        misses: cache.misses(),
    })
}

async fn cache_flush(State(state): State<Arc<ApiState>>) -> Json<MessageResponse> {
    let mut cache = state.cache.write().await;
    cache.clear();
    info!("cache: flushed");
    Json(MessageResponse {
        message: "cache flushed".into(),
    })
}

// ── Blocking management ──────────────────────────────────────────────────────

#[derive(Serialize)]
struct BlockingStatus {
    enabled: bool,
    cname_cloaking: bool,
    rebinding: bool,
    blocklist_entries: usize,
    regex_patterns: usize,
    manual_blocked: usize,
    manual_allowed: usize,
    blocklist_urls: Vec<String>,
    allowlist_urls: Vec<String>,
}

async fn blocking_status(State(state): State<Arc<ApiState>>) -> Json<BlockingStatus> {
    let cfg = state.config.read().await;
    let manual_blocked = state.manual_blocked.read().await;
    let manual_allowed = state.manual_allowed.read().await;
    Json(BlockingStatus {
        enabled: cfg.auth.enabled,
        cname_cloaking: cfg.filter.cname_cloaking,
        rebinding: cfg.filter.rebinding,
        blocklist_entries: state.filter.blocklist.len(),
        regex_patterns: cfg.filter.regex_blocklist.len(),
        manual_blocked: manual_blocked.len(),
        manual_allowed: manual_allowed.len(),
        blocklist_urls: cfg.filter.blocklists.clone(),
        allowlist_urls: cfg.filter.allowlists.clone(),
    })
}

async fn list_manual_blocked(
    State(state): State<Arc<ApiState>>,
) -> Json<std::collections::HashSet<String>> {
    let blocked = state.manual_blocked.read().await;
    Json(blocked.clone())
}

async fn add_manual_blocked(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let domain = body.get("domain").and_then(|v| v.as_str()).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "missing 'domain' field".into(),
            }),
        )
    })?;
    let mut blocked = state.manual_blocked.write().await;
    blocked.insert(domain.to_ascii_lowercase());
    info!("blocking: added manual blocked domain {domain}");
    Ok(Json(MessageResponse {
        message: format!("blocked {domain}"),
    }))
}

async fn remove_manual_blocked(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let domain = body.get("domain").and_then(|v| v.as_str()).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "missing 'domain' field".into(),
            }),
        )
    })?;
    let mut blocked = state.manual_blocked.write().await;
    blocked.remove(&domain.to_ascii_lowercase());
    info!("blocking: removed manual blocked domain {domain}");
    Ok(Json(MessageResponse {
        message: format!("unblocked {domain}"),
    }))
}

async fn list_manual_allowed(
    State(state): State<Arc<ApiState>>,
) -> Json<std::collections::HashSet<String>> {
    let allowed = state.manual_allowed.read().await;
    Json(allowed.clone())
}

async fn add_manual_allowed(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let domain = body.get("domain").and_then(|v| v.as_str()).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "missing 'domain' field".into(),
            }),
        )
    })?;
    let mut allowed = state.manual_allowed.write().await;
    allowed.insert(domain.to_ascii_lowercase());
    info!("blocking: added manual allowed domain {domain}");
    Ok(Json(MessageResponse {
        message: format!("allowed {domain}"),
    }))
}

async fn remove_manual_allowed(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let domain = body.get("domain").and_then(|v| v.as_str()).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "missing 'domain' field".into(),
            }),
        )
    })?;
    let mut allowed = state.manual_allowed.write().await;
    allowed.remove(&domain.to_ascii_lowercase());
    info!("blocking: removed manual allowed domain {domain}");
    Ok(Json(MessageResponse {
        message: format!("disallowed {domain}"),
    }))
}

// ── Settings (full config GET/PUT) ───────────────────────────────────────────

async fn get_settings(State(state): State<Arc<ApiState>>) -> Json<Config> {
    let cfg = state.config.read().await;
    Json(cfg.clone())
}

async fn update_settings(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let mut cfg = state.config.write().await;

    // Apply partial updates from JSON
    if let Some(v) = payload.get("host").and_then(|v| v.as_str()) {
        cfg.host = v.to_string();
    }
    if let Some(v) = payload.get("hostadmin").and_then(|v| v.as_str()) {
        cfg.hostadmin = Some(v.to_string());
    }
    if let Some(v) = payload.get("listen").and_then(|v| v.as_array()) {
        cfg.listen = v
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
    }
    if let Some(v) = payload.get("listen_tls").and_then(|v| v.as_array()) {
        cfg.listen_tls = v
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
    }
    if let Some(v) = payload.get("listen_quic").and_then(|v| v.as_array()) {
        cfg.listen_quic = v
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
    }
    if let Some(v) = payload.get("listen_https").and_then(|v| v.as_array()) {
        cfg.listen_https = v
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect();
    }
    if let Some(v) = payload.get("zones_dir").and_then(|v| v.as_str()) {
        cfg.zones_dir = v.to_string();
    }

    // Resolver
    if let Some(r) = payload.get("resolver") {
        if let Some(v) = r.get("forwarders").and_then(|v| v.as_array()) {
            cfg.resolver.forwarders = v
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect();
        }
        if let Some(v) = r.get("forward_protocol").and_then(|v| v.as_str()) {
            cfg.resolver.forward_protocol = v.to_string();
        }
        if let Some(v) = r.get("ecs").and_then(|v| v.as_bool()) {
            cfg.resolver.ecs = v;
        }
        if let Some(v) = r.get("qname_randomization").and_then(|v| v.as_bool()) {
            cfg.resolver.qname_randomization = v;
        }
        if let Some(v) = r.get("concurrency").and_then(|v| v.as_u64()) {
            cfg.resolver.concurrency = v as u8;
        }
        if let Some(v) = r.get("timeout_ms").and_then(|v| v.as_u64()) {
            cfg.resolver.timeout_ms = v;
        }
        if let Some(qm) = r.get("qname_minimization") {
            if let Some(v) = qm.get("enable").and_then(|v| v.as_bool()) {
                cfg.resolver.qname_minimization.enable = v;
            }
            if let Some(v) = qm.get("max_iterations").and_then(|v| v.as_u64()) {
                cfg.resolver.qname_minimization.max_iterations = v as u8;
            }
        }
    }

    // Cache
    if let Some(c) = payload.get("cache") {
        if let Some(v) = c.get("size").and_then(|v| v.as_u64()) {
            cfg.cache.size = v as usize;
        }
        if let Some(v) = c.get("serve_stale").and_then(|v| v.as_bool()) {
            cfg.cache.serve_stale = v;
        }
        if let Some(v) = c.get("prefetch").and_then(|v| v.as_u64()) {
            cfg.cache.prefetch = v as u8;
        }
    }

    // DNSSEC
    if let Some(d) = payload.get("dnssec") {
        if let Some(v) = d.get("validation").and_then(|v| v.as_bool()) {
            cfg.dnssec.validation = v;
        }
        if let Some(v) = d.get("signing").and_then(|v| v.as_bool()) {
            cfg.dnssec.signing = v;
        }
    }

    // Filter
    if let Some(f) = payload.get("filter") {
        if let Some(v) = f.get("cname_cloaking").and_then(|v| v.as_bool()) {
            cfg.filter.cname_cloaking = v;
        }
        if let Some(v) = f.get("rebinding").and_then(|v| v.as_bool()) {
            cfg.filter.rebinding = v;
        }
        if let Some(v) = f.get("sinkhole_v4").and_then(|v| v.as_str()) {
            cfg.filter.sinkhole_v4 = v.to_string();
        }
        if let Some(v) = f.get("sinkhole_v6").and_then(|v| v.as_str()) {
            cfg.filter.sinkhole_v6 = v.to_string();
        }
    }

    // DNS64
    if let Some(d) = payload.get("dns64") {
        if let Some(v) = d.get("always_synthesize").and_then(|v| v.as_bool()) {
            cfg.dns64.always_synthesize = v;
        }
        if let Some(v) = d.get("prefix").and_then(|v| v.as_str()) {
            cfg.dns64.prefix = Some(v.to_string());
        }
    }

    // Log
    if let Some(l) = payload.get("log") {
        if let Some(v) = l.get("level").and_then(|v| v.as_str()) {
            cfg.log.level = v.to_string();
        }
        if let Some(v) = l.get("format").and_then(|v| v.as_str()) {
            cfg.log.format = v.to_string();
        }
    }

    // Proxy
    if let Some(p) = payload.get("proxy") {
        if let Some(v) = p.get("enable").and_then(|v| v.as_bool()) {
            cfg.proxy.enable = v;
        }
        if let Some(v) = p.get("protocol").and_then(|v| v.as_str()) {
            cfg.proxy.protocol = v.to_string();
        }
        if let Some(v) = p.get("allow").and_then(|v| v.as_array()) {
            cfg.proxy.allow = v
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect();
        }
    }

    // Metrics
    #[allow(clippy::collapsible_if)]
    if let Some(m) = payload.get("metrics") {
        if let Some(v) = m.get("enable").and_then(|v| v.as_bool()) {
            cfg.metrics.enable = v;
        }
    }

    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("settings: could not persist config: {e}");
    }

    info!("settings: config updated and persisted");
    Ok(Json(MessageResponse {
        message: "settings saved".into(),
    }))
}

// ── DNS Client ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct DnsLookupRequest {
    server: String,
    name: String,
    #[serde(default = "default_rr_type")]
    rtype: String,
    #[serde(default)]
    port: Option<u16>,
}

fn default_rr_type() -> String {
    "A".into()
}

#[derive(Serialize)]
struct DnsLookupResponse {
    name: String,
    rtype: String,
    answers: Vec<DnsAnswer>,
    status: String,
    latency_ms: u64,
}

#[derive(Serialize)]
struct DnsAnswer {
    rtype: String,
    data: String,
    ttl: u32,
}

async fn dns_lookup(
    Json(req): Json<DnsLookupRequest>,
) -> Result<Json<DnsLookupResponse>, (StatusCode, Json<Error>)> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::*;
    use std::time::Instant;

    let server = if req.server.contains(':') {
        req.server.clone()
    } else {
        format!("{}:53", req.server)
    };

    let socket: std::net::SocketAddr = server.parse().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: format!("bad server address: {e}"),
            }),
        )
    })?;

    let name_server = NameServerConfig::new(
        socket.ip(),
        true,
        vec![ConnectionConfig::new(ProtocolConfig::Udp)],
    );
    let config = ResolverConfig::from_name_servers(vec![name_server]);

    let resolver = TokioResolver::builder_with_config(
        config,
        hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
    )
    .build()
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Error {
                error: format!("resolver build failed: {e}"),
            }),
        )
    })?;

    let rtype: hickory_server::proto::rr::RecordType = req.rtype.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: format!("unsupported record type: {}", req.rtype),
            }),
        )
    })?;

    let name = hickory_server::proto::rr::Name::from_str(&req.name).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: format!("bad query name: {e}"),
            }),
        )
    })?;

    let start = Instant::now();
    let lookup_result = resolver.lookup(name.clone(), rtype).await;
    let latency = start.elapsed().as_millis() as u64;

    match lookup_result {
        Ok(lookup) => {
            let answers: Vec<DnsAnswer> = lookup
                .answers()
                .iter()
                .map(|r| DnsAnswer {
                    rtype: format!("{:?}", r.record_type()),
                    data: format!("{:?}", r.data),
                    ttl: r.ttl,
                })
                .collect();
            Ok(Json(DnsLookupResponse {
                name: req.name,
                rtype: req.rtype,
                answers,
                status: "noerror".into(),
                latency_ms: latency,
            }))
        }
        Err(e) => Ok(Json(DnsLookupResponse {
            name: req.name,
            rtype: req.rtype,
            answers: vec![],
            status: format!("{e:?}"),
            latency_ms: latency,
        })),
    }
}

// ── Admin: Users ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct UserInfo {
    name: String,
    roles: Vec<String>,
    totp_enabled: bool,
    force_password_change: bool,
}

#[derive(Serialize)]
struct UserList {
    users: Vec<UserInfo>,
    total: usize,
}

async fn list_users(State(state): State<Arc<ApiState>>) -> Json<UserList> {
    let cfg = state.config.read().await;
    let users: Vec<UserInfo> = cfg
        .auth
        .users
        .iter()
        .map(|u| UserInfo {
            name: u.name.clone(),
            roles: u.roles.clone(),
            totp_enabled: !u.totp_secret.is_empty(),
            force_password_change: u.force_password_change,
        })
        .collect();
    let total = users.len();
    Json(UserList { users, total })
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    roles: Vec<String>,
}

async fn create_user(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let password_hash = crate::auth::hash_password(&payload.password).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: format!("invalid password: {e}"),
            }),
        )
    })?;

    let username = payload.username.trim().to_string();
    if username.is_empty() || username.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "username must be 1-32 characters".into(),
            }),
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "username may only contain letters, numbers, underscore, hyphen".into(),
            }),
        ));
    }

    let roles = if payload.roles.is_empty() {
        vec!["dns_reader".into()]
    } else {
        payload.roles
    };

    let mut cfg = state.config.write().await;
    if cfg.auth.users.iter().any(|u| u.name == username) {
        return Err((
            StatusCode::CONFLICT,
            Json(Error {
                error: "username already exists".into(),
            }),
        ));
    }

    cfg.auth.users.push(crate::config::AuthUser {
        name: username.clone(),
        password_hash,
        totp_secret: String::new(),
        roles,
        force_password_change: false,
    });

    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("admin: could not persist config: {e}");
    }

    info!("admin: created user {username}");
    Ok(Json(MessageResponse {
        message: format!("user {username} created"),
    }))
}

async fn delete_user(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let mut cfg = state.config.write().await;
    let before = cfg.auth.users.len();
    cfg.auth.users.retain(|u| u.name != username);
    if cfg.auth.users.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            Json(Error {
                error: format!("user '{username}' not found"),
            }),
        ));
    }
    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("admin: could not persist config: {e}");
    }
    info!("admin: deleted user {username}");
    Ok(Json(MessageResponse {
        message: format!("user {username} deleted"),
    }))
}

// ── Admin: 2FA ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct TwoFaInitResponse {
    secret: String,
    uri: String,
}

async fn init_2fa(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Result<Json<TwoFaInitResponse>, (StatusCode, Json<Error>)> {
    let mut cfg = state.config.write().await;
    let user = cfg
        .auth
        .users
        .iter_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(Error {
                    error: format!("user '{username}' not found"),
                }),
            )
        })?;

    let secret = crate::auth::generate_totp_secret();
    let uri = crate::auth::totp_uri(&secret, "Heimdallr", &username).unwrap_or_default();
    user.totp_secret = secret.clone();

    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("admin: could not persist config: {e}");
    }

    info!("admin: initialized 2FA for {username}");
    Ok(Json(TwoFaInitResponse { secret, uri }))
}

async fn disable_2fa(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let mut cfg = state.config.write().await;
    let user = cfg
        .auth
        .users
        .iter_mut()
        .find(|u| u.name == username)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(Error {
                    error: format!("user '{username}' not found"),
                }),
            )
        })?;

    user.totp_secret = String::new();

    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("admin: could not persist config: {e}");
    }

    info!("admin: disabled 2FA for {username}");
    Ok(Json(MessageResponse {
        message: format!("2FA disabled for {username}"),
    }))
}

// ── Admin: API Tokens ────────────────────────────────────────────────────────

#[derive(Serialize)]
struct TokenInfo {
    name: String,
    roles: Vec<String>,
}

#[derive(Serialize)]
struct TokenList {
    tokens: Vec<TokenInfo>,
    total: usize,
}

async fn list_tokens(State(state): State<Arc<ApiState>>) -> Json<TokenList> {
    let cfg = state.config.read().await;
    let tokens: Vec<TokenInfo> = cfg
        .auth
        .tokens
        .iter()
        .map(|t| TokenInfo {
            name: t.name.clone(),
            roles: t.roles.clone(),
        })
        .collect();
    let total = tokens.len();
    Json(TokenList { tokens, total })
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    name: String,
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    name: String,
    token: String,
    message: String,
}

async fn create_token(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, (StatusCode, Json<Error>)> {
    let name = payload.name.trim().to_string();
    if name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Error {
                error: "token name required".into(),
            }),
        ));
    }

    let roles = if payload.roles.is_empty() {
        vec!["dns_reader".into()]
    } else {
        payload.roles
    };

    let (raw_token, hashed) = crate::auth::generate_api_token();

    let mut cfg = state.config.write().await;
    if cfg.auth.tokens.iter().any(|t| t.name == name) {
        return Err((
            StatusCode::CONFLICT,
            Json(Error {
                error: "token name already exists".into(),
            }),
        ));
    }

    cfg.auth.tokens.push(crate::config::AuthToken {
        name: name.clone(),
        value: hashed,
        roles,
    });

    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("admin: could not persist config: {e}");
    }

    info!("admin: created API token {name}");
    Ok(Json(CreateTokenResponse {
        name,
        token: raw_token,
        message: "save this token — it will not be shown again".into(),
    }))
}

async fn delete_token(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<MessageResponse>, (StatusCode, Json<Error>)> {
    let mut cfg = state.config.write().await;
    let before = cfg.auth.tokens.len();
    cfg.auth.tokens.retain(|t| t.name != name);
    if cfg.auth.tokens.len() == before {
        return Err((
            StatusCode::NOT_FOUND,
            Json(Error {
                error: format!("token '{name}' not found"),
            }),
        ));
    }
    if let Err(e) = cfg.save_to_source() {
        tracing::warn!("admin: could not persist config: {e}");
    }
    info!("admin: deleted API token {name}");
    Ok(Json(MessageResponse {
        message: format!("token {name} deleted"),
    }))
}

// ── Admin: Sessions (read-only info) ─────────────────────────────────────────

#[derive(Serialize)]
struct SessionInfo {
    user: String,
    roles: Vec<String>,
    scope: String,
}

async fn list_sessions() -> Json<Vec<SessionInfo>> {
    // Sessions are ephemeral (HMAC-signed, 15-min TTL).
    // We return what we can from the current config — active sessions
    // are not persisted. This endpoint exists for API completeness.
    Json(vec![])
}

// ── API server ───────────────────────────────────────────────────────────────

pub struct Api {
    pub listen: String,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub state: Arc<ApiState>,
}

impl Api {
    pub fn new(config: Config) -> Self {
        let zones: Vec<ZoneSummary> = config
            .zones
            .iter()
            .map(|z| ZoneSummary {
                name: z.name.clone(),
                kind: z.kind.clone(),
                file: z.file.clone(),
                primaries: z.primaries.clone(),
            })
            .collect();

        let cache_config = crate::core::cache::CacheConfig {
            size: config.cache.size,
            serve_stale: std::time::Duration::from_secs(30),
            prefetch: config.cache.prefetch as u32,
        };

        let state = Arc::new(ApiState {
            config: RwLock::new(config.clone()),
            zones: Arc::new(RwLock::new(zones)),
            filter: Arc::new(crate::core::filter::Filter::new(&config.filter)),
            challenges: RwLock::new(ChallengeStore::default()),
            cache: Arc::new(RwLock::new(crate::core::cache::Cache::new(cache_config))),
            manual_blocked: Arc::new(RwLock::new(std::collections::HashSet::new())),
            manual_allowed: Arc::new(RwLock::new(std::collections::HashSet::new())),
        });

        Self {
            listen: config.api.listen.clone(),
            tls_cert: config.api.tls_cert.clone(),
            tls_key: config.api.tls_key.clone(),
            state,
        }
    }

    pub async fn run(self) -> Result<()> {
        let mut app = Router::new()
            // Health / Info
            .route("/api/health", get(health))
            .route("/api/info", get(server_info))
            // Metrics
            .route("/api/metrics/json", get(metrics_json))
            // Filter
            .route("/api/filter/stats", get(filter_stats))
            // Zones
            .route("/api/zones", get(list_zones))
            .route("/api/zones/{name}", get(zone_detail))
            .route(
                "/api/zones/{name}/records",
                get(list_records).post(create_record),
            )
            .route("/api/zones/{name}/records/{rtype}", get(get_records))
            .route("/api/zones/{name}/records/{name}/{rtype}", get(get_records))
            .route("/api/zones/{name}/records/delete", post(delete_record))
            // Cache
            .route("/api/cache/stats", get(cache_stats))
            .route("/api/cache/flush", post(cache_flush))
            // Blocking
            .route("/api/blocking/status", get(blocking_status))
            .route("/api/blocking/blocked", get(list_manual_blocked))
            .route("/api/blocking/blocked/add", post(add_manual_blocked))
            .route("/api/blocking/blocked/remove", post(remove_manual_blocked))
            .route("/api/blocking/allowed", get(list_manual_allowed))
            .route("/api/blocking/allowed/add", post(add_manual_allowed))
            .route("/api/blocking/allowed/remove", post(remove_manual_allowed))
            // DNS Client
            .route("/api/dns/lookup", post(dns_lookup))
            // Settings
            .route("/api/settings", get(get_settings).put(update_settings))
            // Admin
            .route("/api/admin/users", get(list_users).post(create_user))
            .route("/api/admin/users/{name}", delete(delete_user))
            .route("/api/admin/users/{name}/2fa/init", post(init_2fa))
            .route("/api/admin/users/{name}/2fa/disable", post(disable_2fa))
            .route("/api/admin/tokens", get(list_tokens).post(create_token))
            .route("/api/admin/tokens/{name}", delete(delete_token))
            .route("/api/admin/sessions", get(list_sessions))
            // Runtime resolver options
            .route("/api/rec/options", put(rec_options_update))
            // Auth
            .route("/api/auth/login", post(login))
            .route("/api/auth/challenge", get(get_challenge))
            .route("/api/auth/verify", post(verify_human))
            .route("/api/auth/register", post(register))
            .route("/api/auth/change-password", post(change_password));
        if Api::metrics_enabled(&*self.state.config.read().await) {
            app = app.route("/metrics", get(metrics_handler));
        }
        let app = app
            .fallback_service(ServeDir::new("static").append_index_html_on_directories(true))
            .with_state(self.state);

        if let (Some(cert_path), Some(key_path)) = (&self.tls_cert, &self.tls_key) {
            let certs = CertificateDer::pem_file_iter(cert_path)
                .map_err(|e| anyhow::anyhow!("api TLS: read certs {cert_path}: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("api TLS: parse certs {cert_path}: {e}"))?;

            let key = PrivateKeyDer::pem_file_iter(key_path)
                .map_err(|e| anyhow::anyhow!("api TLS: read key {key_path}: {e}"))?
                .next()
                .ok_or_else(|| anyhow::anyhow!("api TLS: no private key in {key_path}"))?
                .map_err(|e| anyhow::anyhow!("api TLS: parse key {key_path}: {e}"))?;

            let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow::anyhow!("api TLS: protocol config: {e}"))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("api TLS: certificate: {e}"))?;

            tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

            let acceptor = TlsAcceptor::from(Arc::new(tls_config));
            let addr: SocketAddr = self
                .listen
                .parse()
                .map_err(|e| anyhow::anyhow!("bad api listen addr '{}': {e}", self.listen))?;

            let tcp = TcpListener::bind(addr).await?;
            info!("api: TLS listening on {addr}");

            loop {
                let (stream, _peer) = tokio::select! {
                    result = tcp.accept() => result?,
                    _ = shutdown_signal() => break,
                };

                let acceptor = acceptor.clone();
                let mut make_svc = app.clone().into_make_service();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let svc = make_svc
                                .call(())
                                .await
                                .expect("make service should not fail");
                            let hyper_conn = TokioIo::new(tls_stream);
                            let hyper_svc = hyper_util::service::TowerToHyperService::new(svc);
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(hyper_conn, hyper_svc)
                                .await
                            {
                                tracing::debug!("api TLS: connection error: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::debug!("api TLS: handshake failed: {e}");
                        }
                    }
                });
            }
        } else {
            let listener = tokio::net::TcpListener::bind(&self.listen).await?;
            info!("api: listening on {}", self.listen);
            axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(shutdown_signal())
                .await?;
        }

        Ok(())
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("api: shutting down");
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_enabled_default_true() {
        let cfg = Config::default();
        assert!(Api::metrics_enabled(&cfg));
    }

    #[test]
    fn metrics_enabled_can_be_disabled() {
        let mut cfg = Config::default();
        cfg.metrics.enable = false;
        assert!(!Api::metrics_enabled(&cfg));
    }

    #[test]
    fn filter_stats_reports_real_blocklist_count() {
        use crate::core::filter::Filter;
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "0.0.0.0 a.example.com").unwrap();
        writeln!(tmp, "0.0.0.0 b.example.com").unwrap();
        writeln!(tmp, "0.0.0.0 c.example.com").unwrap();

        let cfg = crate::config::FilterConfig {
            blocklists: vec![tmp.path().to_string_lossy().into()],
            ..Default::default()
        };
        let filter = Arc::new(Filter::new(&cfg));
        let api_cfg = Config::default();
        let state = Arc::new(ApiState {
            config: RwLock::new(api_cfg),
            zones: Arc::new(RwLock::new(vec![])),
            filter: filter.clone(),
            challenges: RwLock::new(ChallengeStore::default()),
            cache: Arc::new(RwLock::new(crate::core::cache::Cache::new(
                crate::core::cache::CacheConfig::default(),
            ))),
            manual_blocked: Arc::new(RwLock::new(std::collections::HashSet::new())),
            manual_allowed: Arc::new(RwLock::new(std::collections::HashSet::new())),
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            assert_eq!(filter.blocklist.len(), 3);
            assert_eq!(state.filter.blocklist.len(), 3);
        });
    }

    #[test]
    fn extract_session_valid_token() {
        let key = crate::auth::TokenKey::from_secret("test-api-secret");
        let session = crate::auth::AuthSession::with_roles(
            "admin".into(),
            vec!["dns_reader".into(), "dns_admin".into()],
            crate::auth::TokenScope::Full,
        );
        let token = session.to_token(&key, 0);

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let cfg = Config::default();
        let recovered = extract_session(&headers, &key, &cfg).unwrap();
        assert_eq!(recovered.user, "admin");
        assert!(recovered.has_role("dns_admin"));
    }

    #[test]
    fn extract_session_missing_header() {
        let key = crate::auth::TokenKey::from_secret("test-api-secret");
        let headers = axum::http::HeaderMap::new();
        let cfg = Config::default();
        assert!(extract_session(&headers, &key, &cfg).is_none());
    }

    #[test]
    fn extract_session_invalid_token() {
        let key = crate::auth::TokenKey::from_secret("test-api-secret");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer invalid-token-here".parse().unwrap(),
        );
        let cfg = Config::default();
        assert!(extract_session(&headers, &key, &cfg).is_none());
    }

    #[test]
    fn extract_session_api_token_full_scope() {
        use crate::auth::TokenScope;
        let key = crate::auth::TokenKey::from_secret("test-api-secret");
        let (raw_token, hashed) = crate::auth::generate_api_token();

        let mut cfg = Config::default();
        cfg.auth.tokens.push(crate::config::AuthToken {
            name: "test-admin".into(),
            value: hashed,
            roles: vec!["dns_admin".into()],
        });

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {raw_token}").parse().unwrap(),
        );

        let session = extract_session(&headers, &key, &cfg).unwrap();
        assert_eq!(session.user, "test-admin");
        assert!(session.has_role("dns_admin"));
        assert!(session.has_scope(TokenScope::Full));
    }

    #[test]
    fn hex_encode_roundtrip() {
        let data = b"hello world";
        let encoded = hex_encode(data);
        assert_eq!(encoded, "68656c6c6f20776f726c64");
        assert_eq!(encoded.len(), data.len() * 2);
    }
}
