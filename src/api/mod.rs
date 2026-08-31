// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! HTTP API `:5380` parity `Technitium/DnsServer/APIDOCS.md` + `DnsServerCore/WebService*.cs`.
//! Axum router — `M2` zones+health+info, `M4` TLS, `M6` logs+settings, `M7` auth RBAC+TOTP+OIDC.

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::config::Config;

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

// ── Shared state ─────────────────────────────────────────────────────────────

pub struct ApiState {
    pub config: Config,
    pub zones: Arc<RwLock<Vec<ZoneSummary>>>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn server_info(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let zones = state.zones.read().await;
    Json(ServerInfo {
        version: env!("CARGO_PKG_VERSION"),
        hostname: state.config.host.clone(),
        dns_listen: state.config.listen.clone(),
        api_listen: state.config.api.listen.clone(),
        zones_loaded: zones.len(),
        dnssec_validation: state.config.dnssec.validation,
        cache_size: state.config.cache.size,
        log_level: state.config.log.level.clone(),
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

// ── API server ───────────────────────────────────────────────────────────────

pub struct Api {
    pub listen: String,
    #[allow(dead_code)]
    pub tls_cert: Option<String>,
    #[allow(dead_code)]
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

        let state = Arc::new(ApiState {
            config: config.clone(),
            zones: Arc::new(RwLock::new(zones)),
        });

        Self {
            listen: config.api.listen.clone(),
            tls_cert: config.api.tls_cert.clone(),
            tls_key: config.api.tls_key.clone(),
            state,
        }
    }

    pub async fn run(self) -> Result<()> {
        let app = Router::new()
            .route("/api/health", get(health))
            .route("/api/info", get(server_info))
            .route("/api/zones", get(list_zones))
            .route("/api/zones/{name}", get(zone_detail))
            .with_state(self.state);

        // TODO M4: TLS support via axum-server + rustls when cert+key are configured
        if self.tls_cert.is_some() || self.tls_key.is_some() {
            info!(
                "api: TLS cert/key configured but TLS listener not yet implemented (M4) — serving plain HTTP"
            );
        }

        let listener = tokio::net::TcpListener::bind(&self.listen).await?;
        info!("api: listening on {}", self.listen);
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(shutdown_signal())
            .await?;

        Ok(())
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("api: shutting down");
}
