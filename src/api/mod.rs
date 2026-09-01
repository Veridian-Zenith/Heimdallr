// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! HTTP API `:5380` parity `Technitium/DnsServer/APIDOCS.md` + `DnsServerCore/WebService*.cs`.
//! Axum router — `M2` zones+health+info, `M3` records+TLSA, `M4` TLS, `M6` logs+settings, `M7` auth RBAC+TOTP+OIDC.

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use hyper_util::rt::TokioIo;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::config::Config;
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

// ── Record handlers ──────────────────────────────────────────────────────────

async fn list_records(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(zone_name): axum::extract::Path<String>,
) -> Result<Json<RecordList>, (StatusCode, Json<Error>)> {
    let zone_cfg = find_zone(&state, &zone_name).await?;
    let zones_dir = &state.config.zones_dir;
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
    let zones_dir = &state.config.zones_dir;
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
    let zones_dir = &state.config.zones_dir;
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
    let zones_dir = &state.config.zones_dir;
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
    state
        .config
        .zones
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
            .route(
                "/api/zones/{name}/records",
                get(list_records).post(create_record),
            )
            .route("/api/zones/{name}/records/{rtype}", get(get_records))
            .route("/api/zones/{name}/records/{name}/{rtype}", get(get_records))
            .route("/api/zones/{name}/records/delete", post(delete_record))
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

            use tower::Service;

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
