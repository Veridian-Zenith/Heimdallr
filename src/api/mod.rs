// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! HTTP API `:5380` parity `Technitium/DnsServer/APIDOCS.md` + `DnsServerCore/WebService*.cs`.
//! Axum router — `M6` logs+settings+zones, `M7` auth RBAC+TOTP+OIDC.

use anyhow::Result;
use axum::{Json, Router, routing::get};
use serde::Serialize;
use tracing::info;

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub struct Api {
    pub listen: String,
}

impl Api {
    pub fn new(listen: impl Into<String>) -> Self {
        Self {
            listen: listen.into(),
        }
    }

    pub async fn run(self) -> Result<()> {
        let app = Router::new().route("/api/health", get(health));
        let listener = tokio::net::TcpListener::bind(&self.listen).await?;
        info!("api: listening on {}", self.listen);
        axum::serve(listener, app).await?;
        Ok(())
    }
}
