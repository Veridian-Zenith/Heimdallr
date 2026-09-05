// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

#[allow(dead_code)]
pub mod cache;
pub mod log;
pub mod dnssec;
pub mod filter;
#[allow(dead_code)]
pub mod metrics;
pub mod rec;
pub mod resolver;
#[allow(dead_code)]
pub mod zone;

use crate::config::Config;
use anyhow::Result;
use tracing::info;

/// `Core` — pure resolver/zone/cache/dnssec/filter (`docs/architecture.md`).
/// Same crate compiles for `cargo test` without `tokio` where possible.
pub struct Core {
    _cfg: Config,
}

impl Core {
    pub fn new(cfg: Config) -> Self {
        // Validate (e.g., botan feature gate) already in Config::validate
        Self { _cfg: cfg }
    }

    pub async fn run(self) -> Result<()> {
        info!("core: resolver/cache/zones ready (stub)");
        // TODO M1-M6: wire resolver + cache + zone lookup + filter + dnssec
        Ok(())
    }
}
