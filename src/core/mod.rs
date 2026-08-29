pub mod cache;
pub mod dnssec;
pub mod filter;
pub mod rec;
pub mod resolver;
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
