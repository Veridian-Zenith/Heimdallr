pub mod file;
pub mod notify;
pub mod secondary;

use std::sync::Arc;

use anyhow::{Context, Result};
use hickory_server::authority::{AuthorityObject, Catalog, ZoneType};
use hickory_server::proto::rr::{LowerName, Name};
use tracing::{error, info};

use crate::config::{Config, ZoneConfig};

/// `ZoneManager` owns the hickory `Catalog` and manages zone lifecycle.
pub struct ZoneManager {
    catalog: Catalog,
    cfg: Config,
}

impl ZoneManager {
    pub fn new(cfg: Config) -> Self {
        Self {
            catalog: Catalog::default(),
            cfg,
        }
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn into_catalog(self) -> Catalog {
        self.catalog
    }

    /// Load all zones from config, returning the populated Catalog.
    pub fn load_all(mut self) -> Result<Catalog> {
        let zones_dir = self.cfg.zones_dir.clone();
        let zones: Vec<ZoneConfig> = self.cfg.zones.clone();

        for zone_cfg in &zones {
            match zone_cfg.kind.as_str() {
                "primary" => {
                    self.load_primary(zone_cfg, &zones_dir)?;
                }
                "secondary" => {
                    self.load_secondary_stub(zone_cfg);
                }
                "stub" | "conditional" | "forwarder" => {
                    info!(
                        "zone {}: {} (stub, M4+ forwarder chain)",
                        zone_cfg.name, zone_cfg.kind
                    );
                }
                other => {
                    error!("zone {}: unknown kind '{other}', skipping", zone_cfg.name);
                }
            }
        }

        info!("zones loaded: {} total", zones.len());
        Ok(self.catalog)
    }

    fn load_primary(&mut self, zone_cfg: &ZoneConfig, zones_dir: &str) -> Result<()> {
        let zone_name = zone_cfg.name.clone();
        let file_path = zone_cfg
            .file
            .as_deref()
            .with_context(|| format!("zone {zone_name}: primary requires 'file'"))?;

        let soa_rname = self.cfg.soa_rname();
        let authority = file::load_zone_file(
            file_path,
            &zone_name,
            zones_dir,
            ZoneType::Primary,
            Some(&soa_rname),
        )
        .with_context(|| format!("zone {zone_name}: load failed"))?;

        let origin = LowerName::from(Name::from_ascii(&zone_name).context("invalid zone name")?);

        self.catalog.upsert(
            origin,
            vec![Arc::new(authority) as Arc<dyn AuthorityObject>],
        );

        info!("zone {zone_name}: primary loaded from {file_path}");
        Ok(())
    }

    fn load_secondary_stub(&mut self, zone_cfg: &ZoneConfig) {
        let zone_name = &zone_cfg.name;
        let primaries = &zone_cfg.primaries;
        info!(
            "zone {zone_name}: secondary/stub registered (primaries={primaries:?}, AXFR will run at M2 connect)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_default_empty() {
        let cat = Catalog::default();
        let root = LowerName::from(Name::root());
        assert!(cat.find(&root).is_none());
    }
}
