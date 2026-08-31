// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

pub mod catalog;
pub mod file;
pub mod notify;
pub mod secondary;

use std::sync::Arc;

use anyhow::{Context, Result};
use hickory_server::proto::rr::{LowerName, Name};
use hickory_server::zone_handler::{Catalog, ZoneHandler, ZoneType};
use tracing::{error, info};

use crate::config::{Config, ZoneConfig};
use crate::net::handler::SecondaryZoneInfo;

/// `ZoneManager` owns the hickory `Catalog` and manages zone lifecycle.
pub struct ZoneManager {
    catalog: Catalog,
    cfg: Config,
    secondaries: Vec<SecondaryZoneInfo>,
}

impl ZoneManager {
    pub fn new(cfg: Config) -> Self {
        Self {
            catalog: Catalog::default(),
            cfg,
            secondaries: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Load all zones from config, returning the populated Catalog and
    /// a list of secondary zones that need background AXFR sync.
    pub fn load_all(mut self) -> Result<(Catalog, Vec<SecondaryZoneInfo>)> {
        let zones_dir = self.cfg.zones_dir.clone();
        let zones: Vec<ZoneConfig> = self.cfg.zones.clone();

        for zone_cfg in &zones {
            match zone_cfg.kind.as_str() {
                "primary" => {
                    self.load_primary(zone_cfg, &zones_dir)?;
                }
                "secondary" => {
                    self.load_secondary(zone_cfg);
                }
                "catalog" => {
                    self.load_catalog_zone(zone_cfg);
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
        Ok((self.catalog, self.secondaries))
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

        self.catalog
            .upsert(origin, vec![Arc::new(authority) as Arc<dyn ZoneHandler>]);

        info!("zone {zone_name}: primary loaded from {file_path}");
        Ok(())
    }

    fn load_secondary(&mut self, zone_cfg: &ZoneConfig) {
        let zone_name = &zone_cfg.name;
        let primaries = &zone_cfg.primaries;

        // Register the secondary zone info for NOTIFY handling and background AXFR
        self.secondaries.push(SecondaryZoneInfo {
            name: zone_name.clone(),
            primaries: primaries.clone(),
        });

        // Spawn background AXFR sync
        let zone_name_owned = zone_name.clone();
        let primaries_owned = primaries.clone();
        tokio::spawn(async move {
            for primary in &primaries_owned {
                match crate::core::zone::secondary::axfr_from_primary(&zone_name_owned, primary)
                    .await
                {
                    Ok(_authority) => {
                        info!("zone {zone_name_owned}: synced from {primary}");
                        // The authority is ready but not yet registered in the catalog.
                        // This will be wired in M2.1 when we add dynamic catalog updates.
                        // For now, the zone is known but not served until the catalog
                        // is updated with the transferred records.
                        break;
                    }
                    Err(e) => {
                        error!("zone {zone_name_owned}: sync from {primary} failed: {e}");
                    }
                }
            }
        });

        info!("zone {zone_name}: secondary registered (primaries={primaries:?})");
    }

    fn load_catalog_zone(&mut self, zone_cfg: &ZoneConfig) {
        let zone_name = &zone_cfg.name;
        let primaries = &zone_cfg.primaries;
        info!("zone {zone_name}: catalog zone registered (primaries={primaries:?})");

        let zone_name_owned = zone_name.clone();
        let primaries_owned = primaries.clone();
        tokio::spawn(async move {
            let origin = match Name::from_ascii(&zone_name_owned) {
                Ok(o) => o,
                Err(e) => {
                    error!("catalog zone {zone_name_owned}: invalid name: {e}");
                    return;
                }
            };
            let catalog_handler = catalog::CatalogZoneHandler::new(origin, ZoneType::Secondary);

            for primary in primaries_owned {
                match catalog_handler.sync_catalog(&primary).await {
                    Ok(records) => {
                        info!(
                            "zone {zone_name_owned}: synced catalog from {primary} ({} records)",
                            records.len()
                        );
                        if catalog_handler.verify_version(&records) {
                            let members = catalog_handler.parse_member_zones(&records);
                            info!(
                                "catalog {zone_name_owned}: discovered {} member zones",
                                members.len()
                            );
                            for (uid, member_name) in members {
                                let member_primaries =
                                    catalog_handler.parse_primaries(&records, &uid);
                                info!(
                                    "catalog member: id={uid}, zone={member_name}, primaries={member_primaries:?}"
                                );
                            }
                        } else {
                            error!(
                                "catalog zone {zone_name_owned}: invalid or unsupported catalog version (expected version 2)"
                            );
                        }
                        break;
                    }
                    Err(e) => {
                        error!("catalog zone {zone_name_owned}: sync from {primary} failed: {e}");
                    }
                }
            }
        });
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
