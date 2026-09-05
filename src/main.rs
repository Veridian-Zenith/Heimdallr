// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

#![forbid(unsafe_code)]

mod api;
mod apps;
mod cluster;
mod config;
mod core;
mod dhcp;
mod net;

use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "heimdallr",
    about = "Heimdallr - DNS watcher (from-zero, OSL-3.0)"
)]
struct Args {
    /// Config TOML path (default /etc/heimdallr/config.toml if exists, else built-in defaults)
    #[arg(long)]
    config: Option<String>,

    /// Validate config and exit (like Technitium --check-config concept)
    #[arg(long, default_value_t = false)]
    check_config: bool,

    /// Listen address for DNS (UDP/TCP) — overrides config if set
    #[arg(long)]
    listen: Option<String>,

    /// Web console / API listen — overrides config if set
    #[arg(long)]
    api_listen: Option<String>,

    /// Log level override (trace|debug|info|warn|error) — overrides config
    #[arg(short, long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = load_config(&args)?;

    // Log level: --log-level flag > RUST_LOG env > config log.level > "info"
    let log_level = args.log_level.as_deref().unwrap_or(&cfg.log.level);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    let fmt = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true);

    // Format: "text" for human-readable, "json" for structured/journald
    match cfg.log.format.as_str() {
        "json" => fmt.json().init(),
        _ => fmt.init(),
    }

    if args.check_config {
        println!(
            "config OK: {} listen={:?}",
            args.config.as_deref().unwrap_or("<defaults>"),
            cfg.listen
        );
        return Ok(());
    }

    info!("heimdallr v{} starting", env!("CARGO_PKG_VERSION"));
    info!("config: {}", args.config.as_deref().unwrap_or("<defaults>"));
    let dnssec_provider = cfg.dnssec.provider.clone();
    let provider = core::dnssec::provider_for(&dnssec_provider);
    info!(
        "dnssec provider: {} (ring default, botan optional)",
        provider.name()
    );
    info!("net: listen={:?} api={}", cfg.listen, cfg.api.listen);

    // M6.4: Spawn the PostgreSQL-backed query log writer if configured.
    if cfg.log.query_log.is_some() {
        let query_cfg = crate::core::log::query_log::QueryLogConfig {
            postgres_url: cfg.log
                .query_log
                .as_ref()
                .map(|_| crate::core::log::query_log::QueryLogConfig::default_url())
                .unwrap_or_default()
                .into(),
            table: "dns_logs".into(),
            buffer_size: 64,
            flush_interval_ms: 100,
        };
        let _writer_ref = crate::core::log::query_log::QueryLogWriter::spawn(query_cfg);
    }

    // Wire per docs/architecture.md — net ↔ core ↔ api (channels, not shared Mutex)
    let net = net::Net::new(cfg.clone());
    let core = core::Core::new(cfg.clone());
    let api = api::Api::new(cfg.clone());
    let dhcp = dhcp::Dhcp::new(cfg.dhcp.enable);
    let cluster = cluster::Cluster::new(cfg.cluster.enable);

    // Spawn gates — M1+M4 tests require each listener independently testable
    tokio::try_join!(
        async { net.run().await },
        async { core.run().await },
        async { api.run().await },
        async { dhcp.run().await },
        async { cluster.run().await },
    )?;

    Ok(())
}

fn load_config(args: &Args) -> anyhow::Result<config::Config> {
    let mut cfg = if let Some(path) = &args.config {
        config::Config::from_file(path)?
    } else if std::path::Path::new("/etc/heimdallr/config.toml").exists() {
        config::Config::from_file("/etc/heimdallr/config.toml")?
    } else {
        config::Config::default()
    };

    if let Some(l) = &args.listen {
        cfg.listen = vec![l.clone()];
    }
    if let Some(a) = &args.api_listen {
        cfg.api.listen = a.clone();
    }
    cfg.validate()?;
    Ok(cfg)
}
