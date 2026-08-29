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
    /// Config TOML path (default /etc/heimdallr/heimdallr.toml if exists, else built-in defaults)
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let cfg = load_config(&args)?;

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

    // Wire per docs/architecture.md — net ↔ core ↔ api (channels, not shared Mutex)
    let net = net::Net::new(cfg.clone());
    let core = core::Core::new(cfg.clone());
    let api = api::Api::new(cfg.api.listen.clone());
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
    } else if std::path::Path::new("/etc/heimdallr/heimdallr.toml").exists() {
        config::Config::from_file("/etc/heimdallr/heimdallr.toml")?
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
