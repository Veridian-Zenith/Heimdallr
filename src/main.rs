use clap::Parser;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "heimdallr", about = "Heimdallr - DNS watcher (from-zero, OSL-3.0)")]
struct Args {
    /// Listen address for DNS (UDP/TCP)
    #[arg(long, default_value = "0.0.0.0:53")]
    listen: String,

    /// Web console / API listen (like Technitium :5380)
    #[arg(long, default_value = "0.0.0.0:5380")]
    api_listen: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    info!("heimdallr v{} starting", env!("CARGO_PKG_VERSION"));
    info!("DNS listen: {} | API: {}", args.listen, args.api_listen);
    info!("Rust + hickory-proto + quinn (no libmsquic) - OSL-3.0");

    // TODO: parity ladder - see ROADMAP.md
    // 1. UDP/TCP recursive resolver (hickory-resolver) + cache
    // 2. Authoritative zones, AXFR/IXFR
    // 3. DNSSEC validation/signing (ring)
    // 4. DoT/DoH/DoQ (quinn/rustls)
    println!("Heimdallr scaffold OK - implement ROADMAP.md phases");
    Ok(())
}
