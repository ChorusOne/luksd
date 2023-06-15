use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

mod api;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Config {
    /// Path to final headers
    #[arg(short, long, default_value = "headers")]
    headers: PathBuf,
    /// Path to keys
    #[arg(short, long, default_value = "keys")]
    keys: PathBuf,
    /// Path to saved PCRs
    #[arg(short, long, default_value = "pcrs")]
    pcrs: PathBuf,
    /// Path to saved public keys
    #[arg(short = 'P', long, default_value = "pubkeys")]
    pubkeys: PathBuf,
    /// Path to saved event logs
    #[arg(short, long, default_value = "eventlogs")]
    eventlogs: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = Config::parse();
    let luksd = Arc::new(api::Luksd::new(config));

    let app = api::router(luksd);

    // run it with hyper on localhost:3000
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();

    Ok(())
}
