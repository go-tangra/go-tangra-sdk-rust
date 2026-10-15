//! A minimal module: `minimal <config.yaml>` serves `GET /api/<svc>/v1/ping`
//! over mTLS (HTTP) until SIGINT/SIGTERM, printing the bound addresses.
//!
//! `minimal dial <config.yaml> <host:port> <service>` performs one mTLS
//! handshake as this service to `<service>` and prints `HANDSHAKE_OK` or
//! `HANDSHAKE_REFUSED <reason>` (used to cross-check Go's tlsconf).

use std::sync::Arc;

use axum::routing::get;
use tangra_sdk::app::{App, PeerIdentity, Services};
use tangra_sdk::config::{Config, NoModule};
use tangra_sdk::identity::SpiffeId;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("dial") {
        let cfg = Config::<NoModule>::load(&args[2])?.framework;
        let p = tangra_sdk::identity::file::FileProvider::new(tangra_sdk::identity::file::FileConfig {
            cert: cfg.identity.file.cert.clone().into(),
            key: cfg.identity.file.key.clone().into(),
            bundle: cfg.identity.file.bundle.clone().into(),
            trust_domain: cfg.trust_domain.clone(),
            poll_interval: std::time::Duration::ZERO,
        })?;
        let expected = SpiffeId::new(&cfg.trust_domain, &args[4])?;
        let tls =
            tangra_sdk::tls::client_config(p, expected, tangra_sdk::tls::Options::new(cfg.trust_domain))?;
        let tcp = tokio::net::TcpStream::connect(&args[3]).await?;
        let name = rustls::pki_types::ServerName::try_from("localhost")?;
        match tokio_rustls::TlsConnector::from(Arc::clone(&tls))
            .connect(name, tcp)
            .await
        {
            Ok(_) => println!("HANDSHAKE_OK"),
            Err(e) => println!("HANDSHAKE_REFUSED {}", tangra_sdk::tls::classify(&e)),
        }
        return Ok(());
    }
    let cfg = Config::<NoModule>::load(args.get(1).ok_or("usage: minimal <config.yaml>")?)?;
    let logger = tangra_sdk::log::Logger::new(std::io::stderr(), tangra_sdk::log::Level::Info);
    let app = App::builder(cfg.framework).logger(logger).build().await?;
    let svc = app.config().service_name.clone();
    let router = axum::Router::new().route(
        &format!("/api/{svc}/v1/ping"),
        get(|peer: PeerIdentity| async move { format!("pong {}", peer.id) }),
    );
    if let Some(a) = app.http_local_addr() {
        println!("HTTP {a}");
    }
    if let Some(a) = app.grpc_local_addr() {
        println!("GRPC {a}");
    }
    println!("ADMIN {}", app.admin_url());
    app.run(Services::new().http(router)).await?;
    Ok(())
}
