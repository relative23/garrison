//! The web service: sign-in, the API and the compiled interface, on loopback
//! behind nginx. It holds no administrative credential; maintenance requests
//! and every authorization go through the broker.

pub mod app;
pub mod attempts;
mod coding;
pub mod error;
pub mod models;
pub mod openapi;
pub mod routes;
pub mod security;
pub mod store;
pub mod switch;

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use garrison_broker::client::BrokerClient;
use garrison_core::config::{Config, Database};
use garrison_stalwart::oidc::Provider;

pub use app::{App, INTERFACE, Identity, router};

use crate::security::Gate;
use crate::store::{StoreError, WebStore};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("web store: {0}")]
    Store(#[from] StoreError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// The production objects for `config`: the session store, the broker client
/// and the identity provider.
pub fn application(config: Config, static_directory: PathBuf) -> Result<Arc<App>, Error> {
    let store = Arc::new(WebStore::open(&config.database(Database::Web))?);
    let action_ids: BTreeSet<String> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.clone())
        .collect();
    let gate = Gate::new(
        Arc::clone(&store),
        Arc::new(BrokerClient::new(config.broker.socket.clone())),
        config.deployment.public_origin.clone(),
        action_ids,
        config.web.bind_client_ip,
    );
    let identity = Provider::new(&config.deployment.stalwart_url, &config.deployment.issuer);
    Ok(App::new(
        config,
        store,
        gate,
        Box::new(identity),
        static_directory,
    ))
}

/// Serve on 127.0.0.1 until SIGTERM or SIGINT.
pub fn run(config: Config, static_directory: PathBuf) -> Result<(), Error> {
    let port = config.web.port;
    let app = application(config, static_directory)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        log::info!("Web service listening on 127.0.0.1:{port}");
        garrison_core::systemd::ready();
        axum::serve(
            listener,
            router(app).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(garrison_ingest::stopped())
        .await?;
        Ok(())
    })
}
