//! The web service: sign-in, the API and the compiled interface, on loopback
//! behind nginx. It holds no administrative credential; maintenance requests
//! and every authorization go through the broker.

pub mod app;
pub mod attempts;
mod coding;
pub mod error;
pub mod models;
pub mod openapi;
pub mod queries;
pub mod routes;
pub mod security;
pub mod store;
pub mod switch;

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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

/// How often the sessions that have ended are looked for, and how long
/// after a round that could not end them all the next one waits, so that a
/// Stalwart that does not answer is not asked every second.
const ROUND: Duration = Duration::from_secs(1);
const AGAIN: Duration = Duration::from_secs(60);

/// End the sessions that have ended, with their tokens, within a second of
/// their end and for as long as the service runs; where Stalwart did not
/// answer, a minute later again.
pub async fn end_sessions_on_time(app: Arc<App>) {
    end_sessions_waiting(app, tokio::time::sleep).await;
}

/// [`end_sessions_on_time`], with `wait` for the pause before each round:
/// the service waits by tokio's clock, a test by one it moves itself.
pub async fn end_sessions_waiting<W, F>(app: Arc<App>, mut wait: W)
where
    W: FnMut(Duration) -> F,
    F: Future<Output = ()>,
{
    let mut pause = ROUND;
    loop {
        wait(pause).await;
        let round = Arc::clone(&app);
        let ended = tokio::task::spawn_blocking(move || round.end_ended_sessions()).await;
        pause = if matches!(ended, Ok(true)) {
            ROUND
        } else {
            AGAIN
        };
    }
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
        tokio::spawn(end_sessions_on_time(Arc::clone(&app)));
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
