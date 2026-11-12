//! The ingest service: a loopback webhook receiver that keeps a bounded,
//! privacy-filtered history of Stalwart events.
//!
//! `policy` decides what is stored, `store` writes it, `queries`, `deliveries`
//! and `coverage` read it for the web service and return their `answers`, and
//! `app` receives signed batches.

pub mod answers;
pub mod app;
pub mod attacks;
pub mod coverage;
pub mod deliveries;
pub mod destinations;
pub mod event_type;
pub mod policy;
pub mod queries;
pub mod store;

use std::net::Ipv4Addr;
use std::sync::Arc;

use garrison_core::config::{Config, Database, IngestConfig};
use garrison_core::credentials::Credentials;
use garrison_core::files::ProtectedFileError;
use garrison_core::time;

use crate::store::{EventStore, Limits, SqliteError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("signature key: {0}")]
    Key(#[from] ProtectedFileError),
    #[error("event history: {0}")]
    Store(#[from] SqliteError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Open the history and serve on 127.0.0.1 until SIGTERM or SIGINT.
pub fn run(config: &Config, credentials: &Credentials) -> Result<(), Error> {
    let key = credentials.read_secret(&config.ingest.signature_key)?;
    let ingest = &config.ingest;
    let store = Arc::new(EventStore::open(
        &config.database(Database::Events),
        limits(ingest),
    )?);
    store.start(time::now().as_second())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(serve(store, key.as_bytes(), ingest.port))
}

/// The configured limits; the database budget is set in MiB.
fn limits(ingest: &IngestConfig) -> Limits {
    Limits::new(
        ingest.retention_days,
        ingest.max_events,
        i64::from(ingest.max_database_mib) * 1024 * 1024,
    )
}

async fn serve(store: Arc<EventStore>, key: &[u8], port: u16) -> Result<(), Error> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    log::info!("Event receiver listening on 127.0.0.1:{port}");
    garrison_core::systemd::ready();
    let maintenance = tokio::spawn(app::maintain(store.clone()));
    axum::serve(listener, app::router(store, key))
        .with_graceful_shutdown(stopped())
        .await?;
    maintenance.abort();
    Ok(())
}

/// Waits for the signal that stops a service: systemd sends SIGTERM, a
/// terminal SIGINT. The web service, the other one that serves HTTP, ends on
/// the same signal.
pub async fn stopped() {
    use tokio::signal::unix::{SignalKind, signal};
    match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(mut terminate), Ok(mut interrupt)) => {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        }
        _ => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_database_budget_is_configured_in_mebibytes() {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let ingest = IngestConfig {
            retention_days: 7,
            max_events: 5000,
            max_database_mib: 64,
            ..config.ingest
        };
        let limits = limits(&ingest);
        assert_eq!(
            (limits.retention_days, limits.max_events, limits.max_bytes),
            (7, 5000, 64 * 1024 * 1024)
        );
    }
}
