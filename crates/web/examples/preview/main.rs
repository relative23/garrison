//! A preview of the interface for browser tests and Lighthouse: the production
//! web service and the built interface, with the collector's golden
//! observations, a week of metric history and the ingest test batch. The
//! sign-in approves at once and the broker grants every module and action, so
//! nothing here needs Stalwart or touches a real host.
//!
//! ```sh
//! (cd frontend && npm run build)
//! cargo run -p garrison-web --example preview -- [port] [--busy]
//! ```
//!
//! `--busy` shows a mail server with a lot going on instead: thousands of
//! made-up sessions, deliveries and sign-in attacks and observations with
//! large numbers (`busy.rs`). The browser checks and measurements use the
//! preview without it.
//!
//! It serves `http://127.0.0.1:18091/` until Ctrl+C; its state lives in a
//! temporary directory that goes with it.

// A command-line tool reports on the terminal.
#![allow(clippy::print_stdout)]

mod busy;
mod data;
mod fakes;

use std::collections::BTreeSet;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use garrison_core::config::Database;
use garrison_core::time;
use garrison_web::security::Gate;
use garrison_web::store::WebStore;
use garrison_web::{App, router};

const PORT: u16 = 18091;

fn main() -> Result<(), Box<dyn Error>> {
    garrison_core::logging::init(false);
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    let busy = arguments.iter().any(|argument| argument == "--busy");
    arguments.retain(|argument| argument != "--busy");
    let port = match arguments.first() {
        Some(text) => text.parse()?,
        None => PORT,
    };
    let crate_directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    let static_directory = crate_directory.join("../../frontend/dist");
    if !static_directory.join("index.html").is_file() {
        return Err("build the interface first: (cd frontend && npm run build)".into());
    }
    let work = tempfile::tempdir()?;
    let config = data::config(work.path(), port, fakes::ISSUER_PATH)?;
    let mut live = data::Live::seed(&config, crate_directory, busy)?;
    // The collector runs once a minute and the receiver beats; so does the preview.
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(60));
            if let Err(error) = live.tick(time::now().as_second()) {
                println!("The preview data stopped: {error}");
                return;
            }
        }
    });
    let store = Arc::new(WebStore::open(&config.database(Database::Web))?);
    let actions: BTreeSet<String> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.clone())
        .collect();
    let gate = Gate::new(
        Arc::clone(&store),
        Arc::new(fakes::Broker::new(&config)),
        config.deployment.public_origin.clone(),
        actions,
        false,
    );
    let origin = config.deployment.public_origin.clone();
    let app = App::new(
        config,
        store,
        gate,
        Box::new(fakes::Identity),
        static_directory,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        println!("Preview on {origin}/ (Ctrl+C ends it)");
        let routes = router(app).merge(fakes::sign_in(&origin));
        axum::serve(
            listener,
            routes.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
        Ok(())
    })
}
