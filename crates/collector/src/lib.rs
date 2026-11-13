//! The collector: one run asks every configured check and stores a snapshot
//! and metric samples in the status database; it tells the notification
//! channels what changed, and the watch tells them when runs stop.
//!
//! The checks themselves live in the `garrison-checks-*` crates, built from
//! `garrison-checks`; their modules stay reachable under the names here. It
//! runs with read access to configuration and status sources only; a check
//! never changes what it observes.

pub mod notify;
pub mod providers;
pub mod run;
pub mod snapshot;
pub mod store;
pub mod watch;

pub use garrison_checks::{command, context, dns, fetch, options};
pub use garrison_checks_host::backups;

pub use command::{Runner, SystemRunner};
pub use context::{Context, Provider, Report};
pub use providers::build;
pub use run::{collect, collect_from};

pub(crate) use garrison_checks::values;

/// The checks' test helpers, with the workspace's test configuration.
#[cfg(test)]
mod testing {
    pub(crate) use garrison_checks::testing::*;
    use garrison_core::config::Config;

    pub(crate) fn config(directory: &std::path::Path) -> Config {
        garrison_testing::config(directory, "http://127.0.0.1:9")
    }
}
