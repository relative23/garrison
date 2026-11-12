//! The collector: providers observe the host, Stalwart and its neighbours,
//! and one run stores a snapshot and metric samples in the status database.
//!
//! It runs with read access to configuration and status sources only; a
//! provider never changes what it observes.

pub mod backups;
pub mod command;
pub mod context;
pub mod dns;
pub mod fetch;
pub mod notify;
pub mod options;
pub mod providers;
pub mod run;
pub mod snapshot;
pub mod store;
mod values;
pub mod watch;

pub use command::{Runner, SystemRunner};
pub use context::{Context, Provider, Report};
pub use providers::build;
pub use run::{collect, collect_from};

#[cfg(test)]
mod testing;
