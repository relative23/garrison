//! What every check is built from: the `Provider` contract and its context,
//! the options of a `[[providers]]` table, commands with a time limit, HTTPS
//! and DNS clients, and value helpers. The checks themselves live in the
//! `garrison-checks-*` crates, and `garrison-collector` runs them.
//!
//! A check runs with read access to configuration and status sources only; it
//! never changes what it observes.

pub mod command;
pub mod context;
pub mod dns;
pub mod fetch;
pub mod options;
pub mod values;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
