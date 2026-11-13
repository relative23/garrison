//! Checks of Stalwart: its management API and mailboxes, its metrics exporter,
//! and the releases of Garrison and Stalwart.

pub mod providers;

// The base modules, under the names the checks were written against.
pub(crate) use garrison_checks::{context, fetch, options, values};

/// The checks' test helpers, with the workspace's test configuration.
#[cfg(test)]
mod testing {
    pub(crate) use garrison_checks::testing::*;
    use garrison_core::config::Config;

    pub(crate) fn config(directory: &std::path::Path) -> Config {
        garrison_testing::config(directory, "http://127.0.0.1:9")
    }
}
