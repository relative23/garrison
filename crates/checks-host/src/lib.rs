//! Checks of the host itself: resources, host care, systemd units, installed
//! versions, receipts of jobs, local endpoints and backup repositories.

pub mod backups;
pub mod providers;

// The base modules, under the names the checks were written against.
pub(crate) use garrison_checks::{command, context, options, values};

/// The checks' test helpers, with the workspace's test configuration.
#[cfg(test)]
mod testing {
    pub(crate) use garrison_checks::testing::*;
    use garrison_core::config::Config;

    pub(crate) fn config(directory: &std::path::Path) -> Config {
        garrison_testing::config(directory, "http://127.0.0.1:9")
    }
}
