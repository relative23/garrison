//! Checks of the mail flow: the recorded events in numbers, accounts that send
//! unusually much, test messages through the server and the antivirus scanner.

pub mod providers;

// The base modules, under the names the checks were written against.
pub(crate) use garrison_checks::{context, options};

/// The checks' test helpers, with the workspace's test configuration.
#[cfg(test)]
mod testing {
    pub(crate) use garrison_checks::testing::*;
    use garrison_core::config::Config;

    pub(crate) fn config(directory: &std::path::Path) -> Config {
        garrison_testing::config(directory, "http://127.0.0.1:9")
    }
}
