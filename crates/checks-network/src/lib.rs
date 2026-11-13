//! Checks of the network: the DNS records of each domain, blocklists and
//! reverse names of the sending addresses, and TLS certificates.

pub mod providers;

// The base modules, under the names the checks were written against.
pub(crate) use garrison_checks::{context, dns, fetch, options};

/// The checks' test helpers, with the workspace's test configuration.
#[cfg(test)]
mod testing {
    pub(crate) use garrison_checks::testing::*;
    use garrison_core::config::Config;

    pub(crate) fn config(directory: &std::path::Path) -> Config {
        garrison_testing::config(directory, "http://127.0.0.1:9")
    }
}
