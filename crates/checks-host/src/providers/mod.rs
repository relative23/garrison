//! The checks of the host itself.

mod backupcheck;
mod host;
mod hostcare;
mod receipt;
mod systemd;
mod version;
mod web;

pub use backupcheck::BackupCheck;
pub use host::Host;
pub use hostcare::HostCare;
pub use receipt::Receipt;
pub use systemd::Systemd;
pub use version::VersionCommand;
pub use web::{Bulwark, Http};

#[cfg(test)]
mod systemd_tests;

#[cfg(test)]
mod tests;
