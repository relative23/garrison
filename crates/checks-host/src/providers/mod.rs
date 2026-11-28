//! The checks of the host itself.

mod backupcheck;
mod hidden;
mod host;
mod hostcare;
mod http;
mod ran;
mod receipt;
mod systemd;
mod version;
mod web;

pub use backupcheck::BackupCheck;
pub use host::Host;
pub use hostcare::HostCare;
pub use http::Http;
pub use receipt::Receipt;
pub use systemd::Systemd;
pub use version::VersionCommand;
pub use web::Bulwark;

#[cfg(test)]
mod cuts_tests;

#[cfg(test)]
mod kinds_tests;

#[cfg(test)]
mod opens_tests;

#[cfg(test)]
mod options_tests;

#[cfg(test)]
mod systemd_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod told_tests;
