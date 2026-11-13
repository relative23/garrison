//! The checks of Stalwart and of the releases.

pub mod mailboxes;
pub mod prometheus;
mod releases;
pub mod signin;
pub mod stalwart;

pub use prometheus::Prometheus;
pub use releases::Releases;
pub use signin::SignIn;
pub use stalwart::Stalwart;

#[cfg(test)]
mod tests;
