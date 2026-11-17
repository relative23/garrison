//! The checks of DNS, blocklists and TLS.

mod certificate;
mod dns;
mod domains;
mod reputation;
pub mod tls;

pub use dns::Dns;
pub use reputation::Reputation;
pub use tls::Tls;

#[cfg(test)]
mod resolver_tests;
