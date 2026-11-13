//! The checks of the mail flow and the antivirus scanner.

mod clamav;
pub mod directives;
mod flow;
mod mailtest;
mod senders;

pub use clamav::Clamav;
pub use flow::Flow;
pub use mailtest::MailTest;
pub use senders::Senders;

#[cfg(test)]
mod tests;
