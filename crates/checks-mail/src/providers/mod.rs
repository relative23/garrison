//! The checks of the mail flow and the antivirus scanner.

mod clamav;
pub mod directives;
mod flow;
mod history;
mod mailtest;
mod senders;

pub use clamav::Clamav;
pub use flow::Flow;
pub use mailtest::MailTest;
pub use senders::Senders;

#[cfg(test)]
mod listed_tests;
#[cfg(test)]
mod pipe_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod told_tests;
#[cfg(test)]
mod unreadable_tests;
