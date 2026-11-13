//! Helpers for the checks' tests, in this crate and, with the feature
//! `testing`, in the crates of the checks: a fixed clock, canned command
//! output and a memory that keeps what it is given.

// Helpers fail the test by panicking, like the test itself.
#![allow(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use std::io;

use garrison_core::config::{Config, Database};
use garrison_core::time::{self, Timestamp};

use crate::command::{Output, Runner};
use crate::context::{Context, Forgetful};

/// 2026-10-29T12:00:00Z, the collection time of the tests.
pub fn now() -> Timestamp {
    time::parse("2026-10-29T12:00:00Z").unwrap()
}

/// Answers every command with the same output and exit code 0.
#[derive(Debug)]
pub struct Canned(pub String);

impl Runner for Canned {
    fn run(&self, _: &[&str]) -> io::Result<Output> {
        Ok(Output {
            code: Some(0),
            stdout: self.0.clone(),
        })
    }
}

/// The workspace's test configuration, from garrison-testing, which is no
/// normal dependency: other crates' tests add it in their own `testing`.
#[cfg(test)]
pub fn config(directory: &std::path::Path) -> Config {
    garrison_testing::config(directory, "http://127.0.0.1:9")
}

pub fn context<'a>(config: &'a Config, runner: &'a dyn Runner) -> Context<'a> {
    Context {
        deployment: &config.deployment,
        now: now(),
        native_key: None,
        metrics_credential: None,
        events_database: config.database(Database::Events),
        runner,
        memory: &Forgetful,
    }
}

/// A memory that keeps what it is given for as long as the test runs.
#[derive(Debug, Default)]
pub struct Remembered(pub std::cell::RefCell<std::collections::BTreeMap<String, String>>);

impl crate::context::Memory for Remembered {
    fn recall(&self, key: &str) -> Option<String> {
        self.0.borrow().get(key).cloned()
    }

    fn keep(&self, key: &str, value: &str) {
        self.0.borrow_mut().insert(key.to_owned(), value.to_owned());
    }
}

pub fn table(text: &str) -> toml::Table {
    text.parse().unwrap()
}
