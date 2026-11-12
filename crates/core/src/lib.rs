//! Code shared by every Garrison component.
//!
//! This crate and the other privileged crates (`stalwart`, `authz`, `broker`,
//! `collector`) never depend on a web framework or an async runtime;
//! `cargo xtask layering` enforces it.

pub mod command;
pub mod config;
pub mod constant_time;
pub mod credentials;
pub mod files;
pub mod hex;
pub mod json;
pub mod logging;
pub mod modules;
pub mod observations;
pub mod sqlite;
pub mod systemd;
pub mod time;
pub mod version;
