//! Every state of the commands beside the installer, upgrade and setup,
//! and of the services: their one constructor each, by command.

pub(crate) mod access;
pub(crate) mod backup_check;
pub(crate) mod commands;
pub(crate) mod config;
pub(crate) mod roles;
pub(crate) mod services;

#[cfg(test)]
mod tests;
