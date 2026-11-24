//! Every state of the commands beside the installer, upgrade and setup:
//! their one constructor each, by command.

pub(crate) mod access;
pub(crate) mod backup_check;
pub(crate) mod commands;
pub(crate) mod config;
pub(crate) mod roles;

#[cfg(test)]
mod tests;
