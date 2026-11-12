//! The SELinux policy module that lets nginx reach Garrison's web port, and
//! nothing more.
//!
//! Under SELinux nginx runs confined as `httpd_t`, which may not connect to an
//! unlabelled port: a fresh RHEL-family host answers every request with 502.
//! The usual advice, `setsebool -P httpd_can_network_connect 1`, would let
//! nginx connect anywhere. This module gives Garrison's port a type of its own
//! and allows only that connection. It is CIL, which `semodule` from the base
//! system loads without a compiler.

use std::fs;
use std::path::Path;

use garrison_core::config;

use super::CONFIG;
use super::files::{Step, announce, io, run};

const SEMODULE: &str = "/usr/sbin/semodule";
/// The module as last loaded; `semodule -r garrison` removes it.
pub(super) const MODULE: &str = "/opt/garrison/selinux/garrison.cil";
/// The web service's default port, for a configuration that cannot be loaded.
const DEFAULT_PORT: u16 = 8091;

fn module(port: u16) -> String {
    format!(
        ";; Lets nginx (httpd_t) connect to Garrison's web service on port {port}.\n\
         ;; Written by the Garrison installer; `semodule -r garrison` removes it.\n\
         (type garrison_port_t)\n\
         (roletype object_r garrison_port_t)\n\
         (typeattributeset port_type (garrison_port_t))\n\
         (portcon tcp {port} (system_u object_r garrison_port_t ((s0) (s0))))\n\
         (allow httpd_t garrison_port_t (tcp_socket (name_connect)))\n"
    )
}

fn enabled() -> bool {
    Path::new("/sys/fs/selinux/enforce").exists() && Path::new(SEMODULE).exists()
}

fn loaded() -> bool {
    run(SEMODULE, &["-l"]).is_ok_and(|output| {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.split_whitespace().next() == Some("garrison"))
    })
}

/// Load the module for the configured web port where SELinux is in use. A
/// failure warns instead of stopping the installation: Garrison itself runs,
/// and the warning names the broader way out.
pub(super) fn install() -> Step {
    if !enabled() {
        return Ok(());
    }
    let port = config::load(&Path::new(CONFIG).join("garrison.toml"))
        .map_or(DEFAULT_PORT, |config| config.web.port);
    let text = module(port);
    let path = Path::new(MODULE);
    if loaded() && fs::read_to_string(path).is_ok_and(|current| current == text) {
        return Ok(());
    }
    if let Some(folder) = path.parent() {
        io(fs::create_dir_all(folder), folder)?;
    }
    io(fs::write(path, &text), path)?;
    announce(&format!(
        "Loading the SELinux module that lets nginx reach Garrison on port {port}"
    ));
    let output = run(SEMODULE, &["-i", MODULE])?;
    if !output.status.success() {
        announce(&format!(
            "The SELinux module did not load, so nginx may not reach Garrison: {}. \
             `setsebool -P httpd_can_network_connect 1` allows it more broadly.",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_module_labels_only_the_web_port_and_allows_only_nginx() {
        let text = module(9443);
        assert!(
            text.contains("(portcon tcp 9443 (system_u object_r garrison_port_t ((s0) (s0))))")
        );
        let rules: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("(allow"))
            .collect();
        assert_eq!(
            rules,
            ["(allow httpd_t garrison_port_t (tcp_socket (name_connect)))"]
        );
    }
}
