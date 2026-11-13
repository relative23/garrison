//! Fixtures shared by the crates' tests. This crate is only ever a
//! development dependency.

// Fixtures fail the calling test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

pub mod http;
pub mod lab;
pub mod noise;
pub mod smtp;
pub mod tls;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use garrison_core::config::{self, Config};
use garrison_core::credentials::Credentials;
use garrison_core::modules::ModuleId;
use serde_json::{Value, json};

pub const NATIVE_KEY: &str = "native-key-0123456789";

/// A valid configuration in `directory`:
/// two actions (`run_monitor` for operators, `run_backup`) and one provider.
pub fn config_text(directory: &Path, stalwart_url: &str) -> String {
    let path = |name: &str| directory.join(name).display().to_string();
    format!(
        r#"
schema = 1
credentials_directory = "{credentials}"

[deployment]
public_origin = "https://admin.example.test"
issuer = "https://mail.example.test"
stalwart_url = "{stalwart_url}"
links = {{ webmail = "https://mail.example.test/" }}

[web]
state_directory = "{web}"

[ingest]
state_directory = "{ingest}"

[collector]
state_directory = "{collector}"

[broker]
socket = "{socket}"
state_directory = "{broker}"
policy = "{policy}"

[[actions]]
id = "run_monitor"
title = "Run health checks"
description = "Run the normal health check job."
confirmation = "RUN HEALTH CHECKS"
unit = "monitor.service"
operation = "start"
cooldown_seconds = 300
timeout_seconds = 60
operator = true

[[actions]]
id = "run_backup"
title = "Run health checks"
description = "Run the normal health check job."
confirmation = "RUN BACKUP"
unit = "backup.service"
operation = "start"
cooldown_seconds = 300
timeout_seconds = 60
operator = false

[[providers]]
type = "host"
"#,
        credentials = path("credentials"),
        web = path("web"),
        ingest = path("ingest"),
        collector = path("collector"),
        socket = path("broker.sock"),
        broker = path("broker"),
        policy = path("policy.json"),
    )
}

/// [`config_text`], parsed.
pub fn config(directory: &Path, stalwart_url: &str) -> Config {
    let table: toml::Table = config_text(directory, stalwart_url).parse().unwrap();
    config::parse(&table).unwrap()
}

/// The configured credentials directory, created, with the native API key in it.
pub fn credentials(config: &Config) -> Credentials {
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    let key = credentials.path(&config.broker.native_key);
    write_private(&key, NATIVE_KEY.as_bytes());
    credentials
}

/// A file only its owner can read or write.
pub fn write_private(path: &Path, data: &[u8]) {
    let _ = fs::remove_file(path);
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// The test access policy: native role `v` grants the viewer
/// profile (no actions), role `e` the administrator profile (both actions).
pub fn policy_document() -> Value {
    let all: Vec<&str> = ModuleId::all().map(ModuleId::as_str).collect();
    let viewer: Vec<&str> = all.iter().copied().filter(|id| *id != "actions").collect();
    json!({
        "schemaVersion": 1,
        "profiles": {
            "viewer": {
                "modules": viewer,
                "actions": [],
                "requiredNativePermissions": ["authenticate", "sysAccountGet"],
            },
            "administrator": {
                "modules": all,
                "actions": ["run_backup", "run_monitor"],
                "requiredNativePermissions": ["authenticate", "sysActionCreate", "sysRoleUpdate"],
            },
        },
        "roleBindings": {"e": "administrator", "v": "viewer"},
        "subjects": {},
        "deniedSubjects": [],
    })
}

/// Write the policy where `config` expects it, readable only by its owner.
pub fn write_policy(config: &Config, document: &Value) {
    write_private(&config.broker.policy, document.to_string().as_bytes());
}
