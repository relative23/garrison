use std::path::{Path, PathBuf};

use super::*;

/// A valid configuration in the shape of the `testing` crate's fixture.
const BASE: &str = r#"
schema = 1
credentials_directory = "/srv/test/credentials"

[deployment]
public_origin = "https://admin.example.test"
issuer = "https://mail.example.test"
stalwart_url = "http://127.0.0.1:8080"
links = { webmail = "https://mail.example.test/", status = "https://status.example.test/" }

[web]
state_directory = "/srv/test/web"

[ingest]
state_directory = "/srv/test/ingest"

[collector]
state_directory = "/srv/test/collector"

[broker]
socket = "/srv/test/broker.sock"
state_directory = "/srv/test/broker"
policy = "/srv/test/policy.json"

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

[[providers]]
type = "host"
"#;

pub(super) fn table() -> toml::Table {
    BASE.parse().unwrap()
}

pub(super) fn section<'a>(raw: &'a mut toml::Table, name: &str) -> &'a mut toml::Table {
    raw.entry(name)
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .unwrap()
}

fn first_action(raw: &mut toml::Table) -> &mut toml::Table {
    raw["actions"].as_array_mut().unwrap()[0]
        .as_table_mut()
        .unwrap()
}

pub(super) fn error(raw: &toml::Table) -> String {
    parse(raw).unwrap_err().0
}

#[test]
fn the_example_configuration_is_valid() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config/garrison.example.toml");
    let config = load(&path).unwrap();
    assert!(config.deployment.public_origin.starts_with("https://"));
    assert!(
        !config.collector.providers.is_empty(),
        "the example configures providers"
    );
}

#[test]
fn defaults_fill_every_optional_setting() {
    let config = parse(&table()).unwrap();
    assert_eq!(
        config.web,
        WebConfig {
            port: 8091,
            state_directory: PathBuf::from("/srv/test/web"),
            session_minutes: 30,
            bind_client_ip: false,
        }
    );
    assert_eq!(config.ingest.port, 8094);
    assert_eq!(config.ingest.retention_days, 30);
    assert_eq!(config.ingest.max_events, 1_000_000);
    assert_eq!(config.ingest.max_database_mib, 256);
    assert_eq!(
        config.ingest.signature_key,
        SecretSource::Credential("webhook-signature-key".into())
    );
    assert_eq!(
        config.collector.native_key,
        SecretSource::Credential("collector-native-key".into())
    );
    assert_eq!(
        config.collector.metrics_credential,
        Some(SecretSource::Credential("metrics-credential".into()))
    );
    assert_eq!(config.collector.history_days, 90);
    assert_eq!(
        config.broker.native_key,
        SecretSource::Credential("broker-native-key".into())
    );
    assert_eq!(config.broker.allowed_peers, ["garrison"]);
    // Stalwart's own WebUI, under its issuer unless configured otherwise.
    assert_eq!(
        config.deployment.admin_url,
        "https://mail.example.test/admin/"
    );
    for (database, path) in [
        (Database::Web, "/srv/test/web/web.sqlite"),
        (Database::Events, "/srv/test/ingest/events.sqlite"),
        (Database::Status, "/srv/test/collector/status.sqlite"),
        (Database::Jobs, "/srv/test/broker/jobs.sqlite"),
    ] {
        assert_eq!(config.database(database), Path::new(path));
        assert!(path.contains(database.writer()));
    }
}

#[test]
fn each_database_has_one_writer_and_only_shared_ones_are_group_readable() {
    let table: Vec<_> = Database::ALL
        .iter()
        .map(|database| {
            (
                database.writer(),
                database.file_name(),
                database.has_readers(),
                database.mode(),
            )
        })
        .collect();
    assert_eq!(
        table,
        [
            ("web", "web.sqlite", false, 0o600),
            ("ingest", "events.sqlite", true, 0o640),
            ("collector", "status.sqlite", true, 0o640),
            ("broker", "jobs.sqlite", false, 0o600),
        ]
    );
    assert_eq!(
        [Operation::Start.as_str(), Operation::Restart.as_str()],
        ["start", "restart"]
    );
}

#[test]
fn unknown_settings_are_rejected() {
    let mut raw = table();
    // A typo must not silently become a default.
    section(&mut raw, "web").insert("sesion_minutes".into(), 10.into());
    assert_eq!(error(&raw), "[web] has unknown settings: sesion_minutes");
    let mut raw = table();
    raw.insert("extra".into(), 1.into());
    raw.insert("another".into(), 1.into());
    assert_eq!(
        error(&raw),
        "[top level] has unknown settings: another, extra"
    );
    let mut raw = table();
    raw.insert("web".into(), "not a table".into());
    assert_eq!(error(&raw), "[web] must be a table");
}

#[test]
fn actions_are_strictly_validated() {
    let cases = [
        (
            "unit",
            "../../bin/sh",
            "actions[run_monitor].unit must be a systemd unit name",
        ),
        (
            "operation",
            "stop",
            "actions[run_monitor].operation must be start or restart",
        ),
        (
            "confirmation",
            "lowercase",
            "actions[run_monitor].confirmation must be an uppercase phrase",
        ),
        ("id", "Bad-Id", "actions.id must be a lowercase identifier"),
        (
            "title",
            "",
            "actions[run_monitor].title must be a short text",
        ),
    ];
    for (field, value, message) in cases {
        let mut raw = table();
        first_action(&mut raw).insert(field.into(), value.into());
        assert_eq!(error(&raw), message, "{field}");
    }
    let mut raw = table();
    first_action(&mut raw).remove("timeout_seconds");
    assert_eq!(
        error(&raw),
        "actions[run_monitor].timeout_seconds must be an integer between 5 and 7200"
    );
    let mut raw = table();
    first_action(&mut raw).insert("id".into(), "run_backup".into());
    assert_eq!(error(&raw), "actions must have unique IDs");
}

#[test]
fn actions_keep_their_order_and_expose_only_public_fields() {
    let config = parse(&table()).unwrap();
    let ids: Vec<&str> = config
        .broker
        .actions
        .iter()
        .map(|action| action.id.as_str())
        .collect();
    assert_eq!(ids, ["run_monitor", "run_backup"]);
    let monitor = config.broker.action("run_monitor").unwrap();
    assert!(monitor.operator);
    assert_eq!(monitor.operation, Operation::Start);
    assert!(!config.broker.action("run_backup").unwrap().operator);
    assert_eq!(
        serde_json::to_value(monitor.public()).unwrap(),
        serde_json::json!({
            "id": "run_monitor",
            "title": "Run health checks",
            "description": "Run the normal health check job.",
            "confirmation": "RUN HEALTH CHECKS",
            "cooldownSeconds": 300,
        })
    );
}

#[test]
fn secrets_name_absolute_files_or_systemd_credentials() {
    let mut raw = table();
    section(&mut raw, "ingest").insert("signature_key".into(), "/etc/garrison/hmac".into());
    section(&mut raw, "collector").insert("metrics_credential".into(), "".into());
    let config = parse(&raw).unwrap();
    assert_eq!(
        config.ingest.signature_key,
        SecretSource::File("/etc/garrison/hmac".into())
    );
    assert_eq!(config.collector.metrics_credential, None);
    section(&mut raw, "collector").insert("metrics_credential".into(), "credential:metrics".into());
    assert_eq!(
        parse(&raw).unwrap().collector.metrics_credential,
        Some(SecretSource::Credential("metrics".into()))
    );
    for source in [
        "credential:..",
        "credential:a/b",
        "relative/key",
        "credential:",
    ] {
        let mut raw = table();
        section(&mut raw, "ingest").insert("signature_key".into(), source.into());
        assert_eq!(
            error(&raw),
            "ingest.signature_key must be an absolute path or credential:NAME",
            "{source}"
        );
    }
    let mut raw = table();
    section(&mut raw, "web").insert("state_directory".into(), "credential:web".into());
    assert_eq!(error(&raw), "web.state_directory must be an absolute path");
}

#[test]
fn numbers_and_flags_must_have_the_right_type_and_range() {
    let cases: [(&str, &str, toml::Value, &str); 4] = [
        (
            "web",
            "port",
            80.into(),
            "web.port must be an integer between 1024 and 65535",
        ),
        (
            "web",
            "session_minutes",
            "30".into(),
            "web.session_minutes must be an integer between 5 and 480",
        ),
        (
            "web",
            "bind_client_ip",
            1.into(),
            "web.bind_client_ip must be true or false",
        ),
        (
            "ingest",
            "max_events",
            999.into(),
            "ingest.max_events must be an integer between 1000 and 10000000",
        ),
    ];
    for (name, key, value, message) in cases {
        let mut raw = table();
        section(&mut raw, name).insert(key.into(), value);
        assert_eq!(error(&raw), message);
    }
    let mut raw = table();
    raw.insert("schema".into(), 2.into());
    assert_eq!(error(&raw), "schema must be 1");
}

#[test]
fn peers_and_providers_are_checked() {
    let mut raw = table();
    section(&mut raw, "broker").insert(
        "allowed_peers".into(),
        toml::Value::Array(vec!["Root".into()]),
    );
    assert_eq!(
        error(&raw),
        "broker.allowed_peers must list system user names"
    );
    let mut raw = table();
    section(&mut raw, "broker").insert("allowed_peers".into(), toml::Value::Array(Vec::new()));
    assert_eq!(
        error(&raw),
        "broker.allowed_peers must list system user names"
    );
    let mut raw = table();
    raw["providers"].as_array_mut().unwrap()[0]
        .as_table_mut()
        .unwrap()
        .remove("type");
    assert_eq!(
        error(&raw),
        "providers must be a list of tables with a type"
    );
}

#[test]
fn name_rules_match_the_documented_patterns() {
    assert!(is_unit_name("stalwart.service"));
    assert!(is_unit_name("getty@tty1.service"));
    assert!(is_unit_name("garrison-broker.socket"));
    assert!(!is_unit_name(".service"));
    assert!(!is_unit_name("stalwart"));
    assert!(!is_unit_name("a/b.service"));
    assert!(!is_unit_name("--root=x.service"));
    assert!(!is_unit_name("-.service"));
    assert!(!is_unit_name(&format!("{}.service", "a".repeat(201))));
    assert!(is_action_id("run_backup") && !is_action_id("1run") && !is_action_id(&"a".repeat(65)));
    assert!(is_confirmation("RUN 2 JOBS") && !is_confirmation("RU") && !is_confirmation(" RUN"));
    assert!(is_user_name("_apt") && is_user_name("garrison") && !is_user_name("-x"));
    assert!(is_user_name("www-data2") && !is_user_name("aB") && !is_user_name("a.b"));
}

#[test]
fn modules_bound_what_the_installation_offers() {
    let all: BTreeSet<ModuleId> = ModuleId::all().collect();
    assert_eq!(parse(&table()).unwrap().modules, all);
    // An empty list leaves the dashboard and the services page.
    let mut raw = table();
    raw.insert("modules".into(), toml::Value::Array(Vec::new()));
    let always = BTreeSet::from([ModuleId::Dashboard, ModuleId::Services]);
    assert_eq!(parse(&raw).unwrap().modules, always);
    raw.insert(
        "modules".into(),
        toml::Value::Array(vec!["antivirus".into(), "actions".into()]),
    );
    let chosen = BTreeSet::from([
        ModuleId::Dashboard,
        ModuleId::Services,
        ModuleId::Antivirus,
        ModuleId::Actions,
    ]);
    assert_eq!(parse(&raw).unwrap().modules, chosen);
    // A typo must not drop a module without a word.
    raw.insert(
        "modules".into(),
        toml::Value::Array(vec!["antivirus".into(), "backup".into()]),
    );
    assert_eq!(error(&raw), "modules: \"backup\" is not a module ID");
    raw.insert("modules".into(), "antivirus".into());
    assert_eq!(error(&raw), "modules must be a list of module IDs");
}
