use garrison_core::observations::{Observation, State};
use garrison_testing::http::{answer, serve};
use serde_json::{Value, json};

use super::*;
use crate::testing::{Canned, config, context, table};

pub(super) fn value_of<'a>(observation: &'a Observation, label: &str) -> &'a Value {
    &observation
        .fields
        .iter()
        .find(|field| field.label == label)
        .unwrap()
        .value
}

#[test]
fn systemd_states_and_idle_jobs() {
    let output = "Id=unbound.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n\n\
        Id=backup.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n\n\
        Id=broken.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\n\n\
        Id=backup.timer\nLoadState=loaded\nActiveState=active\nSubState=waiting\nResult=success\n\
        TimersCalendar={ OnCalendar=*-*-* 03:00:00 ; next_elapse=... }\n\
        NextElapseUSecRealtime=Fri 2026-10-30 03:00:00 UTC\nLastTriggerUSec=Thu 2026-10-29 03:00:00 CET\n";
    let provider = Systemd::new(&table(
        r#"type = "systemd"
units = [
  { unit = "unbound.service", label = "DNS", modules = ["services"] },
  { unit = "backup.service", label = "Backup job", modules = ["backups"], expect = "idle" },
  { unit = "broken.service", label = "Broken", modules = ["services"] },
  { unit = "backup.timer", label = "Schedule", modules = ["backups"] },
  { unit = "missing.service", label = "Missing", modules = ["services"] },
]"#,
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(output.into());
    let report = provider.collect(&context(&config, &runner)).unwrap();
    let states: Vec<State> = report.observations.iter().map(|o| o.state).collect();
    assert_eq!(
        states,
        [
            State::Ok,
            State::Ok,
            State::Failed,
            State::Ok,
            State::Unknown
        ]
    );
    let timer = &report.observations[3];
    assert_eq!(
        value_of(timer, "Next run"),
        &json!("2026-10-30T03:00:00+00:00")
    );
    assert_eq!(value_of(timer, "Schedule"), &json!("*-*-* 03:00:00"));
    assert_eq!(
        value_of(timer, "Last trigger"),
        &Value::Null,
        "only UTC is unambiguous"
    );
    assert_eq!(
        value_of(&report.observations[4], "Active state"),
        &json!("unknown (unknown)")
    );
    assert_eq!(report.gauges["healthy_services"], 3.0);
}

#[test]
fn clamav_policy_drift_is_a_finding() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name).display().to_string();
    std::fs::write(
        path("milter.conf"),
        "OnInfected Accept\nOnFail Defer\nMaxFileSize 25M\n",
    )
    .unwrap();
    std::fs::write(path("scan.conf"), "StreamMaxLength 25M\nScanArchive yes\n").unwrap();
    std::fs::write(path("daily.cld"), "signatures").unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{}\"\nclamd_config = \"{}\"\ndatabase_directory = \"{}\"",
        path("milter.conf"),
        path("scan.conf"),
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let report = provider.collect(&context(&config, &runner)).unwrap();
    let configuration = &report.observations[0];
    assert_eq!(configuration.state, State::Warning);
    assert!(configuration.findings[0].contains("Accept"));
    assert_eq!(
        value_of(configuration, "Milter file limit"),
        &json!(25 * 1024 * 1024)
    );
    assert_eq!(value_of(configuration, "Archive scanning"), &json!(true));
    assert_eq!(
        value_of(configuration, "Alert for encrypted content"),
        &Value::Null
    );
    let signatures = &report.observations[1];
    assert_eq!(signatures.state, State::Ok);
    assert_eq!(
        signatures.table.as_ref().unwrap().rows[0][0],
        json!("daily.cld")
    );
    assert!(report.gauges.contains_key("signature_age_hours"));
}

#[test]
fn unknown_provider_types_and_settings_fail_at_start() {
    let error = |text: &str| build(&[table(text)]).err().unwrap().0;
    assert_eq!(
        error("type = \"docker\""),
        "Unknown provider type \"docker\"; known: backup-check, bulwark, clamav, dns, host, host-care, \
         http, mail-flow, mail-test, prometheus, receipt, releases, reputation, senders, stalwart, systemd, tls, version-command"
    );
    assert!(error("name = \"x\"").starts_with("A provider has no type;"));
    assert!(error("type = 7").starts_with("Unknown provider type 7;"));
    assert_eq!(
        error("type = \"host\"\ndisk = \"/\""),
        "providers[host] has unknown settings: disk"
    );
    assert_eq!(
        error("type = \"http\"\nid = \"a\"\ntitle = \"A\"\nurl = \"http://10.0.0.1/\""),
        "providers[http].url must be a loopback http:// URL"
    );
}

#[test]
fn the_example_configuration_builds() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/config/garrison.example.toml");
    let config = garrison_core::config::load(&path).unwrap();
    assert!(!build(&config.collector.providers).unwrap().is_empty());
}

/// The accounts of an answer of Stalwart, as the provider reads them.
fn listed(answer: &Value) -> Vec<stalwart::answers::MailboxAccount> {
    stalwart::answers::rows(answer.as_object().cloned()).unwrap()
}

fn account(address: &str, used: Option<u64>, quota: Option<u64>) -> Value {
    let mut row = json!({"@type": "User", "emailAddress": address, "usedDiskQuota": used});
    if let Some(quota) = quota {
        row["quotas"] = json!({"maxDiskQuota": quota});
    }
    row
}

#[test]
fn mailboxes_put_the_fullest_first_and_warn_at_ninety_percent() {
    const GIB: u64 = 1 << 30;
    let answer = json!({"list": [
        account("small@example.test", Some(GIB), Some(10 * GIB)),
        account("unlimited@example.test", Some(5 * GIB), None),
        account("full@example.test", Some(19 * GIB), Some(20 * GIB)),
        {"@type": "Group", "emailAddress": "team@example.test"},
    ]});
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let observation = mailboxes::mailboxes(&context, Some(&listed(&answer)), 10).unwrap();
    assert_eq!(observation.state, State::Warning);
    let rows = &observation.table.as_ref().unwrap().rows;
    let names: Vec<&str> = rows.iter().map(|row| row[0].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "full@example.test",
            "small@example.test",
            "unlimited@example.test"
        ]
    );
    assert_eq!(
        (rows[0][3].clone(), rows[2][3].clone()),
        (json!(95.0), Value::Null)
    );
    assert_eq!(
        observation.findings,
        ["full@example.test uses 90 % or more of its quota."]
    );

    let three = json!({"list": (0..3).map(|n| account(&format!("user{n}@example.test"), Some(n), Some(100))).collect::<Vec<_>>()});
    let partial = mailboxes::mailboxes(&context, Some(&listed(&three)), 2).unwrap();
    assert_eq!(partial.state, State::Partial);
    assert_eq!(partial.table.unwrap().rows.len(), 2);
    // Exactly as many accounts as listed are not cut.
    assert_eq!(
        mailboxes::mailboxes(&context, Some(&listed(&three)), 3)
            .unwrap()
            .state,
        State::Ok
    );
    // A mailbox with a quota, however empty, comes before one without.
    let tiny = json!({"list": [account("open@example.test", Some(5), None), account("tiny@example.test", Some(1), Some(1000))]});
    let rows = mailboxes::mailboxes(&context, Some(&listed(&tiny)), 10)
        .unwrap()
        .table
        .unwrap()
        .rows;
    assert_eq!(rows[0][0], "tiny@example.test");
    // Without quotas, the largest mailbox comes first.
    let open = json!({"list": [account("a@example.test", Some(1), None), account("b@example.test", Some(9), None)]});
    let rows = mailboxes::mailboxes(&context, Some(&listed(&open)), 10)
        .unwrap()
        .table
        .unwrap()
        .rows;
    assert_eq!(
        (rows[0][0].as_str(), rows[1][0].as_str()),
        (Some("b@example.test"), Some("a@example.test"))
    );
    assert_eq!(
        mailboxes::mailboxes(&context, None, 2).unwrap().state,
        State::Unknown
    );
    // An account is shown with whatever is known of it.
    let odd = json!({"list": [
        {"@type": "User", "emailAddress": null, "usedDiskQuota": "much", "quotas": 5},
        {"@type": "User", "usedDiskQuota": 7, "quotas": {"maxDiskQuota": 0}},
        {"@type": "user", "emailAddress": "lower@example.test"},
        "no account",
    ]});
    let observation = mailboxes::mailboxes(&context, Some(&listed(&odd)), 10).unwrap();
    assert_eq!(
        observation.table.unwrap().rows,
        [
            vec![json!(""), json!(7), json!(0), Value::Null],
            vec![json!("null"), Value::Null, Value::Null, Value::Null],
        ]
    );
}

#[test]
fn the_http_probe_reads_only_the_status_of_large_pages() {
    let body = "x".repeat(2 * 1024 * 1024);
    let server = serve(vec![answer(200, &body)]);
    let provider = Http::new(&table(&format!(
        "type = \"http\"\nid = \"big\"\ntitle = \"Big\"\nurl = \"{}/\"",
        server.url
    )))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let observation = provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(observation.state, State::Ok);
    assert_eq!(observation.fields[0].value, json!(200));
}

#[test]
fn the_exporter_is_read_with_its_credential() {
    let metrics = "stalwart_queue_message_queued_total 7\nstalwart_server_memory_bytes 2097152\n\
                   stalwart_smtp_active_connections 3\n";
    let server = serve(vec![answer(200, metrics), answer(401, "")]);
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), &server.url);
    let runner = Canned(String::new());
    let mut context = context(&config, &runner);
    context.metrics_credential = Some(("user".into(), "secret".into()));
    let provider = Prometheus::new(&table("type = \"prometheus\"")).unwrap();
    let report = provider.collect(&context).unwrap();
    assert_eq!(
        report.counters,
        [("queue_message_queued".to_owned(), 7.0)].into()
    );
    assert_eq!(
        report.gauges,
        [
            ("server_memory_mib".to_owned(), 2.0),
            ("smtp_connections".to_owned(), 3.0)
        ]
        .into()
    );
    let refused = provider.collect(&context).unwrap();
    assert_eq!(
        refused.observations[0].findings,
        ["The exporter answered HTTP 401."]
    );
    let request = server.requests().remove(0);
    assert!(request.starts_with("GET /metrics/prometheus HTTP/1.1"));
    assert!(request.contains("authorization: Basic dXNlcjpzZWNyZXQ=\r\n"));
    context.metrics_credential = None;
    let missing = provider.collect(&context).unwrap();
    assert_eq!(
        missing.observations[0].findings,
        ["No scrape credential is configured."]
    );
}

#[test]
fn a_scrape_without_every_gauge_is_a_warning() {
    let every_gauge = "stalwart_server_memory_bytes 2097152\nstalwart_smtp_active_connections 0\n\
                       stalwart_imap_active_connections 0\nstalwart_http_active_connections 0\n";
    let server = serve(vec![
        answer(200, every_gauge),
        answer(200, "stalwart_server_memory_bytes 2097152\n"),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), &server.url);
    let runner = Canned(String::new());
    let mut context = context(&config, &runner);
    context.metrics_credential = Some(("user".into(), "secret".into()));
    let provider = Prometheus::new(&table("type = \"prometheus\"")).unwrap();
    let complete = provider.collect(&context).unwrap();
    assert_eq!(complete.observations[0].state, State::Ok);
    assert_eq!(complete.counters.len(), 12, "every counter is zero");
    let partial = provider.collect(&context).unwrap();
    assert_eq!(partial.observations[0].state, State::Warning);
    assert!(partial.counters.is_empty());
    assert_eq!(partial.observations[0].findings.len(), 1);
}

#[test]
fn versions_come_from_the_first_group() {
    let provider = VersionCommand::new(&table(
        "type = \"version-command\"\ncomponent = \"ClamAV Scanner\"\ncommand = [\"/usr/bin/clamdscan\", \"--version\"]\npattern = \"^ClamAV (\\\\d+\\\\.\\\\d+\\\\.\\\\d+)\"",
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned("ClamAV 1.4.3/27800/Wed Oct 29 2026\n".into());
    let observation = provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(observation.id, "version.clamav-scanner");
    assert_eq!(observation.value["version"], json!("1.4.3"));
    let other = Canned("something else".into());
    let unknown = provider
        .collect(&context(&config, &other))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(unknown.state, State::Unknown);
    let error = VersionCommand::new(&table(
        "type = \"version-command\"\ncomponent = \"X\"\ncommand = [\"relative\"]",
    ));
    assert_eq!(
        error.unwrap_err().0,
        "providers[version-command].command must be an absolute command"
    );
}

#[test]
fn host_resources_come_from_proc_files() {
    let directory = tempfile::tempdir().unwrap();
    let proc = directory.path().join("proc");
    std::fs::create_dir(&proc).unwrap();
    std::fs::write(
        proc.join("meminfo"),
        "MemTotal: 1000 kB\nMemAvailable: 50 kB\nSwapTotal: 0 kB\n",
    )
    .unwrap();
    std::fs::write(proc.join("loadavg"), "0.52 0.58 0.59 1/100 1234\n").unwrap();
    std::fs::write(proc.join("uptime"), "12345.67 1000.00\n").unwrap();
    let provider = Host::new(&table(&format!(
        "type = \"host\"\nproc = \"{}\"\ndisk_path = \"{}\"",
        proc.display(),
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let report = provider.collect(&context(&config, &runner)).unwrap();
    let observation = &report.observations[0];
    assert_eq!(observation.state, State::Warning);
    assert!(
        observation
            .findings
            .contains(&"Less than 10% of the memory is available.".to_owned())
    );
    assert_eq!(
        value_of(observation, "Load (1 / 5 / 15 min)"),
        &json!("0.52 / 0.58 / 0.59")
    );
    assert_eq!(value_of(observation, "Uptime"), &json!(12345));
    assert_eq!(value_of(observation, "Memory total"), &json!(1_024_000));
    assert_eq!(report.gauges["load_1m"], 0.52);
    std::fs::remove_file(proc.join("uptime")).unwrap();
    let unknown = provider
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(unknown.state, State::Unknown);
}
