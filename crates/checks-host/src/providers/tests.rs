use garrison_core::observations::{Observation, State};
use garrison_testing::http::{answer, serve};
use serde_json::{Value, json};

use super::*;
use crate::context::Provider;
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
