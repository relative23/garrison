//! Timers and jobs as systemd reports them.

use garrison_core::observations::{Observation, State};
use serde_json::{Value, json};

use super::tests::value_of;
use super::*;
use crate::testing::{Canned, config, context, table};

/// A timer that runs again a while after its unit last ran has no calendar;
/// systemd counts its next run from the start of the host.
#[test]
fn an_interval_timer_shows_its_interval_and_its_next_run() {
    let timer = |extra: &str| -> Observation {
        let output = format!(
            "Id=collect.timer\nLoadState=loaded\nActiveState=active\nSubState=waiting\nResult=success\n\
             TimersMonotonic={{ OnUnitActiveUSec=1min ; next_elapse=11h 14min 25.705796s }}\n\
             TimersMonotonic={{ OnBootUSec=30s ; next_elapse=30s }}\nNextElapseUSecRealtime=\n{extra}"
        );
        let provider = Systemd::new(&table(
            r#"type = "systemd"
units = [{ unit = "collect.timer", label = "Collection", modules = ["services"] }]"#,
        ))
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let report = provider
            .collect(&context(&config, &Canned(output)))
            .unwrap();
        report.observations.into_iter().next().unwrap()
    };
    let running = timer(
        "NextElapseUSecMonotonic=11h 14min 25.705796s\nLastTriggerUSec=Tue 2026-11-10 22:15:32 UTC\n\
         LastTriggerUSecMonotonic=11h 13min 25.701930s\n",
    );
    assert_eq!(value_of(&running, "Schedule"), &json!("every 1min"));
    assert_eq!(
        value_of(&running, "Next run"),
        &json!("2026-11-10T22:16:32+00:00")
    );
    // Not yet run since the host started, or a count that makes no sense: no guess.
    let fresh =
        timer("NextElapseUSecMonotonic=30s\nLastTriggerUSec=n/a\nLastTriggerUSecMonotonic=0\n");
    assert_eq!(value_of(&fresh, "Schedule"), &json!("every 1min"));
    assert_eq!(value_of(&fresh, "Next run"), &Value::Null);
    let odd = timer(
        "NextElapseUSecMonotonic=5min\nLastTriggerUSec=Tue 2026-11-10 22:15:32 UTC\n\
         LastTriggerUSecMonotonic=6min\n",
    );
    assert_eq!(value_of(&odd, "Next run"), &Value::Null);
}

/// A job that systemd runs, such as a backup: when it last ran, how it ended
/// and how long it took, without the job writing anything for Garrison.
#[test]
fn a_job_shows_its_last_run_and_may_not_be_older_than_asked() {
    let job = |limit: &str, properties: &str| -> Observation {
        let output = format!(
            "Id=backup.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n{properties}"
        );
        let provider = Systemd::new(&table(&format!(
            r#"type = "systemd"
units = [{{ unit = "backup.service", label = "Backup job", modules = ["backups"], expect = "idle"{limit} }}]"#
        )))
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let report = provider
            .collect(&context(&config, &Canned(output)))
            .unwrap();
        report.observations.into_iter().next().unwrap()
    };
    // The tests collect at 2026-10-29T12:00:00Z.
    let ran = "Result=success\nExecMainStartTimestamp=Thu 2026-10-29 03:30:00 UTC\n\
               ExecMainExitTimestamp=Thu 2026-10-29 03:34:10 UTC\nExecMainStatus=0\n";
    let done = job("", ran);
    assert_eq!(done.state, State::Ok);
    assert_eq!(
        value_of(&done, "Last run"),
        &json!("2026-10-29T03:34:10+00:00")
    );
    assert_eq!(value_of(&done, "Result"), &json!("success"));
    assert_eq!(value_of(&done, "Duration"), &json!(250));
    assert_eq!(job(", max_age_hours = 9", ran).state, State::Ok);
    let late = job(", max_age_hours = 8", ran);
    assert_eq!(late.state, State::Warning);
    assert_eq!(late.findings, ["The last run is older than 8 hours."]);

    let failed = job(
        ", max_age_hours = 30",
        "Result=exit-code\nExecMainStartTimestamp=Thu 2026-10-29 03:30:00 UTC\n\
         ExecMainExitTimestamp=Thu 2026-10-29 03:30:05 UTC\nExecMainStatus=3\n",
    );
    assert_eq!(failed.state, State::Failed);
    assert_eq!(
        value_of(&failed, "Result"),
        &json!("exit-code (exit status 3)")
    );

    // systemd forgets a run when the host starts again: unknown, never fine.
    let never =
        "Result=success\nExecMainStartTimestamp=\nExecMainExitTimestamp=\nExecMainStatus=0\n";
    let unlimited = job("", never);
    assert_eq!(unlimited.state, State::Ok);
    assert_eq!(value_of(&unlimited, "Last run"), &Value::Null);
    assert_eq!(value_of(&unlimited, "Result"), &Value::Null);
    let limited = job(", max_age_hours = 30", never);
    assert_eq!(limited.state, State::Unknown);
    assert_eq!(limited.findings, ["No run since the host started."]);
    // Still running: the start is newer than the last end.
    let running = job(
        "",
        "Result=success\nExecMainStartTimestamp=Thu 2026-10-29 11:59:00 UTC\n\
         ExecMainExitTimestamp=Thu 2026-10-28 03:34:10 UTC\nExecMainStatus=0\n",
    );
    assert_eq!(value_of(&running, "Last run"), &Value::Null);

    // The limit is for jobs only, and within a year.
    for wrong in [
        r#"units = [{ unit = "a.service", label = "A", modules = ["backups"], max_age_hours = 3 }]"#,
        r#"units = [{ unit = "a.service", label = "A", modules = ["backups"], expect = "idle", max_age_hours = 0 }]"#,
        r#"units = [{ unit = "a.service", label = "A", modules = ["backups"], expect = "idle", max_age_hours = "3" }]"#,
    ] {
        assert!(
            Systemd::new(&table(&format!("type = \"systemd\"\n{wrong}"))).is_err(),
            "{wrong}"
        );
    }
}
