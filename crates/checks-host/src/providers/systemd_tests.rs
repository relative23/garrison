//! Timers and jobs as systemd reports them.

use std::io;

use garrison_core::observations::{Observation, State};
use serde_json::{Value, json};

use super::tests::value_of;
use super::*;
use crate::command::{Output, Runner};
use crate::context::Provider;
use crate::testing::{Canned, config, context, table};

/// The observations for `units`, given as `{ unit = …, label = … }` entries,
/// when systemctl answers with `runner`.
fn observed(units: &str, runner: &dyn Runner) -> Vec<Observation> {
    let provider = Systemd::new(&table(&format!("type = \"systemd\"\nunits = [{units}]"))).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    provider
        .collect(&context(&config, runner))
        .unwrap()
        .observations
}

/// systemd 259's answer on Ubuntu 26.04 for `chronyd.service`, an alias of
/// `chrony.service`, then for `chrony.service` itself and a unit that does
/// not exist, in the order they were asked.
const ALIASED: &str = "Id=chrony.service\nNames=chrony.service chronyd.service\n\
    LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n\
    ExecMainStartTimestamp=Mon 2026-11-09 22:26:51 UTC\nExecMainExitTimestamp=\nExecMainStatus=0\n\n\
    Id=chrony.service\nNames=chrony.service chronyd.service\n\
    LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n\
    ExecMainStartTimestamp=Mon 2026-11-09 22:26:51 UTC\nExecMainExitTimestamp=\nExecMainStatus=0\n\n\
    Id=garrison-nothing.service\nNames=garrison-nothing.service\n\
    LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\n\
    ExecMainStartTimestamp=\nExecMainExitTimestamp=\nExecMainStatus=0\n";

/// systemd answers an alias, such as `sshd.service` for `ssh.service` on
/// Debian and Ubuntu, under the unit it names; the alias is one of its names.
#[test]
fn an_alias_shows_the_state_of_the_unit_it_names() {
    let observations = observed(
        r#"{ unit = "chronyd.service", label = "Time (alias)", modules = ["services"] },
           { unit = "chrony.service", label = "Time", modules = ["services"] },
           { unit = "garrison-nothing.service", label = "Gone", modules = ["services"] }"#,
        &Canned(ALIASED.to_owned()),
    );
    let states: Vec<(&str, State)> = observations
        .iter()
        .map(|observation| (observation.id.as_str(), observation.state))
        .collect();
    assert_eq!(
        states,
        [
            ("systemd.chronyd.service", State::Ok),
            ("systemd.chrony.service", State::Ok),
            ("systemd.garrison-nothing.service", State::Failed),
        ]
    );
    assert_eq!(
        value_of(&observations[0], "Active state"),
        &json!("active (running)")
    );
    assert_eq!(observations[0].findings, Vec::<String>::new());
    // The alias's card names the unit it stands for; the others stand for
    // themselves.
    assert_eq!(
        value_of(&observations[0], "Alias of"),
        &json!("chrony.service")
    );
    for unit in &observations[1..] {
        assert!(
            unit.fields.iter().all(|field| field.label != "Alias of"),
            "{}",
            unit.id
        );
    }
}

/// Fails as a systemctl that is not there does.
struct Missing;

impl Runner for Missing {
    fn run(&self, _: &[&str]) -> io::Result<Output> {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }
}

/// An answer is read only for a unit it names. One that names none, too
/// few answers, one without the unit's load state and a systemctl that
/// cannot be run leave the units Unknown, and each says why.
#[test]
fn a_unit_without_an_answer_of_its_own_is_unknown_and_says_why() {
    let block = |id: &str| {
        format!("Id={id}\nNames={id}\nLoadState=loaded\nActiveState=active\nSubState=running\n")
    };
    let units = r#"{ unit = "a.service", label = "A", modules = ["services"] },
        { unit = "b.service", label = "B", modules = ["services"] },
        { unit = "c.service", label = "C", modules = ["services"] }"#;
    // An answer for a.service, one for a unit nobody asked about, none for c.
    let answer = format!("{}\n{}", block("a.service"), block("other.service"));
    let observations = observed(units, &Canned(answer));
    let read: Vec<(State, &[String])> = observations
        .iter()
        .map(|observation| (observation.state, observation.findings.as_slice()))
        .collect();
    let none = ["systemctl show gave no answer for this unit.".to_owned()];
    assert_eq!(
        read,
        [
            (State::Ok, &[][..]),
            (State::Unknown, &none[..]),
            (State::Unknown, &none[..]),
        ]
    );
    assert_eq!(
        value_of(&observations[1], "Active state"),
        &json!("unknown (unknown)")
    );
    // More answers than units asked: each unit still takes its own.
    let answer = format!(
        "{}\n{}\n{}\n{}",
        block("other.service"),
        block("c.service"),
        block("b.service"),
        block("a.service")
    );
    let states: Vec<State> = observed(units, &Canned(answer))
        .iter()
        .map(|observation| observation.state)
        .collect();
    assert_eq!(states, [State::Ok; 3]);
    // An answer that does not say whether the unit is loaded.
    let answer = "Id=a.service\nNames=a.service\nActiveState=active\nSubState=running\n";
    let unloaded = observed(
        r#"{ unit = "a.service", label = "A", modules = ["services"] }"#,
        &Canned(answer.to_owned()),
    );
    assert_eq!(unloaded[0].state, State::Unknown);
    assert_eq!(
        unloaded[0].findings,
        ["systemctl show gave no load state for this unit."]
    );
    // No systemctl at all.
    let observations = observed(units, &Missing);
    for observation in &observations {
        assert_eq!(observation.state, State::Unknown);
        assert_eq!(observation.findings.len(), 1);
        assert!(
            observation.findings[0].starts_with("systemctl show could not be run: "),
            "{:?}",
            observation.findings
        );
    }
}

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
