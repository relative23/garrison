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

/// Gives every command the error of one ended at the runner's time limit.
struct Late;

impl Runner for Late {
    fn run(&self, _: &[&str]) -> io::Result<Output> {
        Err(io::Error::new(io::ErrorKind::TimedOut, "command timed out"))
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
    // A systemctl that ran and was ended at the collector's time limit.
    for observation in observed(units, &Late) {
        assert_eq!(
            (observation.state, observation.findings),
            (
                State::Unknown,
                vec!["systemctl show did not finish within 8 seconds and was ended.".to_owned()]
            )
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
    assert_eq!(limited.findings, [NO_RUN]);
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

/// What `systemctl show` answered, with the collector's arguments, for a
/// stopped and a waiting timer in a container of Debian 13 that runs
/// systemd 257 (`systemd/show/`, measured 2026-11-17).
const TIMER_STOPPED: &str = include_str!("systemd/show/debian-13-timer-stopped.txt");
const TIMER_WAITING: &str = include_str!("systemd/show/debian-13-timer-waiting.txt");

/// A timer, a socket or a path unit is active while it waits and inactive
/// once stopped, and runs nothing of its own: `expect = "idle"`, which takes
/// an inactive unit whose last result was a success for one at rest, called
/// a stopped timer in order (measured: a stopped timer is inactive with
/// Result success), and `max_age_hours` never applied to one. check-config
/// refuses both there and names the service to put them on. A stopped
/// timer that is expected active is Failed, a waiting one in order.
#[test]
fn a_job_expectation_on_a_unit_that_is_no_service_is_refused() {
    for (unit, kind, extra) in [
        ("backup.timer", "timer", "expect = \"idle\""),
        (
            "backup.timer",
            "timer",
            "expect = \"idle\", max_age_hours = 26",
        ),
        ("backup.timer", "timer", "max_age_hours = 26"),
        ("backup.socket", "socket", "expect = \"idle\""),
        ("backup.path", "path", "expect = \"idle\""),
    ] {
        let raw = format!(
            "type = \"systemd\"\nunits = [{{ unit = \"{unit}\", label = \"Backup\", \
             modules = [\"backups\"], {extra} }}]"
        );
        assert_eq!(
            Systemd::new(&table(&raw)).map(|_| ()).unwrap_err().0,
            format!(
                "providers[systemd] unit {unit}: expect = \"idle\" and max_age_hours are for a \
                 service that runs and ends, not for a {kind}; put them on the service the \
                 {kind} starts, such as backup.service"
            ),
            "{unit} {extra}"
        );
    }
    let schedule = r#"{ unit = "hostchk-job.timer", label = "Schedule", modules = ["backups"] }"#;
    let stopped = observed(schedule, &Canned(TIMER_STOPPED.to_owned()));
    assert_eq!(stopped[0].state, State::Failed);
    let waiting = observed(schedule, &Canned(TIMER_WAITING.to_owned()));
    assert_eq!(waiting[0].state, State::Ok);
    assert_eq!(
        value_of(&waiting[0], "Next run"),
        &json!("2026-11-17T03:00:00+00:00")
    );
}

/// What `systemctl show` answered, with the collector's arguments, for a
/// one-shot job in containers of Debian 13 and `AlmaLinux` 10 that run
/// systemd 257 (`systemd/show/`, measured 2026-11-17): while its second run
/// was under way, two seconds after a run where no timer referred to it,
/// after a run its timer kept it loaded for, and in its `ExecStartPost`.
const DEBIAN_RUNNING: &str = include_str!("systemd/show/debian-13-job-while-it-runs.txt");
const ALMA_RUNNING: &str = include_str!("systemd/show/almalinux-10-job-while-it-runs.txt");
const DEBIAN_UNLOADED: &str =
    include_str!("systemd/show/debian-13-job-unreferenced-after-a-run.txt");
const ALMA_UNLOADED: &str =
    include_str!("systemd/show/almalinux-10-job-unreferenced-after-a-run.txt");
const DEBIAN_RAN: &str = include_str!("systemd/show/debian-13-job-after-a-run.txt");
const DEBIAN_START_POST: &str = include_str!("systemd/show/debian-13-job-in-its-start-post.txt");

/// The card of the measured job, `hostchk-job.service`, with `limit` added
/// to its entry, as collected at `now`.
fn the_job(limit: &str, answer: &str, now: &str) -> Observation {
    let provider = Systemd::new(&table(&format!(
        "type = \"systemd\"\nunits = [{{ unit = \"hostchk-job.service\", label = \"Job\", \
         modules = [\"backups\"], expect = \"idle\"{limit} }}]"
    )))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(answer.to_owned());
    let context = crate::context::Context {
        now: garrison_core::time::parse(now).unwrap(),
        ..context(&config, &runner)
    };
    provider.collect(&context).unwrap().observations.remove(0)
}

/// systemd clears the end of a job's last run when it starts the next one,
/// so while that runs nothing says when the last one ended: the card says
/// since when the run is under way, and `max_age_hours` holds that start to
/// the limit, as a run that began within it shows that the job still runs.
#[test]
fn a_run_under_way_says_since_when_and_holds_its_start_to_the_limit() {
    for (answer, started) in [
        (DEBIAN_RUNNING, "2026-11-17T00:24:47+00:00"),
        (ALMA_RUNNING, "2026-11-17T00:26:00+00:00"),
    ] {
        let soon = the_job(", max_age_hours = 26", answer, "2026-11-17T00:30:00Z");
        assert_eq!(
            (soon.state, soon.findings.as_slice()),
            (State::Ok, &[][..]),
            "{started}"
        );
        assert_eq!(value_of(&soon, "Running since"), &json!(started));
        assert_eq!(value_of(&soon, "Last run"), &Value::Null);
        // A run that began longer ago than the limit has not ended within it.
        let stuck = the_job(", max_age_hours = 26", answer, "2026-11-18T03:00:00Z");
        assert_eq!(stuck.state, State::Warning, "{started}");
        assert_eq!(
            stuck.findings,
            ["The run under way began more than 26 hours ago."]
        );
        let unlimited = the_job("", answer, "2026-11-18T03:00:00Z");
        assert_eq!(unlimited.state, State::Ok, "{started}");
        assert_eq!(value_of(&unlimited, "Running since"), &json!(started));
    }
    // In its ExecStartPost the job's main process has ended: that is its run.
    let post = the_job(
        ", max_age_hours = 26",
        DEBIAN_START_POST,
        "2026-11-17T00:30:00Z",
    );
    assert_eq!(post.state, State::Ok);
    assert_eq!(
        value_of(&post, "Last run"),
        &json!("2026-11-17T00:25:19+00:00")
    );
    assert!(
        post.fields
            .iter()
            .all(|field| field.label != "Running since")
    );
}

/// systemd keeps a job's last run only while it keeps the job loaded: it
/// forgets it when the host starts, and as soon as the run ends where no
/// timer or other unit refers to the job, as for one started by hand or by
/// cron (measured: two seconds after such a run both of its times were
/// empty). The card is Unknown then and says that, not that no run was.
#[test]
fn a_job_whose_run_systemd_forgot_says_why_it_knows_none() {
    for answer in [DEBIAN_UNLOADED, ALMA_UNLOADED] {
        let forgotten = the_job(", max_age_hours = 26", answer, "2026-11-17T00:30:00Z");
        assert_eq!(forgotten.state, State::Unknown);
        assert_eq!(forgotten.findings, [NO_RUN]);
    }
    // One that its timer keeps loaded keeps its run.
    let kept = the_job(", max_age_hours = 26", DEBIAN_RAN, "2026-11-17T00:30:00Z");
    assert_eq!(kept.state, State::Ok);
    assert_eq!(
        value_of(&kept, "Last run"),
        &json!("2026-11-17T00:24:47+00:00")
    );
}

/// What a job's card says where systemd remembers no run of it.
const NO_RUN: &str = "systemd remembers no finished run of this job: none since the host \
                      started, or it unloaded the job after its last run, as it does where no \
                      timer or other unit refers to the job.";
