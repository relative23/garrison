//! Run configured systemd operations and observe their results.
//!
//! The broker runs as an unprivileged user. systemd asks polkit whether that
//! user may start or restart a unit; the generated rule (see `polkit`) allows
//! exactly the configured unit/verb pairs. A request can never choose a
//! command, unit or signal.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use garrison_core::command;
use garrison_core::config::{Action, Operation};
use garrison_core::systemd::SYSTEMCTL;

use crate::protocol::{BrokerError, refuse};
use crate::store::JobStatus;

const SHOW_TIMEOUT: Duration = Duration::from_secs(5);
const TRANSITIONS: [&str; 3] = ["activating", "deactivating", "reloading"];

/// How an operation ended: succeeded, failed or uncertain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: JobStatus,
    pub message: &'static str,
    pub may_still_run: bool,
}

/// What the broker needs from systemd; tests use their own.
pub trait Runner: Send + Sync {
    /// Refuse an action whose unit is missing or busy, before anything ran.
    fn preflight(&self, action: &Action) -> Result<(), BrokerError>;
    /// Whether an earlier operation on the action's unit may still be running.
    fn still_running(&self, action: &Action) -> bool;
    fn run(&self, action: &Action) -> Outcome;
}

/// Runs actions through `systemctl`.
#[derive(Clone, Debug)]
pub struct SystemdRunner {
    systemctl: PathBuf,
}

impl Default for SystemdRunner {
    fn default() -> Self {
        SystemdRunner {
            systemctl: PathBuf::from(SYSTEMCTL),
        }
    }
}

impl SystemdRunner {
    /// A runner that calls another `systemctl`, such as a test double.
    pub fn with_systemctl(systemctl: &Path) -> Self {
        SystemdRunner {
            systemctl: systemctl.to_owned(),
        }
    }

    fn program(&self) -> &str {
        self.systemctl.to_str().unwrap_or(SYSTEMCTL)
    }

    fn state(&self, action: &Action) -> Result<BTreeMap<String, String>, BrokerError> {
        let arguments = [
            self.program(),
            "show",
            "--property=LoadState,ActiveState,SubState,Result,Job",
            "--no-pager",
            "--",
            action.unit.as_str(),
        ];
        match command::run(&arguments, SHOW_TIMEOUT) {
            Ok(output) if output.code == Some(0) => Ok(output
                .stdout
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect()),
            _ => Err(refuse(503, "Service state is unavailable")),
        }
    }

    fn busy(action: &Action, state: &BTreeMap<String, String>) -> bool {
        let get = |key: &str| state.get(key).map(String::as_str);
        let job = get("Job")
            .unwrap_or("0")
            .split(' ')
            .next()
            .unwrap_or_default();
        let pending = !job.is_empty() && job != "0";
        let active = get("ActiveState");
        pending
            || active.is_some_and(|state| TRANSITIONS.contains(&state))
            || (action.operation == Operation::Start && active == Some("active"))
    }
}

impl Runner for SystemdRunner {
    fn preflight(&self, action: &Action) -> Result<(), BrokerError> {
        let state = self.state(action)?;
        if state.get("LoadState").map(String::as_str) != Some("loaded") {
            return Err(refuse(
                503,
                "The configured service is not installed or loaded",
            ));
        }
        if Self::busy(action, &state) {
            return Err(refuse(
                409,
                "The service already has an operation in progress",
            ));
        }
        Ok(())
    }

    fn still_running(&self, action: &Action) -> bool {
        self.state(action)
            .map_or(true, |state| Self::busy(action, &state))
    }

    fn run(&self, action: &Action) -> Outcome {
        let outcome = |status, message, may_still_run| Outcome {
            status,
            message,
            may_still_run,
        };
        let arguments = [
            self.program(),
            "--no-ask-password",
            action.operation.as_str(),
            "--",
            action.unit.as_str(),
        ];
        // The time limit ends only this observation, never the target unit.
        let timeout = Duration::from_secs(u64::from(action.timeout_seconds));
        match command::run(&arguments, timeout) {
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                return outcome(
                    JobStatus::Uncertain,
                    "Observation timed out; the underlying job was not stopped.",
                    true,
                );
            }
            Ok(output) if output.code == Some(0) => {}
            _ => {
                return outcome(
                    JobStatus::Failed,
                    "The systemd operation failed. Consult the host journal.",
                    false,
                );
            }
        }
        if action.operation == Operation::Start {
            return outcome(
                JobStatus::Succeeded,
                "The maintenance job completed successfully.",
                false,
            );
        }
        match self.state(action) {
            Err(_) => outcome(
                JobStatus::Uncertain,
                "The restart completed, but the service state could not be verified.",
                false,
            ),
            Ok(state) if state.get("ActiveState").map(String::as_str) == Some("active") => outcome(
                JobStatus::Succeeded,
                "The service restarted and is active.",
                false,
            ),
            Ok(_) => outcome(
                JobStatus::Failed,
                "The restarted service is not active. Consult the host journal.",
                false,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use super::*;

    /// Writing an executable while another test forks can make its start fail
    /// with "text file busy", so the tests that start processes take turns.
    static TURN: Mutex<()> = Mutex::new(());

    fn turn() -> MutexGuard<'static, ()> {
        TURN.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A `systemctl` that logs its arguments, answers `show` with `state` and
    /// ends operations after `seconds` with `code`.
    struct FakeSystemctl {
        directory: tempfile::TempDir,
    }

    impl FakeSystemctl {
        fn new(state: &str, show_code: u8, seconds: u8, code: u8) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let log = directory.path().join("calls");
            let script = format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\nif [ \"$1\" = show ]; then printf '{state}'; exit {show_code}; fi\nsleep {seconds}\nexit {code}\n",
                log.display()
            );
            let program = directory.path().join("systemctl");
            std::fs::write(&program, script).unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
            FakeSystemctl { directory }
        }

        fn runner(&self) -> SystemdRunner {
            SystemdRunner::with_systemctl(&self.directory.path().join("systemctl"))
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(self.directory.path().join("calls")).unwrap_or_default()
        }
    }

    const IDLE: &str = "LoadState=loaded\\nActiveState=inactive\\nJob=\\n";
    const ACTIVE: &str = "LoadState=loaded\\nActiveState=active\\nJob=\\n";

    fn action(operation: Operation) -> Action {
        Action {
            id: "run_monitor".into(),
            title: "Monitor".into(),
            description: "d".into(),
            confirmation: "RUN".into(),
            unit: "m.service".into(),
            operation,
            cooldown_seconds: 0,
            timeout_seconds: 60,
            operator: true,
        }
    }

    fn state(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn busy_units_are_pending_jobs_transitions_or_running_starts() {
        let start = action(Operation::Start);
        let restart = action(Operation::Restart);
        assert!(!SystemdRunner::busy(
            &start,
            &state(&[("Job", ""), ("ActiveState", "inactive")])
        ));
        assert!(SystemdRunner::busy(
            &start,
            &state(&[("Job", "123 start running")])
        ));
        assert!(SystemdRunner::busy(
            &start,
            &state(&[("ActiveState", "reloading")])
        ));
        assert!(SystemdRunner::busy(
            &start,
            &state(&[("ActiveState", "active")])
        ));
        assert!(!SystemdRunner::busy(
            &restart,
            &state(&[("ActiveState", "active")])
        ));
        assert!(!SystemdRunner::busy(&restart, &state(&[("Job", "0")])));
    }

    #[test]
    fn preflight_needs_a_loaded_unit_without_pending_work() {
        let _turn = turn();
        let start = action(Operation::Start);
        let missing = FakeSystemctl::new("LoadState=not-found\\n", 0, 0, 0);
        assert_eq!(missing.runner().preflight(&start).unwrap_err().status, 503);
        let busy = FakeSystemctl::new("LoadState=loaded\\nJob=12 start running\\n", 0, 0, 0);
        assert_eq!(busy.runner().preflight(&start).unwrap_err().status, 409);
        assert!(busy.runner().still_running(&start));
        let unreadable = FakeSystemctl::new(IDLE, 1, 0, 0);
        assert_eq!(
            unreadable.runner().preflight(&start).unwrap_err().status,
            503
        );
        assert!(unreadable.runner().still_running(&start));
        let idle = FakeSystemctl::new(IDLE, 0, 0, 0);
        assert!(idle.runner().preflight(&start).is_ok());
        assert!(!idle.runner().still_running(&start));
        assert_eq!(
            idle.calls(),
            "show --property=LoadState,ActiveState,SubState,Result,Job --no-pager -- m.service\n"
                .repeat(2)
        );
    }

    #[test]
    fn a_start_reports_what_systemctl_answered() {
        let _turn = turn();
        let start = action(Operation::Start);
        let succeeding = FakeSystemctl::new(IDLE, 0, 0, 0);
        let outcome = succeeding.runner().run(&start);
        assert_eq!(
            (outcome.status, outcome.may_still_run),
            (JobStatus::Succeeded, false)
        );
        assert_eq!(succeeding.calls(), "--no-ask-password start -- m.service\n");
        let failing = FakeSystemctl::new(IDLE, 0, 0, 1);
        let outcome = failing.runner().run(&start);
        assert_eq!(
            (outcome.status, outcome.may_still_run),
            (JobStatus::Failed, false)
        );
        // A systemctl that cannot even start ran nothing, so the job failed.
        let missing = SystemdRunner::with_systemctl(Path::new("/nonexistent/systemctl"));
        let outcome = missing.run(&start);
        assert_eq!(
            (outcome.status, outcome.may_still_run),
            (JobStatus::Failed, false)
        );
    }

    #[test]
    fn a_restart_counts_only_when_the_unit_is_active_afterwards() {
        let _turn = turn();
        let restart = action(Operation::Restart);
        let active = FakeSystemctl::new(ACTIVE, 0, 0, 0);
        assert_eq!(active.runner().run(&restart).status, JobStatus::Succeeded);
        assert!(
            active
                .calls()
                .starts_with("--no-ask-password restart -- m.service\n")
        );
        let inactive = FakeSystemctl::new(IDLE, 0, 0, 0);
        assert_eq!(inactive.runner().run(&restart).status, JobStatus::Failed);
        let unreadable = FakeSystemctl::new(ACTIVE, 1, 0, 0);
        assert_eq!(
            unreadable.runner().run(&restart).status,
            JobStatus::Uncertain
        );
    }

    #[test]
    fn an_operation_past_its_timeout_may_still_run() {
        let _turn = turn();
        let slow = FakeSystemctl::new(IDLE, 0, 3, 0);
        let outcome = slow.runner().run(&Action {
            timeout_seconds: 1,
            ..action(Operation::Start)
        });
        assert_eq!(
            (outcome.status, outcome.may_still_run),
            (JobStatus::Uncertain, true)
        );
    }
}
