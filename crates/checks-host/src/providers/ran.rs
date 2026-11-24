//! What the checks of this crate give a command and a file system to
//! answer, and what they say of one that gave no answer.

use std::io;
use std::time::{Duration, Instant};

/// The seconds the collector gives a command before it ends it, as its
/// runner does (`garrison_checks::command`), and that a check gives the
/// file systems it reads.
pub(crate) const SECONDS: u64 = 8;

/// By when a check that begins to read the host's file systems now must
/// have their answers: one that does not answer, as a hard NFS mount whose
/// server is gone, costs that check this time once, and the run's other
/// checks nothing (`garrison_core::files::answered_by`).
pub(crate) fn patience() -> Instant {
    Instant::now() + Duration::from_secs(SECONDS)
}

/// Whether `error` says that a file system gave no answer in that time.
pub(crate) fn silent(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::TimedOut
}

/// Why `program` gave no answer: it could not be started, or it gave none
/// in the collector's time for a command. The runner does not tell apart a
/// command that did not finish, which it ends, from one that exited and
/// left a process behind that keeps its output open, which runs on.
pub(crate) fn not_run(program: &str, error: &io::Error) -> String {
    if error.kind() == io::ErrorKind::TimedOut {
        format!("{program} did not answer within {SECONDS} seconds")
    } else {
        format!("{program} could not be run: {error}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seconds named are the runner's.
    #[test]
    fn the_time_for_a_command_is_the_runners() {
        let runner = include_str!("../../../checks/src/command.rs");
        let limit = format!("const TIMEOUT: Duration = Duration::from_secs({SECONDS});");
        assert!(runner.contains(&limit), "{limit}");
    }
}
