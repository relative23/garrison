//! What the checks of this crate say of a command that gave no answer.

use std::io;

/// The seconds the collector gives a command before it ends it, as its
/// runner does (`garrison_checks::command`).
const COMMAND_SECONDS: u64 = 8;

/// Why `program` gave no answer: it could not be started, or it did not
/// finish in the collector's time for a command and was ended.
pub(crate) fn not_run(program: &str, error: &io::Error) -> String {
    if error.kind() == io::ErrorKind::TimedOut {
        format!("{program} did not finish within {COMMAND_SECONDS} seconds and was ended")
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
        let limit = format!("const TIMEOUT: Duration = Duration::from_secs({COMMAND_SECONDS});");
        assert!(runner.contains(&limit), "{limit}");
    }
}
