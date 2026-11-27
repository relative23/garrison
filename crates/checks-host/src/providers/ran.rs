//! What the checks of this crate give a command and a file system to
//! answer, and what they say of one that gave no answer.

use std::io;

// The seconds the collector gives a command before it ends it, and that a
// check gives the file systems it reads, as its runner names them.
pub(crate) use crate::command::{SECONDS, patience, silent};

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
        assert_eq!(SECONDS, 8);
        for line in [
            "pub const SECONDS: u64 = 8;",
            "const TIMEOUT: Duration = Duration::from_secs(SECONDS);",
        ] {
            assert!(runner.contains(line), "{line}");
        }
    }
}
