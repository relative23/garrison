//! The collector's commands (`systemctl show`, `--version` calls), each with
//! eight seconds to finish, and the same time for a file system that a
//! check reads.

use std::io;
use std::time::{Duration, Instant};

pub use garrison_core::command::Output;

/// The seconds the collector gives a command before it ends it, and that a
/// check gives the file systems it reads.
pub const SECONDS: u64 = 8;
const TIMEOUT: Duration = Duration::from_secs(SECONDS);

/// By when a check that begins to read the host's file systems now must
/// have their answers: one that does not answer, as a hard NFS mount whose
/// server is gone, costs that check this time once, and the run's other
/// checks nothing (`garrison_core::files::answered_by`).
#[must_use]
pub fn patience() -> Instant {
    Instant::now() + TIMEOUT
}

/// Whether `error` says that a file system gave no answer in that time.
#[must_use]
pub fn silent(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::TimedOut
}

pub trait Runner {
    fn run(&self, arguments: &[&str]) -> io::Result<Output>;
}

/// Runs real commands.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, arguments: &[&str]) -> io::Result<Output> {
        garrison_core::command::run(arguments, TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_commands_run_with_the_collector_time_limit() {
        let output = SystemRunner.run(&["/bin/echo", "ready"]).unwrap();
        assert_eq!((output.code, output.stdout.as_str()), (Some(0), "ready\n"));
    }
}
