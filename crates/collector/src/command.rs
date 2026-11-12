//! The collector's commands (`systemctl show`, `--version` calls), each with
//! eight seconds to finish.

use std::io;
use std::time::Duration;

pub use garrison_core::command::Output;

const TIMEOUT: Duration = Duration::from_secs(8);

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
