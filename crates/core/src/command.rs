//! Local commands with a time limit (`systemctl`, `--version` calls).
//!
//! Commands and their arguments come only from reviewed configuration; nothing
//! is passed through a shell. A command still running at its deadline is
//! killed; for `systemctl` that ends only the client, never the systemd job.

use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_OUTPUT: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// The exit code; `None` if a signal ended the command.
    pub code: Option<i32>,
    /// Standard output, decoded as UTF-8 with replacement characters.
    pub stdout: String,
}

/// Run `arguments` (the program first) and wait at most `timeout`. Standard
/// error is discarded; a timeout is [`io::ErrorKind::TimedOut`], also when a
/// child the command left behind keeps its output open.
pub fn run(arguments: &[&str], timeout: Duration) -> io::Result<Output> {
    let (program, rest) = arguments
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no command"))?;
    let mut child = Command::new(program)
        .args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take();
    let (sender, output) = mpsc::channel();
    thread::spawn(move || {
        let mut data = Vec::new();
        if let Some(stdout) = stdout {
            let _ = stdout.take(MAX_OUTPUT).read_to_end(&mut data);
        }
        let _ = sender.send(data);
    });
    let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "command timed out");
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(timed_out());
        }
        thread::sleep(Duration::from_millis(20));
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let data = output.recv_timeout(remaining).map_err(|_| timed_out())?;
    Ok(Output {
        code: status.code(),
        stdout: String::from_utf8_lossy(&data).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn output_beyond_one_mebibyte_is_cut() {
        let output = run(&["/bin/sh", "-c", "head -c 1048577 /dev/zero"], 10 * SECOND).unwrap();
        assert_eq!(output.stdout.len(), 1024 * 1024);
    }

    #[test]
    fn output_and_exit_codes_are_returned() {
        let output = run(&["/bin/sh", "-c", "echo hello; exit 3"], SECOND).unwrap();
        assert_eq!(
            output,
            Output {
                code: Some(3),
                stdout: "hello\n".into()
            }
        );
        let missing = run(&["/nonexistent/command"], SECOND).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_command_past_its_deadline_is_killed() {
        let started = Instant::now();
        let error = run(&["/bin/sleep", "5"], Duration::from_millis(200)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn output_held_open_by_a_leftover_child_ends_at_the_deadline() {
        let started = Instant::now();
        let error = run(
            &["/bin/sh", "-c", "/bin/sleep 5 & echo started"],
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
