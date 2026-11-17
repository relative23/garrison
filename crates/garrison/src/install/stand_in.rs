//! A stand-in for a release, for the tests: `bin/garrison` as a script.
//!
//! A shell of its own writes the script, never the test: a child that
//! another test thread starts while the test holds a file open for writing
//! keeps a copy of that descriptor until it runs its program, and the
//! kernel refuses to run a file that is open for writing ("Text file
//! busy"). No descriptor of the test's own process ever writes the file.

use std::io::Write;
use std::process::{Command, Stdio};

/// A release whose command runs `script` with its arguments.
pub(super) fn release(script: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("bin")).unwrap();
    let mut writer = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(directory.path().join("bin/garrison"))
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = writer.stdin.take().unwrap();
    input
        .write_all(format!("#!/bin/sh\n{script}\n").as_bytes())
        .unwrap();
    drop(input);
    assert!(writer.wait().unwrap().success());
    directory
}
