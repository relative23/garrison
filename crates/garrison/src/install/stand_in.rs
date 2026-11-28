//! A stand-in for a release, for the tests: `bin/garrison` as a script,
//! written as a test's program must be (`garrison_testing::write_program`).

/// A release whose command runs `script` with its arguments.
pub(super) fn release(script: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("bin")).unwrap();
    garrison_testing::write_program(
        &directory.path().join("bin/garrison"),
        &format!("#!/bin/sh\n{script}\n"),
    );
    directory
}
