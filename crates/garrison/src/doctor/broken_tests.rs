//! doctor's lines on hosts that are broken in one way each. A line that
//! says "ok" has looked at what it claims, as the service that needs it
//! meets it; one that could not look says so with the reason; and a fix it
//! names works from the state it found. So on each host here the check that
//! looks at what is broken must say something other than "ok", with the fix
//! that mends it, or, where it could not look, why.

use std::fs;

use garrison_core::config::Database;

use super::{Finding, Level, host};

/// A host broken in one way, and what doctor must say of it.
struct Broken {
    /// What is broken.
    host: &'static str,
    /// What the check that looks at it found there.
    found: Vec<Finding>,
    /// Words of the line that must say it.
    said: String,
    /// Words its fix must hold; `None` for a line that says why the check
    /// could not look, which is unknown and names no fix.
    fix: Option<String>,
}

/// The events database is a folder, as a restore gone wrong may leave it:
/// whether events arrive is not known, which is not "none recorded yet".
fn events_database_is_a_folder() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    fs::create_dir_all(config.database(Database::Events)).unwrap();
    Broken {
        host: "an events database that is a folder",
        found: vec![host::events(&config)],
        said: "the events database".into(),
        fix: None,
    }
}

const HOSTS: [fn() -> Broken; 1] = [events_database_is_a_folder];

#[test]
fn on_a_broken_host_no_check_says_ok_of_what_is_broken() {
    for host in HOSTS {
        let broken = host();
        let lines: Vec<String> = broken.found.iter().map(Finding::line).collect();
        let finding = broken
            .found
            .iter()
            .find(|finding| finding.what.contains(&broken.said))
            .unwrap_or_else(|| {
                panic!(
                    "{}: no line says {:?}:\n{}",
                    broken.host,
                    broken.said,
                    lines.join("\n")
                )
            });
        assert_ne!(
            finding.level,
            Level::Ok,
            "{}: {}",
            broken.host,
            finding.line()
        );
        match &broken.fix {
            Some(fix) => assert!(
                finding
                    .fix
                    .as_deref()
                    .is_some_and(|text| text.contains(fix.as_str())),
                "{}: the fix does not name {fix:?}: {}",
                broken.host,
                finding.line()
            ),
            None => assert_eq!(
                finding.level,
                Level::Unknown,
                "{}: {}",
                broken.host,
                finding.line()
            ),
        }
    }
}
