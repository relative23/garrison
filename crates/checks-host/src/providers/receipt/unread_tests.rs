//! Why a receipt that the card cannot read is not read, and what mends it.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::testing::{Canned, config, context, table};

/// A receipt only this user can change, whatever the umask.
fn write(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// A receipt the card cannot read says why, and what mends it: none there;
/// a folder on the way that the collector's user may not search; a file it
/// may not open, as one a job writes under umask 027 or 077 (both shown
/// without root, by mode 000); a link or no plain file; and a file too large
/// or no JSON object or list. Each is Unknown.
#[test]
fn an_unreadable_receipt_says_why_and_what_mends_it() {
    let directory = tempfile::tempdir().unwrap();
    let folder = directory.path().join("jobs");
    std::fs::create_dir(&folder).unwrap();
    let path = folder.join("receipt.json");
    let (shown, there) = (path.display().to_string(), folder.display().to_string());
    let receipt = Receipt::new(&table(&format!(
        "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{shown}\"\nmodules = [\"backups\"]"
    )))
    .unwrap();
    let (config, runner) = (config(directory.path()), Canned(String::new()));
    let card = || {
        let observation = receipt
            .collect(&context(&config, &runner))
            .unwrap()
            .observations
            .remove(0);
        assert_eq!(
            observation.state,
            State::Unknown,
            "{:?}",
            observation.findings
        );
        observation.findings
    };
    assert_eq!(
        card(),
        [format!(
            "No receipt at {shown}: the job that writes it has written none there."
        )]
    );
    let large = format!("{{\"log\": \"{}\"}}", "x".repeat(1024 * 1024));
    for written in ["", "not json", "\"a text\"", large.as_str()] {
        write(&path, written);
        assert_eq!(
            card(),
            [format!(
                "The receipt at {shown} cannot be read: it must be at most 1024 KiB of JSON, \
                 an object or a list."
            )],
            "{written:.20}"
        );
    }
    write(&path, r#"{"date": "2026-10-29T11:00:00Z"}"#);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&path).is_err() {
        assert_eq!(
            card(),
            [format!(
                "The receipt at {shown} is there, but the collector's user may not open it: \
                 let the job write it with mode 0644 (chmod 0644 {shown})."
            )]
        );
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::symlink_metadata(&path).is_err() {
        assert_eq!(
            card(),
            [format!(
                "The receipt at {shown} cannot be looked for: the collector's user may not \
                 search the folder {there}; let every user search it (chmod o+x {there})."
            )]
        );
    }
    std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(directory.path().join("elsewhere.json"), &path).unwrap();
    assert_eq!(
        card(),
        [format!(
            "The receipt at {shown} is a link, which is not followed: let the job write the \
             file there itself."
        )]
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(
        card(),
        [format!(
            "The receipt at {shown} is no plain file: let the job write it there as one."
        )]
    );
}
