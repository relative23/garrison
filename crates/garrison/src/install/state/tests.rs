use rusqlite::Connection;

use super::*;

/// A database at `path` with schema `version` and one row that says `note`.
fn database(path: &Path, version: i64, note: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let _ = fs::remove_file(path);
    Connection::open(path)
        .unwrap()
        .execute_batch(&format!(
            "CREATE TABLE notes(text TEXT); INSERT INTO notes VALUES('{note}'); \
             PRAGMA user_version = {version};"
        ))
        .unwrap();
}

fn note(path: &Path) -> String {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT text FROM notes", [], |row| row.get(0))
        .unwrap()
}

/// The state before an upgrade, its backup, and what a new release left
/// when its start failed: the status database migrated, a jobs database
/// made, and events recorded since the backup.
fn failed_upgrade(root: &Path) -> (Config, std::path::PathBuf) {
    let config = garrison_testing::config(&root.join("state"), "http://127.0.0.1:9");
    let backup = root.join("backup");
    for kept in [Database::Web, Database::Events, Database::Status] {
        database(&copy_of(&backup, kept), 1, "before the upgrade");
    }
    fs::write(
        backup.join("backup.json"),
        r#"{"createdAt": "2026-11-14T12:00:00+00:00", "release": "0.1.2",
            "databases": {"web": "copied", "ingest": "copied", "collector": "copied",
                          "broker": "absent"}}"#,
    )
    .unwrap();
    database(&config.database(Database::Web), 1, "a session since");
    database(&config.database(Database::Events), 1, "an event since");
    database(&config.database(Database::Status), 2, "migrated");
    database(
        &config.database(Database::Jobs),
        3,
        "made by the new release",
    );
    (config, backup)
}

#[test]
fn only_what_the_new_release_changed_goes_back_after_a_failed_upgrade() {
    let directory = tempfile::tempdir().unwrap();
    let (config, backup) = failed_upgrade(directory.path());
    // SQLite's files beside a database that goes back must not outlive it.
    let status = config.database(Database::Status);
    let journal = status.with_file_name("status.sqlite-journal");
    fs::write(&journal, "stale").unwrap();

    let mut returned = Returned::default();
    restore_migrated(&backup, &config, &mut returned).unwrap();
    assert_eq!(
        (returned.back, returned.removed),
        (vec!["collector"], vec!["broker"])
    );
    // The schema that rose is the one from before again, with its data.
    assert_eq!(crate::ops::stored_version(&status), Some(1));
    assert_eq!(note(&status), "before the upgrade");
    assert!(!journal.exists());
    // What the old release can read keeps what was recorded since.
    assert_eq!(note(&config.database(Database::Web)), "a session since");
    assert_eq!(note(&config.database(Database::Events)), "an event since");
    // A database that did not exist before is not left for a release
    // that could not read it.
    assert!(!config.database(Database::Jobs).exists());
    // A second time there is nothing left to return.
    let mut again = Returned::default();
    restore_migrated(&backup, &config, &mut again).unwrap();
    assert_eq!(again, Returned::default());
}

#[test]
fn a_database_that_can_no_longer_be_read_goes_back_too() {
    let directory = tempfile::tempdir().unwrap();
    let (config, backup) = failed_upgrade(directory.path());
    let events = config.database(Database::Events);
    fs::write(&events, "not a database").unwrap();
    let mut returned = Returned::default();
    restore_migrated(&backup, &config, &mut returned).unwrap();
    assert_eq!(returned.back, ["ingest", "collector"]);
    assert_eq!(note(&events), "before the upgrade");
}

/// A copy larger than the room beside its database is refused before any
/// goes back, without a margin; a sparse file stands in for a large copy.
/// Where they fit, the sentence names what went back and what was removed
/// apart.
#[test]
fn a_switch_back_puts_nothing_back_where_a_copy_does_not_fit() {
    let directory = tempfile::tempdir().unwrap();
    let (config, backup) = failed_upgrade(directory.path());
    let copy = fs::OpenOptions::new()
        .write(true)
        .open(copy_of(&backup, Database::Status))
        .unwrap();
    let stat = rustix::fs::statvfs(directory.path()).unwrap();
    copy.set_len(stat.f_bavail * stat.f_frsize + (1 << 20))
        .unwrap();
    let mut returned = Returned::default();
    let refused = restore_migrated(&backup, &config, &mut returned).unwrap_err();
    assert_eq!(refused.name, "install-copies-no-room");
    assert_eq!(returned, Returned::default());
    let status = config.database(Database::Status);
    assert_eq!(crate::ops::stored_version(&status), Some(2));
    assert!(config.database(Database::Jobs).exists());
    let said = Returned {
        back: vec!["collector"],
        removed: vec!["broker"],
    }
    .said(&backup);
    assert_eq!(
        said,
        states::went_back(&backup, &["collector"], &["broker"])
    );
}

#[test]
fn the_whole_state_goes_back_and_what_did_not_exist_is_removed() {
    let directory = tempfile::tempdir().unwrap();
    let (config, backup) = failed_upgrade(directory.path());
    fs::write(backup.join(crate::ops::POLICY_COPY), "{}").unwrap();
    fs::create_dir_all(config.broker.policy.parent().unwrap()).unwrap();
    let mut restored = Returned::default();
    restore_all(&backup, &config, own(), &mut restored).unwrap();
    // The jobs database had no copy: it was removed, and is named so.
    assert_eq!(
        restored.back,
        ["web", "ingest", "collector", "the access policy"]
    );
    assert_eq!(restored.removed, ["broker"]);
    assert_eq!(
        restored.said(&backup),
        states::went_back(&backup, &restored.back, &["broker"])
    );
    assert_eq!(Returned::default().said(&backup), None);
    for kept in [Database::Web, Database::Events, Database::Status] {
        assert_eq!(note(&config.database(kept)), "before the upgrade");
    }
    assert!(!config.database(Database::Jobs).exists());
    assert_eq!(fs::read_to_string(&config.broker.policy).unwrap(), "{}");
    // A backup that does not say what was absent removes nothing.
    database(&config.database(Database::Jobs), 3, "kept");
    fs::remove_file(backup.join("backup.json")).unwrap();
    restore_all(&backup, &config, own(), &mut Returned::default()).unwrap();
    assert_eq!(note(&config.database(Database::Jobs)), "kept");
}

/// The policy goes back only as a file of its own: a link that
/// `broker.policy` names stays as it is, and so does what it points to.
#[test]
fn the_policy_never_goes_back_through_a_link() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let (config, backup) = failed_upgrade(directory.path());
    fs::write(backup.join(crate::ops::POLICY_COPY), "{\"restored\": true}").unwrap();
    let victim = directory.path().join("passwd");
    fs::write(&victim, "root:x:0:0::/root:/bin/sh\n").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
    fs::create_dir_all(config.broker.policy.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&victim, &config.broker.policy).unwrap();
    let mut restored = Returned::default();
    let refused = restore_all(&backup, &config, own(), &mut restored).unwrap_err();
    assert_eq!(refused, states::policy_left(&config.broker.policy));
    // What went back before the policy is named as such.
    assert_eq!(restored.back, ["web", "ingest", "collector"]);
    assert_eq!(restored.removed, ["broker"]);
    assert_eq!(
        fs::read_to_string(&victim).unwrap(),
        "root:x:0:0::/root:/bin/sh\n"
    );
    assert_eq!(mode(&victim), 0o644);
    assert!(
        fs::symlink_metadata(&config.broker.policy)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    // Nor into a folder of that name, which keeps what it holds.
    fs::remove_file(&config.broker.policy).unwrap();
    fs::create_dir(&config.broker.policy).unwrap();
    fs::write(config.broker.policy.join("mail"), "kept").unwrap();
    assert!(restore_all(&backup, &config, own(), &mut Returned::default()).is_err());
    let kept = fs::read_to_string(config.broker.policy.join("mail")).unwrap();
    assert_eq!(kept, "kept");
}

/// Where no policy is there yet, or one that others may read, the copy
/// becomes a new file of the owner's with mode 0640; the folder's owner
/// does not count, unlike for a database.
#[test]
fn the_policy_goes_back_as_a_new_file_of_its_owner() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempfile::tempdir().unwrap();
    let (config, backup) = failed_upgrade(directory.path());
    fs::write(backup.join(crate::ops::POLICY_COPY), "{\"restored\": true}").unwrap();
    let policy = &config.broker.policy;
    fs::create_dir_all(policy.parent().unwrap()).unwrap();
    for before in [None, Some(0o644)] {
        if let Some(mode) = before {
            fs::write(policy, "{}").unwrap();
            fs::set_permissions(policy, fs::Permissions::from_mode(mode)).unwrap();
        }
        restore_all(&backup, &config, own(), &mut Returned::default()).unwrap();
        let written = fs::symlink_metadata(policy).unwrap();
        assert!(written.file_type().is_file());
        assert_eq!(mode(policy), 0o640);
        let (uid, gid) = own();
        assert_eq!((written.uid(), written.gid()), (uid.as_raw(), gid.as_raw()));
        assert_eq!(fs::read_to_string(policy).unwrap(), "{\"restored\": true}");
        assert!(fs::remove_file(policy).is_ok());
    }
}

/// The test's own user and group stand in for root and the broker's.
fn own() -> (Uid, Gid) {
    (rustix::process::getuid(), rustix::process::getgid())
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_state_written_by_a_newer_release_does_not_suit_an_older_one() {
    let directory = tempfile::tempdir().unwrap();
    let (_, backup) = failed_upgrade(directory.path());
    // Written by 0.1.2: it suits 0.1.2 and what came after it.
    assert_eq!(unsuited(&backup, "0.1.2"), None);
    assert_eq!(unsuited(&backup, "0.2.0"), None);
    assert_eq!(
        unsuited(&backup, "0.1.1"),
        Some(states::state_newer(&backup, "0.1.2", "0.1.1"))
    );
    // A backup that does not name its release is taken as before.
    fs::write(backup.join("backup.json"), r#"{"databases": {}}"#).unwrap();
    assert_eq!(unsuited(&backup, "0.1.1"), None);
    fs::remove_file(backup.join("backup.json")).unwrap();
    assert_eq!(unsuited(&backup, "0.1.1"), None);
}

/// A release's self-check names each database it cannot read, with why; a
/// report in another form is passed on in its own words.
#[test]
fn what_a_self_check_cannot_read_is_named() {
    let report = serde_json::json!({
        "result": "failed",
        "databases": {
            "web": {"ok": true, "integrity": "ok", "schemaVersion": 3, "rows": {}},
            "collector": {"ok": false, "integrity": "ok", "schemaVersion": 2, "rows": {}},
            "ingest": {"ok": false, "integrity": "unreadable (file is not a database)",
                "schemaVersion": null, "rows": {}},
            "broker": {"ok": null, "absent": true}
        },
        "message": "Problems in: collector, ingest"
    });
    assert_eq!(
        unreadable(report.to_string().as_bytes()),
        "collector (schema 2, integrity ok), ingest (schema unknown, integrity unreadable (file is \
         not a database))"
    );
    assert_eq!(
        unreadable(b"  Cannot load the configuration\n"),
        "Cannot load the configuration"
    );
}
