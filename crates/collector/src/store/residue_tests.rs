//! What earlier releases kept of a key of Spamhaus' Data Query Service: the
//! first run of this release leaves no copy of it anywhere in the status
//! database's files, in a row, a free page or a journal, while readers go on
//! reading, and the file keeps its owner, group, mode and SELinux label.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fs, thread};

use garrison_core::sqlite::reading;
use garrison_core::time;
use rusqlite::{Connection, params};

use super::*;

const KEY: &str = "abcdefghijklmnopqrstuvwxyz";

/// The files of `folder` whose bytes hold the key.
fn holding(folder: &Path) -> Vec<String> {
    let mut files: Vec<String> = fs::read_dir(folder)
        .unwrap()
        .flatten()
        .filter(|entry| {
            fs::read(entry.path())
                .unwrap()
                .windows(KEY.len())
                .any(|window| window == KEY.as_bytes())
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    files
}

/// The SELinux label of the file at `path`, where it has one.
fn label(path: &Path) -> Option<Vec<u8>> {
    replace::attribute_of(&File::open(path).unwrap(), "security.selinux").unwrap()
}

/// A status database as a release before this one left it: the reputation
/// check's reading, the notifications' memory of a listing and the newest
/// snapshots name a zone with its key, and the snapshots before them, which
/// the store dropped, did too, so the key stands in free pages as well.
fn as_an_earlier_release_left_it(path: &Path) {
    drop(StatusStore::open(path, 90).unwrap());
    let db = Connection::open(path).unwrap();
    // What this release notes of its own, an earlier one never wrote.
    db.execute("DELETE FROM memory WHERE key LIKE 'store.%'", [])
        .unwrap();
    let zone = format!("{KEY}.zen.dq.spamhaus.net");
    let listed = format!("203.0.113.5 is listed on {zone} (127.0.0.2).");
    for id in 1..=40 {
        let document = format!(
            "{{\"observations\": [{{\"id\": \"reputation.blocklists\", \"findings\": [\"{listed}\"]}}], \
             \"pad\": \"{}\"}}",
            "x".repeat(3000)
        );
        db.execute(
            "INSERT INTO snapshots(id, collected_at, document) VALUES(?1, ?1, ?2)",
            params![id, document],
        )
        .unwrap();
    }
    db.execute("DELETE FROM snapshots WHERE id <= 30", [])
        .unwrap();
    let reading = format!(
        "{{\"at\": 1, \"addresses\": [{{\"lists\": [[\"{zone}\", \"Clear\"], [\"{zone}\", \
         {{\"Unanswered\": \"5.113.0.203.{zone} is no DNS name\"}}]]}}]}}"
    );
    let open = format!("{{\"reputation.blocklists\": {{\"detail\": \"{listed}\"}}}}");
    for (key, value) in [("reputation.read", reading), ("notify.open", open)] {
        db.execute(
            "INSERT OR REPLACE INTO memory(key, value) VALUES(?1, ?2)",
            params![key, value],
        )
        .unwrap();
    }
}

#[test]
fn the_first_run_of_this_release_leaves_no_copy_of_a_dqs_key_in_the_status_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    as_an_earlier_release_left_it(&path);
    // The test's own residue, in the rows and the free pages.
    assert_eq!(holding(directory.path()), ["status.sqlite"]);
    let before = fs::metadata(&path).unwrap();
    let label_before = label(&path);
    // The web service reads the database for each request meanwhile.
    let (stop, failed) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let reader = thread::spawn({
        let (path, stop, failed) = (path.clone(), Arc::clone(&stop), Arc::clone(&failed));
        move || {
            let mut reads = 0;
            while !stop.load(Ordering::SeqCst) {
                let read = reading(&path, Duration::from_secs(2))
                    .ok()
                    .flatten()
                    .and_then(|db| {
                        db.query_row("SELECT count(*) FROM snapshots", [], |row| {
                            row.get::<_, i64>(0)
                        })
                        .ok()
                    });
                if read != Some(10) {
                    failed.store(true, Ordering::SeqCst);
                }
                reads += 1;
            }
            reads
        }
    });
    thread::sleep(Duration::from_millis(50));
    // The run's last step, once its snapshot is stored.
    let mut store = StatusStore::open(&path, 90).unwrap();
    store.clear_residue(
        time::now().as_second(),
        Instant::now() + Duration::from_secs(120),
    );
    thread::sleep(Duration::from_millis(50));
    stop.store(true, Ordering::SeqCst);
    let reads = reader.join().unwrap();
    assert!(reads > 0 && !failed.load(Ordering::SeqCst), "{reads} reads");
    drop(store);
    assert_eq!(holding(directory.path()), Vec::<String>::new());
    // A file of its own now, made as the one it replaced.
    let after = fs::metadata(&path).unwrap();
    assert_ne!(after.ino(), before.ino());
    assert_eq!(
        (after.uid(), after.gid(), after.mode()),
        (before.uid(), before.gid(), before.mode())
    );
    assert_eq!(label(&path), label_before);
    // The rows read on, with the zone named without its key.
    let db = Connection::open(&path).unwrap();
    let kept: String = db
        .query_row(
            "SELECT value FROM memory WHERE key = 'reputation.read'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        kept.contains("[\"….zen.dq.spamhaus.net\", \"Clear\"]"),
        "{kept}"
    );
    assert!(
        kept.contains("5.113.0.203.….zen.dq.spamhaus.net is no DNS name"),
        "{kept}"
    );
    let newest: String = db
        .query_row(
            "SELECT document FROM snapshots ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        newest.contains("is listed on ….zen.dq.spamhaus.net (127.0.0.2)."),
        "{newest}"
    );
}

/// What a run that ran out of time before the copy was done leaves: the
/// database as it was, no copy, and a day's wait before the next rebuild,
/// which a disk too slow for it would otherwise write in every run.
#[test]
fn a_rebuild_out_of_time_leaves_the_database_as_it_was_and_waits_a_day() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    as_an_earlier_release_left_it(&path);
    // A history, so that the copy takes long enough to be stopped midway.
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 5000)
         INSERT INTO samples(name, ts, value, kind) SELECT 'gauge', i * 60, i, 'gauge' FROM n",
    )
    .unwrap();
    drop(db);
    let mut store = StatusStore::open(&path, 90).unwrap();
    let now = time::now().as_second();
    assert!(residue::due(&store.db, &path, now).unwrap());
    let late = residue::clear(&mut store.db, &path, now, Instant::now());
    assert!(matches!(late, Err(residue::Unfinished::Late)), "{late:?}");
    assert_eq!(holding(directory.path()), ["status.sqlite"]);
    assert!(!replace::copy_of(&path).exists());
    for later in [0, 3600, 86_399] {
        assert!(
            !residue::due(&store.db, &path, now + later).unwrap(),
            "{later}"
        );
    }
    // A day on, or a clock that went back since, it is due again.
    assert!(residue::due(&store.db, &path, now + 86_400).unwrap());
    assert!(residue::due(&store.db, &path, now - 60).unwrap());
    store.clear_residue(now + 86_400, Instant::now() + Duration::from_secs(120));
    assert_eq!(holding(directory.path()), Vec::<String>::new());
    assert!(!residue::due(&store.db, &path, now + 86_400).unwrap());
}

/// A rebuild that fails, as on a full disk, costs nothing but the rebuild:
/// no copy stays, the store reads and writes on, and the next run tries
/// again. Here the copy's place is taken by a folder.
#[test]
fn a_rebuild_that_fails_leaves_no_copy_and_the_next_run_tries_again() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    as_an_earlier_release_left_it(&path);
    let mut store = StatusStore::open(&path, 90).unwrap();
    let taken = replace::copy_of(&path);
    fs::create_dir(&taken).unwrap();
    let now = time::now().as_second();
    let failed = residue::clear(
        &mut store.db,
        &path,
        now,
        Instant::now() + Duration::from_secs(120),
    );
    assert!(
        matches!(failed, Err(residue::Unfinished::Failed(_))),
        "{failed:?}"
    );
    assert!(taken.is_dir());
    assert!(residue::due(&store.db, &path, now).unwrap());
    store.keep("check.value", "kept");
    assert_eq!(store.recall("check.value").as_deref(), Some("kept"));
    fs::remove_dir(&taken).unwrap();
    store.clear_residue(now, Instant::now() + Duration::from_secs(120));
    assert_eq!(holding(directory.path()), Vec::<String>::new());
    assert_eq!(store.recall("check.value").as_deref(), Some("kept"));
}

/// A run that leaves less time than a rebuild may need begins none; a
/// later run does it. A copy that a rebuild ended midway left, which may
/// hold the key, goes when the store opens, with its journal.
#[test]
fn a_late_run_begins_no_rebuild_and_a_copy_left_behind_goes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    as_an_earlier_release_left_it(&path);
    let mut store = StatusStore::open(&path, 90).unwrap();
    let now = time::now().as_second();
    store.clear_residue(now, Instant::now() + Duration::from_secs(10));
    assert_eq!(holding(directory.path()), ["status.sqlite"]);
    assert!(residue::due(&store.db, &path, now).unwrap());
    drop(store);
    // As a run ended in the copy's last transaction leaves them.
    let copy = replace::copy_of(&path);
    fs::copy(&path, &copy).unwrap();
    let journal = copy.with_file_name("status.sqlite-clearing-journal");
    fs::write(&journal, KEY).unwrap();
    let store = StatusStore::open(&path, 90).unwrap();
    assert!(!copy.exists() && !journal.exists());
    drop(store);
}

/// The copy is made as the database is: its mode, owner and group, and an
/// attribute such as the SELinux label, which this host cannot set, so the
/// test copies one of the user's own.
#[test]
fn the_copy_is_made_with_the_mode_owner_group_and_label_of_the_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("status.sqlite");
    drop(StatusStore::open(&path, 90).unwrap());
    let attribute = "user.garrison-test";
    let live = File::open(&path).unwrap();
    let set = rustix::fs::fsetxattr(&live, attribute, b"label", rustix::fs::XattrFlags::empty());
    let copy = replace::copy_of(&path);
    replace::made_with(&path, &copy, attribute).unwrap();
    let (before, after) = (fs::metadata(&path).unwrap(), fs::metadata(&copy).unwrap());
    assert_eq!(
        (after.uid(), after.gid(), after.mode(), after.len()),
        (before.uid(), before.gid(), before.mode(), 0)
    );
    if set.is_ok() {
        assert_eq!(
            replace::attribute_of(&File::open(&copy).unwrap(), attribute).unwrap(),
            Some(b"label".to_vec())
        );
    }
}
