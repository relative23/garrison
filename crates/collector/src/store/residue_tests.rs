//! What earlier releases kept of a key of Spamhaus' Data Query Service: the
//! first run of this release leaves no copy of it anywhere in the status
//! database's files, in a row, a free page or a journal, while readers go on
//! reading and the file keeps its inode, owner and mode.

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{fs, thread};

use garrison_core::sqlite::reading;
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
    let store = StatusStore::open(&path, 90).unwrap();
    thread::sleep(Duration::from_millis(50));
    stop.store(true, Ordering::SeqCst);
    let reads = reader.join().unwrap();
    assert!(reads > 0 && !failed.load(Ordering::SeqCst), "{reads} reads");
    drop(store);
    assert_eq!(holding(directory.path()), Vec::<String>::new());
    let after = fs::metadata(&path).unwrap();
    assert_eq!(
        (after.ino(), after.uid(), after.mode()),
        (before.ino(), before.uid(), before.mode())
    );
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
