use std::collections::BTreeMap;

use garrison_collector::snapshot::{SCHEMA, Snapshot};
use garrison_collector::store::StatusStore;

use super::super::Level;
use super::super::states::selinux as said;
use super::*;

const NOW: i64 = 1_794_000_000;

fn judged(last: Result<Option<i64>, String>) -> Finding {
    finished(last, time::Timestamp::from_second(NOW).unwrap())
}

/// The level and the name of a finding.
fn named(finding: &Finding) -> (Level, &str) {
    (finding.level, finding.state.name)
}

#[test]
fn the_collector_is_judged_by_its_newest_snapshot_as_the_watch_judges_it() {
    assert_eq!(
        judged(Ok(Some(NOW - 90))),
        Finding::ok(states::collection_recent(90))
    );
    assert_eq!(
        named(&judged(Ok(Some(NOW - watch::LIMIT)))),
        (Level::Ok, "doctor-collection-recent")
    );
    // A run that never was is not a success, and not yet a failure.
    assert_eq!(judged(Ok(None)), Finding::warn(states::no_collection()));
    // Stopped, failed and unknown stay three answers.
    let last = NOW - watch::LIMIT - 1;
    assert_eq!(
        judged(Ok(Some(last))),
        Finding::fail(states::collection_stopped(last, NOW - last))
    );
    assert_eq!(
        judged(Err("file is not a database".to_owned())),
        Finding::unknown(states::collection_unreadable("file is not a database"))
    );
    // A date from the future gives no age; a few minutes are the clock's
    // own small corrections, and no age below zero.
    assert_eq!(
        judged(Ok(Some(NOW + 3600))),
        Finding::warn(states::snapshot_ahead(3600))
    );
    assert_eq!(
        judged(Ok(Some(NOW + 120))),
        Finding::ok(states::collection_recent(0))
    );
}

/// A damaged or hand-edited status database may date its newest snapshot
/// at a time that is none: it gives no age, and no stop either.
#[test]
fn a_snapshot_dated_at_no_time_gives_no_age() {
    for when in [i64::MIN, i64::MAX] {
        assert_eq!(
            judged(Ok(Some(when))),
            Finding::unknown(states::collection_undated(when))
        );
    }
}

/// A history without an event, or none at all, is no event yet; one that
/// cannot be read says nothing of whether events arrive, and the line says
/// why instead, as the status database's does.
#[test]
fn an_events_database_that_cannot_be_read_is_unknown_with_the_reason() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let path = config.database(Database::Events);
    assert_eq!(events(&config), Finding::warn(states::no_event()));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE events(received_at INTEGER NOT NULL)")
        .unwrap();
    drop(db);
    assert_eq!(events(&config), Finding::warn(states::no_event()));
    fs::write(&path, "no database").unwrap();
    let why = newest_event(&path).unwrap_err();
    assert_eq!(
        events(&config),
        Finding::unknown(states::events_unreadable(&path, &why))
    );
}

/// A damaged or hand-edited event history may record its newest event
/// at a time that is none: that is no arrival minutes or hours ago.
#[test]
fn an_event_recorded_at_no_time_gives_no_age() {
    let found = [i64::MIN, i64::MAX].map(|when| {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let path = config.database(Database::Events);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE events(received_at INTEGER NOT NULL)")
            .unwrap();
        db.execute("INSERT INTO events VALUES(?)", [when]).unwrap();
        drop(db);
        events(&config)
    });
    assert_eq!(
        found,
        [i64::MIN, i64::MAX].map(|when| Finding::unknown(states::event_undated(when)))
    );
}

/// An event recorded ahead of this host's clock, as after the clock went
/// back, arrived before then: how long ago is not known, and no age below
/// zero is given; a few minutes ahead are the clock's own corrections. The
/// event that arrived last counts, also where one before it is dated later.
#[test]
fn an_event_recorded_ahead_of_the_clock_gives_no_age_below_zero() {
    let line = |received: &[i64]| {
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        let path = config.database(Database::Events);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(
            "CREATE TABLE events(seq INTEGER PRIMARY KEY, received_at INTEGER NOT NULL)",
        )
        .unwrap();
        for at in received {
            db.execute("INSERT INTO events(received_at) VALUES(?)", [at])
                .unwrap();
        }
        drop(db);
        events(&config)
    };
    let now = time::now().as_second();
    assert_eq!(
        line(&[now + 3630]),
        Finding::warn(states::event_ahead(3630))
    );
    assert_eq!(line(&[now + 120]), Finding::ok(states::event_recent(0)));
    assert_eq!(
        line(&[now + 3630, now - 615]),
        Finding::ok(states::event_recent(615))
    );
    assert_eq!(
        line(&[now - 30 * 3600]),
        Finding::warn(states::quiet(30 * 3600))
    );
}

/// An event numbered with the greatest integer, as a damaged or hand-edited
/// history may hold, has SQLite number later events at random: the event
/// that arrived last is still the one the receiver stored last.
#[test]
fn an_event_of_the_greatest_number_leaves_the_last_arrival_the_newest() {
    use garrison_ingest::store::{EventStore, Limits};
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let path = config.database(Database::Events);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let store = EventStore::open(&path, Limits::new(30, 1000, 64 * 1024 * 1024)).unwrap();
    let now = time::now().as_second();
    let batch = |index: i64, at: i64| {
        let created = time::isoformat(time::Timestamp::from_second(at).unwrap());
        let event = serde_json::json!({"id": index.to_string(), "createdAt": created,
                                       "type": "auth.failed", "data": {}});
        store.ingest(&[event], at).unwrap();
    };
    batch(0, now - 7200);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("UPDATE events SET seq = ?1", [i64::MAX])
        .unwrap();
    for index in 1..=20 {
        batch(index, now - 3600 + index);
    }
    batch(21, now - 60);
    assert_eq!(events(&config), Finding::ok(states::event_recent(60)));
}

#[test]
fn systemd_names_only_a_last_run_that_did_not_succeed() {
    assert!(last_result(Some("success")).is_none());
    assert_eq!(
        last_result(Some("exit-code")),
        Some(Finding::warn(states::run_failed("exit-code")))
    );
    for silent in [None, Some("")] {
        assert_eq!(
            last_result(silent),
            Some(Finding::unknown(states::run_unknown()))
        );
    }
}

#[test]
fn the_newest_snapshot_is_read_from_the_status_database() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("status.sqlite");
    assert_eq!(
        finished(watch::last_run(&database), time::now()),
        Finding::warn(states::no_collection())
    );
    let mut store = StatusStore::open(&database, 90).unwrap();
    let snapshot = Snapshot {
        schema_version: SCHEMA,
        collected_at: time::now_isoformat(),
        observations: Vec::new(),
        provider_errors: Vec::new(),
    };
    let written = time::now().as_second() - 120;
    store
        .write(written, &snapshot, &BTreeMap::new(), &BTreeMap::new())
        .unwrap();
    drop(store);
    let fresh = finished(watch::last_run(&database), time::now());
    assert_eq!(named(&fresh), (Level::Ok, "doctor-collection-recent"));
    // Doctor reads as root and follows no link to a database.
    let linked = directory.path().join("linked.sqlite");
    std::os::unix::fs::symlink(&database, &linked).unwrap();
    assert_eq!(
        named(&finished(watch::last_run(&linked), time::now())),
        (Level::Unknown, "doctor-collection-unreadable")
    );
}

/// The module's text as the installer writes it for `port`.
fn cil(port: u16) -> String {
    format!(
        ";; Lets nginx (httpd_t) connect to Garrison's web service on port {port}.\n\
         (type garrison_port_t)\n(roletype object_r garrison_port_t)\n\
         (typeattributeset port_type (garrison_port_t))\n\
         (portcon tcp {port} (system_u object_r garrison_port_t ((s0) (s0))))\n\
         (allow httpd_t garrison_port_t (tcp_socket (name_connect)))\n"
    )
}

/// A host's SELinux, made of files: whether it enforces, the boolean that
/// lets nginx connect anywhere, and the module's text as the installer
/// last wrote it, for `written`.
fn selinux_host(enforce: &str, everywhere: &str, written: Option<u16>) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("enforce"), enforce).unwrap();
    fs::write(directory.path().join("boolean"), everywhere).unwrap();
    if let Some(port) = written {
        fs::write(directory.path().join("garrison.cil"), cil(port)).unwrap();
    }
    directory
}

/// What doctor says on `host` for `port` where SELinux has `loaded` this
/// module, `None` where it has not loaded it.
fn on(
    host: &tempfile::TempDir,
    loaded: Option<Result<String, Unread>>,
    port: u16,
) -> Option<Finding> {
    let path = |name: &str| host.path().join(name).display().to_string();
    let (enforce, everywhere, module) = (path("enforce"), path("boolean"), path("garrison.cil"));
    selinux_at(
        &SeLinux {
            enforce: &enforce,
            everywhere: &everywhere,
            module: &module,
        },
        loaded,
        port,
    )
}

/// nginx reaches the web service under SELinux only where the module
/// SELinux has loaded gives its port the type nginx may connect to, or
/// where nginx may connect anywhere; a module for another port fails with
/// the installer, which loads it for web.port, or, where the installer's
/// file names web.port already, as after a load that failed, with the load
/// by hand that the installer does not repeat.
#[test]
fn the_selinux_module_is_judged_by_the_port_it_lets_nginx_reach() {
    let enforcing = selinux_host("1", "0 0", Some(8091));
    assert_eq!(
        on(&enforcing, Some(Ok(cil(8091))), 8091),
        Some(Finding::ok(said::port_reached(8091)))
    );
    assert_eq!(
        on(&enforcing, Some(Ok(cil(8091))), 9443),
        Some(Finding::fail(said::other_port(8091, 9443)))
    );
    // The installer wrote the file for web.port, and loading it failed.
    let written = selinux_host("1", "0 0", Some(9443));
    let module = written.path().join("garrison.cil").display().to_string();
    assert_eq!(
        on(&written, Some(Ok(cil(8091))), 9443),
        Some(Finding::fail(said::load_failed(8091, 9443, &module)))
    );
    let permissive = selinux_host("0", "0 0", Some(8091));
    assert_eq!(
        on(&permissive, Some(Ok(cil(8091))), 9443),
        Some(Finding::warn(said::other_port_permissive(8091, 9443)))
    );
    let written_permissive = selinux_host("0", "0 0", Some(9443));
    let module = written_permissive
        .path()
        .join("garrison.cil")
        .display()
        .to_string();
    assert_eq!(
        on(&written_permissive, Some(Ok(cil(8091))), 9443),
        Some(Finding::warn(said::load_failed_permissive(
            8091, 9443, &module
        )))
    );
    assert_eq!(
        on(&enforcing, None, 8091),
        Some(Finding::fail(said::unloaded()))
    );
    assert_eq!(
        on(&permissive, None, 8091),
        Some(Finding::warn(said::unloaded_permissive()))
    );
    let anywhere = selinux_host("1", "1 1", Some(8091));
    assert_eq!(
        on(&anywhere, Some(Ok(cil(8091))), 9443),
        Some(Finding::ok(said::everywhere()))
    );
    for (loaded, why) in [
        (Err(Unread::NoPort), Unread::NoPort),
        (Ok("(type garrison_port_t)\n".to_owned()), Unread::NoPort),
    ] {
        assert_eq!(
            on(&enforcing, Some(loaded), 8091),
            Some(Finding::unknown(said::port_unknown(&why)))
        );
    }
    // No SELinux, no line.
    let none = tempfile::tempdir().unwrap();
    assert_eq!(on(&none, Some(Ok(cil(8091))), 8091), None);
}

/// A folder not made yet, as /var/backups before the first backup on a
/// distribution that has none, is judged by the disk of the nearest folder
/// of it that exists, as the installer's room check judges it; where the
/// disk cannot be asked, the line says why.
#[test]
fn free_space_is_judged_where_a_folder_will_be_made() {
    let path = "/var/garrison-test-folder-that-is-not-there/backups";
    assert_eq!(nearest(path).unwrap().0, Path::new("/var"));
    let missing = room(path);
    assert!(
        matches!(
            named(&missing),
            (Level::Ok, "doctor-space-enough") | (Level::Warn, "doctor-space-low")
        ),
        "{}",
        missing.line()
    );
    let unasked = "/proc/self/status/garrison";
    let error = nearest(unasked).unwrap_err();
    assert_eq!(
        room(unasked),
        Finding::unknown(states::space_unknown(unasked, error))
    );
    assert_ne!(room("/").level, Level::Unknown);
}

/// The folder doctor extracts SELinux's module into has a name nobody can
/// guess: one another user made under the name doctor would take does not
/// keep doctor from reading the module.
#[test]
fn the_extraction_folder_cannot_be_taken_first() {
    let guessed = std::env::temp_dir().join(format!("garrison-doctor-{}", std::process::id()));
    fs::create_dir_all(&guessed).unwrap();
    let read = loaded_module();
    fs::remove_dir_all(&guessed).unwrap();
    assert!(
        !matches!(&read, Err(Unread::Folder(_, error)) if error.kind() == std::io::ErrorKind::AlreadyExists),
        "{read:?}"
    );
}
