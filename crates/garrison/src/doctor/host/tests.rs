use std::collections::BTreeMap;

use garrison_collector::snapshot::{SCHEMA, Snapshot};
use garrison_collector::store::StatusStore;

use super::super::Level;
use super::*;

const NOW: i64 = 1_794_000_000;

fn judged(last: Result<Option<i64>, String>) -> Finding {
    finished(last, time::Timestamp::from_second(NOW).unwrap())
}

#[test]
fn the_collector_is_judged_by_its_newest_snapshot_as_the_watch_judges_it() {
    let fresh = judged(Ok(Some(NOW - 90)));
    assert_eq!(
        (fresh.level, fresh.what.as_str()),
        (Level::Ok, "the last collection run finished 1 minute ago")
    );
    assert_eq!(judged(Ok(Some(NOW - watch::LIMIT))).level, Level::Ok);
    // A run that never was is not a success, and not yet a failure.
    let never = judged(Ok(None));
    assert_eq!(
        (never.level, never.what.as_str()),
        (Level::Warn, "no collection run has finished yet")
    );
    // Stopped, failed and unknown stay three answers.
    let stopped = judged(Ok(Some(NOW - watch::LIMIT - 1)));
    assert_eq!(stopped.level, Level::Fail);
    assert_eq!(
        stopped.what,
        "no collection run has finished since 2026-11-06T21:09:59+00:00, 10 minutes ago"
    );
    assert!(
        stopped.line().contains(
            "`systemctl status garrison-collect.service garrison-collect.timer` and \
             `garrison check-config` say why."
        ),
        "{}",
        stopped.line()
    );
    let unreadable = judged(Err("file is not a database".to_owned()));
    assert_eq!(unreadable.level, Level::Unknown);
    assert!(unreadable.what.ends_with("(file is not a database)"));
    // A date from the future gives no age; a few minutes are the clock's
    // own small corrections.
    let ahead = judged(Ok(Some(NOW + 3600)));
    assert_eq!(ahead.level, Level::Warn);
    assert!(ahead.what.contains("60 minutes ahead"), "{}", ahead.what);
    assert_eq!(
        judged(Ok(Some(NOW + 120))).what,
        "the last collection run finished 0 minutes ago"
    );
}

/// A damaged or hand-edited status database may date its newest snapshot
/// at a time that is none: it gives no age, and no stop either.
#[test]
fn a_snapshot_dated_at_no_time_gives_no_age() {
    for when in [i64::MIN, i64::MAX] {
        let found = judged(Ok(Some(when)));
        assert_eq!(
            (found.level, found.what),
            (
                Level::Unknown,
                format!(
                    "when the collector last finished a run: the newest status snapshot \
                     is dated {when}, which is no time"
                )
            )
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
    let none = events(&config);
    assert_eq!(
        (none.level, none.what.as_str()),
        (Level::Warn, "no Stalwart event recorded yet")
    );
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE events(received_at INTEGER NOT NULL)")
        .unwrap();
    drop(db);
    assert_eq!(events(&config).what, "no Stalwart event recorded yet");
    fs::write(&path, "no database").unwrap();
    let unread = events(&config);
    assert_eq!(unread.level, Level::Unknown, "{}", unread.line());
    assert!(
        unread.what.starts_with(&format!(
            "when the last Stalwart event arrived: the events database {} cannot be read (",
            path.display()
        )),
        "{}",
        unread.what
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
        let found = events(&config);
        (found.level, found.what)
    });
    assert_eq!(
        found,
        [i64::MIN, i64::MAX].map(|when| (
            Level::Unknown,
            format!(
                "when the last Stalwart event arrived: the newest event is recorded at \
                 {when}, which is no time"
            )
        ))
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
    let ahead = line(&[now + 3630]);
    assert_eq!(
        (ahead.level, ahead.what.as_str()),
        (
            Level::Warn,
            "the last Stalwart event is recorded 60 minutes ahead of this host's clock, so \
             when it arrived is not known"
        )
    );
    assert!(
        ahead
            .line()
            .contains("The clock went back after it arrived"),
        "{}",
        ahead.line()
    );
    for (received, said) in [
        (
            vec![now + 120],
            "the last Stalwart event arrived 0 minutes ago",
        ),
        (
            vec![now + 3630, now - 615],
            "the last Stalwart event arrived 10 minutes ago",
        ),
    ] {
        let found = line(&received);
        assert_eq!((found.level, found.what.as_str()), (Level::Ok, said));
    }
    let quiet = line(&[now - 30 * 3600]);
    assert_eq!(
        (quiet.level, quiet.what.as_str()),
        (Level::Warn, "no Stalwart event for 30 hours")
    );
}

#[test]
fn systemd_names_only_a_last_run_that_did_not_succeed() {
    assert!(last_result(Some("success")).is_none());
    let failed = last_result(Some("exit-code")).unwrap();
    assert_eq!(
        (failed.level, failed.what.as_str()),
        (Level::Warn, "the last collection run ended with exit-code")
    );
    for silent in [None, Some("")] {
        assert_eq!(last_result(silent).unwrap().level, Level::Unknown);
    }
}

#[test]
fn the_newest_snapshot_is_read_from_the_status_database() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("status.sqlite");
    assert_eq!(
        finished(watch::last_run(&database), time::now()).level,
        Level::Warn
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
    assert_eq!(fresh.level, Level::Ok, "{}", fresh.line());
    // Doctor reads as root and follows no link to a database.
    let linked = directory.path().join("linked.sqlite");
    std::os::unix::fs::symlink(&database, &linked).unwrap();
    assert_eq!(
        finished(watch::last_run(&linked), time::now()).level,
        Level::Unknown
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
    loaded: Option<Result<String, String>>,
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
    let kept = on(&enforcing, Some(Ok(cil(8091))), 8091).unwrap();
    assert_eq!(
        (kept.level, kept.what.as_str()),
        (
            Level::Ok,
            "the SELinux module garrison is loaded and lets nginx reach the web service on port \
             8091"
        )
    );
    let moved = on(&enforcing, Some(Ok(cil(8091))), 9443).unwrap();
    assert_eq!(moved.level, Level::Fail, "{}", moved.line());
    assert_eq!(
        moved.what,
        "the SELinux module garrison lets nginx reach port 8091, not 9443 (web.port), so nginx \
         answers 502"
    );
    assert_eq!(
        moved.fix.as_deref(),
        Some("Run the installer again; it loads the module for web.port.")
    );
    // The installer wrote the file for web.port, and loading it failed.
    let written = selinux_host("1", "0 0", Some(9443));
    let failed = on(&written, Some(Ok(cil(8091))), 9443).unwrap();
    assert_eq!(failed.level, Level::Fail, "{}", failed.line());
    assert!(
        failed
            .what
            .starts_with("the SELinux module garrison lets nginx reach port 8091, not 9443"),
        "{}",
        failed.what
    );
    let load = format!(
        "Load the module the installer wrote for web.port: semodule -i {}",
        written.path().join("garrison.cil").display()
    );
    assert_eq!(failed.fix.as_deref(), Some(load.as_str()));
    let permissive = selinux_host("0", "0 0", Some(8091));
    assert_eq!(
        on(&permissive, Some(Ok(cil(8091))), 9443).unwrap().level,
        Level::Warn
    );
    let unlisted = on(&enforcing, None, 8091).unwrap();
    assert_eq!(unlisted.level, Level::Fail, "{}", unlisted.line());
    let anywhere = selinux_host("1", "1 1", Some(8091));
    assert_eq!(
        on(&anywhere, Some(Ok(cil(8091))), 9443).unwrap().level,
        Level::Ok
    );
    let unknown = on(&enforcing, Some(Err("no module".to_owned())), 8091).unwrap();
    assert_eq!(unknown.level, Level::Unknown, "{}", unknown.line());
    // No SELinux, no line.
    let none = tempfile::tempdir().unwrap();
    assert!(on(&none, Some(Ok(cil(8091))), 8091).is_none());
}

/// Where the disk of a folder cannot be asked, the line says why.
#[test]
fn free_space_that_cannot_be_asked_is_unknown_with_why() {
    let found = room("/garrison-test-folder-that-is-not-there");
    assert_eq!(found.level, Level::Unknown, "{}", found.line());
    assert!(
        found
            .what
            .starts_with("free space of /garrison-test-folder-that-is-not-there: "),
        "{}",
        found.what
    );
    assert_ne!(room("/").level, Level::Unknown);
}
