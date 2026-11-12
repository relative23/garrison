use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::*;

const MIGRATIONS: &[Migration] = &[
    &["CREATE TABLE item (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"],
    &[
        "ALTER TABLE item ADD COLUMN size INTEGER NOT NULL DEFAULT 0",
        "CREATE INDEX item_name ON item(name)",
    ],
];

fn user_version(db: &Connection) -> i64 {
    db.query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn writer_creates_a_private_file_and_applies_migrations_in_order() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("state/items.sqlite");
    let db = open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o640).unwrap();
    assert_eq!(user_version(&db), 2);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let journal: String = db
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "delete");
    db.execute("INSERT INTO item (name, size) VALUES ('a', 1)", [])
        .unwrap();
    drop(db);

    // Reopening applies nothing twice and keeps the data.
    let db = open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o600).unwrap();
    let count: i64 = db
        .query_row("SELECT count(*) FROM item", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn private_databases_use_the_write_ahead_log() {
    let directory = tempfile::tempdir().unwrap();
    let db = open_writer(
        &directory.path().join("jobs.sqlite"),
        MIGRATIONS,
        Sharing::Private,
        0o600,
    )
    .unwrap();
    let journal: String = db
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
}

#[test]
fn a_failing_migration_leaves_the_previous_version_intact() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    drop(open_writer(&path, &MIGRATIONS[..1], Sharing::WithReaders, 0o600).unwrap());
    let broken: &[Migration] = &[
        MIGRATIONS[0],
        &[
            "ALTER TABLE item ADD COLUMN size INTEGER",
            "THIS IS NOT SQL",
        ],
    ];
    assert!(open_writer(&path, broken, Sharing::WithReaders, 0o600).is_err());
    let db = Connection::open(&path).unwrap();
    assert_eq!(user_version(&db), 1);
    // The first statement of the failed migration was rolled back as well.
    assert!(db.prepare("SELECT size FROM item").is_err());
}

#[test]
fn a_database_from_a_newer_release_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    drop(open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o600).unwrap());
    let error = open_writer(&path, &MIGRATIONS[..1], Sharing::WithReaders, 0o600).unwrap_err();
    assert!(matches!(error, SqliteError::NewerSchema), "{error}");
}

#[test]
fn readers_see_one_snapshot_and_cannot_write() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    assert!(reading(&path, Duration::from_secs(2)).unwrap().is_none());
    let writer = open_writer(&path, MIGRATIONS, Sharing::Private, 0o600).unwrap();
    writer
        .execute("INSERT INTO item (name) VALUES ('a')", [])
        .unwrap();

    let reader = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
    let count = |db: &Connection| -> i64 {
        db.query_row("SELECT count(*) FROM item", [], |row| row.get(0))
            .unwrap()
    };
    assert_eq!(count(&reader), 1);
    writer
        .execute("INSERT INTO item (name) VALUES ('b')", [])
        .unwrap();
    assert_eq!(
        count(&reader),
        1,
        "the snapshot does not change within one request"
    );
    assert!(
        reader
            .execute("INSERT INTO item (name) VALUES ('c')", [])
            .is_err()
    );
    drop(reader);
    assert_eq!(
        count(&reading(&path, Duration::from_secs(2)).unwrap().unwrap()),
        2
    );
}

#[test]
fn reader_queries_stop_at_the_time_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("items.sqlite");
    drop(open_writer(&path, MIGRATIONS, Sharing::WithReaders, 0o600).unwrap());
    let reader = reading(&path, Duration::from_millis(50)).unwrap().unwrap();
    let endless =
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) SELECT count(*) FROM n";
    // On a thread of its own, a query that is never interrupted fails the
    // test instead of hanging it.
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let stopped = reader.query_row(endless, [], |row| row.get::<_, i64>(0));
        let missing = reader.query_row("SELECT 1 FROM nowhere", [], |row| row.get::<_, i64>(0));
        sender.send((
            stopped.is_err_and(|error| out_of_time(&error)),
            missing.is_err_and(|error| out_of_time(&error)),
        ))
    });
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(5)),
        Ok((true, false)),
        "the query must be interrupted, and only that counts as out of time"
    );
    // Within its budget, a long query runs to the end.
    let patient = reading(&path, Duration::from_secs(60)).unwrap().unwrap();
    let bounded = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 100000) \
                   SELECT count(*) FROM n";
    let count = patient.query_row(bounded, [], |row| row.get::<_, i64>(0));
    assert_eq!(count.unwrap(), 100_000);
}

#[test]
fn schema_statements_are_read_as_sqlite_reads_them() {
    for (sql, kind) in [
        ("CREATE TABLE t(a)", Some("TABLE")),
        ("create  index i ON t(a)", Some("INDEX")),
        ("CREATE UNIQUE INDEX i ON t(a)", Some("UNIQUE")),
        (
            "CREATE/* x */VIRTUAL TABLE v USING fts5(a)",
            Some("VIRTUAL"),
        ),
        (
            "CREATE -- x\nTRIGGER r AFTER INSERT ON t BEGIN SELECT 1; END",
            Some("TRIGGER"),
        ),
        ("CREATE\x0bVIEW w AS SELECT 1", Some("VIEW")),
        ("CREATE /* never closed", Some("")),
        ("CREATEX TABLE t(a)", None),
        ("SELECT 1", None),
    ] {
        assert_eq!(created(sql).as_deref(), kind, "{sql:?}");
    }
}

#[test]
fn untrusted_files_with_more_than_tables_and_indexes_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    for (name, object) in [
        ("view", "CREATE VIEW w AS SELECT a FROM t"),
        (
            "trigger",
            "CREATE TRIGGER r AFTER DELETE ON t BEGIN SELECT 1; END",
        ),
        ("fts", "CREATE VIRTUAL TABLE v USING fts5(a)"),
        ("rtree", "CREATE VIRTUAL TABLE r USING rtree(id, x0, x1)"),
    ] {
        let path = directory.path().join(format!("{name}.sqlite"));
        Connection::open(&path)
            .unwrap()
            .execute_batch(&format!(
                "CREATE TABLE t(a); CREATE INDEX i ON t(a); {object};"
            ))
            .unwrap();
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY;
        assert!(
            matches!(
                open_untrusted(&path, flags),
                Err(SqliteError::ForeignSchema)
            ),
            "{name}"
        );
        assert!(
            matches!(
                reading(&path, Duration::from_secs(1)),
                Err(SqliteError::ForeignSchema)
            ),
            "{name}"
        );
    }
    let plain = directory.path().join("plain.sqlite");
    Connection::open(&plain)
        .unwrap()
        .execute_batch("CREATE TABLE t(a); CREATE UNIQUE INDEX u ON t(a);")
        .unwrap();
    let db = open_untrusted(&plain, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    for (setting, on) in [
        (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
        (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
        (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
        (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
    ] {
        assert_eq!(db.db_config(setting).unwrap(), on);
    }
    // A link to a good database is not followed either.
    let link = directory.path().join("link.sqlite");
    std::os::unix::fs::symlink(&plain, &link).unwrap();
    assert!(open_untrusted(&link, OpenFlags::SQLITE_OPEN_READ_ONLY).is_err());
    assert!(reading(&link, Duration::from_secs(1)).is_err());
    // A linked directory is the operator's, such as state moved to another disk.
    let moved = directory.path().join("moved");
    std::os::unix::fs::symlink(directory.path(), &moved).unwrap();
    assert!(
        open_untrusted(
            &moved.join("plain.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY
        )
        .is_ok()
    );
    assert!(
        reading(&moved.join("plain.sqlite"), Duration::from_secs(1))
            .unwrap()
            .is_some()
    );
    assert!(open_untrusted(&moved.join("link.sqlite"), OpenFlags::SQLITE_OPEN_READ_ONLY).is_err());
    assert!(
        reading(
            &directory.path().join("absent.sqlite"),
            Duration::from_secs(1)
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn the_bundled_sqlite_reads_no_stale_memory_from_a_crafted_log() {
    // RUSTSEC-2026-0459: before 3.54.0 a database with a write-ahead log of
    // another page size made queries return bytes of the reader's memory, and
    // readers here open files that another user writes.
    assert!(
        rusqlite::version_number() >= 3_054_000,
        "{}",
        rusqlite::version()
    );
}
