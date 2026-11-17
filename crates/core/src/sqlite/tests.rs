use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use super::*;

pub(super) const MIGRATIONS: &[Migration] = &[
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
fn a_pipe_or_a_folder_in_place_of_a_database_is_refused_without_waiting() {
    // The user who writes a database can put a named pipe in its place,
    // whose open waits for a writer: every reader is refused at once instead.
    let directory = tempfile::tempdir().unwrap();
    let pipe = directory.path().join("pipe.sqlite");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &pipe,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o644),
        0,
    )
    .unwrap();
    let folder = directory.path().join("folder.sqlite");
    fs::create_dir(&folder).unwrap();
    for path in [pipe, folder] {
        let (sender, receiver) = mpsc::channel();
        let opened = path.clone();
        thread::spawn(move || {
            let reader = reading(&opened, Duration::from_secs(1)).map(|_| ());
            let untrusted = open_untrusted(&opened, OpenFlags::SQLITE_OPEN_READ_ONLY).map(|_| ());
            let _ = sender
                .send([reader, untrusted].map(|answer| answer.map_err(|error| error.to_string())));
        });
        let answers = receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("{} was waited for", path.display()));
        assert_eq!(
            answers,
            [
                Err("not a regular file".to_owned()),
                Err("not a regular file".to_owned())
            ],
            "{}",
            path.display()
        );
    }
}

/// Run again by the test below as a writer in a process of its own: takes
/// the database that `GARRISON_TEST_WRITER` names for writing, without
/// waiting, and says whether it could.
#[test]
#[ignore = "the other process of a_second_reader_keeps_the_lock_of_the_first"]
fn a_writer_of_another_process() {
    let Ok(path) = std::env::var("GARRISON_TEST_WRITER") else {
        return;
    };
    let db = Connection::open(path).unwrap();
    db.busy_timeout(Duration::ZERO).unwrap();
    let taken = db.execute_batch("BEGIN EXCLUSIVE").is_ok();
    println!("writer: {}", if taken { "took it" } else { "was refused" });
}

#[test]
fn a_second_reader_keeps_the_lock_of_the_first() {
    // POSIX locks belong to the process: closing any descriptor of the file
    // drops them all. Two readers of one database at once, as the web
    // service runs them, must keep another process's writer out.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shared.sqlite");
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE t(a); INSERT INTO t VALUES(1);")
        .unwrap();
    let first = reading(&path, Duration::from_secs(5)).unwrap().unwrap();
    let count: i64 = first
        .query_row("SELECT count(*) FROM t", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    let second = reading(&path, Duration::from_secs(5)).unwrap().unwrap();
    let writer = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sqlite::tests::a_writer_of_another_process",
            "--ignored",
            "--nocapture",
        ])
        .env("GARRISON_TEST_WRITER", &path)
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&writer.stdout);
    assert!(said.contains("writer: was refused"), "{said}");
    drop((first, second));
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
