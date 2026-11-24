//! A reader of a database that another user writes takes no value longer
//! than 16 MiB, more than Garrison writes in one: SQLite refuses a longer
//! value as it reads it, before it holds it, so that one row or one schema
//! entry of the writer's choosing cannot take a reader past the memory its
//! service has.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use super::{open_untrusted, reading};

/// The longest value a reader takes.
const LONGEST: i64 = 16 << 20;

/// A database at `path` whose one row holds a text of `length` bytes.
fn with_a_value(path: &Path, length: i64) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE t(a TEXT)").unwrap();
    db.execute(
        "INSERT INTO t VALUES(substr(hex(zeroblob(?1)), 1, ?2))",
        (length / 2 + 1, length),
    )
    .unwrap();
}

/// How each reader of a database another user writes reads the value at
/// `path`: its length, or why not.
fn read_by_each(path: &Path) -> [Result<usize, String>; 2] {
    let length = |db: &Connection| {
        db.query_row("SELECT a FROM t", [], |row| row.get::<_, String>(0))
            .map(|text| text.len())
            .map_err(|error| error.to_string())
    };
    [
        reading(path, Duration::from_secs(10))
            .map_err(|error| error.to_string())
            .and_then(|reader| length(&reader.unwrap())),
        open_untrusted(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| error.to_string())
            .and_then(|db| length(&db)),
    ]
}

#[test]
fn a_value_longer_than_garrison_writes_is_not_read() {
    let directory = tempfile::tempdir().unwrap();
    let (longest, longer) = (
        directory.path().join("longest.sqlite"),
        directory.path().join("longer.sqlite"),
    );
    with_a_value(&longest, LONGEST);
    with_a_value(&longer, LONGEST + 1);
    let fits = usize::try_from(LONGEST).unwrap();
    assert_eq!(read_by_each(&longest), [Ok(fits), Ok(fits)]);
    let too_big = || Err("string or blob too big".to_owned());
    assert_eq!(read_by_each(&longer), [too_big(), too_big()]);
}

#[test]
fn a_schema_entry_longer_than_garrison_writes_is_not_read() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("schema.sqlite");
    let long = "x".repeat(usize::try_from(LONGEST).unwrap());
    Connection::open(&path)
        .unwrap()
        .execute_batch(&format!("CREATE TABLE t(a TEXT DEFAULT '{long}')"))
        .unwrap();
    let opened = [
        reading(&path, Duration::from_secs(10))
            .map(|_| ())
            .map_err(|error| error.to_string()),
        open_untrusted(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map(|_| ())
            .map_err(|error| error.to_string()),
    ];
    for opened in &opened {
        assert!(
            opened.as_ref().is_err_and(|why| why.contains("too big")),
            "{opened:?}"
        );
    }
}
