//! What the status database holds is data. A damaged or hand-edited
//! database, or one that an earlier or a later release wrote, may hold in
//! any column a value of another type than the collector writes there, a
//! time no clock gives, or a text the collector would not write. Such a
//! value costs that one value, and is said at most once: never a collection
//! run, the watch over the collector, the metric history or the status the
//! web service reads.
//!
//! The test fills a status database with collection runs, then changes
//! every column of every table, and every value of the collector's memory,
//! in turn, to each such value. So a table, a column or a memory key that a
//! later change adds is changed too, as long as these runs fill it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use garrison_core::config::{Config, Database, Endpoint};
use garrison_core::credentials::Credentials;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Observation, Required, State};
use garrison_core::sqlite::reading;
use garrison_core::time::{self, Timestamp};
use rusqlite::Connection;
use rustls::RootCertStore;

use crate::context::{Collected, Context, Provider, Report};
use crate::notify::Secrets;
use crate::run::collect_from;
use crate::store::{history, latest_snapshot};
use crate::testing::{Canned, now};
use crate::watch::Watch;

const DAY: i64 = 86_400;

/// What a column or a memory value is changed to, as SQL: text that is no
/// number, a fraction, bytes, text that is no UTF-8, the least and the
/// greatest integer, an empty object.
const VALUES: [&str; 7] = [
    "'no number'",
    "1.5",
    "x'00ff'",
    "CAST(x'ff' AS TEXT)",
    "-9223372036854775808",
    "9223372036854775807",
    "'{}'",
];

/// A check that reports one card, a gauge and a counter that goes down now
/// and then, and keeps a reading of its own.
struct Steady;

impl Provider for Steady {
    fn name(&self) -> &'static str {
        "steady"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let at = context.now.as_second();
        context
            .memory
            .keep("steady.reading", &format!("{{\"at\": {at}}}"));
        let mut report = Report::of(Observation::new(Required {
            id: "steady.card",
            provider: "steady",
            title: "Steady",
            modules: [ModuleId::Services],
            evidence: Evidence::Process,
            state: State::Ok,
            checked_at: &context.checked_at(),
            source: "test",
        })?);
        report.gauges.insert("load".to_owned(), 1.0);
        // Down every third minute: a reset.
        let delivered = f64::from(i32::try_from(at.rem_euclid(180) / 60).unwrap_or(0));
        report.counters.insert("delivered".to_owned(), delivered);
        Ok(report)
    }
}

/// A host in `directory`, with an ntfy topic that the runs never send to:
/// every check is in order.
fn host(directory: &Path) -> (Config, Credentials) {
    let mut config = crate::testing::config(directory);
    config.notifications.ntfy_url = Some(Endpoint::Written("https://127.0.0.1:9/topic".to_owned()));
    let credentials = Credentials::new(&config.credentials_directory);
    (config, credentials)
}

/// A collection run at the second `at`.
fn run(config: &Config, credentials: &Credentials, at: i64) -> Result<(), String> {
    let providers: Vec<Box<dyn Provider>> = vec![Box::new(Steady)];
    let at = Timestamp::from_second(at).unwrap();
    collect_from(&providers, config, credentials, &Canned(String::new()), at)
        .map(drop)
        .map_err(|error| error.to_string())
}

/// The status database of a host whose collector ran four times, the last
/// a minute before the tests' clock, with a day of history older than
/// eight, which a run thins, and the memory a run reads but these do not
/// write.
fn filled(directory: &Path) -> PathBuf {
    let (config, credentials) = host(directory);
    let t0 = now().as_second();
    for minutes in [4, 3, 2] {
        run(&config, &credentials, t0 - minutes * 60).unwrap();
    }
    let path = config.database(Database::Status);
    let db = Connection::open(&path).unwrap();
    for minute in 0..60 {
        db.execute(
            "INSERT INTO samples(name, ts, value, kind) VALUES('load', ?, 1.0, 'gauge')",
            [t0 - 9 * DAY + minute * 60],
        )
        .unwrap();
    }
    drop(db);
    run(&config, &credentials, t0 - 60).unwrap();
    let db = Connection::open(&path).unwrap();
    for (key, value) in [
        ("store.ahead-for", "0".to_owned()),
        ("store.dqs-keys-rebuild-began", (t0 - 60).to_string()),
        ("notify.sent", (t0 - 3600).to_string()),
        ("notify.problem", "webhook: it answered 500".to_owned()),
    ] {
        db.execute("INSERT OR REPLACE INTO memory VALUES(?, ?)", [key, &value])
            .unwrap();
    }
    path
}

/// A place a value is kept: a column of a table, in every row or only in
/// one, the last by its key, or a value of the collector's memory.
#[derive(Debug)]
enum Place {
    Column {
        table: String,
        column: String,
        /// The condition that names one row, or none for every row.
        one: Option<String>,
    },
    Memory(String),
}

impl Place {
    /// The statement that changes it to `value`, and what it holds then:
    /// the type and the bytes of each value, which may be no UTF-8.
    fn change(&self, value: &str) -> (String, String) {
        let held = |column: &str| format!("group_concat(typeof({column}) || ':' || hex({column}))");
        match self {
            Place::Column { table, column, one } => {
                let rows = one
                    .as_ref()
                    .map_or_else(String::new, |one| format!(" WHERE {one}"));
                (
                    format!("UPDATE {table} SET {column} = {value}{rows}"),
                    format!("SELECT {} FROM {table}{rows}", held(column)),
                )
            }
            Place::Memory(key) => (
                format!("UPDATE memory SET value = {value} WHERE key = '{key}'"),
                format!("SELECT {} FROM memory WHERE key = '{key}'", held("value")),
            ),
        }
    }
}

/// Every place of the database at `path`.
fn places(path: &Path) -> Vec<Place> {
    let db = Connection::open(path).unwrap();
    let tables: Vec<(String, String)> = db
        .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let mut places = Vec::new();
    for (table, sql) in tables {
        let columns: Vec<(String, i64)> = db
            .prepare(&format!(
                "SELECT name, pk, type = 'INTEGER' AND pk = 1 \
                        AND (SELECT count(*) FROM pragma_table_info('{table}') WHERE pk > 0) = 1 \
                 FROM pragma_table_info('{table}')"
            ))
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .filter_map(|column| {
                let (name, pk, alone): (String, i64, bool) = column.unwrap();
                // A key that is an INTEGER alone is SQLite's rowid, as a
                // snapshot's id: it takes only integers and is the order of
                // the rows, not a value the collector reads. An id of the
                // greatest integer has SQLite choose every later one at
                // random, so no order is left to hold the store to.
                (!alone || sql.contains("WITHOUT ROWID")).then_some((name, pk))
            })
            .collect();
        // One row: the last that SQLite gave, or in a table without rowid
        // the last by its key.
        let one = if sql.contains("WITHOUT ROWID") {
            let mut key: Vec<&(String, i64)> = columns.iter().filter(|(_, pk)| *pk > 0).collect();
            key.sort_by_key(|(_, pk)| *pk);
            let key: Vec<&str> = key.iter().map(|(name, _)| name.as_str()).collect();
            let last: Vec<String> = key.iter().map(|name| format!("{name} DESC")).collect();
            format!(
                "({0}) = (SELECT {0} FROM {table} ORDER BY {1} LIMIT 1)",
                key.join(", "),
                last.join(", ")
            )
        } else {
            format!("rowid = (SELECT max(rowid) FROM {table})")
        };
        for (column, _) in &columns {
            for one in [None, Some(one.clone())] {
                places.push(Place::Column {
                    table: table.clone(),
                    column: column.clone(),
                    one,
                });
            }
        }
    }
    let keys: Vec<String> = db
        .prepare("SELECT key FROM memory ORDER BY key")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    places.extend(keys.into_iter().map(Place::Memory));
    places
}

/// The collector's own warnings and errors since the last call.
fn warned() -> Vec<String> {
    crate::journal::lines()
        .into_iter()
        .filter(|line| line.level <= log::Level::Warn)
        .map(|line| line.text)
        .collect()
}

/// What goes wrong on a host whose status database is a copy of `filled`
/// changed by `change`, or nothing; `None` where the change changes
/// nothing, as where SQLite refuses the value or turns it back into what
/// was there. Before a run, the watch and the history read it; then two
/// collection runs must store their snapshots, the second without a word
/// of the change, and the watch, the history and the status read it again.
fn faults(filled: &Path, change: Option<(&str, &str)>) -> Option<Vec<String>> {
    let directory = tempfile::tempdir().unwrap();
    let (config, credentials) = host(directory.path());
    let path = config.database(Database::Status);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::copy(filled, &path).unwrap();
    if let Some((change, holds)) = change {
        let db = Connection::open(&path).unwrap();
        let before: Option<String> = db.query_row(holds, [], |row| row.get(0)).unwrap();
        db.execute(change, []).ok()?;
        let after: Option<String> = db.query_row(holds, [], |row| row.get(0)).unwrap();
        if before == after {
            return None;
        }
    }
    let t0 = now().as_second();
    let mut found = Vec::new();
    let look = |at: i64| {
        let watch = Watch {
            database: &path,
            marker: &directory.path().join("collector-stopped"),
            configured: Err(()),
            secrets: Secrets::default(),
            credentials: credentials.clone(),
            now: Timestamp::from_second(at).unwrap(),
            roots: Arc::new(RootCertStore::empty()),
        };
        // A message that did not go out is the watch telling, as it is to.
        match watch.look() {
            Err(error) if !error.starts_with("ntfy: ") => Some(format!("the watch: {error}")),
            _ => None,
        }
    };
    let read = || {
        let db = reading(&path, std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        let mut found = Vec::new();
        if let Err(error) = history(&db, t0 - 10 * DAY, t0 + 600, 60) {
            found.push(format!("the history: {error}"));
        }
        found
    };
    found.extend(look(t0));
    found.extend(read());
    warned();
    for (step, at) in [(1, t0), (2, t0 + 60)] {
        if let Err(error) = run(&config, &credentials, at) {
            found.push(format!("run {step}: {error}"));
            return Some(found);
        }
        let said = warned();
        if step == 2 && !said.is_empty() {
            found.push(format!("run 2 said: {said:?}"));
        }
    }
    found.extend(look(t0 + 60));
    found.extend(read());
    let db = reading(&path, std::time::Duration::from_secs(2))
        .unwrap()
        .unwrap();
    let last = time::isoformat(Timestamp::from_second(t0 + 60).unwrap());
    match latest_snapshot(&db) {
        Ok(Some(snapshot)) if snapshot.collected_at == last => {}
        Ok(Some(snapshot)) => found.push(format!("the status is of {}", snapshot.collected_at)),
        other => found.push(format!("the status: {other:?}")),
    }
    let stored: i64 = db
        .query_row(
            "SELECT count(*) FROM snapshots WHERE collected_at = ?",
            [t0],
            |row| row.get(0),
        )
        .unwrap();
    if stored != 1 {
        found.push(format!("run 1 stored {stored} snapshots"));
    }
    Some(found)
}

/// Each value of each place costs that value alone, and is said at most
/// once.
#[test]
fn a_stored_value_of_another_kind_costs_that_value_alone() {
    let directory = tempfile::tempdir().unwrap();
    let filled = filled(directory.path());
    // The database as the runs left it is in order.
    assert_eq!(faults(&filled, None), Some(Vec::new()));
    let mut found = Vec::new();
    let mut changed = 0;
    for place in places(&filled) {
        for value in VALUES {
            let (change, holds) = place.change(value);
            if let Some(faults) = faults(&filled, Some((&change, &holds))) {
                changed += 1;
                found.extend(faults.into_iter().map(|fault| format!("{change}: {fault}")));
            }
        }
    }
    assert_eq!(found, Vec::<String>::new());
    // Not every value fits every column; far more than none do.
    assert!(changed > 100, "{changed} changes");
}
