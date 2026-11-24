//! The card of the signature databases: how current the daily database is,
//! and what of Fangfrisch's refresh log is kept.

use garrison_core::observations::State;

use super::*;
use crate::context::Provider;
use crate::testing::{Canned, config, context, table};

#[test]
fn the_signature_age_gauge_is_that_of_the_newest_daily_database() {
    use std::time::{Duration, SystemTime};
    // An old full database beside the incremental one that updates keep
    // current: the card judges the newer, and so must the dashboard.
    let directory = tempfile::tempdir().unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\ndatabase_directory = \"{0}\"",
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let checked = SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(context.now.as_second()).unwrap());
    for (name, hours) in [("daily.cvd", 100), ("daily.cld", 2)] {
        let path = directory.path().join(name);
        std::fs::write(&path, "signatures").unwrap();
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(checked - Duration::from_secs(hours * 3600))
            .unwrap();
    }
    let report = provider.collect(&context).unwrap();
    assert_eq!(report.observations[1].state, State::Ok);
    let age = report.gauges["signature_age_hours"];
    assert!((age - 2.0).abs() < 1e-9, "{age}");
}

#[test]
fn signatures_that_were_not_updated_for_two_days_are_a_warning() {
    use std::time::{Duration, SystemTime};
    let directory = tempfile::tempdir().unwrap();
    let daily = directory.path().join("daily.cld");
    std::fs::write(&daily, "signatures").unwrap();
    std::fs::write(directory.path().join("main.cvd"), "signatures").unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\ndatabase_directory = \"{0}\"",
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let checked = SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(context.now.as_second()).unwrap());
    let aged = |hours: u64| {
        // The main database is years old on every host; only the daily one
        // says whether updates arrive.
        for (path, age) in [(&daily, hours), (&directory.path().join("main.cvd"), 9000)] {
            let file = std::fs::File::options().write(true).open(path).unwrap();
            file.set_modified(checked - Duration::from_secs(age * 3600))
                .unwrap();
        }
        provider.collect(&context).unwrap().observations.remove(1)
    };
    let fresh = aged(47);
    assert_eq!((fresh.state, fresh.findings.len()), (State::Ok, 0));
    let old = aged(49);
    assert_eq!(old.state, State::Warning);
    assert_eq!(
        old.findings,
        [
            "daily.cld was last updated 49 hours ago; ClamAV's signatures change every day, so \
          the updates do not arrive."
        ]
    );
    // Without any of the files, the card says where it looked and what
    // names the right place.
    std::fs::rename(&daily, directory.path().join("daily.old")).unwrap();
    std::fs::rename(
        directory.path().join("main.cvd"),
        directory.path().join("main.old"),
    )
    .unwrap();
    let none = provider.collect(&context).unwrap().observations.remove(1);
    assert_eq!(
        (none.state, none.findings),
        (
            State::Unknown,
            vec![format!(
                "None of the listed signature files is in {}: set `database_directory` to \
                 clamd's, which `garrison detect --format toml` names, or `signatures` to the \
                 files it holds.",
                directory.path().display()
            )]
        )
    );
    std::fs::rename(
        directory.path().join("main.old"),
        directory.path().join("main.cvd"),
    )
    .unwrap();
    // Without the daily database nothing says how current the scanner is.
    let without = provider.collect(&context).unwrap().observations.remove(1);
    assert_eq!(without.state, State::Unknown);
    assert_eq!(
        without.findings,
        [
            "No daily signature database (daily.cld or daily.cvd) is among the files; how \
          current the signatures are is not known."
        ]
    );
}

/// The antivirus configuration card over a milter file of `text` and a
/// scanner file of `scan`, with `options` for the check.
#[test]
fn a_daily_database_dated_ahead_of_the_clock_has_no_age() {
    use std::time::{Duration, SystemTime};
    let directory = tempfile::tempdir().unwrap();
    let daily = directory.path().join("daily.cld");
    std::fs::write(&daily, "signatures").unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\ndatabase_directory = \"{0}\"",
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let checked = SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(context.now.as_second()).unwrap());
    let dated = |ahead: u64| {
        let file = std::fs::File::options().write(true).open(&daily).unwrap();
        file.set_modified(checked + Duration::from_secs(ahead))
            .unwrap();
        provider.collect(&context).unwrap()
    };
    // Written while a clock ran two hours ahead: how long updates have
    // stopped since is not known.
    let ahead = dated(2 * 3600);
    let card = &ahead.observations[1];
    assert_eq!(
        (card.state, card.findings.clone()),
        (
            State::Warning,
            vec![
                "daily.cld is dated 120 minutes ahead of this host's clock; one of the two clocks \
                 is wrong, so its age is not known."
                    .to_owned()
            ]
        )
    );
    assert_eq!(ahead.gauges.get("signature_age_hours"), None);
    // A minute is two clocks that agree.
    let near = dated(60);
    assert_eq!(
        (
            near.observations[1].state,
            near.gauges["signature_age_hours"]
        ),
        (State::Ok, 0.0)
    );
}

#[test]
fn the_refresh_log_keeps_only_the_files_the_card_lists() {
    // Whoever writes Fangfrisch's database can fill its log with names: only
    // the listed files' rows are kept, each with its first time.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fangfrisch.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE refreshlog(path TEXT, updated TEXT); BEGIN;")
        .unwrap();
    let row = |name: &str, updated: &str| {
        let path = format!("/var/lib/clamav/{name}");
        db.execute(
            "INSERT INTO refreshlog VALUES(?, ?)",
            [path.as_str(), updated],
        )
        .unwrap();
    };
    for index in 0..5_000 {
        row(&format!("other-{index}.ndb"), "2026-10-29 06:00:00");
    }
    row("junk.ndb", "2026-10-29 05:00:00");
    row("junk.ndb", "2026-10-29 07:00:00");
    row("phish.ndb", "2026-10-28 06:00:00");
    db.execute_batch("COMMIT").unwrap();
    let listed = ["junk.ndb", "phish.ndb", "daily.cld"].map(str::to_owned);
    let log = refresh_log(&path, &listed).unwrap();
    assert_eq!(
        log,
        BTreeMap::from([
            (
                "junk.ndb".to_owned(),
                "2026-10-29T05:00:00+00:00".to_owned()
            ),
            (
                "phish.ndb".to_owned(),
                "2026-10-28T06:00:00+00:00".to_owned()
            ),
        ]),
        "{} names kept",
        log.len()
    );
}

#[test]
fn signature_files_in_a_folder_the_collector_may_not_search_are_not_called_missing() {
    use std::os::unix::fs::PermissionsExt;
    // clamd's own folder, which only its mode keeps the collector's user out
    // of: the files are there, and no other `database_directory` mends it.
    let directory = tempfile::tempdir().unwrap();
    let closed = directory.path().join("closed");
    std::fs::create_dir(&closed).unwrap();
    for name in ["daily.cld", "main.cvd"] {
        std::fs::write(closed.join(name), "signatures").unwrap();
    }
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\n\
         database_directory = \"{1}\"",
        directory.path().display(),
        closed.display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let card = provider
        .collect(&context)
        .map(|mut report| report.observations.remove(1));
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
    let card = card.unwrap();
    let folder = closed.display();
    assert_eq!(
        (card.state, card.findings),
        (
            State::Unknown,
            vec![format!(
                "The signature files in {folder} cannot be looked for: the collector's user may \
                 not search the folder {folder}; let every user search it (chmod o+x {folder})."
            )]
        )
    );
}

#[test]
fn a_refresh_log_row_longer_than_fangfrisch_writes_costs_the_log_not_the_memory() {
    // Whoever writes Fangfrisch's database can write one row of any length;
    // a reader takes no value of more than 16 MiB, so such a row costs the
    // log, which the card names, and not the collector's memory.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fangfrisch.sqlite");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE refreshlog(path TEXT, updated TEXT)")
        .unwrap();
    db.execute(
        "INSERT INTO refreshlog VALUES(hex(zeroblob(?1)) || '/other.ndb', '2026-10-29 06:00:00')",
        [8 << 20],
    )
    .unwrap();
    db.execute(
        "INSERT INTO refreshlog VALUES('/var/lib/clamav/daily.cld', '2026-10-29 06:00:00')",
        [],
    )
    .unwrap();
    drop(db);
    let listed = ["daily.cld".to_owned()];
    assert_eq!(
        refresh_log(&path, &listed),
        Err("string or blob too big".to_owned())
    );
}
