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
    // These files are no databases of ClamAV's, so nothing is asked about
    // them and the card says what it does not know.
    let old = aged(49);
    assert_eq!(old.state, State::Warning);
    assert_eq!(
        old.findings,
        [
            "daily.cld was last updated 49 hours ago; whether ClamAV has published a newer one \
          since is not known: the file names no version of its own."
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
/// A resolver on a free port for one question about `ClamAV`'s newest
/// databases: it answers with `record` as the TXT record, or with the error
/// code SERVFAIL, and ends with the name it was asked for.
fn resolver(record: Option<&'static str>) -> (SocketAddr, std::thread::JoinHandle<String>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    // A card that does not ask fails its test instead of holding it.
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let served = std::thread::spawn(move || {
        let mut question = [0; 512];
        let (length, asker) = socket.recv_from(&mut question).unwrap();
        // The header answers the question's number, then the question as it
        // came, then one record that points back at the question's name.
        let mut answer = question[..length].to_vec();
        answer[2..8].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 1]);
        match record {
            Some(text) => {
                answer.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 7, 8]);
                let length = u8::try_from(text.len()).unwrap();
                answer.extend_from_slice(&[0, length + 1, length]);
                answer.extend_from_slice(text.as_bytes());
            }
            None => answer[2..8].copy_from_slice(&[0x81, 0x82, 0, 1, 0, 0]),
        }
        socket.send_to(&answer, asker).unwrap();
        // The name as written: each label's length gives way to a dot.
        let mut name = String::new();
        let mut at = 12;
        while question[at] != 0 {
            let end = at + 1 + usize::from(question[at]);
            name.push_str(std::str::from_utf8(&question[at + 1..end]).unwrap());
            name.push('.');
            at = end;
        }
        name
    });
    (address, served)
}

#[test]
fn an_old_daily_database_warns_only_where_clamav_has_published_a_newer_one() {
    use std::time::{Duration, SystemTime};
    let directory = tempfile::tempdir().unwrap();
    let daily = directory.path().join("daily.cld");
    // The header of a database as freshclam leaves it, 512 octets, and
    // what follows it.
    let mut database =
        b"ClamAV-VDB:25 Nov 2026 06-26 +0000:28194:355842:90:X:X:svc.clamav-publisher:1795588019"
            .to_vec();
    database.resize(512, b' ');
    database.extend_from_slice(&[0xff; 64]);
    std::fs::write(&daily, database).unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let checked = SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::try_from(context.now.as_second()).unwrap());
    let card = |hours: u64, resolver: SocketAddr| {
        let file = std::fs::File::options().write(true).open(&daily).unwrap();
        file.set_modified(checked - Duration::from_secs(hours * 3600))
            .unwrap();
        let provider = Clamav::new(&table(&format!(
            "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\ndatabase_directory = \"{0}\"",
            directory.path().display()
        )))
        .unwrap()
        .with_resolver(resolver);
        provider.collect(&context).unwrap().observations.remove(1)
    };
    // ClamAV has published nothing since: the database is days old and the
    // newest there is.
    let (address, served) = resolver(Some("1.4.7:63:28194:1795777200:1:90:49192:339"));
    let newest = card(52, address);
    assert_eq!((newest.state, newest.findings.len()), (State::Ok, 0));
    assert_eq!(served.join().unwrap(), "current.cvd.clamav.net.");
    // Two newer ones were published and did not arrive.
    let (address, served) = resolver(Some("1.4.7:63:28196:1795777200:1:90:49192:339"));
    let behind = card(52, address);
    assert_eq!(behind.state, State::Warning);
    assert_eq!(
        behind.findings,
        [
            "daily.cld was last updated 52 hours ago and is version 28194; ClamAV has published \
          version 28196 since, so the updates do not arrive."
        ]
    );
    served.join().unwrap();
    // The resolver cannot say: the card warns and says what it does not know.
    let (address, served) = resolver(None);
    let unasked = card(52, address);
    assert_eq!(unasked.state, State::Warning);
    assert_eq!(
        unasked.findings,
        [
            "daily.cld was last updated 52 hours ago; whether ClamAV has published a newer one \
          since is not known: the resolver could not answer (SERVFAIL)."
        ]
    );
    served.join().unwrap();
    // A database of the last two days is asked about nowhere: this resolver
    // holds its port and gets no question.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    silent.set_nonblocking(true).unwrap();
    let fresh = card(47, silent.local_addr().unwrap());
    assert_eq!((fresh.state, fresh.findings.len()), (State::Ok, 0));
    let unasked = silent.recv_from(&mut [0; 512]).unwrap_err();
    assert_eq!(unasked.kind(), std::io::ErrorKind::WouldBlock);
}

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

/// The folder, the two configuration files and Fangfrisch's log are where an
/// operator names them, which may be a file system that gives no answer, as
/// a hard NFS mount whose server is gone. Each card waits for its files no
/// longer than the check's time and says so: here the time is past before
/// the files are asked for.
#[test]
fn files_whose_file_system_does_not_answer_leave_the_cards_unknown() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name).display().to_string();
    std::fs::write(path("milter.conf"), "OnInfected Reject\nOnFail Defer\n").unwrap();
    std::fs::write(path("scan.conf"), "ScanArchive yes\n").unwrap();
    std::fs::write(path("daily.cld"), "signatures").unwrap();
    let provider = Clamav::new(&table(&format!(
        "type = \"clamav\"\nmilter_config = \"{0}/milter.conf\"\nclamd_config = \"{0}/scan.conf\"\ndatabase_directory = \"{0}\"",
        directory.path().display()
    )))
    .unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = context(&config, &runner);
    let (signatures, age) = provider.signatures(&context, Instant::now()).unwrap();
    assert_eq!(
        (signatures.state, signatures.findings, age),
        (
            State::Unknown,
            vec![format!(
                "The signature files in {} could not be looked at: its file system did not \
                 answer within 8 seconds.",
                directory.path().display()
            )],
            None
        )
    );
    let configuration = provider.configuration(&context, Instant::now()).unwrap();
    assert_eq!(
        (configuration.state, configuration.findings),
        (
            State::Unknown,
            vec![
                format!(
                    "{} could not be read: its file system did not answer within 8 seconds.",
                    path("milter.conf")
                ),
                format!(
                    "{} could not be read: its file system did not answer within 8 seconds.",
                    path("scan.conf")
                ),
            ]
        )
    );
}
