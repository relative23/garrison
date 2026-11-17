//! A named pipe in place of a file that a check reads, as the user who
//! writes the event history or the Fangfrisch database can put there, holds
//! nothing: every check of the crate returns, and says that what it found is
//! not a regular file. The places are each check's own `paths()` that are no
//! folder, and the event history.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use garrison_core::config::Database;
use serde_json::Value;

use super::*;
use crate::context::Provider;
use crate::testing::{Canned, config, context, table};

/// A named pipe at `path`, which nobody writes to.
fn pipe(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o644),
        0,
    )
    .unwrap();
}

/// A mail server that takes every message, so that the mail test reads the
/// event history for how the spam text was filed.
fn taking() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let _ = writer.write_all(b"220 mail.example.test ESMTP\r\n");
            let mut data = false;
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let reply = match (data, line.as_str()) {
                    (true, ".\r\n") => {
                        data = false;
                        "250 2.0.0 Message queued with id 4b7.\r\n"
                    }
                    (true, _) => "",
                    (false, command) if command.starts_with("DATA") => {
                        data = true;
                        "354 go ahead\r\n"
                    }
                    (false, command) if command.starts_with("QUIT") => break,
                    _ => "250 2.1.0 OK\r\n",
                };
                let _ = writer.write_all(reply.as_bytes());
                line.clear();
            }
        }
    });
    port
}

/// Every text a report shows: findings and table cells.
fn said(observations: &[garrison_core::observations::Observation]) -> Vec<String> {
    let mut texts = Vec::new();
    for observation in observations {
        texts.extend(observation.findings.iter().cloned());
        for row in observation.table.iter().flat_map(|table| &table.rows) {
            texts.extend(row.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    texts
}

/// A check of the crate made with options that name its files in a folder,
/// and the port of a mail server for the mail test.
type Made = fn(&Path, u16) -> Box<dyn Provider + Send>;

#[test]
fn a_pipe_in_place_of_a_file_a_check_reads_holds_no_run() {
    let port = taking();
    // Each check of the crate with options that name its files in the
    // folder it is given.
    let checks: [(&str, Made); 4] = [
        ("clamav", |folder, _| {
            let file = |name: &str| folder.join(name).display().to_string();
            Box::new(
                Clamav::new(&table(&format!(
                    "type = \"clamav\"\nmilter_config = \"{}\"\nclamd_config = \"{}\"\n\
                     database_directory = \"{}\"\nfangfrisch_database = \"{}\"",
                    file("milter.conf"),
                    file("scan.conf"),
                    file("signatures"),
                    file("fangfrisch.sqlite")
                )))
                .unwrap(),
            )
        }),
        ("mail-flow", |_, _| {
            Box::new(Flow::new(&table("type = \"mail-flow\"")).unwrap())
        }),
        ("mail-test", |_, port| {
            Box::new(
                MailTest::new(&table(&format!(
                    "type = \"mail-test\"\nrecipient = \"garrison-test@example.test\"\nport = {port}"
                )))
                .unwrap(),
            )
        }),
        ("senders", |_, _| {
            Box::new(Senders::new(&table("type = \"senders\"")).unwrap())
        }),
    ];
    for (name, make) in checks {
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let directory = tempfile::tempdir().unwrap();
            let check = make(directory.path(), port);
            // A folder stays a folder, with a daily database in it.
            std::fs::create_dir_all(directory.path().join("signatures")).unwrap();
            std::fs::write(directory.path().join("signatures/daily.cld"), "x").unwrap();
            let mut pipes = 0;
            for place in check.paths() {
                if !place.path.is_dir() {
                    pipe(place.path);
                    pipes += 1;
                }
            }
            let config = config(directory.path());
            pipe(&config.database(Database::Events));
            let runner = Canned(String::new());
            let report = check.collect(&context(&config, &runner)).unwrap();
            let _ = sender.send((pipes, said(&report.observations)));
        });
        let (pipes, texts) = receiver
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("{name} waited for a writer of a pipe"));
        // Each pipe that was read is named, the event history among them
        // where the check reads it.
        let named = texts
            .iter()
            .filter(|text| text.contains("not a regular file"))
            .count();
        assert!(named >= pipes.max(1), "{name}: {texts:?}");
    }
}
