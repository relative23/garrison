use std::fs;

use serde_json::{Value, json};

use super::super::{answering_milter, silent_port};
use super::*;

/// Stalwart's milters as it answers them.
fn read(list: &Value) -> Vec<Entry> {
    serde_json::from_value(list.clone()).unwrap()
}

/// Stalwart asks an entry in vain where no milter answers at an address its
/// host and port resolve to: a port that does not answer, a host where none
/// listens or a name that does not resolve. One switched off, and one
/// without a port, is not.
#[test]
fn an_entry_is_asked_in_vain_where_no_milter_answers_it() {
    let milter = answering_milter();
    let (_held, silent) = silent_port();
    let stored = read(&json!([
        {"id": "a", "host": "127.0.0.1", "port": milter},
        {"id": "b", "host": "0.0.0.0", "port": milter},
        {"id": "c", "host": "127.1", "port": milter},
        {"id": "d", "host": "localhost", "port": milter},
        {"id": "e", "host": "::1", "port": milter},
        {"id": "f", "host": "127.0.0.2", "port": milter},
        {"id": "g", "host": "127.0.0.1", "port": silent},
        {"id": "h", "host": "garrison-test.invalid", "port": milter},
        {"id": "i", "host": "127.0.0.1", "port": silent,
            "enable": {"match": {}, "else": "false"}},
        {"id": "j", "host": "127.0.0.1", "port": null},
    ]));
    let found = vain(&stored, &|entry| entry.answers(WITHIN));
    let ids: Vec<&str> = found.iter().map(|entry| entry.id.as_str()).collect();
    assert_eq!(ids, ["e", "f", "g", "h"]);
}

/// What listens without speaking the protocol is no milter.
#[test]
fn a_port_that_listens_without_a_milters_answer_does_not_count() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = (&stream).write_all(b"220 mail.example.test ESMTP\r\n");
        }
    });
    assert!(!answers_at(address, WITHIN));
    let milter = answering_milter();
    assert!(answers_at(
        SocketAddr::from(([127, 0, 0, 1], milter)),
        WITHIN
    ));
}

/// What doctor says where Stalwart answers its milters with `answer` and
/// the collector's key is there.
fn doctor_with(answer: String) -> Vec<Finding> {
    let directory = tempfile::tempdir().unwrap();
    let stalwart = garrison_testing::http::serve(vec![answer]);
    let text = garrison_testing::config_text(directory.path(), &stalwart.url);
    let config = garrison_core::config::from_text(&text).unwrap();
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    garrison_testing::write_private(
        &credentials.path(&config.collector.native_key),
        garrison_testing::NATIVE_KEY.as_bytes(),
    );
    checks(&config, &credentials)
}

/// The same, with Stalwart's milters `entries`.
fn doctor_on(entries: &Value) -> Vec<Finding> {
    doctor_with(garrison_testing::http::json(&json!({
        "methodResponses": [["x:MtaMilter/get", {"list": entries}, "0"]]
    })))
}

/// doctor asks Stalwart with the collector's key, as the collector does. A
/// milter that answers goes unsaid; one that does not is a failure where
/// Stalwart defers mail meanwhile and a warning where it takes mail
/// unscanned; a key Stalwart refuses is named as refused, since one it does
/// not know (401) wants a new key, which the key's own line names.
#[test]
fn every_entry_stalwart_asks_in_vain_is_said_and_no_other() {
    let milter = answering_milter();
    let (_held, silent) = silent_port();
    let row = |id: &str, port: u16, defer: bool| {
        json!({"id": id, "host": "127.0.0.1", "port": port,
            "enable": {"match": {}, "else": "true"}, "tempFailOnError": defer})
    };
    assert_eq!(doctor_on(&json!([])), []);
    assert_eq!(doctor_on(&json!([row("a", milter, true)])), []);
    let stored = json!([
        row("a", milter, true),
        row("d", silent, true),
        row("u", silent, false)
    ]);
    let entries = read(&stored);
    assert_eq!(
        doctor_on(&stored),
        [
            Finding::fail(states::stranded(&entries[1])),
            Finding::warn(states::stranded_unscanned(&entries[2])),
        ]
    );
    let refused = garrison_stalwart::Error::InvalidToken(String::new());
    assert_eq!(
        doctor_with(garrison_testing::http::answer(401, "")),
        [Finding::unknown(states::stranded_unknown(
            &states::unasked("", refused)
        ))]
    );
}
