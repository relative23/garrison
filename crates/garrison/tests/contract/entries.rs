//! The macro filter's entry in every state setup meets: whatever setup's
//! note holds, whether garrison.toml has `[milter]`, whichever entries
//! Stalwart holds, and wherever a run stops. No run that ends in success
//! leaves Stalwart asking 127.0.0.1 where nothing answers, a run that
//! refuses changes no entry and names each one asked in vain, and no run
//! changes another program's entry. Stalwart asks the entries as it read
//! them last (measured here with mail), so a run that changed them and
//! stopped before Stalwart read its settings again leaves setup's note
//! saying so, for doctor and the installer to see.

use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::process::{Command, Stdio};

use garrison_testing::config_text;
use garrison_testing::lab::{Lab, random_hex};
use garrison_testing::smtp::Smtp;
use serde_json::{Value, json};

use super::stopper::{Stop, Stopper};
use super::{Setup, forget, lab, text};

/// A port of this host where a milter answers, for as long as the test runs.
fn filter() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        garrison_milter::server::serve(
            &listener,
            garrison_milter::Settings {
                max_bytes: 1024,
                ..Default::default()
            },
        );
    });
    port
}

/// A port of this host where nothing listens.
fn silent() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An entry as setup writes it, for the filter on `port`.
fn written(port: u16) -> Value {
    json!({"host": "127.0.0.1", "port": port, "enable": {"match": {}, "else": "true"},
        "stages": {"data": true}, "tempFailOnError": true})
}

/// The ports of this test.
pub(super) struct Ports {
    /// Where the macro filter answers.
    pub(super) filter: u16,
    /// Where another program's milter answers.
    pub(super) other: u16,
    /// The filter's port before it moved, where nothing answers now.
    pub(super) old: u16,
    /// Where another program's milter answered once.
    pub(super) gone: u16,
}

impl Ports {
    fn all(&self) -> [u16; 4] {
        [self.filter, self.other, self.old, self.gone]
    }

    /// Whether nothing answers at `port`.
    fn silent(&self, port: u64) -> bool {
        port == u64::from(self.old) || port == u64::from(self.gone)
    }
}

/// Stalwart's entries that ask this test's ports, by ID.
pub(super) fn milters(lab: &Lab, ports: &Ports) -> BTreeMap<String, Value> {
    lab.call("x:MtaMilter/get", &json!({"ids": null}))["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| {
            entry["host"] == "127.0.0.1"
                && ports
                    .all()
                    .iter()
                    .any(|port| entry["port"] == u64::from(*port))
        })
        .map(|entry| (entry["id"].as_str().unwrap().to_owned(), entry.clone()))
        .collect()
}

/// Every entry of this test out of Stalwart.
fn clear(lab: &Lab, ports: &Ports) {
    let ids: Vec<String> = milters(lab, ports).into_keys().collect();
    if !ids.is_empty() {
        lab.call("x:MtaMilter/set", &json!({ "destroy": ids }));
    }
}

fn reload(lab: &Lab) {
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
}

/// The entries of `held` that ask in vain: switched on, at 127.0.0.1 where
/// nothing answers.
pub(super) fn in_vain(held: &BTreeMap<String, Value>, ports: &Ports) -> Vec<String> {
    held.values()
        .filter(|entry| {
            entry["enable"]["else"] != "false"
                && entry["port"]
                    .as_u64()
                    .is_some_and(|port| ports.silent(port))
        })
        .map(|entry| format!("127.0.0.1:{}", entry["port"]))
        .collect()
}

/// What Stalwart answers at the end of a message's data.
fn handed_in(smtp: &str) -> String {
    let mut session = Smtp::connect(smtp);
    for command in [
        "EHLO contract.example.net",
        "MAIL FROM:<sender@contract.example.net>",
        "RCPT TO:<admin@example.test>",
        "DATA",
    ] {
        session.command(command);
    }
    let message = format!(
        "From: <sender@contract.example.net>\r\nTo: <admin@example.test>\r\nSubject: entry\r\n\
         Message-ID: <{}@contract.example.net>\r\n\r\nNothing attached.\r\n.",
        random_hex(8)
    );
    let answer = session.command(&message);
    session.command("QUIT");
    answer
}

/// Stalwart's own behaviour, on which the rest stands: an entry it asks in
/// vain defers every message, and it asks its entries as it read them last,
/// so an entry made or taken out counts only once it reads its settings.
fn stalwart_asks_what_it_read_last(lab: &Lab, ports: &Ports) {
    let smtp = std::env::var("GARRISON_LAB_SMTP").unwrap();
    let wait = || std::thread::sleep(std::time::Duration::from_secs(2));
    reload(lab);
    wait();
    let taken = handed_in(&smtp);
    assert!(taken.starts_with("250"), "before: {taken}");
    let made = lab.call(
        "x:MtaMilter/set",
        &json!({"create": {"n": written(ports.old)}}),
    );
    let id = made["created"]["n"]["id"].as_str().unwrap().to_owned();
    let unread = handed_in(&smtp);
    reload(lab);
    wait();
    let read = handed_in(&smtp);
    lab.call("x:MtaMilter/set", &json!({ "destroy": [id] }));
    let removed = handed_in(&smtp);
    reload(lab);
    wait();
    let again = handed_in(&smtp);
    for (when, answer, code) in [
        ("made, not read", &unread, "250"),
        ("made and read", &read, "451"),
        ("taken out, not read", &removed, "451"),
        ("taken out and read", &again, "250"),
    ] {
        assert!(answer.starts_with(code), "{when}: {answer}");
    }
}

/// What setup's note holds in a state.
#[derive(Clone, Copy, Debug)]
pub(super) enum Note {
    Missing,
    Empty,
    /// The ID of the entry `g`.
    Garrisons,
    /// An ID Stalwart has no entry of.
    Lost,
}

/// One state: garrison.toml with or without the filter, setup's note, and
/// Stalwart's entries by name and port: `g` Garrison's, `d` a second one
/// for the filter, `o` another program's.
pub(super) struct State<'a> {
    pub(super) milter: bool,
    pub(super) note: Note,
    pub(super) entries: &'a [(&'a str, u16)],
}

/// The configuration of a state, with Stalwart at `url`.
fn settings(setup: &Setup, url: &str, milter: bool, ports: &Ports) -> String {
    let base = config_text(&setup.directory, url);
    if milter {
        format!("{base}\n[milter]\nport = {}\n", ports.filter)
    } else {
        base
    }
}

/// Bring Stalwart and the folder to `state`, as Stalwart reads them; the
/// IDs of its entries by name.
pub(super) fn arrange(
    lab: &Lab,
    setup: &Setup,
    ports: &Ports,
    state: &State<'_>,
) -> BTreeMap<String, String> {
    clear(lab, ports);
    let mut ids = BTreeMap::new();
    for (name, port) in state.entries {
        let made = lab.call("x:MtaMilter/set", &json!({"create": {"n": written(*port)}}));
        ids.insert(
            (*name).to_owned(),
            made["created"]["n"]["id"].as_str().unwrap().to_owned(),
        );
    }
    reload(lab);
    let note = setup.directory.join("credentials/stalwart-milter-id");
    let _ = fs::remove_file(&note);
    let held = match state.note {
        Note::Missing => None,
        Note::Empty => Some(String::new()),
        Note::Garrisons => Some(ids.get("g").cloned().unwrap_or_else(|| "lost".to_owned())),
        Note::Lost => Some("lost".to_owned()),
    };
    if let Some(held) = held {
        garrison_testing::write_private(&note, format!("{held}\n").as_bytes());
    }
    fs::write(
        setup.directory.join("garrison.toml"),
        settings(setup, &lab.url, state.milter, ports),
    )
    .unwrap();
    ids
}

/// A setup run, through a relay that stops it at request `at` as `stop`
/// says, or that stops it nowhere: its exit code, what it said and the
/// requests it sent.
pub(super) fn through(
    lab: &Lab,
    setup: &Setup,
    ports: &Ports,
    milter: bool,
    at: Option<(usize, Stop)>,
) -> (Option<i32>, String, Vec<String>) {
    let (number, stop) = at.unwrap_or((usize::MAX, Stop::Lost));
    let relay = Stopper::new(&lab.url, number, stop);
    let path = setup.directory.join("garrison.toml");
    fs::write(&path, settings(setup, &relay.url, milter, ports)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_garrison"))
        .arg("--config")
        .arg(&path)
        .args(setup.arguments(&["--skip-metrics"]))
        .env_remove("CREDENTIALS_DIRECTORY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    relay.watch(child.id());
    let output = child.wait_with_output().unwrap();
    fs::write(&path, settings(setup, &lab.url, milter, ports)).unwrap();
    (output.status.code(), text(&output), relay.asked())
}

/// What setup's note holds, if it is there.
pub(super) fn noted(setup: &Setup) -> Option<String> {
    fs::read_to_string(setup.directory.join("credentials/stalwart-milter-id"))
        .ok()
        .map(|held| held.trim().to_owned())
}

/// What is wrong after a run that ended with `code` and said `said`, from
/// `before` to `after`.
pub(super) fn faults(
    state: &State<'_>,
    ports: &Ports,
    (code, said): (Option<i32>, &str),
    (before, after): (&BTreeMap<String, Value>, &BTreeMap<String, Value>),
    note: Option<&str>,
) -> Vec<String> {
    let mut faults = Vec::new();
    if code == Some(0) {
        let vain = in_vain(after, ports);
        if !vain.is_empty() {
            faults.push(format!("success, and Stalwart asks {vain:?} in vain"));
        }
        let at: Vec<&String> = after
            .iter()
            .filter(|(_, entry)| entry["port"] == u64::from(ports.filter))
            .map(|(id, _)| id)
            .collect();
        match (state.milter, note) {
            (true, Some(id)) if at == [id] => {}
            (false, None) => {}
            (milter, note) => faults.push(format!(
                "success, with [milter] {milter}, the entries at the filter's port {at:?} and \
                 the note {note:?}"
            )),
        }
    } else {
        for address in in_vain(before, ports) {
            if !said.contains(&address) {
                faults.push(format!("the refusal does not name {address}"));
            }
        }
        if !said.contains("Run `garrison stalwart setup") {
            faults.push("the refusal names no run that mends it".to_owned());
        }
        if before != after {
            faults.push("a run that refused changed Stalwart's entries".to_owned());
        }
    }
    for (id, entry) in before {
        let others =
            entry["port"] == u64::from(ports.other) || entry["port"] == u64::from(ports.gone);
        if others && after.get(id) != Some(entry) {
            faults.push(format!("another program's entry {id} changed"));
        }
    }
    faults
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn no_run_of_setup_leaves_stalwart_asking_a_filter_in_vain() {
    let (_guard, lab) = lab();
    let setup = Setup::new(&lab, "http://127.0.0.1:9/webhook");
    let credentials = setup.directory.join("credentials");
    forget(&lab, &credentials);
    let ports = Ports {
        filter: filter(),
        other: filter(),
        old: silent(),
        gone: silent(),
    };
    clear(&lab, &ports);
    stalwart_asks_what_it_read_last(&lab, &ports);
    let first = setup.run(&["--skip-metrics"]);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first));
    let mut found = Vec::new();
    every_state(&lab, &setup, &ports, &mut found);
    super::entry_stops::every_stop(&lab, &setup, &ports, &mut found);
    clear(&lab, &ports);
    reload(&lab);
    forget(&lab, &credentials);
    assert_eq!(found, Vec::<String>::new(), "{}", found.join("\n\n"));
}

/// Each state once, with a plain run; where it refuses, the run after the
/// entries it named were taken out, as the Stalwart WebUI takes them out.
fn every_state(lab: &Lab, setup: &Setup, ports: &Ports, found: &mut Vec<String>) {
    let (filter, other, old, gone) = (ports.filter, ports.other, ports.old, ports.gone);
    let sets: [&[(&str, u16)]; 8] = [
        &[],
        &[("g", filter)],
        &[("g", filter), ("d", filter)],
        &[("g", old)],
        &[("g", filter), ("o", other)],
        &[("g", filter), ("o", gone)],
        &[("o", gone)],
        &[("g", old), ("o", other)],
    ];
    for milter in [true, false] {
        for note in [Note::Missing, Note::Empty, Note::Garrisons, Note::Lost] {
            for entries in sets {
                let state = State {
                    milter,
                    note,
                    entries,
                };
                let described = format!("[milter] {milter}, note {note:?}, entries {entries:?}");
                arrange(lab, setup, ports, &state);
                let before = milters(lab, ports);
                let (code, said, _) = through(lab, setup, ports, milter, None);
                let after = milters(lab, ports);
                let mut wrong = faults(
                    &state,
                    ports,
                    (code, &said),
                    (&before, &after),
                    noted(setup).as_deref(),
                );
                if code != Some(0) && wrong.is_empty() {
                    // The operator takes out what the refusal named.
                    let named: Vec<&String> = after
                        .iter()
                        .filter(|(_, entry)| {
                            entry["port"]
                                .as_u64()
                                .is_some_and(|port| ports.silent(port))
                        })
                        .map(|(id, _)| id)
                        .collect();
                    lab.call("x:MtaMilter/set", &json!({ "destroy": named }));
                    reload(lab);
                    let mended = milters(lab, ports);
                    let (code, again, _) = through(lab, setup, ports, milter, None);
                    let last = milters(lab, ports);
                    wrong.extend(
                        faults(
                            &state,
                            ports,
                            (code, &again),
                            (&mended, &last),
                            noted(setup).as_deref(),
                        )
                        .into_iter()
                        .map(|fault| format!("after the named entries went: {fault}: {again}")),
                    );
                }
                if !wrong.is_empty() {
                    found.push(format!("{described}: {}\n{said}", wrong.join("; ")));
                }
            }
        }
    }
}
