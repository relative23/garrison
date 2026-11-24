use std::fs;

use serde_json::{Value, json};

use super::super::Level;
use super::*;

/// Stalwart's milters as it answers them.
fn read(list: &Value) -> Vec<Entry> {
    serde_json::from_value(list.clone()).unwrap()
}

/// An entry as setup writes it, at `port`, deferring mail where `defer`.
fn row(id: &str, port: u16, defer: bool) -> Value {
    json!({"id": id, "host": "127.0.0.1", "port": port,
        "enable": {"match": {}, "else": "true"}, "stages": {"data": true},
        "tempFailOnError": defer})
}

fn said(findings: &[Finding]) -> Vec<(Level, &str)> {
    findings
        .iter()
        .map(|finding| (finding.level, finding.what.as_str()))
        .collect()
}

const NOTHING: fn(u16) -> bool = |_| false;

#[test]
fn a_filter_that_does_not_answer_fails_with_where_to_look() {
    assert_eq!(answering(8096, Ok(())).level, Level::Ok);
    let silent = answering(8096, Err("Connection refused".to_owned()));
    assert_eq!(
        (silent.level, silent.what.as_str()),
        (
            Level::Fail,
            "the macro milter does not answer on 127.0.0.1:8096: Connection refused"
        )
    );
}

/// What doctor says of `entries` where garrison.toml has the filter on
/// `port`, deferring mail while it does not answer where `defer`, and
/// setup's note names `noted`.
fn configured_as(
    (port, defer): (u16, bool),
    noted: Option<&str>,
    entries: &[Entry],
    answers: &dyn Fn(u16) -> bool,
) -> Vec<Finding> {
    let note = noted.map_or(Note::Missing, |id| Note::Named(id.to_owned()));
    judged(Some((port, defer)), &note, entries, &[], answers)
}

/// Stalwart asks the filter where the configuration has it, as setup
/// entered it; each way its entry can differ is named with the setup that
/// mends it.
#[test]
fn stalwart_is_held_to_the_entry_the_configuration_makes() {
    let entered = read(&json!([row("m", 8096, true)]));
    assert_eq!(
        said(&configured_as((8096, true), Some("m"), &entered, &NOTHING)),
        [(
            Level::Ok,
            "Stalwart asks the macro milter on 127.0.0.1:8096 about every message and defers \
             mail while it does not answer"
        )]
    );
    // The port changed without setup: Stalwart asks where nothing answers.
    let moved = configured_as((8097, true), Some("m"), &entered, &NOTHING);
    assert_eq!(
        said(&moved),
        [(
            Level::Fail,
            "Stalwart asks the macro milter at 127.0.0.1:8096, but the configuration has it on \
             127.0.0.1:8097, where nothing answers: Stalwart defers all incoming mail"
        )]
    );
    assert_eq!(moved[0].fix.as_deref(), Some(SETUP));
    // Where something answers there, nothing is said of the mail.
    let answered = configured_as((8097, true), Some("m"), &entered, &|_| true);
    assert!(
        answered[0].what.ends_with("on 127.0.0.1:8097"),
        "{}",
        answered[0].what
    );
    // when_unreachable changed without setup.
    let accepting = configured_as((8096, false), Some("m"), &entered, &NOTHING);
    assert_eq!(
        said(&accepting),
        [(
            Level::Warn,
            "Stalwart defers mail while the macro milter does not answer, though \
             when_unreachable is \"accept\""
        )]
    );
    // No entry at all, or none setup's note names and none at the address,
    // beside another program's milter that answers.
    for (noted, list) in [
        (None, json!([])),
        (Some("gone"), json!([row("x", 9000, true)])),
    ] {
        let none = configured_as((8096, true), noted, &read(&list), &|port| port == 9000);
        assert_eq!(none.len(), 1, "{:?}", said(&none));
        assert_eq!(none[0].level, Level::Warn);
        assert!(
            none[0].what.starts_with("Stalwart has no entry"),
            "{}",
            none[0].what
        );
    }
    // Without the note, an entry at the address is the filter's.
    let unnoted = configured_as((8096, true), None, &entered, &NOTHING);
    assert_eq!(unnoted[0].level, Level::Ok, "{:?}", said(&unnoted));
}

#[test]
fn an_entry_switched_off_asked_too_early_or_twice_is_named() {
    let mut off = row("m", 8096, true);
    off["enable"] = json!({"match": {}, "else": "false"});
    let mut early = row("m", 8096, true);
    early["stages"] = json!({"rcpt": true});
    let mut conditional = row("m", 8096, true);
    conditional["enable"] = json!({"match": {"0": {"if": "x", "then": "true"}}, "else": "false"});
    for (entry, words) in [
        (off, "is switched off"),
        (
            conditional,
            "is switched on only under conditions of its own",
        ),
        (
            early,
            "does not ask the macro milter on 127.0.0.1:8096 once a message's data",
        ),
    ] {
        let found = configured_as((8096, true), Some("m"), &read(&json!([entry])), &NOTHING);
        assert_eq!(found.len(), 1, "{:?}", said(&found));
        assert_eq!(found[0].level, Level::Warn);
        assert!(found[0].what.contains(words), "{}", found[0].what);
        assert_eq!(found[0].fix.as_deref(), Some(SETUP));
    }
    let twice = read(&json!([row("m", 8096, true), row("n", 8096, true)]));
    let found = configured_as((8096, true), Some("m"), &twice, &NOTHING);
    assert_eq!(
        said(&found),
        [(
            Level::Warn,
            "Stalwart has 2 entries for the macro milter on 127.0.0.1:8096"
        )]
    );
}

/// With the section gone, what Stalwart still has decides: an entry that
/// still asks the filter fails, a note of one that is gone, or of none, is
/// a warning, and a Stalwart that cannot be asked leaves the note's word.
#[test]
fn a_filter_the_configuration_dropped_is_judged_by_what_stalwart_holds() {
    let entered = read(&json!([row("m", 8096, true)]));
    let noted = Note::Named("m".to_owned());
    let still = judged(None, &noted, &entered, &[], &|_| true);
    assert_eq!(
        said(&still),
        [(
            Level::Fail,
            "Stalwart still asks the macro milter at 127.0.0.1:8096, which the configuration no \
             longer has"
        )]
    );
    assert!(still[0].fix.as_deref().unwrap().starts_with(SETUP));
    // Once the filter has stopped, what that does to mail.
    let stopped = judged(None, &noted, &entered, &[], &NOTHING);
    assert!(
        stopped[0]
            .what
            .ends_with(", where nothing answers: Stalwart defers all incoming mail"),
        "{}",
        stopped[0].what
    );
    for note in [noted, Note::Empty] {
        let stale = judged(None, &note, &[], &[], &NOTHING);
        assert_eq!(stale.len(), 1, "{:?}", said(&stale));
        assert_eq!(stale[0].level, Level::Warn, "{}", stale[0].line());
        assert!(
            stale[0]
                .fix
                .as_deref()
                .unwrap()
                .contains("which removes the note")
        );
    }
    let unasked = unasked(
        None,
        &Note::Named("m".to_owned()),
        "Stalwart did not answer",
    );
    assert_eq!(unasked.level, Level::Fail);
    assert!(
        unasked.what.ends_with(": Stalwart did not answer"),
        "{}",
        unasked.what
    );
}

/// A note of a run that stopped before Stalwart read its settings again:
/// Stalwart may ask what it held before, which doctor cannot see, so it
/// judges no entry by what Stalwart holds and names the setup that ends it.
#[test]
fn a_run_that_stopped_before_stalwart_read_it_is_named() {
    let entered = read(&json!([row("m", 8096, true)]));
    for filter in [Some((8096, true)), None] {
        for id in [Some("m".to_owned()), None] {
            let found = judged(filter, &Note::Pending(id), &entered, &[], &|_| true);
            assert_eq!(found.len(), 1, "{:?}", said(&found));
            assert_eq!(found[0].level, Level::Fail);
            assert!(
                found[0].what.starts_with("setup's last run changed"),
                "{}",
                found[0].what
            );
            assert_eq!(found[0].fix.as_deref(), Some(SETUP));
        }
    }
}

/// An entry that asks where the running filter listens is the filter's,
/// whatever the note says: with the section gone it still asks the filter,
/// which setup takes out before it stops the filter; with the section on
/// another port it is the filter's entry at its old port, which setup moves.
/// Where Stalwart also asks an entry in vain that setup cannot tell for the
/// filter's, setup refuses, so those lines name setup for afterwards.
#[test]
fn an_entry_the_running_filter_answers_is_the_filters() {
    let entered = read(&json!([row("g", 8096, true)]));
    for note in [Note::Missing, Note::Empty, Note::Named("lost".to_owned())] {
        let still = judged(None, &note, &entered, &[8096], &|port| port == 8096);
        assert_eq!(
            said(&still),
            [(
                Level::Fail,
                "Stalwart still asks the macro milter at 127.0.0.1:8096, which the \
                 configuration no longer has"
            )],
            "{note:?}"
        );
        let moving = judged(Some((8097, true)), &note, &entered, &[8096], &|_| true);
        assert_eq!(moving.len(), 1, "{:?}", said(&moving));
        assert!(
            moving[0]
                .what
                .starts_with("Stalwart asks the macro milter at 127.0.0.1:8096, but"),
            "{}",
            moving[0].what
        );
        assert_eq!(moving[0].fix.as_deref(), Some(SETUP));
    }
    let beside = read(&json!([row("g", 8096, true), row("o", 9000, true)]));
    let found = judged(None, &Note::Missing, &beside, &[8096], &|port| port == 8096);
    assert_eq!(found.len(), 2, "{:?}", said(&found));
    assert!(
        found[0].what.contains("127.0.0.1:9000 (entry o)"),
        "{}",
        found[0].what
    );
    assert_eq!(found[0].fix.as_deref(), Some(entries::REMOVE));
    assert!(
        found[1].fix.as_deref().unwrap().starts_with(AFTER),
        "{}",
        found[1].line()
    );
}

/// doctor asks Stalwart with the collector's key, as the collector does;
/// without the key it says why it could not ask, never "ok".
#[test]
fn stalwart_is_asked_with_the_collectors_key() {
    let directory = tempfile::tempdir().unwrap();
    // A port where nothing listens: the filter's own line fails, which is
    // not what this test is about.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let stalwart = garrison_testing::http::serve(vec![garrison_testing::http::json(&json!({
        "methodResponses": [["x:MtaMilter/get", {"list": [row("m", port, true)]}, "0"]]
    }))]);
    let text = format!(
        "{}\n[milter]\nport = {port}\n",
        garrison_testing::config_text(directory.path(), &stalwart.url)
    );
    let config = garrison_core::config::from_text(&text).unwrap();
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    let unkeyed = checks(&config, &credentials);
    assert_eq!(unkeyed[1].level, Level::Unknown, "{:?}", said(&unkeyed));
    assert!(
        unkeyed[1].what.contains("the collector's API key"),
        "{}",
        unkeyed[1].what
    );
    garrison_testing::write_private(
        &credentials.path(&config.collector.native_key),
        garrison_testing::NATIVE_KEY.as_bytes(),
    );
    garrison_testing::write_private(
        &config.credentials_directory.join(units::MILTER_ENTRY),
        b"m\n",
    );
    let found = checks(&config, &credentials);
    let asked = stalwart.requests().remove(0);
    assert!(
        asked.contains(&format!("Bearer {}", garrison_testing::NATIVE_KEY)),
        "{asked}"
    );
    assert!(asked.contains("x:MtaMilter/get"), "{asked}");
    assert_eq!(found[1].level, Level::Ok, "{:?}", said(&found));
}

/// A port of this host where a milter answers, served until the test ends.
fn answering_milter() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
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
fn silent_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// What doctor says of the macro milter where garrison.toml has the filter
/// on `port`, or has no `[milter]`, setup's note holds `note`, or is
/// missing, and Stalwart holds `entries`.
fn doctor_on(port: Option<u16>, note: Option<&str>, entries: &Value) -> Vec<Finding> {
    let directory = tempfile::tempdir().unwrap();
    let stalwart = garrison_testing::http::serve(vec![garrison_testing::http::json(&json!({
        "methodResponses": [["x:MtaMilter/get", {"list": entries}, "0"]]
    }))]);
    let section = port.map_or_else(String::new, |port| format!("\n[milter]\nport = {port}\n"));
    let text = format!(
        "{}{section}",
        garrison_testing::config_text(directory.path(), &stalwart.url)
    );
    let config = garrison_core::config::from_text(&text).unwrap();
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    garrison_testing::write_private(
        &credentials.path(&config.collector.native_key),
        garrison_testing::NATIVE_KEY.as_bytes(),
    );
    if let Some(note) = note {
        garrison_testing::write_private(
            &config.credentials_directory.join(units::MILTER_ENTRY),
            note.as_bytes(),
        );
    }
    checks(&config, &credentials)
}

/// Whatever setup's note holds and garrison.toml has, wherever Stalwart's
/// entries ask, doctor never leaves a filter Stalwart asks in vain unsaid:
/// an entry switched on that asks 127.0.0.1 where nothing answers gets a
/// line that names it, with `garrison stalwart setup` where setup takes it
/// for Garrison's and mends it, and the Stalwart WebUI where setup cannot
/// tell whose it is. An empty note names no entry.
#[test]
fn no_filter_stalwart_asks_in_vain_goes_unsaid() {
    let filter = answering_milter();
    let other = answering_milter();
    let old = silent_port();
    let gone = silent_port();
    let held = [None, Some(""), Some("g\n"), Some("lost\n")];
    let entries = [
        vec![],
        vec![row("g", filter, true)],
        vec![row("g", filter, true), row("d", filter, true)],
        vec![row("g", old, true)],
        vec![row("g", filter, true), row("o", other, true)],
        vec![row("g", filter, true), row("o", gone, true)],
        vec![row("o", gone, true)],
        vec![row("g", old, true), row("o", other, true)],
    ];
    let mut faults = Vec::new();
    for configured in [Some(filter), None] {
        for note in held {
            for listed in &entries {
                let found = doctor_on(configured, note, &json!(listed));
                let shown: Vec<String> = found.iter().map(Finding::line).collect();
                let state = format!("[milter] {configured:?}, note {note:?}, entries {listed:?}");
                let noted = note.map(str::trim).filter(|id| !id.is_empty());
                for entry in listed {
                    let port = u16::try_from(entry["port"].as_u64().unwrap()).unwrap();
                    if port != old && port != gone {
                        continue;
                    }
                    // Setup takes the noted entry for Garrison's, and with
                    // the section there every entry at its port.
                    let garrisons = noted == entry["id"].as_str();
                    let address = format!("127.0.0.1:{port}");
                    let named = found.iter().find(|finding| finding.what.contains(&address));
                    let fault = match named {
                        None => Some("no line names it"),
                        Some(finding) if finding.level == Level::Ok => Some("its line says ok"),
                        Some(finding) => {
                            let fix = finding.fix.as_deref().unwrap_or_default();
                            if garrisons && !fix.contains("garrison stalwart setup") {
                                Some("setup mends it, and its fix does not name setup")
                            } else if !garrisons && !fix.contains("Stalwart WebUI") {
                                Some("setup cannot tell it is Garrison's, and the fix is setup")
                            } else {
                                None
                            }
                        }
                    };
                    if let Some(fault) = fault {
                        faults.push(format!(
                            "{state}: the entry at {address}, where nothing answers: {fault}:\n{}",
                            shown.join("\n")
                        ));
                    }
                }
                if note == Some("") && shown.iter().any(|line| line.contains("no longer has")) {
                    faults.push(format!(
                        "{state}: an empty note names no entry, but a line says Stalwart no \
                         longer has it:\n{}",
                        shown.join("\n")
                    ));
                }
            }
        }
    }
    assert_eq!(faults, Vec::<String>::new(), "{}", faults.join("\n\n"));
}
