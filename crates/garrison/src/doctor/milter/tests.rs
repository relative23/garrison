use std::fs;
use std::net::ToSocketAddrs;

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
        .map(|finding| (finding.level, finding.state.text.as_str()))
        .collect()
}

/// Where a milter answers: at the ports of `ports`.
fn at(ports: &[u16]) -> impl Fn(&Entry) -> bool + '_ {
    |entry| entry.port().is_some_and(|port| ports.contains(&port))
}

#[test]
fn a_filter_that_does_not_answer_fails_with_where_to_look() {
    assert_eq!(answering(8096, Ok(())).level, Level::Ok);
    let silent = answering(8096, Err("Connection refused".to_owned()));
    assert_eq!(
        (silent.level, silent.state.text.as_str()),
        (
            Level::Fail,
            "the macro milter does not answer on 127.0.0.1:8096: Connection refused"
        )
    );
}

/// What doctor says of `entries` where garrison.toml has the filter on
/// `port`, deferring mail while it does not answer where `defer`.
fn configured_as(
    filter: (u16, bool),
    entries: &[Entry],
    listening: &[u16],
    answers: &dyn Fn(&Entry) -> bool,
) -> Vec<Finding> {
    judged(Some(filter), entries, listening, answers)
}

/// Stalwart asks the filter where the configuration has it, as setup
/// entered it; each way its entry can differ is named with the setup that
/// mends it.
#[test]
fn stalwart_is_held_to_the_entry_the_configuration_makes() {
    let entered = read(&json!([row("m", 8096, true)]));
    assert_eq!(
        said(&configured_as((8096, true), &entered, &[], &at(&[8096]))),
        [(
            Level::Ok,
            "Stalwart asks the macro milter on 127.0.0.1:8096 about every message and defers \
             mail while it does not answer"
        )]
    );
    // The port changed without setup while the filter runs at the old one:
    // Stalwart asks it there, until it moves.
    let moved = configured_as((8097, true), &entered, &[8096], &at(&[8096]));
    assert_eq!(
        said(&moved),
        [(
            Level::Fail,
            "Stalwart asks the macro milter at 127.0.0.1:8096, but the configuration has it on \
             127.0.0.1:8097"
        )]
    );
    assert_eq!(
        moved[0].state.fix.as_deref(),
        Some("Run `garrison stalwart setup`.")
    );
    // The filter down: Stalwart asks it where nothing answers.
    let down = configured_as((8096, true), &entered, &[], &at(&[]));
    assert_eq!(
        said(&down),
        [(
            Level::Fail,
            "Stalwart asks the macro milter at 127.0.0.1:8096, where nothing answers: Stalwart \
             defers all incoming mail"
        )]
    );
    // when_unreachable changed without setup.
    let accepting = configured_as((8096, false), &entered, &[], &at(&[8096]));
    assert_eq!(
        said(&accepting),
        [(
            Level::Warn,
            "Stalwart defers mail while the macro milter does not answer, though \
             when_unreachable is \"accept\""
        )]
    );
    // No entry at the filter's port, beside another program's milter that
    // answers.
    for list in [json!([]), json!([row("x", 9000, true)])] {
        let none = configured_as((8096, true), &read(&list), &[], &at(&[9000]));
        assert_eq!(none.len(), 1, "{:?}", said(&none));
        assert_eq!(none[0].level, Level::Warn);
        assert!(
            none[0].state.text.starts_with("Stalwart has no entry"),
            "{}",
            none[0].state.text
        );
    }
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
        let found = configured_as((8096, true), &read(&json!([entry])), &[], &at(&[8096]));
        assert_eq!(found.len(), 1, "{:?}", said(&found));
        assert_eq!(found[0].level, Level::Warn);
        assert!(
            found[0].state.text.contains(words),
            "{}",
            found[0].state.text
        );
        assert_eq!(
            found[0].state.fix.as_deref(),
            Some("Run `garrison stalwart setup`.")
        );
    }
    let twice = read(&json!([row("m", 8096, true), row("n", 8096, true)]));
    let found = configured_as((8096, true), &twice, &[], &at(&[8096]));
    assert_eq!(
        said(&found),
        [(
            Level::Warn,
            "Stalwart has 2 entries for the macro milter on 127.0.0.1:8096"
        )]
    );
}

/// With the section gone, an entry at the port the running filter listens
/// on still asks it and fails, with what Stalwart then does where the
/// filter has stopped; a Stalwart that cannot be asked leaves it unknown.
#[test]
fn a_filter_the_configuration_dropped_is_judged_by_what_stalwart_holds() {
    let entered = read(&json!([row("m", 8096, true)]));
    let still = judged(None, &entered, &[8096], &at(&[8096]));
    assert_eq!(
        said(&still),
        [(
            Level::Fail,
            "Stalwart still asks the macro milter at 127.0.0.1:8096, which the configuration no \
             longer has"
        )]
    );
    assert!(
        still[0]
            .state
            .fix
            .as_deref()
            .unwrap()
            .starts_with("Run `garrison stalwart setup`.")
    );
    // The filter stopped: nothing tells the entry for the filter's, and
    // Stalwart asks it in vain, which setup refuses to leave so.
    let stopped = judged(None, &entered, &[], &at(&[]));
    assert_eq!(stopped.len(), 1, "{:?}", said(&stopped));
    assert!(
        stopped[0]
            .state
            .text
            .ends_with(", where nothing answers: Stalwart defers all incoming mail"),
        "{}",
        stopped[0].state.text
    );
    assert_eq!(stopped[0].state.fix.as_deref(), Some(entries::REMOVE));
    let unasked = unasked(None, "Stalwart did not answer");
    assert_eq!(unasked.level, Level::Unknown);
    assert!(
        unasked.state.text.ends_with(": Stalwart did not answer"),
        "{}",
        unasked.state.text
    );
}

/// An entry that asks where the running filter listens is the filter's:
/// with the section gone it still asks the filter, which setup takes out
/// before it stops the filter; with the section on another port it is the
/// filter's entry at its old port, which setup moves. Where Stalwart also
/// asks an entry in vain that is not the filter's, setup refuses, so those
/// lines name setup for afterwards.
#[test]
fn an_entry_the_running_filter_answers_is_the_filters() {
    let entered = read(&json!([row("g", 8096, true)]));
    let moving = judged(Some((8097, true)), &entered, &[8096], &at(&[8096]));
    assert_eq!(moving.len(), 1, "{:?}", said(&moving));
    assert!(
        moving[0]
            .state
            .text
            .starts_with("Stalwart asks the macro milter at 127.0.0.1:8096, but"),
        "{}",
        moving[0].state.text
    );
    assert_eq!(
        moving[0].state.fix.as_deref(),
        Some("Run `garrison stalwart setup`.")
    );
    let beside = read(&json!([row("g", 8096, true), row("o", 9000, true)]));
    let found = judged(None, &beside, &[8096], &at(&[8096]));
    assert_eq!(found.len(), 2, "{:?}", said(&found));
    assert!(
        found[0].state.text.contains("127.0.0.1:9000 (entry o)"),
        "{}",
        found[0].state.text
    );
    assert_eq!(found[0].state.fix.as_deref(), Some(entries::REMOVE));
    assert!(
        found[1].state.fix.as_deref().unwrap().starts_with(
            "Run `garrison stalwart setup` once the milters named above are out of Stalwart."
        ),
        "{}",
        found[1].line()
    );
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

/// What doctor says of the macro milter where garrison.toml has the filter
/// on `port`, or has no `[milter]`, Stalwart answers its milters with
/// `answer`, and the collector's key is there.
fn doctor_with(port: Option<u16>, answer: String) -> Vec<Finding> {
    let directory = tempfile::tempdir().unwrap();
    let stalwart = garrison_testing::http::serve(vec![answer]);
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
    checks(&config, &credentials)
}

/// The same, with Stalwart's milters `entries`.
fn doctor_on(port: Option<u16>, entries: &Value) -> Vec<Finding> {
    doctor_with(
        port,
        garrison_testing::http::json(&json!({
            "methodResponses": [["x:MtaMilter/get", {"list": entries}, "0"]]
        })),
    )
}

/// doctor asks Stalwart with the collector's key, as the collector does,
/// and says the filter's entry is in order where it answers there; a key
/// Stalwart refuses is named as refused, not as one lacking permissions,
/// since one it does not know (401) wants a new key, which the key's own
/// line names.
#[test]
fn stalwart_is_asked_with_the_collectors_key() {
    let port = answering_milter();
    let found = doctor_on(Some(port), &json!([row("m", port, true)]));
    assert_eq!(said(&found)[0].0, Level::Ok, "{:?}", said(&found));
    assert_eq!(found[1].level, Level::Ok, "{:?}", said(&found));
    let refused = doctor_with(None, garrison_testing::http::answer(401, ""));
    assert_eq!(
        said(&refused),
        [(
            Level::Unknown,
            "whether Stalwart asks a milter where nothing answers: Stalwart refused the \
             collector's API key"
        )]
    );
}

/// Whether a milter answers at `host` and `port` from this host, as a
/// connection there finds one: the test's milters listen on 127.0.0.1 at
/// `milters`.
fn reached(host: &str, port: u16, milters: &[u16]) -> bool {
    milters.contains(&port)
        && format!("{host}:{port}")
            .to_socket_addrs()
            .is_ok_and(|mut all| {
                all.any(|address| std::net::TcpStream::connect_timeout(&address, WITHIN).is_ok())
            })
}

/// Whatever garrison.toml has, under whatever name of this host Stalwart's
/// entries ask, doctor names every entry Stalwart asks in vain: switched
/// on, where no milter answers. Its fix is `garrison stalwart setup` where
/// setup takes it for the filter's, as it asks this host at the configured
/// port, and the Stalwart WebUI where it is another program's.
#[test]
fn no_entry_stalwart_asks_in_vain_goes_unsaid() {
    let filter = answering_milter();
    let other = answering_milter();
    // Held, so that no stand-in for Stalwart started below is given one.
    let ((_old, old), (_gone, gone), (_elsewhere, elsewhere)) = (
        super::super::silent_port(),
        super::super::silent_port(),
        super::super::silent_port(),
    );
    let named = |id: &str, host: &str, port: u16| {
        let mut entry = row(id, port, true);
        entry["host"] = json!(host);
        entry
    };
    let mut sets = vec![
        vec![],
        vec![row("g", filter, true), row("d", filter, true)],
        vec![row("g", old, true)],
        vec![row("g", filter, true), row("o", other, true)],
        vec![row("g", old, true), row("o", other, true)],
    ];
    for name in [
        "127.0.0.1",
        "localhost",
        "::1",
        "[::1]",
        "127.0.0.2",
        "127.1",
        "0.0.0.0",
        "LOCALHOST",
        "localhost.",
    ] {
        sets.push(vec![named("g", name, filter)]);
        sets.push(vec![row("g", filter, true), named("o", name, gone)]);
    }
    let mut faults = Vec::new();
    for configured in [Some(filter), Some(elsewhere), None] {
        for listed in &sets {
            let found = doctor_on(configured, &json!(listed));
            let shown: Vec<String> = found.iter().map(Finding::line).collect();
            for entry in listed {
                let host = entry["host"].as_str().unwrap();
                let port = u16::try_from(entry["port"].as_u64().unwrap()).unwrap();
                if reached(host, port, &[filter, other]) {
                    continue;
                }
                let resolves = format!("{host}:{port}").to_socket_addrs().is_ok();
                let garrisons = configured == Some(port) && resolves;
                let address = format!("{host}:{port}");
                let line = found
                    .iter()
                    .find(|finding| finding.state.text.contains(&address));
                let fault = match line {
                    None => Some("no line names it"),
                    Some(finding) if finding.level == Level::Ok => Some("its line says ok"),
                    Some(finding) => {
                        let fix = finding.state.fix.as_deref().unwrap_or_default();
                        if garrisons && !fix.contains("garrison stalwart setup") {
                            Some("setup mends it, and its fix does not name setup")
                        } else if !garrisons && !fix.contains("Stalwart WebUI") {
                            Some("it is another program's, and the fix is setup")
                        } else {
                            None
                        }
                    }
                };
                if let Some(fault) = fault {
                    faults.push(format!(
                        "[milter] {configured:?}, entries {listed:?}: the entry at {address}, \
                         where nothing answers: {fault}:\n{}",
                        shown.join("\n")
                    ));
                }
            }
        }
    }
    assert_eq!(faults, Vec::<String>::new(), "{}", faults.join("\n\n"));
}

/// The quick start looks in doctor's output for the filter's line and its
/// entry's line as an empty `[milter]` makes them, after setup entered the
/// entry: each must be a line doctor says, as a script cannot tell a line
/// doctor no longer prints from a fault.
#[test]
fn the_quick_start_looks_for_lines_doctor_says() {
    const SCRIPT: &str = include_str!("../../../../../scripts/acceptance-quickstart.sh");
    let entered = read(&json!([row("m", 8096, true)]));
    let mut lines = vec![answering(8096, Ok(())).line()];
    lines.extend(
        configured_as((8096, true), &entered, &[], &at(&[8096]))
            .iter()
            .map(Finding::line),
    );
    let looked_for: Vec<&str> = SCRIPT
        .split("grep -q \"^")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .filter(|line| line.contains("macro milter"))
        .collect();
    assert_eq!(looked_for.len(), 2, "{looked_for:?}");
    for line in looked_for {
        assert!(
            lines.iter().any(|said| said.starts_with(line)),
            "{line:?} is no line of {lines:?}"
        );
    }
}
