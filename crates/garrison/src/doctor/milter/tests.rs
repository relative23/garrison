use std::fs;
use std::net::ToSocketAddrs;

use serde_json::{Value, json};

use super::super::{Level, answering_milter};
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

/// Where a milter answers: at the ports of `ports`.
fn at(ports: &[u16]) -> impl Fn(&Entry) -> bool + '_ {
    |entry| entry.port().is_some_and(|port| ports.contains(&port))
}

#[test]
fn a_filter_that_does_not_answer_fails_with_where_to_look() {
    assert_eq!(answering(8096, Ok(())), Finding::ok(states::answers(8096)));
    assert_eq!(
        answering(8096, Err("Connection refused".to_owned())),
        Finding::fail(states::silent(8096, "Connection refused"))
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
        configured_as((8096, true), &entered, &[], &at(&[8096])),
        [Finding::ok(states::asked(&entered[0], 8096))]
    );
    // The port changed without setup while the filter runs at the old one:
    // Stalwart asks it there, until it moves.
    assert_eq!(
        configured_as((8097, true), &entered, &[8096], &at(&[8096])),
        [Finding::fail(states::moved(&entered[0], 8097, false))]
    );
    // The filter down: Stalwart asks it where nothing answers.
    assert_eq!(
        configured_as((8096, true), &entered, &[], &at(&[])),
        [Finding::fail(states::unanswered(&entered[0], None, false))]
    );
    // when_unreachable changed without setup.
    assert_eq!(
        configured_as((8096, false), &entered, &[], &at(&[8096])),
        [Finding::warn(states::when_unreachable(
            &entered[0],
            false,
            false
        ))]
    );
    // No entry at the filter's port, beside another program's milter that
    // answers.
    for list in [json!([]), json!([row("x", 9000, true)])] {
        assert_eq!(
            configured_as((8096, true), &read(&list), &[], &at(&[9000])),
            [Finding::warn(states::no_entry(8096, false))]
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
    for (entry, state) in [
        (off, states::off(8096, false)),
        (conditional, states::conditional(8096, false)),
        (early, states::before_data(8096, false)),
    ] {
        assert_eq!(
            configured_as((8096, true), &read(&json!([entry])), &[], &at(&[8096])),
            [Finding::warn(state)]
        );
    }
    let twice = read(&json!([row("m", 8096, true), row("n", 8096, true)]));
    assert_eq!(
        configured_as((8096, true), &twice, &[], &at(&[8096])),
        [Finding::warn(states::several(2, 8096, false))]
    );
}

/// With the section gone, an entry at the port the running filter listens
/// on still asks it and fails, with what Stalwart then does where the
/// filter has stopped; a Stalwart that cannot be asked leaves it unknown.
#[test]
fn a_filter_the_configuration_dropped_is_judged_by_what_stalwart_holds() {
    let entered = read(&json!([row("m", 8096, true)]));
    assert_eq!(
        judged(None, &entered, &[8096], &at(&[8096])),
        [Finding::fail(states::dropped(&entered[0], false, false))]
    );
    // The filter stopped: nothing tells the entry for the filter's, and
    // Stalwart asks it in vain, which setup refuses to leave so.
    assert_eq!(
        judged(None, &entered, &[], &at(&[])),
        [Finding::fail(states::stranded(&entered[0]))]
    );
    assert_eq!(
        unasked(None, "Stalwart did not answer"),
        Finding::unknown(states::stranded_unknown("Stalwart did not answer"))
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
    assert_eq!(
        judged(Some((8097, true)), &entered, &[8096], &at(&[8096])),
        [Finding::fail(states::moved(&entered[0], 8097, false))]
    );
    let beside = read(&json!([row("g", 8096, true), row("o", 9000, true)]));
    assert_eq!(
        judged(None, &beside, &[8096], &at(&[8096])),
        [
            Finding::fail(states::stranded(&beside[1])),
            Finding::fail(states::dropped(&beside[0], false, true)),
        ]
    );
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
    let entered = json!([row("m", port, true)]);
    assert_eq!(
        doctor_on(Some(port), &entered),
        [
            Finding::ok(states::answers(port)),
            Finding::ok(states::asked(&read(&entered)[0], port)),
        ]
    );
    let refused = garrison_stalwart::Error::InvalidToken(String::new());
    assert_eq!(
        doctor_with(None, garrison_testing::http::answer(401, "")),
        [Finding::unknown(states::stranded_unknown(
            &states::unasked("", refused)
        ))]
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
/// on, where no milter answers. Its state is the filter's entry that
/// nothing answers, which `garrison stalwart setup` mends, where setup
/// takes it for the filter's, as it asks this host at the configured port,
/// and an entry stranded there, which the Stalwart WebUI mends, where it is
/// another program's.
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
                let asked: Entry = serde_json::from_value(entry.clone()).unwrap();
                // Setup mends the filter's; another program's, the WebUI.
                let due = if garrisons {
                    [false, true]
                        .map(|others| Finding::fail(states::unanswered(&asked, None, others)))
                } else {
                    [
                        Finding::fail(states::stranded(&asked)),
                        Finding::warn(states::stranded_unscanned(&asked)),
                    ]
                };
                if !due.iter().any(|said| found.contains(said)) {
                    faults.push(format!(
                        "[milter] {configured:?}, entries {listed:?}: the entry at \
                         {host}:{port}, where nothing answers, is not said as {}:\n{}",
                        due[0].state.name,
                        shown.join("\n")
                    ));
                }
            }
        }
    }
    assert_eq!(faults, Vec::<String>::new(), "{}", faults.join("\n\n"));
}

/// The quick start looks in doctor's output for the filter's state and its
/// entry's, as an empty `[milter]` makes them after setup entered the
/// entry: each must be a state doctor says there, in order, as a script
/// cannot tell a state doctor no longer says from a fault.
#[test]
fn the_quick_start_looks_for_states_doctor_says() {
    const SCRIPT: &str = include_str!("../../../../../scripts/acceptance-quickstart.sh");
    let entered = read(&json!([row("m", 8096, true)]));
    let mut said = vec![answering(8096, Ok(()))];
    said.extend(configured_as((8096, true), &entered, &[], &at(&[8096])));
    let looked_for: Vec<String> = SCRIPT
        .split("[doctor-milter-")
        .skip(1)
        .filter_map(|rest| rest.split(']').next())
        .map(|name| format!("doctor-milter-{name}"))
        .collect();
    assert_eq!(looked_for.len(), 2, "{looked_for:?}");
    for name in looked_for {
        assert!(
            said.iter()
                .any(|finding| finding.level == Level::Ok && finding.state.name == name),
            "{name} is no state of {said:?}"
        );
    }
}
