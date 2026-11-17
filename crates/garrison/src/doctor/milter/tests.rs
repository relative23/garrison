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

/// Stalwart asks the filter where the configuration has it, as setup
/// entered it; each way its entry can differ is named with the setup that
/// mends it.
#[test]
fn stalwart_is_held_to_the_entry_the_configuration_makes() {
    let entered = read(&json!([row("m", 8096, true)]));
    assert_eq!(
        said(&configured(8096, true, Some("m"), &entered, &NOTHING)),
        [(
            Level::Ok,
            "Stalwart asks the macro milter on 127.0.0.1:8096 about every message and defers \
             mail while it does not answer"
        )]
    );
    // The port changed without setup: Stalwart asks where nothing answers.
    let moved = configured(8097, true, Some("m"), &entered, &NOTHING);
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
    let answered = configured(8097, true, Some("m"), &entered, &|_| true);
    assert!(
        answered[0].what.ends_with("on 127.0.0.1:8097"),
        "{}",
        answered[0].what
    );
    // when_unreachable changed without setup.
    let accepting = configured(8096, false, Some("m"), &entered, &NOTHING);
    assert_eq!(
        said(&accepting),
        [(
            Level::Warn,
            "Stalwart defers mail while the macro milter does not answer, though \
             when_unreachable is \"accept\""
        )]
    );
    // No entry at all, or none setup's note names and none at the address.
    for (noted, list) in [
        (None, json!([])),
        (Some("gone"), json!([row("x", 9000, true)])),
    ] {
        let none = configured(8096, true, noted, &read(&list), &NOTHING);
        assert_eq!(none.len(), 1, "{:?}", said(&none));
        assert_eq!(none[0].level, Level::Warn);
        assert!(
            none[0].what.starts_with("Stalwart has no entry"),
            "{}",
            none[0].what
        );
    }
    // Without the note, an entry at the address is the filter's.
    let unnoted = configured(8096, true, None, &entered, &NOTHING);
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
        let found = configured(8096, true, Some("m"), &read(&json!([entry])), &NOTHING);
        assert_eq!(found.len(), 1, "{:?}", said(&found));
        assert_eq!(found[0].level, Level::Warn);
        assert!(found[0].what.contains(words), "{}", found[0].what);
        assert_eq!(found[0].fix.as_deref(), Some(SETUP));
    }
    let twice = read(&json!([row("m", 8096, true), row("n", 8096, true)]));
    let found = configured(8096, true, Some("m"), &twice, &NOTHING);
    assert_eq!(
        said(&found),
        [(
            Level::Warn,
            "Stalwart has 2 entries for the macro milter on 127.0.0.1:8096"
        )]
    );
}

/// With the section gone, what Stalwart still has decides: an entry that
/// still asks the filter fails, a note of one that is gone is a warning,
/// and a Stalwart that cannot be asked leaves the note's word.
#[test]
fn a_filter_the_configuration_dropped_is_judged_by_what_stalwart_holds() {
    let entered = read(&json!([row("m", 8096, true)]));
    let still = dropped(Some("m"), Ok(&entered));
    assert_eq!(
        (still.level, still.what.as_str()),
        (
            Level::Fail,
            "Stalwart still asks the macro milter at 127.0.0.1:8096, which the configuration no \
             longer has"
        )
    );
    assert!(still.fix.as_deref().unwrap().starts_with(SETUP));
    for noted in [Some("m"), None] {
        let stale = dropped(noted, Ok(&[]));
        assert_eq!(stale.level, Level::Warn, "{}", stale.line());
        assert!(
            stale
                .fix
                .as_deref()
                .unwrap()
                .contains("which removes the note")
        );
    }
    let unasked = dropped(Some("m"), Err("Stalwart did not answer"));
    assert_eq!(unasked.level, Level::Fail);
    assert!(
        unasked.what.ends_with(": Stalwart did not answer"),
        "{}",
        unasked.what
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
