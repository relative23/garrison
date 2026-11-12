use garrison_core::config::Database;
use serde_json::Value;

use super::answers::{Fixed, Plain, Stages, Tolerant, Written, only, rows, total};
use super::*;
use crate::testing::{Canned, config, context, table};

/// An answer of Stalwart with these keys.
fn answer(value: &Value) -> Option<Object> {
    value.as_object().cloned()
}

#[test]
fn numbers_stay_below_a_trillion() {
    let largest = json!(999_999_999_999_u64);
    assert_eq!(Plain::of(&largest).value(), Some(largest));
    assert_eq!(Plain::of(&json!(1e12)), Plain(None));
    assert_eq!(Plain::of(&json!(true)), Plain(None));
    assert_eq!(Plain::of(&json!("7")), Plain(None));
    // A number keeps the spelling it was written in.
    assert_eq!(Plain::of(&json!(5.0)).value(), Some(json!(5.0)));
    assert_eq!(Plain::of(&json!(5)).float(), Some(5.0));
}

#[test]
fn booleans_may_be_expressions_without_conditions() {
    let fixed = |value: Value| Fixed::of(&value).0;
    assert_eq!(fixed(json!(false)), Some(false));
    assert_eq!(fixed(json!({"match": {}, "else": "false"})), Some(false));
    assert_eq!(fixed(json!({"match": {}, "else": "true"})), Some(true));
    assert_eq!(fixed(json!({"match": {"if": "x"}, "else": "true"})), None);
    assert_eq!(fixed(json!({"match": {}, "else": "maybe"})), None);
    assert_eq!(fixed(json!({"else": "true"})), None);
    assert_eq!(fixed(json!("true")), None);
}

#[test]
fn only_a_single_row_that_holds_something_is_a_singleton() {
    let one: Option<SpamSettings> = only(answer(&json!({"list": [{"scoreSpam": 5}]})));
    assert_eq!(one.unwrap().score_spam.value(), Some(json!(5)));
    for other in [
        json!({"list": [{"scoreSpam": 5}, {"scoreSpam": 6}]}),
        json!({"list": []}),
        json!({"list": [{}]}),
        json!({"list": ["scoreSpam"]}),
        json!({"list": {"scoreSpam": 5}}),
        json!({"total": 1}),
    ] {
        assert_eq!(only::<SpamSettings>(answer(&other)), None, "{other}");
    }
    assert_eq!(only::<SpamSettings>(None), None);
}

/// One odd field must not blank the fields beside it.
#[test]
fn a_field_of_another_shape_is_unknown_and_the_others_are_read() {
    let settings: SpamSettings = only(answer(&json!({"list": [{
        "enable": {"match": {"if": "rcpt"}, "else": "true"},
        "scoreSpam": "5",
        "scoreReject": 9.5,
        "scoreDiscard": null,
        "later": {"added": true},
    }]})))
    .unwrap();
    assert_eq!(
        settings,
        SpamSettings {
            score_reject: Plain::of(&json!(9.5)),
            ..SpamSettings::default()
        }
    );
    let classifier: SpamClassifier = only(answer(&json!({"list": [{
        "model": "none", "trainInterval": 3_600_000, "minHamSamples": true,
    }]})))
    .unwrap();
    assert_eq!(classifier.model, Tolerant::default());
    assert_eq!(classifier.train_interval.float(), Some(3_600_000.0));
    assert_eq!(classifier.min_ham_samples, Plain(None));
    let milters: Vec<Milter> = rows(answer(&json!({"list": [
        {"host": "127.0.0.1", "port": 7357, "stages": ["data"], "enable": 1},
        "not a row",
        {"host": null, "stages": {"data": true, "rcpt": false}},
    ], "notFound": "ignored"})))
    .unwrap();
    assert_eq!(milters.len(), 2, "what is no object is no row");
    assert_eq!(
        (milters[0].host.text(), milters[0].port.text()),
        ("127.0.0.1".to_owned(), "7357".to_owned())
    );
    assert_eq!(
        (milters[0].stages.clone(), milters[0].enable),
        (Tolerant(Stages::default()), Fixed(None))
    );
    assert_eq!(
        (milters[1].host.clone(), milters[1].stages.0.data),
        (Written(None), Fixed(Some(true)))
    );
    assert_eq!(rows::<Milter>(answer(&json!({"total": 2}))), None);
    assert_eq!(rows::<Milter>(None), None);
}

#[test]
fn a_query_is_read_for_its_total() {
    assert_eq!(total(answer(&json!({"total": 7, "ids": ["a"]}))), Some(7));
    for other in [
        json!({"ids": []}),
        json!({"total": -1}),
        json!({"total": "7"}),
        json!({"total": null}),
    ] {
        assert_eq!(total(answer(&other)), None, "{other}");
    }
    assert_eq!(total(None), None);
}

#[test]
fn the_calls_are_written_as_stalwart_reads_them() {
    let written = serde_json::to_value(calls()).unwrap();
    assert_eq!(
        written,
        json!([
            ["x:SpamSettings/get", {"ids": ["singleton"]}],
            ["x:SpamClassifier/get", {"ids": ["singleton"]}],
            ["x:SpamRule/query", {"calculateTotal": true, "limit": 1}],
            ["x:SpamTrainingSample/query", {"calculateTotal": true, "limit": 1}],
            ["x:QueuedMessage/query", {"calculateTotal": true, "limit": 1}],
            ["x:MtaMilter/get", {"ids": null,
                "properties": ["host", "port", "enable", "stages", "tempFailOnError"]}],
            ["x:Account/get", {"ids": null,
                "properties": ["id", "@type", "emailAddress", "quotas", "usedDiskQuota"]}],
        ])
    );
}

fn milter(settings: &str, listed: &Value) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let (config, runner) = (config(directory.path()), Canned(String::new()));
    let provider = Stalwart::new(&table(settings)).unwrap();
    let milters: Option<Vec<Milter>> = rows(answer(&json!({ "list": listed })));
    provider
        .milter(&context(&config, &runner), milters.as_deref())
        .unwrap()
}

#[test]
fn the_milter_is_found_by_host_and_port() {
    let rows = json!([
        {"host": "127.0.0.1", "port": 7357, "enable": true, "tempFailOnError": true},
        {"host": "10.0.0.9", "port": 7357, "enable": true, "tempFailOnError": false},
    ]);
    let found = milter("milter_host = \"127.0.0.1\"\nmilter_port = 7357", &rows);
    assert_eq!((found.state, found.findings.len()), (State::Ok, 0));
    let none = milter("milter_host = \"192.0.2.1\"", &rows);
    assert_eq!(none.state, State::Warning);
    assert_eq!(none.findings, ["Expected one matching milter, found 0."]);
    // The port alone may name the milter as well.
    let ports = json!([
        {"host": "127.0.0.1", "port": 7357, "enable": true, "tempFailOnError": true},
        {"host": "127.0.0.1", "port": 9999, "enable": true, "tempFailOnError": false},
    ]);
    let by_port = milter("milter_port = 7357", &ports);
    assert_eq!((by_port.state, by_port.findings.len()), (State::Ok, 0));
}

#[test]
fn without_a_name_every_milter_counts_and_each_is_judged() {
    let field = |observation: &Observation, label: &str| {
        let found = observation
            .fields
            .iter()
            .find(|field| field.label == label)
            .unwrap();
        found.value.clone()
    };
    // A scanner's milter and Garrison's macro filter beside it: in order.
    let both = json!([
        {"host": "127.0.0.1", "port": 7357, "enable": true, "tempFailOnError": true,
         "stages": {"data": true}},
        {"host": "127.0.0.1", "port": 8096, "enable": true, "tempFailOnError": true,
         "stages": {"data": true}},
    ]);
    let two = milter("", &both);
    assert_eq!((two.state, two.findings.len()), (State::Ok, 0));
    assert_eq!(field(&two, "Matching milters"), json!(2));
    assert_eq!(
        field(&two, "Endpoint"),
        json!("127.0.0.1:7357, 127.0.0.1:8096")
    );
    assert_eq!(field(&two, "Temporary failure on error"), json!(true));
    // One of them lets mail pass while it is away: named, and the field
    // no longer says that all defer.
    let lax = json!([
        {"host": "127.0.0.1", "port": 7357, "enable": true, "tempFailOnError": true},
        {"host": "127.0.0.1", "port": 8096, "enable": true, "tempFailOnError": false},
    ]);
    let one_lax = milter("", &lax);
    assert_eq!(one_lax.state, State::Warning);
    assert_eq!(
        one_lax.findings,
        [
            "Errors of the milter 127.0.0.1:8096 do not cause a temporary rejection; mail may pass \
          it unscanned."
        ]
    );
    assert_eq!(field(&one_lax, "Temporary failure on error"), json!(false));
    // Named, the scanner's milter alone is looked at.
    let named = milter("milter_port = 7357", &lax);
    assert_eq!((named.state, named.findings.len()), (State::Ok, 0));
    assert_eq!(field(&named, "Endpoint"), json!("127.0.0.1:7357"));
    // None at all stays a warning.
    let none = milter("", &json!([]));
    assert_eq!(none.findings, ["Expected one matching milter, found 0."]);
    assert_eq!(field(&none, "Endpoint"), Value::Null);
}

#[test]
fn the_version_comes_from_a_recorded_server_start() {
    let directory = tempfile::tempdir().unwrap();
    let (config, runner) = (config(directory.path()), Canned(String::new()));
    let path = config.database(Database::Events);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE events(created_at INTEGER, type TEXT, fields TEXT)")
        .unwrap();
    let version = |reported: &str| {
        db.execute("DELETE FROM events", []).unwrap();
        db.execute(
            "INSERT INTO events VALUES(1793000000, 'server.startup', ?)",
            [json!({ "version": reported }).to_string()],
        )
        .unwrap();
        let observation = Stalwart::version(&context(&config, &runner)).unwrap();
        observation.value["version"].clone()
    };
    assert_eq!(version("0.14.1"), "0.14.1");
    for invalid in ["", "1.0 beta", &"9".repeat(41)] {
        assert_eq!(version(invalid), Value::Null, "{invalid:?}");
    }
}

#[test]
fn every_provider_reports_under_its_configured_type() {
    let settings = [
        ("stalwart", ""),
        ("host", ""),
        (
            "systemd",
            "units = [{ unit = \"dns.service\", label = \"DNS\", modules = [\"services\"] }]",
        ),
    ];
    for (kind, extra) in settings {
        let raw = table(&format!("type = \"{kind}\"\n{extra}"));
        let providers = crate::providers::build(&[raw]).unwrap();
        assert_eq!(providers[0].name(), kind);
    }
}
