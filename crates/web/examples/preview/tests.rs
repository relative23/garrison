use std::collections::BTreeMap;
use std::time::Duration;

use garrison_core::config::Database;
use garrison_core::credentials::Credentials;
use garrison_core::time;
use garrison_ingest::store::{EventStore, Limits};
use serde_json::{Value, json};

/// Stopped by its process ID, as a script stops it, the preview ends as it
/// does on Ctrl+C: `main` returns, and its temporary state goes with it.
#[test]
fn sigterm_ends_the_preview_as_ctrl_c_does() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let ended = super::ended().unwrap();
        let sent = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        tokio::time::timeout(Duration::from_secs(10), ended)
            .await
            .expect("SIGTERM ends the preview");
    });
}

/// The checks whose cards a test draws here: they read the event history
/// alone, which the busy server's mail fills.
const DRAWN: [&str; 2] = ["mail-flow", "senders"];
/// The checks of the other samples, which ask the network, this host or
/// Stalwart, and so draw no card in a test.
const ASKED_ELSEWHERE: [&str; 17] = [
    "backup-check",
    "bulwark",
    "clamav",
    "dns",
    "host",
    "host-care",
    "http",
    "mail-test",
    "notifications",
    "prometheus",
    "receipt",
    "releases",
    "reputation",
    "stalwart",
    "systemd",
    "tls",
    "version-command",
];

/// What a card is drawn with, whatever it counts: its words, modules,
/// evidence, and the labels and formats of its fields and columns.
fn drawn_as(card: &Value) -> Value {
    let labels = |list: &Value| -> Vec<Value> {
        let items = list.as_array().into_iter().flatten();
        items
            .map(|item| json!([item["label"], item["format"]]))
            .collect()
    };
    json!({
        "provider": card["provider"],
        "title": card["title"],
        "modules": card["modules"],
        "evidence": card["evidence"],
        "kind": card["kind"],
        "source": card["source"],
        "scope": card["scope"],
        "fields": labels(&card["fields"]),
        "columns": labels(&card["table"]["columns"]),
    })
}

/// The preview shows no card that the product no longer draws: a sample of
/// a card that the product draws from the event history, in `extras.json`
/// or `busy.json`, has the words, fields and columns of the card the product
/// draws from the busy server's mail, and every row as many values as
/// there are columns. A sample of any other check is named as asked
/// elsewhere.
#[test]
fn the_samples_show_the_cards_the_product_draws() {
    let work = tempfile::tempdir().unwrap();
    let providers = DRAWN.map(|kind| format!("[[providers]]\ntype = \"{kind}\"\n"));
    let config =
        super::data::with_providers(work.path(), 18091, "/sign-in", &providers.join("\n")).unwrap();
    let now = time::now().as_second();
    let events = EventStore::open(
        &config.database(Database::Events),
        Limits::new(30, 1_000_000, 256 << 20),
    )
    .unwrap();
    events.start(now - 30 * 86_400).unwrap();
    for batch in super::busy::mail_alone(now, 600, 300) {
        events.ingest(&batch, now).unwrap();
    }
    // The checks Stalwart names a sender's domain with, which the busy
    // server's sessions leave out.
    let at = time::isoformat(time::now());
    let failed = [
        (
            "smtp.spf-from-fail",
            json!({"from": "office@forged.example"}),
        ),
        ("smtp.dmarc-fail", json!({"domain": "forged.example"})),
    ];
    let failed: Vec<Value> = failed
        .into_iter()
        .enumerate()
        .map(|(index, (kind, data))| {
            json!({"id": (30_000_000 + index).to_string(), "createdAt": at, "type": kind, "data": data})
        })
        .collect();
    events.ingest(&failed, now).unwrap();
    drop(events);
    let checks = garrison_collector::build(&config.collector.providers).unwrap();
    let credentials = Credentials::new(&config.credentials_directory);
    let runner = garrison_collector::SystemRunner;
    let snapshot =
        garrison_collector::collect_from(&checks, &config, &credentials, &runner, time::now())
            .unwrap();
    let drawn: BTreeMap<String, Value> = snapshot
        .observations
        .iter()
        .map(|card| (card.id.clone(), serde_json::to_value(card).unwrap()))
        .collect();
    for (file, text) in [
        ("extras.json", include_str!("extras.json")),
        ("busy.json", include_str!("busy.json")),
    ] {
        let samples: Vec<Value> = serde_json::from_str(text).unwrap();
        let mut held = 0;
        for sample in &samples {
            let (id, provider) = (sample["id"].as_str().unwrap(), &sample["provider"]);
            if ASKED_ELSEWHERE.iter().any(|kind| provider == kind) {
                continue;
            }
            assert!(
                DRAWN.iter().any(|kind| provider == kind),
                "{file}: {id} is of a check this test neither draws nor names as asked elsewhere"
            );
            let card = drawn
                .get(id)
                .unwrap_or_else(|| panic!("{file}: {id} is no card the product draws"));
            assert_eq!(drawn_as(sample), drawn_as(card), "{file}: {id}");
            let width = sample["table"]["columns"].as_array().map_or(0, Vec::len);
            for row in sample["table"]["rows"].as_array().into_iter().flatten() {
                let values = row.as_array().map_or(0, Vec::len);
                assert_eq!(values, width, "{file}: {id}: {row}");
            }
            held += 1;
        }
        assert!(held > 0, "{file} holds no sample of a card drawn here");
    }
}
