//! A full listener against Stalwart: what Stalwart records where a listener
//! holds as many connections as it may, through the real receiver.
//!
//! Stalwart reads a listener's limit when it starts, not when its settings
//! are read again (measured with 1.2.1), so the test starts the lab's
//! Stalwart anew twice: with the limit, and without it at its end.

use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use garrison_core::sqlite::reading;
use garrison_ingest::attacks::{self, FullListener};
use garrison_ingest::queries::{self, Filter};
use garrison_ingest::store::{EventStore, Limits};
use garrison_testing::lab::{Lab, random_hex};
use serde_json::{Value, json};

use super::{create_webhook, one_at_a_time};

/// The lab's SMTP listener held to `most` connections; as it was, with
/// Stalwart started anew, once this goes.
struct Narrowed<'a> {
    lab: &'a Lab,
    listener: String,
}

impl<'a> Narrowed<'a> {
    fn smtp(lab: &'a Lab, most: u64) -> Self {
        let listeners = lab.call("x:NetworkListener/get", &json!({"ids": null}));
        let listener = listeners["list"]
            .as_array()
            .unwrap()
            .iter()
            .find(|listener| listener["name"] == "smtp")
            .expect("the lab's SMTP listener")["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let narrowed = Narrowed { lab, listener };
        narrowed.limit(&json!(most));
        narrowed
    }

    fn limit(&self, most: &Value) {
        let update = json!({"update": {&self.listener: {"maxConnections": most}}});
        let answer = self.lab.call("x:NetworkListener/set", &update);
        assert!(
            answer["updated"].get(&self.listener).is_some(),
            "{answer:?}"
        );
        self.lab.restart();
    }
}

impl Drop for Narrowed<'_> {
    fn drop(&mut self) {
        self.limit(&Value::Null);
    }
}

/// Five connections to a listener that may hold two: Stalwart greets two
/// and closes three without a word, and records one event for each of the
/// three, with the listener's name. The summary counts them by listener and
/// makes no source of the address, and the event history shows each.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_full_listener_is_recorded_with_its_name_for_each_connection_it_refuses() {
    let _one = one_at_a_time();
    let mut lab = Lab::from_environment();
    let callback = std::env::var("GARRISON_LAB_CALLBACK_HOST").expect("GARRISON_LAB_CALLBACK_HOST");
    let smtp = std::env::var("GARRISON_LAB_SMTP").expect("GARRISON_LAB_SMTP");
    let key = random_hex(32);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("events.sqlite");
    let store = Arc::new(EventStore::open(&path, Limits::new(30, 10_000, 64 << 20)).unwrap());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind((callback.as_str(), 0)))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = garrison_ingest::app::router(Arc::clone(&store), key.as_bytes());
    runtime.spawn(async move { axum::serve(listener, app).await });
    create_webhook(&mut lab, &format!("http://{callback}:{port}/webhook"), &key);
    let narrowed = Narrowed::smtp(&lab, 2);

    let mut held = Vec::new();
    let mut greeted = Vec::new();
    for _ in 0..5 {
        let mut stream = TcpStream::connect((smtp.as_str(), 25)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut first = [0; 3];
        let read = stream.read(&mut first).unwrap_or(0);
        greeted.push(String::from_utf8_lossy(&first[..read]).into_owned());
        held.push(stream);
    }
    assert_eq!(greeted, ["220", "220", "", "", ""]);

    let full = [FullListener {
        listener: "smtp".to_owned(),
        refused: 3,
    }];
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let summary = loop {
        std::thread::sleep(Duration::from_secs(1));
        // The receiver may be writing at this moment.
        if let Ok(Some(db)) = reading(&path, Duration::from_secs(2)) {
            let summary = attacks::attacks(&db, 0, i64::MAX).unwrap();
            if summary.full_listeners == full {
                break summary;
            }
            assert!(std::time::Instant::now() < deadline, "{summary:?}");
        }
    };
    assert_eq!(summary.sources, [], "{summary:?}");
    let db = reading(&path, Duration::from_secs(2)).unwrap().unwrap();
    let filter = Filter {
        event_type: "limit.concurrent-connection".to_owned(),
        ..Filter::default()
    };
    let page = queries::list_events(&db, &filter).unwrap();
    assert_eq!(page.items.len(), 3, "{:?}", page.items);
    for event in &page.items {
        let mut fields: Vec<&str> = event.fields.keys().map(String::as_str).collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            ["listenerId", "localPort", "remoteIp", "remotePort"],
            "{event:?}"
        );
        assert_eq!(event.fields["listenerId"], "smtp", "{event:?}");
    }
    drop(held);
    drop(narrowed);
}
