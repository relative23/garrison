//! The preview's configuration and data: the observations of the collector's
//! golden test and examples of those it cannot make, a week of metric history
//! in the collector's one-minute rhythm and the ingest test batch, all moved
//! to the present. The same inputs give the same preview, apart from the time.

use std::collections::BTreeMap;
use std::error::Error;
use std::f64::consts::TAU;
use std::path::Path;

use garrison_collector::snapshot::{SCHEMA, Snapshot};
use garrison_collector::store::StatusStore;
use garrison_core::config::{self, Config, Database};
use garrison_core::observations::Observation;
use garrison_core::time;
use garrison_ingest::store::{EventStore, Limits};
use serde_json::{Value, json};

type Failure = Box<dyn Error>;

const HISTORY_MINUTES: i64 = 7 * 24 * 60;
/// The newest test event is this old when the preview starts.
const NEWEST_EVENT_AGE: i64 = 300;

/// A configuration that passes validation, then moved to the preview's own
/// loopback origin, where the issuer is the preview too.
pub(crate) fn config(work: &Path, port: u16, issuer_path: &str) -> Result<Config, Failure> {
    let work = work.display();
    let text = format!(
        r#"
schema = 1
credentials_directory = "{work}/credentials"

[deployment]
public_origin = "https://garrison.example.test"
issuer = "https://mail.example.test"
stalwart_url = "http://127.0.0.1:9"
admin_url = "https://mail.example.test/admin/"
links = {{ webmail = "https://mail.example.test/", alarms = "https://notify.example.test/garrison" }}

[web]
port = {port}
state_directory = "{work}/web"

[ingest]
state_directory = "{work}/ingest"

[collector]
state_directory = "{work}/collector"

[broker]
socket = "{work}/broker.sock"
state_directory = "{work}/broker"
policy = "{work}/policy.json"

[[actions]]
id = "restart_unbound"
title = "Restart DNS resolver"
description = "Briefly restart the local Unbound resolver. Mail delivery may wait for DNS during the restart."
confirmation = "RESTART UNBOUND"
unit = "unbound.service"
operation = "restart"
cooldown_seconds = 60
timeout_seconds = 90

[[actions]]
id = "run_backup"
title = "Run full backup"
description = "Run the encrypted backup job. Its consistent snapshot briefly pauses mail services."
confirmation = "RUN BACKUP"
unit = "backup.service"
operation = "start"
cooldown_seconds = 1800
timeout_seconds = 3600

[[actions]]
id = "run_monitor"
title = "Run health checks"
description = "Run the normal health check. Faults found may send real alerts through the alarm channel."
confirmation = "RUN HEALTH CHECKS"
unit = "monitor.service"
operation = "start"
cooldown_seconds = 300
timeout_seconds = 180
operator = true
"#
    );
    let mut config = config::from_text(&text)?;
    // Browsers keep Secure cookies over plain HTTP for `localhost` only.
    let origin = format!("http://localhost:{port}");
    config.deployment.issuer = format!("{origin}{issuer_path}");
    config.deployment.public_origin = origin;
    Ok(config)
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Gauge,
    Counter,
}

/// The collector and receiver stores the web service reads, kept current.
pub(crate) struct Live {
    status: StatusStore,
    events: EventStore,
    observations: Vec<Observation>,
    /// Name, kind and typical value per minute of each series the golden test stores.
    series: Vec<(String, Kind, f64)>,
    totals: BTreeMap<String, f64>,
    /// Whether this is the busy server of `busy.rs`.
    busy: bool,
}

impl Live {
    /// The stores filled for a start now. `busy` fills them as a busy server
    /// has them (`busy.rs`) instead of with the tests' own data.
    pub(crate) fn seed(
        config: &Config,
        crate_directory: &Path,
        busy: bool,
    ) -> Result<Self, Failure> {
        let now = time::now().as_second();
        let fixtures = crate_directory.join("..");
        let golden = read(&fixtures.join("collector/tests/fixtures/golden/golden.json"))?;
        let observations: Vec<Value> = golden["providers"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|provider| {
                provider["observations"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        // The golden test marks its paths and blanks what depends on the
        // machine, the host's state among it: a preview cannot know it either.
        let text = Value::Array(observations)
            .to_string()
            .replace("@FIXTURES@", "/srv/preview")
            .replace("@WORK@", "/var/lib/garrison")
            .replace("@STALWART@", "http://127.0.0.1:8080");
        let mut observations: Vec<Value> = serde_json::from_str(&text)?;
        for observation in &mut observations {
            if observation["state"].is_null() {
                observation["state"] = json!("unknown");
            }
        }
        let mut observations: Vec<Observation> =
            serde_json::from_value(Value::Array(observations))?;
        // What the golden test has no stand-in for: the checks that ask the
        // network (releases, DNS, test mail) and the notification channel.
        observations.extend(serde_json::from_str::<Vec<Observation>>(include_str!(
            "extras.json"
        ))?);
        if busy {
            observations = crate::busy::observations(now)?;
        }
        let series = series(&golden, busy);
        let ingest = &config.ingest;
        let events = EventStore::open(
            &config.database(Database::Events),
            Limits::new(
                ingest.retention_days,
                ingest.max_events,
                i64::from(ingest.max_database_mib) * 1024 * 1024,
            ),
        )?;
        let mut live = Live {
            status: StatusStore::open(
                &config.database(Database::Status),
                config.collector.history_days,
            )?,
            events,
            observations,
            series,
            totals: BTreeMap::new(),
            busy,
        };
        let placeholder = Snapshot {
            schema_version: SCHEMA,
            collected_at: String::new(),
            observations: Vec::new(),
            provider_errors: Vec::new(),
        };
        for minute in (1..=HISTORY_MINUTES).rev() {
            let at = now - minute * 60;
            let (gauges, counters) = live.samples(at);
            live.status.write(at, &placeholder, &gauges, &counters)?;
        }
        // The busy server has recorded for as long as it keeps events.
        let recording = if busy { now - 30 * 86_400 } else { now };
        live.events.start(recording)?;
        if busy {
            for batch in crate::busy::events(now) {
                live.events.ingest(&batch, now)?;
            }
        } else {
            let batch = read(&fixtures.join("ingest/tests/fixtures/batch.json"))?;
            live.events.ingest(&recent(&batch["events"], now), now)?;
            live.events.ingest(&attacks(now), now)?;
            live.events.ingest(&delivery_problems(now), now)?;
        }
        live.tick(now)?;
        Ok(live)
    }

    /// One collector minute: its samples, the golden snapshot checked now and
    /// a receiver heartbeat.
    pub(crate) fn tick(&mut self, now: i64) -> Result<(), Failure> {
        let checked = time::isoformat(time::Timestamp::from_second(now)?);
        let observations = self
            .observations
            .iter()
            .cloned()
            .map(|mut observation| {
                observation.checked_at.clone_from(&checked);
                observation
            })
            .collect();
        let snapshot = Snapshot {
            schema_version: SCHEMA,
            collected_at: checked,
            observations,
            provider_errors: Vec::new(),
        };
        let (gauges, counters) = self.samples(now);
        self.status.write(now, &snapshot, &gauges, &counters)?;
        self.events.heartbeat(now)?;
        Ok(())
    }

    /// The gauges and counter totals at `at`: a daily rhythm around the golden
    /// values, with a little deterministic noise.
    #[allow(clippy::cast_precision_loss)]
    fn samples(&mut self, at: i64) -> (BTreeMap<String, f64>, BTreeMap<String, f64>) {
        let day = (at.rem_euclid(86400) as f64) / 86400.0;
        let rhythm = 1.0 + 0.4 * (TAU * (day - 0.3)).sin();
        let (mut gauges, mut counters) = (BTreeMap::new(), BTreeMap::new());
        for (name, kind, typical) in &self.series {
            let value = typical * rhythm * (0.85 + 0.3 * noise(name, at));
            match kind {
                Kind::Gauge if self.busy => {
                    gauges.insert(
                        name.clone(),
                        crate::busy::settled(name, value.max(0.0), *typical),
                    );
                }
                Kind::Gauge if name.contains("age_hours") => {
                    // Receipts and signatures age through the day and renew.
                    gauges.insert(name.clone(), (at.rem_euclid(86400) as f64) / 3600.0);
                }
                Kind::Gauge => {
                    gauges.insert(name.clone(), value.max(0.0));
                }
                Kind::Counter => {
                    let total = self.totals.entry(name.clone()).or_insert(0.0);
                    // What happens less than once a minute happens in some minutes.
                    let rare = value < 1.0 && noise(&format!("{name}?"), at) < value;
                    *total += if rare { 1.0 } else { value.max(0.0).round() };
                    counters.insert(name.clone(), *total);
                }
            }
        }
        (gauges, counters)
    }
}

/// Name, kind and typical value a minute of each series the golden test
/// stores, or of the busy server.
fn series(golden: &Value, busy: bool) -> Vec<(String, Kind, f64)> {
    golden["stored"]["samples"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|sample| {
            let kind = match sample["kind"].as_str()? {
                "gauge" => Kind::Gauge,
                "increase" => Kind::Counter,
                _ => return None,
            };
            Some((
                sample["name"].as_str()?.to_owned(),
                kind,
                sample["value"].as_f64()?,
            ))
        })
        .fold(Vec::<(String, Kind, f64)>::new(), |mut series, sample| {
            if !series.iter().any(|(name, ..)| *name == sample.0) {
                series.push(sample);
            }
            series
        })
        .into_iter()
        .map(|(name, kind, typical)| {
            let typical = crate::busy::typical(&name)
                .filter(|_| busy)
                .unwrap_or(typical);
            (name, kind, typical)
        })
        .chain(
            crate::busy::MORE_SERIES
                .iter()
                .filter(|_| busy)
                .map(|(name, typical)| ((*name).to_owned(), Kind::Gauge, *typical)),
        )
        .collect()
}

fn read(path: &Path) -> Result<Value, Failure> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

/// The test batch moved so that its newest event happened a few minutes ago.
fn recent(events: &Value, now: i64) -> Vec<Value> {
    let times: Vec<i64> = events
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|event| time::parse(event["createdAt"].as_str()?))
        .map(time::Timestamp::as_second)
        .collect();
    let shift = times
        .iter()
        .max()
        .map_or(0, |newest| now - NEWEST_EVENT_AGE - newest);
    events
        .as_array()
        .into_iter()
        .flatten()
        .cloned()
        .map(|mut event| {
            let moved = event["createdAt"]
                .as_str()
                .and_then(time::parse)
                .and_then(|at| time::Timestamp::from_second(at.as_second() + shift).ok());
            if let Some(at) = moved {
                event["createdAt"] = json!(time::isoformat(at));
            }
            event
        })
        .collect()
}

/// A morning of attacks for the Attacks page: one address that guesses
/// passwords until Stalwart bans it, a second one in its network that stays
/// under the limit, and a scanner whose TLS handshakes fail.
fn attacks(now: i64) -> Vec<Value> {
    let mut events = Vec::new();
    let mut add = |ago: i64, kind: &str, data: Value| {
        let at = time::Timestamp::from_second(now - ago).map(time::isoformat);
        events.push(json!({
            "id": (9_000_000 + events.len()).to_string(),
            "createdAt": at.unwrap_or_default(),
            "type": kind,
            "data": data,
        }));
    };
    for attempt in 0..40_i64 {
        let known = attempt % 4 == 0;
        let mut data = json!({
            "remoteIp": "203.0.113.24", "listenerId": "submission",
            "reason": if known { "Authentication failed" } else { "Account not found" },
            "accountName": if known { "anna@example.test" } else { "admin" },
        });
        if known {
            data["accountId"] = json!(12);
        }
        add(7200 - attempt * 20, "auth.failed", data);
    }
    add(
        6390,
        "security.authentication-ban",
        json!({"remoteIp": "203.0.113.24"}),
    );
    for attempt in 0..6_i64 {
        add(
            5400 - attempt * 600,
            "auth.failed",
            json!({"remoteIp": "203.0.113.77", "listenerId": "imaps", "accountId": 12,
                   "accountName": "anna@example.test", "reason": "Authentication failed"}),
        );
    }
    for attempt in 0..3_i64 {
        add(
            1800 - attempt * 5,
            "tls.handshake-error",
            json!({"remoteIp": "2001:db8:40:1::5", "listenerId": "imaps",
                   "reason": "received corrupt message of type InvalidContentType"}),
        );
    }
    add(
        1780,
        "security.scan-ban",
        json!({"remoteIp": "2001:db8:40:1::5"}),
    );
    events
}

/// Outgoing mail with problems for the Deliveries page: one domain that
/// refuses this server, one that answers slowly, and a message that waits.
fn delivery_problems(now: i64) -> Vec<Value> {
    let mut events = Vec::new();
    let mut add = |ago: i64, kind: &str, data: Value| {
        let at = time::Timestamp::from_second(now - ago).map(time::isoformat);
        events.push(json!({
            "id": (9_500_000 + events.len()).to_string(),
            "createdAt": at.unwrap_or_default(),
            "type": kind,
            "data": data,
        }));
    };
    for message in 0..5_i64 {
        let queue = 880_000_000_000_000_100 + message;
        let to = format!("buyer{message}@strict.example");
        add(
            9000 - message * 900,
            "queue.authenticated-message-queued",
            json!({"queueId": queue, "from": "shop@example.test", "to": [to]}),
        );
        add(
            8990 - message * 900,
            "delivery.dsn-perm-fail",
            json!({
                "queueId": queue, "queueName": "remote", "to": to, "hostname": "mx1.strict.example", "code": 550,
                "details": format!("550 5.7.1 <{to}>: Sender address rejected: blocked using a local list"),
            }),
        );
        add(
            8989 - message * 900,
            "delivery.completed",
            json!({"queueId": queue, "queueName": "remote"}),
        );
    }
    let waiting = 880_000_000_000_000_200_i64;
    add(
        6000,
        "queue.authenticated-message-queued",
        json!({"queueId": waiting, "from": "anna@example.test", "to": ["partner@slow.example"]}),
    );
    for attempt in 0..4_i64 {
        add(
            5990 - attempt * 1200,
            "delivery.dsn-temp-fail",
            json!({
                "queueId": waiting, "queueName": "remote", "to": "partner@slow.example",
                "hostname": "mx.slow.example", "details": "Connection timed out",
            }),
        );
    }
    events
}

/// A number in [0, 1) that depends only on the series and the minute.
#[allow(clippy::cast_precision_loss)]
fn noise(name: &str, at: i64) -> f64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.bytes().chain((at / 60).to_le_bytes()) {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    (hash >> 11) as f64 / (1u64 << 53) as f64
}
