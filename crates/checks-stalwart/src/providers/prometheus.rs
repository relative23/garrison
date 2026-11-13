//! Counters and gauges from Stalwart's Prometheus exporter (Community metrics).
//!
//! The exporter is protected with a dedicated scrape credential and is
//! reachable only on loopback; the public reverse proxy must block /metrics.
//!
//! Stalwart exports a counter only from its first event after the server
//! started, and always exports the gauges (contract test). A counter missing
//! from a scrape with every gauge is therefore zero. It stays unknown, with a
//! warning, when a gauge is missing, as the names may have changed, or when
//! the event history has such an event since the last start.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Field, Format, Observation, State};
use garrison_core::sqlite::reading;
use garrison_stalwart::http::Request;
use rusqlite::params;

use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options};

/// The counted event types; each one's series is its type with `_` for `.` and `-`.
const COUNTERS: [&str; 12] = [
    "queue.message-queued",
    "queue.authenticated-message-queued",
    "delivery.completed",
    "message-ingest.ham",
    "message-ingest.spam",
    "milter.action-reject",
    "milter.action-temp-fail",
    "milter.action-connection-failure",
    "milter.timeout",
    "mta-hook.action-reject",
    "auth.failed",
    "security.authentication-ban",
];
/// Native gauge, stored series name and factor.
const GAUGES: [(&str, &str, f64); 4] = [
    (
        "server_memory",
        "server_memory_mib",
        1.0 / (1024.0 * 1024.0),
    ),
    ("smtp_active_connections", "smtp_connections", 1.0),
    ("imap_active_connections", "imap_connections", 1.0),
    ("http_active_connections", "http_connections", 1.0),
];

/// Stalwart follows the Prometheus naming conventions: counters are
/// `stalwart_<name>_total`, gauges `stalwart_<name>` with a unit suffix.
fn counter_name(name: &str) -> String {
    format!("stalwart_{name}_total")
}

fn gauge_name(name: &str) -> String {
    let unit = if name == "server_memory" {
        "_bytes"
    } else {
        ""
    };
    format!("stalwart_{name}{unit}")
}

/// The stored series of a counted event type, e.g. `queue_message_queued`.
fn series(event_type: &str) -> String {
    event_type.replace(['.', '-'], "_")
}

/// What one scrape gives the store, and what is wrong with it.
#[derive(Debug, Default, PartialEq)]
struct Samples {
    gauges: BTreeMap<String, f64>,
    counters: BTreeMap<String, f64>,
    findings: Vec<String>,
}

/// `recorded` names those of the given event types that the event history
/// has since the server started.
fn samples(
    values: &BTreeMap<String, f64>,
    recorded: impl FnOnce(&[&'static str]) -> BTreeSet<&'static str>,
) -> Samples {
    let mut samples = Samples::default();
    let mut missing = Vec::new();
    for (native, name, factor) in GAUGES {
        let exported = gauge_name(native);
        match values.get(&exported) {
            Some(gauge) => {
                samples.gauges.insert(name.to_owned(), gauge * factor);
            }
            None => missing.push(exported),
        }
    }
    let mut absent = Vec::new();
    for event_type in COUNTERS {
        let name = series(event_type);
        match values.get(&counter_name(&name)) {
            Some(counter) => {
                samples.counters.insert(name, *counter);
            }
            None => absent.push(event_type),
        }
    }
    if !missing.is_empty() {
        samples.findings.push(format!(
            "The exporter has no {}; its names may have changed, so missing counters stay unknown.",
            missing.join(", ")
        ));
        return samples;
    }
    if absent.is_empty() {
        return samples;
    }
    let seen = recorded(&absent);
    for event_type in absent {
        let name = series(event_type);
        if seen.contains(event_type) {
            samples.findings.push(format!(
                "The event history has {event_type} since Stalwart started, but the exporter \
                 has no {}; that counter stays unknown.",
                counter_name(&name)
            ));
        } else {
            // No such event since the server started.
            samples.counters.insert(name, 0.0);
        }
    }
    samples
}

/// The event types among `absent` that the event history has since the
/// server's last recorded start. Without the history or a recorded start
/// there is no such evidence.
fn recorded_since_start(context: &Context<'_>, absent: &[&'static str]) -> BTreeSet<&'static str> {
    let Some(db) = reading(&context.events_database, Duration::from_secs(2))
        .ok()
        .flatten()
    else {
        return BTreeSet::new();
    };
    let started: Option<i64> = db
        .query_row(
            "SELECT max(created_at) FROM events WHERE type='server.startup'",
            [],
            |row| row.get(0),
        )
        .ok()
        .flatten();
    let Some(started) = started else {
        return BTreeSet::new();
    };
    // Event times are whole seconds: leaving out the two before the
    // collection began, every event found here preceded the scrape.
    let before = context.now.as_second() - 2;
    absent
        .iter()
        .copied()
        .filter(|event_type| {
            db.query_row(
                "SELECT EXISTS(SELECT 1 FROM events \
                 WHERE type=? AND created_at>=? AND created_at<?)",
                params![event_type, started, before],
                |row| row.get(0),
            )
            .unwrap_or(false)
        })
        .collect()
}

/// Unlabelled samples only; labelled series are not needed here.
pub fn parse(text: &str) -> BTreeMap<String, f64> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let [name, value] = parts.as_slice() {
            if name.contains('{') {
                continue;
            }
            if let Some(number) = value
                .parse::<f64>()
                .ok()
                .filter(|number| number.is_finite())
            {
                values.insert((*name).to_owned(), number);
            }
        }
    }
    values
}

#[derive(Debug)]
pub struct Prometheus {
    path: String,
}

impl Prometheus {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["path"])?;
        Ok(Prometheus {
            path: options.text("path", Some("/metrics/prometheus"))?,
        })
    }

    fn scrape(&self, context: &Context<'_>) -> Result<BTreeMap<String, f64>, String> {
        let Some((user, secret)) = &context.metrics_credential else {
            return Err("No scrape credential is configured.".into());
        };
        let token = format!("Basic {}", STANDARD.encode(format!("{user}:{secret}")));
        let url = format!("{}{}", context.deployment.stalwart_url, self.path);
        let answer = Request::get(&url)
            .header("Authorization", &token)
            .timeout(Duration::from_secs(8))
            .send()
            .map_err(|_| "The exporter is unavailable.".to_owned())?;
        if answer.status != 200 {
            return Err(format!("The exporter answered HTTP {}.", answer.status));
        }
        Ok(parse(&String::from_utf8_lossy(&answer.body)))
    }
}

impl Provider for Prometheus {
    fn name(&self) -> &'static str {
        "prometheus"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let scraped = self.scrape(context);
        let values = scraped.as_ref().ok();
        let samples = values
            .map(|values| samples(values, |absent| recorded_since_start(context, absent)))
            .unwrap_or_default();
        let (state, findings) = match &scraped {
            Err(error) => (State::Unknown, vec![error.clone()]),
            Ok(_) if !samples.findings.is_empty() => (State::Warning, samples.findings),
            Ok(_) => (State::Ok, Vec::new()),
        };
        let observation = Observation::new(
            "prometheus.exporter",
            self.name(),
            "Native metrics exporter",
            [ModuleId::Dashboard, ModuleId::Services],
            Evidence::Metric,
            state,
            context.checked_at(),
            self.path.clone(),
        )?
        .with_scope(
            "Community metrics exported by the running server; a counter it has not \
             exported since it started counts as zero.",
        )
        .with_fields(vec![Field::new(
            "Samples read",
            values.map(BTreeMap::len),
            Format::Number,
        )])
        .with_findings(findings)
        .with_max_age(180);
        let mut report = Report::of(observation);
        report.gauges = samples.gauges;
        report.counters = samples.counters;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use garrison_core::config::Database;

    use super::*;
    use crate::testing::{Canned, config, context};

    const EXPORTED: &str = "# TYPE stalwart_queue_message_queued_total counter\n\
                            stalwart_queue_message_queued_total 7\nstalwart_server_memory_bytes 2097152\n\
                            stalwart_smtp_active_connections 3\n\
                            stalwart_http_request_time_seconds_bucket{le=\"0.1\"} 4\n";

    #[test]
    fn the_exporters_names_give_the_series() {
        let values = parse(EXPORTED);
        assert_eq!(
            values.get(&counter_name("queue_message_queued")),
            Some(&7.0)
        );
        assert_eq!(values.get(&gauge_name("server_memory")), Some(&2_097_152.0));
        assert_eq!(
            values.get(&gauge_name("smtp_active_connections")),
            Some(&3.0)
        );
        assert_eq!(values.len(), 3, "labelled series are skipped");
        // A comment is skipped even when it looks like a sample.
        assert_eq!(
            parse("#queue_count 5\nqueue_count 2\n")
                .into_iter()
                .collect::<Vec<_>>(),
            [("queue_count".to_owned(), 2.0)]
        );
    }

    #[test]
    fn only_finite_numbers_are_kept() {
        let values = parse("a 1e3\nb NaN\nc +Inf\ne x\nf 1 2\ng -0.5\n");
        let expected = BTreeMap::from([("a".to_owned(), 1000.0), ("g".to_owned(), -0.5)]);
        assert_eq!(values, expected);
    }

    #[test]
    fn random_text_gives_only_unlabelled_finite_samples() {
        let mut noise = garrison_testing::noise::Noise::new(41);
        for _ in 0..20_000 {
            let text = noise.text("ab_{}=\"# \t\n0123456789.-+eEinfNa", 60);
            for (name, value) in parse(&text) {
                assert!(value.is_finite(), "{text:?}");
                assert!(
                    !name.is_empty() && !name.contains(['{', ' ', '\t']),
                    "{text:?}"
                );
            }
        }
    }

    const EVERY_GAUGE: &str = "stalwart_server_memory_bytes 2097152\n\
                               stalwart_smtp_active_connections 0\n\
                               stalwart_imap_active_connections 0\n\
                               stalwart_http_active_connections 1\n";

    #[test]
    fn a_counter_missing_beside_every_gauge_is_zero() {
        let values = parse(&format!("{EVERY_GAUGE}stalwart_auth_failed_total 3\n"));
        let read = samples(&values, |absent| {
            assert_eq!(absent.len(), COUNTERS.len() - 1);
            assert!(!absent.contains(&"auth.failed"));
            BTreeSet::new()
        });
        let mut expected: BTreeMap<String, f64> = COUNTERS
            .iter()
            .map(|event_type| (series(event_type), 0.0))
            .collect();
        expected.insert("auth_failed".to_owned(), 3.0);
        assert_eq!(read.counters, expected);
        assert_eq!(read.gauges.len(), GAUGES.len());
        assert!(read.findings.is_empty(), "{:?}", read.findings);
    }

    #[test]
    fn a_counter_the_event_history_contradicts_stays_unknown() {
        let read = samples(&parse(EVERY_GAUGE), |_| {
            BTreeSet::from(["milter.action-reject"])
        });
        assert_eq!(read.counters.len(), COUNTERS.len() - 1);
        assert!(!read.counters.contains_key("milter_action_reject"));
        assert_eq!(
            read.findings,
            [
                "The event history has milter.action-reject since Stalwart started, but the \
                 exporter has no stalwart_milter_action_reject_total; that counter stays unknown."
            ]
        );
    }

    #[test]
    fn the_history_counts_events_after_the_last_start_and_before_the_scrape() {
        let directory = tempfile::tempdir().unwrap();
        let (config, runner) = (config(directory.path()), Canned(String::new()));
        let context = context(&config, &runner);
        let absent = [
            "auth.failed",
            "milter.timeout",
            "queue.message-queued",
            "delivery.completed",
            "message-ingest.ham",
        ];
        // No history yet: no evidence.
        assert!(recorded_since_start(&context, &absent).is_empty());
        let path = config.database(Database::Events);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE events(type TEXT, created_at INTEGER)")
            .unwrap();
        let now = context.now.as_second();
        for (event_type, at) in [
            ("server.startup", now - 5000),
            ("milter.timeout", now - 3000),
            ("server.startup", now - 1000),
            ("auth.failed", now - 1000),
            ("queue.message-queued", now - 3),
            ("delivery.completed", now - 2),
        ] {
            db.execute("INSERT INTO events VALUES(?,?)", params![event_type, at])
                .unwrap();
        }
        assert_eq!(
            recorded_since_start(&context, &absent),
            BTreeSet::from(["auth.failed", "queue.message-queued"])
        );
        db.execute("DELETE FROM events WHERE type='server.startup'", [])
            .unwrap();
        assert!(recorded_since_start(&context, &absent).is_empty());
    }

    #[test]
    fn without_every_gauge_missing_counters_stay_unknown() {
        let values = parse(
            "stalwart_server_memory_bytes 2097152\nstalwart_smtp_active_connections 0\n\
             stalwart_auth_failed_total 3\n",
        );
        let read = samples(&values, |_| unreachable!("no history without every gauge"));
        assert_eq!(read.counters, [("auth_failed".to_owned(), 3.0)].into());
        assert_eq!(read.gauges.len(), 2);
        assert_eq!(
            read.findings,
            ["The exporter has no stalwart_imap_active_connections, \
                 stalwart_http_active_connections; its names may have changed, so missing \
                 counters stay unknown."]
        );
    }

    #[test]
    fn every_counted_event_type_is_one_stalwart_records() {
        // Written from the supported release's schema by `cargo xtask event-types`.
        let recorded: BTreeMap<String, serde_json::Value> =
            serde_json::from_str(include_str!("../../../ingest/event_types.json")).unwrap();
        for event_type in COUNTERS {
            assert!(recorded.contains_key(event_type), "{event_type}");
        }
        assert_eq!(series("mta-hook.action-reject"), "mta_hook_action_reject");
        let names: BTreeSet<String> = COUNTERS
            .iter()
            .map(|event_type| series(event_type))
            .collect();
        assert_eq!(names.len(), COUNTERS.len());
    }
}
