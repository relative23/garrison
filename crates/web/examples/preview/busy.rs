//! The preview as a busy mail server (`--busy`), for screenshots and for
//! looking at pages that hold a lot: a month of sign-in attacks from many
//! networks, a week of incoming sessions and outgoing deliveries, and the
//! observations in `busy.json` moved to the present.
//!
//! Everything is made up. Names are reserved example names, and addresses
//! come from the ranges reserved for documentation (192.0.2.0/24,
//! 198.51.100.0/24, 203.0.113.0/24, `2001:db8::/32`) and for benchmarking
//! (198.18.0.0/15), which belong to nobody. The same clock gives the same
//! data.

// Counts and indexes here are small and made up; none can overflow.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]

use garrison_core::observations::{Format, Observation};
use garrison_core::time;
use serde_json::{Value, json};

const DAY: i64 = 86_400;
/// The moment the times in `busy.json` are written for.
const WRITTEN_FOR: i64 = 1_793_275_200;

#[rustfmt::skip]
const ACCOUNTS: [&str; 14] = [
    "anna.keller@example.org", "support@example.org", "billing@example.org",
    "sales@example.org", "jonas.weber@example.org", "m.schneider@example.org",
    "press@example.org", "archive@example.org", "postmaster@example.org", "shop@example.net",
    "newsletter@example.net", "office@example.com", "info@example.com", "team@example.net",
];
/// Where mail comes from and goes to; the last ones cause the problems.
#[rustfmt::skip]
const DOMAINS: [&str; 28] = [
    "nordlicht.example", "hafen-logistik.example", "stadtwerke.example", "buchhandlung.example",
    "kanzlei-brandt.example", "atelier-nord.example", "print-shop.example", "bergbahn.example",
    "weingut-sonnenhang.example", "tischlerei-holm.example", "apotheke-am-markt.example",
    "radwerk.example", "campus-verein.example", "steuerbuero.example",
    "kita-regenbogen.example", "elektro-jansen.example", "reisebuero-fernweh.example",
    "praxis-lindner.example", "musikschule.example", "gartenbau-gruen.example",
    "newsletter-hub.example", "crm-mailer.example", "parcel-tracking.example",
    "old-partner.example", "strict-filter.example", "slow-mx.example", "full-mailbox.example",
    "greylist.example",
];
const LISTENERS: [&str; 5] = ["submission", "imaps", "submission", "https", "pop3s"];
const TLS_REASONS: [&str; 4] = [
    "received corrupt message of type InvalidContentType",
    "peer is incompatible: no ciphersuites in common",
    "received fatal alert: ProtocolVersion",
    "peer sent no certificates",
];

/// Numbers that depend only on the seed.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// A number below `limit`.
    fn below(&mut self, limit: u64) -> u64 {
        self.next() % limit.max(1)
    }

    /// Whether something that happens `percent` times in a hundred happens.
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    /// A number below `limit` that is far more often small than large.
    fn skewed(&mut self, limit: u64) -> u64 {
        let first = self.below(limit);
        let second = self.below(limit);
        first.min(second).min(self.below(limit))
    }
}

/// The events of one busy server up to `now`, oldest first.
struct Events {
    now: i64,
    random: Random,
    list: Vec<(i64, Value)>,
}

impl Events {
    fn add(&mut self, ago: i64, kind: &str, data: Value) {
        let at = self.now - ago.max(1);
        let created = time::Timestamp::from_second(at).map(time::isoformat);
        let mut event = json!({
            "id": (20_000_000 + self.list.len()).to_string(),
            "createdAt": created.unwrap_or_default(),
            "type": kind,
        });
        event["data"] = data;
        self.list.push((at, event));
    }

    /// Seconds ago, more often lately: a fifth today, another third this week.
    fn lately(&mut self) -> i64 {
        let window = match self.random.below(100) {
            0..=19 => DAY,
            20..=54 => 7 * DAY,
            _ => 29 * DAY,
        };
        self.random.below(window as u64) as i64 + 30
    }
}

/// The address of attacker `source`: a few hundred addresses in some seventy
/// networks, a seventh of them IPv6.
fn attacker(source: u64) -> String {
    let network = source % 70;
    let host = 2 + (source * 37) % 250;
    match network {
        0..=39 => format!("198.18.{}.{host}", network * 5 + 3),
        40..=59 => format!("198.19.{}.{host}", (network - 40) * 11 + 2),
        60 => format!("203.0.113.{host}"),
        61 => format!("198.51.100.{host}"),
        62 => format!("192.0.2.{host}"),
        _ => format!("2001:db8:{:x}:{:x}::{:x}", 0xa0 + network, source % 5, host),
    }
}

fn sign_in_attacks(events: &mut Events) {
    for _ in 0..22_000 {
        let source = events.random.skewed(280);
        let ago = events.lately();
        // An attacker keeps to one or two ways in.
        let listener = LISTENERS[((source + events.random.below(2)) % 5) as usize];
        let mut data = json!({"remoteIp": attacker(source), "listenerId": listener});
        // Most guesses name an account that does not exist; its name may be a
        // password and is never kept.
        if events.random.chance(38) {
            let account = events.random.skewed(ACCOUNTS.len() as u64);
            data["accountId"] = json!(100 + account);
            data["accountName"] = json!(ACCOUNTS[account as usize]);
            data["reason"] = json!("Authentication failed");
        } else {
            data["accountName"] = json!("admin");
            data["reason"] = json!("Account not found");
        }
        events.add(ago, "auth.failed", data);
    }
    for (count, kind, sources) in [
        (160, "security.authentication-ban", 90),
        (48, "security.scan-ban", 40),
        (22, "security.loiter-ban", 60),
        (9, "security.abuse-ban", 12),
    ] {
        for _ in 0..count {
            let source = events.random.skewed(sources);
            let ago = events.lately();
            events.add(ago, kind, json!({"remoteIp": attacker(source)}));
        }
    }
    for _ in 0..1_100 {
        let source = 140 + events.random.skewed(120);
        let ago = events.lately();
        let reason = TLS_REASONS[events.random.below(4) as usize];
        let listener = if events.random.chance(60) {
            "imaps"
        } else {
            "smtps"
        };
        events.add(
            ago,
            "tls.handshake-error",
            json!({"remoteIp": attacker(source), "listenerId": listener, "reason": reason}),
        );
    }
}

/// One incoming SMTP session a week or less ago, with the checks of its
/// sender, the message it left and how that was filed.
fn incoming_session(events: &mut Events, number: i64) {
    let ago = events.random.below(7 * DAY as u64) as i64 + 120;
    let span = 337_538_776_114_000_000 + number;
    let queue = 880_000_000_000_100_000 + number;
    let domain = DOMAINS[events.random.skewed(DOMAINS.len() as u64) as usize];
    let remote = format!("198.51.100.{}", 10 + events.random.below(200));
    let account = events.random.skewed(ACCOUNTS.len() as u64) as usize;
    let (from, to) = (format!("office@{domain}"), ACCOUNTS[account]);
    let forged = events.random.chance(15);
    let step = |events: &mut Events, offset: i64, kind: &str, mut data: Value| {
        data["spanId"] = json!(span);
        events.add(ago - offset, kind, data);
    };
    step(
        events,
        0,
        "smtp.connection-start",
        json!({"listenerId": "smtp", "remoteIp": remote}),
    );
    step(
        events,
        1,
        "smtp.ehlo",
        json!({"domain": format!("mail.{domain}")}),
    );
    if !events.random.chance(3) {
        step(events, 1, "smtp.start-tls", json!({}));
    }
    let verdict = |passed: bool, check: &str| {
        format!("smtp.{check}-{}", if passed { "pass" } else { "fail" })
    };
    step(events, 2, &verdict(!forged, "iprev"), json!({}));
    step(events, 2, &verdict(!forged, "spf-ehlo"), json!({}));
    step(events, 2, "smtp.mail-from", json!({"from": from}));
    step(events, 2, &verdict(!forged, "spf-from"), json!({}));
    if events.random.chance(6) {
        step(
            events,
            3,
            "smtp.mailbox-does-not-exist",
            json!({"to": "info@example.org"}),
        );
        step(events, 4, "smtp.connection-end", json!({}));
        return;
    }
    step(events, 3, "smtp.rcpt-to", json!({"to": [to]}));
    let signed = !forged && !events.random.chance(18);
    step(events, 4, &verdict(signed, "dkim"), json!({}));
    step(events, 4, &verdict(signed, "dmarc"), json!({}));
    if events.random.chance(1) {
        step(
            events,
            5,
            "milter.action-reject",
            json!({"reason": "rejected by milter"}),
        );
        step(events, 6, "smtp.connection-end", json!({}));
        return;
    }
    step(events, 5, "milter.action-accept", json!({}));
    step(
        events,
        5,
        "queue.message-queued",
        json!({"queueId": queue, "from": from, "to": [to]}),
    );
    step(events, 6, "smtp.connection-end", json!({}));
    let filed = if forged || events.random.chance(14) {
        "spam"
    } else {
        "ham"
    };
    events.add(
        ago - 7,
        &format!("message-ingest.{filed}"),
        json!({"queueId": queue, "accountId": 100 + account}),
    );
    events.add(
        ago - 7,
        "delivery.dsn-success",
        json!({"queueId": queue, "queueName": "local", "to": to}),
    );
    events.add(
        ago - 7,
        "delivery.completed",
        json!({"queueId": queue, "queueName": "local"}),
    );
}

/// One message an account sent a week or less ago and what became of it at
/// its destination.
fn outgoing_message(events: &mut Events, number: i64) {
    let ago = events.random.below(7 * DAY as u64) as i64 + 600;
    let queue = 880_000_000_000_500_000 + number;
    let which = events.random.below(DOMAINS.len() as u64) as usize;
    let domain = DOMAINS[which];
    let from = ACCOUNTS[events.random.skewed(ACCOUNTS.len() as u64) as usize];
    let to = format!("kontakt{}@{domain}", events.random.below(40));
    let host = format!("mx1.{domain}");
    events.add(
        ago,
        "queue.authenticated-message-queued",
        json!({"queueId": queue, "from": from, "to": [to]}),
    );
    events.add(ago - 1, "delivery.attempt-start", json!({"queueId": queue}));
    let outcome = |events: &mut Events, offset: i64, kind: &str, details: &str| {
        events.add(
            ago - offset,
            &format!("delivery.{kind}"),
            json!({"queueId": queue, "queueName": "remote", "to": to, "hostname": host, "details": details}),
        );
    };
    // The last domains of the list are the ones with a problem of their own.
    // Each arm says after how many seconds the message was done with, or
    // nothing where it still waits.
    let trouble = which >= DOMAINS.len() - 5 && events.random.chance(70);
    let done = match (trouble, domain) {
        (true, "strict-filter.example") => {
            let refusal =
                format!("550 5.7.1 <{to}>: Sender address rejected: blocked using a local list");
            outcome(events, 3, "dsn-perm-fail", &refusal);
            Some(4)
        }
        (true, "full-mailbox.example") => {
            outcome(
                events,
                3,
                "dsn-perm-fail",
                &format!("552 5.2.2 <{to}>: Mailbox is full"),
            );
            Some(4)
        }
        (true, "slow-mx.example") => {
            for attempt in 0..3 {
                outcome(
                    events,
                    3 + attempt * 1500,
                    "dsn-temp-fail",
                    "Connection timed out",
                );
            }
            (ago > 40_000).then(|| {
                outcome(events, 4600, "dsn-success", "250 2.0.0 OK");
                4601
            })
        }
        (true, "greylist.example") => {
            outcome(
                events,
                3,
                "dsn-temp-fail",
                "451 4.7.1 Greylisted, try again later",
            );
            (ago > 9000).then(|| {
                outcome(events, 1200, "dsn-success", "250 2.0.0 OK");
                1201
            })
        }
        (true, _) => {
            outcome(
                events,
                3,
                "dsn-temp-fail",
                "421 4.7.0 Too many connections from your network",
            );
            (ago > 14_000).then(|| {
                outcome(events, 2400, "dsn-success", "250 2.0.0 OK");
                2401
            })
        }
        (false, _) if events.random.chance(1) => {
            let unknown = format!("550 5.1.1 <{to}>: Recipient address rejected: User unknown");
            outcome(events, 3, "dsn-perm-fail", &unknown);
            Some(4)
        }
        (false, _) => {
            outcome(events, 3, "dsn-success", "250 2.0.0 OK");
            Some(4)
        }
    };
    if let Some(after) = done {
        events.add(
            ago - after,
            "delivery.completed",
            json!({"queueId": queue, "queueName": "remote"}),
        );
    }
}

/// The event batches of the busy server, oldest first, each small enough for
/// the receiver.
pub(crate) fn events(now: i64) -> Vec<Vec<Value>> {
    let mut events = Events {
        now,
        random: Random(0x9e37_79b9_7f4a_7c15),
        list: Vec::new(),
    };
    events.add(
        19 * DAY + 5 * 3600,
        "server.startup",
        json!({"version": "1.1.0"}),
    );
    sign_in_attacks(&mut events);
    for number in 0..9_000 {
        incoming_session(&mut events, number);
    }
    for number in 0..7_000 {
        outgoing_message(&mut events, number);
    }
    for day in 0..7 {
        events.add(day * DAY + 9 * 3600, "spam.train-completed", json!({}));
    }
    events.list.sort_by_key(|(at, _)| *at);
    let list: Vec<Value> = events.list.into_iter().map(|(_, event)| event).collect();
    list.chunks(500).map(<[Value]>::to_vec).collect()
}

/// A time of `busy.json`, written for `WRITTEN_FOR`, as far before `now`.
fn moved(text: &str, now: i64) -> Option<String> {
    let at = time::parse(text)?.as_second() + (now - WRITTEN_FOR);
    time::Timestamp::from_second(at).ok().map(time::isoformat)
}

/// A day of `busy.json` (`2026-10-29`), as many days before today.
fn moved_day(text: &str, now: i64) -> Option<String> {
    let valid = text.len() == 10 && text.bytes().filter(|byte| *byte == b'-').count() == 2;
    let moved = moved(&format!("{text}T12:00:00+00:00"), now).filter(|_| valid)?;
    Some(moved[..10].to_owned())
}

/// The observations of the busy server, with every time moved to `now`.
pub(crate) fn observations(now: i64) -> Result<Vec<Observation>, serde_json::Error> {
    let mut observations: Vec<Observation> = serde_json::from_str(include_str!("busy.json"))?;
    for observation in &mut observations {
        for field in &mut observation.fields {
            if let (Format::Datetime, Some(text)) = (field.format, field.value.as_str()) {
                field.value = json!(moved(text, now));
            }
        }
        if let Some(started) = observation.value.get("startedAt").and_then(Value::as_i64) {
            observation.value["startedAt"] = json!(started + (now - WRITTEN_FOR));
        }
        let Some(table) = &mut observation.table else {
            continue;
        };
        for row in &mut table.rows {
            for (cell, column) in row.iter_mut().zip(&table.columns) {
                let Some(text) = cell.as_str() else { continue };
                let new = match column.format {
                    Format::Datetime => moved(text, now),
                    Format::Text => moved_day(text, now),
                    _ => None,
                };
                if let Some(new) = new {
                    *cell = json!(new);
                }
            }
        }
    }
    Ok(observations)
}

/// What each metric series shows a minute on the busy server; a series that
/// is not named here keeps the value the preview has for it.
pub(crate) fn typical(name: &str) -> Option<f64> {
    Some(match name {
        "auth_failed" => 9.5,
        "security_authentication_ban" => 0.11,
        "queue_message_queued" => 33.0,
        "queue_authenticated_message_queued" => 9.0,
        "delivery_completed" => 40.0,
        "message_ingest_ham" => 26.0,
        "message_ingest_spam" => 6.5,
        "milter_action_reject" => 0.09,
        "milter_action_temp_fail" => 0.004,
        "mta_hook_action_reject" => 0.02,
        "queue_count" => 37.0,
        "smtp_connections" => 46.0,
        "imap_connections" => 312.0,
        "http_connections" => 88.0,
        "load_1m" => 2.6,
        "ram_used_gib" => 20.8,
        "server_memory_mib" => 2460.0,
        "healthy_services" => 14.0,
        "signature_age_hours" => 1.4,
        _ => return None,
    })
}

/// The series the tests' data has none of: the shortest certificate validity
/// in days and the free disk space.
pub(crate) const MORE_SERIES: [(&str, f64); 2] = [("tls_days", 50.0), ("disk_free_gib", 383.7)];

/// How a gauge of the busy server moves through the day: not at all, in
/// whole numbers, or as the preview moves any gauge.
pub(crate) fn settled(name: &str, value: f64, typical: f64) -> f64 {
    match name {
        "healthy_services" | "tls_days" | "disk_free_gib" | "signature_age_hours" => typical,
        "queue_count" | "smtp_connections" | "imap_connections" | "http_connections" => {
            value.round()
        }
        _ => value,
    }
}
