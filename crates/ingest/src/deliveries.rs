//! Summaries of recorded queue lifecycles and protocol sessions.
//!
//! These functions read only recorded events. A successful recipient event
//! means the receiving server accepted the message, not that it reached an
//! inbox. A summary is "complete" only when the enqueue recipient list and an
//! outcome for every one of those recipients were recorded.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::event_type::EventType;

pub const MAX_SUMMARY_EVENTS: usize = 256;
const MAX_RECIPIENTS: usize = 100;

/// One recorded event: its type and stored fields.
pub type Event = (String, Map<String, Value>);

/// What the recorded events of one queued message say.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Lifecycle {
    /// The first sender recorded; empty when no event names one.
    pub from: String,
    pub to: Vec<String>,
    /// `queued`, `in-progress`, `deferred`, `failed` or `completed` by the
    /// last lifecycle event; with complete evidence the outcome all recipients
    /// share, else `partial`; `unknown` when events are missing.
    pub status: String,
    /// The last outcome recorded for each recipient (`delivered`, `deferred`
    /// or `failed`), in the order the recipients first had one.
    pub recipient_outcomes: Map<String, Value>,
    pub recipient_evidence_complete: bool,
}

/// What the recorded milestones of one SMTP session say.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Milestones {
    pub listener: Option<String>,
    pub remote_ip: Option<String>,
    pub ehlo: Option<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    /// `pass` or `fail` per check (`spf-ehlo`, `spf-from`, `dkim`, `arc`,
    /// `dmarc`, `iprev`), in the order the checks reported.
    pub authentication: Map<String, Value>,
    pub rejections: Vec<&'static str>,
    pub queue_ids: Vec<String>,
    /// Both connection events are recorded and no event is missing.
    pub complete: bool,
}

/// A text field of an event; a value that is no text counts as absent.
fn text(fields: &Map<String, Value>, key: &str) -> Option<String> {
    fields.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn is_set(text: Option<&String>) -> bool {
    text.is_some_and(|text| !text.is_empty())
}

fn addresses(fields: &Map<String, Value>) -> Vec<String> {
    let items = match fields.get("to") {
        Some(Value::Array(items)) => items.as_slice(),
        Some(single) => std::slice::from_ref(single),
        None => &[],
    };
    items
        .iter()
        .take(MAX_RECIPIENTS)
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn code(fields: &Map<String, Value>) -> Option<i64> {
    fields.get("code").and_then(Value::as_i64)
}

/// The outcome one event records for its recipients.
fn outcome(event_type: EventType, fields: &Map<String, Value>) -> Option<&'static str> {
    let code = code(fields);
    let class = |low: i64| code.is_some_and(|code| (low..low + 100).contains(&code));
    match event_type {
        // In 1.0 local recipient completion is reported by dsn-success.
        EventType::DeliveryDelivered => Some("delivered"),
        EventType::DeliveryDsnSuccess if class(200) => Some("delivered"),
        // 1.0 uses "rejected" for temporary 4xx and permanent 5xx answers alike.
        EventType::DeliveryRcptToRejected | EventType::DeliveryMessageRejected if class(400) => {
            Some("deferred")
        }
        EventType::DeliveryRcptToRejected | EventType::DeliveryMessageRejected if class(500) => {
            Some("failed")
        }
        EventType::DeliveryDsnPermFail => Some("failed"),
        EventType::DeliveryRcptToFailed | EventType::DeliveryDsnTempFail => Some("deferred"),
        _ => None,
    }
}

fn status(event_type: EventType, current: &str) -> &str {
    match event_type {
        EventType::DeliveryAttemptStart => "in-progress",
        EventType::DeliveryFailed | EventType::DeliveryDsnPermFail => "failed",
        EventType::QueueRescheduled | EventType::DeliveryDsnTempFail => "deferred",
        EventType::DeliveryCompleted => "completed",
        _ => current,
    }
}

pub fn summarize_queue(events: &[Event], total: usize) -> Lifecycle {
    let mut sender = String::new();
    let mut recipients: Vec<String> = Vec::new();
    let mut expected: BTreeSet<String> = BTreeSet::new();
    let mut outcomes: Map<String, Value> = Map::new();
    let (mut saw_enqueue, mut incomplete) = (false, false);
    let mut inspected = 0;
    let mut current = "unknown";
    for (event_type, fields) in events {
        if inspected >= MAX_SUMMARY_EVENTS {
            incomplete = true;
            break;
        }
        inspected += 1;
        if sender.is_empty()
            && let Some(from) = fields.get("from").and_then(Value::as_str)
        {
            from.clone_into(&mut sender);
        }
        let listed = addresses(fields);
        for address in &listed {
            if !recipients.contains(address) && recipients.len() < MAX_RECIPIENTS {
                recipients.push(address.clone());
            }
        }
        if event_type.starts_with("queue.") && event_type.ends_with("-queued") {
            // Positive claims need the actual enqueue recipient set, not whichever
            // delivered recipients happen to remain within retention.
            if !listed.is_empty() {
                saw_enqueue = true;
                expected.extend(listed.iter().cloned());
            }
            current = "queued";
        }
        // A type that is no longer recorded changes nothing here.
        let Some(kind) = EventType::parse(event_type) else {
            continue;
        };
        if let Some(result) = outcome(kind, fields) {
            for address in &listed {
                outcomes.insert(address.clone(), json!(result));
            }
        }
        current = status(kind, current);
    }
    let truncated = inspected < total;
    let incomplete = incomplete || truncated || !saw_enqueue;
    let complete = !incomplete
        && !expected.is_empty()
        && recipients.iter().all(|address| expected.contains(address))
        && expected
            .iter()
            .all(|address| outcomes.contains_key(address));
    let mut final_status = current.to_owned();
    if complete {
        let states: BTreeSet<&str> = expected
            .iter()
            .filter_map(|address| outcomes[address].as_str())
            .collect();
        final_status = match states.iter().next() {
            Some(only) if states.len() == 1 => (*only).to_owned(),
            _ => "partial".to_owned(),
        };
    } else if truncated {
        "unknown".clone_into(&mut final_status);
    } else if !outcomes.is_empty() && !matches!(current, "failed" | "deferred" | "completed") {
        "partial".clone_into(&mut final_status);
    }
    Lifecycle {
        from: sender,
        to: recipients,
        status: final_status,
        recipient_outcomes: outcomes,
        recipient_evidence_complete: complete,
    }
}

const AUTH_RESULTS: [&str; 6] = ["spf-ehlo", "spf-from", "dkim", "arc", "dmarc", "iprev"];

fn rejection(event_type: EventType) -> Option<&'static str> {
    Some(match event_type {
        EventType::SmtpMailboxDoesNotExist => "Mailbox does not exist",
        EventType::SmtpRelayNotAllowed => "Relay not allowed",
        EventType::SmtpRcptToGreylisted => "Recipient greylisted",
        EventType::SmtpTooManyRecipients => "Too many recipients",
        EventType::SmtpMessageTooLarge => "Message too large",
        EventType::SmtpRateLimitExceeded => "Rate limit exceeded",
        EventType::SmtpConcurrencyLimitExceeded => "Concurrency limit exceeded",
        EventType::SmtpTimeLimitExceeded => "Time limit exceeded",
        EventType::SmtpMailFromUnauthenticated => "Sender not authenticated",
        EventType::SmtpMailFromUnauthorized => "Sender not authorized",
        EventType::SmtpMailFromNotAllowed => "Sender not allowed",
        EventType::SmtpInvalidEhlo => "Invalid EHLO",
        // A milter answers with a reply of its own only to refuse, for now or for good.
        EventType::MilterActionReject | EventType::MilterActionReplyCode => "Refused by a milter",
        EventType::MilterActionTempFail => "Deferred by a milter",
        EventType::MilterActionDiscard => "Discarded by a milter",
        EventType::MtaHookActionReject => "Refused by an MTA hook",
        EventType::MtaHookActionDiscard => "Discarded by an MTA hook",
        EventType::MtaHookActionQuarantine => "Quarantined by an MTA hook",
        _ => return None,
    })
}

pub fn summarize_session(events: &[Event], total: usize) -> Milestones {
    let mut listener: Option<String> = None;
    let mut remote_ip: Option<String> = None;
    let mut ehlo = None;
    let mut from = None;
    let mut to: Vec<String> = Vec::new();
    let mut authentication = Map::new();
    let mut rejections: Vec<&'static str> = Vec::new();
    let mut queue_ids: Vec<String> = Vec::new();
    let (mut started, mut ended) = (false, false);
    let mut inspected = 0;
    for (event_type, fields) in events {
        if inspected >= MAX_SUMMARY_EVENTS {
            break;
        }
        inspected += 1;
        // The first event that names them counts.
        if !is_set(listener.as_ref()) {
            listener = text(fields, "listenerId");
        }
        if !is_set(remote_ip.as_ref()) {
            remote_ip = text(fields, "remoteIp");
        }
        match EventType::parse(event_type) {
            Some(EventType::SmtpConnectionStart) => started = true,
            Some(EventType::SmtpConnectionEnd) => ended = true,
            Some(EventType::SmtpEhlo) => ehlo = text(fields, "domain"),
            Some(EventType::SmtpMailFrom) => from = text(fields, "from"),
            Some(EventType::SmtpRcptTo) => {
                for address in addresses(fields) {
                    if !to.contains(&address) {
                        to.push(address);
                    }
                }
            }
            kind => {
                if let Some(reason) = kind.and_then(rejection) {
                    if !rejections.contains(&reason) {
                        rejections.push(reason);
                    }
                } else if event_type.starts_with("queue.")
                    && let Some(queue) = text(fields, "queueId").filter(|id| !id.is_empty())
                {
                    queue_ids.push(queue);
                }
            }
        }
        for check in AUTH_RESULTS {
            let result = event_type
                .strip_prefix("smtp.")
                .and_then(|rest| rest.strip_prefix(check))
                .and_then(|rest| match rest {
                    "-pass" => Some("pass"),
                    "-fail" => Some("fail"),
                    _ => None,
                });
            if let Some(result) = result {
                authentication.insert(check.to_owned(), json!(result));
            }
        }
    }
    // Both connection events recorded and nothing beyond the inspection bound.
    let complete = started && ended && inspected >= total;
    Milestones {
        listener,
        remote_ip,
        ehlo,
        from,
        to,
        authentication,
        rejections,
        queue_ids,
        complete,
    }
}

#[cfg(test)]
mod tests;
