//! The event history's answers as the API states them.
//!
//! The receiver's types describe what its queries find, the types in `models`
//! what the API promises. Each conversion here names every field, so one the
//! receiver adds or changes fails to compile until the API, and with it the
//! interface's types, takes a decision about it.

use garrison_ingest::answers;
use garrison_ingest::deliveries::{Lifecycle, Milestones};

use crate::models::{
    Coverage, DeliveriesPage, DeliveryDetail, DeliverySummary, EventItem, EventsPage, Gap,
    SessionDetail, SessionSummary, SessionsPage, Trimmed,
};

/// A count as the API states it; none here can pass the largest JSON integer.
fn count(number: usize) -> i64 {
    i64::try_from(number).unwrap_or(i64::MAX)
}

fn items<T, U: From<T>>(items: Vec<T>) -> Vec<U> {
    items.into_iter().map(U::from).collect()
}

impl From<answers::EventItem> for EventItem {
    fn from(event: answers::EventItem) -> Self {
        let answers::EventItem {
            seq,
            id,
            created_at,
            event_type,
            label,
            category,
            span_id,
            queue_id,
            fields,
        } = event;
        EventItem {
            seq,
            id,
            created_at,
            event_type,
            label,
            category,
            span_id,
            queue_id,
            fields,
        }
    }
}

impl From<answers::DeliverySummary> for DeliverySummary {
    fn from(summary: answers::DeliverySummary) -> Self {
        let answers::DeliverySummary {
            queue_id,
            first_seen,
            last_seen,
            event_count,
            lifecycle:
                Lifecycle {
                    from,
                    to,
                    status,
                    recipient_outcomes,
                    recipient_evidence_complete,
                },
        } = summary;
        DeliverySummary {
            queue_id,
            first_seen,
            last_seen,
            event_count: count(event_count),
            from,
            to,
            status,
            recipient_outcomes,
            recipient_evidence_complete,
        }
    }
}

impl From<answers::SessionSummary> for SessionSummary {
    fn from(summary: answers::SessionSummary) -> Self {
        let answers::SessionSummary {
            span_id,
            first_seen,
            last_seen,
            event_count,
            milestones:
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
                },
        } = summary;
        SessionSummary {
            span_id,
            first_seen,
            last_seen,
            event_count: count(event_count),
            listener,
            remote_ip,
            ehlo,
            from,
            to,
            authentication,
            rejections: rejections.into_iter().map(str::to_owned).collect(),
            queue_ids,
            complete,
        }
    }
}

impl From<answers::Page<answers::EventItem>> for EventsPage {
    fn from(page: answers::Page<answers::EventItem>) -> Self {
        let answers::Page { items: found, next } = page;
        EventsPage {
            items: items(found),
            next,
        }
    }
}

impl From<answers::Page<answers::DeliverySummary>> for DeliveriesPage {
    fn from(page: answers::Page<answers::DeliverySummary>) -> Self {
        let answers::Page { items: found, next } = page;
        DeliveriesPage {
            items: items(found),
            next,
        }
    }
}

impl From<answers::Page<answers::SessionSummary>> for SessionsPage {
    fn from(page: answers::Page<answers::SessionSummary>) -> Self {
        let answers::Page { items: found, next } = page;
        SessionsPage {
            items: items(found),
            next,
        }
    }
}

impl From<answers::Detail<answers::DeliverySummary>> for DeliveryDetail {
    fn from(detail: answers::Detail<answers::DeliverySummary>) -> Self {
        let answers::Detail {
            summary,
            events,
            truncated,
        } = detail;
        DeliveryDetail {
            summary: summary.into(),
            events: items(events),
            truncated,
        }
    }
}

impl From<answers::Detail<answers::SessionSummary>> for SessionDetail {
    fn from(detail: answers::Detail<answers::SessionSummary>) -> Self {
        let answers::Detail {
            summary,
            events,
            truncated,
        } = detail;
        SessionDetail {
            summary: summary.into(),
            events: items(events),
            truncated,
        }
    }
}

impl From<answers::Coverage> for Coverage {
    fn from(coverage: answers::Coverage) -> Self {
        let answers::Coverage {
            available,
            receiver,
            heartbeat_at,
            recording_since,
            last_batch_at,
            retention_days,
            event_count,
            trimmed,
            gap_count,
            gaps,
            limitations,
        } = coverage;
        let gaps = gaps
            .into_iter()
            .map(|answers::Gap { start, end, reason }| Gap { start, end, reason })
            .collect();
        Coverage {
            available,
            receiver: receiver.as_str().to_owned(),
            heartbeat_at,
            recording_since,
            last_batch_at,
            retention_days,
            event_count,
            trimmed: trimmed.map(|answers::Trimmed { until, limit }| Trimmed {
                until,
                limit: limit.as_str().to_owned(),
            }),
            gap_count,
            gaps,
            limitations: limitations.into_iter().map(str::to_owned).collect(),
        }
    }
}
