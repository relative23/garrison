//! The summary of delivery problems by destination and cause.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One domain mail was sent to and had a problem with.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Destination {
    pub domain: String,
    /// Recipients a server of the domain accepted.
    pub delivered: i64,
    /// Attempts that ended with a temporary failure.
    pub delays: i64,
    /// Recipients that failed for good.
    pub bounces: i64,
    pub last_problem: i64,
    /// The cause named most often, shortened.
    pub cause: String,
    pub hosts: Vec<String>,
}

/// One cause of delays or bounces, without what differs between messages.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DeliveryCause {
    pub cause: String,
    pub delays: i64,
    pub bounces: i64,
    pub domains: i64,
    pub last_seen: i64,
}

/// A queued message without a recorded end.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WaitingMessage {
    pub queue_id: String,
    pub queued_at: i64,
    pub last_event: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DestinationTotals {
    pub delivered: i64,
    pub delays: i64,
    pub bounces: i64,
    /// Domains with a delay or a bounce, also beyond the rows of the list.
    pub destinations: i64,
    pub waiting: i64,
}

/// Outgoing deliveries of a stretch of the event history by the domain they
/// went to and by the cause of their problems, and the messages that still
/// wait. Each list has at most 50 rows. Mail for this server's own mailboxes
/// is left out.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Destinations {
    pub since: i64,
    pub until: i64,
    /// More events were recorded in the stretch than were read.
    pub truncated: bool,
    pub totals: DestinationTotals,
    pub destinations: Vec<Destination>,
    pub causes: Vec<DeliveryCause>,
    /// The messages that wait longest first.
    pub waiting: Vec<WaitingMessage>,
}
