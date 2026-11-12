//! The summary of failed sign-ins, bans and TLS handshake errors.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One address that failed to sign in, was banned or failed a TLS handshake.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttackSource {
    pub address: String,
    /// The /24 of an IPv4 address, the /64 of an IPv6 address.
    pub network: String,
    pub failed_sign_ins: i64,
    /// The existing accounts it tried.
    pub accounts: i64,
    pub tls_errors: i64,
    pub bans: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub listeners: Vec<String>,
}

/// A network from which more than one address was seen.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttackNetwork {
    pub network: String,
    pub sources: i64,
    pub failed_sign_ins: i64,
    pub tls_errors: i64,
    pub bans: i64,
    pub last_seen: i64,
}

/// An existing account that someone failed to sign in to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttackedAccount {
    pub name: String,
    pub failed_sign_ins: i64,
    pub sources: i64,
    pub last_seen: i64,
}

/// Why Stalwart banned an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BanReason {
    Authentication,
    Abuse,
    Scan,
    Loiter,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Ban {
    pub at: i64,
    pub address: String,
    pub reason: BanReason,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AttackTotals {
    pub failed_sign_ins: i64,
    /// Failed sign-ins that named no existing account.
    pub unknown_accounts: i64,
    pub tls_errors: i64,
    pub bans: i64,
    /// Every address seen, also beyond the rows of the list.
    pub sources: i64,
}

/// Failed sign-ins, bans and TLS handshake errors of a stretch of the event
/// history. Each list has at most 50 rows, the busiest first; the bans are
/// the newest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Attacks {
    pub since: i64,
    pub until: i64,
    /// More events were recorded in the stretch than were read.
    pub truncated: bool,
    pub totals: AttackTotals,
    pub sources: Vec<AttackSource>,
    pub networks: Vec<AttackNetwork>,
    pub accounts: Vec<AttackedAccount>,
    pub bans: Vec<Ban>,
}
