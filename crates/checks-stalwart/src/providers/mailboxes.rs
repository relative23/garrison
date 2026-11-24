//! Mailbox storage on the dashboard: fullest first, a warning near the quota.

use std::cmp::Ordering;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{
    Column, Evidence, Field, Format, Observation, Required, State, Table,
};
use garrison_stalwart::jmap::Listed;
use serde_json::{Value, json};

use super::stalwart::answers::MailboxAccount;
use crate::context::{Context, ProviderError};
use crate::values::{round_one, text};

/// A mailbox at or above this share of its quota is reported as a warning.
pub const FULL_PERCENT: f64 = 90.0;
const MAX_ADDRESS: usize = 254;

struct Row {
    address: String,
    used: Option<Value>,
    quota: Option<Value>,
    share: Option<f64>,
}

impl Row {
    fn of(account: &MailboxAccount) -> Row {
        let address = account.email_address.as_ref().map(text).unwrap_or_default();
        let (used, quota) = (&account.used_disk_quota, &account.quotas.0.max_disk_quota);
        let share = match (used.float(), quota.float()) {
            (Some(used), Some(quota)) if quota != 0.0 => Some(round_one(used / quota * 100.0)),
            _ => None,
        };
        Row {
            address: address.chars().take(MAX_ADDRESS).collect(),
            used: used.value(),
            quota: quota.value(),
            share,
        }
    }

    /// Fullest mailboxes first; accounts without a quota follow, largest first.
    fn order(&self, other: &Row) -> Ordering {
        let share = |row: &Row| -row.share.unwrap_or(-1.0);
        let used = |row: &Row| -row.used.as_ref().and_then(Value::as_f64).unwrap_or(0.0);
        share(self)
            .total_cmp(&share(other))
            .then(used(self).total_cmp(&used(other)))
            .then_with(|| self.address.cmp(&other.address))
    }
}

/// The card of the `accounts` read, the first `max_accounts` of Stalwart's
/// at the most; none where they could not be read.
pub fn mailboxes(
    context: &Context<'_>,
    accounts: Option<&Listed<MailboxAccount>>,
    max_accounts: usize,
) -> Result<Observation, ProviderError> {
    let base = |state| {
        Observation::new(Required {
            id: "stalwart.mailboxes",
            provider: "stalwart",
            title: "Mailbox storage",
            modules: [ModuleId::Dashboard],
            evidence: Evidence::Inventory,
            state,
            checked_at: &context.checked_at(),
            source: "x:Account/get (selected properties)",
        })
        .map(|observation| {
            observation.with_scope(
                "Stored size and quota per user account. Mail contents are not read; \
                 manage accounts in the Stalwart WebUI.",
            )
        })
    };
    let Some(listed) = accounts else {
        return Ok(base(State::Unknown)?);
    };
    let user = Some(json!("User"));
    let users: Vec<&MailboxAccount> = listed
        .objects
        .iter()
        .filter(|row| row.kind.0 == user)
        .collect();
    let mut rows: Vec<Row> = users.iter().map(|account| Row::of(account)).collect();
    rows.sort_by(Row::order);
    let full: Vec<&str> = rows
        .iter()
        .filter(|row| row.share.is_some_and(|share| share >= FULL_PERCENT))
        .map(|row| row.address.as_str())
        .collect();
    let mut findings: Vec<String> = full
        .iter()
        .take(5)
        .map(|name| format!("{name} uses 90 % or more of its quota."))
        .collect();
    // The accounts after those read: beyond `max_accounts`, or where the
    // run's time ended the pages.
    let read = listed.objects.len();
    let left = listed.total > read;
    if left {
        let total = listed.total;
        findings.push(if read >= max_accounts {
            format!("Stalwart has {total} accounts; only the first {max_accounts} are read (`max_accounts`).")
        } else if context.deadline.expired() {
            format!(
                "Stalwart has {total} accounts; only {read} of them were read: the collection run's \
                 time was used up."
            )
        } else {
            format!("Stalwart has {total} accounts; {read} of them could be read.")
        });
    }
    let state = match (full.is_empty(), left) {
        (false, _) => State::Warning,
        (true, true) => State::Partial,
        (true, false) => State::Ok,
    };
    let column = |label: &str, format| Column {
        label: label.to_owned(),
        format,
    };
    let full_count = full.len();
    let table_rows = rows
        .into_iter()
        .map(|row| {
            vec![
                json!(row.address),
                json!(row.used),
                json!(row.quota),
                json!(row.share),
            ]
        })
        .collect();
    Ok(base(state)?
        .with_fields(vec![
            Field::new("User accounts", users.len(), Format::Number),
            Field::new("At 90 % or more", full_count, Format::Number),
        ])
        .with_table(Table {
            columns: vec![
                column("Account", Format::Text),
                column("Used", Format::Bytes),
                column("Quota", Format::Bytes),
                column("Usage (%)", Format::Number),
            ],
            rows: table_rows,
        })
        .with_findings(findings)
        .with_max_age(900))
}
