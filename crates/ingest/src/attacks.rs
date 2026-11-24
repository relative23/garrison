//! Attacks and bans: who tries to sign in and fails, whom Stalwart banned,
//! whose connections it refused while it blocked them and whose TLS
//! handshakes fail, summed over a stretch of the event history.
//!
//! Stalwart counts failed sign-ins itself and bans an address after too many.
//! This summary shows that work and what it cannot catch: an address that
//! stays under the limit, a network that spreads its attempts over many
//! addresses, and an account that many addresses try.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::event_type::EventType;
use crate::queries::Result;

/// The newest events of one type that are read. Where a type has more in the
/// stretch, the summary says that it is cut.
pub const MAX_EVENTS: usize = 100_000;
/// The rows of each list.
pub const MAX_ROWS: usize = 50;

/// The sign-ins Stalwart refused: a wrong password or name, the right
/// password without its second factor, and a credential used from an
/// address it does not allow.
const SIGN_INS: [EventType; 3] = [
    EventType::AuthFailed,
    EventType::AuthMfaRequired,
    EventType::SecurityIpUnauthorized,
];

const BANS: [(EventType, &str); 4] = [
    (EventType::SecurityAuthenticationBan, "authentication"),
    (EventType::SecurityAbuseBan, "abuse"),
    (EventType::SecurityScanBan, "scan"),
    (EventType::SecurityLoiterBan, "loiter"),
];

/// One address that failed to sign in, was banned or refused, or failed a
/// TLS handshake.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Source {
    pub address: String,
    /// The /24 of an IPv4 address, the /64 of an IPv6 address.
    pub network: String,
    pub failed_sign_ins: u64,
    /// The existing accounts it tried.
    pub accounts: u64,
    pub tls_errors: u64,
    pub bans: u64,
    /// Its connections that Stalwart refused while it blocked the address or
    /// its network.
    pub refused: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    /// The listeners it reached, such as `submission` or `imaps`.
    pub listeners: Vec<String>,
}

/// A network from which more than one address was seen.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    pub network: String,
    pub sources: u64,
    pub failed_sign_ins: u64,
    pub tls_errors: u64,
    pub bans: u64,
    pub refused: u64,
    pub last_seen: i64,
}

/// An existing account that someone failed to sign in to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub name: String,
    pub failed_sign_ins: u64,
    /// The addresses that tried it.
    pub sources: u64,
    pub last_seen: i64,
}

/// One ban Stalwart imposed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ban {
    pub at: i64,
    pub address: String,
    /// The /64 of an IPv6 address. Stalwart's event names the address, and
    /// Stalwart 1.2.0 blocks the whole /64 with it, which its own list of
    /// blocked IPs names, unless an account's count of failed sign-ins alone
    /// banned the address (measured).
    pub network: Option<String>,
    /// Why: `authentication`, `abuse`, `scan` or `loiter`.
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Totals {
    pub failed_sign_ins: u64,
    /// Failed sign-ins that named no existing account.
    pub unknown_accounts: u64,
    pub tls_errors: u64,
    pub bans: u64,
    /// Connections Stalwart refused while it blocked their address; `None`
    /// where the history holds none at all, as before setup asked Stalwart
    /// for them: none recorded is no count of none refused.
    pub refused: Option<u64>,
    /// Every address seen, also beyond the rows of the list.
    pub sources: u64,
}

/// The summary of the stretch from `since` to `until`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Attacks {
    pub since: i64,
    pub until: i64,
    /// More events of a type were recorded in the stretch than were read.
    pub truncated: bool,
    pub totals: Totals,
    /// The busiest addresses first.
    pub sources: Vec<Source>,
    pub networks: Vec<Network>,
    pub accounts: Vec<Account>,
    /// The newest bans first.
    pub bans: Vec<Ban>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fields {
    remote_ip: Option<String>,
    account_name: Option<String>,
    /// An existing account, which a refusal may name by its ID alone.
    account_id: Option<serde_json::Value>,
    listener_id: Option<String>,
}

/// The network an address counts to: its /24, or its /64 for IPv6. Text that
/// is no address is its own network.
pub fn network(address: &str) -> String {
    match address.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
        Ok(IpAddr::V4(ip)) => {
            let [a, b, c, _] = ip.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        Ok(IpAddr::V6(ip)) => {
            let [a, b, c, d, ..] = ip.segments();
            format!("{}/64", std::net::Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
        Err(_) => address.to_owned(),
    }
}

/// Whether the history holds any event of `kind`, in any stretch.
fn recorded(db: &Connection, kind: EventType) -> Result<bool> {
    let mut statement = db.prepare_cached("SELECT EXISTS(SELECT 1 FROM events WHERE type=?1)")?;
    Ok(statement.query_row([kind.as_str()], |row| row.get(0))?)
}

/// The /64 that Stalwart blocks with an IPv6 address it bans; an IPv4
/// address it blocks alone.
fn blocked_with(address: &str) -> Option<String> {
    let ipv6 = matches!(
        address.parse::<IpAddr>().map(|ip| ip.to_canonical()),
        Ok(IpAddr::V6(_))
    );
    ipv6.then(|| network(address))
}

#[derive(Default)]
struct Seen {
    source: Source,
    accounts: BTreeSet<String>,
    listeners: BTreeSet<String>,
}

#[derive(Default)]
struct Tried {
    failed: u64,
    sources: BTreeSet<String>,
    last_seen: i64,
}

#[derive(Default)]
struct Sums {
    truncated: bool,
    totals: Totals,
    sources: HashMap<String, Seen>,
    accounts: HashMap<String, Tried>,
    bans: Vec<Ban>,
}

impl Sums {
    /// Read the events of one type in the stretch, newest first, and hand
    /// each to `count` with the address it came from.
    fn read(
        &mut self,
        db: &Connection,
        kind: EventType,
        stretch: (i64, i64),
        mut count: impl FnMut(&mut Self, i64, &str, &Fields),
    ) -> Result<()> {
        let mut statement = db.prepare_cached(
            "SELECT created_at,fields FROM events WHERE type=?1 AND created_at>=?2 \
             AND created_at<=?3 ORDER BY seq DESC LIMIT ?4",
        )?;
        let limit = i64::try_from(MAX_EVENTS + 1).unwrap_or(i64::MAX);
        let mut rows = statement.query((kind.as_str(), stretch.0, stretch.1, limit))?;
        let mut read = 0;
        while let Some(row) = rows.next()? {
            if read == MAX_EVENTS {
                self.truncated = true;
                break;
            }
            read += 1;
            let at: i64 = row.get(0)?;
            let text: String = row.get(1)?;
            // An event without an address says nothing about a source.
            let Ok(fields) = serde_json::from_str::<Fields>(&text) else {
                continue;
            };
            let Some(address) = fields.remote_ip.clone() else {
                continue;
            };
            let seen = self.sources.entry(address.clone()).or_default();
            let source = &mut seen.source;
            if source.last_seen == 0 {
                (source.first_seen, source.last_seen) = (at, at);
            }
            source.first_seen = source.first_seen.min(at);
            source.last_seen = source.last_seen.max(at);
            seen.listeners.extend(fields.listener_id.clone());
            count(self, at, &address, &fields);
        }
        Ok(())
    }

    fn source(&mut self, address: &str) -> &mut Seen {
        self.sources.entry(address.to_owned()).or_default()
    }

    /// One refused sign-in, of its account where it names one.
    fn failed_sign_in(&mut self, at: i64, address: &str, fields: &Fields) {
        self.totals.failed_sign_ins += 1;
        let seen = self.sources.entry(address.to_owned()).or_default();
        seen.source.failed_sign_ins += 1;
        match (&fields.account_name, &fields.account_id) {
            (Some(name), _) => {
                seen.accounts.insert(name.clone());
                let tried = self.accounts.entry(name.clone()).or_default();
                tried.failed += 1;
                tried.sources.insert(address.to_owned());
                tried.last_seen = tried.last_seen.max(at);
            }
            (None, Some(_)) => {}
            (None, None) => self.totals.unknown_accounts += 1,
        }
    }

    /// Every kind the summary counts, read for the stretch.
    fn of(db: &Connection, stretch: (i64, i64)) -> Result<Self> {
        let mut sums = Sums::default();
        for kind in SIGN_INS {
            sums.read(db, kind, stretch, Sums::failed_sign_in)?;
        }
        sums.read(
            db,
            EventType::TlsHandshakeError,
            stretch,
            |sums, _, address, _| {
                sums.totals.tls_errors += 1;
                sums.source(address).source.tls_errors += 1;
            },
        )?;
        for (kind, reason) in BANS {
            sums.read(db, kind, stretch, |sums, at, address, _| {
                sums.totals.bans += 1;
                sums.source(address).source.bans += 1;
                sums.bans.push(Ban {
                    at,
                    address: address.to_owned(),
                    network: blocked_with(address),
                    reason: reason.to_owned(),
                });
            })?;
        }
        let mut refused = 0;
        sums.read(
            db,
            EventType::SecurityIpBlocked,
            stretch,
            |sums, _, address, _| {
                refused += 1;
                sums.source(address).source.refused += 1;
            },
        )?;
        sums.totals.refused = match refused {
            0 => recorded(db, EventType::SecurityIpBlocked)?.then_some(0),
            count => Some(count),
        };
        Ok(sums)
    }
}

/// Busiest first; among equals the one seen last, then by name, so that the
/// order is the same on every request.
fn busiest<T>(items: &mut Vec<T>, weight: impl Fn(&T) -> (u64, i64), name: impl Fn(&T) -> &str) {
    items.sort_by(|left, right| {
        weight(right)
            .cmp(&weight(left))
            .then_with(|| name(left).cmp(name(right)))
    });
    items.truncate(MAX_ROWS);
}

fn networks(sources: &[Source]) -> Vec<Network> {
    let mut found: HashMap<&str, Network> = HashMap::new();
    for source in sources {
        let network = found.entry(&source.network).or_default();
        network.sources += 1;
        network.failed_sign_ins += source.failed_sign_ins;
        network.tls_errors += source.tls_errors;
        network.bans += source.bans;
        network.refused += source.refused;
        network.last_seen = network.last_seen.max(source.last_seen);
    }
    let mut networks: Vec<Network> = found
        .into_iter()
        .filter(|(_, network)| network.sources > 1)
        .map(|(name, network)| Network {
            network: name.to_owned(),
            ..network
        })
        .collect();
    busiest(
        &mut networks,
        |network| {
            (
                network.failed_sign_ins + network.tls_errors + network.refused,
                network.last_seen,
            )
        },
        |network| &network.network,
    );
    networks
}

/// Failed sign-ins, bans and TLS handshake errors between `since` and
/// `until`, by address, network and account.
pub fn attacks(db: &Connection, since: i64, until: i64) -> Result<Attacks> {
    let sums = Sums::of(db, (since, until))?;

    let mut sources: Vec<Source> = sums
        .sources
        .into_iter()
        .map(|(address, seen)| Source {
            network: network(&address),
            address,
            accounts: seen.accounts.len() as u64,
            listeners: seen.listeners.into_iter().collect(),
            ..seen.source
        })
        .collect();
    let mut totals = sums.totals;
    totals.sources = sources.len() as u64;
    // The networks count every address, not only the rows that are shown.
    let networks = networks(&sources);
    busiest(
        &mut sources,
        |source| {
            (
                source.failed_sign_ins + source.tls_errors + source.bans + source.refused,
                source.last_seen,
            )
        },
        |source| &source.address,
    );
    let mut accounts: Vec<Account> = sums
        .accounts
        .into_iter()
        .map(|(name, tried)| Account {
            name,
            failed_sign_ins: tried.failed,
            sources: tried.sources.len() as u64,
            last_seen: tried.last_seen,
        })
        .collect();
    busiest(
        &mut accounts,
        |account| (account.failed_sign_ins, account.last_seen),
        |account| &account.name,
    );
    let mut bans = sums.bans;
    bans.sort_by(|left, right| {
        right
            .at
            .cmp(&left.at)
            .then_with(|| left.address.cmp(&right.address))
    });
    bans.truncate(MAX_ROWS);
    Ok(Attacks {
        since,
        until,
        truncated: sums.truncated,
        totals,
        sources,
        networks,
        accounts,
        bans,
    })
}

#[cfg(test)]
mod tests;
