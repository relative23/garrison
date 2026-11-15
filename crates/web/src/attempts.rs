//! A budget of sign-in code exchanges per client network.
//!
//! Each callback with a matching state makes the web service exchange a code
//! at Stalwart. The state lives in the visitor's own cookie, so anyone can mint
//! and replay one; without a budget a single visitor could make Garrison
//! send Stalwart failed exchanges without end, all from its loopback address.
//! A network is an IPv4 address or an IPv6 /64 prefix, which one client
//! usually holds whole; an IPv4 address written as IPv6 is the IPv4 address.
//!
//! The table of networks is bounded, and anyone with a large IPv6 prefix has
//! more networks than it holds. The networks beyond a full table therefore
//! share one budget: a flood from many networks reaches Stalwart with a
//! bounded number of exchanges, keeps no network it counts from its own
//! budget, and is forgotten one window after it ends.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Code exchanges per network and window; a person needs one per sign-in.
pub const BUDGET: u32 = 10;
const WINDOW: Duration = Duration::from_secs(60);
/// Networks tracked at once. When all of them are recent, further networks
/// share one more budget of [`BUDGET`]: a full table must never refuse
/// everybody new, nor let everybody pass.
pub const MAX_NETWORKS: usize = 4096;

/// The network of a client address; `None` when nginx sent none. An IPv4
/// address in IPv6's form, such as `::ffff:192.0.2.7`, is that IPv4
/// address: nginx names IPv4 clients so where one socket listens for both
/// (`listen [::]:443 ipv6only=off`), and as an IPv6 /64 all of them would
/// be one network.
pub fn network(address: Option<&str>) -> Option<IpAddr> {
    match address?.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => Some(IpAddr::V4(address)),
        IpAddr::V6(address) => Some(match address.to_ipv4_mapped() {
            Some(mapped) => IpAddr::V4(mapped),
            None => IpAddr::V6(Ipv6Addr::from(u128::from(address) & (u128::MAX << 64))),
        }),
    }
}

/// Why a code exchange may not start now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// This network has used its budget in the current window.
    Network,
    /// The table is full of networks seen within the window, and the networks
    /// beyond it have used the budget they share.
    Crowded,
}

/// The exchanges of one window, which starts with its first exchange.
#[derive(Debug)]
struct Window {
    start: Instant,
    count: u32,
}

impl Window {
    fn new(now: Instant) -> Self {
        Window {
            start: now,
            count: 0,
        }
    }

    fn recent(&self, now: Instant) -> bool {
        now.duration_since(self.start) < WINDOW
    }

    /// Count one more exchange at `now`: how many the window holds with it.
    fn take(&mut self, now: Instant) -> u32 {
        if !self.recent(now) {
            *self = Window::new(now);
        }
        self.count = self.count.saturating_add(1);
        self.count
    }
}

#[derive(Debug, Default)]
struct Table {
    networks: HashMap<Option<IpAddr>, Window>,
    /// What the networks beyond a full table used together.
    others: Option<Window>,
    /// No network's window ends before this, so a sweep of the full table
    /// sooner would find nothing to remove; `None` before the first sweep.
    /// Every callback beyond the table takes its lock, and a sweep of 4096
    /// entries a callback would hold it a hundred times as long.
    unchanged_until: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct Attempts {
    table: Mutex<Table>,
}

impl Attempts {
    /// Whether `network` may start one more code exchange at `now`.
    pub fn allow(&self, network: Option<IpAddr>, now: Instant) -> Result<(), Refusal> {
        let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        let Table {
            networks,
            others,
            unchanged_until,
        } = &mut *table;
        if networks.len() >= MAX_NETWORKS && !networks.contains_key(&network) {
            if unchanged_until.is_none_or(|until| now >= until) {
                networks.retain(|_, window| window.recent(now));
                // A window renewed since only ends later than this.
                *unchanged_until = networks
                    .values()
                    .filter_map(|window| window.start.checked_add(WINDOW))
                    .min();
            }
            if networks.len() >= MAX_NETWORKS {
                let count = others.get_or_insert_with(|| Window::new(now)).take(now);
                if count == BUDGET + 1 {
                    log::warn!(
                        "Sign-in exchanges from more than {MAX_NETWORKS} networks in a minute; \
                         the others share {BUDGET} per minute, more wait"
                    );
                }
                return if count <= BUDGET {
                    Ok(())
                } else {
                    Err(Refusal::Crowded)
                };
            }
        }
        let count = networks
            .entry(network)
            .or_insert_with(|| Window::new(now))
            .take(now);
        if count == BUDGET + 1 {
            log::warn!("Sign-in exchanges from one network exceed {BUDGET} per minute; more wait");
        }
        if count <= BUDGET {
            Ok(())
        } else {
            Err(Refusal::Network)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_are_ipv4_addresses_and_ipv6_prefixes() {
        let parsed = |text: &str| network(Some(text)).map(|address| address.to_string());
        assert_eq!(parsed("192.0.2.7").as_deref(), Some("192.0.2.7"));
        assert_eq!(
            parsed("2001:db8:1:2:aa:bb:cc:dd").as_deref(),
            Some("2001:db8:1:2::")
        );
        assert_eq!(network(Some("not an address")), None);
        assert_eq!(network(None), None);
    }

    /// nginx names an IPv4 client so where it listens on IPv6 for both
    /// (`listen [::]:443 ipv6only=off`).
    #[test]
    fn an_ipv4_address_in_ipv6_form_is_that_ipv4_address() {
        let parsed = |text: &str| network(Some(text)).map(|address| address.to_string());
        assert_eq!(parsed("::ffff:192.0.2.7").as_deref(), Some("192.0.2.7"));
        assert_eq!(parsed("::ffff:c000:207").as_deref(), Some("192.0.2.7"));
        // Two such clients are two networks, each with its own budget, and a
        // client is one network in either form.
        let attempts = Attempts::default();
        let one = network(Some("::ffff:192.0.2.1"));
        let two = network(Some("::ffff:198.51.100.1"));
        let start = Instant::now();
        for _ in 0..BUDGET {
            assert_eq!(attempts.allow(one, start), Ok(()));
        }
        assert_eq!(attempts.allow(one, start), Err(Refusal::Network));
        assert_eq!(attempts.allow(two, start), Ok(()));
        assert_eq!(
            attempts.allow(network(Some("192.0.2.1")), start),
            Err(Refusal::Network)
        );
        // An IPv6 address that only begins with zeros stays an IPv6 /64.
        assert_eq!(parsed("::1").as_deref(), Some("::"));
        assert_eq!(parsed("64:ff9b::c000:207").as_deref(), Some("64:ff9b::"));
    }

    #[test]
    fn each_network_gets_its_budget_per_window() {
        let attempts = Attempts::default();
        let (one, two) = (network(Some("192.0.2.1")), network(Some("192.0.2.2")));
        let start = Instant::now();
        for _ in 0..BUDGET {
            assert_eq!(attempts.allow(one, start), Ok(()));
        }
        assert_eq!(attempts.allow(one, start), Err(Refusal::Network));
        assert_eq!(attempts.allow(two, start), Ok(()));
        assert_eq!(attempts.allow(one, start + WINDOW), Ok(()));
    }

    /// A table holding `MAX_NETWORKS` networks of one IPv6 /48, seen at `now`.
    fn full_table(attempts: &Attempts, now: Instant) {
        for index in 0..MAX_NETWORKS {
            assert_eq!(attempts.allow(prefix(index), now), Ok(()));
        }
    }

    /// The `index`th /64 of `2001:db8::/48`.
    fn prefix(index: usize) -> Option<IpAddr> {
        network(Some(&format!("2001:db8:0:{index:x}::1")))
    }

    fn newcomer(index: usize) -> Option<IpAddr> {
        network(Some(&format!("198.51.100.{index}")))
    }

    fn budget() -> usize {
        usize::try_from(BUDGET).unwrap()
    }

    #[test]
    fn a_full_table_gives_further_networks_one_budget_together() {
        let attempts = Attempts::default();
        let start = Instant::now();
        full_table(&attempts, start);
        // Each newcomer is another network; together they get one budget.
        for index in 0..budget() {
            assert_eq!(attempts.allow(newcomer(index), start), Ok(()));
        }
        for index in 0..20 {
            assert_eq!(
                attempts.allow(newcomer(index), start),
                Err(Refusal::Crowded)
            );
        }
        // A network already counted keeps its own budget while the table is full.
        let known = prefix(0);
        for _ in 1..BUDGET {
            assert_eq!(attempts.allow(known, start), Ok(()));
        }
        assert_eq!(attempts.allow(known, start), Err(Refusal::Network));
        // A second before the window ends, the flood still fills the table.
        let late = start + WINDOW.saturating_sub(Duration::from_secs(1));
        assert_eq!(attempts.allow(newcomer(0), late), Err(Refusal::Crowded));
        // Once the old entries expire, a newcomer is tracked with its own budget.
        let later = start + WINDOW;
        for _ in 0..BUDGET {
            assert_eq!(attempts.allow(newcomer(0), later), Ok(()));
        }
        assert_eq!(attempts.allow(newcomer(0), later), Err(Refusal::Network));
    }

    /// A flood beyond a full table: each callback takes the table's lock,
    /// and must not hold it for a sweep of all the networks when none of
    /// their windows can have ended.
    #[test]
    fn a_callback_beyond_a_full_table_costs_no_more_than_a_counted_one() {
        let attempts = Attempts::default();
        let start = Instant::now();
        full_table(&attempts, start);
        let calls = 20_000;
        // The quickest of five rounds, so that a pause of the machine's own
        // does not count.
        let timed = |network: &dyn Fn(usize) -> Option<IpAddr>| {
            (0..5)
                .map(|_| {
                    let began = Instant::now();
                    for index in 0..calls {
                        let _ = attempts.allow(network(index), start + Duration::from_secs(1));
                    }
                    began.elapsed()
                })
                .min()
                .unwrap()
        };
        let counted = timed(&|_| prefix(0));
        let beyond = timed(&|index| newcomer(index % 250));
        // A sweep of 4096 entries took a hundred times as long as a
        // counted network's callback; without one, the two are alike.
        assert!(
            beyond < counted * 10,
            "{calls} callbacks: {beyond:?} beyond the table, {counted:?} of a counted network"
        );
    }

    #[test]
    fn a_lasting_flood_leaves_further_networks_a_budget_each_window() {
        let attempts = Attempts::default();
        let start = Instant::now();
        full_table(&attempts, start);
        for index in 0..=budget() {
            attempts.allow(newcomer(index), start).ok();
        }
        assert_eq!(attempts.allow(newcomer(0), start), Err(Refusal::Crowded));
        // The flood comes back from all its networks as their windows end, so
        // the table stays full; the shared budget is new all the same.
        let next = start + WINDOW;
        full_table(&attempts, next);
        for index in 0..budget() {
            assert_eq!(attempts.allow(newcomer(index), next), Ok(()));
        }
        assert_eq!(attempts.allow(newcomer(0), next), Err(Refusal::Crowded));
    }
}
