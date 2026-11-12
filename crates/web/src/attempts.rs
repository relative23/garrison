//! A budget of sign-in code exchanges per client network.
//!
//! Each callback with a matching state makes the web service exchange a code
//! at Stalwart. The state lives in the visitor's own cookie, so anyone can mint
//! and replay one; without a budget a single visitor could make Garrison
//! send Stalwart failed exchanges without end, all from its loopback address.
//! A network is an IPv4 address or an IPv6 /64 prefix, which one client
//! usually holds whole.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Code exchanges per network and window; a person needs one per sign-in.
pub const BUDGET: u32 = 10;
const WINDOW: Duration = Duration::from_secs(60);
/// Networks tracked at once. When all of them are recent, a further network
/// passes untracked: a full table must never refuse everybody.
const MAX_NETWORKS: usize = 4096;

/// The network of a client address; `None` when nginx sent none.
pub fn network(address: Option<&str>) -> Option<IpAddr> {
    match address?.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => Some(IpAddr::V4(address)),
        IpAddr::V6(address) => Some(IpAddr::V6(Ipv6Addr::from(
            u128::from(address) & (u128::MAX << 64),
        ))),
    }
}

#[derive(Debug, Default)]
pub struct Attempts {
    recent: Mutex<HashMap<Option<IpAddr>, (Instant, u32)>>,
}

impl Attempts {
    /// Whether `network` may start one more code exchange at `now`.
    pub fn allow(&self, network: Option<IpAddr>, now: Instant) -> bool {
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        if recent.len() >= MAX_NETWORKS && !recent.contains_key(&network) {
            recent.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            if recent.len() >= MAX_NETWORKS {
                return true;
            }
        }
        let (start, count) = recent.entry(network).or_insert((now, 0));
        if now.duration_since(*start) >= WINDOW {
            (*start, *count) = (now, 0);
        }
        *count = count.saturating_add(1);
        if *count == BUDGET + 1 {
            log::warn!("Sign-in exchanges from one network exceed {BUDGET} per minute; more wait");
        }
        *count <= BUDGET
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

    #[test]
    fn each_network_gets_its_budget_per_window() {
        let attempts = Attempts::default();
        let (one, two) = (network(Some("192.0.2.1")), network(Some("192.0.2.2")));
        let start = Instant::now();
        for _ in 0..BUDGET {
            assert!(attempts.allow(one, start));
        }
        assert!(!attempts.allow(one, start));
        assert!(attempts.allow(two, start));
        assert!(attempts.allow(one, start + WINDOW));
    }

    #[test]
    fn a_full_table_lets_new_networks_pass_instead_of_refusing_them() {
        let attempts = Attempts::default();
        let start = Instant::now();
        for index in 0..MAX_NETWORKS {
            let address = IpAddr::V6(Ipv6Addr::from((index as u128) << 64));
            assert!(attempts.allow(Some(address), start));
        }
        let newcomer = network(Some("198.51.100.9"));
        for _ in 0..=BUDGET {
            assert!(attempts.allow(newcomer, start));
        }
        // A network already counted keeps its budget while the table is full.
        let known = Some(IpAddr::V6(Ipv6Addr::from(0)));
        for _ in 1..BUDGET {
            assert!(attempts.allow(known, start));
        }
        assert!(!attempts.allow(known, start));
        // Once the old entries expire, the newcomer is tracked again.
        let later = start + WINDOW;
        for _ in 0..BUDGET {
            assert!(attempts.allow(newcomer, later));
        }
        assert!(!attempts.allow(newcomer, later));
    }
}
