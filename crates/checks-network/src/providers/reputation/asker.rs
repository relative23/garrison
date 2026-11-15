//! The questions of one reading, all to one resolver: a list that does not
//! answer is asked no more, and the lists are asked for a time in all.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::verdict::{Said, said};
use crate::dns::{self, Answer, Kind};

/// The lists are asked for this long at most: the collector's run has a
/// limit of its own, and a list that is down answers nothing for seconds.
const PATIENCE: Duration = Duration::from_secs(30);

/// Asks one resolver.
pub(super) struct Asker {
    resolver: SocketAddr,
    /// Lists that gave an error instead of an answer; they are not asked again.
    silent: BTreeSet<String>,
    until: Instant,
}

impl Asker {
    pub(super) fn new(resolver: SocketAddr) -> Self {
        Asker {
            resolver,
            silent: BTreeSet::new(),
            until: Instant::now() + PATIENCE,
        }
    }

    /// What `zone` says of `address`.
    pub(super) fn list(&mut self, zone: &str, address: IpAddr) -> Said {
        if self.silent.contains(zone) {
            return Said::Unanswered("the list did not answer before".to_owned());
        }
        if Instant::now() > self.until {
            return Said::Unanswered("not asked: the lists took too long".to_owned());
        }
        let answer = dns::ask(self.resolver, &dns::reversed(address, Some(zone)), Kind::A);
        if answer.is_err() {
            self.silent.insert(zone.to_owned());
        }
        said(zone, answer)
    }

    /// The records of `kind` at `name`; none where the name has none.
    pub(super) fn records(&self, name: &str, kind: Kind) -> Result<Vec<String>, String> {
        match dns::ask(self.resolver, name, kind)? {
            Answer::Records(records) => Ok(records),
            Answer::NoSuchName => Ok(Vec::new()),
        }
    }
}
