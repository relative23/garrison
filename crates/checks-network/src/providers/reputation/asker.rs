//! The questions of one reading, all to one resolver: a list that does not
//! answer is asked no more, the lists are asked for a time in all, and
//! nothing is asked once the run's checks must be done.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::verdict::{Said, said};
use crate::context::Deadline;
use crate::dns::{self, Answer, Kind};

/// Why a reading stopped before it had asked everything.
pub(super) const RUN_OVER: &str = "the collection run's time was used up";

/// The lists are asked for this long at most: the collector's run has a
/// limit of its own, and a list that is down answers nothing for seconds.
const PATIENCE: Duration = Duration::from_secs(30);

/// Asks one resolver.
pub(super) struct Asker {
    resolver: SocketAddr,
    /// Lists that gave an error instead of an answer; they are not asked again.
    silent: BTreeSet<String>,
    until: Instant,
    /// When the run's checks must be done.
    deadline: Deadline,
    /// Whether a list was left unasked because that time was up.
    pub(super) cut: bool,
}

impl Asker {
    pub(super) fn new(resolver: SocketAddr, deadline: Deadline) -> Self {
        Asker {
            resolver,
            silent: BTreeSet::new(),
            until: Instant::now() + PATIENCE,
            deadline,
            cut: false,
        }
    }

    /// Whether the run's time is up, so that nothing more may be asked.
    pub(super) fn over(&self) -> bool {
        self.deadline.expired()
    }

    /// What `zone` says of `address`.
    pub(super) fn list(&mut self, zone: &str, address: IpAddr) -> Said {
        if self.silent.contains(zone) {
            return Said::Unanswered("the list did not answer before".to_owned());
        }
        if self.over() {
            self.cut = true;
            return Said::Unanswered(format!("not asked: {RUN_OVER}"));
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
