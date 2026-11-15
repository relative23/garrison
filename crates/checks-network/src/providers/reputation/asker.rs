//! The questions of one reading, all to one resolver: a list that does not
//! answer is asked no more, the lists are asked for a time in all, and
//! nothing is asked once the run's checks must be done.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use super::shown;
use super::verdict::{Said, said};
use crate::context::Deadline;
use crate::dns::{self, Answer, Kind};

/// Why a reading stopped before it had asked everything.
pub(super) const RUN_OVER: &str = "the collection run's time was used up";
/// Why a list was not asked about an address: the lists had their time.
pub(super) const SLOW: &str = "the lists took too long";

/// The lists are asked for this long at most: the collector's run has a
/// limit of its own, and a list that is down answers nothing for seconds.
pub(super) const PATIENCE: Duration = Duration::from_secs(30);

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
    /// Whether a list was left unasked because the lists had their time.
    pub(super) slow: bool,
}

impl Asker {
    /// An asker of `resolver` until `deadline`, which asks the lists for
    /// `patience` in all.
    pub(super) fn new(resolver: SocketAddr, deadline: Deadline, patience: Duration) -> Self {
        Asker {
            resolver,
            silent: BTreeSet::new(),
            until: Instant::now() + patience,
            deadline,
            cut: false,
            slow: false,
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
            self.slow = true;
            return Said::Unanswered(format!("not asked: {SLOW}"));
        }
        // An error may repeat the question, and with it a zone's key.
        let answer = dns::ask(self.resolver, &dns::reversed(address, Some(zone)), Kind::A)
            .map_err(|error| error.to_string().replace(zone, &shown(zone)));
        if answer.is_err() {
            self.silent.insert(zone.to_owned());
        }
        said(zone, answer)
    }

    /// The records of `kind` at `name`; none where the name has none.
    pub(super) fn records(&self, name: &str, kind: Kind) -> Result<Vec<String>, dns::Error> {
        match dns::ask(self.resolver, name, kind)? {
            Answer::Records(records) => Ok(records),
            Answer::NoSuchName => Ok(Vec::new()),
        }
    }

    /// The reverse name of `address` and whether it leads back there; `None`
    /// where the run's time was up before it could be followed back. An
    /// answer that cannot be used concerns this address alone: it is kept
    /// as why, and the reading goes on.
    pub(super) fn reverse(&self, address: IpAddr) -> Option<Reverse> {
        let unread = |name: Option<String>, why: &dns::Error| Reverse {
            name,
            confirmed: false,
            unread: Some(why.to_string()),
        };
        let name = match self.records(&dns::reversed(address, None), Kind::Ptr) {
            Ok(names) => names.into_iter().next(),
            Err(why) => return Some(unread(None, &why)),
        };
        let Some(name) = name.map(|name| name.trim_end_matches('.').to_lowercase()) else {
            return Some(Reverse::default());
        };
        if self.over() {
            return None;
        }
        let back = if address.is_ipv4() {
            Kind::A
        } else {
            Kind::Aaaa
        };
        Some(match self.records(&name, back) {
            Ok(found) => Reverse {
                confirmed: found
                    .iter()
                    .any(|found| found.parse::<IpAddr>() == Ok(address)),
                name: Some(name),
                unread: None,
            },
            Err(why) => unread(Some(name), &why),
        })
    }
}

/// What [`Asker::reverse`] found of an address.
#[derive(Debug, Default)]
pub(super) struct Reverse {
    /// The address's reverse name, if it has one.
    pub(super) name: Option<String>,
    /// Whether that name leads back to the address.
    pub(super) confirmed: bool,
    /// Why the name, or where it leads, could not be read.
    pub(super) unread: Option<String>,
}
