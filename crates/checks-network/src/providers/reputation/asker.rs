//! The questions of one reading, all to one resolver: a list that does not
//! answer is asked no more, and neither are reverse names once one went
//! unanswered, nor where they lead once that did; the lists are asked for a
//! time in all, and nothing is asked once the run's checks must be done.

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
/// Why an address's reverse name, or where it leads, was not asked.
const BEFORE: &str = "the resolver did not answer such a question before";
/// The root, as the DNS client writes a name without labels: a reverse
/// name that is the root leads to no address.
pub(super) const ROOT: &str = ".";

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
    /// The kinds of question about an address that the resolver did not
    /// answer, its reverse name (PTR) or where that leads (A, AAAA): each is
    /// asked no more, since every such question would wait out its time.
    /// The resolver answered for the mail hosts, and the lists' zones are
    /// others, so the lists are asked.
    unanswered: Vec<Kind>,
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
            unanswered: Vec::new(),
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

    /// The records of `kind` at `name` about an address, unless the resolver
    /// did not answer such a question before; one it does not answer now is
    /// noted, so that it is the last of its kind.
    fn about(&mut self, name: &str, kind: Kind) -> Result<Vec<String>, String> {
        if self.unanswered.contains(&kind) {
            return Err(BEFORE.to_owned());
        }
        self.records(name, kind).map_err(|why| {
            if matches!(why, dns::Error::NoAnswer { .. }) {
                self.unanswered.push(kind);
            }
            why.to_string()
        })
    }

    /// The reverse name of `address` and whether it leads back there; `None`
    /// where the run's time was up before it could be followed back. An
    /// answer that cannot be used concerns this address alone: it is kept
    /// as why, and the reading goes on.
    pub(super) fn reverse(&mut self, address: IpAddr) -> Option<Reverse> {
        let unread = |name: Option<String>, why: String| Reverse {
            name,
            confirmed: false,
            unread: Some(why),
        };
        let name = match self.about(&dns::reversed(address, None), Kind::Ptr) {
            Ok(names) => names.into_iter().next(),
            Err(why) => return Some(unread(None, why)),
        };
        let Some(name) = name else {
            return Some(Reverse::default());
        };
        // Nothing is asked of where the root leads.
        if name == ROOT {
            return Some(Reverse {
                name: Some(name),
                ..Reverse::default()
            });
        }
        let name = name.trim_end_matches('.').to_lowercase();
        if self.over() {
            return None;
        }
        let back = if address.is_ipv4() {
            Kind::A
        } else {
            Kind::Aaaa
        };
        Some(match self.about(&name, back) {
            Ok(found) => Reverse {
                confirmed: found
                    .iter()
                    .any(|found| found.parse::<IpAddr>() == Ok(address)),
                name: Some(name),
                unread: None,
            },
            Err(why) => unread(Some(name), why),
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
