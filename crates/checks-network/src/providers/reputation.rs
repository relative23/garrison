//! Reputation: whether the addresses this mail server sends from stand on a
//! blocklist, and whether their reverse names fit.
//!
//! A receiving server looks the sender's address up in blocklists and asks
//! for its reverse name; a listing or a name that does not fit sends mail to
//! the spam folder or back. The check asks the same questions for every
//! address of the mail hosts Stalwart names, IPv4 and IPv6 alike: a listing
//! of the IPv6 address is the one that is overlooked. The lists learn the
//! addresses they are asked about, through this host's resolver. Asked every
//! six hours.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Field, Format};
use serde::{Deserialize, Serialize};

use super::dns::{mail_hosts, max_domains, resolver_option, system_resolver};
use crate::context::{Collected, Context, Provider, Report};
use crate::dns::{self, Kind};
use crate::kept::{Kept, cached};
use crate::options::{Checked, Options, fail};

mod asker;
mod cards;
mod verdict;

use asker::{Asker, PATIENCE, RUN_OVER, SLOW};
use verdict::Said;

const EVERY: i64 = 6 * 3600;
const AGAIN: i64 = 3600;
const MEMORY: &str = "reputation.read";
/// So many mail hosts and addresses are asked about at the most: each
/// address costs a question to each list, every six hours.
const MOST_HOSTS: usize = 8;
const MOST_ADDRESSES: usize = 12;
/// Lists asked about IPv4 addresses, and those that also list IPv6.
const LISTS: [&str; 4] = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "psbl.surriel.com",
    "bl.mailspike.net",
];
const LISTS_IPV6: [&str; 1] = ["zen.spamhaus.org"];

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct Asked {
    host: String,
    address: String,
    /// The address's reverse name, if it has one.
    pointer: Option<String>,
    /// Whether that name leads back to the address.
    confirmed: bool,
    lists: Vec<(String, Said)>,
}

/// What the status database keeps of the last reading.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
struct Read {
    hosts: Vec<String>,
    addresses: Vec<Asked>,
    problem: Option<String>,
    /// What to say of Stalwart's domains after the first `max_domains`.
    #[serde(default)]
    rest: Option<String>,
    /// Why not every address or list was asked, where that is so.
    #[serde(default)]
    cut: Option<String>,
    /// What the reading's own limits left out: mail hosts after the first
    /// [`MOST_HOSTS`], addresses after the first [`MOST_ADDRESSES`].
    #[serde(default)]
    left_out: Vec<String>,
}

impl Read {
    /// Whether a list went unasked about an address because the lists had
    /// had their time: the blocklists card cannot be in order then.
    fn lists_unasked(&self) -> bool {
        let unasked = Said::Unanswered(format!("not asked: {SLOW}"));
        self.addresses
            .iter()
            .any(|asked| asked.lists.iter().any(|(_, said)| *said == unasked))
    }
}

#[derive(Debug)]
pub struct Reputation {
    resolver: Option<SocketAddr>,
    /// The mail hosts; without them, those Stalwart names.
    hosts: Vec<String>,
    /// How many of Stalwart's domains name them.
    max_domains: usize,
    lists: Vec<String>,
    lists_ipv6: Vec<String>,
    modules: BTreeSet<ModuleId>,
    /// How long the lists are asked in all; tests shorten it.
    patience: std::time::Duration,
}

/// A list of DNS names from an option; `default` where it is absent.
fn names(raw: &toml::Table, key: &str, default: &[&str]) -> Checked<Vec<String>> {
    let wrong = || {
        fail(format!(
            "providers[reputation].{key} must be a list of DNS names"
        ))
    };
    match raw.get(key) {
        None => Ok(default.iter().map(ToString::to_string).collect()),
        Some(toml::Value::Array(items)) => {
            let mut names = Vec::new();
            for item in items {
                let name = item
                    .as_str()
                    .unwrap_or_default()
                    .trim_end_matches('.')
                    .to_lowercase();
                let plain = |label: &str| {
                    !label.is_empty()
                        && label
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '-')
                };
                if name.len() > 253
                    || !name.contains('.')
                    || !name.split('.').all(plain)
                    || names.contains(&name)
                {
                    return wrong();
                }
                names.push(name);
            }
            Ok(names)
        }
        Some(_) => wrong(),
    }
}

impl Reputation {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(
            raw,
            &[
                "resolver",
                "hosts",
                "max_domains",
                "lists",
                "lists_ipv6",
                "modules",
            ],
        )?;
        Ok(Reputation {
            resolver: resolver_option(raw, "reputation")?,
            hosts: names(raw, "hosts", &[])?,
            max_domains: max_domains(&options)?,
            lists: names(raw, "lists", &LISTS)?,
            lists_ipv6: names(raw, "lists_ipv6", &LISTS_IPV6)?,
            modules: options.modules(&["dns_tls"])?,
            patience: PATIENCE,
        })
    }

    /// For tests: ask the lists for `patience` in all instead of 30 seconds.
    #[cfg(test)]
    #[must_use]
    pub fn with_patience(mut self, patience: std::time::Duration) -> Self {
        self.patience = patience;
        self
    }

    /// Ask about every address of the mail hosts.
    fn read(&self, context: &Context<'_>) -> Result<Read, String> {
        let resolver = self
            .resolver
            .or_else(system_resolver)
            .ok_or("this host names no resolver in /etc/resolv.conf")?;
        let (mut hosts, rest) = if self.hosts.is_empty() {
            mail_hosts(context, self.max_domains)?
        } else {
            (self.hosts.clone(), None)
        };
        let mut left_out = Vec::new();
        if hosts.len() > MOST_HOSTS {
            left_out.push(format!(
                "There are {} mail hosts; only the first {MOST_HOSTS} are asked.",
                hosts.len()
            ));
            hosts.truncate(MOST_HOSTS);
        }
        if hosts.is_empty() {
            return Err("Stalwart names no mail host for its domains".to_owned());
        }
        let mut asker = Asker::new(resolver, context.deadline, self.patience);
        let mut addresses = Vec::new();
        // The addresses after the first MOST_ADDRESSES, counted as they come.
        let mut more = 0;
        // Once the run's time is up, the reading keeps what it has.
        let mut cut = false;
        'hosts: for host in &hosts {
            for kind in [Kind::A, Kind::Aaaa] {
                if asker.over() {
                    cut = true;
                    break 'hosts;
                }
                for text in asker.records(host, kind)? {
                    let Ok(address) = text.parse::<IpAddr>() else {
                        continue;
                    };
                    if addresses.len() == MOST_ADDRESSES {
                        more += 1;
                        continue;
                    }
                    if asker.over() {
                        cut = true;
                        break 'hosts;
                    }
                    let pointer = asker
                        .records(&dns::reversed(address, None), Kind::Ptr)?
                        .into_iter()
                        .next()
                        .map(|name| name.trim_end_matches('.').to_lowercase());
                    let back = if address.is_ipv4() {
                        Kind::A
                    } else {
                        Kind::Aaaa
                    };
                    let confirmed = match &pointer {
                        Some(_) if asker.over() => {
                            cut = true;
                            break 'hosts;
                        }
                        Some(name) => asker
                            .records(name, back)?
                            .iter()
                            .any(|found| found.parse::<IpAddr>() == Ok(address)),
                        None => false,
                    };
                    let lists = if address.is_ipv4() {
                        &self.lists
                    } else {
                        &self.lists_ipv6
                    };
                    let lists = lists
                        .iter()
                        .map(|zone| (zone.clone(), asker.list(zone, address)))
                        .collect();
                    addresses.push(Asked {
                        host: host.clone(),
                        address: text,
                        pointer,
                        confirmed,
                        lists,
                    });
                }
            }
        }
        if more > 0 {
            left_out.push(format!(
                "The mail hosts have {} addresses; only the first {MOST_ADDRESSES} are asked.",
                MOST_ADDRESSES + more
            ));
        }
        Ok(Read {
            hosts,
            addresses,
            problem: None,
            rest,
            cut: (cut || asker.cut).then(|| RUN_OVER.to_owned()),
            left_out,
        })
    }

    /// The last reading, or a new one where that is due: after six hours,
    /// and after an hour where not everything could be asked.
    fn known(&self, context: &Context<'_>) -> Kept<Read> {
        let wait = |_, read: &Read| {
            if read.problem.is_some() || read.cut.is_some() || read.lists_unasked() {
                AGAIN
            } else {
                EVERY
            }
        };
        cached(context, MEMORY, wait, |_| {
            self.read(context).unwrap_or_else(|problem| Read {
                problem: Some(problem),
                ..Read::default()
            })
        })
    }
}

impl Provider for Reputation {
    fn name(&self) -> &'static str {
        "reputation"
    }

    fn ids(&self) -> Vec<String> {
        vec!["reputation.blocklists".to_owned()]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let kept = self.known(context);
        let read = &kept.answer;
        let asked = Field::new("Asked", kept.asked(), Format::Datetime);
        let hosts = Field::text("Mail hosts", read.hosts.join(", "));
        let unknown = read
            .problem
            .as_ref()
            .map(|problem| format!("Nothing could be asked: {problem}."));

        let fields = vec![hosts, asked];
        let cards = [
            self.blocklists(context, read, unknown.as_ref(), fields.clone())?,
            self.reverse(context, read, unknown.as_ref(), fields)?,
        ];
        let mut report = Report::default();
        for mut observation in cards {
            // The hosts of the domains left out are not asked; the state is
            // that of the hosts that are. What the reading's own limits left
            // out keeps the cards from being in order.
            observation.findings.extend(read.rest.clone());
            observation.findings.extend(read.left_out.iter().cloned());
            observation.findings.extend(
                read.cut
                    .as_ref()
                    .map(|reason| format!("Not every address or list was asked: {reason}.")),
            );
            // Both cards are as old as the reading they are made from.
            report.observations.push(kept.dated(observation));
        }
        Ok(report)
    }
}

#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod time_tests;
