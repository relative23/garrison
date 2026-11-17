//! Reputation: whether the addresses this mail server sends from stand on a
//! blocklist, and whether their reverse names fit.
//!
//! A receiving server looks the sender's address up in blocklists and asks
//! for its reverse name; a listing or a name that does not fit sends mail to
//! the spam folder or back. The check asks the same questions for every
//! address of the mail hosts Stalwart names, IPv4 and IPv6 alike: a listing
//! of the IPv6 address is the one that is overlooked. The lists learn the
//! addresses they are asked about, through this host's resolver. Asked every
//! six hours. A zone of Spamhaus' Data Query Service written without its key
//! is asked with the key the collector reads (`dqs.rs`).

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Field, Format};
use serde::{Deserialize, Serialize};

use super::dns::{mail_hosts, resolver_option, system_resolver};
use super::domains::max_domains;
use crate::context::{Collected, Context, Provider, Report};
use crate::dns::{self, Kind};
use crate::kept::{Kept, cached};
use crate::options::{Checked, Options};

mod asker;
mod cards;
mod dqs;
mod named;
mod verdict;

use asker::{Asker, PATIENCE, RUN_OVER};
use named::{Before, names};
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
    /// Why the reverse name, or where it leads, could not be read: an
    /// answer the check cannot use counts for this address alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unread: Option<String>,
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
    /// Why the zones of Spamhaus' Data Query Service written without their
    /// key were not asked, where the run had no key.
    #[serde(default)]
    keyless: Option<String>,
    /// The mail hosts whose addresses of a kind could not be read, and why:
    /// an answer the check cannot use counts for that host alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hosts_unread: Vec<String>,
    /// Whether a list went unasked about an address because the lists had
    /// had their time: the blocklists card cannot be in order then. The
    /// row's words only say so.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    lists_unasked: bool,
}

impl Read {
    /// Whether an address's reverse name could not be read: the reverse
    /// names card cannot be in order then.
    fn reverse_unread(&self) -> bool {
        self.addresses.iter().any(|asked| asked.unread.is_some())
    }

    /// Whether an address of the mail hosts was neither asked nor counted:
    /// then neither card can be in order.
    fn incomplete(&self) -> bool {
        self.cut.is_some() || !self.left_out.is_empty() || !self.hosts_unread.is_empty()
    }

    /// Whether it names a zone with a key, as an earlier release kept it.
    fn names_a_key(&self) -> bool {
        self.addresses
            .iter()
            .any(|asked| asked.lists.iter().any(|(zone, _)| shown(zone) != *zone))
    }
}

/// A list's zone as the cards and the status database name it. A zone of
/// Spamhaus' Data Query Service, `KEY.zen.dq.spamhaus.net`, holds the
/// subscriber's key as its first label, a secret: it is named
/// `….zen.dq.spamhaus.net`, and only the question asks it as configured.
pub(super) fn shown(zone: &str) -> String {
    zone.strip_suffix(".dq.spamhaus.net")
        .and_then(|before| before.split_once('.'))
        .map_or_else(
            || zone.to_owned(),
            |(_, list)| format!("….{list}.dq.spamhaus.net"),
        )
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

/// Say in `said` that the addresses of `kind` of `host` could not be read,
/// for `why`. The IPv6 question follows the host's IPv4 one, so one reason
/// for both is said once.
fn unread(said: &mut Vec<String>, host: &str, kind: Kind, why: &str) {
    let ipv4 = format!("The IPv4 addresses of {host} could not be read: {why}.");
    if kind == Kind::Aaaa && said.last() == Some(&ipv4) {
        said.pop();
        said.push(format!("The addresses of {host} could not be read: {why}."));
    } else if kind == Kind::Aaaa {
        said.push(format!(
            "The IPv6 addresses of {host} could not be read: {why}."
        ));
    } else {
        said.push(ipv4);
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
            hosts: names(raw, "hosts", &[], Before::Nothing)?,
            max_domains: max_domains(&options)?,
            lists: names(raw, "lists", &LISTS, Before::Ipv4)?,
            lists_ipv6: names(raw, "lists_ipv6", &LISTS_IPV6, Before::Ipv6)?,
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
            mail_hosts(context, self.max_domains, "")?
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
        let mut hosts_unread = Vec::new();
        let mut keyless = None;
        // The addresses after the first MOST_ADDRESSES, counted as they come.
        let mut more = 0;
        // The reading keeps what it has once time is up or the resolver is silent.
        let (mut cut, mut silent) = (false, None);
        'hosts: for host in &hosts {
            // Stalwart may name a host that DNS cannot ask, which no option
            // refuses: it has no address to ask about, and the others do.
            if !dns::is_name(host) {
                left_out.push(format!("{}, so it was not asked.", dns::no_name(host)));
                continue;
            }
            for kind in [Kind::A, Kind::Aaaa] {
                if asker.over() {
                    cut = true;
                    break 'hosts;
                }
                let records = match asker.records(host, kind) {
                    Ok(records) => records,
                    // A resolver that did not answer is asked nothing more,
                    // as the dns check does: each question would wait out
                    // its time, and the run has only so long. What it
                    // answered before counts.
                    Err(error @ dns::Error::NoAnswer { .. }) => {
                        silent = Some(error.to_string());
                        break 'hosts;
                    }
                    // An answer it cannot use, malformed or an error of the
                    // resolver, concerns these addresses of this host alone.
                    Err(error) => {
                        unread(&mut hosts_unread, host, kind, &error.to_string());
                        continue;
                    }
                };
                for text in records {
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
                    // Also where the time is up between its two questions.
                    let Some(reverse) = asker.reverse(address) else {
                        cut = true;
                        break 'hosts;
                    };
                    let lists = if address.is_ipv4() {
                        &self.lists
                    } else {
                        &self.lists_ipv6
                    };
                    let lists = dqs::said(lists, address, &mut asker, context, &mut keyless);
                    addresses.push(Asked {
                        host: host.clone(),
                        address: text,
                        pointer: reverse.name,
                        confirmed: reverse.confirmed,
                        unread: reverse.unread,
                        lists,
                    });
                }
            }
        }
        if let Some(silent) = silent.as_ref().filter(|_| addresses.is_empty()) {
            return Err(silent.clone());
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
            cut: silent.or_else(|| (cut || asker.cut).then(|| RUN_OVER.to_owned())),
            left_out,
            keyless,
            hosts_unread,
            lists_unasked: asker.slow,
        })
    }

    /// The last reading, or a new one where that is due: after six hours,
    /// after an hour where not everything could be asked or read, and at once for
    /// one that an earlier release kept with a zone's key, and for one that
    /// had no key for the Data Query Service where this run has one, or
    /// another reason to have none.
    fn known(&self, context: &Context<'_>) -> Kept<Read> {
        let missing = dqs::missing(&context.dqs_key);
        let wait = |_, read: &Read| {
            if read.names_a_key() || (read.keyless.is_some() && read.keyless != missing) {
                0
            } else if read.problem.is_some()
                || read.cut.is_some()
                || read.lists_unasked
                || read.reverse_unread()
                || !read.hosts_unread.is_empty()
            {
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
        vec![
            "reputation.blocklists".to_owned(),
            "reputation.reverse".to_owned(),
        ]
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
            // out, and a host whose addresses could not be read, keep the
            // cards from being in order.
            observation.findings.extend(read.rest.clone());
            observation.findings.extend(read.left_out.iter().cloned());
            observation
                .findings
                .extend(read.hosts_unread.iter().cloned());
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
mod answers_tests;
#[cfg(test)]
mod dqs_tests;
#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod names_tests;
#[cfg(test)]
mod silence_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod time_tests;
