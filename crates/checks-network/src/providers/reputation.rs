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
use garrison_core::observations::{
    Column, Evidence, Field, Format, Observation, Required, State, Table,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::dns::{mail_hosts, max_domains, resolver_option, system_resolver};
use crate::context::{Collected, Context, Provider, Report};
use crate::dns::{self, Kind};
use crate::kept::{Kept, cached};
use crate::options::{Checked, Options, fail};

mod asker;
mod verdict;

use asker::{Asker, RUN_OVER};
use verdict::Said;

const EVERY: i64 = 6 * 3600;
const AGAIN: i64 = 3600;
const MEMORY: &str = "reputation.read";
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
        })
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
        hosts.truncate(MOST_HOSTS);
        if hosts.is_empty() {
            return Err("Stalwart names no mail host for its domains".to_owned());
        }
        let mut asker = Asker::new(resolver, context.deadline);
        let mut addresses = Vec::new();
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
                        break;
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
        Ok(Read {
            hosts,
            addresses,
            problem: None,
            rest,
            cut: (cut || asker.cut).then(|| RUN_OVER.to_owned()),
        })
    }

    /// The last reading, or a new one where that is due: after six hours,
    /// and after an hour where not everything could be asked.
    fn known(&self, context: &Context<'_>) -> Kept<Read> {
        let wait = |_, read: &Read| {
            if read.problem.is_some() || read.cut.is_some() {
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

    /// A listing is a failure; a list without a verdict is only a row.
    fn blocklists(
        &self,
        context: &Context<'_>,
        read: &Read,
        unknown: Option<&String>,
        fields: Vec<Field>,
    ) -> Result<Observation, crate::context::ProviderError> {
        let mut rows = Vec::new();
        let mut listed = Vec::new();
        let mut verdicts = 0;
        for address in &read.addresses {
            for (list, said) in &address.lists {
                let result = match said {
                    Said::Listed(code) => {
                        listed.push(format!("{} is listed on {list} ({code}).", address.address));
                        verdicts += 1;
                        format!("listed ({code})")
                    }
                    Said::Clear => {
                        verdicts += 1;
                        "not listed".to_owned()
                    }
                    Said::Unanswered(reason) => format!("no verdict: {reason}"),
                };
                rows.push(vec![json!(address.address), json!(list), json!(result)]);
            }
        }
        let state = match (unknown, listed.is_empty(), verdicts) {
            (Some(_), _, _) | (None, true, 0) => State::Unknown,
            (None, false, _) => State::Failed,
            (None, true, _) if read.cut.is_some() => State::Partial,
            (None, true, _) => State::Ok,
        };
        let findings = match (unknown, verdicts) {
            (Some(unknown), _) => vec![unknown.clone()],
            // What was not asked is said once, beside both cards.
            (None, 0) if read.cut.is_some() => Vec::new(),
            (None, 0) => vec!["No list gave a verdict.".to_owned()],
            (None, _) => listed,
        };
        Ok(self
            .observation(context, "blocklists", "Blocklists", state)?
            .with_scope(
                "Whether an address this server sends from stands on a blocklist that receiving \
                 servers ask. The lists learn the addresses asked about. Asked every six hours.",
            )
            .with_fields(fields)
            .with_table(Table {
                columns: vec![column("Address"), column("List"), column("Result")],
                rows,
            })
            .with_findings(findings))
    }

    /// Each address needs a reverse name that leads back to it and is a mail
    /// host's own.
    fn reverse(
        &self,
        context: &Context<'_>,
        read: &Read,
        unknown: Option<&String>,
        fields: Vec<Field>,
    ) -> Result<Observation, crate::context::ProviderError> {
        let mut rows = Vec::new();
        let mut findings = Vec::new();
        for address in &read.addresses {
            let result = match &address.pointer {
                None => {
                    findings.push(format!("{} has no reverse name.", address.address));
                    "no reverse name".to_owned()
                }
                Some(name) if !address.confirmed => {
                    findings.push(format!(
                        "{} names {name}, which does not lead back to it.",
                        address.address
                    ));
                    "does not lead back".to_owned()
                }
                Some(name) if !read.hosts.contains(name) => {
                    findings.push(format!(
                        "{} names {name}, which is none of the mail hosts.",
                        address.address
                    ));
                    "not a mail host's name".to_owned()
                }
                Some(_) => "fits".to_owned(),
            };
            rows.push(vec![
                json!(address.address),
                json!(address.host),
                json!(address.pointer),
                json!(result),
            ]);
        }
        let state = match (unknown, findings.is_empty(), read.addresses.is_empty()) {
            (Some(_), _, _) | (None, _, true) => State::Unknown,
            (None, false, false) => State::Warning,
            (None, true, false) if read.cut.is_some() => State::Partial,
            (None, true, false) => State::Ok,
        };
        let findings = match (unknown, read.addresses.is_empty()) {
            (Some(unknown), _) => vec![unknown.clone()],
            (None, true) if read.cut.is_some() => Vec::new(),
            (None, true) => vec!["The mail hosts have no address.".to_owned()],
            (None, false) => findings,
        };
        Ok(self
            .observation(context, "reverse", "Reverse names", state)?
            .with_scope(
                "Each address this server sends from should have a reverse name that leads back \
                 to it and is the name the server greets with.",
            )
            .with_fields(fields)
            .with_table(Table {
                columns: vec![
                    column("Address"),
                    column("Mail host"),
                    column("Reverse name"),
                    column("Result"),
                ],
                rows,
            })
            .with_findings(findings))
    }

    fn observation(
        &self,
        context: &Context<'_>,
        id: &str,
        title: &str,
        state: State,
    ) -> Result<Observation, crate::context::ProviderError> {
        Ok(Observation::new(Required {
            id: &format!("reputation.{id}"),
            provider: self.name(),
            title,
            modules: self.modules.iter().copied(),
            evidence: Evidence::Probe,
            state,
            checked_at: &context.checked_at(),
            source: "this host's resolver",
        })?)
    }
}

fn column(label: &str) -> Column {
    Column {
        label: label.to_owned(),
        format: Format::Text,
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
            // that of the hosts that are.
            observation.findings.extend(read.rest.clone());
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
mod tests;
#[cfg(test)]
mod time_tests;
