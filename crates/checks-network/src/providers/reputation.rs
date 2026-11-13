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
use std::time::{Duration, Instant};

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Field, Format, Observation, State, Table};
use garrison_core::time;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::dns::{mail_hosts, resolver_option, system_resolver};
use crate::context::{Collected, Context, Provider, Report};
use crate::dns::{self, Answer, Kind};
use crate::options::{Checked, Options, fail};

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

/// What a list said of an address.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
enum Said {
    /// Listed, with the list's answer, such as `127.0.0.2`.
    Listed(String),
    Clear,
    /// No verdict, and why.
    Unanswered(String),
}

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
    at: i64,
    hosts: Vec<String>,
    addresses: Vec<Asked>,
    problem: Option<String>,
}

#[derive(Debug)]
pub struct Reputation {
    resolver: Option<SocketAddr>,
    /// The mail hosts; without them, those Stalwart names.
    hosts: Vec<String>,
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

/// A list's answer for an address it was asked about.
fn said(zone: &str, answer: Result<Answer, String>) -> Said {
    match answer {
        Ok(Answer::NoSuchName) => Said::Clear,
        Ok(Answer::Records(records)) => match records.first() {
            None => Said::Clear,
            // Spamhaus answers in 127.255.255.0/24 where it gives no verdict:
            // to a public resolver, or after too many questions.
            Some(code) if zone.ends_with("spamhaus.org") && code.starts_with("127.255.255.") => {
                Said::Unanswered(
                    "the list gives this resolver no verdict; it refuses public resolvers"
                        .to_owned(),
                )
            }
            Some(code) => Said::Listed(code.clone()),
        },
        Err(error) => Said::Unanswered(error),
    }
}

/// The lists are asked for this long at most: the collector's run has a
/// limit of its own, and a list that is down answers nothing for seconds.
const PATIENCE: Duration = Duration::from_secs(30);

/// Asks one resolver, numbering its questions.
struct Asker {
    resolver: SocketAddr,
    asked: u16,
    /// Lists that gave an error instead of an answer; they are not asked again.
    silent: BTreeSet<String>,
    until: Instant,
}

impl Asker {
    fn ask(&mut self, name: &str, kind: Kind) -> Result<Answer, String> {
        self.asked = self.asked.wrapping_add(1);
        dns::ask(self.resolver, name, kind, self.asked)
    }

    /// What `zone` says of `address`.
    fn list(&mut self, zone: &str, address: IpAddr) -> Said {
        if self.silent.contains(zone) {
            return Said::Unanswered("the list did not answer before".to_owned());
        }
        if Instant::now() > self.until {
            return Said::Unanswered("not asked: the lists took too long".to_owned());
        }
        let answer = self.ask(&dns::reversed(address, Some(zone)), Kind::A);
        if answer.is_err() {
            self.silent.insert(zone.to_owned());
        }
        said(zone, answer)
    }

    /// The records of `kind` at `name`; none where the name has none.
    fn records(&mut self, name: &str, kind: Kind) -> Result<Vec<String>, String> {
        match self.ask(name, kind)? {
            Answer::Records(records) => Ok(records),
            Answer::NoSuchName => Ok(Vec::new()),
        }
    }
}

impl Reputation {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(
            raw,
            &["resolver", "hosts", "lists", "lists_ipv6", "modules"],
        )?;
        Ok(Reputation {
            resolver: resolver_option(raw, "reputation")?,
            hosts: names(raw, "hosts", &[])?,
            lists: names(raw, "lists", &LISTS)?,
            lists_ipv6: names(raw, "lists_ipv6", &LISTS_IPV6)?,
            modules: options.modules(&["dns_tls"])?,
        })
    }

    /// Ask about every address of the mail hosts.
    fn read(&self, context: &Context<'_>) -> Result<(Vec<String>, Vec<Asked>), String> {
        let resolver = self
            .resolver
            .or_else(system_resolver)
            .ok_or("this host names no resolver in /etc/resolv.conf")?;
        let mut hosts = if self.hosts.is_empty() {
            mail_hosts(context)?
        } else {
            self.hosts.clone()
        };
        hosts.truncate(MOST_HOSTS);
        if hosts.is_empty() {
            return Err("Stalwart names no mail host for its domains".to_owned());
        }
        let mut asker = Asker {
            resolver,
            asked: 0,
            silent: BTreeSet::new(),
            until: Instant::now() + PATIENCE,
        };
        let mut addresses = Vec::new();
        for host in &hosts {
            for kind in [Kind::A, Kind::Aaaa] {
                for text in asker.records(host, kind)? {
                    let Ok(address) = text.parse::<IpAddr>() else {
                        continue;
                    };
                    if addresses.len() == MOST_ADDRESSES {
                        break;
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
        Ok((hosts, addresses))
    }

    /// The last reading, or a new one where that is due.
    fn known(&self, context: &Context<'_>) -> Read {
        let now = context.now.as_second();
        let kept: Option<Read> = context
            .memory
            .recall(MEMORY)
            .and_then(|text| serde_json::from_str(&text).ok());
        if let Some(kept) = &kept {
            let wait = if kept.problem.is_some() { AGAIN } else { EVERY };
            if (0..wait).contains(&(now - kept.at)) {
                return kept.clone();
            }
        }
        let read = match self.read(context) {
            Ok((hosts, addresses)) => Read {
                at: now,
                hosts,
                addresses,
                problem: None,
            },
            Err(problem) => Read {
                at: now,
                problem: Some(problem),
                ..Read::default()
            },
        };
        if let Ok(text) = serde_json::to_string(&read) {
            context.memory.keep(MEMORY, &text);
        }
        read
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
            (None, true, _) => State::Ok,
        };
        let findings = match (unknown, verdicts) {
            (Some(unknown), _) => vec![unknown.clone()],
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
            .with_findings(findings)
            .with_max_age(180))
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
            (None, true, false) => State::Ok,
        };
        let findings = match (unknown, read.addresses.is_empty()) {
            (Some(unknown), _) => vec![unknown.clone()],
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
            .with_findings(findings)
            .with_max_age(180))
    }

    fn observation(
        &self,
        context: &Context<'_>,
        id: &str,
        title: &str,
        state: State,
    ) -> Result<Observation, crate::context::ProviderError> {
        Ok(Observation::new(
            format!("reputation.{id}"),
            self.name(),
            title,
            self.modules.iter().copied(),
            Evidence::Probe,
            state,
            context.checked_at(),
            "this host's resolver",
        )?)
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

    fn collect(&self, context: &Context<'_>) -> Collected {
        let read = self.known(context);
        let at = time::Timestamp::from_second(read.at)
            .ok()
            .map(time::isoformat);
        let asked = Field::new("Asked", at, Format::Datetime);
        let hosts = Field::text("Mail hosts", read.hosts.join(", "));
        let unknown = read
            .problem
            .as_ref()
            .map(|problem| format!("Nothing could be asked: {problem}."));

        let fields = vec![hosts, asked];
        let mut report =
            Report::of(self.blocklists(context, &read, unknown.as_ref(), fields.clone())?);
        report
            .observations
            .push(self.reverse(context, &read, unknown.as_ref(), fields)?);
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
