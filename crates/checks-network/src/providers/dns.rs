//! The DNS records of each mail domain, held against what Stalwart names.
//!
//! Stalwart writes for every domain the records it expects, as a zone file
//! (`dnsZoneFile`). The provider asks this host's resolver for each of them.
//! Mail does not work without some (MX, SPF, DKIM, DMARC): one of those that
//! is missing, or a DKIM key that differs, is a warning. The others, such as
//! the SRV and TLSA records, are a matter of choice and only shown. The
//! answers are those of one resolver at one moment; elsewhere an older answer
//! may still be held.

use std::net::{IpAddr, SocketAddr};

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Format, Observation, Required, State, Table};
use serde_json::json;

use super::domains::{Domain, domains, left_out, max_domains, not_given};
use crate::context::{Collected, Context, NO_KEY, Provider, Report};
use crate::dns::{self, Answer, Kind};
use crate::options::{Checked, Options, fail};

mod sts;
mod zone;

use zone::{Expected, Verdict, expected, mx_hosts, needed, plain, verdict};

const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The first resolver the host itself uses.
pub(super) fn system_resolver() -> Option<SocketAddr> {
    let text = std::fs::read_to_string(RESOLV_CONF).ok()?;
    dns::resolvers(&text)
        .first()
        .map(|address| (*address, 53).into())
}

/// The `resolver` option of a provider: an address, with port 53.
pub(super) fn resolver_option(raw: &toml::Table, provider: &str) -> Checked<Option<SocketAddr>> {
    match raw.get("resolver") {
        None => Ok(None),
        Some(toml::Value::String(text)) => text
            .parse::<SocketAddr>()
            .or_else(|_| text.parse::<IpAddr>().map(|address| (address, 53).into()))
            .map(Some)
            .or_else(|_| {
                fail(format!(
                    "providers[{provider}].resolver must be an IP address"
                ))
            }),
        Some(_) => fail(format!(
            "providers[{provider}].resolver must be an IP address"
        )),
    }
}

/// The hosts Stalwart names as the mail servers of its first `most` domains,
/// the targets of the MX records in their zone files, and where it has more
/// domains, the finding that says so; where they cannot be read, why, with
/// `besides` for what else mends it (see [`not_given`]), also where the
/// collector has no key.
pub(super) fn mail_hosts(
    context: &Context<'_>,
    most: usize,
    besides: &str,
) -> Result<(Vec<String>, Option<String>), String> {
    let key = context
        .native_key
        .as_deref()
        .ok_or_else(|| format!("{NO_KEY}{besides}"))?;
    let domains = domains(context, key).map_err(|error| not_given(&error, "domains", besides))?;
    let mut hosts: Vec<String> = domains
        .iter()
        .take(most)
        .flat_map(|domain| {
            mx_hosts(&expected(
                domain.dns_zone_file.as_deref().unwrap_or_default(),
            ))
        })
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    let rest = (domains.len() > most).then(|| left_out(domains.len(), most));
    Ok((hosts, rest))
}

/// Why records were not asked.
const RUN_OVER: &str = "the collection run's time was used up";

/// What the questions about a domain's records came to.
#[derive(Debug, Default)]
struct Tally {
    /// The records Stalwart names for the domain.
    records: usize,
    /// The records that are not as Stalwart names them.
    open: Vec<String>,
    /// The needed records the resolver gave no answer for.
    unanswered: usize,
    /// The records not asked, as the run's time for its checks was over.
    unasked: usize,
    /// What is said of the records whose name is no DNS name.
    nameless: Vec<String>,
}

/// The state of a domain and what to say of it: the records that are not as
/// Stalwart names them, those that were not asked, then what the MTA-STS
/// policy leaves open. What was asked counts; what was not keeps the domain
/// from being in order. A record whose name is no DNS name can never be
/// published, so a needed one is not as Stalwart names it.
fn summed(tally: &Tally, policy: sts::Outcome) -> (State, Vec<String>) {
    let (mut state, mut findings) = if tally.records == 0 {
        (
            State::Unknown,
            vec!["Stalwart names no records for this domain.".to_owned()],
        )
    } else if !tally.open.is_empty() {
        (
            State::Warning,
            vec![format!(
                "Not as Stalwart names them: {}.",
                tally.open.join(", ")
            )],
        )
    } else if tally.unanswered > 0 {
        (
            State::Unknown,
            vec![format!(
                "The resolver gave no answer for {} of the needed records.",
                tally.unanswered
            )],
        )
    } else if tally.unasked == tally.records {
        (State::Unknown, Vec::new())
    } else if tally.unasked > 0 {
        (State::Partial, Vec::new())
    } else {
        (State::Ok, Vec::new())
    };
    findings.extend(tally.nameless.iter().cloned());
    if tally.unasked > 0 && tally.unasked == tally.records {
        findings.push(format!("Not asked: {RUN_OVER}."));
    } else if tally.unasked > 0 {
        findings.push(format!(
            "{} of its {} records {} not asked: {RUN_OVER}.",
            tally.unasked,
            tally.records,
            if tally.unasked == 1 { "was" } else { "were" }
        ));
    }
    if tally.open.iter().any(|record| record.starts_with("TLSA ")) {
        findings.push(
            "A published TLSA record that is not the one of Stalwart's certificate makes \
             senders that check DANE refuse this server."
                .to_owned(),
        );
    }
    match policy {
        sts::Outcome::Fits => {}
        sts::Outcome::Finding(finding) => {
            if state == State::Ok {
                state = State::Warning;
            }
            findings.push(finding);
        }
        sts::Outcome::Unasked => {
            if state == State::Ok {
                state = State::Partial;
            }
            findings.push(format!("Its MTA-STS policy was not fetched: {RUN_OVER}."));
        }
    }
    (state, findings)
}

/// What the resolver answers for `record`, and what it found. A resolver
/// that was silent once is not asked again in this run, for this domain or
/// the next: each question would wait out its time, and the run has only so
/// long. Once the run's time for its checks is over, nothing more is asked.
/// A name that is no DNS name is never asked: that needs no resolver.
fn asked(
    context: &Context<'_>,
    resolver: SocketAddr,
    record: &Expected,
    silent: &mut bool,
) -> (Verdict, Vec<String>) {
    if !dns::is_name(&record.name) {
        return (Verdict::NoName, Vec::new());
    }
    if *silent {
        return (Verdict::Unanswered, Vec::new());
    }
    if context.deadline.expired() {
        return (Verdict::Unasked, Vec::new());
    }
    match dns::ask(resolver, &record.name, record.kind) {
        Ok(Answer::Records(found)) => (verdict(record, &found), found),
        Ok(Answer::NoSuchName) => (Verdict::Missing, Vec::new()),
        Err(error) => {
            // An error for one name, such as SERVFAIL, is that name's.
            *silent = matches!(error, dns::Error::NoAnswer { .. });
            (Verdict::Unanswered, Vec::new())
        }
    }
}

#[derive(Debug)]
pub struct Dns {
    /// The resolver to ask instead of the system's.
    resolver: Option<SocketAddr>,
    max_domains: usize,
    /// Where the tests serve an MTA-STS policy; otherwise it is the domain's own address.
    policy_url: Option<String>,
    /// The authorities a policy's server is checked against: the system's,
    /// unless a test gives its own.
    roots: Option<crate::fetch::Roots>,
}

impl Dns {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["resolver", "max_domains"])?;
        Ok(Dns {
            resolver: resolver_option(raw, "dns")?,
            max_domains: max_domains(&options)?,
            policy_url: None,
            roots: None,
        })
    }

    /// For tests: trust these roots for a policy's server.
    #[cfg(test)]
    #[must_use]
    pub fn with_roots(mut self, roots: rustls::RootCertStore) -> Self {
        self.roots = Some(std::sync::Arc::new(roots));
        self
    }

    fn resolver(&self) -> Option<SocketAddr> {
        self.resolver.or_else(system_resolver)
    }

    fn unknown(
        &self,
        context: &Context<'_>,
        finding: &str,
    ) -> Result<Observation, crate::context::ProviderError> {
        Ok(Observation::new(Required {
            id: "dns.records",
            provider: self.name(),
            title: "DNS records",
            modules: [ModuleId::DnsTls],
            evidence: Evidence::Probe,
            state: State::Unknown,
            checked_at: &context.checked_at(),
            source: "x:Domain/get",
        })?
        .with_findings(vec![finding.to_owned()])
        .with_max_age(180))
    }

    /// `silent` is whether the resolver has stopped being asked in this run
    /// because it did not answer once.
    fn domain(
        &self,
        context: &Context<'_>,
        resolver: SocketAddr,
        domain: &Domain,
        silent: &mut bool,
    ) -> Result<Observation, crate::context::ProviderError> {
        let name = plain(&domain.name);
        let records = expected(domain.dns_zone_file.as_deref().unwrap_or_default());
        let mut rows = Vec::new();
        let mut tally = Tally {
            records: records.len(),
            ..Tally::default()
        };
        for record in &records {
            let (verdict, found) = asked(context, resolver, record, silent);
            let needed = needed(&name, record);
            let counts = match verdict {
                Verdict::Missing => needed,
                // An SPF or DMARC policy of the operator's own is in order;
                // another DKIM key or mail host is not what Stalwart uses.
                Verdict::Differs => {
                    // A TLSA record is a matter of choice, but one that is
                    // published and wrong makes senders that check DANE refuse.
                    record.kind == Kind::Tlsa
                        || needed
                            && (record.kind == Kind::Mx || record.name.contains("._domainkey."))
                }
                Verdict::Unanswered => {
                    tally.unanswered += usize::from(needed);
                    false
                }
                Verdict::Unasked => {
                    tally.unasked += 1;
                    false
                }
                Verdict::NoName => {
                    tally.nameless.push(format!(
                        "{}, so its {} record was not asked.",
                        dns::no_name(&record.name),
                        record.kind.name()
                    ));
                    needed
                }
                Verdict::Published => false,
            };
            if counts {
                tally
                    .open
                    .push(format!("{} {}", record.kind.name(), record.name));
            }
            let short = |text: &str| text.chars().take(120).collect::<String>();
            rows.push(vec![
                json!(record.name),
                json!(record.kind.name()),
                json!(if needed { "needed" } else { "optional" }),
                json!(short(&record.value)),
                json!(short(&found.join(" | "))),
                json!(verdict.label()),
            ]);
        }
        // A domain that publishes the record for an MTA-STS policy must have
        // one that senders can read and that names its mail hosts.
        let published = rows.iter().any(|row: &Vec<serde_json::Value>| {
            row[0] == format!("_mta-sts.{name}")
                && row[4].as_str().is_some_and(|found| !found.is_empty())
        });
        let policy = published.then(|| {
            let (row, outcome) = sts::checked(
                context,
                &name,
                &mx_hosts(&records),
                self.policy_url.as_deref(),
                self.roots.as_ref(),
            );
            rows.push(row);
            outcome
        });
        let (state, findings) = summed(&tally, policy.unwrap_or(sts::Outcome::Fits));
        let text = |label: &str| Column {
            label: label.to_owned(),
            format: Format::Text,
        };
        Ok(Observation::new(Required {
            id: &format!("dns.{name}"),
            provider: self.name(),
            title: &format!("DNS records of {name}"),
            modules: [ModuleId::DnsTls],
            evidence: Evidence::Probe,
            state,
            checked_at: &context.checked_at(),
            source: &format!("x:Domain/get; resolver {}", resolver.ip()),
        })?
        .with_scope(
            "What Stalwart names for the domain, asked of this host's resolver now. Records \
             marked optional are a matter of choice; another resolver may still hold older \
             answers. An MTA-STS policy file is fetched once an hour.",
        )
        .with_table(Table {
            columns: vec![
                text("Name"),
                text("Type"),
                text("For mail"),
                text("Stalwart names"),
                text("Found"),
                text("Result"),
            ],
            rows,
        })
        .with_findings(findings)
        .with_max_age(180))
    }
}

impl Provider for Dns {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn ids(&self) -> Vec<String> {
        vec!["dns.records".to_owned()]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let mut report = Report::default();
        let Some(key) = &context.native_key else {
            let finding = format!("Not asked: {NO_KEY}.");
            report.observations.push(self.unknown(context, &finding)?);
            return Ok(report);
        };
        let domains = match domains(context, key) {
            Ok(domains) => domains,
            Err(error) => {
                let finding = format!("{}.", not_given(&error, "domains", ""));
                report.observations.push(self.unknown(context, &finding)?);
                return Ok(report);
            }
        };
        let Some(resolver) = self.resolver() else {
            report
                .observations
                .push(self.unknown(context, "This host names no resolver in /etc/resolv.conf.")?);
            return Ok(report);
        };
        let mut silent = false;
        for domain in domains.iter().take(self.max_domains) {
            report
                .observations
                .push(self.domain(context, resolver, domain, &mut silent)?);
        }
        // The records of the domains after them are not known.
        if domains.len() > self.max_domains {
            report
                .observations
                .push(self.unknown(context, &left_out(domains.len(), self.max_domains))?);
        }
        if domains.is_empty() {
            report
                .observations
                .push(self.unknown(context, "Stalwart has no domain.")?);
        }
        Ok(report)
    }
}

#[cfg(test)]
pub(crate) mod domains_tests;
#[cfg(test)]
mod limits_tests;
#[cfg(test)]
mod root_tests;
#[cfg(test)]
pub(crate) mod stand_in;
#[cfg(test)]
mod sts_tests;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod time_tests;
#[cfg(test)]
mod unread_tests;
