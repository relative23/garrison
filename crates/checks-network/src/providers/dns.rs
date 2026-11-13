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
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Format, Observation, State, Table};
use garrison_stalwart::jmap::JmapClient;
use serde::Deserialize;
use serde_json::json;

use crate::context::{Collected, Context, Provider, Report};
use crate::dns::{self, Answer, Kind};
use crate::options::{Checked, Options, fail};

mod sts;
mod zone;

use zone::{Verdict, expected, mx_hosts, needed, plain, verdict};

const RESOLV_CONF: &str = "/etc/resolv.conf";
const MOST_DOMAINS: usize = 20;

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

/// The hosts Stalwart names as the mail servers of its domains: the targets
/// of the MX records in its zone files.
pub(super) fn mail_hosts(context: &Context<'_>) -> Result<Vec<String>, String> {
    let key = context
        .native_key
        .as_deref()
        .ok_or("the collector's API key could not be read")?;
    let client =
        JmapClient::new(&context.deployment.stalwart_url, key).with_timeout(Duration::from_secs(8));
    let domains = client
        .get::<Domain>("Domain", None, &["name", "dnsZoneFile"])
        .map_err(|_| "Stalwart did not give its domains to the collector's API key")?;
    let mut hosts: Vec<String> = domains
        .iter()
        .take(MOST_DOMAINS)
        .flat_map(|domain| {
            mx_hosts(&expected(
                domain.dns_zone_file.as_deref().unwrap_or_default(),
            ))
        })
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    Ok(hosts)
}

/// The state of a domain and what to say of it: the records that are not as
/// Stalwart names them, then what the MTA-STS policy leaves open.
fn summed(
    empty: bool,
    open: &[String],
    unanswered: usize,
    policy: Option<String>,
) -> (State, Vec<String>) {
    let (mut state, mut findings) = if empty {
        (
            State::Unknown,
            vec!["Stalwart names no records for this domain.".to_owned()],
        )
    } else if !open.is_empty() {
        (
            State::Warning,
            vec![format!("Not as Stalwart names them: {}.", open.join(", "))],
        )
    } else if unanswered > 0 {
        (
            State::Unknown,
            vec![format!(
                "The resolver gave no answer for {unanswered} of the needed records."
            )],
        )
    } else {
        (State::Ok, Vec::new())
    };
    if open.iter().any(|record| record.starts_with("TLSA ")) {
        findings.push(
            "A published TLSA record that is not the one of Stalwart's certificate makes \
             senders that check DANE refuse this server."
                .to_owned(),
        );
    }
    if let Some(finding) = policy {
        if state == State::Ok {
            state = State::Warning;
        }
        findings.push(finding);
    }
    (state, findings)
}

/// A domain as far as it is read.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Domain {
    name: String,
    #[serde(default)]
    dns_zone_file: Option<String>,
}

#[derive(Debug)]
pub struct Dns {
    /// The resolver to ask instead of the system's.
    resolver: Option<SocketAddr>,
    max_domains: usize,
    /// Where the tests serve an MTA-STS policy; otherwise it is the domain's own address.
    policy_url: Option<String>,
}

impl Dns {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["resolver", "max_domains"])?;
        let resolver = resolver_option(raw, "dns")?;
        let max_domains = options.integer("max_domains", 20, 1, 100)?;
        Ok(Dns {
            resolver,
            max_domains: usize::try_from(max_domains).unwrap_or(MOST_DOMAINS),
            policy_url: None,
        })
    }

    fn resolver(&self) -> Option<SocketAddr> {
        self.resolver.or_else(system_resolver)
    }

    fn unknown(
        &self,
        context: &Context<'_>,
        finding: &str,
    ) -> Result<Observation, crate::context::ProviderError> {
        Ok(Observation::new(
            "dns.records",
            self.name(),
            "DNS records",
            [ModuleId::DnsTls],
            Evidence::Probe,
            State::Unknown,
            context.checked_at(),
            "x:Domain/get",
        )?
        .with_findings(vec![finding.to_owned()])
        .with_max_age(180))
    }

    fn domain(
        &self,
        context: &Context<'_>,
        resolver: SocketAddr,
        domain: &Domain,
    ) -> Result<Observation, crate::context::ProviderError> {
        let name = plain(&domain.name);
        let records = expected(domain.dns_zone_file.as_deref().unwrap_or_default());
        let mut rows = Vec::new();
        let (mut open, mut unanswered) = (Vec::new(), 0);
        // A resolver that is silent once is not asked again in this run: each
        // question would wait out its time, and the run has only so long.
        let mut silent = false;
        for (index, record) in records.iter().enumerate() {
            // The question's number only tells the answer from a stray one.
            let id =
                u16::try_from((context.now.as_second().unsigned_abs() + index as u64) % 65_521)
                    .unwrap_or(1);
            let asked = if silent {
                Err(String::new())
            } else {
                dns::ask(resolver, &record.name, record.kind, id)
            };
            let (verdict, found) = match asked {
                Ok(Answer::Records(found)) => (verdict(record, &found), found),
                Ok(Answer::NoSuchName) => (Verdict::Missing, Vec::new()),
                Err(error) => {
                    // An error for one name, such as SERVFAIL, is that name's.
                    silent = silent || error.is_empty() || error.contains("did not answer");
                    (Verdict::Unanswered, Vec::new())
                }
            };
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
                    unanswered += usize::from(needed);
                    false
                }
                Verdict::Published => false,
            };
            if counts {
                open.push(format!("{} {}", record.kind.name(), record.name));
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
            let (row, finding) = sts::checked(
                context,
                &name,
                &mx_hosts(&records),
                self.policy_url.as_deref(),
            );
            rows.push(row);
            finding
        });
        let (state, findings) = summed(records.is_empty(), &open, unanswered, policy.flatten());
        let text = |label: &str| Column {
            label: label.to_owned(),
            format: Format::Text,
        };
        Ok(Observation::new(
            format!("dns.{name}"),
            self.name(),
            format!("DNS records of {name}"),
            [ModuleId::DnsTls],
            Evidence::Probe,
            state,
            context.checked_at(),
            format!("x:Domain/get; resolver {}", resolver.ip()),
        )?
        .with_scope(
            "What Stalwart names for the domain, asked of this host's resolver now. Records \
             marked optional are a matter of choice; another resolver may still hold older \
             answers.",
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

    fn collect(&self, context: &Context<'_>) -> Collected {
        let mut report = Report::default();
        let Some(key) = &context.native_key else {
            report
                .observations
                .push(self.unknown(context, "No API key is configured.")?);
            return Ok(report);
        };
        let client = JmapClient::new(&context.deployment.stalwart_url, key)
            .with_timeout(Duration::from_secs(8));
        let Ok(domains) = client.get::<Domain>("Domain", None, &["name", "dnsZoneFile"]) else {
            report.observations.push(self.unknown(
                context,
                "Stalwart did not give its domains to the collector's API key; run \
                 `garrison stalwart setup` again to let it read them.",
            )?);
            return Ok(report);
        };
        let Some(resolver) = self.resolver() else {
            report
                .observations
                .push(self.unknown(context, "This host names no resolver in /etc/resolv.conf.")?);
            return Ok(report);
        };
        for domain in domains.iter().take(self.max_domains) {
            report
                .observations
                .push(self.domain(context, resolver, domain)?);
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
pub(crate) mod tests;
