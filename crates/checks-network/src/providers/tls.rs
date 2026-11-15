//! TLS certificate probes against local listeners.
//!
//! Each endpoint is contacted on a configured address (normally 127.0.0.1)
//! with the public host name as SNI, and the chain and host name are validated
//! against the system's trust store. SMTP endpoints use STARTTLS. This proves
//! what the local listener presents; it does not prove public reachability or
//! DNS correctness.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use garrison_core::modules::ModuleId;
use garrison_core::observations::{
    Column, Evidence, Field, Format, Observation, Required, State, Table,
};
use garrison_core::time::{self, Timestamp};
use rustls::pki_types::ServerName;
use rustls::{CertificateError, ClientConnection, RootCertStore};
use serde_json::{Value, json};

use super::certificate::not_after;
use super::dns::max_domains;
use crate::context::{Collected, Context, Provider, Report};
use crate::fetch;
use crate::options::{Checked, Options, fail};
use crate::timed::Timed;

const WARN_DAYS: i64 = 14;
/// One step of a probe waits this long at most: the connection, one read or
/// write.
const TIMEOUT: Duration = Duration::from_secs(5);
/// A probe has this long in all, so that a listener that sends a byte now
/// and then cannot hold the run.
const PROBE: Duration = Duration::from_secs(10);
const MAX_REPLY: usize = 65536;

mod listeners;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Endpoint {
    host: String,
    port: u16,
    address: String,
    starttls: bool,
}

/// What a successful probe found.
#[derive(Debug, PartialEq, Eq)]
pub struct Probed {
    pub expires_at: String,
    pub days: i64,
    pub protocol: &'static str,
}

/// Why a probe failed, in the words of the finding.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure(pub &'static str);

fn failure(error: &io::Error) -> Failure {
    if let Some(tls) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return Failure(match tls {
            rustls::Error::InvalidCertificate(reason) => certificate(reason),
            _ => "TLS error",
        });
    }
    Failure(match error.kind() {
        io::ErrorKind::ConnectionRefused => "connection refused",
        io::ErrorKind::ConnectionReset => "connection reset",
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timed out",
        _ => "connection failed",
    })
}

/// A certificate's fault as the card names it.
fn certificate(reason: &CertificateError) -> &'static str {
    match reason {
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
            "certificate expired"
        }
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
            "certificate not valid yet"
        }
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            "certificate not valid for this name"
        }
        CertificateError::UnknownIssuer => "certificate not from a trusted authority",
        _ => "certificate not trusted",
    }
}

fn protocol_error(message: &str) -> io::Error {
    io::Error::other(message.to_owned())
}

/// The last line of one SMTP reply.
fn reply(stream: &mut impl Read) -> io::Result<String> {
    let mut data = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(protocol_error("SMTP connection closed"));
        }
        data.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&data);
        let last = text.lines().last().unwrap_or_default();
        if data.ends_with(b"\r\n") && last.get(3..4) == Some(" ") {
            return Ok(last.to_owned());
        }
        if data.len() > MAX_REPLY {
            return Err(protocol_error("SMTP reply too long"));
        }
    }
}

fn starttls(stream: &mut (impl Read + Write), host: &str) -> io::Result<()> {
    if !reply(stream)?.starts_with("220") {
        return Err(protocol_error("Unexpected SMTP greeting"));
    }
    stream.write_all(b"EHLO garrison.invalid\r\n")?;
    if !reply(stream)?.starts_with("250") {
        return Err(protocol_error("EHLO rejected"));
    }
    stream.write_all(b"STARTTLS\r\n")?;
    if !reply(stream)?.starts_with("220") {
        return Err(protocol_error(&format!("STARTTLS not offered by {host}")));
    }
    Ok(())
}

/// A connection to the listener, with everything said over it done by
/// `until`.
fn connect(address: &str, port: u16, until: Instant) -> Result<Timed, Failure> {
    let targets = (address, port)
        .to_socket_addrs()
        .map_err(|_| Failure("name lookup failed"))?;
    let mut last = Failure("name lookup failed");
    for target in targets {
        let patience = until.saturating_duration_since(Instant::now()).min(TIMEOUT);
        if patience.is_zero() {
            return Err(Failure("timed out"));
        }
        match TcpStream::connect_timeout(&target, patience) {
            Ok(stream) => return Ok(Timed::new(stream, until, TIMEOUT)),
            Err(error) => last = failure(&error),
        }
    }
    Err(last)
}

/// One handshake: STARTTLS if asked, SNI `host`, chain and name validated
/// at `now`; all of it within `PROBE`.
pub fn probe(
    host: &str,
    port: u16,
    address: &str,
    use_starttls: bool,
    roots: &Arc<RootCertStore>,
    now: Timestamp,
) -> Result<Probed, Failure> {
    let name = ServerName::try_from(host.to_owned()).map_err(|_| Failure("invalid host name"))?;
    // The chain is judged at the run's time, as every check judges.
    let config = fetch::client_config(roots, Some(now)).map_err(|_| Failure("TLS error"))?;
    let mut connection =
        ClientConnection::new(Arc::new(config), name).map_err(|_| Failure("TLS error"))?;
    let mut stream = connect(address, port, Instant::now() + PROBE)?;
    let io = |error| failure(&error);
    if use_starttls {
        // A server that answers but refuses STARTTLS is not a network failure.
        starttls(&mut stream, host).map_err(|error| match error.kind() {
            io::ErrorKind::Other => Failure("STARTTLS refused"),
            _ => failure(&error),
        })?;
    }
    while connection.is_handshaking() {
        connection.complete_io(&mut stream).map_err(io)?;
    }
    let certificate = connection
        .peer_certificates()
        .and_then(<[_]>::first)
        .ok_or(Failure("no certificate"))?;
    let expiry = not_after(certificate.as_ref()).ok_or(Failure("unreadable certificate"))?;
    let protocol = match connection.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "unknown",
    };
    connection.send_close_notify();
    let _ = connection.complete_io(&mut stream);
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    let days = ((expiry.as_second() as f64 - time::unix(now)) / 86400.0).floor() as i64;
    Ok(Probed {
        expires_at: time::isoformat(expiry),
        days,
        protocol,
    })
}

/// The system's trust store, as OpenSSL-based tools on this host see it.
fn system_roots() -> Arc<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for error in &loaded.errors {
        log::warn!("Could not load a trusted certificate: {error}");
    }
    roots.add_parsable_certificates(loaded.certs);
    Arc::new(roots)
}

/// What the probes of one run found, and the state that gives.
struct Probes {
    state: State,
    rows: Vec<Vec<Value>>,
    findings: Vec<String>,
    lowest: Option<i64>,
}

/// A row for an endpoint without a certificate to show.
fn bare(label: &str, result: &str) -> Vec<Value> {
    vec![
        json!(label),
        json!(result),
        Value::Null,
        Value::Null,
        Value::Null,
    ]
}

/// Each endpoint probed while the run has time; the ones after that are
/// named, not probed, and keep the state from being in order.
fn probe_each(endpoints: &[Endpoint], roots: &Arc<RootCertStore>, context: &Context<'_>) -> Probes {
    let (mut rows, mut findings, mut unchecked) = (Vec::new(), Vec::new(), Vec::new());
    let (mut lowest, mut failures): (Option<i64>, usize) = (None, 0);
    for endpoint in endpoints {
        let label = format!("{}:{}", endpoint.host, endpoint.port);
        if context.deadline.expired() {
            rows.push(bare(&label, "not checked"));
            unchecked.push(label);
            continue;
        }
        match probe(
            &endpoint.host,
            endpoint.port,
            &endpoint.address,
            endpoint.starttls,
            roots,
            context.now,
        ) {
            Err(Failure(kind)) => {
                failures += 1;
                findings.push(format!("{label} — TLS check failed ({kind})."));
                rows.push(bare(&label, "failed"));
            }
            Ok(found) => {
                lowest = Some(lowest.map_or(found.days, |known| known.min(found.days)));
                if found.days < WARN_DAYS {
                    findings.push(format!(
                        "{label} — certificate expires in {} days.",
                        found.days
                    ));
                }
                rows.push(vec![
                    json!(label),
                    json!("valid"),
                    json!(found.expires_at),
                    json!(found.days),
                    json!(found.protocol),
                ]);
            }
        }
    }
    let state = match (failures, findings.is_empty(), unchecked.len()) {
        (0, true, 0) => State::Ok,
        (0, true, left) if left == endpoints.len() => State::Unknown,
        (0, true, _) => State::Partial,
        (0, false, _) => State::Warning,
        _ => State::Failed,
    };
    if !unchecked.is_empty() {
        findings.push(format!(
            "Not checked in this run, as its time was used up: {}.",
            unchecked.join(", ")
        ));
    }
    Probes {
        state,
        rows,
        findings,
        lowest,
    }
}

#[derive(Debug)]
pub struct Tls {
    modules: BTreeSet<ModuleId>,
    endpoints: Vec<Endpoint>,
    /// Without `endpoints`: of how many of Stalwart's domains the mail hosts
    /// are probed.
    max_domains: usize,
    /// `None` uses the system's trust store; tests pass their own.
    roots: Option<Arc<RootCertStore>>,
}

impl Tls {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["endpoints", "max_domains", "modules"])?;
        let modules = options.modules(&["dns_tls"])?;
        let mut endpoints = Vec::new();
        for item in options.tables("endpoints")? {
            let host = item
                .get("host")
                .and_then(toml::Value::as_str)
                .filter(|host| !host.is_empty());
            let port = item
                .get("port")
                .and_then(toml::Value::as_integer)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port >= 1);
            let address = match item.get("address") {
                None => Some("127.0.0.1"),
                Some(value) => value.as_str(),
            };
            let starttls = match item.get("starttls") {
                None => Some(false),
                Some(value) => value.as_bool(),
            };
            let extra = item
                .keys()
                .any(|key| !["host", "port", "address", "starttls"].contains(&key.as_str()));
            let (Some(host), Some(port), Some(address), Some(starttls), false) =
                (host, port, address, starttls, extra)
            else {
                return fail("providers[tls].endpoints need host, port, address, starttls");
            };
            endpoints.push(Endpoint {
                host: host.to_owned(),
                port,
                address: address.to_owned(),
                starttls,
            });
        }
        // Without endpoints of its own the check finds them in Stalwart.
        Ok(Tls {
            modules,
            endpoints,
            max_domains: max_domains(&options)?,
            roots: None,
        })
    }

    /// For tests: trust these roots instead of the system's.
    #[cfg(test)]
    #[must_use]
    pub fn with_roots(mut self, roots: RootCertStore) -> Self {
        self.roots = Some(Arc::new(roots));
        self
    }
}

impl Tls {
    /// What the check proves, for the card's footer.
    fn scope(&self) -> &'static str {
        if self.endpoints.is_empty() {
            "Every listener of Stalwart that speaks TLS, asked on this host under each mail \
             host's name: the certificate must be trusted and valid for that name. Public \
             reachability and automatic renewal are not tested here."
        } else {
            "Proves what the local listener presents; public reachability and \
             automatic renewal are not tested here."
        }
    }

    /// The check where Stalwart did not say what to probe.
    fn unknown(&self, context: &Context<'_>, reason: &str) -> Collected {
        Ok(Report::of(
            Observation::new(Required {
                id: "tls.endpoints",
                provider: self.name(),
                title: "TLS certificates",
                modules: self.modules.iter().copied(),
                evidence: Evidence::Probe,
                state: State::Unknown,
                checked_at: &context.checked_at(),
                source: "x:NetworkListener/get, x:Domain/get",
            })?
            .with_findings(vec![format!("The endpoints are not known: {reason}.")])
            .with_max_age(900),
        ))
    }
}

impl Provider for Tls {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn ids(&self) -> Vec<String> {
        vec!["tls.endpoints".to_owned()]
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let roots = self.roots.clone().unwrap_or_else(system_roots);
        let found;
        let (mut rest, mut cut) = (None, None);
        let endpoints = if self.endpoints.is_empty() {
            match listeners::endpoints(context, self.max_domains) {
                Ok(derived) => {
                    found = derived.endpoints;
                    (rest, cut) = (derived.rest, derived.cut);
                }
                Err(reason) => return self.unknown(context, &reason),
            }
            &found
        } else {
            &self.endpoints
        };
        let Probes {
            mut state,
            rows,
            mut findings,
            lowest,
        } = probe_each(endpoints, &roots, context);
        // The hosts of the domains left out are not probed; the state is that
        // of the endpoints that are. The endpoints after the first 24 are not
        // probed either, and keep the card from being in order.
        findings.extend(rest);
        if let Some(cut) = cut {
            findings.push(cut);
            if state == State::Ok {
                state = State::Partial;
            }
        }
        let column = |label: &str, format| Column {
            label: label.to_owned(),
            format,
        };
        let observation = Observation::new(Required {
            id: "tls.endpoints",
            provider: self.name(),
            title: "TLS certificates",
            modules: self.modules.iter().copied(),
            evidence: Evidence::Probe,
            state,
            checked_at: &context.checked_at(),
            source: "Local TLS handshake with SNI and chain validation",
        })?
        .with_scope(self.scope())
        .with_fields(vec![Field::new(
            "Lowest remaining validity",
            lowest,
            Format::Number,
        )])
        .with_table(Table {
            columns: vec![
                column("Endpoint", Format::Text),
                column("Result", Format::Text),
                column("Expires", Format::Datetime),
                column("Days left", Format::Number),
                column("Protocol", Format::Text),
            ],
            rows,
        })
        .with_findings(findings)
        .with_max_age(900);
        let mut report = Report::of(observation);
        if let Some(days) = lowest {
            #[allow(clippy::cast_precision_loss)]
            report.gauges.insert("tls_days".into(), days as f64);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod time_tests;
