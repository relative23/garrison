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
use std::time::Duration;

use garrison_core::modules::ModuleId;
use garrison_core::observations::{Column, Evidence, Field, Format, Observation, State, Table};
use garrison_core::time;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde_json::{Value, json};

use super::certificate::not_after;
use crate::context::{Collected, Context, Provider, Report};
use crate::options::{Checked, Options, fail};

const WARN_DAYS: i64 = 14;
const TIMEOUT: Duration = Duration::from_secs(5);
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
            rustls::Error::InvalidCertificate(_) => "certificate not trusted",
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

fn starttls(stream: &mut TcpStream, host: &str) -> io::Result<()> {
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

fn connect(address: &str, port: u16) -> Result<TcpStream, Failure> {
    let targets = (address, port)
        .to_socket_addrs()
        .map_err(|_| Failure("name lookup failed"))?;
    let mut last = Failure("name lookup failed");
    for target in targets {
        match TcpStream::connect_timeout(&target, TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = failure(&error),
        }
    }
    Err(last)
}

/// One handshake: STARTTLS if asked, SNI `host`, chain and name validated.
pub fn probe(
    host: &str,
    port: u16,
    address: &str,
    use_starttls: bool,
    roots: &Arc<RootCertStore>,
) -> Result<Probed, Failure> {
    let name = ServerName::try_from(host.to_owned()).map_err(|_| Failure("invalid host name"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| Failure("TLS error"))?
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let mut connection =
        ClientConnection::new(Arc::new(config), name).map_err(|_| Failure("TLS error"))?;
    let mut stream = connect(address, port)?;
    let io = |error| failure(&error);
    stream.set_read_timeout(Some(TIMEOUT)).map_err(io)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(io)?;
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
    let days = ((expiry.as_second() as f64 - time::unix(time::now())) / 86400.0).floor() as i64;
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

#[derive(Debug)]
pub struct Tls {
    modules: BTreeSet<ModuleId>,
    endpoints: Vec<Endpoint>,
    /// `None` uses the system's trust store; tests pass their own.
    roots: Option<Arc<RootCertStore>>,
}

impl Tls {
    pub fn new(raw: &toml::Table) -> Checked<Self> {
        let options = Options::new(raw, &["endpoints", "modules"])?;
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
            Observation::new(
                "tls.endpoints",
                self.name(),
                "TLS certificates",
                self.modules.iter().copied(),
                Evidence::Probe,
                State::Unknown,
                context.checked_at(),
                "x:NetworkListener/get, x:Domain/get",
            )?
            .with_findings(vec![format!("The endpoints are not known: {reason}.")])
            .with_max_age(900),
        ))
    }
}

impl Provider for Tls {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn collect(&self, context: &Context<'_>) -> Collected {
        let roots = self.roots.clone().unwrap_or_else(system_roots);
        let (mut rows, mut findings) = (Vec::new(), Vec::new());
        let (mut lowest, mut failures): (Option<i64>, usize) = (None, 0);
        let found;
        let endpoints = if self.endpoints.is_empty() {
            match listeners::endpoints(context) {
                Ok(endpoints) => found = endpoints,
                Err(reason) => return self.unknown(context, &reason),
            }
            &found
        } else {
            &self.endpoints
        };
        for endpoint in endpoints {
            let label = format!("{}:{}", endpoint.host, endpoint.port);
            match probe(
                &endpoint.host,
                endpoint.port,
                &endpoint.address,
                endpoint.starttls,
                &roots,
            ) {
                Err(Failure(kind)) => {
                    failures += 1;
                    findings.push(format!("{label} — TLS check failed ({kind})."));
                    rows.push(vec![
                        json!(label),
                        json!("failed"),
                        Value::Null,
                        Value::Null,
                        Value::Null,
                    ]);
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
        let state = match (failures, findings.is_empty()) {
            (0, true) => State::Ok,
            (0, false) => State::Warning,
            _ => State::Failed,
        };
        let column = |label: &str, format| Column {
            label: label.to_owned(),
            format,
        };
        let observation = Observation::new(
            "tls.endpoints",
            self.name(),
            "TLS certificates",
            self.modules.iter().copied(),
            Evidence::Probe,
            state,
            context.checked_at(),
            "Local TLS handshake with SNI and chain validation",
        )?
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
