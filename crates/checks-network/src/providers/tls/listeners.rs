//! The endpoints to probe, as Stalwart itself names them: every listener
//! that speaks TLS, under the name of every mail host.
//!
//! An operator who lists `endpoints` decides what is checked. Without that
//! list a listener added later, such as port 465 beside 25, would go
//! unchecked; Stalwart knows them all. A listener that begins in plain text
//! is asked with STARTTLS where it speaks SMTP. The others that begin in
//! plain text (IMAP on 143, POP3 on 110, Sieve management) are left out: their
//! way into TLS is another one, and they present the certificate of the
//! ports that are asked.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;

use garrison_stalwart::jmap::JmapClient;
use serde::Deserialize;
use serde_json::Value;

use super::Endpoint;
use crate::context::{Context, NO_KEY};
use crate::providers::dns::mail_hosts;
use crate::providers::domains::not_given;

/// So many endpoints are probed at the most.
const MOST: usize = 24;
/// What else mends it where the collector has no key, where Stalwart
/// refused the key its listeners or its domains, or answered in a form this
/// release does not read: named endpoints need none of them.
const BESIDES: &str = ", or name `endpoints`";

/// What to probe, and what to say of what is not.
pub(super) struct Found {
    pub(super) endpoints: Vec<Endpoint>,
    /// What to say of Stalwart's domains after the first `max_domains`.
    pub(super) rest: Option<String>,
    /// What to say of the endpoints after the first [`MOST`], which are not
    /// probed and keep the card from being in order.
    pub(super) cut: Option<String>,
}

/// A listener as far as it is read.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Listener {
    #[serde(default)]
    protocol: String,
    /// The addresses it listens on, such as `[::]:465`, as the keys.
    #[serde(default)]
    bind: BTreeMap<String, Value>,
    #[serde(default)]
    use_tls: bool,
    #[serde(default)]
    implicit_tls: bool,
}

/// Where a listener that listens on every address is reached.
const LOOPBACK: &str = "127.0.0.1";

/// The port of `[::]:465` or `0.0.0.0:465`.
fn port(bind: &str) -> Option<u16> {
    bind.rsplit_once(':')?
        .1
        .parse()
        .ok()
        .filter(|port| *port > 0)
}

/// Where a probe reaches a listener bound to `bind`: at its port, on the
/// address it is bound to, as `192.0.2.10:465`, or on 127.0.0.1 where it
/// listens on every address, as `[::]:465`, which the last value says.
fn reached(bind: &str) -> Option<(String, u16, bool)> {
    let port = port(bind)?;
    Some(match bind.parse::<SocketAddr>() {
        Ok(bound) if !bound.ip().is_unspecified() => (bound.ip().to_string(), port, false),
        _ => (LOOPBACK.to_owned(), port, true),
    })
}

/// Each TLS port of `listeners` once for each of `hosts`, lowest port first,
/// on every address it is reached at: 127.0.0.1 alone where any listener
/// binds the port on every address, and otherwise each single address it is
/// bound to, since the certificate one of them presents says nothing of the
/// other's.
pub(super) fn derived(listeners: &[Listener], hosts: &[String]) -> Vec<Endpoint> {
    // By port: whether it begins in plain text, whether a listener binds it
    // on every address, and the addresses to probe.
    let mut ports: BTreeMap<u16, (bool, bool, BTreeSet<String>)> = BTreeMap::new();
    for listener in listeners.iter().filter(|listener| listener.use_tls) {
        let starttls = !listener.implicit_tls;
        if starttls && listener.protocol != "smtp" {
            continue;
        }
        for (address, port, every) in listener.bind.keys().filter_map(|bind| reached(bind)) {
            let (_, everywhere, addresses) = ports
                .entry(port)
                .or_insert_with(|| (starttls, false, BTreeSet::new()));
            if every && !*everywhere {
                *everywhere = true;
                addresses.clear();
            }
            if every || !*everywhere {
                addresses.insert(address);
            }
        }
    }
    let mut endpoints = Vec::new();
    for host in hosts {
        for (port, (starttls, _, addresses)) in &ports {
            for address in addresses {
                endpoints.push(Endpoint {
                    host: host.clone(),
                    port: *port,
                    address: address.clone(),
                    starttls: *starttls,
                });
            }
        }
    }
    endpoints
}

impl Endpoint {
    /// How the card names this endpoint among `all` it probes: its name and
    /// port, and where those are probed on more than one address, on which.
    pub(super) fn label(&self, all: &[Endpoint]) -> String {
        let same = |other: &&Endpoint| other.host == self.host && other.port == self.port;
        if all.iter().filter(same).count() > 1 {
            format!("{}:{} on {}", self.host, self.port, self.address)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// What to probe, asked of Stalwart, under the mail hosts of its first
/// `most` domains, up to [`MOST`] endpoints, and what to say of the rest;
/// why not, where Stalwart does not say.
pub(super) fn endpoints(context: &Context<'_>, most: usize) -> Result<Found, String> {
    let key = context
        .native_key
        .as_deref()
        .ok_or_else(|| format!("{NO_KEY}{BESIDES}"))?;
    let client =
        JmapClient::new(&context.deployment.stalwart_url, key).with_timeout(Duration::from_secs(8));
    let listeners = client
        .get::<Listener>(
            "NetworkListener",
            None,
            &["protocol", "bind", "useTls", "implicitTls"],
        )
        .map_err(|error| not_given(&error, "listeners", BESIDES))?;
    let (hosts, rest) = mail_hosts(context, most, BESIDES)?;
    let mut endpoints = derived(&listeners, &hosts);
    if endpoints.is_empty() {
        return Err("Stalwart names no mail host with a listener that speaks TLS".to_owned());
    }
    let cut = (endpoints.len() > MOST).then(|| {
        format!(
            "Stalwart's listeners and mail hosts make {} endpoints; only the first {MOST} are \
             checked.",
            endpoints.len()
        )
    });
    endpoints.truncate(MOST);
    Ok(Found {
        endpoints,
        rest,
        cut,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn listeners() -> Vec<Listener> {
        serde_json::from_value(json!([
            {"name": "smtp", "protocol": "smtp", "bind": {"[::]:25": true}, "useTls": true, "implicitTls": false},
            {"name": "submissions", "protocol": "smtp", "bind": {"[::]:465": true, "0.0.0.0:465": true}, "useTls": true, "implicitTls": true},
            {"name": "imaps", "protocol": "imap", "bind": {"[::]:993": true}, "useTls": true, "implicitTls": true},
            {"name": "imap", "protocol": "imap", "bind": {"[::]:143": true}, "useTls": true, "implicitTls": false},
            {"name": "http", "protocol": "http", "bind": {"[::]:8080": true}, "useTls": false, "implicitTls": false},
            {"name": "https", "protocol": "http", "bind": {"[::]:443": true}, "useTls": true, "implicitTls": true},
        ]))
        .unwrap()
    }

    #[test]
    fn every_tls_port_is_probed_under_every_mail_host() {
        let hosts = vec![
            "mail.example.test".to_owned(),
            "mx2.example.test".to_owned(),
        ];
        let endpoints = derived(&listeners(), &hosts);
        let listed: Vec<(&str, u16, bool)> = endpoints
            .iter()
            .map(|endpoint| (endpoint.host.as_str(), endpoint.port, endpoint.starttls))
            .collect();
        // Plain HTTP has no certificate; IMAP on 143 begins in plain text in its own way.
        assert_eq!(
            listed,
            [
                ("mail.example.test", 25, true),
                ("mail.example.test", 443, false),
                ("mail.example.test", 465, false),
                ("mail.example.test", 993, false),
                ("mx2.example.test", 25, true),
                ("mx2.example.test", 443, false),
                ("mx2.example.test", 465, false),
                ("mx2.example.test", 993, false),
            ]
        );
        assert!(
            endpoints
                .iter()
                .all(|endpoint| endpoint.address == "127.0.0.1")
        );
        assert_eq!(derived(&listeners(), &[]), Vec::new());
        assert_eq!(derived(&[], &hosts), Vec::new());
    }

    /// A listener bound to one address is probed on that address; one bound
    /// to every address on 127.0.0.1, also where another binds the same
    /// port to one address.
    #[test]
    fn a_listener_is_probed_on_the_address_it_is_bound_to() {
        let bound: Vec<Listener> = serde_json::from_value(json!([
            {"protocol": "smtp", "bind": {"192.0.2.10:465": true}, "useTls": true, "implicitTls": true},
            {"protocol": "imap", "bind": {"[2001:db8::5]:993": true}, "useTls": true, "implicitTls": true},
            {"protocol": "smtp", "bind": {"192.0.2.10:25": true, "[::]:25": true}, "useTls": true, "implicitTls": false},
        ]))
        .unwrap();
        let reached: Vec<(u16, String)> = derived(&bound, &["mail.example.test".to_owned()])
            .into_iter()
            .map(|endpoint| (endpoint.port, endpoint.address))
            .collect();
        assert_eq!(
            reached,
            [
                (25, "127.0.0.1".to_owned()),
                (465, "192.0.2.10".to_owned()),
                (993, "2001:db8::5".to_owned()),
            ]
        );
    }

    /// A port bound to two single addresses, by one listener or by two, is
    /// probed on each: the certificate one of them presents says nothing of
    /// the other's. Where a listener binds the port on every address, that
    /// one probe on 127.0.0.1 reaches it, whatever else binds it.
    #[test]
    fn a_port_bound_to_two_single_addresses_is_probed_on_each() {
        let reached = |listeners: Value| -> Vec<(u16, String)> {
            let listeners: Vec<Listener> = serde_json::from_value(listeners).unwrap();
            derived(&listeners, &["mail.example.test".to_owned()])
                .into_iter()
                .map(|endpoint| (endpoint.port, endpoint.address))
                .collect()
        };
        let both = [
            (465, "192.0.2.10".to_owned()),
            (465, "198.51.100.7".to_owned()),
        ];
        let one = json!([
            {"protocol": "smtp", "bind": {"198.51.100.7:465": true, "192.0.2.10:465": true}, "useTls": true, "implicitTls": true},
        ]);
        assert_eq!(reached(one), both);
        let two = json!([
            {"protocol": "smtp", "bind": {"198.51.100.7:465": true}, "useTls": true, "implicitTls": true},
            {"protocol": "smtp", "bind": {"192.0.2.10:465": true}, "useTls": true, "implicitTls": true},
        ]);
        assert_eq!(reached(two), both);
        // A bind to 127.0.0.1 alone is one address like another.
        let loopback = json!([
            {"protocol": "smtp", "bind": {"127.0.0.1:465": true, "192.0.2.10:465": true}, "useTls": true, "implicitTls": true},
        ]);
        assert_eq!(
            reached(loopback),
            [
                (465, "127.0.0.1".to_owned()),
                (465, "192.0.2.10".to_owned())
            ]
        );
        let every = json!([
            {"protocol": "smtp", "bind": {"192.0.2.10:465": true}, "useTls": true, "implicitTls": true},
            {"protocol": "smtp", "bind": {"0.0.0.0:465": true}, "useTls": true, "implicitTls": true},
            {"protocol": "smtp", "bind": {"198.51.100.7:465": true}, "useTls": true, "implicitTls": true},
        ]);
        assert_eq!(reached(every), [(465, "127.0.0.1".to_owned())]);
    }

    #[test]
    fn ports_are_read_from_either_kind_of_address() {
        assert_eq!(port("[::]:465"), Some(465));
        assert_eq!(port("0.0.0.0:25"), Some(25));
        assert_eq!(port("[::1]:0"), None);
        assert_eq!(port("no port"), None);
    }
}
