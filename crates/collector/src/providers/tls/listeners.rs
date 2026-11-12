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

use std::collections::BTreeMap;
use std::time::Duration;

use garrison_stalwart::jmap::JmapClient;
use serde::Deserialize;
use serde_json::Value;

use super::Endpoint;
use crate::context::Context;
use crate::providers::dns::mail_hosts;

const MOST: usize = 24;

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

/// The port of `[::]:465` or `0.0.0.0:465`.
fn port(bind: &str) -> Option<u16> {
    bind.rsplit_once(':')?
        .1
        .parse()
        .ok()
        .filter(|port| *port > 0)
}

/// Each TLS port of `listeners` once for each of `hosts`, lowest port first.
pub(super) fn derived(listeners: &[Listener], hosts: &[String]) -> Vec<Endpoint> {
    let mut ports: BTreeMap<u16, bool> = BTreeMap::new();
    for listener in listeners.iter().filter(|listener| listener.use_tls) {
        let starttls = !listener.implicit_tls;
        if starttls && listener.protocol != "smtp" {
            continue;
        }
        for port in listener.bind.keys().filter_map(|bind| port(bind)) {
            ports.entry(port).or_insert(starttls);
        }
    }
    let mut endpoints = Vec::new();
    for host in hosts {
        for (port, starttls) in &ports {
            endpoints.push(Endpoint {
                host: host.clone(),
                port: *port,
                address: "127.0.0.1".to_owned(),
                starttls: *starttls,
            });
        }
    }
    endpoints.truncate(MOST);
    endpoints
}

/// What to probe, asked of Stalwart; why not, where it does not say.
pub(super) fn endpoints(context: &Context<'_>) -> Result<Vec<Endpoint>, String> {
    let key = context
        .native_key
        .as_deref()
        .ok_or("the collector's API key could not be read")?;
    let client =
        JmapClient::new(&context.deployment.stalwart_url, key).with_timeout(Duration::from_secs(8));
    let listeners = client
        .get::<Listener>(
            "NetworkListener",
            None,
            &["protocol", "bind", "useTls", "implicitTls"],
        )
        .map_err(|_| {
            "Stalwart did not give its listeners to the collector's API key; run `garrison \
             stalwart setup` again to let it read them, or name `endpoints`"
        })?;
    let hosts = mail_hosts(context)?;
    let endpoints = derived(&listeners, &hosts);
    if endpoints.is_empty() {
        return Err("Stalwart names no mail host with a listener that speaks TLS".to_owned());
    }
    Ok(endpoints)
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

    #[test]
    fn ports_are_read_from_either_kind_of_address() {
        assert_eq!(port("[::]:465"), Some(465));
        assert_eq!(port("0.0.0.0:25"), Some(25));
        assert_eq!(port("[::1]:0"), None);
        assert_eq!(port("no port"), None);
    }
}
