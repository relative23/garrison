//! The API keys setup writes for the broker and the collector, tried as
//! their services use them: Stalwart must take each from this host, for
//! what its service reads with it. One it no longer takes, as
//! after the key was deleted or narrowed in the Stalwart WebUI or
//! Stalwart's data was put back from before the last rotation, leaves
//! nobody able to sign in, or every card that reads Stalwart unknown.

use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_stalwart::Error;
use garrison_stalwart::http::{MAX_RESPONSE, Request};
use garrison_stalwart::jmap::JmapClient;
use serde_json::{Value, json};

use super::Finding;
use super::states::keys::{self as states, Service};

/// How long Stalwart has to answer a key's try.
const WITHIN: Duration = Duration::from_secs(10);

/// What Stalwart's answer to a try of the key `file`, which `service` uses,
/// says.
pub(super) fn tried(file: &str, service: Service, answer: Result<u16, String>) -> Finding {
    match answer {
        Ok(200) => Finding::ok(states::taken(service, file)),
        Ok(401) => Finding::fail(states::not_known(service, file)),
        Ok(403) => Finding::fail(states::other_address(service, file)),
        Ok(status) => Finding::unknown(states::untried(service, file, &states::answered(status))),
        Err(why) => Finding::unknown(states::untried(service, file, &why)),
    }
}

/// What a service reads with its key.
type Reads = Vec<(&'static str, Value)>;

/// What the broker reads with its key when it checks a user's rights
/// (`garrison_stalwart::permissions::account_rights`): the account, the
/// sign-in settings and the roles, each of a permission of its own.
fn broker_reads() -> Reads {
    vec![
        ("x:Account/get", json!({"ids": null, "properties": ["id"]})),
        (
            "x:Authentication/get",
            json!({"ids": ["singleton"], "properties": ["id"]}),
        ),
        ("x:Role/get", json!({"ids": null, "properties": ["id"]})),
    ]
}

/// The queries by which the collector's checks find Stalwart's domains and
/// accounts, which a key an earlier release's setup made may not make.
fn collector_reads() -> Reads {
    vec![
        ("x:Domain/query", json!({"limit": 1})),
        ("x:Account/query", json!({"limit": 1})),
    ]
}

/// What Stalwart says of the `service`'s `reads` with `key`, where it opened
/// the key's session: a refusal fails.
fn read_with(
    config: &Config,
    (key, file, service): (&str, &str, Service),
    reads: &Reads,
) -> Option<Finding> {
    let answered = JmapClient::new(&config.deployment.stalwart_url, key)
        .with_timeout(WITHIN)
        .call_many(reads, MAX_RESPONSE);
    let refused = match answered {
        Ok(answers) => answers.into_iter().find_map(|answer| match answer {
            Err(Error::Denied(why)) => Some(Ok(why)),
            Err(error) => Some(Err(error.to_string())),
            Ok(_) => None,
        }),
        Err(error) => Some(Err(error.to_string())),
    }?;
    Some(match refused {
        Ok(why) => Finding::fail(states::narrowed(service, file, &why)),
        Err(why) => Finding::unknown(states::reads_unknown(service, file, &why)),
    })
}

/// Stalwart's answer to the JMAP session asked with `key`, or why there is
/// none.
fn session(config: &Config, key: &str) -> Result<u16, String> {
    let url = format!("{}/jmap/session", config.deployment.stalwart_url);
    Request::get(&url)
        .header("Authorization", &format!("Bearer {key}"))
        .timeout(WITHIN)
        .status()
        .map_err(|error| states::silent(&url, error))
}

/// The key of `source` tried: its session, and what its service reads.
fn key_of(
    config: &Config,
    credentials: &Credentials,
    (source, service, reads): (&SecretSource, Service, Reads),
) -> Finding {
    let file = credentials.path(source);
    let name = file.file_name().map_or_else(
        || file.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let key = match credentials.read_secret(source) {
        Ok(key) => key,
        Err(error) => return tried(&name, service, Err(states::unread(error))),
    };
    let answer = session(config, &key);
    if answer == Ok(200)
        && let Some(finding) = read_with(config, (&key, &name, service), &reads)
    {
        return finding;
    }
    tried(&name, service, answer)
}

pub(super) fn checks(config: &Config, credentials: &Credentials) -> Vec<Finding> {
    [
        (&config.broker.native_key, Service::Broker, broker_reads()),
        (
            &config.collector.native_key,
            Service::Collector,
            collector_reads(),
        ),
    ]
    .into_iter()
    .map(|key| key_of(config, credentials, key))
    .collect()
}

#[cfg(test)]
mod tests {
    use garrison_testing::http::{answer, serve};

    use super::super::Level;
    use super::*;

    /// Each key is tried as its service uses it, the broker's with what the
    /// broker reads, and each answer is named: one Stalwart takes, one it
    /// does not know with the setup that makes a new one, one it refuses
    /// from this host's address, and a Stalwart that does not answer, or
    /// answers otherwise, leaves it unknown.
    #[test]
    fn each_key_is_tried_as_its_service_uses_it() {
        let read = serde_json::json!({"methodResponses": [
            ["x:Account/get", {"list": []}, "0"],
            ["x:Authentication/get", {"list": []}, "1"],
            ["x:Role/get", {"list": []}, "2"]]});
        let stalwart = serve(vec![
            answer(200, "{}"),
            garrison_testing::http::json(&read),
            answer(401, ""),
        ]);
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), &stalwart.url);
        let credentials = garrison_testing::credentials(&config);
        garrison_testing::write_private(
            &credentials.path(&config.collector.native_key),
            b"collector-key-0123456789",
        );
        let found = checks(&config, &credentials);
        let asked = stalwart.requests();
        assert!(
            asked[0].starts_with("GET /jmap/session")
                && asked[0].contains(&format!("Bearer {}", garrison_testing::NATIVE_KEY)),
            "{}",
            asked[0]
        );
        assert!(
            asked[1].starts_with("POST /jmap/")
                && ["x:Account/get", "x:Authentication/get", "x:Role/get"]
                    .iter()
                    .all(|method| asked[1].contains(method)),
            "{}",
            asked[1]
        );
        assert!(
            asked[2].contains("Bearer collector-key-0123456789"),
            "{}",
            asked[2]
        );
        assert_eq!(
            found,
            [
                Finding::ok(states::taken(Service::Broker, "broker-native-key")),
                Finding::fail(states::not_known(
                    Service::Collector,
                    "collector-native-key"
                )),
            ]
        );
        // An address Stalwart blocked gets no answer at all (measured on
        // 1.1.0), so a 403 is the key's address, which its state names.
        assert_eq!(
            tried("broker-native-key", Service::Broker, Ok(403)),
            Finding::fail(states::other_address(Service::Broker, "broker-native-key"))
        );
        for (answer, why) in [
            (Ok(500), states::answered(500)),
            (
                Err("Stalwart did not answer".to_owned()),
                "Stalwart did not answer".to_owned(),
            ),
        ] {
            assert_eq!(
                tried("broker-native-key", Service::Broker, answer),
                Finding::unknown(states::untried(Service::Broker, "broker-native-key", &why))
            );
        }
    }

    /// The level and the name of a finding.
    fn named(finding: &Finding) -> (Level, &str) {
        (finding.level, finding.state.name)
    }

    /// A broker's key that opens its session but lacks a permission the
    /// broker reads with (measured on Stalwart 1.1.0: narrowed to
    /// `authenticate`, `forbidden` for x:Account/get) leaves nobody's
    /// rights checked: it fails, with the setup that gives the key its
    /// permissions again.
    #[test]
    fn a_broker_key_refused_what_the_broker_reads_fails() {
        let forbidden = serde_json::json!({"methodResponses": [
            ["error", {"type": "forbidden"}, "0"],
            ["error", {"type": "forbidden"}, "1"],
            ["error", {"type": "forbidden"}, "2"]]});
        let stalwart = serve(vec![
            answer(200, "{}"),
            garrison_testing::http::json(&forbidden),
            answer(200, "{}"),
        ]);
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), &stalwart.url);
        let credentials = garrison_testing::credentials(&config);
        garrison_testing::write_private(
            &credentials.path(&config.collector.native_key),
            b"collector-key-0123456789",
        );
        let found = checks(&config, &credentials);
        assert_eq!(
            named(&found[0]),
            (Level::Fail, "doctor-key-narrowed"),
            "{}",
            found[0].line()
        );
    }

    /// A collector's key that opens its session but may not query the
    /// domains and accounts the checks read, as a key an earlier release's
    /// setup made (measured on Stalwart 1.1.0 with 0.1.2's ten permissions:
    /// `forbidden` for each query), leaves their cards unknown: it fails,
    /// with the setup that gives the key its permissions again.
    #[test]
    fn a_collector_key_refused_the_queries_of_the_checks_fails() {
        let read = serde_json::json!({"methodResponses": [
            ["x:Account/get", {"list": []}, "0"],
            ["x:Authentication/get", {"list": []}, "1"],
            ["x:Role/get", {"list": []}, "2"]]});
        let forbidden = serde_json::json!({"methodResponses": [
            ["error", {"type": "forbidden"}, "0"],
            ["error", {"type": "forbidden"}, "1"]]});
        let stalwart = serve(vec![
            answer(200, "{}"),
            garrison_testing::http::json(&read),
            answer(200, "{}"),
            garrison_testing::http::json(&forbidden),
        ]);
        let directory = tempfile::tempdir().unwrap();
        let config = garrison_testing::config(directory.path(), &stalwart.url);
        let credentials = garrison_testing::credentials(&config);
        garrison_testing::write_private(
            &credentials.path(&config.collector.native_key),
            b"collector-key-0123456789",
        );
        let found = checks(&config, &credentials);
        assert_eq!(
            named(&found[1]),
            (Level::Fail, "doctor-key-narrowed"),
            "{}",
            found[1].line()
        );
        let asked = stalwart.requests();
        assert!(
            asked[3].contains("Bearer collector-key-0123456789")
                && asked[3].contains(
                    r#"["x:Domain/query",{"limit":1},"0"],["x:Account/query",{"limit":1},"1"]"#
                ),
            "{}",
            asked[3]
        );
    }
}
