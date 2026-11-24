//! The API keys setup writes for the broker and the collector, tried as
//! their services use them: Stalwart must take each from this host, and the
//! broker's for what the broker reads with it. One it no longer takes, as
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

/// How long Stalwart has to answer a key's try.
const WITHIN: Duration = Duration::from_secs(10);

/// What Stalwart's answer to a try of the key `file`, which `service` uses,
/// says, with what follows where Stalwart refuses it.
pub(super) fn tried(
    file: &str,
    service: &str,
    refused: &str,
    answer: Result<u16, String>,
) -> Finding {
    match answer {
        Ok(200) => Finding::ok(format!(
            "Stalwart takes the {service}'s API key ({file}) from this host"
        )),
        Ok(401) => Finding::fail(
            format!("Stalwart does not know the {service}'s API key in {file}, so {refused}"),
            "Run `garrison stalwart setup`, which makes a new one.",
        ),
        Ok(403) => Finding::fail(
            format!(
                "Stalwart refuses the {service}'s API key in {file} from this host's address \
                 (HTTP 403), so {refused}"
            ),
            "The key may be used only from this host: run Stalwart in the host network.",
        ),
        Ok(status) => Finding::unknown(format!(
            "whether Stalwart takes the {service}'s API key in {file}: it answered HTTP {status} \
             for the key's JMAP session"
        )),
        Err(why) => Finding::unknown(format!(
            "whether Stalwart takes the {service}'s API key in {file}: {why}"
        )),
    }
}

/// What the broker reads with its key when it checks a user's rights
/// (`garrison_stalwart::permissions::account_rights`): the account, the
/// sign-in settings and the roles, each of a permission of its own.
fn broker_reads() -> [(&'static str, Value); 3] {
    [
        ("x:Account/get", json!({"ids": null, "properties": ["id"]})),
        (
            "x:Authentication/get",
            json!({"ids": ["singleton"], "properties": ["id"]}),
        ),
        ("x:Role/get", json!({"ids": null, "properties": ["id"]})),
    ]
}

/// What Stalwart says of the broker's reads with `key`, where it opened the
/// key's session: a refusal fails, as nobody's rights can then be checked.
fn read_with(config: &Config, key: &str, file: &str) -> Option<Finding> {
    let answered = JmapClient::new(&config.deployment.stalwart_url, key)
        .with_timeout(WITHIN)
        .call_many(&broker_reads(), MAX_RESPONSE);
    let refused = match answered {
        Ok(answers) => answers.into_iter().find_map(|answer| match answer {
            Err(Error::Denied(why)) => Some(Ok(why)),
            Err(error) => Some(Err(error.to_string())),
            Ok(_) => None,
        }),
        Err(error) => Some(Err(error.to_string())),
    }?;
    Some(match refused {
        Ok(why) => Finding::fail(
            format!(
                "Stalwart takes the broker's API key ({file}) but refuses what the broker reads \
                 with it ({why}), so nobody can sign in"
            ),
            "Run `garrison stalwart setup`, which gives the key the permissions it needs.",
        ),
        Err(why) => Finding::unknown(format!(
            "whether Stalwart lets the broker's API key ({file}) read what the broker reads: \
             {why}"
        )),
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
        .map_err(|error| format!("Stalwart did not answer at {url} ({error})"))
}

/// The key of `source` tried: its session, and for the broker its reads.
fn key_of(
    config: &Config,
    credentials: &Credentials,
    (source, service, refused): (&SecretSource, &str, &str),
) -> Finding {
    let file = credentials.path(source);
    let name = file.file_name().map_or_else(
        || file.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let key = match credentials.read_secret(source) {
        Ok(key) => key,
        Err(error) => {
            return tried(
                &name,
                service,
                refused,
                Err(format!("it could not be read ({error})")),
            );
        }
    };
    let answer = session(config, &key);
    if answer == Ok(200)
        && service == "broker"
        && let Some(finding) = read_with(config, &key, &name)
    {
        return finding;
    }
    tried(&name, service, refused, answer)
}

pub(super) fn checks(config: &Config, credentials: &Credentials) -> Vec<Finding> {
    [
        (&config.broker.native_key, "broker", "nobody can sign in"),
        (
            &config.collector.native_key,
            "collector",
            "every card that reads Stalwart stays unknown",
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
            (found[0].level, found[0].what.as_str()),
            (
                Level::Ok,
                "Stalwart takes the broker's API key (broker-native-key) from this host"
            )
        );
        assert_eq!(found[1].level, Level::Fail, "{}", found[1].line());
        assert_eq!(
            found[1].fix.as_deref(),
            Some("Run `garrison stalwart setup`, which makes a new one.")
        );
        let refused = tried("broker-native-key", "broker", "nobody can sign in", Ok(403));
        assert_eq!(refused.level, Level::Fail);
        assert!(refused.what.contains("(HTTP 403)"), "{}", refused.what);
        // An address Stalwart blocked gets no answer at all (measured on
        // 1.1.0), so a 403 names no block.
        assert!(!refused.line().contains("block"), "{}", refused.line());
        for answer in [Ok(500), Err("Stalwart did not answer".to_owned())] {
            let unknown = tried("broker-native-key", "broker", "nobody can sign in", answer);
            assert_eq!(unknown.level, Level::Unknown, "{}", unknown.line());
        }
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
        assert_eq!(found[0].level, Level::Fail, "{}", found[0].line());
        assert!(
            found[0]
                .fix
                .as_deref()
                .unwrap_or_default()
                .contains("garrison stalwart setup"),
            "{}",
            found[0].line()
        );
    }
}
