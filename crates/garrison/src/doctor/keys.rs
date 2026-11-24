//! The API keys setup writes for the broker and the collector, tried as
//! their services use them: Stalwart must take each from this host. One it
//! no longer takes, as after the key was deleted in the Stalwart WebUI or
//! Stalwart's data was put back from before the last rotation, leaves
//! nobody able to sign in, or every card that reads Stalwart unknown.

use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_stalwart::http::Request;

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
            "The key may be used only from this host: run Stalwart in the host network, or lift \
             Stalwart's block of the address (operations.md, \"Sign-in fails\").",
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

/// Stalwart's answer to the JMAP session asked with the key of `source`, or
/// why there is none.
fn session(
    config: &Config,
    credentials: &Credentials,
    source: &SecretSource,
) -> Result<u16, String> {
    let key = credentials
        .read_secret(source)
        .map_err(|error| format!("it could not be read ({error})"))?;
    let url = format!("{}/jmap/session", config.deployment.stalwart_url);
    Request::get(&url)
        .header("Authorization", &format!("Bearer {key}"))
        .timeout(WITHIN)
        .status()
        .map_err(|error| format!("Stalwart did not answer at {url} ({error})"))
}

pub(super) fn checks(config: &Config, credentials: &Credentials) -> Vec<Finding> {
    let broker = &config.broker.native_key;
    let collector = &config.collector.native_key;
    [
        (broker, "broker", "nobody can sign in"),
        (
            collector,
            "collector",
            "every card that reads Stalwart stays unknown",
        ),
    ]
    .into_iter()
    .map(|(source, service, refused)| {
        let file = credentials.path(source);
        let name = file.file_name().map_or_else(
            || file.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        tried(
            &name,
            service,
            refused,
            session(config, credentials, source),
        )
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use garrison_testing::http::{answer, serve};

    use super::super::Level;
    use super::*;

    /// Each key is tried as its service uses it, and each answer is named:
    /// one Stalwart takes, one it does not know with the setup that makes a
    /// new one, one it refuses from this host's address, and a Stalwart
    /// that does not answer, or answers otherwise, leaves it unknown.
    #[test]
    fn each_key_is_tried_as_its_service_uses_it() {
        let stalwart = serve(vec![answer(200, "{}"), answer(401, "")]);
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
            asked[1].contains("Bearer collector-key-0123456789"),
            "{}",
            asked[1]
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
        for answer in [Ok(500), Err("Stalwart did not answer".to_owned())] {
            let unknown = tried("broker-native-key", "broker", "nobody can sign in", answer);
            assert_eq!(unknown.level, Level::Unknown, "{}", unknown.line());
        }
    }
}
