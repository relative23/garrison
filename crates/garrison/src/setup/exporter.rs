//! Stalwart's Prometheus exporter and the scrape credential setup writes
//! for the collector, where the exporter is Garrison's or off.

use std::path::Path;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_collector::run::ScrapeCredential;
use garrison_core::config::Config;
use garrison_core::files::{Privacy, atomic_write, read_private};
use garrison_stalwart::http::Request;
use garrison_stalwart::jmap::{Get, Got};

use super::objects::{Exporter, Metrics, Secret, Set, Stored};
use super::{Admin, random, states};
use crate::state::State;

/// The credential's file, as the collector reads it.
pub(super) const FILE: &str = "metrics-credential";

/// Stalwart's exporter as setup finds it: switched on, whether with
/// Garrison's user, and its settings as Stalwart shows them.
pub(super) struct Found {
    enabled: bool,
    ours: bool,
    stored: Stored,
}

/// The credential Stalwart is to take, as its file holds it, and whether
/// this run made it.
pub(super) struct Scrape {
    secret: String,
    pub(super) new: bool,
}

/// The credential the file at `path` holds, as the collector reads it, in
/// a file of this user's that no other user may read: an empty one, as the
/// installer keeps where setup wrote none, one of a line end alone, one
/// that holds something else and one that others may read hold none.
pub(super) fn read(path: &Path) -> Option<ScrapeCredential> {
    read_private(path, 16384, Privacy::Owned)
        .ok()
        .and_then(|data| ScrapeCredential::read(&data))
}

pub(super) fn find(admin: &Admin) -> Result<Found, State> {
    let singleton = Get {
        ids: Some(&["singleton"]),
        properties: None,
    };
    let got: Got<Stored> = admin.call("x:Metrics/get", &singleton)?;
    let stored = got.list.into_iter().next().unwrap_or_default();
    let exporter = stored.fields.get("prometheus");
    let field = |name: &str| exporter.and_then(|exporter| exporter.get(name)?.as_str());
    let enabled = field("@type") == Some("Enabled");
    let ours = enabled && field("authUsername") == Some("garrison");
    Ok(Found {
        enabled,
        ours,
        stored,
    })
}

/// Where the exporter is Garrison's or off: the file's credential, or where
/// it holds none or a rotation asks for one, a new one, written to the file
/// before Stalwart is given it, which takes it once it reloads its settings.
pub(super) fn credential(
    directory: &Path,
    found: &Found,
    rotate: bool,
) -> Result<Option<Scrape>, State> {
    if found.enabled && !found.ours {
        return Ok(None);
    }
    let target = directory.join(FILE);
    let kept = read(&target).filter(|credential| !rotate && credential.username == "garrison");
    if let Some(credential) = kept {
        return Ok(Some(Scrape {
            secret: credential.secret,
            new: false,
        }));
    }
    let credential = ScrapeCredential {
        username: "garrison".to_owned(),
        secret: random(36)?,
    };
    let document =
        serde_json::to_string(&credential).map_err(|error| states::unwritten(&target, error))?;
    atomic_write(&target, document.as_bytes(), 0o600)
        .map_err(|error| states::unwritten(&target, error))?;
    Ok(Some(Scrape {
        secret: credential.secret,
        new: true,
    }))
}

/// Stalwart is given the file's credential where the exporter is
/// Garrison's or off and does not take it already, as a scrape with it shows
/// (Stalwart shows no secret), so that a run stopped before Stalwart took a
/// new one leaves nothing apart that the next run does not mend. What was
/// done, if anything.
pub(super) fn ensure(
    admin: &Admin,
    config: &Config,
    found: &Found,
    scrape: &Scrape,
) -> Result<Option<String>, State> {
    let target = config.credentials_directory.join(FILE);
    let exporter = Exporter::Enabled {
        auth_username: "garrison",
        auth_secret: Secret::Value {
            secret: &scrape.secret,
        },
    };
    let metrics = Metrics {
        prometheus: exporter,
    };
    if !scrape.new && found.stored.holds(&metrics) && taken(config, &scrape.secret) {
        return Ok(None);
    }
    admin.set("x:Metrics/set", &Set::update("singleton", metrics))?;
    Ok(Some(match (scrape.new, found.ours) {
        (false, true) => "updated Prometheus exporter (credential unchanged)".to_owned(),
        (false, false) => format!(
            "enabled Prometheus exporter with the credential in {}",
            target.display()
        ),
        (true, _) => format!("enabled Prometheus exporter -> {}", target.display()),
    }))
}

/// What setup says of an exporter that someone else switched on, which it
/// leaves as it is.
pub(super) fn theirs(directory: &Path) -> String {
    format!(
        "Prometheus exporter is enabled by someone else; not changed: for the collector, write \
         its user name and password into {} as configuration.md says \
         (collector.metrics_credential)",
        directory.join(FILE).display()
    )
}

/// Whether Stalwart's exporter answers a scrape with Garrison's user and
/// `secret`, where the collector scrapes it unless told otherwise.
fn taken(config: &Config, secret: &str) -> bool {
    let url = format!("{}/metrics/prometheus", config.deployment.stalwart_url);
    let user = STANDARD.encode(format!("garrison:{secret}"));
    Request::get(&url)
        .header("Authorization", &format!("Basic {user}"))
        .timeout(Duration::from_secs(30))
        .status()
        .is_ok_and(|status| status == 200)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use garrison_testing::http::{answer, json, serve};
    use serde_json::{Value, json};

    use super::*;

    /// The installer keeps an empty metrics credential where setup wrote
    /// none; setup makes one there all the same, where the exporter is
    /// Garrison's, instead of calling the exporter configured. So it does
    /// where the file holds a line end alone, or anything else the
    /// collector reads as no credential.
    #[test]
    fn an_empty_credential_file_holds_none() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(FILE);
        assert!(read(&path).is_none());
        for written in [
            "",
            "\n",
            " \r\n",
            "{\"username\": \"garrison\"\n",
            "[\"garrison\", \"s\"]",
        ] {
            std::fs::write(&path, written).unwrap();
            assert!(read(&path).is_none(), "{written:?}");
        }
        garrison_testing::write_private(&path, br#"{"username": "garrison", "secret": "s"}"#);
        assert!(read(&path).is_some());
    }

    /// What setup does where Stalwart's exporter is Garrison's, the file
    /// holds `written` at `mode` and Stalwart answers what setup asks after
    /// the read of its settings with `answers`: the step or the error, the
    /// secret Stalwart was given, if any, what the file holds after, and how
    /// many requests setup made.
    fn exported(
        written: &str,
        mode: u32,
        rotate: bool,
        answers: Vec<String>,
    ) -> (Result<Option<String>, State>, Option<String>, Value, usize) {
        let directory = tempfile::tempdir().unwrap();
        let stored = json(&json!({"methodResponses": [["x:Metrics/get", {"list": [{
            "id": "singleton", "prometheus": {"@type": "Enabled", "authUsername": "garrison",
            "authSecret": {"@type": "Value", "secret": "****"}}}]}, "0"]]}));
        let server = serve([vec![stored], answers].concat());
        let config = garrison_testing::config(directory.path(), &server.url);
        let credentials = &config.credentials_directory;
        std::fs::create_dir_all(credentials).unwrap();
        let path = credentials.join(FILE);
        garrison_testing::write_private(&path, written.as_bytes());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let found = find(&admin).unwrap();
        let scrape = credential(credentials, &found, rotate).unwrap().unwrap();
        let done = ensure(&admin, &config, &found, &scrape);
        let requests = server.requests();
        let sent = requests
            .iter()
            .find(|request| request.contains("x:Metrics/set"));
        let secret = sent.map(|request| {
            let (_, body) = request.split_once("\r\n\r\n").unwrap();
            let call: Value = serde_json::from_str(body).unwrap();
            let secret = &call["methodCalls"][0][1]["update"]["singleton"]["prometheus"];
            secret["authSecret"]["secret"].as_str().unwrap().to_owned()
        });
        let shown = |text: String| text.replace(&directory.path().display().to_string(), "DIR");
        let shown_state = |state: State| State {
            text: shown(state.text),
            ..state
        };
        let held: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let done = done.map(|step| step.map(shown)).map_err(shown_state);
        (done, secret, held, requests.len())
    }

    fn set() -> String {
        json(
            &json!({"methodResponses": [["x:Metrics/set", {"updated": {"singleton": null}}, "0"]]}),
        )
    }

    /// Where the file holds no credential, setup makes one, which is in the
    /// file before Stalwart is given it, also where Stalwart then refuses it.
    #[test]
    fn a_new_credential_is_in_its_file_before_stalwart_gets_it() {
        for (answered, took) in [(set(), true), (answer(503, "{}"), false)] {
            let (step, secret, held, _) = exported("\n", 0o600, false, vec![answered]);
            assert_eq!(step.is_ok(), took);
            if took {
                assert_eq!(
                    step,
                    Ok(Some(
                        "enabled Prometheus exporter -> DIR/credentials/metrics-credential"
                            .to_owned()
                    ))
                );
            }
            assert_eq!(
                held,
                json!({"username": "garrison", "secret": secret.unwrap()})
            );
        }
    }

    /// Where the file holds Garrison's credential, Stalwart is given it
    /// unless its exporter takes it already, as a scrape with it shows, so
    /// that a run stopped between the two cannot leave them apart; a
    /// rotation makes a new one.
    #[test]
    fn stalwart_is_given_the_credential_its_file_holds_where_it_takes_another() {
        let written = r#"{"username": "garrison", "secret": "the-scrape-secret"}"#;
        let (step, secret, held, asked) = exported(written, 0o600, false, vec![answer(200, "")]);
        assert_eq!((step, secret, asked), (Ok(None), None, 2));
        assert_eq!(held["secret"], "the-scrape-secret");
        let refused = vec![answer(401, ""), set()];
        let (step, secret, _, _) = exported(written, 0o600, false, refused);
        assert_eq!(
            (step, secret.as_deref()),
            (
                Ok(Some(
                    "updated Prometheus exporter (credential unchanged)".to_owned()
                )),
                Some("the-scrape-secret")
            )
        );
        let (step, secret, held, _) = exported(written, 0o600, true, vec![set()]);
        assert_eq!(
            step,
            Ok(Some(
                "enabled Prometheus exporter -> DIR/credentials/metrics-credential".to_owned()
            ))
        );
        let secret = secret.unwrap();
        assert_ne!(secret, "the-scrape-secret");
        assert_eq!(held, json!({"username": "garrison", "secret": secret}));
    }

    /// A credential whose file other users may read may have been seen:
    /// Stalwart is given a new one, which its file holds for this user alone.
    #[test]
    fn a_credential_file_others_may_read_gets_a_new_one() {
        let written = r#"{"username": "garrison", "secret": "the-scrape-secret"}"#;
        let (step, secret, held, _) = exported(written, 0o644, false, vec![set()]);
        assert_eq!(
            step,
            Ok(Some(
                "enabled Prometheus exporter -> DIR/credentials/metrics-credential".to_owned()
            ))
        );
        let secret = secret.unwrap();
        assert_ne!(secret, "the-scrape-secret");
        assert_eq!(held, json!({"username": "garrison", "secret": secret}));
    }
}
