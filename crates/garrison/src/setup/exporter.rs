//! Stalwart's Prometheus exporter and the scrape credential setup writes
//! for the collector, where the exporter is Garrison's or off.

use std::path::Path;

use garrison_collector::run::ScrapeCredential;
use garrison_core::files::{Privacy, atomic_write, read_private};
use garrison_stalwart::jmap::{Get, Got};

use super::objects::{Exporter, Metrics, Secret, Set, StoredMetrics};
use super::{Admin, random};

/// The credential's file, as the collector reads it.
pub(super) const FILE: &str = "metrics-credential";

/// What `ensure_metrics` did, and a new credential for its file.
pub(super) struct Exported {
    pub(super) step: String,
    /// For its file once Stalwart has reloaded its settings (`keep`), which
    /// is when it takes it.
    pub(super) new_credential: Option<String>,
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

pub(super) fn ensure_metrics(
    admin: &Admin,
    directory: &Path,
    rotate: bool,
) -> Result<Exported, String> {
    let target = directory.join(FILE);
    let singleton = Get {
        ids: Some(&["singleton"]),
        properties: None,
    };
    let stored: Got<StoredMetrics> = admin.call("x:Metrics/get", &singleton)?;
    let current = stored.list.into_iter().next().unwrap_or_default();
    let current = current.prometheus.unwrap_or_default();
    let enabled = current.kind.as_deref() == Some("Enabled");
    let ours = enabled && current.auth_username.as_deref() == Some("garrison");
    if enabled && !ours {
        return Ok(Exported {
            step: format!(
                "Prometheus exporter is enabled by someone else; not changed: for the \
                 collector, write its user name and password into {} as configuration.md says \
                 (collector.metrics_credential)",
                target.display()
            ),
            new_credential: None,
        });
    }
    // Where the file holds Garrison's credential, Stalwart is given it on
    // every run, as the webhook is given its file's key: a run stopped after
    // Stalwart took a new one and before the file did leaves the two apart.
    let kept = read(&target).filter(|credential| !rotate && credential.username == "garrison");
    let (secret, new) = match kept {
        Some(credential) => (credential.secret, false),
        None => (random(36)?, true),
    };
    let exporter = Exporter::Enabled {
        auth_username: "garrison",
        auth_secret: Secret::Value { secret: &secret },
    };
    let metrics = Metrics {
        prometheus: exporter,
    };
    admin.set("x:Metrics/set", &Set::update("singleton", metrics))?;
    let step = match (new, ours) {
        (false, true) => "updated Prometheus exporter (credential unchanged)".to_owned(),
        (false, false) => format!(
            "enabled Prometheus exporter with the credential in {}",
            target.display()
        ),
        (true, _) => format!("enabled Prometheus exporter -> {}", target.display()),
    };
    let credential = ScrapeCredential {
        username: "garrison".to_owned(),
        secret,
    };
    let document = serde_json::to_string(&credential).map_err(|error| error.to_string())?;
    Ok(Exported {
        step,
        new_credential: new.then_some(document),
    })
}

/// Write a new credential to its file, once Stalwart takes it.
pub(super) fn keep(directory: &Path, document: &str) -> Result<(), String> {
    let target = directory.join(FILE);
    atomic_write(&target, document.as_bytes(), 0o600)
        .map_err(|error| format!("Could not write {}: {error}", target.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use garrison_testing::http::{json, serve};
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

    /// What `ensure_metrics` does where Stalwart's exporter is Garrison's and
    /// the file holds `written` at `mode`: the step, the secret Stalwart was
    /// given, and the new credential for the file, if any; the file itself
    /// is left to `keep`.
    fn exported(written: &str, mode: u32, rotate: bool) -> (String, String, Option<Value>) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(FILE);
        garrison_testing::write_private(&path, written.as_bytes());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let stored = json(&json!({"methodResponses": [["x:Metrics/get", {"list": [{
            "id": "singleton", "prometheus": {"@type": "Enabled", "authUsername": "garrison"}}]}, "0"]]}));
        let set = json(&json!({"methodResponses": [["x:Metrics/set",
            {"updated": {"singleton": null}}, "0"]]}));
        let server = serve(vec![stored, set]);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let done = ensure_metrics(&admin, directory.path(), rotate).unwrap();
        let requests = server.requests();
        let (_, body) = requests[1].split_once("\r\n\r\n").unwrap();
        let call: Value = serde_json::from_str(body).unwrap();
        let secret = &call["methodCalls"][0][1]["update"]["singleton"]["prometheus"]["authSecret"];
        assert_eq!(std::fs::read_to_string(&path).unwrap(), written);
        let step = done
            .step
            .replace(&directory.path().display().to_string(), "DIR");
        let new = done
            .new_credential
            .map(|text| serde_json::from_str(&text).unwrap());
        (step, secret["secret"].as_str().unwrap().to_owned(), new)
    }

    /// Where the file holds no credential, setup makes one, which Stalwart is
    /// given and the file is to take.
    #[test]
    fn a_credential_file_that_holds_none_gets_one_where_the_exporter_is_garrisons() {
        let (step, secret, new) = exported("\n", 0o600, false);
        assert_eq!(
            step,
            "enabled Prometheus exporter -> DIR/metrics-credential"
        );
        assert_eq!(new, Some(json!({"username": "garrison", "secret": secret})));
    }

    /// Where the file holds Garrison's credential, Stalwart is given it, so
    /// that a run stopped between the two cannot leave them apart; a
    /// rotation makes a new one.
    #[test]
    fn stalwart_is_given_the_credential_its_file_holds() {
        let held = r#"{"username": "garrison", "secret": "the-scrape-secret"}"#;
        assert_eq!(
            exported(held, 0o600, false),
            (
                "updated Prometheus exporter (credential unchanged)".to_owned(),
                "the-scrape-secret".to_owned(),
                None
            )
        );
        let (step, secret, new) = exported(held, 0o600, true);
        assert_eq!(
            step,
            "enabled Prometheus exporter -> DIR/metrics-credential"
        );
        assert_ne!(secret, "the-scrape-secret");
        assert_eq!(new, Some(json!({"username": "garrison", "secret": secret})));
    }

    /// A credential whose file other users may read may have been seen:
    /// Stalwart is given a new one, which `keep` writes for this user alone,
    /// where setup once kept the file as it was and called it unchanged.
    #[test]
    fn a_credential_file_others_may_read_gets_a_new_one() {
        let held = r#"{"username": "garrison", "secret": "the-scrape-secret"}"#;
        let (step, secret, new) = exported(held, 0o644, false);
        assert_eq!(
            step,
            "enabled Prometheus exporter -> DIR/metrics-credential"
        );
        assert_ne!(secret, "the-scrape-secret");
        assert_eq!(new, Some(json!({"username": "garrison", "secret": secret})));
        let directory = tempfile::tempdir().unwrap();
        keep(directory.path(), held).unwrap();
        let mode = std::fs::metadata(directory.path().join(FILE)).unwrap();
        assert_eq!(mode.permissions().mode() & 0o777, 0o600);
    }
}
