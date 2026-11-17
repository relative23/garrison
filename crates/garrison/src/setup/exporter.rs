//! Stalwart's Prometheus exporter and the scrape credential setup writes
//! for the collector, where the exporter is Garrison's or off.

use std::path::Path;

use garrison_collector::run::ScrapeCredential;
use garrison_core::files::{atomic_write, read_bounded};
use garrison_stalwart::jmap::{Get, Got};

use super::objects::{Exporter, Metrics, Secret, Set, StoredMetrics};
use super::{Admin, random};

/// The credential the file at `path` holds, as the collector reads it: an
/// empty one, as the installer keeps where setup wrote none, one of a line
/// end alone and one that holds something else hold none.
fn read(path: &Path) -> Option<ScrapeCredential> {
    read_bounded(path, 16384)
        .ok()
        .and_then(|data| ScrapeCredential::read(&data))
}

pub(super) fn ensure_metrics(
    admin: &Admin,
    directory: &Path,
    rotate: bool,
) -> Result<String, String> {
    let target = directory.join("metrics-credential");
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
        return Ok(format!(
            "Prometheus exporter is enabled by someone else; not changed: for the collector, \
             write its user name and password into {} as configuration.md says \
             (collector.metrics_credential)",
            target.display()
        ));
    }
    // Where the file holds Garrison's credential, Stalwart is given it on
    // every run, as the webhook is given its file's key: a run stopped after
    // Stalwart took a new one and before the file did left the two apart,
    // and every run after that kept them so.
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
    match (new, ours) {
        (false, true) => return Ok("updated Prometheus exporter (credential unchanged)".into()),
        (false, false) => {
            return Ok(format!(
                "enabled Prometheus exporter with the credential in {}",
                target.display()
            ));
        }
        (true, _) => {}
    }
    let credential = ScrapeCredential {
        username: "garrison".to_owned(),
        secret,
    };
    let document = serde_json::to_string(&credential).map_err(|error| error.to_string())?;
    atomic_write(&target, document.as_bytes(), 0o600)
        .map_err(|error| format!("Could not write {}: {error}", target.display()))?;
    Ok(format!(
        "enabled Prometheus exporter -> {}",
        target.display()
    ))
}

#[cfg(test)]
mod tests {
    use garrison_testing::http::{json, serve};
    use serde_json::json;

    use super::*;

    /// The installer keeps an empty metrics credential where setup wrote
    /// none; setup writes one there all the same, where the exporter is
    /// Garrison's, instead of giving Stalwart the file's. So it does
    /// where the file holds a line end alone, or anything else the
    /// collector reads as no credential.
    #[test]
    fn an_empty_credential_file_holds_none() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metrics-credential");
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
        std::fs::write(&path, r#"{"username": "garrison", "secret": "s"}"#).unwrap();
        assert!(read(&path).is_some());
    }

    /// Where the exporter is Garrison's and the file holds no credential,
    /// setup writes one, which the collector then reads.
    #[test]
    fn a_credential_file_that_holds_none_gets_one_where_the_exporter_is_garrisons() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metrics-credential");
        std::fs::write(&path, "\n").unwrap();
        let stored = json(&json!({"methodResponses": [["x:Metrics/get", {"list": [{
            "id": "singleton", "prometheus": {"@type": "Enabled", "authUsername": "garrison"}}]}, "0"]]}));
        let set = json(&json!({"methodResponses": [["x:Metrics/set",
            {"updated": {"singleton": null}}, "0"]]}));
        let server = serve(vec![stored, set]);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let step = ensure_metrics(&admin, directory.path(), false).unwrap();
        server.requests();
        assert_eq!(
            step,
            format!("enabled Prometheus exporter -> {}", path.display())
        );
        let written: ScrapeCredential =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(written.username, "garrison");
    }

    /// What `ensure_metrics` does where Stalwart's exporter is Garrison's and
    /// the file holds `written`: the step, and the secret Stalwart was given.
    fn exported(written: &str, rotate: bool) -> (String, String) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metrics-credential");
        std::fs::write(&path, written).unwrap();
        let stored = json(&json!({"methodResponses": [["x:Metrics/get", {"list": [{
            "id": "singleton", "prometheus": {"@type": "Enabled", "authUsername": "garrison"}}]}, "0"]]}));
        let set = json(&json!({"methodResponses": [["x:Metrics/set",
            {"updated": {"singleton": null}}, "0"]]}));
        let server = serve(vec![stored, set]);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let step = ensure_metrics(&admin, directory.path(), rotate).unwrap();
        let requests = server.requests();
        let (_, body) = requests[1].split_once("\r\n\r\n").unwrap();
        let call: serde_json::Value = serde_json::from_str(body).unwrap();
        let secret = &call["methodCalls"][0][1]["update"]["singleton"]["prometheus"]["authSecret"];
        let step = step.replace(&directory.path().display().to_string(), "DIR");
        (step, secret["secret"].as_str().unwrap().to_owned())
    }

    /// Where the file holds Garrison's credential, Stalwart is given it on
    /// every run, so that a run stopped after Stalwart took a new one and
    /// before the file did cannot leave them apart for good; a rotation
    /// makes a new one.
    #[test]
    fn stalwart_is_given_the_credential_its_file_holds() {
        let held = r#"{"username": "garrison", "secret": "the-scrape-secret"}"#;
        assert_eq!(
            exported(held, false),
            (
                "updated Prometheus exporter (credential unchanged)".to_owned(),
                "the-scrape-secret".to_owned()
            )
        );
        let (step, secret) = exported(held, true);
        assert_eq!(
            step,
            "enabled Prometheus exporter -> DIR/metrics-credential"
        );
        assert_ne!(secret, "the-scrape-secret");
    }
}
