//! Stalwart's Prometheus exporter and the scrape credential setup writes
//! for the collector, where the exporter is Garrison's or off.

use std::path::Path;

use garrison_collector::run::ScrapeCredential;
use garrison_core::files::{atomic_write, read_bounded};
use garrison_stalwart::jmap::{Get, Got};

use super::objects::{Exporter, Metrics, Secret, Set, StoredMetrics};
use super::{Admin, random};

/// Whether the file at `path` holds a credential as the collector reads
/// one: an empty one, as the installer keeps where setup wrote none, one of
/// a line end alone and one that holds something else hold none.
fn holds(path: &Path) -> bool {
    read_bounded(path, 16384).is_ok_and(|data| ScrapeCredential::read(&data).is_some())
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
    if ours && holds(&target) && !rotate {
        return Ok("Prometheus exporter already configured".into());
    }
    let secret = random(36)?;
    let exporter = Exporter::Enabled {
        auth_username: "garrison",
        auth_secret: Secret::Value { secret: &secret },
    };
    let metrics = Metrics {
        prometheus: exporter,
    };
    admin.set("x:Metrics/set", &Set::update("singleton", metrics))?;
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
    /// Garrison's, instead of calling the exporter configured. So it does
    /// where the file holds a line end alone, or anything else the
    /// collector reads as no credential.
    #[test]
    fn an_empty_credential_file_holds_none() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metrics-credential");
        assert!(!holds(&path));
        for written in [
            "",
            "\n",
            " \r\n",
            "{\"username\": \"garrison\"\n",
            "[\"garrison\", \"s\"]",
        ] {
            std::fs::write(&path, written).unwrap();
            assert!(!holds(&path), "{written:?}");
        }
        std::fs::write(&path, r#"{"username": "garrison", "secret": "s"}"#).unwrap();
        assert!(holds(&path));
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
}
