//! Stalwart's Prometheus exporter and the scrape credential setup writes
//! for the collector, where the exporter is Garrison's or off.

use std::path::Path;

use garrison_collector::run::ScrapeCredential;
use garrison_core::files::atomic_write;
use garrison_stalwart::jmap::{Get, Got};

use super::objects::{Exporter, Metrics, Secret, Set, StoredMetrics};
use super::{Admin, random};

/// Whether the file at `path` holds something: an empty one, as the
/// installer keeps where setup wrote none, holds no credential.
fn holds(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0)
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
        return Ok(
            "Prometheus exporter is enabled by someone else; not changed \
                   (configure metrics_credential manually)"
                .into(),
        );
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
    atomic_write(&target, document.as_bytes(), 0o600).map_err(|error| error.to_string())?;
    Ok(format!(
        "enabled Prometheus exporter -> {}",
        target.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The installer keeps an empty metrics credential where setup wrote
    /// none; setup writes one there all the same, where the exporter is
    /// Garrison's, instead of calling the exporter configured.
    #[test]
    fn an_empty_credential_file_holds_none() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metrics-credential");
        assert!(!holds(&path));
        std::fs::write(&path, "").unwrap();
        assert!(!holds(&path));
        std::fs::write(&path, r#"{"username": "garrison", "secret": "s"}"#).unwrap();
        assert!(holds(&path));
    }
}
