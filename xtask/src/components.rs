//! What a release ships besides Garrison's own code: the crates compiled into
//! the binary for one target and the production npm packages compiled into the
//! interface. The notices and the SBOM list exactly these.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Ecosystem {
    Cargo,
    Npm,
}

#[derive(Debug)]
pub(crate) struct Component {
    pub(crate) ecosystem: Ecosystem,
    pub(crate) name: String,
    pub(crate) version: String,
    /// The license as the package declares it, if it does.
    pub(crate) license: Option<String>,
    /// The package's own files, its license texts among them.
    pub(crate) folder: PathBuf,
    /// The digest of the downloaded package: CycloneDX algorithm name and hex.
    pub(crate) digest: Option<(&'static str, String)>,
}

/// Registry checksums from Cargo.lock, by name and version.
fn lock_checksums(root: &Path) -> Result<BTreeMap<(String, String), String>, String> {
    let text = fs::read_to_string(root.join("Cargo.lock")).map_err(|error| error.to_string())?;
    let lock = text
        .parse::<toml::Table>()
        .map_err(|error| format!("Cargo.lock: {error}"))?;
    let mut sums = BTreeMap::new();
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let field = |key: &str| package.get(key).and_then(toml::Value::as_str);
        if let (Some(name), Some(version), Some(sum)) =
            (field("name"), field("version"), field("checksum"))
        {
            sums.insert((name.to_owned(), version.to_owned()), sum.to_owned());
        }
    }
    Ok(sums)
}

/// The third-party crates that `garrison` links for `target`, without build tools.
pub(crate) fn crates(root: &Path, target: &str) -> Result<Vec<Component>, String> {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--filter-platform",
            target,
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let metadata: Value =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    let packages: Vec<&Value> = metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    let package = |id: &str| packages.iter().find(|package| package["id"] == id).copied();
    let start = packages
        .iter()
        .find(|package| package["name"] == "garrison")
        .and_then(|package| package["id"].as_str())
        .ok_or("the garrison package is missing")?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or("no dependency graph")?;
    let mut seen = BTreeSet::new();
    let mut pending = vec![start.to_owned()];
    while let Some(id) = pending.pop() {
        let node = nodes
            .iter()
            .find(|node| node["id"] == id.as_str())
            .ok_or("incomplete graph")?;
        for dependency in node["deps"].as_array().into_iter().flatten() {
            // Normal dependencies only: build scripts and macros run at build time.
            let normal = dependency["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|kind| kind["kind"].is_null());
            let id = dependency["pkg"].as_str().unwrap_or_default().to_owned();
            if normal && seen.insert(id.clone()) {
                pending.push(id);
            }
        }
    }
    let sums = lock_checksums(root)?;
    let mut found = Vec::new();
    for id in &seen {
        let Some(package) = package(id).filter(|package| !package["source"].is_null()) else {
            continue; // A workspace crate: project code.
        };
        let (name, version) = (
            package["name"].as_str().unwrap_or_default().to_owned(),
            package["version"].as_str().unwrap_or_default().to_owned(),
        );
        let folder = Path::new(package["manifest_path"].as_str().unwrap_or_default())
            .parent()
            .ok_or("no crate folder")?
            .to_owned();
        let digest = sums
            .get(&(name.clone(), version.clone()))
            .map(|sum| ("SHA-256", sum.clone()));
        found.push(Component {
            ecosystem: Ecosystem::Cargo,
            license: package["license"].as_str().map(str::to_owned),
            name,
            version,
            folder,
            digest,
        });
    }
    found.sort_by_key(|component| (component.name.to_lowercase(), component.version.clone()));
    Ok(found)
}

/// `sha512-<base64>` from package-lock.json as a CycloneDX digest.
fn integrity(text: &str) -> Option<(&'static str, String)> {
    let (algorithm, encoded) = text.split_once('-')?;
    let name = match algorithm {
        "sha512" => "SHA-512",
        "sha384" => "SHA-384",
        "sha256" => "SHA-256",
        "sha1" => "SHA-1",
        _ => return None,
    };
    let bytes = STANDARD.decode(encoded).ok()?;
    Some((name, garrison_core::hex::encode(&bytes)))
}

/// The npm packages compiled into the interface: production, not optional.
pub(crate) fn npm_packages(root: &Path) -> Result<Vec<Component>, String> {
    let lock: Value = serde_json::from_str(
        &fs::read_to_string(root.join("frontend/package-lock.json"))
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let mut found = Vec::new();
    for (location, package) in lock["packages"].as_object().ok_or("no npm packages")? {
        if location.is_empty() || package["dev"] == true || package["optional"] == true {
            continue;
        }
        let folder = root.join("frontend").join(location);
        let manifest: Value = serde_json::from_str(
            &fs::read_to_string(folder.join("package.json"))
                .map_err(|error| format!("{location}: {error}"))?,
        )
        .map_err(|error| error.to_string())?;
        found.push(Component {
            ecosystem: Ecosystem::Npm,
            name: manifest["name"].as_str().unwrap_or(location).to_owned(),
            version: manifest["version"].as_str().unwrap_or_default().to_owned(),
            license: manifest["license"].as_str().map(str::to_owned),
            digest: package["integrity"].as_str().and_then(integrity),
            folder,
        });
    }
    found.sort_by_key(|component| (component.name.clone(), component.version.clone()));
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_integrity_becomes_a_hex_digest() {
        assert_eq!(
            integrity("sha512-AAEC"),
            Some(("SHA-512", "000102".to_owned()))
        );
        assert_eq!(integrity("md5-AAEC"), None);
        assert_eq!(integrity("sha512-not base64"), None);
    }
}
