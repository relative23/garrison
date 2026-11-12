//! A CycloneDX software bill of materials for one release archive, so an
//! operator can tell from the list alone whether a published vulnerability
//! concerns the Garrison they run.

use std::fmt::Write as _;
use std::path::Path;

use garrison_core::time;
use serde_json::{Value, json};

use crate::components::{Component, Ecosystem, crates, npm_packages};

/// Percent-encoding for a package URL part: unreserved characters stay.
fn escape(text: &str) -> String {
    let mut escaped = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b".-_~".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            let _ = write!(escaped, "%{byte:02X}");
        }
    }
    escaped
}

/// A package URL (purl) as the CycloneDX `purl` field takes it.
fn purl(component: &Component) -> String {
    let version = escape(&component.version);
    match component.ecosystem {
        Ecosystem::Cargo => format!("pkg:cargo/{}@{version}", escape(&component.name)),
        Ecosystem::Npm => match component.name.split_once('/') {
            Some((scope, name)) => {
                format!("pkg:npm/{}/{}@{version}", escape(scope), escape(name))
            }
            None => format!("pkg:npm/{}@{version}", escape(&component.name)),
        },
    }
}

/// A declared license as an SPDX expression; old crates write `MIT/Apache-2.0`.
fn expression(license: &str) -> String {
    license.replace('/', " OR ")
}

fn entry(component: &Component) -> Value {
    let reference = purl(component);
    let mut entry = json!({
        "type": "library",
        "bom-ref": reference,
        "name": component.name,
        "version": component.version,
        "purl": reference,
    });
    if component.ecosystem == Ecosystem::Npm
        && let Some((scope, name)) = component.name.split_once('/')
    {
        entry["group"] = json!(scope);
        entry["name"] = json!(name);
    }
    if let Some(license) = &component.license {
        entry["licenses"] = json!([{ "expression": expression(license) }]);
    }
    if let Some((algorithm, digest)) = &component.digest {
        entry["hashes"] = json!([{ "alg": algorithm, "content": digest }]);
    }
    entry
}

/// The SBOM of `garrison-<version>-<architecture>` built for `target` with the
/// Rust `toolchain`, timestamped with the commit (`epoch`), never the clock.
pub(crate) fn cyclonedx(
    root: &Path,
    target: &str,
    version: &str,
    architecture: &str,
    epoch: &str,
    toolchain: &str,
) -> Result<String, String> {
    let timestamp = epoch
        .parse::<f64>()
        .ok()
        .and_then(time::from_unix)
        .map(time::isoformat)
        .ok_or_else(|| format!("{epoch} is not a source date"))?;
    let mut components: Vec<Value> = crates(root, target)?
        .iter()
        .chain(npm_packages(root)?.iter())
        .map(entry)
        .collect();
    components.push(json!({
        "type": "library",
        "bom-ref": "rust-standard-library",
        "name": "rust-std",
        "version": toolchain,
        "purl": format!("pkg:generic/rust-std@{}", escape(toolchain)),
        "licenses": [{ "expression": "MIT OR Apache-2.0" }],
        "description": "The Rust standard library, statically linked with musl libc; \
                        their notices are in licenses/rust-standard-library.html.",
    }));
    components.sort_by(|left, right| left["bom-ref"].as_str().cmp(&right["bom-ref"].as_str()));
    let references: Vec<&Value> = components.iter().map(|entry| &entry["bom-ref"]).collect();
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {
                "type": "application",
                "bom-ref": "garrison",
                "name": "garrison",
                "version": version,
                "purl": format!(
                    "pkg:generic/garrison@{}?arch={architecture}",
                    escape(version)
                ),
                "licenses": [{ "expression": "MIT" }],
            },
        },
        "components": components,
        "dependencies": [{ "ref": "garrison", "dependsOn": references }],
    });
    serde_json::to_string_pretty(&bom)
        .map(|text| text + "\n")
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn component(ecosystem: Ecosystem, name: &str, version: &str) -> Component {
        Component {
            ecosystem,
            name: name.to_owned(),
            version: version.to_owned(),
            license: Some("MIT/Apache-2.0".to_owned()),
            folder: PathBuf::new(),
            digest: Some(("SHA-256", "ab".to_owned())),
        }
    }

    #[test]
    fn package_urls_follow_the_purl_rules() {
        assert_eq!(
            purl(&component(Ecosystem::Cargo, "serde_json", "1.0.0")),
            "pkg:cargo/serde_json@1.0.0"
        );
        assert_eq!(
            purl(&component(Ecosystem::Npm, "@radix-ui/react-tabs", "1.2.1")),
            "pkg:npm/%40radix-ui/react-tabs@1.2.1"
        );
        assert_eq!(
            purl(&component(Ecosystem::Npm, "react", "19.3.1+build")),
            "pkg:npm/react@19.3.1%2Bbuild"
        );
    }

    #[test]
    fn an_entry_carries_group_license_and_digest() {
        let value = entry(&component(Ecosystem::Npm, "@radix-ui/react-tabs", "1.2.1"));
        assert_eq!(value["group"], "@radix-ui");
        assert_eq!(value["name"], "react-tabs");
        assert_eq!(value["licenses"][0]["expression"], "MIT OR Apache-2.0");
        assert_eq!(value["hashes"][0]["alg"], "SHA-256");
        assert_eq!(value["bom-ref"], value["purl"]);
    }
}
