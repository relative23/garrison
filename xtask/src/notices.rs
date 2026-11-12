//! `THIRD_PARTY_NOTICES.txt` for everything a release ships.
//!
//! Covers the crates compiled into the binary for one target and the
//! production npm packages compiled into the interface (see `components`),
//! with the license texts each package ships, and vendored conventions. Fails
//! if a license text is missing.

use std::fs;
use std::path::Path;

use crate::components::{Component, Ecosystem, crates, npm_packages};

const LICENSE_NAMES: [&str; 4] = ["license", "licence", "copying", "notice"];
/// Code that follows another project's source rather than an installed package.
const VENDORED: [(&str, &str); 1] = [(
    "shadcn/ui component conventions (MIT)",
    "frontend/src/components/ui/LICENSE",
)];

fn license_texts(folder: &Path, what: &str) -> Result<String, String> {
    let mut files: Vec<_> = fs::read_dir(folder)
        .map_err(|error| format!("{what}: {error}"))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        let lower = name.to_lowercase();
                        LICENSE_NAMES.iter().any(|prefix| lower.starts_with(prefix))
                    })
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("Missing license text for {what}"));
    }
    let texts: Result<Vec<String>, String> = files
        .iter()
        .map(|path| {
            fs::read_to_string(path)
                .map(|text| text.trim().to_owned())
                .map_err(|error| format!("{what}: {error}"))
        })
        .collect();
    Ok(texts?.join("\n\n"))
}

/// One section per component: name, version, license and the license texts
/// the package ships.
fn sections(components: &[Component]) -> Result<Vec<String>, String> {
    components
        .iter()
        .map(|component| {
            let what = match component.ecosystem {
                Ecosystem::Cargo => format!("crate {}", component.name),
                Ecosystem::Npm => format!("npm package {}", component.name),
            };
            let texts = license_texts(&component.folder, &what)?;
            let license = component.license.as_deref().unwrap_or("see text");
            Ok(format!(
                "{} {} ({license})\n\n{texts}",
                component.name, component.version
            ))
        })
        .collect()
}

/// The notices of a release for `target`, as text.
pub(crate) fn text(root: &Path, target: &str) -> Result<String, String> {
    let mut parts = vec![
        "Third-party notices for Garrison. Project code: see LICENSE (MIT). The Rust \
         standard library compiled into the binary, musl libc among its parts, has its \
         notices in licenses/rust-standard-library.html."
            .to_owned(),
    ];
    parts.extend(sections(&crates(root, target)?)?);
    parts.extend(sections(&npm_packages(root)?)?);
    for (title, path) in VENDORED {
        let text =
            fs::read_to_string(root.join(path)).map_err(|error| format!("{path}: {error}"))?;
        parts.push(format!("{title}\n\n{}", text.trim()));
    }
    let separator = format!("\n\n{}\n\n", "=".repeat(78));
    Ok(format!("{}\n", parts.join(&separator)))
}
