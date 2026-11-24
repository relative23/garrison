//! Checks of the host itself: resources, host care, systemd units, installed
//! versions, receipts of jobs, local endpoints and backup repositories.

pub mod backups;
pub mod providers;

// The base modules, under the names the checks were written against.
pub(crate) use garrison_checks::{command, context, kept, options, values};

/// The checks' test helpers, with the workspace's test configuration.
#[cfg(test)]
mod testing {
    pub(crate) use garrison_checks::testing::*;
    use garrison_core::config::Config;

    pub(crate) fn config(directory: &std::path::Path) -> Config {
        garrison_testing::config(directory, "http://127.0.0.1:9")
    }

    /// The code of this crate's sources, by their path below `src/`, each
    /// without its tests: what follows a file's first `#[cfg(test)]`, the
    /// files whose names end in `tests.rs` and the folders whose names end
    /// in `tests` are left out.
    pub(crate) fn product_code() -> Vec<(String, String)> {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        let mut folders = vec![source.clone()];
        while let Some(folder) = folders.pop() {
            for entry in std::fs::read_dir(&folder).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                if path.is_dir() {
                    if !name.ends_with("tests") {
                        folders.push(path);
                    }
                } else if path.extension().is_some_and(|suffix| suffix == "rs")
                    && !name.ends_with("tests.rs")
                {
                    let text = std::fs::read_to_string(&path).unwrap();
                    let code = text.split("#[cfg(test)]").next().unwrap().to_owned();
                    let file = path.strip_prefix(&source).unwrap().display().to_string();
                    found.push((file, code));
                }
            }
        }
        found.sort();
        found
    }
}
