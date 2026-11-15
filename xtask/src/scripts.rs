//! A script that names its interpreter can be run as its header shows it,
//! `scripts/<name>.sh`: Git keeps it executable. The libraries the scripts
//! source name none and are left as they are.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(crate) fn check(root: &Path) -> Result<Vec<String>, String> {
    let folder = root.join("scripts");
    let entries =
        fs::read_dir(&folder).map_err(|error| format!("{}: {error}", folder.display()))?;
    let mut problems = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|suffix| suffix != "sh") {
            continue;
        }
        let text = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mode = entry
            .metadata()
            .map_err(|error| format!("{}: {error}", path.display()))?
            .permissions()
            .mode();
        if text.starts_with(b"#!") && mode & 0o111 == 0 {
            problems.push(format!(
                "scripts/{} names its interpreter but is not executable (mode {:o}): chmod +x \
                 it and add it again",
                entry.file_name().to_string_lossy(),
                mode & 0o777
            ));
        }
    }
    problems.sort();
    Ok(problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(root: &Path, name: &str, text: &str, mode: u32) {
        let path = root.join("scripts").join(name);
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_script_with_an_interpreter_line_must_be_executable() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("scripts")).unwrap();
        script(root.path(), "run.sh", "#!/bin/sh\necho run\n", 0o755);
        script(
            root.path(),
            "library.sh",
            "# shellcheck shell=sh\nstep() { :; }\n",
            0o644,
        );
        script(root.path(), "notes.txt", "#!/bin/sh\n", 0o644);
        assert_eq!(check(root.path()).unwrap(), Vec::<String>::new());
        script(root.path(), "soak.sh", "#!/bin/sh\necho soak\n", 0o644);
        assert_eq!(
            check(root.path()).unwrap(),
            [
                "scripts/soak.sh names its interpreter but is not executable (mode 644): chmod +x \
              it and add it again"
            ]
        );
    }
}
