//! Handwritten source files stay at or below 500 lines (CONTRIBUTING.md).

use std::fs;
use std::path::Path;

const LIMIT: usize = 500;
const FOLDERS: [&str; 7] = [
    "crates",
    "xtask",
    "scripts",
    "deploy",
    "frontend/src",
    "frontend/tests",
    "frontend/public",
];
const SUFFIXES: [&str; 6] = ["rs", "sh", "ts", "tsx", "css", "js"];
const SKIPPED: [&str; 2] = ["node_modules", "target"];

pub(crate) fn check(root: &Path) -> Vec<String> {
    let mut large = Vec::new();
    for folder in FOLDERS {
        visit(root, &root.join(folder), &mut large);
    }
    large.sort();
    large
}

fn visit(root: &Path, directory: &Path, large: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !SKIPPED.contains(&name.as_str()) {
                visit(root, &path, large);
            }
            continue;
        }
        let handwritten = !name.ends_with(".gen.ts");
        let source = path
            .extension()
            .is_some_and(|suffix| SUFFIXES.iter().any(|known| suffix == *known));
        if !(handwritten && source) {
            continue;
        }
        let lines = fs::read_to_string(&path).map_or(0, |text| text.lines().count());
        if lines > LIMIT {
            let shown = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            large.push(format!("{shown}: {lines} lines"));
        }
    }
}
