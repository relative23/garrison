//! The privileged crates never depend on a web framework or an async runtime.
//!
//! They run with host access (broker, collector) or decide who may do what
//! (authz). Keeping HTTP servers and runtimes out of their dependency graph keeps
//! that code small and reviewable; only `web` and `ingest` serve HTTP.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::process::Command;

use serde_json::Value;

const PRIVILEGED: [&str; 11] = [
    "garrison-core",
    "garrison-stalwart",
    "garrison-authz",
    "garrison-broker",
    "garrison-collector",
    "garrison-checks",
    "garrison-checks-host",
    "garrison-checks-mail",
    "garrison-checks-network",
    "garrison-checks-stalwart",
    "garrison-milter",
];

const FORBIDDEN: [&str; 10] = [
    "axum",
    "axum-core",
    "h2",
    "hyper",
    "hyper-util",
    "tokio",
    "tower",
    "tower-http",
    "utoipa",
    "utoipa-gen",
];

pub(crate) fn check(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let metadata: Value =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    Ok(problems(&metadata))
}

/// The privileged packages in `cargo metadata` output that reach a forbidden crate.
fn problems(metadata: &Value) -> Vec<String> {
    let names: HashMap<&str, &str> = metadata["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|package| Some((package["id"].as_str()?, package["name"].as_str()?)))
        .collect();
    let edges: HashMap<&str, Vec<&str>> = metadata["resolve"]["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| Some((node["id"].as_str()?, runtime_dependencies(node))))
        .collect();
    let mut problems = Vec::new();
    for (id, name) in &names {
        if !PRIVILEGED.contains(name) {
            continue;
        }
        let reachable = closure(id, &edges);
        let found: BTreeSet<&str> = reachable
            .iter()
            .filter_map(|dependency| names.get(dependency).copied())
            .filter(|dependency| FORBIDDEN.contains(dependency))
            .collect();
        if !found.is_empty() {
            problems.push(format!(
                "{name} depends on {}",
                found.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    problems.sort();
    problems
}

/// Normal and build dependencies; development dependencies never ship.
fn runtime_dependencies(node: &Value) -> Vec<&str> {
    node["deps"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|dependency| {
            dependency["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|kind| kind["kind"].as_str() != Some("dev"))
        })
        .filter_map(|dependency| dependency["pkg"].as_str())
        .collect()
}

fn closure<'a>(start: &'a str, edges: &HashMap<&'a str, Vec<&'a str>>) -> BTreeSet<&'a str> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![start];
    while let Some(id) = pending.pop() {
        for dependency in edges.get(id).into_iter().flatten() {
            if seen.insert(*dependency) {
                pending.push(dependency);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn dependency(id: &str, kind: Option<&str>) -> Value {
        json!({"pkg": id, "dep_kinds": [{"kind": kind}]})
    }

    #[test]
    fn indirect_runtime_dependencies_are_found_and_dev_dependencies_ignored() {
        let metadata = json!({
            "packages": [
                {"id": "core", "name": "garrison-core"},
                {"id": "broker", "name": "garrison-broker"},
                {"id": "web", "name": "garrison-web"},
                {"id": "client", "name": "some-client"},
                {"id": "tokio", "name": "tokio"},
                {"id": "axum", "name": "axum"},
            ],
            "resolve": {"nodes": [
                {"id": "core", "deps": [dependency("tokio", Some("dev"))]},
                {"id": "broker", "deps": [dependency("core", None), dependency("client", None)]},
                {"id": "client", "deps": [dependency("tokio", Some("build"))]},
                {"id": "web", "deps": [dependency("axum", None), dependency("tokio", None)]},
                {"id": "tokio", "deps": []},
                {"id": "axum", "deps": [dependency("tokio", None)]},
            ]},
        });
        assert_eq!(problems(&metadata), ["garrison-broker depends on tokio"]);
    }
}
