//! The macro filter's entry, as `stalwart setup` makes it.

use garrison_testing::lab::Lab;
use serde_json::json;

use super::{run, text};

/// The macro filter's entry in Stalwart follows the configuration: none while
/// the filter does not answer, one while the `[milter]` section is there,
/// found by the address it asks, and changed in place. Taking it out again
/// needs to see where the running filter listens, which only root can: the
/// quick start does it.
pub(super) fn macro_filter(
    lab: &mut Lab,
    directory: &std::path::Path,
    credential: &str,
    gateway: &str,
) {
    let path = directory.join("garrison.toml");
    let plain = std::fs::read_to_string(&path).unwrap();
    let setup = || {
        let output = run(
            directory,
            &[
                "stalwart",
                "setup",
                "--admin-credential",
                credential,
                "--webhook-url",
                "http://127.0.0.1:9/webhook",
                "--allow-network",
                gateway,
                "--skip-metrics",
            ],
        );
        (output.status.code(), text(&output))
    };
    let before = milters(lab).len();

    // Nothing listens on the filter's port: setup changes nothing at all.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let with_filter = format!("{plain}\n[milter]\nport = {port}\nwhen_unreachable = \"accept\"\n");
    std::fs::write(&path, &with_filter).unwrap();
    let (code, output) = setup();
    assert_eq!(code, Some(1), "{output}");
    assert!(
        output.contains(&format!(
            "The macro milter does not answer on 127.0.0.1:{port}"
        )),
        "{output}"
    );
    assert!(!output.contains("- updated"), "{output}");
    assert_eq!(milters(lab).len(), before);

    // The filter runs: Stalwart is told of it, as the configuration has it.
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        garrison_milter::server::serve(
            &listener,
            garrison_milter::Settings {
                max_bytes: 1024,
                ..Default::default()
            },
        );
    });
    let (code, output) = setup();
    assert_eq!(code, Some(0), "{output}");
    assert!(
        output.contains(&format!("- entered the macro milter (127.0.0.1:{port})")),
        "{output}"
    );
    let entered = at(lab, port);
    assert_eq!(entered.len(), 1, "{entered:?}");
    let entry = &entered[0];
    let id = entry["id"].as_str().unwrap().to_owned();
    lab.created.push(("MtaMilter".into(), id.clone()));
    assert_eq!(milters(lab).len(), before + 1);
    assert_eq!(entry["host"], "127.0.0.1");
    assert_eq!(entry["tempFailOnError"], false);
    assert_eq!(entry["enable"], json!({"match": {}, "else": "true"}));
    assert_eq!(entry["stages"], json!({"data": true}));

    let id = found_by_its_address(lab, &setup, id, port, before);

    // Once more, with mail deferred while the filter is away: the same entry.
    std::fs::write(
        &path,
        with_filter.replace("when_unreachable = \"accept\"\n", ""),
    )
    .unwrap();
    let (code, output) = setup();
    assert_eq!(code, Some(0), "{output}");
    assert!(
        output.contains("- updated the macro milter's entry"),
        "{output}"
    );
    let updated = at(lab, port);
    assert_eq!(updated.len(), 1, "{updated:?}");
    assert_eq!(updated[0]["id"], id.as_str());
    assert_eq!(updated[0]["tempFailOnError"], true);
    // Stalwart would ask it for the tests after this one.
    std::fs::write(&path, &plain).unwrap();
    lab.call("x:MtaMilter/set", &json!({ "destroy": [id] }));
    lab.call(
        "x:Action/set",
        &json!({"create": {"r": {"@type": "ReloadSettings"}}}),
    );
    lab.created.retain(|(_, known)| *known != id);
}

/// A second entry for the filter beside it, as an earlier release left one,
/// and the first switched off by hand: setup finds both by the address they
/// ask, leaves one and switches it on. Its ID.
fn found_by_its_address(
    lab: &mut Lab,
    setup: &impl Fn() -> (Option<i32>, String),
    id: String,
    port: u16,
    before: usize,
) -> String {
    let second = lab.create(
        "MtaMilter",
        &json!({"host": "127.0.0.1", "port": port, "tempFailOnError": true}),
    );
    let mut off = serde_json::Map::new();
    off.insert(
        id.clone(),
        json!({"enable": {"match": {}, "else": "false"}}),
    );
    lab.call("x:MtaMilter/set", &json!({ "update": off }));
    let (code, output) = setup();
    assert_eq!(code, Some(0), "{output}");
    assert!(
        output.contains("took another entry for it out of Stalwart"),
        "{output}"
    );
    let left = at(lab, port);
    assert_eq!(left.len(), 1, "{left:?}");
    let kept = left[0]["id"].as_str().unwrap().to_owned();
    assert!(kept == id || kept == second, "{kept}");
    let gone = if kept == id { second } else { id };
    lab.created.retain(|(_, known)| *known != gone);
    assert_eq!(milters(lab).len(), before + 1);
    assert_eq!(left[0]["enable"], json!({"match": {}, "else": "true"}));
    assert_eq!(left[0]["tempFailOnError"], false);
    kept
}

/// Stalwart's milter entries, as the lab's administrator reads them.
fn milters(lab: &Lab) -> Vec<serde_json::Value> {
    lab.call("x:MtaMilter/get", &json!({"ids": null}))["list"]
        .as_array()
        .unwrap()
        .clone()
}

/// Those that ask 127.0.0.1 at `port`.
fn at(lab: &Lab, port: u16) -> Vec<serde_json::Value> {
    milters(lab)
        .into_iter()
        .filter(|entry| entry["host"] == "127.0.0.1" && entry["port"] == port)
        .collect()
}
