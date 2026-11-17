//! The macro filter's entry, as `stalwart setup` makes and takes it out.

use garrison_testing::lab::Lab;
use serde_json::json;

use super::{run, text};

/// The macro filter's entry in Stalwart follows the configuration: none while
/// the filter does not answer, one while the `[milter]` section is there,
/// found by its address where setup's note is gone, changed in place, and
/// none again once the section is gone.
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
    let note = directory.join("credentials/stalwart-milter-id");

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
    assert!(!note.exists());

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
    let id = std::fs::read_to_string(&note).unwrap().trim().to_owned();
    lab.created.push(("MtaMilter".into(), id.clone()));
    let entered = milters(lab);
    assert_eq!(entered.len(), before + 1);
    let entry = entered
        .iter()
        .find(|entry| entry["id"] == id.as_str())
        .unwrap();
    assert_eq!(entry["host"], "127.0.0.1");
    assert_eq!(entry["port"], port);
    assert_eq!(entry["tempFailOnError"], false);
    assert_eq!(entry["enable"], json!({"match": {}, "else": "true"}));
    assert_eq!(entry["stages"], json!({"data": true}));

    let id = found_by_its_address(lab, &setup, &note, id, port, before);

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
    let updated = milters(lab);
    assert_eq!(updated.len(), before + 1);
    let entry = updated
        .iter()
        .find(|entry| entry["id"] == id.as_str())
        .unwrap();
    assert_eq!(entry["tempFailOnError"], true);

    // The section is gone: so are the entry, another for the same filter,
    // and setup's note of it.
    let more = lab.create(
        "MtaMilter",
        &json!({"host": "127.0.0.1", "port": port, "tempFailOnError": true}),
    );
    std::fs::write(&path, &plain).unwrap();
    let (code, output) = setup();
    assert_eq!(code, Some(0), "{output}");
    assert!(
        output.contains("- took the macro milter's 2 entries out of Stalwart"),
        "{output}"
    );
    lab.created
        .retain(|(_, known)| *known != id && *known != more);
    assert_eq!(milters(lab).len(), before);
    assert!(!note.exists());
}

/// Setup's note lost, a second entry for the filter beside it, as an
/// earlier release left one, and the first switched off by hand: setup
/// finds its entry by the address it asks, leaves one and switches it on.
/// Its ID, which setup notes again.
fn found_by_its_address(
    lab: &mut Lab,
    setup: &impl Fn() -> (Option<i32>, String),
    note: &std::path::Path,
    id: String,
    port: u16,
    before: usize,
) -> String {
    std::fs::remove_file(note).unwrap();
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
    assert!(output.contains("found by its address"), "{output}");
    assert!(
        output.contains("took another entry for it out of Stalwart"),
        "{output}"
    );
    let kept = std::fs::read_to_string(note).unwrap().trim().to_owned();
    assert!(kept == id || kept == second, "{kept}");
    let gone = if kept == id { second } else { id };
    lab.created.retain(|(_, known)| *known != gone);
    let left = milters(lab);
    assert_eq!(left.len(), before + 1);
    let entry = left
        .iter()
        .find(|entry| entry["id"] == kept.as_str())
        .unwrap();
    assert_eq!(entry["enable"], json!({"match": {}, "else": "true"}));
    assert_eq!(entry["tempFailOnError"], false);
    kept
}

/// Stalwart's milter entries, as the lab's administrator reads them.
fn milters(lab: &Lab) -> Vec<serde_json::Value> {
    lab.call("x:MtaMilter/get", &json!({"ids": null}))["list"]
        .as_array()
        .unwrap()
        .clone()
}
