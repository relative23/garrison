//! The policy's size: no command writes a policy larger than the broker
//! reads, and one that is larger, as an earlier release could write it, is
//! said with its bound and the backup that mends it.

use serde_json::{Value, json};

use super::support::{prepared, run, text};

/// As much as the broker reads of the policy.
const MOST: usize = 64 * 1024;

/// The size of `document` as `garrison access` writes it.
fn written(document: &Value) -> usize {
    serde_json::to_string_pretty(document).unwrap().len() + 1
}

/// `document` with one more right required by a profile of its own, whose
/// name is `length` characters long.
fn padded(document: &Value, number: usize, length: usize) -> Value {
    let mut next = document.clone();
    let profiles = next["profiles"].as_object_mut().unwrap();
    let profile = profiles
        .entry(format!("pad{}", number / 127))
        .or_insert_with(
            || json!({"modules": [], "actions": [], "requiredNativePermissions": ["authenticate"]}),
        );
    let required = profile["requiredNativePermissions"].as_array_mut().unwrap();
    required.push(json!(format!("sys{number:0>width$}", width = length - 3)));
    next
}

/// The standard policy filled with profiles of its own to the most the
/// broker reads, as the command writes it, or a few bytes less.
fn nearly_full() -> Value {
    let mut document = garrison_testing::policy_document();
    let mut number = 0;
    while written(&padded(&document, number, 128)) <= MOST {
        document = padded(&document, number, 128);
        number += 1;
    }
    (8..128)
        .rev()
        .map(|length| padded(&document, number, length))
        .find(|document| written(document) <= MOST)
        .unwrap_or(document)
}

/// A change that would take the policy past what the broker reads is not
/// saved; a policy that is larger already is said with its bound and the
/// backup beside it.
#[test]
fn no_command_writes_a_policy_larger_than_the_broker_reads() {
    let directory = prepared();
    let path = directory.path().join("policy.json");
    let full = nearly_full();
    garrison_testing::write_private(&path, full.to_string().as_bytes());
    let listed = run(directory.path(), &["access", "list"]);
    assert_eq!(text(&listed.stdout).len(), written(&full));
    assert!(written(&full) > MOST - 140, "{}", written(&full));
    let before = std::fs::read(&path).unwrap();
    let subject = "s".repeat(128);
    let denied = run(directory.path(), &["access", "deny", &subject]);
    assert_eq!(
        (denied.status.code(), text(&denied.stderr)),
        (
            Some(1),
            format!(
                "The policy would be larger than the broker reads (64 KiB): the change is not \
                 saved, and {} stays as it is.\n",
                path.display()
            )
        )
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut over = full;
    over["deniedSubjects"] = json!([subject]);
    let text_of = serde_json::to_string_pretty(&over).unwrap();
    assert!(text_of.len() > MOST);
    garrison_testing::write_private(&path, text_of.as_bytes());
    let undone = run(directory.path(), &["access", "deny", &subject, "--undo"]);
    assert_eq!(
        (undone.status.code(), text(&undone.stderr)),
        (
            Some(1),
            format!(
                "The access policy {} is larger than the broker reads (64 KiB), so it is no \
                 policy: copy back the last backup beside it ({}.<time>.bak) with sudo cp.\n",
                path.display(),
                path.display()
            )
        )
    );
}

/// The broker and `garrison access` read the policy to one bound, each with
/// a constant of its own: a policy of 64 KiB is one for both, and a byte
/// more is none for either.
#[test]
fn the_commands_and_the_broker_read_the_policy_to_one_bound() {
    let directory = prepared();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let broker = garrison_authz::Authority::new(&config, garrison_testing::credentials(&config));
    let path = directory.path().join("policy.json");
    let document = garrison_testing::policy_document().to_string();
    for size in [MOST, MOST + 1] {
        let padded = document.clone() + &" ".repeat(size - document.len());
        garrison_testing::write_private(&path, padded.as_bytes());
        // update reads the policy as every command that changes it does.
        let updated = run(directory.path(), &["access", "update"]);
        assert_eq!(
            (broker.policy().is_ok(), updated.status.success()),
            (size == MOST, size == MOST),
            "{size}: {}",
            text(&updated.stderr)
        );
    }
}
