//! Every state's name that an acceptance script or the Ansible role looks
//! for is one the product makes: a script that looks for a name no state has
//! fails for no reason where it looks for it, and passes for none where it
//! looks for its absence; the role would call every play changed.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::path::Path;

/// The areas whose states the scripts look for, as a name begins.
const AREAS: [&str; 17] = [
    "install",
    "upgrade",
    "setup",
    "doctor",
    "access",
    "check-config",
    "config",
    "backup-check",
    "backup",
    "self-check",
    "notify-test",
    "modules",
    "wizard",
    "switch",
    "service",
    "collect",
    "watch",
];

/// Names of commands the scripts run, which are no states.
const COMMANDS: [&str; 5] = [
    "backup-check",
    "check-config",
    "self-check",
    "notify-test",
    "stalwart-switch",
];

/// Every name the constructors in the `.rs` files below `folder` make.
fn made(folder: &Path, names: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(folder).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            made(&path, names);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            for rest in text.split("State::new(").skip(1) {
                if let Some(quoted) = rest.trim_start().strip_prefix('"') {
                    names.insert(quoted[..quoted.find('"').unwrap()].to_owned());
                }
            }
            // An entry of a `states!` table: the name after its signature.
            for rest in text.split("= \"").skip(1) {
                if let Some((name, after)) = rest.split_once('"')
                    && after.starts_with(":\n")
                    && name.contains('-')
                {
                    names.insert(name.to_owned());
                }
            }
        }
    }
}

/// The words of `text` that have a state's form: an area, a hyphen and
/// more words, neither part of a path nor of a file's name.
fn looked_for(text: &str) -> Vec<&str> {
    let word = |character: char| character.is_ascii_lowercase() || character.is_ascii_digit();
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    for (index, character) in text.char_indices().chain([(text.len(), ' ')]) {
        if word(character) || character == '-' {
            continue;
        }
        let token = &text[start..index];
        let before = start.checked_sub(1).map(|at| bytes[at]);
        let after = bytes.get(index).copied();
        let in_a_path = matches!(before, Some(b'/' | b'.')) || matches!(after, Some(b'/' | b'.'));
        let stated = AREAS.iter().any(|area| {
            token
                .strip_prefix(area)
                .and_then(|rest| rest.strip_prefix('-'))
                .is_some_and(|rest| !rest.is_empty() && !rest.ends_with('-'))
        });
        if stated && !in_a_path && !COMMANDS.contains(&token) {
            found.push(token);
        }
        start = index + character.len_utf8();
    }
    found
}

#[test]
fn every_state_a_script_looks_for_is_one_the_product_makes() {
    let crate_folder = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut names = BTreeSet::new();
    made(&crate_folder.join("src"), &mut names);
    assert!(names.contains("install-running"), "{names:?}");
    assert!(names.contains("setup-as-asked"), "{names:?}");
    let scripts = crate_folder.join("../../scripts");
    let mut readers: Vec<_> = std::fs::read_dir(&scripts)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    readers.push(crate_folder.join("../../deploy/ansible/garrison/tasks/main.yml"));
    let mut unknown = Vec::new();
    for path in readers {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for token in looked_for(&text) {
            if !names.contains(token) {
                unknown.push(format!("{}: {token}", path.display()));
            }
        }
    }
    assert_eq!(unknown, Vec::<String>::new());
}

#[test]
fn a_state_is_told_from_a_path_and_a_command() {
    assert_eq!(
        looked_for(
            "acceptance-state /root/answer install-running install-as-installed\n\
             cp /etc/garrison/access-policy.json /root/switch-room.log; garrison check-config"
        ),
        ["install-running", "install-as-installed"]
    );
}

/// The states the operators' page lists: each of its blocks holds one
/// state's whole line, which may carry other states' lines inside it, so a
/// block's state is the last name in brackets that has a state's form. A
/// block that names none is listed as it stands, which no state is called.
fn listed(page: &str) -> Vec<&str> {
    page.split("```text\n")
        .skip(1)
        .map(|rest| {
            let (entry, _) = rest.split_once("\n```").unwrap();
            entry
                .rmatch_indices(" [")
                .find_map(|(at, _)| {
                    let bracketed = &entry[at + 2..];
                    let name = &bracketed[..bracketed.find(']')?];
                    (looked_for(name) == [name]).then_some(name)
                })
                .unwrap_or(entry)
        })
        .collect()
}

#[test]
fn the_page_of_the_states_lists_each_state_once_and_no_other() {
    let crate_folder = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut states = BTreeSet::new();
    made(&crate_folder.join("src"), &mut states);
    // The tests of the table itself make states of no area.
    states.retain(|name| looked_for(name) == [name.as_str()]);
    let page = std::fs::read_to_string(crate_folder.join("../../docs/operator/states.md")).unwrap();
    let names = listed(&page);
    let once: BTreeSet<String> = names.iter().map(|name| (*name).to_owned()).collect();
    let twice: Vec<&&str> = names
        .iter()
        .filter(|name| names.iter().filter(|other| other == name).count() > 1)
        .collect();
    assert!(twice.is_empty(), "the page lists a state twice: {twice:?}");
    assert_eq!(once, states);
}

#[test]
fn a_block_of_the_page_is_the_state_its_last_name_says() {
    assert_eq!(
        listed(
            "# States\n\nOutside a block [install-io] counts for nothing.\n\n\
             ```text\nRun as root. [install-not-root]\n```\n\
             ```text\nthe clock is not synchronized [doctor-clock-unsynchronized]\n      \
             Enable a time service [see timedatectl]\n```\n\
             ```text\nStalwart asks a milter [doctor-milter-stranded]\n      Remove it.\n\
             Setup changed nothing. [setup-milter-stranded]\n```\n"
        ),
        [
            "install-not-root",
            "doctor-clock-unsynchronized",
            "setup-milter-stranded"
        ]
    );
}
