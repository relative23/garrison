//! A refusal changes nothing, whatever the flags: setup decides on
//! Stalwart's entries and on the filter before its first change, so a
//! refusal for another program's entry asked in vain, or for a filter that
//! cannot answer at its port, leaves Stalwart and the credentials as they
//! were, with `--rotate` too. And the note of the filter's entry that an
//! earlier release kept goes with the next run.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use garrison_testing::lab::Lab;

use super::Setup;
use super::entries::{LOOPBACK, Ports, State, arrange, changes, milters, note, plain, through};

/// The files of the credentials folder, with what each holds.
fn files(credentials: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(credentials)
        .into_iter()
        .flatten()
        .flatten()
        .map(|file| {
            let name = file.file_name().to_string_lossy().into_owned();
            (name, fs::read(file.path()).unwrap_or_default())
        })
        .collect()
}

/// Each refusal with each set of flags, and the note of an earlier release.
pub(super) fn every_refusal(lab: &Lab, setup: &Setup, ports: &Ports, found: &mut Vec<String>) {
    let credentials = setup.directory.join("credentials");
    let vain = [("g", LOOPBACK, ports.filter), ("o", LOOPBACK, ports.gone)];
    let alone = [("g", LOOPBACK, ports.filter)];
    let refusals = [
        (&vain[..], ports.filter, ports.gone),
        (&alone[..], ports.taken, ports.taken),
    ];
    let sets: [&[&str]; 4] = [
        &[],
        &["--rotate"],
        &["--skip-metrics"],
        &["--rotate", "--skip-metrics"],
    ];
    for (entries, port, named) in refusals {
        for flags in sets {
            let state = State {
                milter: true,
                entries,
            };
            arrange(lab, setup, ports, &state);
            let (before, kept) = (milters(lab, ports), files(&credentials));
            let (code, said, asked) = through(lab, setup, Some(port), None, flags);
            let mut wrong = Vec::new();
            if code == Some(0) {
                wrong.push("it did not refuse".to_owned());
            }
            if !said.contains(&format!("{LOOPBACK}:{named}")) {
                wrong.push(format!("the refusal does not name {LOOPBACK}:{named}"));
            }
            let changed = changes(&asked);
            if !changed.is_empty() {
                wrong.push(format!("it sent Stalwart {changed:?} first"));
            }
            if milters(lab, ports) != before {
                wrong.push("Stalwart's entries changed".to_owned());
            }
            if files(&credentials) != kept {
                wrong.push("the credentials changed".to_owned());
            }
            if !wrong.is_empty() {
                found.push(format!(
                    "the filter at {port}, entries {entries:?}, flags {flags:?}: {}\n{said}",
                    wrong.join("; ")
                ));
            }
        }
    }
    an_earlier_note_goes(lab, setup, ports, found);
}

/// A note of the filter's entry as 0.1.2 kept it: the next run removes it
/// and says so, since no run reads it any more.
fn an_earlier_note_goes(lab: &Lab, setup: &Setup, ports: &Ports, found: &mut Vec<String>) {
    let state = State {
        milter: true,
        entries: &[("g", LOOPBACK, ports.filter)],
    };
    let ids = arrange(lab, setup, ports, &state);
    garrison_testing::write_private(&note(setup), format!("{}\n", ids["g"]).as_bytes());
    let (code, said, _) = plain(lab, setup, ports, &state, None);
    if code != Some(0) || note(setup).exists() || !said.contains("stalwart-milter-id") {
        found.push(format!(
            "an earlier release's note: exit {code:?}, note there {}\n{said}",
            note(setup).exists()
        ));
    }
}
