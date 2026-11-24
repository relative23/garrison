//! Every stop of a setup run that changes the macro filter's entry: at
//! each of its requests that changes an entry and at Stalwart's reading of
//! its settings, in each of the three ways. A run that changed what Stalwart
//! holds and stopped before Stalwart read it leaves setup's note marked, and
//! the next plain run mends it.

use garrison_testing::lab::Lab;

use super::Setup;
use super::entries::{Note, Ports, State, arrange, faults, in_vain, milters, noted, through};
use super::stopper::Stop;

/// Each run that changes the filter's entry, stopped at each such request.
pub(super) fn every_stop(lab: &Lab, setup: &Setup, ports: &Ports, found: &mut Vec<String>) {
    let (filter, old) = (ports.filter, ports.old);
    let runs: [(&str, State<'_>); 4] = [
        (
            "switched on",
            State {
                milter: true,
                note: Note::Missing,
                entries: &[],
            },
        ),
        (
            "moved to the filter's new port",
            State {
                milter: true,
                note: Note::Garrisons,
                entries: &[("g", old)],
            },
        ),
        (
            "kept where it is",
            State {
                milter: true,
                note: Note::Garrisons,
                entries: &[("g", filter)],
            },
        ),
        (
            "switched off",
            State {
                milter: false,
                note: Note::Garrisons,
                entries: &[("g", filter)],
            },
        ),
    ];
    for (run, state) in runs {
        arrange(lab, setup, ports, &state);
        let (_, said, asked) = through(lab, setup, ports, state.milter, None);
        let changes: Vec<usize> = asked
            .iter()
            .enumerate()
            .filter(|(_, request)| {
                request.starts_with("x:MtaMilter/set") || request.as_str() == "x:Action/set create"
            })
            .map(|(index, _)| index + 1)
            .collect();
        let reading = asked
            .iter()
            .position(|request| request == "x:Action/set create")
            .map(|index| index + 1);
        if changes.len() < 2 || reading.is_none() {
            found.push(format!(
                "{run}: no change and reading of settings seen in {asked:?}\n{said}"
            ));
            continue;
        }
        for at in changes {
            for stop in [Stop::Interrupted, Stop::Lost, Stop::Unreachable] {
                let wrong = stopped_once(lab, setup, ports, &state, reading, (at, stop));
                if let Some(wrong) = wrong {
                    found.push(format!("{run}, stopped {stop:?} at request {at}: {wrong}"));
                }
            }
        }
    }
}

/// One run of `state` stopped at request `at` as `stop` says, Stalwart
/// reading its settings at request `reading`, and the plain run after it:
/// what is wrong, with what the stopped run said.
fn stopped_once(
    lab: &Lab,
    setup: &Setup,
    ports: &Ports,
    state: &State<'_>,
    reading: Option<usize>,
    (at, stop): (usize, Stop),
) -> Option<String> {
    arrange(lab, setup, ports, state);
    let before = milters(lab, ports);
    let (code, said, _) = through(lab, setup, ports, state.milter, Some((at, stop)));
    let after = milters(lab, ports);
    let read =
        reading.is_some_and(|reading| reading < at || (reading == at && stop != Stop::Unreachable));
    let asked_now = if read { &after } else { &before };
    let note = noted(setup);
    let mut wrong = Vec::new();
    if asked_now != &after && !note.as_deref().is_some_and(|held| held.starts_with('!')) {
        wrong.push(format!(
            "Stalwart holds other entries than it asks, and the note is {note:?}"
        ));
    }
    if code == Some(0) && !in_vain(asked_now, ports).is_empty() {
        wrong.push("success while Stalwart asks in vain".to_owned());
    }
    let next = milters(lab, ports);
    let (next_code, again, _) = through(lab, setup, ports, state.milter, None);
    let last = milters(lab, ports);
    wrong.extend(
        faults(
            state,
            ports,
            (next_code, &again),
            (&next, &last),
            noted(setup).as_deref(),
        )
        .into_iter()
        .map(|fault| format!("the next run: {fault}: {again}")),
    );
    if next_code != Some(0) {
        wrong.push(format!("the next run failed: {again}"));
    }
    (!wrong.is_empty()).then(|| format!("{}\n{said}", wrong.join("; ")))
}
