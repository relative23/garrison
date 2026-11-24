//! Every stop of a setup run that changes the macro filter's entries: at
//! each of its requests that changes an entry and at Stalwart's reading of
//! its settings, in each of the three ways. The next plain run, which reads
//! what Stalwart holds as the stopped one did, finishes it. The lab cannot
//! make the runs that need to see where a running filter listens, which
//! only root can: a move of the filter and its switching off.

use garrison_testing::lab::Lab;

use super::Setup;
use super::entries::{LOOPBACK, Ports, State, arrange, faults, in_vain, milters, plain};
use super::stopper::Stop;

/// Each run that changes the filter's entries, stopped at each such request.
pub(super) fn every_stop(lab: &Lab, setup: &Setup, ports: &Ports, found: &mut Vec<String>) {
    let filter = ports.filter;
    let runs: [(&str, State<'_>); 3] = [
        (
            "switched on",
            State {
                milter: true,
                entries: &[],
            },
        ),
        (
            "written anew under another name",
            State {
                milter: true,
                entries: &[("g", "localhost", filter)],
            },
        ),
        (
            "kept, with a second one taken out",
            State {
                milter: true,
                entries: &[("g", LOOPBACK, filter), ("d", LOOPBACK, filter)],
            },
        ),
    ];
    for (run, state) in runs {
        arrange(lab, setup, ports, &state);
        let (_, said, asked) = plain(lab, setup, ports, &state, None);
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
    let (code, said, _) = plain(lab, setup, ports, state, Some((at, stop)));
    let after = milters(lab, ports);
    let read =
        reading.is_some_and(|reading| reading < at || (reading == at && stop != Stop::Unreachable));
    let asked_now = if read { &after } else { &before };
    let mut wrong = Vec::new();
    if code == Some(0) && !in_vain(asked_now, ports).is_empty() {
        wrong.push("success while Stalwart asks in vain".to_owned());
    }
    let next = milters(lab, ports);
    let (next_code, again, asked) = plain(lab, setup, ports, state, None);
    let last = milters(lab, ports);
    wrong.extend(
        faults(state, ports, (next_code, &again, &asked), (&next, &last))
            .into_iter()
            .map(|fault| format!("the next run: {fault}: {again}")),
    );
    if next_code != Some(0) {
        wrong.push(format!("the next run failed: {again}"));
    }
    (!wrong.is_empty()).then(|| format!("{}\n{said}", wrong.join("; ")))
}
