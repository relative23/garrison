use garrison_core::modules::ModuleId;
use garrison_core::observations::{Evidence, Required, State};
use serde_json::json;

use super::*;
use crate::context::Memory;
use crate::testing::{Canned, Remembered, assert_dated, config, now};

/// An answer as a check keeps one: fields of its own, one of them optional.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
struct Answer {
    count: u32,
    problem: Option<String>,
}

const KEY: &str = "test.answer";
const EVERY: i64 = 600;
const AGAIN: i64 = 60;

fn wait(_: i64, answer: &Answer) -> i64 {
    if answer.problem.is_some() {
        AGAIN
    } else {
        EVERY
    }
}

/// The answer `later` seconds after the tests' clock; `ask` runs only where
/// the kept one is not used.
fn asked(
    memory: &Remembered,
    later: i64,
    ask: impl FnOnce(Option<(i64, Answer)>) -> Answer,
) -> Kept<Answer> {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let runner = Canned(String::new());
    let context = Context {
        now: Timestamp::from_second(now().as_second() + later).unwrap(),
        memory,
        ..crate::testing::context(&config, &runner)
    };
    cached(&context, KEY, wait, ask)
}

fn fine(count: u32) -> Answer {
    Answer {
        count,
        problem: None,
    }
}

#[test]
fn an_answer_is_used_for_its_time_and_then_asked_again() {
    let memory = Remembered::default();
    let start = now().as_second();
    let first = asked(&memory, 0, |before| {
        assert_eq!(before, None);
        fine(1)
    });
    assert_eq!(
        (first.at, first.wait, first.answer.count),
        (start, EVERY, 1)
    );
    // It is kept as its own fields with the time beside them.
    let stored: serde_json::Value = serde_json::from_str(&memory.recall(KEY).unwrap()).unwrap();
    assert_eq!(stored, json!({"at": start, "count": 1, "problem": null}));
    // Until its time is up nothing is asked, and it is as old as it is.
    let kept = asked(&memory, EVERY - 1, |_| panic!("asked again too soon"));
    assert_eq!(kept, first);
    // Then it is asked again, and what was kept is handed over.
    let next = asked(&memory, EVERY, |before| {
        assert_eq!(before, Some((start, fine(1))));
        fine(2)
    });
    assert_eq!((next.at, next.answer.count), (start + EVERY, 2));
}

#[test]
fn a_failure_is_tried_again_sooner_and_an_answer_from_ahead_is_not_used() {
    let memory = Remembered::default();
    let failed = Answer {
        count: 0,
        problem: Some("no answer".to_owned()),
    };
    let first = asked(&memory, 0, |_| failed.clone());
    assert_eq!(first.wait, AGAIN);
    assert_eq!(
        asked(&memory, AGAIN - 1, |_| panic!("too soon")).answer,
        failed
    );
    assert_eq!(asked(&memory, AGAIN, |_| fine(3)).answer.count, 3);
    // The clock went back behind the answer: it is none of this time.
    assert_eq!(asked(&memory, AGAIN - 10, |_| fine(4)).answer.count, 4);
    // What cannot be read is asked for again, as is a time no clock shows.
    for unreadable in ["", "{", "[]", r#"{"count": 1, "problem": null}"#] {
        memory.keep(KEY, unreadable);
        assert_eq!(
            asked(&memory, 0, |before| {
                assert_eq!(before, None, "{unreadable}");
                fine(5)
            })
            .answer
            .count,
            5
        );
    }
    memory.keep(
        KEY,
        &format!(r#"{{"at": {}, "count": 6, "problem": null}}"#, i64::MIN),
    );
    assert_eq!(asked(&memory, 0, |_| fine(7)).answer.count, 7);
}

#[test]
fn an_observation_is_as_old_as_its_answer_and_stale_once_the_next_is_late() {
    let observation = || {
        Observation::new(Required {
            id: "test.answer",
            provider: "test",
            title: "Answer",
            modules: [ModuleId::Services],
            evidence: Evidence::Probe,
            state: State::Ok,
            checked_at: "2026-10-29T18:00:00+00:00",
            source: "a source",
        })
        .unwrap()
    };
    let start = now().as_second();
    let kept = Kept {
        at: start,
        wait: EVERY,
        answer: (),
    };
    assert_eq!(kept.asked().as_deref(), Some("2026-10-29T12:00:00+00:00"));
    assert_dated(&kept.dated(observation()), 0, EVERY);
    // An answer that is asked in every run is stale like any other reading.
    let every_run = Kept { wait: 0, ..kept };
    assert_eq!(every_run.dated(observation()).max_age, 180);
    // A wait or a time beyond what can be stated leaves the observation whole.
    let endless = Kept {
        at: i64::MAX,
        wait: i64::MAX,
        answer: (),
    };
    let dated = endless.dated(observation());
    assert_eq!(
        (dated.checked_at.as_str(), dated.max_age),
        ("2026-10-29T18:00:00+00:00", u32::MAX)
    );
    let negative = Kept { wait: -5, ..kept };
    assert_eq!(negative.dated(observation()).max_age, 180);
}
