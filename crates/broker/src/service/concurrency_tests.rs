//! Submissions that arrive at the same moment. The audit decides which comes
//! first; each of the others gets the answer it would get one after the
//! other, and no job is accepted or run twice.

use std::sync::Barrier;
use std::thread;

use serde_json::Value;

use super::tests::{REQUEST, Setup, make, sent};
use super::*;

/// Often enough for the threads to meet in different orders.
const ROUNDS: usize = 25;

/// A submission: token, action, request ID and confirmation phrase.
type Submission<'a> = (&'a str, &'a str, &'a str, &'a str);

/// Each of `submissions` on a thread of its own, all let go at once; the
/// answers in the order of the submissions.
fn together(setup: &Setup, submissions: &[Submission<'_>]) -> Vec<Result<Value, BrokerError>> {
    let start = Barrier::new(submissions.len());
    thread::scope(|scope| {
        let asking: Vec<_> = submissions
            .iter()
            .map(|&(token, action, request, phrase)| {
                let (broker, start) = (&setup.broker, &start);
                scope.spawn(move || {
                    start.wait();
                    broker.submit(token, action, request, phrase).map(sent)
                })
            })
            .collect();
        asking
            .into_iter()
            .map(|asked| asked.join().unwrap())
            .collect()
    })
}

fn jobs(setup: &Setup) -> i64 {
    setup.broker.audit().count().unwrap()
}

/// The two maintenance actions of the test broker, each with its own request.
fn two_actions(other: &str) -> [Submission<'_>; 2] {
    [
        ("admin-token", "run_monitor", REQUEST, "RUN HEALTH CHECKS"),
        ("admin-token", "run_backup", other, "RUN BACKUP"),
    ]
}

#[test]
fn of_two_jobs_submitted_at_once_one_is_accepted_and_the_other_waits_its_turn() {
    let other = REQUEST.replace("0b3f", "3b3f");
    for _ in 0..ROUNDS {
        // The accepted job stays queued: the other finds it in the way.
        let setup = make(true);
        let answers = together(&setup, &two_actions(&other));
        let refused: Vec<(u16, &str)> = answers
            .iter()
            .filter_map(|answer| answer.as_ref().err())
            .map(|error| (error.status, error.message.as_str()))
            .collect();
        assert_eq!(
            refused,
            [(409, "Another maintenance operation is in progress")],
            "{answers:?}"
        );
        assert_eq!(jobs(&setup), 1);
        assert_eq!(setup.queue.as_ref().unwrap().lock().unwrap().len(), 1);
    }
}

#[test]
fn of_two_jobs_submitted_at_once_that_run_at_once_one_runs() {
    let other = REQUEST.replace("0b3f", "3b3f");
    for _ in 0..ROUNDS {
        // The accepted job runs on the thread that submitted it, while the
        // other asks: that one finds it running, or just finished and the
        // time to settle not over.
        let setup = make(false);
        let answers = together(&setup, &two_actions(&other));
        let refused: Vec<u16> = answers
            .iter()
            .filter_map(|answer| answer.as_ref().err())
            .map(|error| error.status)
            .collect();
        assert!(refused == [409] || refused == [429], "{answers:?}");
        assert_eq!(jobs(&setup), 1);
        assert_eq!(setup.systemd.runs.lock().unwrap().len(), 1);
    }
}

#[test]
fn one_request_sent_twice_at_once_is_one_job_that_runs_once() {
    for _ in 0..ROUNDS {
        let setup = make(true);
        let request = ("admin-token", "run_monitor", REQUEST, "RUN HEALTH CHECKS");
        let answers: Vec<Value> = together(&setup, &[request, request])
            .into_iter()
            .map(Result::unwrap)
            .collect();
        // Both answers name the one job; the later says it was a replay.
        assert_eq!(answers[0]["job"]["id"], answers[1]["job"]["id"]);
        let mut replayed: Vec<bool> = answers
            .iter()
            .map(|answer| answer["replayed"].as_bool().unwrap())
            .collect();
        replayed.sort_unstable();
        assert_eq!(replayed, [false, true], "{answers:?}");
        assert_eq!(jobs(&setup), 1);
        let work: Vec<_> = setup
            .queue
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .drain(..)
            .collect();
        assert_eq!(work.len(), 1);
        for job in work {
            job();
        }
        assert_eq!(*setup.systemd.runs.lock().unwrap(), ["run_monitor"]);
    }
}
