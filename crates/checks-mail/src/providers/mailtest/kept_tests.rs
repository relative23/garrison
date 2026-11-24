//! What is kept between runs: a test is sent again once it is due, one
//! that did not happen within the hour, and results kept by an earlier
//! release are used with their one time.

use super::tests::{collected, provider, results, server};
use super::*;
use crate::context::Memory;
use crate::testing::{Remembered, assert_dated, now, table};

/// The time each test was sent at, as the table's second column has it.
fn sent(observation: &Observation) -> Vec<&str> {
    let rows = &observation.table.as_ref().unwrap().rows;
    rows.iter().map(|row| row[1].as_str().unwrap()).collect()
}

#[test]
fn a_test_is_repeated_only_after_its_hours_and_no_session_is_no_result() {
    // Nothing listens there: unknown, with the reason, and tried again
    // within the hour. Port 9, as the tests' Stalwart: a port given up by a
    // listener of this test may be taken by another test's server meanwhile.
    let none = collected(&provider(9), &Remembered::default(), 0, &[]);
    assert_eq!(none.state, State::Unknown);
    assert!(
        results(&none)[0].starts_with("not tested: no session: "),
        "{:?}",
        results(&none)
    );
    assert_dated(&none, 0, AGAIN);
    // Tests that did not happen are no result to keep for a day: they are
    // tried again within the hour, not sooner.
    let (port, handle) = server([
        "at RCPT: 451 4.7.1 not now",
        "at RCPT: 451 4.7.1 not now",
        "550 no",
        "550 no",
        "250 2.0.0 Message queued with id c.",
    ]);
    let provider = provider(port);
    let memory = Remembered::default();
    let turned_away = collected(&provider, &memory, 0, &[]);
    assert_eq!(turned_away.state, State::Unknown);
    assert_dated(&turned_away, 0, AGAIN);
    assert_eq!(
        collected(&provider, &memory, AGAIN - 1, &[]).state,
        State::Unknown
    );
    let tested = collected(&provider, &memory, AGAIN, &[]);
    assert_eq!(tested.state, State::Ok);
    assert_dated(&tested, AGAIN, 86_400);
    // Tests that happened are repeated only after their hours: a session
    // before that would find nobody listening and change the result.
    assert_eq!(handle.join().unwrap().len(), 5);
    let kept = collected(&provider, &memory, AGAIN + 86_399, &[]);
    assert_eq!(results(&kept), results(&tested));
    let (port, handle) = server([
        "550 again",
        "550 again",
        "250 2.0.0 Message queued with id d.",
    ]);
    let next = collected(&self::provider(port), &memory, AGAIN + 86_400, &[]);
    assert_eq!(results(&next)[0], "refused: 550 again");
    handle.join().unwrap();
}

#[test]
fn results_kept_by_an_earlier_release_are_used_with_their_one_time() {
    // As 0.1.2 kept them: one time for the round, none for each test, and no
    // harmless message beside the refusals.
    let memory = Remembered::default();
    let refused =
        |reply: &str| json!({"reply": reply, "code": 550, "queue": null, "at_data": true});
    let kept = json!({
        "at": now().as_second(),
        "eicar": refused("550 virus"),
        "gtube": refused("550 spam"),
        "macros": null,
    });
    memory.keep(MEMORY, &kept.to_string());
    // The next run sends the harmless message alone; the tests stay.
    let (port, handle) = server(["250 2.0.0 Message queued with id c."]);
    let used = collected(&provider(port), &memory, 60, &[]);
    assert_eq!(
        results(&used),
        ["refused: 550 virus", "refused: 550 spam", "accepted"]
    );
    assert_eq!(
        sent(&used),
        [
            "2026-10-29T12:00:00+00:00",
            "2026-10-29T12:00:00+00:00",
            "2026-10-29T12:01:00+00:00"
        ]
    );
    assert_dated(&used, 60, 86_400 - 60);
    let sessions = handle.join().unwrap();
    assert!(
        sessions[0].contains("Harmless message (control)"),
        "{}",
        sessions[0]
    );
}

#[test]
fn results_for_another_listener_recipient_or_sender_are_not_kept() {
    // The results kept for a day are those of the tests as configured: each
    // change of where they go or come from sends them anew in the next run.
    let taken = "250 2.0.0 Message queued with id c.";
    let (port, handle) = server([
        "550 a", "550 a", taken, "550 b", "550 b", taken, "550 c", "550 c", taken,
    ]);
    let made = |port: u16, options: &str| {
        MailTest::new(&table(&format!(
            "type = \"mail-test\"\nport = {port}\n{options}"
        )))
        .unwrap()
    };
    let memory = Remembered::default();
    let other = "recipient = \"other-test@example.test\"";
    let sender = format!("{other}\nsender = \"garrison@example.test\"");
    for (later, options, result) in [
        (
            0,
            "recipient = \"garrison-test@example.test\"",
            "refused: 550 a",
        ),
        (60, other, "refused: 550 b"),
        (120, sender.as_str(), "refused: 550 c"),
    ] {
        let card = collected(&made(port, options), &memory, later, &[]);
        assert_eq!(results(&card), [result, result, "accepted"], "{options}");
    }
    let sessions = handle.join().unwrap();
    assert!(
        sessions[3].contains("RCPT TO:<other-test@example.test>"),
        "{}",
        sessions[3]
    );
    assert!(
        sessions[6].contains("MAIL FROM:<garrison@example.test>"),
        "{}",
        sessions[6]
    );
    // Another host, where nothing listens on that port: a session is
    // tried, and the results of the last are not shown.
    let elsewhere = format!("{sender}\nhost = \"127.0.0.2\"");
    let tried = collected(&made(port, &elsewhere), &memory, 180, &[]);
    assert!(
        results(&tried)
            .iter()
            .all(|result| result.starts_with("not tested: no session: ")),
        "{:?}",
        results(&tried)
    );
    // And another port.
    let (moved, handle) = server(["550 d", "550 d", taken]);
    let card = collected(&made(moved, &sender), &memory, 240, &[]);
    assert_eq!(
        results(&card),
        ["refused: 550 d", "refused: 550 d", "accepted"]
    );
    handle.join().unwrap();
}

#[test]
fn only_the_test_that_did_not_happen_is_tried_again() {
    // The test file is refused as it must be; the session for the spam text
    // is turned away before its message.
    let (port, handle) = server([
        "550 virus",
        "at RCPT: 451 4.7.1 try later",
        "250 2.0.0 Message queued with id c.",
        "550 5.7.1 spam",
        "250 2.0.0 Message queued with id d.",
    ]);
    let memory = Remembered::default();
    let first = collected(&provider(port), &memory, 0, &[]);
    assert_eq!(first.state, State::Unknown);
    assert_eq!(
        results(&first),
        [
            "refused: 550 virus",
            "not tested: 451 4.7.1 try later",
            "accepted"
        ]
    );
    assert_dated(&first, 0, AGAIN);
    // An hour later the spam text alone, with a harmless message after its
    // refusal, and the test file's result stays the one of its own session.
    let again = collected(&provider(port), &memory, AGAIN, &[]);
    let sessions = handle.join().unwrap();
    assert_eq!(sessions.len(), 5);
    assert!(sessions[3].contains("GTUBE"), "{}", sessions[3]);
    assert_eq!(again.state, State::Ok);
    assert_eq!(
        results(&again),
        ["refused: 550 virus", "refused: 550 5.7.1 spam", "accepted"]
    );
    assert_eq!(
        sent(&again),
        [
            "2026-10-29T12:00:00+00:00",
            "2026-10-29T13:00:00+00:00",
            "2026-10-29T13:00:00+00:00"
        ]
    );
    // The test file is due first, a day after its own session.
    assert_dated(&again, AGAIN, 86_400 - AGAIN);
}
