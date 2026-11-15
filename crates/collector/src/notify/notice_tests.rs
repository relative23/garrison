//! A receiver that ends TLS without its closing notice and gives its answer
//! no length, as Python's `http.server` behind `ssl` does: the answer may be
//! cut anywhere after it began, but not in its status line, which is all a
//! notification needs. A complete head with a 2xx status has taken the
//! message; an incomplete one, or another status, has not.

use std::sync::Arc;

use garrison_testing::tls::{Server, serve_without_notice};

use super::tests::observed;
use super::*;
use crate::testing::{Remembered, now};

/// What Python's `http.server` behind `ssl` answers: no length, and the
/// connection ends with the body.
const NO_LENGTH: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";

/// The channels that send on `receiver`'s ntfy topic or webhook alone.
fn on(receiver: &Server, webhook: bool) -> Channels {
    let address = Some(Address {
        url: format!("{}/mailserver", receiver.url),
        token: Secret::Empty,
        ..Address::default()
    });
    Channels {
        host: "garrison.example.org".to_owned(),
        ntfy: if webhook { None } else { address.clone() },
        webhook: if webhook { address } else { None },
        mail: None,
    }
}

/// The channel's observation after three runs with a check that fails: the
/// second has the message to send; and how many messages the receiver took.
fn three_runs(answers: Vec<String>, webhook: bool) -> (Observation, usize) {
    let receiver = serve_without_notice(answers);
    let channels = on(&receiver, webhook);
    let roots = Arc::new(receiver.roots.clone());
    let memory = Remembered::default();
    let failing = [observed("backup", State::Failed, "The last run failed.")];
    let run =
        || after_run_with(&channels, &failing, &memory, now(), &roots, Deadline::NONE).unwrap();
    run();
    run();
    let third = run();
    (third, receiver.finish())
}

#[test]
fn a_complete_head_taken_by_ntfy_or_a_webhook_is_a_message_sent() {
    for webhook in [false, true] {
        let answers = vec![NO_LENGTH.to_owned(), NO_LENGTH.to_owned()];
        let (channel, taken) = three_runs(answers, webhook);
        // Told once, and not again.
        assert_eq!(channel.state, State::Ok, "{:?}", channel.findings);
        assert_eq!(channel.findings, Vec::<String>::new());
        assert_eq!(taken, 1, "webhook: {webhook}");
    }
    // Any 2xx is the webhook's taking, its head complete.
    let accepted = "HTTP/1.1 202 Accepted\r\n\r\n";
    let (channel, taken) = three_runs(vec![accepted.to_owned(), accepted.to_owned()], true);
    assert_eq!((channel.state, taken), (State::Ok, 1));
}

#[test]
fn a_cut_head_or_another_status_is_no_message_sent() {
    for (answer, said) in [
        (
            "HTTP/1.1 200 OK\r\nContent-Type: appl",
            "the connection ended before its answer was whole",
        ),
        (
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nbroken",
            "it answered 500",
        ),
    ] {
        let (channel, taken) = three_runs(vec![answer.to_owned(), answer.to_owned()], false);
        assert_eq!(channel.state, State::Failed, "{answer}");
        assert_eq!(
            channel.findings,
            [format!(
                "The last notification did not go out: ntfy: {said}."
            )]
        );
        // Not taken, so the next run sends it again.
        assert_eq!(taken, 2, "{answer}");
    }
}

/// `garrison notify-test` says what each channel took, from the same
/// sending.
#[test]
fn the_test_message_counts_as_out_where_the_head_arrived() {
    let receiver = serve_without_notice(vec![NO_LENGTH.to_owned()]);
    let channels = on(&receiver, false);
    let roots = Arc::new(receiver.roots.clone());
    let note = Note::plain("test".to_owned(), "test".to_owned(), Level::Good);
    let outcomes = channels.send_with(&note, now(), &roots, Deadline::NONE);
    assert_eq!(outcomes, [("ntfy", Ok(()))]);
    assert_eq!(receiver.finish(), 1);
}
