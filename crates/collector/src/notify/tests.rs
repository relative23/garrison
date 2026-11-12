use garrison_testing::http::{answer, serve};
use serde_json::{Value, json};

use super::*;
use crate::testing::{Remembered, now};

fn observed(id: &str, state: State, finding: &str) -> Observation {
    Observation::new(
        id,
        "test",
        format!("Check {id}"),
        [ModuleId::Services],
        Evidence::Process,
        state,
        time::isoformat(now()),
        "test",
    )
    .unwrap()
    .with_findings(if finding.is_empty() {
        Vec::new()
    } else {
        vec![finding.to_owned()]
    })
}

/// The channel's observation after one run against a stand-in for ntfy.
fn run(url: &str, memory: &Remembered, observations: &[Observation]) -> Observation {
    after_run(&ntfy(url), observations, memory, now()).unwrap()
}

/// The channels of an installation that names only an ntfy topic.
fn ntfy(url: &str) -> Channels {
    Channels {
        host: "garrison.example.org".to_owned(),
        ntfy: Some(Address {
            url: url.to_owned(),
            token: "token-1".to_owned(),
        }),
        ..Channels::default()
    }
}

fn body(request: &str) -> Value {
    serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap()
}

#[test]
fn a_check_is_told_after_two_runs_and_its_return_once() {
    let server = serve(vec![answer(200, "{}"), answer(200, "{}")]);
    let url = format!("{}/mailserver", server.url);
    let memory = Remembered::default();
    let failing = [
        observed("backup", State::Failed, "The last run failed."),
        observed("certificate", State::Warning, "Expires in 9 days."),
        observed("fine", State::Ok, ""),
        observed("dark", State::Unknown, "Not readable."),
    ];
    // The first run tells nothing yet; the second tells both, a third nothing more.
    let first = run(&url, &memory, &failing);
    assert_eq!(first.state, State::Ok);
    assert_eq!(first.fields[1].value, 2);
    assert_eq!(first.fields[2].value, Value::Null);
    run(&url, &memory, &failing);
    let third = run(&url, &memory, &failing);
    assert_eq!(third.fields[2].value, time::isoformat(now()));
    // Back in order: told once; the check that turned unknown stays open, untold.
    let healed = [
        observed("backup", State::Ok, ""),
        observed("certificate", State::Unknown, "Not readable."),
        observed("fine", State::Ok, ""),
    ];
    let after = run(&url, &memory, &healed);
    assert_eq!(after.fields[1].value, 1);
    run(&url, &memory, &healed);
    let requests = server.requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[0].starts_with("POST / HTTP/1.1\r\n"),
        "{}",
        requests[0]
    );
    assert!(requests[0].contains("Authorization: Bearer token-1\r\n"));
    assert_eq!(
        body(&requests[0]),
        json!({
            "topic": "mailserver",
            "title": "Garrison on garrison.example.org: 1 failed, 1 warning",
            "message": "Failed: Check backup: The last run failed.\n\
                        Warning: Check certificate: Expires in 9 days.",
            "priority": 4,
            "tags": ["rotating_light"],
        })
    );
    assert_eq!(
        body(&requests[1]),
        json!({
            "topic": "mailserver",
            "title": "Garrison on garrison.example.org: 1 in order again",
            "message": "In order again: Check backup",
            "priority": 3,
            "tags": ["white_check_mark"],
        })
    );
}

#[test]
fn a_blip_of_one_run_and_a_check_that_was_never_told_say_nothing() {
    let server = serve(Vec::new());
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    run(&url, &memory, &[observed("flaky", State::Failed, "")]);
    run(&url, &memory, &[observed("flaky", State::Ok, "")]);
    run(&url, &memory, &[observed("flaky", State::Warning, "")]);
    run(&url, &memory, &[observed("flaky", State::Failed, "")]);
    run(&url, &memory, &[]);
    assert_eq!(server.requests().len(), 0);
}

#[test]
fn a_warning_that_becomes_a_failure_is_told_again() {
    let server = serve(vec![answer(200, "{}"), answer(200, "{}")]);
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    for state in [State::Warning, State::Warning, State::Failed, State::Failed] {
        run(&url, &memory, &[observed("disk", state, "Nearly full.")]);
    }
    let requests = server.requests();
    assert_eq!(body(&requests[0])["tags"], json!(["warning"]));
    assert_eq!(body(&requests[1])["priority"], 4);
}

#[test]
fn a_message_that_does_not_go_out_is_tried_again_and_shown() {
    let server = serve(vec![answer(403, "forbidden"), answer(200, "{}")]);
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    let failing = [observed("backup", State::Failed, "")];
    run(&url, &memory, &failing);
    let refused = run(&url, &memory, &failing);
    assert_eq!(refused.state, State::Failed);
    assert_eq!(
        refused.findings,
        ["The last notification did not go out: ntfy: it answered 403."]
    );
    assert_eq!(refused.modules, [ModuleId::Alerts].into());
    // The next run sends it; the channel is in order again.
    let sent = run(&url, &memory, &failing);
    assert_eq!(sent.state, State::Ok);
    assert_eq!(sent.findings, Vec::<String>::new());
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn a_return_that_could_not_be_told_is_told_later() {
    let server = serve(vec![
        answer(200, "{}"),
        answer(500, "down"),
        answer(200, "{}"),
    ]);
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    let failing = [observed("backup", State::Failed, "")];
    let healed = [observed("backup", State::Ok, "")];
    run(&url, &memory, &failing);
    run(&url, &memory, &failing);
    run(&url, &memory, &healed);
    run(&url, &memory, &healed);
    run(&url, &memory, &healed);
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        body(&requests[2])["message"],
        "In order again: Check backup"
    );
}

#[test]
fn the_channel_does_not_tell_of_itself_and_long_news_is_cut() {
    let server = serve(vec![answer(200, "{}")]);
    let url = format!("{}/topic", server.url);
    let memory = Remembered::default();
    let mut many: Vec<Observation> = (0..30)
        .map(|index| observed(&format!("c{index:02}"), State::Failed, &"x".repeat(400)))
        .collect();
    many.push(observed("notifications.channels", State::Failed, "itself"));
    run(&url, &memory, &many);
    run(&url, &memory, &many);
    let sent = body(&server.requests()[0]);
    let message = sent["message"].as_str().unwrap();
    assert_eq!(message.lines().count(), MOST_LINES + 1);
    assert!(message.ends_with("and 10 more; see Garrison."), "{message}");
    assert!(message.lines().all(|line| line.chars().count() <= 300));
    assert!(!message.contains("Notifications"));
    assert_eq!(sent["title"], "Garrison on garrison.example.org: 30 failed");
}

#[test]
fn a_test_message_and_a_topic_without_a_token() {
    let server = serve(vec![answer(200, "{}"), answer(401, "no")]);
    let url = format!("{}/topic", server.url);
    let open = Channels {
        ntfy: Some(Address {
            url: url.clone(),
            token: String::new(),
        }),
        ..ntfy(&url)
    };
    assert_eq!(test(&open, now()), [("ntfy", Ok(()))]);
    assert_eq!(
        test(&ntfy(&url), now()),
        [("ntfy", Err("it answered 401".to_owned()))]
    );
    let requests = server.requests();
    assert!(!requests[0].contains("Authorization"), "{}", requests[0]);
    assert_eq!(
        body(&requests[0])["title"],
        "Garrison on garrison.example.org: test"
    );
}

#[test]
fn every_channel_gets_the_message_and_one_that_fails_is_named() {
    let certificates = crate::testing::certificates();
    let topic = serve(vec![answer(200, "{}")]);
    let hook = serve(vec![answer(204, "")]);
    let (port, received) = mail::tests::server(&certificates, "235 OK\r\n", "250 OK\r\n");
    let channels = Channels {
        webhook: Some(Address {
            url: format!("{}/hooks/garrison", hook.url),
            token: "hook-token".to_owned(),
        }),
        mail: Some(mail::tests::mail(port)),
        ..ntfy(&format!("{}/mailserver", topic.url))
    };
    assert_eq!(
        channels.names(),
        [
            format!("ntfy at {}", topic.url.trim_start_matches("http://")),
            format!("webhook at {}", hook.url.trim_start_matches("http://")),
            "mail to anna@example.test".to_owned(),
        ]
    );
    let roots = mail::tests::trusted(&certificates);
    let memory = Remembered::default();
    let failing = [observed("backup", State::Failed, "The last run failed.")];
    after_run_with(&channels, &failing, &memory, now(), &roots).unwrap();
    let told = after_run_with(&channels, &failing, &memory, now(), &roots).unwrap();
    assert_eq!(told.state, State::Ok);
    assert_eq!(told.id, "notifications.channels");

    assert_eq!(topic.requests().len(), 1);
    let posted = hook.requests();
    assert!(
        posted[0].starts_with("POST /hooks/garrison HTTP/1.1\r\n"),
        "{}",
        posted[0]
    );
    assert!(posted[0].contains("Authorization: Bearer hook-token\r\n"));
    let sent = body(&posted[0]);
    assert_eq!(sent["source"], "garrison");
    assert_eq!(sent["host"], "garrison.example.org");
    assert_eq!(sent["level"], "failed");
    assert_eq!(sent["title"], "Garrison on garrison.example.org: 1 failed");
    assert_eq!(
        sent["failed"],
        json!(["Check backup: The last run failed."])
    );
    assert_eq!(sent["recovered"], json!([]));
    let lines = received.recv().unwrap();
    assert!(lines.contains(&"Subject: Garrison on garrison.example.org: 1 failed".to_owned()));

    // The return to order reaches the topic; the webhook refuses it and the
    // mail server is gone. Told it is, and the page names who did not take it.
    let topic = serve(vec![answer(200, "{}")]);
    let broken = serve(vec![answer(500, "broken")]);
    let channels = Channels {
        ntfy: Some(Address {
            url: format!("{}/mailserver", topic.url),
            token: String::new(),
        }),
        webhook: Some(Address {
            url: format!("{}/hooks/garrison", broken.url),
            token: String::new(),
        }),
        ..channels
    };
    let fine = [observed("backup", State::Ok, "")];
    let partly = after_run_with(&channels, &fine, &memory, now(), &roots).unwrap();
    assert_eq!(partly.state, State::Failed);
    let finding = &partly.findings[0];
    assert!(
        finding
            .starts_with("The last notification did not go out: webhook: it answered 500; mail: "),
        "{finding}"
    );
    assert_eq!(topic.requests().len(), 1);
    assert_eq!(broken.requests().len(), 1);
    // Nothing is sent a second time.
    let quiet = serve(Vec::new());
    let silent = Channels {
        webhook: None,
        mail: None,
        ..ntfy(&format!("{}/mailserver", quiet.url))
    };
    after_run_with(&silent, &fine, &memory, now(), &roots).unwrap();
    assert_eq!(quiet.requests().len(), 0);
}

#[test]
fn without_a_channel_nothing_is_kept_or_shown() {
    let memory = Remembered::default();
    let failing = [observed("backup", State::Failed, "The last run failed.")];
    assert_eq!(
        after_run(&Channels::default(), &failing, &memory, now()),
        None
    );
    assert!(memory.0.borrow().is_empty());
    // What is stored of the channels holds no secret.
    let stored = serde_json::to_string(&Channels {
        mail: Some(mail::tests::mail(465)),
        ..ntfy("https://ntfy.example.org/topic")
    })
    .unwrap();
    assert!(
        !stored.contains("token-1") && !stored.contains("app-password"),
        "{stored}"
    );
    assert!(stored.contains("anna@example.test"));
}
