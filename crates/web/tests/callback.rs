//! What the web service's journal says of a sign-in that its callback
//! refuses before the code exchange.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use support::rights::{Fixed, configured, journal, web, written};
use support::{Client, grant};

/// The state of a fresh login, as the provider's sign-in page gets it.
async fn state(client: &mut Client) -> String {
    let answer = client.get("/auth/login").await;
    let location = url::Url::parse(answer.header("location")).unwrap();
    let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
    query["state"].clone()
}

/// A callback that names another issuer than `deployment.issuer`, as where
/// Stalwart names itself under another URL than garrison.toml does, or none,
/// or that carries no code or one too long, fails the sign-in before the
/// code exchange. The web service's journal says which, with the issuer the
/// callback named, quoted and bounded since anyone who can start a sign-in
/// chooses it, and the one configured, but never the code.
#[tokio::test]
async fn a_callback_refused_before_the_exchange_says_why_in_the_journal() {
    let _turn = journal().await;
    let directory = tempfile::tempdir().unwrap();
    let config = configured(directory.path(), "http://127.0.0.1:9");
    let broker = Arc::new(Fixed(Ok(grant("1", &["dashboard"], &[]))));
    let (mut client, _app) = web(&config, broker);
    let code = "code-0123456789secret";
    let ours = "iss=https%3A%2F%2Fmail.example.test";
    let set = "where deployment.issuer is https://mail.example.test";
    // An issuer with a line break and more than the journal repeats.
    let odd = format!("\n{}", "a".repeat(300));
    let shown: String = odd.chars().take(200).collect();
    let cases = [
        (
            format!("code={code}&iss=https%3A%2F%2Fstalwart.example.test"),
            format!("it names the issuer \"https://stalwart.example.test\", {set}"),
        ),
        (
            format!("code={code}&iss=%0A{}", "a".repeat(300)),
            format!("it names the issuer {shown:?}, {set}"),
        ),
        (format!("code={code}"), format!("it names no issuer, {set}")),
        (ours.to_owned(), "it carries no code".to_owned()),
        (
            format!("code={}&{ours}", "c".repeat(4097)),
            "its code is longer than 4096 characters".to_owned(),
        ),
    ];
    for (query, why) in cases {
        let state = state(&mut client).await;
        written();
        let answer = client
            .get(&format!("/auth/callback?state={state}&{query}"))
            .await;
        let lines = written();
        assert_eq!(answer.header("location"), "/admin/?login_error=1", "{why}");
        assert_eq!(
            lines,
            [format!("WARN Sign-in rejected at the callback ({why})")],
            "{why}"
        );
        assert!(lines.iter().all(|line| !line.contains(code)), "{lines:?}");
    }
}
