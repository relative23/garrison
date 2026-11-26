//! The test document for a filter of macros, where it is switched on: what
//! it carries and how its result is kept.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::tests::{collected, provider, results, server};
use super::*;
use crate::testing::{Remembered, table};

/// The attachment of a test message, as a mail program reads it.
fn attached(body: &str) -> Vec<u8> {
    let encoded = body
        .split_once("Content-Transfer-Encoding: base64\r\n\r\n")
        .and_then(|(_, rest)| rest.split_once("\r\n--garrison-mail-test--"))
        .unwrap()
        .0;
    STANDARD.decode(encoded.replace("\r\n", "")).unwrap()
}

#[test]
fn the_macro_document_is_sent_where_it_is_switched_on_and_must_be_refused() {
    let with_macros = |port: u16| {
        MailTest::new(&table(&format!(
            "type = \"mail-test\"\nrecipient = \"garrison-test@example.test\"\nport = {port}\n\
             macro_document = true"
        )))
        .unwrap()
    };
    let refusal = "550 5.7.1 Message refused: Heuristics.OLE2.ContainsMacros.VBA";
    let (port, handle) = server([
        "550 virus",
        "550 virus",
        "550 spam",
        "550 spam",
        refusal,
        refusal,
        "250 2.0.0 Message queued with id c.",
        "250 2.0.0 Message queued with id d.",
    ]);
    let memory = Remembered::default();
    let refused = collected(&with_macros(port), &memory, 0, &[]);
    assert_eq!(refused.state, State::Ok, "{:?}", refused.findings);
    assert_eq!(results(&refused)[2], format!("refused: {refusal}"));
    assert_eq!(&results(&refused)[3..], ["accepted", "accepted"]);
    let sessions = handle.join().unwrap();
    let message = &sessions[4];
    assert!(
        message.contains(
            "Subject: Garrison mail test: Office document with macros (test document)\r\n"
        )
    );
    assert!(message.contains("Content-Type: multipart/mixed; boundary=\"garrison-mail-test\"\r\n"));
    assert!(message.contains("filename=\"garrison-macro-test.docm\"\r\n"));
    assert!(message.ends_with("\r\n--garrison-mail-test--\r\n.\r\nQUIT\r\n"));
    // What travels is the test document, in lines a mail may have.
    let body = message.split_once("\r\nDATA\r\n").unwrap().1;
    assert_eq!(attached(body), document::with_project());
    // No line near the 998 bytes a mail's line may have.
    assert!(body.lines().all(|line| line.len() <= 100), "{body}");
    // Beside it a harmless document of the same build, with no project.
    let harmless = &sessions[7];
    assert!(harmless.contains("Subject: Garrison mail test: Harmless document (control)\r\n"));
    assert!(harmless.contains("filename=\"garrison-harmless-test.docx\"\r\n"));
    let body = harmless.split_once("\r\nDATA\r\n").unwrap().1;
    assert_eq!(attached(body), document::harmless());

    // The result was kept with the macro test: switched off, the provider
    // tests anew, without the document; and on again likewise.
    let (port, handle) = server([
        "550 virus",
        "550 virus",
        "550 spam",
        "550 spam",
        "250 2.0.0 Message queued with id d.",
    ]);
    let without = collected(&provider(port), &memory, 60, &[]);
    assert_eq!(
        results(&without),
        ["refused: 550 virus", "refused: 550 spam", "accepted"]
    );
    assert_eq!(handle.join().unwrap().len(), 5);

    // A document that is taken means nothing filters macros.
    let (port, handle) = server([
        "550 virus",
        "550 virus",
        "550 spam",
        "550 spam",
        "250 2.0.0 Message queued with id a.",
        "250 2.0.0 Message queued with id e.",
    ]);
    let taken = collected(&with_macros(port), &memory, 120, &[]);
    handle.join().unwrap();
    assert_eq!(taken.state, State::Failed);
    assert_eq!(
        taken.findings,
        [
            "Office document with macros (test document): accepted: no filter refused \
             the test document."
        ]
    );
}
