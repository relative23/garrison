//! The rows of a name and port that is probed on more than one address.

use super::tests::CLOSED;
use super::*;

/// A name and port probed on two addresses has a row for each, and each row
/// and finding says on which address it was; one probed on a single address
/// is named as before.
#[test]
fn a_name_and_port_probed_on_two_addresses_says_on_which() {
    let provider = Tls::new(&crate::testing::table(&format!(
        "type = \"tls\"\nendpoints = [\
         {{ host = \"localhost\", port = {CLOSED}, address = \"127.0.0.1\" }}, \
         {{ host = \"localhost\", port = {CLOSED}, address = \"127.0.0.2\" }}, \
         {{ host = \"mail.example.test\", port = {CLOSED} }}]"
    )))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = crate::testing::config(directory.path());
    let runner = crate::testing::Canned(String::new());
    let card = provider
        .collect(&crate::testing::context(&config, &runner))
        .unwrap()
        .observations
        .remove(0);
    assert_eq!(
        (card.state, card.findings),
        (
            State::Failed,
            vec![
                format!("localhost:{CLOSED} on 127.0.0.1 — TLS check failed (connection refused)."),
                format!("localhost:{CLOSED} on 127.0.0.2 — TLS check failed (connection refused)."),
                format!("mail.example.test:{CLOSED} — TLS check failed (connection refused)."),
            ]
        )
    );
    let rows: Vec<String> = card
        .table
        .unwrap()
        .rows
        .iter()
        .map(|row| row[0].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        rows,
        [
            format!("localhost:{CLOSED} on 127.0.0.1"),
            format!("localhost:{CLOSED} on 127.0.0.2"),
            format!("mail.example.test:{CLOSED}"),
        ]
    );
}
