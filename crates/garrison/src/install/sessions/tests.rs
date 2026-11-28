use garrison_testing::http::{answer, serve};
use garrison_web::store::{NewSession, WebStore};

use super::*;

/// A configuration whose Stalwart is at `stalwart`, and a web database
/// with a session for each of `tokens`.
fn signed_in(root: &Path, stalwart: &str, tokens: &[&str]) -> Config {
    let config = garrison_testing::config(root, stalwart);
    let store = WebStore::open(&config.database(Database::Web)).unwrap();
    for token in tokens {
        let session = NewSession {
            subject: "1",
            email: "admin@example.test",
            token,
            client_ip: None,
            lifetime: 1800,
        };
        store.create(&session).unwrap();
    }
    config
}

const FIRST: &str = "token-0123456789abcdef";
const SECOND: &str = "token-fedcba9876543210";

#[test]
fn stalwart_revokes_the_token_of_every_session_that_goes() {
    let directory = tempfile::tempdir().unwrap();
    let stalwart = serve(vec![answer(200, ""), answer(200, "")]);
    let config = signed_in(directory.path(), &stalwart.url, &[FIRST, SECOND]);
    assert_eq!(
        end(&config).unwrap().to_string(),
        "Stalwart revoked the tokens of the 2 sessions that end with this. \
         [install-sessions-revoked]"
    );
    let mut asked: Vec<String> = stalwart
        .requests()
        .iter()
        .map(|request| {
            assert!(request.starts_with("POST /auth/revoke "), "{request}");
            request.rsplit("\r\n").next().unwrap().to_owned()
        })
        .collect();
    asked.sort();
    let client = "client_id=https%3A%2F%2Fadmin.example.test%2Foauth-client.json";
    assert_eq!(
        asked,
        [
            format!("token={FIRST}&{client}"),
            format!("token={SECOND}&{client}")
        ]
    );
}

#[test]
fn a_revocation_stalwart_does_not_take_is_said_and_the_rest_is_not_asked() {
    let directory = tempfile::tempdir().unwrap();
    let stalwart = serve(vec![answer(200, ""), answer(503, "")]);
    let config = signed_in(directory.path(), &stalwart.url, &[FIRST, SECOND, FIRST]);
    assert_eq!(
        end(&config).unwrap().to_string(),
        "Stalwart did not take the revocation of the tokens of 2 of the 3 sessions that end \
         with this (Stalwart answered HTTP 503): they serve until they expire there, an hour \
         after their sign-in by Stalwart's default. [install-sessions-unrevoked]"
    );
    assert_eq!(stalwart.requests().len(), 2);
}

#[test]
fn one_session_is_said_as_one() {
    let directory = tempfile::tempdir().unwrap();
    let stalwart = serve(vec![answer(200, "")]);
    let config = signed_in(directory.path(), &stalwart.url, &[FIRST]);
    assert_eq!(
        end(&config).unwrap().to_string(),
        "Stalwart revoked the token of the session that ends with this. \
         [install-sessions-revoked]"
    );
    let away = serve(vec![answer(503, "")]);
    let directory = tempfile::tempdir().unwrap();
    let config = signed_in(directory.path(), &away.url, &[FIRST]);
    assert_eq!(
        end(&config).unwrap().to_string(),
        "Stalwart did not take the revocation of the token of the session that ends with this \
         (Stalwart answered HTTP 503): it serves until it expires there, an hour after its \
         sign-in by Stalwart's default. [install-sessions-unrevoked]"
    );
    stalwart.requests();
    away.requests();
}

#[test]
fn a_database_without_a_session_asks_stalwart_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let stalwart = serve(vec![]);
    let config = signed_in(directory.path(), &stalwart.url, &[]);
    assert_eq!(end(&config), None);
    std::fs::remove_file(config.database(Database::Web)).unwrap();
    assert_eq!(end(&config), None);
    assert_eq!(stalwart.requests(), Vec::<String>::new());
}

#[test]
fn a_web_database_that_does_not_read_is_said() {
    let directory = tempfile::tempdir().unwrap();
    let config = signed_in(directory.path(), "http://127.0.0.1:9", &[]);
    let path = config.database(Database::Web);
    std::fs::write(&path, "no database").unwrap();
    let said = end(&config).unwrap().to_string();
    assert!(
        said.starts_with(&format!(
            "The sessions in {} could not be read (",
            path.display()
        )) && said.ends_with(
            "): their tokens are not revoked and serve until they expire at Stalwart. \
             [install-sessions-unread]"
        ),
        "{said}"
    );
}
