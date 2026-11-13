use super::*;
use crate::models::Theme;

fn store() -> (WebStore, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    (
        WebStore::open(&directory.path().join("web.sqlite")).unwrap(),
        directory,
    )
}

#[test]
fn sessions_are_found_by_their_cookie_value_only() {
    let (store, _directory) = store();
    let new = NewSession {
        subject: "1",
        email: "1@example.test",
        token: "token-0123456789abcdef",
        client_ip: Some("192.0.2.1"),
        lifetime: 600,
    };
    let (identifier, session) = store.create(&new).unwrap();
    assert_eq!(session.id_hash, digest(&identifier));
    let found = store.get(&identifier).unwrap().unwrap();
    assert_eq!(
        (found.subject.as_str(), found.client_ip.as_deref()),
        ("1", Some("192.0.2.1"))
    );
    assert_eq!(
        store.get(&session.id_hash).unwrap(),
        None,
        "the digest is not a cookie"
    );
    assert_eq!(store.get("").unwrap(), None);
    assert_eq!(store.get(&"x".repeat(129)).unwrap(), None);
    assert_eq!(
        store.delete(&session.id_hash).unwrap().as_deref(),
        Some("token-0123456789abcdef")
    );
    assert_eq!(store.get(&identifier).unwrap(), None);
    let expired = NewSession {
        lifetime: -1,
        ..new
    };
    let (old, _) = store.create(&expired).unwrap();
    assert_eq!(store.get(&old).unwrap(), None);
}

#[test]
fn preferences_are_validated_and_sorted() {
    let (store, _directory) = store();
    assert_eq!(store.preferences("1").unwrap(), Preferences::default());
    let saved = store
        .save_preferences(
            "1",
            Preferences {
                theme: Theme::Dark,
                hidden_modules: vec!["spam".into(), "logs".into()],
                show_switch: false,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(saved.hidden_modules, ["logs", "spam"]);
    assert!(!saved.show_switch);
    assert_eq!(store.preferences("1").unwrap(), saved);
    for hidden in [
        vec!["nonexistent".to_owned()],
        vec!["spam".to_owned(), "spam".to_owned()],
    ] {
        let value = Preferences {
            theme: Theme::Light,
            hidden_modules: hidden,
            ..Preferences::default()
        };
        assert_eq!(store.save_preferences("1", value).unwrap(), None);
    }
    // A module removed in a later release keeps the other settings.
    store
        .db()
        .execute(
            "UPDATE preferences SET document=?",
            [r#"{"theme": "dark", "hiddenModules": ["removed", "spam"]}"#],
        )
        .unwrap();
    let stored = store.preferences("1").unwrap();
    assert_eq!(stored.hidden_modules, ["spam"]);
    // A document that does not name the switch setting hides the switch rows,
    // as the setting does until a user turns it on.
    assert!(!stored.show_switch);
    assert!(!Preferences::default().show_switch);
}

#[test]
fn identifiers_are_hex_digests() {
    assert_eq!(
        digest("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

fn new_session(lifetime: i64) -> NewSession<'static> {
    NewSession {
        subject: "7",
        email: "7@example.test",
        token: "secret-token-0123456789",
        client_ip: None,
        lifetime,
    }
}

#[test]
fn a_session_lasts_its_lifetime_from_now() {
    let (store, _directory) = store();
    let real = || time::now().as_second();
    let before = real();
    let (identifier, session) = store.create(&new_session(600)).unwrap();
    let after = real();
    assert!((before + 600..=after + 600).contains(&session.expires_at));
    assert_eq!(store.get(&identifier).unwrap(), Some(session));
    // A session ends at its second, not after it.
    let (ended, _) = store.create(&new_session(0)).unwrap();
    assert_eq!(store.get(&ended).unwrap(), None);
    let (expired, _) = store.create(&new_session(-1)).unwrap();
    assert_eq!(store.get(&expired).unwrap(), None);
}

#[test]
fn expired_sessions_are_removed() {
    let (store, _directory) = store();
    store.create(&new_session(-1)).unwrap();
    store.create(&new_session(600)).unwrap();
    let count: i64 = store
        .db()
        .query_row("SELECT count(*) FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1, "creating purges expired sessions");
}

#[test]
fn random_tokens_are_base64url_of_their_length() {
    let (state, verifier) = (random_token(32).unwrap(), random_token(48).unwrap());
    assert_eq!((state.len(), verifier.len()), (43, 64));
    assert_ne!(state, random_token(32).unwrap());
    assert!(
        format!("{state}{verifier}")
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
}

#[test]
fn cookie_values_longer_than_any_identifier_are_not_looked_up() {
    let (store, _directory) = store();
    let (longest, too_long) = ("a".repeat(128), "a".repeat(129));
    for identifier in [&longest, &too_long] {
        store
            .db()
            .execute(
                "INSERT INTO sessions VALUES(?,'7','e','t','c',NULL,0,?)",
                params![digest(identifier), now() + 600],
            )
            .unwrap();
    }
    assert!(store.get(&longest).unwrap().is_some());
    assert_eq!(store.get(&too_long).unwrap(), None);
    assert_eq!(store.get("").unwrap(), None);
}

#[test]
fn debug_output_never_shows_tokens() {
    let (store, _directory) = store();
    let new = new_session(600);
    let (_, session) = store.create(&new).unwrap();
    for text in [format!("{session:?}"), format!("{new:?}")] {
        assert!(text.contains("\"7\""), "{text}");
        assert!(!text.contains("secret-token"), "{text}");
        assert!(!text.contains(&session.csrf), "{text}");
    }
}

#[test]
fn every_module_may_be_hidden_but_not_more() {
    let all: Vec<String> = ModuleId::all().map(|id| id.as_str().to_owned()).collect();
    let everything = Preferences {
        theme: Theme::System,
        hidden_modules: all.clone(),
        ..Preferences::default()
    };
    assert_eq!(
        validated(everything).unwrap().hidden_modules.len(),
        all.len()
    );
    let mut repeated = all;
    repeated.push("dashboard".into());
    let too_many = Preferences {
        theme: Theme::System,
        hidden_modules: repeated,
        ..Preferences::default()
    };
    assert_eq!(validated(too_many), None);
}
