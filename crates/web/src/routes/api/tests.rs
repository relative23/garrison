use axum::http::{HeaderMap, HeaderValue};

use super::*;

fn visitor(media: &str) -> Visitor {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_str(media).unwrap());
    Visitor {
        headers,
        ..Visitor::default()
    }
}

#[test]
fn bodies_need_a_json_media_type() {
    let data = br#"{"theme": "dark", "hiddenModules": []}"#;
    for media in [
        "application/json",
        "Application/JSON; charset=utf-8",
        "application/merge-patch+json",
    ] {
        assert!(
            body::<Preferences>(&visitor(media), data).is_ok(),
            "{media}"
        );
    }
    for media in ["text/plain", "application/xml", "text/json", "json"] {
        assert!(
            body::<Preferences>(&visitor(media), data).is_err(),
            "{media}"
        );
    }
    assert!(body::<Preferences>(&Visitor::default(), data).is_err());
}

#[test]
fn bodies_are_strict_json_without_unknown_fields() {
    let json = visitor("application/json");
    let duplicate = br#"{"theme": "dark", "theme": "light", "hiddenModules": []}"#;
    let unknown = br#"{"theme": "dark", "hiddenModules": [], "extra": 1}"#;
    assert!(body::<Preferences>(&json, duplicate).is_err());
    assert!(body::<Preferences>(&json, unknown).is_err());
    assert!(body::<Preferences>(&json, &vec![b' '; MAX_BODY + 1]).is_err());
}

/// The web framework compiles `serde_json` with raw values, and then
/// `serde_json` reads an object with its own key as the JSON inside the text.
/// The strict parser must refuse what the next reader would read differently.
#[test]
fn a_document_serde_json_would_read_as_another_is_refused() {
    let wrapped = r#"{"a": {"$serde_json::private::RawValue": "[1, 2]"}}"#;
    let alone: Value = serde_json::from_str(wrapped).unwrap();
    assert_eq!(
        alone,
        serde_json::json!({"a": [1, 2]}),
        "what is guarded against"
    );
    assert!(json::parse(wrapped.as_bytes(), 1024).is_err());
    let json = visitor("application/json");
    let smuggled =
        br#"{"theme": "dark", "hiddenModules": [], "$serde_json::private::RawValue": "1"}"#;
    assert!(body::<Preferences>(&json, smuggled).is_err());
}

/// An observation checked at `at`; without `max_age` it keeps the default.
fn checked(at: &str, max_age: Option<u32>) -> observations::Observation {
    let observation = observations::Observation::new(
        "x",
        "p",
        "t",
        [ModuleId::Dashboard],
        observations::Evidence::Probe,
        observations::State::Ok,
        at,
        "s",
    )
    .unwrap();
    match max_age {
        Some(seconds) => observation.with_max_age(seconds),
        None => observation,
    }
}

#[test]
fn an_observation_is_stale_after_its_max_age() {
    let minute = checked("2026-10-29T12:00:00+00:00", Some(60));
    let at = time::unix(time::parse("2026-10-29T12:00:00+00:00").unwrap());
    assert!(!stale(&minute, at + 60.0), "exactly max age is still fresh");
    assert!(stale(&minute, at + 61.0));
    assert!(
        !stale(&minute, at - 10.0),
        "a check from the future is fresh"
    );
    let default = checked("2026-10-29 12:00:00", None);
    assert!(
        !stale(&default, at + 300.0),
        "300 seconds by default, naive UTC read"
    );
    assert!(stale(&default, at + 301.0));
    assert!(
        stale(&checked("", None), at),
        "an observation without a time is stale"
    );
    assert!(stale(&checked("yesterday", None), at));
}
