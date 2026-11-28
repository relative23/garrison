//! What `stalwart setup` writes to Stalwart and what it reads of the stored
//! objects, as types.
//!
//! A written object has exactly the keys its type names. A stored object is
//! read for its ID and for the one field that tells Garrison's own object
//! from another application's; anything else it holds is not looked at, and
//! a field that is missing or `null` simply does not match.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::states;
use crate::state::State;

/// A native `{"name": true}` map with every name switched on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(super) struct Enabled(BTreeMap<String, bool>);

/// The event types the webhook asks Stalwart for: those Garrison records,
/// none of which may be one it must never record. The shipped lists keep to
/// that, as a test holds, so only a broken build is refused here.
pub(super) fn webhook_events(
    recorded: Vec<&'static str>,
    forbidden: &[&str],
) -> Result<Vec<&'static str>, State> {
    match recorded.iter().find(|kind| forbidden.contains(kind)) {
        Some(kind) => Err(states::event_forbidden(kind)),
        None => Ok(recorded),
    }
}

impl Enabled {
    pub(super) fn of<S: Into<String>>(names: impl IntoIterator<Item = S>) -> Self {
        Enabled(names.into_iter().map(|name| (name.into(), true)).collect())
    }

    pub(super) fn insert(&mut self, name: String) {
        self.0.insert(name, true);
    }

    pub(super) fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }
}

/// The arguments of a `/set` method. A new object gets the creation ID
/// [`NEW`], under which the answer names it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum Set<'a, T> {
    Create(BTreeMap<&'static str, T>),
    Update(BTreeMap<&'a str, T>),
    Destroy([&'a str; 1]),
}

pub(super) const NEW: &str = "new";

impl<'a, T> Set<'a, T> {
    pub(super) fn create(object: T) -> Self {
        Set::Create(BTreeMap::from([(NEW, object)]))
    }

    pub(super) fn update(id: &'a str, object: T) -> Self {
        Set::Update(BTreeMap::from([(id, object)]))
    }
}

/// The arguments of a method on the objects of another account than the
/// administrator's own, `account`, or on its own where that is `None`. An
/// administrator lists and changes only its own account's API keys unless
/// it names another (measured on Stalwart 1.1.0 and 1.2.0).
#[derive(Debug, Serialize)]
pub(super) struct In<'a, T> {
    #[serde(rename = "accountId", skip_serializing_if = "Option::is_none")]
    pub(super) account: Option<&'a str>,
    #[serde(flatten)]
    pub(super) arguments: T,
}

/// Every object of one kind in an account, and that account.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Listed<T> {
    pub(super) account_id: String,
    pub(super) list: Vec<T>,
}

/// What a `/set` method answers about the objects it created.
#[derive(Debug, Deserialize)]
pub(super) struct Created<T> {
    pub(super) created: BTreeMap<String, T>,
}

/// What a `/set` method refused, by creation ID or object ID. Stalwart
/// answers 200 for a request it carried out only in part.
#[derive(Debug, Default, Deserialize)]
pub(super) struct Refused {
    #[serde(default, rename = "notCreated")]
    created: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, rename = "notUpdated")]
    updated: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, rename = "notDestroyed")]
    destroyed: Option<serde_json::Map<String, serde_json::Value>>,
}

impl Refused {
    /// The first refusal: JMAP's error type of its first object, where
    /// Stalwart names one, and the refusal as Stalwart worded it, shortened.
    pub(super) fn first(self) -> Option<(Option<String>, String)> {
        [self.created, self.updated, self.destroyed]
            .into_iter()
            .flatten()
            .find(|refused| !refused.is_empty())
            .map(|refused| {
                let kind = refused
                    .values()
                    .next()
                    .and_then(|object| object.get("type"));
                let kind = kind.and_then(serde_json::Value::as_str).map(str::to_owned);
                let text = serde_json::Value::Object(refused).to_string();
                (kind, text.chars().take(400).collect())
            })
    }
}

/// An object as Stalwart shows it: its ID and its other fields, of which it
/// masks the secrets.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub(super) struct Stored {
    #[serde(default)]
    pub(super) id: String,
    #[serde(flatten)]
    pub(super) fields: serde_json::Map<String, serde_json::Value>,
}

/// The fields of secrets, which Stalwart does not show.
const SECRETS: [&str; 3] = ["signatureKey", "authSecret", "secret"];

impl Stored {
    /// A field that is text.
    pub(super) fn text(&self, field: &str) -> Option<&str> {
        self.fields.get(field).and_then(serde_json::Value::as_str)
    }

    /// Whether it holds every field of `wanted` as setup writes it, the
    /// secrets aside: writing `wanted` would change nothing Stalwart shows.
    pub(super) fn holds(&self, wanted: &impl Serialize) -> bool {
        let Ok(serde_json::Value::Object(wanted)) = serde_json::to_value(wanted) else {
            return false;
        };
        wanted.iter().all(|(field, value)| {
            SECRETS.contains(&field.as_str())
                || self.fields.get(field).map(open) == Some(open(value))
        })
    }
}

/// `value` without the fields of secrets, at any depth.
fn open(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(fields) => fields
            .iter()
            .filter(|(field, _)| !SECRETS.contains(&field.as_str()))
            .map(|(field, value)| (field.clone(), open(value)))
            .collect(),
        other => other.clone(),
    }
}

/// A secret given by value.
#[derive(Debug, Serialize)]
#[serde(tag = "@type")]
pub(super) enum Secret<'a> {
    Value { secret: &'a str },
}

/// Garrison as an OAuth client: sign-in only (see `ensure_oauth_client`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct OAuthClient<'a> {
    /// Sent when the client is registered; an update keeps it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) client_id: Option<&'a str>,
    pub(super) description: &'static str,
    pub(super) redirect_uris: Enabled,
    pub(super) post_logout_redirect_uris: Enabled,
    pub(super) scopes: Enabled,
    pub(super) grant_types: Enabled,
}

/// The webhook that delivers the recorded event types to the ingest.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct WebHook<'a> {
    pub(super) url: &'a str,
    pub(super) events: Enabled,
    pub(super) events_policy: EventsPolicy,
    /// Events are selected by type only; the level must not filter.
    pub(super) level: Level,
    pub(super) timeout: u32,
    pub(super) throttle: u32,
    /// Stalwart keeps undelivered batches this long (milliseconds); the
    /// ingest records a gap when it was offline for longer.
    pub(super) discard_after: u32,
    pub(super) lossy: bool,
    pub(super) signature_key: Secret<'a>,
    pub(super) http_auth: HttpAuth,
    pub(super) http_headers: BTreeMap<&'static str, &'a str>,
    pub(super) allow_invalid_certs: bool,
    pub(super) enable: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum EventsPolicy {
    Include,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Level {
    Trace,
}

#[derive(Debug, Serialize)]
#[serde(tag = "@type")]
pub(super) enum HttpAuth {
    Unauthenticated,
}

/// What an API key may do and from where; the part an update replaces.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct KeyRights<'a> {
    pub(super) permissions: KeyPermissions,
    pub(super) allowed_ips: &'a Enabled,
}

/// The key's own list instead of its account's roles.
#[derive(Debug, Serialize)]
#[serde(tag = "@type")]
pub(super) enum KeyPermissions {
    Replace { permissions: Enabled },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NewKey<'a> {
    pub(super) description: &'a str,
    #[serde(flatten)]
    pub(super) rights: KeyRights<'a>,
    /// `None` is written as `null`: the key does not expire.
    pub(super) expires_at: Option<&'a str>,
}

/// The secret of a key Stalwart just created; it is sent this once.
#[derive(Deserialize)]
pub(super) struct NewSecret {
    pub(super) id: String,
    pub(super) secret: String,
}

/// The metrics settings with the Prometheus exporter switched on.
#[derive(Debug, Serialize)]
pub(super) struct Metrics<'a> {
    pub(super) prometheus: Exporter<'a>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "@type", rename_all_fields = "camelCase")]
pub(super) enum Exporter<'a> {
    Enabled {
        auth_username: &'a str,
        auth_secret: Secret<'a>,
    },
}

/// A server action.
#[derive(Debug, Serialize)]
#[serde(tag = "@type")]
pub(super) enum Action {
    ReloadSettings,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn objects_are_written_with_the_keys_stalwart_names() {
        let networks = Enabled::of(["127.0.0.1/32"]);
        let key = NewKey {
            description: "garrison broker",
            rights: KeyRights {
                permissions: KeyPermissions::Replace {
                    permissions: Enabled::of(["authenticate", "sysRoleGet"]),
                },
                allowed_ips: &networks,
            },
            expires_at: None,
        };
        assert_eq!(
            json!(Set::create(key)),
            json!({"create": {"new": {
                "description": "garrison broker",
                "permissions": {"@type": "Replace",
                    "permissions": {"authenticate": true, "sysRoleGet": true}},
                "allowedIps": {"127.0.0.1/32": true},
                "expiresAt": null,
            }}})
        );
        let client = OAuthClient {
            client_id: None,
            description: "Garrison",
            redirect_uris: Enabled::of(["https://admin.example.test/auth/callback"]),
            post_logout_redirect_uris: Enabled::default(),
            scopes: Enabled::default(),
            grant_types: Enabled::of(["authorizationCode"]),
        };
        assert_eq!(
            json!(Set::update("c7", client)),
            json!({"update": {"c7": {
                "description": "Garrison",
                "redirectUris": {"https://admin.example.test/auth/callback": true},
                "postLogoutRedirectUris": {},
                "scopes": {},
                "grantTypes": {"authorizationCode": true},
            }}})
        );
        assert_eq!(
            json!(Set::<()>::Destroy(["k1"])),
            json!({"destroy": ["k1"]})
        );
        let theirs = In {
            account: Some("c"),
            arguments: Set::<()>::Destroy(["k1"]),
        };
        assert_eq!(json!(theirs), json!({"accountId": "c", "destroy": ["k1"]}));
        let own = In {
            account: None,
            arguments: Set::<()>::Destroy(["k1"]),
        };
        assert_eq!(json!(own), json!({"destroy": ["k1"]}));
        assert_eq!(
            json!(Set::create(Action::ReloadSettings)),
            json!({"create": {"new": {"@type": "ReloadSettings"}}})
        );
        let metrics = Metrics {
            prometheus: Exporter::Enabled {
                auth_username: "garrison",
                auth_secret: Secret::Value { secret: "s" },
            },
        };
        assert_eq!(
            json!(metrics),
            json!({"prometheus": {"@type": "Enabled", "authUsername": "garrison",
                "authSecret": {"@type": "Value", "secret": "s"}}})
        );
    }

    #[test]
    fn the_webhook_is_written_as_stalwart_stores_it() {
        let webhook = WebHook {
            url: "http://127.0.0.1:8094/webhook",
            events: Enabled::of(["server.startup"]),
            events_policy: EventsPolicy::Include,
            level: Level::Trace,
            timeout: 5000,
            throttle: 1000,
            discard_after: 3_600_000,
            lossy: false,
            signature_key: Secret::Value { secret: "key" },
            http_auth: HttpAuth::Unauthenticated,
            http_headers: BTreeMap::from([("X-Garrison", "events")]),
            allow_invalid_certs: false,
            enable: true,
        };
        assert_eq!(
            json!(webhook),
            json!({
                "url": "http://127.0.0.1:8094/webhook",
                "events": {"server.startup": true},
                "eventsPolicy": "include",
                "level": "trace",
                "timeout": 5000,
                "throttle": 1000,
                "discardAfter": 3_600_000,
                "lossy": false,
                "signatureKey": {"@type": "Value", "secret": "key"},
                "httpAuth": {"@type": "Unauthenticated"},
                "httpHeaders": {"X-Garrison": "events"},
                "allowInvalidCerts": false,
                "enable": true,
            })
        );
    }

    #[test]
    fn stored_objects_are_read_whatever_else_they_hold() {
        let client: Stored = serde_json::from_value(json!({
            "id": "c", "clientId": "https://a.example/oauth-client.json", "logo": null,
        }))
        .unwrap();
        assert_eq!(
            (client.id.as_str(), client.text("clientId")),
            ("c", Some("https://a.example/oauth-client.json"))
        );
        let foreign: Stored =
            serde_json::from_value(json!({"id": "w", "httpHeaders": null, "url": 7})).unwrap();
        assert_eq!(foreign.text("url"), None);
    }

    /// Stalwart holds what setup would write where it holds every field
    /// setup writes as setup writes it, whatever else it holds. A map is held
    /// whole, so an entry more is a change; the secrets are not compared, at
    /// any depth, since Stalwart shows none.
    #[test]
    fn a_stored_object_holds_what_setup_would_write_but_its_secrets() {
        let stored =
            |value: serde_json::Value| -> Stored { serde_json::from_value(value).unwrap() };
        let metrics = Metrics {
            prometheus: Exporter::Enabled {
                auth_username: "garrison",
                auth_secret: Secret::Value { secret: "s" },
            },
        };
        let shown = json!({"id": "singleton", "other": 1, "prometheus": {"@type": "Enabled",
            "authUsername": "garrison", "authSecret": {"@type": "Value", "secret": "****"}}});
        assert!(stored(shown).holds(&metrics));
        let theirs = json!({"id": "singleton", "prometheus": {"@type": "Enabled",
            "authUsername": "someone"}});
        assert!(!stored(theirs).holds(&metrics));
        let client = OAuthClient {
            client_id: None,
            description: "Garrison",
            redirect_uris: Enabled::of(["https://a.example/cb"]),
            post_logout_redirect_uris: Enabled::default(),
            scopes: Enabled::default(),
            grant_types: Enabled::of(["authorizationCode"]),
        };
        let held = json!({"id": "c", "clientId": "x", "description": "Garrison",
            "redirectUris": {"https://a.example/cb": true}, "postLogoutRedirectUris": {},
            "scopes": {}, "grantTypes": {"authorizationCode": true}});
        assert!(stored(held.clone()).holds(&client));
        let mut more = held;
        more["grantTypes"]["refreshToken"] = json!(true);
        assert!(!stored(more).holds(&client));
    }

    #[test]
    fn a_refusal_is_reported_in_stalwarts_words() {
        let done: Refused = serde_json::from_value(json!({
            "created": {"new": {"id": "a"}}, "notCreated": null, "notUpdated": {},
        }))
        .unwrap();
        assert_eq!(done.first(), None);
        let refused: Refused = serde_json::from_value(json!({
            "notUpdated": {"c7": {"type": "invalidProperties", "properties": ["scopes"]}},
        }))
        .unwrap();
        assert_eq!(
            refused.first().unwrap(),
            (
                Some("invalidProperties".to_owned()),
                r#"{"c7":{"type":"invalidProperties","properties":["scopes"]}}"#.to_owned()
            )
        );
        let long: Refused = serde_json::from_value(json!({
            "notDestroyed": {"k": {"description": "x".repeat(1000)}},
        }))
        .unwrap();
        let (kind, text) = long.first().unwrap();
        assert_eq!((kind, text.chars().count()), (None, 400));
    }

    /// Garrison records no event it must never record, so the webhook asks
    /// for every one it records; a build whose lists disagree is refused
    /// with what is wrong, before the webhook changes.
    #[test]
    fn the_webhook_asks_for_every_recorded_event_and_none_that_is_forbidden() {
        use garrison_ingest::policy::{FORBIDDEN_EVENTS, event_types};
        let asked = webhook_events(event_types(), &FORBIDDEN_EVENTS).unwrap();
        assert_eq!(asked, event_types());
        assert_eq!(asked.len(), 131);
        let broken = webhook_events(vec!["smtp.ehlo", "smtp.raw-input"], &FORBIDDEN_EVENTS);
        assert_eq!(broken, Err(states::event_forbidden("smtp.raw-input")));
    }
}
