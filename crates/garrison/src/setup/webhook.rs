//! Garrison's webhook in Stalwart, which delivers the selected events to the
//! receiver, signed with the key setup keeps in the credentials directory.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use garrison_core::config::Config;
use garrison_core::files::{Privacy, read_secret};
use garrison_ingest::policy::{FORBIDDEN_EVENTS, event_types};
use sha2::{Digest, Sha256};

use super::keys::holds_key;
use super::objects::{self, Enabled, EventsPolicy, HttpAuth, Level, Secret, Set, Stored, WebHook};
use super::{Admin, random, write_secret};

/// `WebHook` objects have no description; this header marks Garrison's own webhook.
const MARKER: (&str, &str) = ("X-Garrison", "events");
/// The header that names the signature key by a hash of it, which Stalwart
/// shows where it masks the key, so that a run sees whether it holds the
/// file's.
const KEY_NAME: &str = "X-Garrison-Key";
/// The signature key's file, as the receiver reads it.
pub(super) const KEY_FILE: &str = "webhook-signature-key";

/// The key Stalwart is to sign with, as its file holds it, and whether this
/// run made it.
pub(super) struct Signing {
    key: String,
    pub(super) new: bool,
}

/// The file's signature key, or where it holds none or a rotation asks for
/// one, a new one, written to the file before Stalwart is given it: Stalwart
/// signs with it once it reloads its settings, and the running receiver
/// holds the old one until it starts again. A file that holds no key gets
/// one, as a missing file does: Stalwart takes no empty key, and the
/// receiver does not start with one.
pub(super) fn key(directory: &Path, rotate: bool) -> Result<Signing, String> {
    let path = directory.join(KEY_FILE);
    if !rotate && holds_key(&path) {
        // As the receiver reads it, so that Stalwart signs with what it checks.
        let key = read_secret(&path, Privacy::Owned).map_err(|error| error.to_string())?;
        return Ok(Signing { key, new: false });
    }
    let key = random(48)?;
    write_secret(&path, &key)?;
    Ok(Signing { key, new: true })
}

/// Garrison's webhook, where Stalwart has one.
pub(super) fn find(admin: &Admin) -> Result<Option<Stored>, String> {
    let marked = |item: &Stored| {
        let headers = item.fields.get("httpHeaders");
        headers.and_then(|headers| headers.get(MARKER.0)?.as_str()) == Some(MARKER.1)
    };
    let listed = admin.list::<Stored>("WebHook")?;
    Ok(listed.into_iter().find(marked))
}

/// The webhook made, or updated where Stalwart's differs from it, signing
/// with `signing`'s key; what was done, if anything. Stalwart keeps a batch
/// the receiver refuses while the key changes and sends it again.
pub(super) fn ensure(
    admin: &Admin,
    config: &Config,
    url: Option<&str>,
    existing: Option<&Stored>,
    signing: &Signing,
) -> Result<Option<String>, String> {
    let types = objects::webhook_events(event_types(), &FORBIDDEN_EVENTS)?;
    let named = URL_SAFE_NO_PAD.encode(&Sha256::digest(signing.key.as_bytes())[..12]);
    let url = url.map_or_else(
        || format!("http://127.0.0.1:{}/webhook", config.ingest.port),
        str::to_owned,
    );
    let webhook = WebHook {
        url: &url,
        events: Enabled::of(types.iter().copied()),
        events_policy: EventsPolicy::Include,
        level: Level::Trace,
        timeout: 5000,
        throttle: 1000,
        discard_after: 3_600_000,
        lossy: false,
        signature_key: Secret::Value {
            secret: &signing.key,
        },
        http_auth: HttpAuth::Unauthenticated,
        http_headers: BTreeMap::from([MARKER, (KEY_NAME, named.as_str())]),
        allow_invalid_certs: false,
        enable: true,
    };
    let result = match existing {
        Some(stored) if stored.holds(&webhook) => return Ok(None),
        Some(stored) => {
            admin.set("x:WebHook/set", &Set::update(&stored.id, webhook))?;
            "updated webhook"
        }
        None => {
            admin.set("x:WebHook/set", &Set::create(webhook))?;
            "created webhook"
        }
    };
    Ok(Some(format!(
        "{result} -> {url} ({} event types)",
        types.len()
    )))
}

#[cfg(test)]
mod tests {
    use garrison_testing::http::{answer, json, serve};
    use serde_json::{Value, json};

    use super::*;

    const KEPT: &str = "the-signature-key-0123456789abcdef";

    /// The signature key that the webhook was given where the file held
    /// `written` and Stalwart answered `answer`: the key, whether it is new,
    /// what the file holds after, and whether the webhook took it.
    fn signed_with(written: &str, answered: String) -> (String, bool, String, bool) {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join(KEY_FILE);
        garrison_testing::write_private(&file, written.as_bytes());
        let server = serve(vec![answered]);
        let config = garrison_testing::config(directory.path(), &server.url);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let signing = key(directory.path(), false).unwrap();
        let url = Some("http://127.0.0.1:9/webhook");
        let taken = ensure(&admin, &config, url, None, &signing).is_ok();
        let requests = server.requests();
        let (_, body) = requests[0].split_once("\r\n\r\n").unwrap();
        let sent: Value = serde_json::from_str(body).unwrap();
        let key = &sent["methodCalls"][0][1]["create"]["new"]["signatureKey"]["secret"];
        let held = std::fs::read_to_string(&file).unwrap();
        (key.as_str().unwrap().to_owned(), signing.new, held, taken)
    }

    /// A file that holds no signature key, as an empty one, gets a new key,
    /// which is in the file before Stalwart is given it, also where Stalwart
    /// then refuses it: Stalwart never holds a key that no file holds, and
    /// the next run gives it the file's. A file that holds a key keeps it.
    #[test]
    fn a_new_signature_key_is_in_its_file_before_stalwart_gets_it() {
        let created = || {
            json(&json!({"methodResponses": [["x:WebHook/set",
                {"created": {"new": {"id": "hook"}}}, "0"]]}))
        };
        for written in ["", "\n", "short\n"] {
            for (answered, took) in [(created(), true), (answer(503, "{}"), false)] {
                let (sent, new, held, taken) = signed_with(written, answered);
                assert_eq!(sent.len(), 64, "{written:?}");
                assert_eq!((new, taken), (true, took), "{written:?}");
                assert_eq!(held, format!("{sent}\n"), "{written:?}");
            }
        }
        assert_eq!(
            signed_with(&format!("{KEPT}\n"), created()),
            (KEPT.to_owned(), false, format!("{KEPT}\n"), true)
        );
    }

    /// What setup wrote, read back as Stalwart shows it, with its key
    /// masked, holds what setup would write: the next run sends nothing. A
    /// new key is a change, which the header that names the key shows.
    #[test]
    fn a_webhook_as_setup_wrote_it_is_left_as_it_is() {
        let directory = tempfile::tempdir().unwrap();
        garrison_testing::write_private(&directory.path().join(KEY_FILE), b"");
        let created = json(&json!({"methodResponses": [["x:WebHook/set",
            {"created": {"new": {"id": "hook"}}}, "0"]]}));
        let server = serve(vec![created]);
        let config = garrison_testing::config(directory.path(), &server.url);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let signing = key(directory.path(), false).unwrap();
        let url = Some("http://127.0.0.1:9/webhook");
        ensure(&admin, &config, url, None, &signing).unwrap();
        let requests = server.requests();
        let (_, body) = requests[0].split_once("\r\n\r\n").unwrap();
        let sent: Value = serde_json::from_str(body).unwrap();
        let mut shown = sent["methodCalls"][0][1]["create"]["new"].clone();
        shown["id"] = json!("hook");
        shown["signatureKey"] = json!({"@type": "Value", "secret": "****"});
        let stored: Stored = serde_json::from_value(shown).unwrap();
        let silent = serve(Vec::new());
        let admin = Admin {
            url: format!("{}/jmap/", silent.url),
            authorization: "Bearer admin".to_owned(),
        };
        let kept = key(directory.path(), false).unwrap();
        assert_eq!(ensure(&admin, &config, url, Some(&stored), &kept), Ok(None));
        assert_eq!(silent.requests(), Vec::<String>::new());
        let named = &stored.fields["httpHeaders"]["X-Garrison-Key"];
        assert_eq!(named.as_str().map(str::len), Some(16));
        let rotated = key(directory.path(), true).unwrap();
        let server = serve(vec![json(&json!({"methodResponses": [["x:WebHook/set",
            {"updated": {"hook": null}}, "0"]]}))]);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let updated = ensure(&admin, &config, url, Some(&stored), &rotated).unwrap();
        server.requests();
        assert!(updated.is_some_and(|step| step.starts_with("updated webhook")));
    }
}
