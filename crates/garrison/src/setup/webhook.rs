//! Garrison's webhook in Stalwart, which delivers the selected events to the
//! receiver, signed with the key setup keeps in the credentials directory.

use std::collections::BTreeMap;
use std::path::Path;

use garrison_core::config::Config;
use garrison_core::files::{Privacy, read_secret};
use garrison_ingest::policy::{FORBIDDEN_EVENTS, event_types};

use super::keys::holds_key;
use super::objects::{
    self, Enabled, EventsPolicy, HttpAuth, Level, Secret, Set, StoredWebHook, WebHook,
};
use super::{Admin, random, write_secret};

/// `WebHook` objects have no description; this header marks Garrison's own webhook.
const MARKER: (&str, &str) = ("X-Garrison", "events");
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

/// The ID of Garrison's webhook, where Stalwart has one.
pub(super) fn find(admin: &Admin) -> Result<Option<String>, String> {
    let marked = |item: &StoredWebHook| {
        let headers = item.http_headers.as_ref();
        headers.and_then(|headers| headers.get(MARKER.0)?.as_str()) == Some(MARKER.1)
    };
    let listed = admin.list::<StoredWebHook>("WebHook")?;
    Ok(listed.into_iter().find(marked).map(|item| item.id))
}

/// The webhook made or updated, `existing` where Stalwart has it, signing
/// with `signing`'s key. Stalwart keeps a batch the receiver refuses while
/// the key changes and sends it again.
pub(super) fn ensure(
    admin: &Admin,
    config: &Config,
    url: Option<&str>,
    existing: Option<&str>,
    signing: &Signing,
) -> Result<String, String> {
    let types = objects::webhook_events(event_types(), &FORBIDDEN_EVENTS)?;
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
        http_headers: BTreeMap::from([MARKER]),
        allow_invalid_certs: false,
        enable: true,
    };
    let result = if let Some(id) = existing {
        admin.set("x:WebHook/set", &Set::update(id, webhook))?;
        "updated webhook"
    } else {
        admin.set("x:WebHook/set", &Set::create(webhook))?;
        "created webhook"
    };
    Ok(format!("{result} -> {url} ({} event types)", types.len()))
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
}
