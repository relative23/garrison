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

pub(super) fn ensure_webhook(
    admin: &Admin,
    config: &Config,
    directory: &Path,
    url: Option<&str>,
    rotate: bool,
) -> Result<String, String> {
    let types = objects::webhook_events(event_types(), &FORBIDDEN_EVENTS)?;
    let key_path = directory.join("webhook-signature-key");
    // Stalwart keeps a batch the ingest refuses during the switch and sends it
    // again. A file that holds no key gets one, as a missing file does:
    // Stalwart takes no empty key, and the receiver does not start with one.
    if rotate || !holds_key(&key_path) {
        write_secret(&key_path, &random(48)?)?;
    }
    // As the receiver reads it, so that Stalwart signs with what it checks.
    let key = read_secret(&key_path, Privacy::Owned).map_err(|error| error.to_string())?;
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
        signature_key: Secret::Value { secret: &key },
        http_auth: HttpAuth::Unauthenticated,
        http_headers: BTreeMap::from([MARKER]),
        allow_invalid_certs: false,
        enable: true,
    };
    let marked = |item: &StoredWebHook| {
        let headers = item.http_headers.as_ref();
        headers.and_then(|headers| headers.get(MARKER.0)?.as_str()) == Some(MARKER.1)
    };
    let existing = admin
        .list::<StoredWebHook>("WebHook")?
        .into_iter()
        .find(marked);
    let result = if let Some(item) = existing {
        admin.set("x:WebHook/set", &Set::update(&item.id, webhook))?;
        "updated webhook"
    } else {
        admin.set("x:WebHook/set", &Set::create(webhook))?;
        "created webhook"
    };
    Ok(format!("{result} -> {url} ({} event types)", types.len()))
}

#[cfg(test)]
mod tests {
    use garrison_testing::http::{json, serve};
    use serde_json::{Value, json};

    use super::*;

    const KEPT: &str = "the-signature-key-0123456789abcdef";

    /// The signature key that `ensure_webhook` gave Stalwart where the file
    /// held `written`, and what the file holds after.
    fn signed_with(written: &str) -> (String, String) {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("webhook-signature-key");
        garrison_testing::write_private(&file, written.as_bytes());
        let listed = json(&json!({"methodResponses": [["x:WebHook/get", {"list": []}, "0"]]}));
        let created = json(&json!({"methodResponses": [["x:WebHook/set",
            {"created": {"new": {"id": "hook"}}}, "0"]]}));
        let server = serve(vec![listed, created]);
        let config = garrison_testing::config(directory.path(), &server.url);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let url = Some("http://127.0.0.1:9/webhook");
        ensure_webhook(&admin, &config, directory.path(), url, false).unwrap();
        let requests = server.requests();
        let (_, body) = requests[1].split_once("\r\n\r\n").unwrap();
        let sent: Value = serde_json::from_str(body).unwrap();
        let key = &sent["methodCalls"][0][1]["create"]["new"]["signatureKey"]["secret"];
        let held = std::fs::read_to_string(&file).unwrap();
        (key.as_str().unwrap().to_owned(), held)
    }

    /// A file that holds no signature key, as an empty one, gets a new key,
    /// which Stalwart is given: Stalwart refuses an empty one, and the
    /// receiver starts with none. A file that holds a key keeps it.
    #[test]
    fn a_signature_key_file_that_holds_no_key_gets_a_new_one() {
        for written in ["", "\n", "short\n"] {
            let (sent, held) = signed_with(written);
            assert_eq!(sent.len(), 64, "{written:?}");
            assert_eq!(held, format!("{sent}\n"), "{written:?}");
        }
        assert_eq!(
            signed_with(&format!("{KEPT}\n")),
            (KEPT.to_owned(), format!("{KEPT}\n"))
        );
    }
}
