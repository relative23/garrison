//! Garrison's webhook in Stalwart, which delivers the selected events to the
//! receiver, signed with the key setup keeps in the credentials directory.

use std::collections::BTreeMap;
use std::path::Path;

use garrison_core::config::Config;
use garrison_core::files::{Privacy, read_private};
use garrison_ingest::policy::{FORBIDDEN_EVENTS, event_types};

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
    // Stalwart keeps a batch the ingest refuses during the switch and sends it again.
    if rotate || !key_path.exists() {
        write_secret(&key_path, &random(48)?)?;
    }
    let key = read_private(&key_path, 16384, Privacy::Owned).map_err(|error| error.to_string())?;
    let key = String::from_utf8_lossy(&key).trim().to_owned();
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
