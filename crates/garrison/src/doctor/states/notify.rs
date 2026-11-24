//! The states of the notification channels' check (`doctor/notify.rs`).

use std::path::Path;

use crate::state::State;

/// A channel whose address alone protects it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::doctor) enum Open {
    Ntfy,
    Webhook,
}

pub(in crate::doctor) fn unusable(why: &str) -> State {
    State::new("doctor-notify-unusable", format!("notifications: {why}")).with_fix(
        "Correct the file it names (configuration.md, Notifications), then send a test message: \
         garrison notify-test",
    )
}

/// `channel` takes no token, and garrison.toml, which every user may read,
/// holds its address; `directory` holds the credentials.
pub(in crate::doctor) fn open(channel: Open, directory: &Path) -> State {
    let ((channel, can), (setting, file)) = match channel {
        Open::Ntfy => (
            ("the ntfy topic", "read and send messages on it"),
            ("ntfy_url", "ntfy-url"),
        ),
        Open::Webhook => (
            (
                "the webhook",
                "post to it where its key is part of the address",
            ),
            ("webhook_url", "notify-webhook-url"),
        ),
    };
    let text = format!(
        "{channel} takes no token, and garrison.toml, which every user of this host may \
         read, holds its address: whoever reads it can {can}"
    );
    State::new("doctor-notify-open", text).with_fix(format!(
        "Write the address into {}/{file} (root, mode 0600) and set {setting} = \
         \"credential:{file}\", or give it a token (configuration.md, Notifications).",
        directory.display()
    ))
}

pub(in crate::doctor) fn channels(names: &[String]) -> State {
    let text = format!("notifications: {}", names.join(", "));
    State::new("doctor-notify-channels", text)
}

#[cfg(test)]
pub(super) fn rows() -> Vec<(State, &'static str)> {
    vec![
        (
            unusable("ntfy: notifications.ntfy_url cannot be used: ntfy-url is empty"),
            "notifications: ntfy: notifications.ntfy_url cannot be used: ntfy-url is empty \
             [doctor-notify-unusable]\n      Correct the file it names (configuration.md, \
             Notifications), then send a test message: garrison notify-test",
        ),
        (
            open(Open::Webhook, Path::new("/etc/garrison/credentials")),
            "the webhook takes no token, and garrison.toml, which every user of this host may \
             read, holds its address: whoever reads it can post to it where its key is part of \
             the address [doctor-notify-open]\n      Write the address into \
             /etc/garrison/credentials/notify-webhook-url (root, mode 0600) and set webhook_url \
             = \"credential:notify-webhook-url\", or give it a token (configuration.md, \
             Notifications).",
        ),
        (
            channels(&["ntfy at ntfy.example.org".into(), "mail".into()]),
            "notifications: ntfy at ntfy.example.org, mail [doctor-notify-channels]",
        ),
    ]
}
