//! What the channels read from protected files: the tokens of a topic and a
//! webhook and the password of the account that submits mail, and the
//! addresses that go with them.

use garrison_core::config::Notifications;
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_core::files::{Form, ProtectedFileError};
use serde::{Deserialize, Serialize};

/// A channel's secret as its file holds it.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Secret {
    /// The file is empty: the channel sends none.
    #[default]
    Empty,
    Text(String),
    /// The file cannot be used, and why; never what it holds.
    Unusable(String),
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nothing of a secret belongs in a log or a panic message.
        formatter.write_str(match self {
            Secret::Empty => "Secret::Empty",
            Secret::Text(_) => "Secret::Text(..)",
            Secret::Unusable(_) => "Secret::Unusable(..)",
        })
    }
}

impl Secret {
    /// The secret that `setting` names, read in its form.
    fn read(credentials: &Credentials, source: &SecretSource, setting: &str, form: Form) -> Self {
        match credentials.read_optional_secret(source, form) {
            Ok(None) => Secret::Empty,
            Ok(Some(text)) => Secret::Text(text),
            Err(error) => Secret::Unusable(unusable(setting, form, &error)),
        }
    }

    /// What to send: the secret, nothing for an empty file, or why the
    /// channel cannot send at all.
    pub(crate) fn text(&self) -> Result<&str, String> {
        match self {
            Secret::Empty => Ok(""),
            Secret::Text(text) => Ok(text),
            Secret::Unusable(why) => Err(why.clone()),
        }
    }
}

/// Why the file `setting` names cannot be used. The error names the file
/// and what is wrong with it, never what it holds.
fn unusable(setting: &str, form: Form, error: &ProtectedFileError) -> String {
    let wanted = match (error, form) {
        (ProtectedFileError::InvalidSecret(_), Form::Token) => {
            ". A token is one line of 16 to 8192 printable characters without spaces"
        }
        (ProtectedFileError::InvalidSecret(_), Form::Password) => {
            ". A password is one line of text without control characters, at most 8192 bytes"
        }
        _ => "",
    };
    format!("{setting} cannot be used: {error}{wanted}")
}

/// An address with the token that goes with it; an empty file sends none.
#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Address {
    pub url: String,
    /// Read from its credential, never kept with the address.
    #[serde(skip)]
    pub token: Secret,
}

impl std::fmt::Debug for Address {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Address")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

/// What the channels need beside their addresses.
#[derive(Clone, Default)]
pub struct Secrets {
    pub ntfy: Secret,
    pub webhook: Secret,
    pub mail: Secret,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nothing of a secret belongs in a log or a panic message.
        formatter.debug_struct("Secrets").finish_non_exhaustive()
    }
}

impl Secrets {
    /// The secrets of a configuration. An empty file means that a topic or
    /// a webhook needs no token; a file that cannot be used is that
    /// channel's error, and so is an empty password, since mail is always
    /// submitted signed in.
    #[must_use]
    pub fn read(credentials: &Credentials, notifications: &Notifications) -> Self {
        Self::from_sources(
            credentials,
            [
                &notifications.token,
                &notifications.webhook_token,
                &notifications.mail_password,
            ],
        )
    }

    /// The secrets the units load by name, for a watch whose configuration
    /// does not load: the three settings' defaults.
    #[must_use]
    pub fn loaded(credentials: &Credentials) -> Self {
        let [ntfy, webhook, mail] = ["ntfy-token", "notify-webhook-token", "notify-mail-password"]
            .map(|name| SecretSource::Credential(name.to_owned()));
        Self::from_sources(credentials, [&ntfy, &webhook, &mail])
    }

    fn from_sources(credentials: &Credentials, [ntfy, webhook, mail]: [&SecretSource; 3]) -> Self {
        const PASSWORD: &str = "notifications.mail_password";
        let mail = match Secret::read(credentials, mail, PASSWORD, Form::Password) {
            Secret::Empty => Secret::Unusable(format!(
                "{PASSWORD} is empty, and mail is submitted signed in: write the account's \
                 password into the file it names"
            )),
            secret => secret,
        };
        Secrets {
            ntfy: Secret::read(credentials, ntfy, "notifications.token", Form::Token),
            webhook: Secret::read(
                credentials,
                webhook,
                "notifications.webhook_token",
                Form::Token,
            ),
            mail,
        }
    }
}
