//! What the channels read from protected files: the tokens of a topic and a
//! webhook and the password of the account that submits mail, and the
//! addresses that go with them, which may be secrets themselves.

use garrison_core::config::{ConfigError, Endpoint, Notifications};
use garrison_core::credentials::{Credentials, SecretSource};
use garrison_core::files::{Form, ProtectedFileError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
        (ProtectedFileError::InvalidSecret(_), Form::Address) => {
            ". An address is one line of printable characters without spaces"
        }
        _ => "",
    };
    format!("{setting} cannot be used: {error}{wanted}")
}

/// How a channel's address is checked: [`garrison_core::config::ntfy_address`]
/// or [`garrison_core::config::webhook_address`].
pub(crate) type Rule = fn(&str, &str) -> Result<String, ConfigError>;

/// An address with the token that goes with it; an empty token file sends
/// none. An address kept in a file of its own is a secret like the token: it
/// never shows in a message, a log line or the stored form.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Address {
    /// Where messages go: as the configuration writes it, or as its file
    /// holds it.
    pub url: String,
    /// The file the address is kept in, where it is kept in one.
    pub file: Option<SecretSource>,
    /// Why the address cannot be used as its file stands; never what it holds.
    pub unusable: Option<String>,
    /// Read from its credential, never kept with the address.
    pub token: Secret,
}

impl std::fmt::Debug for Address {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut shown = formatter.debug_struct("Address");
        match &self.file {
            Some(file) => shown.field("file", &file.to_string()),
            None => shown.field("url", &self.url),
        };
        shown.finish_non_exhaustive()
    }
}

impl Address {
    /// The address that `endpoint` names. One kept in a file is read by
    /// [`Channels::located`](crate::notify::Channels::located); until then
    /// it cannot be used.
    #[must_use]
    pub fn configured(endpoint: &Endpoint) -> Self {
        match endpoint {
            Endpoint::Written(url) => Address {
                url: url.clone(),
                ..Address::default()
            },
            Endpoint::File(file) => Address {
                unusable: Some(format!("the address in {file} was not read")),
                file: Some(file.clone()),
                ..Address::default()
            },
        }
    }

    /// Read an address that is kept in a file, which must hold one line that
    /// `rule` takes; `setting` names it in an error, which never shows what
    /// the file holds. A written address is left as it is.
    pub(crate) fn read(&mut self, credentials: &Credentials, setting: &str, rule: Rule) {
        let Some(file) = &self.file else {
            return;
        };
        let path = credentials.path(file);
        let (url, unusable) = match credentials.read_optional_secret(file, Form::Address) {
            Ok(Some(text)) => match rule(&text, &format!("the address in {}", path.display())) {
                Ok(url) => (url, None),
                Err(error) => (
                    String::new(),
                    Some(format!("{setting} cannot be used: {error}")),
                ),
            },
            Ok(None) => (
                String::new(),
                Some(format!(
                    "{setting} cannot be used: {} is empty; write the address into it",
                    path.display()
                )),
            ),
            Err(error) => (
                String::new(),
                Some(unusable(setting, Form::Address, &error)),
            ),
        };
        self.url = url;
        self.unusable = unusable;
    }

    /// Where to send, or why there is nowhere.
    pub(crate) fn usable(&self) -> Result<&str, String> {
        match &self.unusable {
            Some(why) => Err(why.clone()),
            None => Ok(&self.url),
        }
    }
}

/// What the status database keeps of an address for the watch: the address
/// as the configuration writes it, but only the file of one kept in a file,
/// since the database's group may read it.
#[derive(Deserialize, Serialize)]
struct Kept {
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let url = if self.file.is_some() {
            String::new()
        } else {
            self.url.clone()
        };
        let file = self.file.as_ref().map(ToString::to_string);
        Kept { url, file }.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let kept = Kept::deserialize(deserializer)?;
        Ok(match kept.file {
            None => Address {
                url: kept.url,
                ..Address::default()
            },
            Some(text) => match SecretSource::parse(&text) {
                Some(file) => Address::configured(&Endpoint::File(file)),
                None => Address {
                    unusable: Some("the stored channel names no file its address is in".into()),
                    ..Address::default()
                },
            },
        })
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
