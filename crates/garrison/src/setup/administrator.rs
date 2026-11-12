//! The Stalwart administrator that `stalwart setup` acts as. It serves this
//! one run and is stored nowhere by Garrison: asked at the terminal, read from
//! standard input, or read from a root-only file, which the operator is then
//! offered to delete.

use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::files::{Privacy, read_private};
use garrison_core::json;
use serde::Deserialize;

use crate::{complain, say};

const LIMIT: usize = 16384;
/// Reads a secret without echo and puts the terminal back however it ends.
const ASK: &str = "/usr/bin/systemd-ask-password";

/// Where the administrator comes from.
pub(super) enum Source {
    /// `--admin-credential FILE`: a JSON file only its owner can read.
    File(PathBuf),
    /// `--admin-credential -`: the same JSON on standard input.
    Input,
    /// Asked at the terminal.
    Terminal,
}

impl Source {
    pub(super) fn of(argument: Option<&Path>) -> Result<Self, String> {
        match argument {
            Some(path) if path == Path::new("-") => Ok(Self::Input),
            Some(path) => Ok(Self::File(path.to_owned())),
            None if crate::at_terminal() => Ok(Self::Terminal),
            None => Err(
                "Name the Stalwart administrator: run this at a terminal to be asked, \
                         or pass --admin-credential - with the JSON on standard input, \
                         or --admin-credential FILE."
                    .into(),
            ),
        }
    }

    /// The value of the `Authorization` header for the management API.
    pub(super) fn authorization(&self) -> Result<String, String> {
        match self {
            Self::File(path) => document(
                &read_private(path, LIMIT, Privacy::Owned).map_err(|error| error.to_string())?,
            ),
            Self::Input => {
                let mut data = Vec::new();
                io::stdin()
                    .take(LIMIT as u64 + 1)
                    .read_to_end(&mut data)
                    .map_err(|error| format!("standard input: {error}"))?;
                if data.len() > LIMIT {
                    return Err("The administrator on standard input is too long.".into());
                }
                document(&data)
            }
            Self::Terminal => asked(),
        }
    }

    /// After a successful run a file holding the secret should not stay behind.
    pub(super) fn finish(&self) {
        let Self::File(path) = self else {
            return;
        };
        let question = format!(
            "Delete {}? It holds a Stalwart administrator secret. [Y/n]",
            path.display()
        );
        if !crate::at_terminal() {
            complain(&format!(
                "Delete {} when you no longer need it: it holds a Stalwart administrator secret.",
                path.display()
            ));
        } else if confirm(&question, &mut io::stdin().lock(), &mut io::stdout()) {
            match fs::remove_file(path) {
                Ok(()) => say(&format!("Deleted {}.", path.display())),
                Err(error) => complain(&format!("{}: {error}", path.display())),
            }
        }
    }
}

/// The administrator's credential file: a user with a password, or an API
/// key. It holds a secret, so it has no `Debug`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Credential {
    Password {
        username: String,
        secret: String,
    },
    #[serde(rename_all = "camelCase")]
    ApiKey {
        api_key: String,
    },
}

/// `{"username","secret"}` or `{"apiKey"}`.
fn document(data: &[u8]) -> Result<String, String> {
    let value = json::parse(data, LIMIT).map_err(|error| error.to_string())?;
    match json::object(value) {
        Ok(Credential::Password { username, secret }) => Ok(basic(&username, &secret)),
        Ok(Credential::ApiKey { api_key }) => Ok(format!("Bearer {api_key}")),
        Err(_) => Err(r#"The administrator needs {"username","secret"} or {"apiKey"}"#.into()),
    }
}

fn basic(user: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{secret}")))
}

fn asked() -> Result<String, String> {
    say("The Stalwart administrator for this setup; it is used once and stored nowhere.");
    let mut terminal = io::stdout().lock();
    let _ = write!(terminal, "User name (empty for an API key): ");
    let _ = terminal.flush();
    drop(terminal);
    let mut user = String::new();
    io::stdin()
        .lock()
        .read_line(&mut user)
        .map_err(|error| format!("standard input: {error}"))?;
    let user = user.trim();
    if user.is_empty() {
        Ok(format!("Bearer {}", secret("API key:")?))
    } else {
        Ok(basic(user, &secret(&format!("Password of {user}:"))?))
    }
}

fn secret(prompt: &str) -> Result<String, String> {
    let output = Command::new(ASK)
        .args(["--timeout=0", prompt])
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("{ASK}: {error}"))?;
    let text = String::from_utf8(output.stdout).unwrap_or_default();
    let secret = text.trim_end_matches(['\r', '\n']);
    if !output.status.success() || secret.is_empty() {
        return Err("No secret was entered; nothing was changed.".into());
    }
    Ok(secret.to_owned())
}

/// Yes unless the answer is no.
fn confirm(question: &str, input: &mut impl BufRead, output: &mut impl Write) -> bool {
    let _ = write!(output, "{question} ");
    let _ = output.flush();
    let mut answer = String::new();
    if input.read_line(&mut answer).is_err() {
        return false;
    }
    !matches!(answer.trim(), "n" | "N" | "no")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_administrator_is_a_user_with_a_secret_or_an_api_key() {
        assert_eq!(
            document(br#"{"username": "admin", "secret": "s3cret"}"#).unwrap(),
            format!("Basic {}", STANDARD.encode("admin:s3cret"))
        );
        assert_eq!(document(br#"{"apiKey": "key"}"#).unwrap(), "Bearer key");
        // A user with a secret wins over an API key in the same file.
        assert_eq!(
            document(br#"{"apiKey": "key", "username": "a", "secret": "s", "note": 1}"#).unwrap(),
            format!("Basic {}", STANDARD.encode("a:s"))
        );
        for unusable in [
            &br#"{"username": "admin"}"#[..],
            br#"{"username": "admin", "secret": 7}"#,
            br#"{"apiKey": null}"#,
            b"{}",
            br#"["admin", "s3cret"]"#,
            br#""key""#,
        ] {
            assert_eq!(
                document(unusable).unwrap_err(),
                r#"The administrator needs {"username","secret"} or {"apiKey"}"#
            );
        }
        assert!(document(b"not json").is_err());
    }

    #[test]
    fn deleting_the_file_is_the_default_answer() {
        let mut output = Vec::new();
        assert!(confirm("Delete?", &mut "\n".as_bytes(), &mut output));
        assert!(confirm("Delete?", &mut "y\n".as_bytes(), &mut output));
        assert!(!confirm("Delete?", &mut "n\n".as_bytes(), &mut output));
        assert!(!confirm("Delete?", &mut "no\n".as_bytes(), &mut output));
        assert!(String::from_utf8(output).unwrap().starts_with("Delete? "));
    }

    #[test]
    fn a_file_and_standard_input_are_named_explicitly() {
        assert!(matches!(
            Source::of(Some(Path::new("-"))),
            Ok(Source::Input)
        ));
        assert!(matches!(
            Source::of(Some(Path::new("/root/admin.json"))),
            Ok(Source::File(_))
        ));
    }
}
