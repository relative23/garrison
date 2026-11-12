//! Where secrets come from: a file, or a systemd credential.
//!
//! Secrets are never stored in the configuration file. A setting either names an
//! absolute path or `credential:NAME`, which systemd loads for the service
//! (`LoadCredential=`) into `$CREDENTIALS_DIRECTORY`.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::files::{self, Privacy, ProtectedFileError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretSource {
    File(PathBuf),
    Credential(String),
}

impl fmt::Display for SecretSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretSource::File(path) => write!(formatter, "{}", path.display()),
            SecretSource::Credential(name) => write!(formatter, "credential:{name}"),
        }
    }
}

/// A systemd credential name; dots alone would name a directory, not a file.
pub fn is_credential_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        && name.bytes().any(|byte| byte != b'.')
}

/// The directory that holds this process's systemd credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    directory: PathBuf,
}

impl Credentials {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Credentials {
            directory: directory.into(),
        }
    }

    /// Under systemd, `$CREDENTIALS_DIRECTORY` holds the credentials loaded for
    /// this service. Operator commands run outside systemd and read the same
    /// files from the configured source directory.
    pub fn from_environment(configured: &Path) -> Self {
        Self::chosen(std::env::var_os("CREDENTIALS_DIRECTORY"), configured)
    }

    /// systemd's directory when it named one, otherwise the configured one.
    fn chosen(systemd: Option<OsString>, configured: &Path) -> Self {
        match systemd {
            Some(directory) if !directory.is_empty() => Credentials::new(directory),
            _ => Credentials::new(configured),
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn path(&self, source: &SecretSource) -> PathBuf {
        match source {
            SecretSource::File(path) => path.clone(),
            SecretSource::Credential(name) => self.directory.join(name),
        }
    }

    fn privacy(&self, path: &Path) -> Privacy {
        if path.parent() == Some(self.directory.as_path()) {
            Privacy::SystemdCredential
        } else {
            Privacy::Owned
        }
    }

    /// Read a private file such as a JSON credential.
    pub fn read_private(
        &self,
        source: &SecretSource,
        limit: usize,
    ) -> Result<Vec<u8>, ProtectedFileError> {
        let path = self.path(source);
        files::read_private(&path, limit, self.privacy(&path))
    }

    /// Read a single-line secret such as an API key or an HMAC key.
    pub fn read_secret(&self, source: &SecretSource) -> Result<String, ProtectedFileError> {
        let path = self.path(source);
        files::read_secret(&path, self.privacy(&path))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn credential_names_are_plain_file_names() {
        for name in ["broker-native-key", "a", "key.v2", "A_B-c.d"] {
            assert!(is_credential_name(name), "{name}");
        }
        for name in ["", ".", "..", "a/b", "a b", "ä", &"x".repeat(65)] {
            assert!(!is_credential_name(name), "{name:?}");
        }
    }

    #[test]
    fn credentials_resolve_inside_the_directory_and_allow_group_access() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = Credentials::new(directory.path());
        let source = SecretSource::Credential("webhook-signature-key".into());
        let path = credentials.path(&source);
        assert_eq!(path, directory.path().join("webhook-signature-key"));
        fs::write(&path, "0123456789abcdef0123").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            credentials.read_secret(&source).unwrap(),
            "0123456789abcdef0123"
        );

        // The same file named by path outside the directory must be private.
        let elsewhere = Credentials::new(directory.path().join("other"));
        let file = SecretSource::File(path);
        assert!(elsewhere.read_secret(&file).is_err());
        assert_eq!(
            file.to_string(),
            directory
                .path()
                .join("webhook-signature-key")
                .display()
                .to_string()
        );
        assert_eq!(source.to_string(), "credential:webhook-signature-key");
    }

    #[test]
    fn a_private_credential_is_read_whole_within_its_limit() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = Credentials::new(directory.path());
        let source = SecretSource::Credential("admin.json".into());
        let path = credentials.path(&source);
        fs::write(&path, br#"{"apiKey": "k"}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            credentials.read_private(&source, 64).unwrap(),
            br#"{"apiKey": "k"}"#
        );
        assert!(credentials.read_private(&source, 4).is_err());
    }

    #[test]
    fn the_systemd_directory_wins_when_it_is_set() {
        let configured = Path::new("/etc/garrison/credentials");
        let systemd = OsString::from("/run/credentials/garrison-web.service");
        assert_eq!(
            Credentials::chosen(Some(systemd.clone()), configured).directory(),
            Path::new(&systemd)
        );
        for unset in [None, Some(OsString::new())] {
            assert_eq!(
                Credentials::chosen(unset, configured).directory(),
                configured
            );
        }
    }
}
