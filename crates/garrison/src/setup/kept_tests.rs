//! A file of a secret that setup keeps as it is holds one only where no
//! other user may read it: where others may, its secret may have been seen,
//! and setup makes a new one, which it writes for its own user alone.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;

/// How setup judges whether a file holds its secret.
type Holds = fn(&Path) -> bool;

fn scraped(path: &Path) -> bool {
    exporter::read(path).is_some()
}

/// Every file of a secret that setup keeps where it holds one, with the
/// secret and the reader that judges it: the keys of the broker and the
/// collector, the webhook's signature key and the scrape credential.
#[test]
fn a_secret_file_that_others_may_read_holds_none() {
    let key = &b"a-key-of-sixteen-characters-or-more\n"[..];
    let credential = &br#"{"username": "garrison", "secret": "a-scrape-secret"}"#[..];
    let kept: [(&str, &[u8], Holds); 4] = [
        (BROKER.file, key, keys::holds_key),
        (COLLECTOR.file, key, keys::holds_key),
        (webhook::KEY_FILE, key, keys::holds_key),
        (exporter::FILE, credential, scraped),
    ];
    let directory = tempfile::tempdir().unwrap();
    for (name, secret, holds) in kept {
        let path = directory.path().join(name);
        garrison_testing::write_private(&path, secret);
        assert!(holds(&path), "{name}");
        for mode in [0o640, 0o604, 0o644] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(!holds(&path), "{name} at mode {mode:o}");
        }
    }
}
