//! Garrison's two read-only API keys in Stalwart: created or updated with
//! their permissions and networks, written to the credentials directory, and
//! tried from this host.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::files::{self, Form, Holds, Privacy};
use garrison_stalwart::http::Request;

use super::objects::{
    Created, Enabled, KeyPermissions, KeyRights, NEW, NewKey, NewSecret, Set, StoredKey,
};
use super::{Admin, write_secret};

/// One of the keys: its file, as the broker or the collector reads it, its
/// description in Stalwart, what it may do, and whether a running service
/// holds it, which must start again to read a new one.
pub(super) struct Key {
    pub(super) file: &'static str,
    pub(super) description: &'static str,
    pub(super) permissions: &'static [&'static str],
    pub(super) held: bool,
}

/// Whether the file at `path` holds a key as the service that reads it
/// takes one. An empty file, one of a line end alone and one that holds
/// something else hold none: setup makes a key there, as where the file is
/// missing, since a key kept in such a file leaves its service with none.
pub(super) fn holds_key(path: &Path) -> bool {
    files::holds(path, Form::Token).is_ok_and(|held| held == Holds::Secret)
}

/// What `ensure` did: the step, the keys a new one replaces, and whether
/// the file holds a key this run made. `setup` removes the replaced keys
/// once the services that hold them have restarted with the new one, also
/// when it fails on the way (`remove`).
pub(super) struct Ensured {
    pub(super) step: String,
    pub(super) replaced: Vec<String>,
    pub(super) made: bool,
}

/// Whether Stalwart refused a new object for its account's quota, as
/// `Admin::call` words a refusal: JMAP's error type `overQuota` (RFC 8620),
/// which Stalwart gives where an account holds as many API keys as it may,
/// five (measured on Stalwart 1.1.0).
fn over_quota(error: &str) -> bool {
    error.contains(r#""type":"overQuota""#)
}

pub(super) fn ensure(
    admin: &Admin,
    directory: &Path,
    key: &Key,
    networks: &Enabled,
    rotate: bool,
) -> Result<Ensured, String> {
    let (target, description) = (directory.join(key.file), key.description);
    let existing: Vec<StoredKey> = admin
        .list::<StoredKey>("ApiKey")?
        .into_iter()
        .filter(|item| item.description.as_deref() == Some(description))
        .collect();
    let rights = || KeyRights {
        permissions: KeyPermissions::Replace {
            permissions: Enabled::of(key.permissions.iter().copied()),
        },
        allowed_ips: networks,
    };
    // The one key of its description is kept where its file holds a key.
    // Where Stalwart has several, as after a rotation that was stopped or
    // whose clean-up failed, no run can tell which one the file holds, since
    // Stalwart shows no key's secret: a new key replaces them all, as where
    // the file holds none.
    if let ([only], true, false) = (existing.as_slice(), holds_key(&target), rotate) {
        admin.set("x:ApiKey/set", &Set::update(&only.id, rights()))?;
        return Ok(Ensured {
            step: format!("updated API key '{description}' (secret unchanged)"),
            replaced: Vec::new(),
            made: false,
        });
    }
    let mut replaced: Vec<String> = existing.iter().map(|item| item.id.clone()).collect();
    let path = target.display();
    let mut step = match (existing.len(), rotate) {
        (0, _) | (1, false) => format!("created API key '{description}' -> {path}"),
        (count, false) => {
            format!("replaced the {count} API keys '{description}' with one -> {path}")
        }
        (_, true) => format!("replaced API key '{description}' -> {path}"),
    };
    // A new key first and its file next. A running service keeps the old
    // key until it restarts, so the old keys go after that (`remove`). Where
    // Stalwart's quota leaves the new key no room beside them, they go
    // first, and the broker checks no rights until it restarts.
    match make(admin, &target, description, rights()) {
        Err(error) if over_quota(&error) && !replaced.is_empty() => {
            remove(admin, &replaced)?;
            replaced.clear();
            make(admin, &target, description, rights())?;
            step.push_str(" (the old ones went first: Stalwart's quota of API keys left no room)");
        }
        Err(error) if over_quota(&error) => {
            return Err(format!(
                "{error}. Stalwart holds no more API keys for the administrator's account: \
                 remove those of its keys that are no longer needed in the Stalwart WebUI"
            ));
        }
        done => done?,
    }
    Ok(Ensured {
        step,
        replaced,
        made: true,
    })
}

/// A new key, its secret written to `target`. A key whose secret is lost is
/// of no use to anyone, so where the file cannot be written, the new key
/// goes again.
fn make(
    admin: &Admin,
    target: &Path,
    description: &str,
    rights: KeyRights<'_>,
) -> Result<(), String> {
    let new_key = NewKey {
        description,
        rights,
        expires_at: None,
    };
    let created: Created<NewSecret> = admin
        .call("x:ApiKey/set", &Set::create(new_key))
        .map_err(|error| refused(&error, description))?;
    let new = created.created.get(NEW);
    let new = new.ok_or("Stalwart did not return the new API key secret")?;
    let Err(error) = write_secret(target, &new.secret) else {
        return Ok(());
    };
    let undone = admin.set("x:ApiKey/set", &Set::<()>::Destroy([new.id.as_str()]));
    Err(match undone {
        Ok(()) => format!("{error}; the new API key was taken out of Stalwart again"),
        Err(_) => format!(
            "{error}; the new API key stays in Stalwart without its secret, and the next run \
             replaces it"
        ),
    })
}

/// What setup says where Stalwart made no new key. A user without
/// administrator rights reads the list of keys, its own, but may not grant
/// a key the permissions it lacks: JMAP's `forbidden`, as Stalwart answers
/// it (measured on Stalwart 1.1.0).
fn refused(error: &str, description: &str) -> String {
    if error.contains(r#""type":"forbidden""#) {
        return format!(
            "Stalwart refused the administrator the API key '{description}', since it may not \
             grant the key's permissions: run setup as an administrator who holds them, as one \
             with Stalwart's administrator role ({error})"
        );
    }
    format!("{error} (Stalwart did not return the new API key secret)")
}

/// Remove the keys that new ones replaced.
pub(super) fn remove(admin: &Admin, replaced: &[String]) -> Result<(), String> {
    for id in replaced {
        admin.set("x:ApiKey/set", &Set::<()>::Destroy([id.as_str()]))?;
    }
    Ok(())
}

/// Each key opens a JMAP session from this host, as the services will use
/// it; what is returned are the keys that Stalwart does not know. It answers
/// such a key 401, as after the credentials directory was put back from a
/// copy older than the last rotation, and a key it knows from an address the
/// key does not allow 403 (measured on Stalwart 1.1.0). In a container's
/// bridge network Stalwart sees this host as the bridge's gateway, not as
/// 127.0.0.1, and then every key is refused. That is said here, at setup,
/// rather than found later in the collector's results.
pub(super) fn verify<'k>(
    config: &Config,
    directory: &Path,
    keys: &[&'k Key],
) -> Result<Vec<&'k Key>, String> {
    let url = format!("{}/jmap/session", config.deployment.stalwart_url);
    let mut unknown = Vec::new();
    for key in keys {
        let name = key.file;
        // As the services read it, so that what is tried is what they use.
        let secret = files::read_secret(&directory.join(name), Privacy::Owned)
            .map_err(|error| format!("{name}: {error}"))?;
        let authorization = format!("Bearer {secret}");
        let status = Request::get(&url)
            .header("Authorization", &authorization)
            .timeout(Duration::from_secs(30))
            .status()
            .map_err(|error| format!("Trying {name}: {error}"))?;
        match status {
            200 => {}
            401 => unknown.push(*key),
            403 => {
                return Err(format!(
                    "Stalwart refuses the API key in {name} from this host (HTTP 403): it sees \
                     this host at an address the key does not allow. That happens when \
                     Stalwart runs in a Docker or Podman bridge network; run it in the host \
                     network instead (docker run --network host, or network_mode: host with \
                     Compose), then run this again."
                ));
            }
            other => {
                return Err(format!(
                    "Trying {name}: Stalwart answered HTTP {other} for its JMAP session"
                ));
            }
        }
    }
    Ok(unknown)
}

/// A network as `address/prefix`; the host part must be zero.
pub(super) fn network(text: &str) -> Result<String, String> {
    let (address, prefix) = text.split_once('/').unwrap_or((text, ""));
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("invalid network {text}"))?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    let prefix: u32 = if prefix.is_empty() {
        bits
    } else {
        prefix
            .parse()
            .map_err(|_| format!("invalid network {text}"))?
    };
    let host_bits_zero = match address {
        IpAddr::V4(v4) => prefix <= 32 && (prefix == 32 || u32::from(v4) << prefix == 0),
        IpAddr::V6(v6) => prefix <= 128 && (prefix == 128 || u128::from(v6) << prefix == 0),
    };
    if !host_bits_zero {
        return Err(format!("{text} has host bits set"));
    }
    Ok(format!("{address}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use garrison_testing::http::{answer, json, serve};
    use serde_json::json;

    use super::*;

    const OLD: &str = "the-key-stalwart-has-0123456789";
    const NEW: &str = "the-key-stalwart-made-0123456789";
    const COLLECTOR: Key = Key {
        file: "collector-native-key",
        description: "garrison collector",
        permissions: &["authenticate"],
        held: false,
    };

    /// What `ensure` does for the collector's key with the file holding
    /// `written`, while Stalwart has the keys `listed` of that description:
    /// the step, the keys it replaces, what the file holds after, and
    /// whether it asked Stalwart for a new key.
    fn ensured(written: &str, listed: &[&str]) -> (String, Vec<String>, String, bool) {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join(COLLECTOR.file);
        garrison_testing::write_private(&file, written.as_bytes());
        let listed: Vec<_> = listed
            .iter()
            .map(|id| json!({"id": id, "description": "garrison collector"}))
            .collect();
        let listed = json(&json!({"methodResponses": [["x:ApiKey/get", {"list": listed}, "0"]]}));
        let set = json(&json!({"methodResponses": [["x:ApiKey/set",
            {"created": {"new": {"id": "fresh", "secret": NEW}}, "updated": {"old": null}}, "0"]]}));
        let server = serve(vec![listed, set]);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let networks = Enabled::of(["127.0.0.1/32"]);
        let done = ensure(&admin, directory.path(), &COLLECTOR, &networks, false).unwrap();
        let requests = server.requests();
        let step = done
            .step
            .replace(&directory.path().display().to_string(), "DIR");
        let held = std::fs::read_to_string(&file).unwrap();
        assert_eq!(done.made, requests[1].contains("\"create\""));
        (step, done.replaced, held, done.made)
    }

    /// A key file that holds no key, as an empty one, gets a new key, as a
    /// missing one does, and the key it replaces goes: kept, the collector
    /// would have no key while setup said "secret unchanged". A file that
    /// holds a key keeps it.
    #[test]
    fn a_key_file_that_holds_no_key_gets_a_new_one() {
        for written in ["", "\n", " \r\n", "short\n"] {
            assert_eq!(
                ensured(written, &["old"]),
                (
                    "created API key 'garrison collector' -> DIR/collector-native-key".to_owned(),
                    vec!["old".to_owned()],
                    format!("{NEW}\n"),
                    true
                ),
                "{written:?}"
            );
        }
        assert_eq!(
            ensured(&format!("{OLD}\n"), &["old"]),
            (
                "updated API key 'garrison collector' (secret unchanged)".to_owned(),
                Vec::new(),
                format!("{OLD}\n"),
                false
            )
        );
    }

    /// Where Stalwart has two keys of the description, as after a rotation
    /// that was stopped before it removed the old one, no run can tell which
    /// the file holds: a plain run makes one anew and replaces both, where
    /// it once updated the first and kept the other for good.
    #[test]
    fn two_keys_of_one_description_are_replaced_by_one() {
        assert_eq!(
            ensured(&format!("{OLD}\n"), &["old", "older"]),
            (
                "replaced the 2 API keys 'garrison collector' with one -> \
                 DIR/collector-native-key"
                    .to_owned(),
                vec!["old".to_owned(), "older".to_owned()],
                format!("{NEW}\n"),
                true
            )
        );
    }

    /// Stalwart holds at most five keys for an account. Where a new key finds
    /// no room beside the old ones, these go first and the new one is made
    /// then, so that a rotation stopped after it made its keys does not
    /// leave every later run refused.
    #[test]
    fn a_full_quota_lets_the_old_keys_go_first() {
        let directory = tempfile::tempdir().unwrap();
        let listed = json(&json!({"methodResponses": [["x:ApiKey/get", {"list": [
            {"id": "old", "description": "garrison collector"},
            {"id": "older", "description": "garrison collector"}]}, "0"]]}));
        let full = json(
            &json!({"methodResponses": [["x:ApiKey/set", {"notCreated": {"new": {
            "type": "overQuota", "description": "You have exceeded your quota of 5 API keys."}}},
            "0"]]}),
        );
        let gone = |id: &str| {
            json(&json!({"methodResponses": [["x:ApiKey/set", {"destroyed": [id]}, "0"]]}))
        };
        let made = json(&json!({"methodResponses": [["x:ApiKey/set",
            {"created": {"new": {"id": "fresh", "secret": NEW}}}, "0"]]}));
        let server = serve(vec![listed, full, gone("old"), gone("older"), made]);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let networks = Enabled::of(["127.0.0.1/32"]);
        let done = ensure(&admin, directory.path(), &COLLECTOR, &networks, true).unwrap();
        let requests = server.requests();
        assert!(requests[2].contains(r#""destroy":["old"]"#));
        assert!(requests[3].contains(r#""destroy":["older"]"#));
        assert_eq!(
            done.step
                .replace(&directory.path().display().to_string(), "DIR"),
            "replaced API key 'garrison collector' -> DIR/collector-native-key (the old ones \
             went first: Stalwart's quota of API keys left no room)"
        );
        assert_eq!((done.replaced, done.made), (Vec::<String>::new(), true));
        let held = std::fs::read_to_string(directory.path().join(COLLECTOR.file)).unwrap();
        assert_eq!(held, format!("{NEW}\n"));
    }

    /// A key whose file cannot be written goes again, so that Stalwart keeps
    /// no key whose secret nobody holds, and the error names the file.
    #[test]
    fn a_new_key_whose_file_cannot_be_written_goes_again() {
        if rustix::process::geteuid().is_root() {
            return; // Root writes any folder.
        }
        let directory = tempfile::tempdir().unwrap();
        let folder = directory.path().join("credentials");
        std::fs::create_dir(&folder).unwrap();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o500)).unwrap();
        let listed = json(&json!({"methodResponses": [["x:ApiKey/get", {"list": []}, "0"]]}));
        let made = json(&json!({"methodResponses": [["x:ApiKey/set",
            {"created": {"new": {"id": "fresh", "secret": NEW}}}, "0"]]}));
        let gone = json(&json!({"methodResponses": [["x:ApiKey/set",
            {"destroyed": ["fresh"]}, "0"]]}));
        let server = serve(vec![listed, made, gone]);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let networks = Enabled::of(["127.0.0.1/32"]);
        let error = ensure(&admin, &folder, &COLLECTOR, &networks, false)
            .err()
            .unwrap();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
        let requests = server.requests();
        let target = folder.join(COLLECTOR.file);
        assert!(
            error.starts_with(&format!("Could not write {}: ", target.display()))
                && error.ends_with("; the new API key was taken out of Stalwart again"),
            "{error}"
        );
        assert!(
            requests[2].contains(r#""destroy":["fresh"]"#),
            "{}",
            requests[2]
        );
    }

    /// What `verify` makes of Stalwart's answer to the collector's key.
    fn tried(status: u16) -> Result<Vec<&'static str>, String> {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join(COLLECTOR.file);
        garrison_testing::write_private(&file, format!("{OLD}\n").as_bytes());
        let server = serve(vec![answer(status, "{}")]);
        let config = garrison_testing::config(directory.path(), &server.url);
        let tried = verify(&config, directory.path(), &[&COLLECTOR]);
        let requests = server.requests();
        assert!(requests[0].contains(&format!("Bearer {OLD}")));
        tried.map(|unknown| unknown.iter().map(|key| key.file).collect())
    }

    /// Stalwart answers a key it does not know 401 and one it knows from an
    /// address the key does not allow 403 (measured): the first is a key to
    /// make anew, the second a bridge network.
    #[test]
    fn a_key_stalwart_does_not_know_is_told_from_one_it_refuses_here() {
        assert_eq!(tried(200), Ok(Vec::new()));
        assert_eq!(tried(401), Ok(vec!["collector-native-key"]));
        let bridge = tried(403).unwrap_err();
        assert!(
            bridge.starts_with(
                "Stalwart refuses the API key in collector-native-key from this host (HTTP \
                 403): it sees this host at an address the key does not allow."
            ),
            "{bridge}"
        );
        assert_eq!(
            tried(404),
            Err(
                "Trying collector-native-key: Stalwart answered HTTP 404 for its JMAP session"
                    .to_owned()
            )
        );
    }

    /// A user without administrator rights may read the keys, its own, but
    /// not make Garrison's: setup says to run it as an administrator.
    #[test]
    fn an_account_that_may_not_grant_the_permissions_is_told_so() {
        let refusal = r#"x:ApiKey/set: {"new":{"description":"You are not authorized to grant permissions: sysRoleGet","type":"forbidden"}}"#;
        assert!(refused(refusal, "garrison broker").starts_with(
            "Stalwart refused the administrator the API key 'garrison broker', since it may \
                 not grant the key's permissions: run setup as an administrator who holds them"
        ));
        assert_eq!(
            refused("x:ApiKey/set: Stalwart is unavailable", "garrison broker"),
            "x:ApiKey/set: Stalwart is unavailable (Stalwart did not return the new API key secret)"
        );
    }

    #[test]
    fn networks_are_written_in_canonical_form() {
        assert_eq!(network("172.17.0.0/16").unwrap(), "172.17.0.0/16");
        assert_eq!(network("10.1.2.3").unwrap(), "10.1.2.3/32");
        assert_eq!(network("fd00::/8").unwrap(), "fd00::/8");
        assert!(network("172.17.0.1/16").is_err());
        assert!(network("nonsense").is_err());
    }
}
