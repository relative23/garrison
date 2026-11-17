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

/// The key files, as the broker and the collector read them.
const KEYS: [&str; 2] = ["broker-native-key", "collector-native-key"];

/// Whether the file at `path` holds a key as the service that reads it
/// takes one. An empty file, one of a line end alone and one that holds
/// something else hold none: setup makes a key there, as where the file is
/// missing, since a key kept in such a file leaves its service with none.
pub(super) fn holds_key(path: &Path) -> bool {
    files::holds(path, Form::Token).is_ok_and(|held| held == Holds::Secret)
}

/// What `ensure` did, and the keys a new one replaces. `setup` removes those
/// once the services that hold them have restarted with the new one, or
/// when it fails on the way (`remove`).
pub(super) struct Ensured {
    pub(super) step: String,
    pub(super) replaced: Vec<String>,
}

pub(super) fn ensure(
    admin: &Admin,
    directory: &Path,
    name: &str,
    description: &str,
    permissions: &[&str],
    networks: &Enabled,
    rotate: bool,
) -> Result<Ensured, String> {
    let target = directory.join(name);
    let existing: Vec<StoredKey> = admin
        .list::<StoredKey>("ApiKey")?
        .into_iter()
        .filter(|item| item.description.as_deref() == Some(description))
        .collect();
    let rights = || KeyRights {
        permissions: KeyPermissions::Replace {
            permissions: Enabled::of(permissions.iter().copied()),
        },
        allowed_ips: networks,
    };
    if let (Some(first), true, false) = (existing.first(), holds_key(&target), rotate) {
        admin.set("x:ApiKey/set", &Set::update(&first.id, rights()))?;
        return Ok(Ensured {
            step: format!("updated API key '{description}' (secret unchanged)"),
            replaced: Vec::new(),
        });
    }
    // A new key first and its file next, since a key whose file is lost is
    // useless. A running service keeps the old key until it restarts, so
    // the old keys go after that (`remove`).
    let key = NewKey {
        description,
        rights: rights(),
        expires_at: None,
    };
    let created: Created<NewSecret> = admin
        .call("x:ApiKey/set", &Set::create(key))
        .map_err(|error| refused(&error, description))?;
    let new = created.created.get(NEW);
    let new = new.ok_or("Stalwart did not return the new API key secret")?;
    write_secret(&target, &new.secret)?;
    let done = if rotate && !existing.is_empty() {
        "replaced"
    } else {
        "created"
    };
    Ok(Ensured {
        step: format!("{done} API key '{description}' -> {}", target.display()),
        replaced: existing.into_iter().map(|item| item.id).collect(),
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

/// Each key opens a JMAP session from this host, as the services will use it.
/// Stalwart refuses a key outside the networks it allows; in a container's
/// bridge network Stalwart sees this host as the bridge's gateway, not as
/// 127.0.0.1, and then every key fails. That is said here, at setup, rather
/// than found later in the collector's results.
pub(super) fn verify(config: &Config, directory: &Path) -> Result<String, String> {
    let url = format!("{}/jmap/session", config.deployment.stalwart_url);
    for name in KEYS {
        // As the services read it, so that what is tried is what they use.
        let key = files::read_secret(&directory.join(name), Privacy::Owned)
            .map_err(|error| format!("{name}: {error}"))?;
        let authorization = format!("Bearer {key}");
        let status = Request::get(&url)
            .header("Authorization", &authorization)
            .timeout(Duration::from_secs(30))
            .status()
            .map_err(|error| format!("Trying {name}: {error}"))?;
        match status {
            200 => {}
            401 | 403 => {
                return Err(format!(
                    "Stalwart refuses the API key in {name} from this host (HTTP {status}): \
                     it sees this host at an address the key does not allow. That happens when \
                     Stalwart runs in a Docker or Podman bridge network; run it in the host \
                     network instead (docker run --network host, or network_mode: host \
                     with Compose), then run this again."
                ));
            }
            other => {
                return Err(format!(
                    "Trying {name}: Stalwart answered HTTP {other} for its JMAP session"
                ));
            }
        }
    }
    Ok("Stalwart accepts both API keys from this host".into())
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
    use garrison_testing::http::{json, serve};
    use serde_json::json;

    use super::*;

    const OLD: &str = "the-key-stalwart-has-0123456789";
    const NEW: &str = "the-key-stalwart-made-0123456789";

    /// What `ensure` does for the collector's key with the file holding
    /// `written`, while Stalwart still has a key of that description: the
    /// step, the keys it replaces, what the file holds after, and whether
    /// it asked Stalwart for a new key.
    fn ensured(written: &str) -> (String, Vec<String>, String, bool) {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("collector-native-key");
        garrison_testing::write_private(&file, written.as_bytes());
        let listed = json(&json!({"methodResponses": [["x:ApiKey/get",
            {"list": [{"id": "old", "description": "garrison collector"}]}, "0"]]}));
        let set = json(&json!({"methodResponses": [["x:ApiKey/set",
            {"created": {"new": {"id": "fresh", "secret": NEW}}, "updated": {"old": null}}, "0"]]}));
        let server = serve(vec![listed, set]);
        let admin = Admin {
            url: format!("{}/jmap/", server.url),
            authorization: "Bearer admin".to_owned(),
        };
        let networks = Enabled::of(["127.0.0.1/32"]);
        let done = ensure(
            &admin,
            directory.path(),
            "collector-native-key",
            "garrison collector",
            &["authenticate"],
            &networks,
            false,
        )
        .unwrap();
        let requests = server.requests();
        let step = done
            .step
            .replace(&directory.path().display().to_string(), "DIR");
        let held = std::fs::read_to_string(&file).unwrap();
        (
            step,
            done.replaced,
            held,
            requests[1].contains("\"create\""),
        )
    }

    /// A key file that holds no key, as an empty one, gets a new key, as a
    /// missing one does, and the key it replaces goes: kept, the collector
    /// would have no key while setup said "secret unchanged". A file that
    /// holds a key keeps it.
    #[test]
    fn a_key_file_that_holds_no_key_gets_a_new_one() {
        for written in ["", "\n", " \r\n", "short\n"] {
            assert_eq!(
                ensured(written),
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
            ensured(&format!("{OLD}\n")),
            (
                "updated API key 'garrison collector' (secret unchanged)".to_owned(),
                Vec::new(),
                format!("{OLD}\n"),
                false
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
