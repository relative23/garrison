//! Garrison's two read-only API keys in Stalwart: created or updated with
//! their permissions and networks, written to the credentials directory, and
//! tried from this host.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::files::{Privacy, read_private};
use garrison_stalwart::http::Request;

use super::objects::{
    Created, Enabled, KeyPermissions, KeyRights, NEW, NewKey, NewSecret, Set, StoredKey,
};
use super::{Admin, write_secret};

/// The key files, as the broker and the collector read them.
const KEYS: [&str; 2] = ["broker-native-key", "collector-native-key"];

pub(super) fn ensure(
    admin: &Admin,
    directory: &Path,
    name: &str,
    description: &str,
    permissions: &[&str],
    networks: &Enabled,
    rotate: bool,
) -> Result<String, String> {
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
    if let (Some(first), true, false) = (existing.first(), target.exists(), rotate) {
        admin.set("x:ApiKey/set", &Set::update(&first.id, rights()))?;
        return Ok(format!(
            "updated API key '{description}' (secret unchanged)"
        ));
    }
    // A new key first, its file next, the old keys last: a service keeps the
    // old key until it restarts, and a key whose file is lost is useless.
    let key = NewKey {
        description,
        rights: rights(),
        expires_at: None,
    };
    let created: Created<NewSecret> = admin
        .call("x:ApiKey/set", &Set::create(key))
        .map_err(|error| format!("{error} (Stalwart did not return the new API key secret)"))?;
    let new = created.created.get(NEW);
    let new = new.ok_or("Stalwart did not return the new API key secret")?;
    write_secret(&target, &new.secret)?;
    for item in &existing {
        admin.set("x:ApiKey/set", &Set::<()>::Destroy([item.id.as_str()]))?;
    }
    let done = if rotate && !existing.is_empty() {
        "replaced"
    } else {
        "created"
    };
    Ok(format!(
        "{done} API key '{description}' -> {}",
        target.display()
    ))
}

/// Each key opens a JMAP session from this host, as the services will use it.
/// Stalwart refuses a key outside the networks it allows; in a container's
/// bridge network Stalwart sees this host as the bridge's gateway, not as
/// 127.0.0.1, and then every key fails. That is said here, at setup, rather
/// than found later in the collector's results.
pub(super) fn verify(config: &Config, directory: &Path) -> Result<String, String> {
    let url = format!("{}/jmap/session", config.deployment.stalwart_url);
    for name in KEYS {
        let key = read_private(&directory.join(name), 16384, Privacy::Owned)
            .map_err(|error| format!("{name}: {error}"))?;
        let authorization = format!("Bearer {}", String::from_utf8_lossy(&key).trim());
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
    use super::*;

    #[test]
    fn networks_are_written_in_canonical_form() {
        assert_eq!(network("172.17.0.0/16").unwrap(), "172.17.0.0/16");
        assert_eq!(network("10.1.2.3").unwrap(), "10.1.2.3/32");
        assert_eq!(network("fd00::/8").unwrap(), "fd00::/8");
        assert!(network("172.17.0.1/16").is_err());
        assert!(network("nonsense").is_err());
    }
}
