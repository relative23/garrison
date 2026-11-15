//! What the sandboxes of Garrison's units hide from their services:
//! root reads a file there, and the service never does.

use std::path::Path;

use garrison_core::config;

use super::BROKER;

/// The places `garrison-broker.service` hides from the broker, each with the
/// setting that does: they are inaccessible to it (`ProtectHome=true`), or
/// its own and empty (`PrivateTmp=true`, and `PrivateDevices=true` for
/// `/dev`, into which systemd still binds the host's `/dev/shm` and
/// `/dev/mqueue`). Root sees a file there; the broker never reads it.
const BROKER_HIDDEN: [(&str, &str); 6] = [
    ("/home", "ProtectHome=true"),
    ("/root", "ProtectHome=true"),
    ("/run/user", "ProtectHome=true"),
    ("/tmp", "PrivateTmp=true"),
    ("/var/tmp", "PrivateTmp=true"),
    ("/dev", "PrivateDevices=true"),
];
const BROKER_DEV_SHARED: [&str; 2] = ["/dev/shm", "/dev/mqueue"];

/// The hidden place that holds `path`, and the setting that hides it.
fn hidden_place(path: &Path) -> Option<(&'static str, &'static str)> {
    if BROKER_DEV_SHARED
        .iter()
        .any(|shared| path.starts_with(shared))
    {
        return None;
    }
    BROKER_HIDDEN
        .into_iter()
        .find(|(place, _)| path.starts_with(place))
}

/// Why the broker's unit keeps it from reading the policy at `policy`, and
/// what to do; `None` where it reads it there. `resolved` is the same path
/// with the links of its folders followed, as the broker's open follows
/// them: either path in a hidden place hides the file.
fn hidden_at(policy: &Path, resolved: Option<&Path>) -> Option<(String, String)> {
    let (hidden, (place, setting)) = hidden_place(policy)
        .map(|found| (policy, found))
        .or_else(|| resolved.and_then(|path| Some((path, hidden_place(path)?))))?;
    let through = if hidden == policy {
        String::new()
    } else {
        format!(", which leads to {}", hidden.display())
    };
    Some((
        format!(
            "broker.policy is {}{through}, under {place}, which {BROKER} hides from the broker \
             ({setting}): the broker cannot read it there, and nobody can sign in",
            policy.display()
        ),
        "Keep the policy where the broker sees it, such as /etc/garrison/access-policy.json, \
         and name that in broker.policy"
            .to_owned(),
    ))
}

/// [`hidden_at`] for the policy at `policy`.
pub(crate) fn hidden_policy(policy: &Path) -> Option<(String, String)> {
    let resolved = policy
        .parent()
        .and_then(|folder| std::fs::canonicalize(folder).ok())
        .zip(policy.file_name())
        .map(|(folder, name)| folder.join(name));
    hidden_at(policy, resolved.as_deref())
}

/// What check-config says of a policy the broker's unit hides: a refusal
/// (`Err`) for the configuration the units read, since they start every
/// service with the default file, and a warning for any other, such as a
/// draft's or a test's, which no unit runs.
pub(crate) fn policy_place(policy: &Path, configuration: &Path) -> Result<Option<String>, String> {
    let Some((what, fix)) = hidden_policy(policy) else {
        return Ok(None);
    };
    let said = format!("{what}. {fix}.");
    if configuration == Path::new(config::DEFAULT_PATH) {
        Err(said)
    } else {
        Ok(Some(said))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::super::tests::values;
    use super::*;

    /// The places hidden from the broker are those of the settings in its
    /// unit that hide or replace a path, as systemd.exec(5) gives them and a
    /// container showed them (systemd 257): a unit that hides more, or less,
    /// fails here until the list follows.
    #[test]
    fn the_places_hidden_from_the_broker_are_those_its_unit_hides() {
        const HIDING: [&str; 14] = [
            "ProtectHome=",
            "PrivateTmp=",
            "PrivateDevices=",
            "InaccessiblePaths=",
            "TemporaryFileSystem=",
            "BindPaths=",
            "BindReadOnlyPaths=",
            "RootDirectory=",
            "RootImage=",
            "MountImages=",
            "ExtensionImages=",
            "ExtensionDirectories=",
            "PrivateUsers=",
            "ProtectProc=",
        ];
        let set: BTreeSet<String> = HIDING
            .iter()
            .flat_map(|key| {
                values(key)
                    .into_iter()
                    .filter(|(unit, _)| *unit == BROKER)
                    .map(move |(_, value)| format!("{key}{value}"))
            })
            .collect();
        let listed: BTreeSet<String> = BROKER_HIDDEN
            .iter()
            .map(|(_, setting)| (*setting).to_owned())
            .collect();
        assert_eq!(set, listed);
        let places = |wanted: &str| -> Vec<&str> {
            BROKER_HIDDEN
                .iter()
                .filter(|(_, setting)| *setting == wanted)
                .map(|(place, _)| *place)
                .collect()
        };
        assert_eq!(places("ProtectHome=true"), ["/home", "/root", "/run/user"]);
        assert_eq!(places("PrivateTmp=true"), ["/tmp", "/var/tmp"]);
        assert_eq!(places("PrivateDevices=true"), ["/dev"]);
    }

    #[test]
    fn a_policy_where_the_broker_cannot_read_it_is_named_with_the_setting() {
        let said = |policy: &str, resolved: Option<&str>| {
            hidden_at(Path::new(policy), resolved.map(Path::new)).map(|(what, _)| what)
        };
        assert_eq!(
            said("/home/admin/policy.json", None).as_deref(),
            Some(
                "broker.policy is /home/admin/policy.json, under /home, which \
                 garrison-broker.service hides from the broker (ProtectHome=true): the broker \
                 cannot read it there, and nobody can sign in"
            )
        );
        for (policy, setting) in [
            ("/root/policy.json", "(ProtectHome=true)"),
            ("/run/user/0/policy.json", "(ProtectHome=true)"),
            ("/tmp/policy.json", "(PrivateTmp=true)"),
            ("/var/tmp/garrison/policy.json", "(PrivateTmp=true)"),
            ("/dev/policy.json", "(PrivateDevices=true)"),
        ] {
            assert!(said(policy, None).unwrap().contains(setting), "{policy}");
        }
        // The broker sees these, and a name that only begins like a place.
        for policy in [
            "/etc/garrison/access-policy.json",
            "/srv/garrison/policy.json",
            "/dev/shm/policy.json",
            "/homes/policy.json",
            "/var/lib/garrison/policy.json",
        ] {
            assert_eq!(said(policy, Some(policy)), None, "{policy}");
        }
        // A folder that is a link into a hidden place hides the file too.
        assert_eq!(
            said("/srv/policy/access.json", Some("/home/admin/access.json")).as_deref(),
            Some(
                "broker.policy is /srv/policy/access.json, which leads to /home/admin/access.json, \
                 under /home, which garrison-broker.service hides from the broker \
                 (ProtectHome=true): the broker cannot read it there, and nobody can sign in"
            )
        );
        let hidden = Path::new("/home/admin/policy.json");
        assert!(policy_place(hidden, Path::new(config::DEFAULT_PATH)).is_err());
        let draft = policy_place(hidden, Path::new("/root/draft.toml")).unwrap();
        assert!(draft.unwrap().ends_with(
            "Keep the policy where the broker sees it, such as \
                 /etc/garrison/access-policy.json, and name that in broker.policy."
        ));
        let seen = Path::new("/etc/garrison/access-policy.json");
        assert_eq!(
            policy_place(seen, Path::new(config::DEFAULT_PATH)),
            Ok(None)
        );
    }
}
