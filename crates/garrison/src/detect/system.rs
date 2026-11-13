//! The distribution, its package database and what guards the host.

use std::collections::BTreeMap;

use super::host::Host;

/// Package names and default paths differ between the families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Family {
    Rhel,
    Debian,
    Other,
}

impl Family {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Rhel => "rhel",
            Self::Debian => "debian",
            Self::Other => "other",
        }
    }
}

/// The package database to ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Packages {
    Rpm,
    Dpkg,
}

impl Packages {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Rpm => "rpm",
            Self::Dpkg => "dpkg",
        }
    }
}

#[derive(Debug)]
pub(super) struct System {
    pub(super) name: String,
    pub(super) family: Family,
    pub(super) packages: Option<Packages>,
    /// `SELinux` or `AppArmor`, as the kernel reports it.
    pub(super) confinement: Option<String>,
    /// Active firewall and time synchronization units with their labels.
    pub(super) guards: Vec<(String, &'static str)>,
    /// Units of the host's own that load its firewall rules, where none of
    /// the known firewall services runs: what host care's `firewall_units`
    /// should name.
    pub(super) firewall_units: Vec<String>,
}

const GUARDS: [(&str, &str); 6] = [
    ("firewalld.service", "Firewall"),
    ("nftables.service", "Firewall"),
    ("ufw.service", "Firewall"),
    ("chronyd.service", "Time synchronization"),
    ("chrony.service", "Time synchronization"),
    ("systemd-timesyncd.service", "Time synchronization"),
];

/// Services that load firewall rules of the host's own.
const LOADERS: [&str; 8] = [
    "iptables.service",
    "ip6tables.service",
    "netfilter-persistent.service",
    "shorewall.service",
    "shorewall6.service",
    "ferm.service",
    "firehol.service",
    "csf.service",
];
/// Programs that load a rule set as a unit's first command; `nft` does with `-f`.
const RESTORES: [&str; 6] = [
    "iptables-restore",
    "ip6tables-restore",
    "iptables-nft-restore",
    "ip6tables-nft-restore",
    "iptables-legacy-restore",
    "ip6tables-legacy-restore",
];

pub(super) fn inspect(host: &Host<'_>) -> System {
    let release = host
        .read("/etc/os-release")
        .or_else(|| host.read("/usr/lib/os-release"))
        .map(|text| os_release(&text))
        .unwrap_or_default();
    let family = family(&release);
    let names: Vec<&str> = GUARDS.iter().map(|(unit, _)| *unit).collect();
    let units = host.units(&names);
    let mut guards: Vec<(String, &'static str)> = GUARDS
        .iter()
        .filter(|(name, _)| units.get(*name).is_some_and(|unit| unit.active == "active"))
        .map(|(name, label)| ((*name).to_owned(), *label))
        .collect();
    // Host care's firewall check knows the services above; another unit that
    // loads the rules must be named to it.
    let firewall_units = if guards.iter().any(|(_, label)| *label == "Firewall") {
        Vec::new()
    } else {
        own_firewalls(host)
    };
    guards.extend(firewall_units.iter().map(|unit| (unit.clone(), "Firewall")));
    System {
        name: release
            .get("PRETTY_NAME")
            .cloned()
            .unwrap_or_else(|| "an unknown Linux distribution".to_owned()),
        family,
        packages: match family {
            Family::Rhel => Some(Packages::Rpm),
            Family::Debian => Some(Packages::Dpkg),
            Family::Other => None,
        },
        confinement: confinement(host),
        guards,
        firewall_units,
    }
}

/// Running units that load the host's firewall rules: a known loader, a unit
/// named for a firewall, or one whose command is `nft -f` or a restore of
/// iptables rules. A unit that runs a script of its own is found by its name.
fn own_firewalls(host: &Host<'_>) -> Vec<String> {
    let active = host.active_services();
    let names: Vec<&str> = active
        .iter()
        .map(String::as_str)
        .filter(|name| !GUARDS.iter().any(|(guard, _)| guard == name))
        .collect();
    if names.is_empty() {
        return Vec::new();
    }
    let units = host.units(&names);
    names
        .into_iter()
        .filter(|name| {
            LOADERS.contains(name)
                || name.contains("firewall")
                || units
                    .get(*name)
                    .is_some_and(|unit| loads_rules(&unit.command))
        })
        .map(str::to_owned)
        .collect()
}

/// `nft -f /etc/rules.nft` or `iptables-restore /etc/iptables/rules.v4`.
fn loads_rules(command: &[String]) -> bool {
    let Some(program) = command.first() else {
        return false;
    };
    match program.rsplit('/').next().unwrap_or(program) {
        "nft" => command
            .iter()
            .any(|word| word == "-f" || word.starts_with("--file")),
        name => RESTORES.contains(&name),
    }
}

/// `KEY=value` lines; values may be quoted.
fn os_release(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            let value = value
                .trim()
                .trim_matches(|quote| quote == '"' || quote == '\'');
            (key.trim().to_owned(), value.to_owned())
        })
        .collect()
}

fn family(release: &BTreeMap<String, String>) -> Family {
    let words: Vec<&str> = ["ID", "ID_LIKE"]
        .iter()
        .filter_map(|key| release.get(*key))
        .flat_map(|value| value.split_whitespace())
        .collect();
    if words
        .iter()
        .any(|word| matches!(*word, "rhel" | "fedora" | "centos"))
    {
        Family::Rhel
    } else if words
        .iter()
        .any(|word| matches!(*word, "debian" | "ubuntu"))
    {
        Family::Debian
    } else {
        Family::Other
    }
}

fn confinement(host: &Host<'_>) -> Option<String> {
    match host
        .read("/sys/fs/selinux/enforce")
        .as_deref()
        .map(str::trim)
    {
        Some("1") => return Some("SELinux enforcing".to_owned()),
        Some("0") => return Some("SELinux permissive".to_owned()),
        _ => {}
    }
    host.read("/sys/module/apparmor/parameters/enabled")
        .filter(|value| value.trim() == "Y")
        .map(|_| "AppArmor enabled".to_owned())
}
