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
}

const GUARDS: [(&str, &str); 6] = [
    ("firewalld.service", "Firewall"),
    ("nftables.service", "Firewall"),
    ("ufw.service", "Firewall"),
    ("chronyd.service", "Time synchronization"),
    ("chrony.service", "Time synchronization"),
    ("systemd-timesyncd.service", "Time synchronization"),
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
    let guards = GUARDS
        .iter()
        .filter(|(name, _)| units.get(*name).is_some_and(|unit| unit.active == "active"))
        .map(|(name, label)| ((*name).to_owned(), *label))
        .collect();
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
