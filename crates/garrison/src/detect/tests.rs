use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use garrison_core::modules::ModuleId;
use serde_json::Value;

use super::fixtures::{
    Recorded, almalinux, bare, component, debian, detected, leftovers, mentions, own_firewall,
    stub, write,
};
use super::host::Host;
use super::system::Family;
use super::{Format, inspect, report, summary};

#[test]
fn a_red_hat_host_reports_the_paths_its_units_name() {
    let (_root, inventory) = detected(almalinux);
    let system = &inventory.system;
    assert_eq!(system.family, Family::Rhel);
    assert_eq!(system.name, "AlmaLinux 10.0 (Purple Lion)");
    assert_eq!(system.confinement.as_deref(), Some("SELinux enforcing"));
    let guards: Vec<&str> = system
        .guards
        .iter()
        .map(|(unit, _)| unit.as_str())
        .collect();
    assert_eq!(guards, ["firewalld.service", "chronyd.service"]);

    let stalwart = component(&inventory, "stalwart");
    assert!(stalwart.found);
    assert!(mentions(
        stalwart,
        "configuration /opt/stalwart/etc/config.toml (from the unit)"
    ));
    assert!(mentions(stalwart, "listening on 25, 8080"));
    assert!(!mentions(stalwart, "port 25 belongs to"));

    let scanner = component(&inventory, "clamav-scanner");
    assert!(mentions(scanner, "package clamd 1.4.3-1.el10"));
    assert!(mentions(
        scanner,
        "configuration /etc/clamd.d/scan.conf (from the unit)"
    ));
    let milter = component(&inventory, "clamav-milter");
    assert_eq!(
        milter.settings["milter_config"],
        "/etc/mail/clamav-milter.conf"
    );
    assert!(mentions(milter, "milter socket: inet:7357@127.0.0.1"));
    assert!(mentions(milter, "infected mail: Reject"));
    let signatures = component(&inventory, "signatures");
    assert!(mentions(
        signatures,
        "3 signature files in /var/lib/clamav (from clamd.conf)"
    ));
    assert_eq!(
        signatures.settings["fangfrisch_database"],
        "/var/lib/fangfrisch/db.sqlite"
    );

    let proxy = component(&inventory, "proxy");
    assert_eq!(proxy.units, ["nginx.service"]);
    assert!(mentions(proxy, "no /etc/nginx/snippets yet"));
    assert!(mentions(
        component(&inventory, "certificates"),
        "certificates for mail.example.org"
    ));
    // A stopped resolver answers nothing, so only unbound counts.
    let resolver = component(&inventory, "resolver");
    assert_eq!(resolver.units, ["unbound.service"]);
    assert!(mentions(resolver, "asks 127.0.0.1 on this host"));
    let backups = component(&inventory, "backups");
    assert!(mentions(backups, "package restic 0.18.1-1.el10"));
    assert_eq!(backups.units, ["restic-backup.timer"]);
    assert_eq!(backups.jobs, ["restic-backup.service"]);
    // An ntfy server here is named with how to be told through it; the topic
    // is the operator's to choose.
    let notifications = component(&inventory, "notifications");
    assert_eq!(notifications.units, ["ntfy.service"]);
    assert!(mentions(
        notifications,
        "base URL https://notify.example.org (from /etc/ntfy/server.yml)"
    ));
    assert!(mentions(
        notifications,
        "ntfy_url = \"https://notify.example.org/<topic>\" under [notifications]"
    ));
    assert!(!component(&inventory, "garrison").found);
}

#[test]
fn a_debian_host_falls_back_to_the_distribution_paths() {
    let (_root, inventory) = detected(debian);
    assert_eq!(inventory.system.family, Family::Debian);
    assert_eq!(
        inventory.system.confinement.as_deref(),
        Some("AppArmor enabled")
    );
    let scanner = component(&inventory, "clamav-scanner");
    assert_eq!(scanner.settings["clamd_config"], "/etc/clamav/clamd.conf");
    assert!(mentions(
        scanner,
        "configuration /etc/clamav/clamd.conf (distribution default)"
    ));
    assert!(mentions(scanner, "clamav-daemon.service: active, enabled"));
    let milter = component(&inventory, "clamav-milter");
    assert!(mentions(milter, "clamav-milter.service: failed, enabled"));
    assert_eq!(
        milter.settings["milter_config"],
        "/etc/clamav/clamav-milter.conf"
    );
    assert!(mentions(
        component(&inventory, "signatures"),
        "0 signature files in /var/lib/clamav"
    ));
    // Stalwart runs in a container that publishes the SMTP port.
    let stalwart = component(&inventory, "stalwart");
    assert!(stalwart.found);
    assert!(mentions(
        stalwart,
        "container stalwart (stalwartlabs/stalwart:v1.1.0)"
    ));
    assert!(mentions(stalwart, "port 25 belongs to docker-proxy"));
    assert!(!mentions(stalwart, "roundcube"));
    assert!(mentions(
        component(&inventory, "resolver"),
        "asks 9.9.9.9; blocklists"
    ));
    // A package removed with its configuration left behind is not installed,
    // and the distribution's own database backup is not a mail backup.
    let backups = component(&inventory, "backups");
    assert!(!mentions(backups, "package restic"));
    assert_eq!(backups.units, ["borgmatic.timer"]);
}

#[test]
fn the_resolved_stub_is_not_taken_for_a_local_resolver() {
    let (_root, inventory) = detected(stub);
    let resolver = component(&inventory, "resolver");
    assert!(mentions(
        resolver,
        "systemd-resolved stub 127.0.0.53, which forwards"
    ));
    assert!(!mentions(resolver, "on this host"));
}

#[test]
fn an_unknown_host_finds_nothing_and_says_so() {
    let (_root, inventory) = detected(bare);
    assert_eq!(inventory.system.family, Family::Other);
    assert!(
        inventory
            .components
            .iter()
            .all(|component| !component.found)
    );
    let text = report::render(&inventory, Format::Text);
    assert!(text.starts_with("an unknown Linux distribution"));
    assert!(
        text.lines()
            .any(|line| line.starts_with("ClamAV scanner") && line.ends_with("not found"))
    );
    assert!(text.contains("Nothing was changed."));
}

#[test]
fn the_provider_entries_are_valid_configuration() {
    for prepare in [almalinux, debian, bare] {
        let (_root, inventory) = detected(prepare);
        let text = report::render(&inventory, Format::Toml);
        let table: toml::Table = text.parse().unwrap();
        let providers: Vec<toml::Table> = table
            .get("providers")
            .and_then(toml::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_table().cloned())
                    .collect()
            })
            .unwrap_or_default();
        garrison_collector::build(&providers).unwrap();
    }
    let (_root, inventory) = detected(almalinux);
    let text = report::render(&inventory, Format::Toml);
    assert!(text.contains("type = \"clamav\"\nclamd_config = \"/etc/clamd.d/scan.conf\"\n"));
    assert!(text.contains(
        "{ unit = \"clamd@scan.service\", label = \"ClamAV scanner\", modules = [\"antivirus\", \"services\"] }"
    ));
    assert!(text.contains(
        "{ unit = \"firewalld.service\", label = \"Firewall\", modules = [\"services\"] }"
    ));
    for empty in [bare, leftovers] {
        let (_root, inventory) = detected(empty);
        assert!(!report::render(&inventory, Format::Toml).contains("[[providers]]"));
    }
}

#[test]
fn the_inventory_is_json_for_other_tools() {
    let (_root, inventory) = detected(debian);
    let value: Value = serde_json::from_str(&report::render(&inventory, Format::Json)).unwrap();
    assert_eq!(value["system"]["family"], "debian");
    assert_eq!(value["system"]["packages"], "dpkg");
    let scanner = value["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "clamav-scanner")
        .unwrap();
    assert_eq!(scanner["found"], true);
    assert_eq!(
        scanner["settings"]["clamd_config"],
        "/etc/clamav/clamd.conf"
    );
}

/// Every path below `directory`, with each file's content.
fn tree(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    for entry in fs::read_dir(directory).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(tree(&path));
        } else {
            found.push((path.clone(), fs::read(&path).unwrap()));
        }
    }
    found.sort();
    found
}

#[test]
fn detect_changes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let runner = almalinux(root.path());
    let before = tree(root.path());
    let inventory = inspect(&Host::new(root.path().to_owned(), &runner));
    for format in [Format::Text, Format::Json, Format::Toml] {
        report::render(&inventory, format);
    }
    assert_eq!(tree(root.path()), before);
}

#[test]
fn the_summary_names_units_or_else_the_first_fact() {
    let (_root, inventory) = detected(debian);
    let found = summary(&inventory);
    assert_eq!(found["clamav-scanner"], ["clamav-daemon.service"]);
    assert_eq!(
        found["stalwart"],
        ["container stalwart (stalwartlabs/stalwart:v1.1.0)"]
    );
    assert!(!found.contains_key("proxy"));
}

fn providers(text: &str) -> Vec<toml::Table> {
    let table: toml::Table = text.parse().unwrap();
    table["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_table().unwrap().clone())
        .collect()
}

#[test]
fn modules_adds_what_the_chosen_modules_show_and_the_configuration_lacks() {
    let (_root, inventory) = detected(almalinux);
    let chosen = BTreeSet::from([ModuleId::Dashboard, ModuleId::Services, ModuleId::Antivirus]);
    let configured = providers(
        "[[providers]]\ntype = \"systemd\"\n\
         units = [{ unit = \"nginx.service\", label = \"Proxy\", modules = [\"services\"] }]\n",
    );
    let text = report::adoptable(&inventory, &report::Scope::of(&chosen, &configured));
    assert!(text.starts_with("# Added by `garrison modules`"));
    assert!(text.contains("type = \"clamav\"\nclamd_config = \"/etc/clamd.d/scan.conf\""));
    assert!(text.contains("\"clamd@scan.service\""));
    // The services page is always there; nginx is configured already, and
    // DNS & TLS and backups were not chosen.
    assert!(text.contains("\"stalwart.service\""));
    assert!(!text.contains("\"nginx.service\""));
    assert!(!text.contains("unbound") && !text.contains("restic"));
    let mut with_clamav = configured.clone();
    with_clamav.extend(providers("[[providers]]\ntype = \"clamav\"\n"));
    let text = report::adoptable(&inventory, &report::Scope::of(&chosen, &with_clamav));
    assert!(!text.contains("type = \"clamav\""));
    let (_root, nothing) = detected(bare);
    assert_eq!(
        report::adoptable(&nothing, &report::Scope::of(&chosen, &configured)),
        ""
    );
}

/// Debian after a move from Red Hat: the old `ClamAV` configuration stayed.
fn debian_with_red_hat_files(root: &Path) -> Recorded {
    let recorded = debian(root);
    write(root, "/etc/clamd.d/scan.conf", "");
    write(root, "/etc/mail/clamav-milter.conf", "");
    recorded
}

/// A database directory without signature files, and a restic binary that
/// came without a package; SELinux permissive; an installed Garrison.
fn odd(root: &Path) -> Recorded {
    write(root, "/var/lib/clamav/freshclam.dat", "");
    write(root, "/usr/bin/restic", "");
    write(root, "/sys/fs/selinux/enforce", "0\n");
    fs::create_dir_all(root.join("opt/garrison/releases/0.1.0")).unwrap();
    std::os::unix::fs::symlink("releases/0.1.0", root.join("opt/garrison/current")).unwrap();
    bare(root)
}

#[test]
fn each_finding_rests_on_evidence_of_its_own() {
    // A distribution default comes from the host's own family.
    let (_root, moved) = detected(debian_with_red_hat_files);
    let scanner = component(&moved, "clamav-scanner");
    assert_eq!(scanner.settings["clamd_config"], "/etc/clamav/clamd.conf");
    let milter = component(&moved, "clamav-milter");
    assert_eq!(
        milter.settings["milter_config"],
        "/etc/clamav/clamav-milter.conf"
    );

    // Signature files alone count, an empty directory does not.
    let (_root, old) = detected(leftovers);
    let signatures = component(&old, "signatures");
    assert!(signatures.found);
    assert!(mentions(
        signatures,
        "1 signature files in /var/lib/clamav (default)"
    ));
    let (_root, inventory) = detected(odd);
    let signatures = component(&inventory, "signatures");
    assert!(!signatures.found);
    assert!(mentions(signatures, "0 signature files in /var/lib/clamav"));

    // A backup program without its package, SELinux permissive, Garrison.
    let backups = component(&inventory, "backups");
    assert!(backups.found);
    assert!(mentions(backups, "program /usr/bin/restic"));
    assert_eq!(
        inventory.system.confinement.as_deref(),
        Some("SELinux permissive")
    );
    let garrison = component(&inventory, "garrison");
    assert!(garrison.found);
    assert!(mentions(garrison, "release 0.1.0"));

    // Without nginx there is no advice about its snippets, and without ntfy
    // none about a topic.
    let (_root, empty) = detected(bare);
    assert!(!mentions(component(&empty, "proxy"), "snippets"));
    let notifications = component(&empty, "notifications");
    assert!(!notifications.found && notifications.details.is_empty());
}

#[test]
fn units_that_load_the_hosts_own_firewall_rules_are_named_for_host_care() {
    let (_root, inventory) = detected(own_firewall);
    let found = &inventory.system.firewall_units;
    // By its name, by `nft -f` and by a restore of iptables rules; neither
    // nginx nor an `nft` that only watches.
    assert_eq!(
        found,
        &[
            "edge-rules.service",
            "legacy-filter.service",
            "mailstack-firewall.service"
        ]
    );
    let guards: Vec<&str> = inventory
        .system
        .guards
        .iter()
        .map(|(unit, _)| unit.as_str())
        .collect();
    assert_eq!(
        guards,
        [
            "chronyd.service",
            "edge-rules.service",
            "legacy-filter.service",
            "mailstack-firewall.service"
        ]
    );
    let text = report::render(&inventory, Format::Text);
    assert!(
        text.contains("Firewall (mailstack-firewall.service)")
            && text.contains("firewall_units = [\"edge-rules.service\", "),
        "{text}"
    );
    let toml = report::render(&inventory, Format::Toml);
    assert!(
        toml.contains(
            "  { unit = \"mailstack-firewall.service\", label = \"Firewall\", modules = [\"services\"] },"
        ) && toml.contains(
            "# firewall_units = [\"edge-rules.service\", \"legacy-filter.service\", \
             \"mailstack-firewall.service\"]"
        ),
        "{toml}"
    );
    // The entries stay a valid configuration: the hint is a comment.
    assert!(toml.parse::<toml::Table>().is_ok(), "{toml}");
    // A known firewall service needs nothing named.
    let (_root, known) = detected(almalinux);
    assert_eq!(known.system.firewall_units, Vec::<String>::new());
}

#[test]
fn the_report_names_the_guards_and_entries_their_modules() {
    let (_root, inventory) = detected(almalinux);
    let text = report::render(&inventory, Format::Text);
    assert!(
        text.lines()
            .any(|line| line.starts_with("SELinux enforcing, ")),
        "{text}"
    );
    let toml = report::render(&inventory, Format::Toml);
    for (unit, modules) in [
        ("unbound.service", "[\"dns_tls\", \"services\"]"),
        ("restic-backup.timer", "[\"backups\", \"services\"]"),
        ("ntfy.service", "[\"alerts\", \"services\"]"),
    ] {
        let entry = toml
            .lines()
            .find(|line| line.contains(&format!("unit = \"{unit}\"")))
            .unwrap_or_else(|| panic!("{unit}: {toml}"));
        assert!(
            entry.ends_with(&format!("modules = {modules} }},")),
            "{entry}"
        );
    }
    // The job the backup timer starts rests between its runs.
    assert!(
        toml.contains(
            "  { unit = \"restic-backup.service\", label = \"Backup job\", \
             modules = [\"backups\", \"services\"], expect = \"idle\" },"
        ),
        "{toml}"
    );
    // Without guards the first component follows the system line's spacing.
    let (_root, empty) = detected(bare);
    let text = report::render(&empty, Format::Text);
    assert!(
        text.lines()
            .nth(2)
            .is_some_and(|line| line.starts_with("Stalwart")),
        "{text}"
    );
}
