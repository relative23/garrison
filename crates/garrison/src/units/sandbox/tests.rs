use std::collections::BTreeSet;

use super::super::tests::values;
use super::*;

/// The settings of systemd.exec(5) that hide or replace a path.
const HIDING: [&str; 18] = [
    "ProtectHome=",
    "PrivateTmp=",
    "PrivateDevices=",
    "ProtectKernelModules=",
    "ProtectKernelTunables=",
    "ProtectKernelLogs=",
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
    "ProcSubset=",
];

/// The hiding settings of `unit` as it is shipped.
fn hiding_of(unit: &str) -> BTreeSet<String> {
    HIDING
        .iter()
        .flat_map(|key| {
            values(key)
                .into_iter()
                .filter(|(named, _)| *named == unit)
                .map(move |(_, value)| format!("{key}{value}"))
        })
        .collect()
}

/// The places hidden from the broker and from the collector are those of
/// the settings in their units that hide or replace a path, as
/// systemd.exec(5) gives them and a container showed them (systemd 257): a
/// unit that hides more, or less, fails here until its list follows.
#[test]
fn the_places_hidden_are_those_the_broker_and_collector_units_hide() {
    let listed: BTreeSet<&str> = HIDDEN.iter().map(|(_, setting, _)| *setting).collect();
    for (unit, sets) in [(BROKER, &BROKER_SETS[..]), (COLLECT, &COLLECT_SETS[..])] {
        assert!(
            sets.iter().all(|setting| listed.contains(setting)),
            "{unit}"
        );
        let listed: BTreeSet<String> = sets.iter().map(ToString::to_string).collect();
        assert_eq!(hiding_of(unit), listed, "{unit}");
    }
    // No place is listed that neither unit hides.
    let set: BTreeSet<&str> = BROKER_SETS.iter().chain(&COLLECT_SETS).copied().collect();
    assert_eq!(set, listed);
    let places = |wanted: &str| -> Vec<&str> {
        HIDDEN
            .iter()
            .filter(|(_, setting, _)| *setting == wanted)
            .map(|(place, _, _)| *place)
            .collect()
    };
    assert_eq!(places("ProtectHome=true"), ["/home", "/root", "/run/user"]);
    assert_eq!(places("PrivateTmp=true"), ["/tmp", "/var/tmp"]);
    assert_eq!(places("PrivateDevices=true"), ["/dev"]);
    assert_eq!(
        places("ProtectKernelModules=true"),
        ["/lib/modules", "/usr/lib/modules"]
    );
    assert_eq!(
        places("ProtectKernelTunables=true"),
        ["/proc/kallsyms", "/proc/kcore"]
    );
    assert_eq!(places("ProtectKernelLogs=true"), ["/proc/kmsg"]);
    // Only the private /tmp and /var/tmp lie on the host's file systems.
    let same: Vec<&str> = HIDDEN
        .iter()
        .filter(|(_, _, same)| *same)
        .map(|(place, _, _)| *place)
        .collect();
    assert_eq!(same, ["/tmp", "/var/tmp"]);
}

/// The release base is judged by what any service unit hides, since each
/// starts its service from it: a unit that hides more fails here until
/// the list follows.
#[test]
fn a_release_base_no_unit_hides_is_the_only_one_taken() {
    let services = [
        super::super::WEB,
        super::super::INGEST,
        BROKER,
        COLLECT,
        super::super::WATCH,
    ];
    // ProtectProc= and ProcSubset= touch /proc alone, where no release lies.
    let elsewhere = ["ProtectProc=invisible", "ProcSubset=pid"];
    let any: BTreeSet<String> = services
        .iter()
        .flat_map(|unit| hiding_of(unit))
        .filter(|setting| !elsewhere.contains(&setting.as_str()))
        .collect();
    let listed: BTreeSet<String> = ANY_SETS.iter().map(ToString::to_string).collect();
    assert_eq!(any, listed);
    let base = Path::new("/opt/garrison");
    assert_eq!(base_hidden_at(base, Some(base)), None);
    assert_eq!(
        base_hidden_at(base, Some(Path::new("/srv/disk/garrison"))),
        None
    );
    let refused = base_hidden_at(base, Some(Path::new("/home/disk/garrison"))).unwrap();
    assert!(
        refused.starts_with(
            "/opt/garrison leads to /home/disk/garrison, which lies under /home, which \
             Garrison's units hide from their services (ProtectHome=true)"
        ),
        "{refused}"
    );
    for hidden in [
        "/root/garrison",
        "/run/user/0/garrison",
        "/tmp/garrison",
        "/var/tmp/opt",
    ] {
        assert!(
            base_hidden_at(base, Some(Path::new(hidden))).is_some(),
            "{hidden}"
        );
    }
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
        (
            "/usr/lib/modules/policy.json",
            "(ProtectKernelModules=true)",
        ),
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

/// What is said of a check's path in `kind`'s `option`, used so, where its
/// links lead to `resolved`.
fn said(path: &str, used: Use, resolved: Option<&str>) -> Option<String> {
    let host = HostPath {
        option: "option",
        path: Path::new(path),
        used,
    };
    hidden_check("kind", &host, resolved.map(Path::new)).map(|(what, _)| what)
}

#[test]
fn a_checks_path_where_the_collector_cannot_see_it_is_named_with_the_setting() {
    assert_eq!(
        said("/home/admin/nightly.json", Use::Reads, None).as_deref(),
        Some(
            "providers[kind].option is /home/admin/nightly.json, under /home, which \
             garrison-collect.service hides from the collector (ProtectHome=true): the check \
             cannot read it there"
        )
    );
    for (path, used, words) in [
        (
            "/tmp/bin/version",
            Use::Runs,
            "(PrivateTmp=true): the check cannot run it there",
        ),
        (
            "/var/tmp/x",
            Use::Reads,
            "(PrivateTmp=true): the check cannot read it there",
        ),
        ("/root/clamd.conf", Use::Reads, "(ProtectHome=true)"),
        ("/run/user/0/x", Use::Reads, "(ProtectHome=true)"),
        ("/proc/kcore", Use::Reads, "(ProtectKernelTunables=true)"),
        ("/proc/kmsg", Use::Reads, "(ProtectKernelLogs=true)"),
        (
            "/home",
            Use::Measures,
            "(ProtectHome=true): the check would measure the unit's own file system there \
             instead",
        ),
        (
            "/dev",
            Use::Measures,
            "(PrivateDevices=true): the check would measure the unit's own file system there \
             instead",
        ),
        (
            "/home/mail",
            Use::Measures,
            "(ProtectHome=true): the check cannot measure it there",
        ),
        (
            "/tmp/x",
            Use::Measures,
            "(PrivateTmp=true): the check cannot measure it there",
        ),
    ] {
        let found = said(path, used, None).unwrap_or_default();
        assert!(found.contains(words), "{path}: {found}");
    }
    // The collector sees these: its own /tmp and /var/tmp lie on the
    // host's file systems, which statvfs of them measures.
    for (path, used) in [
        ("/tmp", Use::Measures),
        ("/var/tmp", Use::Measures),
        ("/dev/shm", Use::Measures),
        ("/", Use::Measures),
        ("/proc", Use::Reads),
        ("/proc/meminfo", Use::Reads),
        ("/etc/clamd.d/scan.conf", Use::Reads),
        ("/var/lib/garrison/backup-check/restic.json", Use::Reads),
        ("/usr/bin/clamdscan", Use::Runs),
        ("/homes/x", Use::Reads),
        // The installed kernels, which host care's restart check reads.
        ("/lib/modules", Use::Reads),
        ("/usr/lib/modules/6.12.0/modules.dep", Use::Reads),
    ] {
        assert_eq!(said(path, used, Some(path)), None, "{path}");
    }
    // A link into a hidden place hides what it names, the last name too.
    assert_eq!(
        said("/srv/bulwark", Use::Reads, Some("/home/admin/bulwark")).as_deref(),
        Some(
            "providers[kind].option is /srv/bulwark, which leads to /home/admin/bulwark, under \
             /home, which garrison-collect.service hides from the collector (ProtectHome=true): \
             the check cannot read it there"
        )
    );
}

#[test]
fn a_hidden_check_path_is_refused_for_the_file_the_units_read_and_warned_of_elsewhere() {
    let table = |text: &str| -> toml::Table { text.parse().unwrap() };
    let hidden = garrison_collector::build(&[table(
        "type = \"receipt\"\nid = \"nightly\"\ntitle = \"Nightly job\"\n\
         path = \"/home/admin/nightly.json\"\nmodules = [\"services\"]",
    )])
    .unwrap();
    let words = "providers[receipt].path is /home/admin/nightly.json, under /home, which \
                 garrison-collect.service hides from the collector (ProtectHome=true): the check \
                 cannot read it there. Keep it where the collector sees it and name that in \
                 providers[receipt].path, or show the collector that place read-only at another \
                 one (docs/operator/checks.md, \"Paths the collector cannot see\").";
    assert_eq!(
        collector_places(&hidden, Path::new(config::DEFAULT_PATH)),
        Err(vec![words.to_owned()])
    );
    assert_eq!(
        collector_places(&hidden, Path::new("/root/draft.toml")),
        Ok(vec![words.to_owned()])
    );
    // The defaults of every check lie where the collector sees them.
    let defaults = garrison_collector::build(&[
        table("type = \"host\""),
        table("type = \"host-care\""),
        table("type = \"backup-check\""),
        table("type = \"clamav\""),
    ])
    .unwrap();
    assert_eq!(
        collector_places(&defaults, Path::new(config::DEFAULT_PATH)),
        Ok(Vec::new())
    );
}
