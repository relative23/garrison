use super::*;
use crate::testing::table;

#[test]
fn unknown_provider_types_and_settings_fail_at_start() {
    let error = |text: &str| build(&[table(text)]).err().unwrap().0;
    assert_eq!(
        error("type = \"docker\""),
        "Unknown provider type \"docker\"; known: backup-check, bulwark, clamav, dns, host, host-care, \
         http, mail-flow, mail-test, prometheus, receipt, releases, reputation, senders, sign-in, stalwart, systemd, tls, \
         version-command"
    );
    assert!(error("name = \"x\"").starts_with("A provider has no type;"));
    assert!(error("type = 7").starts_with("Unknown provider type 7;"));
    assert_eq!(
        error("type = \"host\"\ndisk = \"/\""),
        "providers[host] has unknown settings: disk"
    );
    assert_eq!(
        error("type = \"http\"\nid = \"a\"\ntitle = \"A\"\nurl = \"http://10.0.0.1/\""),
        "providers[http].url must be a loopback http:// URL"
    );
}

#[test]
fn the_example_configuration_builds() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/config/garrison.example.toml");
    let config = garrison_core::config::load(&path).unwrap();
    assert!(!build(&config.collector.providers).unwrap().is_empty());
}

#[test]
fn every_provider_reports_under_its_configured_type() {
    let settings = [
        ("stalwart", ""),
        ("host", ""),
        (
            "systemd",
            "units = [{ unit = \"dns.service\", label = \"DNS\", modules = [\"services\"] }]",
        ),
    ];
    for (kind, extra) in settings {
        let raw = table(&format!("type = \"{kind}\"\n{extra}"));
        let providers = build(&[raw]).unwrap();
        assert_eq!(providers[0].name(), kind);
    }
}

#[test]
fn two_providers_that_report_one_observation_are_refused_with_their_places() {
    let error = |texts: &[&str]| {
        let tables: Vec<toml::Table> = texts.iter().map(|text| table(text)).collect();
        build(&tables).err().unwrap().0
    };
    let http = |id: &str| {
        format!("type = \"http\"\nid = \"{id}\"\ntitle = \"A\"\nurl = \"http://127.0.0.1:9/\"")
    };
    assert_eq!(
        error(&["type = \"host\"", &http("web"), &http("web")]),
        "providers[2] (http) reports the observation http.web as well as providers[1] (http); \
         give each its own id, unit or component, or take one of them out"
    );
    // With ids of their own, two of a kind are in order.
    let both = [table(&http("web")), table(&http("api"))];
    assert_eq!(build(&both).unwrap().len(), 2);
    let receipt = "type = \"receipt\"\nid = \"backup\"\ntitle = \"B\"\npath = \"/var/lib/receipts/backup.json\"\nmodules = [\"backups\"]";
    assert!(error(&[receipt, receipt]).starts_with(
        "providers[1] (receipt) reports the observation receipt.backup as well as providers[0] (receipt)"
    ));
    // A unit in two tables, and twice in one.
    let unit = "type = \"systemd\"\nunits = [{ unit = \"dns.service\", label = \"DNS\", modules = [\"services\"] }]";
    assert!(error(&[unit, "type = \"host\"", unit]).starts_with(
        "providers[2] (systemd) reports the observation systemd.dns.service as well as providers[0] (systemd)"
    ));
    let twice = "type = \"systemd\"\nunits = [{ unit = \"dns.service\", label = \"DNS\", modules = [\"services\"] }, \
                 { unit = \"dns.service\", label = \"Resolver\", modules = [\"services\"] }]";
    assert!(
        error(&[twice]).starts_with(
            "providers[0] (systemd) reports the observation systemd.dns.service twice"
        )
    );
    // A version command for Stalwart beside the check that reads its version.
    let command = "type = \"version-command\"\ncomponent = \"Stalwart\"\ncommand = [\"/usr/bin/true\"]\npattern = \"(.+)\"";
    assert!(error(&["type = \"stalwart\"", command]).starts_with(
        "providers[1] (version-command) reports the observation version.stalwart as well as providers[0] (stalwart)"
    ));
    // Two checks of a kind that reports fixed ids.
    assert!(error(&["type = \"host\"", "type = \"host\""]).starts_with(
        "providers[1] (host) reports the observation host.resources as well as providers[0] (host)"
    ));
    // Parts of one check in two tables do not meet.
    let care = |checks: &str| format!("type = \"host-care\"\nchecks = [{checks}]");
    let apart = [
        table(&care("\"updates\"")),
        table(&care("\"disk\", \"clock\"")),
    ];
    assert_eq!(build(&apart).unwrap().len(), 2);
    assert!(error(&[&care("\"disk\""), &care("\"disk\"")]).contains("host.disk-forecast"));
}

/// The configuration check holds the paths of the host that the checks name
/// against what the collector's unit hides, from `Provider::paths`. Each
/// check names every option it reads as a path there (`Options::path`, and
/// the program of `version-command`), and no other check reads one: a new
/// option read as a path fails here until its check names it.
#[test]
fn every_option_read_as_a_path_is_one_its_check_names() {
    let named = [
        ("host", "", &["disk_path", "proc"][..]),
        ("host-care", "", &["root", "disk_path"]),
        (
            "receipt",
            "id = \"r\"\ntitle = \"R\"\npath = \"/var/lib/r.json\"\nmodules = [\"services\"]",
            &["path"],
        ),
        ("backup-check", "", &["path"]),
        (
            "clamav",
            "fangfrisch_database = \"/var/lib/fangfrisch/db.sqlite\"",
            &[
                "milter_config",
                "clamd_config",
                "database_directory",
                "fangfrisch_database",
            ],
        ),
        (
            "bulwark",
            "admin_directory = \"/srv/bulwark\"",
            &["admin_directory"],
        ),
        (
            "version-command",
            "component = \"c\"\ncommand = [\"/usr/bin/c\", \"--version\"]",
            &["command"],
        ),
    ];
    for (kind, more, options) in named {
        let built = build(&[table(&format!("type = \"{kind}\"\n{more}"))]).unwrap();
        let paths: Vec<&str> = built[0].paths().iter().map(|path| path.option).collect();
        assert_eq!(paths, options, "{kind}");
    }
    let program = build(&[table(
        "type = \"version-command\"\ncomponent = \"c\"\ncommand = [\"/usr/bin/c\"]",
    )])
    .unwrap();
    assert_eq!(
        program[0].paths()[0].path,
        std::path::Path::new("/usr/bin/c")
    );
    // What the checks' sources read as a path is what the list above names.
    let mut read = std::collections::BTreeSet::new();
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for checks in [
        "checks-host",
        "checks-mail",
        "checks-network",
        "checks-stalwart",
    ] {
        let mut folders = vec![crates.join(checks).join("src/providers")];
        while let Some(folder) = folders.pop() {
            for entry in std::fs::read_dir(&folder).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    folders.push(path);
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for (_, after) in text
                    .match_indices("options.path(\"")
                    .map(|(at, _)| text.split_at(at + 14))
                {
                    read.insert(after.split('"').next().unwrap().to_owned());
                }
            }
        }
    }
    let listed: std::collections::BTreeSet<String> = named
        .iter()
        .flat_map(|(_, _, options)| options.iter().map(ToString::to_string))
        .filter(|option| option != "command")
        .collect();
    assert_eq!(read, listed);
}
