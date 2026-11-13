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
