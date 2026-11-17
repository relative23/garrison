use super::super::Level;
use super::*;

/// A check's path that the collector's unit hides from it is named, as
/// root may read what the collector may not.
#[test]
fn a_checks_path_the_collector_cannot_see_is_named() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let mut check = config.clone();
    check.collector.providers.push(
        "type = \"bulwark\"\nadmin_directory = \"/root/bulwark\""
            .parse()
            .unwrap(),
    );
    let found = files(&check);
    let named = found
        .iter()
        .find(|finding| {
            finding
                .what
                .starts_with("providers[bulwark].admin_directory")
        })
        .unwrap();
    assert_eq!(named.level, Level::Fail, "{}", named.line());
    assert!(
        named.line().contains("Paths the collector cannot see"),
        "{}",
        named.line()
    );
}

/// Each fix names what makes the file, or what gives it owner and mode.
#[test]
fn each_file_names_what_makes_it_and_what_keeps_it_private() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let fix = |found: &[Finding], what: &str| {
        let finding = found
            .iter()
            .find(|finding| finding.what.starts_with(what))
            .unwrap_or_else(|| panic!("{what}"));
        finding.fix.clone().unwrap()
    };
    let missing = files(&config);
    for name in KEYS {
        assert_eq!(
            fix(&missing, &format!("{name} is missing")),
            "Run `garrison stalwart setup`, which makes it.",
            "{name}"
        );
    }
    // A file that is this user's.
    let key = config.credentials_directory.join("broker-native-key");
    fs::create_dir_all(&config.credentials_directory).unwrap();
    fs::write(&key, garrison_testing::NATIVE_KEY).unwrap();
    let present = files(&config);
    assert_eq!(
        fix(&present, &format!("{} is not root-owned", key.display())),
        format!(
            "Make it root's with mode 600: chown root {0} && chmod 600 {0}",
            key.display()
        )
    );
}

/// The finding that starts with `what`.
fn starting<'a>(findings: &'a [Finding], what: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.what.starts_with(what))
        .unwrap_or_else(|| panic!("no finding {what}: {findings:?}"))
}

/// Every file the units load is judged empty as its service reads it: a key
/// setup writes is no key empty, so doctor fails it, as the service refuses
/// it; a file that may be empty means none, so doctor finds it in order, as
/// its reader takes it. A file the units come to load that is neither fails
/// here until someone decides which it is.
#[test]
fn every_file_the_units_load_is_judged_empty_as_it_is_read() {
    use garrison_core::files::{Privacy, ProtectedFileError, read_optional_secret, read_secret};
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    fs::create_dir_all(&config.credentials_directory).unwrap();
    let optional: Vec<&str> = units::COLLECTOR_FILES
        .into_iter()
        .chain(units::NOTIFICATION_FILES)
        .collect();
    for (_, _, name) in units::SECRETS {
        let path = config.credentials_directory.join(name);
        garrison_testing::write_private(&path, b"\n");
        if KEYS.contains(&name) {
            assert!(
                matches!(
                    read_secret(&path, Privacy::Owned),
                    Err(ProtectedFileError::Empty(_))
                ),
                "{name}"
            );
            let found = files(&config);
            let finding = starting(&found, &format!("{name} is empty, so "));
            assert_eq!(finding.level, Level::Fail, "{name}");
        } else if optional.contains(&name) {
            let read = read_optional_secret(&path, Privacy::Owned, Form::Token);
            assert!(matches!(read, Ok(None)), "{name}");
            let kept = Finding::ok(format!("{name} is private (600)"));
            let judged = judged(name, &Held::Nothing, 0o600, reader(&config, name), kept);
            assert_eq!(judged.level, Level::Ok, "{name}: {}", judged.line());
        } else {
            panic!(
                "{name} is loaded by the units, but neither a key setup writes nor a file that may be empty"
            );
        }
    }
}

/// A key file that is empty, or holds something other than a key, gives
/// the service that reads it none, as a missing one does: doctor fails it
/// with the setup that makes the key. One that holds a key is judged by
/// owner and mode, which a test cannot give a file unless it runs as root.
#[test]
fn a_key_file_that_holds_no_key_fails_with_what_makes_one() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    fs::create_dir_all(&config.credentials_directory).unwrap();
    for (name, unit) in [
        ("webhook-signature-key", "garrison-ingest.service"),
        ("collector-native-key", "garrison-collect.service"),
        ("broker-native-key", "garrison-broker.service"),
    ] {
        let path = config.credentials_directory.join(name);
        for (written, lacks) in [
            ("", "is empty"),
            ("\n", "is empty"),
            ("short\n", "holds something other than a key"),
        ] {
            garrison_testing::write_private(&path, written.as_bytes());
            let found = files(&config);
            let finding = starting(&found, &format!("{name} "));
            assert_eq!(
                (finding.level, finding.what.as_str(), finding.fix.as_deref()),
                (
                    Level::Fail,
                    format!("{name} {lacks}, so {unit} has no key: {}", path.display()).as_str(),
                    Some("Run `garrison stalwart setup`, which makes it.")
                ),
                "{name} {written:?}"
            );
        }
        garrison_testing::write_private(&path, garrison_testing::NATIVE_KEY.as_bytes());
        let found = files(&config);
        let kept = starting(&found, &format!("{} is not root-owned", path.display()));
        assert_eq!(kept.level, Level::Fail, "{name}");
    }
}

/// systemd starts no unit whose credential file is missing. A file that
/// may be empty is named with the command that makes it, empty, which
/// means none; where the configuration reads it, with how to fill it.
#[test]
fn a_file_the_units_load_is_named_where_it_is_missing() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let found = files(&config);
    for name in ["metrics-credential", "ntfy-token", "notify-webhook-url"] {
        let path = config.credentials_directory.join(name);
        let missing = starting(&found, &format!("{name} is missing"));
        assert_eq!(missing.level, Level::Fail, "{name}");
        assert!(
            missing.what.contains("garrison-collect.service"),
            "{}",
            missing.what
        );
        assert_eq!(
            missing.fix.as_deref(),
            Some(
                format!(
                    "Make it, empty, which means none: install -m 600 /dev/null {}",
                    path.display()
                )
                .as_str()
            ),
            "{name}"
        );
    }
    assert!(
        starting(&found, "ntfy-token is missing")
            .what
            .contains("garrison-watch.service")
    );
}

/// A file that may be empty is in order empty where nothing reads it;
/// where the configuration reads it, empty is a failure with the way to
/// fill it. (Owner and mode come first, which a test cannot give a
/// file unless it runs as root.)
#[test]
fn an_empty_file_is_in_order_unless_the_configuration_reads_it() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let kept = || Finding::ok("metrics-credential is private (600)");
    let unread = judged(
        "metrics-credential",
        &Held::Nothing,
        0o600,
        reader(&config, "metrics-credential"),
        kept(),
    );
    assert_eq!(
        (unread.level, unread.what.as_str()),
        (
            Level::Ok,
            "metrics-credential is empty, which means none (600)"
        )
    );
    let mut prometheus = toml::Table::new();
    prometheus.insert("type".into(), "prometheus".into());
    config.collector.providers.push(prometheus);
    let read = judged(
        "metrics-credential",
        &Held::Nothing,
        0o600,
        reader(&config, "metrics-credential"),
        kept(),
    );
    assert_eq!(read.level, Level::Fail, "{}", read.line());
    assert_eq!(
        read.what,
        "metrics-credential is empty, but the prometheus check reads Stalwart's exporter with it"
    );
    assert!(
        read.fix
            .as_deref()
            .unwrap()
            .starts_with("Run `garrison stalwart setup`, which writes it"),
        "{}",
        read.line()
    );
    // Filled, it is judged by owner and mode alone.
    let filled = judged(
        "metrics-credential",
        &Held::Usable,
        0o600,
        reader(&config, "metrics-credential"),
        kept(),
    );
    assert_eq!(filled.what, "metrics-credential is private (600)");
    // Missing where it is read, it is named with how to fill it.
    let found = files(&config);
    let missing = starting(&found, "metrics-credential is missing");
    assert!(
        missing
            .fix
            .as_deref()
            .unwrap()
            .starts_with("Run `garrison stalwart setup`, which writes it"),
        "{}",
        missing.line()
    );
    // The notification channels' files are judged with the channels.
    assert_eq!(reader(&config, "ntfy-token"), None);
}

/// The key of Spamhaus' Data Query Service is read where a list written
/// without it is configured and `collector.dqs_key` names its file.
#[test]
fn the_dqs_key_is_read_where_a_list_written_without_it_is_asked() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    assert_eq!(reader(&config, "spamhaus-dqs-key"), None);
    let reputation: toml::Table = "type = \"reputation\"\nhosts = [\"mail.example.test\"]\n\
         lists = [\"zen.dq.spamhaus.net\"]\nlists_ipv6 = []"
        .parse()
        .unwrap();
    config.collector.providers.push(reputation);
    assert_eq!(reader(&config, "spamhaus-dqs-key"), None);
    config.collector.dqs_key = Some(garrison_core::credentials::SecretSource::Credential(
        "spamhaus-dqs-key".into(),
    ));
    let path = config.credentials_directory.join("spamhaus-dqs-key");
    let found = files(&config);
    let missing = starting(&found, "spamhaus-dqs-key is missing");
    assert_eq!(missing.level, Level::Fail);
    assert_eq!(
        missing.fix.as_deref(),
        Some(
            format!(
                "Write the key into it (zen.dq.spamhaus.net is asked with it): install -m 600 \
                 /dev/null {0} && sh -c 'cat > {0}', then paste the key and press Enter and \
                 Ctrl-D.",
                path.display()
            )
            .as_str()
        )
    );
    let empty = judged(
        "spamhaus-dqs-key",
        &Held::Nothing,
        0o600,
        reader(&config, "spamhaus-dqs-key"),
        Finding::ok("spamhaus-dqs-key is private (600)"),
    );
    assert_eq!(
        (empty.level, empty.what.as_str()),
        (
            Level::Fail,
            "spamhaus-dqs-key is empty, but the reputation check asks a list of Spamhaus' \
             Data Query Service with it"
        )
    );
}

/// A file the configuration reads is judged by its reader's own rule where
/// it holds something: a scrape credential written as `user:password`, or
/// as JSON without its secret, and a key of Spamhaus' Data Query Service
/// that is no word of letters and digits hold none, as their readers take
/// them, and fail with how to fill them. Where nothing reads such a file,
/// what it holds is not judged.
#[test]
fn a_file_its_reader_takes_for_none_fails_where_the_configuration_reads_it() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    fs::create_dir_all(&config.credentials_directory).unwrap();
    let kept = || Finding::ok("kept");
    let metrics = config.credentials_directory.join("metrics-credential");
    let mut prometheus = toml::Table::new();
    prometheus.insert("type".into(), "prometheus".into());
    config.collector.providers.push(prometheus);
    for written in [
        "garrison:a-password",
        r#"{"username": "garrison"}"#,
        "short",
    ] {
        garrison_testing::write_private(&metrics, written.as_bytes());
        let held = held(&config, "metrics-credential", &metrics);
        assert_eq!(held, Held::Unusable("holds no credential"), "{written}");
        let reads = reader(&config, "metrics-credential");
        let found = judged("metrics-credential", &held, 0o600, reads, kept());
        assert_eq!(
            (found.level, found.what.as_str(), found.fix.as_deref()),
            (
                Level::Fail,
                "metrics-credential holds no credential, but the prometheus check reads \
                 Stalwart's exporter with it",
                Some(garrison_collector::context::SCRAPE_FIX)
            ),
            "{written}"
        );
    }
    garrison_testing::write_private(&metrics, br#"{"username": "garrison", "secret": "s"}"#);
    assert_eq!(held(&config, "metrics-credential", &metrics), Held::Usable);
    let reputation: toml::Table = "type = \"reputation\"\nhosts = [\"mail.example.test\"]\n\
         lists = [\"zen.dq.spamhaus.net\"]\nlists_ipv6 = []"
        .parse()
        .unwrap();
    config.collector.providers.push(reputation);
    config.collector.dqs_key = Some(garrison_core::credentials::SecretSource::Credential(
        "spamhaus-dqs-key".into(),
    ));
    let key = config.credentials_directory.join("spamhaus-dqs-key");
    for written in [
        "two words".to_owned(),
        "a-hyphen".to_owned(),
        "x".repeat(64),
    ] {
        garrison_testing::write_private(&key, written.as_bytes());
        let held = held(&config, "spamhaus-dqs-key", &key);
        assert_eq!(
            held,
            Held::Unusable("holds no key, one word of letters and digits"),
            "{written}"
        );
        let reads = reader(&config, "spamhaus-dqs-key");
        let found = judged("spamhaus-dqs-key", &held, 0o600, reads, kept());
        assert_eq!(found.level, Level::Fail, "{written}");
        assert!(
            found
                .fix
                .as_deref()
                .unwrap()
                .starts_with("Write the key into it"),
            "{}",
            found.line()
        );
    }
    garrison_testing::write_private(&key, b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(held(&config, "spamhaus-dqs-key", &key), Held::Usable);
    // With nothing that reads it, what it holds is not judged.
    config.collector.dqs_key = None;
    let found = judged(
        "spamhaus-dqs-key",
        &Held::Unusable("holds no key, one word of letters and digits"),
        0o600,
        reader(&config, "spamhaus-dqs-key"),
        kept(),
    );
    assert_eq!(found.what, "kept");
}
