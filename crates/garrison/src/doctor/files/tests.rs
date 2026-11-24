use std::os::unix::fs::PermissionsExt;

use super::super::Level;
use super::*;

/// The mode of the file at `path`, as doctor shows it.
fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o777
}

/// A check's path that the collector's unit hides from it is named, in
/// check-config's words, as root may read what the collector may not.
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
    let providers = garrison_collector::build(&check.collector.providers).unwrap();
    let mut hidden = units::hidden_paths(&providers);
    assert_eq!(hidden.len(), 1);
    let named = Finding::fail(states::path_hidden(hidden.remove(0)));
    let found = files(&check);
    assert!(found.contains(&named), "{found:?}");
}

/// Each fix names what makes the file, or what gives it owner and mode.
#[test]
fn each_file_names_what_makes_it_and_what_keeps_it_private() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let missing = files(&config);
    for name in KEYS {
        let path = config.credentials_directory.join(name);
        let said = Finding::fail(states::missing(name, &path, states::SETUP));
        assert!(missing.contains(&said), "{name}: {missing:?}");
    }
    // A file that is this user's.
    let key = config.credentials_directory.join("broker-native-key");
    fs::create_dir_all(&config.credentials_directory).unwrap();
    fs::write(&key, garrison_testing::NATIVE_KEY).unwrap();
    let present = files(&config);
    let open = Finding::fail(states::open(&key, mode(&key)));
    assert!(present.contains(&open), "{present:?}");
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
            let empty = Finding::fail(states::no_key(name, Lacks::Empty, &path));
            assert!(found.contains(&empty), "{name}: {found:?}");
        } else if optional.contains(&name) {
            let read = read_optional_secret(&path, Privacy::Owned, Form::Token);
            assert!(matches!(read, Ok(None)), "{name}");
            let kept = Finding::ok(states::private(name, 0o600));
            let judged = judged(
                name,
                &Held::Lacking(Lacks::Empty),
                0o600,
                reader(&config, name),
                kept,
            );
            assert_eq!(judged, Finding::ok(states::empty(name, 0o600)), "{name}");
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
        ("webhook-signature-key", units::INGEST),
        ("collector-native-key", units::COLLECT),
        ("broker-native-key", units::BROKER),
    ] {
        // The unit its line names, as the one that has no key.
        assert!(
            units::SECRETS
                .iter()
                .any(|(_, loading, loaded)| *loaded == name && *loading == [unit]),
            "{name}"
        );
        let path = config.credentials_directory.join(name);
        for (written, lacks) in [
            ("", Lacks::Empty),
            ("\n", Lacks::Empty),
            ("short\n", Lacks::Other),
        ] {
            garrison_testing::write_private(&path, written.as_bytes());
            let found = files(&config);
            let said = Finding::fail(states::no_key(name, lacks, &path));
            assert!(found.contains(&said), "{name} {written:?}: {found:?}");
        }
        garrison_testing::write_private(&path, garrison_testing::NATIVE_KEY.as_bytes());
        let found = files(&config);
        let open = Finding::fail(states::open(&path, 0o600));
        assert!(found.contains(&open), "{name}: {found:?}");
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
        let missing = Finding::fail(states::missing_empty(name, &path));
        assert!(found.contains(&missing), "{name}: {found:?}");
    }
    // Their lines name the units that start only with them.
    for (name, loading) in [
        ("metrics-credential", &[units::COLLECT][..]),
        ("ntfy-token", &[units::COLLECT, units::WATCH]),
    ] {
        assert!(
            units::SECRETS
                .iter()
                .any(|(_, loaders, loaded)| *loaded == name && *loaders == loading),
            "{name}"
        );
    }
}

/// A file that may be empty is in order empty where nothing reads it;
/// where the configuration reads it, empty is a failure with the way to
/// fill it. (Owner and mode come first, which a test cannot give a
/// file unless it runs as root.)
#[test]
fn an_empty_file_is_in_order_unless_the_configuration_reads_it() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let name = "metrics-credential";
    let kept = || Finding::ok(states::private(name, 0o600));
    let empty = Held::Lacking(Lacks::Empty);
    let unread = judged(name, &empty, 0o600, reader(&config, name), kept());
    assert_eq!(unread, Finding::ok(states::empty(name, 0o600)));
    let mut prometheus = toml::Table::new();
    prometheus.insert("type".into(), "prometheus".into());
    config.collector.providers.push(prometheus);
    assert_eq!(reader(&config, name), Some(Reader::Prometheus));
    let read = judged(name, &empty, 0o600, reader(&config, name), kept());
    assert_eq!(
        read,
        Finding::fail(states::unusable(name, Lacks::Empty, &Reader::Prometheus))
    );
    // Filled, it is judged by owner and mode alone.
    let filled = judged(name, &Held::Usable, 0o600, reader(&config, name), kept());
    assert_eq!(filled, kept());
    // Missing where it is read, it is named with how to fill it.
    let path = config.credentials_directory.join(name);
    let found = files(&config);
    let missing = Finding::fail(states::missing_read(name, &path, &Reader::Prometheus));
    assert!(found.contains(&missing), "{found:?}");
    // The notification channels' files are judged with the channels.
    assert_eq!(reader(&config, "ntfy-token"), None);
}

/// The key of Spamhaus' Data Query Service is read where a list written
/// without it is configured and `collector.dqs_key` names its file.
#[test]
fn the_dqs_key_is_read_where_a_list_written_without_it_is_asked() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let name = "spamhaus-dqs-key";
    assert_eq!(reader(&config, name), None);
    let reputation: toml::Table = "type = \"reputation\"\nhosts = [\"mail.example.test\"]\n\
         lists = [\"zen.dq.spamhaus.net\"]\nlists_ipv6 = []"
        .parse()
        .unwrap();
    config.collector.providers.push(reputation);
    assert_eq!(reader(&config, name), None);
    config.collector.dqs_key = Some(garrison_core::credentials::SecretSource::Credential(
        name.into(),
    ));
    let path = config.credentials_directory.join(name);
    let dqs = Reader::Dqs {
        zone: "zen.dq.spamhaus.net".into(),
        path: path.clone(),
    };
    assert_eq!(reader(&config, name).as_ref(), Some(&dqs));
    let found = files(&config);
    let missing = Finding::fail(states::missing_read(name, &path, &dqs));
    assert!(found.contains(&missing), "{found:?}");
    let empty = judged(
        name,
        &Held::Lacking(Lacks::Empty),
        0o600,
        reader(&config, name),
        Finding::ok(states::private(name, 0o600)),
    );
    assert_eq!(
        empty,
        Finding::fail(states::unusable(name, Lacks::Empty, &dqs))
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
    let kept = || Finding::ok(states::private("kept", 0o600));
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
        assert_eq!(held, Held::Lacking(Lacks::NoCredential), "{written}");
        let reads = reader(&config, "metrics-credential");
        let found = judged("metrics-credential", &held, 0o600, reads, kept());
        assert_eq!(
            found,
            Finding::fail(states::unusable(
                "metrics-credential",
                Lacks::NoCredential,
                &Reader::Prometheus
            )),
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
    let dqs = Reader::Dqs {
        zone: "zen.dq.spamhaus.net".into(),
        path: key.clone(),
    };
    for written in [
        "two words".to_owned(),
        "a-hyphen".to_owned(),
        "x".repeat(64),
    ] {
        garrison_testing::write_private(&key, written.as_bytes());
        let held = held(&config, "spamhaus-dqs-key", &key);
        assert_eq!(held, Held::Lacking(Lacks::NoKey), "{written}");
        let reads = reader(&config, "spamhaus-dqs-key");
        let found = judged("spamhaus-dqs-key", &held, 0o600, reads, kept());
        assert_eq!(
            found,
            Finding::fail(states::unusable("spamhaus-dqs-key", Lacks::NoKey, &dqs)),
            "{written}"
        );
    }
    garrison_testing::write_private(&key, b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(held(&config, "spamhaus-dqs-key", &key), Held::Usable);
    // With nothing that reads it, what it holds is not judged.
    config.collector.dqs_key = None;
    let found = judged(
        "spamhaus-dqs-key",
        &Held::Lacking(Lacks::NoKey),
        0o600,
        reader(&config, "spamhaus-dqs-key"),
        kept(),
    );
    assert_eq!(found, kept());
}

/// The whole judgment of a file that may be empty, with the test's user in
/// root's place as its owner: missing, empty or holding what its reader
/// takes for none where a check reads it, open to others, and in order.
#[test]
fn a_file_that_may_be_empty_is_judged_whole() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config
        .collector
        .providers
        .push("type = \"prometheus\"".parse().unwrap());
    let me = rustix::process::geteuid().as_raw();
    let name = "metrics-credential";
    let path = config.credentials_directory.join(name);
    let judged = |config: &Config| optional_of(config, name, me);
    assert_eq!(reader(&config, name), Some(Reader::Prometheus));
    assert_eq!(
        judged(&config),
        Finding::fail(states::missing_read(name, &path, &Reader::Prometheus))
    );
    fs::create_dir_all(&config.credentials_directory).unwrap();
    for (written, lacks) in [
        (&b""[..], Lacks::Empty),
        (&b"garrison:a-password\n"[..], Lacks::NoCredential),
    ] {
        garrison_testing::write_private(&path, written);
        assert_eq!(
            judged(&config),
            Finding::fail(states::unusable(name, lacks, &Reader::Prometheus)),
            "{written:?}"
        );
    }
    let credential = br#"{"username": "garrison", "secret": "a-password"}"#;
    garrison_testing::write_private(&path, credential);
    assert_eq!(judged(&config), Finding::ok(states::private(name, 0o600)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(judged(&config), Finding::fail(states::open(&path, 0o644)));
    // Where nothing reads it, empty is in order.
    config.collector.providers.clear();
    garrison_testing::write_private(&path, b"");
    assert_eq!(judged(&config), Finding::ok(states::empty(name, 0o600)));
}
