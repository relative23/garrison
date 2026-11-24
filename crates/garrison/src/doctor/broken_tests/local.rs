//! Hosts broken in what doctor looks at on this host.

use std::fs;
use std::path::Path;

use garrison_core::config::Database;
use garrison_testing::http::{json, serve};

use super::super::{Finding, files, host, milter, notify, policy};
use super::Broken;

/// The events database is a folder, as a restore gone wrong may leave it:
/// whether events arrive is not known, which is not "none recorded yet".
pub(super) fn events_database_is_a_folder() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    fs::create_dir_all(config.database(Database::Events)).unwrap();
    Broken {
        host: "an events database that is a folder",
        found: vec![host::events(&config)],
        said: "the events database".into(),
        fix: None,
    }
}

/// The access policy root's alone, as `chmod 600` or a backup put back
/// with `mv` leaves it: the broker, in its own group, may not read it.
pub(super) fn policy_root_alone() -> Broken {
    let (names, broker) = policy::accounts(
        "root:x:0:0::/root:/bin/sh\ngarrison-broker:x:990:991::/:/usr/sbin/nologin\n",
        "root:x:0:\ngarrison-broker:x:991:\n",
    );
    let file = policy::Seen {
        uid: 0,
        gid: 0,
        mode: 0o600,
    };
    let path = Path::new("/etc/garrison/access-policy.json");
    Broken {
        host: "an access policy root:root 0600",
        found: vec![policy::readable(path, file, &[], broker.as_ref(), &names)],
        said: "may not read the access policy".into(),
        fix: Some("chown root:garrison-broker /etc/garrison/access-policy.json".into()),
    }
}

/// A policy that binds no role and no account, as `access init` leaves it
/// where no role qualifies: the broker refuses everyone.
pub(super) fn policy_binds_nobody() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let mut document = garrison_testing::policy_document();
    document["roleBindings"] = serde_json::json!({});
    garrison_testing::write_policy(&config, &document);
    Broken {
        host: "an access policy that binds nobody",
        found: vec![policy::content(&config)],
        said: "binds no role and no account".into(),
        fix: Some("garrison access bind-role <role-id> --profile administrator".into()),
    }
}

/// A policy that names an action garrison.toml no longer has, which the
/// broker cannot use.
pub(super) fn policy_names_a_dropped_action() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let mut document = garrison_testing::policy_document();
    document["profiles"]["administrator"]["actions"] =
        serde_json::json!(["run_backup", "run_monitor", "run_reports"]);
    garrison_testing::write_policy(&config, &document);
    Broken {
        host: "an access policy that names an action garrison.toml does not have",
        found: vec![policy::content(&config)],
        said: "(run_reports)".into(),
        fix: Some("garrison access update".into()),
    }
}

/// A file that may be empty, holding what `written` says, where a check
/// reads it: what doctor says of `name`, with the test's user in root's
/// place as the file's owner.
fn filled(config: &garrison_core::config::Config, name: &str, written: &[u8]) -> Vec<Finding> {
    let path = config.credentials_directory.join(name);
    fs::create_dir_all(&config.credentials_directory).unwrap();
    garrison_testing::write_private(&path, written);
    vec![files::optional_of(
        config,
        name,
        rustix::process::geteuid().as_raw(),
    )]
}

/// The scrape credential written as `user:password`, where the prometheus
/// check reads it: its reader takes that for none.
pub(super) fn metrics_credential_as_user_and_password() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config
        .collector
        .providers
        .push("type = \"prometheus\"".parse().unwrap());
    Broken {
        host: "a scrape credential written as user:password",
        found: filled(&config, "metrics-credential", b"garrison:a-password\n"),
        said: "metrics-credential holds no credential".into(),
        fix: Some("garrison stalwart setup".into()),
    }
}

/// The key of Spamhaus' Data Query Service of two words, where a list
/// written without its key is asked with it.
pub(super) fn dqs_key_of_two_words() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config.collector.providers.push(
        "type = \"reputation\"\nhosts = [\"mail.example.test\"]\n\
         lists = [\"zen.dq.spamhaus.net\"]\nlists_ipv6 = []"
            .parse()
            .unwrap(),
    );
    config.collector.dqs_key = Some(garrison_core::credentials::SecretSource::Credential(
        "spamhaus-dqs-key".into(),
    ));
    Broken {
        host: "a key of Spamhaus' Data Query Service of two words",
        found: filled(&config, "spamhaus-dqs-key", b"two words\n"),
        said: "spamhaus-dqs-key holds no key".into(),
        fix: Some("install -m 600 /dev/null".into()),
    }
}

/// SELinux enforcing, its module loaded for the web service's old port, as
/// after `web.port` changed and only the include was written anew.
pub(super) fn selinux_module_for_another_port() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name).display().to_string();
    fs::write(path("enforce"), "1\n").unwrap();
    fs::write(path("boolean"), "0 0\n").unwrap();
    fs::write(
        path("garrison.cil"),
        "(portcon tcp 8091 (system_u object_r garrison_port_t ((s0) (s0))))\n",
    )
    .unwrap();
    let (enforce, everywhere, module) = (path("enforce"), path("boolean"), path("garrison.cil"));
    let places = host::SeLinux {
        enforce: &enforce,
        everywhere: &everywhere,
        module: &module,
    };
    let loaded = fs::read_to_string(&module).map_err(|error| error.to_string());
    Broken {
        host: "an SELinux module that labels another port than web.port",
        found: host::selinux_at(&places, Some(loaded), 9443)
            .into_iter()
            .collect(),
        said: "lets nginx reach port 8091".into(),
        fix: Some("Run the installer again".into()),
    }
}

/// The macro milter moved to another port without setup: Stalwart's entry
/// still asks the old one, where nothing answers, which is then no entry of
/// the filter's.
pub(super) fn milter_on_another_port() -> Broken {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        garrison_milter::server::serve(
            &listener,
            garrison_milter::Settings {
                max_bytes: 1024,
                ..Default::default()
            },
        );
    });
    let old = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let stalwart = serve(vec![json(&serde_json::json!({"methodResponses": [[
        "x:MtaMilter/get",
        {"list": [{"id": "m", "host": "127.0.0.1", "port": old,
            "enable": {"match": {}, "else": "true"}, "stages": {"data": true},
            "tempFailOnError": true}]},
        "0"
    ]]}))]);
    let directory = tempfile::tempdir().unwrap();
    let text = format!(
        "{}\n[milter]\nport = {port}\n",
        garrison_testing::config_text(directory.path(), &stalwart.url)
    );
    let config = garrison_core::config::from_text(&text).unwrap();
    let credentials = garrison_core::credentials::Credentials::new(&config.credentials_directory);
    fs::create_dir_all(&config.credentials_directory).unwrap();
    garrison_testing::write_private(
        &credentials.path(&config.collector.native_key),
        garrison_testing::NATIVE_KEY.as_bytes(),
    );
    let found = milter::checks(&config, &credentials);
    stalwart.requests();
    Broken {
        host: "the macro milter on another port than Stalwart's entry",
        found,
        said: format!("at 127.0.0.1:{old}"),
        fix: Some("Stalwart WebUI".into()),
    }
}

/// No release where the installer puts it.
pub(super) fn no_release() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    Broken {
        host: "no release installed",
        found: vec![host::release_in(directory.path())],
        said: "no installed release".into(),
        fix: Some("Run the installer".into()),
    }
}

/// A unit of Garrison's that failed.
pub(super) fn unit_failed() -> Broken {
    Broken {
        host: "a unit of Garrison's that failed",
        found: vec![host::service("garrison-web.service", Some("failed"))],
        said: "garrison-web.service is failed".into(),
        fix: Some("journalctl -u garrison-web.service".into()),
    }
}

/// A collector whose last run finished an hour ago.
pub(super) fn collector_stopped() -> Broken {
    let now = garrison_core::time::now();
    Broken {
        host: "a collector that stopped an hour ago",
        found: vec![host::finished(Ok(Some(now.as_second() - 3600)), now)],
        said: "no collection run has finished since".into(),
        fix: Some("systemctl status garrison-collect.service".into()),
    }
}

/// A key file that is not root's alone, as a copy made by hand leaves it.
pub(super) fn key_not_roots() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    fs::create_dir_all(&config.credentials_directory).unwrap();
    let key = config.credentials_directory.join("broker-native-key");
    fs::write(&key, garrison_testing::NATIVE_KEY).unwrap();
    Broken {
        host: "a key file that is not root's alone",
        found: files::files(&config),
        said: format!("{} is not root-owned", key.display()),
        fix: Some("chmod 600".into()),
    }
}

/// An empty scrape credential where the prometheus check reads it.
pub(super) fn metrics_credential_empty_where_read() -> Broken {
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config
        .collector
        .providers
        .push("type = \"prometheus\"".parse().unwrap());
    Broken {
        host: "an empty scrape credential that the prometheus check reads",
        found: filled(&config, "metrics-credential", b""),
        said: "metrics-credential is empty, but".into(),
        fix: Some("garrison stalwart setup".into()),
    }
}

/// A clock that follows no time server.
pub(super) fn clock_unsynchronized() -> Broken {
    Broken {
        host: "a clock that is not synchronized",
        found: vec![host::synchronized(Some("no"))],
        said: "the clock is not synchronized".into(),
        fix: Some("timedatectl set-ntp true".into()),
    }
}

/// A folder whose disk cannot be asked.
pub(super) fn space_unknown() -> Broken {
    Broken {
        host: "free space that cannot be asked",
        // A path through a file, whose disk statvfs cannot be asked.
        found: vec![host::room("/proc/self/status/garrison")],
        said: "free space of".into(),
        fix: None,
    }
}

/// A macro milter that does not answer on its port.
pub(super) fn milter_silent() -> Broken {
    Broken {
        host: "a macro milter that does not answer",
        found: vec![milter::answering(8096, Err("Connection refused".into()))],
        said: "does not answer on 127.0.0.1:8096".into(),
        fix: Some("journalctl -u garrison-milter.service".into()),
    }
}

/// An ntfy channel whose address file is empty.
pub(super) fn channel_without_its_address() -> Broken {
    use garrison_core::config::Endpoint;
    use garrison_core::credentials::{Credentials, SecretSource};
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config.notifications.ntfy_url =
        Some(Endpoint::File(SecretSource::Credential("ntfy-url".into())));
    let credentials = Credentials::new(&config.credentials_directory);
    fs::create_dir_all(credentials.directory()).unwrap();
    for name in crate::units::NOTIFICATION_FILES {
        garrison_testing::write_private(&credentials.directory().join(name), b"");
    }
    Broken {
        host: "an ntfy channel whose address file is empty",
        found: notify::checks(&config, &credentials),
        said: "notifications: ntfy".into(),
        fix: Some("garrison notify-test".into()),
    }
}
