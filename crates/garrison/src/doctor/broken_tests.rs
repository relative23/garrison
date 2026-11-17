//! doctor's lines on hosts that are broken in one way each. A line that
//! says "ok" has looked at what it claims, as the service that needs it
//! meets it; one that could not look says so with the reason; and a fix it
//! names works from the state it found. So on each host here the check that
//! looks at what is broken must say something other than "ok", with the fix
//! that mends it, or, where it could not look, why.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use garrison_core::config::Database;
use garrison_core::time;
use garrison_testing::http::{json, serve};
use garrison_testing::tls::serve_until;

use super::{Finding, Level, files, host, milter, policy, public};

/// A host broken in one way, and what doctor must say of it.
struct Broken {
    /// What is broken.
    host: &'static str,
    /// What the check that looks at it found there.
    found: Vec<Finding>,
    /// Words of the line that must say it.
    said: String,
    /// Words its fix must hold; `None` for a line that says why the check
    /// could not look, which is unknown and names no fix.
    fix: Option<String>,
}

/// The events database is a folder, as a restore gone wrong may leave it:
/// whether events arrive is not known, which is not "none recorded yet".
fn events_database_is_a_folder() -> Broken {
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

/// The day `days` from now, as a test certificate's end takes it.
fn days_ahead(days: i64) -> (i32, u8, u8) {
    let then = time::now() + time::SignedDuration::from_hours(24 * days);
    let day = then.strftime("%Y %m %d").to_string();
    let parts: Vec<&str> = day.split(' ').collect();
    (
        parts[0].parse().unwrap(),
        parts[1].parse().unwrap(),
        parts[2].parse().unwrap(),
    )
}

/// Garrison's own name on a port of its own, `https://host:port`, whose
/// certificate ends in a few days: doctor must probe that port, whatever
/// listens on 443 of the name.
fn origin_with_a_port() -> Broken {
    let (year, month, day) = days_ahead(5);
    let server = serve_until(vec![String::new()], year, month, day);
    let roots = Arc::new(server.roots.clone());
    let found = vec![public::certificate(&server.url, &roots)];
    server.finish();
    Broken {
        host: "public_origin with a port, its certificate ending in five days",
        found,
        said: "expires in".into(),
        fix: Some("renewal".into()),
    }
}

/// The issuer's name answers Garrison's question about its sign-in client
/// with a web page, as a webmail on the same name may: that is no answer of
/// Stalwart's, and setup, which registers the client, mends nothing there.
fn issuer_answers_with_a_web_page() -> Broken {
    let page = "<html><body>Welcome to our webmail</body></html>";
    let server = serve_until(
        vec![format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{page}",
            page.len()
        )],
        2036,
        1,
        1,
    );
    let roots = Arc::new(server.roots.clone());
    let directory = tempfile::tempdir().unwrap();
    let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    config.deployment.issuer.clone_from(&server.url);
    let found = vec![public::sign_in(&config, &roots)];
    server.finish();
    Broken {
        host: "an issuer whose answer about the sign-in client is a web page",
        found,
        said: "sign-in client".into(),
        fix: Some("/api/auth/client".into()),
    }
}

/// Stalwart names itself another issuer than `deployment.issuer`, as after
/// its Default Hostname changed: every sign-in comes back under that name.
fn issuer_states_another_name() -> Broken {
    let stalwart = serve(vec![json(&serde_json::json!({
        "issuer": "https://other.example.test"
    }))]);
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), &stalwart.url);
    let found = vec![public::issuer(&config)];
    stalwart.requests();
    Broken {
        host: "Stalwart naming itself another issuer than garrison.toml",
        found,
        said: "names itself https://other.example.test".into(),
        fix: Some("issuer = \"https://other.example.test\"".into()),
    }
}

/// The access policy root's alone, as `chmod 600` or a backup put back
/// with `mv` leaves it: the broker, in its own group, may not read it.
fn policy_root_alone() -> Broken {
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
fn policy_binds_nobody() -> Broken {
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
fn policy_names_a_dropped_action() -> Broken {
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
/// reads it: what doctor says of `name`, judged as `optional` judges it once
/// owner and mode are in order.
fn filled(config: &garrison_core::config::Config, name: &str, written: &[u8]) -> Vec<Finding> {
    let path = config.credentials_directory.join(name);
    fs::create_dir_all(&config.credentials_directory).unwrap();
    garrison_testing::write_private(&path, written);
    let held = files::held(config, name, &path);
    let kept = Finding::ok(format!("{name} is private (600)"));
    vec![files::judged(
        name,
        &held,
        0o600,
        files::reader(config, name),
        kept,
    )]
}

/// The scrape credential written as `user:password`, where the prometheus
/// check reads it: its reader takes that for none.
fn metrics_credential_as_user_and_password() -> Broken {
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
fn dqs_key_of_two_words() -> Broken {
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
fn selinux_module_for_another_port() -> Broken {
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
    Broken {
        host: "an SELinux module that labels another port than web.port",
        found: host::selinux_at(&places, true, 9443).into_iter().collect(),
        said: "lets nginx reach port 8091".into(),
        fix: Some("Run the installer again".into()),
    }
}

/// The macro milter moved to another port without setup: Stalwart's entry
/// still asks the old one, where nothing answers.
fn milter_on_another_port() -> Broken {
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
    garrison_testing::write_private(
        &config.credentials_directory.join("stalwart-milter-id"),
        b"m\n",
    );
    let found = milter::checks(&config, &credentials);
    stalwart.requests();
    Broken {
        host: "the macro milter on another port than Stalwart's entry",
        found,
        said: format!("at 127.0.0.1:{old}"),
        fix: Some("garrison stalwart setup".into()),
    }
}

const HOSTS: [fn() -> Broken; 11] = [
    events_database_is_a_folder,
    origin_with_a_port,
    issuer_answers_with_a_web_page,
    issuer_states_another_name,
    policy_root_alone,
    policy_binds_nobody,
    policy_names_a_dropped_action,
    metrics_credential_as_user_and_password,
    dqs_key_of_two_words,
    selinux_module_for_another_port,
    milter_on_another_port,
];

/// What is wrong with what doctor said on `broken`, if anything.
fn fault(broken: &Broken) -> Option<String> {
    let lines: Vec<String> = broken.found.iter().map(Finding::line).collect();
    let Some(finding) = broken
        .found
        .iter()
        .find(|finding| finding.what.contains(&broken.said))
    else {
        return Some(format!(
            "{}: no line says {:?}:\n{}",
            broken.host,
            broken.said,
            lines.join("\n")
        ));
    };
    if finding.level == Level::Ok {
        return Some(format!("{}: {}", broken.host, finding.line()));
    }
    match &broken.fix {
        Some(fix)
            if !finding
                .fix
                .as_deref()
                .is_some_and(|text| text.contains(fix.as_str())) =>
        {
            Some(format!(
                "{}: the fix does not name {fix:?}:\n{}",
                broken.host,
                finding.line()
            ))
        }
        None if finding.level != Level::Unknown => Some(format!(
            "{}: a check that could not look is unknown:\n{}",
            broken.host,
            finding.line()
        )),
        _ => None,
    }
}

#[test]
fn on_a_broken_host_no_check_says_ok_of_what_is_broken() {
    let faults: Vec<String> = HOSTS.iter().filter_map(|host| fault(&host())).collect();
    assert_eq!(faults, Vec::<String>::new(), "{}", faults.join("\n\n"));
}
