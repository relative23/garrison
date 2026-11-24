//! check-config: what it refuses, what it warns of, and where it says it.

use super::support::{prepared, run, text};

#[test]
fn check_config_reports_providers_actions_and_the_policy() {
    let directory = prepared();
    let valid = run(directory.path(), &["check-config"]);
    assert_eq!(valid.status.code(), Some(0), "{}", text(&valid.stderr));
    assert_eq!(
        text(&valid.stdout),
        format!(
            "Configuration valid: 1 providers, 2 actions.\nAccess policy valid: {}\n",
            directory.path().join("policy.json").display()
        )
    );
    // The test origins are reserved names, as the example's are.
    assert!(
        text(&valid.stderr).contains(
            "Warning: deployment.public_origin https://admin.example.test is a placeholder"
        ),
        "{}",
        text(&valid.stderr)
    );
    // Its directories are the test's, not those of the units.
    let credentials = directory.path().join("credentials");
    assert!(
        text(&valid.stderr).contains(&format!(
            "Warning: credentials_directory is {}, but the units load every credential from \
             /etc/garrison/credentials",
            credentials.display()
        )),
        "{}",
        text(&valid.stderr)
    );
    assert!(text(&valid.stderr).contains("Warning: broker.socket is "));
    std::fs::remove_file(directory.path().join("policy.json")).unwrap();
    let unusable = run(directory.path(), &["check-config"]);
    assert_eq!(unusable.status.code(), Some(1));
    // The reason of a failure is on standard error, as for every command.
    assert!(
        text(&unusable.stderr).contains("Access policy not usable: "),
        "{}",
        text(&unusable.stderr)
    );
    assert!(!text(&unusable.stdout).contains("Access policy"));
}

/// systemd hands a service only the credentials its unit loads, under the
/// names it loads them as: another name is never there. check-config
/// refuses it; notify-test, which reads the configured directory as root,
/// sends nothing on a channel the collector could not use.
#[test]
fn a_credential_name_the_unit_does_not_load_is_refused() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let config = std::fs::read_to_string(&path).unwrap().replacen(
        "[collector]\n",
        "[collector]\nnative_key = \"credential:my-key\"\n",
        1,
    ) + "\n[notifications]\nntfy_url = \"https://127.0.0.1:9/topic\"\n\
         token = \"credential:my-token\"\n";
    std::fs::write(&path, config).unwrap();
    // The file is there, in the directory the operator commands read.
    garrison_testing::write_private(
        &directory.path().join("credentials/my-token"),
        b"tk_0123456789abcdefghij",
    );
    let refused = run(directory.path(), &["check-config"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    let said = text(&refused.stderr);
    for line in [
        "Configuration not usable: collector.native_key is credential:my-key, but \
         garrison-collect.service loads this secret only as credential:collector-native-key. \
         Write collector.native_key = \"credential:collector-native-key\" and keep the \
         secret in /etc/garrison/credentials/collector-native-key.\n",
        "Configuration not usable: notifications.token is credential:my-token, but \
         garrison-collect.service and garrison-watch.service load this secret only as \
         credential:ntfy-token. Write notifications.token = \"credential:ntfy-token\" and \
         keep the secret in /etc/garrison/credentials/ntfy-token.\n",
    ] {
        assert!(said.contains(line), "{said}");
    }
    assert_eq!(text(&refused.stdout), "");
    let test = run(directory.path(), &["notify-test"]);
    assert_eq!(
        (test.status.code(), text(&test.stdout)),
        (Some(2), String::new()),
        "{}",
        text(&test.stderr)
    );
    assert!(
        text(&test.stderr).contains("notifications.token is credential:my-token, but "),
        "{}",
        text(&test.stderr)
    );
    assert!(!text(&test.stderr).contains("collector.native_key"));
}

/// A secret named by its path the service would read itself, as its own
/// user, which a command running as root cannot judge for it: notify-test
/// and doctor would call a file usable that the collector cannot read.
#[test]
fn a_secret_named_by_its_path_is_refused() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let token = directory.path().join("ntfy-token");
    garrison_testing::write_private(&token, b"tk_0123456789abcdefghij");
    let config = std::fs::read_to_string(&path).unwrap()
        + &format!(
            "\n[notifications]\nntfy_url = \"https://127.0.0.1:9/topic\"\ntoken = \"{}\"\n",
            token.display()
        );
    std::fs::write(&path, config).unwrap();
    let refused = run(directory.path(), &["check-config"]);
    assert_eq!(refused.status.code(), Some(2), "{}", text(&refused.stderr));
    assert!(
        text(&refused.stderr).contains(&format!(
            "Configuration not usable: notifications.token names the file {}, which the \
             service would read itself, as its own user; garrison-collect.service and \
             garrison-watch.service load this secret for it only as credential:ntfy-token. \
             Move the file to /etc/garrison/credentials/ntfy-token (root, mode 0600) and write \
             notifications.token = \"credential:ntfy-token\".\n",
            token.display()
        )),
        "{}",
        text(&refused.stderr)
    );
    let test = run(directory.path(), &["notify-test"]);
    assert_eq!(
        (test.status.code(), text(&test.stdout)),
        (Some(2), String::new()),
        "{}",
        text(&test.stderr)
    );
    assert!(
        text(&test.stderr).starts_with("Not tested: notifications.token names the file "),
        "{}",
        text(&test.stderr)
    );
}

#[test]
fn check_config_refuses_two_providers_that_report_one_observation() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let mut config = std::fs::read_to_string(&path).unwrap();
    // A second check of the host: every run would report host.resources twice.
    config.push_str("\n[[providers]]\ntype = \"host\"\n");
    std::fs::write(&path, config).unwrap();
    let refused = run(directory.path(), &["check-config"]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(
        text(&refused.stderr).contains(
            "providers[1] (host) reports the observation host.resources as well as providers[0] (host)"
        ),
        "{}",
        text(&refused.stderr)
    );
}

/// The broker's unit hides /home from it, as /root, /run/user, /tmp,
/// /var/tmp and /dev. check-config refuses a policy there in the file the
/// units read (units.rs holds that) and warns in any other, such as this one.
#[test]
fn check_config_names_a_policy_where_the_broker_cannot_read_it() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let policy = directory.path().join("policy.json");
    let config = std::fs::read_to_string(&path).unwrap().replace(
        &format!("policy = \"{}\"", policy.display()),
        "policy = \"/home/garrison-cli-test/policy.json\"",
    );
    std::fs::write(&path, config).unwrap();
    let checked = run(directory.path(), &["check-config"]);
    assert!(
        text(&checked.stderr).contains(
            "Warning: broker.policy is /home/garrison-cli-test/policy.json, under /home, which \
             garrison-broker.service hides from the broker (ProtectHome=true): the broker cannot \
             read it there, and nobody can sign in. Keep the policy where the broker sees it, \
             such as /etc/garrison/access-policy.json, and name that in broker.policy.\n"
        ),
        "{}",
        text(&checked.stderr)
    );
    // Nothing is there, which check-config says after it.
    assert_eq!(checked.status.code(), Some(1));
    assert!(text(&checked.stderr).contains("Access policy not usable: "));
}

/// The collector's unit hides the same places from the collector, so a
/// check's path there is named as the policy is: a refusal for the file the
/// units read (units/sandbox.rs holds that), a warning for any other.
#[test]
fn check_config_names_a_checks_path_where_the_collector_cannot_see_it() {
    let directory = prepared();
    let path = directory.path().join("garrison.toml");
    let mut config = std::fs::read_to_string(&path).unwrap();
    config.push_str(
        "\n[[providers]]\ntype = \"receipt\"\nid = \"nightly\"\ntitle = \"Nightly job\"\n\
         path = \"/home/garrison-cli-test/nightly.json\"\nmodules = [\"services\"]\n",
    );
    std::fs::write(&path, config).unwrap();
    let checked = run(directory.path(), &["check-config"]);
    assert!(
        text(&checked.stderr).contains(
            "Warning: providers[receipt].path is /home/garrison-cli-test/nightly.json, under \
             /home, which garrison-collect.service hides from the collector (ProtectHome=true): \
             the check cannot read it there. Keep it where the collector sees it and name that \
             in providers[receipt].path, or show the collector that place read-only at another \
             one (docs/operator/checks.md, \"Paths the collector cannot see\").\n"
        ),
        "{}",
        text(&checked.stderr)
    );
    assert_eq!(checked.status.code(), Some(0), "{}", text(&checked.stderr));
}
