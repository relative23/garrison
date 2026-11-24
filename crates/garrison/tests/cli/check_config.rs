//! check-config: what it refuses, what it warns of, and where it says it.

use super::support::{prepared, run, states, text};

#[test]
fn check_config_reports_providers_actions_and_the_policy() {
    let directory = prepared();
    let valid = run(directory.path(), &["check-config"]);
    assert_eq!(valid.status.code(), Some(0), "{}", text(&valid.stderr));
    assert_eq!(
        states(&valid.stdout),
        ["check-config-valid", "check-config-policy-valid"]
    );
    // The counts and the policy, as the two outcomes carry them.
    let said = text(&valid.stdout);
    let policy = directory.path().join("policy.json");
    let counts: Vec<&str> = said
        .lines()
        .find(|line| line.ends_with("[check-config-valid]"))
        .unwrap_or_default()
        .split(|character: char| !character.is_ascii_digit())
        .filter(|number| !number.is_empty())
        .collect();
    assert!(
        counts == ["1", "2"] && said.contains(&policy.display().to_string()),
        "{said}"
    );
    // The test origins are reserved names, as the example's are; its
    // directories are the test's, not those of the units.
    let warned = states(&valid.stderr);
    let said = text(&valid.stderr);
    assert!(
        warned.contains(&"check-config-placeholder".to_owned())
            && said.contains("https://admin.example.test"),
        "{said}"
    );
    let credentials = directory.path().join("credentials");
    assert!(
        warned.contains(&"check-config-unfollowed".to_owned())
            && said.contains(&format!(
                "credentials_directory is {}",
                credentials.display()
            ))
            && said.contains("broker.socket is "),
        "{said}"
    );
    std::fs::remove_file(directory.path().join("policy.json")).unwrap();
    let unusable = run(directory.path(), &["check-config"]);
    assert_eq!(unusable.status.code(), Some(1));
    // The reason of a failure is on standard error, as for every command.
    assert!(
        states(&unusable.stderr).contains(&"check-config-policy-refused".to_owned()),
        "{}",
        text(&unusable.stderr)
    );
    assert!(!states(&unusable.stdout).contains(&"check-config-policy-valid".to_owned()));
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
    assert_eq!(
        states(&refused.stderr),
        ["check-config-unloaded", "check-config-unloaded"],
        "{said}"
    );
    // Each secret with the name its unit loads it as.
    let lines: Vec<&str> = said.lines().collect();
    for (line, (setting, named)) in lines.iter().zip([
        (
            "collector.native_key is credential:my-key",
            "credential:collector-native-key",
        ),
        (
            "notifications.token is credential:my-token",
            "credential:ntfy-token",
        ),
    ]) {
        assert!(line.contains(setting) && line.contains(named), "{said}");
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
        states(&test.stderr) == ["notify-test-unloaded"]
            && text(&test.stderr).contains("notifications.token is credential:my-token"),
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
    let said = text(&refused.stderr);
    assert!(
        states(&refused.stderr) == ["check-config-unloaded"]
            && said.contains(&format!(
                "notifications.token names the file {}",
                token.display()
            ))
            && said.contains("credential:ntfy-token"),
        "{said}"
    );
    let test = run(directory.path(), &["notify-test"]);
    assert_eq!(
        (test.status.code(), text(&test.stdout)),
        (Some(2), String::new()),
        "{}",
        text(&test.stderr)
    );
    assert!(
        states(&test.stderr) == ["notify-test-unloaded"]
            && text(&test.stderr).contains(&token.display().to_string()),
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
    assert_eq!(states(&refused.stderr), ["check-config-providers"]);
    // The collector's own words for the two providers.
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
    let said = text(&checked.stderr);
    let warned = said
        .lines()
        .find(|line| states(line.as_bytes()) == ["check-config-policy-warned"])
        .unwrap_or_default();
    assert!(
        warned.contains("/home/garrison-cli-test/policy.json")
            && warned.contains("ProtectHome=true"),
        "{said}"
    );
    // Nothing is there, which check-config says after it.
    assert_eq!(checked.status.code(), Some(1));
    assert!(states(&checked.stderr).contains(&"check-config-policy-refused".to_owned()));
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
    let said = text(&checked.stderr);
    assert!(
        states(&checked.stderr).contains(&"check-config-hidden-check-warned".to_owned())
            && said.contains("providers[receipt].path is /home/garrison-cli-test/nightly.json")
            && said.contains("ProtectHome=true"),
        "{said}"
    );
    assert_eq!(checked.status.code(), Some(0), "{}", text(&checked.stderr));
}
