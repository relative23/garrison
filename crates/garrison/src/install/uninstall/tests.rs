use super::*;

const DEFAULT_POLICY: &str = "/etc/garrison/access-policy.json";

fn host() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    for folder in [
        "etc/systemd/system",
        "etc/polkit-1/rules.d",
        "etc/nginx/snippets",
        "etc/garrison/credentials",
        "etc/sysusers.d",
        "usr/bin",
        "opt/garrison/releases/0.1.0",
        "var/lib/garrison/web",
        "var/backups/garrison/pre-upgrade-20261030T132151",
        "var/backups/garrison/pre-restore-20261030T132152",
        "var/backups/garrison/latest",
        "var/backups/garrison/pre-upgrade-before-migration",
    ] {
        fs::create_dir_all(root.join(folder)).unwrap();
    }
    for file in [
        "etc/systemd/system/garrison-web.service",
        "etc/polkit-1/rules.d/50-garrison.rules",
        "etc/nginx/snippets/garrison.conf",
        "etc/nginx/snippets/garrison-stalwart-server.conf",
        "etc/nginx/snippets/other.conf",
        "etc/sysusers.d/garrison.conf",
    ] {
        fs::write(root.join(file), "").unwrap();
    }
    std::os::unix::fs::symlink(
        "/opt/garrison/current/bin/garrison",
        root.join("usr/bin/garrison"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "pre-upgrade-20261030T132151",
        root.join("var/backups/garrison/last-pre-upgrade"),
    )
    .unwrap();
    directory
}

fn paths(items: &[Item], root: &Path) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Path(path) => Some(path.strip_prefix(root).unwrap().display().to_string()),
            _ => None,
        })
        .collect()
}

#[test]
fn by_default_the_program_goes_and_the_data_stays() {
    let directory = host();
    let root = directory.path();
    let items = plan(root, false, true, Path::new(DEFAULT_POLICY));
    assert_eq!(items[0], Item::Units);
    assert!(items.contains(&Item::Module));
    assert!(!items.contains(&Item::Users));
    assert_eq!(
        paths(&items, root),
        [
            "etc/systemd/system/garrison-web.service",
            "etc/polkit-1/rules.d/50-garrison.rules",
            "etc/nginx/snippets/garrison-stalwart-server.conf",
            "etc/nginx/snippets/garrison.conf",
            "usr/bin/garrison",
            "opt/garrison",
        ]
    );
}

#[test]
fn another_program_of_the_commands_name_stays() {
    let directory = host();
    let root = directory.path();
    fs::remove_file(root.join("usr/bin/garrison")).unwrap();
    fs::write(root.join("usr/bin/garrison"), "another program").unwrap();
    let paths = paths(&plan(root, true, false, Path::new(DEFAULT_POLICY)), root);
    assert!(!paths.contains(&"usr/bin/garrison".to_owned()), "{paths:?}");
}

#[test]
fn a_purge_also_takes_data_users_and_the_installers_backups_only() {
    let directory = host();
    let root = directory.path();
    let items = plan(root, true, false, Path::new(DEFAULT_POLICY));
    assert!(!items.contains(&Item::Module));
    assert!(items.contains(&Item::Users));
    let paths = paths(&items, root);
    for gone in [
        "etc/garrison",
        "var/lib/garrison",
        "var/backups/garrison/last-pre-upgrade",
        "var/backups/garrison/pre-upgrade-20261030T132151",
        "var/backups/garrison/pre-restore-20261030T132152",
        "etc/sysusers.d/garrison.conf",
    ] {
        assert!(paths.contains(&gone.to_owned()), "{gone}");
    }
    // What the operator wrote with `garrison backup --to` stays, under a
    // name of the installer's kind too.
    assert!(!paths.iter().any(|path| {
        path.ends_with("latest")
            || path.ends_with("pre-upgrade-before-migration")
            || path.ends_with("other.conf")
    }));
}

/// A policy kept elsewhere goes with its lock and its backups, and
/// nothing else of its folder.
#[test]
fn a_purge_takes_a_policy_where_the_configuration_names_it() {
    let directory = host();
    let root = directory.path();
    fs::create_dir_all(root.join("srv/garrison")).unwrap();
    for file in [
        "access.json",
        "access.json.lock",
        "access.json.20261030T132151.bak",
        "access.json.orig",
        "other.json",
    ] {
        fs::write(root.join("srv/garrison").join(file), "").unwrap();
    }
    let elsewhere = Path::new("/srv/garrison/access.json");
    let gone = paths(&plan(root, true, false, elsewhere), root);
    let policies: Vec<&String> = gone.iter().filter(|path| path.starts_with("srv")).collect();
    assert_eq!(
        policies,
        [
            "srv/garrison/access.json",
            "srv/garrison/access.json.20261030T132151.bak",
            "srv/garrison/access.json.lock",
        ]
    );
    // Without a purge it stays, as the configuration does.
    let kept = paths(&plan(root, false, false, elsewhere), root);
    assert!(!kept.iter().any(|path| path.starts_with("srv")), "{kept:?}");
}

/// Where garrison.toml does not load, nobody knows where it keeps the
/// policy: the purge says so, and only then.
#[test]
fn a_purge_says_where_it_cannot_find_the_policy() {
    let directory = tempfile::tempdir().unwrap();
    let settings = directory.path().join("garrison.toml");
    assert_eq!(policy_unknown(&settings), None);
    let text = garrison_testing::config_text(directory.path(), "http://127.0.0.1:9");
    fs::write(&settings, &text).unwrap();
    assert_eq!(policy_unknown(&settings), None);
    fs::write(&settings, format!("nonsense_setting = 1\n{text}")).unwrap();
    let error = garrison_core::config::load(&settings).unwrap_err();
    // The configuration's own error names the setting it refuses.
    assert!(error.to_string().contains("nonsense_setting"), "{error}");
    assert_eq!(
        policy_unknown(&settings),
        Some(states::policy_unknown(&settings, error))
    );
}

/// A purge takes only files: a folder or a link that `broker.policy`
/// names, or that bears the name of its lock or of a backup, is not the
/// policy's and stays with all it holds.
#[test]
fn a_purge_takes_only_the_files_of_a_policy_kept_elsewhere() {
    let directory = host();
    let root = directory.path();
    let srv = root.join("srv");
    fs::create_dir_all(srv.join("data/mail")).unwrap();
    fs::write(srv.join("data/mail/inbox"), "mail").unwrap();
    fs::create_dir_all(srv.join("data.20261030T132151.bak")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", srv.join("data.lock")).unwrap();
    let gone = paths(&plan(root, true, false, Path::new("/srv/data")), root);
    assert!(!gone.iter().any(|path| path.starts_with("srv")), "{gone:?}");
}

#[test]
fn a_purge_without_a_configuration_says_that_the_sessions_tokens_stay() {
    let directory = tempfile::tempdir().unwrap();
    let settings = directory.path().join("garrison.toml");
    fs::write(&settings, "nonsense = [").unwrap();
    let database = directory.path().join("web.sqlite");
    // No database, no session.
    assert_eq!(sessions_ended(&settings, &database), None);
    fs::write(&database, "").unwrap();
    let said = sessions_ended(&settings, &database).unwrap().to_string();
    assert!(
        said.starts_with(&format!(
            "The sessions in {} could not be read (",
            database.display()
        )) && said.ends_with("[install-sessions-unread]"),
        "{said}"
    );
}
