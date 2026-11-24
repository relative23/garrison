use super::super::Level;
use super::*;

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                      garrison-broker:x:990:991::/var/empty:/usr/sbin/nologin\n";
const GROUP: &str = "root:x:0:\ngarrison-broker:x:991:\nwheel:x:10:alice\n";
const PATH: &str = "/etc/garrison/access-policy.json";

/// Seen as root's folders are: 755.
fn open(folder: &str) -> (PathBuf, Seen) {
    (
        PathBuf::from(folder),
        Seen {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
    )
}

/// The policy at `PATH` seen so, as the broker of `PASSWD` and `GROUP`
/// meets it.
fn judged(uid: u32, gid: u32, mode: u32) -> Finding {
    let (names, broker) = accounts(PASSWD, GROUP);
    let above = [open("/etc/garrison"), open("/etc"), open("/")];
    readable(
        Path::new(PATH),
        Seen { uid, gid, mode },
        &above,
        broker.as_ref(),
        &names,
    )
}

#[test]
fn the_broker_is_who_the_hosts_accounts_say() {
    let (names, broker) = accounts(
        PASSWD,
        "root:x:0:\ngarrison-broker:x:991:\nshared:x:995:alice,garrison-broker\n",
    );
    let broker = broker.unwrap();
    assert_eq!((broker.uid, broker.groups), (990, vec![991, 995]));
    let seen = |uid, gid| Seen { uid, gid, mode: 0 };
    assert_eq!(names.of(seen(0, 991)), "root:garrison-broker");
    assert_eq!(names.of(seen(7, 8)), "7:8");
    assert!(accounts("root:x:0:0::/:/bin/sh\n", GROUP).1.is_none());
}

/// The broker reads the policy as its own user and takes it only where
/// root or the broker owns it, its group may not change it and others may
/// neither read nor change it: a policy root's alone, or of another group,
/// it may not read; one others may read or change, its group change, or
/// another owns, it does not take. Each fails with why and the command that
/// gives it to root and the broker's group.
#[test]
fn the_policy_is_judged_as_the_broker_meets_it() {
    let kept = judged(0, 991, 0o640);
    assert_eq!(
        (kept.level, kept.state.text.as_str()),
        (
            Level::Ok,
            "the broker may read the access policy, which only root may change \
             (root:garrison-broker, mode 640)"
        )
    );
    assert_eq!(judged(0, 991, 0o440).level, Level::Ok);
    let fix = format!("Run `chown root:garrison-broker {PATH} && chmod 640 {PATH}`.");
    for (gid, mode) in [(0, 0o600), (0, 0o640), (991, 0o600), (10, 0o640)] {
        let found = judged(0, gid, mode);
        assert_eq!(found.level, Level::Fail, "{}", found.line());
        assert!(
            found
                .state
                .text
                .starts_with("garrison-broker may not read the access policy ("),
            "{}",
            found.state.text
        );
        assert_eq!(found.state.fix.as_deref(), Some(fix.as_str()));
    }
    // One the broker does not take is named with why.
    for (uid, mode, why) in [
        (0, 0o644, "others may read it"),
        (0, 0o646, "others may change it"),
        (0, 0o660, "its group may change it"),
        (1000, 0o640, "a user other than root and the broker owns it"),
    ] {
        let found = judged(uid, 991, mode);
        assert_eq!(found.level, Level::Fail, "{}", found.line());
        assert!(
            found
                .state
                .text
                .starts_with("the broker does not take the access policy ("),
            "{}",
            found.state.text
        );
        assert!(found.state.text.contains(why), "{}", found.state.text);
        assert_eq!(found.state.fix.as_deref(), Some(fix.as_str()));
    }
    // One the broker owns it takes, as read_protected does: a warning.
    let owned = judged(990, 991, 0o600);
    assert_eq!(owned.level, Level::Warn, "{}", owned.line());
    assert!(
        owned
            .state
            .text
            .starts_with("garrison-broker owns the access policy (garrison-broker:garrison-broker"),
        "{}",
        owned.state.text
    );
    assert_eq!(owned.state.fix.as_deref(), Some(fix.as_str()));
}

/// A folder above the policy that the broker may not enter hides it as a
/// mode of the file would; a host without the broker's user leaves it
/// unknown.
#[test]
fn a_folder_the_broker_may_not_enter_hides_the_policy() {
    let (names, broker) = accounts(PASSWD, GROUP);
    let file = Seen {
        uid: 0,
        gid: 991,
        mode: 0o640,
    };
    let closed = [(
        PathBuf::from("/srv/private"),
        Seen {
            uid: 0,
            gid: 0,
            mode: 0o700,
        },
    )];
    let path = Path::new("/srv/private/policy.json");
    let hidden = readable(path, file, &closed, broker.as_ref(), &names);
    assert_eq!(hidden.level, Level::Fail);
    assert!(
        hidden
            .state
            .text
            .starts_with("garrison-broker may not enter /srv/private (root:root, mode 700)"),
        "{}",
        hidden.state.text
    );
    assert!(
        hidden
            .state
            .fix
            .as_deref()
            .unwrap()
            .contains("broker.policy")
    );
    let unknown = readable(path, file, &[], None, &names);
    assert_eq!(unknown.level, Level::Unknown, "{}", unknown.line());
}

/// The policy is looked at where the configuration names it, which is
/// where the broker reads it; a missing one, or a folder in its place, is
/// named with what makes the file.
#[test]
fn the_policy_is_judged_where_the_configuration_names_it() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let found = checks(&config);
    assert_eq!(
        (found[0].state.text.clone(), found[0].state.fix.as_deref()),
        (
            format!(
                "the access policy is missing: {}",
                config.broker.policy.display()
            ),
            Some("Run `garrison access init`, which makes it.")
        )
    );
    fs::create_dir_all(&config.broker.policy).unwrap();
    assert_eq!(
        checks(&config)[0].state.fix.as_deref(),
        Some("Remove it; then `garrison access init` makes the file itself there.")
    );
    // Root may read a policy that the broker's unit hides from it.
    let mut hidden = config.clone();
    hidden.broker.policy = "/home/doctor-test/policy.json".into();
    let named = checks(&hidden)
        .into_iter()
        .find(|finding| finding.state.text.contains("(ProtectHome=true)"))
        .unwrap();
    assert_eq!(named.level, Level::Fail, "{}", named.line());
}

/// What the policy grants is read as the broker reads it: one that binds
/// no role and no account refuses everyone, one that names an action
/// garrison.toml does not have, or does not read, keeps the broker from
/// using it; each is named with the command that mends it.
#[test]
fn the_policy_grants_what_the_broker_reads() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let mut document = garrison_testing::policy_document();
    garrison_testing::write_policy(&config, &document);
    let bound = content(&config);
    assert_eq!(
        (bound.level, bound.state.text.as_str()),
        (Level::Ok, "the access policy binds 2 roles and 0 accounts")
    );
    document["roleBindings"] = serde_json::json!({});
    garrison_testing::write_policy(&config, &document);
    let unbound = content(&config);
    assert_eq!(
        (unbound.level, unbound.state.text.as_str()),
        (
            Level::Fail,
            "the access policy binds no role and no account, so nobody can sign in"
        )
    );
    assert!(
        unbound
            .state
            .fix
            .as_deref()
            .unwrap()
            .ends_with("garrison access bind-role <role-id> --profile administrator")
    );
    // An account bound alone lets that account in.
    document["subjects"] = serde_json::json!({"s1": {"accountId": "b", "profile": "viewer"}});
    garrison_testing::write_policy(&config, &document);
    assert_eq!(content(&config).level, Level::Ok);
    let mut dropped = garrison_testing::policy_document();
    dropped["profiles"]["administrator"]["actions"] =
        serde_json::json!(["run_backup", "run_monitor", "run_reports"]);
    garrison_testing::write_policy(&config, &dropped);
    let named = content(&config);
    assert_eq!(
        (
            named.level,
            named.state.text.as_str(),
            named.state.fix.as_deref()
        ),
        (
            Level::Fail,
            "the access policy names actions garrison.toml does not have (run_reports), so \
             nobody can sign in",
            Some("Run `garrison access update`, which mends it.")
        )
    );
    let mut broken = garrison_testing::policy_document();
    broken["schemaVersion"] = serde_json::json!(2);
    garrison_testing::write_policy(&config, &broken);
    let unread = content(&config);
    assert_eq!(unread.level, Level::Fail);
    assert_eq!(
        unread.state.text,
        "the access policy does not read (schemaVersion must be 1), so nobody can sign in"
    );
}

/// doctor takes a policy exactly where the broker's own reading takes it:
/// over every mode of the file and of the folder above it, with the test's
/// user standing for the broker, `read_protected` reading as that user and
/// `readable` judging for it agree. A policy the broker owns is taken, with
/// a warning.
#[test]
fn doctor_takes_the_policy_where_read_protected_takes_it() {
    use std::os::unix::fs::PermissionsExt;
    let me = Reader {
        uid: rustix::process::geteuid().as_raw(),
        groups: vec![rustix::process::getegid().as_raw()],
    };
    let directory = tempfile::tempdir().unwrap();
    let folder = directory.path().join("garrison");
    fs::create_dir(&folder).unwrap();
    let path = folder.join("access-policy.json");
    fs::write(&path, garrison_testing::policy_document().to_string()).unwrap();
    let mode = |path: &Path, mode: u32| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    };
    let mut disagree = Vec::new();
    for bits in 0..=0o777 {
        mode(&path, bits);
        let taken = garrison_core::files::read_protected(&path, LIMIT).is_ok();
        let seen = Seen::of(&fs::metadata(&path).unwrap());
        let found = readable(&path, seen, &folders(&path), Some(&me), &Names::default());
        if taken != matches!(found.level, Level::Ok | Level::Warn) {
            disagree.push(format!("file {bits:o}: taken {taken}: {}", found.line()));
        }
    }
    mode(&path, 0o600);
    let file = Seen::of(&fs::metadata(&path).unwrap());
    for bits in 0..=0o777 {
        mode(&folder, bits);
        let taken = garrison_core::files::read_protected(&path, LIMIT).is_ok();
        let found = readable(&path, file, &folders(&path), Some(&me), &Names::default());
        if taken != matches!(found.level, Level::Ok | Level::Warn) {
            disagree.push(format!("folder {bits:o}: taken {taken}: {}", found.line()));
        }
    }
    mode(&folder, 0o700);
    assert_eq!(disagree, Vec::<String>::new(), "{}", disagree.join("\n"));
}

/// A folder the broker may not enter on the way to the default place is
/// mended by the mode the installer gives it, not by a move to where the
/// policy already is.
#[test]
fn a_closed_folder_on_the_way_to_the_default_place_is_opened() {
    let (names, broker) = accounts(PASSWD, GROUP);
    let file = Seen {
        uid: 0,
        gid: 991,
        mode: 0o640,
    };
    let closed = Seen {
        uid: 0,
        gid: 0,
        mode: 0o700,
    };
    for (folder, fix) in [
        ("/etc/garrison", "Run `chmod 755 /etc/garrison`."),
        ("/etc", "Run `chmod 755 /etc`."),
        (
            "/srv/private",
            "Move the policy to /etc/garrison/access-policy.json and set broker.policy to it.",
        ),
    ] {
        let path = Path::new(folder).join("access-policy.json");
        let found = readable(
            &path,
            file,
            &[(PathBuf::from(folder), closed)],
            broker.as_ref(),
            &names,
        );
        assert_eq!(found.level, Level::Fail, "{}", found.line());
        assert_eq!(found.state.fix.as_deref(), Some(fix), "{folder}");
    }
}

/// check-config says each finding on the policy as one line with its fix:
/// what the broker does not take is a refusal, a warning or what is not
/// known a warning, and a command to run is named as one.
#[test]
fn check_config_says_what_the_broker_meets() {
    let fix = format!("chown root:garrison-broker {PATH} && chmod 640 {PATH}");
    assert_eq!(verdict(&judged(0, 991, 0o640)), Met::Taken(None));
    assert_eq!(
        verdict(&judged(0, 0, 0o600)),
        Met::Refused(format!(
            "garrison-broker may not read the access policy (root:root, mode 600), so nobody \
             can sign in: {PATH}. Run `{fix}`."
        ))
    );
    assert_eq!(
        verdict(&judged(990, 991, 0o600)),
        Met::Taken(Some(format!(
            "garrison-broker owns the access policy (garrison-broker:garrison-broker, mode \
             600), which the installer keeps root's, so that only root may change what it \
             grants. Run `{fix}`."
        )))
    );
    let file = Seen {
        uid: 0,
        gid: 991,
        mode: 0o640,
    };
    let nobody = readable(Path::new(PATH), file, &[], None, &Names::default());
    assert_eq!(
        verdict(&nobody),
        Met::Taken(Some(
            "it is not known whether the broker can read the access policy: this host has no \
             user garrison-broker."
                .to_owned()
        ))
    );
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("access-policy.json");
    assert_eq!(
        as_the_broker(&missing),
        Met::Missing(format!(
            "the access policy is missing: {}. Run `garrison access init`, which makes it.",
            missing.display()
        ))
    );
}

/// What the policy grants is read as the broker reads it, owner and mode
/// aside, which `readable` judges: for a file of the reader's own,
/// `granted` and the broker's `Authority::policy` give the same policy, or
/// the same words for one that is a link, too large, no JSON or names an
/// action garrison.toml does not have.
#[test]
fn what_the_policy_grants_is_read_as_the_broker_reads_it() {
    use garrison_authz::Authority;
    use garrison_core::credentials::Credentials;
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    let broker = || {
        let credentials = Credentials::new(&config.credentials_directory);
        Authority::new(&config, credentials)
            .policy()
            .map_err(|error| error.to_string())
    };
    let path = &config.broker.policy;
    let mut named = garrison_testing::policy_document();
    named["profiles"]["administrator"]["actions"] = serde_json::json!(["run_reports"]);
    let large = format!("{{\"x\": \"{}\"}}", "x".repeat(LIMIT));
    let ways: [(&str, &dyn Fn()); 5] = [
        ("a policy", &|| {
            garrison_testing::write_policy(&config, &garrison_testing::policy_document());
        }),
        ("an action garrison.toml does not have", &|| {
            garrison_testing::write_policy(&config, &named);
        }),
        ("no JSON", &|| garrison_testing::write_private(path, b"{")),
        ("too large", &|| {
            garrison_testing::write_private(path, large.as_bytes());
        }),
        ("a link", &|| {
            let elsewhere = directory.path().join("elsewhere.json");
            fs::rename(path, &elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, path).unwrap();
        }),
    ];
    for (what, made) in ways {
        made();
        let read = broker();
        // The broker words a policy too large so; check-config and doctor
        // say it with the way out.
        let granted = granted(&config).map_err(|unread| match unread {
            Unread::TooLarge => format!(
                "Garrison access policy: Protected file is too large: {}",
                path.display()
            ),
            Unread::Other(error) => error,
        });
        assert_eq!(granted, read, "{what}");
        assert_eq!(read.is_ok(), what == "a policy", "{what}: {read:?}");
    }
}

/// A policy behind a linked folder is judged by the folders above where it
/// lies too: one the broker may not enter fails, as the broker cannot open
/// the policy.
#[test]
fn the_folders_behind_a_linked_folder_are_judged() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let closed = root.join("closed");
    let inner = closed.join("garrison");
    fs::create_dir_all(&inner).unwrap();
    fs::write(inner.join("access-policy.json"), "{}").unwrap();
    let mode = |path: &Path, mode: u32| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    };
    mode(root, 0o755);
    mode(&inner, 0o755);
    mode(&closed, 0o700);
    let link = root.join("etc-garrison");
    symlink(&inner, &link).unwrap();
    let path = link.join("access-policy.json");
    let (names, broker) = accounts(PASSWD, GROUP);
    let file = Seen {
        uid: 0,
        gid: 991,
        mode: 0o640,
    };
    let found = readable(&path, file, &folders(&path), broker.as_ref(), &names);
    mode(&closed, 0o755);
    assert_eq!(found.level, Level::Fail, "{}", found.line());
    assert!(
        found.state.text.contains(&closed.display().to_string()),
        "{}",
        found.state.text
    );
}
