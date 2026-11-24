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
    let path = Path::new(PATH);
    assert_eq!(
        judged(0, 991, 0o640),
        Finding::ok(states::readable("root:garrison-broker, mode 640"))
    );
    assert_eq!(
        judged(0, 991, 0o440),
        Finding::ok(states::readable("root:garrison-broker, mode 440"))
    );
    for (gid, mode, shown) in [
        (0, 0o600, "root:root, mode 600"),
        (0, 0o640, "root:root, mode 640"),
        (991, 0o600, "root:garrison-broker, mode 600"),
        (10, 0o640, "root:wheel, mode 640"),
    ] {
        assert_eq!(
            judged(0, gid, mode),
            Finding::fail(states::unreadable(shown, path)),
            "{shown}"
        );
    }
    // One the broker does not take is named with why.
    for (uid, mode, why, shown) in [
        (
            0,
            0o644,
            states::OTHERS_READ,
            "root:garrison-broker, mode 644",
        ),
        (
            0,
            0o646,
            states::OTHERS_WRITE,
            "root:garrison-broker, mode 646",
        ),
        (
            0,
            0o660,
            states::GROUP_WRITES,
            "root:garrison-broker, mode 660",
        ),
        (
            1000,
            0o640,
            states::FOREIGN,
            "1000:garrison-broker, mode 640",
        ),
    ] {
        assert_eq!(
            judged(uid, 991, mode),
            Finding::fail(states::refused(shown, &[why], path)),
            "{shown}"
        );
    }
    // One the broker owns it takes, as read_protected does: a warning.
    assert_eq!(
        judged(990, 991, 0o600),
        Finding::warn(states::broker_owner(
            "garrison-broker:garrison-broker, mode 600",
            path
        ))
    );
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
    assert_eq!(
        readable(path, file, &closed, broker.as_ref(), &names),
        Finding::fail(states::folder_closed_elsewhere(
            Path::new("/srv/private"),
            "root:root",
            0o700
        ))
    );
    assert_eq!(
        readable(path, file, &[], None, &names),
        Finding::unknown(states::no_broker())
    );
}

/// The policy is looked at where the configuration names it, which is
/// where the broker reads it; a missing one, or a folder in its place, is
/// named with what makes the file.
#[test]
fn the_policy_is_judged_where_the_configuration_names_it() {
    let directory = tempfile::tempdir().unwrap();
    let config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
    assert_eq!(
        checks(&config)[0],
        Finding::fail(states::missing(&config.broker.policy))
    );
    fs::create_dir_all(&config.broker.policy).unwrap();
    assert_eq!(
        checks(&config)[0],
        Finding::fail(states::not_a_file(&config.broker.policy))
    );
    // Root may read a policy that the broker's unit hides from it.
    let mut hidden = config.clone();
    hidden.broker.policy = "/home/doctor-test/policy.json".into();
    let said = units::hidden_policy(&hidden.broker.policy).unwrap();
    let found = checks(&hidden);
    assert!(
        found.contains(&Finding::fail(states::hidden(said))),
        "{found:?}"
    );
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
    assert_eq!(content(&config), Finding::ok(states::bound(2, 0)));
    document["roleBindings"] = serde_json::json!({});
    garrison_testing::write_policy(&config, &document);
    assert_eq!(content(&config), Finding::fail(states::unbound()));
    // An account bound alone lets that account in.
    document["subjects"] = serde_json::json!({"s1": {"accountId": "b", "profile": "viewer"}});
    garrison_testing::write_policy(&config, &document);
    assert_eq!(content(&config), Finding::ok(states::bound(0, 1)));
    let mut dropped = garrison_testing::policy_document();
    dropped["profiles"]["administrator"]["actions"] =
        serde_json::json!(["run_backup", "run_monitor", "run_reports"]);
    garrison_testing::write_policy(&config, &dropped);
    assert_eq!(
        content(&config),
        Finding::fail(states::actions_dropped(&["run_reports".to_owned()]))
    );
    let mut broken = garrison_testing::policy_document();
    broken["schemaVersion"] = serde_json::json!(2);
    garrison_testing::write_policy(&config, &broken);
    // The reason is the broker's own.
    assert_eq!(
        content(&config),
        Finding::fail(states::invalid("schemaVersion must be 1"))
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
    type Closed = fn(&Path, &str, u32) -> State;
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
    for (folder, closed_state) in [
        ("/etc/garrison", states::folder_closed as Closed),
        ("/etc", states::folder_closed),
        ("/srv/private", states::folder_closed_elsewhere),
    ] {
        let path = Path::new(folder).join("access-policy.json");
        let found = readable(
            &path,
            file,
            &[(PathBuf::from(folder), closed)],
            broker.as_ref(),
            &names,
        );
        assert_eq!(
            found,
            Finding::fail(closed_state(Path::new(folder), "root:root", 0o700)),
            "{folder}"
        );
    }
}

/// check-config says each finding on the policy as one line with its fix:
/// what the broker does not take is a refusal, a warning or what is not
/// known a warning, and a command to run is named as one.
#[test]
fn check_config_says_what_the_broker_meets() {
    let path = Path::new(PATH);
    // A state and its fix, as one line of check-config's.
    let line = |state: State| format!("{}. {}", state.text, state.fix.unwrap());
    assert_eq!(verdict(&judged(0, 991, 0o640)), Met::Taken(None));
    assert_eq!(
        verdict(&judged(0, 0, 0o600)),
        Met::Refused(line(states::unreadable("root:root, mode 600", path)))
    );
    assert_eq!(
        verdict(&judged(990, 991, 0o600)),
        Met::Taken(Some(line(states::broker_owner(
            "garrison-broker:garrison-broker, mode 600",
            path
        ))))
    );
    let file = Seen {
        uid: 0,
        gid: 991,
        mode: 0o640,
    };
    let nobody = readable(path, file, &[], None, &Names::default());
    assert_eq!(
        verdict(&nobody),
        Met::Taken(Some(format!(
            "it is not known {}.",
            states::no_broker().text
        )))
    );
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("access-policy.json");
    assert_eq!(
        as_the_broker(&missing),
        Met::Missing(line(states::missing(&missing)))
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
    let seen = Seen::of(&fs::metadata(&closed).unwrap());
    mode(&closed, 0o755);
    assert_eq!(
        found,
        Finding::fail(states::folder_closed_elsewhere(
            &closed,
            &names.of(seen),
            0o700
        ))
    );
}
