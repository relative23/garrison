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
/// root owns it, its group may not change it and others may not read it:
/// a policy root's alone, or of another group, it may not read; one others
/// may read, its group change, or another owns, it does not take. Each
/// fails with the command that gives it to root and the broker's group.
#[test]
fn the_policy_is_judged_as_the_broker_meets_it() {
    let kept = judged(0, 991, 0o640);
    assert_eq!(
        (kept.level, kept.what.as_str()),
        (
            Level::Ok,
            "the broker may read the access policy, which only root may change \
             (root:garrison-broker, mode 640)"
        )
    );
    assert_eq!(judged(0, 991, 0o440).level, Level::Ok);
    let fix = format!("chown root:garrison-broker {PATH} && chmod 640 {PATH}");
    for (gid, mode) in [(0, 0o600), (0, 0o640), (991, 0o600), (10, 0o640)] {
        let found = judged(0, gid, mode);
        assert_eq!(found.level, Level::Fail, "{}", found.line());
        assert!(
            found
                .what
                .starts_with("garrison-broker may not read the access policy ("),
            "{}",
            found.what
        );
        assert_eq!(found.fix.as_deref(), Some(fix.as_str()));
    }
    for (uid, mode) in [(0, 0o644), (0, 0o660), (990, 0o600), (1000, 0o640)] {
        let found = judged(uid, 991, mode);
        assert_eq!(found.level, Level::Fail, "{}", found.line());
        assert!(
            found
                .what
                .starts_with("the broker takes only an access policy"),
            "{}",
            found.what
        );
        assert_eq!(found.fix.as_deref(), Some(fix.as_str()));
    }
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
            .what
            .starts_with("garrison-broker may not enter /srv/private (root:root, mode 700)"),
        "{}",
        hidden.what
    );
    assert!(hidden.fix.as_deref().unwrap().contains("broker.policy"));
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
        (found[0].what.clone(), found[0].fix.as_deref()),
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
        checks(&config)[0].fix.as_deref(),
        Some("Remove it; then `garrison access init` makes the file itself there.")
    );
    // Root may read a policy that the broker's unit hides from it.
    let mut hidden = config.clone();
    hidden.broker.policy = "/home/doctor-test/policy.json".into();
    let named = checks(&hidden)
        .into_iter()
        .find(|finding| finding.what.contains("(ProtectHome=true)"))
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
        (bound.level, bound.what.as_str()),
        (Level::Ok, "the access policy binds 2 roles and 0 accounts")
    );
    document["roleBindings"] = serde_json::json!({});
    garrison_testing::write_policy(&config, &document);
    let unbound = content(&config);
    assert_eq!(
        (unbound.level, unbound.what.as_str()),
        (
            Level::Fail,
            "the access policy binds no role and no account, so nobody can sign in"
        )
    );
    assert!(
        unbound
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
        (named.level, named.what.as_str(), named.fix.as_deref()),
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
        unread.what,
        "the access policy does not read (schemaVersion must be 1), so nobody can sign in"
    );
}
