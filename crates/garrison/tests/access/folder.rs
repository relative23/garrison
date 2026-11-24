//! The policy's folder: `init` makes it where it is missing, and every
//! error of a file in it names that file.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use garrison_testing::http::serve;
use serde_json::json;

use super::support::{against, names, prepared, respond, run, text};
use super::{ADMINISTRATOR_RIGHTS, role};

/// garrison.toml in `directory` with `broker.policy` at `policy`.
fn policy_at(directory: &Path, policy: &Path) {
    let settings = directory.join("garrison.toml");
    let written = std::fs::read_to_string(&settings).unwrap();
    let default = format!("policy = \"{}\"", directory.join("policy.json").display());
    assert!(written.contains(&default), "{written}");
    let moved = written.replace(&default, &format!("policy = \"{}\"", policy.display()));
    std::fs::write(&settings, moved).unwrap();
}

/// `broker.policy` in a folder that is not made yet, as doctor then says to
/// run `garrison access init`: init makes the folders, readable for the
/// broker as /etc/garrison is, and the policy in them.
#[test]
fn init_makes_the_folder_that_garrison_toml_names_for_the_policy() {
    let authentication = json!({"id": "singleton", "defaultAdminRoleIds": names(&["admin"]),
                                "defaultUserRoleIds": {}});
    let server = serve(vec![
        respond("x:Authentication/get", &json!([authentication])),
        respond(
            "x:Role/get",
            &json!([role("admin", &ADMINISTRATOR_RIGHTS, "Administrators")]),
        ),
    ]);
    let directory = against(&server.url);
    let policy = directory.path().join("policies/mail/access.json");
    policy_at(directory.path(), &policy);
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(init.status.code(), Some(0), "{}", text(&init.stderr));
    for folder in ["policies", "policies/mail"] {
        let made = std::fs::metadata(directory.path().join(folder)).unwrap();
        assert_eq!(made.mode() & 0o7777, 0o755, "{folder}");
    }
    assert_eq!(std::fs::metadata(&policy).unwrap().mode() & 0o777, 0o640);
    assert!(text(&init.stdout).contains(&format!("Saved {}", policy.display())));
    server.requests();
}

/// What `garrison access` cannot do in the policy's folder is said with the
/// file it could not make or change, never as the system's error alone.
#[test]
fn an_error_of_a_file_beside_the_policy_names_that_file() {
    let directory = prepared();
    let folder = directory.path();
    let policy = folder.join("policy.json");
    let named = |arguments: &[&str], file: &str| {
        let output = run(folder, arguments);
        assert_eq!(output.status.code(), Some(1), "{arguments:?}");
        let said = text(&output.stderr);
        assert!(said.contains(file), "{arguments:?}: {said}");
        said
    };
    let mode = |mode: u32| {
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    // Root may write where the mode says it may not; that part is for others.
    if !rustix::process::geteuid().is_root() {
        // The lock cannot be made in a folder that cannot be written.
        let lock = folder.join("policy.json.lock");
        let _ = std::fs::remove_file(&lock);
        mode(0o555);
        let said = named(&["access", "deny", "5"], &lock.display().to_string());
        mode(0o755);
        assert!(said.contains("Permission denied"), "{said}");
        // Nor the backup, where the lock is there.
        std::fs::write(&lock, "").unwrap();
        mode(0o555);
        let said = named(&["access", "deny", "5"], &format!("{}.", policy.display()));
        mode(0o755);
        assert!(
            said.contains(".bak") && said.contains("Permission denied"),
            "{said}"
        );
    }
    // A folder at the policy's name: there is no policy to change, and init
    // --force leaves it as it is, as the installer does.
    std::fs::rename(&policy, folder.join("kept.json")).unwrap();
    std::fs::create_dir(&policy).unwrap();
    named(&["access", "deny", "5"], &policy.display().to_string());
    named(
        &["access", "init", "--force"],
        &policy.display().to_string(),
    );
    assert!(policy.is_dir());
    std::fs::remove_dir(&policy).unwrap();
    std::fs::rename(folder.join("kept.json"), &policy).unwrap();
    // A folder at the name the new policy is written to before it takes the
    // policy's place.
    let pending = folder.join(".policy.json.pending");
    std::fs::create_dir(&pending).unwrap();
    named(&["access", "deny", "5"], &pending.display().to_string());
    std::fs::remove_dir(&pending).unwrap();
}

/// A lock that another process holds, as one an earlier release made
/// readable for others that a user opened then, is said at once and not
/// waited for, and the policy stays as it was.
#[test]
fn a_lock_another_process_holds_is_said_and_not_waited_for() {
    let directory = prepared();
    let lock = directory.path().join("policy.json.lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    let holder = std::fs::File::open(&lock).unwrap();
    rustix::fs::flock(&holder, rustix::fs::FlockOperation::LockExclusive).unwrap();
    let policy = directory.path().join("policy.json");
    let before = std::fs::read(&policy).unwrap();
    let denied = run(directory.path(), &["access", "deny", "5"]);
    assert_eq!(
        (denied.status.code(), text(&denied.stderr)),
        (
            Some(1),
            format!(
                "{} is held by another process, as another `garrison access` command: try \
                 again once it has ended. Where none runs, remove the file and run the command \
                 again.\n",
                lock.display()
            )
        )
    );
    assert_eq!(std::fs::read(&policy).unwrap(), before);
    drop(holder);
    let again = run(directory.path(), &["access", "deny", "5"]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
}
