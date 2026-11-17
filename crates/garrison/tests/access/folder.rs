//! The policy's folder: every error of a file in it names that file.

use std::os::unix::fs::PermissionsExt;

use super::support::{prepared, run, text};

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
