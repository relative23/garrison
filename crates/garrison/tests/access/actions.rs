//! The actions of the profiles follow garrison.toml: `init` gives them as
//! the configuration has them then, and `update` gives the default profiles
//! an action added later and takes from every profile one that is gone,
//! and keeps the bindings, the accounts and the denials.

use garrison_testing::http::serve;
use serde_json::{Value, json};

use super::support::{against, names, respond, run, text};
use super::{ADMINISTRATOR_RIGHTS, policy, role};

/// The actions of each of the three default profiles.
fn actions(directory: &std::path::Path) -> Value {
    let written = policy(directory);
    json!(
        ["administrator", "operator", "viewer"]
            .map(|name| written["profiles"][name]["actions"].clone())
    )
}

/// How many backups of the policy its folder holds.
fn backups(directory: &std::path::Path) -> usize {
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| std::path::PathBuf::from(entry.unwrap().file_name()))
        .filter(|name| {
            name.to_string_lossy().starts_with("policy.json.")
                && name.extension().is_some_and(|extension| extension == "bak")
        })
        .count()
}

#[test]
fn update_gives_the_profiles_the_actions_as_garrison_toml_names_them() {
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
    let folder = directory.path();
    let init = run(folder, &["access", "init"]);
    assert_eq!(init.status.code(), Some(0), "{}", text(&init.stderr));
    server.requests();
    assert_eq!(
        actions(folder),
        json!([["run_backup", "run_monitor"], ["run_monitor"], []])
    );
    assert_eq!(
        run(folder, &["access", "deny", "42"]).status.code(),
        Some(0)
    );
    // garrison.toml gains an action for operators and loses run_backup.
    let settings = folder.join("garrison.toml");
    let written = std::fs::read_to_string(&settings).unwrap();
    let start = written.find("[[actions]]\nid = \"run_backup\"").unwrap();
    let end =
        start + written[start..].find("operator = false\n").unwrap() + "operator = false\n".len();
    let changed = format!(
        "{}{}\n[[actions]]\nid = \"install_updates\"\ntitle = \"Install updates\"\n\
         description = \"Installs the pending updates.\"\nconfirmation = \"INSTALL UPDATES\"\n\
         unit = \"updates.service\"\noperation = \"start\"\ncooldown_seconds = 0\n\
         timeout_seconds = 60\noperator = true\n",
        &written[..start],
        &written[end..]
    );
    std::fs::write(&settings, changed).unwrap();
    // A policy that names an action garrison.toml no longer has is said so,
    // with what takes it out.
    let listed = run(folder, &["access", "list"]);
    assert_eq!(listed.status.code(), Some(1));
    assert!(
        text(&listed.stderr).contains(
            "names run_backup, which garrison.toml no longer has: run `garrison access update`"
        ),
        "{}",
        text(&listed.stderr)
    );
    let kept = backups(folder);
    let updated = run(folder, &["access", "update"]);
    assert_eq!(updated.status.code(), Some(0), "{}", text(&updated.stderr));
    let said = text(&updated.stdout);
    for line in [
        "Profile administrator: install_updates added, run_backup taken out.\n",
        "Profile operator: install_updates added.\n",
        "Run the installer again now",
    ] {
        assert!(said.contains(line), "{said}");
    }
    assert_eq!(
        actions(folder),
        json!([
            ["install_updates", "run_monitor"],
            ["install_updates", "run_monitor"],
            []
        ])
    );
    let written = policy(folder);
    assert_eq!(written["roleBindings"], json!({"admin": "administrator"}));
    assert_eq!(written["deniedSubjects"], json!(["42"]));
    assert_eq!(backups(folder), kept + 1);
    // Once they follow, a second update changes nothing.
    let again = run(folder, &["access", "update"]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    assert_eq!(
        text(&again.stdout),
        "The profiles have the actions garrison.toml names; nothing to change.\n"
    );
    assert_eq!(backups(folder), kept + 1);
}
