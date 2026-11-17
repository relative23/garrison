//! Every file `garrison access` makes or changes beside the policy is
//! reached by its name in the policy's folder, never through a link that
//! another user of that folder put there, and nothing is written over what
//! is there: root runs these commands, and `broker.policy` may name a folder
//! that others can write.

use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};

use garrison_core::time::{self, SignedDuration};
use garrison_testing::http::serve;
use serde_json::json;

use super::support::{names, prepared, respond, run, text};
use super::{ADMINISTRATOR_RIGHTS, role};

/// A command that writes the policy, the answers of Stalwart's it needs and
/// what it needs of garrison.toml to change something.
struct Writing {
    arguments: &'static [&'static str],
    answers: fn() -> Vec<String>,
    settings: fn(&str) -> String,
}

fn none() -> Vec<String> {
    Vec::new()
}

fn roles() -> Vec<String> {
    let authentication = json!({"id": "singleton", "defaultAdminRoleIds": names(&["admin"]),
                                "defaultUserRoleIds": {}});
    vec![
        respond("x:Authentication/get", &json!([authentication])),
        respond(
            "x:Role/get",
            &json!([role("admin", &ADMINISTRATOR_RIGHTS, "Administrators")]),
        ),
    ]
}

fn known_role() -> Vec<String> {
    vec![respond("x:Role/get", &json!([{"id": "r2"}]))]
}

fn same(settings: &str) -> String {
    settings.to_owned()
}

/// Every command of `garrison access` that writes the policy.
const WRITING: [Writing; 5] = [
    Writing {
        arguments: &["access", "init", "--force"],
        answers: roles,
        settings: same,
    },
    Writing {
        arguments: &["access", "bind-role", "r2", "--profile", "viewer"],
        answers: known_role,
        settings: same,
    },
    Writing {
        arguments: &["access", "unbind-role", "v"],
        answers: none,
        settings: same,
    },
    Writing {
        arguments: &["access", "deny", "42"],
        answers: none,
        settings: same,
    },
    Writing {
        arguments: &["access", "deny", "7", "--undo"],
        answers: none,
        settings: same,
    },
];

/// The run of `writing` in a prepared directory after `plant` put its links
/// there, with a Stalwart that gives `answers` and fails the test unless
/// each is asked for.
fn ran(
    writing: &Writing,
    answers: Vec<String>,
    plant: impl FnOnce(&Path),
) -> (tempfile::TempDir, std::process::Output) {
    let server = serve(answers);
    let directory = prepared();
    let settings = directory.path().join("garrison.toml");
    let written = std::fs::read_to_string(&settings).unwrap();
    let written = (writing.settings)(&written.replace("http://127.0.0.1:9", &server.url));
    std::fs::write(&settings, written).unwrap();
    plant(directory.path());
    let output = run(directory.path(), writing.arguments);
    server.requests();
    (directory, output)
}

/// The names a command leaves beside the policy in a folder of its own.
fn left(writing: &Writing) -> Result<Vec<String>, String> {
    let (directory, output) = ran(writing, (writing.answers)(), |_| {});
    if output.status.code() != Some(0) {
        return Err(text(&output.stderr));
    }
    let mut names: Vec<String> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("policy.json.") || name.starts_with(".policy.json"))
        .collect();
    names.sort();
    Ok(names)
}

/// Every name a backup of `policy.json` may take within the next seconds.
fn backups() -> Vec<String> {
    let now = time::now();
    (-1..6)
        .flat_map(|seconds| {
            let at = now.checked_add(SignedDuration::from_secs(seconds)).unwrap();
            let stamp = at.strftime("%Y%m%dT%H%M%S").to_string();
            (0..4).map(move |copy| match copy {
                0 => format!("policy.json.{stamp}.bak"),
                copy => format!("policy.json.{stamp}-{copy}.bak"),
            })
        })
        .collect()
}

/// A file outside the folder that a link points to, as it was.
struct Target {
    path: PathBuf,
    text: String,
    mode: u32,
}

impl Target {
    fn new(outside: &Path, name: &str) -> Target {
        let path = outside.join(name);
        let text = format!("what {name} points to\n");
        std::fs::write(&path, &text).unwrap();
        let mode = std::fs::metadata(&path).unwrap().mode();
        Target { path, text, mode }
    }

    fn unchanged(&self) -> bool {
        std::fs::read_to_string(&self.path).unwrap() == self.text
            && std::fs::metadata(&self.path).unwrap().mode() == self.mode
    }
}

/// What went wrong when `writing` ran with links at `planted`, if anything.
fn through_links(writing: &Writing, planted: &[String], outside: &Path) -> Vec<String> {
    let what = writing.arguments.join(" ");
    let targets: Vec<Target> = planted
        .iter()
        .map(|name| Target::new(outside, name))
        .collect();
    // A command refused at its lock asks Stalwart nothing.
    let lock = "policy.json.lock".to_owned();
    let refused = planted.contains(&lock);
    let answers = if refused { none() } else { (writing.answers)() };
    let (directory, output) = ran(writing, answers, |folder| {
        for (name, target) in planted.iter().zip(&targets) {
            symlink(&target.path, folder.join(name)).unwrap();
        }
    });
    let mut wrong: Vec<String> = planted
        .iter()
        .zip(&targets)
        .filter(|(_, target)| !target.unchanged())
        .map(|(name, _)| format!("{what}: wrote through a link at {name}"))
        .collect();
    let lock = directory.path().join(lock);
    let said = text(&output.stderr);
    if refused {
        // A lock that is not the command's own is refused and left as it is.
        let refused = output.status.code() == Some(1) && said.contains(&lock.display().to_string());
        let kept = std::fs::symlink_metadata(&lock).is_ok_and(|kind| kind.is_symlink());
        if !refused || !kept {
            wrong.push(format!(
                "{what}: a link at the lock was not refused: {said}"
            ));
        }
    } else if output.status.code() != Some(0) {
        wrong.push(format!("{what}: with links at {planted:?}: {said}"));
    }
    wrong
}

#[test]
fn no_file_beside_the_policy_is_reached_through_a_link() {
    let outside = tempfile::tempdir().unwrap();
    let mut wrong = Vec::new();
    for writing in &WRITING {
        // The names each command uses: what it leaves in a folder of its
        // own, every name a backup may take and the file the new policy is
        // written to before it takes the policy's place.
        let used = match left(writing) {
            Ok(used) => used,
            Err(said) => {
                wrong.push(format!("{}: {said}", writing.arguments.join(" ")));
                continue;
            }
        };
        let backups = backups();
        let mut alone: Vec<String> = used
            .into_iter()
            .filter(|name| !backups.contains(name))
            .collect();
        alone.push(".policy.json.pending".to_owned());
        alone.sort();
        alone.dedup();
        // Each name alone, so that every one is reached, and the backups at once.
        for name in &alone {
            wrong.extend(through_links(
                writing,
                std::slice::from_ref(name),
                outside.path(),
            ));
        }
        wrong.extend(through_links(writing, &backups, outside.path()));
    }
    assert_eq!(wrong, Vec::<String>::new());
}

/// The commands that only read the policy.
const READING: [&str; 2] = ["check", "list"];

/// Every command of `garrison access` is one that writes the policy, and
/// is above, or one that only reads it: a new one fails this test until it
/// is one of the two.
#[test]
fn every_command_of_access_writes_as_above_or_only_reads() {
    let help = run(prepared().path(), &["access", "--help"]);
    let listed = text(&help.stdout);
    let mut commands: Vec<&str> = listed
        .lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .filter(|command| *command != "help")
        .collect();
    commands.sort_unstable();
    let mut known: Vec<&str> = WRITING
        .iter()
        .map(|writing| writing.arguments[1])
        .chain(READING)
        .collect();
    known.sort_unstable();
    known.dedup();
    assert_eq!(commands, known, "{listed}");
}
