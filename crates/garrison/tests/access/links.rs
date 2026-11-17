//! Every file `garrison access` makes or changes beside the policy is
//! reached by its name in the policy's folder, never through a link, symbolic
//! or hard, that another user of that folder put there, nothing is written
//! over what is there, and the policy is read no further than a policy can
//! be: root runs these commands, and `broker.policy` may name a folder that
//! others can write.

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
    let authentication =
        json!({"id": "singleton", "defaultAdminRoleIds": {}, "defaultUserRoleIds": {}});
    vec![
        respond("x:Authentication/get", &json!([authentication])),
        respond(
            "x:Role/get",
            &json!([role("r2", &["authenticate", "sysAccountGet"], "Readers")]),
        ),
    ]
}

fn same(settings: &str) -> String {
    settings.to_owned()
}

/// An action added after the policy was written.
fn added(settings: &str) -> String {
    format!(
        "{settings}\n[[actions]]\nid = \"install_updates\"\ntitle = \"Install updates\"\n\
         description = \"Installs the pending updates.\"\nconfirmation = \"INSTALL UPDATES\"\n\
         unit = \"updates.service\"\noperation = \"start\"\ncooldown_seconds = 0\n\
         timeout_seconds = 60\n"
    )
}

/// Every command of `garrison access` that writes the policy.
const WRITING: [Writing; 6] = [
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
    Writing {
        arguments: &["access", "update"],
        answers: none,
        settings: added,
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
        // Made anew, so that it has the mode of a new file.
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, &text).unwrap();
        let mode = std::fs::metadata(&path).unwrap().mode();
        Target { path, text, mode }
    }

    fn unchanged(&self) -> bool {
        std::fs::read_to_string(&self.path).unwrap() == self.text
            && std::fs::metadata(&self.path).unwrap().mode() == self.mode
    }
}

/// How a name is planted: a symbolic link to a file outside the folder, or
/// a hard link to it, a second name of that very file.
#[derive(Clone, Copy, Debug)]
enum Link {
    Symbolic,
    Hard,
}

/// What went wrong when `writing` ran with links at `planted`, if anything.
fn through_links(writing: &Writing, planted: &[String], outside: &Path, how: Link) -> Vec<String> {
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
            match how {
                Link::Symbolic => symlink(&target.path, folder.join(name)).unwrap(),
                Link::Hard => std::fs::hard_link(&target.path, folder.join(name)).unwrap(),
            }
        }
    });
    let mut wrong: Vec<String> = planted
        .iter()
        .zip(&targets)
        .filter(|(_, target)| !target.unchanged())
        .map(|(name, _)| format!("{what}: changed what a {how:?} link at {name} names"))
        .collect();
    let lock = directory.path().join(lock);
    let said = text(&output.stderr);
    if refused {
        // A lock that is not the command's own is refused and left as it is.
        let refused = output.status.code() == Some(1) && said.contains(&lock.display().to_string());
        let kept = std::fs::symlink_metadata(&lock).is_ok_and(|kind| match how {
            Link::Symbolic => kind.is_symlink(),
            Link::Hard => kind.is_file() && kind.nlink() == 2,
        });
        if !refused || !kept {
            wrong.push(format!(
                "{what}: a {how:?} link at the lock was not refused: {said}"
            ));
        }
    } else if output.status.code() != Some(0) {
        wrong.push(format!("{what}: with {how:?} links at {planted:?}: {said}"));
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
        // Each name alone, so that every one is reached, and the backups at
        // once; as symbolic and as hard links.
        for how in [Link::Symbolic, Link::Hard] {
            for name in &alone {
                let one = std::slice::from_ref(name);
                wrong.extend(through_links(writing, one, outside.path(), how));
            }
            wrong.extend(through_links(writing, &backups, outside.path(), how));
        }
    }
    assert_eq!(wrong, Vec::<String>::new());
}

/// The policy is read only for its backup, and then no further than a
/// policy can be, which is what the broker reads: a larger file, as a
/// sparse one of many GiB that another user put there, is no policy, and
/// stays as it is.
#[test]
fn the_policy_is_read_no_further_than_a_policy_can_be() {
    let writing = &WRITING[0];
    assert_eq!(writing.arguments, ["access", "init", "--force"]);
    let size = 16 << 20;
    let (directory, output) = ran(writing, (writing.answers)(), |folder| {
        let large = std::fs::File::create(folder.join("policy.json")).unwrap();
        large.set_len(size).unwrap();
    });
    let said = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert!(
        said.contains("is larger than a policy can be (64 KiB), so it is no policy"),
        "{said}"
    );
    let policy = directory.path().join("policy.json");
    assert_eq!(std::fs::metadata(&policy).unwrap().len(), size);
    let backups: Vec<String> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("policy.json."))
        .filter(|name| name != "policy.json.lock")
        .collect();
    assert_eq!(backups, Vec::<String>::new());
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
        // A command's line, not a description's continuation.
        .filter(|line| {
            line.strip_prefix("  ")
                .is_some_and(|rest| !rest.starts_with(' '))
        })
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
