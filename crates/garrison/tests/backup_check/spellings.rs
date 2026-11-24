//! Two runs that each name the repository in their own way, as a daily and
//! a weekly unit may: the second keeps the check and restore of the first
//! wherever the tool takes both names for one place, and keeps neither
//! where they name two places, such as a copy elsewhere, whose ID is the
//! same.

use std::process::Output;

use serde_json::json;

use super::case::{Case, OLD, Way, way};
use super::stand_in::read;
use super::support::{finished, text};

/// How one run names the repository. `{D}` stands for the case's folder.
#[derive(Clone, Copy, Debug)]
enum Named {
    /// `--repo` with this place.
    Repo(&'static str),
    /// The tool's own variable.
    Variable(&'static str),
    /// The file `RESTIC_REPOSITORY_FILE` names, holding this.
    File(&'static str),
    /// `--repo` with this place, run in that folder.
    From(&'static str, &'static str),
}

use Named::{File, From, Repo, Variable};

/// One run of the case's tool that names the repository so, and checks and
/// restores where `weekly`; it writes the case's report.
fn ran(case: &Case, named: Named, weekly: bool) -> Output {
    let folder = case.tools.directory.path();
    let at = |text: &str| text.replace("{D}", &folder.display().to_string());
    let mut arguments = vec![case.tool.to_owned()];
    let mut environment = vec![("REPO_ID".to_owned(), OLD.to_owned())];
    let mut within = None;
    match named {
        Repo(place) => arguments.extend(["--repo".to_owned(), at(place)]),
        Variable(place) => environment.push((case.variable().to_owned(), at(place))),
        File(held) => {
            let file = folder.join("repository");
            std::fs::write(&file, at(held)).unwrap();
            environment.push((
                "RESTIC_REPOSITORY_FILE".to_owned(),
                file.display().to_string(),
            ));
        }
        From(from, place) => {
            arguments.extend(["--repo".to_owned(), place.to_owned()]);
            within = Some(at(from));
        }
    }
    if weekly {
        arguments.extend(["--verify", "--restore", "/etc/hosts"].map(str::to_owned));
    }
    arguments.extend(["--report".to_owned(), case.report.display().to_string()]);
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let environment: Vec<(&str, &str)> = environment
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let mut command = case.tools.command(&arguments, &environment);
    if let Some(within) = within {
        command.current_dir(within);
    }
    let output = finished(&mut command);
    if weekly {
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
        let written = read(&case.report);
        assert_eq!(
            (&written["verify"]["ok"], &written["restore"]["ok"]),
            (&json!(true), &json!(true)),
            "{named:?}"
        );
    }
    output
}

/// Two names, of one place or of two, whether a run under the second keeps
/// a check made under the first, and the tool whose names they are alone.
type Pair = (&'static str, Named, Named, bool, Option<&'static str>);

const PAIRS: [Pair; 19] = [
    (
        "a slash at its end",
        Repo("{D}/srv/repo/"),
        Repo("{D}/srv/repo"),
        true,
        None,
    ),
    (
        "--repo and the tool's variable",
        Repo("{D}/srv/repo"),
        Variable("{D}/srv/repo"),
        true,
        None,
    ),
    (
        "a link on the way",
        Repo("{D}/link/repo"),
        Repo("{D}/srv/repo"),
        true,
        None,
    ),
    (
        "a dot and a doubled slash",
        Repo("{D}/srv/./repo"),
        Repo("{D}//srv/repo"),
        true,
        None,
    ),
    (
        "a folder and back",
        Repo("{D}/mnt/../srv/repo"),
        Repo("{D}/srv/repo"),
        true,
        None,
    ),
    (
        "a name relative to its folder",
        From("{D}/srv", "repo"),
        Repo("{D}/srv/repo"),
        true,
        None,
    ),
    (
        "a copy in another folder",
        Repo("{D}/srv/repo"),
        Repo("{D}/mnt/copy"),
        false,
        None,
    ),
    (
        "a copy by one name from two folders",
        From("{D}/srv", "repo"),
        From("{D}/mnt", "repo"),
        false,
        None,
    ),
    (
        "local: before it",
        Repo("local:{D}/srv/repo"),
        Repo("{D}/srv/repo"),
        true,
        Some("restic"),
    ),
    (
        "restic's file with a slash at its end, and the variable",
        File("{D}/srv/repo/\n"),
        Variable("{D}/srv/repo"),
        true,
        Some("restic"),
    ),
    (
        "restic's file with spaces around it, and --repo",
        File("  {D}/srv/repo\n\n"),
        Repo("{D}/srv/repo"),
        true,
        Some("restic"),
    ),
    (
        "a server's folder with a slash at its end",
        Repo("sftp:backup@host.example:/srv/repo/"),
        Repo("sftp:backup@host.example:/srv/repo"),
        true,
        Some("restic"),
    ),
    (
        "a REST server's, whose password changed",
        Repo("rest:https://backup:old@host.example:8000/repo/"),
        Repo("rest:https://backup:new@host.example:8000/repo"),
        true,
        Some("restic"),
    ),
    (
        "a copy on another server",
        Repo("sftp:backup@host.example:/srv/repo"),
        Repo("sftp:backup@copy.example:/srv/repo"),
        false,
        Some("restic"),
    ),
    (
        "a copy in another user's home on one server",
        Repo("sftp://alice@host.example/repo"),
        Repo("sftp://bob@host.example/repo"),
        false,
        Some("restic"),
    ),
    (
        "borg's two forms of a folder in a home",
        Repo("ssh://backup@host.example/./repo"),
        Repo("backup@host.example:repo"),
        true,
        Some("borg"),
    ),
    (
        "file:// before it",
        Repo("file://{D}/srv/repo"),
        Repo("{D}/srv/repo"),
        true,
        Some("borg"),
    ),
    (
        "a copy in another user's home on one server",
        Repo("alice@host.example:repo"),
        Repo("bob@host.example:repo"),
        false,
        Some("borg"),
    ),
    (
        "a copy on another server",
        Repo("backup@host.example:repo"),
        Repo("backup@copy.example:repo"),
        false,
        Some("borg"),
    ),
];

/// Every pair of `tool`'s, each way round: a weekly run under one name, then
/// a daily run under the other; and one name whose link now leads to a copy.
pub(super) fn ways(tool: &'static str) -> Vec<Way> {
    let mut ways = Vec::new();
    for (name, first, second, kept, only) in PAIRS {
        if only.is_some_and(|only| only != tool) {
            continue;
        }
        for (weekly, daily, order) in [(first, second, ""), (second, first, ", the other way")] {
            ways.push(way(&format!("{name}{order}"), kept, move |case| {
                ran(case, weekly, true);
                Some(ran(case, daily, false))
            }));
        }
    }
    ways.push(way(
        "one name, whose link now leads to a copy elsewhere",
        false,
        |case| {
            ran(case, Repo("{D}/link/repo"), true);
            let folder = case.tools.directory.path();
            std::fs::remove_file(folder.join("link")).unwrap();
            std::os::unix::fs::symlink(folder.join("mnt"), folder.join("link")).unwrap();
            Some(ran(case, Repo("{D}/link/repo"), false))
        },
    ));
    ways
}
