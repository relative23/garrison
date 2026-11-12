//! What `detect` may look at: files below a root directory and the output of
//! read-only commands. Tests use a temporary root and recorded output.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use garrison_collector::Runner;

use super::system::Packages;

const PROPERTIES: &str = "--property=Id,LoadState,ActiveState,UnitFileState,ExecStart";

/// The host under inspection: `/` with real commands, or a test double.
pub(super) struct Host<'a> {
    root: PathBuf,
    runner: &'a dyn Runner,
}

impl std::fmt::Debug for Host<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Host")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

/// What systemd reports for one unit.
#[derive(Debug, Default)]
pub(super) struct Unit {
    pub(super) active: String,
    pub(super) enabled: String,
    /// The first command of `ExecStart`, split into words.
    pub(super) command: Vec<String>,
}

/// A listening TCP port and its process, which `ss` names only to root.
#[derive(Debug)]
pub(super) struct Socket {
    pub(super) port: u16,
    pub(super) process: Option<String>,
}

impl<'a> Host<'a> {
    pub(super) fn new(root: PathBuf, runner: &'a dyn Runner) -> Self {
        Self { root, runner }
    }

    /// An absolute path of the host, below the root.
    pub(super) fn path(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    pub(super) fn exists(&self, path: &str) -> bool {
        self.path(path).exists()
    }

    pub(super) fn read(&self, path: &str) -> Option<String> {
        fs::read_to_string(self.path(path)).ok()
    }

    /// The entries of a directory, sorted; none if it cannot be read.
    pub(super) fn names(&self, path: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.path(path))
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Where a symbolic link points, as written in the link.
    pub(super) fn link(&self, path: &str) -> Option<String> {
        fs::read_link(self.path(path))
            .ok()
            .map(|target| target.display().to_string())
    }

    /// Standard output of a command, or `None` if it cannot run. A command
    /// that fails may still print what it knows, so that output is kept.
    fn output(&self, arguments: &[&str]) -> Option<String> {
        self.runner.run(arguments).ok().map(|output| output.stdout)
    }

    /// The units among `names` that systemd knows, from one `systemctl show`.
    pub(super) fn units(&self, names: &[&str]) -> BTreeMap<String, Unit> {
        let mut arguments = vec!["systemctl", "show", PROPERTIES];
        arguments.extend_from_slice(names);
        self.output(&arguments)
            .map(|text| units(&text))
            .unwrap_or_default()
    }

    /// Every timer systemd has loaded, with the unit it starts.
    pub(super) fn timers(&self) -> Vec<(String, String)> {
        let arguments = [
            "systemctl",
            "list-timers",
            "--all",
            "--no-legend",
            "--plain",
        ];
        let Some(text) = self.output(&arguments) else {
            return Vec::new();
        };
        // The timer and what it starts are the last two columns; dates have
        // spaces in them.
        text.lines()
            .filter_map(|line| {
                let mut columns = line.split_whitespace().rev();
                let starts = columns.next()?;
                Some((columns.next()?, starts))
            })
            .filter(|(name, _)| {
                name.rsplit_once('.')
                    .is_some_and(|(_, kind)| kind == "timer")
            })
            .map(|(name, starts)| (name.to_owned(), starts.to_owned()))
            .collect()
    }

    /// Installed versions of the packages `names`.
    pub(super) fn packages(&self, tool: Packages, names: &[&str]) -> BTreeMap<String, String> {
        let mut arguments = match tool {
            Packages::Rpm => vec![
                "rpm",
                "-q",
                "--queryformat",
                "%{NAME} %{VERSION}-%{RELEASE}\n",
            ],
            Packages::Dpkg => vec![
                "dpkg-query",
                "-W",
                "--showformat",
                "${Package} ${Version} ${db:Status-Abbrev}\n",
            ],
        };
        arguments.extend_from_slice(names);
        let Some(text) = self.output(&arguments) else {
            return BTreeMap::new();
        };
        text.lines()
            .filter_map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                let installed = match tool {
                    // "package x is not installed" has more words.
                    Packages::Rpm => words.len() == 2,
                    // "rc" is removed with its configuration left behind.
                    Packages::Dpkg => words.get(2).is_some_and(|state| state.starts_with("ii")),
                };
                (installed && names.contains(&words[0]))
                    .then(|| (words[0].to_owned(), words[1].to_owned()))
            })
            .collect()
    }

    /// The listening TCP ports.
    pub(super) fn listening(&self) -> Vec<Socket> {
        self.output(&["ss", "-Hltnp"])
            .map(|text| text.lines().filter_map(socket).collect())
            .unwrap_or_default()
    }

    /// Running containers as name and image, from Docker and Podman.
    pub(super) fn containers(&self) -> Vec<(String, String)> {
        ["docker", "podman"]
            .into_iter()
            .filter_map(|tool| self.output(&[tool, "ps", "--format", "{{.Names}} {{.Image}}"]))
            .flat_map(|text| {
                text.lines()
                    .filter_map(|line| line.split_once(' '))
                    .map(|(name, image)| (name.to_owned(), image.trim().to_owned()))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Unit properties from `systemctl show`: one block of `Key=Value` lines per
/// unit, blocks separated by an empty line. Units systemd does not know are
/// left out; masked ones stay, because someone switched them off on purpose.
fn units(text: &str) -> BTreeMap<String, Unit> {
    let mut found = BTreeMap::new();
    for block in text.split("\n\n") {
        let values: BTreeMap<&str, &str> = block
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        let known = matches!(values.get("LoadState"), Some(&("loaded" | "masked")));
        let Some(id) = values.get("Id").filter(|_| known) else {
            continue;
        };
        let value = |key: &str| values.get(key).copied().unwrap_or_default().to_owned();
        found.insert(
            (*id).to_owned(),
            Unit {
                active: value("ActiveState"),
                enabled: value("UnitFileState"),
                command: values
                    .get("ExecStart")
                    .map(|exec| argv(exec))
                    .unwrap_or_default(),
            },
        );
    }
    found
}

/// The words of the first command in an `ExecStart` property:
/// `{ path=/usr/sbin/clamd ; argv[]=/usr/sbin/clamd -c /etc/clamd.d/scan.conf ; … }`.
fn argv(value: &str) -> Vec<String> {
    value
        .split_once("argv[]=")
        .and_then(|(_, rest)| rest.split(" ;").next())
        .map(|words| words.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// One line of `ss -Hltnp`:
/// `LISTEN 0 4096 0.0.0.0:25 0.0.0.0:* users:(("stalwart",pid=812,fd=9))`.
fn socket(line: &str) -> Option<Socket> {
    let local = line.split_whitespace().nth(3)?;
    let port = local.rsplit_once(':')?.1.parse().ok()?;
    let process = line
        .split_once("((\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(name, _)| name.to_owned());
    Some(Socket { port, process })
}
