//! Rules that every check of this crate keeps, each held over all of its
//! places, so that a new check, or a new place of one, that breaks a rule
//! fails here: no card is in order where its check could not look, and a
//! limit that cuts what a card shows says what it left out.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use garrison_core::observations::{Observation, State};

use super::*;
use crate::command::{Output, Runner};
use crate::context::Provider;
use crate::testing::{Canned, config, context, table};

/// The checks this crate gives the collector, as `mod.rs` exports them.
fn exported() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in include_str!("mod.rs")
        .lines()
        .filter_map(|line| line.strip_prefix("pub use "))
    {
        let (_, items) = line.trim_end_matches(';').split_once("::").unwrap();
        for item in items.trim_matches(['{', '}']).split(',') {
            names.insert(item.trim().to_owned());
        }
    }
    names
}

/// Runs no program: each is missing.
struct Missing;

impl Runner for Missing {
    fn run(&self, _: &[&str]) -> io::Result<Output> {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }
}

/// Answers a command that begins with one of its prefixes with that output.
struct Answers(Vec<(&'static str, &'static str)>);

impl Runner for Answers {
    fn run(&self, arguments: &[&str]) -> io::Result<Output> {
        let line = arguments.join(" ");
        self.0
            .iter()
            .find(|(start, _)| line.starts_with(start))
            .map(|(_, stdout)| Output {
                code: Some(0),
                stdout: (*stdout).to_owned(),
            })
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}

/// The cards of `provider`, collected with `runner`.
fn cards(provider: &dyn Provider, runner: &dyn Runner) -> Vec<Observation> {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    provider
        .collect(&context(&config, runner))
        .unwrap()
        .observations
}

/// A file with `text` and its folders, which only this user may change.
fn file(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
}

/// What apt-get printed on Debian 13 where the only pending update was the
/// kernel's, which needs a new package (measured, `hostcare/tests/apt/`),
/// and where no package list was fetched.
const KERNEL_UPGRADE: &str = include_str!("hostcare/tests/apt/debian-13-kernel-only-upgrade.txt");
const KERNEL_DIST_UPGRADE: &str =
    include_str!("hostcare/tests/apt/debian-13-kernel-only-dist-upgrade.txt");
const NO_LISTS: &str = include_str!("hostcare/tests/apt/debian-13-no-lists-dist-upgrade.txt");

/// What one check made of a source it could not look at: the check, what
/// was wrong with its source, and its cards.
type Seen = (&'static str, &'static str, Vec<Observation>);

/// The host's resources and host care, each without what they read.
fn host_checks(at: &dyn Fn(&str) -> PathBuf) -> Vec<Seen> {
    fs::create_dir_all(at("proc")).unwrap();
    let host = Host::new(&table(&format!("proc = \"{}\"", at("proc").display()))).unwrap();
    let mut seen = vec![("Host", "no /proc files", cards(&host, &Missing))];
    fs::create_dir_all(at("root")).unwrap();
    let care = HostCare::new(&table(&format!(
        "root = \"{}\"\ndisk_path = \"{}\"",
        at("root").display(),
        at("gone").display()
    )))
    .unwrap();
    seen.push((
        "HostCare",
        "nothing to read, no program",
        cards(&care, &Missing),
    ));
    let check = |root: &Path, check: &str| {
        HostCare::new(&table(&format!(
            "root = \"{}\"\nchecks = [\"{check}\"]",
            root.display()
        )))
        .unwrap()
    };
    file(&at("apt/usr/bin/apt-get"), "");
    fs::create_dir_all(at("apt/var/lib/apt/lists/partial")).unwrap();
    let lists = Answers(vec![("apt-get", NO_LISTS)]);
    seen.push((
        "HostCare",
        "apt without package lists",
        cards(&check(&at("apt"), "updates"), &lists),
    ));
    file(&at("kernel/usr/bin/apt-get"), "");
    file(
        &at("kernel/var/lib/apt/lists/a_main_binary-amd64_Packages"),
        "",
    );
    let kept_back = Answers(vec![
        (
            "apt-get -s -o Debug::NoLocking=true upgrade",
            KERNEL_UPGRADE,
        ),
        (
            "apt-get -s -o Debug::NoLocking=true dist-upgrade",
            KERNEL_DIST_UPGRADE,
        ),
    ]);
    seen.push((
        "HostCare",
        "a kernel update that needs a new package",
        cards(&check(&at("kernel"), "updates"), &kept_back),
    ));
    file(
        &at("kernels/proc/sys/kernel/osrelease"),
        "6.12.107+deb13-amd64\n",
    );
    file(&at("kernels/lib/modules"), "");
    seen.push((
        "HostCare",
        "installed kernels that cannot be read",
        cards(&check(&at("kernels"), "restart"), &Missing),
    ));
    seen
}

/// Receipts that are missing, too large, no JSON, or whose rows cannot be
/// read.
fn receipts(at: &dyn Fn(&str) -> PathBuf) -> Vec<Seen> {
    let receipt = |name: &str, more: &str| {
        Receipt::new(&table(&format!(
            "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{}\"\n\
             modules = [\"backups\"]\nmax_age_hours = 30\n{more}",
            at(name).display()
        )))
        .unwrap()
    };
    let log = "x".repeat(1024 * 1024);
    file(
        &at("large.json"),
        &format!("{{\"date\": \"2026-10-29T11:00:00Z\", \"log\": \"{log}\"}}"),
    );
    file(&at("text.json"), "the job's log, which is no JSON");
    file(
        &at("unlisted.json"),
        r#"{"date": "2026-10-29T11:00:00Z", "results": null}"#,
    );
    file(
        &at("odd.json"),
        r#"[{"ok": true, "at": "2026-10-29T11:00:00Z"}, "failed"]"#,
    );
    let judged = "rows = [\"results\"]\nok_rows = { key = \"ok\", equals = [true] }";
    let listed = "rows = []\nrow_date = \"at\"\nok_rows = { key = \"ok\", equals = [true] }";
    [
        ("no receipt", "none.json", ""),
        ("a receipt over 1 MiB", "large.json", ""),
        ("a receipt of no JSON", "text.json", ""),
        (
            "rows where the receipt holds no list",
            "unlisted.json",
            judged,
        ),
        ("a row that is no object", "odd.json", listed),
    ]
    .into_iter()
    .map(|(what, name, more)| ("Receipt", what, cards(&receipt(name, more), &Missing)))
    .collect()
}

/// systemd, the backup report, a version command and an endpoint, each
/// without an answer or with one that does not say what is asked.
fn answers(at: &dyn Fn(&str) -> PathBuf) -> Vec<Seen> {
    let unit = "units = [{ unit = \"a.service\", label = \"A\", modules = [\"services\"] }]";
    let systemd = Systemd::new(&table(unit)).unwrap();
    let other =
        Canned("Id=b.service\nNames=b.service\nLoadState=loaded\nActiveState=active\n".into());
    let report = format!("path = \"{}\"", at("restic.json").display());
    let backup = BackupCheck::new(&table(&report)).unwrap();
    let version = VersionCommand::new(&table(
        "component = \"C\"\ncommand = [\"/usr/bin/c\", \"--version\"]",
    ))
    .unwrap();
    let wordy = Canned("c, a build of today\n".into());
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let endpoint = format!("id = \"x\"\ntitle = \"X\"\nurl = \"http://127.0.0.1:{closed}/\"");
    let http = Http::new(&table(&endpoint)).unwrap();
    vec![
        ("Systemd", "no systemctl", cards(&systemd, &Missing)),
        (
            "Systemd",
            "an answer for another unit",
            cards(&systemd, &other),
        ),
        ("BackupCheck", "no report", cards(&backup, &Missing)),
        ("VersionCommand", "no program", cards(&version, &Missing)),
        (
            "VersionCommand",
            "an answer without a version",
            cards(&version, &wordy),
        ),
        ("Http", "nothing listening", cards(&http, &Missing)),
    ]
}

/// Webmail plugins whose bundles cannot be checked, and none named.
fn plugins(at: &dyn Fn(&str) -> PathBuf) -> Vec<Seen> {
    let bulwark = |folder: &Path, named: &str| {
        Bulwark::new(&table(&format!(
            "admin_directory = \"{}\"\nplugins = [{named}]",
            folder.display()
        )))
        .unwrap()
    };
    let mut seen = vec![(
        "Bulwark",
        "no registry",
        cards(&bulwark(&at("nowhere"), "\"spam\""), &Missing),
    )];
    let hash = "0".repeat(64);
    file(
        &at("bulwark/plugins/registry.json"),
        &format!(
            r#"{{"plugins": [{{"id": "spam", "bundleHash": "{hash}"}}, {{"id": "twice"}},
                {{"id": "twice"}}, {{"id": "odd", "bundleHash": "not-a-hash"}}]}}"#
        ),
    );
    for (named, what) in [
        ("\"absent\"", "a plugin the registry does not list"),
        ("\"twice\"", "a plugin it lists twice"),
        ("\"odd\"", "a plugin without a recorded hash"),
        ("\"spam\"", "a bundle that is missing"),
        ("", "no plugin named"),
    ] {
        seen.push((
            "Bulwark",
            what,
            cards(&bulwark(&at("bulwark"), named), &Missing),
        ));
    }
    seen
}

/// Every check of this crate where it cannot look: its source missing or
/// unreadable, cut by a limit, or of a form it does not know. None of their
/// cards may be in order, and every check of the crate has such a case.
#[test]
fn no_card_is_in_order_where_its_check_could_not_look() {
    let work = tempfile::tempdir().unwrap();
    let at = |name: &str| work.path().join(name);
    let mut seen = host_checks(&at);
    seen.extend(receipts(&at));
    seen.extend(answers(&at));
    seen.extend(plugins(&at));
    let covered: BTreeSet<String> = seen.iter().map(|(kind, ..)| (*kind).to_owned()).collect();
    assert_eq!(covered, exported(), "every check has a case");
    let in_order: Vec<String> = seen
        .iter()
        .flat_map(|(kind, what, cards)| {
            cards
                .iter()
                .filter(|card| card.state == State::Ok)
                .map(move |card| format!("{kind}, {what}: {} is in order", card.id))
        })
        .collect();
    assert_eq!(in_order, Vec::<String>::new());
}

/// The limits in this crate's code, before each file's tests: every
/// `const MAX_…` and `const MOST…`, and every `.take(…)`, by its file below
/// src/.
fn limits() -> BTreeSet<(String, String)> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = BTreeSet::new();
    let mut folders = vec![source.clone()];
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if !name.ends_with("tests") {
                    folders.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|suffix| suffix != "rs") || name.ends_with("tests.rs") {
                continue;
            }
            let file = path.strip_prefix(&source).unwrap().display().to_string();
            let text = fs::read_to_string(&path).unwrap();
            for line in text.split("#[cfg(test)]").next().unwrap().lines() {
                let named = line
                    .split("const ")
                    .nth(1)
                    .and_then(|rest| rest.split(':').next());
                if let Some(named) =
                    named.filter(|name| name.starts_with("MAX_") || name.starts_with("MOST"))
                {
                    found.insert((file.clone(), format!("const {named}")));
                }
                for (at, _) in line.match_indices(".take(") {
                    let call = &line[at..=at + line[at..].find(')').unwrap()];
                    if call != ".take()" {
                        found.insert((file.clone(), call.to_owned()));
                    }
                }
            }
        }
    }
    found
}

/// What each cut of this crate's cards says where it cuts: the case, and
/// what the card says of it.
fn cuts(at: &dyn Fn(&str) -> PathBuf) -> Vec<(&'static str, String)> {
    let receipt = |name: &str, more: &str| {
        Receipt::new(&table(&format!(
            "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{}\"\n\
             modules = [\"backups\"]\nmax_age_hours = 30\n{more}",
            at(name).display()
        )))
        .unwrap()
    };
    let rows: Vec<String> = (0..201)
        .map(|run| format!("{{\"run\": {run}, \"at\": \"2026-10-29T11:00:00Z\"}}"))
        .collect();
    file(&at("rows.json"), &format!("[{}]", rows.join(", ")));
    let listed = "rows = []\nrow_date = \"at\"\ncolumns = [{ key = \"run\", label = \"Run\" }]";
    let rows = cards(&receipt("rows.json", listed), &Missing).remove(0);
    let log = "x".repeat(301);
    file(
        &at("text.json"),
        &format!("{{\"date\": \"2026-10-29T11:00:00Z\", \"log\": \"{log}\"}}"),
    );
    let field = "fields = [{ key = \"log\", label = \"Log\" }]";
    let text = cards(&receipt("text.json", field), &Missing).remove(0);
    file(
        &at("restart/proc/sys/kernel/osrelease"),
        "6.12.107+deb13-amd64\n",
    );
    file(&at("restart/run/reboot-required"), "");
    file(
        &at("restart/run/reboot-required.pkgs"),
        "a\nb\nc\nd\ne\nf\n",
    );
    let care = HostCare::new(&table(&format!(
        "root = \"{}\"\nchecks = [\"restart\"]",
        at("restart").display()
    )))
    .unwrap();
    let restart = cards(&care, &Missing).remove(0);
    file(
        &at("long.json"),
        &format!("{{\"date\": \"2026-10-29T11:00:00Z\", \"result\": \"{log}\"}}"),
    );
    let whole = format!("ok_when = {{ key = \"result\", equals = [\"{log}\"] }}");
    let condition = cards(&receipt("long.json", &whole), &Missing).remove(0);
    vec![
        (
            "the rows past a list receipt's table",
            rows.findings.join(" "),
        ),
        (
            "a text past 300 characters",
            text.fields[1].value.as_str().unwrap_or_default().to_owned(),
        ),
        (
            "the packages past five that need a restart",
            restart.findings.join(" "),
        ),
        (
            "a condition on a text past 300 characters",
            format!("{:?} {:?}", condition.state, condition.findings),
        ),
    ]
}

/// Every limit in this crate's code that cuts what a card shows says what
/// it left out: the rows of a list receipt past its table, a text
/// past 300 characters, which a condition still compares whole, and the
/// packages past five that need a restart. A limit that refuses a source
/// whole leaves its card Unknown, never cut. A new limit fails here until it
/// is named below with what it does.
#[test]
fn every_cut_says_what_it_left_out() {
    let work = tempfile::tempdir().unwrap();
    let at = |name: &str| work.path().join(name);
    assert_eq!(
        cuts(&at),
        [
            (
                "the rows past a list receipt's table",
                "The receipt lists 201 rows; the table shows the last 200.".to_owned()
            ),
            (
                "a text past 300 characters",
                format!("{}…", "x".repeat(299))
            ),
            (
                "the packages past five that need a restart",
                "Installed updates need a restart of the host (a, b, c, d, e and 1 more)."
                    .to_owned()
            ),
            (
                "a condition on a text past 300 characters",
                "Ok []".to_owned()
            ),
        ]
    );
    // Every limit in the crate's code is one of these.
    let known = [
        (
            "backups.rs",
            "const MAX_REPORT",
            "a larger report is not read: Unknown, named",
        ),
        (
            "providers/hostcare/restart.rs",
            ".take(5)",
            "the packages past five: said, below",
        ),
        (
            "providers/receipt.rs",
            "const MAX_DOCUMENT",
            "a larger receipt is not read: Unknown",
        ),
        (
            "providers/receipt.rs",
            "const MAX_ROWS",
            "the rows past the table: said, below",
        ),
        (
            "providers/receipt/keys.rs",
            "const MAX_TEXT",
            "a text past it ends in …, below",
        ),
        (
            "providers/receipt/keys.rs",
            ".take(MAX_TEXT - 1)",
            "the same cut",
        ),
        (
            "providers/version.rs",
            "const MAX_OUTPUT",
            "the card is Unknown where it cuts",
        ),
        ("providers/version.rs", ".take(MAX_OUTPUT)", "the same cut"),
        (
            "providers/web.rs",
            "const MAX_BUNDLE",
            "a larger bundle is not read: named",
        ),
        (
            "providers/web.rs",
            "const MAX_REGISTRY",
            "a larger registry is not read: named",
        ),
    ];
    let named: BTreeSet<(String, String)> = known
        .iter()
        .map(|(file, limit, _)| ((*file).to_owned(), (*limit).to_owned()))
        .collect();
    assert_eq!(limits(), named, "a limit that is not named here");
}
