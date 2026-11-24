//! A rule that every check of this crate keeps, held over all of its
//! places, so that a new check, or a new place of one, that breaks it fails
//! here: no card is in order where its check could not look.

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
pub(super) struct Missing;

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
pub(super) fn cards(provider: &dyn Provider, runner: &dyn Runner) -> Vec<Observation> {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    provider
        .collect(&context(&config, runner))
        .unwrap()
        .observations
}

/// A file with `text` and its folders, which only this user may change.
pub(super) fn file(path: &Path, text: &str) {
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
        &at("empty.json"),
        r#"{"date": "2026-10-29T11:00:00Z", "results": []}"#,
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
        (
            "rows where the receipt's list is empty",
            "empty.json",
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
