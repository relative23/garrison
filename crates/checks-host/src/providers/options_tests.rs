//! One rule held over every option of every check of this crate: an option
//! that check-config takes is used in the configuration it is taken in.
//! Each option has a case of two configurations that differ by it alone,
//! whose reports must differ, and the combinations in which it would be
//! unused are refused. The options of each check are read from its source,
//! the lists that a provider's table and its entries' tables are held
//! against, so that a new option without a case fails here, and so does a
//! new source that takes options.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use garrison_testing::http::{answer, serve};
use serde_json::json;

use super::*;
use crate::command::{Output, Runner};
use crate::context::Provider;
use crate::testing::{config, context, table};

mod uses;

use uses::{host_uses, other_uses, receipt_uses, systemd_uses};

/// The sources of this crate's checks that take options, below providers/.
const SOURCES: [(&str, &str); 8] = [
    ("backupcheck.rs", include_str!("backupcheck.rs")),
    ("host.rs", include_str!("host.rs")),
    ("hostcare.rs", include_str!("hostcare.rs")),
    ("receipt.rs", include_str!("receipt.rs")),
    ("receipt/keys.rs", include_str!("receipt/keys.rs")),
    ("systemd.rs", include_str!("systemd.rs")),
    ("version.rs", include_str!("version.rs")),
    ("web.rs", include_str!("web.rs")),
];

/// The option names `source` takes: those of each list it gives
/// `Options::new`, and of each list it holds a table's keys against.
fn taken(source: &str) -> BTreeSet<String> {
    let mut lists = Vec::new();
    for (at, _) in source.match_indices("Options::new(") {
        let rest = &source[at..];
        let open = rest.find("&[").unwrap() + 2;
        lists.push(&rest[open..open + rest[open..].find(']').unwrap()]);
    }
    for (at, _) in source.match_indices("].contains(&") {
        let before = &source[..at];
        lists.push(&before[before.rfind('[').unwrap() + 1..]);
    }
    lists
        .iter()
        .flat_map(|list| list.split('"').skip(1).step_by(2))
        .map(str::to_owned)
        .collect()
}

/// The files below providers/ whose code, before its tests, takes options.
fn takers() -> BTreeSet<String> {
    let providers = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/providers");
    let mut found = BTreeSet::new();
    let mut folders = vec![providers.clone()];
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
            let text = fs::read_to_string(&path).unwrap();
            let code = text.split("#[cfg(test)]").next().unwrap();
            if code.contains("Options::new(") || code.contains("].contains(&") {
                let file = path.strip_prefix(&providers).unwrap();
                found.insert(file.display().to_string());
            }
        }
    }
    found
}

/// Answers a command that begins with one of its prefixes, with exit 0.
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

/// What a check of `kind` with `options` reports, as text, or the words
/// check-config refuses it with.
fn report(kind: &str, options: &str, runner: &dyn Runner) -> Result<String, String> {
    let raw = table(options);
    let provider: Box<dyn Provider> = match kind {
        "backup-check" => Box::new(BackupCheck::new(&raw).map_err(|error| error.0)?),
        "bulwark" => Box::new(Bulwark::new(&raw).map_err(|error| error.0)?),
        "host" => Box::new(Host::new(&raw).map_err(|error| error.0)?),
        "host-care" => Box::new(HostCare::new(&raw).map_err(|error| error.0)?),
        "http" => Box::new(Http::new(&raw).map_err(|error| error.0)?),
        "receipt" => Box::new(Receipt::new(&raw).map_err(|error| error.0)?),
        "systemd" => Box::new(Systemd::new(&raw).map_err(|error| error.0)?),
        _ => Box::new(VersionCommand::new(&raw).map_err(|error| error.0)?),
    };
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let collected = provider.collect(&context(&config, runner)).unwrap();
    Ok(json!({"cards": collected.observations, "gauges": collected.gauges}).to_string())
}

/// A file with `text` and its folders, which only this user may change.
fn file(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
}

/// One option's use: the source that takes it, the check, and two
/// configurations that differ by the option alone.
struct Use {
    source: &'static str,
    option: &'static str,
    kind: &'static str,
    base: String,
    changed: String,
}

fn uses(
    source: &'static str,
    kind: &'static str,
    base: &str,
    options: &[(&'static str, String)],
) -> Vec<Use> {
    options
        .iter()
        .map(|(option, changed)| Use {
            source,
            option,
            kind,
            base: base.to_owned(),
            changed: changed.clone(),
        })
        .collect()
}

/// What every case collects with: systemctl, timedatectl and a version
/// command answer as on a host, nothing else does.
const ANSWERS: [(&str, &str); 4] = [
    ("systemctl is-active", "inactive\ninactive\ninactive\n"),
    ("timedatectl", "yes\n"),
    (
        "/usr/bin/env TZ=UTC /usr/bin/systemctl show",
        "Id=a.service\nNames=a.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n\
         Result=success\nExecMainStartTimestamp=Wed 2026-10-28 03:00:00 UTC\n\
         ExecMainExitTimestamp=Wed 2026-10-28 03:05:00 UTC\nExecMainStatus=0\n",
    ),
    ("/usr/bin/", "c 1.2.3, built with 4.5.6\n"),
];

/// The combinations check-config refuses because an option in them would
/// do nothing, and the words it refuses them with.
fn refused(at: &dyn Fn(&str) -> String) -> Vec<(&'static str, String, &'static str)> {
    let receipt = |more: &str| {
        format!(
            "id = \"r\"\ntitle = \"R\"\npath = \"{}\"\nmodules = [\"backups\"]\n{more}",
            at("a.json")
        )
    };
    let not_a_job = |unit: &str, more: &str| {
        format!("units = [{{ unit = \"{unit}\", label = \"B\", modules = [\"backups\"], {more} }}]")
    };
    vec![
        (
            "host-care",
            "checks = [\"clock\"]\ndisk_path = \"/var\"".to_owned(),
            "providers[host-care].disk_path needs the disk check",
        ),
        (
            "host-care",
            "checks = [\"clock\"]\nfirewall_units = [\"a.service\"]".to_owned(),
            "providers[host-care].firewall_units needs the firewall check",
        ),
        (
            "systemd",
            not_a_job("backup.timer", "expect = \"idle\""),
            "providers[systemd] unit backup.timer: expect = \"idle\" and max_age_hours are for a service that runs and ends, not for a timer; put them on the service the timer starts, such as backup.service",
        ),
        (
            "systemd",
            not_a_job("backup.timer", "max_age_hours = 26"),
            "providers[systemd] unit backup.timer: expect = \"idle\" and max_age_hours are for a service that runs and ends, not for a timer; put them on the service the timer starts, such as backup.service",
        ),
        (
            "systemd",
            not_a_job("a.service", "max_age_hours = 26"),
            "providers[systemd] unit a.service max_age_hours must be 1 to 8760 hours, for a unit with expect = \"idle\"",
        ),
        (
            "version-command",
            "component = \"C\"\ncommand = [\"/usr/bin/c\"]\npattern = \"\\\\d+\"".to_owned(),
            "providers[version-command].pattern needs a group, ( ), around the version",
        ),
        (
            "receipt",
            receipt("columns = [{ key = \"ok\", label = \"OK\" }]"),
            "providers[receipt].columns needs rows",
        ),
        (
            "receipt",
            receipt("ok_rows = { key = \"ok\", equals = [true] }"),
            "providers[receipt].ok_rows needs rows",
        ),
        (
            "receipt",
            receipt("row_date = \"at\""),
            "providers[receipt].row_date needs rows",
        ),
        (
            "receipt",
            receipt("rows = [\"results\"]\nrow_date = \"at\""),
            "providers[receipt].row_date is only for rows = []; rows under a key take the receipt's date from date",
        ),
        (
            "receipt",
            receipt("rows = []"),
            "providers[receipt] with rows = [] needs row_date, the key of each row's date",
        ),
        (
            "receipt",
            receipt("rows = []\nrow_date = \"at\"\nfields = [{ key = \"n\", label = \"N\" }]"),
            "providers[receipt].fields reads an object, but rows = [] reads a list; use columns, ok_rows and row_date",
        ),
        (
            "receipt",
            receipt("rows = []\nrow_date = \"at\"\nok_when = { key = \"r\", equals = [1] }"),
            "providers[receipt].ok_when reads an object, but rows = [] reads a list; use columns, ok_rows and row_date",
        ),
        (
            "receipt",
            receipt("rows = []\nrow_date = \"at\"\ndate = \"when\""),
            "providers[receipt].date reads an object, but rows = [] reads a list; use columns, ok_rows and row_date",
        ),
    ]
}

/// Every option of every check of the crate changes what the check reports
/// in a configuration check-config takes, every combination in which one
/// would not is refused, and every option and every source that takes
/// options has its case.
#[test]
fn every_option_is_used_where_it_is_taken() {
    let work = tempfile::tempdir().unwrap();
    let at = |name: &str| work.path().join(name).display().to_string();
    // Each of the five cases of the endpoint asks it twice.
    let server = serve(vec![answer(200, ""); 10]);
    let mut all = host_uses(&at);
    all.extend(systemd_uses());
    all.extend(receipt_uses(&at));
    all.extend(other_uses(&at, &server.url));
    let runner = Answers(ANSWERS.to_vec());
    let unused: Vec<String> = all
        .iter()
        .filter(|case| {
            report(case.kind, &case.base, &runner).unwrap()
                == report(case.kind, &case.changed, &runner).unwrap()
        })
        .map(|case| format!("{} of {} did nothing", case.option, case.kind))
        .collect();
    assert_eq!(unused, Vec::<String>::new());
    let wrong: Vec<String> = refused(&at)
        .into_iter()
        .filter_map(
            |(kind, options, words)| match report(kind, &options, &runner) {
                Err(refusal) if refusal == words => None,
                Err(refusal) => Some(format!("{kind} {options:?}: refused as {refusal:?}")),
                Ok(_) => Some(format!("{kind} {options:?}: taken")),
            },
        )
        .collect();
    assert_eq!(wrong, Vec::<String>::new());
    let mut covered: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for case in &all {
        covered
            .entry(case.source)
            .or_default()
            .insert(case.option.to_owned());
    }
    let sources: BTreeMap<&str, BTreeSet<String>> = SOURCES
        .iter()
        .map(|(name, text)| (*name, taken(text)))
        .collect();
    assert_eq!(covered, sources, "every option has its case");
    let named: BTreeSet<String> = SOURCES.iter().map(|(name, _)| (*name).to_owned()).collect();
    assert_eq!(takers(), named, "every source that takes options is read");
}
