//! A rule that every check of this crate keeps, held over all of its
//! places, so that a new check, or a new place of one, that breaks it fails
//! here: a limit that cuts what a card shows says what it left out.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::kinds_tests::{Missing, cards, file};
use super::*;
use crate::testing::table;

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
