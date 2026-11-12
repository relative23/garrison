use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use garrison_core::modules::ModuleId;

use super::*;

fn example() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config/garrison.example.toml");
    fs::read_to_string(path).unwrap()
}

fn set(ids: &[ModuleId]) -> BTreeSet<ModuleId> {
    ALWAYS.into_iter().chain(ids.iter().copied()).collect()
}

#[test]
fn the_choice_goes_into_the_example_after_its_explanation() {
    let chosen = set(&[ModuleId::Antivirus, ModuleId::Backups]);
    let text = with_modules(&example(), &chosen);
    assert_eq!(config::from_text(&text).unwrap().modules, chosen);
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| *line == r#"modules = ["antivirus", "backups"]"#)
        .unwrap();
    assert!(lines[at - 1].starts_with('#'), "{}", lines[at - 1]);
    assert!(lines[..at].iter().all(|line| !line.starts_with('[')));
    // Choosing again replaces the line, and the comments stay as they were.
    let again = with_modules(&text, &set(&[ModuleId::Spam]));
    assert_eq!(again.matches("\nmodules = ").count(), 1);
    assert_eq!(
        config::from_text(&again).unwrap().modules,
        set(&[ModuleId::Spam])
    );
    assert!(again.contains(r#"# modules = ["antivirus", "spam""#));
    assert_eq!(with_modules(&again, &set(&[ModuleId::Spam])), again);
}

#[test]
fn a_list_over_several_lines_is_replaced_whole() {
    let text = example().replacen(
        "schema = 1\n",
        "schema = 1\nmodules = [\n  \"antivirus\",\n  \"logs\",\n]\n",
        1,
    );
    assert_eq!(
        config::from_text(&text).unwrap().modules,
        set(&[ModuleId::Antivirus, ModuleId::Logs])
    );
    let replaced = with_modules(&text, &set(&[ModuleId::Backups]));
    assert!(!replaced.contains("\"logs\",\n"));
    assert_eq!(
        config::from_text(&replaced).unwrap().modules,
        set(&[ModuleId::Backups])
    );
}

#[test]
fn what_detect_found_is_suggested() {
    let found = BTreeMap::from([
        ("stalwart", vec!["stalwart.service".to_owned()]),
        ("clamav-scanner", vec!["clamd@scan.service".to_owned()]),
        ("clamav-milter", vec!["clamav-milter.service".to_owned()]),
    ]);
    let suggested = |rows: &[Row]| -> BTreeSet<ModuleId> {
        rows.iter()
            .filter(|row| row.suggested)
            .map(|row| row.id)
            .collect()
    };
    let rows = rows(&found, 2, false);
    assert_eq!(
        suggested(&rows),
        set(&[
            ModuleId::Antivirus,
            ModuleId::Spam,
            ModuleId::Attacks,
            ModuleId::Deliveries,
            ModuleId::Sessions,
            ModuleId::Logs,
            ModuleId::DnsTls,
            ModuleId::Actions,
        ])
    );
    let antivirus = rows
        .iter()
        .find(|row| row.id == ModuleId::Antivirus)
        .unwrap();
    assert_eq!(
        antivirus.hint,
        "ClamAV found: clamd@scan.service, clamav-milter.service"
    );
    // On a bare host only what needs nothing else is suggested.
    assert_eq!(
        suggested(&super::rows(&BTreeMap::new(), 0, false)),
        set(&[ModuleId::DnsTls])
    );
}

#[test]
fn numbers_switch_modules_and_enter_saves() {
    let rows = rows(&BTreeMap::new(), 0, false);
    let mut chosen = set(&[]);
    let mut output = Vec::new();
    // 3 is the antivirus; 1, the dashboard, stays on.
    assert!(choose(&mut "3 1 x\n\n".as_bytes(), &mut output, &rows, &mut chosen).unwrap());
    assert_eq!(chosen, set(&[ModuleId::Antivirus]));
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("Dashboard is always on."));
    assert!(output.contains("x is not a number from the list."));
    assert!(output.contains("  3 [x] Antivirus"));
    // q, or the end of the input, leaves without saving.
    for input in ["3\nq\n", "3\n"] {
        assert!(!choose(&mut input.as_bytes(), &mut Vec::new(), &rows, &mut set(&[])).unwrap());
    }
}

#[test]
fn a_list_on_the_command_line_names_known_modules() {
    assert_eq!(
        parse_list("antivirus, backups").unwrap(),
        set(&[ModuleId::Antivirus, ModuleId::Backups])
    );
    assert_eq!(parse_list("").unwrap(), set(&[]));
    let refused = parse_list("antivirus,backup").unwrap_err();
    assert!(refused.starts_with("backup is not a module ID; known: dashboard, services,"));
}

#[test]
fn writing_keeps_the_previous_file_and_its_mode() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garrison.toml");
    fs::write(&path, example()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let chosen = set(&[ModuleId::Logs]);
    let previous = write(&path, &chosen, "").unwrap();
    assert_eq!(fs::read_to_string(&previous).unwrap(), example());
    assert_eq!(config::load(&path).unwrap().modules, chosen);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    // A file that would not load is never written.
    fs::write(&path, "schema = 2\n").unwrap();
    assert!(write(&path, &chosen, "").is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "schema = 2\n");
}

#[test]
fn entries_are_added_only_when_the_collector_accepts_them() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garrison.toml");
    fs::write(&path, example()).unwrap();
    let before = config::load(&path).unwrap().collector.providers.len();
    let entries = "# Added by `garrison modules` from what `detect` found.\n\n\
                   [[providers]]\ntype = \"systemd\"\nunits = [\n  { unit = \"clamd@scan.service\", \
                   label = \"ClamAV scanner\", modules = [\"antivirus\", \"services\"] },\n]\n";
    write(&path, &set(&[ModuleId::Antivirus]), entries).unwrap();
    let after = config::load(&path).unwrap();
    assert_eq!(after.collector.providers.len(), before + 1);
    assert_eq!(after.modules, set(&[ModuleId::Antivirus]));
    // An entry the collector refuses leaves the file as it was.
    let written = fs::read_to_string(&path).unwrap();
    assert!(write(&path, &set(&[]), "\n[[providers]]\ntype = \"nonsense\"\n").is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), written);
}

#[test]
fn questions_take_their_default_on_enter() {
    let answer = |input: &str, default| ask("?", default, &mut input.as_bytes(), &mut Vec::new());
    assert!(answer("\n", true) && !answer("\n", false));
    assert!(answer("y\n", false) && !answer("no\n", true));
}

#[test]
fn found_entries_are_added_as_the_options_and_the_operator_say() {
    let found = || "[[providers]]\ntype = \"clamav\"\n".to_owned();
    let refuse = |_: &str| false;
    // --set without --adopt adds nothing and asks for nothing.
    let listed = additions(
        true,
        false,
        || unreachable!("not looked for"),
        |_| unreachable!(),
    );
    assert_eq!(listed, "");
    assert_eq!(additions(true, true, found, |_| unreachable!()), found());
    // In the terminal the operator decides, unless nothing was found.
    assert_eq!(additions(false, false, found, |_| true), found());
    assert_eq!(additions(false, false, found, refuse), "");
    assert_eq!(additions(false, true, String::new, |_| unreachable!()), "");
}

#[test]
fn the_action_count_reads_as_a_sentence() {
    let hint = |actions| {
        rows(&BTreeMap::new(), actions, false)
            .into_iter()
            .find(|row| row.id == ModuleId::Actions)
            .map(|row| (row.hint, row.suggested))
            .unwrap()
    };
    assert_eq!(hint(0), ("0 actions configured".to_owned(), false));
    assert_eq!(hint(1), ("1 action configured".to_owned(), true));
    assert_eq!(hint(2), ("2 actions configured".to_owned(), true));
}

#[test]
fn alerts_are_suggested_where_there_is_something_to_tell_through() {
    let hint = |found: &BTreeMap<&str, Vec<String>>, notifying| {
        rows(found, 0, notifying)
            .into_iter()
            .find(|row| row.id == ModuleId::Alerts)
            .map(|row| (row.hint, row.suggested))
            .unwrap()
    };
    let nothing = BTreeMap::new();
    assert_eq!(
        hint(&nothing, false),
        (
            "an ntfy topic, a webhook or a mailbox, or receipts of an outside monitor".to_owned(),
            false
        )
    );
    // A channel in the configuration counts wherever its server runs.
    assert_eq!(
        hint(&nothing, true),
        ("notifications are configured".to_owned(), true)
    );
    let here = BTreeMap::from([("notifications", vec!["ntfy.service".to_owned()])]);
    assert_eq!(
        hint(&here, false),
        ("ntfy found: ntfy.service".to_owned(), true)
    );
}

#[test]
fn commas_and_spaces_between_numbers_are_no_error() {
    let rows = rows(&BTreeMap::new(), 0, false);
    let mut output = Vec::new();
    let mut chosen = set(&[]);
    assert!(choose(&mut "3, 4\n\n".as_bytes(), &mut output, &rows, &mut chosen).unwrap());
    let output = String::from_utf8(output).unwrap();
    assert!(!output.contains("is not a number"), "{output}");
    assert_eq!(chosen.len(), ALWAYS.len() + 2);
}

#[test]
fn the_line_also_fits_a_file_without_top_level_keys() {
    let chosen = set(&[ModuleId::Spam]);
    assert_eq!(
        with_modules("[deployment]\nissuer = \"x\"\n", &chosen),
        "modules = [\"spam\"]\n[deployment]\nissuer = \"x\"\n"
    );
    // The line goes before the blank lines that end the top-level part.
    assert_eq!(
        with_modules("schema = 1\n\n\n[deployment]\n", &chosen),
        "schema = 1\nmodules = [\"spam\"]\n\n\n[deployment]\n"
    );
    // A list that never closes before the first section loses only its line.
    assert_eq!(
        with_modules("modules = [\n[deployment]\n", &chosen),
        "modules = [\"spam\"]\n[deployment]\n"
    );
}
