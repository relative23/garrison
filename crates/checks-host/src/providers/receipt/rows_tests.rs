//! What a receipt with rows says of the rows it could not judge.

use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;
use crate::testing::{Canned, config, context, table};

/// The card of a receipt that holds `document`, with `settings` added.
fn card(document: &Value, settings: &str) -> Observation {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("receipt.json");
    std::fs::write(&path, document.to_string()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let receipt = Receipt::new(&table(&format!(
        "type = \"receipt\"\nid = \"r\"\ntitle = \"R\"\npath = \"{}\"\n\
         modules = [\"backups\"]\nmax_age_hours = 30\n{settings}",
        path.display()
    )))
    .unwrap();
    let (config, runner) = (config(directory.path()), Canned(String::new()));
    receipt
        .collect(&context(&config, &runner))
        .unwrap()
        .observations
        .remove(0)
}

/// Where `ok_rows` judges the rows, a receipt that holds none it could
/// judge is no success: Unknown, as one whose `rows` name no list, and the
/// card says why. Without `ok_rows` an empty list is an empty table.
#[test]
fn ok_rows_that_judge_no_row_leave_the_card_unknown() {
    let judged = "rows = [\"results\"]\nok_rows = { key = \"ok\", equals = [true] }";
    let fresh = "2026-10-29T11:00:00Z";
    let said = |observation: Observation| (observation.state, observation.findings);
    assert_eq!(
        said(card(&json!({"date": fresh, "results": []}), judged)),
        (
            State::Unknown,
            vec!["The receipt lists no rows, so `ok_rows` judged none.".to_owned()]
        )
    );
    assert_eq!(
        said(card(
            &json!({"date": fresh, "results": ["failed", "failed"]}),
            judged
        )),
        (
            State::Unknown,
            vec!["2 of the receipt's 2 rows are no objects and were not read.".to_owned()]
        )
    );
    let listed = "rows = []\nrow_date = \"at\"\nok_rows = { key = \"ok\", equals = [true] }";
    assert_eq!(
        said(card(&json!([]), listed)),
        (
            State::Unknown,
            vec![
                "The receipt has no valid date.".to_owned(),
                "The receipt lists no rows, so `ok_rows` judged none.".to_owned()
            ]
        )
    );
    let shown = "rows = [\"results\"]\ncolumns = [{ key = \"ok\", label = \"OK\" }]";
    let table = card(&json!({"date": fresh, "results": []}), shown);
    assert_eq!(
        (
            table.state,
            table.findings.len(),
            table.table.map(|table| table.rows.len())
        ),
        (State::Ok, 0, Some(0))
    );
}

/// A long list gives one count of its rows: those that are no objects are
/// among the rows it lists, and the table shows the last of those it read.
#[test]
fn a_long_list_with_rows_that_are_no_objects_gives_one_count() {
    let mut rows: Vec<Value> = (0..205)
        .map(|run| json!({"run": run, "at": "2026-10-29T11:00:00Z"}))
        .collect();
    rows.extend([json!("failed"), json!("failed"), json!("failed")]);
    let observation = card(
        &Value::Array(rows),
        "rows = []\nrow_date = \"at\"\ncolumns = [{ key = \"run\", label = \"Run\" }]",
    );
    assert_eq!(
        (observation.state, observation.findings),
        (
            State::Partial,
            vec![
                "3 of the receipt's 208 rows are no objects and were not read.".to_owned(),
                "The receipt lists 208 rows; the table shows the last 200 of the 205 it read."
                    .to_owned()
            ]
        )
    );
    let table = observation.table.unwrap();
    assert_eq!((table.rows.len(), &table.rows[0]), (200, &vec![json!(5)]));
}
