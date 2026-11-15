//! Which events a filter selects: the terms of a `WHERE`, the search in
//! what the events say, and the way to a page of one category.

use rusqlite::Connection;
use rusqlite::functions::FunctionFlags;
use rusqlite::types::{Value as Sql, ValueRef};

use super::{Filter, limit_plus_one};
use crate::policy::EventType;

/// `WHERE` terms for the event columns, with their values. The category is
/// not among them: no index leads to a category's events ([`chosen`]).
pub(super) fn conditions(filter: &Filter) -> (Vec<String>, Vec<Sql>) {
    let mut terms = Vec::new();
    let mut values = Vec::new();
    if !filter.event_type.is_empty() {
        terms.push("type=?".to_owned());
        values.push(Sql::Text(filter.event_type.clone()));
    }
    if let Some(since) = filter.since {
        terms.push("created_at>=?".to_owned());
        values.push(Sql::Integer(since));
    }
    if let Some(until) = filter.until {
        terms.push("created_at<=?".to_owned());
        values.push(Sql::Integer(until));
    }
    if !filter.search.is_empty() {
        let (term, found) = searched(&filter.search);
        terms.push(term);
        values.extend(found);
    }
    (terms, values)
}

/// The term that finds `search` in an event of `events`, and its values.
///
/// An event matches by its type's name or by what its fields say: their
/// values, not their names, which are how an event is stored and stand in
/// every event of a type. The values are read from the stored JSON, so a
/// quote or a backslash is found as it was written. Reading them costs, so
/// the stored text is asked first, with the needle written as JSON writes
/// it: only an event that passes is taken apart.
///
/// Both sides are folded with [`fold`], which the connection has as
/// `garrison_fold` ([`foldable`]): every letter matches in either case.
/// SQLite's own `lower()` folds the letters of ASCII only.
pub(super) fn searched(search: &str) -> (String, [Sql; 3]) {
    // The search between the quotes of a JSON string, folded as the stored
    // text is: an escape such as `\n` is folded with it.
    let written = serde_json::to_string(search).unwrap_or_default();
    let written = written
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(search);
    let needle = fold(search);
    (
        "(instr(garrison_fold(type),?)>0 OR (instr(garrison_fold(fields),?)>0 AND EXISTS \
         (SELECT 1 FROM json_tree(events.fields) AS part \
          WHERE part.atom IS NOT NULL \
          AND instr(garrison_fold(CAST(part.atom AS TEXT)),?)>0)))"
            .to_owned(),
        [
            Sql::Text(needle.clone()),
            Sql::Text(fold(written)),
            Sql::Text(needle),
        ],
    )
}

/// `text` with every letter in capitals, for a search that does not care
/// for case. Capitals rather than small letters: they write ß as SS and
/// every sigma as Σ, so that "strasse" finds "Straße" and "οδος" "ΟΔΟΣ".
pub(super) fn fold(text: &str) -> String {
    if text.is_ascii() {
        text.to_ascii_uppercase()
    } else {
        text.to_uppercase()
    }
}

/// Gives `db` the function `garrison_fold`, which [`searched`] uses: [`fold`]
/// of a text, and NULL for anything else.
pub(super) fn foldable(db: &Connection) -> rusqlite::Result<()> {
    db.create_scalar_function(
        "garrison_fold",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |context| {
            Ok(match context.get_raw(0) {
                ValueRef::Text(text) => Some(fold(&String::from_utf8_lossy(text))),
                _ => None,
            })
        },
    )
}

pub(super) fn clause(terms: &[String]) -> String {
    if terms.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", terms.join(" AND "))
    }
}

/// The query that chooses a page's events by their numbers, newest first,
/// and its values; `None` for a category that has no type.
///
/// A category has no index of its own, and walking the events from the
/// newest until a page of a rare category is full would pass the whole
/// history. A category is a known set of types, and each type's newest
/// events come straight from the index by type: the page is the newest of
/// what each type gives.
pub(super) fn chosen(
    filter: &Filter,
    terms: &[String],
    values: Vec<Sql>,
) -> Option<(String, Vec<Sql>)> {
    let limit = Sql::Integer(limit_plus_one(filter.limit));
    if filter.category.is_empty() || !filter.event_type.is_empty() {
        let mut terms = terms.to_vec();
        let mut values = values;
        if !filter.category.is_empty() {
            // With a type named, the category only has to agree with it.
            terms.push("category=?".to_owned());
            values.push(Sql::Text(filter.category.clone()));
        }
        values.push(limit);
        return Some((
            format!(
                "SELECT seq FROM events{} ORDER BY seq DESC LIMIT ?",
                clause(&terms)
            ),
            values,
        ));
    }
    let types: Vec<&str> = EventType::ALL
        .iter()
        .filter(|kind| kind.category() == filter.category)
        .map(|kind| kind.as_str())
        .collect();
    if types.is_empty() {
        return None;
    }
    let mut of_type = terms.to_vec();
    of_type.push("type=?".to_owned());
    let one = format!(
        "SELECT seq FROM (SELECT seq FROM events{} ORDER BY seq DESC LIMIT ?)",
        clause(&of_type)
    );
    let mut all = Vec::new();
    for kind in &types {
        all.extend(values.iter().cloned());
        all.push(Sql::Text((*kind).to_owned()));
        all.push(limit.clone());
    }
    all.push(limit);
    let parts = vec![one; types.len()].join(" UNION ALL ");
    Some((
        format!("SELECT seq FROM ({parts}) ORDER BY seq DESC LIMIT ?"),
        all,
    ))
}
