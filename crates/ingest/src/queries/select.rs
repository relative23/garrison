//! Which events a filter selects: the terms of a `WHERE`, the search in
//! what the events say, and the way to a page of one category.

use rusqlite::types::Value as Sql;

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
/// SQLite's `lower()` folds the letters of ASCII only. The needle is folded
/// the same way, so both sides agree: ASCII letters match in either case,
/// other letters as they are written.
pub(super) fn searched(search: &str) -> (String, [Sql; 3]) {
    let needle = search.to_ascii_lowercase();
    // The needle between the quotes of a JSON string.
    let written = serde_json::to_string(&needle).unwrap_or_default();
    let written = written
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(&needle)
        .to_owned();
    (
        "(instr(lower(type),?)>0 OR (instr(lower(fields),?)>0 AND EXISTS \
         (SELECT 1 FROM json_tree(events.fields) AS part \
          WHERE part.atom IS NOT NULL AND instr(lower(part.atom),?)>0)))"
            .to_owned(),
        [
            Sql::Text(needle.clone()),
            Sql::Text(written),
            Sql::Text(needle),
        ],
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
