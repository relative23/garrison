//! Objects of a kind, as many as Stalwart has, in pages, the oldest first.
//! Each page is a `/query` for the IDs from a position and a `/get` of those
//! IDs in the same request (`#ids`, a result reference), so that no answer
//! grows with the number of objects. A `/get` of all objects (`ids: null`)
//! gets the first 500 from Stalwart and not a word of the rest (measured on
//! 1.2.0).
//!
//! The list may change between two pages. An object made meanwhile comes
//! last, as no ID is given again; one removed moves every later one up a
//! place, and a page asked from the position the last one reached would
//! leave one out. So each page after the first begins with the last object
//! read: where that object is there, the two pages join, and where it is
//! not, the page is asked again from further back.

use std::collections::{BTreeMap, BTreeSet};

use garrison_core::json;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{JmapClient, Object, answered, read, whole};
use crate::Error;
use crate::http::MAX_RESPONSE;

/// The most objects one page asks for: as many IDs as Stalwart takes in one
/// `/get`, its `maxObjectsInGet` (500 on 1.2.0).
pub const PAGE: usize = 500;

/// The first objects of a kind, and how many Stalwart has.
#[derive(Debug, PartialEq, Eq)]
pub struct Listed<T> {
    /// The oldest first.
    pub objects: Vec<T>,
    /// How many objects of the kind Stalwart has.
    pub total: usize,
    /// Why the objects after these were not read, where a page after the
    /// first failed: the pages before it stand.
    pub rest: Option<Error>,
}

/// The objects from a position of the list, each with its ID, and how many
/// objects the list has.
struct Page<T> {
    from: usize,
    /// How many IDs the query gave: so far the page reaches in the list.
    ids: usize,
    objects: Vec<(String, T)>,
    total: usize,
}

/// What a `/query` answers: the IDs from its position, and how many there
/// are in all.
#[derive(Deserialize)]
struct Queried {
    ids: Vec<String>,
    total: usize,
}

impl JmapClient {
    /// The oldest `most` objects of `kind`, such as `Account`, each read as
    /// a `T` with `properties`, and how many Stalwart has: in pages of
    /// [`PAGE`], each a request of its own. Before each page after the
    /// first, `more` says whether there is time for it; where it says no,
    /// the objects of the pages before are listed.
    ///
    /// The key needs the `/query` permission of the kind beside its `/get`
    /// one, such as `sysAccountQuery`. An object that comes again in a later
    /// page is listed once. Where a page after the first fails, the objects
    /// of the pages before it are listed with why the rest was not read.
    pub fn listed<T: DeserializeOwned>(
        &self,
        kind: &str,
        properties: &[&str],
        most: usize,
        more: impl Fn() -> bool,
    ) -> Result<Listed<T>, Error> {
        let (mut objects, mut seen) = (Vec::new(), BTreeSet::new());
        let (mut total, mut position, mut rest) = (0, 0, None);
        while objects.len() < most && (position == 0 || more()) {
            // A later page begins with an object read before, so one more.
            let wanted = most - objects.len() + usize::from(position > 0);
            let page = match self.joined::<T>(kind, properties, position, PAGE.min(wanted), &seen) {
                Ok(page) => page,
                // The first page's failure is the list's; a later one's
                // leaves what the pages before it gave.
                Err(error) if position > 0 => {
                    rest = Some(error);
                    break;
                }
                Err(error) => return Err(error),
            };
            total = page.total;
            position = page.from + page.ids;
            let before = objects.len();
            for (id, object) in page.objects {
                if seen.insert(id) {
                    objects.push(object);
                }
            }
            if objects.len() == before || position >= total {
                break;
            }
        }
        objects.truncate(most);
        Ok(Listed {
            total: total.max(objects.len()),
            objects,
            rest,
        })
    }

    /// The page that follows the `position` objects read so far, whose IDs
    /// are `seen`. It is asked from the last object read, and joins what
    /// was read where it begins with an object of `seen`. Where it does
    /// not, objects before it were removed since, and it is asked again
    /// from a page further back, then from the first object, from which
    /// every page joins.
    fn joined<T: DeserializeOwned>(
        &self,
        kind: &str,
        properties: &[&str],
        position: usize,
        limit: usize,
        seen: &BTreeSet<String>,
    ) -> Result<Page<T>, Error> {
        let mut back = 1;
        loop {
            let from = position.saturating_sub(back);
            let page = self.page::<T>(kind, properties, from, limit)?;
            let first = page.objects.first();
            if from == 0 || first.is_some_and(|(id, _)| seen.contains(id)) {
                return Ok(page);
            }
            back = if back < PAGE { PAGE } else { position };
        }
    }

    /// The objects of `kind` from `position` on, `limit` of them at the
    /// most, each with its ID, the oldest first, and how many there are.
    fn page<T: DeserializeOwned>(
        &self,
        kind: &str,
        properties: &[&str],
        position: usize,
        limit: usize,
    ) -> Result<Page<T>, Error> {
        let (query, get) = (format!("x:{kind}/query"), format!("x:{kind}/get"));
        // Stalwart's IDs rise with each object made and are not given again,
        // so by ID the oldest come first and a new one comes last; a query
        // that names no order lists the newest first (measured on 1.2.0).
        let oldest = json!([{"property": "id", "isAscending": true}]);
        let calls = [
            (
                query.as_str(),
                json!({"sort": oldest, "position": position, "limit": limit,
                       "calculateTotal": true}),
            ),
            (
                get.as_str(),
                json!({
                    "#ids": {"resultOf": "0", "name": query, "path": "/ids"},
                    "properties": properties,
                }),
            ),
        ];
        let mut answers = self.call_many(&calls, MAX_RESPONSE)?.into_iter();
        let mut next = |method: &str| {
            answers
                .next()
                .unwrap_or_else(|| Err(Error::Unreadable(format!("{method} was not answered"))))
        };
        let (queried, result) = (next(&query)?, next(&get)?);
        let Queried { ids, total } = json::object(Value::Object(queried))
            .map_err(|_| Error::Unreadable(format!("{query} returned no IDs and no total")))?;
        let asked: Vec<&str> = ids.iter().map(String::as_str).collect();
        // An ID the query gave and the get does not find is of an object
        // removed between the two: it is no longer there to be listed.
        let (objects, gone) = answered(&get, result)?;
        whole(&get, &objects, &gone, &asked)?;
        let mut found: BTreeMap<String, Object> = objects
            .into_iter()
            .filter_map(|object| {
                let id = object.get("id")?.as_str()?.to_owned();
                Some((id, object))
            })
            .collect();
        let count = ids.len();
        let mut objects = Vec::with_capacity(count);
        for id in ids {
            if let Some(object) = found.remove(&id) {
                objects.push((id, read(&get, object)?));
            }
        }
        Ok(Page {
            from: position,
            ids: count,
            objects,
            total,
        })
    }
}

#[cfg(test)]
mod tests;
