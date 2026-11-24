//! Objects of a kind, as many as Stalwart has, in pages. Each page is a
//! `/query` for the IDs from a position and a `/get` of those IDs in the
//! same request (`#ids`, a result reference), so that no answer grows with
//! the number of objects. A `/get` of all objects (`ids: null`) gets the
//! first 500 from Stalwart and not a word of the rest (measured on 1.1.0).

use std::collections::{BTreeMap, BTreeSet};

use garrison_core::json;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{JmapClient, Object, got, read};
use crate::Error;
use crate::http::MAX_RESPONSE;

/// The most objects one page asks for: as many IDs as Stalwart takes in one
/// `/get`, its `maxObjectsInGet` (500 on 1.1.0).
pub const PAGE: usize = 500;

/// The first objects of a kind, and how many Stalwart has.
#[derive(Debug, PartialEq, Eq)]
pub struct Listed<T> {
    /// In the order of Stalwart's query.
    pub objects: Vec<T>,
    /// How many objects of the kind Stalwart has.
    pub total: usize,
}

/// What a `/query` answers: the IDs from its position, and how many there
/// are in all.
#[derive(Deserialize)]
struct Queried {
    ids: Vec<String>,
    total: usize,
}

impl JmapClient {
    /// The first `most` objects of `kind` in Stalwart's order, such as
    /// `Account`, each read as a `T` with `properties`, and how many
    /// Stalwart has: in pages of [`PAGE`], each a request of its own. Before
    /// each page after the first, `more` says whether there is time for it;
    /// where it says no, the objects of the pages before are listed.
    ///
    /// The key needs the `/query` permission of the kind beside its `/get`
    /// one, such as `sysAccountQuery`. An object that comes again in a later
    /// page, as where objects were added meanwhile, is listed once.
    pub fn listed<T: DeserializeOwned>(
        &self,
        kind: &str,
        properties: &[&str],
        most: usize,
        more: impl Fn() -> bool,
    ) -> Result<Listed<T>, Error> {
        let (mut objects, mut seen) = (Vec::new(), BTreeSet::new());
        let (mut total, mut position) = (0, 0);
        while objects.len() < most && (position == 0 || more()) {
            let limit = PAGE.min(most - objects.len());
            let (page, counted) = self.page::<T>(kind, properties, position, limit)?;
            total = counted;
            position += page.len();
            let before = objects.len();
            for (id, object) in page {
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
        })
    }

    /// The objects of `kind` from `position` on, `limit` of them at the
    /// most, each with its ID, in the query's order, and how many there are.
    fn page<T: DeserializeOwned>(
        &self,
        kind: &str,
        properties: &[&str],
        position: usize,
        limit: usize,
    ) -> Result<(Vec<(String, T)>, usize), Error> {
        let (query, get) = (format!("x:{kind}/query"), format!("x:{kind}/get"));
        let calls = [
            (
                query.as_str(),
                json!({"position": position, "limit": limit, "calculateTotal": true}),
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
        let mut found: BTreeMap<String, Object> = got(&get, result, Some(&asked))?
            .into_iter()
            .filter_map(|object| {
                let id = object.get("id")?.as_str()?.to_owned();
                Some((id, object))
            })
            .collect();
        let mut page = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(object) = found.remove(&id) {
                page.push((id, read(&get, object)?));
            }
        }
        Ok((page, total))
    }
}

#[cfg(test)]
mod tests;
