//! What the collector asks Stalwart and what it reads of the answers.
//!
//! Stalwart owns these documents. A field of another shape than the one read
//! here is unknown, never an error: one setting written as an expression must
//! not blank the whole observation. So every field reads whatever is there
//! and keeps it only if it is what the observation shows.

use garrison_core::json;
use garrison_stalwart::jmap::{Get, Object};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};

use crate::values::text;

/// The arguments of one call.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Arguments {
    Get(Get<'static>),
    Query(Query),
}

/// A `/query` that only counts: the total, and one ID that is not read.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Query {
    calculate_total: bool,
    limit: u32,
}

impl Arguments {
    pub(super) const COUNT: Arguments = Arguments::Query(Query {
        calculate_total: true,
        limit: 1,
    });

    pub(super) const fn get(
        ids: Option<&'static [&'static str]>,
        properties: Option<&'static [&'static str]>,
    ) -> Arguments {
        Arguments::Get(Get { ids, properties })
    }
}

/// A plain number below 10^12, as Stalwart wrote it; a boolean, a larger
/// value or anything else is no number.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plain(pub Option<Number>);

impl Plain {
    pub fn of(value: &Value) -> Plain {
        Plain(match value {
            Value::Number(number) if number.as_f64().is_some_and(|size| size.abs() < 1e12) => {
                Some(number.clone())
            }
            _ => None,
        })
    }

    pub fn float(&self) -> Option<f64> {
        self.0.as_ref().and_then(Number::as_f64)
    }

    /// The number as it was written, for a field or a table cell.
    pub fn value(&self) -> Option<Value> {
        self.0.clone().map(Value::Number)
    }
}

impl<'de> Deserialize<'de> for Plain {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Plain::of(&Value::deserialize(deserializer)?))
    }
}

/// A fixed boolean, also as an expression without conditions:
/// `{"match": {}, "else": "true"}`. An expression that depends on something
/// has no fixed value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fixed(pub Option<bool>);

impl Fixed {
    pub fn of(value: &Value) -> Fixed {
        Fixed(match value {
            Value::Bool(flag) => Some(*flag),
            Value::Object(map)
                if map
                    .get("match")
                    .is_some_and(|rules| *rules == Value::Object(Object::new())) =>
            {
                match map.get("else").and_then(Value::as_str) {
                    Some("true") => Some(true),
                    Some("false") => Some(false),
                    _ => None,
                }
            }
            _ => None,
        })
    }
}

impl<'de> Deserialize<'de> for Fixed {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Fixed::of(&Value::deserialize(deserializer)?))
    }
}

/// Any value as it was written, or nothing for `null`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Written(pub Option<Value>);

impl Written {
    /// The value as text for operators; `null` when there is none.
    pub fn text(&self) -> String {
        text(self.0.as_ref().unwrap_or(&Value::Null))
    }
}

impl<'de> Deserialize<'de> for Written {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(Written((!value.is_null()).then_some(value)))
    }
}

/// An object read as a `T`, or `T`'s default when there is something else in
/// its place.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Tolerant<T>(pub T);

impl<'de, T: DeserializeOwned + Default> Deserialize<'de> for Tolerant<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Ok(Tolerant(json::object(value).unwrap_or_default()))
    }
}

/// `x:SpamSettings`, as far as it is shown.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SpamSettings {
    pub enable: Fixed,
    pub score_spam: Plain,
    pub score_reject: Plain,
    pub score_discard: Plain,
}

/// `x:SpamClassifier`, as far as it is shown.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SpamClassifier {
    pub model: Tolerant<Model>,
    /// In milliseconds.
    pub train_interval: Plain,
    pub min_ham_samples: Plain,
    pub min_spam_samples: Plain,
}

/// The classifier's model: a variant object, of which the name is shown.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Model {
    #[serde(rename = "@type")]
    pub kind: Written,
}

/// A row of `x:MtaMilter`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Milter {
    pub host: Written,
    pub port: Written,
    pub enable: Fixed,
    pub stages: Tolerant<Stages>,
    pub temp_fail_on_error: Fixed,
}

/// The SMTP stages a milter is asked at.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Stages {
    pub data: Fixed,
}

/// A row of `x:Account`: what the mailbox table shows of a user.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MailboxAccount {
    #[serde(rename = "@type")]
    pub kind: Written,
    /// As written, `null` included; `None` only where the key is missing.
    #[serde(deserialize_with = "present")]
    pub email_address: Option<Value>,
    pub quotas: Tolerant<Quotas>,
    pub used_disk_quota: Plain,
}

fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Quotas {
    pub max_disk_quota: Plain,
}

/// The total of a `/query` answer.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default)]
struct Counted {
    total: Option<u64>,
}

/// The rows of a `/get` answer, whatever they are.
#[derive(Debug, Deserialize)]
struct Listed {
    list: Vec<Value>,
}

/// The rows of a `/get` answer that are objects, each read as a `T`; `None`
/// when the method did not answer or answered without a list.
pub fn rows<T: DeserializeOwned + Default>(answer: Option<Object>) -> Option<Vec<T>> {
    let listed: Listed = json::object(Value::Object(answer?)).ok()?;
    let objects = listed.list.into_iter().filter(Value::is_object);
    Some(
        objects
            .map(|row| json::object(row).unwrap_or_default())
            .collect(),
    )
}

/// The one object of a `/get` answer for a singleton. An answer with another
/// number of rows, or with an empty object, says nothing.
pub fn only<T: DeserializeOwned>(answer: Option<Object>) -> Option<T> {
    let listed: Listed = json::object(Value::Object(answer?)).ok()?;
    let [row] = <[Value; 1]>::try_from(listed.list).ok()?;
    match &row {
        Value::Object(fields) if !fields.is_empty() => json::object(row).ok(),
        _ => None,
    }
}

/// How many objects a `/query` counted.
pub fn total(answer: Option<Object>) -> Option<u64> {
    let counted: Counted = json::object(Value::Object(answer?)).ok()?;
    counted.total
}
