//! Bounded, strict JSON parsing.
//!
//! Every component that reads JSON from a file, a socket or another process uses
//! these functions, so size limits and duplicate-key rejection apply the same way
//! everywhere. Two values for one key could otherwise be read differently by two
//! readers; NaN and Infinity are not JSON and are rejected by the parser. So
//! are the keys `serde_json` keeps for itself, which it would read as
//! something else than an object's key.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// `serde_json` passes raw values and long numbers to its own types as an
/// object with one key of this kind. Where those features are compiled in (the
/// web framework turns raw values on), it reads such an object in a document
/// the same way: `{"$serde_json::private::RawValue": "[1]"}` becomes `[1]`,
/// also when a parsed value is read as a type later. A document with such a
/// key would be one thing to this parser and another to the next reader.
const RESERVED: &str = "$serde_json::private::";

#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    #[error("JSON document exceeds its size limit")]
    TooLarge,
    #[error("invalid JSON: {0}")]
    Invalid(#[from] serde_json::Error),
}

/// Parse a JSON document of at most `limit` bytes, rejecting duplicate keys.
pub fn parse(data: &[u8], limit: usize) -> Result<Value, JsonError> {
    if data.len() > limit {
        return Err(JsonError::TooLarge);
    }
    let Strict(value) = serde_json::from_slice(data)?;
    Ok(value)
}

/// Whether a JSON value is set: not `null`, `false`, `0`, `""`, `[]` or `{}`.
pub fn is_set(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Read a JSON object as a `T`, or say why it is none.
///
/// serde's derived types also read a list of their fields' values in order,
/// and an internally tagged enum a list that starts with its tag. No document
/// of Garrison or Stalwart is written that way, so only an object is read.
pub fn object<T: de::DeserializeOwned>(value: Value) -> Result<T, String> {
    if !value.is_object() {
        return Err("not a JSON object".to_owned());
    }
    serde_json::from_value(value).map_err(|error| error.to_string())
}

/// Whether an object holds exactly these keys: none missing and no other,
/// so nothing is read that the reader does not know.
pub fn has_exactly(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

/// A JSON value whose objects were checked for duplicate keys while parsing.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("unsupported JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(item)) = sequence.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            if key.starts_with(RESERVED) {
                return Err(de::Error::custom("reserved JSON key"));
            }
            let Strict(item) = map.next_value()?;
            object.insert(key, item);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_nested_documents_in_key_order() {
        let document = r#"{"b": [1, -2, 2.5, true, null], "a": {"x": "é"}}"#;
        let value = parse(document.as_bytes(), 1024).unwrap();
        assert_eq!(
            value,
            json!({"b": [1, -2, 2.5, true, null], "a": {"x": "é"}})
        );
        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["b", "a"]);
    }

    #[test]
    fn empty_and_zero_values_are_not_set() {
        for unset in [
            json!(null),
            json!(false),
            json!(0),
            json!(0.0),
            json!(""),
            json!([]),
            json!({}),
        ] {
            assert!(!is_set(&unset), "{unset}");
        }
        for set in [
            json!(true),
            json!(1),
            json!(-0.5),
            json!("x"),
            json!([0]),
            json!({"a": null}),
        ] {
            assert!(is_set(&set), "{set}");
        }
    }

    #[test]
    fn exactly_the_named_keys_means_none_missing_and_no_other() {
        let object = json!({"a": 1, "b": null});
        let object = object.as_object().unwrap();
        assert!(has_exactly(object, &["a", "b"]));
        assert!(has_exactly(object, &["b", "a"]));
        assert!(!has_exactly(object, &["a"]));
        assert!(!has_exactly(object, &["a", "b", "c"]));
        assert!(!has_exactly(object, &["a", "c"]));
        assert!(has_exactly(&Map::new(), &[]));
    }

    #[test]
    fn only_an_object_is_read_as_a_type() {
        #[derive(Debug, PartialEq, Deserialize)]
        struct Pair {
            name: String,
            count: u8,
        }
        #[derive(Debug, PartialEq, Deserialize)]
        #[serde(tag = "kind")]
        enum Shape {
            Square { side: u8 },
        }
        let pair = Pair {
            name: "a".to_owned(),
            count: 2,
        };
        assert_eq!(object(json!({"name": "a", "count": 2})), Ok(pair));
        assert_eq!(
            object(json!({"kind": "Square", "side": 3})),
            Ok(Shape::Square { side: 3 })
        );
        // serde alone reads both of these lists.
        assert!(serde_json::from_value::<Pair>(json!(["a", 2])).is_ok());
        assert!(serde_json::from_value::<Shape>(json!(["Square", 3])).is_ok());
        let none = "not a JSON object";
        assert_eq!(object::<Pair>(json!(["a", 2])).unwrap_err(), none);
        assert_eq!(object::<Shape>(json!(["Square", 3])).unwrap_err(), none);
        assert_eq!(object::<Pair>(json!(null)).unwrap_err(), none);
        assert_eq!(
            object::<Pair>(json!({"name": "a"})),
            Err("missing field `count`".to_owned())
        );
    }

    /// Found by the fuzz target `json`: the faster number parsing of `serde_json`
    /// read both of these one unit in the last place off, so a stored value
    /// was another value when it was read again.
    #[test]
    fn a_number_is_read_as_the_nearest_double_and_survives_being_written() {
        let long = b"999999999999999999999999999989999999989999999999";
        assert_eq!(parse(long, 64).unwrap(), json!(1e48));
        let below = 9.999_999_999_999_999e47_f64;
        assert!(below < 1e48);
        for value in [
            below,
            1e48,
            0.1 + 0.2,
            12.333_333_333_333_334,
            5e-324,
            f64::MAX,
        ] {
            let written = serde_json::to_vec(&json!(value)).unwrap();
            assert_eq!(parse(&written, 64).unwrap(), json!(value), "{value:e}");
        }
    }

    /// Found by the fuzz target `json`, in a build with the web framework.
    #[test]
    fn rejects_the_keys_serde_json_reads_as_something_else() {
        for document in [
            r#"{"$serde_json::private::RawValue": "[1, 2]"}"#,
            r#"{"a": [{"b": 1, "$serde_json::private::RawValue": {}}]}"#,
            r#"{"$serde_json::private::Number": "1e999"}"#,
        ] {
            let error = parse(document.as_bytes(), 1024).unwrap_err().to_string();
            assert!(error.contains("reserved JSON key"), "{document}: {error}");
        }
        // As text, the same words are a text like any other.
        let quoted = r#"{"a": "$serde_json::private::RawValue"}"#;
        assert!(parse(quoted.as_bytes(), 1024).is_ok());
    }

    #[test]
    fn rejects_duplicate_keys_at_any_depth() {
        for document in [r#"{"a": 1, "a": 2}"#, r#"[{"x": {"a": 1, "a": 1}}]"#] {
            let error = parse(document.as_bytes(), 1024).unwrap_err();
            assert!(error.to_string().contains("duplicate JSON key"), "{error}");
        }
    }

    #[test]
    fn rejects_oversized_and_non_json_input() {
        assert!(matches!(parse(b"[1, 2, 3]", 8), Err(JsonError::TooLarge)));
        assert_eq!(parse(b"[1, 2, 3]", 9).unwrap(), json!([1, 2, 3]));
        for document in [
            "NaN",
            "[Infinity]",
            "{\"a\": 1} x",
            "\u{feff}{}",
            "{'a': 1}",
            "",
        ] {
            assert!(parse(document.as_bytes(), 1024).is_err(), "{document:?}");
        }
        assert!(parse(b"[\xff]", 1024).is_err());
    }
}
