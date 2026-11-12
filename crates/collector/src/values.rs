//! How providers compare, show and round values from JSON documents.
//!
//! Configuration values (TOML) are compared with documents (JSON) by value, so
//! `1`, `1.0` and `true` written in either place match. Values shown to
//! operators use JSON spelling.

use serde_json::{Number, Value};

/// A JSON value as text for operators: strings without quotes, the rest as JSON.
pub(crate) fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

/// Equality by value: numbers compare numerically, `true` and `false` count as
/// 1 and 0, arrays and objects compare element by element.
pub(crate) fn loosely_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| loosely_equal(l, r))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right
                        .get(key)
                        .is_some_and(|other| loosely_equal(value, other))
                })
        }
        // Exact equality: both sides come from the same kind of document.
        #[allow(clippy::float_cmp)]
        _ => match (numeric(left), numeric(right)) {
            (Some(left), Some(right)) => left == right,
            _ => left == right,
        },
    }
}

fn numeric(value: &Value) -> Option<f64> {
    match value {
        Value::Bool(flag) => Some(f64::from(u8::from(*flag))),
        Value::Number(number) => number.as_f64(),
        _ => None,
    }
}

/// Rounded to one decimal: the nearest representable value to the correctly
/// rounded decimal, ties to even (0.25 becomes 0.2).
pub(crate) fn round_one(value: f64) -> f64 {
    format!("{value:.1}").parse().unwrap_or(value)
}

/// A float for JSON; non-finite values become `null`, as JSON has no NaN.
pub(crate) fn float(value: f64) -> Value {
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

/// A TOML value from the configuration as JSON, for comparisons with documents.
pub(crate) fn from_toml(value: &toml::Value) -> Value {
    match value {
        toml::Value::String(text) => Value::String(text.clone()),
        toml::Value::Integer(number) => Value::from(*number),
        toml::Value::Float(number) => float(*number),
        toml::Value::Boolean(flag) => Value::Bool(*flag),
        toml::Value::Datetime(moment) => Value::String(moment.to_string()),
        toml::Value::Array(items) => Value::Array(items.iter().map(from_toml).collect()),
        toml::Value::Table(table) => Value::Object(
            table
                .iter()
                .map(|(key, value)| (key.clone(), from_toml(value)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn equality_is_by_value() {
        assert!(loosely_equal(&json!(1), &json!(1.0)));
        assert!(loosely_equal(&json!(true), &json!(1)));
        assert!(!loosely_equal(&json!(true), &json!("true")));
        assert!(loosely_equal(&json!([1, "a"]), &json!([1.0, "a"])));
        assert!(!loosely_equal(&json!(null), &json!(0)));
        assert!(!loosely_equal(&json!([1]), &json!([1, 2])));
        assert!(loosely_equal(&json!({"a": 1}), &json!({"a": 1.0})));
        assert!(!loosely_equal(&json!({"a": 1}), &json!({"a": 1, "b": 2})));
        assert!(!loosely_equal(&json!({"a": 1}), &json!({"b": 1})));
        assert!(!loosely_equal(&json!({"a": 1}), &json!({"a": 2})));
    }

    #[test]
    fn rounding_and_text() {
        // 0.25 and 0.35 are slightly below their decimal value as doubles.
        assert_eq!(round_one(0.25), 0.2);
        assert_eq!(round_one(0.35), 0.3);
        assert_eq!(round_one(94.96), 95.0);
        assert_eq!(round_one(19.0 / 20.0 * 100.0), 95.0);
        assert_eq!(text(&json!(null)), "null");
        assert_eq!(text(&json!(7357)), "7357");
        assert_eq!(text(&json!(false)), "false");
        assert_eq!(text(&json!("plain")), "plain");
    }
}
