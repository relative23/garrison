//! A configuration written out again: the operator's `garrison.toml` with
//! one setting changed, for a release to read with `--config`. Every value
//! is written inline, one key a line, which every TOML reader takes; the
//! comments and the layout of the original are not kept, nor needed.

use std::fmt::Write;

/// A TOML document that reads as `table`.
pub(super) fn document(table: &toml::Table) -> String {
    let mut text = String::new();
    for (key, value) in table {
        let _ = writeln!(text, "{} = {}", string(key), inline(value));
    }
    text
}

fn inline(value: &toml::Value) -> String {
    match value {
        toml::Value::String(text) => string(text),
        toml::Value::Integer(number) => number.to_string(),
        toml::Value::Float(number) => float(*number),
        toml::Value::Boolean(flag) => flag.to_string(),
        toml::Value::Datetime(moment) => moment.to_string(),
        toml::Value::Array(items) => {
            let items: Vec<String> = items.iter().map(inline).collect();
            format!("[{}]", items.join(", "))
        }
        toml::Value::Table(table) => {
            let pairs: Vec<String> = table
                .iter()
                .map(|(key, value)| format!("{} = {}", string(key), inline(value)))
                .collect();
            format!("{{{}}}", pairs.join(", "))
        }
    }
}

/// A float with its point or exponent, so that it stays one, and the
/// special values by TOML's names.
fn float(number: f64) -> String {
    if number.is_nan() {
        "nan".to_owned()
    } else if number.is_infinite() {
        if number > 0.0 { "inf" } else { "-inf" }.to_owned()
    } else {
        format!("{number:?}")
    }
}

/// A basic string: quotes, backslashes and control characters escaped.
fn string(text: &str) -> String {
    let mut quoted = String::from("\"");
    for character in text.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            control if control.is_control() => {
                let _ = write!(quoted, "\\u{:04X}", u32::from(control));
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn again(text: &str) -> (toml::Table, toml::Table) {
        let table: toml::Table = text.parse().unwrap();
        let written = document(&table);
        let read: toml::Table = written
            .parse()
            .unwrap_or_else(|error| panic!("{error}\n{written}"));
        (table, read)
    }

    #[test]
    fn a_configuration_reads_the_same_once_written_out() {
        let example = include_str!("../../../../deploy/config/garrison.example.toml");
        let (table, read) = again(example);
        assert_eq!(read, table);
        let directory = tempfile::tempdir().unwrap();
        let (table, read) = again(&garrison_testing::config_text(
            directory.path(),
            "http://127.0.0.1:9",
        ));
        assert_eq!(read, table);
        // And it loads as the configuration it was.
        assert_eq!(
            garrison_core::config::from_text(&document(&table)).unwrap(),
            garrison_core::config::from_text(&garrison_testing::config_text(
                directory.path(),
                "http://127.0.0.1:9"
            ))
            .unwrap()
        );
    }

    #[test]
    fn every_kind_of_value_and_name_reads_the_same() {
        let text = r#"
"quoted key" = "a \"quote\", a \\ backslash, a tab\t, a line\n, a bell\u0007, a DEL\u007F, é ✓"
"" = ""
"a.b" = { "c d" = [1, -2, 0x10], e = { f = [] } }
float = [1.0, -0.0, 1e100, 1.5e-7, inf, -inf, 3.0e16]
flags = [true, false]
times = [1979-05-27T07:32:00Z, 1979-05-27T00:32:00.999999-07:00, 1979-05-27T07:32:00, 1979-05-27, 07:32:00]
mixed = [1, "two", [3.0], { four = 4 }]
empty = {}
[[providers]]
type = "host"
[[providers]]
type = "reputation"
lists = ["zen.dq.spamhaus.net"]
[nested.deeper]
value = 1
"#;
        let (table, read) = again(text);
        assert_eq!(read, table);
        // NaN is no value equal to itself; it stays NaN.
        let (_, read) = again("x = nan\n");
        assert!(read["x"].as_float().unwrap().is_nan());
    }

    #[test]
    fn random_strings_read_the_same_once_written_out() {
        let mut noise = garrison_testing::noise::Noise::new(71);
        for _ in 0..5_000 {
            let text = noise.text("ab\"\\\n\t\r\u{0}\u{1f}\u{7f}\u{80}\u{9f}é✓ .=[]{}#'", 24);
            let mut table = toml::Table::new();
            table.insert(text.clone(), toml::Value::String(text.clone()));
            let written = document(&table);
            let read: toml::Table = written
                .parse()
                .unwrap_or_else(|error| panic!("{error}\n{written:?}"));
            assert_eq!(read, table, "{written:?}");
        }
    }
}
