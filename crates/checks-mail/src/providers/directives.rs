//! `Key value` configuration files such as clamd.conf.
//!
//! Each line is split into words like a POSIX shell does, with comments: quotes
//! group words, a backslash escapes outside single quotes and `#` starts a
//! comment outside quotes. `ClamAV` takes the first of the lines that set one
//! directive (clamconf 1.4.3 and 1.4.6, for clamav-milter.conf and clamd.conf),
//! but every line of one it takes several of, such as `ClamdSocket`: [`values`]
//! gives every value in the file's order, and [`directives`], for what needs a
//! value nobody could doubt, none for a directive set twice.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

const MAX_FILE: usize = 65536;

/// Every directive of a file with its values in the order of the file, or why
/// the file cannot be read or split, in words for a finding.
pub fn values(path: &Path) -> Result<BTreeMap<String, Vec<String>>, String> {
    // A named pipe would hold the open until a writer came. Only root writes
    // ClamAV's files, so a look before the open is enough here.
    if !std::fs::metadata(path)
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("not a regular file".to_owned());
    }
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut data = Vec::new();
    file.take(MAX_FILE as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() > MAX_FILE {
        return Err(format!("it is larger than {} KiB", MAX_FILE / 1024));
    }
    let text = String::from_utf8(data).map_err(|_| "it is not UTF-8 text".to_owned())?;
    let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let words = split(line).ok_or_else(|| {
            format!(
                "line {} opens a quote it does not close, or ends in a backslash",
                number + 1
            )
        })?;
        let Some((key, rest)) = words.split_first() else {
            continue;
        };
        result.entry(key.clone()).or_default().push(rest.join(" "));
    }
    Ok(result)
}

/// The directives of a file, or `None` if it cannot be read or split.
/// A directive that appears twice maps to `None`.
pub fn directives(path: &Path) -> Option<BTreeMap<String, Option<String>>> {
    let values = values(path).ok()?;
    Some(
        values
            .into_iter()
            .map(|(key, values)| {
                let value = match <[String; 1]>::try_from(values) {
                    Ok([value]) => Some(value),
                    Err(_) => None,
                };
                (key, value)
            })
            .collect(),
    )
}

/// POSIX shell-like word splitting with comments; `None` for an unclosed quote
/// or a trailing escape.
fn split(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(next) = chars.next() {
        match next {
            ' ' | '\t' | '\r' | '\n' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '#' => break,
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        other => word.push(other),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => match chars.next()? {
                            escaped @ ('"' | '\\') => word.push(escaped),
                            other => {
                                word.push('\\');
                                word.push(other);
                            }
                        },
                        other => word.push(other),
                    }
                }
            }
            '\\' => {
                in_word = true;
                word.push(chars.next()?);
            }
            other => {
                in_word = true;
                word.push(other);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Option<Vec<String>> {
        split(line)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn some(expected: &[&str]) -> Option<Vec<String>> {
        Some(expected.iter().map(ToString::to_string).collect())
    }

    #[test]
    fn lines_split_into_shell_words() {
        assert_eq!(words("OnInfected Reject"), some(&["OnInfected", "Reject"]));
        assert_eq!(words("  # a comment"), some(&[]));
        assert_eq!(words("Key value # trailing"), some(&["Key", "value"]));
        assert_eq!(words("Key va#lue"), some(&["Key", "va"]));
        assert_eq!(
            words("Key 'a b' \"c\\\"d\" e\\ f"),
            some(&["Key", "a b", "c\"d", "e f"])
        );
        assert_eq!(words("Key \"a\\nb\" ''"), some(&["Key", "a\\nb", ""]));
        assert_eq!(words("Key 'unclosed"), None);
        assert_eq!(words("Key trailing\\"), None);
        assert_eq!(words("Key 'a'\"b\"c"), some(&["Key", "abc"]));
    }

    #[test]
    fn random_lines_split_without_panics_and_quoted_words_come_back() {
        let mut noise = garrison_testing::noise::Noise::new(37);
        for _ in 0..20_000 {
            let _ = words(&noise.text("ab #'\"\\\t€", 24));
            let expected: Vec<String> = (0..noise.below(4))
                .map(|_| noise.text("ab #\"\\\t€", 6))
                .collect();
            let line = expected
                .iter()
                .map(|word| format!("'{word}'"))
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(words(&line), Some(expected), "{line}");
        }
    }

    #[test]
    fn files_up_to_64_kib_are_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scan.conf");
        let mut text = "Key value\n".to_owned();
        text.push_str(&"#".repeat(MAX_FILE - text.len()));
        std::fs::write(&path, &text).unwrap();
        assert_eq!(directives(&path).unwrap()["Key"].as_deref(), Some("value"));
        text.push('#');
        std::fs::write(&path, &text).unwrap();
        assert_eq!(directives(&path), None);
    }

    #[test]
    fn repeated_directives_have_no_value() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("milter.conf");
        std::fs::write(
            &path,
            "OnInfected Reject\nOnFail Defer\nOnFail Accept\n# x\n\nMaxFileSize 25M\n",
        )
        .unwrap();
        let parsed = directives(&path).unwrap();
        assert_eq!(parsed["OnInfected"].as_deref(), Some("Reject"));
        assert_eq!(parsed["OnFail"], None);
        assert_eq!(parsed["MaxFileSize"].as_deref(), Some("25M"));
        assert_eq!(directives(&directory.path().join("missing")), None);
        std::fs::write(&path, "Key 'open\n").unwrap();
        assert_eq!(directives(&path), None);
    }
}
