//! The DNS names the options give, mail hosts and the lists' zones, each
//! refused where DNS could never ask it as the check asks it.

use super::shown;
use crate::options::{Checked, fail};

/// What a question puts before a name of an option: a mail host's name is
/// asked as it is, a list's zone with the reversed address before it.
#[derive(Clone, Copy)]
pub(super) enum Before {
    Nothing,
    Ipv4,
    Ipv6,
}

impl Before {
    /// The octets of the longest such address with its dot: `255.255.255.255.`,
    /// or the 32 digits of an IPv6 address, each with a dot.
    fn octets(self) -> usize {
        match self {
            Before::Nothing => 0,
            Before::Ipv4 => 16,
            Before::Ipv6 => 64,
        }
    }

    fn says(self) -> &'static str {
        match self {
            Before::Nothing => "it has",
            Before::Ipv4 => {
                "with an IPv4 address before it, as the list is asked, a question has up to"
            }
            Before::Ipv6 => "with an IPv6 address before it, as the list is asked, a question has",
        }
    }
}

/// Why DNS can never ask `name` as the check asks it: no label may be longer
/// than 63 octets, nor the name than 253. The refusal names the entry of
/// `key`, without the key a zone may hold.
pub(super) fn askable(key: &str, name: &str, before: Before) -> Checked<()> {
    let cannot = |why: String, most: usize| {
        fail(format!(
            "providers[reputation].{key} names {}, which DNS cannot ask: {why}, and DNS takes \
             {most} at the most",
            shown(name)
        ))
    };
    if let Some(label) = name.split('.').map(str::len).find(|octets| *octets > 63) {
        return cannot(format!("it has a label of {label} octets"), 63);
    }
    let asked = name.len() + before.octets();
    if asked > 253 {
        return cannot(format!("{} {asked} octets", before.says()), 253);
    }
    Ok(())
}

/// A list of DNS names from an option; `default` where it is absent. Each is
/// asked with `before` before it.
pub(super) fn names(
    raw: &toml::Table,
    key: &str,
    default: &[&str],
    before: Before,
) -> Checked<Vec<String>> {
    let wrong = || {
        fail(format!(
            "providers[reputation].{key} must be a list of DNS names"
        ))
    };
    match raw.get(key) {
        None => Ok(default.iter().map(ToString::to_string).collect()),
        Some(toml::Value::Array(items)) => {
            let mut names = Vec::new();
            for item in items {
                let name = item
                    .as_str()
                    .unwrap_or_default()
                    .trim_end_matches('.')
                    .to_lowercase();
                let plain = |label: &str| {
                    !label.is_empty()
                        && label
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '-')
                };
                if !name.contains('.') || !name.split('.').all(plain) || names.contains(&name) {
                    return wrong();
                }
                askable(key, &name, before)?;
                names.push(name);
            }
            Ok(names)
        }
        Some(_) => wrong(),
    }
}
