//! Semantic-version precedence: `upgrade` only moves forward, and the
//! collector says when a newer release exists.

use std::cmp::Ordering;

#[derive(Debug, PartialEq, Eq)]
enum Identifier {
    Number(u64),
    Text(String),
}

impl Identifier {
    /// Numbers compare as numbers and before any text, as Semantic Versioning 2.0 says.
    fn compare(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Number(left), Self::Number(right)) => left.cmp(right),
            (Self::Number(_), Self::Text(_)) => Ordering::Less,
            (Self::Text(_), Self::Number(_)) => Ordering::Greater,
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
        }
    }
}

/// `MAJOR.MINOR.PATCH[-PRE][+BUILD]`; the build part never counts.
fn parse(text: &str) -> Option<([u64; 3], Vec<Identifier>)> {
    let text = text.split_once('+').map_or(text, |(version, _)| version);
    let (core, pre) = text
        .split_once('-')
        .map_or((text, None), |(core, pre)| (core, Some(pre)));
    let mut numbers = [0; 3];
    let mut parts = core.split('.');
    for number in &mut numbers {
        *number = number_of(parts.next()?)?;
    }
    if parts.next().is_some() {
        return None;
    }
    let mut identifiers = Vec::new();
    for part in pre.map(|pre| pre.split('.')).into_iter().flatten() {
        let allowed = |character: char| character.is_ascii_alphanumeric() || character == '-';
        if part.is_empty() || !part.chars().all(allowed) {
            return None;
        }
        identifiers.push(
            if part.chars().all(|character| character.is_ascii_digit()) {
                Identifier::Number(number_of(part)?)
            } else {
                Identifier::Text(part.to_owned())
            },
        );
    }
    Some((numbers, identifiers))
}

/// A number without a leading zero, as Semantic Versioning requires.
fn number_of(text: &str) -> Option<u64> {
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

/// Whether `candidate` takes precedence over `running`; `None` when either is
/// no semantic version.
#[must_use]
pub fn newer(candidate: &str, running: &str) -> Option<bool> {
    let (candidate, running) = (parse(candidate)?, parse(running)?);
    let order = candidate.0.cmp(&running.0).then_with(|| {
        match (candidate.1.is_empty(), running.1.is_empty()) {
            // A release takes precedence over its pre-releases.
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => candidate
                .1
                .iter()
                .zip(&running.1)
                .map(|(left, right)| left.compare(right))
                .find(|order| order.is_ne())
                .unwrap_or_else(|| candidate.1.len().cmp(&running.1.len())),
        }
    });
    Some(order.is_gt())
}

/// Whether `version` is a pre-release, such as `1.0.0-rc.1`; `None` when it is
/// no semantic version.
#[must_use]
pub fn prerelease(version: &str) -> Option<bool> {
    parse(version).map(|(_, identifiers)| !identifiers.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_follows_semver() {
        // The order from the SemVer 2.0 specification, item 11.
        let order = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ];
        for pair in order.windows(2) {
            assert_eq!(newer(pair[1], pair[0]), Some(true), "{pair:?}");
            assert_eq!(newer(pair[0], pair[1]), Some(false), "{pair:?}");
        }
        assert_eq!(newer("0.1.0-dev.2", "0.1.0-dev"), Some(true));
        assert_eq!(newer("0.1.0", "0.1.0-dev+1a2b3c4"), Some(true));
        // Hyphens belong to the pre-release identifiers.
        assert_eq!(newer("1.0.0-rc-2", "1.0.0-rc-1"), Some(true));
    }

    #[test]
    fn a_pre_release_is_told_from_a_release() {
        assert_eq!(prerelease("0.1.0-dev"), Some(true));
        assert_eq!(prerelease("0.1.0-dev+1a2b3c4"), Some(true));
        assert_eq!(prerelease("1.1.0"), Some(false));
        assert_eq!(prerelease("1.1.0+build-7"), Some(false));
        assert_eq!(prerelease("nightly"), None);
    }

    #[test]
    fn build_metadata_does_not_count() {
        assert_eq!(newer("0.1.0-dev+5d6e7f8", "0.1.0-dev+1a2b3c4"), Some(false));
        assert_eq!(newer("1.0.0+2", "1.0.0+1"), Some(false));
    }

    #[test]
    fn random_versions_compare_without_panics_and_one_way_only() {
        // The same texts on every run: a xorshift generator from a fixed seed.
        let mut state: u64 = 11;
        let mut text = || -> String {
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                usize::try_from(state % 15).unwrap()
            };
            let length = next();
            (0..length)
                .map(|_| char::from(b"0123456789.-+ab"[next()]))
                .collect()
        };
        for _ in 0..20_000 {
            let (left, right) = (text(), text());
            if newer(&left, &right) == Some(true) {
                assert_eq!(newer(&right, &left), Some(false), "{left} {right}");
            }
        }
    }

    #[test]
    fn anything_else_is_no_version() {
        for text in [
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.0.0-",
            "1.0.0-a..b",
            "1.0.0-ä",
            "v1.0.0",
            "",
        ] {
            assert_eq!(newer(text, "1.0.0"), None, "{text}");
        }
    }
}
