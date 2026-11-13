//! What the host-care checks read out of files and command output: pending
//! updates, kernel releases and the trend of the free disk space.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// Pending updates as a package manager lists them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Pending {
    pub(super) security: u64,
    pub(super) other: u64,
}

/// `apt-get -s upgrade`: one `Inst` line for each package it would install,
/// with the archive it comes from in brackets.
pub(super) fn apt(output: &str) -> Pending {
    let mut pending = Pending::default();
    for line in output.lines().filter(|line| line.starts_with("Inst ")) {
        if line.to_lowercase().contains("security") {
            pending.security += 1;
        } else {
            pending.other += 1;
        }
    }
    pending
}

/// The packages `dnf updateinfo list --security --updates` names, one line
/// for each advisory and package; a package with two advisories counts once.
pub(super) fn dnf_security(output: &str) -> u64 {
    let mut packages: Vec<&str> = output
        .lines()
        .filter_map(|line| {
            let mut columns = line.split_whitespace();
            let (_advisory, _kind, package) = (columns.next()?, columns.next()?, columns.next()?);
            columns.next().is_none().then_some(package)
        })
        .collect();
    packages.sort_unstable();
    packages.dedup();
    packages.len() as u64
}

/// The packages `dnf check-update` lists: name, version and repository in
/// three columns, up to the first empty line (obsoleted packages follow it).
pub(super) fn dnf_updates(output: &str) -> u64 {
    output
        .lines()
        .skip_while(|line| line.trim().is_empty())
        .take_while(|line| !line.trim().is_empty())
        .filter(|line| line.split_whitespace().count() == 3)
        .count() as u64
}

/// Release names in the order of their versions: digits compare as numbers,
/// everything between them as text, so `6.12.0-55.12.1` follows `6.12.0-55.9.1`.
pub(super) fn by_version(left: &str, right: &str) -> Ordering {
    fn parts(text: &str) -> Vec<(bool, &str)> {
        let mut parts = Vec::new();
        let mut start = 0;
        let bytes = text.as_bytes();
        for index in 1..=bytes.len() {
            if index == bytes.len()
                || bytes[index].is_ascii_digit() != bytes[start].is_ascii_digit()
            {
                parts.push((bytes[start].is_ascii_digit(), &text[start..index]));
                start = index;
            }
        }
        parts
    }
    let (left, right) = (parts(left), parts(right));
    for (one, other) in left.iter().zip(&right) {
        let order = match (one, other) {
            ((true, one), (true, other)) => {
                let (one, other) = (one.trim_start_matches('0'), other.trim_start_matches('0'));
                one.len().cmp(&other.len()).then_with(|| one.cmp(other))
            }
            ((_, one), (_, other)) => one.cmp(other),
        };
        if order.is_ne() {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

/// One reading of the free disk space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Sample {
    pub(super) at: i64,
    pub(super) free: u64,
}

/// A reading is kept once an hour, for two weeks.
pub(super) const EVERY: i64 = 3600;
pub(super) const KEPT: i64 = 14 * 86_400;
/// A trend needs readings a day apart.
pub(super) const SPAN: i64 = 86_400;

/// The readings with `now` added where an hour has passed, without those
/// older than two weeks.
pub(super) fn recorded(mut samples: Vec<Sample>, now: Sample) -> Vec<Sample> {
    samples.retain(|sample| (0..=KEPT).contains(&(now.at - sample.at)));
    if samples.last().is_none_or(|last| now.at - last.at >= EVERY) {
        samples.push(now);
    }
    samples
}

/// The change of the free space in bytes a day, by least squares over the
/// readings; `None` while they span less than a day.
#[allow(clippy::cast_precision_loss)]
pub(super) fn trend(samples: &[Sample]) -> Option<f64> {
    let (first, last) = (samples.first()?, samples.last()?);
    if last.at - first.at < SPAN {
        return None;
    }
    let count = samples.len() as f64;
    let time = |sample: &Sample| (sample.at - first.at) as f64;
    let mean_time = samples.iter().map(time).sum::<f64>() / count;
    let mean_free = samples.iter().map(|sample| sample.free as f64).sum::<f64>() / count;
    let (mut above, mut below) = (0.0, 0.0);
    for sample in samples {
        let distance = time(sample) - mean_time;
        above += distance * (sample.free as f64 - mean_free);
        below += distance * distance;
    }
    (below > 0.0).then(|| above / below * 86_400.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apt_counts_what_it_would_install_and_where_it_comes_from() {
        let output = "Reading package lists...\nThe following packages will be upgraded:\n  zlib1g curl\n\
            Inst zlib1g [1:1.3.1-1] (1:1.3.1-1+deb13u1 Debian-Security:13/stable-security [amd64])\n\
            Inst curl [8.14.1-2] (8.14.1-2+deb13u2 Debian:13.2/stable [amd64])\n\
            Inst openssl [3.0.13] (3.0.13-0ubuntu3.9 Ubuntu:24.04/noble-security [amd64])\n\
            Conf zlib1g (1:1.3.1-1+deb13u1 Debian-Security:13/stable-security [amd64])\n";
        assert_eq!(
            apt(output),
            Pending {
                security: 2,
                other: 1
            }
        );
        assert_eq!(
            apt("Reading package lists...\n0 upgraded, 0 newly installed.\n"),
            Pending::default()
        );
    }

    #[test]
    fn dnf_counts_each_package_once() {
        let security = "ALSA-2026:96092 Important/Sec. curl-8.12.1-4.el10_2.8.x86_64\n\
            ALSA-2026:96092 Important/Sec. libcurl-minimal-8.12.1-4.el10_2.8.x86_64\n\
            ALSA-2026:97001 Moderate/Sec.  curl-8.12.1-4.el10_2.8.x86_64\n\
            Last metadata expiration check: 0:10:00 ago.\n";
        assert_eq!(dnf_security(security), 2);
        assert_eq!(dnf_security(""), 0);
        let updates = "\ncurl.x86_64        8.12.1-4.el10_2.8   baseos\n\
            glibc.x86_64       2.39-58.el10_2.4    baseos\n\n\
            Obsoleting Packages\nnew.x86_64  1.0  baseos\n    old.x86_64  0.9  @System\n";
        assert_eq!(dnf_updates(updates), 2);
        assert_eq!(dnf_updates(""), 0);
    }

    #[test]
    fn kernel_releases_order_by_their_numbers() {
        let mut releases = [
            "6.12.0-55.12.1.el10_0.x86_64",
            "6.12.0-55.9.1.el10_0.x86_64",
            "6.12.57+deb13-amd64",
            "6.12.0-124.8.1.el10_1.x86_64",
            "6.9.3",
        ];
        releases.sort_by(|left, right| by_version(left, right));
        assert_eq!(
            releases,
            [
                "6.9.3",
                "6.12.0-55.9.1.el10_0.x86_64",
                "6.12.0-55.12.1.el10_0.x86_64",
                "6.12.0-124.8.1.el10_1.x86_64",
                "6.12.57+deb13-amd64",
            ]
        );
        assert_eq!(by_version("5.14.0-070", "5.14.0-70"), Ordering::Equal);
        assert_eq!(by_version("5.14.0", "5.14.0-1"), Ordering::Less);
    }

    #[test]
    fn readings_are_kept_hourly_for_two_weeks() {
        let hour = |index: i64| Sample {
            at: index * 3600,
            free: 100,
        };
        let mut samples = Vec::new();
        for index in 0..400 {
            samples = recorded(samples, hour(index));
            // Within the hour nothing is added.
            samples = recorded(
                samples,
                Sample {
                    at: index * 3600 + 60,
                    free: 1,
                },
            );
        }
        // The last look came a minute past the hour: the reading of exactly
        // two weeks before that hour is a minute too old.
        assert_eq!(samples.len(), 14 * 24);
        assert_eq!(samples.first().unwrap().at, (399 - 14 * 24 + 1) * 3600);
        assert_eq!(samples.last().unwrap().at, 399 * 3600);
        assert!(samples.iter().all(|sample| sample.free == 100));
    }

    #[test]
    fn the_trend_is_the_change_a_day_once_a_day_is_known() {
        let falling: Vec<Sample> = (0..=48)
            .map(|hour| Sample {
                at: hour * 3600,
                free: 1_000_000 - 1000 * u64::try_from(hour).unwrap(),
            })
            .collect();
        assert_eq!(trend(&falling[..20]), None);
        let a_day = trend(&falling).unwrap();
        assert!((a_day + 24_000.0).abs() < 1.0, "{a_day}");
        let steady = [
            Sample { at: 0, free: 5 },
            Sample {
                at: 90_000,
                free: 5,
            },
        ];
        assert_eq!(trend(&steady), Some(0.0));
        assert_eq!(trend(&[]), None);
    }
}
