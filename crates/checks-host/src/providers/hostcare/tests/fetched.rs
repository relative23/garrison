//! The age of the metadata the pending updates are counted from, by the
//! files that apt and dnf leave, as measured in containers of Debian 13 and
//! `AlmaLinux` 10 (2026-11-24): apt writes in `lists/partial` and dnf
//! rewrites `expired_repos.json` each time they fetch, or try to, while
//! apt's lists keep the servers' times and Debian signs its security suite
//! for a week (`Valid-Until`).

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::*;

const DAY: i64 = 86_400;

/// Gives a folder or a file the modification time `at` seconds after the
/// tests' clock.
fn dated(path: &Path, at: i64) {
    let seconds = u64::try_from(now().as_second() + at).unwrap();
    fs::File::open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
        .unwrap();
}

/// A host with apt-get, a package list, and the folder it fetches lists
/// into last written `tried` seconds after the tests' clock.
fn apt_host(root: &Path, tried: i64) {
    host(
        root,
        &[
            ("usr/bin/apt-get", ""),
            (
                "var/lib/apt/lists/deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages",
                "",
            ),
        ],
    );
    fs::create_dir_all(root.join("var/lib/apt/lists/partial")).unwrap();
    dated(&root.join("var/lib/apt/lists/partial"), tried);
}

/// The updates card of a host below `root` whose package manager lists no
/// update.
fn card(root: &Path) -> Observation {
    let nothing = Programs::new(vec![
        ("apt-get -s -o Debug::NoLocking=true dist-upgrade", 0, ""),
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp updateinfo",
            0,
            "",
        ),
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp check-update",
            0,
            "",
        ),
    ]);
    checked(
        &provider(root, "\"updates\""),
        &nothing,
        &Remembered::default(),
        0,
    )
}

/// Lists that apt has not fetched, nor tried to, for a week, as where the
/// host's update job stopped, count no update published since: a warning,
/// which names what fetches them. Six days are in order.
#[test]
fn lists_that_apt_has_not_fetched_for_a_week_are_a_warning() {
    let root = tempfile::tempdir().unwrap();
    apt_host(root.path(), -8 * DAY);
    let stale = card(root.path());
    assert_eq!(
        (stale.state, stale.findings),
        (
            State::Warning,
            vec![
                "apt has not fetched its package lists for 8 days, so updates published since \
                 are not counted: `apt-get update` fetches them, as the host's update job does."
                    .to_owned()
            ]
        )
    );
    apt_host(root.path(), -6 * DAY);
    assert_eq!(card(root.path()).state, State::Ok);
}

/// A list whose `Valid-Until` has passed is one apt could not fetch again,
/// however often it tried: a warning that names it. A list that is still
/// valid, or that carries no such date, is in order.
#[test]
fn a_list_of_apt_whose_time_has_passed_is_a_warning() {
    let root = tempfile::tempdir().unwrap();
    apt_host(root.path(), -3600);
    let release = root
        .path()
        .join("var/lib/apt/lists/deb.debian.org_debian-security_dists_trixie-security_InRelease");
    let signed = |valid: &str| {
        format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Debian\nLabel: \
             Debian-Security\nSuite: stable-security\nDate: Thu, 15 Oct 2026 00:34:34 UTC\n{valid}\
             Architectures: amd64\n"
        )
    };
    fs::write(
        &release,
        signed("Valid-Until: Thu, 22 Oct 2026 00:34:34 UTC\n"),
    )
    .unwrap();
    let expired = card(root.path());
    assert_eq!(
        (expired.state, expired.findings),
        (
            State::Warning,
            vec![
                "apt's list deb.debian.org_debian-security_dists_trixie-security_InRelease \
                 expired on Thu, 22 Oct 2026 00:34:34 UTC, so updates published since are not \
                 counted: `apt-get update` says why apt could not fetch it again."
                    .to_owned()
            ]
        )
    );
    for valid in ["Valid-Until: Sun, 01 Nov 2026 00:34:34 UTC\n", ""] {
        fs::write(&release, signed(valid)).unwrap();
        assert_eq!(card(root.path()).state, State::Ok, "{valid}");
    }
}

/// Metadata that dnf has not refreshed, nor tried to, for a week, as where
/// its timer is off, counts no update published since: a warning, which
/// names what refreshes it.
#[test]
fn metadata_that_dnf_has_not_refreshed_for_a_week_are_a_warning() {
    let root = tempfile::tempdir().unwrap();
    host(
        root.path(),
        &[
            ("usr/bin/dnf", ""),
            ("var/cache/dnf/expired_repos.json", "[]"),
        ],
    );
    dated(
        &root.path().join("var/cache/dnf/expired_repos.json"),
        -9 * DAY,
    );
    let stale = card(root.path());
    assert_eq!(
        (stale.state, stale.findings),
        (
            State::Warning,
            vec![
                "dnf has not refreshed its metadata for 9 days, so updates published since are \
                 not counted: `dnf makecache` refreshes it, as the dnf-makecache timer does."
                    .to_owned()
            ]
        )
    );
    dated(&root.path().join("var/cache/dnf/expired_repos.json"), -DAY);
    assert_eq!(card(root.path()).state, State::Ok);
}
