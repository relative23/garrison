//! The pending updates: apt and dnf, when they are asked again, and the
//! cache folders that keep dnf out.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::json;

use super::*;

const APT: &str = "Inst zlib1g [1.3] (1.3+deb13u1 Debian-Security:13/stable-security [amd64])\n\
    Inst curl [8.14] (8.14+b1 Debian:13.2/stable [amd64])\n";

/// Gives a file the modification time `at` seconds after the tests' clock.
fn touched(path: &Path, at: i64) {
    let seconds = u64::try_from(now().as_second() + at).unwrap();
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds))
        .unwrap();
}

#[test]
fn pending_security_updates_are_a_warning_and_asked_for_every_six_hours() {
    let root = tempfile::tempdir().unwrap();
    host(root.path(), &[("usr/bin/apt-get", "")]);
    let runner = Programs::new(vec![(
        "apt-get -s -o Debug::NoLocking=true upgrade",
        0,
        APT,
    )]);
    let provider = provider(root.path(), "\"updates\"");
    let memory = Remembered::default();
    let first = checked(&provider, &runner, &memory, 0);
    assert_eq!(first.id, "host.updates");
    assert_eq!(first.state, State::Warning);
    assert_eq!(first.findings, ["1 security update is pending."]);
    assert_eq!(field(&first, "Security updates"), &json!(1));
    assert_eq!(field(&first, "Other updates"), &json!(1));
    assert_eq!(first.source, "apt-get -s upgrade");
    // A minute and nearly six hours later the answer is the kept one.
    for later in [60, ASK_EVERY - 1] {
        assert_eq!(
            checked(&provider, &runner, &memory, later).state,
            State::Warning
        );
    }
    assert_eq!(runner.runs("apt-get"), 1);
    checked(&provider, &runner, &memory, ASK_EVERY);
    assert_eq!(runner.runs("apt-get"), 2);
}

#[test]
fn dnf_is_read_from_its_cache_and_updates_without_security_are_in_order() {
    let root = tempfile::tempdir().unwrap();
    host(root.path(), &[("usr/bin/dnf", "")]);
    let quiet = Programs::new(vec![
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp updateinfo list --security --updates",
            0,
            "",
        ),
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp check-update",
            100,
            "\ncurl.x86_64  8.12  baseos\n",
        ),
    ]);
    let provider = provider(root.path(), "\"updates\"");
    let observation = checked(&provider, &quiet, &Remembered::default(), 0);
    assert_eq!(observation.state, State::Ok);
    assert_eq!(observation.findings, Vec::<String>::new());
    assert_eq!(field(&observation, "Other updates"), &json!(1));

    let pending = Programs::new(vec![
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp updateinfo",
            0,
            "ALSA-2026:1 Important/Sec. curl-8.12.1-4.el10.x86_64\nALSA-2026:1 Important/Sec. libcurl-8.12.1-4.el10.x86_64\n",
        ),
        (
            "dnf -q -C --setopt=cachedir=/var/cache/dnf --setopt=logdir=/tmp check-update",
            100,
            "\ncurl.x86_64  8.12  baseos\nlibcurl.x86_64  8.12  baseos\nbash.x86_64  5.2  baseos\n",
        ),
    ]);
    let observation = checked(&provider, &pending, &Remembered::default(), 0);
    assert_eq!(observation.findings, ["2 security updates are pending."]);
    assert_eq!(field(&observation, "Other updates"), &json!(1));
}

#[test]
fn updates_that_cannot_be_read_are_unknown_and_asked_for_again_within_the_hour() {
    for (files, answers, problem) in [
        (
            vec![],
            vec![],
            "no package manager this check reads was found (apt, dnf 4)",
        ),
        (
            vec![("usr/bin/dnf", ""), ("usr/bin/dnf5", "")],
            vec![],
            "this check does not read dnf 5 yet",
        ),
        (
            vec![("usr/bin/apt-get", "")],
            vec![],
            "apt-get did not run: entity not found",
        ),
        (
            vec![("usr/bin/apt-get", "")],
            vec![("apt-get", 100, "")],
            "apt-get could not work out the upgrade",
        ),
        (
            vec![("usr/bin/dnf", "")],
            vec![("dnf", 1, "")],
            "dnf could not list the security updates",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        host(root.path(), &files);
        let runner = Programs::new(answers);
        let provider = provider(root.path(), "\"updates\"");
        let memory = Remembered::default();
        let observation = checked(&provider, &runner, &memory, 0);
        assert_eq!(observation.state, State::Unknown, "{problem}");
        assert_eq!(
            observation.findings,
            [format!("The pending updates are not known: {problem}.")]
        );
        let before = runner.1.borrow().len();
        checked(&provider, &runner, &memory, ASK_AGAIN - 1);
        assert_eq!(runner.1.borrow().len(), before, "{problem}");
    }
}

#[test]
fn installed_packages_are_asked_about_again_within_five_minutes() {
    let root = tempfile::tempdir().unwrap();
    host(
        root.path(),
        &[
            ("usr/bin/apt-get", ""),
            ("var/lib/dpkg/status", "Package: curl\n"),
        ],
    );
    let status = root.path().join("var/lib/dpkg/status");
    touched(&status, -3600);
    let runner = Programs::new(vec![(
        "apt-get -s -o Debug::NoLocking=true upgrade",
        0,
        APT,
    )]);
    let provider = provider(root.path(), "\"updates\"");
    let memory = Remembered::default();
    checked(&provider, &runner, &memory, 0);
    // dpkg installs the updates a minute later.
    touched(&status, 60);
    checked(&provider, &runner, &memory, ASK_SOONEST - 1);
    assert_eq!(runner.runs("apt-get"), 1);
    checked(&provider, &runner, &memory, ASK_SOONEST);
    assert_eq!(runner.runs("apt-get"), 2);
    // Nothing changed since that answer.
    checked(&provider, &runner, &memory, 2 * ASK_SOONEST);
    assert_eq!(runner.runs("apt-get"), 2);
    // A change time ahead of the clock waits until the clock is there.
    touched(&status, 4 * ASK_SOONEST);
    checked(&provider, &runner, &memory, 3 * ASK_SOONEST);
    assert_eq!(runner.runs("apt-get"), 2);
    checked(&provider, &runner, &memory, 4 * ASK_SOONEST);
    assert_eq!(runner.runs("apt-get"), 3);
}

#[test]
fn new_dnf_metadata_or_an_opened_cache_folder_is_asked_about_again() {
    let root = tempfile::tempdir().unwrap();
    let epel = "var/cache/dnf/epel-74fe7744c98fc60d";
    host(
        root.path(),
        &[
            ("usr/bin/dnf", ""),
            (&format!("{epel}/repodata/repomd.xml"), "<repomd/>"),
        ],
    );
    let metadata = root.path().join(epel).join("repodata/repomd.xml");
    touched(&metadata, -3600);
    let docker = root
        .path()
        .join("var/cache/dnf/docker-ce-stable-2af464d7514827bd");
    fs::create_dir_all(&docker).unwrap();
    for (folder, mode) in [(root.path().join(epel), 0o755), (docker.clone(), 0o700)] {
        fs::set_permissions(folder, fs::Permissions::from_mode(mode)).unwrap();
    }
    let provider = provider(root.path(), "\"updates\"");
    let memory = Remembered::default();
    let failing = Programs::new(vec![("dnf", 1, "")]);
    assert_eq!(
        checked(&provider, &failing, &memory, 0).state,
        State::Unknown
    );
    // The operator opens the folder: asked again well before the hour is up.
    fs::set_permissions(&docker, fs::Permissions::from_mode(0o755)).unwrap();
    let working = Programs::new(vec![
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
    let opened = checked(&provider, &working, &memory, ASK_SOONEST);
    assert_eq!(opened.state, State::Ok);
    assert_eq!(working.runs("dnf"), 2);
    // The host's update job fetches new metadata for a repository.
    touched(&metadata, 2 * ASK_SOONEST);
    checked(&provider, &working, &memory, 2 * ASK_SOONEST);
    assert_eq!(working.runs("dnf"), 4);
    checked(&provider, &working, &memory, 3 * ASK_SOONEST);
    assert_eq!(working.runs("dnf"), 4);
}

#[test]
fn a_dnf_cache_that_only_root_may_read_is_named_with_its_remedy() {
    let root = tempfile::tempdir().unwrap();
    host(root.path(), &[("usr/bin/dnf", "")]);
    // What a dnf run under umask 077 leaves behind, as on the reference host.
    let cache = root.path().join("var/cache/dnf");
    let open = |folder: &str, mode| {
        fs::create_dir_all(cache.join(folder)).unwrap();
        fs::set_permissions(cache.join(folder), fs::Permissions::from_mode(mode)).unwrap();
    };
    open("docker-ce-stable-2af464d7514827bd", 0o700);
    open("epel-74fe7744c98fc60d", 0o700);
    open("baseos-dd34f9106e98b1fa", 0o755);
    let failing = Programs::new(vec![("dnf", 1, "")]);
    let provider = provider(root.path(), "\"updates\"");
    let both = checked(&provider, &failing, &Remembered::default(), 0);
    assert_eq!(both.state, State::Unknown);
    assert_eq!(
        both.findings,
        [
            "The pending updates are not known: only root may read the dnf cache folders of \
             docker-ce-stable and epel in /var/cache/dnf; chmod 755 on them lets this check read them."
        ]
    );
    open("epel-74fe7744c98fc60d", 0o755);
    let one = checked(&provider, &failing, &Remembered::default(), 0);
    assert_eq!(
        one.findings,
        [
            "The pending updates are not known: only root may read the dnf cache folder of \
             docker-ce-stable in /var/cache/dnf; chmod 755 on it lets this check read it."
        ]
    );
}
