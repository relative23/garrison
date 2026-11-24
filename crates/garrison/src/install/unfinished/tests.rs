use std::os::unix::fs::symlink;

use super::*;
use crate::units;

/// `base` with the releases `names`, `current` and `previous` as given.
fn host(names: &[&str], current: &str, previous: Option<&str>) -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    let base = directory.path();
    for name in names {
        fs::create_dir_all(base.join("releases").join(name)).unwrap();
    }
    fs::create_dir_all(base.join("backup")).unwrap();
    fs::write(base.join("backup/web.sqlite"), "the copy").unwrap();
    symlink(base.join("releases").join(current), base.join("current")).unwrap();
    if let Some(previous) = previous {
        symlink(base.join("releases").join(previous), base.join("previous")).unwrap();
    }
    directory
}

fn release(base: &Path, name: &str) -> PathBuf {
    fs::canonicalize(base.join("releases").join(name)).unwrap()
}

fn upgrade(base: &Path) -> Unfinished {
    Unfinished::Upgrade {
        from: release(base, "0.1"),
        to: release(base, "0.2"),
        previous: Some(release(base, "0.0")),
        backup: fs::canonicalize(base.join("backup")).unwrap(),
    }
}

fn rollback(base: &Path, state: bool) -> Unfinished {
    Unfinished::Rollback {
        from: release(base, "0.2"),
        to: release(base, "0.1"),
        previous: Some(release(base, "0.2")),
        state: state.then(|| fs::canonicalize(base.join("backup")).unwrap()),
    }
}

fn restore(base: &Path) -> Unfinished {
    Unfinished::Restore {
        source: base.join("source"),
        kept: fs::canonicalize(base.join("backup")).unwrap(),
    }
}

/// The writers when a record is written, and after the web service started.
fn written() -> Stamp {
    Stamp::of("boot", &[(units::WEB, 100), (units::INGEST, 90)])
}

fn started() -> Stamp {
    Stamp::of("boot", &[(units::WEB, 400), (units::INGEST, 90)])
}

fn link(base: &Path, name: &str) -> Option<String> {
    fs::canonicalize(base.join(name))
        .ok()
        .map(|release| super::name(&release))
}

/// Every step of an upgrade leaves links the record fits: before the
/// switch, between the two links, after it, and during a switch back.
#[test]
fn an_upgrade_is_known_at_every_step_and_forgotten_once_done() {
    for (current, previous) in [("0.1", "0.0"), ("0.1", "0.1"), ("0.2", "0.1")] {
        let directory = host(&["0.0", "0.1", "0.2"], current, Some(previous));
        let base = directory.path();
        write_in(base, &upgrade(base), Some(written())).unwrap();
        let seen = read_in(base, Some(&written()), || true).unwrap();
        assert_eq!(seen, Seen::Holds(upgrade(base)), "{current} {previous}");
        clear_in(base).unwrap();
        assert_eq!(
            read_in(base, Some(&written()), || true).unwrap(),
            Seen::Nothing
        );
        // Clearing what is not there is no error.
        clear_in(base).unwrap();
    }
}

/// A record the links no longer fit, as after an older installer ran,
/// is removed and says so; one that cannot be read stops everything.
#[test]
fn a_record_the_host_no_longer_fits_is_removed() {
    let directory = host(&["0.0", "0.1", "0.2", "0.3"], "0.3", Some("0.2"));
    let base = directory.path();
    write_in(base, &upgrade(base), Some(written())).unwrap();
    assert_eq!(
        read_in(base, Some(&written()), || true).unwrap(),
        Seen::Nothing
    );
    assert!(!path(base).exists());
    // Without the release it began from there is nothing to return to.
    let directory = host(&["0.0", "0.1", "0.2"], "0.2", Some("0.1"));
    let base = directory.path();
    write_in(base, &upgrade(base), Some(written())).unwrap();
    fs::remove_dir(base.join("releases/0.1")).unwrap();
    assert_eq!(
        read_in(base, Some(&written()), || true).unwrap(),
        Seen::Nothing
    );
    fs::write(path(base), "{}").unwrap();
    let refused = read_in(base, Some(&written()), || true).unwrap_err();
    assert!(refused.contains("cannot be read"), "{refused}");
    assert!(path(base).exists());
}

#[test]
fn a_rollback_is_known_on_both_sides_of_its_switch() {
    for (current, previous) in [("0.2", "0.1"), ("0.1", "0.1"), ("0.1", "0.2")] {
        let directory = host(&["0.1", "0.2"], current, Some(previous));
        let base = directory.path();
        write_in(base, &rollback(base, true), Some(written())).unwrap();
        let seen = read_in(base, Some(&written()), || true).unwrap();
        assert_eq!(
            seen,
            Seen::Holds(rollback(base, true)),
            "{current} {previous}"
        );
    }
}

#[test]
fn a_restore_is_known_while_its_copy_is_there() {
    let directory = host(&["0.1"], "0.1", None);
    let base = directory.path();
    write_in(base, &restore(base), Some(written())).unwrap();
    let seen = read_in(base, Some(&written()), || true).unwrap();
    assert_eq!(seen, Seen::Holds(restore(base)));
    fs::remove_file(base.join("backup/web.sqlite")).unwrap();
    fs::remove_dir(base.join("backup")).unwrap();
    assert_eq!(
        read_in(base, Some(&written()), || true).unwrap(),
        Seen::Nothing
    );
    assert!(!path(base).exists());
}

/// One record of each kind, each at every pair of links it fits, with the
/// `previous` a stale record leaves there. A kind of record added to
/// `Unfinished` fails to compile here until it is in this list.
fn every_kind(base: &Path) -> Vec<(Unfinished, &'static str, &'static str, Option<&'static str>)> {
    let all = [
        (upgrade(base), "0.1", "0.0", Some("0.0")),
        (upgrade(base), "0.1", "0.1", Some("0.0")),
        (upgrade(base), "0.2", "0.1", Some("0.1")),
        (rollback(base, false), "0.1", "0.2", Some("0.2")),
        (rollback(base, true), "0.1", "0.1", Some("0.2")),
        (rollback(base, true), "0.2", "0.1", Some("0.1")),
        (restore(base), "0.1", "0.0", Some("0.0")),
    ];
    for (record, ..) in &all {
        match record {
            Unfinished::Upgrade { .. }
            | Unfinished::Rollback { .. }
            | Unfinished::Restore { .. } => {}
        }
    }
    all.into()
}

/// The rule over every kind of record: once a service of Garrison's started
/// after it was written, no record holds, and resolving it changes nothing
/// but `previous`: no copy goes anywhere, no release and no backup goes.
/// Only an upgrade whose new release is current and does not run stays, as
/// failed, for its switch back to copy the state first.
#[test]
fn no_record_holds_once_garrison_started_since_it_was_written() {
    let probe = host(&["0.0", "0.1", "0.2"], "0.1", None);
    let count = every_kind(probe.path()).len();
    for index in 0..count {
        let template = every_kind(probe.path())[index].clone();
        let (_, current, previous, left) = template;
        let directory = host(&["0.0", "0.1", "0.2"], current, Some(previous));
        let base = directory.path();
        let (record, ..) = every_kind(base).swap_remove(index);
        let case = format!("{} at {current} {previous}", record.describe());
        // Nothing started since: it holds, also after a reboot.
        write_in(base, &record, Some(written())).unwrap();
        assert_eq!(
            read_in(base, Some(&written()), || true).unwrap(),
            Seen::Holds(record.clone()),
            "{case}"
        );
        let rebooted = Stamp::of("another boot", &[(units::WEB, 0), (units::INGEST, 0)]);
        assert_eq!(
            read_in(base, Some(&rebooted), || true).unwrap(),
            Seen::Holds(record.clone()),
            "{case}"
        );
        // Started since, in this boot or after a reboot.
        let after_reboot = Stamp::of("another boot", &[(units::WEB, 0), (units::INGEST, 5)]);
        let failed = matches!(record, Unfinished::Upgrade { .. }) && current == "0.2";
        for (now, running) in [(started(), true), (after_reboot, true), (started(), false)] {
            write_in(base, &record, Some(written())).unwrap();
            let seen = read_in(base, Some(&now), || running).unwrap();
            if failed && !running {
                assert_eq!(seen, Seen::Failed(record.clone()), "{case}");
                assert!(path(base).exists(), "{case}");
                assert_eq!(link(base, "previous").as_deref(), Some(previous), "{case}");
                continue;
            }
            assert_eq!(seen, Seen::Stale(record.clone()), "{case}");
            assert!(!path(base).exists(), "{case}");
            assert_eq!(link(base, "current").as_deref(), Some(current), "{case}");
            assert_eq!(link(base, "previous").as_deref(), left, "{case}");
            for release in ["0.0", "0.1", "0.2"] {
                assert!(base.join("releases").join(release).is_dir(), "{case}");
            }
            let copy = fs::read_to_string(base.join("backup/web.sqlite")).unwrap();
            assert_eq!(copy, "the copy", "{case}");
        }
    }
}

/// A record of the format before the stamp, without the rollback's state,
/// is read; as nobody knows when it was written, it holds only while
/// nothing has started in this boot.
#[test]
fn a_record_without_a_stamp_holds_only_until_anything_starts() {
    let directory = host(&["0.1", "0.2"], "0.1", Some("0.1"));
    let base = directory.path();
    let old = format!(
        r#"{{"command": "rollback", "from": "{}", "to": "{}", "previous": "{}"}}"#,
        release(base, "0.2").display(),
        release(base, "0.1").display(),
        release(base, "0.2").display()
    );
    fs::write(path(base), &old).unwrap();
    let nothing = Stamp::of("boot", &[(units::WEB, 0)]);
    assert_eq!(
        read_in(base, Some(&nothing), || true).unwrap(),
        Seen::Holds(rollback(base, false))
    );
    assert_eq!(
        read_in(base, Some(&written()), || true).unwrap(),
        Seen::Stale(rollback(base, false))
    );
}

#[test]
fn the_record_is_roots_alone_and_says_what_finishes_it() {
    use std::os::unix::fs::PermissionsExt;
    let directory = host(&["0.0", "0.1", "0.2"], "0.2", Some("0.1"));
    let base = directory.path();
    write_in(base, &upgrade(base), Some(written())).unwrap();
    let mode = fs::metadata(path(base)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(
        upgrade(base).finish_first(),
        "An earlier run left an upgrade from 0.1 to 0.2 unfinished; run the installer of 0.2 \
         again to finish it. Nothing was changed."
    );
    // A rollback that puts the state back is finished with the state.
    let finish = rollback(base, true).finish_first();
    let command = format!(
        "run `{} install --rollback --restore-state` to finish it",
        release(base, "0.2").join("bin/garrison").display()
    );
    assert!(finish.contains(&command), "{finish}");
    assert!(
        finish.contains("with the state from before the upgrade unfinished"),
        "{finish}"
    );
    assert!(
        !rollback(base, false)
            .finish_first()
            .contains("--restore-state")
    );
}
