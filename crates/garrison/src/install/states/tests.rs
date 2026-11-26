//! The installer's states, each with its whole line: the one place in the
//! installer's tests where their words stand.

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;

use super::*;
use crate::state::State;

mod back;

type Rows = Vec<State>;

fn web_restarted() -> State {
    restarting("garrison-web.service", "3", 8)
}

fn checks() -> Rows {
    vec![
        io("/opt/garrison", "Permission denied (os error 13)"),
        busy(),
        not_root(),
        tool_missing("/usr/bin/systemd-sysusers"),
        old_systemd(239, 247),
        systemd_unknown(),
        old_polkit("0.105"),
        no_polkit(),
        base_hidden("/opt/garrison leads to /home/garrison, which lies under /home"),
        no_room(Path::new("/opt"), 29 << 20, "the installation", 512 << 20),
        copies_no_room(Path::new("/var/lib/garrison/collector"), 3 << 20, 5 << 20),
        sums_missing(),
        sums_malformed(),
        sums_outside("../VERSION"),
        sums_twice("VERSION"),
        not_a_file("static/etc"),
        checksum_mismatch("static/index.html"),
        unlisted("static/extra.js"),
        bad_version("../../etc"),
    ]
}

fn runs() -> Rows {
    vec![
        running("0.2.0", Some("garrison install --rollback")),
        as_installed("0.2.0", None),
        not_configured(Path::new("/etc/garrison/garrison.toml"), "garrison"),
        untouched(config_refused()),
        backup_failed("/var/backups/garrison: Not a directory (os error 20)"),
        backup_unloadable(
            "Cannot load /etc/garrison/garrison.toml: unknown field `modules`",
            "0.1.1",
        ),
    ]
}

fn starts() -> Rows {
    let went = went_back(
        Path::new("/var/backups/garrison/pre-upgrade-20261124T080000"),
        &["collector"],
        &[],
    );
    let room = copies_no_room(Path::new("/var/lib/garrison/collector"), 3 << 20, 5 << 20);
    vec![
        web_restarted(),
        not_active("garrison-web.service", "", 8),
        switching_back(),
        migrated_back(went.as_ref().unwrap()),
        unreadable_state("0.1.2", "collector (schema 3, integrity ok)"),
        switched_back("0.2.0", &web_restarted()),
        switch_back_failed(
            "0.2.0",
            &web_restarted(),
            "0.1.2",
            &room,
            None,
            None,
            "garrison",
        ),
        previous_failed(
            "0.2.0",
            &web_restarted(),
            &web_restarted(),
            Some(&io(
                "/opt/garrison/current",
                "Read-only file system (os error 30)",
            )),
            went.as_ref(),
            "garrison",
        ),
        not_restarted("0.2.0", &web_restarted(), "0.1.2", "garrison"),
        stopped("0.2.0", &web_restarted(), Some("0.1.2"), "garrison"),
    ]
}

fn system() -> Rows {
    let polkit = Path::new("/etc/polkit-1/rules.d/50-garrison.rules");
    vec![
        nginx_not_reloaded("nginx: [emerg] unknown directive \"x\""),
        unwritten(
            polkit,
            &["polkit-rule"],
            "Cannot load /etc/garrison/garrison.toml: unknown key",
        ),
        unchanged(policy_foreign(Path::new("/srv/access.json"), 65534)),
        link_taken(
            Path::new("/usr/bin/garrison"),
            "/opt/garrison/current/bin/garrison",
        ),
        link_failed(
            Path::new("/usr/bin/garrison"),
            "Read-only file system (os error 30)",
            "/opt/garrison/current/bin/garrison",
        ),
        selinux_failed(Some("libsemanage: conflict"), ExitStatus::from_raw(1 << 8)),
    ]
}

fn filter() -> Rows {
    vec![filter_runs("garrison-milter.service")]
}

#[test]
fn every_state_of_the_installer_says_its_line() {
    let rows = [
        checks(),
        runs(),
        starts(),
        system(),
        filter(),
        back::rollback(),
        back::restore(),
        back::places(),
    ]
    .concat();
    let sources = [
        include_str!("../states.rs"),
        include_str!("back.rs"),
        include_str!("start.rs"),
    ];
    crate::state::table(&sources, &rows);
}

/// A refusal before anything stopped or changed keeps its name; the table
/// holds the words such a refusal adds.
#[test]
fn a_refusal_before_any_change_keeps_its_name() {
    let foreign = || policy_foreign(Path::new("/srv/access.json"), 65534);
    for said in [untouched(foreign()), unchanged(foreign())] {
        assert_eq!(said.name, foreign().name);
        assert_ne!(said, foreign());
    }
}

/// Where semodule says nothing, how it ended is said instead.
#[test]
fn a_silent_selinux_failure_names_how_semodule_ended() {
    let status = ExitStatus::from_raw(1 << 8);
    let silent = selinux_failed(None, status);
    assert_eq!(silent.name, "install-selinux-failed");
    assert!(silent.text.contains(&status.to_string()), "{silent}");
    assert_ne!(
        silent,
        selinux_failed(Some("libsemanage: conflict"), status)
    );
}

/// Nothing went back: no sentence for it.
#[test]
fn nothing_that_went_back_says_nothing() {
    assert_eq!(
        went_back(Path::new("/var/backups/garrison/x"), &[], &[]),
        None
    );
}
