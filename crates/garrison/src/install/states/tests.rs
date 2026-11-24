//! The installer's states, each with its whole line: the one place in the
//! installer's tests where their words stand.

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;

use super::*;
use crate::state::State;

mod back;

type Rows = Vec<(State, &'static str)>;

fn web_restarted() -> State {
    restarting("garrison-web.service", "3", 8)
}

fn checks() -> Rows {
    vec![
        (
            io("/opt/garrison", "Permission denied (os error 13)"),
            "/opt/garrison: Permission denied (os error 13) [install-io]",
        ),
        (
            busy(),
            "Another garrison install is already running; try again when it has finished. [install-busy]",
        ),
        (not_root(), "Run as root. [install-not-root]"),
        (
            tool_missing("/usr/bin/systemd-sysusers"),
            "/usr/bin/systemd-sysusers is required. [install-tool-missing]",
        ),
        (
            old_systemd(239, 247),
            "systemd 239 is too old: Garrison's units need systemd 247 or newer. [install-old-systemd]",
        ),
        (
            systemd_unknown(),
            "`systemctl --version` names no systemd version. [install-systemd-unknown]",
        ),
        (
            old_polkit("0.105"),
            "polkit 0.105 has no JavaScript rules: Garrison needs polkit 0.106 or newer. [install-old-polkit]",
        ),
        (
            no_polkit(),
            "polkit is required for service actions, with JavaScript rules (polkit 0.106 or newer, \
             /etc/polkit-1/rules.d). [install-no-polkit]",
        ),
        (
            base_hidden("/opt/garrison leads to /home/garrison, which lies under /home"),
            "/opt/garrison leads to /home/garrison, which lies under /home; nothing was changed. \
             [install-base-hidden]",
        ),
        (
            no_room(Path::new("/opt"), 29 << 20, "the installation", 512 << 20),
            "/opt has 29 MiB free and the installation needs 512 MiB; nothing was changed. \
             [install-no-room]",
        ),
        (
            copies_no_room(Path::new("/var/lib/garrison/collector"), 3 << 20, 5 << 20),
            "/var/lib/garrison/collector has 3 MiB free and the copies from before the upgrade need \
             5 MiB there; free space there [install-copies-no-room]",
        ),
        (
            sums_missing(),
            "SHA256SUMS is missing; this is not a complete release. [install-sums-missing]",
        ),
        (
            sums_malformed(),
            "SHA256SUMS is malformed. [install-sums-malformed]",
        ),
        (
            sums_outside("../VERSION"),
            "SHA256SUMS lists \"../VERSION\", which is no file of a release; nothing was installed. \
             [install-sums-outside]",
        ),
        (
            sums_twice("VERSION"),
            "SHA256SUMS lists VERSION twice; nothing was installed. [install-sums-twice]",
        ),
        (
            not_a_file("static/etc"),
            "static/etc is not a regular file; nothing was installed. [install-not-a-file]",
        ),
        (
            checksum_mismatch("static/index.html"),
            "Checksum mismatch for static/index.html; nothing was installed. [install-checksum-mismatch]",
        ),
        (
            unlisted("static/extra.js"),
            "static/extra.js is not listed in SHA256SUMS; nothing was installed. [install-unlisted]",
        ),
        (
            bad_version("../../etc"),
            "VERSION \"../../etc\" is not a release version; nothing was installed. [install-bad-version]",
        ),
    ]
}

fn runs() -> Rows {
    let recorded = Recorded::Switch("upgrade", "0.1.2".into(), "0.2.0".into());
    vec![
        (
            record_removed(Path::new("/opt/garrison/unfinished.json"), &recorded),
            "/opt/garrison/unfinished.json named an unfinished upgrade from 0.1.2 to 0.2.0; nothing \
             reads it any more: it was removed, and nothing was done on its word. \
             [install-record-removed]",
        ),
        (
            running("0.2.0", Some("garrison install --rollback")),
            "Garrison 0.2.0 is running. [install-running]\n      Roll back with: garrison install \
             --rollback",
        ),
        (
            as_installed("0.2.0", None),
            "Garrison 0.2.0 is running as installed; nothing was changed. [install-as-installed]",
        ),
        (
            not_configured(Path::new("/etc/garrison/garrison.toml"), "garrison"),
            "The release is installed, but Garrison is not configured yet.

  1. Edit /etc/garrison/garrison.toml (origins, providers, actions).
     `garrison detect` shows what this host runs, and
     `garrison modules` chooses the modules this installation offers.
  2. Create the Stalwart objects (webhook, API keys, metrics):
       garrison stalwart setup        (asks for a Stalwart administrator)
  3. Create the access policy:   garrison access init
  4. Check everything:           garrison check-config
  5. Run the installer again to start the services.
  6. Give Garrison a host name of its own (never Stalwart's):
     `garrison nginx` prints its server block and the lines for Stalwart's.
     Add
       include /etc/nginx/snippets/garrison-stalwart-server*.conf;
     to every server block that proxies to Stalwart: it keeps the metrics
     exporter that step 2 turns on off the internet.

The command is available as garrison. [install-not-configured]",
        ),
        (
            untouched(config_refused()),
            "check-config failed; the running release was not touched [install-config-refused]",
        ),
        (
            backup_failed("/var/backups/garrison: Not a directory (os error 20)"),
            "backup failed: /var/backups/garrison: Not a directory (os error 20) [install-backup-failed]",
        ),
        (
            backup_unloadable(
                "Cannot load /etc/garrison/garrison.toml: unknown field `modules`",
                "0.1.1",
            ),
            "backup failed: Cannot load /etc/garrison/garrison.toml: unknown field `modules`; 0.1.1, \
             the release that runs, makes the backup before the upgrade and cannot load \
             /etc/garrison/garrison.toml: take out the settings it does not know, upgrade, then put \
             them back [install-backup-unloadable]",
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
        (
            web_restarted(),
            "garrison-web.service restarted 3 times within 8 s of starting [install-restarting]",
        ),
        (
            not_active("garrison-web.service", "", 8),
            "garrison-web.service is unknown within 8 s of starting [install-not-active]",
        ),
        (
            switching_back(),
            "Start failed; switching back to the previous release. [install-switching-back]",
        ),
        (
            migrated_back(went.as_ref().unwrap()),
            "The new release had changed what the release that ran cannot read. These went back to \
             their copies in /var/backups/garrison/pre-upgrade-20261124T080000: collector. \
             [install-went-back] The other databases keep their data. [install-migrated-back]",
        ),
        (
            unreadable_state("0.1.2", "collector (schema 3, integrity ok)"),
            "0.1.2 cannot read the current state, as its self-check says of collector (schema 3, \
             integrity ok) [install-unreadable-state]",
        ),
        (
            switched_back("0.2.0", &web_restarted()),
            "Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of \
             starting [install-restarting]); the previous release is running. See the journal. \
             [install-switched-back]",
        ),
        (
            switch_back_failed(
                "0.2.0",
                &web_restarted(),
                "0.1.2",
                &room,
                None,
                None,
                "garrison",
            ),
            "Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of \
             starting [install-restarting]); switching back to 0.1.2 failed \
             (/var/lib/garrison/collector has 3 MiB free and the copies from before the upgrade \
             need 5 MiB there; free space there [install-copies-no-room]). `garrison install \
             --rollback --restore-state` returns to it with the state from before the upgrade. See \
             the journal. [install-switch-back-failed]",
        ),
        (
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
            "Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of \
             starting [install-restarting]); the previous release did not start either \
             (garrison-web.service restarted 3 times within 8 s of starting [install-restarting]), \
             and the links could not be set back (/opt/garrison/current: Read-only file system (os \
             error 30) [install-io]). These went back to their copies in \
             /var/backups/garrison/pre-upgrade-20261124T080000: collector. [install-went-back] See \
             the journal. [install-previous-failed]",
        ),
        (
            not_restarted("0.2.0", &web_restarted(), "0.1.2", "garrison"),
            "Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of \
             starting [install-restarting]); 0.1.2 did not run when this run began, so it was not \
             started again; `garrison install --rollback` returns to it. See the journal. \
             [install-not-restarted]",
        ),
        (
            stopped("0.2.0", &web_restarted(), Some("0.1.2"), "garrison"),
            "Garrison 0.2.0 did not start (garrison-web.service restarted 3 times within 8 s of \
             starting [install-restarting]); it was stopped; `garrison install --rollback` returns \
             to 0.1.2. See the journal. [install-stopped]",
        ),
    ]
}

fn system() -> Rows {
    let polkit = Path::new("/etc/polkit-1/rules.d/50-garrison.rules");
    vec![
        (
            nginx_not_reloaded("nginx: [emerg] unknown directive \"x\""),
            "nginx -t failed; snippets updated but nginx was not reloaded:\nnginx: [emerg] unknown \
             directive \"x\" [install-nginx-not-reloaded]",
        ),
        (
            unwritten(
                polkit,
                &["polkit-rule"],
                "Cannot load /etc/garrison/garrison.toml: unknown key",
            ),
            "/etc/polkit-1/rules.d/50-garrison.rules was not written, since `garrison polkit-rule` \
             failed: Cannot load /etc/garrison/garrison.toml: unknown key [install-unwritten]",
        ),
        (
            policy_foreign(Path::new("/srv/access.json"), 65534),
            "/srv/access.json, the access policy that broker.policy names, belongs to the user with \
             ID 65534, not to root: the installer makes no other user's file the policy, and the \
             broker takes none. Where it is the policy you mean, `chown root /srv/access.json` and \
             run this again [install-policy-foreign]",
        ),
        (
            link_taken(
                Path::new("/usr/bin/garrison"),
                "/opt/garrison/current/bin/garrison",
            ),
            "/usr/bin/garrison is something else and was left alone; Garrison's command is \
             /opt/garrison/current/bin/garrison. [install-link-taken]",
        ),
        (
            link_failed(
                Path::new("/usr/bin/garrison"),
                "Read-only file system (os error 30)",
                "/opt/garrison/current/bin/garrison",
            ),
            "/usr/bin/garrison could not be made (Read-only file system (os error 30)); Garrison's \
             command is /opt/garrison/current/bin/garrison. [install-link-failed]",
        ),
        (
            selinux_failed(Some("libsemanage: conflict"), ExitStatus::from_raw(1 << 8)),
            "The SELinux module did not load, so nginx may not reach Garrison: libsemanage: \
             conflict. `setsebool -P httpd_can_network_connect 1` allows it more broadly. \
             [install-selinux-failed]",
        ),
    ]
}

fn milter() -> Rows {
    let settings = Path::new("/etc/garrison/garrison.toml");
    let asked = milter_asked("m1", "127.0.0.1:8096");
    vec![
        (
            milter_held(&asked, 8097),
            "The macro filter stays on the port it listens on, which garrison.toml no longer names: \
             Stalwart asks its milter entry m1 at 127.0.0.1:8096 [install-milter-asked]. `garrison \
             stalwart setup` moves it to port 8097. [install-milter-held]",
        ),
        (
            asked.clone(),
            "Stalwart asks its milter entry m1 at 127.0.0.1:8096 [install-milter-asked]",
        ),
        (
            milter_unasked(&io("Stalwart", "connection refused")),
            "Stalwart's milters could not be asked (Stalwart: connection refused [install-io]) \
             [install-milter-unasked]",
        ),
        (
            milter_unseen("garrison-milter.service"),
            "where garrison-milter.service listens cannot be seen [install-milter-unseen]",
        ),
        (
            milter_unloaded(settings),
            "/etc/garrison/garrison.toml does not load, so Stalwart's milters cannot be asked \
             [install-milter-unloaded]",
        ),
        (
            milter_kept(&asked),
            "The macro milter, which the configuration no longer has, keeps running: Stalwart asks \
             its milter entry m1 at 127.0.0.1:8096 [install-milter-asked]. Run `garrison stalwart \
             setup`: it takes the filter out of Stalwart and stops it. [install-milter-kept]",
        ),
        (
            milter_still_asked(&asked, settings),
            "Stalwart still asks Garrison's macro milter about every message, as far as this host \
             can tell, and would defer mail without it: Stalwart asks its milter entry m1 at \
             127.0.0.1:8096 [install-milter-asked]; nothing was changed. Remove the [milter] \
             section from /etc/garrison/garrison.toml, run `garrison stalwart setup` and uninstall \
             then. [install-milter-still-asked]",
        ),
    ]
}

#[test]
fn every_state_of_the_installer_says_its_line() {
    let rows = [
        checks(),
        runs(),
        starts(),
        system(),
        milter(),
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
