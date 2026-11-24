//! `garrison install` of an unpacked release: the first installation, an
//! upgrade or a reinstall.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::files::{Step, announce, copy_tree, exchange, fresh_folder, io, lock, place, switch};
use super::requirements::{base_shown, preflight, room, size, state_size};
use super::services::{check_config, start, stop_services};
use super::system::{install_system_files, protect_policy};
use super::unfinished::{self, Unfinished};
use super::{
    BACKUPS, BASE, CONFIG, LAST, LOCK, cli, command, configured, fallback, here, housekeeping,
    rollback, verify,
};
use crate::say;

/// Unpack next to the target, then rename it into place: the release's name
/// only ever holds a complete tree, also the running one's on a reinstall.
fn install_release(here: &Path, version: &str) -> Step<PathBuf> {
    let releases = Path::new(BASE).join("releases");
    io(fs::create_dir_all(&releases), &releases)?;
    // Hidden entries are trees an interrupted run left behind.
    for entry in io(fs::read_dir(&releases), &releases)?.flatten() {
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            let path = entry.path();
            let removed = if path.is_dir() && !path.is_symlink() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            io(removed, &path)?;
        }
    }
    let (target, staging) = (releases.join(version), releases.join(format!(".{version}")));
    announce(&format!("Creating {}", target.display()));
    io(fs::create_dir_all(staging.join("bin")), &staging)?;
    place(
        &here.join("bin/garrison"),
        &staging.join("bin/garrison"),
        0o755,
    )?;
    copy_tree(&here.join("static"), &staging.join("static"))?;
    copy_tree(&here.join("deploy"), &staging.join("share/deploy"))?;
    copy_tree(&here.join("docs"), &staging.join("share/docs"))?;
    place(&here.join("VERSION"), &staging.join("VERSION"), 0o644)?;
    if target.exists() {
        announce(&format!(
            "Release {version} was unpacked already; replacing it."
        ));
        exchange(&staging, &target)?;
        io(fs::remove_dir_all(&staging), &staging)?;
    } else {
        io(fs::rename(&staging, &target), &target)?;
    }
    Ok(target)
}

/// Back up the running state, and say where to. Only a change of release moves
/// `last-pre-upgrade`, the state `--rollback --restore-state` returns to: a
/// reinstall of the running release would otherwise replace it with data the
/// previous release cannot read.
fn backup_state(current: &Path, upgrade: bool) -> Step<PathBuf> {
    let kind = if upgrade {
        "pre-upgrade"
    } else {
        "pre-reinstall"
    };
    let target = fresh_folder(Path::new(BACKUPS), kind)
        .map_err(|error| format!("backup failed: {error}"))?;
    announce(&format!(
        "Backing up the running state to {}",
        target.display()
    ));
    let output = cli(current, &["backup", "--to", &target.display().to_string()])?;
    if !output.status.success() {
        let _ = fs::remove_dir_all(&target);
        let said = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        // The running release makes this backup: a setting that only the new
        // release knows keeps it from loading the configuration.
        if said.starts_with("Cannot load") {
            let running = fs::canonicalize(current).unwrap_or_else(|_| current.to_owned());
            return Err(format!(
                "backup failed: {said}; {}, the release that runs, makes the backup before the \
                 upgrade and cannot load {CONFIG}/garrison.toml: take out the settings it does \
                 not know, upgrade, then put them back",
                unfinished::name(&running)
            ));
        }
        return Err(format!("backup failed: {said}"));
    }
    copy_config(Path::new(CONFIG), &target.join("etc"))?;
    if upgrade {
        switch(&Path::new(BACKUPS).join(LAST), &target)?;
    }
    Ok(target)
}

/// The configuration without credentials, which have their own protected
/// backup. Each file keeps its mode, at most 0644, so that one put back from
/// the copy with its mode is read as before; the backup's folder is root's
/// alone.
fn copy_config(source: &Path, target: &Path) -> Step {
    io(fs::create_dir_all(target), target)?;
    for entry in io(fs::read_dir(source), source)?.flatten() {
        if entry.file_name() == "credentials" {
            continue;
        }
        let (from, to) = (entry.path(), target.join(entry.file_name()));
        if from.is_dir() {
            copy_config(&from, &to)?;
        } else {
            let mode = io(fs::metadata(&from), &from)?.permissions().mode() & 0o644;
            place(&from, &to, mode)?;
        }
    }
    Ok(())
}

fn first_install_help() -> Step {
    let config = Path::new(CONFIG);
    io(fs::create_dir_all(config.join("credentials")), config)?;
    io(
        fs::set_permissions(
            config.join("credentials"),
            fs::Permissions::from_mode(0o700),
        ),
        config,
    )?;
    let target = config.join("garrison.toml");
    if !target.exists() {
        place(
            &Path::new(BASE).join("current/share/deploy/config/garrison.example.toml"),
            &target,
            0o644,
        )?;
        // At a terminal the modules are chosen now; otherwise with `modules`.
        if crate::at_terminal() {
            crate::selection::first(&target);
        }
    }
    say(&format!(
        "
The release is installed, but Garrison is not configured yet.

  1. Edit {target} (origins, providers, actions).
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

The command is available as {command}.",
        target = target.display(),
        command = command::name()
    ));
    Ok(())
}

/// Make `release` current, install its system files and, once configured,
/// start it; `old`, the release that ran, becomes `previous`.
fn switch_to(release: &Path, old: Option<&Path>, configured: bool) -> Step {
    let base = Path::new(BASE);
    if let Some(old) = old {
        switch(&base.join("previous"), old)?;
    }
    switch(&base.join("current"), release)?;
    install_system_files(release)?;
    if configured { start(release) } else { Ok(()) }
}

pub(super) fn install() -> Step {
    // Root first: without it the release may not even be readable.
    preflight()?;
    base_shown()?;
    let here = here()?;
    let version = verify::verify(&here)?;
    let _held = lock(Path::new(LOCK))?;
    let base = Path::new(BASE);
    let current = base.join("current");
    // An upgrade that an earlier run began goes on, or is switched back first.
    let resumed = fallback::before_install(&version)?;
    let (old, earlier) = match &resumed {
        Some(resumed) => (Some(resumed.from.clone()), resumed.previous.clone()),
        None => (
            fs::canonicalize(&current).ok(),
            fs::canonicalize(base.join("previous")).ok(),
        ),
    };
    let configured = resumed.is_some() || configured(old.is_some());
    // Room for the release and, before an upgrade, the backup of the state.
    let mut needs = vec![(base, size(&here))];
    if old.is_some() && configured && resumed.is_none() {
        needs.push((Path::new(BACKUPS), state_size()));
    }
    room(&needs, "the installation")?;
    let release = install_release(&here, &version)?;
    // As `old` is: where /opt is a link, the path under BASE and the one the
    // links resolve to differ, and a reinstall would pass for an upgrade.
    let release = fs::canonicalize(&release).unwrap_or(release);
    let changed = old.as_deref().filter(|old| *old != release);
    let mut restore = false;
    let mut backup = None;
    if old.is_some() && configured {
        // The installer sets the policy's owner and mode anyway; the check must
        // not refuse what it is about to correct.
        protect_policy()
            .map_err(|error| format!("{error}; the running release was not touched"))?;
        // A configuration the new release refuses leaves the running one
        // alone. Its warnings follow as it starts.
        check_config(&release, false).map_err(|error| match &resumed {
            Some(resumed) => format!(
                "{error}; the upgrade from {} is still unfinished: run this installer again once \
                 check-config passes",
                unfinished::name(&resumed.from)
            ),
            None => format!("{error}; the running release was not touched"),
        })?;
        backup = Some(match &resumed {
            // The state may be the new release's by now.
            Some(resumed) => resumed.backup.clone(),
            None => backup_state(&current, changed.is_some())?,
        });
        // Compared with the state --restore-state returns to, the one from
        // before the upgrade to this release: a reinstall keeps it, and the
        // previous release still cannot read what this one migrated.
        restore = fs::canonicalize(Path::new(BACKUPS).join(LAST))
            .is_ok_and(|last| rollback::schema_rises(&last));
        // From here on, a run that is killed leaves an upgrade that the
        // next run finishes.
        if let (Some(from), Some(backup)) = (changed, &backup) {
            unfinished::write(&Unfinished::Upgrade {
                from: from.to_owned(),
                to: release.clone(),
                previous: earlier.clone(),
                backup: backup.clone(),
            })?;
        }
        stop_services();
    }
    if let Err(error) = switch_to(&release, changed, configured) {
        if !configured {
            return Err(error);
        }
        // Garrison is stopped now: whatever failed, the release that ran goes
        // back, with the databases the new one migrated as they were before.
        let outcome = match changed {
            Some(old) => {
                announce("Start failed; switching back to the previous release.");
                match fallback::switch_back(old, earlier.as_deref(), &release, backup.as_deref()) {
                    Ok(()) => match unfinished::done() {
                        Ok(()) => "the previous release is running".to_owned(),
                        Err(error) => format!("the previous release is running, but {error}"),
                    },
                    Err(failure) => failure,
                }
            }
            None => "no other release was started".to_owned(),
        };
        return Err(format!(
            "The new release did not start ({error}); {outcome}. See the journal."
        ));
    }
    unfinished::done()?;
    if !configured {
        return first_install_help();
    }
    let backups = Path::new(BACKUPS);
    for line in housekeeping::prune(base, backups, &backups.join(LAST)) {
        announce(&line);
    }
    // Only where `previous` names another release is there one to return to.
    let previous = fs::canonicalize(base.join("previous")).ok();
    if previous.is_none_or(|previous| previous == release) {
        announce(&format!("Garrison {version} is running."));
        return Ok(());
    }
    // The release before cannot read a database this one migrates. Name the
    // rollback that works now, not only when a plain `--rollback` refuses.
    announce(&format!(
        "Garrison {version} is running. Roll back with: {} install --rollback{}",
        command::name(),
        if restore { " --restore-state" } else { "" }
    ));
    if restore {
        announce(
            "This upgrade changes a database schema: a rollback returns to the data \
             from before it, and what was recorded since is lost.",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The copy of the configuration in a backup keeps the modes the
    /// services read it by, so that a file put back from it with its mode,
    /// as with `mv` or `cp -p`, is read again; the credentials stay out.
    #[test]
    fn a_configuration_copy_keeps_the_modes_of_its_files() {
        let directory = tempfile::tempdir().unwrap();
        let (source, target) = (directory.path().join("etc"), directory.path().join("copy"));
        fs::create_dir_all(source.join("credentials")).unwrap();
        fs::write(source.join("garrison.toml"), "schema = 1\n").unwrap();
        fs::write(source.join("private.toml"), "kept = true\n").unwrap();
        fs::write(source.join("credentials/broker-native-key"), "secret").unwrap();
        let set = |name: &str, mode: u32| {
            fs::set_permissions(source.join(name), fs::Permissions::from_mode(mode)).unwrap();
        };
        set("garrison.toml", 0o644);
        set("private.toml", 0o600);
        copy_config(&source, &target).unwrap();
        let mode = |name: &str| {
            fs::metadata(target.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("garrison.toml"), 0o644);
        assert_eq!(mode("private.toml"), 0o600);
        assert!(!target.join("credentials").exists());
    }
}
