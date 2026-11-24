//! `garrison install` of an unpacked release: the first installation, an
//! upgrade or a reinstall.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use garrison_core::config;

use super::files::{Step, announce, fresh_folder, io, lock, place, switch};
use super::requirements::{base_shown, preflight, room, size, state_size};
use super::services::{self, check_config, start, stop_services};
use super::system::{install_system_files, protect_policy, unit_file};
use super::unpack::{clear_staging, install_release, unpacked_as};
use super::{
    BACKUPS, BASE, CONFIG, LAST, LOCK, cli, command, configured, fallback, here, housekeeping,
    leftover, name, rollback, verify,
};
use crate::{say, units};

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
                name(&running)
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

/// Make `release` current and `old`, the release current named where it
/// was another, previous; install the system files; and start the release
/// where it is `renewed` (another release, or other files of it), where
/// anything changed, or where a service does not run as `start` leaves it.
/// Whether it started the release.
fn bring_up(release: &Path, old: Option<&Path>, renewed: bool) -> Step<bool> {
    let base = Path::new(BASE);
    if let Some(old) = old {
        switch(&base.join("previous"), old)?;
    }
    switch(&base.join("current"), release)?;
    let mut changed = install_system_files(release)?;
    changed |= services::keep_secret_files()?;
    let milter = config::load(&Path::new(CONFIG).join("garrison.toml"))
        .is_ok_and(|config| config.milter.is_some())
        && unit_file(units::MILTER).exists();
    if !renewed && !changed && services::as_installed(milter) {
        // Its warnings, as a start passes them on. It passed a moment ago,
        // and a run that changes nothing stops nothing for it.
        let _ = check_config(release, true);
        return Ok(false);
    }
    start(release)?;
    Ok(true)
}

/// Why `release` did not run, and what the run did then: where another
/// release, `old`, ran when the run began, it goes back to it with `backup`,
/// the copy it made; otherwise it stops what did start and names the
/// rollback.
fn not_started(
    error: &str,
    release: &Path,
    old: Option<&Path>,
    earlier: Option<&Path>,
    ran: bool,
    backup: Option<&Path>,
) -> String {
    let outcome = match old {
        Some(old) if ran => {
            announce("Start failed; switching back to the previous release.");
            match fallback::switch_back(old, earlier, release, backup) {
                Ok(()) => "the previous release is running".to_owned(),
                Err(failure) => failure,
            }
        }
        Some(old) => {
            stop_services();
            format!(
                "{} did not run when this run began, so it was not started again; `{} install \
                 --rollback` returns to it",
                name(old),
                command::name()
            )
        }
        None => {
            stop_services();
            match earlier.filter(|earlier| *earlier != release) {
                Some(earlier) => format!(
                    "it was stopped; `{} install --rollback` returns to {}",
                    command::name(),
                    name(earlier)
                ),
                None => "it was stopped, and there is no other release to return to".to_owned(),
            }
        }
    };
    format!(
        "Garrison {} did not start ({error}); {outcome}. See the journal.",
        name(release)
    )
}

pub(super) fn install() -> Step {
    // Root first: without it the release may not even be readable.
    preflight()?;
    base_shown()?;
    let here = here()?;
    let version = verify::verify(&here)?;
    let _held = lock(Path::new(LOCK))?;
    let left = leftover()?;
    let base = Path::new(BASE);
    let old = fs::canonicalize(base.join("current")).ok();
    let earlier = fs::canonicalize(base.join("previous")).ok();
    let configured = configured(old.is_some());
    let target = base.join("releases").join(&version);
    let unpack = !unpacked_as(&here, &target);
    // As `old` is: where /opt is a link, the path under BASE and the one the
    // links resolve to differ, and a reinstall would pass for an upgrade.
    let changed = old
        .clone()
        .filter(|old| fs::canonicalize(&target).ok().as_ref() != Some(old));
    // The state is copied before another release, or other files of this
    // one, first start on it.
    let copy = configured && old.is_some() && (changed.is_some() || unpack);
    let mut needs = Vec::new();
    if unpack {
        needs.push((base, size(&here)));
    }
    if copy {
        needs.push((Path::new(BACKUPS), state_size()));
    }
    room(&needs, "the installation")?;
    let mut altered = clear_staging(&base.join("releases"))? || left;
    if unpack {
        install_release(&here, &version)?;
        altered = true;
    }
    let release = fs::canonicalize(&target).unwrap_or(target);
    if !configured {
        if let Some(old) = &changed {
            switch(&base.join("previous"), old)?;
        }
        switch(&base.join("current"), &release)?;
        install_system_files(&release)?;
        return first_install_help();
    }
    // The installer sets the policy's owner and mode anyway; the check must
    // not refuse what it is about to correct.
    altered |= protect_policy()
        .map_err(|error| format!("{error}; the running release was not touched"))?;
    // A configuration the new release refuses leaves the running one alone.
    check_config(&release, false)
        .map_err(|error| format!("{error}; the running release was not touched"))?;
    let ran = services::runs();
    // The installer's backups are kept here from the first start on, and
    // the operator's backup job takes the folder in.
    if fs::symlink_metadata(BACKUPS).is_err() {
        let mut private = fs::DirBuilder::new();
        private.recursive(true).mode(0o700);
        io(private.create(BACKUPS), Path::new(BACKUPS))?;
        altered = true;
    }
    let backup = if copy {
        Some(backup_state(&base.join("current"), changed.is_some())?)
    } else {
        None
    };
    // Compared with the state --restore-state returns to, the one from
    // before the upgrade to this release: a reinstall keeps it, and the
    // previous release still cannot read what this one migrated.
    let restore = fs::canonicalize(Path::new(BACKUPS).join(LAST))
        .is_ok_and(|last| rollback::schema_rises(&last));
    let renewed = changed.is_some() || unpack;
    if renewed {
        stop_services();
    }
    match bring_up(&release, changed.as_deref(), renewed) {
        Ok(started) => altered |= started,
        Err(error) => {
            let (old, earlier) = (changed.as_deref(), earlier.as_deref());
            return Err(not_started(
                &error,
                &release,
                old,
                earlier,
                ran,
                backup.as_deref(),
            ));
        }
    }
    let backups = Path::new(BACKUPS);
    for line in housekeeping::prune(base, backups, &backups.join(LAST)) {
        announce(&line);
        altered = true;
    }
    last_line(&version, &release, restore, altered);
    Ok(())
}

/// The run's last line: `release` runs, and nothing was changed where the run
/// `altered` nothing. Only where `previous` names another release is there
/// one to return to; the release before cannot read a database this one
/// migrates, so the rollback that works is named now, not only when a plain
/// `--rollback` refuses.
fn last_line(version: &str, release: &Path, restore: bool, altered: bool) {
    let previous = fs::canonicalize(Path::new(BASE).join("previous")).ok();
    let back = previous
        .filter(|previous| previous != release)
        .map(|_| {
            format!(
                " Roll back with: {} install --rollback{}",
                command::name(),
                if restore { " --restore-state" } else { "" }
            )
        })
        .unwrap_or_default();
    if !altered {
        announce(&format!(
            "Garrison {version} is running as installed; nothing was changed.{back}"
        ));
        return;
    }
    announce(&format!("Garrison {version} is running.{back}"));
    if restore && !back.is_empty() {
        announce(
            "This upgrade changes a database schema: a rollback returns to the data \
             from before it, and what was recorded since is lost.",
        );
    }
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
