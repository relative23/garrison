//! What a restore of the state checks before anything stops, for
//! `garrison restore` and `install --rollback --restore-state` alike: the
//! release that will start takes today's configuration with the access
//! policy the state puts back, that policy can go where the broker reads
//! it, and every copy fits beside the database it replaces.
//!
//! The release that will start is the judge, also an older one a rollback
//! returns to: its own `check-config` reads today's `garrison.toml` and then
//! a copy of it whose `broker.policy` names the policy that comes back.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Output;

use garrison_core::config::{self, Config, Database};

use super::files::{Step, io, place, run};
use super::requirements::{room, size};
use super::{CONFIG, cli, toml_text};

/// Where a release's check of the policy that comes back is prepared:
/// root's alone; the installer's lock keeps a second run out.
const CHECK: &str = "/run/garrison-install.check";

/// What `check-config` said, both streams: releases differ in which one.
fn said(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
    .trim()
    .to_owned()
}

/// Whether the state in `source` brings an access policy, which then
/// replaces the live one.
pub(super) fn brings_policy(source: &Path) -> bool {
    source.join(crate::ops::POLICY_COPY).is_file()
}

/// `release`'s check-config of today's configuration. Where the state
/// brings a policy, the verdict on the live one, which goes, is left to
/// the check of the policy that comes back: every release exits with 1
/// where only the policy fails, and with 2 for the configuration.
pub(super) fn configuration(release: &Path, policy_comes_back: bool) -> Step<Result<(), String>> {
    let check = cli(release, &["check-config"])?;
    Ok(match check.status.code() {
        Some(0) => Ok(()),
        Some(1) if policy_comes_back => Ok(()),
        _ => Err(said(&check)),
    })
}

/// The place `broker.policy` names takes the policy that comes back as a
/// file of its own: nothing there yet or a file, never a link or a folder,
/// in a folder that exists, where the broker's unit does not hide it.
pub(super) fn policy_place(config: &Config) -> Step {
    let policy = &config.broker.policy;
    match fs::symlink_metadata(policy) {
        Ok(kind) if !kind.is_file() => {
            return Err(format!(
                "broker.policy names {}, which is not a file of its own: the access policy \
                 goes back only as a file, never through a link or into a folder.",
                policy.display()
            ));
        }
        Err(error) if error.kind() != ErrorKind::NotFound => {
            return Err(format!("{}: {error}", policy.display()));
        }
        _ => {}
    }
    if !policy.parent().is_some_and(Path::is_dir) {
        return Err(format!(
            "The folder of broker.policy, {}, does not exist.",
            policy.parent().unwrap_or(policy).display()
        ));
    }
    if let Err(refusal) = crate::units::policy_place(policy, Path::new(config::DEFAULT_PATH)) {
        return Err(format!("Access policy not usable: {refusal}"));
    }
    Ok(())
}

/// `release`'s check-config of today's configuration with the policy the
/// state in `source` brings in place of the live one.
pub(super) fn policy_comes_back(release: &Path, source: &Path) -> Step<Result<(), String>> {
    let settings = Path::new(CONFIG).join("garrison.toml");
    checked_in(Path::new(CHECK), &settings, release, source)
}

/// The check in `folder`, made for it and removed after it: a copy of the
/// configuration at `settings` that names a copy of the policy.
fn checked_in(
    folder: &Path,
    settings: &Path,
    release: &Path,
    source: &Path,
) -> Step<Result<(), String>> {
    let _ = fs::remove_dir_all(folder);
    io(fs::DirBuilder::new().mode(0o700).create(folder), folder)?;
    let checked = check_in(folder, settings, release, source);
    let _ = fs::remove_dir_all(folder);
    checked
}

fn check_in(
    folder: &Path,
    settings: &Path,
    release: &Path,
    source: &Path,
) -> Step<Result<(), String>> {
    let text = io(fs::read_to_string(settings), settings)?;
    let mut table: toml::Table = text
        .parse()
        .map_err(|error| format!("{}: {error}", settings.display()))?;
    let copy = folder.join("access-policy.json");
    place(&source.join(crate::ops::POLICY_COPY), &copy, 0o600)?;
    if let Some(broker) = table
        .entry("broker")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
    {
        broker.insert(
            "policy".into(),
            toml::Value::String(copy.display().to_string()),
        );
    }
    let written = folder.join("garrison.toml");
    io(fs::write(&written, toml_text::document(&table)), &written)?;
    io(
        fs::set_permissions(&written, fs::Permissions::from_mode(0o600)),
        &written,
    )?;
    let binary = release.join("bin/garrison").display().to_string();
    let check = run(
        &binary,
        &["--config", &written.display().to_string(), "check-config"],
    )?;
    Ok(if check.status.success() {
        Ok(())
    } else {
        Err(said(&check))
    })
}

/// Room for every copy in `source` beside the database it replaces, which
/// goes only once the copy is whole, and for what `besides` names.
pub(super) fn copies_fit(source: &Path, config: &Config, besides: &[(&Path, u64)]) -> Step {
    let folders: Vec<(PathBuf, u64)> = Database::ALL
        .into_iter()
        .filter_map(|database| {
            let copy = source.join(database.writer()).join(database.file_name());
            let folder = config.database(database).parent()?.to_owned();
            Some((folder, size(&copy)))
        })
        .collect();
    let mut needs: Vec<(&Path, u64)> = folders
        .iter()
        .map(|(folder, bytes)| (folder.as_path(), *bytes))
        .collect();
    needs.extend_from_slice(besides);
    room(&needs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_goes_back_only_where_a_file_of_its_own_can_be() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = garrison_testing::config(directory.path(), "http://127.0.0.1:9");
        fs::create_dir_all(config.broker.policy.parent().unwrap()).unwrap();
        // A link or a folder named as the policy stays as it is.
        let victim = directory.path().join("passwd");
        fs::write(&victim, "root:x:0:0::/root:/bin/sh\n").unwrap();
        std::os::unix::fs::symlink(&victim, &config.broker.policy).unwrap();
        let refused = policy_place(&config).unwrap_err();
        assert!(refused.contains("not a file of its own"), "{refused}");
        fs::remove_file(&config.broker.policy).unwrap();
        fs::create_dir(&config.broker.policy).unwrap();
        assert!(
            policy_place(&config)
                .unwrap_err()
                .contains("not a file of its own")
        );
        // A folder that does not exist takes nothing.
        config.broker.policy = directory.path().join("absent/access.json");
        assert!(
            policy_place(&config)
                .unwrap_err()
                .contains("does not exist")
        );
    }

    /// A release whose check-config runs `script` with its arguments.
    fn release(script: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("bin")).unwrap();
        let binary = directory.path().join("bin/garrison");
        fs::write(&binary, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        directory
    }

    /// Exit status 1 is the policy's alone, in every release: it does not
    /// count where the state brings its own policy, and 2 always does.
    #[test]
    fn the_live_policy_does_not_count_where_the_state_brings_one() {
        let policy_only = release("echo 'Access policy not usable: unknown actions' >&2; exit 1");
        assert_eq!(configuration(policy_only.path(), true), Ok(Ok(())));
        let refused = configuration(policy_only.path(), false)
            .unwrap()
            .unwrap_err();
        assert_eq!(refused, "Access policy not usable: unknown actions");
        let configuration_too = release(
            "echo 'Configuration valid: 1 providers' ; echo 'Configuration not usable: [x]' >&2; exit 2",
        );
        let refused = configuration(configuration_too.path(), true)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refused,
            "Configuration valid: 1 providers\nConfiguration not usable: [x]"
        );
        assert_eq!(configuration(release("exit 0").path(), false), Ok(Ok(())));
    }

    /// The release is handed today's configuration with only `broker.policy`
    /// changed, naming a copy of the policy the state brings, both root's
    /// alone; its verdict decides, and nothing of the check is left.
    #[test]
    fn the_policy_that_comes_back_is_judged_with_todays_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let settings = directory.path().join("garrison.toml");
        let text = garrison_testing::config_text(directory.path(), "http://127.0.0.1:9");
        fs::write(&settings, &text).unwrap();
        let source = directory.path().join("backup");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join(crate::ops::POLICY_COPY),
            "{\"from\": \"the backup\"}",
        )
        .unwrap();
        let seen = directory.path().join("seen");
        let folder = directory.path().join("check");
        let looking = release(&format!(
            "test \"$1 $3\" = '--config check-config' && cp -r \"$(dirname \"$2\")\" {}",
            seen.display()
        ));
        assert_eq!(
            checked_in(&folder, &settings, looking.path(), &source),
            Ok(Ok(()))
        );
        assert!(!folder.exists());
        let handed: toml::Table = fs::read_to_string(seen.join("garrison.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let mut expected: toml::Table = text.parse().unwrap();
        expected["broker"]["policy"] =
            toml::Value::String(folder.join("access-policy.json").display().to_string());
        assert_eq!(handed, expected);
        let copy = fs::read_to_string(seen.join("access-policy.json")).unwrap();
        assert_eq!(copy, "{\"from\": \"the backup\"}");
        for name in ["garrison.toml", "access-policy.json"] {
            let mode = fs::metadata(seen.join(name)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
        let refusing =
            release("echo 'Access policy not usable: unknown actions: run_check' >&2; exit 1");
        let refused = checked_in(&folder, &settings, refusing.path(), &source)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refused,
            "Access policy not usable: unknown actions: run_check"
        );
        assert!(!folder.exists());
    }

    /// A copy larger than the room beside its database is refused before
    /// anything stops; a sparse file stands in for a large database.
    #[test]
    fn every_copy_must_fit_beside_its_database() {
        let directory = tempfile::tempdir().unwrap();
        let config =
            garrison_testing::config(&directory.path().join("state"), "http://127.0.0.1:9");
        for database in Database::ALL {
            fs::create_dir_all(config.database(database).parent().unwrap()).unwrap();
        }
        let source = directory.path().join("backup");
        fs::create_dir_all(source.join("ingest")).unwrap();
        let copy = fs::File::create(source.join("ingest/events.sqlite")).unwrap();
        copy.set_len(4096).unwrap();
        copies_fit(&source, &config, &[]).unwrap();
        let stat = rustix::fs::statvfs(directory.path()).unwrap();
        copy.set_len(stat.f_bavail * stat.f_frsize).unwrap();
        let refused = copies_fit(&source, &config, &[]).unwrap_err();
        assert!(refused.ends_with("; nothing was changed."), "{refused}");
    }
}
