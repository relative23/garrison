//! The states of `garrison access`: its refusals, what it says of a change,
//! and the reasons it judges a role by.

use std::fmt::Display;
use std::io;
use std::path::Path;

use garrison_authz::SUPPORTED;

pub(crate) use super::roles::*;
use crate::access::{MAX_POLICY, way_out};
use crate::state::State;

pub(crate) fn invalid_profile(value: &str) -> State {
    State::new(
        "access-invalid-profile",
        format!("invalid profile name '{value}'"),
    )
}

pub(crate) fn not_a_file(path: &Path) -> State {
    State::new(
        "access-not-a-file",
        format!(
            "{} is a link or a folder, not a file: remove it; then `garrison access init` makes \
             the file itself there.",
            path.display()
        ),
    )
}

pub(crate) fn missing(path: &Path) -> State {
    State::new(
        "access-missing",
        format!(
            "The access policy {} is missing: `garrison access init` makes it.",
            path.display()
        ),
    )
}

pub(crate) fn too_large(path: &Path) -> State {
    State::new(
        "access-too-large",
        format!(
            "The access policy {} is larger than the broker reads ({} KiB), so it is no policy: \
             {}.",
            path.display(),
            MAX_POLICY / 1024,
            way_out(path)
        ),
    )
}

/// `why`: what Stalwart answered that this release does not read.
pub(crate) fn unread_answer(why: &str) -> State {
    State::new(
        "access-unread-answer",
        format!(
            "Stalwart answered in a form this release of Garrison does not read ({why}); \
             {SUPPORTED}"
        ),
    )
}

pub(crate) fn no_object() -> State {
    State::new("access-no-object", "Stalwart returned no object")
}

/// The authorization's refusals, each in its own words: Stalwart could not
/// be reached, ...
pub(crate) fn unavailable(why: String) -> State {
    State::new("access-unavailable", why)
}

/// ... it limits how often it is asked, ...
pub(crate) fn limited(why: String) -> State {
    State::new("access-limited", why)
}

/// ... the token is not one Stalwart takes, ...
pub(crate) fn invalid_token(why: String) -> State {
    State::new("access-invalid-token", why)
}

/// ... the policy grants nothing, ...
pub(crate) fn denied(why: String) -> State {
    State::new("access-denied", why)
}

/// ... or Garrison is not set up to ask.
pub(crate) fn misconfigured(why: String) -> State {
    State::new("access-misconfigured", why)
}

/// The policy names the actions `gone`, which garrison.toml no longer has.
pub(crate) fn actions_gone(path: &Path, gone: &[String]) -> State {
    State::new(
        "access-actions-gone",
        format!(
            "The access policy {} names {}, which garrison.toml no longer has: run `garrison \
             access update`, which takes {} out of the profiles.",
            path.display(),
            gone.join(", "),
            if gone.len() == 1 { "it" } else { "them" }
        ),
    )
}

/// What went wrong with `path`, and for an operator who is not root that
/// the command is root's.
pub(crate) fn io(path: &Path, error: impl Into<io::Error>) -> State {
    let error: io::Error = error.into();
    let hint = if error.kind() == io::ErrorKind::PermissionDenied
        && !rustix::process::geteuid().is_root()
    {
        "; run `garrison access` as root"
    } else {
        ""
    };
    State::new("access-io", format!("{}: {error}{hint}", path.display()))
}

/// `error`: what keeps the policy from reading, in the policy's own words.
pub(crate) fn invalid_policy(error: impl Display) -> State {
    State::new("access-invalid-policy", error.to_string())
}

/// `error`: why the policy's file could not be read.
pub(crate) fn unread_policy(error: impl Display) -> State {
    State::new(
        "access-unread-policy",
        format!("Garrison access policy: {error}"),
    )
}

pub(crate) fn save_too_large(path: &Path) -> State {
    State::new(
        "access-save-too-large",
        format!(
            "The policy would be larger than the broker reads ({} KiB): the change is not saved, \
             and {} stays as it is.",
            MAX_POLICY / 1024,
            path.display()
        ),
    )
}

pub(crate) fn no_group(policy: &Path) -> State {
    State::new(
        "access-no-group",
        format!(
            "Note: the broker cannot read {}: this host has no group garrison-broker. Run the \
             installer, which makes the group and gives it the policy.",
            policy.display()
        ),
    )
}

pub(crate) fn not_chowned(policy: &Path, error: impl Display) -> State {
    State::new(
        "access-not-chowned",
        format!(
            "Note: the broker cannot read {}: it could not be made root's with the group \
             garrison-broker ({error}). Run the command as root, or the installer again, which \
             does.",
            policy.display()
        ),
    )
}

/// The policy is saved; `backup`, where the previous file is kept.
pub(crate) fn saved(path: &Path, backup: Option<&Path>) -> State {
    let text = match backup {
        Some(backup) => format!(
            "Saved {}; the previous file is kept as {}.",
            path.display(),
            backup.display()
        ),
        None => format!("Saved {}", path.display()),
    };
    State::new("access-saved", text)
}

pub(crate) fn actions_held() -> State {
    State::new(
        "access-actions-held",
        "The profiles have the actions garrison.toml names; nothing to change.",
    )
}

pub(crate) fn profile_changed(name: &str, added: &[&str], taken: &[&str]) -> State {
    let said: Vec<String> = [(added, "added"), (taken, "taken out")]
        .into_iter()
        .filter(|(actions, _)| !actions.is_empty())
        .map(|(actions, what)| format!("{} {what}", actions.join(", ")))
        .collect();
    State::new(
        "access-profile-changed",
        format!("Profile {name}: {}.", said.join(", ")),
    )
}

pub(crate) fn run_installer() -> State {
    State::new(
        "access-run-installer",
        "Run the installer again now: it writes the polkit rule for these actions and restarts \
         the broker and the web service, which read them only when they start; until then an \
         added action is offered to nobody.",
    )
}

pub(crate) fn exists(path: &Path) -> State {
    State::new(
        "access-exists",
        format!(
            "{} exists; use --force to replace it (a backup is kept).",
            path.display()
        ),
    )
}

pub(crate) fn unknown_profile(profile: &str, known: &[&str]) -> State {
    State::new(
        "access-unknown-profile",
        format!("Unknown profile {profile}; known: {}", known.join(", ")),
    )
}

pub(crate) fn no_subject(subject: &str) -> State {
    State::new(
        "access-no-subject",
        format!(
            "{subject:?} is no subject: a subject is 1 to 128 letters, digits and _ . : @ -, and \
             that of a local Stalwart account its numeric account ID."
        ),
    )
}

pub(crate) fn no_file_name(policy: &Path) -> State {
    State::new(
        "access-no-file-name",
        format!("broker.policy names no file: {}", policy.display()),
    )
}

pub(crate) fn lock_link(lock: &Path) -> State {
    State::new(
        "access-lock-link",
        format!(
            "{} is a link, not the lock of `garrison access`: remove it, then run the command \
             again.",
            lock.display()
        ),
    )
}

pub(crate) fn lock_not_a_file(lock: &Path) -> State {
    State::new(
        "access-lock-not-a-file",
        format!(
            "{} is not a file, so not the lock of `garrison access`: remove it, then run the \
             command again.",
            lock.display()
        ),
    )
}

pub(crate) fn lock_foreign(lock: &Path) -> State {
    State::new(
        "access-lock-foreign",
        format!(
            "{} is another user's file, not the lock of `garrison access`: remove it, then run \
             the command again.",
            lock.display()
        ),
    )
}

pub(crate) fn lock_linked(lock: &Path) -> State {
    State::new(
        "access-lock-linked",
        format!(
            "{} has another name too (a hard link), so it is not the lock of `garrison access`: \
             remove it, then run the command again.",
            lock.display()
        ),
    )
}

pub(crate) fn lock_held(lock: &Path) -> State {
    State::new(
        "access-lock-held",
        format!(
            "{} is held by another process, as another `garrison access` command: try again once \
             it has ended. Where none runs, remove the file and run the command again.",
            lock.display()
        ),
    )
}

pub(crate) fn no_backup_name(policy: &Path) -> State {
    State::new(
        "access-no-backup-name",
        format!(
            "No backup of {} could be kept: every name for one of this second is taken.",
            policy.display()
        ),
    )
}

pub(crate) fn pending_folder(path: &Path) -> State {
    State::new(
        "access-pending-folder",
        format!(
            "{} is a folder, not the file `garrison access` writes the policy to first: remove \
             it, then run the command again.",
            path.display()
        ),
    )
}
