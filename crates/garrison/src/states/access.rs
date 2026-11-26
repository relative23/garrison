//! The states of `garrison access`: its refusals, what it says of a change,
//! and the reasons it judges a role by.

use std::fmt::Display;
use std::io;
use std::path::Path;

use garrison_authz::SUPPORTED;

pub(crate) use super::roles::*;
use crate::access::{MAX_POLICY, way_out};
use crate::state::{State, states};

states! {
    pub(crate) fn invalid_profile(value: &str) = "access-invalid-profile":
        "invalid profile name '{value}'";
    pub(crate) fn not_a_file(path: &Path) = "access-not-a-file":
        "{} is a link or a folder, not a file: remove it; then `garrison access init` makes \
         the file itself there.", path.display();
    pub(crate) fn missing(path: &Path) = "access-missing":
        "The access policy {} is missing: `garrison access init` makes it.", path.display();
    pub(crate) fn too_large(path: &Path) = "access-too-large":
        "The access policy {} is larger than the broker reads ({} KiB), so it is no policy: \
         {}.", path.display(), MAX_POLICY / 1024, way_out(path);
    /// `why`: what Stalwart answered that this release does not read.
    pub(crate) fn unread_answer(why: &str) = "access-unread-answer":
        "Stalwart answered in a form this release of Garrison does not read ({why}); \
         {SUPPORTED}";
    pub(crate) fn no_object() = "access-no-object":
        "Stalwart returned no object";
    /// The policy names the actions `gone`, which garrison.toml no longer has.
    pub(crate) fn actions_gone(path: &Path, gone: &[String]) = "access-actions-gone":
        "The access policy {} names {}, which garrison.toml no longer has: run `garrison \
         access update`, which takes {} out of the profiles.", path.display(), gone.join(", "),
        if gone.len() == 1 { "it" } else { "them" };
    /// `error`: why the policy's file could not be read.
    pub(crate) fn unread_policy(error: impl Display) = "access-unread-policy":
        "Garrison access policy: {error}";
    pub(crate) fn save_too_large(path: &Path) = "access-save-too-large":
        "The policy would be larger than the broker reads ({} KiB): the change is not saved, \
         and {} stays as it is.", MAX_POLICY / 1024, path.display();
    pub(crate) fn no_group(policy: &Path) = "access-no-group":
        "Note: the broker cannot read {}: this host has no group garrison-broker. Run the \
         installer, which makes the group and gives it the policy.", policy.display();
    pub(crate) fn not_chowned(policy: &Path, error: impl Display) = "access-not-chowned":
        "Note: the broker cannot read {}: it could not be made root's with the group \
         garrison-broker ({error}). Run the command as root, or the installer again, which \
         does.", policy.display();
    pub(crate) fn actions_held() = "access-actions-held":
        "The profiles have the actions garrison.toml names; nothing to change.";
    pub(crate) fn run_installer() = "access-run-installer":
        "Run the installer again now: it writes the polkit rule for these actions and restarts \
         the broker and the web service, which read them only when they start; until then an \
         added action is offered to nobody.";
    pub(crate) fn exists(path: &Path) = "access-exists":
        "{} exists; use --force to replace it (a backup is kept).", path.display();
    pub(crate) fn unknown_profile(profile: &str, known: &[&str]) = "access-unknown-profile":
        "Unknown profile {profile}; known: {}", known.join(", ");
    pub(crate) fn no_subject(subject: &str) = "access-no-subject":
        "{subject:?} is no subject: a subject is 1 to 128 letters, digits and _ . : @ -, and \
         that of a local Stalwart account its numeric account ID.";
    pub(crate) fn no_file_name(policy: &Path) = "access-no-file-name":
        "broker.policy names no file: {}", policy.display();
    pub(crate) fn lock_link(lock: &Path) = "access-lock-link":
        "{} is a link, not the lock of `garrison access`: remove it, then run the command \
         again.", lock.display();
    pub(crate) fn lock_not_a_file(lock: &Path) = "access-lock-not-a-file":
        "{} is not a file, so not the lock of `garrison access`: remove it, then run the \
         command again.", lock.display();
    pub(crate) fn lock_foreign(lock: &Path) = "access-lock-foreign":
        "{} is another user's file, not the lock of `garrison access`: remove it, then run \
         the command again.", lock.display();
    pub(crate) fn lock_linked(lock: &Path) = "access-lock-linked":
        "{} has another name too (a hard link), so it is not the lock of `garrison access`: \
         remove it, then run the command again.", lock.display();
    pub(crate) fn lock_held(lock: &Path) = "access-lock-held":
        "{} is held by another process, as another `garrison access` command: try again once \
         it has ended. Where none runs, remove the file and run the command again.", lock.display();
    pub(crate) fn no_backup_name(policy: &Path) = "access-no-backup-name":
        "No backup of {} could be kept: every name for one of this second is taken.",
        policy.display();
    pub(crate) fn pending_folder(path: &Path) = "access-pending-folder":
        "{} is a folder, not the file `garrison access` writes the policy to first: remove \
         it, then run the command again.", path.display();
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
