//! The states of the rollback, the restore, the copies of the state they
//! put back, and the uninstallation.

use std::fmt::Display;
use std::path::Path;

use crate::install::{BACKUPS, BASE, CONFIG, LAST};
use crate::state::{State, states};

states! {
    pub(crate) fn no_previous() = "install-no-previous":
        "There is no previous release to return to.";
    pub(crate) fn no_other_release() = "install-no-other-release":
        "There is no other release to return to: {BASE}/previous names the release \
         {BASE}/current names. A rollback cut short is finished by the installer its first \
         line named.";
    pub(crate) fn no_state(last: &Path) = "install-no-state":
        "There is no state from before an upgrade to restore ({}); nothing was changed.",
        last.display();
    /// The state in `source` was written by a release newer than `target`.
    pub(crate) fn state_newer(source: &Path, written_by: &str, target: &str)
        = "install-state-newer":
        "The state in {} was written by Garrison {written_by}, which is newer than {target}; \
         {target} cannot read it. Nothing was changed.", source.display();
    pub(crate) fn no_broker_group() = "install-no-broker-group":
        "The group garrison-broker, which reads the access policy, does not exist; the installer \
         makes it. Nothing was changed.";
    /// `said`: what the check-config of `name`, the release a rollback returns
    /// to, said.
    pub(crate) fn rollback_unloadable(name: &str, said: &str) = "install-rollback-unloadable":
        "{name} cannot load {CONFIG}/garrison.toml:\n{said}\nRemove the settings {name} does \
         not know, or put back the file from before the upgrade \
         ({BACKUPS}/{LAST}/etc/garrison.toml), then roll back.";
    /// `unreadable`: the databases the self-check of `name` cannot read.
    pub(crate) fn rollback_unreadable(name: &str, unreadable: &str) = "install-rollback-unreadable":
        "{name} cannot read the current data, as its self-check says of {unreadable}. Roll \
         back with --restore-state to return to the data from before the upgrade.";
    pub(crate) fn rollback_policy(source: &Path, settings: &Path, target: &str, said: &str)
        = "install-rollback-policy":
        "The access policy from before the upgrade, in {}, does not suit {}, as {target}'s \
         check-config says:\n{said}\nNothing was changed.", source.display(), settings.display();
    /// The rollback's first line; `command` finishes a rollback cut short.
    pub(crate) fn rolling_back(name: &str, command: &str) = "install-rolling-back":
        "Rolling back to {name}."
        => "If this is interrupted, run it again: {command}";
    /// The rollback to `name` failed for `error` while `name` was current
    /// already, and it is stopped; `went`, what went back.
    pub(crate) fn rollback_stopped(error: &State, name: &str, went: Option<&State>)
        = "install-rollback-stopped":
        "The rollback failed ({error}); {name} is stopped.{} See the journal.", also(went);
    pub(crate) fn rollback_returned(error: &State, went: Option<&State>)
        = "install-rollback-returned":
        "The rollback failed ({error}); the release that ran before is running again.{} See \
         the journal.", also(went);
    pub(crate) fn rollback_neither(error: &State, went: Option<&State>)
        = "install-rollback-neither":
        "The rollback failed ({error}); the release that ran before did not start either.{} \
         See the journal.", also(went);
    pub(crate) fn rolled_back(name: &str) = "install-rolled-back":
        "Rolled back to {name}.";
    pub(crate) fn not_a_backup(from: &Path) = "install-not-a-backup":
        "{} is no backup that `garrison backup` wrote (no backup.json there); nothing was \
         changed.", from.display();
    /// `said`: what the self-check of the copies said.
    pub(crate) fn copies_refused(place: &str, said: &str) = "install-copies-refused":
        "The copies in {place} did not pass `garrison self-check --state`; nothing was \
         changed.\n{said}";
    pub(crate) fn restore_config_refused(name: &str, settings: &Path, said: &str)
        = "install-restore-config-refused":
        "Garrison {name}'s check-config refuses {}; nothing was changed:\n{said}",
        settings.display();
    pub(crate) fn restore_policy(place: &str, settings: &Path, name: &str, said: &str)
        = "install-restore-policy":
        "The access policy in {place} does not suit {}, as Garrison {name}'s check-config \
         says; nothing was changed:\n{said}", settings.display();
    /// `why`: why the copy of the state as it is failed.
    pub(crate) fn keep_failed(why: impl Display) = "install-keep-failed":
        "The state as it is could not be backed up ({why}); nothing was changed.";
    pub(crate) fn restored(place: &str, name: &str, kept: &Path) = "install-restored":
        "Restored the state from {place}; Garrison {name} is running. Users sign in again: a \
         backup holds no sessions. The state from before is in {}.", kept.display();
    /// The restore failed for `error`, and Garrison runs on what went back.
    pub(crate) fn restore_failed(error: &State, went: Option<&State>, kept: &Path)
        = "install-restore-failed":
        "The restore failed ({error}); Garrison is running with what could be put back.{} The \
         state from before is in {}.", also(went), kept.display();
    pub(crate) fn restore_neither(error: &State, went: Option<&State>, kept: &Path)
        = "install-restore-neither":
        "The restore failed ({error}); Garrison did not start either.{} The state from before \
         is in {}.", also(went), kept.display();
    pub(crate) fn restore_unstarted(error: &State, kept: &Path) = "install-restore-unstarted":
        "The state was put back, but Garrison did not start ({error}). The state from before \
         is in {}; see the journal.", kept.display();
    /// The access policy as it goes back: `broker.policy` names something that
    /// is not a file, which stays as it is.
    pub(crate) fn policy_left(target: &Path) = "install-policy-left":
        "broker.policy names {}, which is not a file of its own; it was left as it is",
        target.display();
    pub(crate) fn policy_nameless(target: &Path) = "install-policy-nameless":
        "broker.policy names {}, which is no file's name", target.display();
    /// Before anything stops: the policy that comes back cannot go where
    /// `broker.policy` names it.
    pub(crate) fn policy_place(policy: &Path) = "install-policy-place":
        "broker.policy names {}, which is not a file of its own: the access policy goes back \
         only as a file, never through a link or into a folder. Nothing was changed.",
        policy.display();
    pub(crate) fn policy_folder(folder: &Path) = "install-policy-folder":
        "The folder of broker.policy, {}, does not exist. Nothing was changed.", folder.display();
    /// `refusal`: the units' account of the place they hide the policy in.
    pub(crate) fn policy_hidden(refusal: &str) = "install-policy-hidden":
        "Access policy not usable: {refusal} Nothing was changed.";
    pub(crate) fn policy_unknown(settings: &Path, error: impl Display) = "install-policy-unknown":
        "{} does not load, so an access policy it names outside {CONFIG} is not removed \
         ({error}); remove it yourself if there is one.", settings.display();
    pub(crate) fn needs_unshare(unshare: &str) = "install-needs-unshare":
        "{unshare} (util-linux) is needed to test nginx without Garrison's snippets; nothing \
         was changed";
    /// `said`: what nginx's test said.
    pub(crate) fn nginx_invalid(said: &str) = "install-nginx-invalid":
        "nginx would not start without Garrison's snippets; nothing was changed. Remove the \
         `include /etc/nginx/snippets/garrison…` lines from your server blocks first:\n{said}";
}

/// What went back to its copy in `source` and what was removed, as it did
/// not exist then; none where nothing changed.
pub(crate) fn went_back(source: &Path, back: &[&str], removed: &[&str]) -> Option<State> {
    let back = (!back.is_empty()).then(|| {
        format!(
            "These went back to their copies in {}: {}.",
            source.display(),
            back.join(", ")
        )
    });
    let removed = (!removed.is_empty()).then(|| {
        format!(
            "Removed, as they did not exist then: {}.",
            removed.join(", ")
        )
    });
    let said: Vec<String> = back.into_iter().chain(removed).collect();
    (!said.is_empty()).then(|| State::new("install-went-back", said.join(" ")))
}

/// `went` as the sentences after another's.
fn also(went: Option<&State>) -> String {
    went.map_or_else(String::new, |went| format!(" {went}"))
}

pub(crate) fn policy_unreachable(target: &Path, error: impl Display) -> State {
    super::io(
        format_args!("broker.policy names {}", target.display()),
        error,
    )
}
