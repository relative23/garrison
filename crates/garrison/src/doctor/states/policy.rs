//! The states of the access policy's checks (`doctor/policy.rs`).

use std::path::Path;

use super::counted;
use crate::doctor::policy::{BROKER, DEFAULT};
use crate::state::State;

/// Why the broker does not take a policy: each as a policy's state names it.
pub(in crate::doctor) const FOREIGN: &str = "a user other than root and the broker owns it";
pub(in crate::doctor) const GROUP_WRITES: &str = "its group may change it";
pub(in crate::doctor) const OTHERS_READ: &str = "others may read it";
pub(in crate::doctor) const OTHERS_WRITE: &str = "others may change it";

/// Owner and group, `owner:group`, and mode of a file or a folder.
fn seen(owner: &str, mode: u32) -> String {
    format!("{owner}, mode {mode:o}")
}

/// What makes the policy at `path` root's, readable for the broker's group
/// alone, as the installer keeps it.
fn chown(path: &Path) -> String {
    format!(
        "Run `chown root:{BROKER} {0} && chmod 640 {0}`.",
        path.display()
    )
}

pub(in crate::doctor) fn missing(path: &Path) -> State {
    let text = format!("the access policy is missing: {}", path.display());
    State::new("doctor-policy-missing", text)
        .with_fix("Run `garrison access init`, which makes it.")
}

pub(in crate::doctor) fn not_a_file(path: &Path) -> State {
    let text = format!(
        "the access policy is a link or a folder, not a file: {}",
        path.display()
    );
    State::new("doctor-policy-not-a-file", text)
        .with_fix("Remove it; then `garrison access init` makes the file itself there.")
}

/// The broker does not take the policy at `path`, owned so with `mode`,
/// for each of `why`.
pub(in crate::doctor) fn refused(owner: &str, mode: u32, why: &[&str], path: &Path) -> State {
    let shown = seen(owner, mode);
    let text = format!(
        "the broker does not take the access policy ({shown}): {}, so nobody can sign in: \
         {}",
        why.join(", and "),
        path.display()
    );
    State::new("doctor-policy-refused", text).with_fix(chown(path))
}

pub(in crate::doctor) fn no_broker() -> State {
    let text =
        format!("whether the broker can read the access policy: this host has no user {BROKER}");
    State::new("doctor-policy-no-broker", text)
}

/// The broker may not enter `folder`, owned as `owner` with `mode`.
fn closed(folder: &Path, owner: &str, mode: u32) -> String {
    format!(
        "{BROKER} may not enter {} ({}), so it cannot read the access policy and nobody can sign \
         in",
        folder.display(),
        seen(owner, mode)
    )
}

/// Such a folder on the way to the default place, which the installer
/// makes 755.
pub(in crate::doctor) fn folder_closed(folder: &Path, owner: &str, mode: u32) -> State {
    State::new("doctor-policy-folder-closed", closed(folder, owner, mode))
        .with_fix(format!("Run `chmod 755 {}`.", folder.display()))
}

/// Such a folder elsewhere.
pub(in crate::doctor) fn folder_closed_elsewhere(folder: &Path, owner: &str, mode: u32) -> State {
    let text = closed(folder, owner, mode);
    State::new("doctor-policy-folder-closed-elsewhere", text).with_fix(format!(
        "Move the policy to {DEFAULT} and set broker.policy to it."
    ))
}

pub(in crate::doctor) fn unreadable(owner: &str, mode: u32, path: &Path) -> State {
    let shown = seen(owner, mode);
    let text = format!(
        "{BROKER} may not read the access policy ({shown}), so nobody can sign in: {}",
        path.display()
    );
    State::new("doctor-policy-unreadable", text).with_fix(chown(path))
}

pub(in crate::doctor) fn broker_owner(owner: &str, mode: u32, path: &Path) -> State {
    let shown = seen(owner, mode);
    let text = format!(
        "{BROKER} owns the access policy ({shown}), which the installer keeps root's, so \
         that only root may change what it grants"
    );
    State::new("doctor-policy-broker-owner", text).with_fix(chown(path))
}

pub(in crate::doctor) fn readable(owner: &str, mode: u32) -> State {
    let shown = seen(owner, mode);
    let text =
        format!("the broker may read the access policy, which only root may change ({shown})");
    State::new("doctor-policy-readable", text)
}

/// The policy at `path` is larger than the `kib` the broker reads.
pub(in crate::doctor) fn too_large(path: &Path, kib: usize) -> State {
    let mut fix = crate::access::way_out(path);
    fix.replace_range(..1, &fix[..1].to_uppercase());
    let text = format!(
        "the access policy is larger than the broker reads ({kib} KiB), so nobody can sign \
         in: {}",
        path.display()
    );
    State::new("doctor-policy-too-large", text).with_fix(format!("{fix}."))
}

pub(in crate::doctor) fn actions_dropped(actions: &[String]) -> State {
    let text = format!(
        "the access policy names actions garrison.toml does not have ({}), so nobody can \
         sign in",
        actions.join(", ")
    );
    State::new("doctor-policy-actions-dropped", text)
        .with_fix("Run `garrison access update`, which mends it.")
}

pub(in crate::doctor) fn invalid(why: &str) -> State {
    let text = format!("the access policy does not read ({why}), so nobody can sign in");
    State::new("doctor-policy-invalid", text)
        .with_fix("Correct it as docs/operator/access.md shows.")
}

pub(in crate::doctor) fn unbound() -> State {
    let text = "the access policy binds no role and no account, so nobody can sign in";
    State::new("doctor-policy-unbound", text).with_fix(
        "Bind the role of your administrators: garrison access bind-role <role-id> --profile \
         administrator",
    )
}

pub(in crate::doctor) fn bound(roles: usize, accounts: usize) -> State {
    let text = format!(
        "the access policy binds {} and {}",
        counted(roles, "role", "roles"),
        counted(accounts, "account", "accounts")
    );
    State::new("doctor-policy-bound", text)
}

/// A policy the broker's unit hides from it, in check-config's words.
pub(in crate::doctor) fn hidden((what, fix): (String, String)) -> State {
    State::new("doctor-policy-hidden", what).with_fix(format!("{fix}."))
}

#[cfg(test)]
pub(super) fn rows() -> Vec<(State, &'static str)> {
    [taken(), grants()].concat()
}

/// Whether the broker takes the policy's file.
#[cfg(test)]
fn taken() -> Vec<(State, &'static str)> {
    let path = Path::new("/etc/garrison/access-policy.json");
    vec![
        (
            missing(path),
            "the access policy is missing: /etc/garrison/access-policy.json \
             [doctor-policy-missing]\n      Run `garrison access init`, which makes it.",
        ),
        (
            not_a_file(path),
            "the access policy is a link or a folder, not a file: \
             /etc/garrison/access-policy.json [doctor-policy-not-a-file]\n      Remove it; then \
             `garrison access init` makes the file itself there.",
        ),
        (
            refused(
                "root:garrison-broker",
                0o664,
                &[GROUP_WRITES, OTHERS_READ],
                path,
            ),
            "the broker does not take the access policy (root:garrison-broker, mode 664): its \
             group may change it, and others may read it, so nobody can sign in: \
             /etc/garrison/access-policy.json [doctor-policy-refused]\n      Run `chown \
             root:garrison-broker /etc/garrison/access-policy.json && chmod 640 \
             /etc/garrison/access-policy.json`.",
        ),
        (
            no_broker(),
            "whether the broker can read the access policy: this host has no user \
             garrison-broker [doctor-policy-no-broker]",
        ),
        (
            folder_closed(Path::new("/etc/garrison"), "root:root", 0o700),
            "garrison-broker may not enter /etc/garrison (root:root, mode 700), so it cannot \
             read the access policy and nobody can sign in [doctor-policy-folder-closed]\n      \
             Run `chmod 755 /etc/garrison`.",
        ),
        (
            folder_closed_elsewhere(Path::new("/srv/private"), "root:root", 0o700),
            "garrison-broker may not enter /srv/private (root:root, mode 700), so it cannot read \
             the access policy and nobody can sign in [doctor-policy-folder-closed-elsewhere]\n      \
             Move the policy to /etc/garrison/access-policy.json and set broker.policy to it.",
        ),
        (
            unreadable("root:root", 0o600, path),
            "garrison-broker may not read the access policy (root:root, mode 600), so nobody can \
             sign in: /etc/garrison/access-policy.json [doctor-policy-unreadable]\n      Run \
             `chown root:garrison-broker /etc/garrison/access-policy.json && chmod 640 \
             /etc/garrison/access-policy.json`.",
        ),
        (
            broker_owner("garrison-broker:garrison-broker", 0o600, path),
            "garrison-broker owns the access policy (garrison-broker:garrison-broker, mode 600), \
             which the installer keeps root's, so that only root may change what it grants \
             [doctor-policy-broker-owner]\n      Run `chown root:garrison-broker \
             /etc/garrison/access-policy.json && chmod 640 /etc/garrison/access-policy.json`.",
        ),
        (
            readable("root:garrison-broker", 0o640),
            "the broker may read the access policy, which only root may change \
             (root:garrison-broker, mode 640) [doctor-policy-readable]",
        ),
    ]
}

/// What the policy grants, and where the broker's unit hides it.
#[cfg(test)]
fn grants() -> Vec<(State, &'static str)> {
    let path = Path::new("/etc/garrison/access-policy.json");
    vec![
        (
            too_large(path, 64),
            "the access policy is larger than the broker reads (64 KiB), so nobody can sign in: \
             /etc/garrison/access-policy.json [doctor-policy-too-large]\n      Move it away and \
             run `garrison access init`, or copy back the newest backup beside it \
             (/etc/garrison/access-policy.json.<time>.bak) with sudo cp where there is one.",
        ),
        (
            actions_dropped(&["run_reports".into()]),
            "the access policy names actions garrison.toml does not have (run_reports), so \
             nobody can sign in [doctor-policy-actions-dropped]\n      Run `garrison access \
             update`, which mends it.",
        ),
        (
            invalid("schemaVersion must be 1"),
            "the access policy does not read (schemaVersion must be 1), so nobody can sign in \
             [doctor-policy-invalid]\n      Correct it as docs/operator/access.md shows.",
        ),
        (
            unbound(),
            "the access policy binds no role and no account, so nobody can sign in \
             [doctor-policy-unbound]\n      Bind the role of your administrators: garrison \
             access bind-role <role-id> --profile administrator",
        ),
        (
            bound(1, 0),
            "the access policy binds 1 role and 0 accounts [doctor-policy-bound]",
        ),
        (
            hidden((
                "broker.policy is /home/admin/access-policy.json, under /home, which \
                 garrison-broker.service hides from the broker (ProtectHome=true): the broker \
                 cannot read it there, and nobody can sign in"
                    .into(),
                "Keep the policy where the broker sees it".into(),
            )),
            "broker.policy is /home/admin/access-policy.json, under /home, which \
             garrison-broker.service hides from the broker (ProtectHome=true): the broker cannot \
             read it there, and nobody can sign in [doctor-policy-hidden]\n      Keep the policy \
             where the broker sees it.",
        ),
    ]
}
