//! The states of how `garrison access` judges Stalwart's roles: what `init`
//! and `bind-role` say of them, and the reasons a role is left out by.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::path::Path;

use crate::access::Candidate;
use crate::state::{State, states};

/// `init` bound no role and wrote the policy anew.
pub(crate) fn unbound(candidates: &BTreeMap<String, Candidate>) -> State {
    let mut lines = vec![format!(
        "No native administrator role with full administrative rights was found, so the policy \
         binds no role and nobody can sign in yet. {}",
        requires()
    )];
    lines.extend(candidates_said(candidates));
    State::new("access-unbound", lines.join("\n"))
}

/// `init --force` kept the policy at `path`, since no role qualifies;
/// `gone`, the actions it names that garrison.toml no longer has; where it
/// binds nobody, the candidates and what to do.
pub(crate) fn kept(
    path: &Path,
    gone: Option<&State>,
    binds_nobody: bool,
    candidates: &BTreeMap<String, Candidate>,
) -> State {
    let mut lines = vec![format!(
        "No native administrator role with full administrative rights was found, and a new \
         default policy would bind no role and sign everyone out: {} is kept as it is.",
        path.display()
    )];
    lines.extend(gone.map(ToString::to_string));
    if binds_nobody {
        lines.push(format!(
            "It binds no role or account either, so nobody can sign in yet. {}",
            requires()
        ));
        lines.extend(candidates_said(candidates));
    }
    State::new("access-kept", lines.join("\n"))
}

states! {
    pub(crate) fn bound(role: &str, description: Option<&str>) = "access-bound":
        "Bound native role {} to profile administrator.", named(role, description);
    pub(crate) fn no_role(role: &str) = "access-no-role":
        "Stalwart has no role {role}: bind one of the roles the native administration shows \
         (Roles).";
    /// `role`'s rights cannot be evaluated for `why`.
    pub(crate) fn role_unjudged(role: &str, profile: &str, why: &State) = "access-role-unjudged":
        "Note: the rights of role {role} cannot be evaluated ({why}), so whether its users \
         get the profile {profile} is not known; `garrison access check <subject>` shows \
         what a user gets.";
    /// `role` lacks the rights `lacks` that `profile` requires, and meets the
    /// profiles `meets` as it is.
    pub(crate) fn role_lacks(role: &str, profile: &str, lacks: &[String], meets: &[String])
        = "access-role-lacks":
        "Note: role {role} lacks {}, which the profile {profile} requires, so its users get \
         nothing of it until Stalwart's administrator gives the role {} in the native \
         administration (Roles). {}", listed(lacks), those(lacks), as_it_is(meets);
    pub(crate) fn too_many_roles(max: usize) = "access-too-many-roles":
        "it inherits from more than {max} roles, more than Garrison evaluates";
    pub(crate) fn inherits_missing(gone: &str) = "access-inherits-missing":
        "it inherits from role {gone}, which Stalwart does not have";
    pub(crate) fn role_unreadable(id: &str) = "access-role-unreadable":
        "this release cannot read role {id}";
    pub(crate) fn every_users_role() = "access-every-users-role":
        "it is every user's default role too, and binding it would make every user an \
         administrator";
    pub(crate) fn no_such_role() = "access-no-such-role":
        "Stalwart has no role of that ID";
    pub(crate) fn rights_unevaluated(why: &State) = "access-rights-unevaluated":
        "its rights cannot be evaluated ({why})";
}

/// The role, or `parent`, one it inherits from, belongs to a tenant.
pub(crate) fn tenant_role(parent: Option<&str>) -> State {
    let text = match parent {
        None => "it belongs to a tenant".to_owned(),
        Some(id) => format!("role {id}, from which it inherits, belongs to a tenant"),
    };
    State::new("access-tenant-role", text)
}

/// `error`: why the evaluation of the role's rights failed, in its words.
pub(crate) fn unevaluable(error: impl Display) -> State {
    State::new("access-unevaluable", error.to_string())
}

/// A role as messages name it: its ID, with its description where it has one.
fn named(identifier: &str, description: Option<&str>) -> String {
    match description {
        Some(description) => format!("{identifier} ({description})"),
        None => identifier.to_owned(),
    }
}

/// `a`, `a and b`, `a, b and c`.
fn listed(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [first @ .., last] => format!("{} and {last}", first.join(", ")),
    }
}

fn those(rights: &[String]) -> &'static str {
    if rights.len() == 1 {
        "that right"
    } else {
        "those rights"
    }
}

/// What a role meets as it is, as a sentence ends.
fn as_it_is(meets: &[String]) -> String {
    match meets {
        [] => "As it is, it meets none of the profiles.".to_owned(),
        [one] => format!("As it is, it meets the profile {one}."),
        more => format!("As it is, it meets the profiles {}.", listed(more)),
    }
}

/// The rights the administrator profile requires, as a sentence.
fn requires() -> String {
    let required: Vec<String> = crate::access::ADMIN_PERMISSIONS
        .iter()
        .map(|right| (*right).to_owned())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    format!("The administrator profile requires {}.", listed(&required))
}

/// For each of Stalwart's default administrator roles what it lacks of the
/// administrator profile's rights, where to give them and what it meets as
/// it is, or why `init` leaves it out; and how to bind a role of one's own
/// where none is left that only lacks rights. One line each.
fn candidates_said(candidates: &BTreeMap<String, Candidate>) -> Vec<String> {
    let mut lines = Vec::new();
    for (identifier, candidate) in candidates {
        let role = named(identifier, candidate.description.as_deref());
        lines.push(match &candidate.fit {
            Ok(fit) => format!(
                "Stalwart's default administrator role {role} lacks {}: give the role {} in the \
                 native administration (Roles), then run garrison access bind-role {identifier} \
                 --profile administrator. {}",
                listed(&fit.lacks),
                those(&fit.lacks),
                as_it_is(&fit.meets)
            ),
            Err(why) => format!("Stalwart's default administrator role {role} is left out: {why}."),
        });
    }
    let bind = "bind it with garrison access bind-role <role-id> --profile administrator.";
    if candidates.is_empty() {
        lines.push(format!(
            "Stalwart names no default administrator role: once the role of your administrators \
             holds these rights, {bind}"
        ));
    } else if candidates.values().all(|candidate| candidate.fit.is_err()) {
        lines.push(format!(
            "Once the role of your administrators holds these rights, {bind}"
        ));
    }
    lines
}
