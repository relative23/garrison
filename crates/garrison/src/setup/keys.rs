//! Garrison's two read-only API keys in Stalwart: created or updated with
//! their permissions and networks, written to the credentials directory,
//! tried from this host and taken up by the service that holds them before
//! the keys they replace go.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use garrison_core::config::Config;
use garrison_core::files::{self, Form, Holds, Privacy};
use garrison_core::json;
use garrison_stalwart::http::Request;

use super::api::Failed;
use super::objects::{
    Created, Enabled, KeyPermissions, KeyRights, Listed, NEW, NewKey, NewSecret, Set, Stored,
};
use super::{Admin, MAX_ANSWER, restart, say, states, write_secret};
use crate::state::State;

/// One of the keys: its file, as the broker or the collector reads it, its
/// description in Stalwart, what it may do, and whether a running service
/// holds it, which must start again to read a new one.
pub(super) struct Key {
    pub(super) file: &'static str,
    pub(super) description: &'static str,
    pub(super) permissions: &'static [&'static str],
    pub(super) held: bool,
}

/// Whether the file at `path` holds a key as the service that reads it
/// takes one, in a file of this user's that no other user may read. An
/// empty file, one of a line end alone, one that holds something else and
/// one that others may read hold none: setup makes a key there, as where
/// the file is missing, since a key kept in such a file leaves its service
/// with none, or with one that others may have seen.
pub(super) fn holds_key(path: &Path) -> bool {
    files::read_secret(path, Privacy::Owned).is_ok()
}

/// A key of one of Garrison's descriptions, in the account that holds it:
/// the administrator's own where `account` is `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AccountKey {
    pub(super) account: Option<String>,
    pub(super) id: String,
}

/// What a file's key opens: a session in an account, none for a key
/// Stalwart does not know (401), or none for one it refuses from this
/// host's address (403), whose account is then not known.
#[derive(Debug, PartialEq, Eq)]
enum Session {
    Of(String),
    Unknown,
    Refused,
}

/// The session the key in `target` opens, as the account it belongs to,
/// asked also where others may read the file, which then holds a key to
/// replace in that account. Without an answer, or with another one, the
/// account is not known, and the run stops before it changes anything:
/// taken for the administrator's own, it would leave another
/// administrator's key valid.
fn owner(admin: &Admin, target: &Path) -> Result<Option<Session>, State> {
    if !files::holds(target, Form::Token).is_ok_and(|held| held == Holds::Secret) {
        return Ok(None);
    }
    let asked = |why: &dyn std::fmt::Display| states::owner_unknown(target, why);
    let data = files::read_bounded(target, 16384).map_err(|error| asked(&error))?;
    let secret = String::from_utf8_lossy(&data);
    let answer = Request::get(&admin.session_url())
        .header("Authorization", &format!("Bearer {}", secret.trim()))
        .timeout(Duration::from_secs(30))
        .limit(MAX_ANSWER)
        .send()
        .map_err(|error| match error {
            garrison_stalwart::Error::Limited(_) => asked(&states::LIMITED),
            error => asked(&error),
        })?;
    match answer.status {
        200 => {}
        401 => return Ok(Some(Session::Unknown)),
        403 => return Ok(Some(Session::Refused)),
        status => return Err(asked(&format_args!("Stalwart answered HTTP {status}"))),
    }
    let method = "GET /jmap/session";
    let session =
        json::parse(&answer.body, MAX_ANSWER).map_err(|error| states::unreadable(method, error))?;
    let account = session["primaryAccounts"]["urn:stalwart:jmap"].as_str();
    let account = account.ok_or_else(|| states::unreadable(method, "no account named"))?;
    Ok(Some(Session::Of(account.to_owned())))
}

/// What setup says where Stalwart does not show the administrator the
/// account that a file's key belongs to: JMAP's `accountNotFound`, as
/// Stalwart answers a user without its administrator rights who asks for
/// that account's keys (measured on Stalwart 1.1.0).
fn unseen(failed: Failed, target: &Path) -> State {
    if failed.is("accountNotFound") {
        return states::account_unseen(target, &failed.state);
    }
    failed.state
}

/// What Stalwart and its file hold of one key, read before anything
/// changes: its keys of the description in the accounts concerned, the one
/// to keep where its file holds it, as Stalwart shows it, what a new key is
/// said as, and what setup says where Stalwart's quota leaves a new one no
/// room.
pub(super) struct Found {
    existing: Vec<AccountKey>,
    keep: Option<(AccountKey, Stored)>,
    made: String,
    full: State,
}

/// The keys of `keys` as Stalwart and the files hold them: the
/// administrator's own keys and those of every account a file's key opens a
/// session in, each account listed once, so that a key that a run moved out
/// of an account and could not remove there is found while any file names
/// that account. The keys setup makes are the administrator's that made
/// them, and an administrator lists only its own account's keys unless it
/// names another (measured on Stalwart 1.1.0 and 1.2.0).
pub(super) fn find(
    admin: &Admin,
    directory: &Path,
    keys: &[&Key],
    rotate: bool,
) -> Result<Vec<Found>, State> {
    let Listed { account_id, list } = admin.list_in::<Stored>("ApiKey", None)?;
    let named: Vec<String> = list
        .iter()
        .map(|item| match item.text("description") {
            Some(text) => format!("'{text}'"),
            None => format!("one without a description ({})", item.id),
        })
        .collect();
    let mut held: Vec<(Option<String>, Stored)> =
        list.into_iter().map(|item| (None, item)).collect();
    let (mut sessions, mut listed) = (Vec::new(), vec![account_id]);
    for key in keys {
        let target = directory.join(key.file);
        let session = owner(admin, &target)?;
        if let Some(Session::Of(account)) = &session
            && !listed.contains(account)
        {
            let theirs = admin.list_in::<Stored>("ApiKey", Some(account));
            let theirs = theirs.map_err(|error| unseen(error, &target))?;
            held.extend(
                theirs
                    .list
                    .into_iter()
                    .map(|item| (Some(account.clone()), item)),
            );
            listed.push(account.clone());
        }
        sessions.push(session);
    }
    let mut found = Vec::new();
    for (key, session) in keys.iter().zip(sessions) {
        let target = directory.join(key.file);
        let ours: Vec<&(Option<String>, Stored)> = held
            .iter()
            .filter(|(_, item)| item.text("description") == Some(key.description))
            .collect();
        let existing: Vec<AccountKey> = ours
            .iter()
            .map(|(account, item)| AccountKey {
                account: account.clone(),
                id: item.id.clone(),
            })
            .collect();
        // The one key of its description is kept where its file holds it.
        // Where Stalwart has several, as after a run that stopped before
        // the old one went, no run can tell which one the file holds, since
        // Stalwart shows no key's secret: a new key replaces them all.
        let known = matches!(session, Some(Session::Of(_) | Session::Refused));
        let keep = match (existing.as_slice(), ours.as_slice()) {
            ([only], [(_, stored)]) if known && !rotate && holds_key(&target) => {
                Some((only.clone(), stored.clone()))
            }
            _ => None,
        };
        let (path, description) = (target.display(), key.description);
        let made = match (existing.len(), rotate) {
            _ if session == Some(Session::Unknown) => {
                format!("Stalwart did not know the API key in {path}; made a new one")
            }
            (0, _) | (1, false) => format!("created API key '{description}' -> {path}"),
            (count, false) => {
                format!("replaced the {count} API keys '{description}' with one -> {path}")
            }
            (_, true) => format!("replaced API key '{description}' -> {path}"),
        };
        let full = states::account_full(&named.join(", "), description);
        found.push(Found {
            existing,
            keep,
            made,
            full,
        });
    }
    Ok(found)
}

/// One key as it was asked for: the file's kept with the rights setup
/// gives it, or a new one made, written to its file, tried from this host
/// and taken up by its service, and only then the keys it replaces
/// removed, so that a service always holds a key Stalwart takes. Where
/// Stalwart's quota leaves the new key no room (JMAP's error type
/// `overQuota`, RFC 8620, where an account holds as many API keys as
/// Stalwart takes, five: measured on Stalwart 1.1.0 and 1.2.0), nothing of
/// this key changes. `take_up` has the service that holds the key read a
/// new one. Whether anything changed: a kept key whose rights are as setup
/// gives them is left as it is.
pub(super) fn settle(
    admin: &Admin,
    config: &Config,
    key: &Key,
    found: Found,
    networks: &Enabled,
    take_up: &dyn Fn(&Key) -> Result<(), State>,
) -> Result<bool, State> {
    let directory = &config.credentials_directory;
    let (target, description) = (directory.join(key.file), key.description);
    let rights = || KeyRights {
        permissions: KeyPermissions::Replace {
            permissions: Enabled::of(key.permissions.iter().copied()),
        },
        allowed_ips: networks,
    };
    if let Some((kept, stored)) = &found.keep {
        let shown = KeyRights {
            allowed_ips: &as_shown(networks),
            ..rights()
        };
        let changed = !stored.holds(&rights()) && !stored.holds(&shown);
        if changed {
            let update = Set::update(&kept.id, rights());
            admin.set_in("x:ApiKey/set", kept.account.as_deref(), &update)?;
        }
        tried(config, key)?;
        if changed {
            say(&format!(
                "- updated API key '{description}' (secret unchanged)"
            ));
        }
        return Ok(changed);
    }
    if let Err(failed) = make(admin, &target, description, rights()) {
        return Err(if failed.is("overQuota") {
            found.full
        } else {
            failed.state
        });
    }
    tried(config, key)?;
    say(&format!("- {}", found.made));
    take_up(key)?;
    for old in &found.existing {
        let destroy = Set::<()>::Destroy([old.id.as_str()]);
        admin
            .set_in("x:ApiKey/set", old.account.as_deref(), &destroy)
            .map_err(|error| states::replaced_stays(error, description))?;
    }
    Ok(true)
}

/// `networks` as Stalwart shows a key's: a single address without its
/// prefix (measured on Stalwart 1.1.0 and 1.2.0). A key that Stalwart shows
/// as setup wrote it is held as well.
fn as_shown(networks: &Enabled) -> Enabled {
    Enabled::of(networks.names().map(|network| {
        let single = if network.contains(':') { "/128" } else { "/32" };
        network.strip_suffix(single).unwrap_or(network).to_owned()
    }))
}

/// A new key, its secret written to `target`. A key whose secret is lost is
/// of no use to anyone, so where the file cannot be written, the new key
/// goes again.
fn make(
    admin: &Admin,
    target: &Path,
    description: &str,
    rights: KeyRights<'_>,
) -> Result<(), Failed> {
    let new_key = NewKey {
        description,
        rights,
        expires_at: None,
    };
    let created: Created<NewSecret> = admin
        .call("x:ApiKey/set", &Set::create(new_key))
        .map_err(|failed| refused(failed, description))?;
    let new = created.created.get(NEW);
    let new = new.ok_or_else(states::secret_missing)?;
    let Err(error) = write_secret(target, &new.secret) else {
        return Ok(());
    };
    let undone = admin.set("x:ApiKey/set", &Set::<()>::Destroy([new.id.as_str()]));
    Err(match undone {
        Ok(()) => states::taken_out(error),
        Err(_) => states::left_in(error),
    }
    .into())
}

/// The service that holds `key` reads its new one: the broker starts again,
/// the collector reads it at its next run. Where root's restart fails, the
/// broker may still hold the key the new one replaces, which then stays.
pub(super) fn take_up(key: &Key) -> Result<(), State> {
    if !key.held {
        return Ok(());
    }
    match restart::restart(&BTreeSet::from([key.file])) {
        Ok(said) => {
            if let Some(state) = said {
                say(&state.to_string());
            }
            Ok(())
        }
        Err(asked) => Err(states::old_key_kept(&asked)),
    }
}

/// What setup says where Stalwart made no new key. A user without
/// administrator rights reads the list of keys, its own, but may not grant
/// a key the permissions it lacks: JMAP's `forbidden`, as Stalwart answers
/// it (measured on Stalwart 1.1.0 only). JMAP's error type stays with it.
fn refused(failed: Failed, description: &str) -> Failed {
    let state = if failed.is("forbidden") {
        states::key_not_granted(description, &failed.state)
    } else {
        states::unreturned(failed.state)
    };
    Failed { state, ..failed }
}

/// The key in its file opens a JMAP session from this host, as its service
/// will use it. Stalwart answers a key it knows from an address the key
/// does not allow 403 (measured on Stalwart 1.1.0 and 1.2.0). In a
/// container's bridge network Stalwart sees this host as the bridge's
/// gateway, not as 127.0.0.1, and then every key is refused. That is said
/// here, at setup, rather than found later in the collector's results.
fn tried(config: &Config, key: &Key) -> Result<(), State> {
    let url = format!("{}/jmap/session", config.deployment.stalwart_url);
    let name = key.file;
    // As the services read it, so that what is tried is what they use.
    let path = config.credentials_directory.join(name);
    let secret = files::read_secret(&path, Privacy::Owned).map_err(states::file_unread)?;
    let status = Request::get(&url)
        .header("Authorization", &format!("Bearer {secret}"))
        .timeout(Duration::from_secs(30))
        .status()
        .map_err(|error| states::key_untried(name, error))?;
    match status {
        200 => Ok(()),
        401 => Err(states::key_untaken(name)),
        403 => Err(states::key_refused_here(name)),
        other => Err(states::key_untried(
            name,
            format_args!("Stalwart answered HTTP {other} for its JMAP session"),
        )),
    }
}

/// A network as `address/prefix`; the host part must be zero.
pub(super) fn network(text: &str) -> Result<String, State> {
    let (address, prefix) = text.split_once('/').unwrap_or((text, ""));
    let address: IpAddr = address.parse().map_err(|_| states::network_invalid(text))?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    let prefix: u32 = if prefix.is_empty() {
        bits
    } else {
        prefix.parse().map_err(|_| states::network_invalid(text))?
    };
    let host_bits_zero = match address {
        IpAddr::V4(v4) => prefix <= 32 && (prefix == 32 || u32::from(v4) << prefix == 0),
        IpAddr::V6(v6) => prefix <= 128 && (prefix == 128 || u128::from(v6) << prefix == 0),
    };
    if !host_bits_zero {
        return Err(states::network_host_bits(text));
    }
    Ok(format!("{address}/{prefix}"))
}

#[cfg(test)]
mod account_tests;
#[cfg(test)]
mod tests;
