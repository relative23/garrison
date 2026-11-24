//! A role is judged by its own inheritance, as the broker judges an
//! account's roles: however many roles the server holds, `init` and
//! `bind-role` read the role and those it inherits from, no more, and a
//! role whose rights cannot be evaluated is named with the reason.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

use super::support::{against, names, prepared, run, text};
use super::{ADMINISTRATOR_RIGHTS, policy, role};

/// A stand-in for Stalwart that answers by what it is asked, as Stalwart
/// does: `x:Authentication/get` with `authentication`, `x:Role/get` with
/// the roles of the IDs asked for, every role where no ID is named, and the
/// IDs it does not have as not found; and how many roles it has sent.
pub(super) fn stalwart(authentication: Value, roles: Vec<Value>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let sent = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&sent);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request: Value = serde_json::from_slice(&body).unwrap();
            let (method, asked) = (&request["methodCalls"][0][0], &request["methodCalls"][0][1]);
            let has = |id: &Value| roles.iter().any(|role| &role["id"] == id);
            let (list, missing): (Vec<Value>, Vec<Value>) =
                match (method.as_str(), asked["ids"].as_array()) {
                    (Some("x:Authentication/get"), _) => (vec![authentication.clone()], Vec::new()),
                    (Some("x:Role/get"), None) => (roles.clone(), Vec::new()),
                    (Some("x:Role/get"), Some(ids)) => (
                        roles
                            .iter()
                            .filter(|role| ids.contains(&role["id"]))
                            .cloned()
                            .collect(),
                        ids.iter().filter(|id| !has(id)).cloned().collect(),
                    ),
                    _ => (Vec::new(), Vec::new()),
                };
            if method == "x:Role/get" {
                counted.fetch_add(list.len(), Ordering::SeqCst);
            }
            let answer =
                json!({"methodResponses": [[method, {"list": list, "notFound": missing}, "0"]]});
            let answer = garrison_testing::http::json(&answer);
            let _ = reader.into_inner().write_all(answer.as_bytes());
        }
    });
    (url, sent)
}

/// `role` that inherits from `parents`.
fn inheriting(id: &str, enabled: &[&str], description: &str, parents: &[&str]) -> Value {
    let mut made = role(id, enabled, description);
    made["roleIds"] = names(parents);
    made
}

/// Roles of other software and of tenants beside the administrators': more
/// than one evaluation takes.
fn crowded() -> Vec<Value> {
    (0..70)
        .map(|number| role(&format!("other{number}"), &["authenticate"], "Another's"))
        .collect()
}

/// Other roles on the server count for nothing: `init` binds the
/// administrators' role and `bind-role` a role of the users, each read with
/// the role it inherits from and nothing else.
#[test]
fn a_server_with_more_roles_than_an_evaluation_takes_binds_by_the_role_alone() {
    let mut roles = crowded();
    roles.extend([
        inheriting(
            "admins",
            &ADMINISTRATOR_RIGHTS[1..],
            "Administrators",
            &["base"],
        ),
        role("base", &["authenticate"], "Everyone"),
    ]);
    let authentication = json!({"id": "singleton", "defaultAdminRoleIds": names(&["admins"]),
                                "defaultUserRoleIds": names(&["base"])});
    let (url, sent) = stalwart(authentication, roles);
    let directory = against(&url);
    let init = run(directory.path(), &["access", "init"]);
    assert_eq!(init.status.code(), Some(0), "{}", text(&init.stderr));
    assert!(
        text(&init.stdout)
            .contains("Bound native role admins (Administrators) to profile administrator.\n"),
        "{}",
        text(&init.stdout)
    );
    let bound = run(
        directory.path(),
        &["access", "bind-role", "base", "--profile", "viewer"],
    );
    assert_eq!(bound.status.code(), Some(0), "{}", text(&bound.stderr));
    assert!(
        text(&bound.stdout).contains(
            "Note: role base lacks sysAccountGet and sysDomainGet, which the profile viewer \
             requires"
        ),
        "{}",
        text(&bound.stdout)
    );
    assert_eq!(
        policy(directory.path())["roleBindings"],
        json!({"admins": "administrator", "base": "viewer"})
    );
    // An ID that is no numeral of Stalwart's is no role of its, unasked.
    let typed = run(
        directory.path(),
        &["access", "bind-role", "no-such-role", "--profile", "viewer"],
    );
    assert_eq!(
        (typed.status.code(), text(&typed.stderr)),
        (
            Some(1),
            "Stalwart has no role no-such-role: bind one of the roles the native administration \
             shows (Roles).\n"
                .to_owned()
        )
    );
    // init read admins and base, bind-role base.
    assert_eq!(sent.load(Ordering::SeqCst), 3);
}

/// A role whose rights cannot be evaluated is bound as asked, and the note
/// names the role and why: a tenant's role it inherits from, one Stalwart
/// does not have, one this release cannot read, more roles than an
/// evaluation takes.
#[test]
fn a_role_whose_rights_cannot_be_evaluated_is_named_with_the_reason() {
    let mut tenants = role("tenants", &ADMINISTRATOR_RIGHTS, "A tenant's");
    tenants["memberTenantId"] = json!("t1");
    let mut odd = role("odd", &["authenticate"], "Of another shape");
    odd["enabledPermissions"] = json!(["authenticate"]);
    let mut roles = vec![
        tenants,
        odd,
        inheriting("local", &["authenticate"], "Local", &["tenants"]),
        inheriting("orphan", &["authenticate"], "Orphaned", &["gone"]),
    ];
    // wide inherits from 8 roles, each of which from 8 more: 73 in all.
    let ids = |prefix: &str| -> Vec<String> { (0..8).map(|n| format!("{prefix}x{n}")).collect() };
    let middle = ids("wide");
    let named: Vec<&str> = middle.iter().map(String::as_str).collect();
    roles.push(inheriting("wide", &["authenticate"], "Wide", &named));
    for one in &middle {
        let below = ids(one);
        let named: Vec<&str> = below.iter().map(String::as_str).collect();
        roles.push(inheriting(one, &[], "", &named));
        roles.extend(below.iter().map(|id| role(id, &[], "")));
    }
    let authentication =
        json!({"id": "singleton", "defaultAdminRoleIds": {}, "defaultUserRoleIds": {}});
    let (url, _) = stalwart(authentication, roles);
    let directory = prepared();
    let settings = directory.path().join("garrison.toml");
    let written = std::fs::read_to_string(&settings).unwrap();
    std::fs::write(&settings, written.replace("http://127.0.0.1:9", &url)).unwrap();
    for (bound, why) in [
        ("tenants", "it belongs to a tenant"),
        (
            "local",
            "role tenants, from which it inherits, belongs to a tenant",
        ),
        (
            "orphan",
            "it inherits from role gone, which Stalwart does not have",
        ),
        ("odd", "this release cannot read role odd"),
        (
            "wide",
            "it inherits from more than 64 roles, more than Garrison evaluates",
        ),
    ] {
        let ran = run(
            directory.path(),
            &["access", "bind-role", bound, "--profile", "viewer"],
        );
        assert_eq!(ran.status.code(), Some(0), "{bound}: {}", text(&ran.stderr));
        assert!(
            text(&ran.stdout).contains(&format!(
                "Note: the rights of role {bound} cannot be evaluated ({why}), so whether its \
                 users get the profile viewer is not known; `garrison access check <subject>` \
                 shows what a user gets.\n"
            )),
            "{bound}: {}",
            text(&ran.stdout)
        );
        assert_eq!(
            policy(directory.path())["roleBindings"][bound],
            "viewer",
            "{bound}"
        );
    }
}
