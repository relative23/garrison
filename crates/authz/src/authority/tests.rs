use garrison_core::modules::ModuleId;
use garrison_testing::http::{answer, json as respond, serve};
use garrison_testing::{NATIVE_KEY, config, credentials, policy_document, write_policy};
use serde_json::{Value, json};

use super::*;

const TOKEN: &str = "token-0123456789abcdef";

fn jmap(method: &str, list: &Value) -> String {
    respond(&json!({"methodResponses": [[method, {"list": list, "notFound": []}, "0"]]}))
}

/// Stalwart's answers for subject 1 (JMAP account `b`) holding custom role `role`.
fn native(role: &str, permissions: &[&str]) -> Vec<String> {
    let enabled: Value = permissions
        .iter()
        .map(|name| (name.to_string(), json!(true)))
        .collect();
    vec![
        respond(&json!({"sub": "1", "email": "ann@example.test"})),
        jmap(
            "x:Account/get",
            &json!([{"id": "b", "@type": "User", "roles": {"@type": "Custom", "roleIds": {role: true}},
                    "permissions": {"@type": "Inherit"}}]),
        ),
        jmap(
            "x:Authentication/get",
            &json!([{"id": "singleton", "defaultAdminRoleIds": {}, "defaultUserRoleIds": {}}]),
        ),
        jmap(
            "x:Role/get",
            &json!([{"id": role, "roleIds": {}, "enabledPermissions": enabled, "disabledPermissions": {}}]),
        ),
    ]
}

fn authority(
    responses: Vec<String>,
) -> (Authority, garrison_testing::http::Server, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(responses);
    let config = config(directory.path(), &server.url);
    let credentials = credentials(&config);
    write_policy(&config, &policy_document());
    (Authority::new(&config, credentials), server, directory)
}

#[test]
fn identity_comes_from_userinfo_and_rights_from_the_native_roles() {
    let rights = [
        "authenticate",
        "sysActionCreate",
        "sysRoleUpdate",
        "sysAccountGet",
    ];
    let (authority, server, _directory) = authority(native("e", &rights));
    let grant = authority.authorize(TOKEN).unwrap();
    assert_eq!(
        (grant.subject.as_str(), grant.email.as_str()),
        ("1", "ann@example.test")
    );
    assert_eq!(grant.profiles, ["administrator"]);
    assert!(grant.allows_module(ModuleId::Actions) && grant.allows_action("run_backup"));
    assert!(time::parse(&grant.checked_at).is_some());
    let requests = server.requests();
    assert!(requests[0].contains(&format!("authorization: Bearer {TOKEN}\r\n")));
    for request in &requests[1..] {
        assert!(request.contains(&format!("authorization: Bearer {NATIVE_KEY}\r\n")));
    }
    assert!(requests[1].contains(r#""ids":["b"]"#), "{}", requests[1]);
}

#[test]
fn the_profile_needs_its_native_rights_now() {
    let (authority, server, _directory) =
        authority(native("e", &["authenticate", "sysAccountGet"]));
    assert_eq!(
        authority.authorize(TOKEN),
        Err(Error::Denied(
            "This identity has no eligible Garrison profile".into()
        ))
    );
    server.requests();
}

#[test]
fn failures_keep_their_meaning() {
    let (authority, server, directory) = authority(vec![answer(401, ""), answer(502, "")]);
    assert_eq!(
        authority.authorize(TOKEN),
        Err(Error::InvalidToken(
            "The access token is no longer valid".into()
        ))
    );
    assert_eq!(
        authority.authorize(TOKEN),
        Err(Error::Unavailable(
            "Native authorization is temporarily unavailable".into()
        ))
    );
    server.requests();
    // A policy file that others may change grants nothing.
    let config = config(directory.path(), "http://127.0.0.1:9");
    let policy = &config.broker.policy;
    std::fs::set_permissions(policy, std::os::unix::fs::PermissionsExt::from_mode(0o666)).unwrap();
    assert!(matches!(authority.policy(), Err(Error::Misconfigured(_))));
}

/// Stalwart's rate limit, named by whose budget met it: the user's token at
/// UserInfo, the broker's key at the management API.
#[test]
fn stalwarts_rate_limit_is_named_by_whose_budget_met_it() {
    let identity = respond(&json!({"sub": "1", "email": "ann@example.test"}));
    let (authority, server, _directory) =
        authority(vec![answer(429, ""), identity, answer(429, "")]);
    assert_eq!(
        authority.authorize(TOKEN),
        Err(Error::Limited("the user's token".into()))
    );
    assert_eq!(
        authority.authorize(TOKEN),
        Err(Error::Limited("the broker's key".into()))
    );
    server.requests();
}

/// What `authorize` says where Garrison's own setup is broken in `broken`.
fn with_broken_setup(responses: Vec<String>, broken: impl Fn(&Config)) -> Error {
    let (authority, server, directory) = authority(responses);
    broken(&config(directory.path(), &server.url));
    let error = authority.authorize(TOKEN).unwrap_err();
    drop(server);
    error
}

#[test]
fn a_broken_setup_is_no_refusal_of_the_user() {
    let rights = ["authenticate", "sysActionCreate", "sysRoleUpdate"];
    // A typo in the policy: it no longer reads as one.
    let typo = with_broken_setup(native("e", &rights), |config| {
        std::fs::write(&config.broker.policy, "{\"schemaVersion\": 1,").unwrap();
    });
    assert!(
        matches!(&typo, Error::Misconfigured(reason) if reason.contains("policy")),
        "{typo:?}"
    );
    // A profile that names an action the configuration no longer has.
    let stale = with_broken_setup(native("e", &rights), |config| {
        let mut document = policy_document();
        document["profiles"]["administrator"]["actions"] = json!(["run_backup", "gone"]);
        write_policy(config, &document);
    });
    assert!(matches!(stale, Error::Misconfigured(_)), "{stale:?}");
    // The broker's key is gone, or Stalwart no longer takes it.
    let keyless = with_broken_setup(native("e", &rights), |config| {
        let directory = config.broker.policy.parent().unwrap();
        std::fs::remove_file(directory.join("credentials").join("broker-native-key")).unwrap();
    });
    assert!(matches!(keyless, Error::Misconfigured(_)), "{keyless:?}");
    let userinfo = respond(&json!({"sub": "1", "email": "ann@example.test"}));
    let rotated = with_broken_setup(vec![userinfo.clone(), answer(401, "")], |_| {});
    assert!(
        matches!(&rotated, Error::Misconfigured(reason) if reason.contains("key was rejected")),
        "{rotated:?}"
    );
    // An answer of Stalwart's that this release does not read, as after an
    // upgrade of Stalwart: no refusal either, and named by the request it
    // answered.
    let changed = with_broken_setup(vec![userinfo, answer(200, "<html>")], |_| {});
    assert_eq!(
        changed,
        Error::Unreadable("the management API: Malformed native API response".into())
    );
    let unread = with_broken_setup(vec![answer(200, "{}")], |_| {});
    assert_eq!(
        unread,
        Error::Unreadable("UserInfo: The provider returned no stable subject".into())
    );
    // Someone who has no profile is refused, and that is no setup problem.
    let (authority, server, _directory) = authority(native("e", &["authenticate"]));
    assert!(matches!(authority.authorize(TOKEN), Err(Error::Denied(_))));
    server.requests();
}

#[test]
fn a_denied_subject_is_refused_before_the_native_lookup() {
    let (authority, server, directory) = authority(native("e", &[]));
    let config = config(directory.path(), &server.url);
    let mut document = policy_document();
    document["deniedSubjects"] = json!(["1"]);
    write_policy(&config, &document);
    assert_eq!(
        authority.authorize(TOKEN),
        Err(Error::Denied(
            "This identity is explicitly denied Garrison access".into()
        ))
    );
    // Only UserInfo was asked; the server thread still waits for the rest.
    drop(server);
}

#[test]
fn a_module_the_installation_does_not_offer_is_granted_to_nobody() {
    let rights = [
        "authenticate",
        "sysActionCreate",
        "sysRoleUpdate",
        "sysAccountGet",
    ];
    let directory = tempfile::tempdir().unwrap();
    let server = serve(native("e", &rights));
    let mut config = config(directory.path(), &server.url);
    config.modules = BTreeSet::from([ModuleId::Dashboard, ModuleId::Services]);
    let credentials = credentials(&config);
    write_policy(&config, &policy_document());
    // The policy gives the administrator maintenance; this installation has none.
    let grant = Authority::new(&config, credentials)
        .authorize(TOKEN)
        .unwrap();
    assert_eq!(grant.profiles, ["administrator"]);
    assert!(grant.modules.is_subset(&config.modules));
    assert!(grant.allows_module(ModuleId::Dashboard));
    assert!(!grant.allows_module(ModuleId::Actions));
    assert!(grant.actions.is_empty());
    server.requests();
}

#[test]
fn a_profile_with_no_module_the_installation_offers_is_a_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(native("v", &["authenticate", "sysAccountGet"]));
    let mut config = config(directory.path(), &server.url);
    config.modules = BTreeSet::from([ModuleId::Dashboard, ModuleId::Services]);
    let credentials = credentials(&config);
    let mut document = policy_document();
    document["profiles"]["viewer"]["modules"] = json!(["attacks", "logs"]);
    write_policy(&config, &document);
    // The viewer's profile applies, but names only modules this
    // installation does not offer. A grant of nothing is no grant: the web
    // service would refuse it as malformed and answer 502 on every request.
    assert_eq!(
        Authority::new(&config, credentials).authorize(TOKEN),
        Err(Error::Denied(
            "This identity's profiles grant no module this installation offers".into()
        ))
    );
    server.requests();
}
