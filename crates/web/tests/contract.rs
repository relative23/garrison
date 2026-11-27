//! The sign-in that the web service relies on, against the pinned Stalwart and
//! with the OAuth client registered the way `stalwart setup` registers it:
//! PKCE is required, the redirect must match exactly, a code works once, the
//! answer names the issuer, the token is good for sign-in only, revocation
//! ends it and that sign-in alone, and no refresh token of it serves. The
//! sidebar test is an early warning for the row that
//! `frontend/public/stalwart-switch.js` adds to Stalwart's WebUI. Run with the
//! variables of `cargo xtask lab start`:
//! `cargo test --workspace --test contract -- --ignored`.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use garrison_stalwart::Error;
use garrison_stalwart::http::Request;
use garrison_stalwart::oidc::{CodeExchange, Provider};
use garrison_testing::lab::{Lab, random_hex, unique};
use garrison_web::app::{client_id, redirect_uri};
use garrison_web::routes::auth::challenge;
use serde_json::{Value, json};
use url::form_urlencoded;

const ISSUER: &str = "https://mail.example.test";

/// The lab with an administrator who signs in and Garrison's client,
/// under an origin of its own so that tests can run side by side.
struct SignIn {
    lab: Lab,
    origin: String,
    account: String,
    password: String,
}

fn lab() -> SignIn {
    let mut lab = Lab::from_environment();
    let origin = format!("https://{}.example.test", unique());
    lab.create(
        "OAuthClient",
        &json!({
            "clientId": client_id(&origin),
            "description": "Garrison",
            "redirectUris": {redirect_uri(&origin): true},
            "postLogoutRedirectUris": {},
            "scopes": {},
            "grantTypes": {"authorizationCode": true},
        }),
    );
    let domains = lab.call("x:Domain/get", &json!({"ids": null, "properties": ["id"]}));
    let (name, password) = (unique(), random_hex(18));
    // An administrator: the token must still carry no administrative right.
    lab.create(
        "Account",
        &json!({
            "@type": "User",
            "name": name,
            "domainId": domains["list"][0]["id"],
            "credentials": {"0": {"@type": "Password", "secret": password}},
            "roles": {"@type": "Admin"},
            "permissions": {"@type": "Inherit"},
        }),
    );
    SignIn {
        lab,
        origin,
        account: format!("{name}@example.test"),
        password,
    }
}

fn query(origin: &str, redirect: &str, scope: &str, verifier: Option<&str>) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("client_id", &client_id(origin))
        .append_pair("redirect_uri", redirect)
        .append_pair("response_type", "code")
        .append_pair("scope", scope)
        .append_pair("state", "state-0123");
    if let Some(verifier) = verifier {
        query
            .append_pair("code_challenge", &challenge(verifier))
            .append_pair("code_challenge_method", "S256");
    }
    query.finish()
}

impl SignIn {
    /// Sign in with this query; the parameters of the redirect, which always
    /// goes to the exact callback.
    fn returned(&self, query: &str) -> HashMap<String, String> {
        let answer = self.lab.authorize(query, &self.account, &self.password);
        let location = answer["location"]
            .as_str()
            .unwrap_or_else(|| panic!("no redirect: {answer}"));
        let url = url::Url::parse(location).unwrap();
        assert_eq!(&url[..url::Position::AfterPath], redirect_uri(&self.origin));
        url.query_pairs().into_owned().collect()
    }
}

/// A request with the user's token, as somebody holding it would send it.
fn with_token(lab: &Lab, path: &str, token: &str, body: Option<&Value>) -> Value {
    let url = format!("{}{path}", lab.url);
    let authorization = format!("Bearer {token}");
    let text = body.map(Value::to_string);
    let request = match &text {
        Some(text) => {
            Request::post(&url, text.as_bytes()).header("Content-Type", "application/json")
        }
        None => Request::get(&url),
    };
    let answer = request
        .header("Host", "mail.example.test")
        .header("X-Forwarded-Proto", "https")
        .header("Authorization", &authorization)
        .send()
        .unwrap();
    assert_eq!(answer.status, 200, "{path}");
    serde_json::from_slice(&answer.body).unwrap()
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_code_works_once_with_its_verifier_and_the_token_only_signs_in() {
    let sign_in = lab();
    let (lab, origin) = (&sign_in.lab, sign_in.origin.as_str());
    let provider = Provider::new(&lab.url, ISSUER);
    let verifier = random_hex(32);
    let params = sign_in.returned(&query(
        origin,
        &redirect_uri(origin),
        "openid",
        Some(&verifier),
    ));
    assert_eq!(
        (params["state"].as_str(), params["iss"].as_str()),
        ("state-0123", ISSUER)
    );
    let (client, callback) = (client_id(origin), redirect_uri(origin));
    let exchange = |verifier: &str| {
        provider.exchange_code(&CodeExchange {
            client_id: &client,
            redirect_uri: &callback,
            code: &params["code"],
            verifier,
            client_ip: None,
        })
    };
    assert!(matches!(exchange(&random_hex(32)), Err(Error::Denied(_))));
    let token = exchange(&verifier).unwrap();
    assert!(
        matches!(exchange(&verifier), Err(Error::Denied(_))),
        "a code works once"
    );
    let identity = provider.userinfo(&token.access_token, None).unwrap();
    assert_eq!(identity.email, sign_in.account);

    // Sign-in only: no administrative permission, no management API, no mail.
    let account_info = with_token(lab, "/api/account", &token.access_token, None);
    let permissions: Vec<&str> = account_info["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(permissions.contains(&"authenticate"), "{permissions:?}");
    assert!(
        permissions.iter().all(|name| !name.starts_with("sys")),
        "{permissions:?}"
    );
    let management = json!({"using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
        "methodCalls": [["x:Account/get", {"ids": null, "properties": ["id"]}, "0"]]});
    let answer = with_token(lab, "/jmap/", &token.access_token, Some(&management));
    assert_eq!(answer["methodResponses"][0][0], "error", "{answer}");
    let session = with_token(lab, "/jmap/session", &token.access_token, None);
    assert!(
        !session.to_string().contains("urn:ietf:params:jmap:mail"),
        "{session}"
    );

    provider.revoke(&client, &token.access_token).unwrap();
    assert!(matches!(
        provider.userinfo(&token.access_token, None),
        Err(Error::InvalidToken(_))
    ));
    // So is a token Stalwart never issued: UserInfo answers it 401, which
    // alone ends a sign-in; any other status ends none.
    assert!(matches!(
        provider.userinfo(&random_hex(24), None),
        Err(Error::InvalidToken(_))
    ));
}

#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_client_needs_pkce_its_own_callback_and_asks_for_no_service() {
    let sign_in = lab();
    let origin = sign_in.origin.as_str();
    let verifier = random_hex(32);
    let callback = redirect_uri(origin);
    let refused = sign_in.returned(&query(origin, &callback, "openid", None));
    assert_eq!(
        refused.get("error").map(String::as_str),
        Some("invalid_request")
    );
    assert!(!refused.contains_key("code"));
    let mail = "openid urn:ietf:params:oauth:scope:mail";
    let refused = sign_in.returned(&query(origin, &callback, mail, Some(&verifier)));
    assert_eq!(
        refused.get("error").map(String::as_str),
        Some("invalid_scope")
    );
    // Another address, or the callback with anything added, gets no redirect.
    for other in [
        "https://evil.example/auth/callback".to_owned(),
        format!("{callback}/more"),
        format!("{callback}?next=1"),
    ] {
        let request = query(origin, &other, "openid", Some(&verifier));
        let answer = sign_in
            .lab
            .authorize(&request, &sign_in.account, &sign_in.password);
        assert_eq!(answer["type"], "invalid", "{other}: {answer}");
        assert!(answer.get("location").is_none(), "{other}");
    }
}

/// The file name that starts with `prefix` and ends with `.js` in `text`.
fn script_name<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let start = text.find(prefix)?;
    let end = start + text[start..].find(".js")? + 3;
    let name = &text[start..end];
    name.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_./".contains(&byte))
        .then_some(name)
}

/// Whether a script names `word` as a text of its own, in any quotes.
fn names(script: &str, word: &str) -> bool {
    ['"', '\'', '`']
        .iter()
        .any(|quote| script.contains(&format!("{quote}{word}{quote}")))
}

/// An early warning, not a proof. Stalwart serves the same WebUI to every
/// server version and replaces it without a server update. The row that
/// `frontend/public/stalwart-switch.js` adds is built for a sidebar that is an
/// `aside` with its menu in a `nav`, the open page marked `aria-current` and
/// the sections as pressed buttons. If this fails, the WebUI was rebuilt:
/// open it, see whether the row still sits right, and fit the script and this
/// test to what is there.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn the_webui_still_has_the_sidebar_the_switch_row_is_built_for() {
    let lab = Lab::from_environment();
    // Stalwart downloads its WebUI after the first start.
    let mut page = String::new();
    for _ in 0..60 {
        let (status, _, text) = lab.page("/admin/");
        if status == 200 && text.contains("assets/index-") {
            page = text;
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let entry = script_name(&page, "assets/index-").expect("the lab serves no WebUI at /admin/");
    let (status, _, entry) = lab.page(&format!("/admin/{entry}"));
    assert_eq!(status, 200, "the WebUI's script");
    let panel = script_name(&entry, "AdminPanel-")
        .expect("the WebUI no longer has a script named AdminPanel for its signed-in interface");
    let (status, _, panel) = lab.page(&format!("/admin/assets/{panel}"));
    assert_eq!(
        status, 200,
        "the WebUI's script for its signed-in interface"
    );
    for (what, word) in [
        ("a sidebar that is an aside element", "aside"),
        ("a menu in a nav element", "nav"),
        ("the open page marked with aria-current", "aria-current"),
        ("sections as buttons with aria-pressed", "aria-pressed"),
    ] {
        assert!(
            names(&panel, word),
            "the Stalwart WebUI no longer has {what}; look at the switch row"
        );
    }
}

/// A form posted to one of Stalwart's OAuth endpoints, as the web service
/// posts it.
fn posted(lab: &Lab, path: &str, form: &str) -> garrison_stalwart::http::Response {
    let url = format!("{}{path}", lab.url);
    Request::post(&url, form.as_bytes())
        .header("Host", "mail.example.test")
        .header("X-Forwarded-Proto", "https")
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .unwrap()
}

impl SignIn {
    /// A sign-in to Garrison's client: the access token Stalwart gives for
    /// its code, and the refresh token where it gives one.
    fn tokens(&self) -> (String, Option<String>) {
        let (client, callback) = (client_id(&self.origin), redirect_uri(&self.origin));
        let verifier = random_hex(32);
        let params = self.returned(&query(&self.origin, &callback, "openid", Some(&verifier)));
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &params["code"])
            .append_pair("client_id", &client)
            .append_pair("redirect_uri", &callback)
            .append_pair("code_verifier", &verifier)
            .finish();
        let answer = posted(&self.lab, "/auth/token", &form);
        assert_eq!(answer.status, 200);
        let token: Value = serde_json::from_slice(&answer.body).unwrap();
        let text = |key: &str| token[key].as_str().map(str::to_owned);
        (text("access_token").unwrap(), text("refresh_token"))
    }
}

/// Another client registered with Stalwart, with the refresh grant Stalwart
/// gives by default; its client ID.
fn another_client(sign_in: &mut SignIn) -> String {
    let other = format!("https://{}.example.test/oauth-client.json", unique());
    sign_in.lab.create(
        "OAuthClient",
        &json!({
            "clientId": other,
            "description": "Another client, with the refresh grant Stalwart gives by default",
            "redirectUris": {format!("https://{}.example.test/callback", unique()): true},
            "postLogoutRedirectUris": {},
            "scopes": {},
        }),
    );
    other
}

/// What a revocation's answer does not tell: Stalwart answers one that
/// names another client, registered with it or not, as it answers one it
/// carries out, and the token serves on. Garrison's revocation names its
/// client as `deployment.public_origin` gives it now, so a token of a
/// sign-in under another origin outlives its session until it expires
/// (docs/architecture/security.md). A revocation that names no client is
/// refused, which `Provider::revoke` takes for none.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_revocation_in_another_clients_name_is_answered_as_one_and_ends_nothing() {
    let mut sign_in = lab();
    let provider = Provider::new(&sign_in.lab.url, ISSUER);
    let (token, _) = sign_in.tokens();
    let other = another_client(&mut sign_in);
    let unknown = format!("https://{}.example.test/oauth-client.json", unique());
    for client in [other.as_str(), unknown.as_str()] {
        assert_eq!(provider.revoke(client, &token), Ok(()), "{client}");
        assert!(provider.userinfo(&token, None).is_ok(), "{client}");
    }
    let nameless = form_urlencoded::Serializer::new(String::new())
        .append_pair("token", &token)
        .finish();
    assert_eq!(posted(&sign_in.lab, "/auth/revoke", &nameless).status, 401);
    assert_eq!(
        provider.revoke("", &token),
        Err(Error::Denied("Stalwart answered HTTP 401".into()))
    );
    assert!(provider.userinfo(&token, None).is_ok());
    assert_eq!(provider.revoke(&client_id(&sign_in.origin), &token), Ok(()));
    assert!(matches!(
        provider.userinfo(&token, None),
        Err(Error::InvalidToken(_))
    ));
}

/// What ends a sign-in's token before its hour is up: its revocation, which
/// the web service asks for whenever a session ends, by its time too. It
/// ends that token alone, not another sign-in of the account. Asked again,
/// or for a token Stalwart never issued, Stalwart answers as it does for one
/// it ends, so that a revocation asked again until Stalwart answers comes to
/// an end. The refresh token Stalwart gives with a sign-in serves neither
/// Garrison's client nor another: the access token is all a sign-in leaves
/// that acts as its user.
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_revocation_ends_its_own_sign_in_and_no_refresh_token_serves() {
    let mut sign_in = lab();
    let client = client_id(&sign_in.origin);
    let provider = Provider::new(&sign_in.lab.url, ISSUER);
    let ((first, refresh), (second, _)) = (sign_in.tokens(), sign_in.tokens());
    let subject = |token: &str| {
        provider
            .userinfo(token, None)
            .map(|identity| identity.subject)
    };
    assert!(subject(&first).is_ok());
    assert_eq!(subject(&first), subject(&second));
    provider.revoke(&client, &first).unwrap();
    assert!(matches!(subject(&first), Err(Error::InvalidToken(_))));
    assert!(
        subject(&second).is_ok(),
        "another sign-in of the account goes on"
    );
    let revoking = |token: &str| {
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("client_id", &client)
            .finish();
        posted(&sign_in.lab, "/auth/revoke", &form).status
    };
    assert_eq!((revoking(&first), revoking(&random_hex(24))), (200, 200));
    let other = another_client(&mut sign_in);
    for client_id in refresh
        .iter()
        .flat_map(|_| [client.as_str(), other.as_str()])
    {
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", refresh.as_deref().unwrap_or_default())
            .append_pair("client_id", client_id)
            .finish();
        let answer = posted(&sign_in.lab, "/auth/token", &form);
        let body: Value = serde_json::from_slice(&answer.body).unwrap_or(Value::Null);
        assert!(
            answer.status != 200 && body.get("access_token").is_none(),
            "{client_id}: {} {body}",
            answer.status
        );
    }
}

/// An account removed while its user is signed in: UserInfo answers its
/// token 403, which Garrison takes for no sign-out, as a block of the
/// address answers the same, and the management API has no such account.
/// So a token that UserInfo still takes names an account Stalwart has,
/// unless the policy binds the subject by hand (`authz::Authority`).
#[test]
#[ignore = "needs the Stalwart lab (cargo xtask lab start)"]
fn a_removed_accounts_token_is_answered_403_at_userinfo() {
    let mut sign_in = lab();
    let origin = sign_in.origin.clone();
    let provider = Provider::new(&sign_in.lab.url, ISSUER);
    let verifier = random_hex(32);
    let params = sign_in.returned(&query(
        &origin,
        &redirect_uri(&origin),
        "openid",
        Some(&verifier),
    ));
    let (client, callback) = (client_id(&origin), redirect_uri(&origin));
    let token = provider
        .exchange_code(&CodeExchange {
            client_id: &client,
            redirect_uri: &callback,
            code: &params["code"],
            verifier: &verifier,
            client_ip: None,
        })
        .unwrap();
    let identity = provider.userinfo(&token.access_token, None).unwrap();
    let account = garrison_stalwart::ids::account_id_for_subject(&identity.subject).unwrap();
    sign_in
        .lab
        .call("x:Account/set", &json!({"destroy": [account]}));
    sign_in.lab.created.retain(|(_, id)| *id != account);
    assert_eq!(
        provider.userinfo(&token.access_token, None),
        Err(Error::Unreadable("Stalwart answered HTTP 403".into()))
    );
    let after = sign_in.lab.call(
        "x:Account/get",
        &json!({"ids": [account], "properties": ["id"]}),
    );
    assert_eq!(
        (&after["list"], &after["notFound"]),
        (&json!([]), &json!([account]))
    );
}
