//! The sign-in client's part of the setup contract test: Garrison's client
//! registered for sign-in only, and another application's left alone.

use garrison_testing::lab::Lab;
use serde_json::json;

/// Stalwart's answer to doctor's sign-in check (doctor/public.rs): a sign-in
/// request with a fixed state and code challenge, with or without Garrison's
/// callback.
fn sign_in_answer(lab: &Lab, client: &str, callback: Option<&str>) -> serde_json::Value {
    let mut request = ureq::get(format!("{}/api/auth/client", lab.url)).query("client_id", client);
    if let Some(callback) = callback {
        request = request.query("redirect_uri", callback);
    }
    let mut answer = request
        .query("response_type", "code")
        .query("scope", "openid")
        .query("state", "garrison-doctor-0123456789abcdef")
        .query(
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        .query("code_challenge_method", "S256")
        .call()
        .unwrap();
    serde_json::from_str(&answer.body_mut().read_to_string().unwrap()).unwrap()
}

/// Stalwart names a registered client only for a request with its callback;
/// without one it answers with an error, which once made doctor report a
/// registered client as unknown.
pub(super) fn assert_sign_in_check(lab: &Lab, client: &str) {
    let callback = "https://admin.example.test/auth/callback";
    let answer = sign_in_answer(lab, client, Some(callback));
    assert_eq!(answer["verified"], true, "{answer}");
    assert_eq!(answer["name"], "Garrison", "{answer}");
    let answer = sign_in_answer(lab, client, None);
    assert_eq!(answer["error"], "invalid_request", "{answer}");
}

/// Another application's client at Stalwart's own origin.
const FOREIGN: &str = "https://mail.example.test/oauth-client.json";

pub(super) fn register_foreign_client(lab: &Lab) {
    lab.call(
        "x:OAuthClient/set",
        &json!({"create": {"o": {"clientId": FOREIGN, "description": "Another application",
            "redirectUris": {}, "postLogoutRedirectUris": {}, "scopes": {}}}}),
    );
}

pub(super) fn assert_foreign_client_kept(lab: &Lab) {
    let clients = lab.call("x:OAuthClient/get", &json!({"ids": null}));
    assert!(
        clients["list"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["clientId"] == FOREIGN),
        "{clients:?}"
    );
}

/// The one OAuth client with this client ID, registered for sign-in only: no
/// service such as mail, no grant but the authorization code, back only to
/// its callback.
pub(super) fn oauth_client(lab: &Lab, client: &str) -> serde_json::Value {
    let list = lab.call("x:OAuthClient/get", &json!({"ids": null}));
    let mut matching = list["list"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["clientId"] == client);
    let found = matching
        .next()
        .unwrap_or_else(|| panic!("no OAuth client {client}"));
    assert!(matching.next().is_none(), "two OAuth clients {client}");
    assert_eq!(
        found["redirectUris"],
        json!({"https://admin.example.test/auth/callback": true})
    );
    assert_eq!(found["scopes"], json!({}));
    assert_eq!(found["grantTypes"], json!({"authorizationCode": true}));
    found.clone()
}
