//! Garrison's OAuth client in Stalwart, for sign-in only.

use garrison_core::config::Config;

use super::Admin;
use super::objects::{Enabled, OAuthClient, Set, Stored};

/// Garrison's OAuth client, where Stalwart has one: the one with Garrison's
/// client ID.
pub(super) fn find(admin: &Admin, config: &Config) -> Result<Option<Stored>, String> {
    let client_id = garrison_web::app::client_id(&config.deployment.public_origin);
    let listed = admin.list::<Stored>("OAuthClient")?;
    Ok(listed
        .into_iter()
        .find(|item| item.text("clientId") == Some(client_id.as_str())))
}

/// Register Garrison as an OAuth client of Stalwart, or update the one
/// `existing` names where it differs; what was done, if anything.
///
/// Sign-in uses a client ID URL. Stalwart accepts such IDs from any website
/// only through its `clientMetadataDocuments` policy, which can stay off: a
/// registered client needs none and is shown under its own name as verified.
/// It may only return to the callback, gets no service such as mail (sign-in
/// only) and no grant but the authorization code: Stalwart allows a client a
/// refresh token unless told otherwise, and Garrison never asks for one.
pub(super) fn ensure(
    admin: &Admin,
    config: &Config,
    existing: Option<Stored>,
) -> Result<Option<String>, String> {
    let origin = &config.deployment.public_origin;
    let client_id = garrison_web::app::client_id(origin);
    let mut wanted = OAuthClient {
        client_id: None,
        description: "Garrison",
        redirect_uris: Enabled::of([garrison_web::app::redirect_uri(origin)]),
        post_logout_redirect_uris: Enabled::default(),
        scopes: Enabled::default(),
        grant_types: Enabled::of(["authorizationCode"]),
    };
    if let Some(stored) = existing {
        if stored.holds(&wanted) {
            return Ok(None);
        }
        admin.set("x:OAuthClient/set", &Set::update(&stored.id, wanted))?;
        return Ok(Some(format!("updated OAuth client {client_id}")));
    }
    wanted.client_id = Some(&client_id);
    admin.set("x:OAuthClient/set", &Set::create(wanted))?;
    Ok(Some(format!("registered OAuth client {client_id}")))
}
