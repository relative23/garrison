//! Garrison's OAuth client in Stalwart, for sign-in only.

use garrison_core::config::Config;

use super::Admin;
use super::objects::{Enabled, OAuthClient, Set, StoredClient};

/// Register Garrison as an OAuth client of Stalwart.
///
/// Sign-in uses a client ID URL. Stalwart accepts such IDs from any website
/// only through its `clientMetadataDocuments` policy, which can stay off: a
/// registered client needs none and is shown under its own name as verified.
/// It may only return to the callback, gets no service such as mail (sign-in
/// only) and no grant but the authorization code: Stalwart allows a client a
/// refresh token unless told otherwise, and Garrison never asks for one.
pub(super) fn ensure_oauth_client(admin: &Admin, config: &Config) -> Result<String, String> {
    let origin = &config.deployment.public_origin;
    let client_id = garrison_web::app::client_id(origin);
    let mut wanted = OAuthClient {
        client_id: None,
        description: "Garrison",
        redirect_uris: Enabled::of([garrison_web::app::redirect_uri(origin)]),
        post_logout_redirect_uris: Enabled::none(),
        scopes: Enabled::none(),
        grant_types: Enabled::of(["authorizationCode"]),
    };
    let existing = admin
        .list::<StoredClient>("OAuthClient")?
        .into_iter()
        .find(|item| item.client_id.as_deref() == Some(client_id.as_str()));
    if let Some(item) = existing {
        admin.set("x:OAuthClient/set", &Set::update(&item.id, wanted))?;
        return Ok(format!("updated OAuth client {client_id}"));
    }
    wanted.client_id = Some(&client_id);
    admin.set("x:OAuthClient/set", &Set::create(wanted))?;
    Ok(format!("registered OAuth client {client_id}"))
}
