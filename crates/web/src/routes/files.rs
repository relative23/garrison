//! The compiled interface: each view's page, hashed assets, the icon and the
//! switch script that the Stalwart WebUI loads.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use garrison_core::files::read_bounded;
use sha2::{Digest, Sha256};

use crate::app::{App, INTERFACE, InlineStyle};
use crate::coding::accepts;
use crate::error::ApiError;
use crate::models::Theme;
use crate::security::Visitor;
use crate::switch::{SCRIPT, origin};

const NOT_BUILT: &str = "<!doctype html><title>Garrison</title><p>The interface has not \
                         been built. Run <code>npm ci && npm run build</code> or install a \
                         release archive.</p>";
/// Larger files are not part of the interface.
const MAX_FILE: usize = 16 * 1024 * 1024;
/// The build leaves a Brotli and a gzip copy beside each asset and page, best
/// first: the content coding and the copy's suffix.
const ENCODINGS: [(&str, &str); 2] = [("br", "br"), ("gzip", "gz")];

pub(crate) fn routes() -> Router<Arc<App>> {
    Router::new()
        // The root leads to the interface, as Stalwart's leads to its WebUI.
        .route("/", get(root))
        .route(INTERFACE, get(slash))
        .route(&format!("{INTERFACE}/"), get(root_page))
        .route(&format!("{INTERFACE}/assets/{{name}}"), get(asset))
        .route(&format!("{INTERFACE}/favicon.svg"), get(favicon))
        .route(&format!("{INTERFACE}/{SCRIPT}"), get(switch_script))
        .route(&format!("{INTERFACE}/{{*view}}"), get(view))
}

/// Media types of the interface files; text types carry their charset.
fn media_type(name: &str) -> &'static str {
    match name.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/vnd.microsoft.icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// A regular file of the interface, read off the async threads without
/// following symbolic links.
async fn file(path: PathBuf, media: &'static str) -> Option<Response> {
    let data = tokio::task::spawn_blocking(move || read_bounded(&path, MAX_FILE))
        .await
        .ok()?
        .ok()?;
    let mut response = data.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(media));
    Some(response)
}

fn moved(status: StatusCode) -> Response {
    let mut response = status.into_response();
    if let Ok(location) = HeaderValue::from_str(&format!("{INTERFACE}/")) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

async fn root() -> Response {
    moved(StatusCode::FOUND)
}

async fn slash() -> Response {
    moved(StatusCode::PERMANENT_REDIRECT)
}

/// The page of a view the build drew ahead (frontend/prerender.mjs): a plain
/// name of letters and underscores, or none. A detail below a view gets none:
/// the drawn page starts the requests of the view's list.
fn drawn(view: &str) -> Option<&str> {
    let mut parts = view.split('/');
    let name = parts.next().filter(|name| !name.is_empty())?;
    let plain = name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
    (plain && parts.all(str::is_empty)).then_some(name)
}

/// The theme a signed-in user chose, which the web service keeps with the
/// user's other preferences. Preferences that cannot be read leave the page
/// to follow the system, as before anything is chosen; the interface then
/// says what failed when it asks for the session.
fn chosen_theme(app: &App, subject: &str) -> Theme {
    app.store
        .preferences(subject)
        .map(|preferences| preferences.theme)
        .unwrap_or_default()
}

/// The files that may hold `name` (a page, or the index) for `theme`, best
/// first. The build draws each page once more for each theme a user can
/// choose, as `name.dark.html` beside `name.html`, so that the first paint
/// is in that theme; the plain page follows the system. No request names a
/// file: `drawn` takes no dot.
fn themed(name: &str, theme: Theme) -> Vec<String> {
    let plain = format!("{name}.html");
    match theme {
        Theme::System => vec![plain],
        Theme::Light => vec![format!("{name}.light.html"), plain],
        Theme::Dark => vec![format!("{name}.dark.html"), plain],
    }
}

/// The page for a path: with a session the view's frame, without one the
/// sign-in page, both drawn by the build so the first paint needs no script,
/// and with a session in the theme its user chose. The root leads to the
/// dashboard. Anything else gets the plain index, in that theme as well.
async fn page(app: Arc<App>, visitor: Visitor, headers: &HeaderMap, view: &str) -> Response {
    let reader = Arc::clone(&app);
    let visit = tokio::task::spawn_blocking(move || {
        let session = reader.gate.bound_session(&visitor)?;
        Ok::<_, ApiError>(session.map(|session| chosen_theme(&reader, &session.subject)))
    })
    .await;
    let (name, theme) = match visit {
        Ok(Ok(Some(theme))) => (
            drawn(view).or(view.is_empty().then_some("dashboard")),
            theme,
        ),
        // Nobody's choice is known: the sign-in page follows the system.
        Ok(Ok(None)) => (Some("sign-in"), Theme::System),
        // The plain index asks for the session itself.
        _ => (None, Theme::System),
    };
    if let Some(name) = name {
        let pages = app.static_directory.join("pages");
        for file in themed(name, theme) {
            if let Some(response) = drawn_page(pages.join(file), headers).await {
                return response;
            }
        }
    }
    index(&app, headers, theme).await
}

/// A page the build drew, with the hash of the stylesheet it carries inline
/// (`InlineStyle`), taken from the page itself so the two always match.
async fn drawn_page(path: PathBuf, headers: &HeaderMap) -> Option<Response> {
    let plain = path.clone();
    let page = tokio::task::spawn_blocking(move || read_bounded(&plain, MAX_FILE))
        .await
        .ok()?
        .ok()?;
    let mut response = encoded(path, "text/html; charset=utf-8", headers).await?;
    if let Some(hash) = inline_style(&page) {
        response.extensions_mut().insert(InlineStyle(hash));
    }
    Some(response)
}

/// The CSP hash of a page's `<style>` element, computed as the browser does,
/// over the element's text.
fn inline_style(page: &[u8]) -> Option<String> {
    let (_, rest) = std::str::from_utf8(page).ok()?.split_once("<style>")?;
    let (style, _) = rest.split_once("</style>")?;
    Some(format!("sha256-{}", STANDARD.encode(Sha256::digest(style))))
}

async fn index(app: &App, headers: &HeaderMap, theme: Theme) -> Response {
    for file in themed("index", theme) {
        let path = app.static_directory.join(file);
        if let Some(response) = encoded(path, "text/html; charset=utf-8", headers).await {
            return response;
        }
    }
    let mut response = (StatusCode::SERVICE_UNAVAILABLE, NOT_BUILT).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

async fn asset(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    // One plain file name: an encoded "../" arrives here decoded and is refused.
    let plain = !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != "..";
    if !plain {
        return ApiError::not_found().into_response();
    }
    let path = app.static_directory.join("assets").join(&name);
    encoded(path, media_type(&name), &headers)
        .await
        .unwrap_or_else(|| ApiError::not_found().into_response())
}

/// `path` in the best coding the browser accepts, or as it is.
async fn encoded(path: PathBuf, media: &'static str, headers: &HeaderMap) -> Option<Response> {
    let accepted = headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let mut answer = None;
    for (coding, suffix) in ENCODINGS {
        if !accepts(accepted, coding) {
            continue;
        }
        let mut copy = path.clone().into_os_string();
        copy.push(format!(".{suffix}"));
        if let Some(mut response) = file(copy.into(), media).await {
            response
                .headers_mut()
                .insert(header::CONTENT_ENCODING, HeaderValue::from_static(coding));
            answer = Some(response);
            break;
        }
    }
    let mut response = match answer {
        Some(response) => response,
        None => file(path, media).await?,
    };
    // Caches keep the copies apart by what each browser accepts.
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    Some(response)
}

async fn favicon(State(app): State<Arc<App>>) -> Response {
    file(app.static_directory.join("favicon.svg"), "image/svg+xml")
        .await
        .unwrap_or_else(|| ApiError::not_found().into_response())
}

/// Loaded into the Stalwart WebUI by the nginx include (see `switch`), possibly
/// from another origin; the tag pins it by hash.
async fn switch_script(State(app): State<Arc<App>>) -> Response {
    let script = app.static_directory.join(SCRIPT);
    let Some(mut response) = file(script, "text/javascript; charset=utf-8").await else {
        return ApiError::not_found().into_response();
    };
    if let Ok(value) = HeaderValue::from_str(&origin(&app.config.deployment.admin_url)) {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    response
}

/// Client-side routes such as /admin/logs load the same page.
async fn root_page(State(app): State<Arc<App>>, visitor: Visitor, headers: HeaderMap) -> Response {
    page(app, visitor, &headers, "").await
}

async fn view(
    State(app): State<Arc<App>>,
    Path(view): Path<String>,
    visitor: Visitor,
    headers: HeaderMap,
) -> Response {
    if view.starts_with("assets/") {
        return ApiError::not_found().into_response();
    }
    page(app, visitor, &headers, &view).await
}
