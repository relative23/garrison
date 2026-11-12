//! Content codings: which ones a browser accepts, and gzip for the API's JSON
//! answers, so that a page's data takes less of a slow link from its scripts.

use std::io::Write;

use axum::body::{Body, HttpBody, to_bytes};
use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use flate2::Compression;
use flate2::write::GzEncoder;

use crate::error::ApiError;

/// Smaller answers gain nothing from compression.
const SMALLEST: u64 = 1024;
/// Larger bodies go out as they are; no answer of the API is this large.
const LARGEST: u64 = 16 * 1024 * 1024;

/// Whether an `Accept-Encoding` value takes `coding`: by name with a weight
/// above zero, or else through `*`.
pub(crate) fn accepts(header: &str, coding: &str) -> bool {
    let mut any = false;
    for part in header.split(',') {
        let mut fields = part.split(';');
        let name = fields.next().unwrap_or_default().trim();
        let weight = fields
            .find_map(|field| field.trim().strip_prefix("q="))
            .map_or(1.0, |value| value.trim().parse::<f32>().unwrap_or(0.0));
        if name.eq_ignore_ascii_case(coding) {
            return weight > 0.0;
        }
        if name == "*" {
            any = weight > 0.0;
        }
    }
    any
}

/// Sends a JSON answer gzipped when the browser accepts gzip. Never the
/// session's: it carries the CSRF token, and a compressed answer that holds a
/// secret next to text an attacker chose gives the secret away by its length
/// (BREACH). No other answer of the API holds a secret.
pub(crate) async fn compress(request: Request, next: Next) -> Response {
    let gzip = request
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| accepts(value, "gzip"));
    let session = request.uri().path() == "/api/session";
    let response = next.run(request).await;
    let json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"application/json"));
    let size = response.body().size_hint().exact();
    let worth = size.is_some_and(|size| (SMALLEST..=LARGEST).contains(&size));
    if !gzip
        || session
        || !json
        || !worth
        || response.headers().contains_key(header::CONTENT_ENCODING)
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    // The whole body is in memory already: its exact size is known.
    let bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(error) => return ApiError::internal(&error).into_response(),
    };
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    let Some(compressed) = encoder
        .write_all(&bytes)
        .ok()
        .and_then(|()| encoder.finish().ok())
    else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    parts
        .headers
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    parts
        .headers
        .insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(compressed))
}
