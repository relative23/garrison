//! API errors: a status and a `detail` text, as `{"detail": "..."}`.
//!
//! Details are fixed, operator-readable texts; internal causes go to the
//! journal only, since they may contain addresses or identifiers. The journal
//! line names the request's reference, which the answer carries.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garrison_collector::store::{HistoryError, SnapshotError};
use garrison_core::sqlite::{SqliteError, out_of_time};
use serde_json::json;

use crate::store::StoreError;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct ApiError {
    pub status: StatusCode,
    pub detail: String,
    /// What failed inside, for the journal only.
    cause: Option<String>,
}

/// The cause of an internal error on its way from the answer to the journal;
/// the reference middleware takes it off before the answer leaves.
#[derive(Clone, Debug)]
pub struct Cause(pub String);

impl ApiError {
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            detail: detail.into(),
            cause: None,
        }
    }

    /// A request parameter or body did not match the API.
    pub fn invalid() -> Self {
        ApiError::new(400, "Invalid request parameters")
    }

    pub fn not_found() -> Self {
        ApiError::new(404, "Not found")
    }

    /// Something failed inside the service; the cause is logged, not sent.
    pub fn internal(cause: &dyn std::fmt::Display) -> Self {
        ApiError {
            cause: Some(cause.to_string()),
            ..ApiError::new(500, "Internal error")
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(json!({"detail": self.detail}))).into_response();
        if let Some(cause) = self.cause {
            response.extensions_mut().insert(Cause(cause));
        }
        response
    }
}

/// A failing store, database or stored document is an internal error. Its
/// text may name paths or identifiers, so it goes to the journal only.
impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        ApiError::internal(&error)
    }
}

impl From<SqliteError> for ApiError {
    fn from(error: SqliteError) -> Self {
        ApiError::internal(&error)
    }
}

impl From<SnapshotError> for ApiError {
    fn from(error: SnapshotError) -> Self {
        ApiError::internal(&error)
    }
}

/// A metric history that ran out of its reader's time is the size of the
/// request: the user can ask for less, and nothing needs the journal.
impl From<HistoryError> for ApiError {
    fn from(error: HistoryError) -> Self {
        match error {
            HistoryError::Sqlite(cause) if out_of_time(&cause) => {
                ApiError::new(503, "The query took too long; choose a shorter period")
            }
            error => ApiError::internal(&error),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Run blocking work (SQLite, the broker socket, Stalwart) off the async
/// threads.
pub async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> ApiResult<T> + Send + 'static,
) -> ApiResult<T> {
    tokio::task::spawn_blocking(work)
        .await
        .unwrap_or_else(|error| Err(ApiError::internal(&error)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cause(response: &Response) -> Option<&str> {
        response
            .extensions()
            .get::<Cause>()
            .map(|Cause(cause)| cause.as_str())
    }

    #[test]
    fn only_an_internal_error_hands_its_cause_to_the_journal() {
        let internal = ApiError::internal(&"disk I/O error").into_response();
        assert_eq!(internal.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(cause(&internal), Some("disk I/O error"));
        assert_eq!(cause(&ApiError::not_found().into_response()), None);
    }

    #[test]
    fn a_metric_history_out_of_time_says_what_the_user_can_do() {
        let sqlite = |code| {
            HistoryError::Sqlite(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                None,
            ))
        };
        let slow = ApiError::from(sqlite(rusqlite::ffi::SQLITE_INTERRUPT)).into_response();
        assert_eq!(slow.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(cause(&slow), None);
        let detail = ApiError::from(sqlite(rusqlite::ffi::SQLITE_INTERRUPT)).detail;
        assert_eq!(detail, "The query took too long; choose a shorter period");
        // Anything else stays an internal error with its cause in the journal.
        for broken in [sqlite(rusqlite::ffi::SQLITE_CORRUPT), HistoryError::Invalid] {
            let answer = ApiError::from(broken).into_response();
            assert_eq!(answer.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(cause(&answer).is_some());
        }
    }
}
