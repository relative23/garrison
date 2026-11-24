//! API errors: a status and a `detail` text, as `{"detail": "..."}`.
//!
//! Details are fixed, operator-readable texts; internal causes go to the
//! journal only, since they may contain addresses or identifiers. The journal
//! line names the request's reference, which the answer carries.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use garrison_collector::store::{HistoryError, SnapshotError};
use garrison_core::sqlite::{SqliteError, held_by_the_writer, out_of_time};

use crate::models::ErrorDetail;
use crate::store::StoreError;

/// What a reader of another service's database answers where that service
/// held its database for longer than a reader waits, as the receiver does
/// while it removes a tenth of a full history: the writer's moment, which
/// passes. A narrower filter would not help.
pub(crate) const WAITED: &str =
    "The query waited too long for another service's write; try again in a moment";

/// What a read of another service's database that was stopped answers: one
/// that waited out the writer's commit, [`WAITED`], or one that ran out of
/// its own time, `slow`, which says what the user can do. Neither is a fault
/// of the service, so neither gets a line here; a reader that waited out the
/// writer has said so itself, once a minute for each database
/// (`garrison_core::sqlite`). `None` for any other error.
#[must_use]
pub(crate) fn stopped(cause: &rusqlite::Error, slow: &'static str) -> Option<ApiError> {
    if held_by_the_writer(cause) {
        Some(ApiError::new(503, WAITED))
    } else if out_of_time(cause) {
        Some(ApiError::new(503, slow))
    } else {
        None
    }
}

/// What a read stopped by its own time says where there is no filter to
/// narrow and no period to shorten.
pub(crate) const SLOW: &str = "The query took too long; try again in a moment";

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct ApiError {
    pub(crate) status: StatusCode,
    pub(crate) detail: String,
    /// What failed inside, for the journal only.
    cause: Option<String>,
}

/// The cause of an internal error on its way from the answer to the journal;
/// the reference middleware takes it off before the answer leaves.
#[derive(Clone, Debug)]
pub(crate) struct Cause(pub(crate) String);

impl ApiError {
    pub(crate) fn new(status: u16, detail: impl Into<String>) -> Self {
        ApiError {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            detail: detail.into(),
            cause: None,
        }
    }

    /// A request parameter or body did not match the API.
    pub(crate) fn invalid() -> Self {
        ApiError::new(400, "Invalid request parameters")
    }

    pub(crate) fn not_found() -> Self {
        ApiError::new(404, "Not found")
    }

    /// Something failed inside the service; the cause is logged, not sent.
    pub(crate) fn internal(cause: &dyn std::fmt::Display) -> Self {
        ApiError {
            cause: Some(cause.to_string()),
            ..ApiError::new(500, "Internal error")
        }
    }

    /// What failed, for the journal: the cause of an internal error, the
    /// detail of any other.
    pub fn cause(&self) -> &str {
        self.cause.as_deref().unwrap_or(&self.detail)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorDetail {
            detail: self.detail,
        };
        let mut response = (self.status, Json(body)).into_response();
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

/// Only a reader of another service's database meets this, where it opens
/// the database; the web service's own store has errors of its own.
impl From<SqliteError> for ApiError {
    fn from(error: SqliteError) -> Self {
        match &error {
            SqliteError::Sqlite(cause) => stopped(cause, SLOW),
            SqliteError::NewerSchema
            | SqliteError::JournalMode(_)
            | SqliteError::ForeignSchema
            | SqliteError::Io(_) => None,
        }
        .unwrap_or_else(|| ApiError::internal(&error))
    }
}

impl From<SnapshotError> for ApiError {
    fn from(error: SnapshotError) -> Self {
        match &error {
            SnapshotError::Sqlite(cause) => stopped(cause, SLOW),
            SnapshotError::Unreadable(_) => None,
        }
        .unwrap_or_else(|| ApiError::internal(&error))
    }
}

/// A metric history that ran out of its reader's time is the size of the
/// request: the user can ask for less, and nothing needs the journal.
impl From<HistoryError> for ApiError {
    fn from(error: HistoryError) -> Self {
        match &error {
            HistoryError::Sqlite(cause) => {
                stopped(cause, "The query took too long; choose a shorter period")
            }
            HistoryError::Invalid => None,
        }
        .unwrap_or_else(|| ApiError::internal(&error))
    }
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;

/// Run blocking work (SQLite, the broker socket, Stalwart) off the async
/// threads.
pub(crate) async fn blocking<T: Send + 'static>(
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

    /// Each error a reader of another service's database can meet, from
    /// opening it to its query, says that a wait for the writer passes, and
    /// hands nothing to the journal; a broken database stays the service's
    /// fault.
    #[test]
    fn a_reader_that_waited_out_the_writer_is_told_that_it_passes() {
        let failure = |code| rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), None);
        let busy = || failure(rusqlite::ffi::SQLITE_BUSY);
        let answers = [
            ApiError::from(SqliteError::Sqlite(busy())),
            ApiError::from(SnapshotError::Sqlite(busy())),
            ApiError::from(HistoryError::Sqlite(busy())),
        ];
        for answer in answers {
            assert_eq!(
                (answer.status.as_u16(), answer.detail.as_str()),
                (503, WAITED)
            );
            assert_eq!(cause(&answer.into_response()), None);
        }
        // The status out of its own time has no filter to narrow.
        let slow = ApiError::from(SnapshotError::Sqlite(failure(
            rusqlite::ffi::SQLITE_INTERRUPT,
        )));
        assert_eq!((slow.status.as_u16(), slow.detail.as_str()), (503, SLOW));
        for broken in [
            ApiError::from(SqliteError::Sqlite(failure(rusqlite::ffi::SQLITE_CORRUPT))),
            ApiError::from(SqliteError::ForeignSchema),
            ApiError::from(SnapshotError::Sqlite(failure(
                rusqlite::ffi::SQLITE_CORRUPT,
            ))),
        ] {
            assert_eq!(broken.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(cause(&broken.into_response()).is_some());
        }
    }
}
