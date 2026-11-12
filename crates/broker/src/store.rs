//! Durable job audit and idempotency records for maintenance actions.

use std::path::Path;

use garrison_core::config::Database;
use garrison_core::sqlite::{self, Migration, SqliteError};
use garrison_core::time;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};

const RETENTION_SECONDS: i64 = 30 * 86400;
pub const MAX_JOBS: i64 = 1000;
const COLUMNS: &str = "id,action_id,actor,actor_email,request_id,status,created_at,\
                       started_at,finished_at,message,may_still_run";

/// The schema version this release writes; `self-check` accepts up to it.
pub const SCHEMA_VERSION: usize = MIGRATIONS.len();

const MIGRATIONS: [Migration; 1] = [&[
    "CREATE TABLE jobs(
        id TEXT PRIMARY KEY,
        action_id TEXT NOT NULL,
        actor TEXT NOT NULL,
        actor_email TEXT NOT NULL,
        request_id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL CHECK(status IN
            ('queued','running','succeeded','failed','uncertain')),
        created_at INTEGER NOT NULL,
        started_at INTEGER,
        finished_at INTEGER,
        message TEXT NOT NULL,
        may_still_run INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE INDEX jobs_created ON jobs(created_at)",
]];

/// Seconds since the epoch, as the job timestamps are stored.
pub fn now() -> i64 {
    time::now().as_second()
}

fn iso(stamp: Option<i64>) -> Option<String> {
    let instant = time::Timestamp::from_second(stamp?).ok()?;
    Some(time::isoformat(instant))
}

/// Where a job is in its life, stored and sent as its lowercase name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    /// The result could not be confirmed.
    Uncertain,
}

impl JobStatus {
    const ALL: [JobStatus; 5] = [
        JobStatus::Queued,
        JobStatus::Running,
        JobStatus::Succeeded,
        JobStatus::Failed,
        JobStatus::Uncertain,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            JobStatus::Queued => "queued",
            JobStatus::Running => "running",
            JobStatus::Succeeded => "succeeded",
            JobStatus::Failed => "failed",
            JobStatus::Uncertain => "uncertain",
        }
    }

    /// Accepted and not finished yet.
    pub const fn is_pending(self) -> bool {
        matches!(self, JobStatus::Queued | JobStatus::Running)
    }
}

impl ToSql for JobStatus {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(self.as_str().into())
    }
}

impl FromSql for JobStatus {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let text = value.as_str()?;
        JobStatus::ALL
            .into_iter()
            .find(|status| status.as_str() == text)
            .ok_or(FromSqlError::InvalidType)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Job {
    pub id: String,
    pub action_id: String,
    /// The OIDC subject that asked for the job.
    pub actor: String,
    /// The subject's address when it asked; empty if Stalwart named none.
    pub actor_email: String,
    pub request_id: String,
    pub status: JobStatus,
    /// Seconds since the epoch, like the two times after it.
    pub created_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub message: String,
    /// The operation may still be running although its record is finished.
    pub may_still_run: bool,
}

impl Job {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Job> {
        Ok(Job {
            id: row.get(0)?,
            action_id: row.get(1)?,
            actor: row.get(2)?,
            actor_email: row.get(3)?,
            request_id: row.get(4)?,
            status: row.get(5)?,
            created_at: row.get(6)?,
            started_at: row.get(7)?,
            finished_at: row.get(8)?,
            message: row.get(9)?,
            may_still_run: row.get::<_, i64>(10)? != 0,
        })
    }

    pub fn view(&self) -> JobView {
        JobView {
            id: self.id.clone(),
            action_id: self.action_id.clone(),
            actor: self.actor.clone(),
            actor_email: self.actor_email.clone(),
            request_id: self.request_id.clone(),
            status: self.status,
            created_at: iso(Some(self.created_at)),
            started_at: iso(self.started_at),
            finished_at: iso(self.finished_at),
            message: self.message.clone(),
        }
    }
}

/// What the interface may see of a job, as the broker sends it: the times as
/// ISO 8601 text, and not whether the operation may still run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobView {
    pub id: String,
    pub action_id: String,
    pub actor: String,
    pub actor_email: String,
    pub request_id: String,
    pub status: JobStatus,
    pub created_at: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub message: String,
}

/// A change to a job record; only these fields ever change.
#[derive(Clone, Debug, Default)]
pub struct Change<'a> {
    pub status: Option<JobStatus>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub message: Option<&'a str>,
    pub may_still_run: Option<bool>,
}

#[derive(Debug)]
pub struct JobStore {
    db: Connection,
}

impl JobStore {
    /// Open the audit. A broker restart cannot know whether systemd finished
    /// an accepted job: such jobs are recorded as uncertain, never repeated.
    pub fn open(path: &Path) -> Result<Self, SqliteError> {
        let db = sqlite::open_database(path, &MIGRATIONS, Database::Jobs)?;
        db.execute(
            "UPDATE jobs SET status='uncertain', finished_at=?, may_still_run=1, \
             message='The broker restarted while the result was pending; the operation \
             was not repeated.' WHERE status IN ('queued','running')",
            [now()],
        )?;
        let store = JobStore { db };
        store.prune()?;
        Ok(store)
    }

    /// Expire old records, but keep anything that may still be running.
    pub fn prune(&self) -> rusqlite::Result<()> {
        self.db.execute(
            "DELETE FROM jobs WHERE created_at < ? AND may_still_run=0 \
             AND status NOT IN ('queued','running')",
            [now() - RETENTION_SECONDS],
        )?;
        Ok(())
    }

    fn one(&self, condition: &str, value: &str) -> rusqlite::Result<Option<Job>> {
        let sql = format!("SELECT {COLUMNS} FROM jobs WHERE {condition}=?");
        self.db.query_row(&sql, [value], Job::from_row).optional()
    }

    pub fn by_request(&self, request_id: &str) -> rusqlite::Result<Option<Job>> {
        self.one("request_id", request_id)
    }

    pub fn get(&self, identifier: &str) -> rusqlite::Result<Option<Job>> {
        self.one("id", identifier)
    }

    fn many(&self, sql: &str, limit: Option<i64>) -> rusqlite::Result<Vec<Job>> {
        let mut statement = self.db.prepare(sql)?;
        let rows = match limit {
            Some(limit) => statement.query_map([limit], Job::from_row)?,
            None => statement.query_map([], Job::from_row)?,
        };
        rows.collect()
    }

    /// The newest jobs first; of one second, the one recorded last.
    pub fn recent(&self, limit: i64) -> rusqlite::Result<Vec<Job>> {
        self.many(
            &format!("SELECT {COLUMNS} FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?"),
            Some(limit),
        )
    }

    /// Jobs that are queued, running or may still be running.
    pub fn active(&self) -> rusqlite::Result<Vec<Job>> {
        self.many(
            &format!(
                "SELECT {COLUMNS} FROM jobs WHERE status IN ('queued','running') OR may_still_run=1"
            ),
            None,
        )
    }

    /// When the newest job (of one action, or of any) was created.
    pub fn latest_created(&self, action_id: Option<&str>) -> rusqlite::Result<Option<i64>> {
        match action_id {
            None => self
                .db
                .query_row("SELECT max(created_at) FROM jobs", [], |row| row.get(0)),
            Some(action) => self.db.query_row(
                "SELECT max(created_at) FROM jobs WHERE action_id=?",
                [action],
                |row| row.get(0),
            ),
        }
    }

    pub fn count(&self) -> rusqlite::Result<i64> {
        self.db
            .query_row("SELECT count(*) FROM jobs", [], |row| row.get(0))
    }

    pub fn insert(&self, job: &Job) -> rusqlite::Result<()> {
        self.db.execute(
            &format!("INSERT INTO jobs({COLUMNS}) VALUES(?,?,?,?,?,?,?,?,?,?,?)"),
            params![
                job.id,
                job.action_id,
                job.actor,
                job.actor_email,
                job.request_id,
                job.status,
                job.created_at,
                job.started_at,
                job.finished_at,
                job.message,
                i64::from(job.may_still_run),
            ],
        )?;
        Ok(())
    }

    pub fn update(&self, identifier: &str, change: &Change<'_>) -> rusqlite::Result<()> {
        // COALESCE keeps every field the change leaves out.
        self.db.execute(
            "UPDATE jobs SET status=COALESCE(?,status), started_at=COALESCE(?,started_at), \
             finished_at=COALESCE(?,finished_at), message=COALESCE(?,message), \
             may_still_run=COALESCE(?,may_still_run) WHERE id=?",
            params![
                change.status,
                change.started_at,
                change.finished_at,
                change.message,
                change.may_still_run.map(i64::from),
                identifier,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
