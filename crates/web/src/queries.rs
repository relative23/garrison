//! Turns of the history queries.
//!
//! A history query (a list, detail or summary of the event history, or the
//! metric history) reads a database that another service writes, and while
//! it reads, that writer's commits wait; it also holds one of the few threads
//! the unit allows (`TasksMax=64`). So only [`RUNNING`] run at once. A further
//! one waits for its turn for as long as a query may run, and no more than
//! [`WAITING`] wait; any other is refused at once with 429. A query whose
//! request goes away, as when the browser has moved on to another filter,
//! stops at its reader's next check and gives its turn to the next one
//! instead of keeping it for nobody.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use garrison_core::sqlite::reading_until;
use rusqlite::Connection;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::error::{ApiError, ApiResult, blocking};

/// History queries that run at once.
pub const RUNNING: usize = 2;
/// History queries that may wait for a turn beside those that run.
pub const WAITING: usize = 8;
/// How long a history query may run, and so how long the next one waits.
pub(crate) const BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub struct Queries {
    /// A turn to run, held from a query's start to its end.
    pub running: Arc<Semaphore>,
    /// A place to run or to wait for a turn; a request that finds none is
    /// refused at once.
    pub admitted: Arc<Semaphore>,
    wait: Duration,
    budget: Duration,
}

impl Default for Queries {
    fn default() -> Self {
        Queries::new(RUNNING, WAITING, BUDGET, BUDGET)
    }
}

impl Queries {
    /// `running` queries at once and `waiting` more that wait up to `wait`
    /// for a turn; each runs for at most `budget`.
    pub(crate) fn new(running: usize, waiting: usize, wait: Duration, budget: Duration) -> Self {
        Queries {
            running: Arc::new(Semaphore::new(running)),
            admitted: Arc::new(Semaphore::new(running + waiting)),
            wait,
            budget,
        }
    }

    /// Run `query` on a reader of the database at `path` in this request's
    /// turn: 429 when too many wait or no turn comes within the wait, 503
    /// with `missing` while the database does not exist.
    pub async fn run<T: Send + 'static>(
        &self,
        path: PathBuf,
        missing: &'static str,
        query: impl FnOnce(&Connection) -> ApiResult<T> + Send + 'static,
    ) -> ApiResult<T> {
        let busy = || ApiError::new(429, "Too many concurrent history queries");
        let admitted = Arc::clone(&self.admitted)
            .try_acquire_owned()
            .map_err(|_| busy())?;
        // The semaphore is never closed, so an error is the time that ran out.
        let Ok(Ok(turn)) = timeout(self.wait, Arc::clone(&self.running).acquire_owned()).await
        else {
            return Err(busy());
        };
        let gone = Gone::default();
        let (stop, budget) = (Arc::clone(&gone.0), self.budget);
        blocking(move || {
            let _held = (admitted, turn);
            let db =
                reading_until(&path, budget, stop)?.ok_or_else(|| ApiError::new(503, missing))?;
            query(&db)
        })
        .await
    }
}

/// Set when the request a query answers is dropped. The server drops it when
/// its client closes the connection, as nginx does when a browser gives up a
/// request (it resets the HTTP/2 stream or closes its connection).
#[derive(Debug, Default)]
struct Gone(Arc<AtomicBool>);

impl Drop for Gone {
    fn drop(&mut self) {
        // After an answer as well, when no reader is left to look.
        self.0.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::sync::mpsc;
    use std::time::Instant;

    use axum::Router;
    use axum::routing::get;

    use super::*;

    const LONG: Duration = Duration::from_secs(3600);

    fn database() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("history.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE t(x)")
            .unwrap();
        (directory, path)
    }

    /// A query that runs until its reader stops it.
    fn endless(db: &Connection) -> ApiResult<i64> {
        let sql = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) \
                   SELECT count(*) FROM n";
        db.query_row(sql, [], |row| row.get(0))
            .map_err(|error| ApiError::internal(&error))
    }

    fn one(db: &Connection) -> ApiResult<i64> {
        db.query_row("SELECT 1", [], |row| row.get(0))
            .map_err(|error| ApiError::internal(&error))
    }

    /// Waits until `free` turns are left, for at most five seconds.
    async fn turns_left(queries: &Queries, free: usize) {
        for _ in 0..500 {
            if queries.running.available_permits() == free {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("{free} turns were never left");
    }

    fn status(answer: &ApiResult<i64>) -> Result<i64, u16> {
        answer
            .as_ref()
            .copied()
            .map_err(|error| error.status.as_u16())
    }

    #[tokio::test]
    async fn a_query_whose_request_is_gone_stops_and_gives_its_turn_away() {
        let (_directory, path) = database();
        // One turn, a long wait and a budget the test never reaches: only
        // the stop gives the turn to the next query in time.
        let queries = Arc::new(Queries::new(1, 1, LONG, LONG));
        let first = tokio::spawn({
            let (queries, path) = (Arc::clone(&queries), path.clone());
            async move { queries.run(path, "missing", endless).await }
        });
        turns_left(&queries, 0).await;
        first.abort();
        let started = Instant::now();
        let next = timeout(Duration::from_secs(10), queries.run(path, "missing", one)).await;
        assert_eq!(next.map(|answer| status(&answer)), Ok(Ok(1)));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// The writer of the database commits: a query that waits for it holds
    /// its turn only for as long as its request is there.
    #[tokio::test]
    async fn a_query_that_waits_for_the_writer_gives_its_turn_away_when_its_request_is_gone() {
        let (_directory, path) = database();
        let writer = Connection::open(&path).unwrap();
        writer.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let queries = Arc::new(Queries::new(1, 1, LONG, LONG));
        let first = tokio::spawn({
            let (queries, path) = (Arc::clone(&queries), path.clone());
            async move { queries.run(path, "missing", one).await }
        });
        turns_left(&queries, 0).await;
        first.abort();
        // The reader waited up to two seconds for the lock before.
        let freed = timeout(Duration::from_millis(1000), turns_left(&queries, 1)).await;
        writer.execute_batch("COMMIT").unwrap();
        assert!(
            freed.is_ok(),
            "the turn was not given away while the writer held its lock"
        );
        assert_eq!(status(&queries.run(path, "missing", one).await), Ok(1));
    }

    #[tokio::test]
    async fn a_query_waits_for_its_turn_and_overload_is_refused() {
        let (_directory, path) = database();
        let queries = Arc::new(Queries::new(1, 1, Duration::from_millis(300), LONG));
        // A query that runs until the test lets it end.
        let hold = |queries: &Arc<Queries>| {
            let (release, held) = mpsc::channel::<()>();
            let (queries, path) = (Arc::clone(queries), path.clone());
            let task = tokio::spawn(async move {
                let query = move |_: &Connection| Ok(i64::from(held.recv().is_ok()));
                queries.run(path, "missing", query).await
            });
            (release, task)
        };
        let (release, first) = hold(&queries);
        turns_left(&queries, 0).await;
        let second = tokio::spawn({
            let (queries, path) = (Arc::clone(&queries), path.clone());
            async move { queries.run(path, "missing", one).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // One runs and one waits: a third finds no room and is refused at once.
        let started = Instant::now();
        let third = queries.run(path.clone(), "missing", one).await;
        assert_eq!(status(&third), Err(429));
        assert!(started.elapsed() < Duration::from_millis(100));
        // The one that waited gets the turn when it is free.
        release.send(()).unwrap();
        assert_eq!(status(&first.await.unwrap()), Ok(1));
        assert_eq!(status(&second.await.unwrap()), Ok(1));
        // One that gets no turn within the wait is refused after it.
        let (release, first) = hold(&queries);
        turns_left(&queries, 0).await;
        let started = Instant::now();
        let late = queries.run(path.clone(), "missing", one).await;
        assert_eq!(status(&late), Err(429));
        assert!(started.elapsed() >= Duration::from_millis(300));
        release.send(()).unwrap();
        assert_eq!(status(&first.await.unwrap()), Ok(1));
        // A database that does not exist yet is the caller's message.
        let missing = queries
            .run(path.with_extension("none"), "missing", one)
            .await;
        assert_eq!(status(&missing), Err(503));
    }

    #[tokio::test]
    async fn a_query_stops_when_its_client_closes_the_connection() {
        let (_directory, path) = database();
        let queries = Arc::new(Queries::new(1, 0, LONG, LONG));
        let route = {
            let queries = Arc::clone(&queries);
            Router::new().route(
                "/",
                get(move || {
                    let (queries, path) = (Arc::clone(&queries), path.clone());
                    async move {
                        queries
                            .run(path, "missing", endless)
                            .await
                            .map(|count| count.to_string())
                    }
                }),
            )
        };
        // Served as the web service serves, with the peer's address.
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                route.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: garrison.example.test\r\n\r\n")
            .unwrap();
        turns_left(&queries, 0).await;
        // The browser gives the request up: its query ends, the turn is free.
        drop(client);
        turns_left(&queries, 1).await;
    }
}
