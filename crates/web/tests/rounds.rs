//! The web service's rounds, which end the sessions whose time is over
//! with their tokens: once a second, and a minute after a round that
//! Stalwart did not answer. The rounds are given a clock that the test
//! moves itself, so that no second has to pass.

// Helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use support::{Setup, setup};
use tokio::sync::{mpsc, oneshot};

/// The pause before a round, and what ends it.
type Pause = (Duration, oneshot::Sender<()>);

/// The rows that hold `admin-token`, and how many of them a cookie finds.
fn rows(setup: &Setup) -> (i64, i64) {
    let db =
        rusqlite::Connection::open(setup.config.web.state_directory.join("web.sqlite")).unwrap();
    db.query_row(
        "SELECT count(*), count(*) FILTER (WHERE expires_at > unixepoch()) FROM sessions \
         WHERE token = 'admin-token'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

#[tokio::test]
async fn the_rounds_end_a_session_on_time_and_ask_again_a_minute_later() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    let (pausing, mut paused) = mpsc::unbounded_channel::<Pause>();
    let rounds = tokio::spawn(garrison_web::end_sessions_waiting(
        Arc::clone(&setup.app),
        move |pause| {
            let (end, ended) = oneshot::channel();
            pausing.send((pause, end)).unwrap();
            async move {
                let _ = ended.await;
            }
        },
    ));
    let revoked = |setup: &Setup| setup.provider.revoked.lock().unwrap().clone();
    // A second before the first round, and before the next while the
    // session lasts, which a round leaves alone.
    let (pause, end) = paused.recv().await.unwrap();
    assert_eq!(pause, Duration::from_secs(1));
    end.send(()).unwrap();
    let (pause, end) = paused.recv().await.unwrap();
    assert_eq!(pause, Duration::from_secs(1));
    assert_eq!((revoked(&setup), rows(&setup)), (Vec::new(), (1, 1)));
    // Its time is over, and Stalwart does not answer the revocation: the
    // session has ended, and its row waits a minute for the next round.
    let db =
        rusqlite::Connection::open(setup.config.web.state_directory.join("web.sqlite")).unwrap();
    db.execute(
        "UPDATE sessions SET expires_at = unixepoch() - 1 WHERE token = 'admin-token'",
        [],
    )
    .unwrap();
    setup.provider.away.store(true, Ordering::SeqCst);
    end.send(()).unwrap();
    let (pause, end) = paused.recv().await.unwrap();
    assert_eq!(pause, Duration::from_secs(60));
    assert_eq!((revoked(&setup), rows(&setup)), (Vec::new(), (1, 0)));
    // Stalwart answers again: the token is revoked, the row goes, and the
    // rounds come once a second again.
    setup.provider.away.store(false, Ordering::SeqCst);
    end.send(()).unwrap();
    let (pause, _end) = paused.recv().await.unwrap();
    assert_eq!(pause, Duration::from_secs(1));
    assert_eq!(
        (revoked(&setup), rows(&setup)),
        (vec!["admin-token".to_owned()], (0, 0))
    );
    rounds.abort();
}

/// A revocation that Stalwart refuses is not one, and no asking again
/// makes it one: the row goes, so that the rounds do not ask for it every
/// minute for good, and the next round comes after a second.
#[tokio::test]
async fn a_revocation_stalwart_refuses_is_not_asked_again() {
    let mut setup = setup();
    setup.client.sign_in("code-admin").await;
    let (pausing, mut paused) = mpsc::unbounded_channel::<Pause>();
    let rounds = tokio::spawn(garrison_web::end_sessions_waiting(
        Arc::clone(&setup.app),
        move |pause| {
            let (end, ended) = oneshot::channel();
            pausing.send((pause, end)).unwrap();
            async move {
                let _ = ended.await;
            }
        },
    ));
    let (_, end) = paused.recv().await.unwrap();
    let db =
        rusqlite::Connection::open(setup.config.web.state_directory.join("web.sqlite")).unwrap();
    db.execute(
        "UPDATE sessions SET expires_at = unixepoch() - 1 WHERE token = 'admin-token'",
        [],
    )
    .unwrap();
    setup.provider.refusing.store(true, Ordering::SeqCst);
    end.send(()).unwrap();
    let (pause, _end) = paused.recv().await.unwrap();
    assert_eq!(pause, Duration::from_secs(1));
    let revoked = setup.provider.revoked.lock().unwrap().clone();
    assert_eq!((revoked, rows(&setup)), (Vec::<String>::new(), (0, 0)));
    rounds.abort();
}
