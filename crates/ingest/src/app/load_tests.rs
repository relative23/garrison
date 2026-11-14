//! The receiver under load, over real connections: a sender that stalls,
//! batches side by side, and a store that needs its clean-up.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

use tokio::runtime::Runtime;

use super::tests::{AT, KEY, WRITTEN, batch};
use super::*;
use crate::store::tests::{event, read, store};

/// The routes with `window` for a batch to arrive, and what tells the
/// maintenance task that the clean-up is due.
fn receiver(store: Arc<EventStore>, window: Duration) -> (Router, Arc<Notify>) {
    let receiver = Receiver::new(store, KEY, || WRITTEN, window);
    let due = Arc::clone(&receiver.due);
    (routes(receiver), due)
}

fn serve(runtime: &Runtime, app: Router) -> SocketAddr {
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let address = listener.local_addr().unwrap();
    runtime.spawn(async move { axum::serve(listener, app).await });
    address
}

/// A connection that sent the head of a signed batch and `sent` of its body.
fn begin(address: SocketAddr, body: &[u8], sent: usize) -> TcpStream {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let head = format!(
        "POST /webhook HTTP/1.1\r\nHost: receiver\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nX-Signature: {}\r\nConnection: close\r\n\r\n",
        body.len(),
        signature(KEY, body)
    );
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(&body[..sent]).unwrap();
    stream
}

/// The status and the body of the answer, or `None` if none came in time.
fn answer(stream: &mut TcpStream) -> Option<(u16, Value)> {
    let mut text = Vec::new();
    // The receiver closes the connection after its answer.
    stream.read_to_end(&mut text).ok()?;
    let text = String::from_utf8(text).ok()?;
    let status = text.split(' ').nth(1)?.parse().ok()?;
    let body = text.split_once("\r\n\r\n")?.1;
    Some((status, serde_json::from_str(body).unwrap_or(Value::Null)))
}

fn one_event(seq: u64) -> Vec<u8> {
    batch(&[event(seq, "auth.failed", AT, &json!({}))])
}

#[test]
fn a_batch_that_stalls_is_turned_away_and_counted() {
    let directory = tempfile::tempdir().unwrap();
    let events = Arc::new(store(directory.path(), 1000));
    let runtime = Runtime::new().unwrap();
    let (app, _) = receiver(Arc::clone(&events), Duration::from_millis(500));
    let address = serve(&runtime, app);
    let body = one_event(1);
    let began = Instant::now();
    // The head and ten bytes arrive, the rest never.
    let mut stalled = begin(address, &body, 10);
    let turned_away = answer(&mut stalled).expect("an answer to a sender that stalls");
    assert_eq!(turned_away.0, 408, "{turned_away:?}");
    assert!(began.elapsed() >= Duration::from_millis(400));
    // No batch was taken, and since when is kept as for any refusal.
    let health = events.health();
    assert_eq!(
        (health.refused, health.failing_since),
        (1, Some(WRITTEN)),
        "{health:?}"
    );
    // The turn is free again: the batch arrives whole and is stored.
    let mut whole = begin(address, &body, body.len());
    assert_eq!(
        answer(&mut whole),
        Some((200, json!({"status": "stored", "stored": 1, "skipped": 0})))
    );
    assert_eq!(events.health().failing_since, None);
}

#[test]
fn a_batch_waits_while_two_others_are_read() {
    let directory = tempfile::tempdir().unwrap();
    let events = Arc::new(store(directory.path(), 1000));
    let runtime = Runtime::new().unwrap();
    let window = Duration::from_secs(2);
    let (app, _) = receiver(Arc::clone(&events), window);
    let address = serve(&runtime, app);
    let body = one_event(1);
    // Two senders hold the two turns for as long as a batch has.
    let mut holders = [begin(address, &body, 10), begin(address, &body, 10)];
    std::thread::sleep(window / 2);
    let sent = Instant::now();
    let mut third = begin(address, &body, body.len());
    assert_eq!(
        answer(&mut third),
        Some((200, json!({"status": "stored", "stored": 1, "skipped": 0})))
    );
    // It was whole at once, and still read only when a turn was free.
    assert!(sent.elapsed() >= window / 3, "{:?}", sent.elapsed());
    for holder in &mut holders {
        assert_eq!(answer(holder).map(|(status, _)| status), Some(408));
    }
}

fn count(directory: &std::path::Path) -> i64 {
    read(directory)
        .query_row("SELECT count(*) FROM events", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn the_clean_up_follows_the_answer_and_does_not_wait_for_its_turn() {
    let directory = tempfile::tempdir().unwrap();
    // The store keeps a thousand events.
    let events = Arc::new(store(directory.path(), 1000));
    let runtime = Runtime::new().unwrap();
    let (app, due) = receiver(Arc::clone(&events), Duration::from_secs(5));
    let address = serve(&runtime, app);
    let many: Vec<Value> = (0..1100)
        .map(|seq| event(seq, "auth.failed", AT, &json!({})))
        .collect();
    let body = batch(&many);
    let mut sender = begin(address, &body, body.len());
    assert_eq!(
        answer(&mut sender),
        Some((
            200,
            json!({"status": "stored", "stored": 1100, "skipped": 0})
        ))
    );
    // The batch is answered before anything is removed for the limit.
    assert_eq!(count(directory.path()), 1100);
    assert!(events.cleanup_due());
    // The maintenance task was told: it cleans up now, not with its next
    // heartbeat in half a minute or its next round in ten.
    let maintenance = runtime.spawn(maintain(Arc::clone(&events), due));
    let began = Instant::now();
    while count(directory.path()) != 1000 {
        assert!(began.elapsed() < Duration::from_secs(10), "no clean-up");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!events.cleanup_due());
    maintenance.abort();
}
