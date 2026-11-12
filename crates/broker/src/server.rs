//! The broker's side of the protocol: accept, check the peer, answer.
//!
//! The socket is created by systemd (garrison-broker.socket) with group
//! `garrison` and mode 0660. In addition, the broker reads the peer's
//! kernel-verified UID (`SO_PEERCRED`) and accepts only the configured service
//! users. No shared token exists that could leak from a configuration file.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::protocol::{BrokerError, MAX_REQUEST, Request, decode, read_line, refuse};
use crate::service::Broker;

const TIMEOUT: Duration = Duration::from_secs(10);
/// Requests served at once. The unit allows the broker 32 tasks
/// (`TasksMax=`); the rest stays free for a maintenance job and its
/// `systemctl`. A connection beyond the limit is closed unanswered, which its
/// client reports as an unavailable broker.
const MAX_CONNECTIONS: usize = 16;
/// The pause after a failed accept. It doubles up to the longest one while
/// accepting keeps failing, as it does without a free file descriptor, so
/// that the loop neither spins nor fills the journal.
const FIRST_PAUSE: Duration = Duration::from_millis(5);
const LONGEST_PAUSE: Duration = Duration::from_secs(1);

/// The `result` of an answer line.
fn result(answer: impl Serialize) -> Value {
    serde_json::to_value(answer).unwrap_or(Value::Null)
}

/// One request to one broker operation.
pub fn dispatch(broker: &Arc<Broker>, request: &Request) -> Result<Value, BrokerError> {
    match request {
        Request::Authorize { token } => broker.authorize(token).map(result),
        Request::Catalog { token } => broker.catalog(token).map(result),
        Request::Job { token, id } => broker.job(token, id).map(result),
        Request::Submit {
            token,
            action,
            request_id,
            confirmation,
        } => broker
            .submit(token, action, request_id, confirmation)
            .map(result),
    }
}

fn failure(error: &BrokerError) -> Value {
    json!({"ok": false, "status": error.status, "error": error.message})
}

/// Serve one connection: check the peer, answer one request.
fn handle(broker: &Arc<Broker>, allowed: &BTreeSet<u32>, mut stream: UnixStream) {
    if stream.set_read_timeout(Some(TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(TIMEOUT)).is_err()
    {
        return;
    }
    let peer =
        rustix::net::sockopt::socket_peercred(&stream).map(|credentials| credentials.uid.as_raw());
    if !peer.is_ok_and(|uid| allowed.contains(&uid)) {
        log::warn!("Rejected a broker connection from an unexpected user");
        return;
    }
    let request = match read_line(&mut stream, MAX_REQUEST) {
        Ok(line) => decode(&line),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            Err(refuse(400, "Invalid broker request"))
        }
        Err(_) => return, // The client went away.
    };
    let answer = match request {
        Err(error) => failure(&error),
        Ok(request) => match catch_unwind(AssertUnwindSafe(|| dispatch(broker, &request))) {
            Ok(Ok(result)) => json!({"ok": true, "result": result}),
            Ok(Err(error)) => failure(&error),
            Err(_) => {
                log::error!("Broker request failed");
                failure(&refuse(500, "Internal broker error"))
            }
        },
    };
    let mut text = answer.to_string();
    text.push('\n');
    // The client may have given up already.
    let _ = stream.write_all(text.as_bytes());
}

/// One of the [`MAX_CONNECTIONS`] places. It is free again when dropped, also
/// when its request's thread panics or could not be started.
struct Place(Arc<AtomicUsize>);

impl Place {
    fn take(taken: &Arc<AtomicUsize>) -> Option<Place> {
        taken
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_CONNECTIONS).then_some(count + 1)
            })
            .ok()
            .map(|_| Place(Arc::clone(taken)))
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Accept connections forever, one thread each.
pub fn serve_on(listener: &UnixListener, broker: &Arc<Broker>, allowed: &BTreeSet<u32>) {
    serve(listener.incoming(), broker, allowed, &thread::sleep);
}

/// Serve `connections` until they end; `pause` waits after a failed accept.
///
/// The journal gets one line when accepting starts to fail or the places run
/// out, and none for each further connection until a request is served again.
fn serve(
    connections: impl Iterator<Item = io::Result<UnixStream>>,
    broker: &Arc<Broker>,
    allowed: &BTreeSet<u32>,
    pause: &dyn Fn(Duration),
) {
    let taken = Arc::new(AtomicUsize::new(0));
    let mut wait = FIRST_PAUSE;
    let (mut failing, mut full) = (false, false);
    for connection in connections {
        let stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                if !failing {
                    log::error!("Could not accept broker connections: {error}");
                }
                failing = true;
                pause(wait);
                wait = (wait * 2).min(LONGEST_PAUSE);
                continue;
            }
        };
        if failing {
            log::info!("Accepting broker connections again");
        }
        (failing, wait) = (false, FIRST_PAUSE);
        let Some(place) = Place::take(&taken) else {
            if !full {
                log::warn!(
                    "Closing broker connections: {MAX_CONNECTIONS} requests are being served"
                );
            }
            full = true;
            continue;
        };
        full = false;
        let (broker, allowed) = (Arc::clone(broker), allowed.clone());
        let started = thread::Builder::new()
            .name("broker-request".into())
            .spawn(move || {
                let _place = place;
                handle(&broker, &allowed, stream);
            });
        if let Err(error) = started {
            log::error!("Could not handle a broker connection: {error}");
        }
    }
}

/// The socket systemd passed, or a newly bound one for development.
///
/// Call this before any other thread starts: taking over the socket clears
/// systemd's `LISTEN_*` variables from the environment.
pub fn listener(socket_path: &Path) -> io::Result<UnixListener> {
    let activated = std::env::var("LISTEN_PID").ok() == Some(std::process::id().to_string())
        && std::env::var("LISTEN_FDS").ok().as_deref() == Some("1");
    if activated && let Some(listener) = listenfd::ListenFd::from_env().take_unix_listener(0)? {
        return Ok(listener);
    }
    match std::fs::remove_file(socket_path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixStream;
    use std::sync::{Mutex, mpsc};
    use std::time::Instant;

    use serde_json::Value;

    use crate::protocol::MAX_ANSWER;
    use crate::service::tests::make;

    const CATALOG: &[u8] = b"{\"op\": \"catalog\", \"token\": \"admin-token\"}\n";

    fn own_user() -> BTreeSet<u32> {
        BTreeSet::from([rustix::process::geteuid().as_raw()])
    }

    /// One request on a new connection handed to `serve`: the answer, or
    /// `None` when the connection was closed without one.
    fn asked(connections: &mpsc::Sender<io::Result<UnixStream>>) -> Option<Value> {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(CATALOG).unwrap();
        connections.send(Ok(server)).unwrap();
        match read_line(&mut client, MAX_ANSWER) {
            Ok(line) if line.is_empty() => None,
            Ok(line) => Some(serde_json::from_slice(&line).unwrap()),
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => None,
            Err(error) => panic!("neither answered nor closed: {error}"),
        }
    }

    #[test]
    fn accepting_pauses_longer_while_it_fails_and_starts_over_after_a_connection() {
        let setup = make(false);
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(CATALOG).unwrap();
        // As accept fails when the process has no file descriptor left.
        let failed = || Err(io::Error::from(rustix::io::Errno::MFILE));
        let mut connections: Vec<io::Result<UnixStream>> = (0..10).map(|_| failed()).collect();
        connections.push(Ok(server));
        connections.push(failed());
        let pauses = Mutex::new(Vec::new());
        serve(
            connections.into_iter(),
            &setup.broker,
            &own_user(),
            &|time| pauses.lock().unwrap().push(time.as_millis()),
        );
        assert_eq!(
            *pauses.lock().unwrap(),
            [5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000, 5]
        );
        // The connection between the failures was served.
        let line = read_line(&mut client, MAX_ANSWER).unwrap();
        let answer: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(answer["ok"], true, "{answer}");
    }

    #[test]
    fn connections_beyond_the_limit_are_closed_unanswered_until_a_place_is_free() {
        let setup = make(false);
        let (connections, incoming) = mpsc::channel();
        let broker = Arc::clone(&setup.broker);
        let server =
            thread::spawn(move || serve(incoming.into_iter(), &broker, &own_user(), &|_| {}));
        // Clients that send nothing keep every place taken.
        let mut silent = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let (client, server) = UnixStream::pair().unwrap();
            connections.send(Ok(server)).unwrap();
            silent.push(client);
        }
        assert_eq!(asked(&connections), None);
        // One of them goes away, and its place serves the next request.
        silent.pop();
        let deadline = Instant::now() + Duration::from_secs(5);
        let answer = loop {
            if let Some(answer) = asked(&connections) {
                break answer;
            }
            assert!(Instant::now() < deadline, "no place became free");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(answer["ok"], true, "{answer}");
        drop((connections, silent));
        server.join().unwrap();
    }

    #[test]
    fn an_oversized_request_gets_an_answer() {
        let broker = make(false).broker;
        let (mut client, server) = UnixStream::pair().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        client.write_all(&vec![b'x'; MAX_REQUEST + 1]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        handle(&broker, &BTreeSet::from([uid]), server);
        let answer: Value = serde_json::from_slice(&read_line(&mut client, 4096).unwrap()).unwrap();
        assert_eq!(
            answer,
            json!({"ok": false, "status": 400, "error": "Invalid broker request"})
        );
    }

    #[test]
    fn a_stranger_gets_no_answer() {
        let broker = make(false).broker;
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(b"{}\n").unwrap();
        handle(&broker, &BTreeSet::new(), server);
        // Closed unread, or reset because the request was never read.
        assert!(!read_line(&mut client, 4096).is_ok_and(|line| !line.is_empty()));
    }

    #[test]
    fn a_development_socket_replaces_a_stale_one_with_group_access() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker.sock");
        drop(listener(&path).unwrap());
        // The socket file stays behind, as after a crash; binding again replaces it.
        let again = listener(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o660);
        drop(again);
        let occupied = directory.path().join("occupied");
        std::fs::create_dir(&occupied).unwrap();
        let error = listener(&occupied).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::IsADirectory, "{error}");
    }
}
