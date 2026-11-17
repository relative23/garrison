//! The broker's side of the protocol: accept, check the peer, answer.
//!
//! The socket is created by systemd (garrison-broker.socket) with group
//! `garrison` and mode 0660. In addition, the broker reads the peer's
//! kernel-verified UID (`SO_PEERCRED`) and accepts only the configured service
//! users. No shared token exists that could leak from a configuration file.
//!
//! The peer is checked where the connection is accepted, before it gets one
//! of the places or a thread: a user who may not speak to the broker costs
//! it one system call, and takes no place from one who may.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::socket::getsockopt;
use nix::sys::socket::sockopt::PeerCredentials;
use serde::Serialize;
use serde_json::{Value, json};

use crate::protocol::{BrokerError, MAX_REQUEST, Request, decode, read_line, refuse};
use crate::quiet::Quiet;
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

/// Whether the user at the other end of `stream`, as the kernel names it, is
/// one of `allowed`. The UID is the boundary: the kernel names the PID of a
/// peer that the broker's PID namespace cannot see as 0, which rustix's
/// `UCred` cannot hold (its PID is never 0), so the credentials are read
/// into nix's, which takes the kernel's struct as it is.
fn peer_allowed(stream: &UnixStream, allowed: &BTreeSet<u32>) -> bool {
    getsockopt(stream, PeerCredentials)
        .is_ok_and(|credentials| allowed.contains(&credentials.uid()))
}

/// Say that the broker could not read a request, at once and then at most
/// once a minute, with how many more there were. Only an admitted peer
/// sends one, and the web service sends none such of this release: one of
/// another release, or a client of another program, would.
fn unreadable(said: &Mutex<Quiet>, error: &BrokerError) {
    let more = said.lock().unwrap_or_else(PoisonError::into_inner).due(
        &error.message,
        "for",
        Instant::now(),
    );
    if let Some(more) = more {
        log::warn!(
            "The broker could not read a request ({}): its peer sent what is no request of \
             this release's protocol, as a web service of another release would; restart \
             garrison-web and garrison-broker, so that both run this release{more}",
            error.message
        );
    }
}

/// Serve one connection whose peer was admitted: answer one request.
fn handle(broker: &Arc<Broker>, mut stream: UnixStream, said: &Mutex<Quiet>) {
    if stream.set_read_timeout(Some(TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(TIMEOUT)).is_err()
    {
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
        Err(error) => {
            unreadable(said, &error);
            failure(&error)
        }
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
    serve(
        listener.incoming(),
        broker,
        &|stream| peer_allowed(stream, allowed),
        &thread::sleep,
    );
}

/// Whether the `count`-th connection of an unexpected user is worth a line
/// in the journal: the first is, and then every hundredth.
const fn worth_a_line(count: u64) -> bool {
    count == 1 || count.is_multiple_of(100)
}

/// Serve those of `connections` that `admits` lets in, until they end;
/// `pause` waits after a failed accept.
///
/// The journal gets one line when accepting starts to fail or the places run
/// out, and none for each further connection until a request is served again.
fn serve(
    connections: impl Iterator<Item = io::Result<UnixStream>>,
    broker: &Arc<Broker>,
    admits: &dyn Fn(&UnixStream) -> bool,
    pause: &dyn Fn(Duration),
) {
    let taken = Arc::new(AtomicUsize::new(0));
    let said = Arc::new(Mutex::new(Quiet::new()));
    let mut wait = FIRST_PAUSE;
    let (mut failing, mut full) = (false, false);
    let mut strangers: u64 = 0;
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
        // Closed unanswered, here and now: no place, no thread.
        if !admits(&stream) {
            strangers += 1;
            if worth_a_line(strangers) {
                log::warn!(
                    "Rejected a broker connection from an unexpected user ({strangers} since \
                     the broker started)"
                );
            }
            continue;
        }
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
        let (broker, said) = (Arc::clone(broker), Arc::clone(&said));
        let started = thread::Builder::new()
            .name("broker-request".into())
            .spawn(move || {
                let _place = place;
                handle(&broker, stream, &said);
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
    use crate::service::limit_tests::{kept, kept_lines};
    use crate::service::tests::make;

    const CATALOG: &[u8] = b"{\"op\": \"catalog\", \"token\": \"admin-token\"}\n";

    /// Everyone is let in: the tests' connections are all this user's.
    fn anyone(_: &UnixStream) -> bool {
        true
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
        serve(connections.into_iter(), &setup.broker, &anyone, &|time| {
            pauses.lock().unwrap().push(time.as_millis());
        });
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
        let server = thread::spawn(move || serve(incoming.into_iter(), &broker, &anyone, &|_| {}));
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
        client.write_all(&vec![b'x'; MAX_REQUEST + 1]).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        handle(&broker, server, &Mutex::new(Quiet::new()));
        let answer: Value = serde_json::from_slice(&read_line(&mut client, 4096).unwrap()).unwrap();
        assert_eq!(
            answer,
            json!({"ok": false, "status": 400, "error": "Invalid broker request"})
        );
    }

    /// A request the broker cannot read gets its answer, and the broker's
    /// journal says so at once, but once a minute however many come.
    #[test]
    fn a_request_the_broker_cannot_read_is_said_in_its_journal() {
        kept();
        let broker = make(false).broker;
        let said = Mutex::new(Quiet::new());

        for _ in 0..3 {
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .write_all(b"{\"op\": \"shell\", \"token\": \"admin-token\"}\n")
                .unwrap();
            handle(&broker, server, &said);
            let line = read_line(&mut client, 4096).unwrap();
            let answer: Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(
                answer,
                json!({"ok": false, "status": 400, "error": "Unknown broker operation"})
            );
        }
        let start = "WARN The broker could not read a request (Unknown broker operation)";
        assert_eq!(kept_lines(start, "").len(), 1);
    }

    #[test]
    fn the_peer_is_who_the_kernel_says_it_is() {
        let (_client, server) = UnixStream::pair().unwrap();
        let own = rustix::process::geteuid().as_raw();
        assert!(peer_allowed(&server, &BTreeSet::from([own])));
        assert!(!peer_allowed(&server, &BTreeSet::from([own + 1])));
        assert!(!peer_allowed(&server, &BTreeSet::new()));
    }

    #[test]
    fn a_stranger_is_sent_away_where_it_is_accepted_and_takes_no_place() {
        let setup = make(false);
        let (connections, incoming) = mpsc::channel();
        let broker = Arc::clone(&setup.broker);
        // Where each connection was looked at, and whether it was let in:
        // the first hundred are strangers.
        let looked_at = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&looked_at);
        let server = thread::spawn(move || {
            let admits = |_: &UnixStream| {
                let mut seen = seen.lock().unwrap();
                seen.push(thread::current().id());
                seen.len() > 100
            };
            serve(incoming.into_iter(), &broker, &admits, &|_| {});
        });
        // Each sends a request that would be answered, and stays connected.
        let mut strangers = Vec::new();
        for _ in 0..100 {
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client.write_all(CATALOG).unwrap();
            connections.send(Ok(server)).unwrap();
            strangers.push(client);
        }
        // A hundred of them, far more than there are places, keep nobody
        // out who may speak to the broker.
        let answer = asked(&connections).expect("an answer for an admitted peer");
        assert_eq!(answer["ok"], true, "{answer}");
        for mut stranger in strangers {
            // Closed unanswered, or reset because the request was never read.
            assert!(!read_line(&mut stranger, MAX_ANSWER).is_ok_and(|line| !line.is_empty()));
        }
        drop(connections);
        let accepting = server.thread().id();
        server.join().unwrap();
        // Every connection was looked at by the thread that accepts them:
        // none got a thread of its own for that.
        let looked_at = looked_at.lock().unwrap();
        assert_eq!(looked_at.len(), 101);
        assert!(looked_at.iter().all(|thread| *thread == accepting));
    }

    #[test]
    fn the_journal_gets_the_first_stranger_and_every_hundredth() {
        let said: Vec<u64> = (1..=250).filter(|count| worth_a_line(*count)).collect();
        assert_eq!(said, [1, 100, 200]);
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
