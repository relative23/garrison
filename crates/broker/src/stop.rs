//! How the broker ends. systemd asks it to with a signal, at a restart of
//! the unit as the installer and `garrison stalwart setup --rotate` make
//! one. A signal that ended the process there and then took the requests
//! under way with it: a rights check or a sign-in got no answer, and its
//! user "Authorization is temporarily unavailable". So the signal is kept
//! from every thread and read where connections are accepted: once it has
//! come, no further connection is accepted, and the requests under way are
//! answered before the process ends. A connection that came after it stays
//! in systemd's socket, for the broker that is started next.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};

/// What says that the broker is to stop: readable once it is.
#[derive(Debug)]
pub struct Stop {
    asked: OwnedFd,
}

impl Stop {
    /// The signals by which systemd and a terminal end a service, kept from
    /// this thread and from every thread it starts, and read here instead.
    /// Call it before any other thread exists: a thread that was there
    /// before would still be ended by them, and the process with it.
    pub fn by_signal() -> io::Result<Stop> {
        let mut signals = SigSet::empty();
        signals.add(Signal::SIGTERM);
        signals.add(Signal::SIGINT);
        signals.thread_block()?;
        let asked = SignalFd::with_flags(&signals, SfdFlags::SFD_CLOEXEC)?;
        Ok(Stop::when_readable(asked.as_fd().try_clone_to_owned()?))
    }

    /// A stop that is asked for once `asked` can be read, as the end of a
    /// pipe is that was written to.
    #[must_use]
    pub fn when_readable(asked: OwnedFd) -> Stop {
        Stop { asked }
    }

    /// The connections of `listener`, each as it comes, until the stop is
    /// asked for: from then on none is accepted, also none that waits.
    pub fn connections<'a>(
        &'a self,
        listener: &'a UnixListener,
    ) -> impl Iterator<Item = io::Result<UnixStream>> + 'a {
        // Accepting must not wait where a connection went away again
        // between the poll and the accept.
        let prepared = listener.set_nonblocking(true);
        let mut prepared = Some(prepared);
        std::iter::from_fn(move || {
            if let Some(Err(error)) = prepared.take() {
                return Some(Err(error));
            }
            loop {
                let mut waiting = [
                    PollFd::new(self.asked.as_fd(), PollFlags::POLLIN),
                    PollFd::new(listener.as_fd(), PollFlags::POLLIN),
                ];
                match poll(&mut waiting, PollTimeout::NONE) {
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(error) => return Some(Err(error.into())),
                    Ok(_) => {}
                }
                let ready = |at: usize| waiting[at].any().unwrap_or(false);
                if ready(0) {
                    return None;
                }
                if !ready(1) {
                    continue;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        return Some(stream.set_nonblocking(false).map(|()| stream));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Some(Err(error)),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use serde_json::Value;

    use super::*;
    use crate::protocol::{MAX_ANSWER, read_line};
    use crate::server::serve;
    use crate::service::tests::make;

    const CATALOG: &[u8] = b"{\"op\": \"catalog\", \"token\": \"admin-token\"}\n";

    /// Once the stop is asked for, no further connection is accepted: one
    /// that came before it is served, and one that waits when it comes
    /// stays in the socket, where the broker started next finds it.
    #[test]
    fn a_connection_that_waits_when_the_stop_is_asked_for_stays_in_the_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // One end of a pair says the stop once the other is written to.
        let (asked, mut ask) = UnixStream::pair().unwrap();
        let stop = Stop::when_readable(asked.into());
        let mut connections = stop.connections(&listener);
        let first = UnixStream::connect(&path).unwrap();
        assert!(connections.next().unwrap().is_ok());
        // The stop is asked for, and then a second client connects.
        ask.write_all(b"x").unwrap();
        let second = UnixStream::connect(&path).unwrap();
        assert!(connections.next().is_none());
        assert!(connections.next().is_none());
        drop(connections);
        // The connection is still there for whoever accepts next.
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_ok());
        drop((first, second));
    }

    /// A request that is under way when the connections end, as they do
    /// when the stop is asked for, is answered before the serving returns:
    /// the process that ends after it takes no request with it.
    #[test]
    fn a_request_under_way_when_the_connections_end_is_answered_first() {
        let setup = make(false);
        let (connections, incoming) = mpsc::channel();
        let broker = Arc::clone(&setup.broker);
        let (returned, serving) = mpsc::channel();
        thread::spawn(move || {
            serve(incoming.into_iter(), &broker, &|_| true, &|_| {});
            returned.send(Instant::now()).unwrap();
        });
        // Half a request is sent, then the connections end.
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (begin, rest) = CATALOG.split_at(10);
        client.write_all(begin).unwrap();
        connections.send(Ok(server)).unwrap();
        drop(connections);
        // The serving waits for it: it has not returned a moment later.
        assert!(serving.recv_timeout(Duration::from_millis(300)).is_err());
        client.write_all(rest).unwrap();
        let line = read_line(&mut client, MAX_ANSWER).unwrap();
        let answered = Instant::now();
        let answer: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(answer["ok"], true, "{answer}");
        // And returns once the request is answered.
        let returned = serving.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(returned + Duration::from_millis(50) >= answered);
    }
}
