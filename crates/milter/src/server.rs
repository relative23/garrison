//! The filter's side of a connection, and the listener that takes them.
//!
//! The mail server opens a connection for a message, says what it can send,
//! then sends the message's headers and body. The filter keeps them up to a
//! size, scans them at the body's end and gives its one answer: take the
//! message, or refuse it. Where the operator chose to tag instead, the
//! message is taken with a header that says what was found.
//!
//! A message the scan could not look at completely is no clean message. It
//! gets what the operator chose for it ([`Settings::on_incomplete`]): a
//! header of its own, a temporary failure or a refusal.
//!
//! Memory is bounded for all connections together ([`Shared`]): the messages
//! being received may hold so much and no more, and one message is scanned
//! at a time. A message that finds no room is answered with a temporary
//! failure, so the sending server brings it again; the filter itself stays up.
//!
//! Time is bounded too: from a message's end the filter answers within
//! [`SCAN_TIME`], the wait for its turn included. A message whose scan is
//! not done by then was not looked at completely.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use garrison_core::config::IncompleteAction;

use crate::protocol::{
    self, Command, NO_REPLY_BODY, NO_REPLY_END_OF_HEADERS, NO_REPLY_HEADER, Reply,
};
use crate::scan::{self, Gap, Outcome};

/// The header a tagged message gets.
pub const HEADER: &str = "X-Garrison-Macro";
/// What the sender's server is told of a refused message.
pub const REFUSAL: &str = "550 5.7.1 Message refused: an attached Office document contains macros.";
/// The header a message gets that was taken although the scan could not
/// look at all of it, and the header's value.
pub const UNSCANNED_HEADER: &str = "X-Garrison-Scan";
pub const UNSCANNED: &str = "unscanned";
/// What the sender's server is told of a message that is refused because it
/// could not be scanned completely.
pub const UNSCANNED_REFUSAL: &str =
    "550 5.7.1 Message refused: its attachments could not be scanned completely.";
/// A mail server that is silent for this long has gone.
const PATIENCE: Duration = Duration::from_secs(60);
/// Connections at one time; a mail server opens one for each message it is
/// taking in.
const MOST_SESSIONS: usize = 64;
/// What the messages being received may hold together, unless one message
/// alone may be larger.
const HELD: usize = 256 * 1024 * 1024;
/// A message's answer comes within this time of its end, the wait for the
/// scan's turn included. A mail server waits for a milter's answer for half
/// a minute or more.
pub const SCAN_TIME: Duration = Duration::from_secs(20);

/// How the filter was set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Take a message with macros and mark it, instead of refusing it.
    pub tag: bool,
    /// What a message gets that could not be scanned completely.
    pub on_incomplete: IncompleteAction,
    /// A message larger than this is not scanned.
    pub max_bytes: usize,
    /// What a message's wait and scan may take together.
    pub scan_time: Duration,
}

impl Settings {
    /// Whether an answer of this filter may add a header to a message.
    fn adds_headers(self) -> bool {
        self.tag || self.on_incomplete == IncompleteAction::Tag
    }
}

impl Default for Settings {
    /// The filter as an empty `[milter]` section sets it up.
    fn default() -> Self {
        Settings {
            tag: false,
            on_incomplete: IncompleteAction::Tag,
            max_bytes: 64 * 1024 * 1024,
            scan_time: SCAN_TIME,
        }
    }
}

/// The turn to scan, which one connection has at a time: a scan holds
/// copies of the message it unpacks.
#[derive(Debug, Default)]
struct Turn {
    taken: Mutex<bool>,
    free: Condvar,
}

/// The turn, until it is dropped.
struct Taken<'a>(&'a Turn);

impl Turn {
    /// Wait for the turn, but not beyond `until`.
    fn take(&self, until: Instant) -> Option<Taken<'_>> {
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        while *taken {
            let left = until.checked_duration_since(Instant::now())?;
            if left.is_zero() {
                return None;
            }
            taken = self
                .free
                .wait_timeout(taken, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *taken = true;
        Some(Taken(self))
    }
}

impl Drop for Taken<'_> {
    fn drop(&mut self) {
        *self.0.taken.lock().unwrap_or_else(PoisonError::into_inner) = false;
        self.0.free.notify_one();
    }
}

/// What all connections of one filter share: the room their messages take
/// and the turn to scan.
#[derive(Debug)]
pub struct Shared {
    /// The bytes all messages together may hold.
    room: usize,
    held: AtomicUsize,
    scanning: Turn,
}

impl Shared {
    /// Room for the messages of a filter set up as `settings` says: always
    /// enough for one message of the largest size that is scanned.
    #[must_use]
    pub fn new(settings: Settings) -> Shared {
        Shared::with_room(HELD.max(settings.max_bytes))
    }

    fn with_room(room: usize) -> Shared {
        Shared {
            room,
            held: AtomicUsize::new(0),
            scanning: Turn::default(),
        }
    }

    /// Take `bytes` of the room, if they are there.
    fn take(&self, bytes: usize) -> bool {
        let mut held = self.held.load(Ordering::SeqCst);
        loop {
            let Some(sum) = held.checked_add(bytes).filter(|sum| *sum <= self.room) else {
                return false;
            };
            match self
                .held
                .compare_exchange(held, sum, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return true,
                Err(now) => held = now,
            }
        }
    }

    fn give_back(&self, bytes: usize) {
        self.held.fetch_sub(bytes, Ordering::SeqCst);
    }
}

/// One message as it arrives.
struct Message<'a> {
    shared: &'a Shared,
    data: Vec<u8>,
    /// Whether the empty line between headers and body is written.
    headed: bool,
    /// More arrived than is scanned.
    too_large: bool,
    /// The filter had no room left for it.
    crowded: bool,
}

impl Drop for Message<'_> {
    fn drop(&mut self) {
        self.shared.give_back(self.data.len());
    }
}

impl<'a> Message<'a> {
    fn new(shared: &'a Shared) -> Self {
        Message {
            shared,
            data: Vec::new(),
            headed: false,
            too_large: false,
            crowded: false,
        }
    }

    /// Keep nothing of the message any more.
    fn let_go(&mut self) {
        self.shared.give_back(self.data.len());
        self.data = Vec::new();
    }

    fn add(&mut self, bytes: &[u8], limit: usize) {
        if self.too_large || self.crowded {
            return;
        }
        if self.data.len() + bytes.len() > limit {
            self.too_large = true;
            self.let_go();
        } else if self.shared.take(bytes.len()) {
            self.data.extend_from_slice(bytes);
        } else {
            self.crowded = true;
            self.let_go();
        }
    }

    fn body(&mut self, limit: usize) {
        if !self.headed {
            self.headed = true;
            self.add(b"\r\n", limit);
        }
    }
}

/// Speak with the mail server over `stream` until it ends the connection,
/// as the only connection there is.
pub fn session(stream: &mut (impl Read + Write), settings: Settings) -> io::Result<()> {
    session_among(stream, settings, &Shared::new(settings))
}

/// Speak with the mail server over `stream` until it ends the connection;
/// `shared` is what this connection has in common with the others.
pub fn session_among(
    stream: &mut (impl Read + Write),
    settings: Settings,
    shared: &Shared,
) -> io::Result<()> {
    let mut message = Message::new(shared);
    // Until the opening says otherwise, every step is answered.
    let mut quiet = 0;
    while let Some(command) = protocol::read(stream)? {
        let answered = |flag: u32| quiet & flag == 0;
        match command {
            Command::Negotiate {
                actions, protocol, ..
            } => {
                let reply = protocol::negotiated(actions, protocol, settings.adds_headers());
                if let Reply::Negotiate { protocol, .. } = reply {
                    quiet = protocol;
                }
                protocol::write(stream, &reply)?;
            }
            Command::Header { name, value } => {
                message.add(&name, settings.max_bytes);
                message.add(b": ", settings.max_bytes);
                message.add(&value, settings.max_bytes);
                message.add(b"\r\n", settings.max_bytes);
                if answered(NO_REPLY_HEADER) {
                    protocol::write(stream, &Reply::Continue)?;
                }
            }
            Command::EndOfHeaders => {
                message.body(settings.max_bytes);
                if answered(NO_REPLY_END_OF_HEADERS) {
                    protocol::write(stream, &Reply::Continue)?;
                }
            }
            Command::Body(chunk) => {
                message.body(settings.max_bytes);
                message.add(&chunk, settings.max_bytes);
                if answered(NO_REPLY_BODY) {
                    protocol::write(stream, &Reply::Continue)?;
                }
            }
            Command::EndOfBody => {
                let whole = std::mem::replace(&mut message, Message::new(shared));
                for reply in verdict(&whole, settings) {
                    protocol::write(stream, &reply)?;
                }
            }
            Command::Abort => message = Message::new(shared),
            Command::Quit => break,
            // Macros come with a step and are never answered; a step that was
            // not asked for is let pass.
            Command::Other(b'D') => {}
            Command::Other(_) => protocol::write(stream, &Reply::Continue)?,
        }
    }
    Ok(())
}

/// The answer to one message.
fn verdict(message: &Message<'_>, settings: Settings) -> Vec<Reply> {
    if message.crowded {
        log::warn!(
            "A message was not scanned: the messages being received fill the filter's memory. \
             The sending server was told to bring it again."
        );
        return vec![Reply::TempFail];
    }
    match judged(message, settings) {
        Outcome::Clean => vec![Reply::Accept],
        Outcome::Incomplete(gap) => unscanned(gap, settings.on_incomplete),
        Outcome::Macros(found) if settings.tag => {
            log::info!("Tagged a message with {}", found.name());
            vec![
                Reply::AddHeader {
                    name: HEADER.to_owned(),
                    value: "yes".to_owned(),
                },
                Reply::Accept,
            ]
        }
        Outcome::Macros(found) => {
            log::info!("Refused a message with {}", found.name());
            vec![Reply::Refuse(REFUSAL.to_owned())]
        }
    }
}

/// What the scan says of a message, within the time a message has.
fn judged(message: &Message<'_>, settings: Settings) -> Outcome {
    if message.too_large {
        return Outcome::Incomplete(Gap::Size);
    }
    let until = Instant::now() + settings.scan_time;
    match message.shared.scanning.take(until) {
        Some(_turn) => scan::macros_until(&message.data, until),
        None => Outcome::Incomplete(Gap::Deadline),
    }
}

/// The answer to a message that could not be scanned completely. The log
/// gets the kind of reason and nothing of the message.
fn unscanned(gap: Gap, action: IncompleteAction) -> Vec<Reply> {
    let reason = gap.name();
    match action {
        IncompleteAction::Tag => {
            log::warn!("Tagged a message as not scanned completely: {reason}");
            vec![
                Reply::AddHeader {
                    name: UNSCANNED_HEADER.to_owned(),
                    value: UNSCANNED.to_owned(),
                },
                Reply::Accept,
            ]
        }
        IncompleteAction::Defer => {
            log::warn!(
                "Deferred a message that was not scanned completely: {reason}. The sending \
                 server was told to bring it again."
            );
            vec![Reply::TempFail]
        }
        IncompleteAction::Refuse => {
            log::warn!("Refused a message that was not scanned completely: {reason}");
            vec![Reply::Refuse(UNSCANNED_REFUSAL.to_owned())]
        }
    }
}

/// Take connections on `listener` for as long as the process lives.
pub fn serve(listener: &TcpListener, settings: Settings) {
    let open = Arc::new(AtomicUsize::new(0));
    let shared = Arc::new(Shared::new(settings));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        // More than the mail server would open at once: closed again, and
        // the server does with the message what its own setting says.
        if open.fetch_add(1, Ordering::SeqCst) >= MOST_SESSIONS {
            open.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let open = Arc::clone(&open);
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            let spoken =
                timed(&stream).and_then(|()| session_among(&mut stream, settings, &shared));
            if let Err(error) = spoken {
                log::warn!("A connection of the mail server ended early: {error}");
            }
            open.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn timed(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(PATIENCE))?;
    stream.set_write_timeout(Some(PATIENCE))
}

#[cfg(test)]
pub(crate) mod tests;
