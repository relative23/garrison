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
//! [`most_memory`] adds up what that comes to, and the unit's limit lies
//! above it.
//!
//! Time is bounded too: from a message's end the filter answers within
//! [`SCAN_TIME`], the wait for its turn included. A message whose scan is
//! not done by then was not looked at completely.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use garrison_core::config::IncompleteAction;

use crate::protocol::{
    self, Command, NO_REPLY_BODY, NO_REPLY_END_OF_HEADERS, NO_REPLY_HEADER, Reply,
};
use crate::scan::{self, Gap, Outcome};

mod places;
mod room;

use places::Places;
use room::Message;
pub use room::Shared;

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

/// Speak with the mail server over `stream` until it ends the connection,
/// as the only connection there is.
pub fn session(stream: &mut (impl Read + Write), settings: Settings) -> io::Result<()> {
    session_among(stream, settings, &Shared::of(settings.max_bytes))
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

/// The most memory a filter takes that scans messages of up to `max_bytes`.
/// The unit's `MemoryMax` must lie above what this says of the largest
/// `max_message_mib` the configuration takes; a test holds the two together.
#[must_use]
pub const fn most_memory(max_bytes: usize) -> usize {
    // The messages that arrive, the one that is being scanned among them.
    let room = if room::HELD > max_bytes {
        room::HELD
    } else {
        max_bytes
    };
    // A buffer that grows may be copied to its new place: for that moment
    // both exist, and every connection's may grow at the same moment.
    let growing = room;
    // The scan's own copy of the message: one stretch of base64 decoded,
    // three quarters of it, or its quoted-printable undone.
    let read = max_bytes;
    room + growing + read + scan::MOST_UNPACKED
}

/// Take connections on `listener` for as long as the process lives.
pub fn serve(listener: &TcpListener, settings: Settings) {
    let places = Arc::new(Places::default());
    let shared = Arc::new(Shared::of(settings.max_bytes));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else {
            continue;
        };
        // More than the mail server would open at once: closed again, and
        // the server does with the message what its own setting says.
        let Some(place) = places.take(MOST_SESSIONS) else {
            if let Some(count) = places.turned_away() {
                log::warn!(
                    "Closed a connection of the mail server unanswered: {MOST_SESSIONS} are \
                     open, which is as many as the filter takes ({count} closed since it \
                     started). The mail server does with such a message what it was told \
                     for a filter that does not answer."
                );
            }
            continue;
        };
        let shared = Arc::clone(&shared);
        let session = move || {
            // The place is this connection's until the thread ends, also
            // where it ends in a panic.
            let _place = place;
            let spoken =
                timed(&stream).and_then(|()| session_among(&mut stream, settings, &shared));
            if let Err(error) = spoken {
                log::warn!("A connection of the mail server ended early: {error}");
            }
        };
        // A thread the system does not give ends this connection, not the
        // filter: the place and the connection go with what was not run.
        if let Err(error) = std::thread::Builder::new().spawn(session) {
            log::error!("No thread for a connection of the mail server: {error}");
        }
    }
}

fn timed(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(PATIENCE))?;
    stream.set_write_timeout(Some(PATIENCE))
}

#[cfg(test)]
mod room_tests;
#[cfg(test)]
pub(crate) mod tests;
