//! The filter's side of a connection, and the listener that takes them.
//!
//! The mail server opens a connection for a message, says what it can send,
//! then sends the message's headers and body. The filter keeps them up to a
//! size, scans them at the body's end and gives its one answer: take the
//! message, or refuse it. Where the operator chose to tag instead, the
//! message is taken with a header that says what was found.
//!
//! Memory is bounded for all connections together ([`Shared`]): the messages
//! being received may hold so much and no more, and one message is scanned
//! at a time. A message that finds no room is answered with a temporary
//! failure, so the sending server brings it again; the filter itself stays up.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::protocol::{
    self, Command, NO_REPLY_BODY, NO_REPLY_END_OF_HEADERS, NO_REPLY_HEADER, Reply,
};
use crate::scan;

/// The header a tagged message gets.
pub const HEADER: &str = "X-Garrison-Macro";
/// What the sender's server is told of a refused message.
pub const REFUSAL: &str = "550 5.7.1 Message refused: an attached Office document contains macros.";
/// A mail server that is silent for this long has gone.
const PATIENCE: Duration = Duration::from_secs(60);
/// Connections at one time; a mail server opens one for each message it is
/// taking in.
const MOST_SESSIONS: usize = 64;
/// What the messages being received may hold together, unless one message
/// alone may be larger.
const HELD: usize = 256 * 1024 * 1024;

/// How the filter was set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Take a message with macros and mark it, instead of refusing it.
    pub tag: bool,
    /// A message larger than this is not scanned, and is taken.
    pub max_bytes: usize,
}

/// What all connections of one filter share: the room their messages take
/// and the turn to scan.
#[derive(Debug)]
pub struct Shared {
    /// The bytes all messages together may hold.
    room: usize,
    held: AtomicUsize,
    scanning: Mutex<()>,
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
            scanning: Mutex::new(()),
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
                let reply = protocol::negotiated(actions, protocol, settings.tag);
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
    if message.too_large {
        log::warn!(
            "A message larger than {} bytes was not scanned",
            settings.max_bytes
        );
        return vec![Reply::Accept];
    }
    if message.crowded {
        log::warn!(
            "A message was not scanned: the messages being received fill the filter's memory. \
             The sending server was told to bring it again."
        );
        return vec![Reply::TempFail];
    }
    // One scan at a time: a scan holds copies of the message it unpacks.
    let _turn = message
        .shared
        .scanning
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match scan::macros(&message.data) {
        None => vec![Reply::Accept],
        Some(found) if settings.tag => {
            log::info!("Tagged a message with {}", found.name());
            vec![
                Reply::AddHeader {
                    name: HEADER.to_owned(),
                    value: "yes".to_owned(),
                },
                Reply::Accept,
            ]
        }
        Some(found) => {
            log::info!("Refused a message with {}", found.name());
            vec![Reply::Refuse(REFUSAL.to_owned())]
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
