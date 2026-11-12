//! The milter protocol as far as this filter speaks it.
//!
//! Every message between the mail server and a milter is a frame: four bytes
//! of length, one byte that says what it is, then its data. The server
//! begins by saying which steps of an SMTP session it can send and which
//! answers it can do without; the filter answers with what it wants of
//! that. This filter wants the headers and the body of a message and gives
//! one answer, at the body's end.

use std::io::{self, Read, Write};

/// The largest frame that is read. A mail server sends the body in pieces of
/// 64 KiB; this leaves room for one that sends larger ones.
pub const MAX_FRAME: usize = 2 * 1024 * 1024;

// What the mail server need not send (`SMFIP_NO...`), and the answers it need
// not wait for (`SMFIP_NR_...`).
const NO_CONNECT: u32 = 0x0000_0001;
const NO_HELO: u32 = 0x0000_0002;
const NO_MAIL: u32 = 0x0000_0004;
const NO_RCPT: u32 = 0x0000_0008;
const NO_UNKNOWN: u32 = 0x0000_0100;
const NO_DATA: u32 = 0x0000_0200;
pub const NO_REPLY_HEADER: u32 = 0x0000_0080;
pub const NO_REPLY_END_OF_HEADERS: u32 = 0x0004_0000;
pub const NO_REPLY_BODY: u32 = 0x0008_0000;
/// The steps this filter does without, and the answers it does not give.
const WANTED: u32 = NO_CONNECT
    | NO_HELO
    | NO_MAIL
    | NO_RCPT
    | NO_UNKNOWN
    | NO_DATA
    | NO_REPLY_HEADER
    | NO_REPLY_END_OF_HEADERS
    | NO_REPLY_BODY;
/// The filter may add a header (`SMFIF_ADDHDRS`).
pub const ADD_HEADERS: u32 = 0x0000_0001;
const VERSION: u32 = 6;

/// What the mail server sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// The opening: the protocol's version, what the filter may change and
    /// what the server can leave out.
    Negotiate {
        version: u32,
        actions: u32,
        protocol: u32,
    },
    Header {
        name: Vec<u8>,
        value: Vec<u8>,
    },
    EndOfHeaders,
    Body(Vec<u8>),
    EndOfBody,
    /// The message is given up; another may follow.
    Abort,
    Quit,
    /// A step this filter did not ask for, or macros that go with one. The
    /// letter is the frame's; macros (`D`) get no answer.
    Other(u8),
}

/// What the filter answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    Negotiate {
        actions: u32,
        protocol: u32,
    },
    Continue,
    Accept,
    /// Not now: the sending server keeps the message and brings it again.
    TempFail,
    /// Refuse with a reply of the filter's own, such as `550 5.7.1 ...`.
    Refuse(String),
    AddHeader {
        name: String,
        value: String,
    },
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_owned())
}

fn word(data: &[u8], at: usize) -> io::Result<u32> {
    data.get(at..at + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| invalid("a frame is shorter than its fields"))
}

/// The next frame, or `None` where the server closed the connection between
/// two frames.
pub fn read(stream: &mut impl Read) -> io::Result<Option<Command>> {
    let mut length = [0; 4];
    match stream.read(&mut length[..1])? {
        0 => return Ok(None),
        _ => stream.read_exact(&mut length[1..])?,
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(invalid("a frame's length is out of range"));
    }
    let mut frame = vec![0; length];
    stream.read_exact(&mut frame)?;
    let data = &frame[1..];
    Ok(Some(match frame[0] {
        b'O' => Command::Negotiate {
            version: word(data, 0)?,
            actions: word(data, 4)?,
            protocol: word(data, 8)?,
        },
        b'L' => {
            // Name and value, each ended by a zero.
            let mut parts = data.split(|byte| *byte == 0);
            let name = parts.next().unwrap_or_default().to_vec();
            let value = parts.next().unwrap_or_default().to_vec();
            Command::Header { name, value }
        }
        b'N' => Command::EndOfHeaders,
        b'B' => Command::Body(data.to_vec()),
        b'E' => Command::EndOfBody,
        b'A' => Command::Abort,
        b'Q' => Command::Quit,
        other => Command::Other(other),
    }))
}

/// What the filter takes of what the server offers.
#[must_use]
pub fn negotiated(actions: u32, protocol: u32, tagging: bool) -> Reply {
    Reply::Negotiate {
        actions: if tagging { actions & ADD_HEADERS } else { 0 },
        protocol: protocol & WANTED,
    }
}

pub fn write(stream: &mut impl Write, reply: &Reply) -> io::Result<()> {
    let mut frame = Vec::new();
    match reply {
        Reply::Negotiate { actions, protocol } => {
            frame.push(b'O');
            for value in [VERSION, *actions, *protocol] {
                frame.extend_from_slice(&value.to_be_bytes());
            }
        }
        Reply::Continue => frame.push(b'c'),
        Reply::Accept => frame.push(b'a'),
        Reply::TempFail => frame.push(b't'),
        Reply::Refuse(text) => {
            frame.push(b'y');
            // One line: nothing that would end it goes out.
            frame.extend(
                text.bytes()
                    .filter(|byte| !matches!(byte, 0 | b'\r' | b'\n')),
            );
            frame.push(0);
        }
        Reply::AddHeader { name, value } => {
            frame.push(b'h');
            for part in [name, value] {
                frame.extend(
                    part.bytes()
                        .filter(|byte| !matches!(byte, 0 | b'\r' | b'\n')),
                );
                frame.push(0);
            }
        }
    }
    let length = u32::try_from(frame.len()).map_err(|_| invalid("a reply is too long"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(&frame)?;
    stream.flush()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A frame as the mail server writes it.
    pub(crate) fn frame(kind: u8, data: &[u8]) -> Vec<u8> {
        let mut frame = u32::try_from(data.len() + 1)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        frame.push(kind);
        frame.extend_from_slice(data);
        frame
    }

    pub(crate) fn opening(protocol: u32) -> Vec<u8> {
        let fields: Vec<u8> = [6u32, 0x1ff, protocol]
            .iter()
            .flat_map(|value| value.to_be_bytes())
            .collect();
        frame(b'O', &fields)
    }

    fn one(bytes: &[u8]) -> io::Result<Option<Command>> {
        read(&mut &bytes[..])
    }

    #[test]
    fn frames_are_read_as_what_they_are() {
        assert_eq!(
            one(&opening(0x001f_ffff)).unwrap(),
            Some(Command::Negotiate {
                version: 6,
                actions: 0x1ff,
                protocol: 0x001f_ffff
            })
        );
        assert_eq!(
            one(&frame(b'L', b"Subject\0The invoice\0")).unwrap(),
            Some(Command::Header {
                name: b"Subject".to_vec(),
                value: b"The invoice".to_vec()
            })
        );
        assert_eq!(one(&frame(b'N', b"")).unwrap(), Some(Command::EndOfHeaders));
        assert_eq!(
            one(&frame(b'B', b"line\r\n")).unwrap(),
            Some(Command::Body(b"line\r\n".to_vec()))
        );
        assert_eq!(one(&frame(b'E', b"")).unwrap(), Some(Command::EndOfBody));
        assert_eq!(one(&frame(b'A', b"")).unwrap(), Some(Command::Abort));
        assert_eq!(one(&frame(b'Q', b"")).unwrap(), Some(Command::Quit));
        assert_eq!(
            one(&frame(b'D', b"Cj\0mail.example.test\0")).unwrap(),
            Some(Command::Other(b'D'))
        );
        // The connection closed between two frames, and inside one.
        assert_eq!(one(b"").unwrap(), None);
        assert!(one(&[0, 0]).is_err());
        assert!(one(&frame(b'B', b"cut")[..6]).is_err());
    }

    #[test]
    fn frames_that_cannot_be_are_refused() {
        assert!(one(&[0, 0, 0, 0]).is_err());
        let huge = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
        assert!(one(&huge).is_err());
        assert!(one(&frame(b'O', &[0, 0, 0, 6])).is_err());
    }

    #[test]
    fn the_filter_takes_only_what_the_server_offers() {
        // A server of protocol 2 offers none of the answers to do without.
        assert_eq!(
            negotiated(0x1ff, 0x0000_007f, false),
            Reply::Negotiate {
                actions: 0,
                protocol: 0x0f
            }
        );
        let all = negotiated(0x1ff, 0x001f_ffff, true);
        assert_eq!(
            all,
            Reply::Negotiate {
                actions: ADD_HEADERS,
                protocol: WANTED
            }
        );
        let mut written = Vec::new();
        write(&mut written, &all).unwrap();
        assert_eq!(written.len(), 4 + 13);
        assert_eq!(&written[..5], [0, 0, 0, 13, b'O']);
        assert_eq!(&written[5..9], 6u32.to_be_bytes());
    }

    #[test]
    fn replies_are_one_frame_and_one_line() {
        let written = |reply: &Reply| {
            let mut data = Vec::new();
            write(&mut data, reply).unwrap();
            data
        };
        assert_eq!(written(&Reply::Accept), [0, 0, 0, 1, b'a']);
        assert_eq!(written(&Reply::Continue), [0, 0, 0, 1, b'c']);
        assert_eq!(written(&Reply::TempFail), [0, 0, 0, 1, b't']);
        assert_eq!(
            written(&Reply::Refuse("550 5.7.1 No\r\n250 OK".to_owned())),
            frame(b'y', b"550 5.7.1 No250 OK\0")
        );
        assert_eq!(
            written(&Reply::AddHeader {
                name: "X-Garrison-Macro".to_owned(),
                value: "yes".to_owned()
            }),
            frame(b'h', b"X-Garrison-Macro\0yes\0")
        );
    }
}
