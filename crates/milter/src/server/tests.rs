use std::io::Cursor;

use super::*;
use crate::protocol::tests::{frame, opening};
use crate::sample::document;
use crate::scan::tests::message;

/// What the mail server sends, and what the filter wrote back.
struct Wire {
    sent: Cursor<Vec<u8>>,
    answered: Vec<u8>,
}

impl Read for Wire {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.sent.read(buffer)
    }
}

impl Write for Wire {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.answered.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const SETTINGS: Settings = Settings {
    tag: false,
    max_bytes: 8 * 1024 * 1024,
};
/// Everything a mail server of protocol 6 can leave out or do without.
const MODERN: u32 = 0x001f_ffff;

/// One message as the mail server sends it: headers one by one, then the
/// body in pieces of `piece` bytes.
pub(crate) fn sent(raw: &[u8], piece: usize) -> Vec<u8> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let (headers, body) = (&raw[..split], &raw[split + 4..]);
    let mut frames = Vec::new();
    for line in String::from_utf8_lossy(headers).split("\r\n") {
        let (name, value) = line.split_once(": ").unwrap();
        frames.extend(frame(
            b'L',
            &[name.as_bytes(), b"\0", value.as_bytes(), b"\0"].concat(),
        ));
    }
    frames.extend(frame(b'N', b""));
    for chunk in body.chunks(piece) {
        frames.extend(frame(b'B', chunk));
    }
    frames.extend(frame(b'E', b""));
    frames
}

/// The frames the filter answers `frames` with, as their letter and data.
fn answers(frames: Vec<u8>, settings: Settings) -> Vec<(u8, Vec<u8>)> {
    answers_among(frames, settings, &Shared::new(settings))
}

/// The same on a connection that shares the filter's room with others.
fn answers_among(frames: Vec<u8>, settings: Settings, shared: &Shared) -> Vec<(u8, Vec<u8>)> {
    let mut wire = Wire {
        sent: Cursor::new(frames),
        answered: Vec::new(),
    };
    session_among(&mut wire, settings, shared).unwrap();
    let mut replies = Vec::new();
    let mut rest = wire.answered.as_slice();
    while rest.len() >= 5 {
        let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        replies.push((rest[4], rest[5..4 + length].to_vec()));
        rest = &rest[4 + length..];
    }
    replies
}

fn conversation(raw: &[u8], protocol: u32, settings: Settings) -> Vec<(u8, Vec<u8>)> {
    let mut frames = opening(protocol);
    frames.extend(sent(raw, 1000));
    frames.extend(frame(b'Q', b""));
    answers(frames, settings)
}

#[test]
fn a_message_with_macros_is_refused_and_one_without_is_taken() {
    let refused = conversation(&message("invoice.docm", &document()), MODERN, SETTINGS);
    // The opening's answer, then the one answer to the message.
    assert_eq!(refused.len(), 2);
    assert_eq!(refused[0].0, b'O');
    assert_eq!(refused[1], (b'y', [REFUSAL.as_bytes(), b"\0"].concat()));
    let taken = conversation(
        &message("letter.txt", b"Nothing but text."),
        MODERN,
        SETTINGS,
    );
    assert_eq!(taken[1..], [(b'a', Vec::new())]);
}

#[test]
fn where_the_operator_tags_the_message_is_taken_with_a_header() {
    let tagging = Settings {
        tag: true,
        ..SETTINGS
    };
    let tagged = conversation(&message("invoice.docm", &document()), MODERN, tagging);
    assert_eq!(
        tagged[1..],
        [
            (b'h', b"X-Garrison-Macro\0yes\0".to_vec()),
            (b'a', Vec::new())
        ]
    );
    // The filter asked for leave to add headers, and for nothing else.
    assert_eq!(tagged[0].1[4..8], 1u32.to_be_bytes());
    let plain = conversation(&message("invoice.docm", &document()), MODERN, SETTINGS);
    assert_eq!(plain[0].1[4..8], 0u32.to_be_bytes());
}

#[test]
fn a_mail_server_that_waits_for_every_answer_gets_them() {
    // Protocol 2 knows no answers to do without: each header, the end of the
    // headers and each piece of the body is answered.
    let raw = message("invoice.docm", &document());
    let pieces = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|split| (raw.len() - split - 4).div_ceil(1000))
        .unwrap();
    let replies = conversation(&raw, 0x0000_007f, SETTINGS);
    let continues = replies.iter().filter(|(kind, _)| *kind == b'c').count();
    assert_eq!(continues, 5 + 1 + pieces);
    assert_eq!(replies.last().unwrap().0, b'y');
}

#[test]
fn several_messages_on_one_connection_are_judged_each_for_itself() {
    let mut frames = opening(MODERN);
    frames.extend(sent(&message("invoice.docm", &document()), 4096));
    frames.extend(sent(&message("letter.txt", b"Nothing but text."), 4096));
    // A message that is given up half way leaves nothing behind.
    let half = sent(&message("invoice.docm", &document()), 4096);
    frames.extend(&half[..half.len() - 5]);
    frames.extend(frame(b'A', b""));
    frames.extend(sent(&message("letter.txt", b"Nothing but text."), 4096));
    let replies = answers(frames, SETTINGS);
    let kinds: Vec<u8> = replies.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, [b'O', b'y', b'a', b'a']);
}

#[test]
fn a_message_that_finds_no_room_is_deferred_and_the_room_comes_back() {
    let raw = message("invoice.docm", &document());
    let mut frames = opening(MODERN);
    frames.extend(sent(&raw, 1000));
    frames.extend(frame(b'Q', b""));
    // Room for one such message and a half.
    let shared = Shared::with_room(raw.len() * 3 / 2);
    // Another connection is in the middle of a message of its own.
    let mut other = Message::new(&shared);
    other.add(&raw, usize::MAX);
    assert!(!other.crowded);
    let deferred = answers_among(frames.clone(), SETTINGS, &shared);
    assert_eq!(deferred[1..], [(b't', Vec::new())]);
    // What the deferred message had taken is free again; the other's is not.
    assert_eq!(shared.held.load(Ordering::SeqCst), raw.len());
    // The other connection is done: the next message is scanned as ever.
    drop(other);
    let refused = answers_among(frames, SETTINGS, &shared);
    assert_eq!(refused[1].0, b'y');
    assert_eq!(shared.held.load(Ordering::SeqCst), 0);

    // A message given up, one too large and one cut off by the connection's
    // end all give their room back.
    let mut given_up = opening(MODERN);
    given_up.extend(sent(&raw, 1000));
    given_up.truncate(given_up.len() - 5);
    given_up.extend(frame(b'A', b""));
    given_up.extend(sent(&raw, 1000));
    given_up.truncate(given_up.len() - 5);
    assert_eq!(answers_among(given_up, SETTINGS, &shared).len(), 1);
    let small = Settings {
        max_bytes: 512,
        ..SETTINGS
    };
    let mut large = opening(MODERN);
    large.extend(sent(&raw, 1000));
    assert_eq!(
        answers_among(large, small, &shared)[1..],
        [(b'a', Vec::new())]
    );
    assert_eq!(shared.held.load(Ordering::SeqCst), 0);
    // One message of the largest size always has room.
    let roomy = Settings {
        max_bytes: 2 * HELD,
        ..SETTINGS
    };
    assert_eq!(Shared::new(roomy).room, 2 * HELD);
    assert_eq!(Shared::new(SETTINGS).room, HELD);
}

#[test]
fn a_message_beyond_the_size_that_is_scanned_is_taken() {
    let small = Settings {
        max_bytes: 512,
        ..SETTINGS
    };
    let replies = conversation(&message("invoice.docm", &document()), MODERN, small);
    assert_eq!(replies[1..], [(b'a', Vec::new())]);
}

#[test]
fn steps_that_were_not_asked_for_pass_and_broken_frames_end_the_connection() {
    let mut frames = opening(MODERN);
    // Macros, then a connect and a recipient the filter said it does without.
    frames.extend(frame(b'D', b"Cj\0mail.example.test\0"));
    frames.extend(frame(b'C', b"client.example.net\0"));
    frames.extend(frame(b'R', b"<b@example.test>\0"));
    let replies = answers(frames, SETTINGS);
    let kinds: Vec<u8> = replies.iter().map(|(kind, _)| *kind).collect();
    assert_eq!(kinds, [b'O', b'c', b'c']);

    let mut wire = Wire {
        sent: Cursor::new([opening(MODERN), vec![0, 0, 0, 0]].concat()),
        answered: Vec::new(),
    };
    assert!(session(&mut wire, SETTINGS).is_err());
    // A connection that ends inside a message is an early end, not a panic.
    let half = sent(&message("invoice.docm", &document()), 4096);
    let mut wire = Wire {
        sent: Cursor::new([opening(MODERN), half[..half.len() / 2].to_vec()].concat()),
        answered: Vec::new(),
    };
    let _ = session(&mut wire, SETTINGS);
}
