//! A sweep over base64 that is not canonical, against models of the mail
//! programs' decoders (`crate::decoders`): wherever a model the scan follows
//! rebuilds a document with macros from a body, the message with that body is
//! not clean. The bodies are the base64 of macro documents (a compound file,
//! a zip archive, a zip archive deflated inside another) changed in the ways
//! decoders disagree about, from fixed seeds, so every run sweeps the same.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::tests::{compound, plain_document};
use super::*;
use crate::decoders::{NOT_READ, READ};
use crate::sample::{archive, document};

/// A xorshift generator, the same numbers from the same seed.
struct Numbers(u64);

impl Numbers {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(limit.max(1)).unwrap()).unwrap()
    }
}

fn macro_documents() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "compound",
            compound(&["WordDocument", "Macros", "VBA", "_VBA_PROJECT"]),
        ),
        ("zip", document()),
        ("zip in zip", archive(&[("a.docm", &document(), true)])),
    ]
}

/// The ways a body is changed, each by a seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    /// `=` written for an `A` at the given place of its group, for each with
    /// one chance in two, or for all.
    ZeroAt(usize, bool),
    /// So many `=` put in anywhere.
    Inserted(usize),
    /// The data encoded in pieces of up to so many bytes, each padded.
    Pieces(usize),
    /// Bytes outside the alphabet, white space and a few `=` put in.
    Junk,
    /// Groups put in that hold `=` at their second place.
    SecondPlace,
    /// Two bytes in a group where its third place is `=`, as `GLib` reads it.
    ThirdPlace,
    /// One byte in a group where its third place is `=`, as `MimeKit` reads it.
    OneByte,
    /// A symbol and `=` put in between groups.
    Dangling,
    /// The other alphabet's `-` and `_` for `+` and `/`.
    Url,
}

/// The symbol of a value.
fn symbol(value: u8) -> u8 {
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[usize::from(value & 63)]
}

const CHANGES: [Change; 18] = [
    Change::ZeroAt(0, false),
    Change::ZeroAt(0, true),
    Change::ZeroAt(1, false),
    Change::ZeroAt(1, true),
    Change::ZeroAt(2, false),
    Change::ZeroAt(2, true),
    Change::ZeroAt(3, false),
    Change::ZeroAt(3, true),
    Change::Inserted(1),
    Change::Inserted(6),
    Change::Pieces(3),
    Change::Pieces(60),
    Change::Junk,
    Change::SecondPlace,
    Change::ThirdPlace,
    Change::OneByte,
    Change::Dangling,
    Change::Url,
];

/// So many seeds for each document and change.
const SEEDS: u64 = 16;

fn changed(data: &[u8], change: Change, numbers: &mut Numbers) -> Vec<u8> {
    let mut body = STANDARD.encode(data).into_bytes();
    match change {
        Change::ZeroAt(place, all) => {
            for group in body.chunks_mut(4) {
                if group.get(place) == Some(&b'A') && (all || numbers.next().is_multiple_of(2)) {
                    group[place] = b'=';
                }
            }
        }
        Change::Inserted(count) => {
            for _ in 0..count {
                let at = numbers.below(body.len() + 1);
                body.insert(at, b'=');
            }
        }
        Change::Pieces(largest) => {
            body.clear();
            let mut rest = data;
            while !rest.is_empty() {
                let size = (1 + numbers.below(largest)).min(rest.len());
                body.extend_from_slice(STANDARD.encode(&rest[..size]).as_bytes());
                rest = &rest[size..];
            }
        }
        Change::Junk => {
            for _ in 0..=numbers.below(body.len() / 8) {
                let at = numbers.below(body.len() + 1);
                body.insert(at, b" \r\n!*-_=."[numbers.below(9)]);
            }
        }
        Change::SecondPlace => {
            for _ in 0..=numbers.below(8) {
                let at = numbers.below(body.len() / 4 + 1) * 4;
                let group = [b"QUJD"[numbers.below(4)], b'=', b'x', b'y'];
                body.splice(at..at, group);
            }
        }
        Change::ThirdPlace | Change::OneByte => {
            body.clear();
            let mut at = 0;
            while at < data.len() {
                let first = data[at];
                let next = data.get(at + 1).copied();
                let take = match change {
                    Change::ThirdPlace => next.is_some_and(|next| next < 64),
                    _ => true,
                } && numbers.next().is_multiple_of(2);
                if take {
                    let low = u8::try_from(numbers.below(16)).unwrap();
                    let last = match change {
                        Change::ThirdPlace => next.unwrap_or(0),
                        _ => u8::try_from(numbers.below(64)).unwrap(),
                    };
                    body.extend_from_slice(&[
                        symbol(first >> 2),
                        symbol(((first & 3) << 4) | low),
                        b'=',
                        symbol(last),
                    ]);
                    at += if change == Change::ThirdPlace { 2 } else { 1 };
                } else {
                    let end = (at + 3).min(data.len());
                    body.extend_from_slice(STANDARD.encode(&data[at..end]).as_bytes());
                    at = end;
                }
            }
        }
        Change::Dangling => {
            for _ in 0..=numbers.below(8) {
                let at = numbers.below(body.len() / 4 + 1) * 4;
                body.splice(
                    at..at,
                    [symbol(u8::try_from(numbers.below(64)).unwrap()), b'='],
                );
            }
        }
        Change::Url => {
            for byte in &mut body {
                *byte = match *byte {
                    b'+' => b'-',
                    b'/' => b'_',
                    other => other,
                };
            }
        }
    }
    body
}

fn message(body: &[u8]) -> Vec<u8> {
    let mut message = b"Subject: x\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    for line in body.chunks(76) {
        message.extend_from_slice(line);
        message.extend_from_slice(b"\r\n");
    }
    message
}

/// Every generated case: the document's name, the change, the body.
fn cases() -> Vec<(&'static str, Change, Vec<u8>)> {
    let mut cases = Vec::new();
    for (name, data) in macro_documents() {
        for (index, change) in CHANGES.iter().enumerate() {
            for seed in 1..=SEEDS {
                let mut numbers = Numbers(seed * 7919 + u64::try_from(index).unwrap());
                cases.push((name, *change, changed(&data, *change, &mut numbers)));
            }
        }
    }
    cases
}

#[test]
fn no_document_a_decoder_the_scan_follows_rebuilds_is_called_clean() {
    let mut rebuilt = 0;
    for (name, change, body) in cases() {
        let builders: Vec<&str> = READ
            .iter()
            .filter(|(_, decode)| in_file(&decode(&body)).is_some())
            .map(|(decoder, _)| *decoder)
            .collect();
        if builders.is_empty() {
            continue;
        }
        rebuilt += 1;
        assert_ne!(
            macros(&message(&body)),
            Outcome::Clean,
            "{name}, {change:?}: {builders:?} rebuild it: {}",
            String::from_utf8_lossy(&body)
        );
    }
    // The sweep is no sweep if the changes hide the document from every model.
    assert!(rebuilt > cases().len() / 2, "{rebuilt}");
}

/// The decoders the scan does not follow rebuild documents it calls clean:
/// the documents name them, and this holds the list true.
#[test]
fn the_decoders_the_scan_does_not_follow_are_still_not_followed() {
    for (decoder, decode) in NOT_READ {
        assert!(
            cases().iter().any(|(_, _, body)| {
                in_file(&decode(body)).is_some() && macros(&message(body)) == Outcome::Clean
            }),
            "{decoder}"
        );
    }
}

#[test]
fn canonical_base64_of_clean_files_is_clean() {
    let mut numbers = Numbers(23);
    let mut files = vec![
        plain_document(),
        compound(&["WordDocument", "SummaryInformation"]),
    ];
    for _ in 0..24 {
        let size = numbers.below(5000);
        files.push((0..size).map(|_| numbers.next().to_le_bytes()[0]).collect());
    }
    for file in files {
        let body = STANDARD.encode(&file).into_bytes();
        assert_eq!(macros(&message(&body)), Outcome::Clean, "{}", file.len());
        for (decoder, decode) in READ {
            assert!(
                decode(&body).starts_with(&file[..file.len().saturating_sub(2)]),
                "{decoder} reads canonical base64 otherwise"
            );
        }
    }
}
