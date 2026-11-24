//! base64 in which `=` stands where a symbol does. Mail programs disagree
//! about it: some take `=` for the value 0 and decide by its place in a group
//! of four what the group gives, some count it, some drop it. A document that
//! any of them rebuilds is found.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::tests::compound;
use super::*;

fn macro_compound() -> Vec<u8> {
    compound(&["WordDocument", "Macros", "VBA", "_VBA_PROJECT"])
}

/// The base64 of `data` with every `A` at the first place of a group of four
/// written as `=`, but in the groups `kept`.
fn equals_for_zero(data: &[u8], kept: &[usize]) -> Vec<u8> {
    let mut encoded = STANDARD.encode(data).into_bytes();
    for (group, symbols) in encoded.chunks_mut(4).enumerate() {
        if symbols[0] == b'A' && !kept.contains(&group) {
            symbols[0] = b'=';
        }
    }
    let mut message = b"Subject: x\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
    message.extend_from_slice(&encoded);
    message.extend_from_slice(b"\r\n");
    message
}

/// The groups whose `A` a reviewer's message of 2026-11-24 left as it was.
const KEPT: [usize; 36] = [
    5, 8, 13, 15, 22, 24, 27, 38, 52, 57, 69, 85, 86, 104, 110, 131, 140, 148, 181, 191, 192, 199,
    209, 210, 231, 236, 241, 244, 273, 274, 276, 284, 299, 301, 305, 320,
];

// GLib (Evolution), GMime (Geary, Balsa) and MimeKit take `=` for 0 and give
// a group's first byte whatever its first place holds: they rebuild the
// document byte for byte.
#[test]
fn a_compound_file_with_equals_for_zero_is_found() {
    let message = equals_for_zero(&macro_compound(), &KEPT);
    assert_eq!(message.len(), 1355);
    assert_eq!(macros(&message), Outcome::Macros(Found::Compound));
    let every = equals_for_zero(&macro_compound(), &[]);
    assert_eq!(macros(&every), Outcome::Macros(Found::Compound));
}
