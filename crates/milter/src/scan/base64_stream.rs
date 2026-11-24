//! Decoding the base64 in a message, free of its structure.
//!
//! A decoder that follows RFC 2045 drops every byte outside the alphabet, so
//! the base64 of an attachment is a run of symbols somewhere in the message's
//! one stream of symbols, whatever headers, boundaries or junk stand around
//! it. The stream is decoded [`PHASES`] times, from symbol 0, 1, 2 and 3: a
//! run that is grid-aligned in one of those phases comes out whole, with
//! noise decoded before and after it, and the scan finds the document in it.
//! Where a part begins or ends, how deep it is nested and how its headers are
//! written are never read here.
//!
//! Each phase is decoded straight from the raw message as the scan goes, one
//! buffer at a time, sized once from the symbol count, so the scan's own copy
//! of the message stays three quarters of it at the most, as before.
//!
//! What a decoder does with `=` is not one thing. One drops it with every
//! other byte outside the alphabet: [`decode_phase`]. The others read four
//! characters at a time, `=` among them as the value 0, and go on with the
//! next group; they differ in which of a group's three bytes they give where
//! `=` stands in it ([`Group`]): [`decode_tokens`]. Each way is read.

use base64::Engine;
use base64::engine::general_purpose::GeneralPurpose;
use base64::engine::{DecodePaddingMode, GeneralPurposeConfig};

/// So many symbols are decoded at a time: whole groups of four.
const PIECE: usize = 4096;
/// The grids a run of base64 symbols can sit on; one of them holds it whole.
pub(super) const PHASES: usize = 4;

/// base64 as mail programs read it: padding or none, and stray bits at the end.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// For every byte, whether it is a symbol of the alphabet, or that or `=`.
const fn table(padding: bool) -> [bool; 256] {
    let mut table = [false; 256];
    let mut byte = 0;
    while byte < 256 {
        #[allow(clippy::cast_possible_truncation)]
        let character = byte as u8;
        table[byte] = character.is_ascii_alphanumeric()
            || matches!(character, b'+' | b'/')
            || (padding && character == b'=');
        byte += 1;
    }
    table
}
static SYMBOL: [bool; 256] = table(false);
static TOKEN: [bool; 256] = table(true);

/// For every byte, its value as a symbol; `=` and the rest count as 0.
const fn values() -> [u8; 256] {
    let mut values = [0; 256];
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut value = 0;
    while value < 64 {
        #[allow(clippy::cast_possible_truncation)]
        let symbol = value as u8;
        values[alphabet[value] as usize] = symbol;
        value += 1;
    }
    values
}
static VALUE: [u8; 256] = values();

/// How many base64 symbols the message holds.
pub(super) fn count(message: &[u8]) -> usize {
    message
        .iter()
        .filter(|byte| SYMBOL[usize::from(**byte)])
        .count()
}

/// How many `=` the message holds.
pub(super) fn padding(message: &[u8]) -> usize {
    memchr::memchr_iter(b'=', message).count()
}

/// The message's bytes that `of` has, from the `phase`-th of them, handed to
/// `whole` in pieces of whole groups of four. What is left at the end, fewer
/// than four, is returned. The bytes are taken a run at a time, since an
/// encoded body is lines of them.
fn pieces(message: &[u8], of: &[bool; 256], phase: usize, mut whole: impl FnMut(&[u8])) -> Vec<u8> {
    let has = |at: usize| of[usize::from(message[at])];
    let mut piece: Vec<u8> = Vec::with_capacity(PIECE);
    let mut skip = phase;
    let mut at = 0;
    while at < message.len() {
        if !has(at) {
            at += 1;
            continue;
        }
        let start = at;
        while at < message.len() && has(at) {
            at += 1;
        }
        let gone = skip.min(at - start);
        skip -= gone;
        let mut run = &message[start + gone..at];
        while !run.is_empty() {
            let (now, later) = run.split_at(run.len().min(PIECE - piece.len()));
            piece.extend_from_slice(now);
            run = later;
            if piece.len() == PIECE {
                whole(&piece);
                piece.clear();
            }
        }
    }
    let cut = piece.len() - piece.len() % 4;
    whole(&piece[..cut]);
    piece.split_off(cut)
}

/// The bytes the message's base64 stream holds, read from its `phase`-th
/// symbol with everything outside the alphabet ignored. `symbols` is
/// [`count`] of the same message, so the buffer is sized once and does not
/// grow past three quarters of the stream.
pub(super) fn decode_phase(message: &[u8], phase: usize, symbols: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(symbols.saturating_sub(phase) / 4 * 3 + 3);
    let rest = pieces(message, &SYMBOL, phase, |piece| append(piece, &mut out));
    // Two or three symbols more are one or two bytes; one alone is none.
    if rest.len() >= 2 {
        append(&rest, &mut out);
    }
    out
}

/// Decode `symbols` to the end of `data`; what does not decode adds nothing.
fn append(symbols: &[u8], data: &mut Vec<u8>) {
    let before = data.len();
    if LENIENT.decode_vec(symbols, data).is_err() {
        data.truncate(before);
    }
}

/// Which of its three bytes a group of four gives that holds `=`, which
/// counts as the value 0 in each.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Group {
    /// Thunderbird's: one byte fewer for each `=` in the group, one at least.
    Counted,
    /// `GLib`'s (Evolution) and `GMime`'s (Geary, Balsa): the first byte always,
    /// the second unless the third place is `=`, the third unless the fourth
    /// is.
    Placed,
    /// `MimeKit`'s: nothing if the second place is `=`, else the first byte,
    /// then the second unless the third place is, then the third unless the
    /// fourth is.
    Nested,
}

impl Group {
    pub(super) const ALL: [Group; 3] = [Group::Counted, Group::Placed, Group::Nested];
}

/// The bytes a decoder gives that reads the message's symbols and `=` four at
/// a time from the `phase`-th of them, a group as `group` says, and the next
/// group as any other. `tokens` is [`count`] and [`padding`] of the same
/// message together. A group the message's end cuts short gives nothing.
pub(super) fn decode_tokens(message: &[u8], phase: usize, tokens: usize, group: Group) -> Vec<u8> {
    let mut out = Vec::with_capacity(tokens.saturating_sub(phase) / 4 * 3);
    pieces(message, &TOKEN, phase, |piece| {
        append_groups(piece, group, &mut out);
    });
    out
}

/// Decode whole groups of four. Most pieces hold no `=`, and those are plain
/// base64.
fn append_groups(tokens: &[u8], kind: Group, out: &mut Vec<u8>) {
    if !tokens.contains(&b'=') {
        append(tokens, out);
        return;
    }
    let (groups, _) = tokens.as_chunks::<4>();
    out.reserve(groups.len() * 3);
    for group in groups {
        push_group(*group, kind, out);
    }
}

/// One group of four as such a decoder reads it.
fn push_group(group: [u8; 4], kind: Group, out: &mut Vec<u8>) {
    let number = group.iter().fold(0_u32, |number, token| {
        (number << 6) | u32::from(VALUE[usize::from(*token)])
    });
    let [_, first, second, third] = number.to_be_bytes();
    let pad = group.map(|token| token == b'=');
    match kind {
        Group::Counted => {
            let given = 3 - pad.iter().filter(|pad| **pad).count().min(2);
            out.extend_from_slice(&[first, second, third][..given]);
        }
        Group::Placed => {
            out.push(first);
            if !pad[2] {
                out.push(second);
            }
            if !pad[3] {
                out.push(third);
            }
        }
        Group::Nested => {
            let given = if pad[1] {
                0
            } else if pad[2] {
                1
            } else if pad[3] {
                2
            } else {
                3
            };
            out.extend_from_slice(&[first, second, third][..given]);
        }
    }
}
