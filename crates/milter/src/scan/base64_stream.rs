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
//! other byte outside the alphabet: [`decode_phase`]. Another reads four
//! characters at a time, `=` among them, gives two bytes or one for a group
//! that ends in `=`, and goes on with the next group: [`decode_tokens`], which
//! is how a body written in padded pieces comes out whole. Both are read.

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

pub(super) fn is_symbol(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

/// How many base64 symbols the message holds.
pub(super) fn count(message: &[u8]) -> usize {
    message.iter().filter(|byte| is_symbol(**byte)).count()
}

/// The bytes the message's base64 stream holds, read from its `phase`-th
/// symbol with everything outside the alphabet ignored. `symbols` is
/// [`count`] of the same message, so the buffer is sized once and does not
/// grow past three quarters of the stream.
pub(super) fn decode_phase(message: &[u8], phase: usize, symbols: usize) -> Vec<u8> {
    let kept = symbols.saturating_sub(phase);
    let mut out = Vec::with_capacity(kept / 4 * 3 + 3);
    let mut piece: Vec<u8> = Vec::with_capacity(PIECE);
    let mut skipped = 0;
    for symbol in message.iter().copied().filter(|byte| is_symbol(*byte)) {
        if skipped < phase {
            skipped += 1;
            continue;
        }
        piece.push(symbol);
        if piece.len() == PIECE {
            append(&piece, &mut out);
            piece.clear();
        }
    }
    let whole = piece.len() - piece.len() % 4;
    append(&piece[..whole], &mut out);
    // Two or three symbols more are one or two bytes; one alone is none.
    if piece.len() - whole >= 2 {
        append(&piece[whole..], &mut out);
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

/// How many characters the message holds that a decoder of groups of four
/// takes: the symbols and `=`.
pub(super) fn count_tokens(message: &[u8]) -> usize {
    message
        .iter()
        .filter(|byte| is_symbol(**byte) || **byte == b'=')
        .count()
}

/// The bytes a decoder gives that reads the message's symbols and `=` four at
/// a time from the `phase`-th of them: three bytes for a group, two where it
/// holds one `=` and one where it holds more, with `=` counted as zero, and
/// the next group read as any other. `tokens` is [`count_tokens`] of the same
/// message. A group the message's end cuts short gives nothing.
pub(super) fn decode_tokens(message: &[u8], phase: usize, tokens: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(tokens.saturating_sub(phase) / 4 * 3);
    let mut piece: Vec<u8> = Vec::with_capacity(PIECE);
    let mut skipped = 0;
    for token in message
        .iter()
        .copied()
        .filter(|byte| is_symbol(*byte) || *byte == b'=')
    {
        if skipped < phase {
            skipped += 1;
            continue;
        }
        piece.push(token);
        if piece.len() == PIECE {
            append_groups(&piece, &mut out);
            piece.clear();
        }
    }
    let whole = piece.len() - piece.len() % 4;
    append_groups(&piece[..whole], &mut out);
    out
}

/// Decode whole groups of four. Most pieces hold no `=`, and those are plain
/// base64.
fn append_groups(tokens: &[u8], out: &mut Vec<u8>) {
    if !tokens.contains(&b'=') {
        append(tokens, out);
        return;
    }
    let (groups, _) = tokens.as_chunks::<4>();
    for group in groups {
        if group.contains(&b'=') {
            push_group(*group, out);
        } else {
            append(group, out);
        }
    }
}

/// One group of four as such a decoder reads it.
fn push_group(group: [u8; 4], out: &mut Vec<u8>) {
    let mut number: u32 = 0;
    let mut padding = 0;
    for token in group {
        let value = match token {
            b'A'..=b'Z' => token - b'A',
            b'a'..=b'z' => token - b'a' + 26,
            b'0'..=b'9' => token - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => {
                padding += 1;
                0
            }
        };
        number = (number << 6) | u32::from(value);
    }
    let [_, first, second, third] = number.to_be_bytes();
    match padding {
        0 => out.extend_from_slice(&[first, second, third]),
        1 => out.extend_from_slice(&[first, second]),
        _ => out.push(first),
    }
}
