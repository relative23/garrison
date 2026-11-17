//! Decoding uuencode, which mail programs still take although it is no MIME
//! transfer encoding: a `begin <mode> <name>` block in any body, or a part
//! that declares it. A block the scan commits to (its first data line is a
//! valid one) but that does not end is reported as cut, so the message is
//! incomplete rather than clean.

use super::parts::{after, line_end, trim_cr};

/// The bytes that open a uuencode block.
const BEGIN: &[u8] = b"begin ";
/// A full uuencode data line carries 45 bytes.
const UU_FULL: usize = 45;

/// The start of the next uuencode block at or after `from`: a line
/// `begin <octal mode> <name>` whose first data line is a valid one.
pub(super) fn next_begin(body: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    while at < body.len() {
        let end = line_end(body, at);
        if at == 0 || body[at - 1] == b'\n' {
            let line = trim_cr(&body[at..end]);
            if begins_block(line) && first_data_line_valid(body, after(body, end)) {
                return Some(at);
            }
        }
        at = after(body, end);
    }
    None
}

/// Decode the uuencode block that begins at the start of `block`. Returns the
/// bytes, whether it ended with `end`, and how far it read; `None` if the
/// first data line is not a valid one, so the `begin` opened no block.
pub(super) fn decode(block: &[u8]) -> Option<(Vec<u8>, bool, usize)> {
    let mut at = after(block, line_end(block, 0)); // past the begin line
    let mut out = Vec::new();
    let mut any = false;
    loop {
        if at >= block.len() {
            return any.then_some((out, false, at));
        }
        let end = line_end(block, at);
        let line = trim_cr(&block[at..end]);
        let next = after(block, end);
        if line == b"end" {
            return Some((out, true, next));
        }
        match uu_line(line, &mut out) {
            Some(0) => {} // A zero-length line precedes `end`; read on for it.
            Some(_) => any = true,
            None if any => return Some((out, false, at)),
            None => return None,
        }
        at = next;
    }
}

/// Whether a line is `begin <octal mode> <name>` with a non-empty name.
fn begins_block(line: &[u8]) -> bool {
    let Some(rest) = line.strip_prefix(BEGIN) else {
        return false;
    };
    let mode = rest
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(rest.len());
    (1..=4).contains(&mode)
        && rest[..mode].iter().all(|byte| (b'0'..=b'7').contains(byte))
        && rest.get(mode) == Some(&b' ')
        && mode + 1 < rest.len()
}

/// Whether the line at `from` decodes as a uuencode data line: the guard that
/// keeps prose that merely says "begin 644 notes" from counting as a block.
fn first_data_line_valid(body: &[u8], from: usize) -> bool {
    if from >= body.len() {
        return false;
    }
    let line = trim_cr(&body[from..line_end(body, from)]);
    let mut decoded = Vec::new();
    uu_line(line, &mut decoded).is_some()
}

/// Decode one uuencode data line onto `out`, returning the count it carried,
/// or `None` if it is not a valid line.
fn uu_line(line: &[u8], out: &mut Vec<u8>) -> Option<usize> {
    let (&first, rest) = line.split_first()?;
    let length = usize::from(uu_value(first)?);
    if length > UU_FULL {
        return None;
    }
    let groups = length.div_ceil(3);
    let characters = rest.get(..groups * 4)?;
    let before = out.len();
    let (groups_of_four, _) = characters.as_chunks::<4>();
    for group in groups_of_four {
        let (a, b, c, d) = (
            uu_value(group[0])?,
            uu_value(group[1])?,
            uu_value(group[2])?,
            uu_value(group[3])?,
        );
        out.push((a << 2) | (b >> 4));
        out.push(((b & 0x0f) << 4) | (c >> 2));
        out.push(((c & 0x03) << 6) | d);
    }
    out.truncate(before + length);
    Some(length)
}

/// The six bits a uuencode character stands for, or `None` if it is not one.
fn uu_value(character: u8) -> Option<u8> {
    match character {
        b'`' => Some(0),
        0x20..=0x5f => Some((character - 0x20) & 0x3f),
        _ => None,
    }
}
