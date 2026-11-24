//! Decoding uuencode, which mail programs still take although it is no MIME
//! transfer encoding: a `begin <mode> <name>` block in any body, or a part
//! that declares it.
//!
//! It is read as a mail program reads it that asks least of it, so that what
//! is scanned is what such a program hands its user. A character is whatever
//! six bits `(c - 0x20) & 0x3f` gives. A line carries as many bytes as its
//! first character says, up to 63, and zeros for those its characters do not
//! reach. A line ends at LF, CR or both. A block runs to its `end` line, to
//! the next block's `begin`, or to the end of the data, whatever its lines
//! hold. Under a declared uuencode any line that starts with `begin ` opens
//! one.

/// The bytes that open a uuencode block.
const BEGIN: &[u8] = b"begin ";
/// A data line of the format's own writers carries 45 bytes at the most.
const UU_FULL: usize = 45;

/// A decoded block.
pub(super) struct Block {
    pub(super) bytes: Vec<u8>,
    /// Whether all of it was read: not where a block that a writer of the
    /// format made has no `end`, nor where it gave more bytes than are read.
    pub(super) whole: bool,
    /// How far the block reaches from its `begin`.
    pub(super) length: usize,
}

/// Where the line that begins at `from` ends: at its LF or CR, or the data's end.
fn line_end(data: &[u8], from: usize) -> usize {
    memchr::memchr2(b'\n', b'\r', &data[from..]).map_or(data.len(), |at| from + at)
}

/// Where the line after the one that ends at `line_end` begins.
fn after(data: &[u8], line_end: usize) -> usize {
    let ending = if data[line_end..].starts_with(b"\r\n") {
        2
    } else {
        1
    };
    (line_end + ending).min(data.len())
}

/// The start of the next uuencode block at or after `from`.
pub(super) fn next_begin(body: &[u8], from: usize, declared: bool) -> Option<usize> {
    let from = from.min(body.len());
    memchr::memmem::find_iter(&body[from..], BEGIN)
        .map(|offset| from + offset)
        .find(|begin| opens(body, *begin, declared))
}

/// Whether a block begins at `at`. Under a `declared` uuencode any line that
/// starts with `begin ` begins one. Elsewhere it is `begin`, an octal mode
/// and a space: with a mode of three or four digits that is enough, as it is
/// for a mail program; with one of one or two, as a sentence has ("begin 2
/// weeks earlier"), a name must follow and the next line must be one a
/// writer of the format makes.
fn opens(body: &[u8], at: usize, declared: bool) -> bool {
    if at != 0 && !matches!(body[at - 1], b'\n' | b'\r') {
        return false;
    }
    let end = line_end(body, at);
    let Some(rest) = body[at..end].strip_prefix(BEGIN) else {
        return false;
    };
    if declared {
        return true;
    }
    let digits = rest
        .iter()
        .position(|byte| !(b'0'..=b'7').contains(byte))
        .unwrap_or(rest.len());
    if rest.get(digits) != Some(&b' ') {
        return false;
    }
    match digits {
        3..=4 => true,
        1..=2 => digits + 1 < rest.len() && written(body, after(body, end)),
        _ => false,
    }
}

/// Whether the line at `from` is a data line as a writer of the format makes
/// one: its characters from 0x20 to 0x60, no more than 45 bytes, and all the
/// characters those need.
fn written(body: &[u8], from: usize) -> bool {
    let line = &body[from.min(body.len())..line_end(body, from.min(body.len()))];
    let usual = |byte: &u8| (0x20..=0x60).contains(byte);
    line.split_first().is_some_and(|(first, rest)| {
        let length = usize::from((first.wrapping_sub(0x20)) & 0x3f);
        usual(first)
            && length <= UU_FULL
            && rest.len() >= length.div_ceil(3) * 4
            && rest.iter().all(usual)
    })
}

/// Decode the block whose `begin` line is at the start of `block`, up to
/// `limit` bytes: a line of one character may stand for 63 zeros, so a block
/// can give many times what it is long.
pub(super) fn decode(block: &[u8], declared: bool, limit: usize) -> Block {
    let mut at = after(block, line_end(block, 0));
    let made_by_a_writer = written(block, at);
    let mut bytes = Vec::new();
    let (mut ended, mut cut) = (false, false);
    while at < block.len() && !opens(block, at, declared) {
        let end = line_end(block, at);
        let line = &block[at..end];
        at = after(block, end);
        if line == b"end" {
            ended = true;
            break;
        }
        read_line(line, &mut bytes);
        if bytes.len() > limit {
            bytes.truncate(limit);
            cut = true;
            break;
        }
    }
    Block {
        bytes,
        whole: !cut && (ended || !made_by_a_writer),
        length: at,
    }
}

/// One data line as a mail program decodes it: as many bytes as the first
/// character says, from the characters that are there, and zeros for the
/// rest.
fn read_line(line: &[u8], out: &mut Vec<u8>) {
    let six = |character: u8| character.wrapping_sub(0x20) & 0x3f;
    let Some((&first, rest)) = line.split_first() else {
        return;
    };
    let length = usize::from(six(first));
    let there = length.min(rest.len() * 3 / 4);
    let start = out.len();
    for group in rest.chunks(4) {
        if out.len() - start >= there {
            break;
        }
        let at = |index: usize| six(group.get(index).copied().unwrap_or(b' '));
        out.push((at(0) << 2) | (at(1) >> 4));
        out.push((at(1) << 4) | (at(2) >> 2));
        out.push((at(2) << 6) | at(3));
    }
    out.truncate(start + there);
    out.resize(start + length, 0);
}
