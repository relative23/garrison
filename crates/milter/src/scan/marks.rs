//! What a document with macros cannot be without, searched in bytes as they
//! stand. Every search here reads its data a fixed number of times, however
//! the data is written: a sender chooses the bytes, never the work.

use super::Found;

/// A compound file's first bytes.
pub(super) const OLE: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
/// `_VBA_PROJECT` as a compound file's directory writes it: UTF-16LE.
const VBA_STORAGE: &[u8] = b"_\0V\0B\0A\0_\0P\0R\0O\0J\0E\0C\0T\0";
pub(super) const ZIP_ENTRY: &[u8] = b"PK\x03\x04";
/// An entry of the directory at an archive's end, which is what Office reads.
const ZIP_LISTED: &[u8] = b"PK\x01\x02";
const ACTIVE_MIME: &[u8] = b"ActiveMime";
/// The names inside a zip archive that are macros, in lower case.
const ZIP_MACROS: [&[u8]; 2] = [b"vbaproject.bin", b"xl/macrosheets/"];

pub(super) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Where `needle`, which is in lower case, first stands in `haystack` in
/// either case.
fn position_lowercase(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    haystack.windows(needle.len()).position(|window| {
        window[0].to_ascii_lowercase() == first && window.eq_ignore_ascii_case(needle)
    })
}

pub(super) fn number(data: &[u8], at: usize, bytes: usize) -> Option<usize> {
    let field = data.get(at..at + bytes)?;
    Some(
        field
            .iter()
            .rev()
            .fold(0, |sum, byte| (sum << 8) | usize::from(*byte)),
    )
}

/// The next place of one name at or after a position. The positions asked
/// for only rise, so all questions together read the data once, however
/// many headers ask and however long the names they claim.
struct Next<'a> {
    data: &'a [u8],
    name: &'a [u8],
    /// The first place at or after the last position asked for.
    found: Option<usize>,
    /// No place is left.
    done: bool,
}

impl<'a> Next<'a> {
    fn new(data: &'a [u8], name: &'a [u8]) -> Self {
        Next {
            data,
            name,
            found: None,
            done: false,
        }
    }

    /// Whether the name stands whole between `start` and `end`.
    fn within(&mut self, start: usize, end: usize) -> bool {
        if self.found.is_none_or(|found| found < start) && !self.done {
            // What was found before lies behind `start`, and so does
            // everything before it.
            let from = start.min(self.data.len());
            self.found = position_lowercase(&self.data[from..], self.name).map(|at| from + at);
            self.done = self.found.is_none();
        }
        self.found
            .is_some_and(|found| found >= start && found + self.name.len() <= end)
    }
}

/// Whether a zip header in `data` names a file that is macros: the header
/// before a file or the directory's entry for it, wherever one stands. A
/// name that is cut off counts as far as it goes.
fn names_macros(data: &[u8]) -> bool {
    // One search for each name and each kind of header: the places the
    // headers of one kind ask about only rise.
    let searches = || ZIP_MACROS.map(|name| Next::new(data, name));
    let (mut before_files, mut listed) = (searches(), searches());
    let mut at = 0;
    while let Some(offset) = data[at..].windows(2).position(|window| window == b"PK") {
        let header = at + offset;
        at = header + 2;
        // Where the name's length stands, and where the name begins.
        let (names, length, name) = match data.get(header..header + 4) {
            Some(ZIP_ENTRY) => (&mut before_files, 26, 30),
            Some(ZIP_LISTED) => (&mut listed, 28, 46),
            _ => continue,
        };
        let Some(length) = number(data, header + length, 2) else {
            continue;
        };
        let start = (header + name).min(data.len());
        let end = (start + length).min(data.len());
        if names.iter_mut().any(|macros| macros.within(start, end)) {
            return true;
        }
    }
    false
}

/// Whether a file begins with `ActiveMime` somewhere in `data`: at its start
/// or a line's, and followed by the bytes of a file, not by a sentence.
fn active_mime(data: &[u8]) -> bool {
    let mut at = 0;
    while let Some(offset) = data[at..]
        .windows(ACTIVE_MIME.len())
        .position(|window| window == ACTIVE_MIME)
    {
        let found = at + offset;
        at = found + ACTIVE_MIME.len();
        let begins = found == 0 || data[found - 1] == b'\n';
        let binary = data[at..]
            .iter()
            .take(16)
            .any(|byte| *byte < 0x20 && !matches!(byte, b'\t' | b'\r' | b'\n'));
        if begins && binary {
            return true;
        }
    }
    false
}

/// What `data` shows without unpacking anything.
pub(super) fn plain(data: &[u8]) -> Option<Found> {
    if contains(data, OLE) && contains(data, VBA_STORAGE) {
        return Some(Found::Compound);
    }
    if names_macros(data) {
        return Some(Found::Zipped);
    }
    active_mime(data).then_some(Found::ActiveMime)
}
