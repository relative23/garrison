//! What a document with macros cannot be without, searched in bytes as they
//! stand. Every search here reads its data a fixed number of times, however
//! the data is written: a sender chooses the bytes, never the work.

use memchr::memmem;

use super::Found;

/// A compound file's first bytes.
pub(super) const OLE: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
/// `_VBA_PROJECT` as a compound file's directory writes it, UTF-16LE, in
/// lower case. The directory finds a name in any case (MS-CFB 2.6.4: both
/// in upper case, by Unicode's simple case folding, which for these letters
/// is ASCII's), so the project is there in any case of it.
const VBA_STORAGE: &[u8] = b"_\0v\0b\0a\0_\0p\0r\0o\0j\0e\0c\0t\0";
pub(super) const ZIP_ENTRY: &[u8] = b"PK\x03\x04";
/// An entry of the directory at an archive's end, which is what Office reads.
pub(super) const ZIP_LISTED: &[u8] = b"PK\x01\x02";
const ACTIVE_MIME: &[u8] = b"ActiveMime";
/// The names inside a zip archive that are macros, in lower case.
const ZIP_MACROS: [&[u8]; 2] = [b"vbaproject.bin", b"xl/macrosheets/"];

pub(super) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && memmem::find(haystack, needle).is_some()
}

/// Where `needle`, which is in lower case, first stands in `haystack` in
/// either case.
fn position_lowercase(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let starts = haystack.len().checked_sub(needle.len())? + 1;
    memchr::memchr2_iter(first, first.to_ascii_uppercase(), &haystack[..starts])
        .find(|at| haystack[*at..*at + needle.len()].eq_ignore_ascii_case(needle))
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
    for header in memmem::find_iter(data, b"PK") {
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

/// Whether `ActiveMime` stands in `data` followed by the bytes of a file, not
/// by a sentence. The marker is sought at any offset: a decoded base64 stream
/// holds the file with noise before it, so where the file begins is not read;
/// the binary bytes that must follow keep the word in prose from counting.
fn active_mime(data: &[u8]) -> bool {
    memmem::find_iter(data, ACTIVE_MIME).any(|found| {
        data[found + ACTIVE_MIME.len()..]
            .iter()
            .take(16)
            .any(|byte| *byte < 0x20 && !matches!(byte, b'\t' | b'\r' | b'\n'))
    })
}

/// What `data` shows without unpacking anything.
pub(super) fn plain(data: &[u8]) -> Option<Found> {
    if contains(data, OLE) && position_lowercase(data, VBA_STORAGE).is_some() {
        return Some(Found::Compound);
    }
    if names_macros(data) {
        return Some(Found::Zipped);
    }
    active_mime(data).then_some(Found::ActiveMime)
}
