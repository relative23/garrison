//! Whether a message carries an Office document with macros.
//!
//! The scan does not trust the message's structure. A sender who wants a
//! document past a filter writes the MIME around it wrongly on purpose, in a
//! way mail programs forgive. So nothing here follows boundaries or part
//! headers: every stretch of base64 in the message is decoded, the message is
//! also read as it stands and with its quoted-printable undone, and each of
//! these is searched for what a document with macros cannot be without.
//!
//! - An old Word or Excel file (`.doc`, `.xls`) is a compound file, and its
//!   macros live in a storage whose directory names `_VBA_PROJECT`, in any
//!   case: the directory finds its names so.
//! - A new one (`.docm`, `.xlsm`, `.pptm`, also when it is named `.docx`) is
//!   a zip archive whose macros are the file `vbaProject.bin`; the names of
//!   an archive's files are never compressed. By the format's specification
//!   that file is itself a compound file with a `_VBA_PROJECT`, so it is
//!   found under another name too.
//! - Word's "single file web page" carries them as an `ActiveMime` part.
//!
//! Text that only speaks of these names is no document: an archive's names
//! count where its headers have them, and `ActiveMime` where a file begins
//! with it.
//!
//! An archive inside the message is opened, and archives inside it, so far
//! as [`DEPTH`] goes. What the scan cannot see is said in the crate's
//! documentation: encrypted archives, Excel 4.0 macro sheets in old `.xls`
//! files and the macros of an old `.ppt` file among it.
//!
//! What the scan could have seen but did not look at is another matter, and
//! never passes for a clean message: more packed data than it unpacks, a
//! file packed otherwise than by deflate, or time that ran out end as
//! [`Outcome::Incomplete`], and the filter's operator decides what such a
//! message gets.

use std::time::Instant;

mod base64_stream;
mod marks;
mod parts;
mod quoted;
mod unpack;
mod uu;

use marks::contains;
use quoted::{lone_cr_break, unquoted};
use unpack::Work;

/// Archives inside archives are opened this deep.
pub const DEPTH: usize = 3;
/// Quoted-printable inside quoted-printable is undone this often more.
const QUOTED: usize = 2;
/// What a scan holds of unpacked files at the most: one at each depth, in
/// a buffer that may hold twice what was unpacked into it.
pub(crate) const MOST_UNPACKED: usize = DEPTH * 2 * unpack::UNPACKED;

/// What kind of document with macros was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// An old Office file with a VBA project.
    Compound,
    /// A new Office file with `vbaProject.bin` or macro sheets.
    Zipped,
    /// A web page of Word's with an `ActiveMime` part.
    ActiveMime,
}

impl Found {
    /// The kind in words, for the log.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Found::Compound => "an Office document (compound file) with a VBA project",
            Found::Zipped => "an Office document (Open XML) with macros",
            Found::ActiveMime => "a web page with an ActiveMime part",
        }
    }
}

/// Why a scan could not look at all of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    /// Its archives hold more than the scan unpacks or reads.
    Budget,
    /// One packed file is larger than the scan unpacks of one.
    Truncated,
    /// A file is packed in a way the scan does not read.
    Method,
    /// The scan's time ran out.
    Deadline,
    /// The message is larger than what is scanned at all.
    Size,
    /// A part declares a transfer encoding the scan does not decode, or a
    /// uuencode block that began and did not end.
    Encoding,
}

impl Gap {
    /// The reason in words, for the log. It says nothing of the message.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Gap::Budget => "its archives hold more than the scan unpacks",
            Gap::Truncated => "a packed file in it is larger than the scan unpacks",
            Gap::Method => "an archive in it is packed in a way the scan does not read",
            Gap::Deadline => "the scan's time ran out",
            Gap::Size => "it is larger than the configured max_message_mib",
            Gap::Encoding => "a part is encoded in a way the scan does not read",
        }
    }
}

/// What a scan says of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Everything was looked at, and no document with macros is in it.
    Clean,
    /// The first document with macros in it.
    Macros(Found),
    /// No document with macros was seen, but not everything could be looked
    /// at: this is not a clean message.
    Incomplete(Gap),
}

/// What `message` carries, with all the time the scan needs.
#[must_use]
pub fn macros(message: &[u8]) -> Outcome {
    scan(message, None)
}

/// What `message` carries, so far as that is known at `until`: a scan that
/// is not done by then ends as [`Gap::Deadline`].
#[must_use]
pub fn macros_until(message: &[u8], until: Instant) -> Outcome {
    scan(message, Some(until))
}

/// What a file holds that a mail program handed over: a document in it as it
/// stands, or in the message it is where it names an encoding. Its last four
/// bytes are left out, which a group of base64 that the data's end cuts short
/// gives as each decoder ends: they decide no document, since an archive
/// ends in the record of its directory's end and a compound file's names
/// stand first in entries of 128 bytes. For the tests and the fuzz targets,
/// to ask of a decoder's output.
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn in_file(file: &[u8]) -> Option<Found> {
    let file = &file[..file.len().saturating_sub(4)];
    Work::new(None, file.len()).scanned_deep(file)
}

fn scan(message: &[u8], until: Option<Instant>) -> Outcome {
    let mut work = Work::new(until, message.len());
    match (candidates(message, &mut work), work.gap) {
        (Some(found), _) => Outcome::Macros(found),
        (None, Some(gap)) => Outcome::Incomplete(gap),
        (None, None) => Outcome::Clean,
    }
}

/// The first document with macros in what `message` may be read as. No pass
/// reads where a part begins or ends, how deep it is, or how its headers are
/// written: structure may make an answer more exact, never more lenient.
fn candidates(message: &[u8], work: &mut Work) -> Option<Found> {
    // The message as it stands: a document in the clear, any encoding's bytes
    // that happen to be literal, the archives in them, and a message file in
    // an archive, which `scanned` reads as a message of its own.
    let whole = work.allowance();
    if let Some(found) = work.scanned(message, DEPTH) {
        return Some(found);
    }
    // The message's transfer encodings, undone over the whole of it.
    let left = work.allowance();
    work.allow(whole);
    if let Some(found) = work.decode_encodings(message) {
        return Some(found);
    }
    work.allow(left.least(work.allowance()));
    // The one thing a header can still decide, and only to make the answer
    // stricter: a part that declares a transfer encoding the scan does not
    // decode is a message not scanned completely, not a clean one.
    work.flag_undecodable_encoding(message);
    None
}

/// What the readings of one text may unpack. Readings often hold the same
/// archive (a base64 body without `=` in it reads the same in each of them,
/// and again once quoted-printable is undone around it), and it is then
/// unpacked for each. So each reading unpacks within the
/// bounds the text came with, and the scan goes on with what the reading
/// that unpacked most has left.
struct Readings {
    whole: unpack::Allowance,
    least: unpack::Allowance,
}

impl Work {
    /// Undo the message's transfer encodings over the whole of it, reading no
    /// structure: the base64 on each of the four grids a run of symbols can
    /// sit on (so a base64 body anywhere comes out whole in one phase,
    /// whatever junk, boundary or header surrounds it), the uuencode blocks,
    /// and the same again with the quoted-printable undone. Each decoded
    /// stream is scanned for a document and, where it is itself a message
    /// with a nested encoding, read again.
    fn decode_encodings(&mut self, data: &[u8]) -> Option<Found> {
        let whole = self.allowance();
        let mut readings = Readings {
            whole,
            least: whole,
        };
        let found = self.encoded(data, &mut readings, QUOTED, None);
        self.allow(readings.least);
        found
    }

    /// One reading of `readings`' text.
    fn reading(
        &mut self,
        readings: &mut Readings,
        read: impl FnOnce(&mut Self) -> Option<Found>,
    ) -> Option<Found> {
        if self.stopped() {
            return None;
        }
        self.allow(readings.whole);
        let found = read(self);
        readings.least = readings.least.least(self.allowance());
        found
    }

    /// `data`'s base64 and uuencode, then the same of `data` with its
    /// quoted-printable undone, `rounds` times over at the most, with a lone
    /// CR taken for a line's end as `lone_cr` says where a round above
    /// decided it.
    fn encoded(
        &mut self,
        data: &[u8],
        readings: &mut Readings,
        rounds: usize,
        lone_cr: Option<bool>,
    ) -> Option<Found> {
        let symbols = base64_stream::count(data);
        let tokens = symbols + base64_stream::padding(data);
        let dropped = |phase| base64_stream::decode_phase(data, phase, symbols);
        if let Some(found) = self.reading(readings, |work| work.base64(dropped)) {
            return Some(found);
        }
        // Without `=` every way to read base64 reads the same.
        if tokens > symbols {
            for group in base64_stream::Group::ALL {
                let grouped = |phase| base64_stream::decode_tokens(data, phase, tokens, group);
                if let Some(found) = self.reading(readings, |work| work.base64(grouped)) {
                    return Some(found);
                }
            }
        }
        if let Some(found) = self.reading(readings, |work| work.scanned_uuencoded(data)) {
            return Some(found);
        }
        if self.stopped() || !contains(data, b"=") {
            return None;
        }
        // Thunderbird and PHP take `=` before a CR that no LF follows for a
        // soft break as well. Where `data` holds one, it is undone both ways,
        // and each way keeps to itself in the rounds below.
        let ways: &[(bool, Option<bool>)] = match lone_cr {
            Some(false) => &[(false, Some(false))],
            Some(true) => &[(true, Some(true))],
            None if lone_cr_break(data) => &[(false, Some(false)), (true, Some(true))],
            None => &[(false, None)],
        };
        for (way, below) in ways {
            if self.stopped() {
                return None;
            }
            let (undone, triplets) = unquoted(data, *way);
            if let Some(found) =
                self.quoted(&undone, triplets, data.len(), readings, (rounds, *below))
            {
                return Some(found);
            }
        }
        None
    }

    /// The reading of a text whose quoted-printable was undone: as it stands,
    /// and as the text was read where triplets were undone.
    fn quoted(
        &mut self,
        undone: &[u8],
        triplets: usize,
        length: usize,
        readings: &mut Readings,
        (rounds, lone_cr): (usize, Option<bool>),
    ) -> Option<Found> {
        if undone.len() == length || !self.may_decode(undone.len()) {
            return None;
        }
        if let Some(found) = self.reading(readings, |work| work.scanned(undone, DEPTH)) {
            return Some(found);
        }
        // Where only soft line breaks went, the base64 reads as before: `=`
        // and a line's end are no symbols. A uuencode block's lines are
        // whole only now.
        if triplets == 0 {
            return self.reading(readings, |work| work.scanned_uuencoded(undone));
        }
        // An `=XX` is two symbols to the base64 readers and one byte, or
        // none, to a mail program that undoes it first: one of them inside a
        // base64 body shifts everything behind it. So the result is read as
        // `data` was, and again where it holds quoted-printable of its own,
        // as a message does that was wrapped twice.
        if rounds == 0 {
            self.gap.get_or_insert(Gap::Encoding);
            return None;
        }
        self.encoded(undone, readings, rounds - 1, lone_cr)
    }

    /// One way to read the base64, on each of its grids.
    fn base64(&mut self, decode: impl Fn(usize) -> Vec<u8>) -> Option<Found> {
        for phase in 0..base64_stream::PHASES {
            if self.late() {
                return None;
            }
            let stream = decode(phase);
            if !self.may_decode(stream.len()) {
                return None;
            }
            if let Some(found) = self.scanned_deep(&stream) {
                return Some(found);
            }
        }
        None
    }

    /// Scan a decoded stream for a document (marks and archives), and, where
    /// it is itself a message with a nested transfer encoding, read that too.
    pub(super) fn scanned_deep(&mut self, stream: &[u8]) -> Option<Found> {
        if let Some(found) = self.scanned(stream, DEPTH) {
            return Some(found);
        }
        self.nested(stream)
    }

    /// Follow a nested transfer encoding, but only where `data` itself says it
    /// is there: a client decodes a body a second time only because the inner
    /// message's headers name a `Content-Transfer-Encoding` or a uuencode
    /// block begins. Noise does not hold that name by chance, so ordinary mail
    /// is not read again. Below the depth the scan follows, such a message is
    /// incomplete, never clean.
    pub(super) fn nested(&mut self, data: &[u8]) -> Option<Found> {
        let declared = first_declaration(data)?;
        if self.encodings == 0 {
            self.gap.get_or_insert(Gap::Encoding);
            return None;
        }
        // A mail program decodes nothing of the message before its first
        // declaration, nor before a block it cannot decode: two readings of
        // a body that agree from there on are one message, read once.
        let from = parts::unread_opening(data).map_or(declared, |opening| opening.min(declared));
        let line = data[..from]
            .iter()
            .rposition(|byte| matches!(byte, b'\n' | b'\r'))
            .map_or(0, |end| end + 1);
        if !self.unread_message(&data[line..]) {
            return None;
        }
        self.encodings -= 1;
        let found = self.decode_encodings(data);
        self.encodings += 1;
        if found.is_none() {
            self.flag_undecodable_encoding(data);
        }
        found
    }
}

/// Where `data` first says of itself that it holds an encoding: a message that
/// names a transfer encoding (the header name in the clear, the only way a
/// client would read it, any case), a uuencode block's `begin` line, or an
/// element that Office's XML formats fill with base64.
fn first_declaration(data: &[u8]) -> Option<usize> {
    const NAME: &[u8] = b"content-transfer-encoding";
    // Found by its first `-`, which decoded noise holds far less often than
    // a letter.
    const DASH: usize = 7;
    let named = memchr::memchr_iter(b'-', data)
        .find(|dash| {
            *dash >= DASH
                && data
                    .get(dash - DASH..dash - DASH + NAME.len())
                    .is_some_and(|name| name.eq_ignore_ascii_case(NAME))
        })
        .map(|dash| dash - DASH);
    [
        named,
        uu::next_begin(data, 0, false),
        marks::office_xml(data),
    ]
    .into_iter()
    .flatten()
    .min()
}

#[cfg(test)]
mod bounds_tests;
#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod encoding_tests;
#[cfg(test)]
mod equals_tests;
#[cfg(test)]
mod incomplete_tests;
#[cfg(test)]
mod nested_tests;
#[cfg(test)]
mod parts_tests;
#[cfg(test)]
mod structure_tests;
#[cfg(test)]
mod sweep_tests;
#[cfg(test)]
pub(crate) mod tests;
