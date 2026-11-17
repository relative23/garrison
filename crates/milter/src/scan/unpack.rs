//! Opening the archives in a message, within bounds its sender cannot move.
//!
//! An archive's headers are the sender's words. What they claim (a place,
//! how many files there are) decides where the scan looks, never how much it
//! does: what is unpacked, what is read to unpack it, the number of files
//! and the time are each bounded here. Nor does the header before a file
//! decide whether, or how much of, the file is unpacked: a program that goes
//! by the directory at the archive's end takes both from there, and the two
//! headers may disagree.

use std::time::Instant;

use flate2::{Decompress, FlushDecompress, Status};

use super::marks::{self, ZIP_ENTRY, ZIP_LISTED, number};
use super::{Found, Gap};

/// One file of an archive is unpacked up to this size, all of a message's
/// together up to four times as much.
pub(super) const UNPACKED: usize = 16 * 1024 * 1024;
/// So many files are opened in one message: what an archive lists without
/// the format's 64-bit extension.
const ENTRIES: usize = 65_535;
/// Packed data is read, and unpacked data written, in pieces of this size,
/// so that the scan looks at the clock in between.
const PIECE: usize = 64 * 1024;

/// How the unpacking of one file ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    /// The file is there as a whole.
    Whole,
    /// The packed data it was given was used up before the file ended.
    Spent,
    /// The data was no deflate from some point on, as a stored file's bytes
    /// are: more of it would have given nothing more.
    Broken,
    /// The file is larger than what the scan unpacks.
    Cut,
    /// The scan's time ran out.
    Late,
}

/// How many levels of transfer encoding are followed below the top message
/// (a body inside a base64 or uuencode body, as a base64-encoded forwarded
/// message carries its own base64 attachment). Three levels in all, as zip
/// archives are followed three deep.
pub(super) const ENCODINGS: usize = 2;
/// A sender can put the mark of a nested encoding into every phase's output
/// at every level and force the recursion to branch; the bytes decoded over
/// all levels are bounded by this multiple of the message's size. Honest
/// nesting three levels deep decodes up to about eight times (measured).
const DECODE_BUDGET: usize = 16;

/// What one scan may still do, and what it had to leave out.
pub(super) struct Work {
    /// What may still be unpacked, of all files together.
    budget: usize,
    /// How many packed files may still be opened.
    entries: usize,
    /// How many bytes the scan may still decode, over all encoding levels.
    decoded: usize,
    /// How many more levels of transfer encoding may be followed.
    pub(super) encodings: usize,
    until: Option<Instant>,
    /// The first thing the scan could not look at.
    pub(super) gap: Option<Gap>,
    inflater: Decompress,
}

impl Work {
    pub(super) fn new(until: Option<Instant>, message_bytes: usize) -> Self {
        Work {
            budget: 4 * UNPACKED,
            entries: ENTRIES,
            decoded: DECODE_BUDGET.saturating_mul(message_bytes),
            encodings: ENCODINGS,
            until,
            gap: None,
            inflater: Decompress::new(false),
        }
    }

    /// Whether `bytes` more may be decoded. Once the budget is spent, the
    /// message was not scanned completely.
    pub(super) fn may_decode(&mut self, bytes: usize) -> bool {
        if bytes > self.decoded {
            self.decoded = 0;
            self.gap.get_or_insert(Gap::Budget);
            false
        } else {
            self.decoded -= bytes;
            true
        }
    }

    /// Whether the scan's time is up, which then is why it is incomplete.
    pub(super) fn late(&mut self) -> bool {
        let late = self.until.is_some_and(|until| Instant::now() >= until);
        if late {
            self.gap = Some(Gap::Deadline);
        }
        late
    }

    /// The scan of one candidate: what it shows, and what the deflated files
    /// of an archive in it show.
    pub(super) fn scanned(&mut self, data: &[u8], depth: usize) -> Option<Found> {
        if self.late() {
            return None;
        }
        if let Some(found) = marks::plain(data) {
            return Some(found);
        }
        if depth == 0 {
            return None;
        }
        // An archive's packed files lie one after the other, so together
        // they are no longer than the archive. Headers that each claim the
        // same stretch are not read past that: the scan would unpack it once
        // for every header.
        let mut readable = data.len();
        // Every header, wherever the archive begins: the one before a file,
        // and the directory's entry for it, which is what a program that
        // opens the archive goes by.
        let mut at = 0;
        while let Some(offset) = data[at..].windows(2).position(|window| window == b"PK") {
            let header = at + offset;
            at = header + 2;
            match data.get(header..header + 4) {
                Some(ZIP_LISTED) => {
                    if number(data, header + 10, 2).is_some_and(unread) {
                        self.gap.get_or_insert(Gap::Method);
                    }
                }
                Some(ZIP_ENTRY) => {
                    if let Some(found) = self.file(data, header, depth, &mut readable) {
                        return Some(found);
                    }
                    if self.gap == Some(Gap::Deadline) {
                        return None;
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// The file behind the header at `header`, unpacked as deflate whatever
    /// that header says of how it is packed and how long it is: the
    /// directory may call deflated what it calls stored, or give the file
    /// its whole length where it gives one byte. Deflate ends by itself.
    /// Bytes that are none, as a stored file's, end the try within a few,
    /// and a stored file was searched with the data around it. A method the
    /// scan does not read is a gap.
    fn file(
        &mut self,
        data: &[u8],
        header: usize,
        depth: usize,
        readable: &mut usize,
    ) -> Option<Found> {
        let (Some(method), Some(name), Some(extra)) = (
            number(data, header + 8, 2),
            number(data, header + 26, 2),
            number(data, header + 28, 2),
        ) else {
            return None;
        };
        if unread(method) {
            self.gap.get_or_insert(Gap::Method);
        }
        // Where the file begins is the one thing every program takes from
        // this header.
        let rest = data.get(header + 30 + name + extra..)?;
        if self.budget == 0 || self.entries == 0 || (*readable == 0 && !rest.is_empty()) {
            self.gap.get_or_insert(Gap::Budget);
            return None;
        }
        self.entries -= 1;
        let offered = rest.len().min(*readable);
        let limit = self.budget.min(UNPACKED);
        let (unpacked, read, end) = self.unpacked(&rest[..offered], limit);
        *readable = readable.saturating_sub(read);
        self.budget = self.budget.saturating_sub(unpacked.len());
        match end {
            End::Late => return None,
            // The file goes on beyond what was unpacked of it.
            End::Cut if limit < UNPACKED => {
                self.gap.get_or_insert(Gap::Budget);
            }
            End::Cut => {
                self.gap.get_or_insert(Gap::Truncated);
            }
            // The deflate went on to the end of what it was given, and the
            // archive held more.
            End::Spent if offered < rest.len() => {
                self.gap.get_or_insert(Gap::Budget);
            }
            End::Whole | End::Spent | End::Broken => {}
        }
        // An unpacked entry may itself be a message with a transfer-encoded
        // body (a message file stored in a zip): read it as one too.
        if let Some(found) = self.scanned(&unpacked, depth - 1) {
            return Some(found);
        }
        self.nested(&unpacked)
    }

    /// One deflated file: at most `limit` bytes of it, how much of `packed`
    /// was read for them, and how it ended.
    fn unpacked(&mut self, packed: &[u8], limit: usize) -> (Vec<u8>, usize, End) {
        self.inflater.reset(false);
        let mut data = Vec::new();
        let mut read = 0;
        loop {
            if self.late() {
                return (data, read, End::Late);
            }
            let filled = data.len();
            if filled > limit {
                // One byte more than is kept came out: the file goes on.
                data.truncate(limit);
                return (data, read, End::Cut);
            }
            let room = PIECE.min(limit + 1 - filled);
            let piece = &packed[read..(read + PIECE).min(packed.len())];
            let before = (self.inflater.total_in(), self.inflater.total_out());
            data.resize(filled + room, 0);
            let status =
                self.inflater
                    .decompress(piece, &mut data[filled..], FlushDecompress::None);
            let taken = moved(before.0, self.inflater.total_in());
            let written = moved(before.1, self.inflater.total_out());
            read += taken;
            data.truncate(filled + written);
            match status {
                Ok(Status::StreamEnd) if data.len() <= limit => return (data, read, End::Whole),
                Ok(Status::StreamEnd) => {}
                // Nothing more can come: the packed data is used up.
                Ok(_) if taken == 0 && written == 0 => return (data, read, End::Spent),
                Ok(_) => {}
                // No deflate from here on. What came out before is scanned.
                Err(_) => return (data, read, End::Broken),
            }
        }
    }
}

/// Whether `method` is a way to pack a zip archive's file that this scan
/// does not unpack: every one the format knows but "stored" and "deflated".
/// The number that stands for an encrypted file is left out: what a password
/// hides is a limit the documentation names. A number the format does not
/// know is noise, since no program unpacks such a file.
const fn unread(method: usize) -> bool {
    matches!(method, 1..=7 | 9 | 10 | 12 | 14 | 16 | 18..=20 | 93..=98)
}

/// How far a counter of the inflater went in one step.
fn moved(before: u64, after: u64) -> usize {
    usize::try_from(after.saturating_sub(before)).unwrap_or(usize::MAX)
}
