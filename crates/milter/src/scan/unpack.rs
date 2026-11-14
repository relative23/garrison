//! Opening the archives in a message, within bounds its sender cannot move.
//!
//! An archive's headers are the sender's words. What they claim (a size, a
//! place, how many files there are) decides where the scan looks, never how
//! much it does: what is unpacked, what is read to unpack it, the number of
//! packed files and the time are each bounded here.

use std::time::Instant;

use flate2::{Decompress, FlushDecompress, Status};

use super::marks::{self, ZIP_ENTRY, ZIP_LISTED, number};
use super::{Found, Gap};

/// One file of an archive is unpacked up to this size, all of a message's
/// together up to four times as much.
const UNPACKED: usize = 16 * 1024 * 1024;
/// How a zip archive names a deflated file.
const DEFLATED: usize = 8;
/// So many packed files are opened in one message: what an archive lists
/// without the format's 64-bit extension.
const ENTRIES: usize = 65_535;
/// Packed data is read, and unpacked data written, in pieces of this size,
/// so that the scan looks at the clock in between.
const PIECE: usize = 64 * 1024;

/// How the unpacking of one file ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    /// The file is there as a whole.
    Whole,
    /// The packed data ended, or was no deflate, before the file did.
    Short,
    /// The file is larger than what the scan unpacks.
    Cut,
    /// The scan's time ran out.
    Late,
}

/// What one scan may still do, and what it had to leave out.
pub(super) struct Work {
    /// What may still be unpacked, of all files together.
    budget: usize,
    /// How many packed files may still be opened.
    entries: usize,
    until: Option<Instant>,
    /// The first thing the scan could not look at.
    pub(super) gap: Option<Gap>,
    inflater: Decompress,
}

impl Work {
    pub(super) fn new(until: Option<Instant>) -> Self {
        Work {
            budget: 4 * UNPACKED,
            entries: ENTRIES,
            until,
            gap: None,
            inflater: Decompress::new(false),
        }
    }

    /// Whether the scan's time is up, which then is why it is incomplete.
    fn late(&mut self) -> bool {
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

    /// The file behind the header at `header`: one that is stored was
    /// searched with the data around it, one that is deflated is unpacked
    /// and scanned, and one packed otherwise is a gap.
    fn file(
        &mut self,
        data: &[u8],
        header: usize,
        depth: usize,
        readable: &mut usize,
    ) -> Option<Found> {
        let (Some(method), Some(packed), Some(name), Some(extra)) = (
            number(data, header + 8, 2),
            number(data, header + 18, 4),
            number(data, header + 26, 2),
            number(data, header + 28, 2),
        ) else {
            return None;
        };
        if unread(method) {
            self.gap.get_or_insert(Gap::Method);
        }
        if method != DEFLATED {
            return None;
        }
        let rest = data.get(header + 30 + name + extra..)?;
        // The header's size is zero where the archive was written as a
        // stream; the deflated data ends itself either way.
        let claimed = if packed == 0 {
            rest.len()
        } else {
            packed.min(rest.len())
        };
        if self.budget == 0 || self.entries == 0 || (*readable == 0 && claimed > 0) {
            self.gap.get_or_insert(Gap::Budget);
            return None;
        }
        self.entries -= 1;
        let offered = claimed.min(*readable);
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
            End::Short if offered < claimed => {
                self.gap.get_or_insert(Gap::Budget);
            }
            End::Whole | End::Short => {}
        }
        self.scanned(&unpacked, depth - 1)
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
                Ok(_) if taken == 0 && written == 0 => return (data, read, End::Short),
                Ok(_) => {}
                // No deflate from here on. What came out before is scanned.
                Err(_) => return (data, read, End::Short),
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
