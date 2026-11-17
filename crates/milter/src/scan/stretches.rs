//! The stretches of base64 in a message, decoded one at a time.
//!
//! An attachment is one stretch, and nearly as long as its message. Decoded
//! all at once and before any was scanned, the stretches of a message stood
//! in memory together, each beside the copy of its symbols it was decoded
//! from: close to three times the message. Here a stretch is found first,
//! then decoded piece by piece into a buffer of exactly its size, scanned,
//! and given up before the next: the scan's copy is three quarters of the
//! message at the most.

use base64::Engine;
use base64::engine::general_purpose::GeneralPurpose;
use base64::engine::{DecodePaddingMode, GeneralPurposeConfig};

/// A stretch of base64 shorter than this holds no document.
const SHORTEST: usize = 64;
/// So many symbols are decoded at a time: whole groups of four.
const PIECE: usize = 4096;

/// base64 as mail programs read it: padding or none, and stray bits at the end.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

fn is_symbol(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

/// The stretches of a message: lines that are base64 and nothing else, in
/// the message's order. Empty lines belong to a stretch: a mail program
/// reads over them.
pub(super) struct Stretches<'a> {
    message: &'a [u8],
    at: usize,
}

/// One stretch as it stands in the message.
pub(super) struct Stretch<'a> {
    lines: &'a [u8],
    symbols: usize,
}

impl<'a> Stretches<'a> {
    pub(super) fn of(message: &'a [u8]) -> Self {
        Stretches { message, at: 0 }
    }
}

impl<'a> Iterator for Stretches<'a> {
    type Item = Stretch<'a>;

    fn next(&mut self) -> Option<Stretch<'a>> {
        // Where the stretch being read begins, and its symbols so far.
        let mut begun: Option<(usize, usize)> = None;
        while self.at < self.message.len() {
            let start = self.at;
            let rest = &self.message[start..];
            let end = rest
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(rest.len());
            self.at = start + end + 1;
            let line = rest[..end].trim_ascii();
            if line.is_empty() {
                continue;
            }
            // A base64 decoder ignores white space between the symbols
            // (RFC 2045 section 6.8), so a line of symbols that a transport
            // broke up with space or tab is base64 all the same.
            if line
                .iter()
                .all(|byte| is_symbol(*byte) || *byte == b'=' || byte.is_ascii_whitespace())
            {
                let symbols = line.iter().filter(|byte| is_symbol(**byte)).count();
                begun.get_or_insert((start, 0)).1 += symbols;
            } else if let Some((from, symbols)) = begun.take()
                && symbols >= SHORTEST
            {
                return Some(Stretch {
                    lines: &self.message[from..start],
                    symbols,
                });
            }
        }
        let (from, symbols) = begun?;
        (symbols >= SHORTEST).then(|| Stretch {
            lines: &self.message[from..],
            symbols,
        })
    }
}

impl Stretch<'_> {
    /// The bytes the stretch stands for. Padding ends a file's data, but
    /// not what a mail program reads: the symbols behind it count on. What
    /// does not decode as a whole decodes up to its last whole group.
    pub(super) fn decoded(&self) -> Vec<u8> {
        // Exactly what the symbols hold, with the room the decoder asks for
        // a last group: a buffer that grew as it was filled would hold up
        // to twice as much.
        let mut data = Vec::with_capacity(self.symbols / 4 * 3 + 3);
        let mut piece: Vec<u8> = Vec::with_capacity(PIECE);
        // Between the symbols of a stretch stand only padding and the ends
        // of lines.
        for symbol in self.lines.iter().copied().filter(|byte| is_symbol(*byte)) {
            piece.push(symbol);
            if piece.len() == PIECE {
                append(&piece, &mut data);
                piece.clear();
            }
        }
        let whole = piece.len() - piece.len() % 4;
        append(&piece[..whole], &mut data);
        // Two or three symbols more are one or two bytes; one alone is none.
        if piece.len() - whole >= 2 {
            append(&piece[whole..], &mut data);
        }
        data
    }
}

/// Decode `symbols` to the end of `data`; what does not decode adds nothing.
fn append(symbols: &[u8], data: &mut Vec<u8>) {
    let before = data.len();
    if LENIENT.decode_vec(symbols, data).is_err() {
        data.truncate(before);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stretches as the scan read them before: every stretch's symbols
    /// gathered, then decoded as a whole.
    fn all_at_once(message: &[u8]) -> Vec<Vec<u8>> {
        let mut decoded = Vec::new();
        let mut run: Vec<u8> = Vec::new();
        let mut close = |run: &mut Vec<u8>| {
            if run.len() >= SHORTEST {
                let whole = run.len() - run.len() % 4;
                if let Ok(data) = LENIENT
                    .decode(&*run)
                    .or_else(|_| LENIENT.decode(&run[..whole]))
                {
                    decoded.push(data);
                }
            }
            run.clear();
        };
        for line in message.split(|byte| *byte == b'\n') {
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }
            if line
                .iter()
                .all(|byte| is_symbol(*byte) || *byte == b'=' || byte.is_ascii_whitespace())
            {
                run.extend(line.iter().copied().filter(|byte| is_symbol(*byte)));
            } else {
                close(&mut run);
            }
        }
        close(&mut run);
        decoded
    }

    /// Numbers that look random and are the same in every run.
    struct Noise(u64);

    impl Noise {
        fn below(&mut self, limit: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(self.0 >> 33).unwrap_or(0) % limit
        }
    }

    /// A message of lines as a sender may write them: base64 of every
    /// length, with padding in and behind it, and what ends a stretch.
    fn written(noise: &mut Noise) -> Vec<u8> {
        const SYMBOLS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut message = Vec::new();
        for _ in 0..noise.below(40) {
            match noise.below(12) {
                0 => message.extend_from_slice(b"--boundary"),
                1 => message.extend_from_slice(b"Content-Type: text/plain"),
                2 => message.extend_from_slice(b"QUJD REVG"),
                3 => message.extend_from_slice(b"  \t"),
                4 => {}
                kind => {
                    // Now and then a line longer than a piece that is decoded.
                    let length = if kind == 5 {
                        4000 + noise.below(9000)
                    } else {
                        noise.below(120)
                    };
                    for _ in 0..length {
                        message.push(SYMBOLS[noise.below(SYMBOLS.len())]);
                        if noise.below(400) == 0 {
                            message.push(b'=');
                        }
                    }
                    message.extend(std::iter::repeat_n(b'=', noise.below(3)));
                }
            }
            message.extend_from_slice(if noise.below(2) == 0 { b"\r\n" } else { b"\n" });
        }
        message.truncate(message.len().saturating_sub(noise.below(3)));
        message
    }

    #[test]
    fn one_at_a_time_reads_what_all_at_once_read() {
        let mut noise = Noise(7);
        let mut stretches = 0;
        for _ in 0..3000 {
            let message = written(&mut noise);
            let one_by_one: Vec<Vec<u8>> = Stretches::of(&message)
                .map(|stretch| stretch.decoded())
                .collect();
            assert_eq!(
                one_by_one,
                all_at_once(&message),
                "{}",
                String::from_utf8_lossy(&message)
            );
            stretches += one_by_one.len();
        }
        // The messages did hold stretches, short and long.
        assert!(stretches > 3000, "{stretches}");
    }

    #[test]
    fn a_stretch_is_decoded_into_a_buffer_of_its_own_size() {
        // An attachment of 3 MB as a mail program writes it.
        let file: Vec<u8> = (0..3_000_000_u32)
            .map(|index| index.to_le_bytes()[0])
            .collect();
        let text = base64::engine::general_purpose::STANDARD.encode(&file);
        let lines: Vec<&[u8]> = text.as_bytes().chunks(76).collect();
        let message = lines.join(&b"\r\n"[..]);
        let stretches: Vec<Stretch<'_>> = Stretches::of(&message).collect();
        assert_eq!(stretches.len(), 1);
        let decoded = stretches[0].decoded();
        assert_eq!(decoded, file);
        assert!(
            decoded.capacity() <= file.len() + 3,
            "{}",
            decoded.capacity()
        );
    }
}
