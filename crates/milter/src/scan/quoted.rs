//! Undoing a message's quoted-printable, over the whole of it.

/// Where a message's header block ends for every reader at the latest: at the
/// first line that is neither a header field (a name of printable characters
/// and a colon) nor the continuation of one (white space, then more). A line
/// ends at LF or at CR. No reader takes anything before this for a body, so
/// what stands there belongs to no attachment.
fn headers_end(message: &[u8]) -> usize {
    let blank = |byte: &u8| matches!(byte, b' ' | b'\t');
    let mut at = 0;
    let mut field_before = false;
    while at < message.len() {
        let end = message[at..]
            .iter()
            .position(|byte| matches!(byte, b'\n' | b'\r'))
            .map_or(message.len(), |end| at + end);
        let line = &message[at..end];
        let field = line
            .iter()
            .position(|byte| *byte == b':')
            .is_some_and(|colon| colon > 0 && line[..colon].iter().all(u8::is_ascii_graphic));
        let continued = field_before && line.first().is_some_and(blank) && !line.iter().all(blank);
        if !field && !continued {
            return at;
        }
        field_before = true;
        at = end
            + if message[end..].starts_with(b"\r\n") {
                2
            } else {
                1
            };
    }
    message.len()
}

/// The message with its quoted-printable undone: `=XX` is a byte in either
/// hexadecimal case, and `=` at a line's end joins the lines. A transport
/// may pad an encoded line with space and tab before the break; RFC 2045
/// section 6.7 rule 3 has the decoder strip it, so `=` then white space then
/// the line's end is a soft break as well. Where `lone_cr` is set, a CR that
/// no LF follows ends a line too, as Thunderbird and PHP take it. With it,
/// how many `=XX` were undone past the header block: each stands where a
/// body may be.
pub(super) fn unquoted(message: &[u8], lone_cr: bool) -> (Vec<u8>, usize) {
    let hex = |byte: u8| char::from(byte).to_digit(16);
    let body = headers_end(message);
    let mut plain = Vec::with_capacity(message.len());
    let mut triplets = 0;
    let mut at = 0;
    while at < message.len() {
        if message[at] == b'=' {
            // A soft line break: `=`, then any space or tab a transport
            // added, then the line's end. None of it reaches the output.
            let mut end = at + 1;
            while matches!(message.get(end), Some(b' ' | b'\t')) {
                end += 1;
            }
            match (message.get(end), message.get(end + 1)) {
                (Some(b'\r'), Some(b'\n')) => {
                    at = end + 2;
                    continue;
                }
                (Some(b'\n'), _) => {
                    at = end + 1;
                    continue;
                }
                (Some(b'\r'), _) if lone_cr => {
                    at = end + 1;
                    continue;
                }
                _ => {}
            }
            // `=XX`: the high hexadecimal digit then the low, either case.
            if let (Some(high), Some(low)) = (message.get(at + 1), message.get(at + 2))
                && let (Some(high), Some(low)) = (hex(*high), hex(*low))
            {
                plain.push(u8::try_from(high * 16 + low).unwrap_or(b'='));
                triplets += usize::from(at >= body);
                at += 3;
                continue;
            }
        }
        plain.push(message[at]);
        at += 1;
    }
    (plain, triplets)
}

/// Whether `data` holds `=`, then any space or tab, then a CR that no LF
/// follows.
pub(super) fn lone_cr_break(data: &[u8]) -> bool {
    memchr::memchr_iter(b'=', data).any(|at| {
        let end = at
            + 1
            + data[at + 1..]
                .iter()
                .take_while(|byte| matches!(byte, b' ' | b'\t'))
                .count();
        data.get(end) == Some(&b'\r') && data.get(end + 1) != Some(&b'\n')
    })
}
