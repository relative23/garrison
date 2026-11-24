//! Models of mail programs' base64 decoders, written after their public
//! source, for the tests and the fuzz targets to hold the scan against. Each
//! takes the body of a part as the program is handed it and returns what the
//! program hands its user. They follow `GLib` 2.90 (`g_base64_decode_step`),
//! `GMime` 3.2.15 and its development branch, `MimeKit`'s `Base64Decoder`,
//! Thunderbird's `mimeenc.cpp`, PHP's `base64_decode`, Python 3.14's
//! `email` package, Perl's `MIME::Base64` 3.16, Apache mime4j, Jakarta Mail's
//! `BASE64DecoderStream` and Node's `Buffer`.

/// The value of a symbol of the alphabet.
fn value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The three bytes of a group of four, `=` and anything else counted as 0.
fn triple(group: &[u8]) -> [u8; 3] {
    let number = group.iter().fold(0_u32, |number, byte| {
        (number << 6) | u32::from(value(*byte).unwrap_or(0))
    });
    let [_, first, second, third] = number.to_be_bytes();
    [first, second, third]
}

/// The symbols and `=` of a body, in order.
fn tokens(body: &[u8]) -> Vec<u8> {
    body.iter()
        .copied()
        .filter(|byte| value(*byte).is_some() || *byte == b'=')
        .collect()
}

/// A run of symbols decoded as one: whole groups, then one byte for two
/// symbols left over and two for three.
fn run(symbols: &[u8], out: &mut Vec<u8>) {
    let (groups, rest) = symbols.as_chunks::<4>();
    for group in groups {
        out.extend_from_slice(&triple(group));
    }
    if rest.len() >= 2 {
        let mut group = [b'A'; 4];
        group[..rest.len()].copy_from_slice(rest);
        out.extend_from_slice(&triple(&group)[..rest.len() - 1]);
    }
}

/// `GLib`, which Evolution's Camel uses, and `GMime` 3.0 to 3.2 (Geary, Balsa):
/// `=` is 0, the first byte comes always, the second unless the third place
/// is `=`, the third unless the fourth is; a group the end cuts short gives
/// nothing.
#[must_use]
pub fn glib(body: &[u8]) -> Vec<u8> {
    let tokens = tokens(body);
    let mut out = Vec::new();
    for group in tokens.as_chunks::<4>().0 {
        let [first, second, third] = triple(group);
        out.push(first);
        if group[2] != b'=' {
            out.push(second);
        }
        if group[3] != b'=' {
            out.push(third);
        }
    }
    out
}

/// `MimeKit`, and `GMime`'s development branch: nothing where the second place
/// is `=`, else the first byte, the second unless the third place is, the
/// third unless the fourth is; at the end, as `Flush` does, one or two bytes
/// of a group cut short.
#[must_use]
pub fn mimekit(body: &[u8]) -> Vec<u8> {
    let tokens = tokens(body);
    let (groups, rest) = tokens.as_chunks::<4>();
    let mut out = Vec::new();
    for group in groups {
        let bytes = triple(group);
        let given = if group[1] == b'=' {
            0
        } else if group[2] == b'=' {
            1
        } else if group[3] == b'=' {
            2
        } else {
            3
        };
        out.extend_from_slice(&bytes[..given]);
    }
    if rest.len() >= 2 && rest[0] != b'=' && rest[1] != b'=' {
        let mut group = [b'='; 4];
        group[..rest.len()].copy_from_slice(rest);
        let bytes = triple(&group);
        out.push(bytes[0]);
        if rest.len() == 3 && rest[2] != b'=' {
            out.push(bytes[1]);
        }
    }
    out
}

/// Thunderbird: one byte fewer for each `=` in a group, one at least; what
/// the end cuts short is written as the characters it is.
#[must_use]
pub fn thunderbird(body: &[u8]) -> Vec<u8> {
    let tokens = tokens(body);
    let (groups, rest) = tokens.as_chunks::<4>();
    let mut out = Vec::new();
    for group in groups {
        let padding = memchr::memchr_iter(b'=', group).count();
        out.extend_from_slice(&triple(group)[..3 - padding.min(2)]);
    }
    if rest.first().is_some_and(|byte| *byte != b'=') {
        out.extend_from_slice(rest);
        out.resize(out.len() + 4 - rest.len(), b'=');
    }
    out
}

/// PHP's `base64_decode` outside strict mode and Python's `email` (3.13 and
/// later): every `=` is dropped with the other bytes outside the alphabet.
#[must_use]
pub fn dropped(body: &[u8]) -> Vec<u8> {
    let symbols: Vec<u8> = body
        .iter()
        .copied()
        .filter(|byte| value(*byte).is_some())
        .collect();
    let mut out = Vec::new();
    run(&symbols, &mut out);
    out
}

/// Python's `email` package, 3.14 (`_encoded_words.decode_b`): as
/// [`dropped`], and the text as it stands where one symbol is left over.
#[must_use]
pub fn python(body: &[u8]) -> Vec<u8> {
    let joined: Vec<u8> = body
        .iter()
        .copied()
        .filter(|byte| !matches!(byte, b'\r' | b'\n'))
        .collect();
    if joined.iter().filter(|byte| value(**byte).is_some()).count() % 4 == 1 {
        return joined;
    }
    dropped(&joined)
}

/// The first `=` ends the data, after the bytes its group's symbols give:
/// Perl's `MIME::Base64`, mime4j, Node's `Buffer` with this alphabet.
#[must_use]
pub fn stopped(body: &[u8]) -> Vec<u8> {
    let end = body
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(body.len());
    dropped(&body[..end])
}

/// Jakarta Mail as it is set by default: `=` at a group's third or fourth
/// place ends the group (at the third, a second `=` must follow), the next
/// group starts after it, and any other `=` ends the data with an error.
#[must_use]
pub fn jakarta(body: &[u8]) -> Vec<u8> {
    let tokens = tokens(body);
    let mut out = Vec::new();
    let mut group = Vec::with_capacity(4);
    let mut at = 0;
    while at < tokens.len() {
        let token = tokens[at];
        at += 1;
        if token != b'=' {
            group.push(token);
            if group.len() == 4 {
                out.extend_from_slice(&triple(&group));
                group.clear();
            }
            continue;
        }
        match group.len() {
            2 if tokens.get(at) == Some(&b'=') => {
                at += 1;
                out.push(triple(&[group[0], group[1], b'A', b'A'])[0]);
            }
            3 => out.extend_from_slice(&triple(&[group[0], group[1], group[2], b'A'])[..2]),
            _ => return out,
        }
        group.clear();
    }
    out
}

/// A decoder by its name, as the tests and the fuzz targets list them.
pub type Decoder = (&'static str, fn(&[u8]) -> Vec<u8>);

/// The decoders whose reading the scan follows, alone or as a part of
/// another's: a document any of them hands over is found. Those it does not
/// follow are named in the documents.
pub const READ: [Decoder; 7] = [
    ("GLib, GMime 3", glib),
    ("MimeKit", mimekit),
    ("Thunderbird", thunderbird),
    ("PHP", dropped),
    ("Python", python),
    ("Perl, mime4j", stopped),
    ("Jakarta Mail", jakarta),
];
