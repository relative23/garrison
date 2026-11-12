//! The end of a certificate's validity period, read from its DER encoding.
//!
//! Only certificates that rustls has already validated reach this code, so
//! the structure is known to be well-formed; the parser still checks every
//! length and returns `None` for anything unexpected.

use garrison_core::time::{self, Timestamp};

/// One DER element: its tag, its content and what follows it.
fn element(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (bytes, rest) = rest.split_at(count);
        let length = bytes
            .iter()
            .fold(0_usize, |total, byte| (total << 8) | usize::from(*byte));
        (length, rest)
    };
    if rest.len() < length {
        return None;
    }
    let (content, rest) = rest.split_at(length);
    Some((tag, content, rest))
}

const SEQUENCE: u8 = 0x30;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0] EXPLICIT Version`, present from X.509 v2.
const VERSION: u8 = 0xa0;

/// `notAfter` of an X.509 certificate.
pub(super) fn not_after(der: &[u8]) -> Option<Timestamp> {
    let (SEQUENCE, certificate, _) = element(der)? else {
        return None;
    };
    let (SEQUENCE, tbs, _) = element(certificate)? else {
        return None;
    };
    let mut rest = tbs;
    let (tag, _, after) = element(rest)?;
    if tag == VERSION {
        rest = after;
    }
    // serialNumber, signature, issuer, then validity.
    for _ in 0..3 {
        rest = element(rest)?.2;
    }
    let (SEQUENCE, validity, _) = element(rest)? else {
        return None;
    };
    let (_, _, after_start) = element(validity)?;
    let (tag, end, _) = element(after_start)?;
    let text = std::str::from_utf8(end).ok()?;
    match tag {
        UTC_TIME => utc_time(text),
        GENERALIZED_TIME => generalized_time(text),
        _ => None,
    }
}

/// `YYMMDDHHMMSSZ`; years 50 to 99 are 19xx (RFC 5280).
fn utc_time(text: &str) -> Option<Timestamp> {
    let digits = text.strip_suffix('Z')?;
    if digits.len() != 12 {
        return None;
    }
    let year: u32 = digits.get(..2)?.parse().ok()?;
    let century = if year >= 50 { "19" } else { "20" };
    generalized_time(&format!("{century}{text}"))
}

/// `YYYYMMDDHHMMSSZ`.
fn generalized_time(text: &str) -> Option<Timestamp> {
    let digits = text.strip_suffix('Z')?;
    if digits.len() != 14 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let iso = format!(
        "{}-{}-{}T{}:{}:{}",
        &digits[..4],
        &digits[4..6],
        &digits[6..8],
        &digits[8..10],
        &digits[10..12],
        &digits[12..14]
    );
    time::parse_naive_utc(&iso)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_validity_end_is_read() {
        let certificates = crate::testing::certificates();
        let end = not_after(&certificates.server).unwrap();
        assert_eq!(time::isoformat(end), "2036-10-26T00:00:00+00:00");
        // The CA's validity runs to rcgen's default end, encoded as GeneralizedTime.
        assert_eq!(
            time::isoformat(not_after(&certificates.ca).unwrap()),
            "4096-01-01T00:00:00+00:00"
        );
    }

    #[test]
    fn times_use_both_encodings() {
        assert_eq!(
            time::isoformat(utc_time("491231235959Z").unwrap()),
            "2049-12-31T23:59:59+00:00"
        );
        assert_eq!(
            time::isoformat(utc_time("500101000000Z").unwrap()),
            "1950-01-01T00:00:00+00:00"
        );
        assert!(utc_time("4912312359Z").is_none());
        // Twelve bytes, but not twelve digits.
        assert!(utc_time("€123456789Z").is_none());
        assert!(generalized_time("20491231235959").is_none());
        assert!(generalized_time("2049123123595Z").is_none());
    }

    #[test]
    fn lengths_use_the_short_or_the_long_form_of_der() {
        assert_eq!(element(b"\x04\x7f"), None);
        assert_eq!(element(b"\x04\x02ab!"), Some((4, &b"ab"[..], &b"!"[..])));
        assert_eq!(element(b"\x04\x81\x00"), Some((4, &b""[..], &b""[..])));
        assert_eq!(
            element(b"\x04\x84\x00\x00\x00\x02ab"),
            Some((4, &b"ab"[..], &b""[..]))
        );
        // Indefinite lengths, more than four length bytes and missing ones are refused.
        let indefinite = [&[0x04, 0x80][..], &[b'a'; 128]].concat();
        assert_eq!(element(&indefinite), None);
        assert_eq!(element(b"\x04\x80ab"), None);
        assert_eq!(element(b"\x04\x85\x00\x00\x00\x00\x02ab"), None);
        assert_eq!(element(b"\x04\x82\x00"), None);
    }

    #[test]
    fn truncated_input_is_refused() {
        let der = crate::testing::certificates().server;
        for length in [0, 1, 2, 10, der.len() / 2] {
            assert_eq!(not_after(&der[..length]), None, "{length}");
        }
        assert_eq!(not_after(b"\x30\x84\xff\xff\xff\xff"), None);
    }

    #[test]
    fn damaged_certificates_and_random_times_are_read_without_panics() {
        let mut noise = garrison_testing::noise::Noise::new(29);
        let der = crate::testing::certificates().server.to_vec();
        let byte = |noise: &mut garrison_testing::noise::Noise| noise.next_u64().to_le_bytes()[0];
        for _ in 0..20_000 {
            let mut damaged = der.clone();
            for _ in 0..=noise.below(3) {
                let at = noise.below(damaged.len());
                damaged[at] = byte(&mut noise);
            }
            damaged.truncate(noise.below(damaged.len() + 1));
            let _ = not_after(&damaged);
            let random: Vec<u8> = (0..noise.below(48)).map(|_| byte(&mut noise)).collect();
            let _ = not_after(&random);
            let text = noise.text("0123456789Z+-€", 16);
            let _ = (utc_time(&text), generalized_time(&text));
        }
    }
}
