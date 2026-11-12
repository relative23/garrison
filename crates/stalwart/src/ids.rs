//! The Stalwart 1.0 numeric account-ID representation.
//!
//! Native OIDC subjects contain the decimal u32 account ID. JMAP represents that
//! ID as a base-32 numeral with Stalwart's own alphabet, not as base-32 encoded
//! bytes. The contract tests check the mapping against a running Stalwart.

use crate::Error;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz792013";

/// One unsigned 64-bit numeral in Stalwart's native alphabet.
pub fn encode_native_id(mut number: u64) -> String {
    let mut symbols = Vec::new();
    loop {
        // The remainder is below 32, so the index is in range.
        symbols.push(char::from(ALPHABET[(number % 32) as usize]));
        number /= 32;
        if number == 0 {
            break;
        }
    }
    symbols.into_iter().rev().collect()
}

/// The number a numeral in Stalwart's native alphabet stands for; `None` for
/// text that is no such numeral or is too long for 64 bits.
pub fn decode_native_id(text: &str) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    text.bytes().try_fold(0u64, |number, symbol| {
        let digit = ALPHABET.iter().position(|known| *known == symbol)?;
        number.checked_mul(32)?.checked_add(digit as u64)
    })
}

/// Maps only canonical local OIDC u32 subjects; opaque IDs are never guessed.
pub fn account_id_for_subject(subject: &str) -> Result<String, Error> {
    let canonical = subject == "0"
        || (matches!(subject.len(), 1..=10)
            && subject.bytes().all(|byte| byte.is_ascii_digit())
            && !subject.starts_with('0'));
    if !canonical {
        return Err(Error::denied(
            "An explicit verified native account mapping is required",
        ));
    }
    match subject.parse::<u32>() {
        Ok(number) => Ok(encode_native_id(u64::from(number))),
        Err(_) => Err(Error::denied(
            "Native account subject exceeds its supported range",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_numeral_reads_back_as_its_number() {
        for number in [0, 1, 31, 32, 1023, 1024, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(
                decode_native_id(&encode_native_id(number)),
                Some(number),
                "{number}"
            );
        }
        assert_eq!(decode_native_id("b"), Some(1));
        for wrong in [
            "",
            "B",
            "a-b",
            "8",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab2222222222222",
        ] {
            assert_eq!(decode_native_id(wrong), None, "{wrong:?}");
        }
    }

    #[test]
    fn numerals_use_the_native_alphabet() {
        assert_eq!(encode_native_id(0), "a");
        assert_eq!(encode_native_id(1), "b");
        assert_eq!(encode_native_id(31), "3");
        assert_eq!(encode_native_id(32), "ba");
        assert_eq!(encode_native_id(u64::MAX), "p333333333333");
    }

    #[test]
    fn only_canonical_u32_subjects_map() {
        assert_eq!(account_id_for_subject("0").unwrap(), "a");
        assert_eq!(account_id_for_subject("4294967295").unwrap(), "d333333");
        for subject in ["", "01", "-1", "1.0", "abc", " 1", "12345678901", "١"] {
            assert_eq!(
                account_id_for_subject(subject),
                Err(Error::denied(
                    "An explicit verified native account mapping is required"
                )),
                "{subject}"
            );
        }
        assert_eq!(
            account_id_for_subject("4294967296"),
            Err(Error::denied(
                "Native account subject exceeds its supported range"
            ))
        );
    }
}
