//! What the scan could not look at is said, never passed off as clean.

use super::tests::message;
use super::*;
use crate::sample::{archive, document};

/// An archive of one file, with `method` written where its two headers
/// name how the file is packed: the one before it, the directory's, or both.
fn packed_as(method: u8, before_file: bool, listed: bool) -> Vec<u8> {
    let mut data = archive(&[(
        "report.txt",
        b"Nothing but text.".repeat(20).as_slice(),
        true,
    )]);
    let directory = data
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    if before_file {
        data[8] = method;
    }
    if listed {
        data[directory + 10] = method;
    }
    data
}

#[test]
fn a_document_behind_a_spent_budget_is_not_called_clean() {
    // Four files of zeros use up all that is unpacked; the document after
    // them is deflated inside its archive, so its name is not in sight.
    let zeros = vec![0u8; 16 * 1024 * 1024];
    let mut hidden = vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
    hidden.extend(std::iter::repeat_n(b'A', 8192));
    let inner = archive(&[("word/vbaProject.bin", &hidden, false)]);
    let alone = archive(&[("invoice.docm", &inner, true)]);
    assert_eq!(
        macros(&message("invoice.zip", &alone)),
        Outcome::Macros(Found::Zipped)
    );
    let spent = archive(&[
        ("a.bin", &zeros, true),
        ("b.bin", &zeros, true),
        ("c.bin", &zeros, true),
        ("d.bin", &zeros, true),
        ("invoice.docm", &inner, true),
    ]);
    assert_eq!(
        macros(&message("invoice.zip", &spent)),
        Outcome::Incomplete(Gap::Budget)
    );
    // What is left of the budget cuts a file as well.
    let nearly = archive(&[
        ("a.bin", &zeros, true),
        ("b.bin", &zeros, true),
        ("c.bin", &zeros, true),
        ("d.bin", &zeros[..zeros.len() - 100], true),
        ("e.bin", &zeros[..200], true),
    ]);
    assert_eq!(
        macros(&message("nearly.zip", &nearly)),
        Outcome::Incomplete(Gap::Budget)
    );
}

#[test]
fn a_file_packed_in_a_way_the_scan_does_not_read_is_not_called_clean() {
    // bzip2, LZMA, zstd, and Deflate64, which Windows itself unpacks.
    for method in [9, 12, 14, 93] {
        for (before_file, listed) in [(true, true), (true, false), (false, true)] {
            assert_eq!(
                macros(&message("a.zip", &packed_as(method, before_file, listed))),
                Outcome::Incomplete(Gap::Method),
                "{method} {before_file} {listed}"
            );
        }
    }
    // Stored and deflated are read. A number no program unpacks is noise,
    // and the one that stands for a password is the limit it always was.
    for method in [0, 8, 11, 99, 200] {
        assert_eq!(
            macros(&message("a.zip", &packed_as(method, true, true))),
            Outcome::Clean,
            "{method}"
        );
    }
}

#[test]
fn a_file_cut_at_the_size_that_is_unpacked_is_not_called_clean() {
    let large = vec![0u8; 16 * 1024 * 1024 + 1];
    let cut = archive(&[("large.bin", &large, true)]);
    assert_eq!(
        macros(&message("large.zip", &cut)),
        Outcome::Incomplete(Gap::Truncated)
    );
    // A file of just that size is there as a whole.
    let whole = archive(&[("large.bin", &large[1..], true)]);
    assert_eq!(macros(&message("large.zip", &whole)), Outcome::Clean);
    // A document that is in sight is found whatever else was left out.
    let both = archive(&[("large.bin", &large, true), ("a.docm", &document(), true)]);
    assert_eq!(
        macros(&message("both.zip", &both)),
        Outcome::Macros(Found::Zipped)
    );
    for gap in [Gap::Truncated, Gap::Method, Gap::Size] {
        assert_ne!(gap.name(), "");
    }
}
