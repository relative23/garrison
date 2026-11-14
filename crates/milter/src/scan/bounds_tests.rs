//! The scan's work stays in proportion to the message, whatever its headers say.

use std::time::{Duration, Instant};

use super::tests::message;
use super::*;
use crate::sample::{archive, document};

/// What a scan of a megabyte may take. An optimized build is what runs on a
/// mail host; the other one is given the time its checks cost.
fn in_time() -> Duration {
    if cfg!(debug_assertions) {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(1)
    }
}

/// Local file headers, deflated and written as a stream (no size), whose
/// extra fields all end where the headers end: each one's data is everything
/// that follows them. What follows is deflate that takes input and gives
/// nothing: empty stored blocks.
fn headers_that_share_their_data(count: usize, rest: usize) -> Vec<u8> {
    let mut data = Vec::new();
    for index in 0..count {
        let extra = u16::try_from((count - index - 1) * 30).unwrap();
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&[20, 0, 0, 0, 8, 0]); // version, flags, method
        data.extend_from_slice(&[0; 16]); // time, date, checksum, sizes
        data.extend_from_slice(&[0, 0]); // name
        data.extend_from_slice(&extra.to_le_bytes());
    }
    data.extend(b"\x00\x00\x00\xff\xff".repeat(rest / 5));
    data
}

#[test]
fn a_megabyte_of_directory_headers_is_searched_in_time() {
    // Each of these names a "name" of 19 280 bytes: the next header's first
    // bytes read as a length.
    let data = b"PK\x01\x02".repeat(256 * 1024);
    let began = Instant::now();
    assert_eq!(macros(&message("data.bin", &data)), Outcome::Clean);
    assert!(began.elapsed() < in_time(), "{:?}", began.elapsed());
}

#[test]
fn two_thousand_headers_over_the_same_data_are_unpacked_in_time() {
    let data = headers_that_share_their_data(2000, 1024 * 1024);
    let began = Instant::now();
    // The data is read once, for the first header; the others claim what is
    // read already, which no archive's files do.
    assert_eq!(
        macros(&message("data.zip", &data)),
        Outcome::Incomplete(Gap::Budget)
    );
    assert!(began.elapsed() < in_time(), "{:?}", began.elapsed());
}

#[test]
fn an_archive_of_many_small_files_is_read_to_its_last_one() {
    // Nothing overlaps here: every file is unpacked, the last one too.
    let names: Vec<String> = (0..3000)
        .map(|index| format!("notes/{index}.txt"))
        .collect();
    let mut entries: Vec<(&str, &[u8], bool)> = names
        .iter()
        .map(|name| (name.as_str(), b"Nothing but text.".as_slice(), true))
        .collect();
    assert_eq!(
        macros(&message("notes.zip", &archive(&entries))),
        Outcome::Clean
    );
    let inner = document();
    entries.push(("invoice.docm", &inner, true));
    assert_eq!(
        macros(&message("notes.zip", &archive(&entries))),
        Outcome::Macros(Found::Zipped)
    );
}

#[test]
fn more_packed_files_than_an_archive_lists_are_not_all_opened() {
    // An empty deflated file is two bytes; its header, thirty.
    let mut data = Vec::new();
    for _ in 0..=65_535 {
        data.extend_from_slice(b"PK\x03\x04");
        data.extend_from_slice(&[20, 0, 0, 0, 8, 0]);
        data.extend_from_slice(&[0; 8]);
        data.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        data.extend_from_slice(&[3, 0]);
    }
    assert_eq!(macros(&data), Outcome::Incomplete(Gap::Budget));
    assert_eq!(macros(&data[..65_535 * 32]), Outcome::Clean);
}

#[test]
fn a_scan_whose_time_is_up_does_not_call_the_message_clean() {
    let clean = message("letter.txt", b"Nothing but text.");
    assert_eq!(
        macros_until(&clean, Instant::now()),
        Outcome::Incomplete(Gap::Deadline)
    );
    let later = Instant::now() + Duration::from_secs(60);
    assert_eq!(macros_until(&clean, later), Outcome::Clean);
    assert_eq!(
        macros_until(&message("invoice.docm", &document()), later),
        Outcome::Macros(Found::Zipped)
    );
    assert_eq!(Gap::Deadline.name(), "the scan's time ran out");
    assert_eq!(
        Gap::Budget.name(),
        "its archives hold more than the scan unpacks"
    );
}

#[test]
fn the_time_runs_out_inside_a_file_that_is_being_unpacked() {
    // Deflate that takes input and gives nothing keeps a scan busy for as
    // long as there is input: the clock is looked at in between.
    let mut data = b"PK\x03\x04".to_vec();
    data.extend_from_slice(&[20, 0, 0, 0, 8, 0]);
    data.extend_from_slice(&[0; 20]);
    data.extend(b"\x00\x00\x00\xff\xff".repeat(8 * 1024 * 1024 / 5));
    let began = Instant::now();
    assert_eq!(
        macros_until(&data, began + Duration::from_millis(1)),
        Outcome::Incomplete(Gap::Deadline)
    );
    assert!(began.elapsed() < in_time(), "{:?}", began.elapsed());
}
