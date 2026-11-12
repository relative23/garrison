//! A resolver's answer, as the DNS provider reads it: no input panics, and
//! what is read as a record is text of bounded length.
#![no_main]

use garrison_collector::dns::{Answer, Kind, read};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first two bytes are the number the answer must carry.
    let id = match data {
        [first, second, ..] => u16::from_be_bytes([*first, *second]),
        _ => 0,
    };
    for kind in [
        Kind::A,
        Kind::Aaaa,
        Kind::Cname,
        Kind::Mx,
        Kind::Txt,
        Kind::Srv,
        Kind::Tlsa,
    ] {
        if let Ok(Some(Answer::Records(records))) = read(data, id, kind) {
            assert!(records.len() <= 64);
            for record in records {
                assert!(record.len() <= 4 * data.len() + 64, "{kind:?}");
            }
        }
    }
});
