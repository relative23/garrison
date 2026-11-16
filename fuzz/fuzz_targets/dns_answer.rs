//! A resolver's answer, as the DNS provider reads it: no input panics, what
//! is read as a record is text of bounded length, and a name read from it is
//! one that a question can carry, 253 octets at the most as written, and
//! never empty: the root reads as `.`.
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
        Kind::Ptr,
        Kind::Txt,
        Kind::Srv,
        Kind::Tlsa,
    ] {
        if let Ok(Some(Answer::Records(records))) = read(data, id, kind) {
            assert!(records.len() <= 64);
            for record in records {
                assert!(record.len() <= 4 * data.len() + 64, "{kind:?}");
                // A name comes last in these records, and holds no space.
                if matches!(kind, Kind::Cname | Kind::Mx | Kind::Ptr | Kind::Srv) {
                    let name = record.rsplit(' ').next().unwrap_or_default();
                    assert!(name.len() <= 253, "{kind:?}: {}", name.len());
                    assert!(!name.is_empty(), "{kind:?}: {record:?}");
                }
            }
        }
    }
});
