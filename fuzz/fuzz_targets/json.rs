//! The strict JSON parser every component reads with: whatever it accepts is
//! JSON with the same value for any reader, and survives being written again.
#![no_main]

use garrison_core::json;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(strict) = json::parse(data, 1 << 20) else {
        return;
    };
    let plain: Value = serde_json::from_slice(data).expect("strict JSON is JSON");
    assert_eq!(plain, strict);
    let written = serde_json::to_vec(&strict).expect("a value can be written");
    let again = json::parse(&written, usize::MAX).expect("written JSON is strict JSON");
    assert_eq!(again, strict);
});
