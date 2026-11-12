//! The text of Stalwart's metrics endpoint: parsing never panics and keeps
//! only finite numbers, which the status database can store.
#![no_main]

use garrison_collector::providers::prometheus::parse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for (name, value) in parse(&text) {
        assert!(value.is_finite(), "{name}");
        assert!(!name.contains(char::is_whitespace), "{name:?}");
    }
});
