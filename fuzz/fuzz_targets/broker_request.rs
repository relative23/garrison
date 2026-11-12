//! A line on the broker's socket: decoding never panics, and a request that
//! was decoded is the same request when it is written and decoded again.
#![no_main]

use garrison_broker::protocol::decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = decode(data) else {
        return;
    };
    let line = serde_json::to_vec(&request).expect("a request can be written");
    assert!(decode(&line).is_ok_and(|again| again == request));
});
