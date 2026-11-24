//! A part's base64 as the mail programs the macro scan follows read it:
//! wherever one of their decoders hands over a file with a document with
//! macros in it, the message that carries the body is not clean.
#![no_main]

use garrison_milter::decoders::READ;
use garrison_milter::scan::{Outcome, in_file, macros};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    let rebuilt = READ
        .iter()
        .find(|(_, decode)| in_file(&decode(body)).is_some());
    if let Some((decoder, _)) = rebuilt {
        let mut message = b"Subject: x\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
        message.extend_from_slice(body);
        assert_ne!(macros(&message), Outcome::Clean, "{decoder} rebuilds it");
    }
});
