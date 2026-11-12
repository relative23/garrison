//! A message as the macro milter scans it: no input panics or runs away,
//! whatever it claims of base64, quoted-printable and archives in archives.
#![no_main]

use garrison_milter::scan::macros;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = macros(data);
});
