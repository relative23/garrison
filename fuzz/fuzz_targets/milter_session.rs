//! What a mail server sends the macro milter on one connection: no sequence
//! of frames panics, and the filter never answers more than a little for
//! each frame it was sent.
#![no_main]

use std::io::{self, Cursor, Read, Write};

use garrison_milter::server::{Settings, session};
use libfuzzer_sys::fuzz_target;

/// What the mail server sent, and how much the filter wrote back.
struct Wire<'a> {
    sent: Cursor<&'a [u8]>,
    answered: usize,
}

impl Read for Wire<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.sent.read(buffer)
    }
}

impl Write for Wire<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.answered += data.len();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    for tag in [false, true] {
        let mut wire = Wire {
            sent: Cursor::new(data),
            answered: 0,
        };
        let _ = session(
            &mut wire,
            Settings {
                tag,
                max_bytes: 64 * 1024,
            },
        );
        // A frame is at least five bytes, and the longest answer to one is
        // the refusal with its header.
        assert!(wire.answered <= 256 * (data.len() / 5 + 1), "{}", wire.answered);
    }
});
